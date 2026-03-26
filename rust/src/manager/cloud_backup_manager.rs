mod cloud_inventory;
mod ops;
mod pending;
mod verify;
mod wallets;

use std::sync::{Arc, LazyLock, atomic::AtomicBool};

use cove_cspp::CsppStore as _;
use cove_cspp::backup_data::MASTER_KEY_RECORD_ID;
use flume::{Receiver, Sender};
use parking_lot::RwLock;
use tracing::{error, info, warn};

use cove_device::keychain::{
    CSPP_CREDENTIAL_ID_KEY, CSPP_NAMESPACE_ID_KEY, CSPP_PRF_SALT_KEY, Keychain,
};
use cove_types::network::Network;

use crate::backup::model::DescriptorPair as LocalDescriptorPair;
use crate::database::Database;
use crate::database::global_config::CloudBackup;
use crate::wallet::metadata::{WalletMode as LocalWalletMode, WalletType};

use self::wallets::{all_local_wallets, count_all_wallets};
use super::cloud_backup_detail_manager::{
    CloudOnlyOperation, CloudOnlyState, RecoveryState, SyncState, VerificationState,
};

type LocalWalletSecret = crate::backup::model::WalletSecret;

const RP_ID: &str = "covebitcoinwallet.com";
const UPLOAD_VERIFICATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

type Message = CloudBackupReconcileMessage;

pub static CLOUD_BACKUP_MANAGER: LazyLock<Arc<RustCloudBackupManager>> =
    LazyLock::new(RustCloudBackupManager::init);

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Enum)]
pub enum CloudBackupState {
    Disabled,
    Enabling,
    Restoring,
    Enabled,
    PasskeyMissing,
    Error(String),
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudBackupReconcileMessage {
    Updated,
    StateChanged(CloudBackupState),
    ProgressUpdated { completed: u32, total: u32 },
    EnableComplete,
    RestoreComplete(CloudBackupRestoreReport),
    SyncFailed(String),
    PendingUploadVerificationChanged { pending: bool },
    ExistingBackupFound,
    PasskeyDiscoveryCancelled,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CloudBackupRestoreReport {
    pub wallets_restored: u32,
    pub wallets_failed: u32,
    pub failed_wallet_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, uniffi::Record)]
pub struct CloudBackupProgress {
    pub completed: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Enum)]
pub enum CloudBackupWalletStatus {
    BackedUp,
    NotBackedUp,
    DeletedFromDevice,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, uniffi::Record)]
pub struct CloudBackupWalletItem {
    pub name: String,
    pub network: Network,
    pub wallet_mode: LocalWalletMode,
    pub wallet_type: WalletType,
    pub fingerprint: Option<String>,
    pub status: CloudBackupWalletStatus,
    /// Deterministic cloud record ID for the wallet backup represented by this item
    pub record_id: String,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudBackupDetailResult {
    Success(CloudBackupDetail),
    AccessError(String),
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CloudBackupDetail {
    pub last_sync: Option<u64>,
    pub backed_up: Vec<CloudBackupWalletItem>,
    pub not_backed_up: Vec<CloudBackupWalletItem>,
    /// Number of wallets in the cloud that aren't on this device
    pub cloud_only_count: u32,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum DeepVerificationResult {
    Verified(DeepVerificationReport),
    PasskeyConfirmed(Option<CloudBackupDetail>),
    PasskeyMissing(Option<CloudBackupDetail>),
    UserCancelled(Option<CloudBackupDetail>),
    NotEnabled,
    Failed(DeepVerificationFailure),
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeepVerificationReport {
    /// Cloud master key PRF wrapping was repaired
    pub master_key_wrapper_repaired: bool,
    /// Local keychain was repaired from verified cloud master key
    pub local_master_key_repaired: bool,
    /// credential_id was recovered via discoverable auth
    pub credential_recovered: bool,
    pub wallets_verified: u32,
    pub wallets_failed: u32,
    /// Wallet backups with unsupported version (newer format, skipped)
    pub wallets_unsupported: u32,
    /// May be None if wallet list was missing but master key verified
    pub detail: Option<CloudBackupDetail>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeepVerificationFailure {
    pub kind: VerificationFailureKind,
    pub message: String,
    pub detail: Option<CloudBackupDetail>,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum VerificationFailureKind {
    /// Transient iCloud/network/passkey error — safe to retry
    Retry,
    /// Manifest missing, master key verified intact — recreate from local wallets
    RecreateManifest { warning: String },
    /// No verified cloud or local master key available — full re-enable needed
    ReinitializeBackup { warning: String },
    /// Backup uses a newer format — do not overwrite
    UnsupportedVersion,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CloudBackupSnapshot {
    pub state: CloudBackupState,
    pub progress: Option<CloudBackupProgress>,
    pub restore_report: Option<CloudBackupRestoreReport>,
    pub sync_error: Option<String>,
    pub has_pending_upload_verification: bool,
    pub is_unverified: bool,
    pub is_configured: bool,
    pub detail: Option<CloudBackupDetail>,
    pub verification: VerificationState,
    pub sync: SyncState,
    pub recovery: RecoveryState,
    pub cloud_only: CloudOnlyState,
    pub cloud_only_operation: CloudOnlyOperation,
}

impl Default for CloudBackupSnapshot {
    fn default() -> Self {
        Self {
            state: CloudBackupState::Disabled,
            progress: None,
            restore_report: None,
            sync_error: None,
            has_pending_upload_verification: false,
            is_unverified: false,
            is_configured: false,
            detail: None,
            verification: VerificationState::Idle,
            sync: SyncState::Idle,
            recovery: RecoveryState::Idle,
            cloud_only: CloudOnlyState::NotFetched,
            cloud_only_operation: CloudOnlyOperation::Idle,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CloudBackupError {
    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("passkey error: {0}")]
    Passkey(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("cloud storage error: {0}")]
    Cloud(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("Passkey didn't match any backups, please try a new one")]
    PasskeyMismatch,

    #[error("user cancelled passkey discovery")]
    PasskeyDiscoveryCancelled,
}

#[uniffi::export(callback_interface)]
pub trait CloudBackupManagerReconciler: Send + Sync + std::fmt::Debug + 'static {
    fn reconcile(&self, message: CloudBackupReconcileMessage);
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct RustCloudBackupManager {
    pub snapshot: Arc<RwLock<CloudBackupSnapshot>>,
    pub reconciler: Sender<Message>,
    pub reconcile_receiver: Arc<Receiver<Message>>,
    pending_upload_verifier_running: Arc<AtomicBool>,
}

impl RustCloudBackupManager {
    fn init() -> Arc<Self> {
        let (sender, receiver) = flume::bounded(1000);

        Self {
            snapshot: Arc::new(RwLock::new(CloudBackupSnapshot::default())),
            reconciler: sender,
            reconcile_receiver: Arc::new(receiver),
            pending_upload_verifier_running: Arc::new(AtomicBool::new(false)),
        }
        .into()
    }

    fn refresh_snapshot_flags(snapshot: &mut CloudBackupSnapshot) {
        let db_state = Database::global().global_config.cloud_backup();
        snapshot.is_unverified = matches!(db_state, CloudBackup::Unverified { .. });
        snapshot.is_configured = !matches!(db_state, CloudBackup::Disabled);
    }

    fn apply_message_to_snapshot(&self, message: &Message) {
        let mut snapshot = self.snapshot.write();

        match message {
            Message::Updated => {}
            Message::StateChanged(state) => {
                snapshot.state = state.clone();

                if matches!(state, CloudBackupState::Enabling | CloudBackupState::Restoring) {
                    snapshot.progress = None;
                    snapshot.restore_report = None;
                }
            }
            Message::ProgressUpdated { completed, total } => {
                snapshot.progress =
                    Some(CloudBackupProgress { completed: *completed, total: *total });
            }
            Message::EnableComplete => snapshot.progress = None,
            Message::RestoreComplete(report) => {
                snapshot.restore_report = Some(report.clone());
                snapshot.progress = None;
            }
            Message::SyncFailed(error) => snapshot.sync_error = Some(error.clone()),
            Message::PendingUploadVerificationChanged { pending } => {
                snapshot.has_pending_upload_verification = *pending;
            }
            Message::ExistingBackupFound | Message::PasskeyDiscoveryCancelled => {}
        }

        Self::refresh_snapshot_flags(&mut snapshot);
    }

    fn send(&self, message: Message) {
        self.apply_message_to_snapshot(&message);

        if let Err(error) = self.reconciler.send(message) {
            error!("unable to send cloud backup message: {error:?}");
        }
    }

    pub(crate) fn update_snapshot<F>(&self, update: F)
    where
        F: FnOnce(&mut CloudBackupSnapshot),
    {
        {
            let mut snapshot = self.snapshot.write();
            update(&mut snapshot);
            Self::refresh_snapshot_flags(&mut snapshot);
        }

        self.send(Message::Updated);
    }

    fn current_namespace_id(&self) -> Result<String, CloudBackupError> {
        let keychain = Keychain::global();
        keychain
            .get(CSPP_NAMESPACE_ID_KEY.into())
            .ok_or_else(|| CloudBackupError::Internal("namespace_id not found in keychain".into()))
    }

    fn start_background_operation<F>(
        self: Arc<Self>,
        operation_name: &str,
        entering_state: Option<CloudBackupState>,
        work: F,
    ) where
        F: FnOnce(Arc<Self>) -> Result<(), CloudBackupError> + Send + 'static,
    {
        {
            let state = self.snapshot.read().state.clone();
            if matches!(state, CloudBackupState::Enabling | CloudBackupState::Restoring) {
                warn!("{operation_name} called while {state:?}, ignoring");
                return;
            }
        }

        let operation_name = operation_name.to_owned();
        cove_tokio::task::spawn_blocking(move || {
            if let Some(state) = entering_state {
                self.send(Message::StateChanged(state));
            }

            if let Err(error) = work(self.clone()) {
                error!("{operation_name} failed: {error}");
                self.send(Message::StateChanged(CloudBackupState::Error(error.to_string())));
            }
        });
    }
}

#[uniffi::export]
impl RustCloudBackupManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        CLOUD_BACKUP_MANAGER.clone()
    }

    pub fn listen_for_updates(&self, reconciler: Box<dyn CloudBackupManagerReconciler>) {
        let reconcile_receiver = self.reconcile_receiver.clone();

        std::thread::spawn(move || {
            while let Ok(field) = reconcile_receiver.recv() {
                reconciler.reconcile(field);
            }
        });
    }

    pub fn current_state(&self) -> CloudBackupState {
        self.snapshot.read().state.clone()
    }

    pub fn snapshot(&self) -> CloudBackupSnapshot {
        let mut snapshot = self.snapshot.read().clone();
        Self::refresh_snapshot_flags(&mut snapshot);
        snapshot.has_pending_upload_verification = self.has_pending_cloud_upload_verification();
        snapshot
    }

    /// Number of wallets in the cloud backup
    pub fn backup_wallet_count(&self) -> Option<u32> {
        let db = Database::global();
        let current = db.global_config.cloud_backup();

        match current.wallet_count() {
            Some(count) => Some(count),
            None if !matches!(&current, CloudBackup::Disabled) => {
                let count = count_all_wallets(&db);
                let _ = db.global_config.set_cloud_backup(&current.with_wallet_count(Some(count)));
                Some(count)
            }
            None => None,
        }
    }

    /// Read persisted cloud backup state from DB and update in-memory state
    ///
    /// Called after bootstrap completes so the UI reflects the correct state
    /// even before the reconciler has delivered its first message
    pub fn sync_persisted_state(&self) {
        let db_state = Database::global().global_config.cloud_backup();
        let mut snapshot = self.snapshot.write();

        if matches!(snapshot.state, CloudBackupState::Disabled) {
            let new_state = match db_state {
                CloudBackup::Enabled { .. } | CloudBackup::Unverified { .. } => {
                    CloudBackupState::Enabled
                }
                CloudBackup::PasskeyMissing { .. } => CloudBackupState::PasskeyMissing,
                CloudBackup::Disabled => CloudBackupState::Disabled,
            };

            if snapshot.state != new_state {
                snapshot.state = new_state.clone();
                Self::refresh_snapshot_flags(&mut snapshot);
                drop(snapshot);
                self.send(Message::StateChanged(new_state));
            }
        }
    }

    /// Check if cloud backup is enabled, used as nav guard
    pub fn is_cloud_backup_enabled(&self) -> bool {
        let db = Database::global();
        matches!(
            db.global_config.cloud_backup(),
            CloudBackup::Enabled { .. }
                | CloudBackup::Unverified { .. }
                | CloudBackup::PasskeyMissing { .. }
        )
    }

    /// Whether the persisted cloud backup state is unverified
    pub fn is_cloud_backup_unverified(&self) -> bool {
        matches!(Database::global().global_config.cloud_backup(), CloudBackup::Unverified { .. })
    }

    /// Whether the persisted cloud backup passkey is missing
    pub fn is_cloud_backup_passkey_missing(&self) -> bool {
        matches!(
            Database::global().global_config.cloud_backup(),
            CloudBackup::PasskeyMissing { .. }
        )
    }

    pub fn has_pending_cloud_upload_verification(&self) -> bool {
        Database::global()
            .cloud_backup_upload_verification
            .get()
            .ok()
            .flatten()
            .is_some_and(|pending| pending.has_unconfirmed())
    }

    pub fn resume_pending_cloud_upload_verification(&self) {
        self.start_pending_upload_verification_loop();
    }

    /// Reset local cloud backup state (keychain + DB) without touching iCloud
    ///
    /// Debug-only: pair with Swift-side iCloud wipe for full reset
    pub fn debug_reset_cloud_backup_state(&self) {
        let keychain = Keychain::global();
        keychain.delete(CSPP_NAMESPACE_ID_KEY.to_string());
        keychain.delete(CSPP_CREDENTIAL_ID_KEY.to_string());
        keychain.delete(CSPP_PRF_SALT_KEY.to_string());

        // also delete the master key so next enable starts clean
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        cspp.delete_master_key();
        cove_cspp::reset_master_key_cache();

        let db = Database::global();
        let _ = db.global_config.set_cloud_backup(&CloudBackup::Disabled);
        let _ = db.cloud_backup_upload_verification.delete();

        self.update_snapshot(|snapshot| {
            *snapshot = CloudBackupSnapshot::default();
        });
        self.send(Message::StateChanged(CloudBackupState::Disabled));
        self.send(Message::PendingUploadVerificationChanged { pending: false });
        info!("Debug: reset cloud backup local state (including master key)");
    }

    /// Background startup health check for cloud backup integrity
    pub fn verify_backup_integrity(&self) -> Option<String> {
        self.verify_backup_integrity_impl()
    }

    /// Enable cloud backup — idempotent, safe to retry
    ///
    /// Creates passkey, encrypts master key + all wallets, hands them off to iCloud,
    /// then verifies full upload in the background
    pub fn enable_cloud_backup(&self) {
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "enable_cloud_backup",
            None,
            |this| this.do_enable_cloud_backup(),
        );
    }

    /// Enable cloud backup, skipping recovery — creates a new namespace
    ///
    /// Called after the user confirms they want a new backup when existing cloud
    /// backups were found but not recovered (UserDeclined or NoMatch)
    pub fn enable_cloud_backup_force_new(&self) {
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "enable_cloud_backup_force_new",
            Some(CloudBackupState::Enabling),
            |this| this.do_enable_cloud_backup_create_new(),
        );
    }

    /// Enable cloud backup, skipping passkey discovery — goes straight to registration
    ///
    /// Called after the user cancels the passkey discovery picker and chooses
    /// "Create New Passkey" from the options alert
    pub fn enable_cloud_backup_no_discovery(&self) {
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "enable_cloud_backup_no_discovery",
            Some(CloudBackupState::Enabling),
            |this| this.do_enable_cloud_backup_no_discovery(),
        );
    }

    /// Restore from cloud backup — called after device restore
    ///
    /// Uses discoverable credential assertion (no local keychain state required)
    pub fn restore_from_cloud_backup(&self) {
        info!("restore_from_cloud_backup: spawning restore task");
        CLOUD_BACKUP_MANAGER.clone().start_background_operation(
            "restore_from_cloud_backup",
            None,
            |this| {
                info!("restore_from_cloud_backup: task started");
                this.do_restore_from_cloud_backup()
            },
        );
    }

    /// Back up a newly created wallet, fire-and-forget
    ///
    /// Returns immediately if cloud backup isn't enabled (e.g. during restore)
    pub fn backup_new_wallet(&self, metadata: crate::wallet::metadata::WalletMetadata) {
        let state = self.snapshot.read().state.clone();
        if !matches!(state, CloudBackupState::Enabled | CloudBackupState::PasskeyMissing) {
            return;
        }

        let this = CLOUD_BACKUP_MANAGER.clone();
        cove_tokio::task::spawn_blocking(move || {
            if let Err(error) = this.do_backup_wallets(&[metadata]) {
                warn!("Failed to backup new wallet, retrying full sync: {error}");
                if let Err(error) = this.do_sync_unsynced_wallets() {
                    error!("Retry sync also failed: {error}");
                    this.send(Message::SyncFailed(error.to_string()));
                }
            }
        });
    }
}

/// Wipe all local encrypted databases (main db + per-wallet databases)
///
/// Callers:
///   - iOS: CatastrophicErrorView ("Start Fresh" recovery)
///   - iOS: AboutScreen debug wipe (DEBUG + beta only, paired with cloud wipe)
///
/// Removes both current encrypted filenames and legacy plaintext filenames
#[uniffi::export]
pub fn wipe_local_data() {
    use crate::database::migration::log_remove_file;

    delete_all_wallet_keychain_items();

    let root = &*cove_common::consts::ROOT_DATA_DIR;

    log_remove_file(&root.join("cove.encrypted.db"));
    log_remove_file(&root.join("cove.db"));

    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("bdk_wallet") {
                log_remove_file(&entry.path());
            }
        }
    }

    let wallet_dir = &*cove_common::consts::WALLET_DATA_DIR;
    if wallet_dir.exists()
        && let Err(error) = std::fs::remove_dir_all(wallet_dir)
    {
        error!("Failed to remove wallet data dir: {error}");
    }
}

/// Re-open the database after wipe+re-bootstrap so `Database::global()`
/// returns a handle to the fresh file instead of the deleted one
#[uniffi::export]
pub fn reinit_database() {
    crate::database::wallet_data::DATABASE_CONNECTIONS.write().clear();
    Database::reinit();
}

#[uniffi::export]
pub fn cspp_master_key_record_id() -> String {
    MASTER_KEY_RECORD_ID.to_string()
}

#[uniffi::export]
pub fn cspp_namespaces_subdirectory() -> String {
    cove_cspp::backup_data::NAMESPACES_SUBDIRECTORY.to_string()
}

/// Delete keychain items for all wallets across all networks and modes
///
/// Best-effort: if the database isn't initialized (e.g. key mismatch), skip
fn delete_all_wallet_keychain_items() {
    let Some(db_swap) = crate::database::DATABASE.get() else {
        warn!("Database not initialized, skipping keychain cleanup during wipe");
        return;
    };

    let db = db_swap.load();
    let keychain = Keychain::global();

    for wallet in all_local_wallets(&db) {
        keychain.delete_wallet_items(&wallet.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_cloud_secret_mnemonic() {
        let secret = cove_cspp::backup_data::WalletSecret::Mnemonic("abandon".into());
        let result = wallets::convert_cloud_secret(&secret);
        assert!(matches!(result, LocalWalletSecret::Mnemonic(ref m) if m == "abandon"));
    }

    #[test]
    fn convert_cloud_secret_tap_signer() {
        let secret = cove_cspp::backup_data::WalletSecret::TapSignerBackup(vec![1, 2, 3]);
        let result = wallets::convert_cloud_secret(&secret);
        assert!(matches!(result, LocalWalletSecret::TapSignerBackup(ref b) if b == &[1, 2, 3]));
    }

    #[test]
    fn convert_cloud_secret_descriptor_to_none() {
        let secret = cove_cspp::backup_data::WalletSecret::Descriptor("wpkh(...)".into());
        let result = wallets::convert_cloud_secret(&secret);
        assert!(matches!(result, LocalWalletSecret::None));
    }

    #[test]
    fn convert_cloud_secret_watch_only_to_none() {
        let result =
            wallets::convert_cloud_secret(&cove_cspp::backup_data::WalletSecret::WatchOnly);
        assert!(matches!(result, LocalWalletSecret::None));
    }
}
