mod passkey_auth;
mod session;
mod wrapper_repair;

use cove_cspp::CsppStore as _;
use cove_device::cloud_storage::{CloudStorage, CloudStorageError};
use cove_device::keychain::{CSPP_CREDENTIAL_ID_KEY, CSPP_PRF_SALT_KEY, Keychain};
use cove_device::passkey::PasskeyAccess;
use cove_util::ResultExt as _;
use tracing::{error, info, warn};

use self::session::VerificationSession;
use self::wrapper_repair::{WrapperRepairOperation, WrapperRepairStrategy};
use super::wallets::count_all_wallets;
use super::{
    CloudBackupError, CloudBackupState, DeepVerificationFailure, DeepVerificationResult, RP_ID,
    RustCloudBackupManager, VerificationFailureKind,
};
use crate::database::Database;
use crate::database::global_config::CloudBackup;

impl RustCloudBackupManager {
    /// Background startup health check for cloud backup integrity
    ///
    /// Verifies the master key is in the keychain and backup files exist in iCloud.
    /// Returns None if everything is OK, Some(warning) if there's a problem
    pub(super) fn verify_backup_integrity_impl(&self) -> Option<String> {
        let state = self.snapshot.read().state.clone();
        if !matches!(state, CloudBackupState::Enabled | CloudBackupState::PasskeyMissing) {
            return None;
        }

        let mut issues: Vec<&str> = Vec::new();

        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        if !cspp.has_master_key() {
            issues.push("master key not found in keychain");
        }

        if keychain.get(CSPP_CREDENTIAL_ID_KEY.into()).is_none() {
            issues
                .push("passkey credential not found — open Cloud Backup in Settings to re-verify");
        }
        if keychain.get(CSPP_PRF_SALT_KEY.into()).is_none() {
            issues.push("passkey salt not found — open Cloud Backup in Settings to re-verify");
        }

        let namespace = match self.current_namespace_id() {
            Ok(ns) => ns,
            Err(_) => {
                issues.push("namespace_id not found in keychain");
                return Some(issues.join("; "));
            }
        };

        let cloud = CloudStorage::global();
        if issues.is_empty() {
            match cloud.list_wallet_backups(namespace) {
                Ok(wallet_record_ids) => {
                    let db = Database::global();
                    let local_count = count_all_wallets(&db);
                    let cloud_count = wallet_record_ids.len() as u32;

                    if local_count > cloud_count {
                        info!(
                            "Backup integrity: {local_count} local wallets vs {cloud_count} in cloud, auto-syncing"
                        );
                        if let Err(error) = self.do_sync_unsynced_wallets() {
                            error!("Backup integrity: auto-sync failed: {error}");
                            issues.push("some wallets are not backed up");
                        }
                    }
                }
                Err(error) => {
                    warn!("Backup integrity: wallet list check failed: {error}");
                }
            }
        }

        if issues.is_empty() {
            info!("Backup integrity check passed");
            None
        } else {
            let message = issues.join("; ");
            error!("Backup integrity issues: {message}");
            Some(message)
        }
    }

    /// Deep verification of cloud backup integrity
    ///
    /// Checks state, runs do_deep_verify, wraps errors, persists result
    pub(crate) fn deep_verify_cloud_backup(
        &self,
        force_discoverable: bool,
    ) -> DeepVerificationResult {
        let state = self.snapshot.read().state.clone();
        if !matches!(state, CloudBackupState::Enabled | CloudBackupState::PasskeyMissing) {
            return DeepVerificationResult::NotEnabled;
        }

        let result = match self.do_deep_verify_cloud_backup(force_discoverable) {
            Ok(result) => result,
            Err(error) => {
                error!("Deep verification unexpected error: {error}");
                DeepVerificationResult::Failed(DeepVerificationFailure {
                    kind: VerificationFailureKind::Retry,
                    message: error.to_string(),
                    detail: None,
                })
            }
        };

        self.persist_verification_result(&result);
        result
    }

    pub(crate) fn persist_verification_result(&self, result: &DeepVerificationResult) {
        let db = Database::global();
        let current = db.global_config.cloud_backup();

        let (last_sync, wallet_count) = match &current {
            CloudBackup::Enabled { last_sync, wallet_count }
            | CloudBackup::Unverified { last_sync, wallet_count }
            | CloudBackup::PasskeyMissing { last_sync, wallet_count } => {
                (*last_sync, *wallet_count)
            }
            CloudBackup::Disabled => return,
        };

        let new_state = match result {
            DeepVerificationResult::Verified(_) => CloudBackup::Enabled { last_sync, wallet_count },
            DeepVerificationResult::PasskeyConfirmed(_) => return,
            DeepVerificationResult::PasskeyMissing(_) => {
                CloudBackup::PasskeyMissing { last_sync, wallet_count }
            }
            DeepVerificationResult::UserCancelled(_) | DeepVerificationResult::Failed(_) => {
                CloudBackup::Unverified { last_sync, wallet_count }
            }
            DeepVerificationResult::NotEnabled => return,
        };

        if current != new_state {
            if let Err(error) = db.global_config.set_cloud_backup(&new_state) {
                error!("Failed to persist verification state: {error}");
                return;
            }

            let runtime_state = match new_state {
                CloudBackup::PasskeyMissing { .. } => CloudBackupState::PasskeyMissing,
                CloudBackup::Enabled { .. } | CloudBackup::Unverified { .. } => {
                    CloudBackupState::Enabled
                }
                CloudBackup::Disabled => return,
            };
            self.send(super::CloudBackupReconcileMessage::StateChanged(runtime_state));
        }
    }

    pub(crate) fn do_repair_passkey_wrapper(&self) -> Result<(), CloudBackupError> {
        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        let cloud = CloudStorage::global();
        let passkey = PasskeyAccess::global();
        let namespace = self.current_namespace_id()?;

        let local_master_key = cspp
            .load_master_key_from_store()
            .map_err_prefix("load local master key", CloudBackupError::Internal)?
            .ok_or_else(|| CloudBackupError::Internal("no local master key".into()))?;

        let wallet_record_ids = match cloud.list_wallet_backups(namespace.clone()) {
            Ok(ids) => ids,
            Err(CloudStorageError::NotFound(_)) => Vec::new(),
            Err(error) => {
                return Err(CloudBackupError::Cloud(format!("list wallet backups: {error}")));
            }
        };

        let repair = WrapperRepairOperation::new(self, keychain, cloud, passkey, &namespace);
        repair
            .run(&local_master_key, &wallet_record_ids, WrapperRepairStrategy::CreateNew)
            .map_err(|error| error.into_cloud_backup_error())?;

        info!("Repaired cloud master key wrapper with new passkey");
        Ok(())
    }

    pub(crate) fn do_deep_verify_cloud_backup(
        &self,
        force_discoverable: bool,
    ) -> Result<DeepVerificationResult, CloudBackupError> {
        VerificationSession::new(self, force_discoverable)?.run()
    }
}
