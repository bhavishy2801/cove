use tracing::error;

use super::cloud_backup_manager::{
    CLOUD_BACKUP_MANAGER, CloudBackupError, CloudBackupReconcileMessage, CloudBackupWalletItem,
    DeepVerificationFailure, DeepVerificationReport, DeepVerificationResult,
    RustCloudBackupManager,
};

#[derive(Debug, Clone, uniffi::Enum)]
pub enum RecoveryAction {
    RecreateManifest,
    ReinitializeBackup,
    RepairPasskey,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum VerificationState {
    Idle,
    Verifying,
    Verified(DeepVerificationReport),
    PasskeyConfirmed,
    Failed(DeepVerificationFailure),
    Cancelled,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum SyncState {
    Idle,
    Syncing,
    Failed(String),
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum RecoveryState {
    Idle,
    Recovering(RecoveryAction),
    Failed { action: RecoveryAction, error: String },
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudOnlyState {
    NotFetched,
    Loading,
    Loaded { wallets: Vec<CloudBackupWalletItem> },
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CloudOnlyOperation {
    Idle,
    Operating { record_id: String },
    Failed { error: String },
}

#[uniffi::export]
impl RustCloudBackupManager {
    pub fn start_verification(&self) {
        if let Err(error) = self.dismiss_verification_prompt_impl() {
            error!("Failed to dismiss verification prompt before verification: {error}");
        }
        CLOUD_BACKUP_MANAGER.clone().spawn_verification(false);
    }

    pub fn start_verification_discoverable(&self) {
        if let Err(error) = self.dismiss_verification_prompt_impl() {
            error!("Failed to dismiss verification prompt before verification: {error}");
        }
        CLOUD_BACKUP_MANAGER.clone().spawn_verification(true);
    }

    pub fn dismiss_verification_prompt(&self) {
        if let Err(error) = self.dismiss_verification_prompt_impl() {
            error!("Failed to dismiss verification prompt: {error}");
        }
    }

    pub fn recreate_manifest(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_recovery(RecoveryAction::RecreateManifest);
    }

    pub fn reinitialize_backup(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_recovery(RecoveryAction::ReinitializeBackup);
    }

    pub fn repair_passkey(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_repair_passkey(false);
    }

    pub fn repair_passkey_no_discovery(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_repair_passkey(true);
    }

    pub fn sync_unsynced(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_sync();
    }

    pub fn fetch_cloud_only(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_fetch_cloud_only();
    }

    pub fn restore_cloud_wallet(&self, record_id: String) {
        CLOUD_BACKUP_MANAGER.clone().spawn_restore_cloud_wallet(record_id);
    }

    pub fn delete_cloud_wallet(&self, record_id: String) {
        CLOUD_BACKUP_MANAGER.clone().spawn_delete_cloud_wallet(record_id);
    }

    pub fn refresh_detail(&self) {
        CLOUD_BACKUP_MANAGER.clone().spawn_refresh_detail();
    }
}

impl RustCloudBackupManager {
    fn spawn_verification(self: std::sync::Arc<Self>, force_discoverable: bool) {
        cove_tokio::task::spawn_blocking(move || {
            self.handle_start_verification(force_discoverable)
        });
    }

    fn spawn_recovery(self: std::sync::Arc<Self>, action: RecoveryAction) {
        cove_tokio::task::spawn_blocking(move || self.handle_recovery(action));
    }

    fn spawn_repair_passkey(self: std::sync::Arc<Self>, no_discovery: bool) {
        cove_tokio::task::spawn_blocking(move || self.handle_repair_passkey(no_discovery));
    }

    fn spawn_sync(self: std::sync::Arc<Self>) {
        cove_tokio::task::spawn_blocking(move || self.handle_sync());
    }

    fn spawn_fetch_cloud_only(self: std::sync::Arc<Self>) {
        cove_tokio::task::spawn_blocking(move || self.handle_fetch_cloud_only());
    }

    fn spawn_restore_cloud_wallet(self: std::sync::Arc<Self>, record_id: String) {
        cove_tokio::task::spawn_blocking(move || self.handle_restore_cloud_wallet(&record_id));
    }

    fn spawn_delete_cloud_wallet(self: std::sync::Arc<Self>, record_id: String) {
        cove_tokio::task::spawn_blocking(move || self.handle_delete_cloud_wallet(&record_id));
    }

    fn spawn_refresh_detail(self: std::sync::Arc<Self>) {
        cove_tokio::task::spawn_blocking(move || self.handle_refresh_detail());
    }

    fn handle_start_verification(&self, force_discoverable: bool) {
        self.update_state(|state| {
            state.verification = VerificationState::Verifying;
        });

        let result = self.deep_verify_cloud_backup(force_discoverable);

        match result {
            DeepVerificationResult::Verified(report) => {
                self.update_state(|state| {
                    if let Some(detail) = &report.detail {
                        state.detail = Some(detail.clone());
                    }
                    state.verification = VerificationState::Verified(report);
                    state.recovery = RecoveryState::Idle;
                });
            }
            DeepVerificationResult::PasskeyConfirmed(detail) => {
                self.update_state(|state| {
                    if let Some(detail) = detail {
                        state.detail = Some(detail);
                    }
                    state.verification = VerificationState::PasskeyConfirmed;
                });
            }
            DeepVerificationResult::PasskeyMissing(detail) => {
                self.update_state(|state| {
                    if let Some(detail) = detail {
                        state.detail = Some(detail);
                    }
                    state.verification = VerificationState::Idle;
                    state.recovery = RecoveryState::Idle;
                });
            }
            DeepVerificationResult::UserCancelled(detail) => {
                self.update_state(|state| {
                    if let Some(detail) = detail {
                        state.detail = Some(detail);
                    }
                    state.verification = VerificationState::Cancelled;
                });
            }
            DeepVerificationResult::NotEnabled => {}
            DeepVerificationResult::Failed(failure) => {
                self.update_state(|state| {
                    if let Some(detail) = failure.detail.clone() {
                        state.detail = Some(detail);
                    }
                    state.verification = VerificationState::Failed(failure);
                });
            }
        }
    }

    fn handle_recovery(&self, action: RecoveryAction) {
        self.update_state(|state| {
            state.recovery = RecoveryState::Recovering(action.clone());
        });

        let result = match &action {
            RecoveryAction::RecreateManifest => self.do_reupload_all_wallets(),
            RecoveryAction::ReinitializeBackup => self.do_enable_cloud_backup(),
            RecoveryAction::RepairPasskey => self.do_repair_passkey_wrapper(),
        };

        match result {
            Ok(()) => {
                self.update_state(|state| {
                    state.recovery = RecoveryState::Idle;
                });
                self.handle_start_verification(false);
            }
            Err(error) => {
                self.update_state(|state| {
                    state.recovery = RecoveryState::Failed { action, error: error.to_string() };
                });
            }
        }
    }

    fn handle_repair_passkey(&self, no_discovery: bool) {
        self.update_state(|state| {
            state.recovery = RecoveryState::Recovering(RecoveryAction::RepairPasskey);
        });

        let result = if no_discovery {
            self.do_repair_passkey_wrapper_no_discovery()
        } else {
            self.do_repair_passkey_wrapper()
        };

        match result {
            Ok(()) => {
                if let Err(error) = self.finalize_passkey_repair() {
                    self.update_state(|state| {
                        state.recovery = RecoveryState::Failed {
                            action: RecoveryAction::RepairPasskey,
                            error: error.to_string(),
                        };
                    });
                    return;
                }

                self.update_state(|state| {
                    state.recovery = RecoveryState::Idle;
                    state.verification = VerificationState::Idle;
                });
            }
            Err(CloudBackupError::PasskeyDiscoveryCancelled) => {
                self.update_state(|state| {
                    state.recovery = RecoveryState::Idle;
                });
                self.send(CloudBackupReconcileMessage::PasskeyDiscoveryCancelled);
            }
            Err(error) => {
                self.update_state(|state| {
                    state.recovery = RecoveryState::Failed {
                        action: RecoveryAction::RepairPasskey,
                        error: error.to_string(),
                    };
                });
            }
        }
    }

    fn handle_sync(&self) {
        self.update_state(|state| {
            state.sync = SyncState::Syncing;
        });

        match self.do_sync_unsynced_wallets() {
            Ok(()) => {
                self.handle_refresh_detail();
                self.update_state(|state| {
                    state.sync = SyncState::Idle;
                });
            }
            Err(error) => {
                self.update_state(|state| {
                    state.sync = SyncState::Failed(error.to_string());
                });
            }
        }
    }

    fn handle_fetch_cloud_only(&self) {
        self.update_state(|state| {
            state.cloud_only = CloudOnlyState::Loading;
        });

        match self.do_fetch_cloud_only_wallets() {
            Ok(items) => {
                self.update_state(|state| {
                    state.cloud_only = CloudOnlyState::Loaded { wallets: items };
                });
            }
            Err(error) => {
                error!("Failed to fetch cloud-only wallets: {error}");
                self.update_state(|state| {
                    state.cloud_only = CloudOnlyState::Loaded { wallets: Vec::new() };
                });
            }
        }
    }

    fn handle_restore_cloud_wallet(&self, record_id: &str) {
        self.update_state(|state| {
            state.cloud_only_operation =
                CloudOnlyOperation::Operating { record_id: record_id.to_string() };
        });

        match self.do_restore_cloud_wallet(record_id) {
            Ok(()) => {
                self.update_state(|state| {
                    state.cloud_only_operation = CloudOnlyOperation::Idle;

                    if let CloudOnlyState::Loaded { wallets } = &mut state.cloud_only {
                        wallets.retain(|wallet| wallet.record_id != record_id);
                    }
                });
                self.handle_refresh_detail();
            }
            Err(error) => {
                self.update_state(|state| {
                    state.cloud_only_operation =
                        CloudOnlyOperation::Failed { error: error.to_string() };
                });
            }
        }
    }

    fn handle_delete_cloud_wallet(&self, record_id: &str) {
        self.update_state(|state| {
            state.cloud_only_operation =
                CloudOnlyOperation::Operating { record_id: record_id.to_string() };
        });

        match self.do_delete_cloud_wallet(record_id) {
            Ok(()) => {
                self.update_state(|state| {
                    state.cloud_only_operation = CloudOnlyOperation::Idle;

                    if let CloudOnlyState::Loaded { wallets } = &mut state.cloud_only {
                        wallets.retain(|wallet| wallet.record_id != record_id);
                    }
                });
                self.handle_refresh_detail();
            }
            Err(error) => {
                self.update_state(|state| {
                    state.cloud_only_operation =
                        CloudOnlyOperation::Failed { error: error.to_string() };
                });
            }
        }
    }

    fn handle_refresh_detail(&self) {
        if let Some(result) = self.refresh_cloud_backup_detail() {
            match result {
                super::cloud_backup_manager::CloudBackupDetailResult::Success(detail) => {
                    self.update_state(|state| {
                        state.detail = Some(detail);
                    });
                }
                super::cloud_backup_manager::CloudBackupDetailResult::AccessError(error) => {
                    error!("Failed to refresh detail: {error}");
                }
            }
        }
    }
}
