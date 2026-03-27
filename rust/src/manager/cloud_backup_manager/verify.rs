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
use super::wallets::{count_all_wallets, persist_enabled_cloud_backup_state};
use super::{
    CloudBackupDetailResult, CloudBackupError, CloudBackupStatus, DeepVerificationFailure,
    DeepVerificationResult, RustCloudBackupManager, VerificationFailureKind,
};
use crate::database::Database;
use crate::database::cloud_backup::{PersistedCloudBackupState, PersistedCloudBackupStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrityDowngrade {
    Unverified,
}

impl RustCloudBackupManager {
    /// Background startup health check for cloud backup integrity
    ///
    /// Verifies the master key is in the keychain and backup files exist in iCloud.
    /// Returns None if everything is OK, Some(warning) if there's a problem
    pub(super) fn verify_backup_integrity_impl(&self) -> Option<String> {
        let state = self.state.read().status.clone();
        if !matches!(state, CloudBackupStatus::Enabled | CloudBackupStatus::PasskeyMissing) {
            return None;
        }

        let mut issues: Vec<&str> = Vec::new();

        let keychain = Keychain::global();
        let cspp = cove_cspp::Cspp::new(keychain.clone());
        if !cspp.has_master_key() {
            issues.push("master key not found in keychain");
        }

        let mut downgrade = None;
        let has_prf_salt = keychain.get(CSPP_PRF_SALT_KEY.into()).is_some();
        let stored_credential_id = load_stored_credential_id(keychain);

        // keep launch integrity checks non-interactive so app startup never presents passkey UI
        if stored_credential_id.is_none() {
            issues
                .push("passkey credential not found — open Cloud Backup in Settings to re-verify");
            downgrade = Some(IntegrityDowngrade::Unverified);
        }
        if !has_prf_salt {
            issues.push("passkey salt not found — open Cloud Backup in Settings to re-verify");
            downgrade = Some(IntegrityDowngrade::Unverified);
        }

        let namespace = match self.current_namespace_id() {
            Ok(ns) => ns,
            Err(_) => {
                issues.push("namespace_id not found in keychain");
                self.persist_integrity_downgrade(downgrade);
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
            self.persist_integrity_downgrade(downgrade);
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
        let state = self.state.read().status.clone();
        if !matches!(state, CloudBackupStatus::Enabled | CloudBackupStatus::PasskeyMissing) {
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
        let current = RustCloudBackupManager::load_persisted_state();
        if matches!(current.status, PersistedCloudBackupStatus::Disabled) {
            return;
        }

        let mut new_state = current.clone();
        match result {
            DeepVerificationResult::Verified(_) => {
                new_state.status = PersistedCloudBackupStatus::Enabled;
                new_state.last_verified_at =
                    Some(jiff::Timestamp::now().as_second().try_into().unwrap_or(0));
            }
            DeepVerificationResult::PasskeyConfirmed(_) => return,
            DeepVerificationResult::PasskeyMissing(_) => {
                new_state.status = PersistedCloudBackupStatus::PasskeyMissing;
            }
            DeepVerificationResult::UserCancelled(_) | DeepVerificationResult::Failed(_) => {
                new_state.status = PersistedCloudBackupStatus::Unverified;
            }
            DeepVerificationResult::NotEnabled => return,
        };

        if current != new_state
            && let Err(error) =
                self.persist_cloud_backup_state(&new_state, "persist verification state")
        {
            error!("Failed to persist verification state: {error}");
        }
    }

    pub(crate) fn mark_verification_required_after_wallet_change(&self) {
        let current = RustCloudBackupManager::load_persisted_state();

        match current.status {
            PersistedCloudBackupStatus::Enabled | PersistedCloudBackupStatus::Unverified => {
                let Some(mut new_state) =
                    downgrade_cloud_backup_state(&current, IntegrityDowngrade::Unverified)
                else {
                    return;
                };

                new_state.last_verification_requested_at =
                    Some(jiff::Timestamp::now().as_second().try_into().unwrap_or(0));

                if let Err(error) = self.persist_cloud_backup_state(
                    &new_state,
                    "mark cloud backup unverified after wallet change",
                ) {
                    error!("Failed to mark cloud backup unverified after wallet change: {error}");
                }
            }
            PersistedCloudBackupStatus::PasskeyMissing | PersistedCloudBackupStatus::Disabled => {}
        }
    }

    pub(crate) fn do_repair_passkey_wrapper(&self) -> Result<(), CloudBackupError> {
        self.do_repair_passkey_wrapper_with_strategy(WrapperRepairStrategy::DiscoverOrCreate)
    }

    pub(crate) fn do_repair_passkey_wrapper_no_discovery(&self) -> Result<(), CloudBackupError> {
        self.do_repair_passkey_wrapper_with_strategy(WrapperRepairStrategy::CreateNew)
    }

    fn do_repair_passkey_wrapper_with_strategy(
        &self,
        strategy: WrapperRepairStrategy,
    ) -> Result<(), CloudBackupError> {
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
            .run(&local_master_key, &wallet_record_ids, strategy)
            .map_err(|error| error.into_cloud_backup_error())?;

        info!("Repaired cloud master key wrapper with repaired passkey association");
        Ok(())
    }

    pub(crate) fn finalize_passkey_repair(&self) -> Result<(), CloudBackupError> {
        let namespace = self.current_namespace_id()?;
        let cloud = CloudStorage::global();
        let wallet_record_ids =
            cloud.list_wallet_backups(namespace).map_err_str(CloudBackupError::Cloud)?;

        persist_enabled_cloud_backup_state(&Database::global(), wallet_record_ids.len() as u32)?;
        self.send(super::CloudBackupReconcileMessage::StatusChanged(CloudBackupStatus::Enabled));

        match self.refresh_cloud_backup_detail() {
            Some(CloudBackupDetailResult::Success(detail)) => {
                self.update_state(|state| {
                    state.detail = Some(detail);
                });
            }
            Some(CloudBackupDetailResult::AccessError(error)) => {
                warn!("Failed to refresh detail after passkey repair: {error}");
            }
            None => {}
        }

        Ok(())
    }

    pub(crate) fn do_deep_verify_cloud_backup(
        &self,
        force_discoverable: bool,
    ) -> Result<DeepVerificationResult, CloudBackupError> {
        VerificationSession::new(self, force_discoverable)?.run()
    }
}

impl RustCloudBackupManager {
    fn persist_integrity_downgrade(&self, downgrade: Option<IntegrityDowngrade>) {
        let Some(downgrade) = downgrade else {
            return;
        };

        info!("Cloud backup integrity: applying downgrade={downgrade:?}");

        let current = RustCloudBackupManager::load_persisted_state();
        let Some(new_state) = downgrade_cloud_backup_state(&current, downgrade) else {
            return;
        };

        if let Err(error) =
            self.persist_cloud_backup_state(&new_state, "persist backup integrity state")
        {
            error!("Failed to persist backup integrity state: {error}");
        };
    }
}

pub(super) fn load_stored_credential_id(keychain: &Keychain) -> Option<Vec<u8>> {
    keychain.get(CSPP_CREDENTIAL_ID_KEY.into()).and_then(|hex_str| {
        hex::decode(hex_str)
            .inspect_err(|error| warn!("Failed to decode stored credential_id: {error}"))
            .ok()
    })
}

fn downgrade_cloud_backup_state(
    current: &PersistedCloudBackupState,
    downgrade: IntegrityDowngrade,
) -> Option<PersistedCloudBackupState> {
    match downgrade {
        IntegrityDowngrade::Unverified => match current.status {
            PersistedCloudBackupStatus::Enabled => Some(PersistedCloudBackupState {
                status: PersistedCloudBackupStatus::Unverified,
                ..current.clone()
            }),
            PersistedCloudBackupStatus::Unverified => Some(current.clone()),
            PersistedCloudBackupStatus::PasskeyMissing | PersistedCloudBackupStatus::Disabled => {
                None
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downgrade_state_marks_enabled_as_unverified() {
        let current = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Enabled,
            last_sync: Some(5),
            wallet_count: Some(2),
            last_verified_at: Some(21),
            ..PersistedCloudBackupState::default()
        };

        let updated =
            downgrade_cloud_backup_state(&current, IntegrityDowngrade::Unverified).unwrap();

        assert_eq!(
            updated,
            PersistedCloudBackupState {
                status: PersistedCloudBackupStatus::Unverified,
                last_sync: Some(5),
                wallet_count: Some(2),
                last_verified_at: Some(21),
                ..PersistedCloudBackupState::default()
            }
        );
    }

    #[test]
    fn downgrade_state_keeps_passkey_missing_when_only_unverified_requested() {
        let current = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::PasskeyMissing,
            last_sync: Some(11),
            wallet_count: Some(4),
            last_verified_at: Some(22),
            ..PersistedCloudBackupState::default()
        };

        let updated = downgrade_cloud_backup_state(&current, IntegrityDowngrade::Unverified);

        assert!(updated.is_none());
    }
}
