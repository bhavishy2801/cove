mod detail;
mod queue_processor;

use std::sync::atomic::Ordering;
use std::time::Duration;

use backon::{BackoffBuilder as _, FibonacciBackoff, FibonacciBuilder};
use cove_util::ResultExt as _;
use tracing::{error, info};

use self::queue_processor::PendingUploadVerifier;
use super::{CLOUD_BACKUP_MANAGER, CloudBackupError, RustCloudBackupManager};
use crate::database::Database;
use crate::database::cloud_backup::{
    CloudBlobFailedState, CloudBlobUploadedPendingConfirmationState, CloudUploadKind,
    PersistedCloudBlobState, PersistedCloudBlobSyncState,
};
use crate::wallet::metadata::WalletId;

pub(crate) use detail::remote_wallet_revision_matches;

const MAX_PENDING_UPLOAD_VERIFICATION_DELAY: Duration = Duration::from_secs(10);

struct PendingUploadRetryBackoff(FibonacciBackoff);

impl PendingUploadRetryBackoff {
    fn new() -> Self {
        Self(build_pending_upload_backoff())
    }

    fn next_delay(&mut self) -> Duration {
        self.0
            .next()
            .map(|delay| delay.min(MAX_PENDING_UPLOAD_VERIFICATION_DELAY))
            .unwrap_or(MAX_PENDING_UPLOAD_VERIFICATION_DELAY)
    }

    fn reset(&mut self) {
        self.0 = build_pending_upload_backoff();
    }
}

fn build_pending_upload_backoff() -> FibonacciBackoff {
    FibonacciBuilder::default()
        .with_max_delay(MAX_PENDING_UPLOAD_VERIFICATION_DELAY)
        .without_max_times()
        .build()
}

impl RustCloudBackupManager {
    pub(crate) fn replace_blob_state_if_current(
        &self,
        current_state: &PersistedCloudBlobSyncState,
        next_state: PersistedCloudBlobState,
        error_context: &'static str,
    ) -> Result<bool, CloudBackupError> {
        let next_sync_state =
            PersistedCloudBlobSyncState { state: next_state, ..current_state.clone() };

        Database::global()
            .cloud_blob_sync_states
            .set_if_current(current_state, &next_sync_state)
            .map_err_prefix(error_context, CloudBackupError::Internal)
    }

    pub(crate) fn mark_blob_uploaded_pending_confirmation(
        &self,
        namespace_id: &str,
        wallet_id: Option<WalletId>,
        record_id: String,
        revision_hash: String,
        uploaded_at: u64,
    ) -> Result<(), CloudBackupError> {
        let sync_state = PersistedCloudBlobSyncState {
            kind: CloudUploadKind::BackupBlob,
            namespace_id: namespace_id.to_string(),
            wallet_id,
            record_id,
            state: PersistedCloudBlobState::UploadedPendingConfirmation(
                CloudBlobUploadedPendingConfirmationState {
                    revision_hash,
                    uploaded_at,
                    attempt_count: 0,
                    last_checked_at: None,
                },
            ),
        };

        Database::global()
            .cloud_blob_sync_states
            .set(&sync_state)
            .map_err_prefix("persist uploaded cloud blob state", CloudBackupError::Internal)?;

        self.set_pending_upload_verification(true);
        self.wake_pending_upload_verifier();
        self.start_pending_upload_verification_loop();

        Ok(())
    }

    pub(crate) fn mark_blob_uploaded_pending_confirmation_if_current(
        &self,
        current_state: &PersistedCloudBlobSyncState,
        revision_hash: String,
        uploaded_at: u64,
    ) -> Result<bool, CloudBackupError> {
        let updated = self.replace_blob_state_if_current(
            current_state,
            PersistedCloudBlobState::UploadedPendingConfirmation(
                CloudBlobUploadedPendingConfirmationState {
                    revision_hash,
                    uploaded_at,
                    attempt_count: 0,
                    last_checked_at: None,
                },
            ),
            "persist uploaded cloud blob state",
        )?;

        if !updated {
            return Ok(false);
        }

        self.set_pending_upload_verification(true);
        self.wake_pending_upload_verifier();
        self.start_pending_upload_verification_loop();

        Ok(true)
    }

    pub(crate) fn mark_blob_failed_if_current(
        &self,
        current_state: &PersistedCloudBlobSyncState,
        revision_hash: Option<String>,
        retryable: bool,
        error: String,
    ) -> Result<bool, CloudBackupError> {
        let failed_at = jiff::Timestamp::now().as_second().try_into().unwrap_or(0);

        self.replace_blob_state_if_current(
            current_state,
            PersistedCloudBlobState::Failed(CloudBlobFailedState {
                revision_hash,
                retryable,
                error,
                failed_at,
            }),
            "persist failed cloud blob state",
        )
    }

    pub(super) fn remove_blob_sync_states<I>(&self, record_ids: I) -> Result<(), CloudBackupError>
    where
        I: IntoIterator<Item = String>,
    {
        let table = &Database::global().cloud_blob_sync_states;

        for record_id in record_ids {
            table
                .delete(&record_id)
                .map_err_prefix("remove cloud blob sync state", CloudBackupError::Internal)?;
        }

        self.set_pending_upload_verification(self.has_pending_cloud_upload_verification());
        self.wake_pending_upload_verifier();

        Ok(())
    }

    pub(super) fn start_pending_upload_verification_loop(&self) {
        if self
            .pending_upload_verifier_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let this = CLOUD_BACKUP_MANAGER.clone();
        let wakeup = this.pending_upload_verifier_wakeup.clone();
        cove_tokio::task::spawn(async move {
            info!("Pending upload verification: started");
            let mut backoff = PendingUploadRetryBackoff::new();

            loop {
                let this_for_pass = this.clone();
                let has_pending = cove_tokio::task::spawn_blocking(move || {
                    this_for_pass.verify_pending_uploads_once()
                })
                .await
                .unwrap_or_else(|error| {
                    error!("Pending upload verification task failed: {error}");
                    true
                });

                if !has_pending {
                    break;
                }

                let delay = backoff.next_delay();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = wakeup.notified() => {
                        backoff.reset();
                    }
                }
            }

            this.pending_upload_verifier_running.store(false, Ordering::SeqCst);

            if this.has_pending_cloud_upload_verification() {
                this.start_pending_upload_verification_loop();
                return;
            }

            info!("Pending upload verification: idle");
        });
    }

    fn verify_pending_uploads_once(&self) -> bool {
        PendingUploadVerifier(self.clone()).run_once()
    }

    #[cfg(test)]
    pub(super) fn verify_pending_uploads_once_for_test(&self) -> bool {
        self.verify_pending_uploads_once()
    }

    fn wake_pending_upload_verifier(&self) {
        if self.pending_upload_verifier_running.load(Ordering::SeqCst) {
            self.pending_upload_verifier_wakeup.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_upload_retry_backoff_resets_to_short_delay() {
        let mut backoff = PendingUploadRetryBackoff::new();
        let initial_delay = backoff.next_delay();

        let _ = backoff.next_delay();
        let _ = backoff.next_delay();

        backoff.reset();

        assert_eq!(backoff.next_delay(), initial_delay);
    }

    #[test]
    fn pending_upload_retry_backoff_caps_at_max_delay() {
        let mut backoff = PendingUploadRetryBackoff::new();

        for _ in 0..10 {
            assert!(backoff.next_delay() <= MAX_PENDING_UPLOAD_VERIFICATION_DELAY);
        }
    }
}
