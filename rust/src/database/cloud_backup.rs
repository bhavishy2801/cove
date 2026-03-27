use std::{collections::HashSet, sync::Arc};

use redb::TableDefinition;
use serde::{Deserialize, Serialize};

use cove_types::redb::Json;
use cove_util::result_ext::ResultExt as _;

use super::Error;

const CURRENT_KEY: &str = "current";

pub const CLOUD_BACKUP_STATE_TABLE: TableDefinition<&'static str, Json<PersistedCloudBackupState>> =
    TableDefinition::new("cloud_backup_state");
pub const CLOUD_UPLOAD_QUEUE_TABLE: TableDefinition<&'static str, Json<PendingCloudUploadQueue>> =
    TableDefinition::new("cloud_upload_queue");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistedCloudBackupStatus {
    Disabled,
    Enabled,
    Unverified,
    PasskeyMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedCloudBackupState {
    pub status: PersistedCloudBackupStatus,
    #[serde(default)]
    pub last_sync: Option<u64>,
    #[serde(default)]
    pub wallet_count: Option<u32>,
    #[serde(default)]
    pub last_verified_at: Option<u64>,
    #[serde(default)]
    pub last_verification_requested_at: Option<u64>,
    #[serde(default)]
    pub last_verification_dismissed_at: Option<u64>,
}

impl Default for PersistedCloudBackupState {
    fn default() -> Self {
        Self {
            status: PersistedCloudBackupStatus::Disabled,
            last_sync: None,
            wallet_count: None,
            last_verified_at: None,
            last_verification_requested_at: None,
            last_verification_dismissed_at: None,
        }
    }
}

impl PersistedCloudBackupState {
    pub fn is_configured(&self) -> bool {
        !matches!(self.status, PersistedCloudBackupStatus::Disabled)
    }

    pub fn is_unverified(&self) -> bool {
        matches!(self.status, PersistedCloudBackupStatus::Unverified)
    }

    pub fn is_passkey_missing(&self) -> bool {
        matches!(self.status, PersistedCloudBackupStatus::PasskeyMissing)
    }

    pub fn should_prompt_verification(&self) -> bool {
        if !self.is_unverified() {
            return false;
        }

        let Some(requested_at) = self.last_verification_requested_at else {
            return false;
        };

        if self.last_verified_at.is_some_and(|verified_at| verified_at >= requested_at) {
            return false;
        }

        if self
            .last_verification_dismissed_at
            .is_some_and(|dismissed_at| dismissed_at >= requested_at)
        {
            return false;
        }

        true
    }

    pub fn with_wallet_count(&self, wallet_count: Option<u32>) -> Self {
        Self { wallet_count, ..self.clone() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudUploadKind {
    BackupBlob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCloudUploadItem {
    pub kind: CloudUploadKind,
    pub namespace_id: String,
    pub record_id: String,
    pub enqueued_at: u64,
    pub last_checked_at: Option<u64>,
    pub attempt_count: u32,
    /// Set when isBackupUploaded confirms the blob, kept until the listing catches up
    #[serde(default)]
    pub confirmed_at: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCloudUploadQueue {
    pub items: Vec<PendingCloudUploadItem>,
}

impl PendingCloudUploadQueue {
    pub fn has_unconfirmed(&self) -> bool {
        self.items.iter().any(|item| item.confirmed_at.is_none())
    }

    pub fn cleanup_listed(
        &mut self,
        kind: CloudUploadKind,
        namespace_id: &str,
        listed_ids: &HashSet<String>,
    ) {
        self.items.retain(|item| {
            if item.kind != kind || item.namespace_id != namespace_id {
                return true;
            }

            item.confirmed_at.is_none() || !listed_ids.contains(&item.record_id)
        });
    }
}

#[derive(Debug, Clone)]
pub struct CloudBackupStateTable {
    db: Arc<redb::Database>,
}

impl CloudBackupStateTable {
    pub fn new(db: Arc<redb::Database>, write_txn: &redb::WriteTransaction) -> Self {
        write_txn
            .open_table(CLOUD_BACKUP_STATE_TABLE)
            .expect("failed to create cloud backup state table");

        Self { db }
    }

    pub fn get(&self) -> Result<PersistedCloudBackupState, Error> {
        let read_txn = self.db.begin_read().map_err_str(Error::DatabaseAccess)?;
        let table =
            read_txn.open_table(CLOUD_BACKUP_STATE_TABLE).map_err_str(Error::TableAccess)?;

        Ok(table
            .get(CURRENT_KEY)
            .map_err_str(Error::TableAccess)?
            .map(|value| value.value())
            .unwrap_or_default())
    }

    pub fn set(&self, value: &PersistedCloudBackupState) -> Result<(), Error> {
        let write_txn = self.db.begin_write().map_err_str(Error::DatabaseAccess)?;

        {
            let mut table =
                write_txn.open_table(CLOUD_BACKUP_STATE_TABLE).map_err_str(Error::TableAccess)?;
            table.insert(CURRENT_KEY, value).map_err_str(Error::TableAccess)?;
        }

        write_txn.commit().map_err_str(Error::DatabaseAccess)?;

        Ok(())
    }

    pub fn delete(&self) -> Result<(), Error> {
        let write_txn = self.db.begin_write().map_err_str(Error::DatabaseAccess)?;

        {
            let mut table =
                write_txn.open_table(CLOUD_BACKUP_STATE_TABLE).map_err_str(Error::TableAccess)?;
            table.remove(CURRENT_KEY).map_err_str(Error::TableAccess)?;
        }

        write_txn.commit().map_err_str(Error::DatabaseAccess)?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CloudUploadQueueTable {
    db: Arc<redb::Database>,
}

impl CloudUploadQueueTable {
    pub fn new(db: Arc<redb::Database>, write_txn: &redb::WriteTransaction) -> Self {
        write_txn
            .open_table(CLOUD_UPLOAD_QUEUE_TABLE)
            .expect("failed to create cloud upload queue table");

        Self { db }
    }

    pub fn get(&self) -> Result<Option<PendingCloudUploadQueue>, Error> {
        let read_txn = self.db.begin_read().map_err_str(Error::DatabaseAccess)?;
        let table =
            read_txn.open_table(CLOUD_UPLOAD_QUEUE_TABLE).map_err_str(Error::TableAccess)?;

        Ok(table.get(CURRENT_KEY).map_err_str(Error::TableAccess)?.map(|value| value.value()))
    }

    pub fn set(&self, value: &PendingCloudUploadQueue) -> Result<(), Error> {
        let write_txn = self.db.begin_write().map_err_str(Error::DatabaseAccess)?;

        {
            let mut table =
                write_txn.open_table(CLOUD_UPLOAD_QUEUE_TABLE).map_err_str(Error::TableAccess)?;
            table.insert(CURRENT_KEY, value).map_err_str(Error::TableAccess)?;
        }

        write_txn.commit().map_err_str(Error::DatabaseAccess)?;

        Ok(())
    }

    pub fn delete(&self) -> Result<(), Error> {
        let write_txn = self.db.begin_write().map_err_str(Error::DatabaseAccess)?;

        {
            let mut table =
                write_txn.open_table(CLOUD_UPLOAD_QUEUE_TABLE).map_err_str(Error::TableAccess)?;
            table.remove(CURRENT_KEY).map_err_str(Error::TableAccess)?;
        }

        write_txn.commit().map_err_str(Error::DatabaseAccess)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_prompt_requires_newer_request() {
        let state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Unverified,
            last_verification_requested_at: Some(20),
            last_verification_dismissed_at: Some(10),
            ..PersistedCloudBackupState::default()
        };

        assert!(state.should_prompt_verification());
    }

    #[test]
    fn verification_prompt_respects_dismissal() {
        let state = PersistedCloudBackupState {
            status: PersistedCloudBackupStatus::Unverified,
            last_verification_requested_at: Some(20),
            last_verification_dismissed_at: Some(20),
            ..PersistedCloudBackupState::default()
        };

        assert!(!state.should_prompt_verification());
    }

    #[test]
    fn cleanup_listed_only_removes_confirmed_matching_items() {
        let mut queue = PendingCloudUploadQueue {
            items: vec![
                PendingCloudUploadItem {
                    kind: CloudUploadKind::BackupBlob,
                    namespace_id: "ns-1".into(),
                    record_id: "wallet-a".into(),
                    enqueued_at: 10,
                    last_checked_at: None,
                    attempt_count: 0,
                    confirmed_at: Some(12),
                },
                PendingCloudUploadItem {
                    kind: CloudUploadKind::BackupBlob,
                    namespace_id: "ns-1".into(),
                    record_id: "wallet-b".into(),
                    enqueued_at: 11,
                    last_checked_at: None,
                    attempt_count: 0,
                    confirmed_at: None,
                },
            ],
        };

        queue.cleanup_listed(
            CloudUploadKind::BackupBlob,
            "ns-1",
            &HashSet::from([String::from("wallet-a")]),
        );

        assert_eq!(queue.items.len(), 1);
        assert_eq!(queue.items[0].record_id, "wallet-b");
    }
}
