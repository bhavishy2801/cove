use cove_cspp::master_key::MasterKey;
use cove_cspp::master_key_crypto;
use cove_cspp::wallet_crypto;
use cove_device::cloud_storage::CloudStorage;
use cove_device::keychain::Keychain;
use cove_device::passkey::PasskeyAccess;
use cove_util::ResultExt as _;
use rand::RngExt as _;
use tracing::info;
use zeroize::Zeroizing;

use super::super::{CloudBackupError, RP_ID, RustCloudBackupManager, cspp_master_key_record_id};
use crate::manager::cloud_backup_manager::wallets::{
    create_prf_key_without_persisting, discover_or_create_prf_key_without_persisting,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalKeyProof {
    Verified,
    WrongKey,
    Inconclusive,
}

#[derive(Debug)]
pub(super) enum WrapperRepairError {
    WrongKey,
    Inconclusive,
    Operation(CloudBackupError),
}

impl WrapperRepairError {
    pub(super) fn into_cloud_backup_error(self) -> CloudBackupError {
        match self {
            Self::WrongKey => CloudBackupError::Crypto(
                "local master key cannot decrypt existing cloud wallet backups".into(),
            ),
            Self::Inconclusive => {
                CloudBackupError::Cloud("could not download any wallet to verify local key".into())
            }
            Self::Operation(error) => error,
        }
    }
}

#[derive(Debug)]
pub(super) enum WrapperRepairStrategy {
    CreateNew,
    DiscoverOrCreate,
    ReuseExisting(Vec<u8>),
}

#[derive(Debug)]
struct WrapperRepairCredentials {
    prf_key: [u8; 32],
    prf_salt: [u8; 32],
    credential_id: Vec<u8>,
}

struct LocalKeyVerifier<'a> {
    cloud: &'a CloudStorage,
    namespace: &'a str,
}

impl<'a> LocalKeyVerifier<'a> {
    fn new(cloud: &'a CloudStorage, namespace: &'a str) -> Self {
        Self { cloud, namespace }
    }

    fn prove(&self, wallet_record_ids: &[String], master_key: &MasterKey) -> LocalKeyProof {
        let critical_key = Zeroizing::new(master_key.critical_data_key());
        let mut had_wrong_key = false;
        let mut verified = false;

        for record_id in wallet_record_ids {
            let wallet_json = match self
                .cloud
                .download_wallet_backup(self.namespace.to_owned(), record_id.clone())
            {
                Ok(json) => json,
                Err(_) => continue,
            };

            let encrypted: cove_cspp::backup_data::EncryptedWalletBackup =
                match serde_json::from_slice(&wallet_json) {
                    Ok(encrypted) => encrypted,
                    Err(_) => continue,
                };

            if encrypted.version != 1 {
                continue;
            }

            match wallet_crypto::decrypt_wallet_backup(&encrypted, &critical_key) {
                Ok(_) => {
                    verified = true;
                    break;
                }
                Err(cove_cspp::CsppError::WrongKey) => {
                    had_wrong_key = true;
                }
                Err(_) => {}
            }
        }

        if verified {
            LocalKeyProof::Verified
        } else if had_wrong_key {
            LocalKeyProof::WrongKey
        } else {
            LocalKeyProof::Inconclusive
        }
    }
}

pub(super) struct WrapperRepairOperation<'a> {
    manager: &'a RustCloudBackupManager,
    keychain: &'a Keychain,
    cloud: &'a CloudStorage,
    passkey: &'a PasskeyAccess,
    namespace: &'a str,
}

impl<'a> WrapperRepairOperation<'a> {
    pub(super) fn new(
        manager: &'a RustCloudBackupManager,
        keychain: &'a Keychain,
        cloud: &'a CloudStorage,
        passkey: &'a PasskeyAccess,
        namespace: &'a str,
    ) -> Self {
        Self { manager, keychain, cloud, passkey, namespace }
    }

    pub(super) fn run(
        &self,
        local_master_key: &MasterKey,
        wallet_record_ids: &[String],
        strategy: WrapperRepairStrategy,
    ) -> Result<(), WrapperRepairError> {
        self.verify_local_key(wallet_record_ids, local_master_key)?;

        let credentials = self.credentials(strategy).map_err(WrapperRepairError::Operation)?;
        let encrypted_backup = master_key_crypto::encrypt_master_key(
            local_master_key,
            &credentials.prf_key,
            &credentials.prf_salt,
        )
        .map_err_str(CloudBackupError::Crypto)
        .map_err(WrapperRepairError::Operation)?;

        let backup_json = serde_json::to_vec(&encrypted_backup)
            .map_err_str(CloudBackupError::Internal)
            .map_err(WrapperRepairError::Operation)?;

        self.cloud
            .upload_master_key_backup(self.namespace.to_owned(), backup_json)
            .map_err_str(CloudBackupError::Cloud)
            .map_err(WrapperRepairError::Operation)?;

        self.keychain
            .save_cspp_passkey(&credentials.credential_id, credentials.prf_salt)
            .map_err_prefix("save cspp credentials", CloudBackupError::Internal)
            .map_err(WrapperRepairError::Operation)?;
        self.manager
            .enqueue_pending_uploads(self.namespace, std::iter::once(cspp_master_key_record_id()))
            .map_err(WrapperRepairError::Operation)?;

        Ok(())
    }

    fn verify_local_key(
        &self,
        wallet_record_ids: &[String],
        local_master_key: &MasterKey,
    ) -> Result<(), WrapperRepairError> {
        if wallet_record_ids.is_empty() {
            return Ok(());
        }

        let verifier = LocalKeyVerifier::new(self.cloud, self.namespace);
        match verifier.prove(wallet_record_ids, local_master_key) {
            LocalKeyProof::Verified => Ok(()),
            LocalKeyProof::WrongKey => Err(WrapperRepairError::WrongKey),
            LocalKeyProof::Inconclusive => Err(WrapperRepairError::Inconclusive),
        }
    }

    fn credentials(
        &self,
        strategy: WrapperRepairStrategy,
    ) -> Result<WrapperRepairCredentials, CloudBackupError> {
        match strategy {
            WrapperRepairStrategy::CreateNew => {
                let new_prf = create_prf_key_without_persisting(self.passkey)?;
                info!("Creating new passkey for wrapper repair");

                Ok(WrapperRepairCredentials {
                    prf_key: new_prf.prf_key,
                    prf_salt: new_prf.prf_salt,
                    credential_id: new_prf.credential_id,
                })
            }
            WrapperRepairStrategy::DiscoverOrCreate => {
                let passkey = discover_or_create_prf_key_without_persisting(self.passkey)?;
                info!("Using discovered-or-new passkey for wrapper repair");

                Ok(WrapperRepairCredentials {
                    prf_key: passkey.prf_key,
                    prf_salt: passkey.prf_salt,
                    credential_id: passkey.credential_id,
                })
            }
            WrapperRepairStrategy::ReuseExisting(credential_id) => {
                let prf_salt: [u8; 32] = rand::rng().random();
                let challenge: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
                let prf_output = self
                    .passkey
                    .authenticate_with_prf(
                        RP_ID.to_owned(),
                        credential_id.clone(),
                        prf_salt.to_vec(),
                        challenge,
                    )
                    .map_err_str(CloudBackupError::Passkey)?;

                let prf_key: [u8; 32] = prf_output
                    .try_into()
                    .map_err(|_| CloudBackupError::Internal("PRF output is not 32 bytes".into()))?;

                info!("Reusing discovered passkey for wrapper repair");

                Ok(WrapperRepairCredentials { prf_key, prf_salt, credential_id })
            }
        }
    }
}
