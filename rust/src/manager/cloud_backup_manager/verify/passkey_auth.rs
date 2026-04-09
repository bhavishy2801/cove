use cove_device::keychain::Keychain;
use cove_device::passkey::{PasskeyAccess, PasskeyError};
use rand::RngExt as _;
use tracing::info;

use super::super::{CloudBackupError, PASSKEY_RP_ID};
use super::load_stored_credential_id;
use super::session::VerificationSession;

#[derive(Debug, PartialEq)]
pub(super) struct AuthenticatedPasskey {
    pub(super) prf_key: [u8; 32],
    pub(super) credential_id: Vec<u8>,
    pub(super) credential_recovered: bool,
}

#[derive(Debug, PartialEq)]
pub(super) enum PasskeyAuthOutcome {
    Authenticated(AuthenticatedPasskey),
    UserCancelled,
    NoCredentialFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PasskeyAuthPolicy {
    StoredOnly,
    StoredThenDiscover,
    DiscoverOnly,
}

pub(super) fn authenticate_with_policy(
    keychain: &Keychain,
    passkey: &PasskeyAccess,
    prf_salt: &[u8; 32],
    policy: PasskeyAuthPolicy,
) -> Result<PasskeyAuthOutcome, CloudBackupError> {
    if matches!(policy, PasskeyAuthPolicy::StoredOnly | PasskeyAuthPolicy::StoredThenDiscover) {
        if let Some(ref credential_id) = load_stored_credential_id(keychain) {
            let challenge: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
            match passkey.authenticate_with_prf(
                PASSKEY_RP_ID.to_string(),
                credential_id.clone(),
                prf_salt.to_vec(),
                challenge,
            ) {
                Ok(prf_output) => {
                    let prf_key: [u8; 32] = prf_output.try_into().map_err(|_| {
                        CloudBackupError::Internal("PRF output is not 32 bytes".into())
                    })?;

                    return Ok(PasskeyAuthOutcome::Authenticated(AuthenticatedPasskey {
                        prf_key,
                        credential_id: credential_id.clone(),
                        credential_recovered: false,
                    }));
                }
                Err(PasskeyError::UserCancelled) => {
                    return Ok(PasskeyAuthOutcome::UserCancelled);
                }
                Err(error) => {
                    info!("Stored credential auth failed ({error})");
                    if matches!(policy, PasskeyAuthPolicy::StoredOnly) {
                        return Ok(PasskeyAuthOutcome::NoCredentialFound);
                    }

                    info!("Trying discovery after stored credential auth failed");
                }
            }
        } else if matches!(policy, PasskeyAuthPolicy::StoredOnly) {
            return Ok(PasskeyAuthOutcome::NoCredentialFound);
        }
    }

    if matches!(policy, PasskeyAuthPolicy::StoredOnly) {
        return Ok(PasskeyAuthOutcome::NoCredentialFound);
    }

    let challenge: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
    let discovered = match passkey.discover_and_authenticate_with_prf(
        PASSKEY_RP_ID.to_string(),
        prf_salt.to_vec(),
        challenge,
    ) {
        Ok(discovered) => discovered,
        Err(error) => return map_discovery_error(error),
    };

    let prf_key: [u8; 32] = discovered
        .prf_output
        .try_into()
        .map_err(|_| CloudBackupError::Internal("PRF output is not 32 bytes".into()))?;

    Ok(PasskeyAuthOutcome::Authenticated(AuthenticatedPasskey {
        prf_key,
        credential_id: discovered.credential_id,
        credential_recovered: true,
    }))
}

impl VerificationSession {
    pub(super) fn authenticate_with_fallback(
        &self,
        prf_salt: &[u8; 32],
    ) -> Result<PasskeyAuthOutcome, CloudBackupError> {
        let policy = if self.force_discoverable {
            PasskeyAuthPolicy::DiscoverOnly
        } else {
            PasskeyAuthPolicy::StoredThenDiscover
        };

        authenticate_with_policy(&self.keychain, &self.passkey, prf_salt, policy)
    }
}

fn map_discovery_error(error: PasskeyError) -> Result<PasskeyAuthOutcome, CloudBackupError> {
    match error {
        PasskeyError::UserCancelled => Ok(PasskeyAuthOutcome::UserCancelled),
        PasskeyError::NoCredentialFound => Ok(PasskeyAuthOutcome::NoCredentialFound),
        other => Err(CloudBackupError::Passkey(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_discovery_error_returns_user_cancelled() {
        let outcome = map_discovery_error(PasskeyError::UserCancelled).unwrap();
        assert_eq!(outcome, PasskeyAuthOutcome::UserCancelled);
    }

    #[test]
    fn map_discovery_error_returns_no_credential_found() {
        let outcome = map_discovery_error(PasskeyError::NoCredentialFound).unwrap();
        assert_eq!(outcome, PasskeyAuthOutcome::NoCredentialFound);
    }

    #[test]
    fn map_discovery_error_preserves_unexpected_errors() {
        let error =
            map_discovery_error(PasskeyError::AuthenticationFailed("boom".into())).unwrap_err();
        assert!(
            matches!(error, CloudBackupError::Passkey(message) if message == "authentication failed: boom")
        );
    }
}
