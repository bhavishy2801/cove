use cove_device::passkey::PasskeyError;
use rand::RngExt as _;
use tracing::info;

use super::session::VerificationSession;
use super::{CloudBackupError, RP_ID, load_stored_credential_id};

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

impl VerificationSession<'_> {
    pub(super) fn authenticate_with_fallback(
        &self,
        prf_salt: &[u8; 32],
    ) -> Result<PasskeyAuthOutcome, CloudBackupError> {
        if !self.force_discoverable
            && let Some(ref credential_id) = load_stored_credential_id(&self.keychain)
        {
            let challenge: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
            match self.passkey.authenticate_with_prf(
                RP_ID.to_string(),
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
                    info!("Stored credential auth failed ({error}), trying discovery");
                }
            }
        }

        let challenge: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
        let discovered = match self.passkey.discover_and_authenticate_with_prf(
            RP_ID.to_string(),
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
