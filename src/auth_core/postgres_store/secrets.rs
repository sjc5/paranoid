use super::*;

pub(in crate::auth_core) const AUTH_CREDENTIAL_SECRET_BYTES: usize = 32;
pub(in crate::auth_core) const SESSION_SECRET_MAC_CONTEXT_PREFIX: &[u8] =
    b"paranoid/auth/v1/session-secret";
pub(in crate::auth_core) const TRUSTED_DEVICE_SECRET_MAC_CONTEXT_PREFIX: &[u8] =
    b"paranoid/auth/v1/trusted-device-secret";
pub(in crate::auth_core) const ACTIVE_PROOF_CONTINUATION_SECRET_MAC_CONTEXT_PREFIX: &[u8] =
    b"paranoid/auth/v1/active-proof-continuation-secret";
pub(in crate::auth_core) struct PresentedSecretClassificationInput<'a> {
    pub(in crate::auth_core) keyset: &'a Keyset,
    pub(in crate::auth_core) current_target: CoreStorageTarget,
    pub(in crate::auth_core) current_mac_bytes: Option<&'a [u8]>,
    pub(in crate::auth_core) secret: &'a AuthCredentialSecret,
    pub(in crate::auth_core) current_version: SecretVersion,
    pub(in crate::auth_core) previous_target: CoreStorageTarget,
    pub(in crate::auth_core) previous_mac_bytes: Option<&'a [u8]>,
    pub(in crate::auth_core) previous_version: Option<SecretVersion>,
    pub(in crate::auth_core) previous_secret_accept_until: Option<UnixSeconds>,
    pub(in crate::auth_core) now: UnixSeconds,
}

pub(in crate::auth_core) fn classify_presented_secret(
    input: PresentedSecretClassificationInput<'_>,
) -> Result<StoredSecretMatch, PostgresAuthStoreError> {
    if let Some(current_mac) = input.current_mac_bytes {
        let current_mac = MacOverSecret::try_from(current_mac)
            .map_err(|_| PostgresAuthStoreError::InvalidStoredData("malformed current MAC"))?;
        if current_mac.verify(
            input.keyset,
            input.secret.expose_secret(),
            &credential_secret_mac_context(&input.current_target),
        ) {
            return Ok(StoredSecretMatch::Current);
        }
    }
    if input.previous_version.is_some()
        && let Some(previous_mac) = input.previous_mac_bytes
    {
        let previous_mac = MacOverSecret::try_from(previous_mac)
            .map_err(|_| PostgresAuthStoreError::InvalidStoredData("malformed previous MAC"))?;
        if previous_mac.verify(
            input.keyset,
            input.secret.expose_secret(),
            &credential_secret_mac_context(&input.previous_target),
        ) {
            if input
                .previous_version
                .is_some_and(|version| version != input.current_version)
                && input
                    .previous_secret_accept_until
                    .is_some_and(|accept_until| input.now < accept_until)
            {
                return Ok(StoredSecretMatch::PreviousWithinGrace);
            }
            return Ok(StoredSecretMatch::PreviousAfterGrace);
        }
    }
    Ok(StoredSecretMatch::Unknown)
}

pub(in crate::auth_core) fn credential_secret_mac_context(target: &CoreStorageTarget) -> Vec<u8> {
    let mut context = Vec::new();
    match target {
        CoreStorageTarget::SessionCredentialSecret {
            session_id,
            secret_version,
        } => {
            context.extend_from_slice(SESSION_SECRET_MAC_CONTEXT_PREFIX);
            append_context_bytes(&mut context, session_id.as_bytes());
            context.extend_from_slice(&secret_version.get().to_be_bytes());
        }
        CoreStorageTarget::TrustedDeviceCredentialSecret {
            device_credential_id,
            secret_version,
        } => {
            context.extend_from_slice(TRUSTED_DEVICE_SECRET_MAC_CONTEXT_PREFIX);
            append_context_bytes(&mut context, device_credential_id.as_bytes());
            context.extend_from_slice(&secret_version.get().to_be_bytes());
        }
        CoreStorageTarget::ActiveProofContinuationSecret { attempt_id } => {
            context.extend_from_slice(ACTIVE_PROOF_CONTINUATION_SECRET_MAC_CONTEXT_PREFIX);
            append_context_bytes(&mut context, attempt_id.as_bytes());
        }
        _ => {}
    }
    context
}

pub(in crate::auth_core) fn append_context_bytes(context: &mut Vec<u8>, bytes: &[u8]) {
    context.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    context.extend_from_slice(bytes);
}
