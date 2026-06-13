use std::fmt;

use crate::crypto::{Keyset, MacOverSecret, SecretBytes};

use super::prelude::*;

/// Secret bytes for a session or trusted-device credential.
pub struct AuthCredentialSecret(SecretBytes<AuthCredentialSecretKind>);

/// Marker for auth credential secret bytes.
pub enum AuthCredentialSecretKind {}

impl AuthCredentialSecret {
    /// Wraps secret bytes as auth credential material.
    pub fn from_secret_bytes(secret: SecretBytes<AuthCredentialSecretKind>) -> Result<Self, Error> {
        if secret.expose_secret().is_empty() {
            return Err(Error::EmptyCredentialSecret);
        }
        Ok(Self(secret))
    }

    /// Explicitly exposes the credential secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    pub(crate) fn to_mac(
        &self,
        keyset: &Keyset,
        context: &[u8],
    ) -> Result<MacOverSecret, crate::crypto::Error> {
        self.0.to_mac(keyset, context)
    }
}

impl TryFrom<&[u8]> for AuthCredentialSecret {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::EmptyCredentialSecret);
        }
        Ok(Self(
            SecretBytes::<AuthCredentialSecretKind>::try_from(value).map_err(|_| {
                Error::LoadedStateContradiction("credential secret could not be allocated")
            })?,
        ))
    }
}

impl TryFrom<Vec<u8>> for AuthCredentialSecret {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::EmptyCredentialSecret);
        }
        Ok(Self(
            SecretBytes::<AuthCredentialSecretKind>::try_from(value).map_err(|_| {
                Error::LoadedStateContradiction("credential secret could not be allocated")
            })?,
        ))
    }
}

impl fmt::Debug for AuthCredentialSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthCredentialSecret")
            .field("len", &self.expose_secret().len())
            .finish()
    }
}

/// Presented cookie credential secrets decoded by the runtime but not shown to the reducer.
#[derive(Debug, Default)]
pub struct PresentedAuthCookieSecrets {
    session: Option<PresentedSessionCookieSecret>,
    trusted_device: Option<PresentedTrustedDeviceCookieSecret>,
    active_proof_continuation: Option<PresentedActiveProofContinuationCookieSecret>,
}

impl PresentedAuthCookieSecrets {
    /// Creates presented cookie secrets.
    pub fn new(
        session: Option<PresentedSessionCookieSecret>,
        trusted_device: Option<PresentedTrustedDeviceCookieSecret>,
        active_proof_continuation: Option<PresentedActiveProofContinuationCookieSecret>,
    ) -> Self {
        Self {
            session,
            trusted_device,
            active_proof_continuation,
        }
    }

    /// Returns the presented session cookie secret, if any.
    pub fn session(&self) -> Option<&PresentedSessionCookieSecret> {
        self.session.as_ref()
    }

    /// Returns the presented trusted-device cookie secret, if any.
    pub fn trusted_device(&self) -> Option<&PresentedTrustedDeviceCookieSecret> {
        self.trusted_device.as_ref()
    }

    /// Returns the presented active-proof continuation cookie secret, if any.
    pub fn active_proof_continuation(
        &self,
    ) -> Option<&PresentedActiveProofContinuationCookieSecret> {
        self.active_proof_continuation.as_ref()
    }

    pub(crate) fn validate_matches_presented_cookies(
        &self,
        presented_cookies: &PresentedAuthCookies,
    ) -> Result<(), Error> {
        if let Some(session_secret) = &self.session {
            let Some(session_cookie) = &presented_cookies.session_cookie else {
                return Err(Error::PresentedSessionCookieSecretMismatch);
            };
            if session_secret.session_id != session_cookie.session_id
                || session_secret.secret_version != session_cookie.secret_version
            {
                return Err(Error::PresentedSessionCookieSecretMismatch);
            }
        }
        if let Some(trusted_device_secret) = &self.trusted_device {
            let Some(trusted_device_cookie) = &presented_cookies.trusted_device_cookie else {
                return Err(Error::PresentedTrustedDeviceCookieSecretMismatch);
            };
            if trusted_device_secret.device_credential_id
                != trusted_device_cookie.device_credential_id
                || trusted_device_secret.secret_version != trusted_device_cookie.secret_version
            {
                return Err(Error::PresentedTrustedDeviceCookieSecretMismatch);
            }
        }
        if let Some(continuation_secret) = &self.active_proof_continuation {
            let Some(continuation_cookie) = &presented_cookies.active_proof_continuation_cookie
            else {
                return Err(Error::PresentedActiveProofContinuationCookieSecretMismatch);
            };
            if continuation_secret.attempt_id != continuation_cookie.attempt_id {
                return Err(Error::PresentedActiveProofContinuationCookieSecretMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn take_session(
        &mut self,
        draft: &SessionCookieDraft,
    ) -> Result<AuthCredentialSecret, Error> {
        let presented = self
            .session
            .take()
            .ok_or(Error::MissingSessionCookieResponseSecret)?;
        if presented.session_id != draft.session_id
            || presented.secret_version != draft.secret_version
        {
            return Err(Error::PresentedSessionCookieSecretMismatch);
        }
        Ok(presented.secret)
    }

    pub(crate) fn take_trusted_device(
        &mut self,
        draft: &TrustedDeviceCookieDraft,
    ) -> Result<AuthCredentialSecret, Error> {
        let presented = self
            .trusted_device
            .take()
            .ok_or(Error::MissingTrustedDeviceCookieResponseSecret)?;
        if presented.device_credential_id != draft.device_credential_id
            || presented.secret_version != draft.secret_version
        {
            return Err(Error::PresentedTrustedDeviceCookieSecretMismatch);
        }
        Ok(presented.secret)
    }

    pub(crate) fn take_active_proof_continuation(
        &mut self,
        draft: &ActiveProofContinuationCookieDraft,
    ) -> Result<AuthCredentialSecret, Error> {
        let presented = self
            .active_proof_continuation
            .take()
            .ok_or(Error::MissingActiveProofContinuationCookieResponseSecret)?;
        if presented.attempt_id != draft.attempt_id {
            return Err(Error::PresentedActiveProofContinuationCookieSecretMismatch);
        }
        Ok(presented.secret)
    }
}

/// Presented session cookie credential secret.
#[derive(Debug)]
pub struct PresentedSessionCookieSecret {
    session_id: SessionId,
    secret_version: SecretVersion,
    secret: AuthCredentialSecret,
}

impl PresentedSessionCookieSecret {
    /// Creates a presented session cookie secret.
    pub fn new(
        session_id: SessionId,
        secret_version: SecretVersion,
        secret: AuthCredentialSecret,
    ) -> Self {
        Self {
            session_id,
            secret_version,
            secret,
        }
    }

    /// Returns the session id.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the credential secret version.
    pub fn secret_version(&self) -> SecretVersion {
        self.secret_version
    }

    /// Returns the credential secret.
    pub fn secret(&self) -> &AuthCredentialSecret {
        &self.secret
    }
}

/// Presented trusted-device cookie credential secret.
#[derive(Debug)]
pub struct PresentedTrustedDeviceCookieSecret {
    device_credential_id: TrustedDeviceCredentialId,
    secret_version: SecretVersion,
    secret: AuthCredentialSecret,
}

/// Presented active-proof continuation cookie credential secret.
#[derive(Debug)]
pub struct PresentedActiveProofContinuationCookieSecret {
    attempt_id: ActiveProofAttemptId,
    secret: AuthCredentialSecret,
}

impl PresentedActiveProofContinuationCookieSecret {
    /// Creates a presented active-proof continuation cookie secret.
    pub fn new(attempt_id: ActiveProofAttemptId, secret: AuthCredentialSecret) -> Self {
        Self { attempt_id, secret }
    }

    /// Returns the active-proof attempt id.
    pub fn attempt_id(&self) -> &ActiveProofAttemptId {
        &self.attempt_id
    }

    /// Returns the credential secret.
    pub fn secret(&self) -> &AuthCredentialSecret {
        &self.secret
    }
}

impl PresentedTrustedDeviceCookieSecret {
    /// Creates a presented trusted-device cookie secret.
    pub fn new(
        device_credential_id: TrustedDeviceCredentialId,
        secret_version: SecretVersion,
        secret: AuthCredentialSecret,
    ) -> Self {
        Self {
            device_credential_id,
            secret_version,
            secret,
        }
    }

    /// Returns the trusted-device credential id.
    pub fn device_credential_id(&self) -> &TrustedDeviceCredentialId {
        &self.device_credential_id
    }

    /// Returns the credential secret version.
    pub fn secret_version(&self) -> SecretVersion {
        self.secret_version
    }

    /// Returns the credential secret.
    pub fn secret(&self) -> &AuthCredentialSecret {
        &self.secret
    }
}

/// Materialized response-local effect ready for the web adapter.
#[derive(Debug)]
pub enum MaterializedResponseEffect {
    /// Issue or replace the encrypted session cookie.
    IssueSessionCookie(MaterializedSessionCookieResponse),
    /// Delete the encrypted session cookie.
    DeleteSessionCookie,
    /// Issue or replace the encrypted trusted-device cookie.
    IssueTrustedDeviceCookie(MaterializedTrustedDeviceCookieResponse),
    /// Delete the encrypted trusted-device cookie.
    DeleteTrustedDeviceCookie,
    /// Issue or replace the encrypted active-proof challenge cookie.
    IssueActiveProofChallengeCookie(ActiveProofChallengeCookieDraft),
    /// Delete the encrypted active-proof challenge cookie.
    DeleteActiveProofChallengeCookie,
    /// Issue or replace the encrypted active-proof continuation cookie.
    IssueActiveProofContinuationCookie(MaterializedActiveProofContinuationCookieResponse),
    /// Delete the encrypted active-proof continuation cookie.
    DeleteActiveProofContinuationCookie,
    /// Cycle the CSRF token after session identity or freshness changes.
    CycleCsrfToken {
        /// Session id to bind to, or `None` when logging out.
        session_id: Option<SessionId>,
    },
}

/// Materialized session cookie payload plus credential secret.
#[derive(Debug)]
pub struct MaterializedSessionCookieResponse {
    draft: SessionCookieDraft,
    credential_secret: AuthCredentialSecret,
}

impl MaterializedSessionCookieResponse {
    /// Creates a materialized session cookie.
    pub fn new(draft: SessionCookieDraft, credential_secret: AuthCredentialSecret) -> Self {
        Self {
            draft,
            credential_secret,
        }
    }

    /// Returns the session cookie draft.
    pub fn draft(&self) -> &SessionCookieDraft {
        &self.draft
    }

    /// Returns the credential secret that must be encrypted into the cookie.
    pub fn credential_secret(&self) -> &AuthCredentialSecret {
        &self.credential_secret
    }
}

/// Materialized trusted-device cookie payload plus credential secret.
#[derive(Debug)]
pub struct MaterializedTrustedDeviceCookieResponse {
    draft: TrustedDeviceCookieDraft,
    credential_secret: AuthCredentialSecret,
}

/// Materialized active-proof continuation cookie payload plus credential secret.
#[derive(Debug)]
pub struct MaterializedActiveProofContinuationCookieResponse {
    draft: ActiveProofContinuationCookieDraft,
    credential_secret: AuthCredentialSecret,
}

impl MaterializedActiveProofContinuationCookieResponse {
    /// Creates a materialized active-proof continuation cookie.
    pub fn new(
        draft: ActiveProofContinuationCookieDraft,
        credential_secret: AuthCredentialSecret,
    ) -> Self {
        Self {
            draft,
            credential_secret,
        }
    }

    /// Returns the active-proof continuation cookie draft.
    pub fn draft(&self) -> &ActiveProofContinuationCookieDraft {
        &self.draft
    }

    /// Returns the credential secret that must be encrypted into the cookie.
    pub fn credential_secret(&self) -> &AuthCredentialSecret {
        &self.credential_secret
    }
}

impl MaterializedTrustedDeviceCookieResponse {
    /// Creates a materialized trusted-device cookie.
    pub fn new(draft: TrustedDeviceCookieDraft, credential_secret: AuthCredentialSecret) -> Self {
        Self {
            draft,
            credential_secret,
        }
    }

    /// Returns the trusted-device cookie draft.
    pub fn draft(&self) -> &TrustedDeviceCookieDraft {
        &self.draft
    }

    /// Returns the credential secret that must be encrypted into the cookie.
    pub fn credential_secret(&self) -> &AuthCredentialSecret {
        &self.credential_secret
    }
}

/// Materialized response effects ready for a transport adapter.
#[derive(Debug, Default)]
pub struct MaterializedResponseEffects(Vec<MaterializedResponseEffect>);

impl MaterializedResponseEffects {
    pub(crate) fn from_vec(effects: Vec<MaterializedResponseEffect>) -> Self {
        Self(effects)
    }

    pub(crate) fn extend(&mut self, effects: MaterializedResponseEffects) {
        self.0.extend(effects.0);
    }

    pub(crate) fn from_validated_response_effects(
        effects: ValidatedResponseEffects,
        commit_success: Option<AtomicCommitSuccess>,
        mut presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<Self, Error> {
        let mut fresh_secrets = commit_success
            .map(AtomicCommitSuccess::into_materialized_fresh_credential_secrets)
            .unwrap_or_default();
        let mut materialized = Vec::new();
        for effect in effects.into_vec() {
            let effect = match effect {
                ResponseEffect::IssueSessionCookie(draft) => {
                    let target = CoreStorageTarget::SessionCredentialSecret {
                        session_id: draft.session_id.clone(),
                        secret_version: draft.secret_version,
                    };
                    let secret = fresh_secrets
                        .take_secret_for_target(&target)
                        .map(Ok)
                        .unwrap_or_else(|| presented_cookie_secrets.take_session(&draft))?;
                    MaterializedResponseEffect::IssueSessionCookie(
                        MaterializedSessionCookieResponse::new(draft, secret),
                    )
                }
                ResponseEffect::DeleteSessionCookie => {
                    MaterializedResponseEffect::DeleteSessionCookie
                }
                ResponseEffect::IssueTrustedDeviceCookie(draft) => {
                    let target = CoreStorageTarget::TrustedDeviceCredentialSecret {
                        device_credential_id: draft.device_credential_id.clone(),
                        secret_version: draft.secret_version,
                    };
                    let secret = fresh_secrets
                        .take_secret_for_target(&target)
                        .map(Ok)
                        .unwrap_or_else(|| presented_cookie_secrets.take_trusted_device(&draft))?;
                    MaterializedResponseEffect::IssueTrustedDeviceCookie(
                        MaterializedTrustedDeviceCookieResponse::new(draft, secret),
                    )
                }
                ResponseEffect::DeleteTrustedDeviceCookie => {
                    MaterializedResponseEffect::DeleteTrustedDeviceCookie
                }
                ResponseEffect::IssueActiveProofChallengeCookie(draft) => {
                    MaterializedResponseEffect::IssueActiveProofChallengeCookie(draft)
                }
                ResponseEffect::DeleteActiveProofChallengeCookie => {
                    MaterializedResponseEffect::DeleteActiveProofChallengeCookie
                }
                ResponseEffect::IssueActiveProofContinuationCookie(draft) => {
                    let target = CoreStorageTarget::ActiveProofContinuationSecret {
                        attempt_id: draft.attempt_id.clone(),
                    };
                    let secret = fresh_secrets
                        .take_secret_for_target(&target)
                        .map(Ok)
                        .unwrap_or_else(|| {
                            presented_cookie_secrets.take_active_proof_continuation(&draft)
                        })?;
                    MaterializedResponseEffect::IssueActiveProofContinuationCookie(
                        MaterializedActiveProofContinuationCookieResponse::new(draft, secret),
                    )
                }
                ResponseEffect::DeleteActiveProofContinuationCookie => {
                    MaterializedResponseEffect::DeleteActiveProofContinuationCookie
                }
                ResponseEffect::CycleCsrfToken { session_id } => {
                    MaterializedResponseEffect::CycleCsrfToken { session_id }
                }
            };
            materialized.push(effect);
        }
        Ok(Self(materialized))
    }

    /// Returns whether there are no materialized response effects.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns materialized response effects.
    pub fn as_slice(&self) -> &[MaterializedResponseEffect] {
        &self.0
    }

    /// Consumes the wrapper and returns materialized response effects.
    pub fn into_vec(self) -> Vec<MaterializedResponseEffect> {
        self.0
    }
}

/// Command execution completed with materialized response effects.
#[derive(Debug)]
pub struct MaterializedCompletedCommandExecution {
    outcome: Outcome,
    materialized_response_effects: MaterializedResponseEffects,
}

impl MaterializedCompletedCommandExecution {
    pub(crate) fn new(
        outcome: Outcome,
        materialized_response_effects: MaterializedResponseEffects,
    ) -> Self {
        Self {
            outcome,
            materialized_response_effects,
        }
    }

    /// Returns the semantic reducer outcome.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Returns response effects carrying the secrets needed for cookie encryption.
    pub fn materialized_response_effects(&self) -> &MaterializedResponseEffects {
        &self.materialized_response_effects
    }

    /// Splits completed execution into outcome and materialized response effects.
    pub fn into_parts(self) -> (Outcome, MaterializedResponseEffects) {
        (self.outcome, self.materialized_response_effects)
    }
}
