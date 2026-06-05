use std::fmt;

use crate::crypto::Keyset;
use crate::web::{
    CookieManager, CookieMaxAgeSeconds, CsrfBinding, CsrfProtector, SecureCookie,
    SecureCookieConfig,
};
use http::HeaderMap;
use http::header::{HeaderValue, SET_COOKIE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::*;

/// Default encrypted session cookie suffix.
pub const DEFAULT_AUTH_SESSION_COOKIE_NAME: &str = "__paranoid_auth_session";

/// Default encrypted trusted-device cookie suffix.
pub const DEFAULT_AUTH_TRUSTED_DEVICE_COOKIE_NAME: &str = "__paranoid_auth_trusted_device";

/// Default encrypted active-proof challenge cookie suffix.
pub const DEFAULT_AUTH_ACTIVE_PROOF_CHALLENGE_COOKIE_NAME: &str =
    "__paranoid_auth_active_proof_challenge";

/// Default encrypted active-proof continuation cookie suffix.
pub const DEFAULT_AUTH_ACTIVE_PROOF_CONTINUATION_COOKIE_NAME: &str =
    "__paranoid_auth_active_proof_continuation";

/// Auth web transport configuration.
pub struct AuthWebTransportConfig {
    /// Cookie manager used for encrypted auth cookies.
    pub cookie_manager: CookieManager,
    /// CSRF protector used to cycle CSRF token cookies.
    pub csrf_protector: CsrfProtector,
    /// Keyset used for challenge-response stateless fast-fail MACs.
    pub active_proof_challenge_fast_fail_keyset: Keyset,
    /// Host-only encrypted session cookie suffix.
    pub session_cookie_name: String,
    /// Host-only encrypted trusted-device cookie suffix.
    pub trusted_device_cookie_name: String,
    /// Host-only encrypted active-proof challenge cookie suffix.
    pub active_proof_challenge_cookie_name: String,
    /// Host-only encrypted active-proof continuation cookie suffix.
    pub active_proof_continuation_cookie_name: String,
}

impl AuthWebTransportConfig {
    /// Creates auth web transport configuration.
    pub fn new(
        cookie_manager: CookieManager,
        csrf_protector: CsrfProtector,
        active_proof_challenge_fast_fail_keyset: Keyset,
    ) -> Self {
        Self {
            cookie_manager,
            csrf_protector,
            active_proof_challenge_fast_fail_keyset,
            session_cookie_name: DEFAULT_AUTH_SESSION_COOKIE_NAME.to_owned(),
            trusted_device_cookie_name: DEFAULT_AUTH_TRUSTED_DEVICE_COOKIE_NAME.to_owned(),
            active_proof_challenge_cookie_name: DEFAULT_AUTH_ACTIVE_PROOF_CHALLENGE_COOKIE_NAME
                .to_owned(),
            active_proof_continuation_cookie_name:
                DEFAULT_AUTH_ACTIVE_PROOF_CONTINUATION_COOKIE_NAME.to_owned(),
        }
    }
}

impl fmt::Debug for AuthWebTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthWebTransportConfig")
            .field("cookie_manager", &self.cookie_manager)
            .field("csrf_protector", &"[csrf protector]")
            .field(
                "active_proof_challenge_fast_fail_keyset",
                &self.active_proof_challenge_fast_fail_keyset,
            )
            .field("session_cookie_name", &self.session_cookie_name)
            .field(
                "trusted_device_cookie_name",
                &self.trusted_device_cookie_name,
            )
            .field(
                "active_proof_challenge_cookie_name",
                &self.active_proof_challenge_cookie_name,
            )
            .field(
                "active_proof_continuation_cookie_name",
                &self.active_proof_continuation_cookie_name,
            )
            .finish()
    }
}

/// Auth transport backed by Paranoid web cookies and CSRF primitives.
pub struct AuthWebTransport {
    cookie_manager: CookieManager,
    csrf_protector: CsrfProtector,
    active_proof_challenge_fast_fail_keyset: Keyset,
    session_cookie_name: String,
    trusted_device_cookie_name: String,
    active_proof_challenge_cookie_name: String,
    active_proof_continuation_cookie_name: String,
}

impl AuthWebTransport {
    /// Creates auth web transport.
    pub fn new(config: AuthWebTransportConfig) -> Self {
        Self {
            cookie_manager: config.cookie_manager,
            csrf_protector: config.csrf_protector,
            active_proof_challenge_fast_fail_keyset: config.active_proof_challenge_fast_fail_keyset,
            session_cookie_name: config.session_cookie_name,
            trusted_device_cookie_name: config.trusted_device_cookie_name,
            active_proof_challenge_cookie_name: config.active_proof_challenge_cookie_name,
            active_proof_continuation_cookie_name: config.active_proof_continuation_cookie_name,
        }
    }

    /// Decodes auth cookies from HTTP request headers.
    pub fn decode_presented_cookies_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<DecodedAuthWebCookies, AuthWebTransportError> {
        let session = self
            .session_cookie(None)?
            .get_optional_from_headers(headers)?
            .map(DecodedSessionCookie::try_from)
            .transpose()?;
        let trusted_device = self
            .trusted_device_cookie(None)?
            .get_optional_from_headers(headers)?
            .map(DecodedTrustedDeviceCookie::try_from)
            .transpose()?;
        let active_proof_challenge = self
            .active_proof_challenge_cookie(None)?
            .get_optional_from_headers(headers)?
            .map(DecodedActiveProofChallengeCookie::try_from)
            .transpose()?;
        let active_proof_continuation = self
            .active_proof_continuation_cookie(None)?
            .get_optional_from_headers(headers)?
            .map(DecodedActiveProofContinuationCookie::try_from)
            .transpose()?;
        Ok(decoded_auth_web_cookies(
            session,
            trusted_device,
            active_proof_challenge,
            active_proof_continuation,
        ))
    }

    /// Decodes auth cookies from one HTTP `Cookie` header value.
    pub fn decode_presented_cookies_from_cookie_header(
        &self,
        cookie_header: &str,
    ) -> Result<DecodedAuthWebCookies, AuthWebTransportError> {
        let session = self
            .session_cookie(None)?
            .get_optional_from_cookie_header(cookie_header)?
            .map(DecodedSessionCookie::try_from)
            .transpose()?;
        let trusted_device = self
            .trusted_device_cookie(None)?
            .get_optional_from_cookie_header(cookie_header)?
            .map(DecodedTrustedDeviceCookie::try_from)
            .transpose()?;
        let active_proof_challenge = self
            .active_proof_challenge_cookie(None)?
            .get_optional_from_cookie_header(cookie_header)?
            .map(DecodedActiveProofChallengeCookie::try_from)
            .transpose()?;
        let active_proof_continuation = self
            .active_proof_continuation_cookie(None)?
            .get_optional_from_cookie_header(cookie_header)?
            .map(DecodedActiveProofContinuationCookie::try_from)
            .transpose()?;
        Ok(decoded_auth_web_cookies(
            session,
            trusted_device,
            active_proof_challenge,
            active_proof_continuation,
        ))
    }

    pub(crate) fn active_proof_challenge_fast_fail_keyset(&self) -> &Keyset {
        &self.active_proof_challenge_fast_fail_keyset
    }

    /// Renders materialized response effects into `Set-Cookie` header values.
    pub fn render_set_cookie_headers(
        &self,
        now: UnixSeconds,
        response_effects: MaterializedResponseEffects,
    ) -> Result<AuthSetCookieHeaders, AuthWebTransportError> {
        let mut headers = Vec::new();
        for effect in response_effects.into_vec() {
            let cookie = match effect {
                MaterializedResponseEffect::IssueSessionCookie(cookie) => {
                    let max_age = max_age_until(now, cookie.draft().session_fast_fail_until)?;
                    self.session_cookie(Some(max_age))?
                        .new_cookie(&AuthSessionCookiePayload::from_materialized_cookie(&cookie))?
                }
                MaterializedResponseEffect::DeleteSessionCookie => {
                    self.session_cookie(None)?.deletion_cookie()
                }
                MaterializedResponseEffect::IssueTrustedDeviceCookie(cookie) => {
                    let max_age = max_age_until(now, cookie.draft().device_fast_fail_until)?;
                    self.trusted_device_cookie(Some(max_age))?.new_cookie(
                        &AuthTrustedDeviceCookiePayload::from_materialized_cookie(&cookie),
                    )?
                }
                MaterializedResponseEffect::DeleteTrustedDeviceCookie => {
                    self.trusted_device_cookie(None)?.deletion_cookie()
                }
                MaterializedResponseEffect::IssueActiveProofChallengeCookie(cookie) => {
                    let max_age = max_age_until(now, cookie.expires_at)?;
                    self.active_proof_challenge_cookie(Some(max_age))?
                        .new_cookie(&AuthActiveProofChallengeCookiePayload::from_draft(&cookie))?
                }
                MaterializedResponseEffect::DeleteActiveProofChallengeCookie => {
                    self.active_proof_challenge_cookie(None)?.deletion_cookie()
                }
                MaterializedResponseEffect::IssueActiveProofContinuationCookie(cookie) => {
                    let max_age = max_age_until(now, cookie.draft().attempt_fast_fail_until)?;
                    self.active_proof_continuation_cookie(Some(max_age))?
                        .new_cookie(
                            &AuthActiveProofContinuationCookiePayload::from_materialized_cookie(
                                &cookie,
                            ),
                        )?
                }
                MaterializedResponseEffect::DeleteActiveProofContinuationCookie => self
                    .active_proof_continuation_cookie(None)?
                    .deletion_cookie(),
                MaterializedResponseEffect::CycleCsrfToken { session_id } => {
                    let binding = csrf_binding_for_session_id(session_id.as_ref())?;
                    self.csrf_protector
                        .cycle_token_cookie_for_binding(binding.as_ref())?
                }
            };
            headers.push(AuthSetCookieHeader::from_cookie_string(cookie.to_string())?);
        }
        Ok(AuthSetCookieHeaders(headers))
    }

    fn session_cookie(
        &self,
        max_age: Option<CookieMaxAgeSeconds>,
    ) -> Result<SecureCookie<AuthSessionCookiePayload>, crate::web::Error> {
        let mut config = SecureCookieConfig::new(self.session_cookie_name.clone());
        config.max_age = max_age;
        self.cookie_manager.secure_cookie(config)
    }

    fn trusted_device_cookie(
        &self,
        max_age: Option<CookieMaxAgeSeconds>,
    ) -> Result<SecureCookie<AuthTrustedDeviceCookiePayload>, crate::web::Error> {
        let mut config = SecureCookieConfig::new(self.trusted_device_cookie_name.clone());
        config.max_age = max_age;
        self.cookie_manager.secure_cookie(config)
    }

    fn active_proof_challenge_cookie(
        &self,
        max_age: Option<CookieMaxAgeSeconds>,
    ) -> Result<SecureCookie<AuthActiveProofChallengeCookiePayload>, crate::web::Error> {
        let mut config = SecureCookieConfig::new(self.active_proof_challenge_cookie_name.clone());
        config.max_age = max_age;
        self.cookie_manager.secure_cookie(config)
    }

    fn active_proof_continuation_cookie(
        &self,
        max_age: Option<CookieMaxAgeSeconds>,
    ) -> Result<SecureCookie<AuthActiveProofContinuationCookiePayload>, crate::web::Error> {
        let mut config =
            SecureCookieConfig::new(self.active_proof_continuation_cookie_name.clone());
        config.max_age = max_age;
        self.cookie_manager.secure_cookie(config)
    }
}

impl fmt::Debug for AuthWebTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthWebTransport")
            .field("cookie_manager", &self.cookie_manager)
            .field("csrf_protector", &"[csrf protector]")
            .field(
                "active_proof_challenge_fast_fail_keyset",
                &self.active_proof_challenge_fast_fail_keyset,
            )
            .field("session_cookie_name", &self.session_cookie_name)
            .field(
                "trusted_device_cookie_name",
                &self.trusted_device_cookie_name,
            )
            .field(
                "active_proof_challenge_cookie_name",
                &self.active_proof_challenge_cookie_name,
            )
            .field(
                "active_proof_continuation_cookie_name",
                &self.active_proof_continuation_cookie_name,
            )
            .finish()
    }
}

/// Decoded auth cookies and their separated credential secrets.
#[derive(Debug, Default)]
pub struct DecodedAuthWebCookies {
    presented_cookies: PresentedAuthCookies,
    presented_cookie_secrets: PresentedAuthCookieSecrets,
}

impl DecodedAuthWebCookies {
    /// Returns the reducer-visible presented cookies.
    pub fn presented_cookies(&self) -> &PresentedAuthCookies {
        &self.presented_cookies
    }

    /// Returns the separated presented cookie credential secrets.
    pub fn presented_cookie_secrets(&self) -> &PresentedAuthCookieSecrets {
        &self.presented_cookie_secrets
    }

    /// Consumes the decoded cookies.
    pub fn into_parts(self) -> (PresentedAuthCookies, PresentedAuthCookieSecrets) {
        (self.presented_cookies, self.presented_cookie_secrets)
    }
}

/// Rendered `Set-Cookie` headers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthSetCookieHeaders(Vec<AuthSetCookieHeader>);

impl AuthSetCookieHeaders {
    pub(crate) fn prepend(&mut self, mut headers: AuthSetCookieHeaders) {
        headers.0.extend(std::mem::take(&mut self.0));
        self.0 = headers.0;
    }

    /// Returns whether there are no headers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns rendered `Set-Cookie` headers.
    pub fn as_slice(&self) -> &[AuthSetCookieHeader] {
        &self.0
    }

    /// Appends these `Set-Cookie` headers to an HTTP header map.
    pub fn append_to_headers(&self, headers: &mut HeaderMap) {
        for header in &self.0 {
            headers.append(SET_COOKIE, header.value.clone());
        }
    }

    /// Consumes the wrapper and returns rendered `Set-Cookie` headers.
    pub fn into_vec(self) -> Vec<AuthSetCookieHeader> {
        self.0
    }
}

/// One rendered `Set-Cookie` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSetCookieHeader {
    value: HeaderValue,
}

impl AuthSetCookieHeader {
    fn from_cookie_string(value: String) -> Result<Self, AuthWebTransportError> {
        Ok(Self {
            value: HeaderValue::from_str(&value)?,
        })
    }

    /// Returns the validated header value.
    pub fn header_value(&self) -> &HeaderValue {
        &self.value
    }

    /// Returns the header as visible text.
    pub fn as_str(&self) -> &str {
        self.value
            .to_str()
            .expect("cookie header value is visible text")
    }
}

/// Error returned by auth web transport helpers.
#[derive(Debug)]
pub enum AuthWebTransportError {
    /// Auth core rejected a transport operation.
    Core(Error),
    /// Paranoid web primitive returned an error.
    Web(crate::web::Error),
    /// Rendered cookie text was not a valid HTTP header value.
    InvalidSetCookieHeader(http::header::InvalidHeaderValue),
}

impl fmt::Display for AuthWebTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Web(error) => write!(f, "{error}"),
            Self::InvalidSetCookieHeader(error) => {
                write!(f, "auth core: invalid Set-Cookie header: {error}")
            }
        }
    }
}

impl std::error::Error for AuthWebTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Web(error) => Some(error),
            Self::InvalidSetCookieHeader(error) => Some(error),
        }
    }
}

impl From<Error> for AuthWebTransportError {
    fn from(value: Error) -> Self {
        Self::Core(value)
    }
}

impl From<crate::web::Error> for AuthWebTransportError {
    fn from(value: crate::web::Error) -> Self {
        Self::Web(value)
    }
}

impl From<http::header::InvalidHeaderValue> for AuthWebTransportError {
    fn from(value: http::header::InvalidHeaderValue) -> Self {
        Self::InvalidSetCookieHeader(value)
    }
}

#[derive(Serialize, Deserialize)]
struct AuthSessionCookiePayload {
    session_id: Vec<u8>,
    subject_id: Vec<u8>,
    secret_version: u64,
    credential_secret: Vec<u8>,
    session_fast_fail_until: u64,
    safe_read_valid_until: Option<u64>,
    step_up_valid_until: Option<u64>,
}

impl AuthSessionCookiePayload {
    fn from_materialized_cookie(cookie: &MaterializedSessionCookieResponse) -> Self {
        Self {
            session_id: cookie.draft().session_id.as_bytes().to_vec(),
            subject_id: cookie.draft().subject_id.as_bytes().to_vec(),
            secret_version: cookie.draft().secret_version.get(),
            credential_secret: cookie.credential_secret().expose_secret().to_vec(),
            session_fast_fail_until: cookie.draft().session_fast_fail_until.get(),
            safe_read_valid_until: cookie.draft().safe_read_valid_until.map(UnixSeconds::get),
            step_up_valid_until: cookie.draft().step_up_valid_until.map(UnixSeconds::get),
        }
    }
}

impl Drop for AuthSessionCookiePayload {
    fn drop(&mut self) {
        self.credential_secret.zeroize();
    }
}

struct DecodedSessionCookie {
    draft: SessionCookieDraft,
    secret: PresentedSessionCookieSecret,
}

impl TryFrom<AuthSessionCookiePayload> for DecodedSessionCookie {
    type Error = Error;

    fn try_from(mut payload: AuthSessionCookiePayload) -> Result<Self, Self::Error> {
        let session_id = SessionId::from_bytes(payload.session_id.clone())?;
        let subject_id = SubjectId::from_bytes(std::mem::take(&mut payload.subject_id))?;
        let secret_version = SecretVersion::new(payload.secret_version)?;
        let draft = SessionCookieDraft {
            session_id: session_id.clone(),
            subject_id,
            secret_version,
            session_fast_fail_until: UnixSeconds::new(payload.session_fast_fail_until),
            safe_read_valid_until: payload.safe_read_valid_until.map(UnixSeconds::new),
            step_up_valid_until: payload.step_up_valid_until.map(UnixSeconds::new),
        };
        let secret = PresentedSessionCookieSecret::new(
            session_id,
            secret_version,
            AuthCredentialSecret::try_from(std::mem::take(&mut payload.credential_secret))?,
        );
        Ok(Self { draft, secret })
    }
}

#[derive(Serialize, Deserialize)]
struct AuthTrustedDeviceCookiePayload {
    device_credential_id: Vec<u8>,
    subject_id: Vec<u8>,
    secret_version: u64,
    credential_secret: Vec<u8>,
    device_fast_fail_until: u64,
    silent_revival_fast_fail_until: u64,
}

impl AuthTrustedDeviceCookiePayload {
    fn from_materialized_cookie(cookie: &MaterializedTrustedDeviceCookieResponse) -> Self {
        Self {
            device_credential_id: cookie.draft().device_credential_id.as_bytes().to_vec(),
            subject_id: cookie.draft().subject_id.as_bytes().to_vec(),
            secret_version: cookie.draft().secret_version.get(),
            credential_secret: cookie.credential_secret().expose_secret().to_vec(),
            device_fast_fail_until: cookie.draft().device_fast_fail_until.get(),
            silent_revival_fast_fail_until: cookie.draft().silent_revival_fast_fail_until.get(),
        }
    }
}

impl Drop for AuthTrustedDeviceCookiePayload {
    fn drop(&mut self) {
        self.credential_secret.zeroize();
    }
}

struct DecodedTrustedDeviceCookie {
    draft: TrustedDeviceCookieDraft,
    secret: PresentedTrustedDeviceCookieSecret,
}

impl TryFrom<AuthTrustedDeviceCookiePayload> for DecodedTrustedDeviceCookie {
    type Error = Error;

    fn try_from(mut payload: AuthTrustedDeviceCookiePayload) -> Result<Self, Self::Error> {
        let device_credential_id =
            TrustedDeviceCredentialId::from_bytes(payload.device_credential_id.clone())?;
        let subject_id = SubjectId::from_bytes(std::mem::take(&mut payload.subject_id))?;
        let secret_version = SecretVersion::new(payload.secret_version)?;
        let draft = TrustedDeviceCookieDraft {
            device_credential_id: device_credential_id.clone(),
            subject_id,
            secret_version,
            device_fast_fail_until: UnixSeconds::new(payload.device_fast_fail_until),
            silent_revival_fast_fail_until: UnixSeconds::new(
                payload.silent_revival_fast_fail_until,
            ),
        };
        let secret = PresentedTrustedDeviceCookieSecret::new(
            device_credential_id,
            secret_version,
            AuthCredentialSecret::try_from(std::mem::take(&mut payload.credential_secret))?,
        );
        Ok(Self { draft, secret })
    }
}

#[derive(Serialize, Deserialize)]
struct AuthActiveProofChallengeCookiePayload {
    attempt_id: Vec<u8>,
    challenge_id: Vec<u8>,
    proof_family: u8,
    proof_method_label: String,
    proof_online_guessing_risk: u8,
    issued_at: u64,
    expires_at: u64,
    nonce: Vec<u8>,
    response_mac: Option<Vec<u8>>,
    method_challenge_state: Option<Vec<u8>>,
    requires_stateless_fast_fail: bool,
}

impl AuthActiveProofChallengeCookiePayload {
    fn from_draft(draft: &ActiveProofChallengeCookieDraft) -> Self {
        Self {
            attempt_id: draft.attempt_id.as_bytes().to_vec(),
            challenge_id: draft.challenge_id.as_bytes().to_vec(),
            proof_family: proof_family_wire_id(draft.proof.family()),
            proof_method_label: draft.proof.method_label().to_owned(),
            proof_online_guessing_risk: online_guessing_risk_wire_id(
                draft.proof.online_guessing_risk(),
            ),
            issued_at: draft.issued_at.get(),
            expires_at: draft.expires_at.get(),
            nonce: draft.nonce.as_bytes().to_vec(),
            response_mac: draft
                .response_mac
                .as_ref()
                .map(|response_mac| response_mac.as_bytes().to_vec()),
            method_challenge_state: draft
                .method_challenge_state
                .as_ref()
                .map(|state| state.as_bytes().to_vec()),
            requires_stateless_fast_fail: draft.requires_stateless_fast_fail(),
        }
    }
}

struct DecodedActiveProofChallengeCookie {
    draft: ActiveProofChallengeCookieDraft,
}

impl TryFrom<AuthActiveProofChallengeCookiePayload> for DecodedActiveProofChallengeCookie {
    type Error = Error;

    fn try_from(payload: AuthActiveProofChallengeCookiePayload) -> Result<Self, Self::Error> {
        let proof_family = proof_family_from_wire_id(payload.proof_family)?;
        let online_guessing_risk =
            online_guessing_risk_from_wire_id(payload.proof_online_guessing_risk)?;
        let proof = ProofSummary::new_with_online_guessing_risk(
            proof_family,
            payload.proof_method_label,
            online_guessing_risk,
        )?;
        let context = ActiveProofChallengeCookieContext::new(
            ActiveProofAttemptId::from_bytes(payload.attempt_id)?,
            ActiveProofChallengeId::from_bytes(payload.challenge_id)?,
            proof,
            UnixSeconds::new(payload.issued_at),
            UnixSeconds::new(payload.expires_at),
            ActiveProofChallengeFastFailNonce::from_bytes(&payload.nonce)?,
        )?;
        let draft =
            ActiveProofChallengeCookieDraft::new_with_optional_response_mac_and_method_state_with_fast_fail_requirement(
                context,
                payload
                    .response_mac
                    .as_deref()
                    .map(ActiveProofChallengeFastFailMac::from_bytes)
                    .transpose()?,
                payload
                    .method_challenge_state
                    .map(ActiveProofMethodChallengeState::try_from_bytes)
                    .transpose()?,
                payload.requires_stateless_fast_fail,
            )?;
        Ok(Self { draft })
    }
}

#[derive(Serialize, Deserialize)]
struct AuthActiveProofContinuationCookiePayload {
    attempt_id: Vec<u8>,
    proof_use: u8,
    subject_id: Option<Vec<u8>>,
    credential_secret: Vec<u8>,
    attempt_fast_fail_until: u64,
}

impl AuthActiveProofContinuationCookiePayload {
    fn from_materialized_cookie(
        cookie: &MaterializedActiveProofContinuationCookieResponse,
    ) -> Self {
        Self {
            attempt_id: cookie.draft().attempt_id.as_bytes().to_vec(),
            proof_use: proof_use_wire_id(cookie.draft().proof_use),
            subject_id: cookie
                .draft()
                .subject_id
                .as_ref()
                .map(|subject_id| subject_id.as_bytes().to_vec()),
            credential_secret: cookie.credential_secret().expose_secret().to_vec(),
            attempt_fast_fail_until: cookie.draft().attempt_fast_fail_until.get(),
        }
    }
}

impl Drop for AuthActiveProofContinuationCookiePayload {
    fn drop(&mut self) {
        self.credential_secret.zeroize();
    }
}

struct DecodedActiveProofContinuationCookie {
    draft: ActiveProofContinuationCookieDraft,
    secret: PresentedActiveProofContinuationCookieSecret,
}

impl TryFrom<AuthActiveProofContinuationCookiePayload> for DecodedActiveProofContinuationCookie {
    type Error = Error;

    fn try_from(
        mut payload: AuthActiveProofContinuationCookiePayload,
    ) -> Result<Self, Self::Error> {
        let attempt_id = ActiveProofAttemptId::from_bytes(payload.attempt_id.clone())?;
        let subject_id = payload
            .subject_id
            .take()
            .map(SubjectId::from_bytes)
            .transpose()?;
        let draft = ActiveProofContinuationCookieDraft {
            attempt_id: attempt_id.clone(),
            proof_use: proof_use_from_wire_id(payload.proof_use)?,
            subject_id,
            attempt_fast_fail_until: UnixSeconds::new(payload.attempt_fast_fail_until),
        };
        let secret = PresentedActiveProofContinuationCookieSecret::new(
            attempt_id,
            AuthCredentialSecret::try_from(std::mem::take(&mut payload.credential_secret))?,
        );
        Ok(Self { draft, secret })
    }
}

fn decoded_auth_web_cookies(
    session: Option<DecodedSessionCookie>,
    trusted_device: Option<DecodedTrustedDeviceCookie>,
    active_proof_challenge: Option<DecodedActiveProofChallengeCookie>,
    active_proof_continuation: Option<DecodedActiveProofContinuationCookie>,
) -> DecodedAuthWebCookies {
    let (session_cookie, session_secret) = session
        .map(|session| (Some(session.draft), Some(session.secret)))
        .unwrap_or((None, None));
    let (trusted_device_cookie, trusted_device_secret) = trusted_device
        .map(|trusted_device| (Some(trusted_device.draft), Some(trusted_device.secret)))
        .unwrap_or((None, None));
    let active_proof_challenge_cookie =
        active_proof_challenge.map(|active_proof_challenge| active_proof_challenge.draft);
    let (active_proof_continuation_cookie, active_proof_continuation_secret) =
        active_proof_continuation
            .map(|continuation| (Some(continuation.draft), Some(continuation.secret)))
            .unwrap_or((None, None));
    DecodedAuthWebCookies {
        presented_cookies: PresentedAuthCookies {
            session_cookie,
            trusted_device_cookie,
            active_proof_challenge_cookie,
            active_proof_continuation_cookie,
        },
        presented_cookie_secrets: PresentedAuthCookieSecrets::new(
            session_secret,
            trusted_device_secret,
            active_proof_continuation_secret,
        ),
    }
}

fn max_age_until(
    now: UnixSeconds,
    expires_at: UnixSeconds,
) -> Result<CookieMaxAgeSeconds, AuthWebTransportError> {
    let Some(seconds) = expires_at.get().checked_sub(now.get()) else {
        return Err(Error::TimeOverflow.into());
    };
    CookieMaxAgeSeconds::new(seconds).map_err(AuthWebTransportError::from)
}

fn csrf_binding_for_session_id(
    session_id: Option<&SessionId>,
) -> Result<Option<CsrfBinding>, AuthWebTransportError> {
    session_id
        .map(|session_id| CsrfBinding::from_non_empty_bytes(session_id.as_bytes()))
        .transpose()
        .map_err(AuthWebTransportError::from)
}
