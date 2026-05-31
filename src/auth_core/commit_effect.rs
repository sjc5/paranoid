use super::*;

/// Response-local effect applied only after a successful commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseEffect {
    /// Issue or replace the encrypted session cookie.
    IssueSessionCookie(SessionCookieDraft),
    /// Delete the encrypted session cookie.
    DeleteSessionCookie,
    /// Issue or replace the encrypted trusted-device cookie.
    IssueTrustedDeviceCookie(TrustedDeviceCookieDraft),
    /// Delete the encrypted trusted-device cookie.
    DeleteTrustedDeviceCookie,
    /// Issue or replace the encrypted active-proof challenge cookie.
    IssueActiveProofChallengeCookie(ActiveProofChallengeCookieDraft),
    /// Delete the encrypted active-proof challenge cookie.
    DeleteActiveProofChallengeCookie,
    /// Issue or replace the encrypted active-proof continuation cookie.
    IssueActiveProofContinuationCookie(ActiveProofContinuationCookieDraft),
    /// Delete the encrypted active-proof continuation cookie.
    DeleteActiveProofContinuationCookie,
    /// Cycle the CSRF token after session identity or freshness changes.
    CycleCsrfToken {
        /// Session id to bind to, or `None` when logging out.
        session_id: Option<SessionId>,
    },
}

/// Durable effect command committed atomically before external delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableEffectCommand {
    /// Send an out-of-band message through an adapter after commit.
    SendOutOfBandMessage(OutOfBandMessageCommand),
    /// Notify the user or security log about a significant auth event.
    NotifySecurityEvent(SecurityNotificationCommand),
}

/// Out-of-band message command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutOfBandMessageCommand {
    /// Challenge whose proof material should be delivered.
    pub challenge_id: ActiveProofChallengeId,
    /// Adapter-specific proof method label, such as `email_otp`.
    pub proof_method_label: String,
    /// Opaque recipient handle understood by the adapter.
    pub recipient_handle: String,
    /// Idempotency key the adapter must use to avoid duplicate sends.
    pub idempotency_key: String,
    /// Delivery command expiration.
    pub expires_at: UnixSeconds,
}

/// Security notification command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityNotificationCommand {
    /// Stable notification kind.
    pub kind: SecurityNotificationKind,
    /// Subject id to notify.
    pub subject_id: SubjectId,
}

/// Core-owned security notification kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityNotificationKind {
    /// A trusted-device credential was created.
    TrustedDeviceCreated,
}
