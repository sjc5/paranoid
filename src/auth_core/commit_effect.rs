use super::prelude::*;

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
    /// Ask the mounted application to apply subject data lifecycle work.
    ApplyApplicationSubjectDataLifecycle(ApplicationSubjectDataLifecycleCommand),
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

/// App-owned subject data lifecycle work committed by auth-state deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationSubjectDataLifecycleCommand {
    /// App-owned subject data action requested by the mounted auth flow.
    pub action: ApplicationSubjectDataLifecycleAction,
    /// Subject whose app-owned data should be updated.
    pub subject_id: SubjectId,
    /// Time the auth transition committed this durable request.
    pub requested_at: UnixSeconds,
}

/// App-owned subject data action requested after auth-state deletion commits.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApplicationSubjectDataLifecycleAction {
    /// Delete app-owned data associated with the subject.
    DeleteSubjectData,
    /// Disable app-owned data associated with the subject without deleting it.
    DisableSubjectData,
}

impl ApplicationSubjectDataLifecycleAction {
    /// Returns the stable Queue/application label for this action.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeleteSubjectData => "delete_subject_data",
            Self::DisableSubjectData => "disable_subject_data",
        }
    }
}

/// Core-owned security notification kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityNotificationKind {
    /// A trusted-device credential was created.
    TrustedDeviceCreated,
    /// A credential reset was authorized for immediate execution.
    CredentialResetAuthorized,
    /// A delayed credential reset action was scheduled.
    CredentialResetPendingActionScheduled,
    /// A credential reset was executed.
    CredentialResetExecuted,
    /// A delayed credential reset action was cancelled.
    CredentialResetPendingActionCancelled,
    /// A credential was added.
    CredentialAdded,
    /// A credential replacement was authorized for immediate execution.
    CredentialReplacementAuthorized,
    /// A delayed credential replacement action was scheduled.
    CredentialReplacementPendingActionScheduled,
    /// A credential replacement action was executed.
    CredentialReplacementExecuted,
    /// A delayed credential replacement action was cancelled.
    CredentialReplacementPendingActionCancelled,
    /// A credential removal was authorized for immediate execution.
    CredentialRemovalAuthorized,
    /// A delayed credential removal action was scheduled.
    CredentialRemovalPendingActionScheduled,
    /// A credential removal action was executed.
    CredentialRemovalExecuted,
    /// A delayed credential removal action was cancelled.
    CredentialRemovalPendingActionCancelled,
    /// A credential-set regeneration was authorized for immediate execution.
    CredentialRegenerationAuthorized,
    /// A delayed credential-set regeneration action was scheduled.
    CredentialRegenerationPendingActionScheduled,
    /// A delayed credential-set regeneration action was executed.
    CredentialRegenerationExecuted,
    /// A delayed credential-set regeneration action was cancelled.
    CredentialRegenerationPendingActionCancelled,
    /// A credential verifier or secret was rotated.
    CredentialRotated,
    /// A support/admin intervention was requested.
    AdminSupportInterventionRequested,
    /// A support/admin intervention was approved.
    AdminSupportInterventionApproved,
    /// A support/admin intervention was denied.
    AdminSupportInterventionDenied,
    /// A support/admin intervention expired.
    AdminSupportInterventionExpired,
    /// A support/admin intervention authorized credential lifecycle work immediately.
    AdminSupportCredentialLifecycleInterventionAuthorized,
    /// A support/admin intervention scheduled delayed credential lifecycle work.
    AdminSupportCredentialLifecycleInterventionPendingActionScheduled,
    /// A delayed subject-auth-state deletion action was scheduled.
    SubjectAuthStateDeletionPendingActionScheduled,
    /// A delayed subject-auth-state deletion action was executed.
    SubjectAuthStateDeletionExecuted,
    /// A delayed subject-auth-state deletion action was cancelled.
    SubjectAuthStateDeletionPendingActionCancelled,
    /// A delayed out-of-band identifier change action was scheduled.
    OutOfBandIdentifierChangePendingActionScheduled,
    /// A delayed out-of-band identifier change action was cancelled.
    OutOfBandIdentifierChangePendingActionCancelled,
    /// A subject's out-of-band identifier binding was changed.
    OutOfBandIdentifierChanged,
}
