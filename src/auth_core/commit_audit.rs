use super::*;

/// Audit event committed with auth mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    /// Kind of event.
    pub kind: AuditEventKind,
    /// Subject id associated with the event, if known.
    pub subject_id: Option<SubjectId>,
    /// Session id associated with the event, if any.
    pub session_id: Option<SessionId>,
    /// Trusted-device credential id associated with the event, if any.
    pub device_credential_id: Option<TrustedDeviceCredentialId>,
    /// Active-proof attempt id associated with the event, if any.
    pub attempt_id: Option<ActiveProofAttemptId>,
    /// Active-proof challenge id associated with the event, if any.
    pub challenge_id: Option<ActiveProofChallengeId>,
    /// Weak-proof gate that was verified for the event, if any.
    pub weak_proof_gate: Option<WeakProofGateSummary>,
    /// Event timestamp.
    pub occurred_at: UnixSeconds,
}

/// Audit event kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditEventKind {
    /// A session was created.
    SessionCreated,
    /// A session was refreshed.
    SessionRefreshed,
    /// A trusted device silently revived a session.
    TrustedDeviceSilentRevival,
    /// A trusted device plus active proof revived a session.
    TrustedDeviceActiveProofRevival,
    /// A trusted device was created.
    TrustedDeviceCreated,
    /// A trusted-device credential was rotated.
    TrustedDeviceRotated,
    /// A session received fresh step-up proof.
    StepUpCompleted,
    /// A credential mismatch was observed.
    CredentialMismatch,
    /// A session was revoked.
    SessionRevoked,
    /// A trusted-device credential was revoked.
    TrustedDeviceRevoked,
    /// Subject-wide auth state was revoked.
    SubjectAuthStateRevoked,
    /// An active-proof attempt was started.
    ActiveProofAttemptStarted,
    /// A method-specific active-proof challenge was issued.
    ActiveProofMethodChallengeIssued,
    /// An out-of-band challenge was issued.
    OutOfBandChallengeIssued,
    /// An out-of-band challenge was queued for another delivery.
    OutOfBandChallengeResent,
    /// An active proof failed.
    ActiveProofFailed,
    /// An active proof succeeded.
    ActiveProofSucceeded,
    /// An active-proof attempt was closed by a successful auth transition.
    ActiveProofAttemptClosed,
    /// An active-proof attempt was hard-deleted after weak proof failures.
    ActiveProofAttemptDeletedAfterWeakProofFailures,
    /// A credential reset was authorized for immediate execution.
    CredentialResetAuthorized,
    /// A delayed credential reset action was scheduled.
    CredentialResetPendingActionScheduled,
    /// A credential reset was executed.
    CredentialResetExecuted,
    /// A delayed credential reset action was cancelled.
    CredentialResetPendingActionCancelled,
    /// A delayed credential replacement action was executed.
    CredentialReplacementExecuted,
    /// A delayed credential replacement action was cancelled.
    CredentialReplacementPendingActionCancelled,
    /// A delayed credential removal action was executed.
    CredentialRemovalExecuted,
    /// A delayed credential removal action was cancelled.
    CredentialRemovalPendingActionCancelled,
    /// A delayed credential-set regeneration action was executed.
    CredentialRegenerationExecuted,
    /// A delayed credential-set regeneration action was cancelled.
    CredentialRegenerationPendingActionCancelled,
}
