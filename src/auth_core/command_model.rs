use super::*;

/// Whether a request can be authenticated from cached state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RequestKind {
    /// Read-only request eligible for bounded safe-read cache authentication.
    SafeRead,
    /// Mutating request that must not use a safe-read cache hit.
    StateChanging,
    /// Sensitive request requiring a fresh step-up proof in addition to a live session.
    Sensitive,
}

/// Command submitted to the auth core reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    /// Resolve request authentication state.
    ResolveRequest(ResolveRequest),
    /// Create an active-proof attempt for a future auth transition.
    StartActiveProofAttempt(StartActiveProofAttempt),
    /// Create an active-proof attempt bound to the currently presented session.
    StartActiveProofAttemptForCurrentSession(StartActiveProofAttemptForCurrentSession),
    /// Create an active-proof attempt bound to the currently presented trusted device.
    StartActiveProofAttemptForCurrentTrustedDevice(StartActiveProofAttemptForCurrentTrustedDevice),
    /// Create a method-specific active-proof challenge.
    IssueActiveProofMethodChallenge(IssueActiveProofMethodChallenge),
    /// Create and queue delivery for an out-of-band challenge.
    IssueOutOfBandChallenge(IssueOutOfBandChallenge),
    /// Queue another delivery for an existing out-of-band challenge.
    ResendOutOfBandChallenge(ResendOutOfBandChallenge),
    /// Complete one active-proof challenge after plugin verification.
    CompleteActiveProofChallenge(CompleteActiveProofChallenge),
    /// Record an active-proof failure and enforce weak-proof budgets.
    RecordActiveProofFailure(RecordActiveProofFailure),
    /// Create a session after the configured full-authentication policy has been satisfied.
    CompleteFullAuthentication(CompleteFullAuthentication),
    /// Mark a live session as freshly proven for sensitive operations.
    CompleteStepUp(CompleteStepUp),
    /// Create a session from a trusted device after an active proof for the same subject.
    CompleteTrustedDeviceRevivalWithActiveProof(CompleteTrustedDeviceRevivalWithActiveProof),
    /// Revoke the currently presented session and clear response-local auth state.
    LogoutCurrentSession(LogoutCurrentSession),
    /// Revoke a specific session after the app has authorized that operation.
    RevokeSession(RevokeSession),
    /// Revoke a specific trusted-device credential after the app has authorized that operation.
    RevokeTrustedDevice(RevokeTrustedDevice),
    /// Invalidate all auth state created at or before this timestamp for one subject.
    RevokeSubjectAuthState(RevokeSubjectAuthState),
}

impl Command {
    /// Returns the server time carried by this command.
    pub fn now(&self) -> UnixSeconds {
        match self {
            Self::ResolveRequest(command) => command.now,
            Self::StartActiveProofAttempt(command) => command.now,
            Self::StartActiveProofAttemptForCurrentSession(command) => command.now,
            Self::StartActiveProofAttemptForCurrentTrustedDevice(command) => command.now,
            Self::IssueActiveProofMethodChallenge(command) => command.now,
            Self::IssueOutOfBandChallenge(command) => command.now,
            Self::ResendOutOfBandChallenge(command) => command.now,
            Self::CompleteActiveProofChallenge(command) => command.now,
            Self::RecordActiveProofFailure(command) => command.now,
            Self::CompleteFullAuthentication(command) => command.now,
            Self::CompleteStepUp(command) => command.now,
            Self::CompleteTrustedDeviceRevivalWithActiveProof(command) => command.now,
            Self::LogoutCurrentSession(command) => command.now,
            Self::RevokeSession(command) => command.now,
            Self::RevokeTrustedDevice(command) => command.now,
            Self::RevokeSubjectAuthState(command) => command.now,
        }
    }
}

/// Request-resolution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveRequest {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Request class being resolved.
    pub request_kind: RequestKind,
    /// Fresh session id to use if trusted-device silent revival creates a session.
    pub fresh_session_id: Option<SessionId>,
}

/// Runtime-facing request-resolution input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolveRequestInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Request class being resolved.
    pub request_kind: RequestKind,
}

/// Full-authentication completion command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteFullAuthentication {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active-proof attempt that satisfied full authentication.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh session id for the new session.
    pub fresh_session_id: SessionId,
    /// Optional trusted device credential to create at the same atomic boundary.
    pub trust_device: Option<TrustDeviceAfterFullAuthentication>,
}

/// Runtime-facing full-authentication completion input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteFullAuthenticationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Optional trusted-device creation request.
    pub trust_device: Option<TrustDeviceAfterFullAuthenticationInput>,
}

/// Trusted-device creation data after full authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustDeviceAfterFullAuthentication {
    /// Fresh trusted-device credential id.
    pub device_credential_id: TrustedDeviceCredentialId,
    /// Display label captured by the adapter, such as a user-agent summary.
    pub display_label: Option<String>,
}

/// Runtime-facing trusted-device creation request after full authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustDeviceAfterFullAuthenticationInput {
    /// Display label captured by the adapter, such as a user-agent summary.
    pub display_label: Option<String>,
}

/// Step-up completion command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteStepUp {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active-proof attempt that satisfied step-up policy.
    pub attempt_id: ActiveProofAttemptId,
}

/// Runtime-facing step-up completion input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteStepUpInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Active-proof completion command for a trusted device past silent revival.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteTrustedDeviceRevivalWithActiveProof {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active-proof attempt that satisfied trusted-device revival.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh session id for the new session.
    pub fresh_session_id: SessionId,
}

/// Runtime-facing trusted-device active-proof revival input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteTrustedDeviceRevivalWithActiveProofInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Logout command for the currently presented session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutCurrentSession {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Specific-session revocation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeSession {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Subject that must own the session.
    pub subject_id: SubjectId,
    /// Session to revoke.
    pub session_id: SessionId,
    /// Revocation reason.
    pub reason: RevocationReason,
}

/// Specific trusted-device revocation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeTrustedDevice {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Subject that must own the trusted-device credential.
    pub subject_id: SubjectId,
    /// Trusted-device credential to revoke.
    pub device_credential_id: TrustedDeviceCredentialId,
    /// Revocation reason.
    pub reason: RevocationReason,
}

/// Subject-wide auth-state revocation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeSubjectAuthState {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Subject whose existing sessions and credentials should stop being valid.
    pub subject_id: SubjectId,
    /// Revocation reason.
    pub reason: RevocationReason,
}
