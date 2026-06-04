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
    /// Plan a credential reset from loaded lifecycle authority policy.
    PlanCredentialReset(PlanCredentialReset),
    /// Execute an authorized credential reset and atomically apply method-owned verifier work.
    ExecuteCredentialReset(ExecuteCredentialReset),
    /// Cancel an open delayed credential reset action.
    CancelPendingCredentialReset(CancelPendingCredentialReset),
    /// Execute a delayed non-reset credential lifecycle action.
    ExecuteNonResetPendingCredentialLifecycleAction(
        ExecuteNonResetPendingCredentialLifecycleAction,
    ),
    /// Cancel an open delayed non-reset credential lifecycle action.
    CancelNonResetPendingCredentialLifecycleAction(CancelNonResetPendingCredentialLifecycleAction),
    /// Schedule delayed deletion of one subject's Paranoid-owned auth state.
    ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion),
    /// Execute a matured delayed subject-auth-state deletion action.
    ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion),
    /// Cancel an open delayed subject-auth-state deletion action.
    CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion),
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
            Self::PlanCredentialReset(command) => command.now,
            Self::ExecuteCredentialReset(command) => command.now,
            Self::CancelPendingCredentialReset(command) => command.now,
            Self::ExecuteNonResetPendingCredentialLifecycleAction(command) => command.now,
            Self::CancelNonResetPendingCredentialLifecycleAction(command) => command.now,
            Self::ScheduleSubjectAuthStateDeletion(command) => command.now,
            Self::ExecutePendingSubjectAuthStateDeletion(command) => command.now,
            Self::CancelPendingSubjectAuthStateDeletion(command) => command.now,
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

/// Credential reset planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCredentialReset {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Active-proof attempt consumed by this reset plan, if planning used a recovery proof.
    pub active_proof_attempt_to_close: Option<ActiveProofAttemptRecord>,
    /// Whether immediate reset requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
    /// Existing auth-state revocation policy for the immediate-reset branch.
    pub immediate_subject_auth_revocation: CredentialResetSubjectAuthRevocation,
}

/// Fresh pending-action material supplied by the runtime for delayed credential reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCredentialLifecycleActionSchedule {
    /// Fresh pending action id.
    pub pending_action_id: PendingCredentialLifecycleActionId,
    /// Earliest time this delayed action may execute.
    pub earliest_execute_at: UnixSeconds,
    /// Last time this delayed action remains executable.
    pub expires_at: UnixSeconds,
}

/// Delayed credential reset timing supplied to a runtime facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialResetPendingActionTiming {
    /// Earliest time this delayed action may execute.
    pub earliest_execute_at: UnixSeconds,
    /// Last time this delayed action remains executable.
    pub expires_at: UnixSeconds,
}

/// Credential reset execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteCredentialReset {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Authority that allows this reset to execute.
    pub execution_authority: CredentialResetExecutionAuthority,
    /// Method/plugin work that mutates the target credential verifier.
    pub method_commit_work: Vec<MethodCommitWork>,
    /// Existing auth-state revocation policy after the reset executes.
    pub subject_auth_revocation: CredentialResetSubjectAuthRevocation,
}

/// Authority source for executing a credential reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialResetExecutionAuthority {
    /// The current ceremony has immediate lifecycle authority.
    Immediate {
        /// Loaded lifecycle-policy context for the target credential.
        lifecycle_context: CredentialLifecycleActionContext,
        /// Whether immediate reset requires an independent proof source.
        independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    },
    /// A previously scheduled pending action has matured.
    MaturePendingAction {
        /// Loaded target credential metadata.
        target_credential: CredentialInstanceMetadata,
        /// Loaded pending action row.
        pending_action: PendingCredentialLifecycleActionRecord,
    },
}

/// Method-specific credential reset payload supplied to a registered method plugin.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialResetMethodPayload(Vec<u8>);

impl CredentialResetMethodPayload {
    /// Creates a bounded opaque reset payload.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Ok(Self(bounded_non_empty_method_payload_bytes(
            "credential reset method payload",
            bytes.into(),
            Error::EmptyCredentialResetMethodPayload,
        )?))
    }

    /// Returns the opaque reset payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CredentialResetMethodPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialResetMethodPayload").finish()
    }
}

/// Method-specific payload supplied to a registered plugin for delayed lifecycle execution.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialLifecycleMethodPayload(Vec<u8>);

impl CredentialLifecycleMethodPayload {
    /// Creates a bounded opaque lifecycle payload.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Ok(Self(bounded_non_empty_method_payload_bytes(
            "credential lifecycle method payload",
            bytes.into(),
            Error::EmptyCredentialLifecycleMethodPayload,
        )?))
    }

    /// Returns the opaque lifecycle payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CredentialLifecycleMethodPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialLifecycleMethodPayload").finish()
    }
}

fn bounded_non_empty_method_payload_bytes(
    label: &'static str,
    bytes: Vec<u8>,
    empty_error: Error,
) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() {
        return Err(empty_error);
    }
    validate_auth_bytes_not_too_long(label, &bytes, METHOD_COMMIT_PAYLOAD_MAX_BYTES)?;
    Ok(bytes)
}

/// Runtime-facing authenticated credential reset execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to reset.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Method-specific reset payload.
    pub method_payload: CredentialResetMethodPayload,
    /// Whether immediate reset requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Existing auth-state revocation policy after the reset executes.
    pub subject_auth_revocation: CredentialResetSubjectAuthRevocation,
}

/// Runtime-facing authenticated credential reset planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAuthenticatedCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to reset.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Whether immediate reset requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Delayed-action timing to use if lifecycle policy requires delayed execution.
    pub pending_action_timing: Option<CredentialResetPendingActionTiming>,
    /// Existing auth-state revocation policy for the immediate-reset branch.
    pub immediate_subject_auth_revocation: CredentialResetSubjectAuthRevocation,
}

/// Runtime-facing unauthenticated credential reset planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanUnauthenticatedCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to reset.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Whether immediate reset requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Delayed-action timing to use if lifecycle policy requires delayed execution.
    pub pending_action_timing: Option<CredentialResetPendingActionTiming>,
    /// Existing auth-state revocation policy for the immediate-reset branch.
    pub immediate_subject_auth_revocation: CredentialResetSubjectAuthRevocation,
}

/// Runtime-facing matured pending credential reset execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteMaturePendingCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to execute.
    pub pending_action_id: PendingCredentialLifecycleActionId,
    /// Method-specific reset payload.
    pub method_payload: CredentialResetMethodPayload,
    /// Existing auth-state revocation policy after the reset executes.
    pub subject_auth_revocation: CredentialResetSubjectAuthRevocation,
}

/// Pending credential reset cancellation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelPendingCredentialReset {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded target credential metadata.
    pub target_credential: CredentialInstanceMetadata,
    /// Loaded pending action row to close.
    pub pending_action: PendingCredentialLifecycleActionRecord,
}

/// Runtime-facing authenticated pending credential reset cancellation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAuthenticatedPendingCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to cancel.
    pub pending_action_id: PendingCredentialLifecycleActionId,
}

/// Whether executing a credential lifecycle action should revoke existing auth state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialLifecycleSubjectAuthRevocation {
    /// Existing sessions/devices stay live after the lifecycle action.
    PreserveExistingAuthState,
    /// Existing sessions/devices are invalidated by subject-wide auth-state revocation.
    RevokeSubjectAuthState,
}

/// Delayed non-reset credential lifecycle action execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteNonResetPendingCredentialLifecycleAction {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded target credential metadata.
    pub target_credential: CredentialInstanceMetadata,
    /// Loaded pending action row.
    pub pending_action: PendingCredentialLifecycleActionRecord,
    /// Method/plugin work required by replacement or regeneration actions.
    pub method_commit_work: Vec<MethodCommitWork>,
    /// Auth-state revocation policy after the action executes.
    pub subject_auth_revocation: CredentialLifecycleSubjectAuthRevocation,
}

/// Delayed non-reset credential lifecycle action cancellation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelNonResetPendingCredentialLifecycleAction {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded target credential metadata.
    pub target_credential: CredentialInstanceMetadata,
    /// Loaded pending action row to close.
    pub pending_action: PendingCredentialLifecycleActionRecord,
}

/// Runtime-facing matured pending credential lifecycle execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteMaturePendingCredentialLifecycleActionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to execute.
    pub pending_action_id: PendingCredentialLifecycleActionId,
    /// Method-specific payload for replacement or regeneration actions.
    pub method_payload: Option<CredentialLifecycleMethodPayload>,
    /// Auth-state revocation policy after the action executes.
    pub subject_auth_revocation: CredentialLifecycleSubjectAuthRevocation,
}

/// Runtime-facing authenticated pending credential lifecycle cancellation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAuthenticatedPendingCredentialLifecycleActionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to cancel.
    pub pending_action_id: PendingCredentialLifecycleActionId,
}

/// Fresh pending-action material supplied by the runtime for delayed subject deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSubjectLifecycleActionSchedule {
    /// Fresh pending action id.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// Earliest time this delayed action may execute.
    pub earliest_execute_at: UnixSeconds,
    /// Last time this delayed action remains executable.
    pub expires_at: UnixSeconds,
}

/// Schedule delayed deletion of one subject's Paranoid-owned auth state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleSubjectAuthStateDeletion {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Subject whose auth state is scheduled for deletion.
    pub subject_id: SubjectId,
    /// Runtime-owned pending-action schedule.
    pub pending_action: PendingSubjectLifecycleActionSchedule,
}

/// Execute a matured delayed subject-auth-state deletion action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutePendingSubjectAuthStateDeletion {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded pending action row.
    pub pending_action: PendingSubjectLifecycleActionRecord,
}

/// Cancel an open delayed subject-auth-state deletion action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelPendingSubjectAuthStateDeletion {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded pending action row to close.
    pub pending_action: PendingSubjectLifecycleActionRecord,
}

/// Runtime-facing matured pending subject auth-state deletion execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteMaturePendingSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to execute.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

/// Runtime-facing authenticated pending subject auth-state deletion cancellation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to cancel.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}
