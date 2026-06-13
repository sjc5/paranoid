use super::prelude::*;

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
    /// Plan credential replacement from loaded lifecycle authority policy.
    PlanCredentialReplacement(PlanCredentialReplacement),
    /// Execute an authorized credential replacement and atomically apply method-owned replacement work.
    ExecuteCredentialReplacement(ExecuteCredentialReplacement),
    /// Plan credential removal from loaded lifecycle authority policy.
    PlanCredentialRemoval(PlanCredentialRemoval),
    /// Execute an authorized credential removal.
    ExecuteCredentialRemoval(ExecuteCredentialRemoval),
    /// Plan credential-set regeneration from loaded lifecycle authority policy.
    PlanCredentialRegeneration(PlanCredentialRegeneration),
    /// Execute an authorized credential-set regeneration and atomically apply method-owned work.
    ExecuteCredentialRegeneration(ExecuteCredentialRegeneration),
    /// Execute an authorized credential rotation and atomically apply method-owned rotation work.
    ExecuteCredentialRotation(ExecuteCredentialRotation),
    /// Cancel an open delayed credential reset action.
    CancelPendingCredentialReset(CancelPendingCredentialReset),
    /// Add a new active credential instance after lifecycle policy authorizes creation.
    AddCredential(AddCredential),
    /// Execute a delayed non-reset credential lifecycle action.
    ExecuteNonResetPendingCredentialLifecycleAction(
        ExecuteNonResetPendingCredentialLifecycleAction,
    ),
    /// Cancel an open delayed non-reset credential lifecycle action.
    CancelNonResetPendingCredentialLifecycleAction(CancelNonResetPendingCredentialLifecycleAction),
    /// Request a support/admin intervention for one credential lifecycle action.
    RequestAdminSupportIntervention(RequestAdminSupportIntervention),
    /// Approve a support/admin intervention and convert it into lifecycle work.
    ApproveAdminSupportIntervention(ApproveAdminSupportIntervention),
    /// Deny a support/admin intervention without mutating credentials.
    DenyAdminSupportIntervention(DenyAdminSupportIntervention),
    /// Expire a support/admin intervention without mutating credentials.
    ExpireAdminSupportIntervention(ExpireAdminSupportIntervention),
    /// Plan credential lifecycle work from a verified admin/support intervention.
    PlanAdminSupportCredentialLifecycleIntervention(
        PlanAdminSupportCredentialLifecycleIntervention,
    ),
    /// Schedule delayed deletion of one subject's Paranoid-owned auth state.
    ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion),
    /// Execute a matured delayed subject-auth-state deletion action.
    ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion),
    /// Cancel an open delayed subject-auth-state deletion action.
    CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion),
    /// Execute a matured delayed out-of-band identifier change action.
    ExecutePendingOutOfBandIdentifierChange(ExecutePendingOutOfBandIdentifierChange),
    /// Cancel an open delayed out-of-band identifier change action.
    CancelPendingOutOfBandIdentifierChange(CancelPendingOutOfBandIdentifierChange),
    /// Plan an authenticated out-of-band identifier binding change.
    PlanOutOfBandIdentifierChange(PlanOutOfBandIdentifierChange),
    /// Reserve a proven candidate out-of-band identifier binding for later lifecycle execution.
    ReserveOutOfBandIdentifierChangeCandidateBinding(
        ReserveOutOfBandIdentifierChangeCandidateBinding,
    ),
    /// Execute an authorized out-of-band identifier binding change.
    ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange),
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
            Self::PlanCredentialReplacement(command) => command.now,
            Self::ExecuteCredentialReplacement(command) => command.now,
            Self::PlanCredentialRemoval(command) => command.now,
            Self::ExecuteCredentialRemoval(command) => command.now,
            Self::PlanCredentialRegeneration(command) => command.now,
            Self::ExecuteCredentialRegeneration(command) => command.now,
            Self::ExecuteCredentialRotation(command) => command.now,
            Self::CancelPendingCredentialReset(command) => command.now,
            Self::AddCredential(command) => command.now,
            Self::ExecuteNonResetPendingCredentialLifecycleAction(command) => command.now,
            Self::CancelNonResetPendingCredentialLifecycleAction(command) => command.now,
            Self::RequestAdminSupportIntervention(command) => command.now,
            Self::ApproveAdminSupportIntervention(command) => command.now,
            Self::DenyAdminSupportIntervention(command) => command.now,
            Self::ExpireAdminSupportIntervention(command) => command.now,
            Self::PlanAdminSupportCredentialLifecycleIntervention(command) => command.now,
            Self::ScheduleSubjectAuthStateDeletion(command) => command.now,
            Self::ExecutePendingSubjectAuthStateDeletion(command) => command.now,
            Self::CancelPendingSubjectAuthStateDeletion(command) => command.now,
            Self::ExecutePendingOutOfBandIdentifierChange(command) => command.now,
            Self::CancelPendingOutOfBandIdentifierChange(command) => command.now,
            Self::PlanOutOfBandIdentifierChange(command) => command.now,
            Self::ReserveOutOfBandIdentifierChangeCandidateBinding(command) => command.now,
            Self::ExecuteOutOfBandIdentifierChange(command) => command.now,
        }
    }

    pub(crate) fn direct_web_runtime_rejection(&self) -> Option<Error> {
        match self {
            Self::ResolveRequest(_) => {
                Some(Error::RequestResolutionRequiresRuntimeFreshIdGeneration)
            }
            Self::StartActiveProofAttempt(_)
            | Self::StartActiveProofAttemptForCurrentSession(_)
            | Self::StartActiveProofAttemptForCurrentTrustedDevice(_) => {
                Some(Error::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration)
            }
            Self::IssueActiveProofMethodChallenge(_) => {
                Some(Error::ActiveProofMethodChallengeIssueRequiresRuntimeMethodDispatch)
            }
            Self::IssueOutOfBandChallenge(_) => {
                Some(Error::OutOfBandChallengeIssueRequiresRuntimeCookieConstruction)
            }
            Self::ResendOutOfBandChallenge(_) => {
                Some(Error::OutOfBandChallengeResendRequiresRuntimeMethodDispatch)
            }
            Self::CompleteActiveProofChallenge(_) => {
                Some(Error::ActiveProofCompletionRequiresRuntimeMethodDispatch)
            }
            Self::RecordActiveProofFailure(_) => {
                Some(Error::ActiveProofFailureRequiresRuntimeMethodDispatch)
            }
            Self::CompleteFullAuthentication(_) => {
                Some(Error::FullAuthenticationCompletionRequiresRuntimeFreshIdGeneration)
            }
            Self::CompleteStepUp(_) => {
                Some(Error::StepUpCompletionRequiresRuntimeAttemptContinuation)
            }
            Self::CompleteTrustedDeviceRevivalWithActiveProof(_) => {
                Some(Error::TrustedDeviceRevivalCompletionRequiresRuntimeFreshIdGeneration)
            }
            Self::PlanCredentialReset(_) => {
                Some(Error::CredentialResetPlanningRequiresRuntimeLifecycleDecision)
            }
            Self::ExecuteCredentialReset(_) => {
                Some(Error::CredentialResetExecutionRequiresRuntimeMethodDispatch)
            }
            Self::PlanCredentialReplacement(_) => {
                Some(Error::CredentialReplacementPlanningRequiresRuntimeLifecycleDecision)
            }
            Self::ExecuteCredentialReplacement(_) => {
                Some(Error::CredentialReplacementExecutionRequiresRuntimeMethodDispatch)
            }
            Self::PlanCredentialRemoval(_) => {
                Some(Error::CredentialRemovalPlanningRequiresRuntimeLifecycleDecision)
            }
            Self::ExecuteCredentialRemoval(_) => {
                Some(Error::CredentialRemovalExecutionRequiresRuntimeLifecycleDecision)
            }
            Self::PlanCredentialRegeneration(_) => {
                Some(Error::CredentialRegenerationPlanningRequiresRuntimeLifecycleDecision)
            }
            Self::ExecuteCredentialRegeneration(_) => {
                Some(Error::CredentialRegenerationExecutionRequiresRuntimeMethodDispatch)
            }
            Self::ExecuteCredentialRotation(_) => {
                Some(Error::CredentialRotationExecutionRequiresRuntimeMethodDispatch)
            }
            Self::CancelPendingCredentialReset(_) => {
                Some(Error::CredentialResetCancellationRequiresRuntimeLifecycleDecision)
            }
            Self::AddCredential(_) => Some(Error::CredentialAdditionRequiresRuntimeMethodDispatch),
            Self::ExecuteNonResetPendingCredentialLifecycleAction(_) => {
                Some(Error::CredentialLifecycleExecutionRequiresRuntimeMethodDispatch)
            }
            Self::CancelNonResetPendingCredentialLifecycleAction(_) => {
                Some(Error::CredentialLifecycleCancellationRequiresRuntimeLifecycleDecision)
            }
            Self::RequestAdminSupportIntervention(_)
            | Self::ApproveAdminSupportIntervention(_)
            | Self::DenyAdminSupportIntervention(_)
            | Self::ExpireAdminSupportIntervention(_) => {
                Some(Error::AdminSupportInterventionWorkflowRequiresRuntimeLifecycleDecision)
            }
            Self::PlanAdminSupportCredentialLifecycleIntervention(_) => {
                Some(Error::AdminSupportInterventionPlanningRequiresRuntimeLifecycleDecision)
            }
            Self::ScheduleSubjectAuthStateDeletion(_) => {
                Some(Error::SubjectAuthStateDeletionSchedulingRequiresRuntimeLifecycleDecision)
            }
            Self::ExecutePendingSubjectAuthStateDeletion(_) => {
                Some(Error::SubjectAuthStateDeletionExecutionRequiresRuntimeLifecycleDecision)
            }
            Self::CancelPendingSubjectAuthStateDeletion(_) => {
                Some(Error::SubjectAuthStateDeletionCancellationRequiresRuntimeLifecycleDecision)
            }
            Self::ExecutePendingOutOfBandIdentifierChange(_)
            | Self::CancelPendingOutOfBandIdentifierChange(_) => {
                Some(Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision)
            }
            Self::PlanOutOfBandIdentifierChange(_) => {
                Some(Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision)
            }
            Self::ReserveOutOfBandIdentifierChangeCandidateBinding(_) => {
                Some(Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision)
            }
            Self::ExecuteOutOfBandIdentifierChange(_) => {
                Some(Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision)
            }
            Self::LogoutCurrentSession(_)
            | Self::RevokeSession(_)
            | Self::RevokeTrustedDevice(_)
            | Self::RevokeSubjectAuthState(_) => None,
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
    /// Active-proof attempt consumed by this reset plan, if delayed recovery scheduling used a recovery proof.
    pub active_proof_attempt_to_close: Option<ActiveProofAttemptRecord>,
    /// Whether immediate reset requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
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

/// Credential reset execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteCredentialReset {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Authority that allows this reset to execute.
    pub execution_authority: CredentialResetExecutionAuthority,
    /// Active-proof attempt consumed by this reset execution, if execution used a recovery proof.
    pub active_proof_attempt_to_close: Option<ActiveProofAttemptRecord>,
    /// Method/plugin work that mutates the target credential verifier.
    pub method_commit_work: Vec<MethodCommitWork>,
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

/// Method-specific payload supplied to a registered plugin for credential creation.
#[derive(Clone, Eq, PartialEq)]
pub struct CredentialCreationMethodPayload(Vec<u8>);

impl CredentialCreationMethodPayload {
    /// Creates a bounded opaque credential-creation payload.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Ok(Self(bounded_non_empty_method_payload_bytes(
            "credential creation method payload",
            bytes.into(),
            Error::EmptyCredentialCreationMethodPayload,
        )?))
    }

    /// Returns the opaque credential-creation payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CredentialCreationMethodPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCreationMethodPayload").finish()
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
}

/// Runtime-facing authenticated credential reset planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAuthenticatedCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to reset.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Runtime-facing unauthenticated delayed credential reset scheduling input for one configured method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Configured credential method to reset for the recovered subject.
    pub target_method: ProofMethodDeclaration,
}

/// Runtime-facing unauthenticated immediate credential reset execution input for one configured method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Configured credential method to reset for the recovered subject.
    pub target_method: ProofMethodDeclaration,
    /// Method-specific reset payload.
    pub method_payload: CredentialResetMethodPayload,
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
}

/// Credential replacement planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCredentialReplacement {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate replacement requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
}

/// Credential replacement execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteCredentialReplacement {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Authority that allows this replacement to execute immediately.
    pub execution_authority: CredentialReplacementExecutionAuthority,
    /// Core-visible successor credential created by this replacement.
    pub successor: CredentialReplacementSuccessor,
    /// Method/plugin work that replaces the target credential verifier or secret state.
    pub method_commit_work: Vec<MethodCommitWork>,
}

/// Core-visible successor created by a credential replacement transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReplacementSuccessor {
    metadata: CredentialInstanceMetadata,
    recovery_authorities: Vec<CredentialRecoveryAuthority>,
    authority_ids: Vec<RecoveryAuthorityId>,
}

impl CredentialReplacementSuccessor {
    /// Creates successor credential state for a replacement transition.
    pub fn new(
        metadata: CredentialInstanceMetadata,
        recovery_authorities: impl IntoIterator<Item = CredentialRecoveryAuthority>,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        let recovery_authorities = recovery_authorities.into_iter().collect::<Vec<_>>();
        CredentialRecoveryAuthorityGraph::new(recovery_authorities.clone())?;
        let authority_ids = authority_ids.into_iter().collect::<Vec<_>>();
        LifecycleAuthorityEvidence::from_verified_proof_source(
            metadata.verified_proof_source(),
            authority_ids.clone(),
        )?;
        Ok(Self {
            metadata,
            recovery_authorities,
            authority_ids,
        })
    }

    /// Creates an active successor that inherits the target credential's core-visible policy.
    pub fn inheriting_target_policy(
        credential_instance_id: VerifiedProofSourceId,
        target: &CredentialInstanceMetadata,
        target_recovery_authorities: impl IntoIterator<Item = CredentialRecoveryAuthority>,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        let metadata = CredentialInstanceMetadata::new(
            credential_instance_id,
            target.subject_id().clone(),
            target.kind(),
            target.method_label(),
            target.reset_policy_role(),
            CredentialLifecycleState::Active,
        )?;
        let recovery_authorities = target_recovery_authorities
            .into_iter()
            .map(|authority| {
                CredentialRecoveryAuthority::new(
                    metadata.credential_instance_id().clone(),
                    authority.action(),
                    authority.authority_id().clone(),
                    authority.timing(),
                )
            })
            .collect::<Vec<_>>();
        Self::new(metadata, recovery_authorities, authority_ids)
    }

    /// Returns the successor credential metadata.
    pub const fn metadata(&self) -> &CredentialInstanceMetadata {
        &self.metadata
    }

    /// Returns recovery authorities to persist for the successor.
    pub fn recovery_authorities(&self) -> &[CredentialRecoveryAuthority] {
        &self.recovery_authorities
    }

    /// Returns effective authorities represented by proofs from the successor credential.
    pub fn authority_ids(&self) -> &[RecoveryAuthorityId] {
        &self.authority_ids
    }

    pub(crate) fn authority_evidence(&self) -> Result<LifecycleAuthorityEvidence, Error> {
        LifecycleAuthorityEvidence::from_verified_proof_source(
            self.metadata.verified_proof_source(),
            self.authority_ids.clone(),
        )
    }
}

/// Authority source for executing an immediate credential replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReplacementExecutionAuthority {
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate replacement requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
}

/// Runtime-facing authenticated credential replacement planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAuthenticatedCredentialReplacementInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to replace.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Runtime-facing authenticated credential replacement execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedCredentialReplacementInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to replace.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Method-specific replacement payload.
    pub method_payload: CredentialLifecycleMethodPayload,
}

/// Credential removal planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCredentialRemoval {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate removal requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
}

/// Credential removal execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteCredentialRemoval {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Authority that allows this removal to execute immediately.
    pub execution_authority: CredentialRemovalExecutionAuthority,
}

/// Authority source for executing an immediate credential removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRemovalExecutionAuthority {
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate removal requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
}

/// Runtime-facing authenticated credential removal planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAuthenticatedCredentialRemovalInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to remove.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Runtime-facing authenticated credential removal execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedCredentialRemovalInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to remove.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Credential-set regeneration planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanCredentialRegeneration {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate regeneration authorization requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
}

/// Runtime-facing authenticated credential-set regeneration planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAuthenticatedCredentialRegenerationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance whose credential set will be regenerated.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Credential-set regeneration execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteCredentialRegeneration {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Authority that allows this regeneration to execute immediately.
    pub execution_authority: CredentialRegenerationExecutionAuthority,
    /// Method/plugin work that regenerates the target credential set.
    pub method_commit_work: Vec<MethodCommitWork>,
}

/// Authority source for executing immediate credential-set regeneration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRegenerationExecutionAuthority {
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate regeneration requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
}

/// Runtime-facing authenticated credential-set regeneration execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedCredentialRegenerationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance whose credential set will be regenerated.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Method-specific regeneration payload for the target credential's registered method.
    pub method_payload: CredentialLifecycleMethodPayload,
}

/// Credential rotation execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteCredentialRotation {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Authority that allows this rotation to execute immediately.
    pub execution_authority: CredentialRotationExecutionAuthority,
    /// Method/plugin work that rotates the target credential verifier or secret state.
    pub method_commit_work: Vec<MethodCommitWork>,
}

/// Authority source for executing an immediate credential rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotationExecutionAuthority {
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate rotation requires an independent proof source.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
}

/// Runtime-facing authenticated credential rotation execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedCredentialRotationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Credential instance to rotate.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Method-specific rotation payload for the target credential's registered method.
    pub method_payload: CredentialLifecycleMethodPayload,
}

/// Recovery-authority rule for a credential being added by the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAdditionRecoveryAuthorityRule {
    /// Lifecycle action this authority can perform for the new credential.
    pub action: CredentialLifecycleAction,
    /// Effective authority id.
    pub authority_id: RecoveryAuthorityId,
    /// Whether this authority is immediate or delayed for this action.
    pub timing: RecoveryAuthorityTiming,
}

impl CredentialAdditionRecoveryAuthorityRule {
    pub(crate) fn into_authority(
        self,
        target_credential_instance_id: VerifiedProofSourceId,
    ) -> CredentialRecoveryAuthority {
        CredentialRecoveryAuthority::new(
            target_credential_instance_id,
            self.action,
            self.authority_id,
            self.timing,
        )
    }
}

/// Runtime-facing authenticated credential addition input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedCredentialAdditionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Method that will own the new credential.
    pub method: ProofMethodDeclaration,
    /// Reset policy role assigned to the new credential.
    pub reset_policy_role: CredentialResetPolicyRole,
    /// Recovery-authority graph to persist for the new credential.
    pub recovery_authority_rules: Vec<CredentialAdditionRecoveryAuthorityRule>,
    /// Recovery authority ids represented by proofs produced by the new credential.
    pub new_credential_authority_ids: Vec<RecoveryAuthorityId>,
    /// Method-specific creation payload.
    pub method_payload: CredentialCreationMethodPayload,
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

/// Add a new active credential instance and atomically create its method-owned verifier state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddCredential {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded lifecycle-policy context for the new credential's creation.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate creation requires independent evidence.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Recovery authority ids represented by proofs produced by the new credential.
    pub new_credential_authority_ids: Vec<RecoveryAuthorityId>,
    /// Method/plugin work that creates the credential verifier or secret state.
    pub method_commit_work: Vec<MethodCommitWork>,
}

/// Support/admin intervention request command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestAdminSupportIntervention {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Runtime-generated intervention id.
    pub intervention_id: AdminSupportInterventionId,
    /// Subject this intervention may affect.
    pub subject_id: SubjectId,
    /// Credential this intervention may affect.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Credential lifecycle action this intervention may authorize.
    pub action: CredentialLifecycleAction,
    /// Last time this intervention may be approved or denied.
    pub expires_at: UnixSeconds,
}

/// Plan credential lifecycle work from a verified admin/support intervention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAdminSupportCredentialLifecycleIntervention {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Runtime-verified admin/support intervention.
    pub intervention: VerifiedAdminSupportCredentialLifecycleIntervention,
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate support intervention requires independent evidence.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
}

/// Approve a stored support/admin intervention and enter the lifecycle policy boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveAdminSupportIntervention {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded support/admin intervention record.
    pub intervention: AdminSupportInterventionRecord,
    /// Loaded lifecycle-policy context for the target credential.
    pub lifecycle_context: CredentialLifecycleActionContext,
    /// Whether immediate support intervention requires independent evidence.
    pub independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingCredentialLifecycleActionSchedule>,
}

/// Deny a stored support/admin intervention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyAdminSupportIntervention {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded support/admin intervention record.
    pub intervention: AdminSupportInterventionRecord,
}

/// Expire a stored support/admin intervention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpireAdminSupportIntervention {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded support/admin intervention record.
    pub intervention: AdminSupportInterventionRecord,
}

/// Runtime-facing support/admin intervention request input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestAdminSupportInterventionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Subject this intervention may affect.
    pub subject_id: SubjectId,
    /// Credential this intervention may affect.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Credential lifecycle action this intervention may authorize.
    pub action: CredentialLifecycleAction,
}

/// Runtime-facing support/admin intervention approval input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveAdminSupportInterventionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Intervention to approve.
    pub intervention_id: AdminSupportInterventionId,
}

/// Runtime-facing support/admin intervention denial input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyAdminSupportInterventionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Intervention to deny.
    pub intervention_id: AdminSupportInterventionId,
}

/// Runtime-facing support/admin intervention expiry input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpireAdminSupportInterventionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Intervention to expire.
    pub intervention_id: AdminSupportInterventionId,
}

/// Runtime-facing authenticated pending credential reset cancellation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAuthenticatedPendingCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to cancel.
    pub pending_action_id: PendingCredentialLifecycleActionId,
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
    /// Successor credential state required by delayed replacement execution.
    pub replacement_successor: Option<CredentialReplacementSuccessor>,
    /// Method/plugin work required by replacement or regeneration actions.
    pub method_commit_work: Vec<MethodCommitWork>,
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
    /// Optional mounted app-owned data action to commit with auth-state deletion.
    pub application_subject_data_lifecycle_action: Option<ApplicationSubjectDataLifecycleAction>,
}

/// Cancel an open delayed subject-auth-state deletion action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelPendingSubjectAuthStateDeletion {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded pending action row to close.
    pub pending_action: PendingSubjectLifecycleActionRecord,
}

/// Execute a matured delayed out-of-band identifier change action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutePendingOutOfBandIdentifierChange {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded pending action row.
    pub pending_action: PendingSubjectLifecycleActionRecord,
}

/// Cancel an open delayed out-of-band identifier change action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelPendingOutOfBandIdentifierChange {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded pending action row to close.
    pub pending_action: PendingSubjectLifecycleActionRecord,
}

/// Runtime-facing authenticated subject auth-state deletion scheduling input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleAuthenticatedSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Runtime-facing matured pending subject auth-state deletion execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteMaturePendingSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to execute.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// Optional mounted app-owned data action to commit with auth-state deletion.
    pub application_subject_data_lifecycle_action: Option<ApplicationSubjectDataLifecycleAction>,
}

/// Runtime-facing authenticated pending subject auth-state deletion cancellation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to cancel.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

/// Runtime-facing matured pending out-of-band identifier change execution input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteMaturePendingOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to execute.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

/// Runtime-facing authenticated pending out-of-band identifier change cancellation input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Pending action to cancel.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

/// Runtime-facing authenticated out-of-band identifier change planning input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanAuthenticatedOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active identifier source being replaced or superseded.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Proven pending candidate identifier source to activate later.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

/// Runtime-facing authenticated immediate out-of-band identifier change input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteAuthenticatedOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active identifier source being replaced or superseded.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Proven pending candidate identifier source to activate.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

/// Plan an authorized out-of-band identifier binding change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanOutOfBandIdentifierChange {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded policy and binding context for the identifier change.
    pub change_context: OutOfBandIdentifierChangeContext,
    /// Whether immediate identifier change requires independent evidence.
    pub independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement,
    /// Effective recovery authorities represented by the candidate source after activation.
    pub candidate_authority_ids: Vec<RecoveryAuthorityId>,
    /// Pending-action schedule to use if policy requires delayed execution.
    pub pending_action: Option<PendingSubjectLifecycleActionSchedule>,
}

/// Reserve a pending out-of-band identifier binding after the candidate endpoint is proven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveOutOfBandIdentifierChangeCandidateBinding {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Subject-bound active-proof attempt proving candidate reachability.
    pub attempt_id: ActiveProofAttemptId,
    /// Out-of-band challenge completed by the candidate endpoint.
    pub challenge_id: ActiveProofChallengeId,
    /// Verified out-of-band proof source representing the candidate endpoint.
    pub candidate_identifier_source: VerifiedProofSource,
    /// Whether required stateless fast-fail verification happened before state was loaded.
    pub stateless_fast_fail: StatelessFastFailStatus,
    /// Whether the configured weak-proof gate was verified before state was loaded.
    pub weak_proof_gate: WeakProofGateStatus,
    /// Method/plugin work that must commit atomically with accepting this candidate proof.
    pub(super) method_commit_work: Vec<MethodCommitWork>,
}

/// Execute an authorized out-of-band identifier binding change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteOutOfBandIdentifierChange {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Loaded policy and binding context for the identifier change.
    pub change_context: OutOfBandIdentifierChangeContext,
    /// Whether immediate identifier change requires independent evidence.
    pub independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement,
    /// Effective recovery authorities the candidate source should represent after activation.
    pub candidate_authority_ids: Vec<RecoveryAuthorityId>,
}
