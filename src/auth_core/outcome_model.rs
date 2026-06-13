use super::prelude::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Transition {
    /// Semantic result of the command.
    pub(crate) outcome: Outcome,
    /// Atomic plan that must be committed before effects are applied.
    pub(crate) commit_plan: CommitPlan,
}

/// Semantic result of a reducer command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The request or command produced an authenticated session.
    Authenticated(Authenticated),
    /// A live session exists, but the request requires fresher proof.
    NeedsStepUp {
        /// Session id that needs fresh proof.
        session_id: SessionId,
        /// Subject id that owns the session.
        subject_id: SubjectId,
    },
    /// A valid trusted device exists, but silent revival is no longer allowed.
    NeedsActiveProofFromTrustedDevice {
        /// Trusted-device credential id.
        device_credential_id: TrustedDeviceCredentialId,
        /// Subject id that owns the trusted device.
        subject_id: SubjectId,
    },
    /// An active-proof attempt was started.
    ActiveProofAttemptStarted {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
    /// A method-specific active-proof challenge was created.
    ActiveProofMethodChallengeIssued {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Challenge id.
        challenge_id: ActiveProofChallengeId,
        /// Proof this challenge can satisfy.
        proof: ProofSummary,
        /// Method-specific public challenge material shown to the client.
        method_challenge: ActiveProofMethodChallengePresentation,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
    /// An out-of-band challenge was created and queued for delivery.
    OutOfBandChallengeIssued {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Challenge id.
        challenge_id: ActiveProofChallengeId,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
    /// An existing out-of-band challenge was queued for another delivery.
    OutOfBandChallengeResent {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Challenge id.
        challenge_id: ActiveProofChallengeId,
        /// Resend count after this transition.
        resend_count: u32,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
    /// An active proof was completed inside an attempt.
    ActiveProofCompleted {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Completed proof.
        proof: ProofSummary,
    },
    /// An active-proof failure was recorded.
    ActiveProofFailureRecorded {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Whether the attempt should be hard-deleted.
        attempt_was_deleted: bool,
    },
    /// No usable auth state was found.
    NeedsFullAuthentication,
    /// A revocation command produced a commit plan.
    RevocationPlanned(RevocationOutcome),
    /// A credential reset was authorized immediately or scheduled as a delayed action.
    CredentialResetPlanned(CredentialResetOutcome),
    /// A credential reset was executed.
    CredentialResetExecuted(CredentialResetExecutionOutcome),
    /// A credential replacement was authorized immediately or scheduled as a delayed action.
    CredentialReplacementPlanned(CredentialReplacementOutcome),
    /// An immediate credential replacement was executed.
    CredentialReplacementExecuted(CredentialReplacementExecutionOutcome),
    /// A credential removal was authorized immediately or scheduled as a delayed action.
    CredentialRemovalPlanned(CredentialRemovalOutcome),
    /// An immediate credential removal was executed.
    CredentialRemovalExecuted(CredentialRemovalExecutionOutcome),
    /// A credential-set regeneration was authorized immediately or scheduled as a delayed action.
    CredentialRegenerationPlanned(CredentialRegenerationOutcome),
    /// An immediate credential-set regeneration was executed.
    CredentialRegenerated(CredentialRegenerationExecutionOutcome),
    /// An immediate credential rotation was executed.
    CredentialRotated(CredentialRotationExecutionOutcome),
    /// A delayed credential reset was cancelled.
    CredentialResetPendingActionCancelled(CredentialResetCancellationOutcome),
    /// A credential was added.
    CredentialAdded(CredentialAdditionOutcome),
    /// A delayed non-reset credential lifecycle action was executed.
    NonResetPendingCredentialLifecycleActionExecuted(
        NonResetPendingCredentialLifecycleActionExecutionOutcome,
    ),
    /// A delayed non-reset credential lifecycle action was cancelled.
    NonResetPendingCredentialLifecycleActionCancelled(
        NonResetPendingCredentialLifecycleActionCancellationOutcome,
    ),
    /// A support/admin intervention was requested.
    AdminSupportInterventionRequested(AdminSupportInterventionRequestOutcome),
    /// A verified admin/support intervention authorized or scheduled credential lifecycle work.
    AdminSupportCredentialLifecycleInterventionPlanned(
        AdminSupportCredentialLifecycleInterventionOutcome,
    ),
    /// A support/admin intervention was denied without mutating credentials.
    AdminSupportInterventionDenied(AdminSupportInterventionClosureOutcome),
    /// A support/admin intervention was expired without mutating credentials.
    AdminSupportInterventionExpired(AdminSupportInterventionClosureOutcome),
    /// A delayed subject-auth-state deletion action was scheduled.
    SubjectAuthStateDeletionScheduled(SubjectAuthStateDeletionScheduledOutcome),
    /// A delayed subject-auth-state deletion action was executed.
    PendingSubjectAuthStateDeletionExecuted(PendingSubjectAuthStateDeletionExecutionOutcome),
    /// A delayed subject-auth-state deletion action was cancelled.
    PendingSubjectAuthStateDeletionCancelled(PendingSubjectAuthStateDeletionCancellationOutcome),
    /// A delayed out-of-band identifier change action was executed.
    PendingOutOfBandIdentifierChangeExecuted(PendingOutOfBandIdentifierChangeExecutionOutcome),
    /// A delayed out-of-band identifier change action was cancelled.
    PendingOutOfBandIdentifierChangeCancelled(PendingOutOfBandIdentifierChangeCancellationOutcome),
    /// A candidate out-of-band identifier binding was proven and reserved.
    OutOfBandIdentifierChangeCandidateBindingReserved(
        OutOfBandIdentifierChangeCandidateBindingReservationOutcome,
    ),
    /// An out-of-band identifier change was authorized immediately or scheduled.
    OutOfBandIdentifierChangePlanned(OutOfBandIdentifierChangePlanningOutcome),
    /// A subject's out-of-band identifier binding was changed.
    OutOfBandIdentifierChanged(OutOfBandIdentifierChangeOutcome),
}

/// Semantic result of a revocation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationOutcome {
    /// Subject affected by the revocation, if known.
    pub subject_id: Option<SubjectId>,
    /// Revocation target.
    pub target: RevocationTarget,
}

/// Revocation target represented by a reducer outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationTarget {
    /// The current session, if any.
    CurrentSession,
    /// One specific session.
    Session(SessionId),
    /// One specific trusted-device credential.
    TrustedDevice(TrustedDeviceCredentialId),
    /// All auth state for one subject created at or before the revocation timestamp.
    SubjectAuthState(SubjectId),
}

/// Semantic result of a credential reset planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialResetOutcome {
    /// The reset is authorized to commit during the current ceremony.
    AuthorizedImmediate {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// The reset may only execute after the configured delay.
    PendingActionCreated {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Pending action id.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Earliest execution time.
        earliest_execute_at: UnixSeconds,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
}

/// Semantic result of a credential reset execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialResetExecutionOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Pending action consumed by this execution, if any.
    pub pending_action_id: Option<PendingCredentialLifecycleActionId>,
}

/// Semantic result of a credential replacement planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialReplacementOutcome {
    /// The replacement is authorized to commit during the current ceremony.
    AuthorizedImmediate {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// The replacement may only execute after the configured delay.
    PendingActionCreated {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Pending action id.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Earliest execution time.
        earliest_execute_at: UnixSeconds,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
}

/// Semantic result of an immediate credential replacement execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReplacementExecutionOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance that was superseded.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Semantic result of a credential removal planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialRemovalOutcome {
    /// The removal is authorized to commit during the current ceremony.
    AuthorizedImmediate {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// The removal may only execute after the configured delay.
    PendingActionCreated {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Pending action id.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Earliest execution time.
        earliest_execute_at: UnixSeconds,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
}

/// Semantic result of an immediate credential removal execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRemovalExecutionOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance that was revoked.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Semantic result of a credential-set regeneration planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialRegenerationOutcome {
    /// The regeneration is authorized to execute during the current ceremony.
    AuthorizedImmediate {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// The regeneration may only execute after the configured delay.
    PendingActionCreated {
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Pending action id.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Earliest execution time.
        earliest_execute_at: UnixSeconds,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
}

/// Semantic result of an immediate credential-set regeneration execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRegenerationExecutionOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance whose set was regenerated.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Semantic result of an immediate credential rotation execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotationExecutionOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance that was rotated.
    pub target_credential_instance_id: VerifiedProofSourceId,
}

/// Semantic result of a pending credential reset cancellation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialResetCancellationOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Pending action that was cancelled.
    pub pending_action_id: PendingCredentialLifecycleActionId,
}

/// Semantic result of an add-credential command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAdditionOutcome {
    /// Subject that owns the new credential.
    pub subject_id: SubjectId,
    /// New credential instance.
    pub credential_instance_id: VerifiedProofSourceId,
}

/// Semantic result of a delayed non-reset credential lifecycle action execution command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonResetPendingCredentialLifecycleActionExecutionOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Lifecycle action that executed.
    pub action: CredentialLifecycleAction,
    /// Pending action consumed by this execution.
    pub pending_action_id: PendingCredentialLifecycleActionId,
}

/// Semantic result of a delayed non-reset credential lifecycle action cancellation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonResetPendingCredentialLifecycleActionCancellationOutcome {
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Target credential instance.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Lifecycle action that was cancelled.
    pub action: CredentialLifecycleAction,
    /// Pending action that was cancelled.
    pub pending_action_id: PendingCredentialLifecycleActionId,
}

/// Semantic result of requesting a support/admin intervention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSupportInterventionRequestOutcome {
    /// Requested intervention id.
    pub intervention_id: AdminSupportInterventionId,
    /// Subject the intervention may affect.
    pub subject_id: SubjectId,
    /// Credential the intervention may affect.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Lifecycle action the intervention may authorize.
    pub action: CredentialLifecycleAction,
    /// Last time this intervention may be approved or denied.
    pub expires_at: UnixSeconds,
}

/// Semantic result of admin/support credential lifecycle intervention planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminSupportCredentialLifecycleInterventionOutcome {
    /// The intervention authorized the lifecycle action for immediate follow-on execution.
    AuthorizedImmediate {
        /// Verified support/admin intervention id.
        intervention_id: AdminSupportInterventionId,
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action authorized by the intervention.
        action: CredentialLifecycleAction,
    },
    /// The intervention may only execute after the configured delay.
    PendingActionCreated {
        /// Verified support/admin intervention id.
        intervention_id: AdminSupportInterventionId,
        /// Subject that owns the target credential.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action scheduled by the intervention.
        action: CredentialLifecycleAction,
        /// Pending action id.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Earliest execution time.
        earliest_execute_at: UnixSeconds,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
}

/// Semantic result of closing a support/admin intervention without lifecycle mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSupportInterventionClosureOutcome {
    /// Closed intervention id.
    pub intervention_id: AdminSupportInterventionId,
    /// Subject the intervention would have affected.
    pub subject_id: SubjectId,
    /// Credential the intervention would have affected.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Lifecycle action the intervention would have authorized.
    pub action: CredentialLifecycleAction,
}

/// Semantic result of scheduling delayed subject-auth-state deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAuthStateDeletionScheduledOutcome {
    /// Subject whose auth state is scheduled for deletion.
    pub subject_id: SubjectId,
    /// Pending action id.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// Earliest execution time.
    pub earliest_execute_at: UnixSeconds,
    /// Expiration time.
    pub expires_at: UnixSeconds,
}

/// Semantic result of executing delayed subject-auth-state deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSubjectAuthStateDeletionExecutionOutcome {
    /// Subject whose auth state was deleted or invalidated.
    pub subject_id: SubjectId,
    /// Pending action consumed by this execution.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

/// Semantic result of cancelling delayed subject-auth-state deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSubjectAuthStateDeletionCancellationOutcome {
    /// Subject whose pending deletion was cancelled.
    pub subject_id: SubjectId,
    /// Pending action that was cancelled.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

/// Semantic result of executing delayed out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOutOfBandIdentifierChangeExecutionOutcome {
    /// Subject whose identifier binding changed.
    pub subject_id: SubjectId,
    /// Pending action consumed by this execution.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// Previous active identifier source.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Newly activated identifier source.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

/// Semantic result of cancelling delayed out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOutOfBandIdentifierChangeCancellationOutcome {
    /// Subject whose pending identifier change was cancelled.
    pub subject_id: SubjectId,
    /// Pending action that was cancelled.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// Current identifier source that would have been superseded.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Candidate identifier source that would have been activated.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

/// Semantic result of an out-of-band identifier change planning command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutOfBandIdentifierChangePlanningOutcome {
    /// The identifier change is authorized to commit during the current ceremony.
    AuthorizedImmediate {
        /// Subject whose identifier binding would change.
        subject_id: SubjectId,
        /// Current identifier source being superseded.
        current_identifier_source_id: VerifiedProofSourceId,
        /// Candidate identifier source to activate.
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
    /// The identifier change may only execute after the configured delay.
    PendingActionCreated {
        /// Subject whose identifier binding will change.
        subject_id: SubjectId,
        /// Current identifier source to supersede at execution.
        current_identifier_source_id: VerifiedProofSourceId,
        /// Candidate identifier source to activate at execution.
        candidate_identifier_source_id: VerifiedProofSourceId,
        /// Pending subject action id.
        pending_action_id: PendingSubjectLifecycleActionId,
        /// Earliest execution time.
        earliest_execute_at: UnixSeconds,
        /// Expiration time.
        expires_at: UnixSeconds,
    },
}

/// Semantic result of changing a subject's out-of-band identifier binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutOfBandIdentifierChangeOutcome {
    /// Subject whose identifier binding changed.
    pub subject_id: SubjectId,
    /// Previous active identifier source.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Newly activated identifier source.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

/// Semantic result of reserving a proven candidate out-of-band identifier binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutOfBandIdentifierChangeCandidateBindingReservationOutcome {
    /// Subject that owns the pending candidate binding.
    pub subject_id: SubjectId,
    /// Candidate identifier source that was reserved.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

/// Authenticated-session details returned by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticated {
    /// Authenticated subject id.
    pub subject_id: SubjectId,
    /// Authenticated session id.
    pub session_id: SessionId,
    /// Source of the authentication decision.
    pub source: AuthenticationSource,
    /// Whether the session is fresh enough for sensitive operations.
    pub step_up_is_fresh: bool,
}

/// Source of an authenticated decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthenticationSource {
    /// Safe-read cache inside an encrypted session cookie.
    SafeReadCache,
    /// Authoritative session validation.
    AuthoritativeSession,
    /// Authoritative session validation that refreshed the session.
    RefreshedSession,
    /// Trusted device silently created a new session.
    SilentTrustedDeviceRevival,
    /// Trusted device plus active proof created a new session.
    TrustedDeviceRevivalWithActiveProof,
    /// Full authentication created a new session.
    FullAuthentication,
    /// Step-up proof refreshed the current session's proof freshness.
    StepUp,
}

impl From<Authenticated> for Outcome {
    fn from(value: Authenticated) -> Self {
        Self::Authenticated(value)
    }
}
