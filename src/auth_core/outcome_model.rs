use super::*;

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
    /// A delayed credential reset was cancelled.
    CredentialResetPendingActionCancelled(CredentialResetCancellationOutcome),
    /// A delayed non-reset credential lifecycle action was executed.
    NonResetPendingCredentialLifecycleActionExecuted(
        NonResetPendingCredentialLifecycleActionExecutionOutcome,
    ),
    /// A delayed non-reset credential lifecycle action was cancelled.
    NonResetPendingCredentialLifecycleActionCancelled(
        NonResetPendingCredentialLifecycleActionCancellationOutcome,
    ),
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
