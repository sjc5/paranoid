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
