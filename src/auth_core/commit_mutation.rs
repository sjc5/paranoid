use super::prelude::*;

/// Commit-time precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Precondition {
    /// Session row must still be live with the current credential version observed before planning.
    SessionStillMatches {
        /// Session id to guard.
        session_id: SessionId,
        /// Subject that must still own the session.
        subject_id: SubjectId,
        /// Transition time used to decide whether the session is still live.
        now: UnixSeconds,
        /// Current credential version observed before planning.
        current_secret_version: SecretVersion,
    },
    /// Trusted-device row must still be live with the current credential version observed before planning.
    TrustedDeviceStillMatches {
        /// Trusted-device credential id to guard.
        device_credential_id: TrustedDeviceCredentialId,
        /// Subject that must still own the trusted-device credential.
        subject_id: SubjectId,
        /// Transition time used to decide whether the trusted device is still live.
        now: UnixSeconds,
        /// Current credential version observed before planning.
        current_secret_version: SecretVersion,
    },
    /// Session row must belong to this subject.
    SessionBelongsToSubject {
        /// Session id to guard.
        session_id: SessionId,
        /// Subject that must own the session.
        subject_id: SubjectId,
    },
    /// Trusted-device credential row must belong to this subject.
    TrustedDeviceBelongsToSubject {
        /// Trusted-device credential id to guard.
        device_credential_id: TrustedDeviceCredentialId,
        /// Subject that must own the trusted-device credential.
        subject_id: SubjectId,
    },
    /// Active-proof attempt must still be open and not invalidated by subject-wide revocation.
    ActiveProofAttemptStillOpen {
        /// Attempt id to guard.
        attempt_id: ActiveProofAttemptId,
        /// Transition time used to decide whether the attempt is still open.
        now: UnixSeconds,
        /// Subject binding observed before planning.
        observed_subject_id: Option<SubjectId>,
        /// Satisfied proof stack observed before planning.
        observed_satisfied_proofs: Vec<SatisfiedProof>,
        /// Weak failure count observed before planning.
        observed_weak_proof_failures: u32,
        /// Subject whose revocation cutoff must not invalidate this attempt, if known.
        subject_id_for_revocation: Option<SubjectId>,
        /// Attempt creation time observed before planning.
        created_at: UnixSeconds,
    },
    /// Active-proof challenge must still be open.
    ActiveProofChallengeStillOpen {
        /// Challenge id to guard.
        challenge_id: ActiveProofChallengeId,
        /// Transition time used to decide whether the challenge is still open.
        now: UnixSeconds,
    },
    /// Out-of-band challenge resend budget and delivery idempotency state must still match.
    OutOfBandChallengeResendStillAllowed {
        /// Challenge id to guard.
        challenge_id: ActiveProofChallengeId,
        /// Transition time used to decide whether the challenge is still open.
        now: UnixSeconds,
        /// Resend count observed before planning.
        observed_resend_count: u32,
        /// Delivery idempotency keys observed before planning.
        observed_used_delivery_idempotency_keys: Vec<String>,
    },
    /// No open out-of-band challenge may exist for this dedupe key.
    NoOpenOutOfBandChallengeForDedupeKey {
        /// Dedupe key to guard.
        challenge_dedupe_key: OutOfBandChallengeDedupeKey,
        /// Transition time used to ignore already-expired challenges.
        now: UnixSeconds,
        /// Live challenges created at or before this timestamp may be replaced.
        replaceable_created_at_or_before: Option<UnixSeconds>,
    },
    /// Target credential metadata must still be active and owned by the loaded subject.
    CredentialInstanceStillActive {
        /// Credential instance to guard.
        credential_instance_id: VerifiedProofSourceId,
        /// Subject that must own the credential.
        subject_id: SubjectId,
    },
    /// Subject must retain an acceptable credential posture after removing the target.
    SubjectRetainsRequiredCredentialPostureAfterRemoval {
        /// Subject that must retain an acceptable credential posture.
        subject_id: SubjectId,
        /// Credential instance being removed or disabled.
        removed_credential_instance_id: VerifiedProofSourceId,
        /// Reset policy role of the credential being removed.
        removed_credential_reset_policy_role: CredentialResetPolicyRole,
    },
    /// Subject must retain an acceptable credential posture after replacing the target.
    SubjectRetainsRequiredCredentialPostureAfterReplacement {
        /// Subject that must retain an acceptable credential posture.
        subject_id: SubjectId,
        /// Credential instance being replaced.
        replaced_credential_instance_id: VerifiedProofSourceId,
        /// Reset policy role of the credential being replaced.
        replaced_credential_reset_policy_role: CredentialResetPolicyRole,
        /// Successor credential created by the replacement.
        successor: CredentialReplacementSuccessor,
    },
    /// Adding a credential must not create a collapsed ordinary/second-factor posture.
    SubjectRetainsRequiredCredentialPostureAfterAddition {
        /// Subject that must retain an honest credential posture.
        subject_id: SubjectId,
        /// Credential instance being added.
        added_credential: CredentialInstanceMetadata,
        /// Recovery authorities being added with the credential.
        added_recovery_authorities: Vec<CredentialRecoveryAuthority>,
    },
    /// No open pending action may already exist for this target/action pair.
    NoOpenPendingCredentialLifecycleActionForTarget {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time used to close expired pending actions.
        now: UnixSeconds,
    },
    /// Pending credential lifecycle action must still be open, mature, unexpired, and target-matched.
    PendingCredentialLifecycleActionStillExecutable {
        /// Pending action to guard.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Subject that must own the pending action.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time used to decide executability.
        now: UnixSeconds,
    },
    /// Pending credential lifecycle action must still be open, unexpired, and target-matched.
    PendingCredentialLifecycleActionStillCancellableForTarget {
        /// Pending action to guard.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Subject that must own the pending action.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time used to decide cancellability.
        now: UnixSeconds,
    },
    /// No open pending subject lifecycle action may already exist for this subject/action pair.
    NoOpenPendingSubjectLifecycleActionForSubject {
        /// Subject targeted by the pending action.
        subject_id: SubjectId,
        /// Subject lifecycle action.
        action: SubjectLifecycleAction,
        /// Transition time used to close expired pending actions.
        now: UnixSeconds,
    },
    /// Pending subject lifecycle action must still be open, mature, unexpired, and subject-matched.
    PendingSubjectLifecycleActionStillExecutable {
        /// Pending action to guard.
        pending_action_id: PendingSubjectLifecycleActionId,
        /// Subject that must own the pending action.
        subject_id: SubjectId,
        /// Subject lifecycle action.
        action: SubjectLifecycleAction,
        /// Transition time used to decide executability.
        now: UnixSeconds,
    },
    /// Pending subject lifecycle action must still be open, unexpired, and subject-matched.
    PendingSubjectLifecycleActionStillCancellableForSubject {
        /// Pending action to guard.
        pending_action_id: PendingSubjectLifecycleActionId,
        /// Subject that must own the pending action.
        subject_id: SubjectId,
        /// Subject lifecycle action.
        action: SubjectLifecycleAction,
        /// Transition time used to decide cancellability.
        now: UnixSeconds,
    },
    /// Out-of-band identifier binding must still be active for this subject.
    OutOfBandIdentifierBindingStillActive {
        /// Identifier source to guard.
        source_id: VerifiedProofSourceId,
        /// Subject that must own the binding.
        subject_id: SubjectId,
    },
    /// Out-of-band identifier binding must still be pending activation for this subject.
    OutOfBandIdentifierBindingStillPendingActivation {
        /// Identifier source to guard.
        source_id: VerifiedProofSourceId,
        /// Subject that must own the binding.
        subject_id: SubjectId,
    },
    /// No open admin/support intervention may already exist for this target/action pair.
    NoOpenAdminSupportInterventionForTarget {
        /// Subject targeted by the intervention.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time used to close expired interventions.
        now: UnixSeconds,
    },
    /// Admin/support intervention must still be open, unexpired, and target-matched.
    AdminSupportInterventionStillOpen {
        /// Intervention to guard.
        intervention_id: AdminSupportInterventionId,
        /// Subject targeted by the intervention.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time used to decide liveness.
        now: UnixSeconds,
    },
    /// Admin/support intervention must still be open, expired, and target-matched.
    AdminSupportInterventionStillExpiredOpen {
        /// Intervention to guard.
        intervention_id: AdminSupportInterventionId,
        /// Subject targeted by the intervention.
        subject_id: SubjectId,
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time used to decide expiry.
        now: UnixSeconds,
    },
}

/// State mutation planned by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mutation {
    /// Create a new session row.
    CreateSession(SessionRecord),
    /// Refresh a live session and rotate its credential.
    RefreshSession {
        /// Session id to refresh.
        session_id: SessionId,
        /// New current credential version.
        new_secret_version: SecretVersion,
        /// Previous credential version retained for race grace.
        previous_secret_version: SecretVersion,
        /// Last time the previous credential version may be accepted.
        previous_secret_accept_until: UnixSeconds,
        /// New refreshed-at timestamp.
        refreshed_at: UnixSeconds,
        /// New session expiration.
        expires_at: UnixSeconds,
    },
    /// Record step-up freshness and rotate the session credential.
    RecordStepUp {
        /// Session id to update.
        session_id: SessionId,
        /// New current credential version.
        new_secret_version: SecretVersion,
        /// Previous credential version retained for race grace.
        previous_secret_version: SecretVersion,
        /// Last time the previous credential version may be accepted.
        previous_secret_accept_until: UnixSeconds,
        /// New step-up freshness deadline.
        step_up_expires_at: UnixSeconds,
    },
    /// Create a trusted-device credential row.
    CreateTrustedDeviceCredential(TrustedDeviceCredentialRecord),
    /// Create an active-proof attempt row.
    CreateActiveProofAttempt(ActiveProofAttemptRecord),
    /// Create an active-proof challenge row.
    CreateActiveProofChallenge(ActiveProofChallengeRecord),
    /// Record one failed weak proof inside an attempt.
    RecordWeakProofFailure {
        /// Attempt id to update.
        attempt_id: ActiveProofAttemptId,
        /// New weak failure count.
        weak_proof_failures: u32,
    },
    /// Record one satisfied active proof inside an attempt.
    RecordActiveProofSucceeded {
        /// Attempt id to update.
        attempt_id: ActiveProofAttemptId,
        /// Subject id after this proof, if the attempt is now subject-bound.
        subject_id: Option<SubjectId>,
        /// Proof that was satisfied.
        proof: SatisfiedProof,
        /// Proof satisfaction timestamp.
        satisfied_at: UnixSeconds,
    },
    /// Close all still-open active-proof challenges for one satisfied proof family.
    CloseOpenActiveProofChallengesForAttemptProofFamily {
        /// Attempt whose challenges should be closed.
        attempt_id: ActiveProofAttemptId,
        /// Proof family that was satisfied.
        proof_family: ProofFamily,
        /// Closure timestamp.
        closed_at: UnixSeconds,
    },
    /// Record that an out-of-band challenge was accepted for another delivery.
    RecordOutOfBandChallengeResent {
        /// Challenge id to update.
        challenge_id: ActiveProofChallengeId,
        /// Resend count after this transition.
        resend_count: u32,
        /// Delivery idempotency keys after this transition.
        used_delivery_idempotency_keys: Vec<String>,
        /// Resend timestamp.
        resent_at: UnixSeconds,
    },
    /// Hard-delete an active-proof attempt.
    DeleteActiveProofAttempt {
        /// Attempt id to delete.
        attempt_id: ActiveProofAttemptId,
    },
    /// Rotate a trusted-device credential after use.
    RotateTrustedDeviceCredential {
        /// Trusted-device credential id to rotate.
        device_credential_id: TrustedDeviceCredentialId,
        /// New current credential version.
        new_secret_version: SecretVersion,
        /// Previous credential version retained for race grace.
        previous_secret_version: SecretVersion,
        /// Last time the previous credential version may be accepted.
        previous_secret_accept_until: UnixSeconds,
        /// Last-used timestamp.
        last_used_at: UnixSeconds,
        /// Silent-revival deadline.
        silent_revival_until: UnixSeconds,
        /// Absolute credential expiration.
        expires_at: UnixSeconds,
    },
    /// Revoke a session.
    RevokeSession {
        /// Session id to revoke.
        session_id: SessionId,
        /// Revocation reason.
        reason: RevocationReason,
        /// Revocation timestamp.
        revoked_at: UnixSeconds,
    },
    /// Revoke a trusted-device credential.
    RevokeTrustedDeviceCredential {
        /// Trusted-device credential id to revoke.
        device_credential_id: TrustedDeviceCredentialId,
        /// Revocation reason.
        reason: RevocationReason,
        /// Revocation timestamp.
        revoked_at: UnixSeconds,
    },
    /// Raise the subject-wide auth revocation cutoff without moving it backward.
    RaiseSubjectAuthRevocationCutoff {
        /// Subject whose existing auth state is invalidated.
        subject_id: SubjectId,
        /// Auth records created at or before this cutoff are invalid.
        revoke_records_created_at_or_before: UnixSeconds,
        /// Revocation reason.
        reason: RevocationReason,
    },
    /// Record a core-visible credential lifecycle action that was authorized immediately.
    RecordCredentialLifecycleActionAuthorized {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Time the action was authorized.
        authorized_at: UnixSeconds,
    },
    /// Create core-visible metadata for a new credential instance.
    CreateCredentialInstanceMetadata {
        /// New credential instance metadata.
        metadata: CredentialInstanceMetadata,
        /// Creation timestamp.
        created_at: UnixSeconds,
    },
    /// Create one recovery-authority edge for a credential instance.
    CreateCredentialRecoveryAuthority {
        /// Recovery-authority edge to persist.
        authority: CredentialRecoveryAuthority,
        /// Creation timestamp.
        created_at: UnixSeconds,
    },
    /// Create one lifecycle authority-source mapping.
    CreateLifecycleAuthoritySource {
        /// Lifecycle authority source.
        source: LifecycleAuthoritySource,
        /// Effective recovery authority represented by the source.
        authority_id: RecoveryAuthorityId,
        /// Creation timestamp.
        created_at: UnixSeconds,
    },
    /// Delete every lifecycle authority-source mapping for one source.
    DeleteLifecycleAuthoritySourcesForSource {
        /// Lifecycle authority source whose authority mappings must be replaced.
        source: LifecycleAuthoritySource,
    },
    /// Create a delayed credential lifecycle action.
    CreatePendingCredentialLifecycleAction(PendingCredentialLifecycleActionRecord),
    /// Record a core-visible credential lifecycle action that has executed.
    RecordCredentialLifecycleActionExecuted {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
        /// Time the action executed.
        executed_at: UnixSeconds,
    },
    /// Set a credential's core-visible lifecycle state.
    SetCredentialLifecycleState {
        /// Credential instance to update.
        credential_instance_id: VerifiedProofSourceId,
        /// New lifecycle state.
        lifecycle_state: CredentialLifecycleState,
        /// Update timestamp.
        updated_at: UnixSeconds,
    },
    /// Close a delayed credential lifecycle action after execution or cancellation.
    ClosePendingCredentialLifecycleAction {
        /// Pending action to close.
        pending_action_id: PendingCredentialLifecycleActionId,
        /// Closure timestamp.
        closed_at: UnixSeconds,
    },
    /// Create a delayed subject lifecycle action.
    CreatePendingSubjectLifecycleAction(PendingSubjectLifecycleActionRecord),
    /// Close a delayed subject lifecycle action after execution or cancellation.
    ClosePendingSubjectLifecycleAction {
        /// Pending action to close.
        pending_action_id: PendingSubjectLifecycleActionId,
        /// Closure timestamp.
        closed_at: UnixSeconds,
    },
    /// Create a Paranoid-owned out-of-band identifier binding row.
    CreateOutOfBandIdentifierBinding {
        /// Binding record to insert.
        record: OutOfBandIdentifierBindingRecord,
        /// Creation timestamp.
        created_at: UnixSeconds,
    },
    /// Set an out-of-band identifier binding lifecycle state.
    SetOutOfBandIdentifierBindingLifecycleState {
        /// Identifier source to update.
        source_id: VerifiedProofSourceId,
        /// New lifecycle state.
        lifecycle_state: OutOfBandIdentifierBindingLifecycleState,
        /// Update timestamp.
        updated_at: UnixSeconds,
    },
    /// Create a support/admin intervention record.
    CreateAdminSupportIntervention(AdminSupportInterventionRecord),
    /// Close a support/admin intervention after approval, denial, or expiry.
    CloseAdminSupportIntervention {
        /// Intervention to close.
        intervention_id: AdminSupportInterventionId,
        /// Terminal status to write.
        status: AdminSupportInterventionStatus,
        /// Closure timestamp.
        closed_at: UnixSeconds,
    },
}

/// Reason a record was revoked.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RevocationReason {
    /// Subject explicitly logged out.
    Logout,
    /// App-authorized actor remotely revoked the record.
    RemoteRevocation,
    /// Evidence proved credential compromise.
    Tripwire,
    /// Subject-wide auth state changed.
    SubjectAuthStateChanged,
}
