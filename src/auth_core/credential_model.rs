use super::*;

/// Core-visible class of an app-owned credential instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialInstanceKind {
    /// A verifier used by password-derived, SSH, wallet, or similar message-signature auth.
    MessageSignatureVerifier,
    /// A configured shared-secret OTP verifier, such as TOTP.
    SharedSecretOtpVerifier,
    /// An origin-bound public-key credential, such as a WebAuthn passkey.
    OriginBoundPublicKeyCredential,
    /// A one-time recovery credential.
    RecoveryCodeCredential,
    /// A trusted-device rotating bearer credential.
    TrustedDeviceCredential,
}

impl CredentialInstanceKind {
    /// Returns the proof family produced by this credential kind.
    pub const fn proof_family(self) -> ProofFamily {
        match self {
            Self::MessageSignatureVerifier => ProofFamily::MessageSignature,
            Self::SharedSecretOtpVerifier => ProofFamily::SharedSecretOtp,
            Self::OriginBoundPublicKeyCredential => ProofFamily::OriginBoundPublicKey,
            Self::RecoveryCodeCredential => ProofFamily::RecoveryCode,
            Self::TrustedDeviceCredential => ProofFamily::TrustedDevice,
        }
    }

    /// Returns the credential-instance kind for proof families backed by app-owned credentials.
    pub fn try_from_proof_family(family: ProofFamily) -> Result<Self, Error> {
        match family {
            ProofFamily::MessageSignature => Ok(Self::MessageSignatureVerifier),
            ProofFamily::SharedSecretOtp => Ok(Self::SharedSecretOtpVerifier),
            ProofFamily::OriginBoundPublicKey => Ok(Self::OriginBoundPublicKeyCredential),
            ProofFamily::RecoveryCode => Ok(Self::RecoveryCodeCredential),
            ProofFamily::TrustedDevice => Ok(Self::TrustedDeviceCredential),
            ProofFamily::OutOfBandCode | ProofFamily::FederatedIdentityAssertion => Err(
                Error::InvalidConfig("proof family is not an app-owned credential instance"),
            ),
        }
    }
}

/// Lifecycle state for a credential instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialLifecycleState {
    /// The credential may produce new proofs.
    Active,
    /// The credential has been requested but is not active yet.
    PendingActivation,
    /// The credential is being replaced by another credential.
    PendingReplacement,
    /// The credential is being removed but the removal has not committed.
    PendingRemoval,
    /// The credential is scheduled for delayed deletion.
    ScheduledDeletion,
    /// The credential was used once and cannot be used again.
    Consumed,
    /// The credential was revoked by policy or operator action.
    Revoked,
    /// The credential reached its configured expiry.
    Expired,
    /// The credential was superseded by replacement.
    Superseded,
    /// The credential is suspended by an admin/support intervention.
    AdminSuspended,
}

impl CredentialLifecycleState {
    /// Returns whether this state can produce new proofs.
    pub const fn can_produce_new_proofs(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Core-visible metadata for one app-owned credential instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialInstanceMetadata {
    /// Stable credential-instance identifier.
    credential_instance_id: VerifiedProofSourceId,
    /// Subject that owns this credential instance.
    subject_id: SubjectId,
    /// Core-visible credential class.
    kind: CredentialInstanceKind,
    /// Concrete method label that produced or uses this credential instance.
    method_label: String,
    /// Current lifecycle state.
    lifecycle_state: CredentialLifecycleState,
}

impl CredentialInstanceMetadata {
    /// Creates metadata for one app-owned credential instance.
    pub fn new(
        credential_instance_id: VerifiedProofSourceId,
        subject_id: SubjectId,
        kind: CredentialInstanceKind,
        method_label: impl Into<String>,
        lifecycle_state: CredentialLifecycleState,
    ) -> Result<Self, Error> {
        let method_label = method_label.into();
        if method_label.is_empty() {
            return Err(Error::EmptyProofMethodLabel);
        }
        validate_auth_identifier_string(
            "credential instance method label",
            &method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(Self {
            credential_instance_id,
            subject_id,
            kind,
            method_label,
            lifecycle_state,
        })
    }

    /// Returns the stable credential-instance id.
    pub const fn credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.credential_instance_id
    }

    /// Returns the subject that owns this credential instance.
    pub const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    /// Returns the core-visible credential class.
    pub const fn kind(&self) -> CredentialInstanceKind {
        self.kind
    }

    /// Returns the concrete method label.
    pub fn method_label(&self) -> &str {
        &self.method_label
    }

    /// Returns the current lifecycle state.
    pub const fn lifecycle_state(&self) -> CredentialLifecycleState {
        self.lifecycle_state
    }

    /// Returns whether this credential can produce new proofs.
    pub const fn can_produce_new_proofs(&self) -> bool {
        self.lifecycle_state.can_produce_new_proofs()
    }

    /// Returns this metadata with a different lifecycle state.
    pub fn with_lifecycle_state(&self, lifecycle_state: CredentialLifecycleState) -> Self {
        Self {
            credential_instance_id: self.credential_instance_id.clone(),
            subject_id: self.subject_id.clone(),
            kind: self.kind,
            method_label: self.method_label.clone(),
            lifecycle_state,
        }
    }

    /// Returns the proof source recorded for proofs produced by this credential instance.
    pub fn verified_proof_source(&self) -> VerifiedProofSource {
        VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            self.credential_instance_id.clone(),
        )
    }

    /// Returns the proof family produced by this credential instance.
    pub const fn proof_family(&self) -> ProofFamily {
        self.kind.proof_family()
    }
}

/// Credential lifecycle mutation whose recovery authority must be modeled.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialLifecycleAction {
    /// Create a credential instance.
    Create,
    /// Reset verifier or secret material for an existing credential instance.
    Reset,
    /// Replace a credential instance with another one.
    Replace,
    /// Remove a credential instance from the subject.
    Remove,
    /// Disable a credential instance without deleting it.
    Disable,
    /// Regenerate a credential set, such as one-time recovery codes.
    Regenerate,
    /// Recover subject access after the ordinary credentials are unavailable.
    RecoverSubjectAccess,
}

impl CredentialLifecycleAction {
    /// Returns the pending-action contract for delayed credential-targeted actions.
    pub const fn pending_credential_action_contract(
        self,
    ) -> Option<PendingLifecycleActionContract> {
        match self {
            Self::Reset => Some(PendingLifecycleActionContract {
                target: PendingLifecycleActionTarget::CredentialInstance,
                execution: PendingLifecycleActionExecution::MethodOwnedCredential,
                credential_state_after_execution:
                    PendingCredentialStateAfterExecution::PreserveCurrentState,
                cancellation: PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice,
                expiry: PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup,
                revocation: PendingLifecycleActionRevocation::ExplicitTransitionPolicy,
            }),
            Self::Replace => Some(PendingLifecycleActionContract {
                target: PendingLifecycleActionTarget::CredentialInstance,
                execution: PendingLifecycleActionExecution::MethodOwnedCredential,
                credential_state_after_execution:
                    PendingCredentialStateAfterExecution::MarkTargetSuperseded,
                cancellation: PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice,
                expiry: PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup,
                revocation: PendingLifecycleActionRevocation::ExplicitTransitionPolicy,
            }),
            Self::Remove => Some(PendingLifecycleActionContract {
                target: PendingLifecycleActionTarget::CredentialInstance,
                execution: PendingLifecycleActionExecution::CoreCredentialState,
                credential_state_after_execution:
                    PendingCredentialStateAfterExecution::MarkTargetRevoked,
                cancellation: PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice,
                expiry: PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup,
                revocation: PendingLifecycleActionRevocation::ExplicitTransitionPolicy,
            }),
            Self::Regenerate => Some(PendingLifecycleActionContract {
                target: PendingLifecycleActionTarget::CredentialInstance,
                execution: PendingLifecycleActionExecution::MethodOwnedCredential,
                credential_state_after_execution:
                    PendingCredentialStateAfterExecution::PreserveCurrentState,
                cancellation: PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice,
                expiry: PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup,
                revocation: PendingLifecycleActionRevocation::ExplicitTransitionPolicy,
            }),
            Self::Create | Self::Disable | Self::RecoverSubjectAccess => None,
        }
    }
}

/// Subject-level lifecycle action whose pending-action target is not a credential instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SubjectLifecycleAction {
    /// Delete or disable the subject's Paranoid-owned auth state after a waiting period.
    DeleteSubjectAuthState,
}

impl SubjectLifecycleAction {
    /// Returns the pending-action contract for delayed subject-targeted actions.
    pub const fn pending_subject_action_contract(self) -> PendingLifecycleActionContract {
        match self {
            Self::DeleteSubjectAuthState => PendingLifecycleActionContract {
                target: PendingLifecycleActionTarget::SubjectAuthState,
                execution: PendingLifecycleActionExecution::CoreSubjectAuthState,
                credential_state_after_execution:
                    PendingCredentialStateAfterExecution::NoCredentialTarget,
                cancellation: PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice,
                expiry: PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup,
                revocation: PendingLifecycleActionRevocation::SubjectWideOnExecution,
            },
        }
    }
}

/// Stable semantics for a delayed lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingLifecycleActionContract {
    /// Record family targeted by the pending action.
    target: PendingLifecycleActionTarget,
    /// Commit-work shape required when the pending action executes.
    execution: PendingLifecycleActionExecution,
    /// Credential-state mutation that follows successful execution.
    credential_state_after_execution: PendingCredentialStateAfterExecution,
    /// Cancellation semantics.
    cancellation: PendingLifecycleActionCancellation,
    /// Expiry semantics.
    expiry: PendingLifecycleActionExpiry,
    /// Auth-state revocation semantics.
    revocation: PendingLifecycleActionRevocation,
}

impl PendingLifecycleActionContract {
    /// Returns the record family targeted by the pending action.
    pub const fn target(self) -> PendingLifecycleActionTarget {
        self.target
    }

    /// Returns the commit-work shape required when the pending action executes.
    pub const fn execution(self) -> PendingLifecycleActionExecution {
        self.execution
    }

    /// Returns the credential-state mutation that follows successful execution.
    pub const fn credential_state_after_execution(self) -> PendingCredentialStateAfterExecution {
        self.credential_state_after_execution
    }

    /// Returns the cancellation semantics.
    pub const fn cancellation(self) -> PendingLifecycleActionCancellation {
        self.cancellation
    }

    /// Returns the expiry semantics.
    pub const fn expiry(self) -> PendingLifecycleActionExpiry {
        self.expiry
    }

    /// Returns the auth-state revocation semantics.
    pub const fn revocation(self) -> PendingLifecycleActionRevocation {
        self.revocation
    }
}

/// Record family targeted by a delayed lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingLifecycleActionTarget {
    /// The pending action targets one credential instance.
    CredentialInstance,
    /// The pending action targets the subject's auth state rather than one credential.
    SubjectAuthState,
}

/// Execution shape required by a delayed lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingLifecycleActionExecution {
    /// The action must commit method-owned verifier, secret, or credential-set work.
    MethodOwnedCredential,
    /// The action is primarily a core credential lifecycle-state mutation.
    CoreCredentialState,
    /// The action mutates subject-level auth state rather than one credential instance.
    CoreSubjectAuthState,
}

/// Credential-state result of executing a delayed lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingCredentialStateAfterExecution {
    /// The target credential stays in its current core lifecycle state.
    PreserveCurrentState,
    /// The target credential is revoked or removed from proof production.
    MarkTargetRevoked,
    /// The target credential is superseded by replacement.
    MarkTargetSuperseded,
    /// The pending action has no credential target.
    NoCredentialTarget,
}

/// Cancellation semantics for delayed lifecycle actions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingLifecycleActionCancellation {
    /// Cancellation is an explicit transition only while the action is still unexpired.
    ExplicitWhileUnexpiredWithNotice,
}

/// Expiry semantics for delayed lifecycle actions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingLifecycleActionExpiry {
    /// Expiry is derived from the deadline; cleanup may quietly close expired rows.
    DeadlineDerivedQuietCleanup,
}

/// Auth-state revocation semantics for delayed lifecycle actions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingLifecycleActionRevocation {
    /// The concrete transition must choose and record its revocation policy explicitly.
    ExplicitTransitionPolicy,
    /// Successful execution revokes older subject auth state.
    SubjectWideOnExecution,
}

/// Whether a recovery authority can mutate credentials immediately or only after delay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecoveryAuthorityTiming {
    /// The authority can perform the lifecycle action as part of the current ceremony.
    Immediate,
    /// The authority can only schedule or complete the lifecycle action after a delay.
    Delayed,
}

impl RecoveryAuthorityTiming {
    /// Returns whether this timing allows immediate credential mutation.
    pub const fn is_immediate(self) -> bool {
        matches!(self, Self::Immediate)
    }
}

/// Lifecycle evidence source presented to a credential lifecycle policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAuthoritySource {
    /// A satisfied proof source.
    VerifiedProofSource(VerifiedProofSource),
    /// A live authenticated session.
    AuthenticatedSession(SessionId),
    /// A Paranoid-shaped admin/support recovery intervention.
    AdminSupportIntervention(VerifiedProofSourceId),
}

/// Recovery-authority metadata for one presented lifecycle authority source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuthorityEvidence {
    /// Presented authority source.
    source: LifecycleAuthoritySource,
    /// Effective recovery authorities represented by this source.
    authority_ids: Vec<RecoveryAuthorityId>,
}

impl LifecycleAuthorityEvidence {
    /// Creates lifecycle authority evidence from a verified proof source.
    pub fn from_verified_proof_source(
        source: VerifiedProofSource,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        Self::new(
            LifecycleAuthoritySource::VerifiedProofSource(source),
            authority_ids,
        )
    }

    /// Creates lifecycle authority evidence from a live authenticated session.
    pub fn authenticated_session(
        session_id: SessionId,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        Self::new(
            LifecycleAuthoritySource::AuthenticatedSession(session_id),
            authority_ids,
        )
    }

    /// Creates lifecycle authority evidence from a verified admin/support intervention.
    pub fn admin_support_intervention(
        intervention_id: VerifiedProofSourceId,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        Self::new(
            LifecycleAuthoritySource::AdminSupportIntervention(intervention_id),
            authority_ids,
        )
    }

    pub(crate) fn new(
        source: LifecycleAuthoritySource,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        let authority_ids: Vec<RecoveryAuthorityId> = authority_ids.into_iter().collect();
        if authority_ids.is_empty() {
            return Err(Error::InvalidConfig(
                "lifecycle authority evidence must name at least one recovery authority",
            ));
        }
        if contains_duplicate_recovery_authority_ids(&authority_ids) {
            return Err(Error::InvalidConfig(
                "lifecycle authority evidence must not duplicate recovery authorities",
            ));
        }
        Ok(Self {
            source,
            authority_ids,
        })
    }

    /// Returns the presented authority source.
    pub const fn source(&self) -> &LifecycleAuthoritySource {
        &self.source
    }

    /// Returns effective recovery authorities represented by this source.
    pub fn authority_ids(&self) -> &[RecoveryAuthorityId] {
        &self.authority_ids
    }

    /// Returns whether this evidence is independent from another evidence source.
    pub fn is_recovery_independent_from(&self, other: &Self) -> bool {
        recovery_authority_id_sets_are_disjoint(&self.authority_ids, &other.authority_ids)
    }
}

/// Recovery authority for one target credential lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRecoveryAuthority {
    /// Credential instance this authority can mutate.
    target_credential_instance_id: VerifiedProofSourceId,
    /// Lifecycle action authorized by this record.
    action: CredentialLifecycleAction,
    /// Effective recovery authority.
    authority_id: RecoveryAuthorityId,
    /// Whether this authority can act immediately.
    timing: RecoveryAuthorityTiming,
}

impl CredentialRecoveryAuthority {
    /// Creates a target credential recovery-authority record.
    pub fn new(
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        authority_id: RecoveryAuthorityId,
        timing: RecoveryAuthorityTiming,
    ) -> Self {
        Self {
            target_credential_instance_id,
            action,
            authority_id,
            timing,
        }
    }

    /// Returns the target credential instance.
    pub const fn target_credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.target_credential_instance_id
    }

    /// Returns the lifecycle action.
    pub const fn action(&self) -> CredentialLifecycleAction {
        self.action
    }

    /// Returns the effective recovery authority.
    pub const fn authority_id(&self) -> &RecoveryAuthorityId {
        &self.authority_id
    }

    /// Returns the authority timing.
    pub const fn timing(&self) -> RecoveryAuthorityTiming {
        self.timing
    }
}

/// Recovery-authority graph for credential lifecycle policy checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRecoveryAuthorityGraph {
    /// Target credential authority records.
    authorities: Vec<CredentialRecoveryAuthority>,
}

impl CredentialRecoveryAuthorityGraph {
    /// Creates a recovery-authority graph.
    pub fn new(
        authorities: impl IntoIterator<Item = CredentialRecoveryAuthority>,
    ) -> Result<Self, Error> {
        let authorities: Vec<CredentialRecoveryAuthority> = authorities.into_iter().collect();
        if contains_duplicate_credential_recovery_authorities(&authorities) {
            return Err(Error::InvalidConfig(
                "credential recovery authority graph must not contain duplicate authorities",
            ));
        }
        Ok(Self { authorities })
    }

    /// Returns the authority records.
    pub fn authorities(&self) -> &[CredentialRecoveryAuthority] {
        &self.authorities
    }

    /// Returns whether evidence can immediately authorize the target credential action.
    pub fn evidence_can_immediately_authorize_credential_action(
        &self,
        evidence: &LifecycleAuthorityEvidence,
        target_credential_instance_id: &VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    ) -> bool {
        self.authorities.iter().any(|authority| {
            authority.target_credential_instance_id == *target_credential_instance_id
                && authority.action == action
                && authority.timing.is_immediate()
                && evidence
                    .authority_ids
                    .iter()
                    .any(|authority_id| authority_id == &authority.authority_id)
        })
    }

    /// Returns whether evidence can schedule the target credential action for delayed execution.
    pub fn evidence_can_schedule_delayed_credential_action(
        &self,
        evidence: &LifecycleAuthorityEvidence,
        target_credential_instance_id: &VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    ) -> bool {
        self.authorities.iter().any(|authority| {
            authority.target_credential_instance_id == *target_credential_instance_id
                && authority.action == action
                && authority.timing == RecoveryAuthorityTiming::Delayed
                && evidence
                    .authority_ids
                    .iter()
                    .any(|authority_id| authority_id == &authority.authority_id)
        })
    }

    /// Returns whether evidence is independent for the target credential action.
    pub fn evidence_is_independent_for_credential_action(
        &self,
        evidence: &LifecycleAuthorityEvidence,
        target_credential_instance_id: &VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    ) -> bool {
        !self.evidence_can_immediately_authorize_credential_action(
            evidence,
            target_credential_instance_id,
            action,
        )
    }

    /// Returns whether any presented evidence can immediately authorize the target action.
    pub fn evidence_set_can_immediately_authorize_credential_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        target_credential_instance_id: &VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_can_immediately_authorize_credential_action(
                evidence,
                target_credential_instance_id,
                action,
            )
        })
    }

    /// Returns whether any presented evidence can schedule the target action for delayed execution.
    pub fn evidence_set_can_schedule_delayed_credential_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        target_credential_instance_id: &VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_can_schedule_delayed_credential_action(
                evidence,
                target_credential_instance_id,
                action,
            )
        })
    }

    /// Returns whether any presented evidence is independent from the target action.
    pub fn evidence_set_contains_independent_evidence_for_credential_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        target_credential_instance_id: &VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_is_independent_for_credential_action(
                evidence,
                target_credential_instance_id,
                action,
            )
        })
    }
}

/// Loaded lifecycle-policy context for one target credential action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLifecycleActionContext {
    target_credential: CredentialInstanceMetadata,
    recovery_authority_graph: CredentialRecoveryAuthorityGraph,
    presented_evidence: Vec<LifecycleAuthorityEvidence>,
}

impl CredentialLifecycleActionContext {
    /// Creates loaded lifecycle-policy context for one target credential.
    pub fn new(
        target_credential: CredentialInstanceMetadata,
        recovery_authority_graph: CredentialRecoveryAuthorityGraph,
        presented_evidence: impl IntoIterator<Item = LifecycleAuthorityEvidence>,
    ) -> Self {
        Self {
            target_credential,
            recovery_authority_graph,
            presented_evidence: presented_evidence.into_iter().collect(),
        }
    }

    /// Returns the target credential metadata.
    pub const fn target_credential(&self) -> &CredentialInstanceMetadata {
        &self.target_credential
    }

    /// Returns the recovery-authority graph for the target credential.
    pub const fn recovery_authority_graph(&self) -> &CredentialRecoveryAuthorityGraph {
        &self.recovery_authority_graph
    }

    /// Returns the presented lifecycle evidence.
    pub fn presented_evidence(&self) -> &[LifecycleAuthorityEvidence] {
        &self.presented_evidence
    }

    /// Evaluates whether the presented evidence may perform or schedule a lifecycle action.
    pub fn evaluate_action(
        &self,
        action: CredentialLifecycleAction,
        independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    ) -> CredentialLifecycleActionDecision {
        if !self.target_credential.can_produce_new_proofs() {
            return CredentialLifecycleActionDecision::Rejected;
        }
        let target_id = self.target_credential.credential_instance_id();
        if self
            .recovery_authority_graph
            .evidence_set_can_immediately_authorize_credential_action(
                &self.presented_evidence,
                target_id,
                action,
            )
        {
            if independent_evidence_required.is_required()
                && !self
                    .recovery_authority_graph
                    .evidence_set_contains_independent_evidence_for_credential_action(
                        &self.presented_evidence,
                        target_id,
                        action,
                    )
            {
                return CredentialLifecycleActionDecision::RequiresDelayedAction;
            }
            return CredentialLifecycleActionDecision::AuthorizedImmediate;
        }
        if self
            .recovery_authority_graph
            .evidence_set_can_schedule_delayed_credential_action(
                &self.presented_evidence,
                target_id,
                action,
            )
        {
            return CredentialLifecycleActionDecision::RequiresDelayedAction;
        }
        CredentialLifecycleActionDecision::Rejected
    }
}

/// Whether an immediate credential lifecycle action requires independent evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialLifecycleIndependentEvidenceRequirement {
    /// The lifecycle action may be performed by the target's configured recovery authority alone.
    NotRequired,
    /// The lifecycle action needs some presented evidence independent from the target action.
    Required,
}

impl CredentialLifecycleIndependentEvidenceRequirement {
    /// Returns whether independent evidence is required.
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// Decision for a credential lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialLifecycleActionDecision {
    /// The action may commit immediately.
    AuthorizedImmediate,
    /// The presented evidence can start the action, but immediate mutation would degrade auth.
    RequiresDelayedAction,
    /// The action is not authorized by the loaded credential lifecycle policy.
    Rejected,
}

/// Delayed credential-lifecycle action row owned by the auth core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCredentialLifecycleActionRecord {
    /// Pending action id.
    pub pending_action_id: PendingCredentialLifecycleActionId,
    /// Subject that owns the target credential.
    pub subject_id: SubjectId,
    /// Credential instance the action will mutate when executed.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Lifecycle action to execute later.
    pub action: CredentialLifecycleAction,
    /// Time the pending action was requested.
    pub requested_at: UnixSeconds,
    /// Earliest time the pending action may execute.
    pub earliest_execute_at: UnixSeconds,
    /// Last time the pending action remains executable.
    pub expires_at: UnixSeconds,
    /// Closure timestamp, if this pending action is no longer open.
    pub closed_at: Option<UnixSeconds>,
}

impl PendingCredentialLifecycleActionRecord {
    /// Creates an open delayed credential-lifecycle action.
    pub fn new_open(
        pending_action_id: PendingCredentialLifecycleActionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        requested_at: UnixSeconds,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, Error> {
        if earliest_execute_at <= requested_at || expires_at <= earliest_execute_at {
            return Err(Error::InvalidCredentialLifecyclePendingActionTiming);
        }
        Ok(Self {
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            action,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at: None,
        })
    }

    /// Returns whether this pending action is open and executable at `now`.
    pub fn is_executable_at(&self, now: UnixSeconds) -> bool {
        self.closed_at.is_none() && self.earliest_execute_at <= now && now < self.expires_at
    }

    /// Returns whether this pending action is open and unexpired at `now`.
    pub fn is_cancellable_at(&self, now: UnixSeconds) -> bool {
        self.closed_at.is_none() && now < self.expires_at
    }

    /// Returns whether this pending action has not yet been closed.
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }

    /// Returns whether this pending action targets the supplied credential/action.
    pub fn matches_target_action(
        &self,
        target: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
    ) -> bool {
        self.subject_id == *target.subject_id()
            && self.target_credential_instance_id == *target.credential_instance_id()
            && self.action == action
    }
}

/// Delayed subject-lifecycle action row owned by the auth core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingSubjectLifecycleActionRecord {
    /// Pending action id.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// Subject whose auth state the action will mutate when executed.
    pub subject_id: SubjectId,
    /// Subject lifecycle action to execute later.
    pub action: SubjectLifecycleAction,
    /// Time the pending action was requested.
    pub requested_at: UnixSeconds,
    /// Earliest time the pending action may execute.
    pub earliest_execute_at: UnixSeconds,
    /// Last time the pending action remains executable.
    pub expires_at: UnixSeconds,
    /// Closure timestamp, if this pending action is no longer open.
    pub closed_at: Option<UnixSeconds>,
}

impl PendingSubjectLifecycleActionRecord {
    /// Creates an open delayed subject-lifecycle action.
    pub fn new_open(
        pending_action_id: PendingSubjectLifecycleActionId,
        subject_id: SubjectId,
        action: SubjectLifecycleAction,
        requested_at: UnixSeconds,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, Error> {
        if earliest_execute_at <= requested_at || expires_at <= earliest_execute_at {
            return Err(Error::InvalidSubjectLifecyclePendingActionTiming);
        }
        Ok(Self {
            pending_action_id,
            subject_id,
            action,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at: None,
        })
    }

    /// Returns whether this pending action is open and executable at `now`.
    pub fn is_executable_at(&self, now: UnixSeconds) -> bool {
        self.closed_at.is_none() && self.earliest_execute_at <= now && now < self.expires_at
    }

    /// Returns whether this pending action is open and unexpired at `now`.
    pub fn is_cancellable_at(&self, now: UnixSeconds) -> bool {
        self.closed_at.is_none() && now < self.expires_at
    }

    /// Returns whether this pending action has not yet been closed.
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }

    /// Returns whether this pending action targets the supplied subject/action.
    pub fn matches_subject_action(
        &self,
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
    ) -> bool {
        self.subject_id == *subject_id && self.action == action
    }
}

/// Whether an immediate credential reset should revoke existing auth state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialResetSubjectAuthRevocation {
    /// Existing sessions/devices stay live after the immediate reset.
    PreserveExistingAuthState,
    /// Existing sessions/devices are invalidated by subject-wide auth-state revocation.
    RevokeSubjectAuthState,
}

fn contains_duplicate_recovery_authority_ids(authority_ids: &[RecoveryAuthorityId]) -> bool {
    for (index, authority_id) in authority_ids.iter().enumerate() {
        if authority_ids[index + 1..]
            .iter()
            .any(|other| other == authority_id)
        {
            return true;
        }
    }
    false
}

fn contains_duplicate_credential_recovery_authorities(
    authorities: &[CredentialRecoveryAuthority],
) -> bool {
    for (index, authority) in authorities.iter().enumerate() {
        if authorities[index + 1..].iter().any(|other| {
            other.target_credential_instance_id == authority.target_credential_instance_id
                && other.action == authority.action
                && other.authority_id == authority.authority_id
                && other.timing == authority.timing
        }) {
            return true;
        }
    }
    false
}

fn recovery_authority_id_sets_are_disjoint(
    left: &[RecoveryAuthorityId],
    right: &[RecoveryAuthorityId],
) -> bool {
    !left
        .iter()
        .any(|left_id| right.iter().any(|right_id| right_id == left_id))
}
