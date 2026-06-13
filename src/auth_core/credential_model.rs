use super::prelude::*;

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

/// Policy role used when resetting one credential instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CredentialResetPolicyRole {
    /// Ordinary credential reset policy for primary or convenience credentials.
    OrdinaryCredential,
    /// Second-factor reset policy for credentials that policy treats as independent factors.
    SecondFactorCredential,
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
    /// Policy role used for reset lifecycle transitions.
    reset_policy_role: CredentialResetPolicyRole,
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
        reset_policy_role: CredentialResetPolicyRole,
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
            reset_policy_role,
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

    /// Returns the reset policy role for this credential instance.
    pub const fn reset_policy_role(&self) -> CredentialResetPolicyRole {
        self.reset_policy_role
    }

    /// Returns the current lifecycle state.
    pub const fn lifecycle_state(&self) -> CredentialLifecycleState {
        self.lifecycle_state
    }

    /// Returns whether this credential can produce new proofs.
    pub const fn can_produce_new_proofs(&self) -> bool {
        self.lifecycle_state.can_produce_new_proofs()
    }

    /// Returns whether this credential can preserve subject access after another credential is removed.
    pub const fn can_preserve_subject_access_after_another_credential_is_removed(&self) -> bool {
        self.can_produce_new_proofs()
            && !matches!(self.kind, CredentialInstanceKind::TrustedDeviceCredential)
    }

    /// Returns whether this credential satisfies the survivor requirement after removing a credential.
    pub const fn satisfies_survivor_requirement_after_removing_credential_with_role(
        &self,
        removed_credential_reset_policy_role: CredentialResetPolicyRole,
    ) -> bool {
        if !self.can_preserve_subject_access_after_another_credential_is_removed() {
            return false;
        }
        match removed_credential_reset_policy_role {
            CredentialResetPolicyRole::OrdinaryCredential => true,
            CredentialResetPolicyRole::SecondFactorCredential => {
                matches!(
                    self.reset_policy_role,
                    CredentialResetPolicyRole::SecondFactorCredential
                )
            }
        }
    }

    /// Returns this metadata with a different lifecycle state.
    pub fn with_lifecycle_state(&self, lifecycle_state: CredentialLifecycleState) -> Self {
        Self {
            credential_instance_id: self.credential_instance_id.clone(),
            subject_id: self.subject_id.clone(),
            kind: self.kind,
            method_label: self.method_label.clone(),
            reset_policy_role: self.reset_policy_role,
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

/// Returns whether a subject still has an acceptable credential posture after removal.
pub fn subject_retains_required_credential_posture_after_removal<'a>(
    credentials: impl IntoIterator<Item = &'a CredentialInstanceMetadata>,
    recovery_authorities: impl IntoIterator<Item = &'a CredentialRecoveryAuthority>,
    subject_id: &SubjectId,
    removed_credential_instance_id: &VerifiedProofSourceId,
    removed_credential_reset_policy_role: CredentialResetPolicyRole,
) -> bool {
    let recovery_authorities: Vec<&CredentialRecoveryAuthority> =
        recovery_authorities.into_iter().collect();
    let survivors: Vec<&CredentialInstanceMetadata> = credentials
        .into_iter()
        .filter(|credential| {
            credential.subject_id() == subject_id
                && credential.credential_instance_id() != removed_credential_instance_id
                && credential.can_preserve_subject_access_after_another_credential_is_removed()
        })
        .collect();
    match removed_credential_reset_policy_role {
        CredentialResetPolicyRole::OrdinaryCredential => {
            !survivors.is_empty()
                && survivor_credentials_have_no_ordinary_second_factor_collapse(
                    &survivors,
                    &recovery_authorities,
                )
        }
        CredentialResetPolicyRole::SecondFactorCredential => {
            subject_retains_second_factor_credential_posture(&survivors, &recovery_authorities)
        }
    }
}

/// Returns whether a subject still has an acceptable credential posture after replacement.
pub fn subject_retains_required_credential_posture_after_replacement<'a>(
    credentials: impl IntoIterator<Item = &'a CredentialInstanceMetadata>,
    recovery_authorities: impl IntoIterator<Item = &'a CredentialRecoveryAuthority>,
    subject_id: &SubjectId,
    replaced_credential_instance_id: &VerifiedProofSourceId,
    replaced_credential_reset_policy_role: CredentialResetPolicyRole,
    successor: &'a CredentialReplacementSuccessor,
) -> bool {
    let credentials = credentials.into_iter().collect::<Vec<_>>();
    let recovery_authorities = recovery_authorities.into_iter().collect::<Vec<_>>();
    let mut after_credentials = credentials.clone();
    after_credentials.push(successor.metadata());
    let mut after_recovery_authorities = recovery_authorities.clone();
    after_recovery_authorities.extend(successor.recovery_authorities());
    if !subject_retains_required_credential_posture_after_removal(
        after_credentials,
        after_recovery_authorities.iter().copied(),
        subject_id,
        replaced_credential_instance_id,
        replaced_credential_reset_policy_role,
    ) {
        return false;
    }
    let survivor_credentials = credentials
        .into_iter()
        .filter(|credential| credential.credential_instance_id() != replaced_credential_instance_id)
        .collect::<Vec<_>>();
    subject_retains_required_credential_posture_after_addition(
        survivor_credentials,
        recovery_authorities,
        subject_id,
        successor.metadata(),
        successor.recovery_authorities(),
    )
}

/// Returns whether adding a credential would preserve honest factor posture.
pub fn subject_retains_required_credential_posture_after_addition<'a>(
    credentials: impl IntoIterator<Item = &'a CredentialInstanceMetadata>,
    recovery_authorities: impl IntoIterator<Item = &'a CredentialRecoveryAuthority>,
    subject_id: &SubjectId,
    added_credential: &'a CredentialInstanceMetadata,
    added_recovery_authorities: impl IntoIterator<Item = &'a CredentialRecoveryAuthority>,
) -> bool {
    if added_credential.subject_id() != subject_id
        || !added_credential.can_preserve_subject_access_after_another_credential_is_removed()
    {
        return true;
    }
    let existing_credentials = credentials
        .into_iter()
        .filter(|credential| {
            credential.subject_id() == subject_id
                && credential.can_preserve_subject_access_after_another_credential_is_removed()
        })
        .collect::<Vec<_>>();
    let mut all_recovery_authorities = recovery_authorities.into_iter().collect::<Vec<_>>();
    let added_recovery_authorities = added_recovery_authorities.into_iter().collect::<Vec<_>>();
    all_recovery_authorities.extend(added_recovery_authorities.iter().copied());
    match added_credential.reset_policy_role() {
        CredentialResetPolicyRole::OrdinaryCredential => existing_credentials
            .iter()
            .filter(|credential| {
                credential.reset_policy_role() == CredentialResetPolicyRole::SecondFactorCredential
            })
            .all(|second_factor| {
                credential_immediate_reset_authorities_are_independent(
                    added_credential,
                    second_factor,
                    &all_recovery_authorities,
                )
            }),
        CredentialResetPolicyRole::SecondFactorCredential => existing_credentials
            .iter()
            .filter(|credential| {
                credential.reset_policy_role() != CredentialResetPolicyRole::SecondFactorCredential
            })
            .all(|ordinary| {
                credential_immediate_reset_authorities_are_independent(
                    added_credential,
                    ordinary,
                    &all_recovery_authorities,
                )
            }),
    }
}

fn subject_retains_second_factor_credential_posture(
    survivors: &[&CredentialInstanceMetadata],
    recovery_authorities: &[&CredentialRecoveryAuthority],
) -> bool {
    let second_factor_survivors = survivors
        .iter()
        .copied()
        .filter(|credential| {
            credential.reset_policy_role() == CredentialResetPolicyRole::SecondFactorCredential
        })
        .collect::<Vec<_>>();
    if second_factor_survivors.is_empty() {
        return false;
    }
    survivor_credentials_have_no_ordinary_second_factor_collapse(survivors, recovery_authorities)
}

fn survivor_credentials_have_no_ordinary_second_factor_collapse(
    survivors: &[&CredentialInstanceMetadata],
    recovery_authorities: &[&CredentialRecoveryAuthority],
) -> bool {
    let second_factor_survivors = survivors
        .iter()
        .copied()
        .filter(|credential| {
            credential.reset_policy_role() == CredentialResetPolicyRole::SecondFactorCredential
        })
        .collect::<Vec<_>>();
    let ordinary_survivors = survivors
        .iter()
        .copied()
        .filter(|credential| {
            credential.reset_policy_role() != CredentialResetPolicyRole::SecondFactorCredential
        })
        .collect::<Vec<_>>();
    if ordinary_survivors.is_empty() {
        return true;
    }
    second_factor_survivors
        .iter()
        .all(|second_factor_survivor| {
            let second_factor_authorities = immediate_reset_authority_ids_for_credential(
                second_factor_survivor,
                recovery_authorities,
            );
            ordinary_survivors.iter().all(|ordinary_survivor| {
                let ordinary_authorities = immediate_reset_authority_ids_for_credential(
                    ordinary_survivor,
                    recovery_authorities,
                );
                immediate_reset_authority_id_sets_are_independent(
                    &second_factor_authorities,
                    &ordinary_authorities,
                )
            })
        })
}

fn credential_immediate_reset_authorities_are_independent(
    left: &CredentialInstanceMetadata,
    right: &CredentialInstanceMetadata,
    recovery_authorities: &[&CredentialRecoveryAuthority],
) -> bool {
    let left_authorities = immediate_reset_authority_ids_for_credential(left, recovery_authorities);
    let right_authorities =
        immediate_reset_authority_ids_for_credential(right, recovery_authorities);
    immediate_reset_authority_id_sets_are_independent(&left_authorities, &right_authorities)
}

fn immediate_reset_authority_id_sets_are_independent(
    left: &[RecoveryAuthorityId],
    right: &[RecoveryAuthorityId],
) -> bool {
    left.is_empty() || right.is_empty() || recovery_authority_id_sets_are_disjoint(left, right)
}

fn immediate_reset_authority_ids_for_credential<'a>(
    credential: &CredentialInstanceMetadata,
    recovery_authorities: &'a [&CredentialRecoveryAuthority],
) -> Vec<RecoveryAuthorityId> {
    recovery_authorities
        .iter()
        .filter_map(|authority| {
            (authority.target_credential_instance_id() == credential.credential_instance_id()
                && authority.action() == CredentialLifecycleAction::Reset
                && authority.timing().is_immediate())
            .then_some(authority.authority_id().clone())
        })
        .collect()
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
    /// Rotate verifier or secret material for an existing credential instance.
    Rotate,
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
            Self::Create | Self::Disable | Self::Rotate | Self::RecoverSubjectAccess => None,
        }
    }
}

/// Subject-level lifecycle action whose pending-action target is not a credential instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SubjectLifecycleAction {
    /// Delete or disable the subject's Paranoid-owned auth state after a waiting period.
    DeleteSubjectAuthState,
    /// Change a Paranoid-owned out-of-band identifier binding for the subject.
    ChangeOutOfBandIdentifier,
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
            Self::ChangeOutOfBandIdentifier => PendingLifecycleActionContract {
                target: PendingLifecycleActionTarget::SubjectOutOfBandIdentifierBinding,
                execution: PendingLifecycleActionExecution::CoreOutOfBandIdentifierBinding,
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
    /// The pending action targets one subject-owned out-of-band identifier binding.
    SubjectOutOfBandIdentifierBinding,
}

/// Execution shape required by a delayed lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PendingLifecycleActionExecution {
    /// The action must commit method-owned verifier, secret, or credential-set work.
    MethodOwnedCredential,
    /// The action mutates core out-of-band identifier binding state.
    CoreOutOfBandIdentifierBinding,
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

/// Runtime-verified admin/support authority for one credential lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAdminSupportCredentialLifecycleIntervention {
    /// Stable intervention id recorded as a lifecycle authority source.
    intervention_id: AdminSupportInterventionId,
    /// Subject this intervention is allowed to affect.
    target_subject_id: SubjectId,
    /// Credential this intervention is allowed to affect.
    target_credential_instance_id: VerifiedProofSourceId,
    /// Credential lifecycle action this intervention is allowed to authorize.
    action: CredentialLifecycleAction,
    /// Time the runtime verified the intervention.
    verified_at: UnixSeconds,
    /// Last instant before which this intervention may be used.
    expires_at: UnixSeconds,
}

impl VerifiedAdminSupportCredentialLifecycleIntervention {
    /// Creates one scoped admin/support lifecycle intervention.
    pub fn new(
        intervention_id: AdminSupportInterventionId,
        target_subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        verified_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, Error> {
        if expires_at <= verified_at {
            return Err(Error::InvalidConfig(
                "admin support intervention must expire after verification",
            ));
        }
        Ok(Self {
            intervention_id,
            target_subject_id,
            target_credential_instance_id,
            action,
            verified_at,
            expires_at,
        })
    }

    /// Returns the verified intervention id.
    pub const fn intervention_id(&self) -> &AdminSupportInterventionId {
        &self.intervention_id
    }

    /// Returns the subject this intervention may affect.
    pub const fn target_subject_id(&self) -> &SubjectId {
        &self.target_subject_id
    }

    /// Returns the credential this intervention may affect.
    pub const fn target_credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.target_credential_instance_id
    }

    /// Returns the lifecycle action this intervention may authorize.
    pub const fn action(&self) -> CredentialLifecycleAction {
        self.action
    }

    /// Returns when the intervention was verified.
    pub const fn verified_at(&self) -> UnixSeconds {
        self.verified_at
    }

    /// Returns when the intervention stops being usable.
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Returns whether the intervention is still usable at the supplied time.
    pub fn is_live_at(&self, now: UnixSeconds) -> bool {
        self.verified_at <= now && now < self.expires_at
    }

    fn matches_credential_lifecycle_target(
        &self,
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        self.target_subject_id == *target_credential.subject_id()
            && self.target_credential_instance_id == *target_credential.credential_instance_id()
            && self.action == action
            && self.is_live_at(now)
    }
}

/// Stored lifecycle state for one admin/support intervention.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdminSupportInterventionStatus {
    /// The intervention has been requested and can still be approved or denied.
    Requested,
    /// The intervention was approved and converted into lifecycle work.
    Approved,
    /// The intervention was denied without mutating credentials.
    Denied,
    /// The intervention expired before approval.
    Expired,
}

impl AdminSupportInterventionStatus {
    /// Returns whether this status keeps the intervention open.
    pub const fn is_requested(self) -> bool {
        matches!(self, Self::Requested)
    }
}

/// Stored admin/support intervention scoped to one credential lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSupportInterventionRecord {
    /// Stable intervention id.
    pub intervention_id: AdminSupportInterventionId,
    /// Subject this intervention is allowed to affect.
    pub subject_id: SubjectId,
    /// Credential this intervention is allowed to affect.
    pub target_credential_instance_id: VerifiedProofSourceId,
    /// Credential lifecycle action this intervention may authorize.
    pub action: CredentialLifecycleAction,
    /// Stored intervention status.
    pub status: AdminSupportInterventionStatus,
    /// Time this intervention was requested.
    pub requested_at: UnixSeconds,
    /// Last instant before which this intervention may be approved or denied.
    pub expires_at: UnixSeconds,
    /// Closure timestamp for approved, denied, or expired interventions.
    pub closed_at: Option<UnixSeconds>,
}

impl AdminSupportInterventionRecord {
    /// Creates an open admin/support intervention request.
    pub fn new_requested(
        intervention_id: AdminSupportInterventionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        requested_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, Error> {
        if expires_at <= requested_at {
            return Err(Error::InvalidAdminSupportInterventionTiming);
        }
        Ok(Self {
            intervention_id,
            subject_id,
            target_credential_instance_id,
            action,
            status: AdminSupportInterventionStatus::Requested,
            requested_at,
            expires_at,
            closed_at: None,
        })
    }

    /// Returns whether this intervention can still be approved or denied at `now`.
    pub fn is_open_at(&self, now: UnixSeconds) -> bool {
        self.status.is_requested() && self.closed_at.is_none() && now < self.expires_at
    }

    /// Returns whether this intervention is still open but expired at `now`.
    pub fn is_expired_open_at(&self, now: UnixSeconds) -> bool {
        self.status.is_requested() && self.closed_at.is_none() && self.expires_at <= now
    }

    /// Converts an open stored intervention into runtime-verified lifecycle evidence.
    pub fn verified_at(
        &self,
        verified_at: UnixSeconds,
    ) -> Result<VerifiedAdminSupportCredentialLifecycleIntervention, Error> {
        if !self.is_open_at(verified_at) {
            return Err(Error::AdminSupportInterventionNotApprovable);
        }
        VerifiedAdminSupportCredentialLifecycleIntervention::new(
            self.intervention_id.clone(),
            self.subject_id.clone(),
            self.target_credential_instance_id.clone(),
            self.action,
            verified_at,
            self.expires_at,
        )
    }
}

/// Lifecycle evidence source presented to a credential lifecycle policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAuthoritySource {
    /// A satisfied proof source.
    VerifiedProofSource(VerifiedProofSource),
    /// A live authenticated session.
    AuthenticatedSession(SessionId),
    /// A runtime-verified admin/support intervention scoped to one lifecycle action.
    AdminSupportIntervention(VerifiedAdminSupportCredentialLifecycleIntervention),
}

impl LifecycleAuthoritySource {
    pub(crate) fn storage_key(&self) -> (LifecycleAuthoritySourceKind, VerifiedProofSourceId) {
        match self {
            Self::VerifiedProofSource(source) => {
                let kind = match source.kind() {
                    VerifiedProofSourceKind::CredentialInstance => {
                        LifecycleAuthoritySourceKind::CredentialInstance
                    }
                    VerifiedProofSourceKind::OutOfBandIdentifier => {
                        LifecycleAuthoritySourceKind::OutOfBandIdentifier
                    }
                    VerifiedProofSourceKind::ExternalAuthority => {
                        LifecycleAuthoritySourceKind::ExternalAuthority
                    }
                };
                (kind, source.source_id().clone())
            }
            Self::AuthenticatedSession(session_id) => (
                LifecycleAuthoritySourceKind::AuthenticatedSession,
                VerifiedProofSourceId::from_bytes(session_id.as_bytes().to_vec())
                    .expect("session id already validated as an auth id"),
            ),
            Self::AdminSupportIntervention(intervention) => (
                LifecycleAuthoritySourceKind::AdminSupportIntervention,
                VerifiedProofSourceId::from_bytes(
                    intervention.intervention_id().as_bytes().to_vec(),
                )
                .expect("intervention id already validated as an auth id"),
            ),
        }
    }
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
        intervention: VerifiedAdminSupportCredentialLifecycleIntervention,
        authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        Self::new(
            LifecycleAuthoritySource::AdminSupportIntervention(intervention),
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

    fn can_be_used_for_credential_lifecycle_action(
        &self,
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        match &self.source {
            LifecycleAuthoritySource::VerifiedProofSource(_)
            | LifecycleAuthoritySource::AuthenticatedSession(_) => true,
            LifecycleAuthoritySource::AdminSupportIntervention(intervention) => {
                intervention.matches_credential_lifecycle_target(target_credential, action, now)
            }
        }
    }

    fn can_be_used_for_subject_lifecycle_action(
        &self,
        _subject_id: &SubjectId,
        _action: SubjectLifecycleAction,
        _now: UnixSeconds,
    ) -> bool {
        match &self.source {
            LifecycleAuthoritySource::VerifiedProofSource(_)
            | LifecycleAuthoritySource::AuthenticatedSession(_) => true,
            LifecycleAuthoritySource::AdminSupportIntervention(_) => false,
        }
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
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        if !evidence.can_be_used_for_credential_lifecycle_action(target_credential, action, now) {
            return false;
        }
        let target_credential_instance_id = target_credential.credential_instance_id();
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
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        if !evidence.can_be_used_for_credential_lifecycle_action(target_credential, action, now) {
            return false;
        }
        let target_credential_instance_id = target_credential.credential_instance_id();
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
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        if !evidence.can_be_used_for_credential_lifecycle_action(target_credential, action, now) {
            return false;
        }
        !self.evidence_can_immediately_authorize_credential_action(
            evidence,
            target_credential,
            action,
            now,
        )
    }

    /// Returns whether any presented evidence can immediately authorize the target action.
    pub fn evidence_set_can_immediately_authorize_credential_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_can_immediately_authorize_credential_action(
                evidence,
                target_credential,
                action,
                now,
            )
        })
    }

    /// Returns whether any presented evidence can schedule the target action for delayed execution.
    pub fn evidence_set_can_schedule_delayed_credential_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_can_schedule_delayed_credential_action(
                evidence,
                target_credential,
                action,
                now,
            )
        })
    }

    /// Returns whether any presented evidence is independent from the target action.
    pub fn evidence_set_contains_independent_evidence_for_credential_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_is_independent_for_credential_action(
                evidence,
                target_credential,
                action,
                now,
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
    pub fn evaluate_action_at(
        &self,
        now: UnixSeconds,
        action: CredentialLifecycleAction,
        independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    ) -> CredentialLifecycleActionDecision {
        if !self.target_credential.can_produce_new_proofs() {
            return CredentialLifecycleActionDecision::Rejected;
        }
        if self
            .recovery_authority_graph
            .evidence_set_can_immediately_authorize_credential_action(
                &self.presented_evidence,
                &self.target_credential,
                action,
                now,
            )
        {
            if independent_evidence_required.is_required()
                && !self
                    .recovery_authority_graph
                    .evidence_set_contains_independent_evidence_for_credential_action(
                        &self.presented_evidence,
                        &self.target_credential,
                        action,
                        now,
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
                &self.target_credential,
                action,
                now,
            )
        {
            return CredentialLifecycleActionDecision::RequiresDelayedAction;
        }
        CredentialLifecycleActionDecision::Rejected
    }
}

/// Recovery authority for one subject-level lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectLifecycleAuthority {
    /// Subject this authority can mutate.
    subject_id: SubjectId,
    /// Subject lifecycle action authorized by this record.
    action: SubjectLifecycleAction,
    /// Effective recovery authority.
    authority_id: RecoveryAuthorityId,
    /// Whether this authority can act immediately.
    timing: RecoveryAuthorityTiming,
}

impl SubjectLifecycleAuthority {
    /// Creates a subject lifecycle authority record.
    pub fn new(
        subject_id: SubjectId,
        action: SubjectLifecycleAction,
        authority_id: RecoveryAuthorityId,
        timing: RecoveryAuthorityTiming,
    ) -> Self {
        Self {
            subject_id,
            action,
            authority_id,
            timing,
        }
    }

    /// Returns the subject this authority can mutate.
    pub const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    /// Returns the lifecycle action.
    pub const fn action(&self) -> SubjectLifecycleAction {
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

/// Lifecycle state for a Paranoid-owned out-of-band identifier binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OutOfBandIdentifierBindingLifecycleState {
    /// The identifier has been proven reachable but is not active yet.
    PendingActivation,
    /// The identifier may resolve proofs for the subject.
    Active,
    /// The identifier binding has been replaced by another binding.
    Superseded,
    /// The identifier binding was revoked by lifecycle policy.
    Revoked,
}

impl OutOfBandIdentifierBindingLifecycleState {
    /// Returns whether this binding may resolve new proofs.
    pub const fn can_resolve_new_proofs(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns whether this binding may be activated by an identifier-change transition.
    pub const fn can_be_activated_by_identifier_change(self) -> bool {
        matches!(self, Self::PendingActivation)
    }
}

/// Core-visible binding between an out-of-band proof source and a subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutOfBandIdentifierBindingRecord {
    /// Verified proof source that represents the canonical out-of-band identifier.
    source: VerifiedProofSource,
    /// Subject that owns the binding.
    subject_id: SubjectId,
    /// Method label that owns canonicalization and delivery for this binding.
    proof_method_label: String,
    /// Current binding lifecycle state.
    lifecycle_state: OutOfBandIdentifierBindingLifecycleState,
}

impl OutOfBandIdentifierBindingRecord {
    /// Creates one out-of-band identifier binding record.
    pub fn new(
        source: VerifiedProofSource,
        subject_id: SubjectId,
        proof_method_label: impl Into<String>,
        lifecycle_state: OutOfBandIdentifierBindingLifecycleState,
    ) -> Result<Self, Error> {
        if source.kind() != VerifiedProofSourceKind::OutOfBandIdentifier {
            return Err(Error::InvalidConfig(
                "out-of-band identifier binding source must be an out-of-band identifier",
            ));
        }
        let proof_method_label = proof_method_label.into();
        if proof_method_label.is_empty() {
            return Err(Error::EmptyProofMethodLabel);
        }
        validate_auth_identifier_string(
            "out-of-band identifier binding proof method label",
            &proof_method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(Self {
            source,
            subject_id,
            proof_method_label,
            lifecycle_state,
        })
    }

    /// Returns the verified proof source for this binding.
    pub const fn source(&self) -> &VerifiedProofSource {
        &self.source
    }

    /// Returns the subject that owns this binding.
    pub const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    /// Returns the method label that owns this binding.
    pub fn proof_method_label(&self) -> &str {
        &self.proof_method_label
    }

    /// Returns the binding lifecycle state.
    pub const fn lifecycle_state(&self) -> OutOfBandIdentifierBindingLifecycleState {
        self.lifecycle_state
    }

    /// Returns whether this binding may resolve new proofs.
    pub const fn can_resolve_new_proofs(&self) -> bool {
        self.lifecycle_state.can_resolve_new_proofs()
    }

    /// Returns whether this binding may be activated by an identifier-change transition.
    pub const fn can_be_activated_by_identifier_change(&self) -> bool {
        self.lifecycle_state.can_be_activated_by_identifier_change()
    }

    /// Returns this binding with a different lifecycle state.
    pub fn with_lifecycle_state(
        mut self,
        lifecycle_state: OutOfBandIdentifierBindingLifecycleState,
    ) -> Self {
        self.lifecycle_state = lifecycle_state;
        self
    }
}

/// Recovery-authority graph for subject-level lifecycle policy checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectLifecycleAuthorityGraph {
    /// Subject-level authority records.
    authorities: Vec<SubjectLifecycleAuthority>,
}

impl SubjectLifecycleAuthorityGraph {
    /// Creates a subject lifecycle authority graph.
    pub fn new(
        authorities: impl IntoIterator<Item = SubjectLifecycleAuthority>,
    ) -> Result<Self, Error> {
        let authorities: Vec<SubjectLifecycleAuthority> = authorities.into_iter().collect();
        if contains_duplicate_subject_lifecycle_authorities(&authorities) {
            return Err(Error::InvalidConfig(
                "subject lifecycle authority graph must not contain duplicate authorities",
            ));
        }
        Ok(Self { authorities })
    }

    /// Returns the authority records.
    pub fn authorities(&self) -> &[SubjectLifecycleAuthority] {
        &self.authorities
    }

    /// Returns whether evidence can immediately authorize the subject action.
    pub fn evidence_can_immediately_authorize_subject_action(
        &self,
        evidence: &LifecycleAuthorityEvidence,
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        if !evidence.can_be_used_for_subject_lifecycle_action(subject_id, action, now) {
            return false;
        }
        self.authorities.iter().any(|authority| {
            authority.subject_id == *subject_id
                && authority.action == action
                && authority.timing.is_immediate()
                && evidence
                    .authority_ids
                    .iter()
                    .any(|authority_id| authority_id == &authority.authority_id)
        })
    }

    /// Returns whether evidence can schedule the subject action for delayed execution.
    pub fn evidence_can_schedule_delayed_subject_action(
        &self,
        evidence: &LifecycleAuthorityEvidence,
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        if !evidence.can_be_used_for_subject_lifecycle_action(subject_id, action, now) {
            return false;
        }
        self.authorities.iter().any(|authority| {
            authority.subject_id == *subject_id
                && authority.action == action
                && authority.timing == RecoveryAuthorityTiming::Delayed
                && evidence
                    .authority_ids
                    .iter()
                    .any(|authority_id| authority_id == &authority.authority_id)
        })
    }

    /// Returns whether evidence is independent for the subject action.
    pub fn evidence_is_independent_for_subject_action(
        &self,
        evidence: &LifecycleAuthorityEvidence,
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        if !evidence.can_be_used_for_subject_lifecycle_action(subject_id, action, now) {
            return false;
        }
        !self.evidence_can_immediately_authorize_subject_action(evidence, subject_id, action, now)
    }

    /// Returns whether any presented evidence can immediately authorize the subject action.
    pub fn evidence_set_can_immediately_authorize_subject_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_can_immediately_authorize_subject_action(
                evidence, subject_id, action, now,
            )
        })
    }

    /// Returns whether any presented evidence can schedule the subject action.
    pub fn evidence_set_can_schedule_delayed_subject_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_can_schedule_delayed_subject_action(evidence, subject_id, action, now)
        })
    }

    /// Returns whether any presented evidence is independent from the subject action.
    pub fn evidence_set_contains_independent_evidence_for_subject_action(
        &self,
        evidence: &[LifecycleAuthorityEvidence],
        subject_id: &SubjectId,
        action: SubjectLifecycleAction,
        now: UnixSeconds,
    ) -> bool {
        evidence.iter().any(|evidence| {
            self.evidence_is_independent_for_subject_action(evidence, subject_id, action, now)
        })
    }
}

/// Loaded lifecycle-policy context for one subject-level action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectLifecycleActionContext {
    subject_id: SubjectId,
    authority_graph: SubjectLifecycleAuthorityGraph,
    presented_evidence: Vec<LifecycleAuthorityEvidence>,
}

impl SubjectLifecycleActionContext {
    /// Creates loaded lifecycle-policy context for one subject.
    pub fn new(
        subject_id: SubjectId,
        authority_graph: SubjectLifecycleAuthorityGraph,
        presented_evidence: impl IntoIterator<Item = LifecycleAuthorityEvidence>,
    ) -> Self {
        Self {
            subject_id,
            authority_graph,
            presented_evidence: presented_evidence.into_iter().collect(),
        }
    }

    /// Returns the target subject.
    pub const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    /// Returns the authority graph for this subject.
    pub const fn authority_graph(&self) -> &SubjectLifecycleAuthorityGraph {
        &self.authority_graph
    }

    /// Returns the presented lifecycle evidence.
    pub fn presented_evidence(&self) -> &[LifecycleAuthorityEvidence] {
        &self.presented_evidence
    }

    /// Evaluates whether the presented evidence may perform or schedule a subject action.
    pub fn evaluate_action_at(
        &self,
        now: UnixSeconds,
        action: SubjectLifecycleAction,
        independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement,
    ) -> SubjectLifecycleActionDecision {
        if self
            .authority_graph
            .evidence_set_can_immediately_authorize_subject_action(
                &self.presented_evidence,
                &self.subject_id,
                action,
                now,
            )
        {
            if independent_evidence_required.is_required()
                && !self
                    .authority_graph
                    .evidence_set_contains_independent_evidence_for_subject_action(
                        &self.presented_evidence,
                        &self.subject_id,
                        action,
                        now,
                    )
            {
                return SubjectLifecycleActionDecision::RequiresDelayedAction;
            }
            return SubjectLifecycleActionDecision::AuthorizedImmediate;
        }
        if self
            .authority_graph
            .evidence_set_can_schedule_delayed_subject_action(
                &self.presented_evidence,
                &self.subject_id,
                action,
                now,
            )
        {
            return SubjectLifecycleActionDecision::RequiresDelayedAction;
        }
        SubjectLifecycleActionDecision::Rejected
    }
}

/// Whether an immediate subject lifecycle action requires independent evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SubjectLifecycleIndependentEvidenceRequirement {
    /// The lifecycle action may be performed by the configured authority alone.
    NotRequired,
    /// The lifecycle action needs some presented evidence independent from that authority.
    Required,
}

impl SubjectLifecycleIndependentEvidenceRequirement {
    /// Returns whether independent evidence is required.
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// Decision for a subject lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SubjectLifecycleActionDecision {
    /// The action may commit immediately.
    AuthorizedImmediate,
    /// The presented evidence can start the action, but immediate mutation would degrade auth.
    RequiresDelayedAction,
    /// The action is not authorized by the loaded subject lifecycle policy.
    Rejected,
}

/// Loaded policy context for changing a subject's out-of-band identifier binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutOfBandIdentifierChangeContext {
    subject_lifecycle_context: SubjectLifecycleActionContext,
    current_identifier_source: VerifiedProofSource,
    candidate_identifier_source: VerifiedProofSource,
}

impl OutOfBandIdentifierChangeContext {
    /// Creates a subject identifier-change context.
    pub fn new(
        subject_lifecycle_context: SubjectLifecycleActionContext,
        current_identifier_source: VerifiedProofSource,
        candidate_identifier_source: VerifiedProofSource,
    ) -> Result<Self, Error> {
        if current_identifier_source.kind() != VerifiedProofSourceKind::OutOfBandIdentifier {
            return Err(Error::InvalidConfig(
                "current identifier source must be an out-of-band identifier",
            ));
        }
        if candidate_identifier_source.kind() != VerifiedProofSourceKind::OutOfBandIdentifier {
            return Err(Error::InvalidConfig(
                "candidate identifier source must be an out-of-band identifier",
            ));
        }
        if current_identifier_source.source_id() == candidate_identifier_source.source_id() {
            return Err(Error::InvalidConfig(
                "identifier change requires distinct current and candidate identifier sources",
            ));
        }
        if subject_lifecycle_context
            .presented_evidence()
            .iter()
            .any(|evidence| {
                evidence_has_verified_proof_source(evidence, &candidate_identifier_source)
            })
        {
            return Err(Error::InvalidConfig(
                "candidate identifier proof cannot authorize its own binding",
            ));
        }
        Ok(Self {
            subject_lifecycle_context,
            current_identifier_source,
            candidate_identifier_source,
        })
    }

    /// Returns the subject lifecycle policy context.
    pub const fn subject_lifecycle_context(&self) -> &SubjectLifecycleActionContext {
        &self.subject_lifecycle_context
    }

    /// Returns the current identifier source being replaced or superseded.
    pub const fn current_identifier_source(&self) -> &VerifiedProofSource {
        &self.current_identifier_source
    }

    /// Returns the candidate identifier source already proven reachable.
    pub const fn candidate_identifier_source(&self) -> &VerifiedProofSource {
        &self.candidate_identifier_source
    }

    /// Evaluates whether the identifier change may execute or must wait.
    pub fn evaluate_action_at(
        &self,
        now: UnixSeconds,
        independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement,
    ) -> SubjectLifecycleActionDecision {
        self.subject_lifecycle_context.evaluate_action_at(
            now,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
            independent_evidence_required,
        )
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
    /// Current identifier source for a delayed out-of-band identifier change.
    pub current_identifier_source_id: Option<VerifiedProofSourceId>,
    /// Candidate identifier source for a delayed out-of-band identifier change.
    pub candidate_identifier_source_id: Option<VerifiedProofSourceId>,
    /// Recovery authorities represented by the candidate identifier after activation.
    pub candidate_identifier_authority_ids: Vec<RecoveryAuthorityId>,
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
        if action != SubjectLifecycleAction::DeleteSubjectAuthState {
            return Err(Error::InvalidConfig(
                "subject lifecycle pending action target details are required for this action",
            ));
        }
        Ok(Self {
            pending_action_id,
            subject_id,
            action,
            current_identifier_source_id: None,
            candidate_identifier_source_id: None,
            candidate_identifier_authority_ids: Vec::new(),
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at: None,
        })
    }

    /// Creates an open delayed out-of-band identifier change action.
    pub fn new_open_out_of_band_identifier_change(
        pending_action_id: PendingSubjectLifecycleActionId,
        subject_id: SubjectId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_authority_ids: Vec<RecoveryAuthorityId>,
        requested_at: UnixSeconds,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, Error> {
        if earliest_execute_at <= requested_at || expires_at <= earliest_execute_at {
            return Err(Error::InvalidSubjectLifecyclePendingActionTiming);
        }
        if current_identifier_source_id == candidate_identifier_source_id {
            return Err(Error::InvalidConfig(
                "pending identifier change requires distinct current and candidate sources",
            ));
        }
        if candidate_identifier_authority_ids.is_empty() {
            return Err(Error::InvalidConfig(
                "pending identifier change candidate must name at least one recovery authority",
            ));
        }
        if candidate_identifier_authority_ids.len()
            > OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT
        {
            return Err(Error::InvalidConfig(
                "pending identifier change candidate names too many recovery authorities",
            ));
        }
        if contains_duplicate_recovery_authority_ids(&candidate_identifier_authority_ids) {
            return Err(Error::InvalidConfig(
                "pending identifier change candidate must not duplicate recovery authorities",
            ));
        }
        Ok(Self {
            pending_action_id,
            subject_id,
            action: SubjectLifecycleAction::ChangeOutOfBandIdentifier,
            current_identifier_source_id: Some(current_identifier_source_id),
            candidate_identifier_source_id: Some(candidate_identifier_source_id),
            candidate_identifier_authority_ids,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at: None,
        })
    }

    /// Validates that the stored target fields match the subject lifecycle action.
    pub fn validate_target_details(&self) -> Result<(), Error> {
        match self.action {
            SubjectLifecycleAction::DeleteSubjectAuthState => {
                if self.current_identifier_source_id.is_some()
                    || self.candidate_identifier_source_id.is_some()
                    || !self.candidate_identifier_authority_ids.is_empty()
                {
                    return Err(Error::InvalidConfig(
                        "subject auth-state deletion pending action must not carry identifier-change target details",
                    ));
                }
            }
            SubjectLifecycleAction::ChangeOutOfBandIdentifier => {
                let Some(current_identifier_source_id) = &self.current_identifier_source_id else {
                    return Err(Error::InvalidConfig(
                        "pending identifier change is missing current identifier source",
                    ));
                };
                let Some(candidate_identifier_source_id) = &self.candidate_identifier_source_id
                else {
                    return Err(Error::InvalidConfig(
                        "pending identifier change is missing candidate identifier source",
                    ));
                };
                if current_identifier_source_id == candidate_identifier_source_id {
                    return Err(Error::InvalidConfig(
                        "pending identifier change requires distinct current and candidate sources",
                    ));
                }
                if self.candidate_identifier_authority_ids.is_empty() {
                    return Err(Error::InvalidConfig(
                        "pending identifier change candidate must name at least one recovery authority",
                    ));
                }
                if self.candidate_identifier_authority_ids.len()
                    > OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT
                {
                    return Err(Error::InvalidConfig(
                        "pending identifier change candidate names too many recovery authorities",
                    ));
                }
                if contains_duplicate_recovery_authority_ids(
                    &self.candidate_identifier_authority_ids,
                ) {
                    return Err(Error::InvalidConfig(
                        "pending identifier change candidate must not duplicate recovery authorities",
                    ));
                }
            }
        }
        Ok(())
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

pub(crate) fn contains_duplicate_recovery_authority_ids(
    authority_ids: &[RecoveryAuthorityId],
) -> bool {
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

fn contains_duplicate_subject_lifecycle_authorities(
    authorities: &[SubjectLifecycleAuthority],
) -> bool {
    for (index, authority) in authorities.iter().enumerate() {
        if authorities[index + 1..].iter().any(|other| {
            other.subject_id == authority.subject_id
                && other.action == authority.action
                && other.authority_id == authority.authority_id
        }) {
            return true;
        }
    }
    false
}

fn evidence_has_verified_proof_source(
    evidence: &LifecycleAuthorityEvidence,
    source: &VerifiedProofSource,
) -> bool {
    matches!(
        evidence.source(),
        LifecycleAuthoritySource::VerifiedProofSource(evidence_source)
            if evidence_source == source
    )
}

fn recovery_authority_id_sets_are_disjoint(
    left: &[RecoveryAuthorityId],
    right: &[RecoveryAuthorityId],
) -> bool {
    !left
        .iter()
        .any(|left_id| right.iter().any(|right_id| right_id == left_id))
}
