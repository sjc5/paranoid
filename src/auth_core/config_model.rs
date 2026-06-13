use super::prelude::*;

/// Core lifecycle configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// How long a freshly authenticated session remains alive.
    pub short_session_lifetime: DurationSeconds,
    /// Final portion of the session lifetime where authoritative validation refreshes the session.
    pub session_refresh_window: DurationSeconds,
    /// How long a recently used trusted device may silently revive a dead session.
    pub trusted_device_silent_revival_lifetime: DurationSeconds,
    /// Absolute lifetime of a trusted device credential.
    pub trusted_device_credential_lifetime: DurationSeconds,
    /// How long a completed step-up proof remains fresh for sensitive requests.
    pub step_up_lifetime: DurationSeconds,
    /// Optional bounded authoritative-validation cache for safe reads only.
    pub safe_read_cache_lifetime: Option<DurationSeconds>,
    /// How long an immediately previous credential secret remains acceptable for races.
    pub stale_secret_grace_lifetime: DurationSeconds,
    /// How long an active-proof attempt may remain open.
    pub active_proof_attempt_lifetime: DurationSeconds,
    /// How long an out-of-band challenge may remain open.
    pub out_of_band_challenge_lifetime: DurationSeconds,
    /// How long a live out-of-band challenge suppresses replacement for the same dedupe key.
    pub out_of_band_challenge_replacement_cooldown: DurationSeconds,
    /// User-visible resends allowed for one out-of-band challenge.
    pub max_out_of_band_challenge_resends_per_challenge: u32,
    /// Weak proof failures allowed before the attempt is hard-deleted.
    pub max_weak_proof_failures_per_attempt: u32,
    /// Cheap gate required before unauthenticated active-proof challenge issue.
    pub unauthenticated_challenge_issue_preflight_gate: WeakProofGateSummary,
    /// Policy for credential and subject-auth lifecycle mutations.
    pub credential_lifecycle_policy: CredentialLifecyclePolicy,
    /// Proof-stack policy for final auth transitions.
    pub proof_policy: ProofPolicy,
}

impl Config {
    /// Validates relationships among lifecycle durations.
    pub fn validate(&self) -> Result<(), Error> {
        if self.short_session_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "short_session_lifetime must be non-zero",
            ));
        }
        if self.session_refresh_window >= self.short_session_lifetime {
            return Err(Error::InvalidConfig(
                "session_refresh_window must be shorter than short_session_lifetime",
            ));
        }
        if self.stale_secret_grace_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "stale_secret_grace_lifetime must be non-zero",
            ));
        }
        if self.stale_secret_grace_lifetime >= self.session_refresh_window {
            return Err(Error::InvalidConfig(
                "stale_secret_grace_lifetime must be shorter than session_refresh_window",
            ));
        }
        if self.trusted_device_silent_revival_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "trusted_device_silent_revival_lifetime must be non-zero",
            ));
        }
        if self.trusted_device_credential_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "trusted_device_credential_lifetime must be non-zero",
            ));
        }
        if self.stale_secret_grace_lifetime >= self.trusted_device_credential_lifetime {
            return Err(Error::InvalidConfig(
                "stale_secret_grace_lifetime must be shorter than trusted_device_credential_lifetime",
            ));
        }
        if self.step_up_lifetime.is_zero() {
            return Err(Error::InvalidConfig("step_up_lifetime must be non-zero"));
        }
        if self.active_proof_attempt_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "active_proof_attempt_lifetime must be non-zero",
            ));
        }
        if self.out_of_band_challenge_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "out_of_band_challenge_lifetime must be non-zero",
            ));
        }
        if self.out_of_band_challenge_replacement_cooldown.is_zero() {
            return Err(Error::InvalidConfig(
                "out_of_band_challenge_replacement_cooldown must be non-zero",
            ));
        }
        if self.out_of_band_challenge_replacement_cooldown >= self.out_of_band_challenge_lifetime {
            return Err(Error::InvalidConfig(
                "out_of_band_challenge_replacement_cooldown must be shorter than out_of_band_challenge_lifetime",
            ));
        }
        if self.max_weak_proof_failures_per_attempt == 0 {
            return Err(Error::InvalidConfig(
                "max_weak_proof_failures_per_attempt must be non-zero",
            ));
        }
        self.credential_lifecycle_policy.validate()?;
        self.proof_policy.validate()?;
        if let Some(safe_read_cache_lifetime) = self.safe_read_cache_lifetime
            && safe_read_cache_lifetime.is_zero()
        {
            return Err(Error::InvalidConfig(
                "safe_read_cache_lifetime must be None or non-zero",
            ));
        }
        Ok(())
    }
}

/// Lifecycle mutation policy owned by the auth runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLifecyclePolicy {
    /// Policy for authenticated credential additions.
    pub credential_addition: CredentialAdditionLifecyclePolicy,
    /// Policies for credential reset planning and execution.
    pub credential_reset: CredentialResetLifecyclePolicies,
    /// Policy for authenticated credential replacement planning and execution.
    pub credential_replacement: CredentialReplacementLifecyclePolicy,
    /// Policy for authenticated credential removal planning and execution.
    pub credential_removal: CredentialRemovalLifecyclePolicy,
    /// Policy for authenticated credential-set regeneration planning.
    pub credential_regeneration: CredentialRegenerationLifecyclePolicy,
    /// Policy for authenticated credential rotation execution.
    pub credential_rotation: CredentialRotationLifecyclePolicy,
    /// Freshness required before cancelling delayed replacement, removal, or regeneration.
    pub credential_lifecycle_cancellation_step_up_freshness: StepUpFreshnessRequirement,
    /// Policy for subject-auth-state deletion.
    pub subject_auth_state_deletion: SubjectAuthStateDeletionLifecyclePolicy,
    /// Policy for out-of-band identifier changes.
    pub out_of_band_identifier_change: OutOfBandIdentifierChangeLifecyclePolicy,
    /// Policy for support/admin intervention candidates and approval.
    pub admin_support_intervention: AdminSupportInterventionLifecyclePolicy,
}

impl CredentialLifecyclePolicy {
    /// Validates lifecycle policy timing relationships.
    pub fn validate(&self) -> Result<(), Error> {
        self.credential_addition.validate()?;
        self.credential_reset.validate()?;
        self.credential_replacement.validate()?;
        self.credential_removal.validate()?;
        self.credential_regeneration.validate()?;
        self.credential_rotation.validate()?;
        self.subject_auth_state_deletion.validate()?;
        self.out_of_band_identifier_change.validate()?;
        self.admin_support_intervention.validate()
    }
}

/// Policy for authenticated credential addition lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialAdditionLifecyclePolicy {
    /// Whether immediate create authority must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Freshness required before adding a credential through an authenticated session.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
}

impl CredentialAdditionLifecyclePolicy {
    /// Validates addition lifecycle policy.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Reset policies keyed by the target credential's reset policy role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialResetLifecyclePolicies {
    /// Policy for ordinary credential resets.
    pub ordinary_credential: CredentialResetLifecyclePolicy,
    /// Policy for second-factor credential resets.
    pub second_factor_credential: CredentialResetLifecyclePolicy,
}

impl CredentialResetLifecyclePolicies {
    /// Returns the reset lifecycle policy for a loaded credential role.
    pub const fn policy_for_role(
        &self,
        role: CredentialResetPolicyRole,
    ) -> &CredentialResetLifecyclePolicy {
        match role {
            CredentialResetPolicyRole::OrdinaryCredential => &self.ordinary_credential,
            CredentialResetPolicyRole::SecondFactorCredential => &self.second_factor_credential,
        }
    }

    pub(crate) const fn role_independent_authenticated_planning_step_up_freshness(
        &self,
    ) -> Option<StepUpFreshnessRequirement> {
        shared_step_up_freshness(
            self.ordinary_credential
                .authenticated_planning_step_up_freshness,
            self.second_factor_credential
                .authenticated_planning_step_up_freshness,
        )
    }

    pub(crate) const fn role_independent_authenticated_execution_step_up_freshness(
        &self,
    ) -> Option<StepUpFreshnessRequirement> {
        shared_step_up_freshness(
            self.ordinary_credential
                .authenticated_execution_step_up_freshness,
            self.second_factor_credential
                .authenticated_execution_step_up_freshness,
        )
    }

    pub(crate) const fn role_independent_authenticated_cancellation_step_up_freshness(
        &self,
    ) -> Option<StepUpFreshnessRequirement> {
        shared_step_up_freshness(
            self.ordinary_credential
                .authenticated_cancellation_step_up_freshness,
            self.second_factor_credential
                .authenticated_cancellation_step_up_freshness,
        )
    }

    /// Validates reset lifecycle policies.
    pub fn validate(&self) -> Result<(), Error> {
        self.ordinary_credential.validate()?;
        self.second_factor_credential.validate()
    }
}

/// Policy for credential reset lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialResetLifecyclePolicy {
    /// Whether immediate reset authority must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Schedule used when reset policy requires delayed execution.
    pub delayed_action_timing: Option<DelayedLifecycleActionTimingPolicy>,
    /// Freshness required before authenticated reset planning.
    pub authenticated_planning_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before authenticated immediate reset execution.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before cancelling a delayed reset.
    pub authenticated_cancellation_step_up_freshness: StepUpFreshnessRequirement,
}

impl CredentialResetLifecyclePolicy {
    /// Validates reset lifecycle policy timing.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(timing) = self.delayed_action_timing {
            timing.validate()?;
        }
        Ok(())
    }
}

/// Policy for credential replacement lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReplacementLifecyclePolicy {
    /// Whether immediate replacement authority must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Schedule used when replacement policy requires delayed execution.
    pub delayed_action_timing: Option<DelayedLifecycleActionTimingPolicy>,
    /// Freshness required before authenticated replacement planning.
    pub authenticated_planning_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before authenticated immediate replacement execution.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
}

impl CredentialReplacementLifecyclePolicy {
    /// Validates replacement lifecycle policy timing.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(timing) = self.delayed_action_timing {
            timing.validate()?;
        }
        Ok(())
    }
}

/// Policy for credential removal lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRemovalLifecyclePolicy {
    /// Whether immediate removal authority must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Schedule used when removal policy requires delayed execution.
    pub delayed_action_timing: Option<DelayedLifecycleActionTimingPolicy>,
    /// Freshness required before authenticated removal planning.
    pub authenticated_planning_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before authenticated immediate removal execution.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
}

impl CredentialRemovalLifecyclePolicy {
    /// Validates removal lifecycle policy timing.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(timing) = self.delayed_action_timing {
            timing.validate()?;
        }
        Ok(())
    }
}

/// Policy for credential-set regeneration lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRegenerationLifecyclePolicy {
    /// Whether immediate regeneration authority must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Schedule used when regeneration policy requires delayed execution.
    pub delayed_action_timing: Option<DelayedLifecycleActionTimingPolicy>,
    /// Freshness required before authenticated regeneration planning.
    pub authenticated_planning_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before authenticated immediate regeneration execution.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
}

impl CredentialRegenerationLifecyclePolicy {
    /// Validates regeneration lifecycle policy timing.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(timing) = self.delayed_action_timing {
            timing.validate()?;
        }
        Ok(())
    }
}

/// Policy for authenticated credential rotation lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotationLifecyclePolicy {
    /// Whether immediate rotation authority must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Freshness required before rotating a credential through an authenticated session.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
}

impl CredentialRotationLifecyclePolicy {
    /// Validates rotation lifecycle policy.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Policy for subject-auth-state deletion lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAuthStateDeletionLifecyclePolicy {
    /// Schedule used when subject-auth-state deletion is requested.
    pub delayed_action_timing: DelayedLifecycleActionTimingPolicy,
    /// Freshness required before scheduling delayed subject-auth-state deletion.
    pub authenticated_scheduling_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before cancelling a delayed subject-auth-state deletion.
    pub authenticated_cancellation_step_up_freshness: StepUpFreshnessRequirement,
}

impl SubjectAuthStateDeletionLifecyclePolicy {
    /// Validates subject-auth-state deletion lifecycle policy timing.
    pub fn validate(&self) -> Result<(), Error> {
        self.delayed_action_timing.validate()
    }
}

/// Policy for out-of-band identifier change lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutOfBandIdentifierChangeLifecyclePolicy {
    /// Whether immediate identifier change authority must be paired with independent evidence.
    pub independent_evidence_requirement: SubjectLifecycleIndependentEvidenceRequirement,
    /// Schedule used when identifier change policy requires delayed execution.
    pub delayed_action_timing: Option<DelayedLifecycleActionTimingPolicy>,
    /// Freshness required before authenticated identifier-change planning.
    pub authenticated_planning_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before authenticated immediate identifier-change execution.
    pub authenticated_execution_step_up_freshness: StepUpFreshnessRequirement,
    /// Freshness required before authenticated delayed identifier-change cancellation.
    pub authenticated_cancellation_step_up_freshness: StepUpFreshnessRequirement,
}

impl OutOfBandIdentifierChangeLifecyclePolicy {
    /// Validates out-of-band identifier change lifecycle policy timing.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(timing) = self.delayed_action_timing {
            timing.validate()?;
        }
        Ok(())
    }
}

/// Policy for support/admin intervention lifecycle transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSupportInterventionLifecyclePolicy {
    /// How long a requested intervention may be approved or denied.
    pub intervention_lifetime: DurationSeconds,
    /// Effective recovery authorities represented by a verified support intervention.
    pub effective_recovery_authority_ids: Vec<RecoveryAuthorityId>,
    /// Whether immediate support approval must be paired with independent evidence.
    pub independent_evidence_requirement: CredentialLifecycleIndependentEvidenceRequirement,
    /// Schedule used when support approval must become delayed lifecycle work.
    pub delayed_action_timing: Option<DelayedLifecycleActionTimingPolicy>,
}

impl AdminSupportInterventionLifecyclePolicy {
    /// Validates support intervention lifecycle policy.
    pub fn validate(&self) -> Result<(), Error> {
        if self.intervention_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "admin support intervention lifetime must be non-zero",
            ));
        }
        if self.effective_recovery_authority_ids.is_empty() {
            return Err(Error::InvalidConfig(
                "admin support intervention authorities must be non-empty",
            ));
        }
        if recovery_authority_ids_contain_duplicate(&self.effective_recovery_authority_ids) {
            return Err(Error::InvalidConfig(
                "admin support intervention authorities must not contain duplicates",
            ));
        }
        if let Some(timing) = self.delayed_action_timing {
            timing.validate()?;
        }
        Ok(())
    }
}

/// Whether a lifecycle transition needs a currently fresh step-up.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StepUpFreshnessRequirement {
    /// A live authenticated session is enough for this transition.
    NotRequired,
    /// The live authenticated session must still be inside its step-up freshness window.
    Required,
}

impl StepUpFreshnessRequirement {
    /// Returns whether step-up freshness is required.
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

fn recovery_authority_ids_contain_duplicate(authority_ids: &[RecoveryAuthorityId]) -> bool {
    authority_ids
        .iter()
        .enumerate()
        .any(|(index, authority_id)| authority_ids[index + 1..].contains(authority_id))
}

const fn shared_step_up_freshness(
    first: StepUpFreshnessRequirement,
    second: StepUpFreshnessRequirement,
) -> Option<StepUpFreshnessRequirement> {
    match (first, second) {
        (StepUpFreshnessRequirement::NotRequired, StepUpFreshnessRequirement::NotRequired) => {
            Some(StepUpFreshnessRequirement::NotRequired)
        }
        (StepUpFreshnessRequirement::Required, StepUpFreshnessRequirement::Required) => {
            Some(StepUpFreshnessRequirement::Required)
        }
        _ => None,
    }
}

/// Relative timing policy for a delayed lifecycle action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DelayedLifecycleActionTimingPolicy {
    /// How long the action must wait before execution is allowed.
    pub delay: DurationSeconds,
    /// How long the action remains executable after it is requested.
    pub expires_after: DurationSeconds,
}

impl DelayedLifecycleActionTimingPolicy {
    /// Validates the delayed action timing relationship.
    pub fn validate(self) -> Result<(), Error> {
        if self.delay.is_zero() {
            return Err(Error::InvalidConfig(
                "delayed lifecycle action delay must be non-zero",
            ));
        }
        if self.expires_after.is_zero() {
            return Err(Error::InvalidConfig(
                "delayed lifecycle action expiry must be non-zero",
            ));
        }
        if self.expires_after <= self.delay {
            return Err(Error::InvalidConfig(
                "delayed lifecycle action expiry must be after maturity",
            ));
        }
        Ok(())
    }

    pub(crate) fn pending_credential_lifecycle_action_schedule(
        self,
        now: UnixSeconds,
        pending_action_id: PendingCredentialLifecycleActionId,
    ) -> Result<PendingCredentialLifecycleActionSchedule, Error> {
        self.validate()?;
        Ok(PendingCredentialLifecycleActionSchedule {
            pending_action_id,
            earliest_execute_at: now.checked_add_duration(self.delay)?,
            expires_at: now.checked_add_duration(self.expires_after)?,
        })
    }

    pub(crate) fn pending_subject_lifecycle_action_schedule(
        self,
        now: UnixSeconds,
        pending_action_id: PendingSubjectLifecycleActionId,
    ) -> Result<PendingSubjectLifecycleActionSchedule, Error> {
        self.validate()?;
        Ok(PendingSubjectLifecycleActionSchedule {
            pending_action_id,
            earliest_execute_at: now.checked_add_duration(self.delay)?,
            expires_at: now.checked_add_duration(self.expires_after)?,
        })
    }
}
