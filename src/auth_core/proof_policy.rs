use super::{
    Error, METHOD_LABEL_MAX_BYTES, ProofFamily, ProofInteraction, ProofSubjectRole, ProofSummary,
    ProofUse, validate_auth_identifier_string,
};

/// Configurable proof-stack policy for final auth transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofPolicy {
    /// Accepted proof stacks for creating a fully authenticated session.
    pub full_authentication: ProofStackPolicy,
    /// Accepted proof stacks for refreshing proof freshness on a live session.
    pub step_up: ProofStackPolicy,
    /// Accepted active-proof stacks when a trusted device is present but past silent revival.
    pub trusted_device_active_revival: ProofStackPolicy,
}

impl ProofPolicy {
    /// Returns a safe default proof policy for exact application method labels.
    pub fn safe_defaults_for_exact_methods(
        methods: ProofPolicyExactMethodLabels,
    ) -> Result<Self, Error> {
        methods.validate()?;
        Ok(Self {
            full_authentication: ProofStackPolicy {
                accepted_stacks: vec![
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::OutOfBandCode,
                        methods.out_of_band_code_method_label.clone(),
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::MessageSignature,
                        methods.message_signature_method_label.clone(),
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::RecoveryCode,
                        methods.recovery_code_method_label.clone(),
                    )?,
                ],
            },
            step_up: ProofStackPolicy {
                accepted_stacks: vec![
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::OutOfBandCode,
                        methods.out_of_band_code_method_label.clone(),
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::MessageSignature,
                        methods.message_signature_method_label.clone(),
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::SharedSecretOtp,
                        methods.totp_method_label.clone(),
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::RecoveryCode,
                        methods.recovery_code_method_label.clone(),
                    )?,
                ],
            },
            trusted_device_active_revival: ProofStackPolicy {
                accepted_stacks: vec![
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::OutOfBandCode,
                        methods.out_of_band_code_method_label,
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::MessageSignature,
                        methods.message_signature_method_label,
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::SharedSecretOtp,
                        methods.totp_method_label,
                    )?,
                    ProofStackRequirement::one_exact_method(
                        ProofFamily::RecoveryCode,
                        methods.recovery_code_method_label,
                    )?,
                ],
            },
        })
    }

    /// Returns the default proof-stack shape while accepting any method label inside each family.
    pub fn defaults_accepting_any_method_label_in_each_family() -> Self {
        Self {
            full_authentication: ProofStackPolicy {
                accepted_stacks: vec![
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::OutOfBandCode,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::MessageSignature,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::RecoveryCode,
                    ),
                ],
            },
            step_up: ProofStackPolicy {
                accepted_stacks: vec![
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::OutOfBandCode,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::MessageSignature,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::SharedSecretOtp,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::RecoveryCode,
                    ),
                ],
            },
            trusted_device_active_revival: ProofStackPolicy {
                accepted_stacks: vec![
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::OutOfBandCode,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::MessageSignature,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::SharedSecretOtp,
                    ),
                    ProofStackRequirement::one_any_method_label_in_family(
                        ProofFamily::RecoveryCode,
                    ),
                ],
            },
        }
    }

    pub(super) fn validate(&self) -> Result<(), Error> {
        self.full_authentication.validate(
            ProofUse::ContributeToFullAuthentication,
            ProofStackSafetyFloor::FullAuthenticationAnchor,
        )?;
        self.step_up
            .validate(ProofUse::SatisfyStepUp, ProofStackSafetyFloor::ActiveProof)?;
        self.trusted_device_active_revival.validate(
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            ProofStackSafetyFloor::ActiveProof,
        )?;
        Ok(())
    }

    fn stack_policy_for_use(&self, proof_use: ProofUse) -> Option<&ProofStackPolicy> {
        match proof_use {
            ProofUse::ContributeToFullAuthentication => Some(&self.full_authentication),
            ProofUse::SatisfyStepUp => Some(&self.step_up),
            ProofUse::ReviveTrustedDeviceWithActiveProof => {
                Some(&self.trusted_device_active_revival)
            }
            ProofUse::BindSubjectToActiveProofAttempt
            | ProofUse::SilentlyReviveTrustedDeviceSession
            | ProofUse::ReduceAuthenticationRequirement
            | ProofUse::RecoverOrReplaceCredential => None,
        }
    }
}

/// Exact application method labels used by `ProofPolicy::safe_defaults_for_exact_methods`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofPolicyExactMethodLabels {
    /// Accepted out-of-band-code method label.
    pub out_of_band_code_method_label: String,
    /// Accepted message-signature method label.
    pub message_signature_method_label: String,
    /// Accepted TOTP method label.
    pub totp_method_label: String,
    /// Accepted recovery-code method label.
    pub recovery_code_method_label: String,
}

impl ProofPolicyExactMethodLabels {
    /// Creates exact method labels for the safe default proof-stack shape.
    pub fn new(
        out_of_band_code_method_label: impl Into<String>,
        message_signature_method_label: impl Into<String>,
        totp_method_label: impl Into<String>,
        recovery_code_method_label: impl Into<String>,
    ) -> Result<Self, Error> {
        let labels = Self {
            out_of_band_code_method_label: out_of_band_code_method_label.into(),
            message_signature_method_label: message_signature_method_label.into(),
            totp_method_label: totp_method_label.into(),
            recovery_code_method_label: recovery_code_method_label.into(),
        };
        labels.validate()?;
        Ok(labels)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.out_of_band_code_method_label.is_empty()
            || self.message_signature_method_label.is_empty()
            || self.totp_method_label.is_empty()
            || self.recovery_code_method_label.is_empty()
        {
            return Err(Error::EmptyProofRequirementMethodLabel);
        }
        validate_auth_identifier_string(
            "out-of-band-code proof requirement method label",
            &self.out_of_band_code_method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        validate_auth_identifier_string(
            "message-signature proof requirement method label",
            &self.message_signature_method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        validate_auth_identifier_string(
            "totp proof requirement method label",
            &self.totp_method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        validate_auth_identifier_string(
            "recovery-code proof requirement method label",
            &self.recovery_code_method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(())
    }
}

/// Accepted proof stacks for one auth transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofStackPolicy {
    /// Alternative proof-stack requirements. Any matching entry satisfies the policy.
    pub accepted_stacks: Vec<ProofStackRequirement>,
}

impl ProofStackPolicy {
    fn validate(
        &self,
        proof_use: ProofUse,
        safety_floor: ProofStackSafetyFloor,
    ) -> Result<(), Error> {
        if self.accepted_stacks.is_empty() {
            return Err(Error::InvalidConfig(
                "proof policy accepted_stacks must not be empty",
            ));
        }
        for accepted_stack in &self.accepted_stacks {
            accepted_stack.validate(proof_use, safety_floor)?;
        }
        Ok(())
    }

    fn is_satisfied_by(&self, proofs: &[ProofSummary]) -> bool {
        self.accepted_stacks
            .iter()
            .any(|accepted_stack| accepted_stack.is_satisfied_by(proofs))
    }
}

/// One required proof inside an accepted proof stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRequirement {
    /// Required proof family.
    pub family: ProofFamily,
    /// Exact method label required inside the family. `None` accepts any method label in the family.
    pub method_label: Option<String>,
}

impl ProofRequirement {
    /// Returns a requirement that accepts any method label in the family.
    pub fn any_method_label_in_family(family: ProofFamily) -> Self {
        Self {
            family,
            method_label: None,
        }
    }

    /// Returns a requirement for one exact method label inside the family.
    pub fn exact_method(
        family: ProofFamily,
        method_label: impl Into<String>,
    ) -> Result<Self, Error> {
        let method_label = method_label.into();
        if method_label.is_empty() {
            return Err(Error::EmptyProofRequirementMethodLabel);
        }
        validate_auth_identifier_string(
            "proof requirement method label",
            &method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(Self {
            family,
            method_label: Some(method_label),
        })
    }

    fn validate(&self, proof_use: ProofUse) -> Result<(), Error> {
        if self.method_label.as_ref().is_some_and(String::is_empty) {
            return Err(Error::EmptyProofRequirementMethodLabel);
        }
        if let Some(method_label) = &self.method_label {
            validate_auth_identifier_string(
                "proof requirement method label",
                method_label,
                METHOD_LABEL_MAX_BYTES,
            )?;
        }
        if !self.family.supports_use(proof_use) {
            return Err(Error::InvalidConfig(
                "proof policy family cannot satisfy configured use",
            ));
        }
        Ok(())
    }

    fn is_satisfied_by(&self, proof: &ProofSummary) -> bool {
        proof.family == self.family
            && self
                .method_label
                .as_ref()
                .is_none_or(|method_label| proof.method_label == *method_label)
    }
}

/// One accepted proof-stack requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofStackRequirement {
    /// Proofs that must all be present in the satisfied proof stack.
    pub required_proofs: Vec<ProofRequirement>,
}

impl ProofStackRequirement {
    /// Returns a stack satisfied by one proof family using any method label.
    pub fn one_any_method_label_in_family(family: ProofFamily) -> Self {
        Self {
            required_proofs: vec![ProofRequirement::any_method_label_in_family(family)],
        }
    }

    /// Returns a stack satisfied by one exact method label inside a proof family.
    pub fn one_exact_method(
        family: ProofFamily,
        method_label: impl Into<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            required_proofs: vec![ProofRequirement::exact_method(family, method_label)?],
        })
    }

    /// Returns a stack satisfied by all listed proof families using any method label in each family.
    pub fn all_any_method_label_in_each_family(
        families: impl IntoIterator<Item = ProofFamily>,
    ) -> Self {
        Self {
            required_proofs: families
                .into_iter()
                .map(ProofRequirement::any_method_label_in_family)
                .collect(),
        }
    }

    fn validate(
        &self,
        proof_use: ProofUse,
        safety_floor: ProofStackSafetyFloor,
    ) -> Result<(), Error> {
        if self.required_proofs.is_empty() {
            return Err(Error::InvalidConfig(
                "proof policy required_proofs must not be empty",
            ));
        }
        for required_proof in &self.required_proofs {
            required_proof.validate(proof_use)?;
        }
        if has_duplicate_proof_family(&self.required_proofs) {
            return Err(Error::InvalidConfig(
                "proof policy required_proofs must not contain duplicate families",
            ));
        }
        if !safety_floor.is_met_by_families(required_proof_families(&self.required_proofs)) {
            return Err(Error::InvalidConfig(
                "proof policy stack does not meet the required safety floor",
            ));
        }
        Ok(())
    }

    fn is_satisfied_by(&self, proofs: &[ProofSummary]) -> bool {
        self.required_proofs
            .iter()
            .all(|required_proof| proof_stack_contains_requirement(proofs, required_proof))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ProofStackSafetyFloor {
    FullAuthenticationAnchor,
    ActiveProof,
}

impl ProofStackSafetyFloor {
    fn is_met_by_families(self, families: impl IntoIterator<Item = ProofFamily>) -> bool {
        match self {
            Self::FullAuthenticationAnchor => families
                .into_iter()
                .any(proof_family_can_anchor_full_authentication),
            Self::ActiveProof => families.into_iter().any(proof_family_is_active),
        }
    }
}

pub(super) fn validate_satisfied_proof_stack_for_use(
    proof_policy: &ProofPolicy,
    proofs: &[ProofSummary],
    proof_use: ProofUse,
) -> Result<(), Error> {
    validate_proofs_for_use(proofs, proof_use)?;
    if !satisfied_proof_stack_can_satisfy_use(proof_policy, proofs, proof_use) {
        return Err(Error::SatisfiedProofStackCannotSatisfyUse { proof_use });
    }
    Ok(())
}

fn validate_proofs_for_use(proofs: &[ProofSummary], proof_use: ProofUse) -> Result<(), Error> {
    if proofs.is_empty() {
        return Err(Error::MissingSatisfiedProof);
    }
    for proof in proofs {
        validate_proof_for_use(proof, proof_use)?;
    }
    Ok(())
}

fn validate_proof_for_use(proof: &ProofSummary, proof_use: ProofUse) -> Result<(), Error> {
    if proof.method_label.is_empty() {
        return Err(Error::EmptyProofMethodLabel);
    }
    if !proof.family.supports_use(proof_use) {
        return Err(Error::ProofFamilyCannotSatisfyUse {
            family: proof.family,
            proof_use,
        });
    }
    Ok(())
}

fn satisfied_proof_stack_can_satisfy_use(
    proof_policy: &ProofPolicy,
    proofs: &[ProofSummary],
    proof_use: ProofUse,
) -> bool {
    if let Some(policy) = proof_policy.stack_policy_for_use(proof_use) {
        return policy.is_satisfied_by(proofs);
    }
    match proof_use {
        ProofUse::BindSubjectToActiveProofAttempt => {
            proof_stack_contains_any_family(proofs, proof_family_can_bind_subject)
        }
        ProofUse::SilentlyReviveTrustedDeviceSession
        | ProofUse::ReduceAuthenticationRequirement => {
            proof_stack_contains_family(proofs, ProofFamily::TrustedDevice)
        }
        ProofUse::RecoverOrReplaceCredential => {
            proof_stack_contains_family(proofs, ProofFamily::RecoveryCode)
        }
        ProofUse::ContributeToFullAuthentication
        | ProofUse::ReviveTrustedDeviceWithActiveProof
        | ProofUse::SatisfyStepUp => false,
    }
}

fn proof_stack_contains_any_family(
    proofs: &[ProofSummary],
    predicate: fn(ProofFamily) -> bool,
) -> bool {
    proofs.iter().any(|proof| predicate(proof.family))
}

fn proof_stack_contains_family(proofs: &[ProofSummary], family: ProofFamily) -> bool {
    proofs
        .iter()
        .any(|proof| ProofRequirement::any_method_label_in_family(family).is_satisfied_by(proof))
}

fn proof_stack_contains_requirement(
    proofs: &[ProofSummary],
    required_proof: &ProofRequirement,
) -> bool {
    proofs
        .iter()
        .any(|proof| required_proof.is_satisfied_by(proof))
}

fn has_duplicate_proof_family(required_proofs: &[ProofRequirement]) -> bool {
    for (index, required_proof) in required_proofs.iter().enumerate() {
        if required_proofs[index + 1..]
            .iter()
            .any(|other| other.family == required_proof.family)
        {
            return true;
        }
    }
    false
}

fn required_proof_families(
    required_proofs: &[ProofRequirement],
) -> impl Iterator<Item = ProofFamily> + '_ {
    required_proofs
        .iter()
        .map(|required_proof| required_proof.family)
}

fn proof_family_can_bind_subject(family: ProofFamily) -> bool {
    matches!(
        family.semantics().subject_role,
        ProofSubjectRole::CanBindSubjectFromIdentifier
            | ProofSubjectRole::CanBindExistingSubjectFromVerifier
            | ProofSubjectRole::CanBindSubjectFromExternalAssertion
    )
}

fn proof_family_can_anchor_full_authentication(family: ProofFamily) -> bool {
    matches!(
        family,
        ProofFamily::OutOfBandCode
            | ProofFamily::MessageSignature
            | ProofFamily::OriginBoundPublicKey
            | ProofFamily::FederatedIdentityAssertion
            | ProofFamily::RecoveryCode
    )
}

fn proof_family_is_active(family: ProofFamily) -> bool {
    family.semantics().interaction == ProofInteraction::Active
}
