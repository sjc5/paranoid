use super::prelude::*;

/// Core-owned proof family.
///
/// Plugins may provide many concrete implementations, such as email, SMS, or
/// postal delivery for out-of-band codes. The core still needs this fixed
/// vocabulary because each family proves a different security fact and unlocks
/// different lifecycle transitions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofFamily {
    /// Active proof of control over an out-of-band delivery endpoint.
    OutOfBandCode,
    /// Active proof of control over a verifier by signing a bound message.
    MessageSignature,
    /// Active proof from an origin-bound public-key authenticator.
    OriginBoundPublicKey,
    /// Active proof from a trusted external identity provider assertion.
    FederatedIdentityAssertion,
    /// Active proof of a configured shared-secret OTP verifier.
    SharedSecretOtp,
    /// Passive proof of a trusted-device credential.
    TrustedDevice,
    /// Active proof of a high-entropy recovery credential.
    RecoveryCode,
}

impl ProofFamily {
    /// Returns the core security semantics of this proof family.
    pub const fn semantics(self) -> ProofSemantics {
        match self {
            Self::OutOfBandCode => ProofSemantics {
                subject_role: ProofSubjectRole::CanBindSubjectFromIdentifier,
                interaction: ProofInteraction::Active,
                mechanism: ProofMechanism::OutOfBandDeliveryCode,
            },
            Self::MessageSignature => ProofSemantics {
                subject_role: ProofSubjectRole::CanBindExistingSubjectFromVerifier,
                interaction: ProofInteraction::Active,
                mechanism: ProofMechanism::MessageSignature,
            },
            Self::OriginBoundPublicKey => ProofSemantics {
                subject_role: ProofSubjectRole::CanBindExistingSubjectFromVerifier,
                interaction: ProofInteraction::Active,
                mechanism: ProofMechanism::OriginBoundPublicKey,
            },
            Self::FederatedIdentityAssertion => ProofSemantics {
                subject_role: ProofSubjectRole::CanBindSubjectFromExternalAssertion,
                interaction: ProofInteraction::Active,
                mechanism: ProofMechanism::FederatedIdentityAssertion,
            },
            Self::SharedSecretOtp => ProofSemantics {
                subject_role: ProofSubjectRole::RequiresKnownSubject,
                interaction: ProofInteraction::Active,
                mechanism: ProofMechanism::LowEntropyConfiguredSecret,
            },
            Self::TrustedDevice => ProofSemantics {
                subject_role: ProofSubjectRole::BoundToTrustedDeviceCredential,
                interaction: ProofInteraction::Passive,
                mechanism: ProofMechanism::RotatingBearerCredential,
            },
            Self::RecoveryCode => ProofSemantics {
                subject_role: ProofSubjectRole::CanBindExistingSubjectFromVerifier,
                interaction: ProofInteraction::Active,
                mechanism: ProofMechanism::OneTimeRecoveryCredential,
            },
        }
    }

    /// Returns whether this family may be used for a specific core transition.
    pub const fn supports_use(self, proof_use: ProofUse) -> bool {
        match (self, proof_use) {
            (Self::OutOfBandCode, ProofUse::BindSubjectToActiveProofAttempt) => true,
            (Self::OutOfBandCode, ProofUse::ContributeToFullAuthentication) => true,
            (Self::OutOfBandCode, ProofUse::ReviveTrustedDeviceWithActiveProof) => true,
            (Self::OutOfBandCode, ProofUse::SatisfyStepUp) => true,
            (Self::OutOfBandCode, ProofUse::SilentlyReviveTrustedDeviceSession) => false,
            (Self::OutOfBandCode, ProofUse::ReduceAuthenticationRequirement) => false,
            (Self::OutOfBandCode, ProofUse::RecoverOrReplaceCredential) => false,
            (Self::OutOfBandCode, ProofUse::ProveOutOfBandIdentifierChangeCandidate) => true,

            (Self::MessageSignature, ProofUse::BindSubjectToActiveProofAttempt) => true,
            (Self::MessageSignature, ProofUse::ContributeToFullAuthentication) => true,
            (Self::MessageSignature, ProofUse::ReviveTrustedDeviceWithActiveProof) => true,
            (Self::MessageSignature, ProofUse::SatisfyStepUp) => true,
            (Self::MessageSignature, ProofUse::SilentlyReviveTrustedDeviceSession) => false,
            (Self::MessageSignature, ProofUse::ReduceAuthenticationRequirement) => false,
            (Self::MessageSignature, ProofUse::RecoverOrReplaceCredential) => false,
            (Self::MessageSignature, ProofUse::ProveOutOfBandIdentifierChangeCandidate) => false,

            (Self::OriginBoundPublicKey, ProofUse::BindSubjectToActiveProofAttempt) => true,
            (Self::OriginBoundPublicKey, ProofUse::ContributeToFullAuthentication) => true,
            (Self::OriginBoundPublicKey, ProofUse::ReviveTrustedDeviceWithActiveProof) => true,
            (Self::OriginBoundPublicKey, ProofUse::SatisfyStepUp) => true,
            (Self::OriginBoundPublicKey, ProofUse::SilentlyReviveTrustedDeviceSession) => false,
            (Self::OriginBoundPublicKey, ProofUse::ReduceAuthenticationRequirement) => false,
            (Self::OriginBoundPublicKey, ProofUse::RecoverOrReplaceCredential) => false,
            (Self::OriginBoundPublicKey, ProofUse::ProveOutOfBandIdentifierChangeCandidate) => {
                false
            }

            (Self::FederatedIdentityAssertion, ProofUse::BindSubjectToActiveProofAttempt) => true,
            (Self::FederatedIdentityAssertion, ProofUse::ContributeToFullAuthentication) => true,
            (Self::FederatedIdentityAssertion, ProofUse::ReviveTrustedDeviceWithActiveProof) => {
                true
            }
            (Self::FederatedIdentityAssertion, ProofUse::SatisfyStepUp) => true,
            (Self::FederatedIdentityAssertion, ProofUse::SilentlyReviveTrustedDeviceSession) => {
                false
            }
            (Self::FederatedIdentityAssertion, ProofUse::ReduceAuthenticationRequirement) => false,
            (Self::FederatedIdentityAssertion, ProofUse::RecoverOrReplaceCredential) => false,
            (
                Self::FederatedIdentityAssertion,
                ProofUse::ProveOutOfBandIdentifierChangeCandidate,
            ) => false,

            (Self::SharedSecretOtp, ProofUse::BindSubjectToActiveProofAttempt) => false,
            (Self::SharedSecretOtp, ProofUse::ContributeToFullAuthentication) => true,
            (Self::SharedSecretOtp, ProofUse::ReviveTrustedDeviceWithActiveProof) => true,
            (Self::SharedSecretOtp, ProofUse::SatisfyStepUp) => true,
            (Self::SharedSecretOtp, ProofUse::SilentlyReviveTrustedDeviceSession) => false,
            (Self::SharedSecretOtp, ProofUse::ReduceAuthenticationRequirement) => false,
            (Self::SharedSecretOtp, ProofUse::RecoverOrReplaceCredential) => false,
            (Self::SharedSecretOtp, ProofUse::ProveOutOfBandIdentifierChangeCandidate) => false,

            (Self::TrustedDevice, ProofUse::BindSubjectToActiveProofAttempt) => false,
            (Self::TrustedDevice, ProofUse::ContributeToFullAuthentication) => false,
            (Self::TrustedDevice, ProofUse::ReviveTrustedDeviceWithActiveProof) => false,
            (Self::TrustedDevice, ProofUse::SatisfyStepUp) => false,
            (Self::TrustedDevice, ProofUse::SilentlyReviveTrustedDeviceSession) => true,
            (Self::TrustedDevice, ProofUse::ReduceAuthenticationRequirement) => true,
            (Self::TrustedDevice, ProofUse::RecoverOrReplaceCredential) => false,
            (Self::TrustedDevice, ProofUse::ProveOutOfBandIdentifierChangeCandidate) => false,

            (Self::RecoveryCode, ProofUse::BindSubjectToActiveProofAttempt) => false,
            (Self::RecoveryCode, ProofUse::ContributeToFullAuthentication) => true,
            (Self::RecoveryCode, ProofUse::ReviveTrustedDeviceWithActiveProof) => true,
            (Self::RecoveryCode, ProofUse::SatisfyStepUp) => true,
            (Self::RecoveryCode, ProofUse::SilentlyReviveTrustedDeviceSession) => false,
            (Self::RecoveryCode, ProofUse::ReduceAuthenticationRequirement) => false,
            (Self::RecoveryCode, ProofUse::RecoverOrReplaceCredential) => true,
            (Self::RecoveryCode, ProofUse::ProveOutOfBandIdentifierChangeCandidate) => false,
        }
    }

    /// Returns the default online-guessing risk for this proof family.
    pub const fn default_online_guessing_risk(self) -> OnlineGuessingRisk {
        match self.semantics().mechanism {
            ProofMechanism::LowEntropyConfiguredSecret => OnlineGuessingRisk::OnlineGuessable,
            ProofMechanism::OutOfBandDeliveryCode
            | ProofMechanism::MessageSignature
            | ProofMechanism::OriginBoundPublicKey
            | ProofMechanism::FederatedIdentityAssertion
            | ProofMechanism::RotatingBearerCredential
            | ProofMechanism::OneTimeRecoveryCredential => OnlineGuessingRisk::NotOnlineGuessable,
        }
    }

    /// Returns whether accepting this proof family requires method/plugin commit work.
    pub const fn requires_method_commit_work_on_success(self) -> bool {
        matches!(
            self.semantics().mechanism,
            ProofMechanism::OneTimeRecoveryCredential
        )
    }
}

/// Security meaning attached to a proof family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProofSemantics {
    /// How this proof family relates to subject identity.
    pub subject_role: ProofSubjectRole,
    /// Whether using this proof requires direct user interaction.
    pub interaction: ProofInteraction,
    /// Operational mechanism the core must account for.
    pub mechanism: ProofMechanism,
}

/// How a proof family relates to subject identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofSubjectRole {
    /// Can bind an active-proof attempt to a subject selected from a public identifier.
    CanBindSubjectFromIdentifier,
    /// Can bind an active-proof attempt to an existing subject selected from a verifier.
    CanBindExistingSubjectFromVerifier,
    /// Can bind an active-proof attempt to a subject selected from an external assertion.
    CanBindSubjectFromExternalAssertion,
    /// Requires the flow to already know the subject.
    RequiresKnownSubject,
    /// Is bound to an existing trusted-device credential.
    BoundToTrustedDeviceCredential,
}

/// Whether using a proof family requires direct user interaction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofInteraction {
    /// The user actively supplies or computes a proof.
    Active,
    /// The client passively presents a bearer credential.
    Passive,
}

/// Operational mechanism the core must account for.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofMechanism {
    /// Requires a durable delivery command and bounded challenge lifecycle.
    OutOfBandDeliveryCode,
    /// Requires message canonicalization, challenge binding, and signature verification.
    MessageSignature,
    /// Requires origin/RP binding, authenticator challenge verification, and verifier lookup.
    OriginBoundPublicKey,
    /// Requires issuer trust, assertion validation, and external subject mapping.
    FederatedIdentityAssertion,
    /// Requires attempt budgeting and usually proof-of-work.
    LowEntropyConfiguredSecret,
    /// Requires server-side credential binding and rotation.
    RotatingBearerCredential,
    /// Requires one-time closure and recovery-heavy side effects.
    OneTimeRecoveryCredential,
}

/// Core transition a proof family may or may not be allowed to satisfy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofUse {
    /// Bind an active-proof attempt to a subject after adapter-side subject resolution.
    BindSubjectToActiveProofAttempt,
    /// Contribute to the configured full-authentication policy.
    ContributeToFullAuthentication,
    /// Prove one active factor after a trusted device is past silent revival.
    ReviveTrustedDeviceWithActiveProof,
    /// Satisfy a fresh-proof requirement for sensitive requests.
    SatisfyStepUp,
    /// Silently create a new session from a trusted-device credential.
    SilentlyReviveTrustedDeviceSession,
    /// Reduce how much active proof is needed because a trusted device is present.
    ReduceAuthenticationRequirement,
    /// Recover or replace another credential.
    RecoverOrReplaceCredential,
    /// Prove reachability of a candidate out-of-band identifier before lifecycle authorization.
    ProveOutOfBandIdentifierChangeCandidate,
}

/// Whether a concrete proof method is online-guessable and must use weak-proof guards.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OnlineGuessingRisk {
    /// The proof is not meaningfully guessable through repeated online attempts.
    NotOnlineGuessable,
    /// The proof can be guessed online and must use weak-proof gates and attempt budgets.
    OnlineGuessable,
}

/// Concrete proof method declaration supplied by a Paranoid-owned method plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofMethodDeclaration {
    /// Core-owned proof family implemented by this method.
    family: ProofFamily,
    /// Concrete method label.
    method_label: String,
    /// Concrete method online-guessing risk.
    online_guessing_risk: OnlineGuessingRisk,
}

impl ProofMethodDeclaration {
    /// Declares a method using the proof family's default online-guessing risk.
    pub(crate) fn new(family: ProofFamily, method_label: impl Into<String>) -> Result<Self, Error> {
        Self::new_with_online_guessing_risk(
            family,
            method_label,
            family.default_online_guessing_risk(),
        )
    }

    /// Declares an online-guessable method that must use weak-proof gates and budgets.
    pub(crate) fn new_online_guessable(
        family: ProofFamily,
        method_label: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::new_with_online_guessing_risk(
            family,
            method_label,
            OnlineGuessingRisk::OnlineGuessable,
        )
    }

    /// Declares a method with an explicit online-guessing risk.
    pub(crate) fn new_with_online_guessing_risk(
        family: ProofFamily,
        method_label: impl Into<String>,
        online_guessing_risk: OnlineGuessingRisk,
    ) -> Result<Self, Error> {
        let proof = ProofSummary::new_with_online_guessing_risk(
            family,
            method_label,
            online_guessing_risk,
        )?;
        Ok(Self {
            family: proof.family,
            method_label: proof.method_label,
            online_guessing_risk: proof.online_guessing_risk,
        })
    }

    /// Returns the core-owned proof family implemented by this method.
    pub const fn family(&self) -> ProofFamily {
        self.family
    }

    /// Returns the concrete method label.
    pub fn method_label(&self) -> &str {
        &self.method_label
    }

    /// Returns the concrete method's online-guessing risk.
    pub const fn online_guessing_risk(&self) -> OnlineGuessingRisk {
        self.online_guessing_risk
    }

    /// Returns the core security semantics derived from this method's family.
    pub const fn semantics(&self) -> ProofSemantics {
        self.family.semantics()
    }

    /// Returns whether this method's family can satisfy a specific core transition.
    pub const fn supports_use(&self, proof_use: ProofUse) -> bool {
        self.family.supports_use(proof_use)
    }

    /// Returns whether successful proof completion requires method-owned commit work.
    pub const fn requires_method_commit_work_on_success(&self) -> bool {
        self.family.requires_method_commit_work_on_success()
    }

    /// Returns whether failed attempts for this method consume the weak-proof budget.
    pub const fn uses_weak_attempt_failure_budget(&self) -> bool {
        matches!(
            self.online_guessing_risk,
            OnlineGuessingRisk::OnlineGuessable
        )
    }

    /// Returns the verified-proof summary emitted after this method verifies a proof.
    pub fn verified_proof_summary(&self) -> ProofSummary {
        ProofSummary {
            family: self.family,
            method_label: self.method_label.clone(),
            online_guessing_risk: self.online_guessing_risk,
        }
    }
}

/// Proof accepted by a method/plugin after method-specific verification succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedActiveProof {
    /// Satisfied proof record.
    satisfied_proof: SatisfiedProof,
    /// Subject resolved by this proof, when the proof family is allowed to bind one.
    subject_id: Option<SubjectId>,
}

impl VerifiedActiveProof {
    pub(crate) fn from_summary(
        proof: ProofSummary,
        subject_id: Option<SubjectId>,
    ) -> Result<Self, Error> {
        if subject_id.is_some() && !proof.family().can_bind_subject_from_verified_proof() {
            return Err(Error::ProofFamilyCannotCarryVerifiedSubject {
                family: proof.family(),
            });
        }
        Ok(Self {
            satisfied_proof: SatisfiedProof::new_without_source(proof),
            subject_id,
        })
    }

    pub(crate) fn from_summary_with_source(
        proof: ProofSummary,
        subject_id: Option<SubjectId>,
        source: VerifiedProofSource,
    ) -> Result<Self, Error> {
        if subject_id.is_some() && !proof.family().can_bind_subject_from_verified_proof() {
            return Err(Error::ProofFamilyCannotCarryVerifiedSubject {
                family: proof.family(),
            });
        }
        Ok(Self {
            satisfied_proof: SatisfiedProof::new(proof, Some(source)),
            subject_id,
        })
    }

    /// Returns the verified proof summary.
    pub fn proof(&self) -> &ProofSummary {
        self.satisfied_proof.proof()
    }

    /// Returns the source that produced the verified proof, if available.
    pub fn source(&self) -> Option<&VerifiedProofSource> {
        self.satisfied_proof.source()
    }

    /// Returns the subject resolved by the proof, if any.
    pub fn subject_id(&self) -> Option<&SubjectId> {
        self.subject_id.as_ref()
    }

    pub(super) fn into_parts(self) -> (SatisfiedProof, Option<SubjectId>) {
        (self.satisfied_proof, self.subject_id)
    }
}

/// Source that produced a satisfied proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProofSource {
    /// Kind of authority or credential that produced the proof.
    kind: VerifiedProofSourceKind,
    /// Stable method-owned source id.
    source_id: VerifiedProofSourceId,
}

impl VerifiedProofSource {
    /// Creates a verified proof source from a kind and stable source id.
    pub fn new(kind: VerifiedProofSourceKind, source_id: VerifiedProofSourceId) -> Self {
        Self { kind, source_id }
    }

    /// Returns the source kind.
    pub const fn kind(&self) -> VerifiedProofSourceKind {
        self.kind
    }

    /// Returns the stable source id.
    pub const fn source_id(&self) -> &VerifiedProofSourceId {
        &self.source_id
    }
}

/// Kind of credential or authority that produced a satisfied proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerifiedProofSourceKind {
    /// A Paranoid-auth credential instance owned by the subject.
    CredentialInstance,
    /// An out-of-band identifier such as an email address or phone number.
    OutOfBandIdentifier,
    /// An external identity authority or provider assertion.
    ExternalAuthority,
}

/// Proof recorded inside an active-proof attempt after successful verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SatisfiedProof {
    /// Verified proof family and concrete method label.
    proof: ProofSummary,
    /// Credential or authority source that produced this proof, when known.
    source: Option<VerifiedProofSource>,
}

impl SatisfiedProof {
    /// Creates a satisfied proof with source provenance.
    pub fn new(proof: ProofSummary, source: Option<VerifiedProofSource>) -> Self {
        Self { proof, source }
    }

    pub(crate) fn new_without_source(proof: ProofSummary) -> Self {
        Self::new(proof, None)
    }

    /// Returns the verified proof summary.
    pub const fn proof(&self) -> &ProofSummary {
        &self.proof
    }

    /// Returns the source that produced this proof, if available.
    pub const fn source(&self) -> Option<&VerifiedProofSource> {
        self.source.as_ref()
    }

    /// Returns the core-known proof family.
    pub const fn family(&self) -> ProofFamily {
        self.proof.family()
    }

    /// Returns the concrete method label.
    pub fn method_label(&self) -> &str {
        self.proof.method_label()
    }

    /// Returns the concrete method's online-guessing risk.
    pub const fn online_guessing_risk(&self) -> OnlineGuessingRisk {
        self.proof.online_guessing_risk()
    }

    /// Returns whether failed attempts for this proof consume the weak-proof budget.
    pub const fn uses_weak_attempt_failure_budget(&self) -> bool {
        self.proof.uses_weak_attempt_failure_budget()
    }

    pub(super) fn validate(&self) -> Result<(), Error> {
        self.proof.validate()
    }
}

/// Opaque proof summary for audit and policy explanations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSummary {
    /// Core-known proof family.
    pub(super) family: ProofFamily,
    /// Adapter-specific proof label, such as `email_otp`, `sms_otp`, or `totp`.
    pub(super) method_label: String,
    /// Concrete method online-guessing risk.
    pub(super) online_guessing_risk: OnlineGuessingRisk,
}

impl ProofSummary {
    /// Creates a proof summary from a core family and adapter label.
    #[cfg(test)]
    pub(crate) fn new(family: ProofFamily, method_label: impl Into<String>) -> Result<Self, Error> {
        Self::new_with_online_guessing_risk(
            family,
            method_label,
            family.default_online_guessing_risk(),
        )
    }

    /// Creates an online-guessable proof summary from a core family and adapter label.
    #[cfg(test)]
    pub(crate) fn new_online_guessable(
        family: ProofFamily,
        method_label: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::new_with_online_guessing_risk(
            family,
            method_label,
            OnlineGuessingRisk::OnlineGuessable,
        )
    }

    /// Creates a proof summary with an explicit online-guessing risk.
    pub(crate) fn new_with_online_guessing_risk(
        family: ProofFamily,
        method_label: impl Into<String>,
        online_guessing_risk: OnlineGuessingRisk,
    ) -> Result<Self, Error> {
        validate_online_guessing_risk_for_family(family, online_guessing_risk)?;
        let method_label = method_label.into();
        if method_label.is_empty() {
            return Err(Error::EmptyProofMethodLabel);
        }
        validate_auth_identifier_string(
            "proof method label",
            &method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(Self {
            family,
            method_label,
            online_guessing_risk,
        })
    }

    /// Returns the core-known proof family.
    pub const fn family(&self) -> ProofFamily {
        self.family
    }

    /// Returns the adapter-specific proof label.
    pub fn method_label(&self) -> &str {
        &self.method_label
    }

    /// Returns the concrete method's online-guessing risk.
    pub const fn online_guessing_risk(&self) -> OnlineGuessingRisk {
        self.online_guessing_risk
    }

    /// Returns whether failed attempts for this proof consume the weak-proof budget.
    pub const fn uses_weak_attempt_failure_budget(&self) -> bool {
        matches!(
            self.online_guessing_risk,
            OnlineGuessingRisk::OnlineGuessable
        )
    }

    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.method_label.is_empty() {
            return Err(Error::EmptyProofMethodLabel);
        }
        validate_auth_identifier_string(
            "proof method label",
            &self.method_label,
            METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(())
    }
}

impl ProofFamily {
    const fn can_bind_subject_from_verified_proof(self) -> bool {
        matches!(
            self.semantics().subject_role,
            ProofSubjectRole::CanBindSubjectFromIdentifier
                | ProofSubjectRole::CanBindExistingSubjectFromVerifier
                | ProofSubjectRole::CanBindSubjectFromExternalAssertion
        )
    }
}

fn validate_online_guessing_risk_for_family(
    family: ProofFamily,
    online_guessing_risk: OnlineGuessingRisk,
) -> Result<(), Error> {
    if family.default_online_guessing_risk() == OnlineGuessingRisk::OnlineGuessable
        && online_guessing_risk == OnlineGuessingRisk::NotOnlineGuessable
    {
        return Err(Error::InvalidConfig(
            "proof method cannot weaken family online-guessing risk",
        ));
    }
    Ok(())
}
