use super::*;

/// Contract for one auth method adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodAdapterContract {
    method: ProofMethodDeclaration,
    ownership: MethodAdapterOwnership,
    core_derived: Vec<MethodCoreDerivedResponsibility>,
    pre_state_load: Vec<MethodPreStateLoadResponsibility>,
    post_state_load: Vec<MethodPostStateLoadResponsibility>,
    verification: MethodVerificationContract,
    challenge_cookie: MethodChallengeCookieContract,
    postgres_state: Vec<MethodPostgresStateContract>,
    durable_effects: Vec<MethodDurableEffectContract>,
    commit_work: MethodCommitWorkAdapterContract,
    forbidden: Vec<MethodAdapterForbiddenResponsibility>,
}

impl MethodAdapterContract {
    /// Builds the method adapter contract for a declared proof method.
    pub fn for_method(method: ProofMethodDeclaration) -> Self {
        let family = method.family();
        Self {
            ownership: ownership_for_family(family),
            core_derived: core_derived_responsibilities_for_method(&method),
            pre_state_load: pre_state_load_responsibilities_for_method(&method),
            post_state_load: post_state_load_responsibilities_for_method(&method),
            verification: MethodVerificationContract::for_method(&method),
            challenge_cookie: MethodChallengeCookieContract::for_method(&method),
            postgres_state: postgres_state_contracts_for_family(family),
            durable_effects: durable_effect_contracts_for_family(family),
            commit_work: MethodCommitWorkAdapterContract::for_method(&method),
            forbidden: forbidden_method_responsibilities(),
            method,
        }
    }

    /// Builds the separate challenge-bound configured-secret contract for TOTP-like methods.
    pub fn for_challenge_bound_configured_secret_method(
        method: ProofMethodDeclaration,
    ) -> Result<Self, Error> {
        let family = method.family();
        if family != ProofFamily::SharedSecretOtp {
            return Err(
                Error::ProofMethodCannotUseChallengeBoundConfiguredSecretFastFail { family },
            );
        }
        let mut pre_state_load = vec![MethodPreStateLoadResponsibility::EncryptedChallengeCookie];
        if method.uses_weak_attempt_failure_budget() {
            pre_state_load.push(MethodPreStateLoadResponsibility::WeakProofGateBeforeStateLoad);
        }
        pre_state_load.push(
            MethodPreStateLoadResponsibility::ChallengeBoundConfiguredSecretFastFailBloomFilter,
        );
        Ok(Self {
            ownership: ownership_for_family(family),
            core_derived: core_derived_responsibilities_for_method(&method),
            pre_state_load,
            post_state_load: post_state_load_responsibilities_for_method(&method),
            verification: MethodVerificationContract::for_method(&method),
            challenge_cookie:
                MethodChallengeCookieContract::for_challenge_bound_configured_secret_method(),
            postgres_state: postgres_state_contracts_for_family(family),
            durable_effects: durable_effect_contracts_for_family(family),
            commit_work: MethodCommitWorkAdapterContract::for_method(&method),
            forbidden: forbidden_method_responsibilities(),
            method,
        })
    }

    /// Returns the method declaration.
    pub const fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    /// Returns whether this is a normal plugin method or core-owned method.
    pub const fn ownership(&self) -> MethodAdapterOwnership {
        self.ownership
    }

    /// Returns facts the core derives from the method family and declaration.
    pub fn core_derived(&self) -> &[MethodCoreDerivedResponsibility] {
        &self.core_derived
    }

    /// Returns method responsibilities that must run before state loading.
    pub fn pre_state_load(&self) -> &[MethodPreStateLoadResponsibility] {
        &self.pre_state_load
    }

    /// Returns method responsibilities that require loaded core state.
    pub fn post_state_load(&self) -> &[MethodPostStateLoadResponsibility] {
        &self.post_state_load
    }

    /// Returns how method verification feeds the core completion boundary.
    pub const fn verification(&self) -> &MethodVerificationContract {
        &self.verification
    }

    /// Returns the challenge-cookie contract.
    pub const fn challenge_cookie(&self) -> &MethodChallengeCookieContract {
        &self.challenge_cookie
    }

    /// Returns method-owned Postgres state contracts.
    pub fn postgres_state(&self) -> &[MethodPostgresStateContract] {
        &self.postgres_state
    }

    /// Returns durable-effect contracts for this method.
    pub fn durable_effects(&self) -> &[MethodDurableEffectContract] {
        &self.durable_effects
    }

    /// Returns method commit-work placement rules.
    pub const fn commit_work(&self) -> &MethodCommitWorkAdapterContract {
        &self.commit_work
    }

    /// Returns responsibilities method adapters must not own.
    pub fn forbidden(&self) -> &[MethodAdapterForbiddenResponsibility] {
        &self.forbidden
    }
}

/// Whether a method is externally pluggable or core-owned.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodAdapterOwnership {
    /// Normal method adapter implemented outside the lower core.
    PluginOwned,
    /// Core-owned method with no external plugin authority over lifecycle.
    CoreOwned,
}

/// Security facts derived by the core, not supplied by a plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MethodCoreDerivedResponsibility {
    /// Proof family semantics are derived from `ProofFamily`.
    ProofSemantics(ProofSemantics),
    /// Allowed proof uses are derived from `ProofFamily`.
    SupportedProofUses(Vec<ProofUse>),
    /// Online-guessable methods consume weak-proof attempt budget on failure.
    WeakFailureBudgetUse(OnlineGuessingRisk),
    /// One-time families must include method commit work on success.
    SuccessCommitWorkRequirement {
        /// Whether success requires method commit work.
        required: bool,
    },
}

/// Method work that must happen before loading reducer state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodPreStateLoadResponsibility {
    /// Verify an encrypted challenge cookie before accepting submitted proof material.
    EncryptedChallengeCookie,
    /// Verify the stateless fast-fail MAC carried inside the encrypted challenge cookie.
    StatelessFastFailMacFromEncryptedChallengeCookie,
    /// Verify weak-proof gate before any stateful weak-proof check.
    WeakProofGateBeforeStateLoad,
    /// Verify the configured-secret Bloom filter carried inside the encrypted challenge cookie.
    ChallengeBoundConfiguredSecretFastFailBloomFilter,
    /// Verify message signature over a core-bound challenge before emitting a verified proof.
    BoundMessageSignature,
    /// Verify origin-bound authenticator assertion before emitting a verified proof.
    OriginBoundPublicKeyAssertion,
    /// Verify trusted issuer assertion before emitting a verified proof.
    FederatedIdentityAssertion,
}

/// Method work that requires loaded core state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodPostStateLoadResponsibility {
    /// Verify configured secret proof for the active-proof attempt's known subject.
    VerifyConfiguredSecretProofForKnownSubject,
    /// Verify one-time recovery proof for the active-proof attempt's known subject.
    VerifyOneTimeRecoveryProofForKnownSubject,
}

/// Method verification output contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodVerificationContract {
    completion_input: MethodCompletionInputKind,
    verified_proof_identity: MethodVerifiedProofIdentitySource,
    subject_binding: MethodVerifiedProofSubjectBinding,
}

impl MethodVerificationContract {
    /// Builds the verification contract for one declared method.
    pub fn for_method(method: &ProofMethodDeclaration) -> Self {
        match method.family() {
            ProofFamily::OutOfBandCode => Self {
                completion_input: MethodCompletionInputKind::SubmittedSecretResponse,
                verified_proof_identity:
                    MethodVerifiedProofIdentitySource::EncryptedChallengeCookie,
                subject_binding: MethodVerifiedProofSubjectBinding::MethodMayResolve,
            },
            ProofFamily::MessageSignature => Self {
                completion_input: MethodCompletionInputKind::BoundMessageSignatureAssertion,
                verified_proof_identity:
                    MethodVerifiedProofIdentitySource::EncryptedChallengeCookie,
                subject_binding: MethodVerifiedProofSubjectBinding::MethodMayResolve,
            },
            ProofFamily::OriginBoundPublicKey => Self {
                completion_input: MethodCompletionInputKind::OriginBoundPublicKeyAssertion,
                verified_proof_identity:
                    MethodVerifiedProofIdentitySource::EncryptedChallengeCookie,
                subject_binding: MethodVerifiedProofSubjectBinding::MethodMayResolve,
            },
            ProofFamily::FederatedIdentityAssertion => Self {
                completion_input: MethodCompletionInputKind::FederatedIdentityAssertion,
                verified_proof_identity:
                    MethodVerifiedProofIdentitySource::EncryptedChallengeCookie,
                subject_binding: MethodVerifiedProofSubjectBinding::MethodMayResolve,
            },
            ProofFamily::SharedSecretOtp => Self {
                completion_input: MethodCompletionInputKind::ConfiguredSecretProof,
                verified_proof_identity: MethodVerifiedProofIdentitySource::MethodDeclaration,
                subject_binding: MethodVerifiedProofSubjectBinding::KnownAttemptSubject,
            },
            ProofFamily::RecoveryCode => Self {
                completion_input: MethodCompletionInputKind::RecoveryCredential,
                verified_proof_identity: MethodVerifiedProofIdentitySource::MethodDeclaration,
                subject_binding: MethodVerifiedProofSubjectBinding::KnownAttemptSubject,
            },
            ProofFamily::TrustedDevice => Self {
                completion_input: MethodCompletionInputKind::PassiveTrustedDeviceCredential,
                verified_proof_identity: MethodVerifiedProofIdentitySource::TrustedDeviceCredential,
                subject_binding: MethodVerifiedProofSubjectBinding::TrustedDeviceCredentialSubject,
            },
        }
    }

    /// Returns the method-specific material that enters the runtime.
    pub const fn completion_input(&self) -> MethodCompletionInputKind {
        self.completion_input
    }

    /// Returns where the core proof identity comes from.
    pub const fn verified_proof_identity(&self) -> MethodVerifiedProofIdentitySource {
        self.verified_proof_identity
    }

    /// Returns how a verified proof may bind a subject.
    pub const fn subject_binding(&self) -> MethodVerifiedProofSubjectBinding {
        self.subject_binding
    }
}

/// Method-specific material accepted by the runtime before completing a proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodCompletionInputKind {
    /// Submitted secret response to a challenge, such as an email code.
    SubmittedSecretResponse,
    /// Signature over a core-bound canonical message.
    BoundMessageSignatureAssertion,
    /// Assertion from an origin/RP-bound public-key authenticator.
    OriginBoundPublicKeyAssertion,
    /// Assertion from a configured external identity provider.
    FederatedIdentityAssertion,
    /// Code derived from a configured per-subject secret.
    ConfiguredSecretProof,
    /// One-time recovery credential.
    RecoveryCredential,
    /// Passive trusted-device credential resolved by the core lifecycle.
    PassiveTrustedDeviceCredential,
}

/// Source of the proof identity accepted by core completion.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodVerifiedProofIdentitySource {
    /// Runtime derives proof identity from an encrypted challenge cookie.
    EncryptedChallengeCookie,
    /// Runtime derives proof identity from the method declaration.
    MethodDeclaration,
    /// Core derives proof identity from a trusted-device credential record.
    TrustedDeviceCredential,
}

/// How method verification may affect subject binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodVerifiedProofSubjectBinding {
    /// Method verification may resolve a subject from recipient, verifier, or assertion state.
    MethodMayResolve,
    /// The proof may only apply to a subject the attempt already knows.
    KnownAttemptSubject,
    /// Core uses the trusted-device credential's stored subject.
    TrustedDeviceCredentialSubject,
}

/// Challenge-cookie contract for a method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodChallengeCookieContract {
    kind: MethodChallengeCookieKind,
    fields: Vec<MethodChallengeCookieField>,
    associated_data: Vec<MethodChallengeCookieAssociatedData>,
}

impl MethodChallengeCookieContract {
    /// Builds the challenge-cookie contract for one method.
    pub fn for_method(method: &ProofMethodDeclaration) -> Self {
        match method.family() {
            ProofFamily::OutOfBandCode => Self::required(
                MethodChallengeCookieKind::EncryptedOutOfBandFastFail,
                vec![
                    MethodChallengeCookieField::AttemptId,
                    MethodChallengeCookieField::ChallengeId,
                    MethodChallengeCookieField::ProofMethodLabel,
                    MethodChallengeCookieField::IssuedAt,
                    MethodChallengeCookieField::ExpiresAt,
                    MethodChallengeCookieField::FastFailNonce,
                    MethodChallengeCookieField::StatelessFastFailMac,
                ],
            ),
            ProofFamily::MessageSignature => Self::required(
                MethodChallengeCookieKind::EncryptedMessageSignatureChallenge,
                vec![
                    MethodChallengeCookieField::AttemptId,
                    MethodChallengeCookieField::ChallengeId,
                    MethodChallengeCookieField::ProofMethodLabel,
                    MethodChallengeCookieField::IssuedAt,
                    MethodChallengeCookieField::ExpiresAt,
                    MethodChallengeCookieField::ChallengeNonce,
                    MethodChallengeCookieField::CanonicalMessageHash,
                ],
            ),
            ProofFamily::OriginBoundPublicKey => Self::required(
                MethodChallengeCookieKind::EncryptedOriginBoundPublicKeyChallenge,
                vec![
                    MethodChallengeCookieField::AttemptId,
                    MethodChallengeCookieField::ChallengeId,
                    MethodChallengeCookieField::ProofMethodLabel,
                    MethodChallengeCookieField::IssuedAt,
                    MethodChallengeCookieField::ExpiresAt,
                    MethodChallengeCookieField::ChallengeNonce,
                    MethodChallengeCookieField::OriginOrRelyingPartyId,
                ],
            ),
            ProofFamily::FederatedIdentityAssertion => Self::required(
                MethodChallengeCookieKind::EncryptedFederatedIdentityState,
                vec![
                    MethodChallengeCookieField::AttemptId,
                    MethodChallengeCookieField::ChallengeId,
                    MethodChallengeCookieField::ProofMethodLabel,
                    MethodChallengeCookieField::IssuedAt,
                    MethodChallengeCookieField::ExpiresAt,
                    MethodChallengeCookieField::ChallengeNonce,
                    MethodChallengeCookieField::FederatedIssuer,
                ],
            ),
            ProofFamily::SharedSecretOtp
            | ProofFamily::TrustedDevice
            | ProofFamily::RecoveryCode => Self::not_used(),
        }
    }

    fn required(kind: MethodChallengeCookieKind, fields: Vec<MethodChallengeCookieField>) -> Self {
        Self {
            kind,
            fields,
            associated_data: vec![
                MethodChallengeCookieAssociatedData::CookieVersion,
                MethodChallengeCookieAssociatedData::ProofFamily,
                MethodChallengeCookieAssociatedData::ProofMethodLabel,
                MethodChallengeCookieAssociatedData::AttemptId,
                MethodChallengeCookieAssociatedData::ChallengeId,
            ],
        }
    }

    fn not_used() -> Self {
        Self {
            kind: MethodChallengeCookieKind::NotUsed,
            fields: Vec::new(),
            associated_data: Vec::new(),
        }
    }

    fn for_challenge_bound_configured_secret_method() -> Self {
        Self::required(
            MethodChallengeCookieKind::EncryptedConfiguredSecretFastFailChallenge,
            vec![
                MethodChallengeCookieField::AttemptId,
                MethodChallengeCookieField::ChallengeId,
                MethodChallengeCookieField::ProofMethodLabel,
                MethodChallengeCookieField::IssuedAt,
                MethodChallengeCookieField::ExpiresAt,
                MethodChallengeCookieField::ChallengeNonce,
                MethodChallengeCookieField::ConfiguredSecretFastFailBloomFilter,
            ],
        )
    }

    /// Returns the challenge-cookie kind.
    pub const fn kind(&self) -> MethodChallengeCookieKind {
        self.kind
    }

    /// Returns fields that must be present in the encrypted cookie payload.
    pub fn fields(&self) -> &[MethodChallengeCookieField] {
        &self.fields
    }

    /// Returns values bound as associated data or equivalent context.
    pub fn associated_data(&self) -> &[MethodChallengeCookieAssociatedData] {
        &self.associated_data
    }
}

/// Method challenge-cookie shape.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodChallengeCookieKind {
    /// No method challenge cookie is required.
    NotUsed,
    /// Encrypted out-of-band challenge cookie carrying a stateless fast-fail MAC.
    EncryptedOutOfBandFastFail,
    /// Encrypted message-signature challenge cookie.
    EncryptedMessageSignatureChallenge,
    /// Encrypted origin-bound public-key challenge cookie.
    EncryptedOriginBoundPublicKeyChallenge,
    /// Encrypted federated-identity state and nonce cookie.
    EncryptedFederatedIdentityState,
    /// Encrypted configured-secret challenge cookie carrying a fast-fail Bloom filter.
    EncryptedConfiguredSecretFastFailChallenge,
}

/// Field inside a method challenge cookie.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodChallengeCookieField {
    /// Active-proof attempt id.
    AttemptId,
    /// Active-proof challenge id.
    ChallengeId,
    /// Concrete proof method label.
    ProofMethodLabel,
    /// Issue timestamp.
    IssuedAt,
    /// Expiration timestamp.
    ExpiresAt,
    /// Random nonce for fast-fail or challenge binding.
    FastFailNonce,
    /// MAC stored in the encrypted cookie for stateless fast-fail.
    StatelessFastFailMac,
    /// Random challenge nonce.
    ChallengeNonce,
    /// Hash of the canonical message to be signed.
    CanonicalMessageHash,
    /// Origin or relying-party id binding.
    OriginOrRelyingPartyId,
    /// Trusted issuer identifier.
    FederatedIssuer,
    /// Bloom filter for challenge-bound configured-secret fast-fail.
    ConfiguredSecretFastFailBloomFilter,
}

/// Context bound to method challenge cookies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodChallengeCookieAssociatedData {
    /// Cookie schema version.
    CookieVersion,
    /// Core proof family.
    ProofFamily,
    /// Concrete proof method label.
    ProofMethodLabel,
    /// Active-proof attempt id.
    AttemptId,
    /// Active-proof challenge id.
    ChallengeId,
}

/// Method-owned Postgres state contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodPostgresStateContract {
    purpose: MethodPostgresStatePurpose,
    key_policy: MethodPostgresStateKeyPolicy,
    mutation_boundary: MethodPostgresStateMutationBoundary,
}

impl MethodPostgresStateContract {
    fn new(
        purpose: MethodPostgresStatePurpose,
        key_policy: MethodPostgresStateKeyPolicy,
        mutation_boundary: MethodPostgresStateMutationBoundary,
    ) -> Self {
        Self {
            purpose,
            key_policy,
            mutation_boundary,
        }
    }

    /// Returns the state-table purpose.
    pub const fn purpose(&self) -> MethodPostgresStatePurpose {
        self.purpose
    }

    /// Returns required key semantics.
    pub const fn key_policy(&self) -> MethodPostgresStateKeyPolicy {
        self.key_policy
    }

    /// Returns where mutations to this state may happen.
    pub const fn mutation_boundary(&self) -> MethodPostgresStateMutationBoundary {
        self.mutation_boundary
    }
}

/// Purpose of method-owned Postgres state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodPostgresStatePurpose {
    /// Private state for active out-of-band challenges.
    OutOfBandChallengePrivateState,
    /// Verifier registry or credential lookup state.
    VerifierRegistry,
    /// External issuer subject mapping.
    FederatedIdentitySubjectMapping,
    /// Configured per-subject secret verifier.
    ConfiguredSecretVerifier,
    /// One-time recovery credential verifier.
    OneTimeRecoveryCredential,
}

/// Key semantics for method-owned Postgres state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodPostgresStateKeyPolicy {
    /// Keyed by active-proof challenge id.
    ChallengeId,
    /// Keyed by subject id plus verifier id.
    SubjectAndVerifierId,
    /// Keyed by external issuer plus external subject bytes.
    ExternalIssuerAndSubject,
    /// Keyed by subject id.
    SubjectId,
    /// Keyed by subject id plus one-time credential id.
    SubjectAndOneTimeCredentialId,
}

/// Boundary where method-owned state may be mutated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodPostgresStateMutationBoundary {
    /// Read before command construction, but do not mutate in that read path.
    ReadOnlyBeforeCommandConstruction,
    /// Mutate only through method commit work inside the core atomic boundary.
    OnlyThroughMethodCommitWorkInsideCoreAtomicCommit,
}

/// Durable effect contract for a method.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodDurableEffectContract {
    /// Out-of-band delivery is represented as a core durable command.
    CoreOutOfBandDeliveryCommand,
    /// Method may persist method-specific durable commands only inside method commit work.
    MethodDurableCommandInsideCoreAtomicCommit,
}

/// Method commit-work placement contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitWorkAdapterContract {
    allowed_stages: Vec<MethodCommitBoundaryStage>,
    success_requirement: MethodCommitWorkSuccessRequirement,
}

impl MethodCommitWorkAdapterContract {
    /// Builds commit-work contract for a method.
    pub fn for_method(method: &ProofMethodDeclaration) -> Self {
        Self {
            allowed_stages: vec![
                MethodCommitBoundaryStage::EnforceAfterCorePreconditions,
                MethodCommitBoundaryStage::ApplyAfterCoreMutations,
                MethodCommitBoundaryStage::PersistDurableCommandsBeforeCommit,
            ],
            success_requirement: if method.requires_method_commit_work_on_success() {
                MethodCommitWorkSuccessRequirement::RequiredForSuccessfulProofCompletion
            } else {
                MethodCommitWorkSuccessRequirement::OptionalWhenMethodHasPrivateStateChange
            },
        }
    }

    /// Returns where method commit work may run.
    pub fn allowed_stages(&self) -> &[MethodCommitBoundaryStage] {
        &self.allowed_stages
    }

    /// Returns whether proof success requires method commit work.
    pub const fn success_requirement(&self) -> MethodCommitWorkSuccessRequirement {
        self.success_requirement
    }
}

/// Whether successful proof completion requires method commit work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodCommitWorkSuccessRequirement {
    /// Method commit work is required when accepting a verified proof.
    RequiredForSuccessfulProofCompletion,
    /// Method commit work is optional and used only for private method state changes.
    OptionalWhenMethodHasPrivateStateChange,
}

/// Responsibility forbidden to method adapters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodAdapterForbiddenResponsibility {
    /// Method adapters must not create, refresh, or revoke core sessions.
    MutateCoreSessionLifecycle,
    /// Method adapters must not create, rotate, or revoke trusted-device credentials.
    MutateTrustedDeviceLifecycle,
    /// Method adapters must not emit or delete auth cookies.
    EmitAuthCookies,
    /// Method adapters must not cycle CSRF tokens.
    CycleCsrfTokens,
    /// Method adapters must not decide final proof-stack sufficiency.
    DecideProofStackSufficiency,
    /// Method adapters must not override proof-family semantics or proof-use support.
    OverrideCoreProofSemantics,
    /// Method adapters must not construct core completion commands directly.
    ConstructCoreCompletionCommandDirectly,
    /// Method adapters must not mark stateless fast-fail as verified.
    MarkStatelessFastFailVerified,
    /// Method adapters must not append core audit events.
    AppendCoreAuditEvents,
    /// Method adapters must not deliver external effects before atomic commit succeeds.
    DeliverExternalEffectsBeforeCommit,
}

fn ownership_for_family(family: ProofFamily) -> MethodAdapterOwnership {
    match family {
        ProofFamily::TrustedDevice => MethodAdapterOwnership::CoreOwned,
        ProofFamily::OutOfBandCode
        | ProofFamily::MessageSignature
        | ProofFamily::OriginBoundPublicKey
        | ProofFamily::FederatedIdentityAssertion
        | ProofFamily::SharedSecretOtp
        | ProofFamily::RecoveryCode => MethodAdapterOwnership::PluginOwned,
    }
}

fn core_derived_responsibilities_for_method(
    method: &ProofMethodDeclaration,
) -> Vec<MethodCoreDerivedResponsibility> {
    Vec::from([
        MethodCoreDerivedResponsibility::ProofSemantics(method.semantics()),
        MethodCoreDerivedResponsibility::SupportedProofUses(supported_uses_for_family(
            method.family(),
        )),
        MethodCoreDerivedResponsibility::WeakFailureBudgetUse(method.online_guessing_risk()),
        MethodCoreDerivedResponsibility::SuccessCommitWorkRequirement {
            required: method.requires_method_commit_work_on_success(),
        },
    ])
}

fn supported_uses_for_family(family: ProofFamily) -> Vec<ProofUse> {
    [
        ProofUse::BindSubjectToActiveProofAttempt,
        ProofUse::ContributeToFullAuthentication,
        ProofUse::ReviveTrustedDeviceWithActiveProof,
        ProofUse::SatisfyStepUp,
        ProofUse::SilentlyReviveTrustedDeviceSession,
        ProofUse::ReduceAuthenticationRequirement,
        ProofUse::RecoverOrReplaceCredential,
    ]
    .into_iter()
    .filter(|proof_use| family.supports_use(*proof_use))
    .collect()
}

fn pre_state_load_responsibilities_for_method(
    method: &ProofMethodDeclaration,
) -> Vec<MethodPreStateLoadResponsibility> {
    let mut responsibilities = match method.family() {
        ProofFamily::OutOfBandCode => vec![
            MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::StatelessFastFailMacFromEncryptedChallengeCookie,
        ],
        ProofFamily::MessageSignature => vec![
            MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::BoundMessageSignature,
        ],
        ProofFamily::OriginBoundPublicKey => vec![
            MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::OriginBoundPublicKeyAssertion,
        ],
        ProofFamily::FederatedIdentityAssertion => vec![
            MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::FederatedIdentityAssertion,
        ],
        ProofFamily::SharedSecretOtp | ProofFamily::RecoveryCode => Vec::new(),
        ProofFamily::TrustedDevice => Vec::new(),
    };
    if method.uses_weak_attempt_failure_budget() {
        responsibilities.push(MethodPreStateLoadResponsibility::WeakProofGateBeforeStateLoad);
    }
    responsibilities
}

fn post_state_load_responsibilities_for_method(
    method: &ProofMethodDeclaration,
) -> Vec<MethodPostStateLoadResponsibility> {
    match method.family() {
        ProofFamily::SharedSecretOtp => {
            vec![MethodPostStateLoadResponsibility::VerifyConfiguredSecretProofForKnownSubject]
        }
        ProofFamily::RecoveryCode => {
            vec![MethodPostStateLoadResponsibility::VerifyOneTimeRecoveryProofForKnownSubject]
        }
        ProofFamily::OutOfBandCode
        | ProofFamily::MessageSignature
        | ProofFamily::OriginBoundPublicKey
        | ProofFamily::FederatedIdentityAssertion
        | ProofFamily::TrustedDevice => Vec::new(),
    }
}

fn postgres_state_contracts_for_family(family: ProofFamily) -> Vec<MethodPostgresStateContract> {
    match family {
        ProofFamily::OutOfBandCode => vec![MethodPostgresStateContract::new(
            MethodPostgresStatePurpose::OutOfBandChallengePrivateState,
            MethodPostgresStateKeyPolicy::ChallengeId,
            MethodPostgresStateMutationBoundary::OnlyThroughMethodCommitWorkInsideCoreAtomicCommit,
        )],
        ProofFamily::MessageSignature | ProofFamily::OriginBoundPublicKey => {
            vec![MethodPostgresStateContract::new(
                MethodPostgresStatePurpose::VerifierRegistry,
                MethodPostgresStateKeyPolicy::SubjectAndVerifierId,
                MethodPostgresStateMutationBoundary::ReadOnlyBeforeCommandConstruction,
            )]
        }
        ProofFamily::FederatedIdentityAssertion => vec![MethodPostgresStateContract::new(
            MethodPostgresStatePurpose::FederatedIdentitySubjectMapping,
            MethodPostgresStateKeyPolicy::ExternalIssuerAndSubject,
            MethodPostgresStateMutationBoundary::ReadOnlyBeforeCommandConstruction,
        )],
        ProofFamily::SharedSecretOtp => vec![MethodPostgresStateContract::new(
            MethodPostgresStatePurpose::ConfiguredSecretVerifier,
            MethodPostgresStateKeyPolicy::SubjectId,
            MethodPostgresStateMutationBoundary::ReadOnlyBeforeCommandConstruction,
        )],
        ProofFamily::RecoveryCode => vec![MethodPostgresStateContract::new(
            MethodPostgresStatePurpose::OneTimeRecoveryCredential,
            MethodPostgresStateKeyPolicy::SubjectAndOneTimeCredentialId,
            MethodPostgresStateMutationBoundary::OnlyThroughMethodCommitWorkInsideCoreAtomicCommit,
        )],
        ProofFamily::TrustedDevice => Vec::new(),
    }
}

fn durable_effect_contracts_for_family(family: ProofFamily) -> Vec<MethodDurableEffectContract> {
    match family {
        ProofFamily::OutOfBandCode => vec![
            MethodDurableEffectContract::CoreOutOfBandDeliveryCommand,
            MethodDurableEffectContract::MethodDurableCommandInsideCoreAtomicCommit,
        ],
        ProofFamily::RecoveryCode => {
            vec![MethodDurableEffectContract::MethodDurableCommandInsideCoreAtomicCommit]
        }
        ProofFamily::MessageSignature
        | ProofFamily::OriginBoundPublicKey
        | ProofFamily::FederatedIdentityAssertion
        | ProofFamily::SharedSecretOtp
        | ProofFamily::TrustedDevice => Vec::new(),
    }
}

fn forbidden_method_responsibilities() -> Vec<MethodAdapterForbiddenResponsibility> {
    Vec::from([
        MethodAdapterForbiddenResponsibility::MutateCoreSessionLifecycle,
        MethodAdapterForbiddenResponsibility::MutateTrustedDeviceLifecycle,
        MethodAdapterForbiddenResponsibility::EmitAuthCookies,
        MethodAdapterForbiddenResponsibility::CycleCsrfTokens,
        MethodAdapterForbiddenResponsibility::DecideProofStackSufficiency,
        MethodAdapterForbiddenResponsibility::OverrideCoreProofSemantics,
        MethodAdapterForbiddenResponsibility::ConstructCoreCompletionCommandDirectly,
        MethodAdapterForbiddenResponsibility::MarkStatelessFastFailVerified,
        MethodAdapterForbiddenResponsibility::AppendCoreAuditEvents,
        MethodAdapterForbiddenResponsibility::DeliverExternalEffectsBeforeCommit,
    ])
}
