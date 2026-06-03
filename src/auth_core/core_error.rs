use std::fmt;

use super::*;

/// Auth core reducer error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Error {
    /// Opaque identifiers must not be empty.
    EmptyId,
    /// Credential versions must be non-zero.
    SecretVersionZero,
    /// Credential version arithmetic overflowed.
    SecretVersionOverflow,
    /// Timestamp arithmetic overflowed.
    TimeOverflow,
    /// Proof summaries must include a non-empty adapter label.
    EmptyProofMethodLabel,
    /// Exact proof requirements must include a non-empty adapter label.
    EmptyProofRequirementMethodLabel,
    /// Method atomic work must contain at least one atomic item.
    EmptyMethodCommitWork,
    /// Method atomic work item labels must be non-empty.
    EmptyMethodCommitWorkItemLabel,
    /// Method atomic work must belong to the exact proof being completed.
    MethodCommitWorkProofMismatch,
    /// Atomic work contains more than one method-work batch for the same proof.
    DuplicateMethodCommitWorkForProof,
    /// One-time proof families must carry method atomic work when accepted.
    MissingMethodCommitWorkForOneTimeProof,
    /// Atomic work is missing required fresh credential-secret work.
    MissingFreshCredentialSecret,
    /// Atomic work includes fresh credential-secret work without a matching mutation.
    UnexpectedFreshCredentialSecret,
    /// Atomic work includes the same fresh credential-secret work more than once.
    DuplicateFreshCredentialSecret,
    /// A committed transaction omitted a required fresh credential-secret materialization.
    MissingMaterializedFreshCredentialSecret,
    /// A committed transaction materialized a fresh credential secret the plan did not request.
    UnexpectedMaterializedFreshCredentialSecret,
    /// A committed transaction materialized the same fresh credential-secret target twice.
    DuplicateMaterializedFreshCredentialSecret,
    /// A reported atomic commit success belongs to different atomic work.
    AtomicCommitSuccessDoesNotMatchPlannedWork,
    /// A session-cookie response effect is not backed by same-commit credential state.
    UnbackedSessionCookieResponseEffect,
    /// A trusted-device-cookie response effect is not backed by same-commit credential state.
    UnbackedTrustedDeviceCookieResponseEffect,
    /// A challenge-cookie response effect is not backed by same-commit challenge state.
    UnbackedActiveProofChallengeCookieResponseEffect,
    /// A continuation-cookie response effect is not backed by same-commit attempt state.
    UnbackedActiveProofContinuationCookieResponseEffect,
    /// Response effects cannot be released until required atomic commit work succeeds.
    AtomicCommitRequiredBeforeResponseEffects,
    /// A session-cookie response needed a credential secret that was not available.
    MissingSessionCookieResponseSecret,
    /// A trusted-device-cookie response needed a credential secret that was not available.
    MissingTrustedDeviceCookieResponseSecret,
    /// An active-proof continuation-cookie response needed a credential secret that was not available.
    MissingActiveProofContinuationCookieResponseSecret,
    /// A presented session cookie secret did not match the decoded session cookie.
    PresentedSessionCookieSecretMismatch,
    /// A presented trusted-device cookie secret did not match the decoded trusted-device cookie.
    PresentedTrustedDeviceCookieSecretMismatch,
    /// A presented active-proof continuation cookie secret did not match the decoded continuation cookie.
    PresentedActiveProofContinuationCookieSecretMismatch,
    /// Weak-proof gate summaries must include a non-empty adapter label.
    EmptyWeakProofGateMethodLabel,
    /// Weak-proof gate responses must not be empty.
    EmptyWeakProofGateResponsePayload,
    /// Auth core inputs must stay inside resource bounds.
    InputTooLong {
        /// Input that exceeded the bound.
        input_name: &'static str,
        /// Maximum accepted UTF-8 or byte length.
        max_bytes: usize,
    },
    /// Auth core identifier strings must be visible ASCII without whitespace.
    InvalidIdentifierString {
        /// Input that contained an invalid byte.
        input_name: &'static str,
    },
    /// Out-of-band dedupe keys must not be empty.
    EmptyOutOfBandChallengeDedupeKey,
    /// Out-of-band recipient handles must not be empty.
    EmptyOutOfBandRecipientHandle,
    /// Delivery idempotency keys must not be empty.
    EmptyOutOfBandDeliveryIdempotencyKey,
    /// A transition requiring authentication proof was given no proofs.
    MissingSatisfiedProof,
    /// A proof family cannot satisfy the requested core transition.
    ProofFamilyCannotSatisfyUse {
        /// Proof family that was rejected.
        family: ProofFamily,
        /// Requested transition use.
        proof_use: ProofUse,
    },
    /// Only out-of-band proof methods can issue out-of-band challenges.
    ProofMethodCannotIssueOutOfBandChallenge {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// Only non-out-of-band active proof methods can issue method challenges.
    ProofMethodCannotIssueActiveProofMethodChallenge {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// Only known-subject configured methods can use known-subject active-proof completion.
    ProofMethodCannotCompleteKnownSubjectActiveProof {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// Only configured-secret proof methods can use challenge-bound configured-secret fast-fail.
    ProofMethodCannotUseChallengeBoundConfiguredSecretFastFail {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// Out-of-band challenge issue requires runtime-owned fast-fail cookie construction.
    OutOfBandChallengeIssueRequiresRuntimeCookieConstruction,
    /// Out-of-band challenge resend requires runtime-owned method dispatch.
    OutOfBandChallengeResendRequiresRuntimeMethodDispatch,
    /// Active-proof completion requires runtime-owned method dispatch.
    ActiveProofCompletionRequiresRuntimeMethodDispatch,
    /// Active-proof failure recording requires runtime-owned method dispatch.
    ActiveProofFailureRequiresRuntimeMethodDispatch,
    /// Request resolution requires runtime-owned fresh session id generation.
    RequestResolutionRequiresRuntimeFreshIdGeneration,
    /// Active-proof attempt start requires runtime-owned fresh attempt id generation.
    ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration,
    /// Full-authentication completion requires runtime-owned fresh id generation.
    FullAuthenticationCompletionRequiresRuntimeFreshIdGeneration,
    /// Trusted-device revival completion requires runtime-owned fresh session id generation.
    TrustedDeviceRevivalCompletionRequiresRuntimeFreshIdGeneration,
    /// Step-up completion requires runtime-owned active-proof continuation validation.
    StepUpCompletionRequiresRuntimeAttemptContinuation,
    /// Public unbound attempt start requires runtime-owned method challenge issue.
    UnboundActiveProofAttemptStartRequiresRuntimeMethodDispatch,
    /// Credential reset planning requires runtime-owned lifecycle-authority loading.
    CredentialResetPlanningRequiresRuntimeLifecycleDecision,
    /// Credential reset execution requires runtime-owned method dispatch.
    CredentialResetExecutionRequiresRuntimeMethodDispatch,
    /// Pending credential reset cancellation requires runtime-owned lifecycle loading.
    CredentialResetCancellationRequiresRuntimeLifecycleDecision,
    /// Non-reset credential lifecycle execution requires runtime-owned method dispatch.
    CredentialLifecycleExecutionRequiresRuntimeMethodDispatch,
    /// Non-reset credential lifecycle cancellation requires runtime-owned lifecycle loading.
    CredentialLifecycleCancellationRequiresRuntimeLifecycleDecision,
    /// Out-of-band proof completion must use the challenge-response runtime path.
    OutOfBandActiveProofCompletionRequiresChallengeResponse,
    /// A verified proof carried a subject even though its family cannot resolve subjects.
    ProofFamilyCannotCarryVerifiedSubject {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// A proof family requiring credential or authority provenance did not carry it.
    ProofFamilyRequiresVerifiedProofSource {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// A proof stack is individually valid but insufficient for the requested transition.
    SatisfiedProofStackCannotSatisfyUse {
        /// Requested transition use.
        proof_use: ProofUse,
    },
    /// A proof stack matched required methods but lacked known distinct proof sources.
    ProofStackRequiresKnownDistinctProofSources {
        /// Requested transition use.
        proof_use: ProofUse,
    },
    /// An active-proof attempt was requested for a transition no active proof can satisfy.
    ActiveProofUseCannotBeSatisfiedByActiveProof {
        /// Requested transition use.
        proof_use: ProofUse,
    },
    /// Configuration is invalid.
    InvalidConfig(&'static str),
    /// A transition required fresh random material that was not supplied.
    MissingFreshValue(&'static str),
    /// A delayed credential lifecycle action had impossible timing.
    InvalidCredentialLifecyclePendingActionTiming,
    /// A credential lifecycle transition was not authorized by loaded policy.
    CredentialLifecycleActionNotAuthorized,
    /// Credential reset execution requires method-owned verifier mutation work.
    CredentialResetExecutionMissingMethodCommitWork,
    /// Credential reset execution method work did not match the target credential.
    CredentialResetExecutionMethodCommitWorkTargetMismatch,
    /// A non-reset pending credential lifecycle command was given reset action state.
    NonResetPendingCredentialLifecycleActionCannotBeReset,
    /// Credential lifecycle execution requires method-owned work for this action.
    CredentialLifecycleExecutionMissingMethodCommitWork,
    /// Credential lifecycle execution method work did not match the target credential.
    CredentialLifecycleExecutionMethodCommitWorkTargetMismatch,
    /// Credential lifecycle execution was given method work for a core-only action.
    CredentialLifecycleExecutionUnexpectedMethodCommitWork,
    /// A pending credential lifecycle action was not executable at the transition time.
    PendingCredentialLifecycleActionNotExecutable,
    /// A pending credential lifecycle action was not open for cancellation.
    PendingCredentialLifecycleActionNotCancellable,
    /// Fresh random material could not be generated.
    FreshRandomMaterialUnavailable,
    /// Credential secrets must not be empty.
    EmptyCredentialSecret,
    /// Active-proof challenge responses must not be empty.
    EmptyActiveProofChallengeResponseSecret,
    /// Active-proof method challenge presentations must not be empty.
    EmptyActiveProofMethodChallengePresentation,
    /// Active-proof method challenge state payloads must not be empty.
    EmptyActiveProofMethodChallengeState,
    /// Active-proof method response payloads must not be empty.
    EmptyActiveProofMethodResponsePayload,
    /// Known-subject active-proof secret responses must not be empty.
    EmptyKnownSubjectActiveProofSecretResponse,
    /// Credential reset method payloads must not be empty.
    EmptyCredentialResetMethodPayload,
    /// Credential lifecycle method payloads must not be empty.
    EmptyCredentialLifecycleMethodPayload,
    /// Active-proof challenge fast-fail nonces must be exactly 32 bytes.
    InvalidActiveProofChallengeFastFailNonceLength {
        /// Actual byte length.
        actual: usize,
    },
    /// Active-proof challenge fast-fail MACs must be exactly one `MacOverSecret`.
    InvalidActiveProofChallengeFastFailMacLength {
        /// Actual byte length.
        actual: usize,
    },
    /// Active-proof challenge fast-fail MAC bytes were malformed.
    InvalidActiveProofChallengeFastFailMac,
    /// Challenge-bound configured-secret Bloom filters must not have an empty bitset.
    EmptyChallengeBoundConfiguredSecretFastFailBloomFilter,
    /// Challenge-bound configured-secret Bloom filters must use a supported hash count.
    InvalidChallengeBoundConfiguredSecretFastFailBloomFilterHashCount {
        /// Hash probe count that was rejected.
        actual: u8,
    },
    /// Active-proof challenge cookies must expire after they are issued.
    ActiveProofChallengeCookieExpiresAtOrBeforeIssuedAt,
    /// An active-proof completion needed a challenge cookie that was absent.
    MissingActiveProofChallengeCookie,
    /// An active-proof continuation needed a continuation cookie that was absent.
    MissingActiveProofContinuationCookie,
    /// The challenge cookie did not match the active-proof completion command.
    ActiveProofChallengeCookieCommandMismatch,
    /// A submitted-secret fast-fail cookie was used for a proof family that does not support it.
    ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
        /// Proof family that was rejected.
        family: ProofFamily,
    },
    /// The challenge cookie was expired before state loading.
    ActiveProofChallengeCookieExpired,
    /// The challenge cookie payload was malformed.
    InvalidActiveProofChallengeCookiePayload,
    /// The continuation cookie payload was malformed.
    InvalidActiveProofContinuationCookiePayload,
    /// A method-specific active-proof completion needed method state from the challenge cookie.
    MissingActiveProofMethodChallengeState,
    /// Stateless fast-fail verification failed before state loading.
    StatelessFastFailVerificationFailed,
    /// Loaded state contradicted itself.
    LoadedStateContradiction(&'static str),
    /// Loaded state does not satisfy the command's adapter load contract.
    LoadedStateDoesNotSatisfyLoadContract(&'static str),
    /// Runtime-loaded state requirements changed after challenge cookie construction.
    RuntimeLoadedStateContractChangedAfterCookieConstruction,
    /// The active-proof attempt already contains this proof family.
    ActiveProofAlreadySatisfied,
    /// The out-of-band challenge has no remaining user-visible resends.
    OutOfBandChallengeResendBudgetExhausted,
    /// The resend idempotency key must be fresh for this challenge.
    OutOfBandDeliveryIdempotencyKeyAlreadyUsed,
    /// A required stateless fast-fail check was not performed before state loading.
    StatelessFastFailVerificationRequired,
    /// A required weak-proof gate check was not performed before state loading.
    WeakProofGateVerificationRequired,
    /// The presented active-proof continuation secret did not match stored state.
    ActiveProofContinuationSecretMismatch,
    /// A weak-proof gate was supplied for a proof that does not use one.
    UnexpectedWeakProofGateResponse,
    /// The configured weak-proof gate rejected the submitted response.
    WeakProofGateVerificationFailed,
    /// The challenge-issue preflight response did not match the configured gate.
    ChallengeIssuePreflightGateMismatch,
    /// The active-proof attempt is no longer usable.
    ActiveProofAttemptNotOpen,
    /// The active-proof challenge is no longer usable.
    ActiveProofChallengeNotOpen,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => write!(f, "auth core: id is empty"),
            Self::SecretVersionZero => write!(f, "auth core: secret version is zero"),
            Self::SecretVersionOverflow => write!(f, "auth core: secret version overflow"),
            Self::TimeOverflow => write!(f, "auth core: time overflow"),
            Self::EmptyProofMethodLabel => write!(f, "auth core: proof method label is empty"),
            Self::EmptyProofRequirementMethodLabel => {
                write!(f, "auth core: proof requirement method label is empty")
            }
            Self::EmptyMethodCommitWork => write!(f, "auth core: method commit work is empty"),
            Self::EmptyMethodCommitWorkItemLabel => {
                write!(f, "auth core: method commit work item label is empty")
            }
            Self::MethodCommitWorkProofMismatch => {
                write!(
                    f,
                    "auth core: method commit work proof differs from completed proof"
                )
            }
            Self::DuplicateMethodCommitWorkForProof => {
                write!(
                    f,
                    "auth core: atomic work has duplicate method commit work for one proof"
                )
            }
            Self::MissingMethodCommitWorkForOneTimeProof => {
                write!(
                    f,
                    "auth core: one-time proof completion is missing method commit work"
                )
            }
            Self::MissingFreshCredentialSecret => {
                write!(
                    f,
                    "auth core: atomic work is missing a fresh credential secret"
                )
            }
            Self::UnexpectedFreshCredentialSecret => {
                write!(
                    f,
                    "auth core: atomic work has an unexpected fresh credential secret"
                )
            }
            Self::DuplicateFreshCredentialSecret => {
                write!(
                    f,
                    "auth core: atomic work has a duplicate fresh credential secret"
                )
            }
            Self::MissingMaterializedFreshCredentialSecret => {
                write!(
                    f,
                    "auth core: atomic commit is missing a materialized fresh credential secret"
                )
            }
            Self::UnexpectedMaterializedFreshCredentialSecret => {
                write!(
                    f,
                    "auth core: atomic commit has an unexpected materialized fresh credential secret"
                )
            }
            Self::DuplicateMaterializedFreshCredentialSecret => {
                write!(
                    f,
                    "auth core: atomic commit has a duplicate materialized fresh credential secret"
                )
            }
            Self::AtomicCommitSuccessDoesNotMatchPlannedWork => {
                write!(
                    f,
                    "auth core: atomic commit success does not match the planned work"
                )
            }
            Self::UnbackedSessionCookieResponseEffect => {
                write!(
                    f,
                    "auth core: session-cookie response effect is not backed by commit work"
                )
            }
            Self::UnbackedTrustedDeviceCookieResponseEffect => {
                write!(
                    f,
                    "auth core: trusted-device-cookie response effect is not backed by commit work"
                )
            }
            Self::UnbackedActiveProofChallengeCookieResponseEffect => {
                write!(
                    f,
                    "auth core: active-proof challenge-cookie response effect is not backed by commit work"
                )
            }
            Self::UnbackedActiveProofContinuationCookieResponseEffect => {
                write!(
                    f,
                    "auth core: active-proof continuation-cookie response effect is not backed by commit work"
                )
            }
            Self::AtomicCommitRequiredBeforeResponseEffects => {
                write!(
                    f,
                    "auth core: atomic commit must succeed before response effects are released"
                )
            }
            Self::MissingSessionCookieResponseSecret => {
                write!(
                    f,
                    "auth core: session-cookie response is missing a credential secret"
                )
            }
            Self::MissingTrustedDeviceCookieResponseSecret => {
                write!(
                    f,
                    "auth core: trusted-device-cookie response is missing a credential secret"
                )
            }
            Self::MissingActiveProofContinuationCookieResponseSecret => {
                write!(
                    f,
                    "auth core: active-proof continuation-cookie response is missing a credential secret"
                )
            }
            Self::PresentedSessionCookieSecretMismatch => {
                write!(
                    f,
                    "auth core: presented session cookie secret does not match the decoded cookie"
                )
            }
            Self::PresentedTrustedDeviceCookieSecretMismatch => {
                write!(
                    f,
                    "auth core: presented trusted-device cookie secret does not match the decoded cookie"
                )
            }
            Self::PresentedActiveProofContinuationCookieSecretMismatch => {
                write!(
                    f,
                    "auth core: presented active-proof continuation cookie secret does not match the decoded cookie"
                )
            }
            Self::EmptyWeakProofGateMethodLabel => {
                write!(f, "auth core: weak-proof gate method label is empty")
            }
            Self::EmptyWeakProofGateResponsePayload => {
                write!(f, "auth core: weak-proof gate response payload is empty")
            }
            Self::InputTooLong {
                input_name,
                max_bytes,
            } => {
                write!(
                    f,
                    "auth core: {input_name} exceeds maximum length of {max_bytes} bytes"
                )
            }
            Self::InvalidIdentifierString { input_name } => {
                write!(
                    f,
                    "auth core: {input_name} must be visible ASCII without whitespace"
                )
            }
            Self::EmptyOutOfBandChallengeDedupeKey => {
                write!(f, "auth core: out-of-band challenge dedupe key is empty")
            }
            Self::EmptyOutOfBandRecipientHandle => {
                write!(f, "auth core: out-of-band recipient handle is empty")
            }
            Self::EmptyOutOfBandDeliveryIdempotencyKey => {
                write!(
                    f,
                    "auth core: out-of-band delivery idempotency key is empty"
                )
            }
            Self::MissingSatisfiedProof => write!(f, "auth core: satisfied proof is missing"),
            Self::ProofFamilyCannotSatisfyUse { family, proof_use } => write!(
                f,
                "auth core: proof family {family:?} cannot satisfy use {proof_use:?}"
            ),
            Self::ProofMethodCannotIssueOutOfBandChallenge { family } => write!(
                f,
                "auth core: proof family {family:?} cannot issue out-of-band challenges"
            ),
            Self::ProofMethodCannotIssueActiveProofMethodChallenge { family } => write!(
                f,
                "auth core: proof family {family:?} cannot issue active-proof method challenges"
            ),
            Self::ProofMethodCannotCompleteKnownSubjectActiveProof { family } => write!(
                f,
                "auth core: proof family {family:?} cannot complete known-subject active proofs"
            ),
            Self::ProofMethodCannotUseChallengeBoundConfiguredSecretFastFail { family } => write!(
                f,
                "auth core: proof family {family:?} cannot use challenge-bound configured-secret fast-fail"
            ),
            Self::OutOfBandChallengeIssueRequiresRuntimeCookieConstruction => {
                write!(
                    f,
                    "auth core: out-of-band challenge issue requires runtime-owned fast-fail cookie construction"
                )
            }
            Self::OutOfBandChallengeResendRequiresRuntimeMethodDispatch => {
                write!(
                    f,
                    "auth core: out-of-band challenge resend requires runtime-owned method dispatch"
                )
            }
            Self::ActiveProofCompletionRequiresRuntimeMethodDispatch => {
                write!(
                    f,
                    "auth core: active-proof completion requires runtime-owned method dispatch"
                )
            }
            Self::ActiveProofFailureRequiresRuntimeMethodDispatch => {
                write!(
                    f,
                    "auth core: active-proof failure requires runtime-owned method dispatch"
                )
            }
            Self::RequestResolutionRequiresRuntimeFreshIdGeneration => {
                write!(
                    f,
                    "auth core: request resolution requires runtime-owned fresh id generation"
                )
            }
            Self::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration => {
                write!(
                    f,
                    "auth core: active-proof attempt start requires runtime-owned fresh id generation"
                )
            }
            Self::FullAuthenticationCompletionRequiresRuntimeFreshIdGeneration => {
                write!(
                    f,
                    "auth core: full authentication requires runtime-owned fresh id generation"
                )
            }
            Self::TrustedDeviceRevivalCompletionRequiresRuntimeFreshIdGeneration => {
                write!(
                    f,
                    "auth core: trusted-device revival requires runtime-owned fresh id generation"
                )
            }
            Self::StepUpCompletionRequiresRuntimeAttemptContinuation => {
                write!(
                    f,
                    "auth core: step-up completion requires runtime-owned active-proof continuation validation"
                )
            }
            Self::UnboundActiveProofAttemptStartRequiresRuntimeMethodDispatch => {
                write!(
                    f,
                    "auth core: unbound active-proof attempt start requires runtime-owned method challenge issue"
                )
            }
            Self::CredentialResetPlanningRequiresRuntimeLifecycleDecision => {
                write!(
                    f,
                    "auth core: credential reset planning requires runtime-owned lifecycle decision"
                )
            }
            Self::CredentialResetExecutionRequiresRuntimeMethodDispatch => {
                write!(
                    f,
                    "auth core: credential reset execution requires runtime-owned method dispatch"
                )
            }
            Self::CredentialResetCancellationRequiresRuntimeLifecycleDecision => {
                write!(
                    f,
                    "auth core: credential reset cancellation requires runtime-owned lifecycle decision"
                )
            }
            Self::CredentialLifecycleExecutionRequiresRuntimeMethodDispatch => {
                write!(
                    f,
                    "auth core: credential lifecycle execution requires runtime-owned method dispatch"
                )
            }
            Self::CredentialLifecycleCancellationRequiresRuntimeLifecycleDecision => {
                write!(
                    f,
                    "auth core: credential lifecycle cancellation requires runtime-owned lifecycle decision"
                )
            }
            Self::OutOfBandActiveProofCompletionRequiresChallengeResponse => {
                write!(
                    f,
                    "auth core: out-of-band active-proof completion requires challenge-response runtime"
                )
            }
            Self::ProofFamilyCannotCarryVerifiedSubject { family } => write!(
                f,
                "auth core: proof family {family:?} cannot carry a verified subject"
            ),
            Self::ProofFamilyRequiresVerifiedProofSource { family } => write!(
                f,
                "auth core: proof family {family:?} requires verified proof source provenance"
            ),
            Self::SatisfiedProofStackCannotSatisfyUse { proof_use } => write!(
                f,
                "auth core: satisfied proof stack cannot satisfy use {proof_use:?}"
            ),
            Self::ProofStackRequiresKnownDistinctProofSources { proof_use } => write!(
                f,
                "auth core: proof stack for use {proof_use:?} requires known distinct proof sources"
            ),
            Self::ActiveProofUseCannotBeSatisfiedByActiveProof { proof_use } => write!(
                f,
                "auth core: no active proof can satisfy use {proof_use:?}"
            ),
            Self::InvalidConfig(message) => write!(f, "auth core: invalid config: {message}"),
            Self::MissingFreshValue(label) => {
                write!(f, "auth core: missing fresh value: {label}")
            }
            Self::InvalidCredentialLifecyclePendingActionTiming => {
                write!(
                    f,
                    "auth core: credential lifecycle pending action timing is invalid"
                )
            }
            Self::CredentialLifecycleActionNotAuthorized => {
                write!(
                    f,
                    "auth core: credential lifecycle action is not authorized"
                )
            }
            Self::CredentialResetExecutionMissingMethodCommitWork => {
                write!(
                    f,
                    "auth core: credential reset execution is missing method commit work"
                )
            }
            Self::CredentialResetExecutionMethodCommitWorkTargetMismatch => {
                write!(
                    f,
                    "auth core: credential reset execution method commit work does not match the target credential"
                )
            }
            Self::NonResetPendingCredentialLifecycleActionCannotBeReset => {
                write!(
                    f,
                    "auth core: non-reset pending credential lifecycle action cannot be reset"
                )
            }
            Self::CredentialLifecycleExecutionMissingMethodCommitWork => {
                write!(
                    f,
                    "auth core: credential lifecycle execution is missing required method commit work"
                )
            }
            Self::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch => {
                write!(
                    f,
                    "auth core: credential lifecycle execution method commit work does not match the target credential"
                )
            }
            Self::CredentialLifecycleExecutionUnexpectedMethodCommitWork => {
                write!(
                    f,
                    "auth core: credential lifecycle execution has unexpected method commit work"
                )
            }
            Self::PendingCredentialLifecycleActionNotExecutable => {
                write!(
                    f,
                    "auth core: pending credential lifecycle action is not executable"
                )
            }
            Self::PendingCredentialLifecycleActionNotCancellable => {
                write!(
                    f,
                    "auth core: pending credential lifecycle action is not cancellable"
                )
            }
            Self::FreshRandomMaterialUnavailable => {
                write!(f, "auth core: fresh random material unavailable")
            }
            Self::EmptyCredentialSecret => write!(f, "auth core: credential secret is empty"),
            Self::EmptyActiveProofChallengeResponseSecret => {
                write!(
                    f,
                    "auth core: active-proof challenge response secret is empty"
                )
            }
            Self::EmptyActiveProofMethodChallengePresentation => {
                write!(
                    f,
                    "auth core: active-proof method challenge presentation is empty"
                )
            }
            Self::EmptyActiveProofMethodChallengeState => {
                write!(f, "auth core: active-proof method challenge state is empty")
            }
            Self::EmptyActiveProofMethodResponsePayload => {
                write!(
                    f,
                    "auth core: active-proof method response payload is empty"
                )
            }
            Self::EmptyKnownSubjectActiveProofSecretResponse => {
                write!(
                    f,
                    "auth core: known-subject active-proof secret response is empty"
                )
            }
            Self::EmptyCredentialResetMethodPayload => {
                write!(f, "auth core: credential reset method payload is empty")
            }
            Self::EmptyCredentialLifecycleMethodPayload => {
                write!(f, "auth core: credential lifecycle method payload is empty")
            }
            Self::InvalidActiveProofChallengeFastFailNonceLength { actual } => {
                write!(
                    f,
                    "auth core: active-proof challenge fast-fail nonce length is {actual}"
                )
            }
            Self::InvalidActiveProofChallengeFastFailMacLength { actual } => {
                write!(
                    f,
                    "auth core: active-proof challenge fast-fail MAC length is {actual}"
                )
            }
            Self::InvalidActiveProofChallengeFastFailMac => {
                write!(
                    f,
                    "auth core: active-proof challenge fast-fail MAC is invalid"
                )
            }
            Self::EmptyChallengeBoundConfiguredSecretFastFailBloomFilter => {
                write!(
                    f,
                    "auth core: challenge-bound configured-secret fast-fail Bloom filter is empty"
                )
            }
            Self::InvalidChallengeBoundConfiguredSecretFastFailBloomFilterHashCount { actual } => {
                write!(
                    f,
                    "auth core: challenge-bound configured-secret fast-fail Bloom filter hash count is {actual}"
                )
            }
            Self::ActiveProofChallengeCookieExpiresAtOrBeforeIssuedAt => {
                write!(
                    f,
                    "auth core: active-proof challenge cookie expires at or before issue time"
                )
            }
            Self::MissingActiveProofChallengeCookie => {
                write!(f, "auth core: active-proof challenge cookie is missing")
            }
            Self::MissingActiveProofContinuationCookie => {
                write!(f, "auth core: active-proof continuation cookie is missing")
            }
            Self::ActiveProofChallengeCookieCommandMismatch => {
                write!(
                    f,
                    "auth core: active-proof challenge cookie does not match command"
                )
            }
            Self::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret { family } => {
                write!(
                    f,
                    "auth core: active-proof challenge cookie proof family {family:?} cannot use submitted-secret fast-fail"
                )
            }
            Self::ActiveProofChallengeCookieExpired => {
                write!(f, "auth core: active-proof challenge cookie is expired")
            }
            Self::InvalidActiveProofChallengeCookiePayload => {
                write!(
                    f,
                    "auth core: active-proof challenge cookie payload is invalid"
                )
            }
            Self::InvalidActiveProofContinuationCookiePayload => {
                write!(
                    f,
                    "auth core: active-proof continuation cookie payload is invalid"
                )
            }
            Self::MissingActiveProofMethodChallengeState => {
                write!(
                    f,
                    "auth core: active-proof method challenge state is missing"
                )
            }
            Self::StatelessFastFailVerificationFailed => {
                write!(f, "auth core: stateless fast-fail verification failed")
            }
            Self::LoadedStateContradiction(message) => {
                write!(f, "auth core: loaded state contradiction: {message}")
            }
            Self::LoadedStateDoesNotSatisfyLoadContract(message) => {
                write!(
                    f,
                    "auth core: loaded state does not satisfy load contract: {message}"
                )
            }
            Self::RuntimeLoadedStateContractChangedAfterCookieConstruction => {
                write!(
                    f,
                    "auth core: runtime loaded-state contract changed after challenge cookie construction"
                )
            }
            Self::ActiveProofAlreadySatisfied => {
                write!(f, "auth core: active proof is already satisfied")
            }
            Self::OutOfBandChallengeResendBudgetExhausted => {
                write!(
                    f,
                    "auth core: out-of-band challenge resend budget is exhausted"
                )
            }
            Self::OutOfBandDeliveryIdempotencyKeyAlreadyUsed => {
                write!(
                    f,
                    "auth core: out-of-band delivery idempotency key was already used"
                )
            }
            Self::StatelessFastFailVerificationRequired => {
                write!(f, "auth core: stateless fast-fail verification is required")
            }
            Self::WeakProofGateVerificationRequired => {
                write!(f, "auth core: weak-proof gate verification is required")
            }
            Self::ActiveProofContinuationSecretMismatch => {
                write!(
                    f,
                    "auth core: active-proof continuation secret did not match stored state"
                )
            }
            Self::UnexpectedWeakProofGateResponse => {
                write!(
                    f,
                    "auth core: weak-proof gate response was supplied for a proof that does not use one"
                )
            }
            Self::WeakProofGateVerificationFailed => {
                write!(f, "auth core: weak-proof gate verification failed")
            }
            Self::ChallengeIssuePreflightGateMismatch => {
                write!(
                    f,
                    "auth core: challenge-issue preflight gate does not match config"
                )
            }
            Self::ActiveProofAttemptNotOpen => {
                write!(f, "auth core: active-proof attempt is not open")
            }
            Self::ActiveProofChallengeNotOpen => {
                write!(f, "auth core: active-proof challenge is not open")
            }
        }
    }
}

impl std::error::Error for Error {}
