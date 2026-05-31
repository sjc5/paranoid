use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::db::Tx;

use super::postgres_store::{PostgresAuthMethodCommitError, PostgresAuthMethodCommitExecutor};
use super::*;

pub(crate) trait PostgresAuthMethodPlugin: Send + Sync {
    fn method(&self) -> &ProofMethodDeclaration;

    fn build_out_of_band_issue(
        &self,
        request: &IssueOutOfBandChallengeRequest,
    ) -> Result<PostgresOutOfBandChallengeIssueBuild, PostgresAuthMethodBuildError> {
        let _ = request;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "out_of_band_issue",
        ))
    }

    fn build_active_proof_method_challenge(
        &self,
        request: &IssueActiveProofMethodChallengeRequest,
        challenge: &ActiveProofMethodChallengeSeed,
    ) -> Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError> {
        let _ = request;
        let _ = challenge;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "active_proof_method_challenge_issue",
        ))
    }

    fn build_out_of_band_resend_commit_work(
        &self,
        request: &ResendOutOfBandChallengeRequest,
        challenge: &ActiveProofChallengeRecord,
    ) -> Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError> {
        let _ = request;
        let _ = challenge;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "out_of_band_resend",
        ))
    }

    fn build_out_of_band_completion_commit_work(
        &self,
        challenge_id: &ActiveProofChallengeId,
        response: &CompleteOutOfBandChallengeResponse,
    ) -> Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError> {
        let _ = challenge_id;
        let _ = response;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "out_of_band_completion",
        ))
    }

    fn resolve_out_of_band_subject_id<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        challenge_id: &'a ActiveProofChallengeId,
        response: &'a CompleteOutOfBandChallengeResponse,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<SubjectId>, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = challenge_id;
        let _ = response;
        Box::pin(async { Ok(None) })
    }

    fn verify_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<ActiveProofMethodPreStateVerification, PostgresAuthMethodBuildError> {
        let _ = challenge;
        let _ = response;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "active_proof_completion",
        ))
    }

    fn verify_active_proof_method_response_with_authoritative_state<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        context: ActiveProofMethodAuthoritativeVerificationContext<'a>,
        pre_state_verified: &'a VerifiedActiveProofMethodResponse,
        response: &'a CompleteActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ActiveProofMethodAuthoritativeConfirmation,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = context;
        let _ = pre_state_verified;
        let _ = response;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "active_proof_authoritative_confirmation",
            ))
        })
    }

    fn verify_known_subject_active_proof_method_response<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        subject_id: &'a SubjectId,
        response: &'a CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        KnownSubjectActiveProofMethodVerification,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = subject_id;
        let _ = response;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "known_subject_active_proof_completion",
            ))
        })
    }

    fn migrate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        let _ = tx;
        Box::pin(async { Ok(()) })
    }

    fn validate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        let _ = tx;
        Box::pin(async { Ok(()) })
    }

    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;
}

pub(crate) struct PostgresAuthMethodRegistry {
    plugins: BTreeMap<PostgresAuthMethodRegistryKey, Arc<dyn PostgresAuthMethodPlugin>>,
}

impl fmt::Debug for PostgresAuthMethodRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresAuthMethodRegistry")
            .field("registered_method_count", &self.plugins.len())
            .finish()
    }
}

impl PostgresAuthMethodRegistry {
    pub(crate) fn new(
        plugins: impl IntoIterator<Item = Arc<dyn PostgresAuthMethodPlugin>>,
    ) -> Result<Self, PostgresAuthMethodRegistryError> {
        let mut by_method = BTreeMap::new();
        for plugin in plugins {
            let method = plugin.method().clone();
            let contract = MethodAdapterContract::for_method(method.clone());
            if contract.ownership() != MethodAdapterOwnership::PluginOwned {
                return Err(PostgresAuthMethodRegistryError::CoreOwnedMethod {
                    family: method.family(),
                    method_label: method.method_label().to_owned(),
                });
            }
            let key = PostgresAuthMethodRegistryKey::from_method(&method);
            if by_method.insert(key, plugin).is_some() {
                return Err(PostgresAuthMethodRegistryError::DuplicateMethod {
                    family: method.family(),
                    method_label: method.method_label().to_owned(),
                });
            }
        }
        Ok(Self { plugins: by_method })
    }

    pub(crate) async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        for plugin in self.plugins.values() {
            plugin.migrate_schema(tx).await?;
        }
        Ok(())
    }

    pub(crate) async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        for plugin in self.plugins.values() {
            plugin.validate_schema(tx).await?;
        }
        Ok(())
    }

    pub(crate) fn build_out_of_band_issue(
        &self,
        request: &IssueOutOfBandChallengeRequest,
    ) -> Result<PostgresOutOfBandChallengeIssueBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&request.method)?
            .build_out_of_band_issue(request)
    }

    pub(crate) fn build_active_proof_method_challenge(
        &self,
        request: &IssueActiveProofMethodChallengeRequest,
        challenge: &ActiveProofMethodChallengeSeed,
    ) -> Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&request.method)?
            .build_active_proof_method_challenge(request, challenge)
    }

    pub(crate) fn build_out_of_band_resend_commit_work(
        &self,
        request: &ResendOutOfBandChallengeRequest,
        challenge: &ActiveProofChallengeRecord,
    ) -> Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(&challenge.proof)?
            .build_out_of_band_resend_commit_work(request, challenge)
    }

    pub(crate) fn build_out_of_band_completion_commit_work(
        &self,
        proof: &ProofSummary,
        challenge_id: &ActiveProofChallengeId,
        response: &CompleteOutOfBandChallengeResponse,
    ) -> Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(proof)?
            .build_out_of_band_completion_commit_work(challenge_id, response)
    }

    pub(crate) async fn resolve_out_of_band_subject_id<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        proof: &ProofSummary,
        challenge_id: &ActiveProofChallengeId,
        response: &CompleteOutOfBandChallengeResponse,
    ) -> Result<Option<SubjectId>, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(proof)?
            .resolve_out_of_band_subject_id(tx, challenge_id, response)
            .await
    }

    pub(crate) fn verify_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<ActiveProofMethodPreStateVerification, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(&challenge.proof)?
            .verify_active_proof_method_response_before_state_load(challenge, response)
    }

    pub(crate) async fn verify_active_proof_method_response_with_authoritative_state<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        context: ActiveProofMethodAuthoritativeVerificationContext<'_>,
        pre_state_verified: &VerifiedActiveProofMethodResponse,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<ActiveProofMethodAuthoritativeConfirmation, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(&context.challenge().proof)?
            .verify_active_proof_method_response_with_authoritative_state(
                tx,
                context,
                pre_state_verified,
                response,
            )
            .await
    }

    pub(crate) async fn verify_known_subject_active_proof_method_response<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        subject_id: &SubjectId,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&response.method)?
            .verify_known_subject_active_proof_method_response(tx, subject_id, response)
            .await
    }

    fn plugin_for_work(
        &self,
        work: &MethodCommitWork,
    ) -> Result<&dyn PostgresAuthMethodPlugin, PostgresAuthMethodCommitError> {
        let proof = work.proof();
        self.plugins
            .get(&PostgresAuthMethodRegistryKey::from_proof(proof))
            .map(Arc::as_ref)
            .ok_or_else(|| PostgresAuthMethodCommitError::UnregisteredMethod {
                family: proof.family(),
                method_label: proof.method_label().to_owned(),
            })
    }

    fn plugin_for_method(
        &self,
        method: &ProofMethodDeclaration,
    ) -> Result<&dyn PostgresAuthMethodPlugin, PostgresAuthMethodBuildError> {
        self.plugins
            .get(&PostgresAuthMethodRegistryKey::from_method(method))
            .map(Arc::as_ref)
            .ok_or_else(|| PostgresAuthMethodBuildError::UnregisteredMethod {
                family: method.family(),
                method_label: method.method_label().to_owned(),
            })
    }

    fn plugin_for_proof(
        &self,
        proof: &ProofSummary,
    ) -> Result<&dyn PostgresAuthMethodPlugin, PostgresAuthMethodBuildError> {
        self.plugins
            .get(&PostgresAuthMethodRegistryKey::from_proof(proof))
            .map(Arc::as_ref)
            .ok_or_else(|| PostgresAuthMethodBuildError::UnregisteredMethod {
                family: proof.family(),
                method_label: proof.method_label().to_owned(),
            })
    }
}

impl PostgresAuthMethodCommitExecutor for PostgresAuthMethodRegistry {
    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            self.plugin_for_work(work)?
                .enforce_precondition(tx, work, precondition)
                .await
        })
    }

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            self.plugin_for_work(work)?
                .apply_mutation(tx, work, mutation)
                .await
        })
    }

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            self.plugin_for_work(work)?
                .append_durable_effect_command(tx, work, command)
                .await
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedActiveProofMethodResponse {
    verified_proof: VerifiedActiveProof,
    method_commit_work: Vec<MethodCommitWork>,
}

impl VerifiedActiveProofMethodResponse {
    pub(crate) fn new(
        verified_proof: VerifiedActiveProof,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> Self {
        Self {
            verified_proof,
            method_commit_work,
        }
    }

    pub(crate) fn into_parts(self) -> (VerifiedActiveProof, Vec<MethodCommitWork>) {
        (self.verified_proof, self.method_commit_work)
    }

    pub(crate) fn verified_proof(&self) -> &VerifiedActiveProof {
        &self.verified_proof
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActiveProofMethodPreStateVerification {
    Accepted(VerifiedActiveProofMethodResponse),
    AcceptedNeedsAuthoritativeConfirmation(VerifiedActiveProofMethodResponse),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ActiveProofMethodAuthoritativeVerificationContext<'a> {
    challenge: &'a ActiveProofMethodChallengeMaterial,
    attempt_record: &'a ActiveProofAttemptRecord,
    challenge_record: &'a ActiveProofChallengeRecord,
}

impl<'a> ActiveProofMethodAuthoritativeVerificationContext<'a> {
    pub(crate) fn new(
        challenge: &'a ActiveProofMethodChallengeMaterial,
        attempt_record: &'a ActiveProofAttemptRecord,
        challenge_record: &'a ActiveProofChallengeRecord,
    ) -> Self {
        Self {
            challenge,
            attempt_record,
            challenge_record,
        }
    }

    pub(crate) fn challenge(&self) -> &'a ActiveProofMethodChallengeMaterial {
        self.challenge
    }

    pub(crate) fn attempt_record(&self) -> &'a ActiveProofAttemptRecord {
        self.attempt_record
    }

    pub(crate) fn challenge_record(&self) -> &'a ActiveProofChallengeRecord {
        self.challenge_record
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KnownSubjectActiveProofMethodVerification {
    Accepted(VerifiedActiveProofMethodResponse),
    Rejected,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ActiveProofMethodAuthoritativeConfirmation {
    method_commit_work: Vec<MethodCommitWork>,
}

impl ActiveProofMethodAuthoritativeConfirmation {
    pub(crate) fn new(method_commit_work: Vec<MethodCommitWork>) -> Self {
        Self { method_commit_work }
    }

    pub(crate) fn into_method_commit_work(self) -> Vec<MethodCommitWork> {
        self.method_commit_work
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveProofMethodChallengeBuild {
    presentation: ActiveProofMethodChallengePresentation,
    state: ActiveProofMethodChallengeState,
    method_commit_work: Vec<MethodCommitWork>,
}

impl ActiveProofMethodChallengeBuild {
    pub(crate) fn new(
        presentation: ActiveProofMethodChallengePresentation,
        state: ActiveProofMethodChallengeState,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> Self {
        Self {
            presentation,
            state,
            method_commit_work,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ActiveProofMethodChallengePresentation,
        ActiveProofMethodChallengeState,
        Vec<MethodCommitWork>,
    ) {
        (self.presentation, self.state, self.method_commit_work)
    }
}

pub(crate) struct PostgresOutOfBandChallengeIssueBuild {
    response_secret: ActiveProofChallengeResponseSecret,
    method_commit_work: Vec<MethodCommitWork>,
}

impl PostgresOutOfBandChallengeIssueBuild {
    pub(crate) fn new(
        response_secret: ActiveProofChallengeResponseSecret,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> Self {
        Self {
            response_secret,
            method_commit_work,
        }
    }

    pub(crate) fn into_parts(self) -> (ActiveProofChallengeResponseSecret, Vec<MethodCommitWork>) {
        (self.response_secret, self.method_commit_work)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PostgresAuthMethodRegistryKey {
    proof_family_wire_id: u8,
    method_label: String,
}

impl PostgresAuthMethodRegistryKey {
    fn from_method(method: &ProofMethodDeclaration) -> Self {
        Self {
            proof_family_wire_id: proof_family_wire_id(method.family()),
            method_label: method.method_label().to_owned(),
        }
    }

    fn from_proof(proof: &ProofSummary) -> Self {
        Self {
            proof_family_wire_id: proof_family_wire_id(proof.family()),
            method_label: proof.method_label().to_owned(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum PostgresAuthMethodRegistryError {
    CoreOwnedMethod {
        family: ProofFamily,
        method_label: String,
    },
    DuplicateMethod {
        family: ProofFamily,
        method_label: String,
    },
}

impl fmt::Display for PostgresAuthMethodRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoreOwnedMethod {
                family,
                method_label,
            } => write!(
                f,
                "cannot register core-owned auth method {family:?}/{method_label}"
            ),
            Self::DuplicateMethod {
                family,
                method_label,
            } => write!(
                f,
                "duplicate auth method registration for {family:?}/{method_label}"
            ),
        }
    }
}

impl std::error::Error for PostgresAuthMethodRegistryError {}

#[derive(Debug)]
pub(crate) enum PostgresAuthMethodBuildError {
    UnregisteredMethod {
        family: ProofFamily,
        method_label: String,
    },
    UnsupportedOperation {
        family: ProofFamily,
        method_label: String,
        operation: &'static str,
    },
    PluginRejected {
        family: ProofFamily,
        method_label: String,
        operation: &'static str,
        reason: String,
    },
}

impl PostgresAuthMethodBuildError {
    fn unsupported(method: &ProofMethodDeclaration, operation: &'static str) -> Self {
        Self::UnsupportedOperation {
            family: method.family(),
            method_label: method.method_label().to_owned(),
            operation,
        }
    }

    pub(crate) fn plugin_rejected(
        method: &ProofMethodDeclaration,
        operation: &'static str,
        error: impl fmt::Display,
    ) -> Self {
        Self::PluginRejected {
            family: method.family(),
            method_label: method.method_label().to_owned(),
            operation,
            reason: error.to_string(),
        }
    }
}

impl fmt::Display for PostgresAuthMethodBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredMethod {
                family,
                method_label,
            } => write!(f, "auth method {family:?}/{method_label} is not registered"),
            Self::UnsupportedOperation {
                family,
                method_label,
                operation,
            } => write!(
                f,
                "auth method {family:?}/{method_label} does not support {operation}"
            ),
            Self::PluginRejected {
                family,
                method_label,
                operation,
                reason,
            } => write!(
                f,
                "auth method {family:?}/{method_label} rejected {operation}: {reason}"
            ),
        }
    }
}

impl std::error::Error for PostgresAuthMethodBuildError {}
