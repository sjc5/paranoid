use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;

use crate::db::{Tx, WritePool, WriteTx, queue};

use super::postgres_durable_effect_queue::{
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::postgres_store::{PostgresAuthMethodCommitError, PostgresAuthMethodCommitExecutor};
use super::prelude::*;

pub(crate) trait PostgresAuthMethodPlugin: Send + Sync {
    fn method(&self) -> &ProofMethodDeclaration;

    fn mounted_route_capabilities(&self) -> PostgresAuthMethodMountedRouteCapabilities {
        PostgresAuthMethodMountedRouteCapabilities::empty()
    }

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

    fn derive_out_of_band_challenge_start(
        &self,
        request: &PostgresOutOfBandChallengeStartBuildRequest<'_>,
    ) -> Result<PostgresOutOfBandChallengeStartBuild, PostgresAuthMethodBuildError> {
        let _ = request;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "out_of_band_challenge_start_derivation",
        ))
    }

    fn build_active_proof_method_challenge<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: &'a IssueActiveProofMethodChallengeRequest,
        challenge: &'a ActiveProofMethodChallengeSeed,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError>,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = request;
        let _ = challenge;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "active_proof_method_challenge_issue",
            ))
        })
    }

    fn build_challenge_bound_known_subject_active_proof_method_challenge<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: &'a IssueActiveProofMethodChallengeRequest,
        subject_id: &'a SubjectId,
        challenge: &'a ActiveProofMethodChallengeSeed,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError>,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = request;
        let _ = subject_id;
        let _ = challenge;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "challenge_bound_known_subject_active_proof_method_challenge_issue",
            ))
        })
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

    fn resolve_out_of_band_proof<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        challenge_id: &'a ActiveProofChallengeId,
        response: &'a CompleteOutOfBandChallengeResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<PostgresOutOfBandProofResolution, PostgresAuthMethodBuildError>,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = challenge_id;
        let _ = response;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "out_of_band_proof_resolution",
            ))
        })
    }

    fn resolve_out_of_band_identifier_change_candidate_source<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        challenge_id: &'a ActiveProofChallengeId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<VerifiedProofSource, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = challenge_id;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "out_of_band_identifier_change_candidate_source",
            ))
        })
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

    fn verify_known_subject_active_proof_method_response_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresAuthMethodBuildError> {
        let _ = continuation;
        let _ = response;
        Ok(())
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

    fn resolve_recovery_credential_subject_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<SubjectId, PostgresAuthMethodBuildError> {
        let _ = continuation;
        let _ = response;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "recovery_credential_active_proof_completion_pre_state",
        ))
    }

    fn verify_recovery_credential_active_proof_method_response<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        candidate_subject_id: &'a SubjectId,
        response: &'a CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        RecoveryCredentialActiveProofMethodVerification,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = candidate_subject_id;
        let _ = response;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "recovery_credential_active_proof_completion",
            ))
        })
    }

    fn verify_challenge_bound_known_subject_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresAuthMethodBuildError> {
        let _ = challenge;
        let _ = response;
        Err(PostgresAuthMethodBuildError::unsupported(
            self.method(),
            "challenge_bound_known_subject_active_proof_completion",
        ))
    }

    fn verify_challenge_bound_known_subject_active_proof_method_response<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        subject_id: &'a SubjectId,
        challenge: &'a ActiveProofMethodChallengeMaterial,
        response: &'a CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
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
        let _ = challenge;
        let _ = response;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "challenge_bound_known_subject_active_proof_completion",
            ))
        })
    }

    fn build_credential_reset_commit_work<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: CredentialResetMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        let _ = tx;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                match request.authority {
                    CredentialResetMethodWorkAuthority::Immediate { .. } => {
                        "authenticated_credential_reset"
                    }
                    CredentialResetMethodWorkAuthority::MaturePendingAction { .. } => {
                        "mature_pending_credential_reset"
                    }
                },
            ))
        })
    }

    fn build_credential_creation_commit_work<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: CredentialCreationMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<CredentialMethodWorkBuild, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        let _ = tx;
        let _ = request;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                "authenticated_credential_addition",
            ))
        })
    }

    fn build_credential_lifecycle_commit_work<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: CredentialLifecycleMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<CredentialMethodWorkBuild, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        let _ = tx;
        Box::pin(async move {
            Err(PostgresAuthMethodBuildError::unsupported(
                self.method(),
                unsupported_credential_lifecycle_operation_label(&request),
            ))
        })
    }

    fn migrate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn validate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

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

    fn register_durable_effect_queue_handlers(
        &self,
        task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError>;

    fn enqueue_available_durable_effects_to_queue_in_current_transaction<'a, 'tx>(
        &'a self,
        tx: &'a mut WriteTx<'tx>,
        queue_store: &'a queue::Store,
        limit: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresAuthDurableEffectQueueDispatchSummary,
                        PostgresAuthDurableEffectQueueDispatchError,
                    >,
                > + Send
                + 'a,
        >,
    >;
}

pub(crate) fn register_no_queue_handlers_for_method_durable_effects(
    task_registry: &mut queue::TaskRegistry,
) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError> {
    let _ = task_registry;
    Ok(())
}

pub(crate) fn enqueue_no_method_durable_effects_to_queue_in_current_transaction<'a, 'tx>(
    tx: &'a mut WriteTx<'tx>,
    queue_store: &'a queue::Store,
    limit: NonZeroU32,
    enqueued_at: UnixSeconds,
) -> Pin<
    Box<
        dyn Future<
                Output = Result<
                    PostgresAuthDurableEffectQueueDispatchSummary,
                    PostgresAuthDurableEffectQueueDispatchError,
                >,
            > + Send
            + 'a,
    >,
> {
    let _ = tx;
    let _ = queue_store;
    let _ = limit;
    let _ = enqueued_at;
    Box::pin(async { Ok(PostgresAuthDurableEffectQueueDispatchSummary::default()) })
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

    pub(crate) fn register_durable_effect_queue_handlers(
        &self,
        task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError> {
        for plugin in self.plugins.values() {
            plugin.register_durable_effect_queue_handlers(task_registry)?;
        }
        Ok(())
    }

    pub(crate) fn contains_method(&self, method: &ProofMethodDeclaration) -> bool {
        self.plugins
            .contains_key(&PostgresAuthMethodRegistryKey::from_method(method))
    }

    pub(crate) fn mounted_route_capabilities_for_method(
        &self,
        method: &ProofMethodDeclaration,
    ) -> Option<PostgresAuthMethodMountedRouteCapabilities> {
        self.plugins
            .get(&PostgresAuthMethodRegistryKey::from_method(method))
            .map(|plugin| plugin.mounted_route_capabilities())
    }

    pub(crate) fn any_method_supports_mounted_route_capability(
        &self,
        predicate: impl Fn(PostgresAuthMethodMountedRouteCapabilities) -> bool,
    ) -> bool {
        self.plugins
            .values()
            .any(|plugin| predicate(plugin.mounted_route_capabilities()))
    }

    pub(crate) async fn enqueue_available_method_durable_effects_to_queue(
        &self,
        pool: &WritePool,
        queue_store: &queue::Store,
        limit_per_method: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Result<
        PostgresAuthDurableEffectQueueDispatchSummary,
        PostgresAuthDurableEffectQueueDispatchError,
    > {
        const METHOD_DURABLE_EFFECT_DISPATCH_OPERATION: &str =
            "auth_core.method_durable_effect_queue.dispatch";

        let mut tx = pool.begin_transaction().await?;
        let result = self
            .enqueue_available_method_durable_effects_to_queue_in_current_transaction(
                &mut tx,
                queue_store,
                limit_per_method,
                enqueued_at,
            )
            .await;

        match result {
            Ok(summary) => {
                tx.commit().await?;
                Ok(summary)
            }
            Err(error) => {
                let rollback_result = tx.rollback().await;
                if let Err(rollback_error) = rollback_result {
                    return Err(
                        PostgresAuthDurableEffectQueueDispatchError::DatabaseOperationRollbackFailed {
                            operation: METHOD_DURABLE_EFFECT_DISPATCH_OPERATION,
                            operation_error: Box::new(error),
                            rollback_error: Box::new(rollback_error),
                        },
                    );
                }
                Err(error)
            }
        }
    }

    pub(crate) async fn enqueue_available_method_durable_effects_to_queue_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        queue_store: &queue::Store,
        limit_per_method: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Result<
        PostgresAuthDurableEffectQueueDispatchSummary,
        PostgresAuthDurableEffectQueueDispatchError,
    > {
        let mut aggregate = PostgresAuthDurableEffectQueueDispatchSummary::default();
        for plugin in self.plugins.values() {
            let summary = plugin
                .enqueue_available_durable_effects_to_queue_in_current_transaction(
                    tx,
                    queue_store,
                    limit_per_method,
                    enqueued_at,
                )
                .await?;
            aggregate.add(summary);
        }
        Ok(aggregate)
    }

    pub(crate) fn build_out_of_band_issue(
        &self,
        request: &IssueOutOfBandChallengeRequest,
    ) -> Result<PostgresOutOfBandChallengeIssueBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&request.method)?
            .build_out_of_band_issue(request)
    }

    pub(crate) fn derive_out_of_band_challenge_start(
        &self,
        method: &ProofMethodDeclaration,
        request: &PostgresOutOfBandChallengeStartBuildRequest<'_>,
    ) -> Result<PostgresOutOfBandChallengeStartBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_method(method)?
            .derive_out_of_band_challenge_start(request)
    }

    pub(crate) async fn build_active_proof_method_challenge<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        request: &IssueActiveProofMethodChallengeRequest,
        challenge: &ActiveProofMethodChallengeSeed,
    ) -> Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&request.method)?
            .build_active_proof_method_challenge(tx, request, challenge)
            .await
    }

    pub(crate) async fn build_challenge_bound_known_subject_active_proof_method_challenge<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        request: &IssueActiveProofMethodChallengeRequest,
        subject_id: &SubjectId,
        challenge: &ActiveProofMethodChallengeSeed,
    ) -> Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&request.method)?
            .build_challenge_bound_known_subject_active_proof_method_challenge(
                tx, request, subject_id, challenge,
            )
            .await
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

    pub(crate) async fn resolve_out_of_band_proof<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        proof: &ProofSummary,
        challenge_id: &ActiveProofChallengeId,
        response: &CompleteOutOfBandChallengeResponse,
    ) -> Result<PostgresOutOfBandProofResolution, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(proof)?
            .resolve_out_of_band_proof(tx, challenge_id, response)
            .await
    }

    pub(crate) async fn resolve_out_of_band_identifier_change_candidate_source<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        proof: &ProofSummary,
        challenge_id: &ActiveProofChallengeId,
    ) -> Result<VerifiedProofSource, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(proof)?
            .resolve_out_of_band_identifier_change_candidate_source(tx, challenge_id)
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

    pub(crate) fn resolve_recovery_credential_subject_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<SubjectId, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&response.method)?
            .resolve_recovery_credential_subject_before_state_load(continuation, response)
    }

    pub(crate) async fn verify_recovery_credential_active_proof_method_response<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        candidate_subject_id: &SubjectId,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<RecoveryCredentialActiveProofMethodVerification, PostgresAuthMethodBuildError> {
        self.plugin_for_method(&response.method)?
            .verify_recovery_credential_active_proof_method_response(
                tx,
                candidate_subject_id,
                response,
            )
            .await
    }

    pub(crate) fn verify_challenge_bound_known_subject_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresAuthMethodBuildError> {
        self.plugin_for_proof(&challenge.proof)?
            .verify_challenge_bound_known_subject_active_proof_method_response_before_state_load(
                challenge, response,
            )
    }

    pub(crate) async fn verify_challenge_bound_known_subject_active_proof_method_response<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        subject_id: &SubjectId,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Result<KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError> {
        self.plugin_for_proof(&challenge.proof)?
            .verify_challenge_bound_known_subject_active_proof_method_response(
                tx, subject_id, challenge, response,
            )
            .await
    }

    pub(crate) fn verify_known_subject_active_proof_method_response_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresAuthMethodBuildError> {
        self.plugin_for_method(&response.method)?
            .verify_known_subject_active_proof_method_response_before_state_load(
                continuation,
                response,
            )
    }

    pub(crate) async fn build_credential_reset_commit_work<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        request: CredentialResetMethodWorkBuildRequest<'_>,
    ) -> Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError> {
        self.plugin_for_credential_target(request.target_credential)?
            .build_credential_reset_commit_work(tx, request)
            .await
    }

    pub(crate) async fn build_credential_creation_commit_work<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        request: CredentialCreationMethodWorkBuildRequest<'_>,
    ) -> Result<CredentialMethodWorkBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_credential_target(request.new_credential)?
            .build_credential_creation_commit_work(tx, request)
            .await
    }

    pub(crate) async fn build_credential_lifecycle_commit_work<'tx>(
        &self,
        tx: &mut Tx<'tx>,
        request: CredentialLifecycleMethodWorkBuildRequest<'_>,
    ) -> Result<CredentialMethodWorkBuild, PostgresAuthMethodBuildError> {
        self.plugin_for_credential_target(request.target_credential)?
            .build_credential_lifecycle_commit_work(tx, request)
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

    fn plugin_for_credential_target(
        &self,
        target: &CredentialInstanceMetadata,
    ) -> Result<&dyn PostgresAuthMethodPlugin, PostgresAuthMethodBuildError> {
        let key = PostgresAuthMethodRegistryKey {
            proof_family_wire_id: proof_family_wire_id(target.proof_family()),
            method_label: target.method_label().to_owned(),
        };
        self.plugins.get(&key).map(Arc::as_ref).ok_or_else(|| {
            PostgresAuthMethodBuildError::UnregisteredMethod {
                family: target.proof_family(),
                method_label: target.method_label().to_owned(),
            }
        })
    }
}

#[derive(Debug)]
pub(crate) enum PostgresAuthMethodDurableEffectQueueRegistrationError {
    Queue(queue::Error),
}

impl fmt::Display for PostgresAuthMethodDurableEffectQueueRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queue(error) => write!(
                f,
                "auth method durable-effect queue registration failed: {error}"
            ),
        }
    }
}

impl std::error::Error for PostgresAuthMethodDurableEffectQueueRegistrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Queue(error) => Some(error),
        }
    }
}

impl From<queue::Error> for PostgresAuthMethodDurableEffectQueueRegistrationError {
    fn from(error: queue::Error) -> Self {
        Self::Queue(error)
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
    ) -> Result<Self, Error> {
        if active_method_proof_family_requires_source(verified_proof.proof().family())
            && verified_proof.source().is_none()
        {
            return Err(Error::ProofFamilyRequiresVerifiedProofSource {
                family: verified_proof.proof().family(),
            });
        }
        Ok(Self {
            verified_proof,
            method_commit_work,
        })
    }

    pub(crate) fn into_parts(self) -> (VerifiedActiveProof, Vec<MethodCommitWork>) {
        (self.verified_proof, self.method_commit_work)
    }

    pub(crate) fn verified_proof(&self) -> &VerifiedActiveProof {
        &self.verified_proof
    }
}

fn active_method_proof_family_requires_source(family: ProofFamily) -> bool {
    matches!(
        family,
        ProofFamily::MessageSignature
            | ProofFamily::SharedSecretOtp
            | ProofFamily::OriginBoundPublicKey
            | ProofFamily::FederatedIdentityAssertion
            | ProofFamily::RecoveryCode
    )
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryCredentialActiveProofMethodVerification {
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct CredentialResetMethodWorkBuildRequest<'a> {
    pub(crate) now: UnixSeconds,
    pub(crate) target_credential: &'a CredentialInstanceMetadata,
    pub(crate) method_payload: &'a CredentialResetMethodPayload,
    pub(crate) authority: CredentialResetMethodWorkAuthority<'a>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CredentialResetMethodWorkAuthority<'a> {
    Immediate {
        lifecycle_context: &'a CredentialLifecycleActionContext,
    },
    MaturePendingAction {
        pending_action: &'a PendingCredentialLifecycleActionRecord,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CredentialCreationMethodWorkBuildRequest<'a> {
    pub(crate) now: UnixSeconds,
    pub(crate) new_credential: &'a CredentialInstanceMetadata,
    pub(crate) method_payload: &'a CredentialCreationMethodPayload,
}

#[derive(Debug)]
pub(crate) struct CredentialMethodWorkBuild {
    method_commit_work: Vec<MethodCommitWork>,
    post_commit_response_material: PostCommitMethodResponseMaterial,
}

impl CredentialMethodWorkBuild {
    pub(crate) fn from_method_commit_work(method_commit_work: Vec<MethodCommitWork>) -> Self {
        Self {
            method_commit_work,
            post_commit_response_material: PostCommitMethodResponseMaterial::empty(),
        }
    }

    pub(crate) fn new(
        method_commit_work: Vec<MethodCommitWork>,
        post_commit_response_material: PostCommitMethodResponseMaterial,
    ) -> Self {
        Self {
            method_commit_work,
            post_commit_response_material,
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<MethodCommitWork>, PostCommitMethodResponseMaterial) {
        (self.method_commit_work, self.post_commit_response_material)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CredentialLifecycleMethodWorkBuildRequest<'a> {
    pub(crate) now: UnixSeconds,
    pub(crate) target_credential: &'a CredentialInstanceMetadata,
    pub(crate) action: CredentialLifecycleAction,
    pub(crate) replacement_successor: Option<&'a CredentialReplacementSuccessor>,
    pub(crate) method_payload: &'a CredentialLifecycleMethodPayload,
    pub(crate) authority: CredentialLifecycleMethodWorkAuthority<'a>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CredentialLifecycleMethodWorkAuthority<'a> {
    ImmediateReplacement {
        lifecycle_context: &'a CredentialLifecycleActionContext,
    },
    ImmediateRotation {
        lifecycle_context: &'a CredentialLifecycleActionContext,
    },
    ImmediateRegeneration {
        lifecycle_context: &'a CredentialLifecycleActionContext,
    },
    MaturePendingAction {
        pending_action: &'a PendingCredentialLifecycleActionRecord,
    },
}

fn unsupported_credential_lifecycle_operation_label(
    request: &CredentialLifecycleMethodWorkBuildRequest<'_>,
) -> &'static str {
    match (request.action, request.authority) {
        (
            CredentialLifecycleAction::Replace,
            CredentialLifecycleMethodWorkAuthority::ImmediateReplacement { .. },
        ) => "authenticated_credential_replacement",
        (
            CredentialLifecycleAction::Rotate,
            CredentialLifecycleMethodWorkAuthority::ImmediateRotation { .. },
        ) => "authenticated_credential_rotation",
        (
            CredentialLifecycleAction::Regenerate,
            CredentialLifecycleMethodWorkAuthority::ImmediateRegeneration { .. },
        ) => "authenticated_credential_regeneration",
        (
            CredentialLifecycleAction::Replace,
            CredentialLifecycleMethodWorkAuthority::MaturePendingAction { .. },
        ) => "mature_pending_credential_replacement",
        (
            CredentialLifecycleAction::Regenerate,
            CredentialLifecycleMethodWorkAuthority::MaturePendingAction { .. },
        ) => "mature_pending_credential_regeneration",
        _ => "credential_lifecycle_action",
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PostgresAuthMethodMountedRouteCapabilities {
    out_of_band_full_authentication: bool,
    no_session_recovery_credential: bool,
    credential_creation: bool,
    credential_reset: bool,
    credential_replacement: bool,
    credential_regeneration: bool,
    credential_rotation: bool,
    out_of_band_identifier_change: bool,
}

impl PostgresAuthMethodMountedRouteCapabilities {
    pub(crate) const fn empty() -> Self {
        Self {
            out_of_band_full_authentication: false,
            no_session_recovery_credential: false,
            credential_creation: false,
            credential_reset: false,
            credential_replacement: false,
            credential_regeneration: false,
            credential_rotation: false,
            out_of_band_identifier_change: false,
        }
    }

    pub(crate) const fn with_out_of_band_full_authentication(mut self) -> Self {
        self.out_of_band_full_authentication = true;
        self
    }

    pub(crate) const fn with_no_session_recovery_credential(mut self) -> Self {
        self.no_session_recovery_credential = true;
        self
    }

    pub(crate) const fn with_credential_creation(mut self) -> Self {
        self.credential_creation = true;
        self
    }

    pub(crate) const fn with_credential_reset(mut self) -> Self {
        self.credential_reset = true;
        self
    }

    pub(crate) const fn with_credential_replacement(mut self) -> Self {
        self.credential_replacement = true;
        self
    }

    pub(crate) const fn with_credential_regeneration(mut self) -> Self {
        self.credential_regeneration = true;
        self
    }

    pub(crate) const fn with_credential_rotation(mut self) -> Self {
        self.credential_rotation = true;
        self
    }

    pub(crate) const fn with_out_of_band_identifier_change(mut self) -> Self {
        self.out_of_band_identifier_change = true;
        self
    }

    pub(crate) const fn out_of_band_full_authentication(self) -> bool {
        self.out_of_band_full_authentication
    }

    pub(crate) const fn no_session_recovery_credential(self) -> bool {
        self.no_session_recovery_credential
    }

    pub(crate) const fn credential_creation(self) -> bool {
        self.credential_creation
    }

    pub(crate) const fn credential_reset(self) -> bool {
        self.credential_reset
    }

    pub(crate) const fn credential_replacement(self) -> bool {
        self.credential_replacement
    }

    pub(crate) const fn credential_regeneration(self) -> bool {
        self.credential_regeneration
    }

    pub(crate) const fn credential_rotation(self) -> bool {
        self.credential_rotation
    }

    pub(crate) const fn out_of_band_identifier_change(self) -> bool {
        self.out_of_band_identifier_change
    }
}

pub(crate) struct PostgresOutOfBandChallengeIssueBuild {
    response_secret: ActiveProofChallengeResponseSecret,
    method_commit_work: Vec<MethodCommitWork>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PostgresOutOfBandChallengeStartBuildRequest<'a> {
    pub(crate) now: UnixSeconds,
    pub(crate) proof_use: ProofUse,
    pub(crate) attempt_id: &'a ActiveProofAttemptId,
    pub(crate) challenge_id: &'a ActiveProofChallengeId,
    pub(crate) method_payload: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresOutOfBandChallengeStartBuild {
    challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    recipient_handle: String,
    idempotency_key: String,
}

impl PostgresOutOfBandChallengeStartBuild {
    pub(crate) fn new(
        challenge_dedupe_key: OutOfBandChallengeDedupeKey,
        recipient_handle: String,
        idempotency_key: String,
    ) -> Result<Self, Error> {
        if recipient_handle.is_empty() {
            return Err(Error::EmptyOutOfBandRecipientHandle);
        }
        validate_auth_string_not_too_long(
            "out-of-band recipient handle",
            &recipient_handle,
            OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
        )?;
        if idempotency_key.is_empty() {
            return Err(Error::EmptyOutOfBandDeliveryIdempotencyKey);
        }
        validate_auth_identifier_string(
            "out-of-band delivery idempotency key",
            &idempotency_key,
            DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
        )?;
        Ok(Self {
            challenge_dedupe_key,
            recipient_handle,
            idempotency_key,
        })
    }

    pub(crate) fn into_issue_request(
        self,
        now: UnixSeconds,
        attempt_id: ActiveProofAttemptId,
        challenge_id: ActiveProofChallengeId,
        method: ProofMethodDeclaration,
        replaceable_created_at_or_before: Option<UnixSeconds>,
    ) -> IssueOutOfBandChallengeRequest {
        IssueOutOfBandChallengeRequest {
            now,
            attempt_id,
            challenge_id,
            method,
            challenge_dedupe_key: self.challenge_dedupe_key,
            replaceable_created_at_or_before,
            recipient_handle: self.recipient_handle,
            idempotency_key: self.idempotency_key,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresOutOfBandProofResolution {
    subject_id: Option<SubjectId>,
    source: Option<VerifiedProofSource>,
}

impl PostgresOutOfBandProofResolution {
    pub(crate) fn new(subject_id: Option<SubjectId>, source: Option<VerifiedProofSource>) -> Self {
        Self { subject_id, source }
    }

    pub(crate) fn into_verified_proof(
        self,
        proof: ProofSummary,
    ) -> Result<VerifiedActiveProof, Error> {
        match self.source {
            Some(source) => {
                VerifiedActiveProof::from_summary_with_source(proof, self.subject_id, source)
            }
            None => VerifiedActiveProof::from_summary(proof, self.subject_id),
        }
    }
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
