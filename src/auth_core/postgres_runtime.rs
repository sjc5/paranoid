use std::cmp::min;
use std::fmt;
use std::sync::Arc;

use http::{HeaderMap, Request};

use crate::db::{DbError, Pool, Tx};

use super::postgres_method_runtime::{
    ActiveProofMethodAuthoritativeVerificationContext, ActiveProofMethodPreStateVerification,
    CredentialCreationMethodWorkBuildRequest, CredentialLifecycleMethodWorkAuthority,
    CredentialLifecycleMethodWorkBuildRequest, CredentialResetMethodWorkAuthority,
    CredentialResetMethodWorkBuildRequest, KnownSubjectActiveProofMethodVerification,
    PostgresAuthMethodBuildError, PostgresAuthMethodRegistry,
    PostgresOutOfBandChallengeStartBuildRequest, RecoveryCredentialActiveProofMethodVerification,
    VerifiedActiveProofMethodResponse,
};
use super::postgres_store::{
    PostgresAuthStore, PostgresAuthStoreConfig, PostgresAuthStoreError,
    finish_auth_store_transaction,
};
use super::prelude::*;

mod active_proof_challenge_runtime;
mod active_proof_response_runtime;
mod admin_support_runtime;
mod credential_read_and_addition_runtime;
mod credential_regeneration_rotation_runtime;
mod credential_replacement_removal_runtime;
mod credential_reset_runtime;
mod pending_credential_lifecycle_runtime;
mod request_session_device_runtime;
mod subject_lifecycle_runtime;

pub(crate) struct PostgresAuthWebRuntime {
    pub(super) runtime: AuthWebRuntime,
    pub(super) pool: Pool,
    pub(super) store: PostgresAuthStore,
    pub(super) weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
}

impl PostgresAuthWebRuntime {
    pub(crate) fn new(
        runtime: AuthWebRuntime,
        pool: Pool,
        store: PostgresAuthStore,
        weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
    ) -> Self {
        Self {
            runtime,
            pool,
            store,
            weak_proof_gate_verifier,
        }
    }

    pub(crate) fn store_config(&self) -> &PostgresAuthStoreConfig {
        self.store.config()
    }

    pub(crate) fn core_config(&self) -> &Config {
        self.runtime.config()
    }

    fn out_of_band_challenge_replaceable_created_at_or_before(
        &self,
        now: UnixSeconds,
    ) -> Option<UnixSeconds> {
        now.checked_sub_duration(
            self.runtime
                .config()
                .out_of_band_challenge_replacement_cooldown,
        )
    }

    pub(crate) fn method_registry_arc(&self) -> Option<Arc<PostgresAuthMethodRegistry>> {
        self.store.method_registry_arc()
    }

    pub(crate) fn verify_csrf_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(), AuthPostgresWebRuntimeExecutionError> {
        self.runtime
            .web_transport()
            .verify_csrf_request(request)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)
    }

    pub(crate) fn issue_csrf_token_cookie_if_needed_for_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Option<AuthSetCookieHeader>, AuthPostgresWebRuntimeExecutionError> {
        self.runtime
            .web_transport()
            .issue_csrf_token_cookie_if_needed_for_request(request)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)
    }

    async fn commit_runtime_owned_prepared_command_inside_open_transaction(
        &self,
        operation: &'static str,
        now: UnixSeconds,
        tx: Tx<'_>,
        prepared: PreparedCommandExecution,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        if prepared_storage_boundary_contract.boundary_before_reduce()
            != StorageBoundaryBeforeReduce::None
        {
            return Err(rollback_after_core_error(
                "auth_core.runtime.prepare",
                tx,
                Error::LoadedStateContradiction(
                    "runtime-owned command unexpectedly required additional loaded state",
                ),
            )
            .await);
        }
        let loaded = loaded_state_from_presented_cookies(prepared.presented_cookies());
        let planned = match prepared.reduce_loaded_state(self.runtime.config(), &loaded) {
            Ok(planned) => planned,
            Err(error) => {
                return Err(rollback_after_core_error("auth_core.runtime.reduce", tx, error).await);
            }
        };
        let planned_storage_boundary_contract =
            match PlannedStorageBoundaryContract::for_planned_execution(
                &prepared_storage_boundary_contract,
                &planned,
            ) {
                Ok(contract) => contract,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.plan_storage_boundary",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        if planned_storage_boundary_contract.atomic_commit_boundary()
            != AtomicCommitBoundary::CommitOnlyBoundary
        {
            return Err(rollback_after_core_error(
                "auth_core.runtime.plan_storage_boundary",
                tx,
                Error::LoadedStateContradiction(
                    "runtime-owned command unexpectedly avoided commit-only boundary",
                ),
            )
            .await);
        }
        self.commit_planned_inside_transaction(
            operation,
            now,
            tx,
            planned,
            planned_storage_boundary_contract,
            presented_cookie_secrets,
        )
        .await
    }

    async fn commit_start_active_proof_attempt_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        presented_cookies: PresentedAuthCookies,
        command: StartActiveProofAttempt,
    ) -> Result<AuthSetCookieHeaders, AuthPostgresWebRuntimeExecutionError> {
        let now = command.now;
        let prepared = PreparedCommandExecution::prepare(
            self.runtime.config(),
            Command::StartActiveProofAttempt(command),
            presented_cookies,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        if prepared_storage_boundary_contract.boundary_before_reduce()
            != StorageBoundaryBeforeReduce::None
        {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::LoadedStateContradiction(
                    "active-proof attempt start unexpectedly required state load",
                ),
            ));
        }
        let loaded = loaded_state_from_presented_cookies(prepared.presented_cookies());
        let planned = prepared
            .reduce_loaded_state(self.runtime.config(), &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let planned_storage_boundary_contract =
            PlannedStorageBoundaryContract::for_planned_execution(
                &prepared_storage_boundary_contract,
                &planned,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        if planned_storage_boundary_contract.atomic_commit_boundary()
            != AtomicCommitBoundary::CommitOnlyBoundary
        {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::LoadedStateContradiction(
                    "active-proof attempt start unexpectedly required loaded-state commit boundary",
                ),
            ));
        }
        let request = AtomicCommitRequest::for_atomic_work_with_storage_boundary(
            planned.atomic_commit_work(),
            planned_storage_boundary_contract,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let materialized = self
            .store
            .commit_atomic_work_in_current_transaction(tx, request)
            .await
            .map_err(AuthPostgresWebRuntimeExecutionError::store)?;
        let materialized_fresh_credential_secrets =
            MaterializedFreshCredentialSecrets::for_atomic_work(
                planned.atomic_commit_work(),
                materialized,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let commit_success = AtomicCommitSuccess::for_atomic_work(
            planned.atomic_commit_work(),
            materialized_fresh_credential_secrets,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let completed = planned
            .finish_after_successful_atomic_commit(commit_success)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let materialized = completed
            .materialize_response_effects(PresentedAuthCookieSecrets::default())
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let (_, response_effects) = materialized.into_parts();
        self.runtime
            .web_transport()
            .render_set_cookie_headers(now, response_effects)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)
    }

    async fn load_verified_active_proof_subject_revocation_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        now: UnixSeconds,
        presented_cookies: &PresentedAuthCookies,
        presented_cookie_secrets: &PresentedAuthCookieSecrets,
        loaded: &mut LoadedState,
        subject_id: &SubjectId,
    ) -> Result<(), AuthPostgresWebRuntimeExecutionError> {
        let loaded_state_contract =
            CommandLoadedStateContract::for_verified_active_proof_subject_revocation(
                self.runtime.config(),
                subject_id,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let extra_loaded = match self
            .store
            .load_state_in_current_transaction(
                tx,
                AuthLoadStateRequest::new(
                    now,
                    presented_cookies,
                    presented_cookie_secrets,
                    &loaded_state_contract,
                    &prepared_storage_boundary_contract,
                ),
            )
            .await
        {
            Ok(extra_loaded) => extra_loaded,
            Err(error) => return Err(AuthPostgresWebRuntimeExecutionError::store(error)),
        };
        loaded_state_contract
            .validate_loaded_state(&extra_loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        for revocation in extra_loaded.subject_revocations.loaded_subjects() {
            loaded
                .subject_revocations
                .push_loaded(
                    revocation.subject_id().clone(),
                    revocation.revocation().cloned(),
                )
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        }
        Ok(())
    }

    async fn execute_decoded(
        &self,
        decoded: DecodedAuthWebCookies,
        command: Command,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let prepared =
            PreparedCommandExecution::prepare(self.runtime.config(), command, presented_cookies)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        match prepared_storage_boundary_contract.boundary_before_reduce() {
            StorageBoundaryBeforeReduce::None => {
                self.execute_prepared_without_loaded_state_boundary(
                    prepared,
                    prepared_storage_boundary_contract,
                    presented_cookie_secrets,
                )
                .await
            }
            StorageBoundaryBeforeReduce::OpenBeforeStateLoad => {
                let mut tx = self.begin_runtime_transaction().await?;
                let loaded = match self
                    .store
                    .load_state_in_current_transaction(
                        &mut tx,
                        AuthLoadStateRequest::new(
                            prepared.command().now(),
                            prepared.presented_cookies(),
                            &presented_cookie_secrets,
                            prepared.loaded_state_contract(),
                            &prepared_storage_boundary_contract,
                        ),
                    )
                    .await
                {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        return Err(rollback_after_store_error(
                            "auth_core.runtime.load",
                            tx,
                            error,
                        )
                        .await);
                    }
                };
                self.execute_prepared_with_loaded_state_boundary(
                    tx,
                    prepared,
                    prepared_storage_boundary_contract,
                    loaded,
                    presented_cookie_secrets,
                )
                .await
            }
        }
    }

    async fn execute_prepared_without_loaded_state_boundary(
        &self,
        prepared: PreparedCommandExecution,
        prepared_storage_boundary_contract: PreparedStorageBoundaryContract,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = prepared.command().now();
        let loaded = loaded_state_from_presented_cookies(prepared.presented_cookies());
        let planned = prepared
            .reduce_loaded_state(self.runtime.config(), &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let planned_storage_boundary_contract =
            PlannedStorageBoundaryContract::for_planned_execution(
                &prepared_storage_boundary_contract,
                &planned,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        match planned_storage_boundary_contract.atomic_commit_boundary() {
            AtomicCommitBoundary::None => {
                self.finish_without_atomic_commit(now, planned, presented_cookie_secrets)
            }
            AtomicCommitBoundary::CommitOnlyBoundary => {
                let tx = self.begin_runtime_transaction().await?;
                self.commit_planned_inside_transaction(
                    "auth_core.runtime.commit_only",
                    now,
                    tx,
                    planned,
                    planned_storage_boundary_contract,
                    presented_cookie_secrets,
                )
                .await
            }
            AtomicCommitBoundary::LoadedStateBoundary => Err(
                AuthPostgresWebRuntimeExecutionError::core(Error::LoadedStateContradiction(
                    "planned execution required loaded-state commit boundary without loaded-state boundary",
                )),
            ),
        }
    }

    async fn execute_prepared_with_loaded_state_boundary(
        &self,
        tx: Tx<'_>,
        prepared: PreparedCommandExecution,
        prepared_storage_boundary_contract: PreparedStorageBoundaryContract,
        loaded: LoadedState,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = prepared.command().now();
        let planned = match prepared.reduce_loaded_state(self.runtime.config(), &loaded) {
            Ok(planned) => planned,
            Err(error) => {
                return Err(rollback_after_core_error("auth_core.runtime.reduce", tx, error).await);
            }
        };
        let planned_storage_boundary_contract =
            match PlannedStorageBoundaryContract::for_planned_execution(
                &prepared_storage_boundary_contract,
                &planned,
            ) {
                Ok(contract) => contract,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.plan_storage_boundary",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        match planned_storage_boundary_contract.atomic_commit_boundary() {
            AtomicCommitBoundary::None => {
                if let Err(error) = tx.rollback().await {
                    return Err(AuthPostgresWebRuntimeExecutionError::store(
                        PostgresAuthStoreError::Database(error),
                    ));
                }
                self.finish_without_atomic_commit(now, planned, presented_cookie_secrets)
            }
            AtomicCommitBoundary::LoadedStateBoundary => {
                self.commit_planned_inside_transaction(
                    "auth_core.runtime.loaded_state_commit",
                    now,
                    tx,
                    planned,
                    planned_storage_boundary_contract,
                    presented_cookie_secrets,
                )
                .await
            }
            AtomicCommitBoundary::CommitOnlyBoundary => Err(
                rollback_after_core_error(
                    "auth_core.runtime.plan_storage_boundary",
                    tx,
                    Error::LoadedStateContradiction(
                        "planned execution opened a commit-only boundary after loading authoritative state",
                    ),
                )
                .await,
            ),
        }
    }

    async fn commit_planned_inside_transaction(
        &self,
        operation: &'static str,
        now: UnixSeconds,
        mut tx: Tx<'_>,
        planned: PlannedCommandExecution,
        planned_storage_boundary_contract: PlannedStorageBoundaryContract,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let commit_result = async {
            let request = AtomicCommitRequest::for_atomic_work_with_storage_boundary(
                planned.atomic_commit_work(),
                planned_storage_boundary_contract,
            )?;
            let materialized = self
                .store
                .commit_atomic_work_in_current_transaction(&mut tx, request)
                .await?;
            let materialized_fresh_credential_secrets =
                MaterializedFreshCredentialSecrets::for_atomic_work(
                    planned.atomic_commit_work(),
                    materialized,
                )?;
            AtomicCommitSuccess::for_atomic_work(
                planned.atomic_commit_work(),
                materialized_fresh_credential_secrets,
            )
            .map_err(PostgresAuthStoreError::from)
        }
        .await;
        let commit_success = finish_auth_store_transaction(operation, tx, commit_result)
            .await
            .map_err(AuthPostgresWebRuntimeExecutionError::store)?;
        self.finish_after_successful_atomic_commit(
            now,
            planned,
            commit_success,
            presented_cookie_secrets,
        )
    }

    async fn begin_runtime_transaction(
        &self,
    ) -> Result<Tx<'_>, AuthPostgresWebRuntimeExecutionError> {
        self.pool
            .begin_transaction()
            .await
            .map_err(PostgresAuthStoreError::from)
            .map_err(AuthPostgresWebRuntimeExecutionError::store)
    }

    fn method_registry(
        &self,
    ) -> Result<&PostgresAuthMethodRegistry, AuthPostgresWebRuntimeExecutionError> {
        self.store
            .method_registry()
            .ok_or(PostgresAuthStoreError::MethodRegistryNotConfigured)
            .map_err(AuthPostgresWebRuntimeExecutionError::store)
    }

    async fn load_credential_lifecycle_context_for_unauthenticated_reset_method_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        target_method: &ProofMethodDeclaration,
        recovery_attempt: &ActiveProofAttemptRecord,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Option<CredentialLifecycleActionContext>, PostgresAuthStoreError> {
        let Some(recovered_subject_id) = recovery_attempt.subject_id.as_ref() else {
            return Err(PostgresAuthStoreError::Core(
                Error::LoadedStateContradiction(
                    "recovery active-proof attempt is not subject-bound",
                ),
            ));
        };
        self.store
            .load_credential_lifecycle_action_context_for_subject_and_method_in_current_transaction(
                tx,
                recovered_subject_id,
                target_method,
                evidence_sources,
            )
            .await
    }

    fn finish_without_atomic_commit(
        &self,
        now: UnixSeconds,
        planned: PlannedCommandExecution,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let completed = planned
            .finish_without_atomic_commit()
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        self.materialize_and_render(now, completed, presented_cookie_secrets)
    }

    fn finish_after_successful_atomic_commit(
        &self,
        now: UnixSeconds,
        planned: PlannedCommandExecution,
        commit_success: AtomicCommitSuccess,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let completed = planned
            .finish_after_successful_atomic_commit(commit_success)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        self.materialize_and_render(now, completed, presented_cookie_secrets)
    }

    fn materialize_and_render(
        &self,
        now: UnixSeconds,
        completed: CompletedCommandExecution,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let materialized = completed
            .materialize_response_effects(presented_cookie_secrets)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let (outcome, materialized_response_effects) = materialized.into_parts();
        let set_cookie_headers = self
            .runtime
            .web_transport()
            .render_set_cookie_headers(now, materialized_response_effects)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        Ok(AuthWebRuntimeExecution::new(outcome, set_cookie_headers))
    }
}

fn command_from_active_proof_method_response(
    response: CompleteActiveProofMethodResponse,
    challenge_cookie: &ActiveProofChallengeCookieDraft,
    weak_proof_gate: WeakProofGateStatus,
    verified: VerifiedActiveProofMethodResponse,
) -> CompleteActiveProofChallenge {
    let (verified_proof, method_commit_work) = verified.into_parts();
    response.into_command_with_verified_proof(
        challenge_cookie,
        verified_proof,
        weak_proof_gate,
        method_commit_work,
    )
}

fn command_from_known_subject_active_proof_method_response(
    response: CompleteKnownSubjectActiveProofMethodResponse,
    attempt_id: ActiveProofAttemptId,
    weak_proof_gate: WeakProofGateStatus,
    verification: KnownSubjectActiveProofMethodVerification,
) -> Result<Command, Error> {
    match verification {
        KnownSubjectActiveProofMethodVerification::Accepted(verified) => {
            let (verified_proof, method_commit_work) = verified.into_parts();
            if verified_proof.proof() != &response.method.verified_proof_summary() {
                return Err(Error::LoadedStateContradiction(
                    "known-subject method verified a different proof",
                ));
            }
            if verified_proof.subject_id().is_some() {
                return Err(Error::LoadedStateContradiction(
                    "known-subject method unexpectedly resolved a subject",
                ));
            }
            Ok(Command::CompleteActiveProofChallenge(
                CompleteActiveProofChallenge {
                    now: response.now,
                    attempt_id,
                    challenge_id: None,
                    verified_proof,
                    stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                    weak_proof_gate,
                    method_commit_work,
                },
            ))
        }
        KnownSubjectActiveProofMethodVerification::Rejected => Ok(
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: response.now,
                attempt_id,
                challenge_id: None,
                method: response.method,
                weak_proof_gate,
            }),
        ),
    }
}

fn command_from_recovery_credential_active_proof_method_response(
    response: CompleteRecoveryCredentialActiveProofMethodResponse,
    attempt_id: ActiveProofAttemptId,
    candidate_subject_id: SubjectId,
    verification: RecoveryCredentialActiveProofMethodVerification,
) -> Result<Command, Error> {
    match verification {
        RecoveryCredentialActiveProofMethodVerification::Accepted(verified) => {
            let (verified_proof, method_commit_work) = verified.into_parts();
            if verified_proof.proof() != &response.method.verified_proof_summary() {
                return Err(Error::LoadedStateContradiction(
                    "recovery credential method verified a different proof",
                ));
            }
            if verified_proof.subject_id() != Some(&candidate_subject_id) {
                return Err(Error::LoadedStateContradiction(
                    "recovery credential method verified a different subject",
                ));
            }
            Ok(Command::CompleteActiveProofChallenge(
                CompleteActiveProofChallenge {
                    now: response.now,
                    attempt_id,
                    challenge_id: None,
                    verified_proof,
                    stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                    weak_proof_gate: WeakProofGateStatus::NotRequired,
                    method_commit_work,
                },
            ))
        }
        RecoveryCredentialActiveProofMethodVerification::Rejected => Ok(
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: response.now,
                attempt_id,
                challenge_id: None,
                method: response.method,
                weak_proof_gate: WeakProofGateStatus::NotRequired,
            }),
        ),
    }
}

fn command_from_challenge_bound_known_subject_active_proof_method_response(
    response: CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    challenge_cookie: &ActiveProofChallengeCookieDraft,
    method: ProofMethodDeclaration,
    weak_proof_gate: WeakProofGateStatus,
    verification: KnownSubjectActiveProofMethodVerification,
) -> Result<Command, Error> {
    match verification {
        KnownSubjectActiveProofMethodVerification::Accepted(verified) => {
            let (verified_proof, method_commit_work) = verified.into_parts();
            if verified_proof.proof() != &challenge_cookie.proof {
                return Err(Error::LoadedStateContradiction(
                    "challenge-bound known-subject method verified a different proof",
                ));
            }
            if verified_proof.subject_id().is_some() {
                return Err(Error::LoadedStateContradiction(
                    "challenge-bound known-subject method unexpectedly resolved a subject",
                ));
            }
            Ok(Command::CompleteActiveProofChallenge(
                CompleteActiveProofChallenge {
                    now: response.now,
                    attempt_id: challenge_cookie.attempt_id.clone(),
                    challenge_id: Some(challenge_cookie.challenge_id.clone()),
                    verified_proof,
                    stateless_fast_fail: StatelessFastFailStatus::verified_before_state_load(),
                    weak_proof_gate,
                    method_commit_work,
                },
            ))
        }
        KnownSubjectActiveProofMethodVerification::Rejected => Ok(
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: response.now,
                attempt_id: challenge_cookie.attempt_id.clone(),
                challenge_id: Some(challenge_cookie.challenge_id.clone()),
                method,
                weak_proof_gate,
            }),
        ),
    }
}

fn proof_summary_to_method_declaration(
    proof: &ProofSummary,
) -> Result<ProofMethodDeclaration, Error> {
    ProofMethodDeclaration::new_with_online_guessing_risk(
        proof.family(),
        proof.method_label().to_owned(),
        proof.online_guessing_risk(),
    )
}

#[derive(Debug)]
pub(crate) enum AuthPostgresWebRuntimeExecutionError {
    Core(Error),
    Web(AuthWebTransportError),
    Store(PostgresAuthStoreError),
    MethodBuild(PostgresAuthMethodBuildError),
}

impl AuthPostgresWebRuntimeExecutionError {
    fn core(error: Error) -> Self {
        Self::Core(error)
    }

    fn web(error: AuthWebTransportError) -> Self {
        Self::Web(error)
    }

    fn store(error: PostgresAuthStoreError) -> Self {
        Self::Store(error)
    }

    fn method_build(error: PostgresAuthMethodBuildError) -> Self {
        Self::MethodBuild(error)
    }
}

impl fmt::Display for AuthPostgresWebRuntimeExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Web(error) => write!(f, "{error}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::MethodBuild(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuthPostgresWebRuntimeExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Web(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::MethodBuild(error) => Some(error),
        }
    }
}

fn loaded_state_from_presented_cookies(presented_cookies: &PresentedAuthCookies) -> LoadedState {
    LoadedState {
        session_cookie: presented_cookies.session_cookie.clone(),
        trusted_device_cookie: presented_cookies.trusted_device_cookie.clone(),
        ..LoadedState::default()
    }
}

fn pending_credential_reset_schedule_from_policy(
    now: UnixSeconds,
    timing: Option<DelayedLifecycleActionTimingPolicy>,
) -> Result<Option<PendingCredentialLifecycleActionSchedule>, AuthPostgresWebRuntimeExecutionError>
{
    pending_credential_lifecycle_action_schedule_from_policy(now, timing)
}

fn pending_credential_lifecycle_action_schedule_from_policy(
    now: UnixSeconds,
    timing: Option<DelayedLifecycleActionTimingPolicy>,
) -> Result<Option<PendingCredentialLifecycleActionSchedule>, AuthPostgresWebRuntimeExecutionError>
{
    timing
        .map(|timing| {
            let pending_action_id = generate_auth_id()?;
            timing
                .pending_credential_lifecycle_action_schedule(now, pending_action_id)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)
        })
        .transpose()
}

fn pending_subject_lifecycle_action_schedule_from_policy(
    now: UnixSeconds,
    timing: Option<DelayedLifecycleActionTimingPolicy>,
) -> Result<Option<PendingSubjectLifecycleActionSchedule>, AuthPostgresWebRuntimeExecutionError> {
    timing
        .map(|timing| {
            let pending_action_id = generate_auth_id()?;
            timing
                .pending_subject_lifecycle_action_schedule(now, pending_action_id)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)
        })
        .transpose()
}

fn credential_reset_policy_for_target<'a>(
    policies: &'a CredentialResetLifecyclePolicies,
    lifecycle_context: &CredentialLifecycleActionContext,
) -> &'a CredentialResetLifecyclePolicy {
    credential_reset_policy_for_loaded_target(policies, lifecycle_context.target_credential())
}

fn credential_reset_policy_for_loaded_target<'a>(
    policies: &'a CredentialResetLifecyclePolicies,
    target_credential: &CredentialInstanceMetadata,
) -> &'a CredentialResetLifecyclePolicy {
    policies.policy_for_role(target_credential.reset_policy_role())
}

async fn build_replacement_successor_in_current_transaction(
    store: &PostgresAuthStore,
    tx: &mut Tx<'_>,
    target_credential: &CredentialInstanceMetadata,
    target_recovery_authorities: impl IntoIterator<Item = CredentialRecoveryAuthority>,
) -> Result<CredentialReplacementSuccessor, AuthPostgresWebRuntimeExecutionError> {
    let target_authority_ids = load_verified_proof_source_authority_ids_in_current_transaction(
        store,
        tx,
        target_credential.verified_proof_source(),
        "replacement target credential must have lifecycle authority-source metadata",
    )
    .await
    .map_err(AuthPostgresWebRuntimeExecutionError::store)?;
    CredentialReplacementSuccessor::inheriting_target_policy(
        generate_auth_id()?,
        target_credential,
        target_recovery_authorities,
        target_authority_ids,
    )
    .map_err(AuthPostgresWebRuntimeExecutionError::core)
}

async fn load_verified_proof_source_authority_ids_in_current_transaction(
    store: &PostgresAuthStore,
    tx: &mut Tx<'_>,
    source: VerifiedProofSource,
    missing_metadata_error: &'static str,
) -> Result<Vec<RecoveryAuthorityId>, PostgresAuthStoreError> {
    let authority_source = LifecycleAuthoritySource::VerifiedProofSource(source);
    let mut loaded_evidence = store
        .load_lifecycle_authority_evidence_for_sources_in_current_transaction(
            tx,
            &[authority_source],
        )
        .await?;
    loaded_evidence
        .pop()
        .ok_or(PostgresAuthStoreError::Core(Error::InvalidConfig(
            missing_metadata_error,
        )))
        .map(|evidence| evidence.authority_ids().to_vec())
}

fn lifecycle_step_up_freshness_outcome(
    now: UnixSeconds,
    session: &SessionRecord,
    requirement: StepUpFreshnessRequirement,
) -> Option<Outcome> {
    if requirement.is_required()
        && !super::session_lifecycle_helpers::step_up_is_fresh(session.step_up_expires_at, now)
    {
        return Some(Outcome::NeedsStepUp {
            session_id: session.session_id.clone(),
            subject_id: session.subject_id.clone(),
        });
    }
    None
}

fn impossible_authenticated_lifecycle_session_outcome(
    runtime: &AuthWebRuntime,
    now: UnixSeconds,
    presented_cookies: &PresentedAuthCookies,
) -> Result<Option<AuthWebRuntimeExecution>, AuthPostgresWebRuntimeExecutionError> {
    let Some(session_cookie) = presented_cookies.session_cookie.as_ref() else {
        return Ok(Some(AuthWebRuntimeExecution::new(
            Outcome::NeedsFullAuthentication,
            AuthSetCookieHeaders::default(),
        )));
    };
    if now < session_cookie.session_fast_fail_until {
        return Ok(None);
    }
    let set_cookie_headers = runtime
        .web_transport()
        .render_set_cookie_headers(
            now,
            MaterializedResponseEffects::from_vec(vec![
                MaterializedResponseEffect::DeleteSessionCookie,
                MaterializedResponseEffect::CycleCsrfToken { session_id: None },
            ]),
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
    Ok(Some(AuthWebRuntimeExecution::new(
        Outcome::NeedsFullAuthentication,
        set_cookie_headers,
    )))
}

async fn rollback_and_return_outcome(
    tx: Tx<'_>,
    outcome: Outcome,
) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
    if let Err(error) = tx.rollback().await {
        return Err(AuthPostgresWebRuntimeExecutionError::store(
            PostgresAuthStoreError::Database(error),
        ));
    }
    Ok(AuthWebRuntimeExecution::new(
        outcome,
        AuthSetCookieHeaders::default(),
    ))
}

async fn rollback_and_return_credential_inventory_outcome(
    tx: Tx<'_>,
    outcome: MountedCredentialInventoryServiceOutcome,
) -> Result<MountedCredentialInventoryServiceOutcome, AuthPostgresWebRuntimeExecutionError> {
    if let Err(error) = tx.rollback().await {
        return Err(AuthPostgresWebRuntimeExecutionError::store(
            PostgresAuthStoreError::Database(error),
        ));
    }
    Ok(outcome)
}

fn lifecycle_authority_sources_from_satisfied_proofs(
    proofs: &[SatisfiedProof],
) -> Result<Vec<LifecycleAuthoritySource>, Error> {
    proofs
        .iter()
        .map(|proof| {
            proof
                .source()
                .cloned()
                .map(LifecycleAuthoritySource::VerifiedProofSource)
                .ok_or(Error::ProofFamilyRequiresVerifiedProofSource {
                    family: proof.family(),
                })
        })
        .collect()
}

fn live_authenticated_session_record_for_lifecycle_request(
    now: UnixSeconds,
    loaded: &LoadedState,
) -> Result<Option<&SessionRecord>, Error> {
    let Some(cookie) = loaded.session_cookie.as_ref() else {
        return Ok(None);
    };
    let Some(record) = loaded.session_record.as_ref() else {
        return Ok(None);
    };
    super::session_lifecycle_helpers::validate_session_cookie_record_pair(cookie, record)?;
    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || now >= record.expires_at
        || super::session_lifecycle_helpers::subject_revocation_invalidates_record(
            subject_revocation,
            record.created_at,
        )
    {
        return Ok(None);
    }
    let secret_match = loaded
        .session_secret_match
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "authenticated lifecycle request requires session secret match",
        ))?
        .kind();
    super::session_lifecycle_helpers::validate_session_secret_match_consistency(
        now,
        secret_match,
        cookie,
        record,
    )?;
    if !secret_match.is_accepted() {
        return Ok(None);
    }
    Ok(Some(record))
}

fn generate_auth_id<K>() -> Result<Id<K>, AuthPostgresWebRuntimeExecutionError> {
    Id::generate().map_err(AuthPostgresWebRuntimeExecutionError::core)
}

async fn rollback_after_core_error(
    operation: &'static str,
    tx: Tx<'_>,
    error: Error,
) -> AuthPostgresWebRuntimeExecutionError {
    match tx.rollback().await {
        Ok(()) => AuthPostgresWebRuntimeExecutionError::core(error),
        Err(rollback_error) => AuthPostgresWebRuntimeExecutionError::store(
            PostgresAuthStoreError::Database(DbError::DatabaseOperationRollbackFailed {
                operation,
                operation_error: Box::new(DbError::schema_mismatch(error.to_string())),
                rollback_error: Box::new(rollback_error),
            }),
        ),
    }
}

async fn rollback_after_store_error(
    operation: &'static str,
    tx: Tx<'_>,
    error: PostgresAuthStoreError,
) -> AuthPostgresWebRuntimeExecutionError {
    match tx.rollback().await {
        Ok(()) => AuthPostgresWebRuntimeExecutionError::store(error),
        Err(rollback_error) => AuthPostgresWebRuntimeExecutionError::store(
            PostgresAuthStoreError::Database(DbError::DatabaseOperationRollbackFailed {
                operation,
                operation_error: Box::new(db_error_from_auth_store_error(error)),
                rollback_error: Box::new(rollback_error),
            }),
        ),
    }
}

async fn rollback_after_runtime_error(
    operation: &'static str,
    tx: Tx<'_>,
    error: AuthPostgresWebRuntimeExecutionError,
) -> AuthPostgresWebRuntimeExecutionError {
    match tx.rollback().await {
        Ok(()) => error,
        Err(rollback_error) => AuthPostgresWebRuntimeExecutionError::store(
            PostgresAuthStoreError::Database(DbError::DatabaseOperationRollbackFailed {
                operation,
                operation_error: Box::new(DbError::schema_mismatch(error.to_string())),
                rollback_error: Box::new(rollback_error),
            }),
        ),
    }
}

fn db_error_from_auth_store_error(error: PostgresAuthStoreError) -> DbError {
    match error {
        PostgresAuthStoreError::Database(error) => error,
        other => DbError::schema_mismatch(other.to_string()),
    }
}
