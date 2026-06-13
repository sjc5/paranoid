use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn execute_out_of_band_identifier_change_candidate_binding_from_headers(
        &self,
        headers: &HeaderMap,
        response: CompleteOutOfBandChallengeResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = response.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let continuation =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                now,
                ProofUse::ProveOutOfBandIdentifierChangeCandidate,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let challenge_cookie = decoded
            .presented_cookies()
            .active_proof_challenge_cookie
            .clone()
            .ok_or(Error::MissingActiveProofChallengeCookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        if challenge_cookie.attempt_id != continuation.attempt_id {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ActiveProofChallengeCookieCommandMismatch,
            ));
        }
        challenge_cookie
            .validate_for_out_of_band_completion_before_state_load(now)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                now,
                &challenge_cookie.proof,
                response.weak_proof_gate_response.as_ref(),
                None,
                self.weak_proof_gate_verifier.as_ref(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let verification_command = CompleteActiveProofChallenge {
            now,
            attempt_id: challenge_cookie.attempt_id.clone(),
            challenge_id: Some(challenge_cookie.challenge_id.clone()),
            verified_proof: VerifiedActiveProof::from_summary(challenge_cookie.proof.clone(), None)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?,
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: weak_proof_gate.clone(),
            method_commit_work: Vec::new(),
        };
        let stateless_fast_fail = challenge_cookie
            .verify_response_secret_before_state_load(
                self.runtime
                    .web_transport()
                    .active_proof_challenge_fast_fail_keyset(),
                now,
                &verification_command,
                &response.secret_response,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let candidate_identifier_source = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .resolve_out_of_band_identifier_change_candidate_source(
                        &mut tx,
                        &challenge_cookie.proof,
                        &challenge_cookie.challenge_id,
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(source) => source,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.resolve_out_of_band_identifier_change_candidate_source",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.resolve_out_of_band_identifier_change_candidate_source",
                    tx,
                    error,
                )
                .await);
            }
        };
        let method_commit_work = match self.method_registry().and_then(|registry| {
            registry
                .build_out_of_band_completion_commit_work(
                    &challenge_cookie.proof,
                    &challenge_cookie.challenge_id,
                    &response,
                )
                .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
        }) {
            Ok(method_commit_work) => method_commit_work,
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_identifier_change_candidate_method_work",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = ReserveOutOfBandIdentifierChangeCandidateBinding {
            now,
            attempt_id: challenge_cookie.attempt_id.clone(),
            challenge_id: challenge_cookie.challenge_id.clone(),
            candidate_identifier_source,
            stateless_fast_fail,
            weak_proof_gate,
            method_commit_work,
        };
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            Command::ReserveOutOfBandIdentifierChangeCandidateBinding(command),
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        if prepared_storage_boundary_contract.boundary_before_reduce()
            != StorageBoundaryBeforeReduce::OpenBeforeStateLoad
        {
            return Err(rollback_after_core_error(
                "auth_core.runtime.plan_storage_boundary",
                tx,
                Error::LoadedStateContradiction(
                    "identifier-change candidate binding unexpectedly avoided loaded-state boundary",
                ),
            )
            .await);
        }
        let loaded = match self
            .store
            .load_state_in_current_transaction(
                &mut tx,
                AuthLoadStateRequest::new(
                    now,
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
                return Err(rollback_after_store_error("auth_core.runtime.load", tx, error).await);
            }
        };
        if let Err(error) = prepared
            .loaded_state_contract()
            .validate_loaded_state(&loaded)
        {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        self.execute_prepared_with_loaded_state_boundary(
            tx,
            prepared,
            prepared_storage_boundary_contract,
            loaded,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_out_of_band_identifier_change_planning_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanAuthenticatedOutOfBandIdentifierChangeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let change_policy = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .out_of_band_identifier_change
            .clone();
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        if let Some(outcome) = impossible_authenticated_lifecycle_session_outcome(
            &self.runtime,
            now,
            &presented_cookies,
        )? {
            return Ok(outcome);
        }
        let loaded_state_contract =
            CommandLoadedStateContract::for_authenticated_session_lifecycle_request(
                self.runtime.config(),
                now,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = self.begin_runtime_transaction().await?;
        let loaded = match self
            .store
            .load_state_in_current_transaction(
                &mut tx,
                AuthLoadStateRequest::new(
                    now,
                    &presented_cookies,
                    &presented_cookie_secrets,
                    &loaded_state_contract,
                    &prepared_storage_boundary_contract,
                ),
            )
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => {
                return Err(rollback_after_store_error("auth_core.runtime.load", tx, error).await);
            }
        };
        if let Err(error) = loaded_state_contract.validate_loaded_state(&loaded) {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        let Some(session) = live_authenticated_session_record_for_lifecycle_request(now, &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
        else {
            if let Err(error) = tx.rollback().await {
                return Err(AuthPostgresWebRuntimeExecutionError::store(
                    PostgresAuthStoreError::Database(error),
                ));
            }
            return Ok(AuthWebRuntimeExecution::new(
                Outcome::NeedsFullAuthentication,
                AuthSetCookieHeaders::default(),
            ));
        };
        if let Some(outcome) = lifecycle_step_up_freshness_outcome(
            now,
            session,
            change_policy.authenticated_planning_step_up_freshness,
        ) {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let evidence_sources = [LifecycleAuthoritySource::AuthenticatedSession(
            session.session_id.clone(),
        )];
        let current_identifier_source = VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            request.current_identifier_source_id,
        );
        let candidate_identifier_source = VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            request.candidate_identifier_source_id,
        );
        let change_context = match self
            .store
            .load_out_of_band_identifier_change_context_in_current_transaction(
                &mut tx,
                &session.subject_id,
                current_identifier_source,
                candidate_identifier_source,
                &evidence_sources,
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_out_of_band_identifier_change_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_out_of_band_identifier_change_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        let candidate_authority_ids =
            match load_verified_proof_source_authority_ids_in_current_transaction(
                &self.store,
                &mut tx,
                change_context.current_identifier_source().clone(),
                "identifier change current source must have lifecycle authority-source metadata",
            )
            .await
            {
                Ok(authority_ids) => authority_ids,
                Err(error) => {
                    return Err(rollback_after_store_error(
                        "auth_core.runtime.load_identifier_change_current_authorities",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let pending_action = match pending_subject_lifecycle_action_schedule_from_policy(
            now,
            change_policy.delayed_action_timing,
        ) {
            Ok(pending_action) => pending_action,
            Err(error) => {
                return Err(
                    rollback_after_runtime_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let command = Command::PlanOutOfBandIdentifierChange(PlanOutOfBandIdentifierChange {
            now,
            change_context,
            independent_evidence_required: change_policy.independent_evidence_requirement,
            candidate_authority_ids,
            pending_action,
        });
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.authenticated_out_of_band_identifier_change_planning",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_out_of_band_identifier_change_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteAuthenticatedOutOfBandIdentifierChangeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let change_policy = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .out_of_band_identifier_change
            .clone();
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        if let Some(outcome) = impossible_authenticated_lifecycle_session_outcome(
            &self.runtime,
            now,
            &presented_cookies,
        )? {
            return Ok(outcome);
        }
        let loaded_state_contract =
            CommandLoadedStateContract::for_authenticated_session_lifecycle_request(
                self.runtime.config(),
                now,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = self.begin_runtime_transaction().await?;
        let loaded = match self
            .store
            .load_state_in_current_transaction(
                &mut tx,
                AuthLoadStateRequest::new(
                    now,
                    &presented_cookies,
                    &presented_cookie_secrets,
                    &loaded_state_contract,
                    &prepared_storage_boundary_contract,
                ),
            )
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => {
                return Err(rollback_after_store_error("auth_core.runtime.load", tx, error).await);
            }
        };
        if let Err(error) = loaded_state_contract.validate_loaded_state(&loaded) {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        let Some(session) = live_authenticated_session_record_for_lifecycle_request(now, &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
        else {
            if let Err(error) = tx.rollback().await {
                return Err(AuthPostgresWebRuntimeExecutionError::store(
                    PostgresAuthStoreError::Database(error),
                ));
            }
            return Ok(AuthWebRuntimeExecution::new(
                Outcome::NeedsFullAuthentication,
                AuthSetCookieHeaders::default(),
            ));
        };
        if let Some(outcome) = lifecycle_step_up_freshness_outcome(
            now,
            session,
            change_policy.authenticated_execution_step_up_freshness,
        ) {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let evidence_sources = [LifecycleAuthoritySource::AuthenticatedSession(
            session.session_id.clone(),
        )];
        let current_identifier_source = VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            request.current_identifier_source_id,
        );
        let candidate_identifier_source = VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            request.candidate_identifier_source_id,
        );
        let change_context = match self
            .store
            .load_out_of_band_identifier_change_context_in_current_transaction(
                &mut tx,
                &session.subject_id,
                current_identifier_source,
                candidate_identifier_source,
                &evidence_sources,
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_out_of_band_identifier_change_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_out_of_band_identifier_change_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        let candidate_authority_ids =
            match load_verified_proof_source_authority_ids_in_current_transaction(
                &self.store,
                &mut tx,
                change_context.current_identifier_source().clone(),
                "identifier change current source must have lifecycle authority-source metadata",
            )
            .await
            {
                Ok(authority_ids) => authority_ids,
                Err(error) => {
                    return Err(rollback_after_store_error(
                        "auth_core.runtime.load_identifier_change_current_authorities",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let command = Command::ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange {
            now,
            change_context,
            independent_evidence_required: change_policy.independent_evidence_requirement,
            candidate_authority_ids,
        });
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.authenticated_out_of_band_identifier_change",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn schedule_authenticated_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: ScheduleAuthenticatedSubjectAuthStateDeletionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let deletion_policy = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .subject_auth_state_deletion
            .clone();
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        if let Some(outcome) = impossible_authenticated_lifecycle_session_outcome(
            &self.runtime,
            now,
            &presented_cookies,
        )? {
            return Ok(outcome);
        }
        let loaded_state_contract =
            CommandLoadedStateContract::for_authenticated_session_lifecycle_request(
                self.runtime.config(),
                now,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = self.begin_runtime_transaction().await?;
        let loaded = match self
            .store
            .load_state_in_current_transaction(
                &mut tx,
                AuthLoadStateRequest::new(
                    now,
                    &presented_cookies,
                    &presented_cookie_secrets,
                    &loaded_state_contract,
                    &prepared_storage_boundary_contract,
                ),
            )
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => {
                return Err(rollback_after_store_error("auth_core.runtime.load", tx, error).await);
            }
        };
        if let Err(error) = loaded_state_contract.validate_loaded_state(&loaded) {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        let Some(session) = live_authenticated_session_record_for_lifecycle_request(now, &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
        else {
            if let Err(error) = tx.rollback().await {
                return Err(AuthPostgresWebRuntimeExecutionError::store(
                    PostgresAuthStoreError::Database(error),
                ));
            }
            return Ok(AuthWebRuntimeExecution::new(
                Outcome::NeedsFullAuthentication,
                AuthSetCookieHeaders::default(),
            ));
        };
        if let Some(outcome) = lifecycle_step_up_freshness_outcome(
            now,
            session,
            deletion_policy.authenticated_scheduling_step_up_freshness,
        ) {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let pending_action = match pending_subject_lifecycle_action_schedule_from_policy(
            now,
            Some(deletion_policy.delayed_action_timing),
        ) {
            Ok(Some(pending_action)) => pending_action,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.prepare_subject_auth_state_deletion_schedule",
                    tx,
                    Error::InvalidConfig(
                        "subject-auth-state deletion must have delayed action timing",
                    ),
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.prepare_subject_auth_state_deletion_schedule",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion {
            now,
            subject_id: session.subject_id.clone(),
            pending_action,
        });
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.authenticated_subject_auth_state_deletion_scheduling",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_mature_pending_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMaturePendingSubjectAuthStateDeletionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let pending_action = match self
            .store
            .load_pending_subject_lifecycle_action_for_execution_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(pending_action)) => pending_action,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_subject_auth_state_deletion",
                    tx,
                    Error::PendingSubjectLifecycleActionNotExecutable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_subject_auth_state_deletion",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ExecutePendingSubjectAuthStateDeletion(
            ExecutePendingSubjectAuthStateDeletion {
                now,
                pending_action,
                application_subject_data_lifecycle_action: request
                    .application_subject_data_lifecycle_action,
            },
        );
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.mature_pending_subject_auth_state_deletion",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelAuthenticatedPendingSubjectAuthStateDeletionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let step_up_freshness = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .subject_auth_state_deletion
            .authenticated_cancellation_step_up_freshness;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        if let Some(outcome) = impossible_authenticated_lifecycle_session_outcome(
            &self.runtime,
            now,
            &presented_cookies,
        )? {
            return Ok(outcome);
        }
        let loaded_state_contract =
            CommandLoadedStateContract::for_authenticated_session_lifecycle_request(
                self.runtime.config(),
                now,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = self.begin_runtime_transaction().await?;
        let loaded = match self
            .store
            .load_state_in_current_transaction(
                &mut tx,
                AuthLoadStateRequest::new(
                    now,
                    &presented_cookies,
                    &presented_cookie_secrets,
                    &loaded_state_contract,
                    &prepared_storage_boundary_contract,
                ),
            )
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => {
                return Err(rollback_after_store_error("auth_core.runtime.load", tx, error).await);
            }
        };
        if let Err(error) = loaded_state_contract.validate_loaded_state(&loaded) {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        let Some(session) = live_authenticated_session_record_for_lifecycle_request(now, &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
        else {
            if let Err(error) = tx.rollback().await {
                return Err(AuthPostgresWebRuntimeExecutionError::store(
                    PostgresAuthStoreError::Database(error),
                ));
            }
            return Ok(AuthWebRuntimeExecution::new(
                Outcome::NeedsFullAuthentication,
                AuthSetCookieHeaders::default(),
            ));
        };
        if let Some(outcome) = lifecycle_step_up_freshness_outcome(now, session, step_up_freshness)
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let pending_action = match self
            .store
            .load_pending_subject_lifecycle_action_for_cancellation_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(pending_action)) => pending_action,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_subject_auth_state_deletion_cancellation",
                    tx,
                    Error::PendingSubjectLifecycleActionNotCancellable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_subject_auth_state_deletion_cancellation",
                    tx,
                    error,
                )
                .await);
            }
        };
        if pending_action.subject_id != session.subject_id {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_pending_subject_auth_state_deletion_cancellation_subject",
                tx,
                Error::CredentialLifecycleActionNotAuthorized,
            )
            .await);
        }
        let command =
            Command::CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion {
                now,
                pending_action,
            });
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.authenticated_pending_subject_auth_state_deletion_cancellation",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_mature_pending_out_of_band_identifier_change_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMaturePendingOutOfBandIdentifierChangeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let pending_action = match self
            .store
            .load_pending_subject_lifecycle_action_for_execution_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(pending_action)) => pending_action,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_out_of_band_identifier_change",
                    tx,
                    Error::PendingSubjectLifecycleActionNotExecutable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_out_of_band_identifier_change",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ExecutePendingOutOfBandIdentifierChange(
            ExecutePendingOutOfBandIdentifierChange {
                now,
                pending_action,
            },
        );
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.mature_pending_out_of_band_identifier_change",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelAuthenticatedPendingOutOfBandIdentifierChangeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let step_up_freshness = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .out_of_band_identifier_change
            .authenticated_cancellation_step_up_freshness;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        if let Some(outcome) = impossible_authenticated_lifecycle_session_outcome(
            &self.runtime,
            now,
            &presented_cookies,
        )? {
            return Ok(outcome);
        }
        let loaded_state_contract =
            CommandLoadedStateContract::for_authenticated_session_lifecycle_request(
                self.runtime.config(),
                now,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = self.begin_runtime_transaction().await?;
        let loaded = match self
            .store
            .load_state_in_current_transaction(
                &mut tx,
                AuthLoadStateRequest::new(
                    now,
                    &presented_cookies,
                    &presented_cookie_secrets,
                    &loaded_state_contract,
                    &prepared_storage_boundary_contract,
                ),
            )
            .await
        {
            Ok(loaded) => loaded,
            Err(error) => {
                return Err(rollback_after_store_error("auth_core.runtime.load", tx, error).await);
            }
        };
        if let Err(error) = loaded_state_contract.validate_loaded_state(&loaded) {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        let Some(session) = live_authenticated_session_record_for_lifecycle_request(now, &loaded)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
        else {
            if let Err(error) = tx.rollback().await {
                return Err(AuthPostgresWebRuntimeExecutionError::store(
                    PostgresAuthStoreError::Database(error),
                ));
            }
            return Ok(AuthWebRuntimeExecution::new(
                Outcome::NeedsFullAuthentication,
                AuthSetCookieHeaders::default(),
            ));
        };
        if let Some(outcome) = lifecycle_step_up_freshness_outcome(now, session, step_up_freshness)
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let pending_action = match self
            .store
            .load_pending_subject_lifecycle_action_for_cancellation_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(pending_action)) => pending_action,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_out_of_band_identifier_change_cancellation",
                    tx,
                    Error::PendingSubjectLifecycleActionNotCancellable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_out_of_band_identifier_change_cancellation",
                    tx,
                    error,
                )
                .await);
            }
        };
        if pending_action.subject_id != session.subject_id {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_pending_out_of_band_identifier_change_cancellation_subject",
                tx,
                Error::CredentialLifecycleActionNotAuthorized,
            )
            .await);
        }
        let command = Command::CancelPendingOutOfBandIdentifierChange(
            CancelPendingOutOfBandIdentifierChange {
                now,
                pending_action,
            },
        );
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            command,
            presented_cookies,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.authenticated_pending_out_of_band_identifier_change_cancellation",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }
}
