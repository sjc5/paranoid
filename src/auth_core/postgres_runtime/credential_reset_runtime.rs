use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn execute_authenticated_credential_reset_planning_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanAuthenticatedCredentialResetInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let reset_policies = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_reset;
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
        if let Some(shared_freshness) =
            reset_policies.role_independent_authenticated_planning_step_up_freshness()
            && let Some(outcome) =
                lifecycle_step_up_freshness_outcome(now, session, shared_freshness)
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let evidence_sources = [LifecycleAuthoritySource::AuthenticatedSession(
            session.session_id.clone(),
        )];
        let lifecycle_context = match self
            .store
            .load_credential_lifecycle_action_context_for_subject_in_current_transaction(
                &mut tx,
                &session.subject_id,
                &request.target_credential_instance_id,
                &evidence_sources,
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        let reset_policy = credential_reset_policy_for_target(reset_policies, &lifecycle_context);
        if reset_policies
            .role_independent_authenticated_planning_step_up_freshness()
            .is_none()
            && let Some(outcome) = lifecycle_step_up_freshness_outcome(
                now,
                session,
                reset_policy.authenticated_planning_step_up_freshness,
            )
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let pending_action = match pending_credential_reset_schedule_from_policy(
            now,
            reset_policy.delayed_action_timing,
        ) {
            Ok(pending_action) => pending_action,
            Err(error) => {
                return Err(
                    rollback_after_runtime_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let command = Command::PlanCredentialReset(PlanCredentialReset {
            now,
            lifecycle_context,
            active_proof_attempt_to_close: None,
            independent_evidence_required: reset_policy.independent_evidence_requirement,
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
            "auth_core.runtime.authenticated_credential_reset_planning",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
        &self,
        headers: &HeaderMap,
        request: ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let reset_policies = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_reset;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_verified_proof_bound_recovery_continuation_before_state_load(
                decoded.presented_cookies(),
                now,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_recover_or_replace_credential_lifecycle_request(
                self.runtime.config(),
                &attempt_id,
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
        let attempt = match super::active_proof::validate_active_proof_attempt_satisfies_use(
            &self.runtime.config().proof_policy,
            &loaded,
            &attempt_id,
            now,
            ProofUse::RecoverOrReplaceCredential,
        ) {
            Ok(attempt) => attempt,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    error,
                )
                .await);
            }
        };
        let evidence_sources =
            match lifecycle_authority_sources_from_satisfied_proofs(&attempt.satisfied_proofs) {
                Ok(sources) => sources,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.derive_lifecycle_evidence",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let active_proof_attempt_to_close = attempt.clone();
        let lifecycle_context = match self
            .load_credential_lifecycle_context_for_unauthenticated_reset_method_in_current_transaction(
                &mut tx,
                &request.target_method,
                &active_proof_attempt_to_close,
                &evidence_sources,
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        if let Err(error) = super::active_proof::ensure_active_proof_attempt_matches_subject(
            &active_proof_attempt_to_close,
            lifecycle_context.target_credential().subject_id(),
        ) {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_recovery_attempt_subject",
                tx,
                error,
            )
            .await);
        }
        let reset_policy = credential_reset_policy_for_target(reset_policies, &lifecycle_context);
        match lifecycle_context.evaluate_action_at(
            now,
            CredentialLifecycleAction::Reset,
            reset_policy.independent_evidence_requirement,
        ) {
            CredentialLifecycleActionDecision::RequiresDelayedAction => {}
            CredentialLifecycleActionDecision::AuthorizedImmediate => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_reset_scheduling_policy",
                    tx,
                    Error::UnauthenticatedCredentialRecoveryResetSchedulingRequiresDelayedAction,
                )
                .await);
            }
            CredentialLifecycleActionDecision::Rejected => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_reset_scheduling_policy",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
        }
        let pending_action = match pending_credential_reset_schedule_from_policy(
            now,
            reset_policy.delayed_action_timing,
        ) {
            Ok(pending_action) => pending_action,
            Err(error) => {
                return Err(
                    rollback_after_runtime_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let command = Command::PlanCredentialReset(PlanCredentialReset {
            now,
            lifecycle_context,
            active_proof_attempt_to_close: Some(active_proof_attempt_to_close),
            independent_evidence_required: reset_policy.independent_evidence_requirement,
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
            "auth_core.runtime.unauthenticated_credential_reset_scheduling",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_unauthenticated_credential_reset_for_configured_method_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let reset_policies = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_reset;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_verified_proof_bound_recovery_continuation_before_state_load(
                decoded.presented_cookies(),
                now,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_recover_or_replace_credential_lifecycle_request(
                self.runtime.config(),
                &attempt_id,
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
        let attempt = match super::active_proof::validate_active_proof_attempt_satisfies_use(
            &self.runtime.config().proof_policy,
            &loaded,
            &attempt_id,
            now,
            ProofUse::RecoverOrReplaceCredential,
        ) {
            Ok(attempt) => attempt,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    error,
                )
                .await);
            }
        };
        let evidence_sources =
            match lifecycle_authority_sources_from_satisfied_proofs(&attempt.satisfied_proofs) {
                Ok(sources) => sources,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.derive_lifecycle_evidence",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let active_proof_attempt_to_close = attempt.clone();
        let lifecycle_context = match self
            .load_credential_lifecycle_context_for_unauthenticated_reset_method_in_current_transaction(
                &mut tx,
                &request.target_method,
                &active_proof_attempt_to_close,
                &evidence_sources,
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        if let Err(error) = super::active_proof::ensure_active_proof_attempt_matches_subject(
            &active_proof_attempt_to_close,
            lifecycle_context.target_credential().subject_id(),
        ) {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_recovery_attempt_subject",
                tx,
                error,
            )
            .await);
        }
        let reset_policy = credential_reset_policy_for_target(reset_policies, &lifecycle_context);
        let decision = lifecycle_context.evaluate_action_at(
            now,
            CredentialLifecycleAction::Reset,
            reset_policy.independent_evidence_requirement,
        );
        if decision != CredentialLifecycleActionDecision::AuthorizedImmediate {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_recovery_reset_immediate_authority",
                tx,
                Error::CredentialLifecycleActionNotAuthorized,
            )
            .await);
        }
        let method_commit_work = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .build_credential_reset_commit_work(
                        &mut tx,
                        CredentialResetMethodWorkBuildRequest {
                            now,
                            target_credential: lifecycle_context.target_credential(),
                            method_payload: &request.method_payload,
                            authority: CredentialResetMethodWorkAuthority::Immediate {
                                lifecycle_context: &lifecycle_context,
                            },
                        },
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(work) => work,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.build_credential_reset_work",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_credential_reset_work",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now,
            execution_authority: CredentialResetExecutionAuthority::Immediate {
                lifecycle_context,
                independent_evidence_required: reset_policy.independent_evidence_requirement,
            },
            active_proof_attempt_to_close: Some(active_proof_attempt_to_close),
            method_commit_work,
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
            "auth_core.runtime.unauthenticated_credential_reset",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_credential_reset_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteAuthenticatedCredentialResetInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let reset_policies = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_reset;
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
        if let Some(shared_freshness) =
            reset_policies.role_independent_authenticated_execution_step_up_freshness()
            && let Some(outcome) =
                lifecycle_step_up_freshness_outcome(now, session, shared_freshness)
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let evidence_sources = [LifecycleAuthoritySource::AuthenticatedSession(
            session.session_id.clone(),
        )];
        let lifecycle_context = match self
            .store
            .load_credential_lifecycle_action_context_for_subject_in_current_transaction(
                &mut tx,
                &session.subject_id,
                &request.target_credential_instance_id,
                &evidence_sources,
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_credential_lifecycle_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        let reset_policy = credential_reset_policy_for_target(reset_policies, &lifecycle_context);
        if reset_policies
            .role_independent_authenticated_execution_step_up_freshness()
            .is_none()
            && let Some(outcome) = lifecycle_step_up_freshness_outcome(
                now,
                session,
                reset_policy.authenticated_execution_step_up_freshness,
            )
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let method_commit_work = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .build_credential_reset_commit_work(
                        &mut tx,
                        CredentialResetMethodWorkBuildRequest {
                            now,
                            target_credential: lifecycle_context.target_credential(),
                            method_payload: &request.method_payload,
                            authority: CredentialResetMethodWorkAuthority::Immediate {
                                lifecycle_context: &lifecycle_context,
                            },
                        },
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(work) => work,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.build_credential_reset_work",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_credential_reset_work",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now,
            execution_authority: CredentialResetExecutionAuthority::Immediate {
                lifecycle_context,
                independent_evidence_required: reset_policy.independent_evidence_requirement,
            },
            active_proof_attempt_to_close: None,
            method_commit_work,
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
            "auth_core.runtime.authenticated_credential_reset",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_mature_pending_credential_reset_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMaturePendingCredentialResetInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let (target_credential, pending_action) = match self
            .store
            .load_pending_credential_reset_execution_authority_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(authority)) => authority,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_credential_reset",
                    tx,
                    Error::PendingCredentialLifecycleActionNotExecutable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_credential_reset",
                    tx,
                    error,
                )
                .await);
            }
        };
        let method_commit_work = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .build_credential_reset_commit_work(
                        &mut tx,
                        CredentialResetMethodWorkBuildRequest {
                            now,
                            target_credential: &target_credential,
                            method_payload: &request.method_payload,
                            authority: CredentialResetMethodWorkAuthority::MaturePendingAction {
                                pending_action: &pending_action,
                            },
                        },
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(work) => work,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.build_credential_reset_work",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_credential_reset_work",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now,
            execution_authority: CredentialResetExecutionAuthority::MaturePendingAction {
                target_credential,
                pending_action,
            },
            active_proof_attempt_to_close: None,
            method_commit_work,
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
            "auth_core.runtime.mature_pending_credential_reset",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_pending_credential_reset_cancellation_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelAuthenticatedPendingCredentialResetInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let reset_policies = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_reset;
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
        if let Some(shared_freshness) =
            reset_policies.role_independent_authenticated_cancellation_step_up_freshness()
            && let Some(outcome) =
                lifecycle_step_up_freshness_outcome(now, session, shared_freshness)
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let (target_credential, pending_action) = match self
            .store
            .load_pending_credential_reset_for_cancellation_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(authority)) => authority,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_credential_reset_cancellation",
                    tx,
                    Error::PendingCredentialLifecycleActionNotCancellable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_credential_reset_cancellation",
                    tx,
                    error,
                )
                .await);
            }
        };
        if pending_action.subject_id != session.subject_id {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_pending_credential_reset_cancellation_subject",
                tx,
                Error::CredentialLifecycleActionNotAuthorized,
            )
            .await);
        }
        let reset_policy =
            credential_reset_policy_for_loaded_target(reset_policies, &target_credential);
        if reset_policies
            .role_independent_authenticated_cancellation_step_up_freshness()
            .is_none()
            && let Some(outcome) = lifecycle_step_up_freshness_outcome(
                now,
                session,
                reset_policy.authenticated_cancellation_step_up_freshness,
            )
        {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let command = Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
            now,
            target_credential,
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
            "auth_core.runtime.authenticated_pending_credential_reset_cancellation",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }
}
