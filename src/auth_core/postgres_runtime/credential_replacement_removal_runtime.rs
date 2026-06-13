use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn execute_authenticated_credential_replacement_planning_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanAuthenticatedCredentialReplacementInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let replacement_policy = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_replacement;
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
            replacement_policy.authenticated_planning_step_up_freshness,
        ) {
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
        let pending_action = match pending_credential_lifecycle_action_schedule_from_policy(
            now,
            replacement_policy.delayed_action_timing,
        ) {
            Ok(pending_action) => pending_action,
            Err(error) => {
                return Err(
                    rollback_after_runtime_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let command = Command::PlanCredentialReplacement(PlanCredentialReplacement {
            now,
            lifecycle_context,
            independent_evidence_required: replacement_policy.independent_evidence_requirement,
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
            "auth_core.runtime.authenticated_credential_replacement_planning",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_credential_replacement_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteAuthenticatedCredentialReplacementInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let replacement_policy = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_replacement;
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
            replacement_policy.authenticated_execution_step_up_freshness,
        ) {
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
        let replacement_successor = match build_replacement_successor_in_current_transaction(
            &self.store,
            &mut tx,
            lifecycle_context.target_credential(),
            lifecycle_context
                .recovery_authority_graph()
                .authorities()
                .iter()
                .cloned(),
        )
        .await
        {
            Ok(successor) => successor,
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_credential_replacement_successor",
                    tx,
                    error,
                )
                .await);
            }
        };
        let (method_commit_work, post_commit_method_response_material) =
            match self.method_registry() {
                Ok(registry) => {
                    match registry
                        .build_credential_lifecycle_commit_work(
                            &mut tx,
                            CredentialLifecycleMethodWorkBuildRequest {
                                now,
                                target_credential: lifecycle_context.target_credential(),
                                action: CredentialLifecycleAction::Replace,
                                replacement_successor: Some(&replacement_successor),
                                method_payload: &request.method_payload,
                                authority:
                                    CredentialLifecycleMethodWorkAuthority::ImmediateReplacement {
                                        lifecycle_context: &lifecycle_context,
                                    },
                            },
                        )
                        .await
                        .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                    {
                        Ok(build) => build.into_parts(),
                        Err(error) => {
                            return Err(rollback_after_runtime_error(
                                "auth_core.runtime.build_credential_replacement_work",
                                tx,
                                error,
                            )
                            .await);
                        }
                    }
                }
                Err(error) => {
                    return Err(rollback_after_runtime_error(
                        "auth_core.runtime.build_credential_replacement_work",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let command = Command::ExecuteCredentialReplacement(ExecuteCredentialReplacement {
            now,
            execution_authority: CredentialReplacementExecutionAuthority {
                lifecycle_context,
                independent_evidence_required: replacement_policy.independent_evidence_requirement,
            },
            successor: replacement_successor,
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
        let mut execution = self
            .commit_runtime_owned_prepared_command_inside_open_transaction(
                "auth_core.runtime.authenticated_credential_replacement",
                now,
                tx,
                prepared,
                presented_cookie_secrets,
            )
            .await?;
        execution
            .append_post_commit_method_response_material(post_commit_method_response_material)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        Ok(execution)
    }

    pub(crate) async fn execute_authenticated_credential_removal_planning_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanAuthenticatedCredentialRemovalInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let removal_policy = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_removal;
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
            removal_policy.authenticated_planning_step_up_freshness,
        ) {
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
        let pending_action = match pending_credential_lifecycle_action_schedule_from_policy(
            now,
            removal_policy.delayed_action_timing,
        ) {
            Ok(pending_action) => pending_action,
            Err(error) => {
                return Err(
                    rollback_after_runtime_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let command = Command::PlanCredentialRemoval(PlanCredentialRemoval {
            now,
            lifecycle_context,
            independent_evidence_required: removal_policy.independent_evidence_requirement,
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
            "auth_core.runtime.authenticated_credential_removal_planning",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_authenticated_credential_removal_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteAuthenticatedCredentialRemovalInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let removal_policy = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_removal;
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
            removal_policy.authenticated_execution_step_up_freshness,
        ) {
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
        let command = Command::ExecuteCredentialRemoval(ExecuteCredentialRemoval {
            now,
            execution_authority: CredentialRemovalExecutionAuthority {
                lifecycle_context,
                independent_evidence_required: removal_policy.independent_evidence_requirement,
            },
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
            "auth_core.runtime.authenticated_credential_removal",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }
}
