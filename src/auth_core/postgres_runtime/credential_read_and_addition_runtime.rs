use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn load_authenticated_credential_inventory_from_headers(
        &self,
        headers: &HeaderMap,
        now: UnixSeconds,
    ) -> Result<MountedCredentialInventoryServiceOutcome, AuthPostgresWebRuntimeExecutionError>
    {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let Some(session_cookie) = presented_cookies.session_cookie.as_ref() else {
            return Ok(MountedCredentialInventoryServiceOutcome::NeedsFullAuthentication);
        };
        if now >= session_cookie.session_fast_fail_until {
            return Ok(MountedCredentialInventoryServiceOutcome::NeedsFullAuthentication);
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
            return rollback_and_return_credential_inventory_outcome(
                tx,
                MountedCredentialInventoryServiceOutcome::NeedsFullAuthentication,
            )
            .await;
        };
        let credentials = match self
            .store
            .load_active_subject_credential_inventory_in_current_transaction(
                &mut tx,
                &session.subject_id,
            )
            .await
        {
            Ok(credentials) => credentials,
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_credential_inventory",
                    tx,
                    error,
                )
                .await);
            }
        };
        let outcome = match MountedCredentialInventoryServiceOutcome::credentials(credentials) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_credential_inventory",
                    tx,
                    error,
                )
                .await);
            }
        };
        rollback_and_return_credential_inventory_outcome(tx, outcome).await
    }

    pub(crate) async fn execute_authenticated_credential_addition_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteAuthenticatedCredentialAdditionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let credential_kind =
            CredentialInstanceKind::try_from_proof_family(request.method.family())
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let addition_policy = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_addition;
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
            addition_policy.authenticated_execution_step_up_freshness,
        ) {
            return rollback_and_return_outcome(tx, outcome).await;
        }
        let credential_instance_id = generate_auth_id()?;
        let new_credential = match CredentialInstanceMetadata::new(
            credential_instance_id,
            session.subject_id.clone(),
            credential_kind,
            request.method.method_label(),
            request.reset_policy_role,
            CredentialLifecycleState::Active,
        ) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_credential_addition_metadata",
                    tx,
                    error,
                )
                .await);
            }
        };
        let evidence_sources = [LifecycleAuthoritySource::AuthenticatedSession(
            session.session_id.clone(),
        )];
        let presented_evidence = match self
            .store
            .load_lifecycle_authority_evidence_for_sources_in_current_transaction(
                &mut tx,
                &evidence_sources,
            )
            .await
        {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_lifecycle_authority_evidence",
                    tx,
                    error,
                )
                .await);
            }
        };
        let recovery_authorities = request
            .recovery_authority_rules
            .into_iter()
            .map(|rule| rule.into_authority(new_credential.credential_instance_id().clone()))
            .collect::<Vec<_>>();
        let recovery_authority_graph =
            match CredentialRecoveryAuthorityGraph::new(recovery_authorities) {
                Ok(graph) => graph,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.build_credential_addition_authority_graph",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let lifecycle_context = CredentialLifecycleActionContext::new(
            new_credential.clone(),
            recovery_authority_graph,
            presented_evidence,
        );
        let (method_commit_work, post_commit_method_response_material) =
            match self.method_registry() {
                Ok(registry) => {
                    match registry
                        .build_credential_creation_commit_work(
                            &mut tx,
                            CredentialCreationMethodWorkBuildRequest {
                                now,
                                new_credential: &new_credential,
                                method_payload: &request.method_payload,
                            },
                        )
                        .await
                        .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                    {
                        Ok(build) => build.into_parts(),
                        Err(error) => {
                            return Err(rollback_after_runtime_error(
                                "auth_core.runtime.build_credential_creation_work",
                                tx,
                                error,
                            )
                            .await);
                        }
                    }
                }
                Err(error) => {
                    return Err(rollback_after_runtime_error(
                        "auth_core.runtime.build_credential_creation_work",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let command = Command::AddCredential(AddCredential {
            now,
            lifecycle_context,
            independent_evidence_required: addition_policy.independent_evidence_requirement,
            new_credential_authority_ids: request.new_credential_authority_ids,
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
                "auth_core.runtime.authenticated_credential_addition",
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
}
