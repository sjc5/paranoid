use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn execute_mature_pending_credential_lifecycle_action_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMaturePendingCredentialLifecycleActionInput,
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
            .load_pending_credential_lifecycle_action_with_target_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(authority)) => authority,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_credential_lifecycle_action",
                    tx,
                    Error::PendingCredentialLifecycleActionNotExecutable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_credential_lifecycle_action",
                    tx,
                    error,
                )
                .await);
            }
        };
        let replacement_successor = if pending_action.action == CredentialLifecycleAction::Replace {
            let target_recovery_authorities = match self
                .store
                .load_credential_recovery_authorities_for_credential_in_current_transaction(
                    &mut tx,
                    target_credential.credential_instance_id(),
                )
                .await
            {
                Ok(authorities) => authorities,
                Err(error) => {
                    return Err(rollback_after_store_error(
                        "auth_core.runtime.load_credential_recovery_authorities",
                        tx,
                        error,
                    )
                    .await);
                }
            };
            match build_replacement_successor_in_current_transaction(
                &self.store,
                &mut tx,
                &target_credential,
                target_recovery_authorities,
            )
            .await
            {
                Ok(successor) => Some(successor),
                Err(error) => {
                    return Err(rollback_after_runtime_error(
                        "auth_core.runtime.build_credential_replacement_successor",
                        tx,
                        error,
                    )
                    .await);
                }
            }
        } else {
            None
        };
        let (method_commit_work, post_commit_method_response_material) = match pending_action.action
        {
            CredentialLifecycleAction::Replace | CredentialLifecycleAction::Regenerate => {
                let Some(method_payload) = request.method_payload.as_ref() else {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.build_credential_lifecycle_work",
                        tx,
                        Error::CredentialLifecycleExecutionMissingMethodCommitWork,
                    )
                    .await);
                };
                match self.method_registry() {
                    Ok(registry) => {
                        match registry
                            .build_credential_lifecycle_commit_work(
                                &mut tx,
                                CredentialLifecycleMethodWorkBuildRequest {
                                    now,
                                    target_credential: &target_credential,
                                    action: pending_action.action,
                                    replacement_successor: replacement_successor.as_ref(),
                                    method_payload,
                                    authority:
                                        CredentialLifecycleMethodWorkAuthority::MaturePendingAction {
                                            pending_action: &pending_action,
                                        },
                                },
                            )
                            .await
                            .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                        {
                            Ok(build) => build.into_parts(),
                            Err(error) => {
                                return Err(rollback_after_runtime_error(
                                    "auth_core.runtime.build_credential_lifecycle_work",
                                    tx,
                                    error,
                                )
                                .await);
                            }
                        }
                    }
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.build_credential_lifecycle_work",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            CredentialLifecycleAction::Remove => {
                if request.method_payload.is_some() {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.build_credential_lifecycle_work",
                        tx,
                        Error::CredentialLifecycleExecutionUnexpectedMethodCommitWork,
                    )
                    .await);
                }
                (Vec::new(), PostCommitMethodResponseMaterial::empty())
            }
            CredentialLifecycleAction::Reset => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_credential_lifecycle_work",
                    tx,
                    Error::NonResetPendingCredentialLifecycleActionCannotBeReset,
                )
                .await);
            }
            CredentialLifecycleAction::Create
            | CredentialLifecycleAction::Disable
            | CredentialLifecycleAction::Rotate
            | CredentialLifecycleAction::RecoverSubjectAccess => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_credential_lifecycle_work",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
        };
        let command = Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now,
                target_credential,
                pending_action,
                replacement_successor,
                method_commit_work,
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
        let mut execution = self
            .commit_runtime_owned_prepared_command_inside_open_transaction(
                "auth_core.runtime.mature_pending_credential_lifecycle_action",
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

    pub(crate) async fn mounted_delayed_credential_lifecycle_action_execution_request(
        &self,
        request: &ExecuteMountedDelayedCredentialLifecycleActionInput,
    ) -> Result<
        MountedExecutableDelayedCredentialLifecycleAction,
        AuthPostgresWebRuntimeExecutionError,
    > {
        let mut tx = self.begin_runtime_transaction().await?;
        let pending_action = match self
            .store
            .load_pending_credential_lifecycle_action_with_target_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some((_target_credential, pending_action))) => pending_action,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.mounted_delayed_credential_lifecycle_action",
                    tx,
                    Error::PendingCredentialLifecycleActionNotExecutable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.mounted_delayed_credential_lifecycle_action",
                    tx,
                    error,
                )
                .await);
            }
        };
        if let Err(error) = tx.rollback().await {
            return Err(AuthPostgresWebRuntimeExecutionError::store(
                PostgresAuthStoreError::Database(error),
            ));
        }
        MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
            &pending_action,
            request.now,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)
    }

    pub(crate) async fn execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelAuthenticatedPendingCredentialLifecycleActionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let step_up_freshness = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .credential_lifecycle_cancellation_step_up_freshness;
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
        let (target_credential, pending_action) = match self
            .store
            .load_pending_credential_lifecycle_action_with_target_in_current_transaction(
                &mut tx,
                &request.pending_action_id,
            )
            .await
        {
            Ok(Some(authority)) => authority,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_pending_credential_lifecycle_action_cancellation",
                    tx,
                    Error::PendingCredentialLifecycleActionNotCancellable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_pending_credential_lifecycle_action_cancellation",
                    tx,
                    error,
                )
                .await);
            }
        };
        if pending_action.subject_id != session.subject_id {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_pending_credential_lifecycle_action_cancellation_subject",
                tx,
                Error::CredentialLifecycleActionNotAuthorized,
            )
            .await);
        }
        let command = Command::CancelNonResetPendingCredentialLifecycleAction(
            CancelNonResetPendingCredentialLifecycleAction {
                now,
                target_credential,
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
            "auth_core.runtime.authenticated_pending_credential_lifecycle_action_cancellation",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }
}
