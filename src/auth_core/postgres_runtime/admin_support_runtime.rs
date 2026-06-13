use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn execute_admin_support_intervention_request_from_headers(
        &self,
        headers: &HeaderMap,
        request: RequestAdminSupportInterventionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let intervention_lifetime = self
            .runtime
            .config()
            .credential_lifecycle_policy
            .admin_support_intervention
            .intervention_lifetime;
        let expires_at = now
            .checked_add_duration(intervention_lifetime)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let command = Command::RequestAdminSupportIntervention(RequestAdminSupportIntervention {
            now,
            intervention_id: generate_auth_id()?,
            subject_id: request.subject_id,
            target_credential_instance_id: request.target_credential_instance_id,
            action: request.action,
            expires_at,
        });
        let prepared =
            PreparedCommandExecution::prepare(self.runtime.config(), command, presented_cookies)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let tx = self.begin_runtime_transaction().await?;
        self.commit_runtime_owned_prepared_command_inside_open_transaction(
            "auth_core.runtime.admin_support_intervention_request",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn execute_admin_support_intervention_approval_from_headers(
        &self,
        headers: &HeaderMap,
        request: ApproveAdminSupportInterventionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let policy = &self
            .runtime
            .config()
            .credential_lifecycle_policy
            .admin_support_intervention;
        let effective_recovery_authority_ids = policy.effective_recovery_authority_ids.clone();
        let independent_evidence_required = policy.independent_evidence_requirement;
        let delayed_action_timing = policy.delayed_action_timing;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let intervention = match self
            .store
            .load_admin_support_intervention_in_current_transaction(
                &mut tx,
                &request.intervention_id,
            )
            .await
        {
            Ok(Some(intervention)) => intervention,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_admin_support_intervention_approval",
                    tx,
                    Error::AdminSupportInterventionNotApprovable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_admin_support_intervention_approval",
                    tx,
                    error,
                )
                .await);
            }
        };
        let verified_intervention = match intervention.verified_at(now) {
            Ok(verified_intervention) => verified_intervention,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.verify_admin_support_intervention",
                    tx,
                    error,
                )
                .await);
            }
        };
        let evidence = match LifecycleAuthorityEvidence::admin_support_intervention(
            verified_intervention,
            effective_recovery_authority_ids,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_admin_support_evidence",
                    tx,
                    error,
                )
                .await);
            }
        };
        let lifecycle_context = match self
            .store
            .load_credential_lifecycle_action_context_with_evidence_in_current_transaction(
                &mut tx,
                &intervention.target_credential_instance_id,
                vec![evidence],
            )
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_admin_support_lifecycle_context",
                    tx,
                    Error::CredentialLifecycleActionNotAuthorized,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_admin_support_lifecycle_context",
                    tx,
                    error,
                )
                .await);
            }
        };
        let pending_action = match pending_credential_lifecycle_action_schedule_from_policy(
            now,
            delayed_action_timing,
        ) {
            Ok(pending_action) => pending_action,
            Err(error) => {
                return Err(
                    rollback_after_runtime_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
        let command = Command::ApproveAdminSupportIntervention(ApproveAdminSupportIntervention {
            now,
            intervention,
            lifecycle_context,
            independent_evidence_required,
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
            "auth_core.runtime.admin_support_intervention_approval",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn mounted_admin_support_approval_staff_verification_request(
        &self,
        request: &ApproveAdminSupportInterventionInput,
    ) -> Result<MountedAdminSupportStaffVerificationRequest, AuthPostgresWebRuntimeExecutionError>
    {
        let intervention = self
            .load_admin_support_intervention_snapshot_for_mounted_workflow(
                "auth_core.runtime.mounted_admin_support_approval_candidate",
                &request.intervention_id,
                Error::AdminSupportInterventionNotApprovable,
            )
            .await?;
        MountedAdminSupportStaffVerificationRequest::for_open_intervention_approval(
            &intervention,
            request.now,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)
    }

    pub(crate) async fn execute_admin_support_intervention_denial_from_headers(
        &self,
        headers: &HeaderMap,
        request: DenyAdminSupportInterventionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let intervention = match self
            .store
            .load_admin_support_intervention_in_current_transaction(
                &mut tx,
                &request.intervention_id,
            )
            .await
        {
            Ok(Some(intervention)) => intervention,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_admin_support_intervention_denial",
                    tx,
                    Error::AdminSupportInterventionNotDeniable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_admin_support_intervention_denial",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::DenyAdminSupportIntervention(DenyAdminSupportIntervention {
            now,
            intervention,
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
            "auth_core.runtime.admin_support_intervention_denial",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn mounted_admin_support_denial_staff_verification_request(
        &self,
        request: &DenyAdminSupportInterventionInput,
    ) -> Result<MountedAdminSupportStaffVerificationRequest, AuthPostgresWebRuntimeExecutionError>
    {
        let intervention = self
            .load_admin_support_intervention_snapshot_for_mounted_workflow(
                "auth_core.runtime.mounted_admin_support_denial_candidate",
                &request.intervention_id,
                Error::AdminSupportInterventionNotDeniable,
            )
            .await?;
        MountedAdminSupportStaffVerificationRequest::for_open_intervention_denial(
            &intervention,
            request.now,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)
    }

    pub(crate) async fn execute_admin_support_intervention_expiry_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExpireAdminSupportInterventionInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let intervention = match self
            .store
            .load_admin_support_intervention_in_current_transaction(
                &mut tx,
                &request.intervention_id,
            )
            .await
        {
            Ok(Some(intervention)) => intervention,
            Ok(None) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.load_admin_support_intervention_expiry",
                    tx,
                    Error::AdminSupportInterventionNotExpirable,
                )
                .await);
            }
            Err(error) => {
                return Err(rollback_after_store_error(
                    "auth_core.runtime.load_admin_support_intervention_expiry",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ExpireAdminSupportIntervention(ExpireAdminSupportIntervention {
            now,
            intervention,
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
            "auth_core.runtime.admin_support_intervention_expiry",
            now,
            tx,
            prepared,
            presented_cookie_secrets,
        )
        .await
    }

    pub(crate) async fn mounted_admin_support_expiry_cleanup_request(
        &self,
        request: &ExpireAdminSupportInterventionInput,
    ) -> Result<MountedAdminSupportExpiryCleanupRequest, AuthPostgresWebRuntimeExecutionError> {
        let intervention = self
            .load_admin_support_intervention_snapshot_for_mounted_workflow(
                "auth_core.runtime.mounted_admin_support_expiry_candidate",
                &request.intervention_id,
                Error::AdminSupportInterventionNotExpirable,
            )
            .await?;
        MountedAdminSupportExpiryCleanupRequest::from_expired_open_intervention(
            &intervention,
            request.now,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)
    }

    async fn load_admin_support_intervention_snapshot_for_mounted_workflow(
        &self,
        operation: &'static str,
        intervention_id: &AdminSupportInterventionId,
        missing_error: Error,
    ) -> Result<AdminSupportInterventionRecord, AuthPostgresWebRuntimeExecutionError> {
        let mut tx = self.begin_runtime_transaction().await?;
        let intervention = match self
            .store
            .load_admin_support_intervention_in_current_transaction(&mut tx, intervention_id)
            .await
        {
            Ok(Some(intervention)) => intervention,
            Ok(None) => return Err(rollback_after_core_error(operation, tx, missing_error).await),
            Err(error) => return Err(rollback_after_store_error(operation, tx, error).await),
        };
        if let Err(error) = tx.rollback().await {
            return Err(AuthPostgresWebRuntimeExecutionError::store(
                PostgresAuthStoreError::Database(error),
            ));
        }
        Ok(intervention)
    }
}
