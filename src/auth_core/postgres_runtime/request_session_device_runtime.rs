use super::*;

impl PostgresAuthWebRuntime {
    pub(crate) async fn execute_request_resolution_from_headers(
        &self,
        headers: &HeaderMap,
        request: ResolveRequestInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let command = Command::ResolveRequest(ResolveRequest {
            now: request.now,
            request_kind: request.request_kind,
            fresh_session_id: Some(generate_auth_id()?),
        });
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_current_session_active_proof_attempt_start_from_headers(
        &self,
        headers: &HeaderMap,
        request: StartCurrentSessionActiveProofAttemptInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let command = Command::StartActiveProofAttemptForCurrentSession(
            StartActiveProofAttemptForCurrentSession {
                now: request.now,
                attempt_id: generate_auth_id()?,
                proof_use: request.proof_use,
            },
        );
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_current_trusted_device_active_proof_attempt_start_from_headers(
        &self,
        headers: &HeaderMap,
        request: StartCurrentTrustedDeviceActiveProofAttemptInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let command = Command::StartActiveProofAttemptForCurrentTrustedDevice(
            StartActiveProofAttemptForCurrentTrustedDevice {
                now: request.now,
                attempt_id: generate_auth_id()?,
                proof_use: request.proof_use,
            },
        );
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_unauthenticated_recovery_active_proof_attempt_start_from_headers(
        &self,
        headers: &HeaderMap,
        request: StartUnauthenticatedRecoveryActiveProofAttemptInput,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        super::active_proof_support::validate_recovery_credential_active_proof_method(
            &request.method,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        super::active_proof_support::verify_challenge_issue_preflight_before_state_load(
            self.runtime.config(),
            request.now,
            ProofUse::RecoverOrReplaceCredential,
            &request.method.verified_proof_summary(),
            &preflight_response,
            self.weak_proof_gate_verifier.as_ref(),
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let command = Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: request.now,
            attempt_id: generate_auth_id()?,
            proof_use: ProofUse::RecoverOrReplaceCredential,
            subject_id: None,
        });
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_full_authentication_completion_from_headers(
        &self,
        headers: &HeaderMap,
        request: CompleteFullAuthenticationInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                request.now,
                ProofUse::ContributeToFullAuthentication,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        let trust_device = match request.trust_device {
            Some(trust_device) => Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: generate_auth_id()?,
                display_label: trust_device.display_label,
            }),
            None => None,
        };
        let command = Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: request.now,
            attempt_id,
            fresh_session_id: generate_auth_id()?,
            trust_device,
        });
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_step_up_completion_from_headers(
        &self,
        headers: &HeaderMap,
        request: CompleteStepUpInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                request.now,
                ProofUse::SatisfyStepUp,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        self.execute_decoded(
            decoded,
            Command::CompleteStepUp(CompleteStepUp {
                now: request.now,
                attempt_id,
            }),
        )
        .await
    }

    pub(crate) async fn execute_trusted_device_revival_completion_from_headers(
        &self,
        headers: &HeaderMap,
        request: CompleteTrustedDeviceRevivalWithActiveProofInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                request.now,
                ProofUse::ReviveTrustedDeviceWithActiveProof,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        let command = Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: request.now,
                attempt_id,
                fresh_session_id: generate_auth_id()?,
            },
        );
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_from_headers(
        &self,
        headers: &HeaderMap,
        command: Command,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        if let Some(error) = command.direct_web_runtime_rejection() {
            return Err(AuthPostgresWebRuntimeExecutionError::core(error));
        }
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        self.execute_decoded(decoded, command).await
    }
}
