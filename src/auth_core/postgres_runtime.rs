use std::cmp::min;
use std::fmt;
use std::sync::Arc;

use http::HeaderMap;

use crate::db::{DbError, Pool, Tx};

use super::postgres_method_runtime::{
    ActiveProofMethodAuthoritativeVerificationContext, ActiveProofMethodPreStateVerification,
    KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError,
    PostgresAuthMethodRegistry, VerifiedActiveProofMethodResponse,
};
use super::postgres_store::{
    PostgresAuthStore, PostgresAuthStoreError, finish_auth_store_transaction,
};
use super::*;

pub(crate) struct PostgresAuthWebRuntime {
    runtime: AuthWebRuntime,
    pool: Pool,
    store: PostgresAuthStore,
    weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
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
        if matches!(command, Command::ResolveRequest(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::RequestResolutionRequiresRuntimeFreshIdGeneration,
            ));
        }
        if matches!(command, Command::StartActiveProofAttempt(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration,
            ));
        }
        if matches!(
            command,
            Command::StartActiveProofAttemptForCurrentSession(_)
                | Command::StartActiveProofAttemptForCurrentTrustedDevice(_)
        ) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration,
            ));
        }
        if matches!(command, Command::CompleteFullAuthentication(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::FullAuthenticationCompletionRequiresRuntimeFreshIdGeneration,
            ));
        }
        if matches!(
            command,
            Command::CompleteTrustedDeviceRevivalWithActiveProof(_)
        ) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::TrustedDeviceRevivalCompletionRequiresRuntimeFreshIdGeneration,
            ));
        }
        if matches!(command, Command::CompleteStepUp(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::StepUpCompletionRequiresRuntimeAttemptContinuation,
            ));
        }
        if matches!(command, Command::IssueOutOfBandChallenge(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::OutOfBandChallengeIssueRequiresRuntimeCookieConstruction,
            ));
        }
        if matches!(command, Command::IssueActiveProofMethodChallenge(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::LoadedStateContradiction(
                    "active-proof method challenge issue requires runtime nonce construction",
                ),
            ));
        }
        if matches!(command, Command::ResendOutOfBandChallenge(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::OutOfBandChallengeResendRequiresRuntimeMethodDispatch,
            ));
        }
        if matches!(command, Command::CompleteActiveProofChallenge(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ActiveProofCompletionRequiresRuntimeMethodDispatch,
            ));
        }
        if matches!(command, Command::RecordActiveProofFailure(_)) {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ActiveProofFailureRequiresRuntimeMethodDispatch,
            ));
        }
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        self.execute_decoded(decoded, command).await
    }

    pub(crate) async fn execute_out_of_band_challenge_issue_from_headers(
        &self,
        headers: &HeaderMap,
        request: IssueOutOfBandChallengeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let continuation =
            super::active_proof_support::require_active_proof_continuation_before_state_load(
                decoded.presented_cookies(),
                request.now,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let request = request.into_request(continuation.attempt_id.clone(), generate_auth_id()?);
        let tx = self.begin_runtime_transaction().await?;
        self.execute_out_of_band_challenge_issue_from_decoded_in_current_transaction(
            tx, decoded, request,
        )
        .await
    }

    pub(crate) async fn execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
        &self,
        headers: &HeaderMap,
        request: StartAndIssueOutOfBandChallengeInput,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let proof_use = request.proof_use;
        super::active_proof_support::verify_challenge_issue_preflight_before_state_load(
            self.runtime.config(),
            request.now,
            proof_use,
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
        let attempt_id = generate_auth_id()?;
        let request = request.into_request(attempt_id.clone(), generate_auth_id()?);
        let mut tx = self.begin_runtime_transaction().await?;
        let start_set_cookie_headers = match self
            .commit_start_active_proof_attempt_in_current_transaction(
                &mut tx,
                decoded.presented_cookies().clone(),
                StartActiveProofAttempt {
                    now: request.now,
                    attempt_id,
                    proof_use,
                    subject_id: None,
                },
            )
            .await
        {
            Ok(headers) => headers,
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.start_and_issue",
                    tx,
                    error,
                )
                .await);
            }
        };
        let mut execution = self
            .execute_out_of_band_challenge_issue_from_decoded_in_current_transaction(
                tx, decoded, request,
            )
            .await?;
        execution.prepend_set_cookie_headers(start_set_cookie_headers);
        Ok(execution)
    }

    async fn execute_out_of_band_challenge_issue_from_decoded_in_current_transaction(
        &self,
        tx: Tx<'_>,
        decoded: DecodedAuthWebCookies,
        request: IssueOutOfBandChallengeRequest,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_out_of_band_challenge_issue_request(
                self.runtime.config(),
                &request,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = tx;
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
        let Some(attempt) = loaded.active_proof_attempt_record.as_ref() else {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_load",
                tx,
                Error::LoadedStateDoesNotSatisfyLoadContract(
                    "required active-proof attempt record is missing",
                ),
            )
            .await);
        };
        let proof = request.method.verified_proof_summary();
        let expires_at = match now
            .checked_add_duration(self.runtime.config().out_of_band_challenge_lifetime)
            .map(|candidate| min(candidate, attempt.expires_at))
        {
            Ok(expires_at) => expires_at,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_challenge_cookie",
                    tx,
                    error,
                )
                .await);
            }
        };
        let (response_secret, method_commit_work) =
            match self.method_registry().and_then(|registry| {
                registry
                    .build_out_of_band_issue(&request)
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
            }) {
                Ok(issue_build) => issue_build.into_parts(),
                Err(error) => {
                    return Err(rollback_after_runtime_error(
                        "auth_core.runtime.build_method_work",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let challenge_cookie = match ActiveProofChallengeCookieDraft::new_with_response_secret(
            self.runtime
                .web_transport()
                .active_proof_challenge_fast_fail_keyset(),
            request.attempt_id.clone(),
            request.challenge_id.clone(),
            proof,
            now,
            expires_at,
            match ActiveProofChallengeFastFailNonce::generate() {
                Ok(nonce) => nonce,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.build_challenge_cookie",
                        tx,
                        error,
                    )
                    .await);
                }
            },
            &response_secret,
        ) {
            Ok(cookie) => cookie,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_challenge_cookie",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::IssueOutOfBandChallenge(
            request
                .into_command_with_stateless_fast_fail_cookie(challenge_cookie, method_commit_work),
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
        if prepared.loaded_state_contract() != &loaded_state_contract {
            return Err(rollback_after_core_error(
                "auth_core.runtime.prepare",
                tx,
                Error::RuntimeLoadedStateContractChangedAfterCookieConstruction,
            )
            .await);
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

    pub(crate) async fn execute_active_proof_method_challenge_issue_from_headers(
        &self,
        headers: &HeaderMap,
        request: IssueActiveProofMethodChallengeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let continuation =
            super::active_proof_support::require_active_proof_continuation_before_state_load(
                decoded.presented_cookies(),
                request.now,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let request = request.into_request(continuation.attempt_id.clone(), generate_auth_id()?);
        let tx = self.begin_runtime_transaction().await?;
        self.execute_active_proof_method_challenge_issue_from_decoded_in_current_transaction(
            tx, decoded, request,
        )
        .await
    }

    pub(crate) async fn execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
        &self,
        headers: &HeaderMap,
        request: StartAndIssueActiveProofMethodChallengeInput,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let proof_use = request.proof_use;
        super::active_proof_support::verify_challenge_issue_preflight_before_state_load(
            self.runtime.config(),
            request.now,
            proof_use,
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
        let attempt_id = generate_auth_id()?;
        let request = request.into_request(attempt_id.clone(), generate_auth_id()?);
        let mut tx = self.begin_runtime_transaction().await?;
        let start_set_cookie_headers = match self
            .commit_start_active_proof_attempt_in_current_transaction(
                &mut tx,
                decoded.presented_cookies().clone(),
                StartActiveProofAttempt {
                    now: request.now,
                    attempt_id,
                    proof_use,
                    subject_id: None,
                },
            )
            .await
        {
            Ok(headers) => headers,
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.start_and_issue",
                    tx,
                    error,
                )
                .await);
            }
        };
        let mut execution = self
            .execute_active_proof_method_challenge_issue_from_decoded_in_current_transaction(
                tx, decoded, request,
            )
            .await?;
        execution.prepend_set_cookie_headers(start_set_cookie_headers);
        Ok(execution)
    }

    async fn execute_active_proof_method_challenge_issue_from_decoded_in_current_transaction(
        &self,
        tx: Tx<'_>,
        decoded: DecodedAuthWebCookies,
        request: IssueActiveProofMethodChallengeRequest,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let challenge_cookie_kind = MethodAdapterContract::for_method(request.method.clone())
            .challenge_cookie()
            .kind();
        if request.method.family() == ProofFamily::OutOfBandCode
            || request.method.semantics().interaction != ProofInteraction::Active
            || challenge_cookie_kind == MethodChallengeCookieKind::NotUsed
        {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ProofMethodCannotIssueActiveProofMethodChallenge {
                    family: request.method.family(),
                },
            ));
        }
        let now = request.now;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_active_proof_method_challenge_issue_request(
                self.runtime.config(),
                &request,
                &presented_cookies,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = tx;
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
        let Some(attempt) = loaded.active_proof_attempt_record.as_ref() else {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_load",
                tx,
                Error::LoadedStateDoesNotSatisfyLoadContract(
                    "required active-proof attempt record is missing",
                ),
            )
            .await);
        };
        let proof = request.method.verified_proof_summary();
        let expires_at = match now
            .checked_add_duration(self.runtime.config().out_of_band_challenge_lifetime)
            .map(|candidate| min(candidate, attempt.expires_at))
        {
            Ok(expires_at) => expires_at,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_challenge_cookie",
                    tx,
                    error,
                )
                .await);
            }
        };
        let nonce = match ActiveProofChallengeFastFailNonce::generate() {
            Ok(nonce) => nonce,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_challenge_cookie",
                    tx,
                    error,
                )
                .await);
            }
        };
        let challenge_seed = ActiveProofMethodChallengeSeed {
            attempt_id: request.attempt_id.clone(),
            challenge_id: request.challenge_id.clone(),
            proof,
            issued_at: now,
            expires_at,
            nonce,
        };
        let challenge_build = match self.method_registry().and_then(|registry| {
            registry
                .build_active_proof_method_challenge(&request, &challenge_seed)
                .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
        }) {
            Ok(challenge_build) => challenge_build,
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_method_challenge",
                    tx,
                    error,
                )
                .await);
            }
        };
        let (method_challenge, method_challenge_state, method_commit_work) =
            challenge_build.into_parts();
        let challenge_cookie =
            match ActiveProofChallengeCookieDraft::new_with_method_challenge_state(
                challenge_seed.attempt_id.clone(),
                challenge_seed.challenge_id.clone(),
                challenge_seed.proof.clone(),
                challenge_seed.issued_at,
                challenge_seed.expires_at,
                challenge_seed.nonce.clone(),
                method_challenge_state,
            ) {
                Ok(cookie) => cookie,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.build_challenge_cookie",
                        tx,
                        error,
                    )
                    .await);
                }
            };
        let command =
            Command::IssueActiveProofMethodChallenge(request.into_command_with_challenge(
                challenge_cookie,
                method_challenge,
                method_commit_work,
            ));
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
        if prepared.loaded_state_contract() != &loaded_state_contract {
            return Err(rollback_after_core_error(
                "auth_core.runtime.prepare",
                tx,
                Error::RuntimeLoadedStateContractChangedAfterCookieConstruction,
            )
            .await);
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

    pub(crate) async fn execute_out_of_band_challenge_resend_from_headers(
        &self,
        headers: &HeaderMap,
        request: ResendOutOfBandChallengeRequest,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let challenge_cookie = decoded
            .presented_cookies()
            .active_proof_challenge_cookie
            .clone()
            .ok_or(Error::MissingActiveProofChallengeCookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        challenge_cookie
            .validate_for_out_of_band_resend_before_state_load(now)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_out_of_band_challenge_resend_request(
                self.runtime.config(),
                &request,
                &challenge_cookie,
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
        let Some(challenge) = loaded.active_proof_challenge_record.as_ref() else {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_load",
                tx,
                Error::LoadedStateDoesNotSatisfyLoadContract(
                    "required active-proof challenge record is missing",
                ),
            )
            .await);
        };
        let method_commit_work = match self.method_registry().and_then(|registry| {
            registry
                .build_out_of_band_resend_commit_work(&request, challenge)
                .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
        }) {
            Ok(method_commit_work) => method_commit_work,
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.build_method_work",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = Command::ResendOutOfBandChallenge(
            request.into_command_with_challenge_cookie(&challenge_cookie, method_commit_work),
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
        if prepared.loaded_state_contract() != &loaded_state_contract {
            return Err(rollback_after_core_error(
                "auth_core.runtime.prepare",
                tx,
                Error::RuntimeLoadedStateContractChangedAfterCookieConstruction,
            )
            .await);
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

    pub(crate) async fn execute_out_of_band_challenge_response_from_headers(
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
        let challenge_cookie = decoded
            .presented_cookies()
            .active_proof_challenge_cookie
            .clone()
            .ok_or(Error::MissingActiveProofChallengeCookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        challenge_cookie
            .validate_for_out_of_band_completion_before_state_load(now)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                now,
                &challenge_cookie.proof,
                response.weak_proof_gate_response.as_ref(),
                self.weak_proof_gate_verifier.as_ref(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let mut command = CompleteActiveProofChallenge {
            now,
            attempt_id: challenge_cookie.attempt_id.clone(),
            challenge_id: Some(challenge_cookie.challenge_id.clone()),
            verified_proof: VerifiedActiveProof::from_summary(challenge_cookie.proof.clone(), None)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?,
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate,
            method_commit_work: Vec::new(),
        };
        command.stateless_fast_fail = challenge_cookie
            .verify_response_secret_before_state_load(
                self.runtime
                    .web_transport()
                    .active_proof_challenge_fast_fail_keyset(),
                now,
                &command,
                &response.secret_response,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut tx = self.begin_runtime_transaction().await?;
        let resolved_subject_id = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .resolve_out_of_band_subject_id(
                        &mut tx,
                        &challenge_cookie.proof,
                        &challenge_cookie.challenge_id,
                        &response,
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(subject_id) => subject_id,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.resolve_out_of_band_subject",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.resolve_out_of_band_subject",
                    tx,
                    error,
                )
                .await);
            }
        };
        command.verified_proof = match VerifiedActiveProof::from_summary(
            challenge_cookie.proof.clone(),
            resolved_subject_id,
        ) {
            Ok(verified_proof) => verified_proof,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.resolve_out_of_band_subject",
                    tx,
                    error,
                )
                .await);
            }
        };
        command.method_commit_work = match self.method_registry().and_then(|registry| {
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
                    "auth_core.runtime.build_method_work",
                    tx,
                    error,
                )
                .await);
            }
        };
        let prepared = match PreparedCommandExecution::prepare(
            self.runtime.config(),
            Command::CompleteActiveProofChallenge(command),
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
                    "out-of-band completion unexpectedly avoided loaded-state boundary",
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

    pub(crate) async fn execute_active_proof_method_response_from_headers(
        &self,
        headers: &HeaderMap,
        response: CompleteActiveProofMethodResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let challenge_cookie = decoded
            .presented_cookies()
            .active_proof_challenge_cookie
            .clone()
            .ok_or(Error::MissingActiveProofChallengeCookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        challenge_cookie
            .validate_for_active_method_completion_before_state_load(response.now)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                response.now,
                &challenge_cookie.proof,
                response.weak_proof_gate_response.as_ref(),
                self.weak_proof_gate_verifier.as_ref(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(&challenge_cookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let verification = self.method_registry().and_then(|registry| {
            registry
                .verify_active_proof_method_response_before_state_load(
                    &challenge_material,
                    &response,
                )
                .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
        })?;
        match verification {
            ActiveProofMethodPreStateVerification::Accepted(verified) => {
                let command = Command::CompleteActiveProofChallenge(
                    command_from_active_proof_method_response(
                        response,
                        &challenge_cookie,
                        weak_proof_gate,
                        verified,
                    ),
                );
                self.execute_decoded(decoded, command).await
            }
            ActiveProofMethodPreStateVerification::AcceptedNeedsAuthoritativeConfirmation(
                verified,
            ) => {
                self.execute_authoritative_active_proof_method_response_from_decoded(
                    decoded,
                    response,
                    challenge_cookie,
                    challenge_material,
                    weak_proof_gate,
                    verified,
                )
                .await
            }
        }
    }

    async fn execute_authoritative_active_proof_method_response_from_decoded(
        &self,
        decoded: DecodedAuthWebCookies,
        response: CompleteActiveProofMethodResponse,
        challenge_cookie: ActiveProofChallengeCookieDraft,
        challenge_material: ActiveProofMethodChallengeMaterial,
        weak_proof_gate: WeakProofGateStatus,
        pre_state_verified: VerifiedActiveProofMethodResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = response.now;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_active_proof_method_authoritative_verification(
                self.runtime.config(),
                &challenge_cookie,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let mut tx = self.begin_runtime_transaction().await?;
        let mut loaded = match self
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
        let authoritative_confirmation = {
            let attempt_record = loaded.active_proof_attempt_record.as_ref().ok_or_else(|| {
                AuthPostgresWebRuntimeExecutionError::core(
                    Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required active-proof attempt record is missing",
                    ),
                )
            })?;
            let challenge_record =
                loaded
                    .active_proof_challenge_record
                    .as_ref()
                    .ok_or_else(|| {
                        AuthPostgresWebRuntimeExecutionError::core(
                            Error::LoadedStateDoesNotSatisfyLoadContract(
                                "required active-proof challenge record is missing",
                            ),
                        )
                    })?;
            let context = ActiveProofMethodAuthoritativeVerificationContext::new(
                &challenge_material,
                attempt_record,
                challenge_record,
            );
            match self.method_registry() {
                Ok(registry) => {
                    match registry
                        .verify_active_proof_method_response_with_authoritative_state(
                            &mut tx,
                            context,
                            &pre_state_verified,
                            &response,
                        )
                        .await
                        .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                    {
                        Ok(verified) => verified,
                        Err(error) => {
                            return Err(rollback_after_runtime_error(
                                "auth_core.runtime.verify_active_method_authoritative",
                                tx,
                                error,
                            )
                            .await);
                        }
                    }
                }
                Err(error) => {
                    return Err(rollback_after_runtime_error(
                        "auth_core.runtime.verify_active_method_authoritative",
                        tx,
                        error,
                    )
                    .await);
                }
            }
        };
        let (verified_proof, mut method_commit_work) = pre_state_verified.into_parts();
        method_commit_work.extend(authoritative_confirmation.into_method_commit_work());
        let verified = VerifiedActiveProofMethodResponse::new(verified_proof, method_commit_work);
        if let Some(subject_id) = verified.verified_proof().subject_id() {
            if let Err(error) = self
                .load_verified_active_proof_subject_revocation_in_current_transaction(
                    &mut tx,
                    now,
                    &presented_cookies,
                    &presented_cookie_secrets,
                    &mut loaded,
                    subject_id,
                )
                .await
            {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.load_verified_subject_revocation",
                    tx,
                    error,
                )
                .await);
            }
        }
        let command =
            Command::CompleteActiveProofChallenge(command_from_active_proof_method_response(
                response,
                &challenge_cookie,
                weak_proof_gate,
                verified,
            ));
        let prepared =
            PreparedCommandExecution::prepare(self.runtime.config(), command, presented_cookies)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        if prepared_storage_boundary_contract.boundary_before_reduce()
            != StorageBoundaryBeforeReduce::OpenBeforeStateLoad
        {
            return Err(rollback_after_core_error(
                "auth_core.runtime.plan_storage_boundary",
                tx,
                Error::LoadedStateContradiction(
                    "active-method authoritative completion unexpectedly avoided loaded-state boundary",
                ),
            )
            .await);
        }
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

    pub(crate) async fn execute_known_subject_active_proof_method_response_from_headers(
        &self,
        headers: &HeaderMap,
        response: CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        super::active_proof_support::validate_known_subject_active_proof_method(&response.method)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let now = response.now;
        let decoded = self
            .runtime
            .web_transport()
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthPostgresWebRuntimeExecutionError::web)?;
        let continuation =
            super::active_proof_support::require_active_proof_continuation_before_state_load(
                decoded.presented_cookies(),
                now,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let attempt_id = continuation.attempt_id.clone();
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                now,
                &response.method.verified_proof_summary(),
                response.weak_proof_gate_response.as_ref(),
                self.weak_proof_gate_verifier.as_ref(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_known_subject_active_proof_method_response(
                self.runtime.config(),
                &response,
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
        let Some(attempt) = loaded.active_proof_attempt_record.as_ref() else {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_load",
                tx,
                Error::LoadedStateDoesNotSatisfyLoadContract(
                    "required active-proof attempt record is missing",
                ),
            )
            .await);
        };
        let Some(subject_id) = attempt.subject_id.as_ref() else {
            return Err(rollback_after_core_error(
                "auth_core.runtime.validate_load",
                tx,
                Error::LoadedStateContradiction(
                    "known-subject active proof requires a subject-bound attempt",
                ),
            )
            .await);
        };
        let verification = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .verify_known_subject_active_proof_method_response(
                        &mut tx, subject_id, &response,
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(verified) => verified,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.verify_known_subject_method",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.verify_known_subject_method",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = match command_from_known_subject_active_proof_method_response(
            response,
            attempt_id,
            weak_proof_gate,
            verification,
        ) {
            Ok(command) => command,
            Err(error) => {
                return Err(
                    rollback_after_core_error("auth_core.runtime.prepare", tx, error).await,
                );
            }
        };
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
        if prepared.loaded_state_contract() != &loaded_state_contract {
            return Err(rollback_after_core_error(
                "auth_core.runtime.prepare",
                tx,
                Error::RuntimeLoadedStateContractChangedAfterCookieConstruction,
            )
            .await);
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
                method: response.method,
                weak_proof_gate,
            }),
        ),
    }
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
