use super::*;

impl PostgresAuthWebRuntime {
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
        let replaceable_created_at_or_before =
            self.out_of_band_challenge_replaceable_created_at_or_before(request.now);
        let request = request.into_request(
            continuation.attempt_id.clone(),
            generate_auth_id()?,
            replaceable_created_at_or_before,
        );
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
        let replaceable_created_at_or_before =
            self.out_of_band_challenge_replaceable_created_at_or_before(request.now);
        let request = request.into_request(
            attempt_id.clone(),
            generate_auth_id()?,
            replaceable_created_at_or_before,
        );
        self.execute_unbound_out_of_band_challenge_issue_request_from_decoded(
            decoded, proof_use, request,
        )
        .await
    }

    pub(crate) async fn execute_method_derived_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
        &self,
        headers: &HeaderMap,
        request: StartAndIssueMethodDerivedOutOfBandChallengeInput,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        let proof_use = request.proof_use;
        let method = request.method;
        let method_payload = request.method_payload;
        if method.family() != ProofFamily::OutOfBandCode {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::ProofMethodCannotIssueOutOfBandChallenge {
                    family: method.family(),
                },
            ));
        }
        super::active_proof_support::verify_challenge_issue_preflight_before_state_load(
            self.runtime.config(),
            now,
            proof_use,
            &method.verified_proof_summary(),
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
        let challenge_id = generate_auth_id()?;
        let issue_build = self.method_registry().and_then(|registry| {
            registry
                .derive_out_of_band_challenge_start(
                    &method,
                    &PostgresOutOfBandChallengeStartBuildRequest {
                        now,
                        proof_use,
                        attempt_id: &attempt_id,
                        challenge_id: &challenge_id,
                        method_payload: &method_payload,
                    },
                )
                .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
        })?;
        let request = issue_build.into_issue_request(
            now,
            attempt_id,
            challenge_id,
            method,
            self.out_of_band_challenge_replaceable_created_at_or_before(now),
        );
        self.execute_unbound_out_of_band_challenge_issue_request_from_decoded(
            decoded, proof_use, request,
        )
        .await
    }

    async fn execute_unbound_out_of_band_challenge_issue_request_from_decoded(
        &self,
        decoded: DecodedAuthWebCookies,
        proof_use: ProofUse,
        request: IssueOutOfBandChallengeRequest,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let attempt_id = request.attempt_id.clone();
        let mut loaded = loaded_state_from_presented_cookies(decoded.presented_cookies());
        loaded.active_proof_attempt_record = Some(ActiveProofAttemptRecord {
            attempt_id: attempt_id.clone(),
            proof_use,
            subject_id: None,
            satisfied_proofs: Vec::new(),
            weak_proof_failures: 0,
            max_weak_proof_failures: self.runtime.config().max_weak_proof_failures_per_attempt,
            created_at: request.now,
            expires_at: request
                .now
                .checked_add_duration(self.runtime.config().active_proof_attempt_lifetime)
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?,
            closed_at: None,
        });
        let loaded_state_contract =
            CommandLoadedStateContract::for_out_of_band_challenge_issue_request(
                self.runtime.config(),
                &request,
                decoded.presented_cookies(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
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
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let mut execution = self
            .execute_out_of_band_challenge_issue_with_loaded_state_in_current_transaction(
                tx,
                presented_cookies,
                presented_cookie_secrets,
                request,
                loaded_state_contract,
                prepared_storage_boundary_contract,
                loaded,
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
        self.execute_out_of_band_challenge_issue_with_loaded_state_in_current_transaction(
            tx,
            presented_cookies,
            presented_cookie_secrets,
            request,
            loaded_state_contract,
            prepared_storage_boundary_contract,
            loaded,
        )
        .await
    }

    async fn execute_out_of_band_challenge_issue_with_loaded_state_in_current_transaction(
        &self,
        tx: Tx<'_>,
        presented_cookies: PresentedAuthCookies,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
        request: IssueOutOfBandChallengeRequest,
        loaded_state_contract: CommandLoadedStateContract,
        prepared_storage_boundary_contract: PreparedStorageBoundaryContract,
        loaded: LoadedState,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        let now = request.now;
        if let Err(error) = loaded_state_contract.validate_loaded_state(&loaded) {
            return Err(
                rollback_after_core_error("auth_core.runtime.validate_load", tx, error).await,
            );
        }
        let proof = request.method.verified_proof_summary();
        let expires_at = {
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
            match now
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
        let challenge_context = match ActiveProofChallengeCookieContext::new(
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
        ) {
            Ok(context) => context,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_challenge_cookie",
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
            challenge_context,
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
}

impl PostgresAuthWebRuntime {
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
            tx,
            decoded,
            request,
            ActiveProofMethodChallengeIssueKind::NormalActiveMethod,
        )
        .await
    }

    pub(crate) async fn execute_challenge_bound_known_subject_active_proof_method_challenge_issue_from_headers(
        &self,
        headers: &HeaderMap,
        request: IssueChallengeBoundKnownSubjectActiveProofMethodChallengeInput,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        super::active_proof_support::validate_challenge_bound_known_subject_active_proof_method(
            &request.method,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
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
        let request = IssueActiveProofMethodChallengeRequest {
            now: request.now,
            attempt_id: continuation.attempt_id.clone(),
            challenge_id: generate_auth_id()?,
            method: request.method,
            method_challenge_request_payload: request.method_challenge_request_payload,
        };
        let tx = self.begin_runtime_transaction().await?;
        self.execute_active_proof_method_challenge_issue_from_decoded_in_current_transaction(
            tx,
            decoded,
            request,
            ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail,
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
                tx,
                decoded,
                request,
                ActiveProofMethodChallengeIssueKind::NormalActiveMethod,
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
        challenge_issue_kind: ActiveProofMethodChallengeIssueKind,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        match challenge_issue_kind {
            ActiveProofMethodChallengeIssueKind::NormalActiveMethod => {
                let challenge_cookie_kind =
                    MethodAdapterContract::for_method(request.method.clone())
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
            }
            ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail => {
                super::active_proof_support::validate_challenge_bound_known_subject_active_proof_method(
                    &request.method,
                )
                .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
            }
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
        let challenge_bound_subject_id = if challenge_issue_kind
            == ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail
        {
            let Some(subject_id) = attempt.subject_id.as_ref() else {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_load",
                    tx,
                    Error::LoadedStateContradiction(
                        "challenge-bound configured-secret issue requires a subject-bound attempt",
                    ),
                )
                .await);
            };
            Some(subject_id)
        } else {
            None
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
        let challenge_build = match self.method_registry() {
            Ok(registry) => {
                let build_result = match challenge_bound_subject_id {
                    Some(subject_id) => {
                        registry
                            .build_challenge_bound_known_subject_active_proof_method_challenge(
                                &mut tx,
                                &request,
                                subject_id,
                                &challenge_seed,
                            )
                            .await
                    }
                    None => {
                        registry
                            .build_active_proof_method_challenge(&mut tx, &request, &challenge_seed)
                            .await
                    }
                };
                match build_result.map_err(AuthPostgresWebRuntimeExecutionError::method_build) {
                    Ok(challenge_build) => challenge_build,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.build_method_challenge",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
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
        let challenge_context = match ActiveProofChallengeCookieContext::new(
            challenge_seed.attempt_id.clone(),
            challenge_seed.challenge_id.clone(),
            challenge_seed.proof.clone(),
            challenge_seed.issued_at,
            challenge_seed.expires_at,
            challenge_seed.nonce.clone(),
        ) {
            Ok(context) => context,
            Err(error) => {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.build_challenge_cookie",
                    tx,
                    error,
                )
                .await);
            }
        };
        let challenge_cookie = match challenge_issue_kind {
            ActiveProofMethodChallengeIssueKind::NormalActiveMethod => {
                ActiveProofChallengeCookieDraft::new_with_method_challenge_state(
                    challenge_context,
                    method_challenge_state,
                )
            }
            ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail => {
                ActiveProofChallengeCookieDraft::new_with_method_challenge_state_requiring_stateless_fast_fail(
                    challenge_context,
                    method_challenge_state,
                )
            }
        };
        let challenge_cookie = match challenge_cookie {
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
        let command = Command::IssueActiveProofMethodChallenge(IssueActiveProofMethodChallenge {
            now: request.now,
            attempt_id: request.attempt_id,
            challenge_id: request.challenge_id,
            method: request.method,
            challenge_issue_kind,
            challenge_cookie,
            method_challenge,
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
                None,
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
        let resolved_proof = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .resolve_out_of_band_proof(
                        &mut tx,
                        &challenge_cookie.proof,
                        &challenge_cookie.challenge_id,
                        &response,
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(resolution) => resolution,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.resolve_out_of_band_proof",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.resolve_out_of_band_proof",
                    tx,
                    error,
                )
                .await);
            }
        };
        command.verified_proof =
            match resolved_proof.into_verified_proof(challenge_cookie.proof.clone()) {
                Ok(verified_proof) => verified_proof,
                Err(error) => {
                    return Err(rollback_after_core_error(
                        "auth_core.runtime.resolve_out_of_band_proof",
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
}
