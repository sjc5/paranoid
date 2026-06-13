use super::*;

impl PostgresAuthWebRuntime {
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
        let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(&challenge_cookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate_binding = WeakProofGateBinding::for_active_method_response(
            &challenge_material,
            &response.response_payload,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                response.now,
                &challenge_cookie.proof,
                response.weak_proof_gate_response.as_ref(),
                Some(&weak_proof_gate_binding),
                self.weak_proof_gate_verifier.as_ref(),
            )
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
        let verified = VerifiedActiveProofMethodResponse::new(verified_proof, method_commit_work)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        if let Some(subject_id) = verified.verified_proof().subject_id()
            && let Err(error) = self
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

    pub(crate) async fn execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
        &self,
        headers: &HeaderMap,
        response: CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
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
        if !challenge_cookie.requires_stateless_fast_fail() {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::StatelessFastFailVerificationRequired,
            ));
        }
        let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(&challenge_cookie)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let method = proof_summary_to_method_declaration(&challenge_cookie.proof)
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        super::active_proof_support::validate_challenge_bound_known_subject_active_proof_method(
            &method,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate_binding =
            WeakProofGateBinding::for_challenge_bound_known_subject_secret_response(
                &challenge_material,
                &response.secret_response,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                response.now,
                &challenge_cookie.proof,
                response.weak_proof_gate_response.as_ref(),
                Some(&weak_proof_gate_binding),
                self.weak_proof_gate_verifier.as_ref(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        self.method_registry()?
            .verify_challenge_bound_known_subject_active_proof_method_response_before_state_load(
                &challenge_material,
                &response,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::method_build)?;

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
                    "challenge-bound known-subject completion requires a subject-bound attempt",
                ),
            )
            .await);
        };
        let verification = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .verify_challenge_bound_known_subject_active_proof_method_response(
                        &mut tx,
                        subject_id,
                        &challenge_material,
                        &response,
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(verified) => verified,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.verify_challenge_bound_known_subject_method",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.verify_challenge_bound_known_subject_method",
                    tx,
                    error,
                )
                .await);
            }
        };
        let command = match command_from_challenge_bound_known_subject_active_proof_method_response(
            response,
            &challenge_cookie,
            method,
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
        let weak_proof_gate_binding = WeakProofGateBinding::for_known_subject_secret_response(
            continuation,
            &response.method.verified_proof_summary(),
            &response.secret_response,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                now,
                &response.method.verified_proof_summary(),
                response.weak_proof_gate_response.as_ref(),
                Some(&weak_proof_gate_binding),
                self.weak_proof_gate_verifier.as_ref(),
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        self.method_registry()?
            .verify_known_subject_active_proof_method_response_before_state_load(
                continuation,
                &response,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::method_build)?;
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

    pub(crate) async fn execute_recovery_credential_active_proof_method_response_from_headers(
        &self,
        headers: &HeaderMap,
        response: CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<AuthWebRuntimeExecution, AuthPostgresWebRuntimeExecutionError> {
        super::active_proof_support::validate_recovery_credential_active_proof_method(
            &response.method,
        )
        .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
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
                ProofUse::RecoverOrReplaceCredential,
            )
            .map_err(AuthPostgresWebRuntimeExecutionError::core)?;
        if continuation.subject_id.is_some() {
            return Err(AuthPostgresWebRuntimeExecutionError::core(
                Error::LoadedStateContradiction(
                    "unauthenticated recovery credential proof requires an unbound active-proof continuation",
                ),
            ));
        }
        let attempt_id = continuation.attempt_id.clone();
        let candidate_subject_id = self
            .method_registry()?
            .resolve_recovery_credential_subject_before_state_load(continuation, &response)
            .map_err(AuthPostgresWebRuntimeExecutionError::method_build)?;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_recovery_credential_active_proof_method_response(
                self.runtime.config(),
                &response,
                &attempt_id,
                &presented_cookies,
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
        {
            let attempt = match super::active_proof_support::loaded_active_attempt(&loaded) {
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
            if let Err(error) =
                super::active_proof_support::validate_active_proof_attempt_id(&attempt_id, attempt)
            {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    error,
                )
                .await);
            }
            if let Err(error) =
                super::active_proof_support::ensure_active_proof_attempt_is_open(now, attempt)
            {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    error,
                )
                .await);
            }
            if attempt.proof_use != ProofUse::RecoverOrReplaceCredential {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    Error::LoadedStateContradiction(
                        "recovery credential completion loaded a different proof use",
                    ),
                )
                .await);
            }
            if attempt.subject_id.is_some() {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    Error::LoadedStateContradiction(
                        "unauthenticated recovery credential proof requires an unbound active-proof attempt",
                    ),
                )
                .await);
            }
            if let Err(error) =
                super::active_proof_support::ensure_active_proof_not_already_satisfied(
                    attempt,
                    ProofFamily::RecoveryCode,
                )
            {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.validate_recovery_attempt",
                    tx,
                    error,
                )
                .await);
            }
        }
        let verification = match self.method_registry() {
            Ok(registry) => {
                match registry
                    .verify_recovery_credential_active_proof_method_response(
                        &mut tx,
                        &candidate_subject_id,
                        &response,
                    )
                    .await
                    .map_err(AuthPostgresWebRuntimeExecutionError::method_build)
                {
                    Ok(verified) => verified,
                    Err(error) => {
                        return Err(rollback_after_runtime_error(
                            "auth_core.runtime.verify_recovery_credential_method",
                            tx,
                            error,
                        )
                        .await);
                    }
                }
            }
            Err(error) => {
                return Err(rollback_after_runtime_error(
                    "auth_core.runtime.verify_recovery_credential_method",
                    tx,
                    error,
                )
                .await);
            }
        };
        if let RecoveryCredentialActiveProofMethodVerification::Accepted(verified) = &verification {
            let Some(subject_id) = verified.verified_proof().subject_id() else {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.verify_recovery_credential_method",
                    tx,
                    Error::LoadedStateContradiction(
                        "recovery credential method did not resolve a subject",
                    ),
                )
                .await);
            };
            if subject_id != &candidate_subject_id {
                return Err(rollback_after_core_error(
                    "auth_core.runtime.verify_recovery_credential_method",
                    tx,
                    Error::LoadedStateContradiction(
                        "recovery credential method resolved a different subject",
                    ),
                )
                .await);
            }
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
                    "auth_core.runtime.load_recovery_subject_revocation",
                    tx,
                    error,
                )
                .await);
            }
        }
        let command = match command_from_recovery_credential_active_proof_method_response(
            response,
            attempt_id,
            candidate_subject_id,
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
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        if prepared_storage_boundary_contract.boundary_before_reduce()
            != StorageBoundaryBeforeReduce::OpenBeforeStateLoad
        {
            return Err(rollback_after_core_error(
                "auth_core.runtime.plan_storage_boundary",
                tx,
                Error::LoadedStateContradiction(
                    "recovery credential completion unexpectedly avoided loaded-state boundary",
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
}
