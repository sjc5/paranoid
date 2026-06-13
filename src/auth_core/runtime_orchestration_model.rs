use std::cmp::min;
use std::fmt;

use http::HeaderMap;

use super::prelude::*;

/// Storage adapter used by the internal web runtime facade.
pub(crate) trait AuthRuntimeStorageAdapter: AtomicCommitAdapter {
    /// Loads and classifies the state required by one prepared command.
    fn load_state(&mut self, request: AuthLoadStateRequest<'_>)
    -> Result<LoadedState, Self::Error>;
}

/// State-load request passed to a runtime storage adapter.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthLoadStateRequest<'a> {
    now: UnixSeconds,
    presented_cookies: &'a PresentedAuthCookies,
    presented_cookie_secrets: &'a PresentedAuthCookieSecrets,
    loaded_state_contract: &'a CommandLoadedStateContract,
    prepared_storage_boundary_contract: &'a PreparedStorageBoundaryContract,
}

impl<'a> AuthLoadStateRequest<'a> {
    pub(crate) fn new(
        now: UnixSeconds,
        presented_cookies: &'a PresentedAuthCookies,
        presented_cookie_secrets: &'a PresentedAuthCookieSecrets,
        loaded_state_contract: &'a CommandLoadedStateContract,
        prepared_storage_boundary_contract: &'a PreparedStorageBoundaryContract,
    ) -> Self {
        Self {
            now,
            presented_cookies,
            presented_cookie_secrets,
            loaded_state_contract,
            prepared_storage_boundary_contract,
        }
    }

    /// Returns the command timestamp used for time-sensitive classification.
    pub(crate) const fn now(&self) -> UnixSeconds {
        self.now
    }

    /// Returns reducer-visible presented cookie metadata.
    pub(crate) fn presented_cookies(&self) -> &PresentedAuthCookies {
        self.presented_cookies
    }

    /// Returns presented cookie credential secrets for MAC comparison.
    pub(crate) fn presented_cookie_secrets(&self) -> &PresentedAuthCookieSecrets {
        self.presented_cookie_secrets
    }

    /// Returns the state contract that the loaded snapshot must satisfy.
    pub(crate) fn loaded_state_contract(&self) -> &CommandLoadedStateContract {
        self.loaded_state_contract
    }

    /// Returns the storage-boundary contract for loading this command.
    pub(crate) fn prepared_storage_boundary_contract(&self) -> &PreparedStorageBoundaryContract {
        self.prepared_storage_boundary_contract
    }
}

/// Web runtime that executes one auth command end to end.
#[derive(Debug)]
pub(crate) struct AuthWebRuntime {
    config: Config,
    web_transport: AuthWebTransport,
}

impl AuthWebRuntime {
    /// Creates a web runtime from core config and web transport.
    pub(crate) fn new(config: Config, web_transport: AuthWebTransport) -> Self {
        Self {
            config,
            web_transport,
        }
    }

    /// Returns the core configuration.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the web transport used by this runtime.
    pub(crate) fn web_transport(&self) -> &AuthWebTransport {
        &self.web_transport
    }

    /// Resolves request auth state with runtime-owned fresh values.
    pub(crate) fn execute_request_resolution_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: ResolveRequestInput,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let command = Command::ResolveRequest(ResolveRequest {
            now: request.now,
            request_kind: request.request_kind,
            fresh_session_id: Some(generate_auth_id().map_err(AuthWebRuntimeExecutionError::core)?),
        });
        self.execute_decoded(decoded, command, adapter)
    }

    /// Starts an active-proof attempt bound to the current session.
    pub(crate) fn execute_current_session_active_proof_attempt_start_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: StartCurrentSessionActiveProofAttemptInput,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let command = Command::StartActiveProofAttemptForCurrentSession(
            StartActiveProofAttemptForCurrentSession {
                now: request.now,
                attempt_id: generate_auth_id().map_err(AuthWebRuntimeExecutionError::core)?,
                proof_use: request.proof_use,
            },
        );
        self.execute_decoded(decoded, command, adapter)
    }

    /// Starts an active-proof attempt bound to the current trusted-device credential.
    pub(crate) fn execute_current_trusted_device_active_proof_attempt_start_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: StartCurrentTrustedDeviceActiveProofAttemptInput,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let command = Command::StartActiveProofAttemptForCurrentTrustedDevice(
            StartActiveProofAttemptForCurrentTrustedDevice {
                now: request.now,
                attempt_id: generate_auth_id().map_err(AuthWebRuntimeExecutionError::core)?,
                proof_use: request.proof_use,
            },
        );
        self.execute_decoded(decoded, command, adapter)
    }

    /// Completes full authentication with runtime-owned session and trusted-device ids.
    pub(crate) fn execute_full_authentication_completion_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: CompleteFullAuthenticationInput,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                request.now,
                ProofUse::ContributeToFullAuthentication,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        let trust_device = match request.trust_device {
            Some(trust_device) => Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: generate_auth_id()
                    .map_err(AuthWebRuntimeExecutionError::core)?,
                display_label: trust_device.display_label,
            }),
            None => None,
        };
        let command = Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: request.now,
            attempt_id,
            fresh_session_id: generate_auth_id().map_err(AuthWebRuntimeExecutionError::core)?,
            trust_device,
        });
        self.execute_decoded(decoded, command, adapter)
    }

    /// Completes step-up after validating the runtime-owned active-proof continuation.
    pub(crate) fn execute_step_up_completion_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: CompleteStepUpInput,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                request.now,
                ProofUse::SatisfyStepUp,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        self.execute_decoded(
            decoded,
            Command::CompleteStepUp(CompleteStepUp {
                now: request.now,
                attempt_id,
            }),
            adapter,
        )
    }

    /// Completes trusted-device revival with a runtime-owned session id.
    pub(crate) fn execute_trusted_device_revival_completion_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: CompleteTrustedDeviceRevivalWithActiveProofInput,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let attempt_id =
            super::active_proof_support::require_active_proof_continuation_for_use_before_state_load(
                decoded.presented_cookies(),
                request.now,
                ProofUse::ReviveTrustedDeviceWithActiveProof,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?
            .attempt_id
            .clone();
        let command = Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: request.now,
                attempt_id,
                fresh_session_id: generate_auth_id().map_err(AuthWebRuntimeExecutionError::core)?,
            },
        );
        self.execute_decoded(decoded, command, adapter)
    }

    /// Executes one auth command from HTTP request headers.
    pub(crate) fn execute_from_headers<A>(
        &self,
        headers: &HeaderMap,
        command: Command,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        if let Some(error) = command.direct_web_runtime_rejection() {
            return Err(AuthWebRuntimeExecutionError::core(error));
        }
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        self.execute_decoded(decoded, command, adapter)
    }

    /// Executes out-of-band active-proof challenge issuance with runtime-owned fast-fail cookie construction.
    pub(crate) fn execute_out_of_band_challenge_issue_from_headers<A>(
        &self,
        headers: &HeaderMap,
        request: IssueOutOfBandChallengeInput,
        response_secret: &ActiveProofChallengeResponseSecret,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let continuation =
            super::active_proof_support::require_active_proof_continuation_before_state_load(
                decoded.presented_cookies(),
                request.now,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let replaceable_created_at_or_before = request
            .now
            .checked_sub_duration(self.config.out_of_band_challenge_replacement_cooldown);
        let request = request.into_request(
            continuation.attempt_id.clone(),
            generate_auth_id().map_err(AuthWebRuntimeExecutionError::core)?,
            replaceable_created_at_or_before,
        );
        let now = request.now;
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let loaded_state_contract =
            CommandLoadedStateContract::for_out_of_band_challenge_issue_request(
                &self.config,
                &request,
                &presented_cookies,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_loaded_state_contract(&loaded_state_contract);
        let loaded = adapter
            .load_state(AuthLoadStateRequest::new(
                now,
                &presented_cookies,
                &presented_cookie_secrets,
                &loaded_state_contract,
                &prepared_storage_boundary_contract,
            ))
            .map_err(AuthWebRuntimeExecutionError::load_state)?;
        loaded_state_contract
            .validate_loaded_state(&loaded)
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let attempt = loaded.active_proof_attempt_record.as_ref().ok_or_else(|| {
            AuthWebRuntimeExecutionError::core(Error::LoadedStateDoesNotSatisfyLoadContract(
                "required active-proof attempt record is missing",
            ))
        })?;
        let proof = request.method.verified_proof_summary();
        let expires_at = min(
            now.checked_add_duration(self.config.out_of_band_challenge_lifetime)
                .map_err(AuthWebRuntimeExecutionError::core)?,
            attempt.expires_at,
        );
        let challenge_cookie = ActiveProofChallengeCookieDraft::new_with_response_secret(
            self.web_transport.active_proof_challenge_fast_fail_keyset(),
            ActiveProofChallengeCookieContext::new(
                request.attempt_id.clone(),
                request.challenge_id.clone(),
                proof,
                now,
                expires_at,
                ActiveProofChallengeFastFailNonce::generate()
                    .map_err(AuthWebRuntimeExecutionError::core)?,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?,
            response_secret,
        )
        .map_err(AuthWebRuntimeExecutionError::core)?;
        let command = Command::IssueOutOfBandChallenge(
            request.into_command_with_stateless_fast_fail_cookie(challenge_cookie, Vec::new()),
        );
        let prepared = PreparedCommandExecution::prepare(&self.config, command, presented_cookies)
            .map_err(AuthWebRuntimeExecutionError::core)?;
        if prepared.loaded_state_contract() != &loaded_state_contract {
            return Err(AuthWebRuntimeExecutionError::core(
                Error::RuntimeLoadedStateContractChangedAfterCookieConstruction,
            ));
        }
        self.execute_prepared_with_loaded(
            prepared,
            prepared_storage_boundary_contract,
            loaded,
            presented_cookie_secrets,
            adapter,
        )
    }

    /// Executes an out-of-band active-proof response after stateless fast-fail verification.
    pub(crate) fn execute_out_of_band_challenge_response_from_headers<A>(
        &self,
        headers: &HeaderMap,
        response: CompleteOutOfBandChallengeResponse,
        weak_proof_gate_verifier: &(impl WeakProofGateVerifier + ?Sized),
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let now = response.now;
        let decoded = self
            .web_transport
            .decode_presented_cookies_from_headers(headers)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        let challenge_cookie = decoded
            .presented_cookies()
            .active_proof_challenge_cookie
            .as_ref()
            .ok_or(Error::MissingActiveProofChallengeCookie)
            .map_err(AuthWebRuntimeExecutionError::core)?;
        challenge_cookie
            .validate_for_out_of_band_completion_before_state_load(now)
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let verified_proof =
            VerifiedActiveProof::from_summary(challenge_cookie.proof.clone(), None)
                .map_err(AuthWebRuntimeExecutionError::core)?;
        let weak_proof_gate =
            super::active_proof_support::verify_weak_proof_gate_before_state_load(
                now,
                &challenge_cookie.proof,
                response.weak_proof_gate_response.as_ref(),
                None,
                weak_proof_gate_verifier,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let mut command = CompleteActiveProofChallenge {
            now,
            attempt_id: challenge_cookie.attempt_id.clone(),
            challenge_id: Some(challenge_cookie.challenge_id.clone()),
            verified_proof,
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate,
            method_commit_work: Vec::new(),
        };
        command.stateless_fast_fail = challenge_cookie
            .verify_response_secret_before_state_load(
                self.web_transport.active_proof_challenge_fast_fail_keyset(),
                now,
                &command,
                &response.secret_response,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?;
        self.execute_decoded(
            decoded,
            Command::CompleteActiveProofChallenge(command),
            adapter,
        )
    }

    fn execute_decoded<A>(
        &self,
        decoded: DecodedAuthWebCookies,
        command: Command,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
        let now = command.now();
        let prepared = PreparedCommandExecution::prepare(&self.config, command, presented_cookies)
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let prepared_storage_boundary_contract =
            PreparedStorageBoundaryContract::for_prepared_command(&prepared);
        match prepared_storage_boundary_contract.boundary_before_reduce() {
            StorageBoundaryBeforeReduce::None => {
                let loaded = loaded_state_from_presented_cookies(prepared.presented_cookies());
                self.execute_prepared_with_loaded(
                    prepared,
                    prepared_storage_boundary_contract,
                    loaded,
                    presented_cookie_secrets,
                    adapter,
                )
            }
            StorageBoundaryBeforeReduce::OpenBeforeStateLoad => {
                let loaded = adapter
                    .load_state(AuthLoadStateRequest::new(
                        now,
                        prepared.presented_cookies(),
                        &presented_cookie_secrets,
                        prepared.loaded_state_contract(),
                        &prepared_storage_boundary_contract,
                    ))
                    .map_err(AuthWebRuntimeExecutionError::load_state)?;
                prepared
                    .loaded_state_contract()
                    .validate_loaded_state(&loaded)
                    .map_err(AuthWebRuntimeExecutionError::core)?;
                self.execute_prepared_with_loaded(
                    prepared,
                    prepared_storage_boundary_contract,
                    loaded,
                    presented_cookie_secrets,
                    adapter,
                )
            }
        }
    }

    fn execute_prepared_with_loaded<A>(
        &self,
        prepared: PreparedCommandExecution,
        prepared_storage_boundary_contract: PreparedStorageBoundaryContract,
        loaded: LoadedState,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
        adapter: &mut A,
    ) -> Result<AuthWebRuntimeExecution, AuthWebRuntimeExecutionError<A::Error>>
    where
        A: AuthRuntimeStorageAdapter,
    {
        let now = prepared.command().now();
        let planned = prepared
            .reduce_loaded_state(&self.config, &loaded)
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let planned_storage_boundary_contract =
            PlannedStorageBoundaryContract::for_planned_execution(
                &prepared_storage_boundary_contract,
                &planned,
            )
            .map_err(AuthWebRuntimeExecutionError::core)?;
        let materialized = planned
            .complete_with_commit_adapter_and_storage_boundary_and_materialize_response(
                adapter,
                planned_storage_boundary_contract,
                presented_cookie_secrets,
            )
            .map_err(AuthWebRuntimeExecutionError::from_runtime_adapter_error)?;
        let (outcome, materialized_response_effects) = materialized.into_parts();
        let set_cookie_headers = self
            .web_transport
            .render_set_cookie_headers(now, materialized_response_effects)
            .map_err(AuthWebRuntimeExecutionError::web)?;
        Ok(AuthWebRuntimeExecution::new(outcome, set_cookie_headers))
    }
}

/// Completed web runtime execution.
#[derive(Debug)]
pub(crate) struct AuthWebRuntimeExecution {
    outcome: Outcome,
    set_cookie_headers: AuthSetCookieHeaders,
    post_commit_method_response_material: PostCommitMethodResponseMaterial,
}

impl AuthWebRuntimeExecution {
    pub(crate) fn new(outcome: Outcome, set_cookie_headers: AuthSetCookieHeaders) -> Self {
        Self {
            outcome,
            set_cookie_headers,
            post_commit_method_response_material: PostCommitMethodResponseMaterial::empty(),
        }
    }

    pub(crate) fn prepend_set_cookie_headers(&mut self, headers: AuthSetCookieHeaders) {
        self.set_cookie_headers.prepend(headers);
    }

    pub(crate) fn append_post_commit_method_response_material(
        &mut self,
        material: PostCommitMethodResponseMaterial,
    ) -> Result<(), Error> {
        self.post_commit_method_response_material.append(material)
    }

    /// Returns the semantic reducer outcome.
    pub(crate) fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Returns rendered `Set-Cookie` headers.
    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        &self.set_cookie_headers
    }

    pub(crate) fn post_commit_method_response_material(&self) -> &PostCommitMethodResponseMaterial {
        &self.post_commit_method_response_material
    }

    pub(crate) fn into_post_commit_method_response_material(
        self,
    ) -> PostCommitMethodResponseMaterial {
        self.post_commit_method_response_material
    }

    pub(crate) fn into_response_projection_parts(
        self,
    ) -> (AuthSetCookieHeaders, PostCommitMethodResponseMaterial) {
        (
            self.set_cookie_headers,
            self.post_commit_method_response_material,
        )
    }

    /// Consumes the execution result.
    pub(crate) fn into_parts(self) -> (Outcome, AuthSetCookieHeaders) {
        (self.outcome, self.set_cookie_headers)
    }
}

/// Response-only projection of a committed web runtime execution.
#[derive(Debug)]
pub(crate) struct AuthWebRuntimeResponseProjection {
    #[cfg(not(test))]
    set_cookie_headers: AuthSetCookieHeaders,
    #[cfg(not(test))]
    post_commit_method_response_material: PostCommitMethodResponseMaterial,
    #[cfg(test)]
    runtime_execution: AuthWebRuntimeExecution,
}

impl AuthWebRuntimeResponseProjection {
    pub(crate) fn from_runtime_execution(runtime_execution: AuthWebRuntimeExecution) -> Self {
        #[cfg(not(test))]
        {
            let (set_cookie_headers, post_commit_method_response_material) =
                runtime_execution.into_response_projection_parts();
            Self {
                set_cookie_headers,
                post_commit_method_response_material,
            }
        }
        #[cfg(test)]
        {
            Self { runtime_execution }
        }
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        #[cfg(not(test))]
        {
            &self.set_cookie_headers
        }
        #[cfg(test)]
        {
            self.runtime_execution.set_cookie_headers()
        }
    }

    pub(crate) fn post_commit_method_response_material(&self) -> &PostCommitMethodResponseMaterial {
        #[cfg(not(test))]
        {
            &self.post_commit_method_response_material
        }
        #[cfg(test)]
        {
            self.runtime_execution
                .post_commit_method_response_material()
        }
    }

    pub(crate) fn into_post_commit_method_response_material(
        self,
    ) -> PostCommitMethodResponseMaterial {
        #[cfg(not(test))]
        {
            self.post_commit_method_response_material
        }
        #[cfg(test)]
        {
            self.runtime_execution
                .into_post_commit_method_response_material()
        }
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        &self.runtime_execution
    }

    #[cfg(test)]
    pub(crate) fn into_runtime_execution(self) -> AuthWebRuntimeExecution {
        self.runtime_execution
    }
}

/// Error returned by web runtime execution.
#[derive(Debug)]
pub(crate) enum AuthWebRuntimeExecutionError<E> {
    /// Core planning or validation failed.
    Core(Error),
    /// Web transport failed to decode or render cookies.
    Web(AuthWebTransportError),
    /// The storage adapter failed while loading required state.
    LoadState(E),
    /// The storage adapter failed while committing atomic work.
    AtomicCommit(E),
}

impl<E> AuthWebRuntimeExecutionError<E> {
    pub(crate) fn core(error: Error) -> Self {
        Self::Core(error)
    }

    pub(crate) fn web(error: AuthWebTransportError) -> Self {
        Self::Web(error)
    }

    pub(crate) fn load_state(error: E) -> Self {
        Self::LoadState(error)
    }

    fn from_runtime_adapter_error(error: RuntimeAdapterExecutionError<E>) -> Self {
        match error {
            RuntimeAdapterExecutionError::Core(error) => Self::Core(error),
            RuntimeAdapterExecutionError::AtomicCommit(error) => Self::AtomicCommit(error),
        }
    }
}

impl<E: fmt::Display> fmt::Display for AuthWebRuntimeExecutionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Web(error) => write!(f, "{error}"),
            Self::LoadState(error) => write!(f, "auth core: state load failed: {error}"),
            Self::AtomicCommit(error) => write!(f, "auth core: atomic commit failed: {error}"),
        }
    }
}

impl<E> std::error::Error for AuthWebRuntimeExecutionError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Web(error) => Some(error),
            Self::LoadState(error) | Self::AtomicCommit(error) => Some(error),
        }
    }
}

fn generate_auth_id<K>() -> Result<Id<K>, Error> {
    Id::generate()
}

fn loaded_state_from_presented_cookies(presented_cookies: &PresentedAuthCookies) -> LoadedState {
    LoadedState {
        session_cookie: presented_cookies.session_cookie.clone(),
        trusted_device_cookie: presented_cookies.trusted_device_cookie.clone(),
        ..LoadedState::default()
    }
}
