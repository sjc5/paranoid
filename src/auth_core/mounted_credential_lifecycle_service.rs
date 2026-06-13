use http::{HeaderMap, Request, Response};

use super::postgres_method_runtime::PostgresAuthMethodBuildError;
use super::postgres_runtime::{AuthPostgresWebRuntimeExecutionError, PostgresAuthWebRuntime};
use super::prelude::*;

/// Mounted execution workflow for credential lifecycle actions.
pub(crate) struct MountedCredentialLifecyclePostgresService<'a> {
    runtime: &'a PostgresAuthWebRuntime,
}

impl<'a> MountedCredentialLifecyclePostgresService<'a> {
    pub(crate) fn new(runtime: &'a PostgresAuthWebRuntime) -> Self {
        Self { runtime }
    }

    pub(crate) async fn load_authenticated_credential_inventory_from_headers(
        &self,
        headers: &HeaderMap,
        now: UnixSeconds,
    ) -> Result<MountedCredentialInventoryServiceOutcome, MountedCredentialLifecycleServiceError>
    {
        Ok(self
            .runtime
            .load_authenticated_credential_inventory_from_headers(headers, now)
            .await?)
    }

    pub(crate) async fn execute_authenticated_credential_addition_from_headers(
        &self,
        headers: &HeaderMap,
        method: &MountedCredentialAdditionMethod,
        request: ExecuteMountedAuthenticatedCredentialAdditionInput,
    ) -> Result<MountedCredentialAdditionServiceExecution, MountedCredentialLifecycleServiceError>
    {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_addition_from_headers(
                headers,
                method.runtime_input(request),
            )
            .await?;
        MountedCredentialAdditionServiceExecution::from_runtime_execution(runtime_execution)
    }

    async fn start_no_session_credential_recovery_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: StartMountedNoSessionCredentialRecoveryInput,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Result<
        MountedUnauthenticatedCredentialRecoveryAttemptStartServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_unauthenticated_recovery_active_proof_attempt_start_from_headers(
                headers,
                flow.start_runtime_input(request),
                preflight_response,
            )
            .await?;
        MountedUnauthenticatedCredentialRecoveryAttemptStartServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    async fn execute_no_session_credential_recovery_route_request_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: MountedNoSessionCredentialRecoveryRouteRequest,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteExecution,
        MountedCredentialLifecycleServiceError,
    > {
        match request {
            MountedNoSessionCredentialRecoveryRouteRequest::StartRecoveryAttempt {
                request,
                preflight_response,
            } => {
                self.start_no_session_credential_recovery_route_from_headers(
                    headers,
                    flow,
                    request,
                    preflight_response,
                )
                .await
            }
            MountedNoSessionCredentialRecoveryRouteRequest::SubmitRecoveryProof { request } => {
                self.complete_no_session_credential_recovery_proof_route_from_headers(
                    headers, flow, request,
                )
                .await
            }
            MountedNoSessionCredentialRecoveryRouteRequest::ScheduleDelayedReset { request } => {
                self.schedule_no_session_credential_recovery_reset_route_from_headers(
                    headers, flow, request,
                )
                .await
            }
            MountedNoSessionCredentialRecoveryRouteRequest::ExecuteImmediateReset { request } => {
                self.execute_no_session_credential_recovery_reset_route_from_headers(
                    headers, flow, request,
                )
                .await
            }
        }
    }

    async fn execute_no_session_credential_recovery_route_request<B>(
        &self,
        request: &Request<B>,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        route_request: MountedNoSessionCredentialRecoveryRouteRequest,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        if route_request.requires_csrf() {
            self.runtime.verify_csrf_request(request)?;
        }
        let execution = self
            .execute_no_session_credential_recovery_route_request_from_headers(
                request.headers(),
                flow,
                route_request,
            )
            .await?;
        self.route_response_with_csrf_handoff_cookie_if_needed(request, execution)
    }

    fn route_response_with_csrf_handoff_cookie_if_needed<B>(
        &self,
        request: &Request<B>,
        execution: MountedNoSessionCredentialRecoveryRouteExecution,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        let mut route_response = execution.into_route_response();
        if route_response.is_recovery_proof_accepted()
            && let Some(header) = self
                .runtime
                .issue_csrf_token_cookie_if_needed_for_request(request)?
        {
            route_response.push_set_cookie_header(header);
        }
        Ok(route_response)
    }

    async fn start_no_session_credential_recovery_http_request(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryStartRouteRequestBody>,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        let (parts, body) = request.into_parts();
        let route_request = body.into_route_request(now);
        let request_without_body = Request::from_parts(parts, ());
        self.execute_no_session_credential_recovery_route_request(
            &request_without_body,
            flow,
            route_request,
        )
        .await
    }

    async fn submit_no_session_credential_recovery_proof_http_request(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryProofRouteRequestBody>,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        let (parts, body) = request.into_parts();
        let route_request = body.into_route_request(now);
        let request_without_body = Request::from_parts(parts, ());
        self.execute_no_session_credential_recovery_route_request(
            &request_without_body,
            flow,
            route_request,
        )
        .await
    }

    async fn schedule_no_session_credential_recovery_reset_http_request(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody>,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        let (parts, body) = request.into_parts();
        let route_request = body.into_route_request(now);
        let request_without_body = Request::from_parts(parts, ());
        self.execute_no_session_credential_recovery_route_request(
            &request_without_body,
            flow,
            route_request,
        )
        .await
    }

    async fn execute_no_session_credential_recovery_reset_http_request(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody>,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        let (parts, body) = request.into_parts();
        let route_request = body.into_route_request(now);
        let request_without_body = Request::from_parts(parts, ());
        self.execute_no_session_credential_recovery_route_request(
            &request_without_body,
            flow,
            route_request,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn execute_no_session_credential_recovery_route_request_and_return_runtime_execution<
        B,
    >(
        &self,
        request: &Request<B>,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        route_request: MountedNoSessionCredentialRecoveryRouteRequest,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteExecution,
        MountedCredentialLifecycleServiceError,
    > {
        if route_request.requires_csrf() {
            self.runtime.verify_csrf_request(request)?;
        }
        self.execute_no_session_credential_recovery_route_request_from_headers(
            request.headers(),
            flow,
            route_request,
        )
        .await
    }

    async fn start_no_session_credential_recovery_route_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: StartMountedNoSessionCredentialRecoveryInput,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let execution = self
            .start_no_session_credential_recovery_from_headers(
                headers,
                flow,
                request,
                preflight_response,
            )
            .await?;
        Ok(
            MountedNoSessionCredentialRecoveryRouteExecution::from_start_service_execution(
                execution,
            ),
        )
    }

    async fn complete_no_session_credential_recovery_proof_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: CompleteMountedNoSessionCredentialRecoveryProofInput,
    ) -> Result<
        MountedUnauthenticatedCredentialRecoveryProofCompletionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_recovery_credential_active_proof_method_response_from_headers(
                headers,
                flow.completion_runtime_input(request),
            )
            .await?;
        MountedUnauthenticatedCredentialRecoveryProofCompletionServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    async fn complete_no_session_credential_recovery_proof_route_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: CompleteMountedNoSessionCredentialRecoveryProofInput,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let execution = match self
            .complete_no_session_credential_recovery_proof_from_headers(headers, flow, request)
            .await
        {
            Ok(execution) => execution,
            Err(MountedCredentialLifecycleServiceError::Runtime(
                AuthPostgresWebRuntimeExecutionError::MethodBuild(
                    PostgresAuthMethodBuildError::PluginRejected {
                        operation: "recovery_credential_active_proof_completion_pre_state",
                        ..
                    },
                ),
            )) => {
                return Ok(
                    MountedNoSessionCredentialRecoveryRouteExecution::from_pre_state_recovery_proof_rejection(),
                );
            }
            Err(error) => return Err(error),
        };
        Ok(
            MountedNoSessionCredentialRecoveryRouteExecution::from_proof_completion_service_execution(
                execution,
            ),
        )
    }

    pub(crate) async fn plan_authenticated_credential_reset_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanMountedAuthenticatedCredentialResetInput,
    ) -> Result<
        MountedCredentialResetPlanningServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_reset_planning_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialResetPlanningServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_authenticated_credential_reset_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedAuthenticatedCredentialResetInput,
    ) -> Result<
        MountedCredentialResetExecutionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_reset_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialResetExecutionServiceExecution::from_runtime_execution(runtime_execution)
    }

    async fn schedule_no_session_credential_recovery_reset_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: ScheduleMountedNoSessionCredentialRecoveryResetInput,
    ) -> Result<
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
                headers,
                flow.schedule_reset_runtime_input(request),
            )
            .await?;
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    async fn schedule_no_session_credential_recovery_reset_route_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: ScheduleMountedNoSessionCredentialRecoveryResetInput,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let execution = self
            .schedule_no_session_credential_recovery_reset_from_headers(headers, flow, request)
            .await?;
        Ok(
            MountedNoSessionCredentialRecoveryRouteExecution::from_reset_scheduling_service_execution(
                execution,
            ),
        )
    }

    async fn execute_no_session_credential_recovery_reset_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: ExecuteMountedNoSessionCredentialRecoveryResetInput,
    ) -> Result<
        MountedUnauthenticatedCredentialRecoveryResetExecutionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
                headers,
                flow.execute_reset_runtime_input(request),
            )
            .await?;
        MountedUnauthenticatedCredentialRecoveryResetExecutionServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    async fn execute_no_session_credential_recovery_reset_route_from_headers(
        &self,
        headers: &HeaderMap,
        flow: &MountedNoSessionCredentialRecoveryFlow,
        request: ExecuteMountedNoSessionCredentialRecoveryResetInput,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let execution = self
            .execute_no_session_credential_recovery_reset_from_headers(headers, flow, request)
            .await?;
        Ok(
            MountedNoSessionCredentialRecoveryRouteExecution::from_reset_execution_service_execution(
                execution,
            ),
        )
    }

    pub(crate) async fn plan_authenticated_credential_replacement_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanMountedAuthenticatedCredentialReplacementInput,
    ) -> Result<
        MountedCredentialReplacementPlanningServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_replacement_planning_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialReplacementPlanningServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    pub(crate) async fn execute_authenticated_credential_replacement_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedAuthenticatedCredentialReplacementInput,
    ) -> Result<
        MountedCredentialReplacementExecutionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_replacement_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialReplacementExecutionServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    pub(crate) async fn plan_authenticated_credential_removal_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanMountedAuthenticatedCredentialRemovalInput,
    ) -> Result<
        MountedCredentialRemovalPlanningServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_removal_planning_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialRemovalPlanningServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_authenticated_credential_removal_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedAuthenticatedCredentialRemovalInput,
    ) -> Result<
        MountedCredentialRemovalExecutionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_removal_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialRemovalExecutionServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn plan_authenticated_credential_regeneration_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanMountedAuthenticatedCredentialRegenerationInput,
    ) -> Result<
        MountedCredentialRegenerationPlanningServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_regeneration_planning_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialRegenerationPlanningServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    pub(crate) async fn execute_authenticated_credential_regeneration_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedAuthenticatedCredentialRegenerationInput,
    ) -> Result<
        MountedCredentialRegenerationExecutionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_regeneration_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialRegenerationExecutionServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    pub(crate) async fn execute_authenticated_credential_rotation_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedAuthenticatedCredentialRotationInput,
    ) -> Result<
        MountedCredentialRotationExecutionServiceExecution,
        MountedCredentialLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_credential_rotation_from_headers(
                headers,
                request.into_runtime_input(),
            )
            .await?;
        MountedCredentialRotationExecutionServiceExecution::from_runtime_execution(
            runtime_execution,
        )
    }

    pub(crate) async fn execute_delayed_credential_lifecycle_action_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedDelayedCredentialLifecycleActionInput,
    ) -> Result<MountedCredentialLifecycleServiceExecution, MountedCredentialLifecycleServiceError>
    {
        let executable_action = self
            .runtime
            .mounted_delayed_credential_lifecycle_action_execution_request(&request)
            .await?;
        let runtime_input = executable_action
            .runtime_execution_input(request)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let runtime_execution = match runtime_input {
            MountedDelayedCredentialLifecycleRuntimeInput::Reset(request) => {
                self.runtime
                    .execute_mature_pending_credential_reset_from_headers(headers, request)
                    .await?
            }
            MountedDelayedCredentialLifecycleRuntimeInput::NonResetCredentialLifecycle(request) => {
                self.runtime
                    .execute_mature_pending_credential_lifecycle_action_from_headers(
                        headers, request,
                    )
                    .await?
            }
        };
        MountedCredentialLifecycleServiceExecution::from_runtime_execution(runtime_execution)
    }
}

/// Mounted route service for one configured no-session recovery flow.
pub(crate) struct MountedNoSessionCredentialRecoveryPostgresRouteService<'a> {
    lifecycle_service: MountedCredentialLifecyclePostgresService<'a>,
    flow: MountedNoSessionCredentialRecoveryFlow,
}

impl<'a> MountedNoSessionCredentialRecoveryPostgresRouteService<'a> {
    pub(crate) fn new(
        runtime: &'a PostgresAuthWebRuntime,
        flow: MountedNoSessionCredentialRecoveryFlow,
    ) -> Self {
        Self {
            lifecycle_service: MountedCredentialLifecyclePostgresService::new(runtime),
            flow,
        }
    }

    #[cfg(test)]
    pub(crate) async fn handle_recovery_endpoint_request(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryEndpointRequestBody>,
        now: UnixSeconds,
    ) -> Result<
        Response<MountedNoSessionCredentialRecoveryRouteResponseBody>,
        MountedCredentialLifecycleServiceError,
    > {
        let endpoint = MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            request.method(),
            request.uri().path(),
        )
        .ok_or_else(|| {
            MountedCredentialLifecycleServiceError::NoSessionRecoveryRouteNotFound {
                method: request.method().clone(),
                path: request.uri().path().to_owned(),
            }
        })?;
        self.handle_selected_recovery_endpoint_request(request, endpoint, now)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn handle_selected_recovery_endpoint_request(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryEndpointRequestBody>,
        endpoint: MountedNoSessionCredentialRecoveryEndpoint,
        now: UnixSeconds,
    ) -> Result<
        Response<MountedNoSessionCredentialRecoveryRouteResponseBody>,
        MountedCredentialLifecycleServiceError,
    > {
        let (request_without_body, route_request) =
            selected_recovery_endpoint_request_parts(request, endpoint, now)?;
        let route_response = self
            .lifecycle_service
            .execute_no_session_credential_recovery_route_request(
                &request_without_body,
                &self.flow,
                route_request,
            )
            .await?;
        Ok(response_from_no_session_recovery_route_response(
            route_response,
        ))
    }

    pub(crate) async fn handle_selected_recovery_endpoint_request_after_mounted_auth_route_guard(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryEndpointRequestBody>,
        guarded_endpoint: MountedAuthRouteGuardedNoSessionRecoveryEndpoint,
        now: UnixSeconds,
    ) -> Result<
        Response<MountedNoSessionCredentialRecoveryRouteResponseBody>,
        MountedCredentialLifecycleServiceError,
    > {
        let (request_without_body, route_request) =
            selected_recovery_endpoint_request_parts(request, guarded_endpoint.endpoint(), now)?;
        let route_execution = self
            .lifecycle_service
            .execute_no_session_credential_recovery_route_request_from_headers(
                request_without_body.headers(),
                &self.flow,
                route_request,
            )
            .await?;
        let route_response = self
            .lifecycle_service
            .route_response_with_csrf_handoff_cookie_if_needed(
                &request_without_body,
                route_execution,
            )?;
        Ok(response_from_no_session_recovery_route_response(
            route_response,
        ))
    }

    #[cfg(test)]
    pub(crate) async fn start_recovery_attempt(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryStartRouteRequestBody>,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        self.lifecycle_service
            .start_no_session_credential_recovery_http_request(request, &self.flow, now)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn submit_recovery_proof(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryProofRouteRequestBody>,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        self.lifecycle_service
            .submit_no_session_credential_recovery_proof_http_request(request, &self.flow, now)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn schedule_delayed_reset(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody>,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        self.lifecycle_service
            .schedule_no_session_credential_recovery_reset_http_request(request, &self.flow, now)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn execute_immediate_reset(
        &self,
        request: Request<MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody>,
        now: UnixSeconds,
    ) -> Result<
        MountedNoSessionCredentialRecoveryRouteResponse,
        MountedCredentialLifecycleServiceError,
    > {
        self.lifecycle_service
            .execute_no_session_credential_recovery_reset_http_request(request, &self.flow, now)
            .await
    }
}

fn selected_recovery_endpoint_request_parts(
    request: Request<MountedNoSessionCredentialRecoveryEndpointRequestBody>,
    endpoint: MountedNoSessionCredentialRecoveryEndpoint,
    now: UnixSeconds,
) -> Result<
    (Request<()>, MountedNoSessionCredentialRecoveryRouteRequest),
    MountedCredentialLifecycleServiceError,
> {
    let (parts, body) = request.into_parts();
    let body_step = body.step();
    let route_step = endpoint.step();
    if body_step != route_step {
        return Err(
            MountedCredentialLifecycleServiceError::NoSessionRecoveryRouteBodyMismatch {
                route_step,
                body_step,
            },
        );
    }
    let route_request = body.into_route_request(now);
    Ok((Request::from_parts(parts, ()), route_request))
}

fn response_from_no_session_recovery_route_response(
    route_response: MountedNoSessionCredentialRecoveryRouteResponse,
) -> Response<MountedNoSessionCredentialRecoveryRouteResponseBody> {
    let mut response = Response::new(route_response.body());
    route_response.append_set_cookie_headers_to(response.headers_mut());
    response
}

/// Route-shaped execution for mounted no-session recovery.
#[derive(Debug)]
pub(crate) struct MountedNoSessionCredentialRecoveryRouteExecution {
    outcome: MountedNoSessionCredentialRecoveryRouteOutcome,
    set_cookie_headers: AuthSetCookieHeaders,
    #[cfg(test)]
    runtime_execution: Option<AuthWebRuntimeExecution>,
}

impl MountedNoSessionCredentialRecoveryRouteExecution {
    fn from_pre_state_recovery_proof_rejection() -> Self {
        Self {
            outcome: MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryProofRejected,
            set_cookie_headers: AuthSetCookieHeaders::default(),
            #[cfg(test)]
            runtime_execution: None,
        }
    }

    fn from_start_service_execution(
        execution: MountedUnauthenticatedCredentialRecoveryAttemptStartServiceExecution,
    ) -> Self {
        #[cfg(not(test))]
        {
            Self {
                outcome: execution.route_outcome(),
                set_cookie_headers: execution.set_cookie_headers().clone(),
            }
        }
        #[cfg(test)]
        {
            let (outcome, runtime_execution) = execution.into_parts();
            Self {
                outcome: MountedNoSessionCredentialRecoveryRouteOutcome::from_start_service_outcome(
                    &outcome,
                ),
                set_cookie_headers: runtime_execution.set_cookie_headers().clone(),
                runtime_execution: Some(runtime_execution),
            }
        }
    }

    fn from_proof_completion_service_execution(
        execution: MountedUnauthenticatedCredentialRecoveryProofCompletionServiceExecution,
    ) -> Self {
        #[cfg(not(test))]
        {
            Self {
                outcome: execution.route_outcome(),
                set_cookie_headers: execution.set_cookie_headers().clone(),
            }
        }
        #[cfg(test)]
        {
            let (outcome, runtime_execution) = execution.into_parts();
            Self {
                outcome:
                    MountedNoSessionCredentialRecoveryRouteOutcome::from_proof_completion_service_outcome(
                        &outcome,
                    ),
                set_cookie_headers: runtime_execution.set_cookie_headers().clone(),
                runtime_execution: Some(runtime_execution),
            }
        }
    }

    fn from_reset_scheduling_service_execution(
        execution: MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceExecution,
    ) -> Self {
        #[cfg(not(test))]
        {
            Self {
                outcome: execution.route_outcome(),
                set_cookie_headers: execution.set_cookie_headers().clone(),
            }
        }
        #[cfg(test)]
        {
            let (outcome, runtime_execution) = execution.into_parts();
            Self {
                outcome:
                    MountedNoSessionCredentialRecoveryRouteOutcome::from_reset_scheduling_service_outcome(
                        &outcome,
                    ),
                set_cookie_headers: runtime_execution.set_cookie_headers().clone(),
                runtime_execution: Some(runtime_execution),
            }
        }
    }

    fn from_reset_execution_service_execution(
        execution: MountedUnauthenticatedCredentialRecoveryResetExecutionServiceExecution,
    ) -> Self {
        #[cfg(not(test))]
        {
            Self {
                outcome: execution.route_outcome(),
                set_cookie_headers: execution.set_cookie_headers().clone(),
            }
        }
        #[cfg(test)]
        {
            let (outcome, runtime_execution) = execution.into_parts();
            Self {
                outcome:
                    MountedNoSessionCredentialRecoveryRouteOutcome::from_reset_execution_service_outcome(
                        &outcome,
                    ),
                set_cookie_headers: runtime_execution.set_cookie_headers().clone(),
                runtime_execution: Some(runtime_execution),
            }
        }
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedNoSessionCredentialRecoveryRouteOutcome {
        &self.outcome
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        match &self.runtime_execution {
            Some(runtime_execution) => runtime_execution,
            None => panic!("pre-state route rejection has no runtime execution"),
        }
    }

    #[cfg(test)]
    pub(crate) fn route_response(&self) -> MountedNoSessionCredentialRecoveryRouteResponse {
        MountedNoSessionCredentialRecoveryRouteResponse {
            outcome: self.outcome.clone(),
            set_cookie_headers: self.set_cookie_headers.clone(),
        }
    }

    pub(crate) fn into_route_response(self) -> MountedNoSessionCredentialRecoveryRouteResponse {
        MountedNoSessionCredentialRecoveryRouteResponse {
            outcome: self.outcome,
            set_cookie_headers: self.set_cookie_headers,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedNoSessionCredentialRecoveryRouteOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.runtime_execution
                .expect("pre-state route rejection has no runtime execution"),
        )
    }
}

/// Mounted no-session recovery response visible to route-shaped code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedNoSessionCredentialRecoveryRouteResponse {
    outcome: MountedNoSessionCredentialRecoveryRouteOutcome,
    set_cookie_headers: AuthSetCookieHeaders,
}

impl MountedNoSessionCredentialRecoveryRouteResponse {
    fn is_recovery_proof_accepted(&self) -> bool {
        matches!(
            self.outcome,
            MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryProofAccepted
        )
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedNoSessionCredentialRecoveryRouteOutcome {
        &self.outcome
    }

    pub(crate) fn body(&self) -> MountedNoSessionCredentialRecoveryRouteResponseBody {
        MountedNoSessionCredentialRecoveryRouteResponseBody::from_route_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        &self.set_cookie_headers
    }

    pub(crate) fn append_set_cookie_headers_to(&self, headers: &mut HeaderMap) {
        self.set_cookie_headers.append_to_headers(headers);
    }

    fn push_set_cookie_header(&mut self, header: AuthSetCookieHeader) {
        self.set_cookie_headers.push(header);
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedNoSessionCredentialRecoveryRouteOutcome,
        AuthSetCookieHeaders,
    ) {
        (self.outcome, self.set_cookie_headers)
    }

    #[cfg(test)]
    pub(crate) fn into_body_and_set_cookie_headers(
        self,
    ) -> (
        MountedNoSessionCredentialRecoveryRouteResponseBody,
        AuthSetCookieHeaders,
    ) {
        (
            MountedNoSessionCredentialRecoveryRouteResponseBody::from_route_outcome(&self.outcome),
            self.set_cookie_headers,
        )
    }
}

type MountedCredentialLifecycleRuntimeResponseProjection = AuthWebRuntimeResponseProjection;

fn generated_recovery_codes_route_response_from_projection(
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
) -> Option<MountedGeneratedRecoveryCodeSetRouteResponseBody> {
    response_projection
        .into_post_commit_method_response_material()
        .into_generated_recovery_codes()
        .map(MountedGeneratedRecoveryCodeSetRouteResponseBody::from_generated_recovery_code_set)
}

fn project_credential_lifecycle_runtime_execution<O>(
    runtime_execution: AuthWebRuntimeExecution,
    derive_outcome: impl FnOnce(&AuthWebRuntimeExecution) -> Option<O>,
) -> Result<
    (O, MountedCredentialLifecycleRuntimeResponseProjection),
    MountedCredentialLifecycleServiceError,
> {
    let outcome = derive_outcome(&runtime_execution)
        .ok_or(MountedCredentialLifecycleServiceError::UnexpectedRuntimeOutcome)?;
    let response_projection =
        MountedCredentialLifecycleRuntimeResponseProjection::from_runtime_execution(
            runtime_execution,
        );
    Ok((outcome, response_projection))
}

/// Completed mounted authenticated credential reset planning.
#[derive(Debug)]
pub(crate) struct MountedCredentialResetPlanningServiceExecution {
    outcome: MountedCredentialResetPlanningServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialResetPlanningServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialResetPlanningServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialResetPlanningServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialResetRouteResponseBody {
        MountedCredentialResetRouteResponseBody::from_planning_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialResetPlanningServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated immediate credential reset.
#[derive(Debug)]
pub(crate) struct MountedCredentialResetExecutionServiceExecution {
    outcome: MountedCredentialResetExecutionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialResetExecutionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialResetExecutionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialResetExecutionServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialResetRouteResponseBody {
        MountedCredentialResetRouteResponseBody::from_execution_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialResetExecutionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted delayed unauthenticated credential recovery reset scheduling.
#[derive(Debug)]
pub(crate) struct MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceExecution {
    outcome: MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    fn route_outcome(&self) -> MountedNoSessionCredentialRecoveryRouteOutcome {
        MountedNoSessionCredentialRecoveryRouteOutcome::from_reset_scheduling_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted unauthenticated immediate credential recovery reset.
#[derive(Debug)]
pub(crate) struct MountedUnauthenticatedCredentialRecoveryResetExecutionServiceExecution {
    outcome: MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedUnauthenticatedCredentialRecoveryResetExecutionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    fn route_outcome(&self) -> MountedNoSessionCredentialRecoveryRouteOutcome {
        MountedNoSessionCredentialRecoveryRouteOutcome::from_reset_execution_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated credential replacement planning.
#[derive(Debug)]
pub(crate) struct MountedCredentialReplacementPlanningServiceExecution {
    outcome: MountedCredentialReplacementPlanningServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialReplacementPlanningServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialReplacementPlanningServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialReplacementPlanningServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialReplacementRouteResponseBody {
        MountedCredentialReplacementRouteResponseBody::from_planning_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialReplacementPlanningServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated immediate credential replacement.
#[derive(Debug)]
pub(crate) struct MountedCredentialReplacementExecutionServiceExecution {
    outcome: MountedCredentialReplacementExecutionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialReplacementExecutionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialReplacementExecutionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialReplacementExecutionServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialReplacementRouteResponseBody {
        MountedCredentialReplacementRouteResponseBody::from_execution_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialReplacementExecutionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated credential removal planning.
#[derive(Debug)]
pub(crate) struct MountedCredentialRemovalPlanningServiceExecution {
    outcome: MountedCredentialRemovalPlanningServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialRemovalPlanningServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialRemovalPlanningServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialRemovalPlanningServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialRemovalRouteResponseBody {
        MountedCredentialRemovalRouteResponseBody::from_planning_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialRemovalPlanningServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated immediate credential removal.
#[derive(Debug)]
pub(crate) struct MountedCredentialRemovalExecutionServiceExecution {
    outcome: MountedCredentialRemovalExecutionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialRemovalExecutionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialRemovalExecutionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialRemovalExecutionServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialRemovalRouteResponseBody {
        MountedCredentialRemovalRouteResponseBody::from_execution_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialRemovalExecutionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated credential-set regeneration planning.
#[derive(Debug)]
pub(crate) struct MountedCredentialRegenerationPlanningServiceExecution {
    outcome: MountedCredentialRegenerationPlanningServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialRegenerationPlanningServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialRegenerationPlanningServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialRegenerationPlanningServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialRegenerationRouteResponseBody {
        MountedCredentialRegenerationRouteResponseBody::from_planning_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialRegenerationPlanningServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated immediate credential-set regeneration.
#[derive(Debug)]
pub(crate) struct MountedCredentialRegenerationExecutionServiceExecution {
    outcome: MountedCredentialRegenerationExecutionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialRegenerationExecutionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialRegenerationExecutionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialRegenerationExecutionServiceOutcome {
        &self.outcome
    }

    pub(crate) fn into_route_response_body_after_commit(
        self,
    ) -> MountedCredentialRegenerationRouteResponseBody {
        let outcome = self.outcome.clone();
        let generated_recovery_codes =
            self.into_generated_recovery_codes_route_response_after_commit();
        MountedCredentialRegenerationRouteResponseBody::from_execution_service_outcome(
            &outcome,
            generated_recovery_codes,
        )
    }

    pub(crate) fn into_generated_recovery_codes_route_response_after_commit(
        self,
    ) -> Option<MountedGeneratedRecoveryCodeSetRouteResponseBody> {
        if matches!(
            self.outcome,
            MountedCredentialRegenerationExecutionServiceOutcome::CredentialRegenerated { .. }
        ) {
            generated_recovery_codes_route_response_from_projection(self.response_projection)
        } else {
            None
        }
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialRegenerationExecutionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated immediate credential rotation.
#[derive(Debug)]
pub(crate) struct MountedCredentialRotationExecutionServiceExecution {
    outcome: MountedCredentialRotationExecutionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialRotationExecutionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialRotationExecutionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialRotationExecutionServiceOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedCredentialRotationRouteResponseBody {
        MountedCredentialRotationRouteResponseBody::from_execution_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialRotationExecutionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated credential addition.
#[derive(Debug)]
pub(crate) struct MountedCredentialAdditionServiceExecution {
    outcome: MountedCredentialAdditionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialAdditionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedCredentialAdditionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedCredentialAdditionServiceOutcome {
        &self.outcome
    }

    pub(crate) fn committed_outcome(&self) -> Option<MountedCredentialAdditionCommittedOutcome> {
        self.outcome.committed_outcome()
    }

    pub(crate) fn into_route_response_body_after_commit(
        self,
    ) -> MountedCredentialAdditionRouteResponseBody {
        let outcome = self.outcome.clone();
        let generated_recovery_codes =
            self.into_generated_recovery_codes_route_response_after_commit();
        match outcome {
            MountedCredentialAdditionServiceOutcome::CredentialAdded { .. } => {
                MountedCredentialAdditionRouteResponseBody::CredentialAdded {
                    generated_recovery_codes,
                }
            }
            MountedCredentialAdditionServiceOutcome::NeedsFullAuthentication => {
                MountedCredentialAdditionRouteResponseBody::NeedsFullAuthentication
            }
            MountedCredentialAdditionServiceOutcome::NeedsStepUp { .. } => {
                MountedCredentialAdditionRouteResponseBody::NeedsStepUp
            }
        }
    }

    pub(crate) fn into_generated_recovery_codes_route_response_after_commit(
        self,
    ) -> Option<MountedGeneratedRecoveryCodeSetRouteResponseBody> {
        if self.outcome.committed_outcome().is_some() {
            generated_recovery_codes_route_response_from_projection(self.response_projection)
        } else {
            None
        }
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedCredentialAdditionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted unauthenticated credential recovery attempt start.
#[derive(Debug)]
pub(crate) struct MountedUnauthenticatedCredentialRecoveryAttemptStartServiceExecution {
    outcome: MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedUnauthenticatedCredentialRecoveryAttemptStartServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    fn route_outcome(&self) -> MountedNoSessionCredentialRecoveryRouteOutcome {
        MountedNoSessionCredentialRecoveryRouteOutcome::from_start_service_outcome(&self.outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted unauthenticated credential recovery proof completion.
#[derive(Debug)]
pub(crate) struct MountedUnauthenticatedCredentialRecoveryProofCompletionServiceExecution {
    outcome: MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedUnauthenticatedCredentialRecoveryProofCompletionServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (outcome, response_projection) = project_credential_lifecycle_runtime_execution(
            runtime_execution,
            MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    fn route_outcome(&self) -> MountedNoSessionCredentialRecoveryRouteOutcome {
        MountedNoSessionCredentialRecoveryRouteOutcome::from_proof_completion_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted delayed credential lifecycle execution.
#[derive(Debug)]
pub(crate) struct MountedCredentialLifecycleServiceExecution {
    committed_outcome: MountedDelayedCredentialLifecycleCommittedOutcome,
    response_projection: MountedCredentialLifecycleRuntimeResponseProjection,
}

impl MountedCredentialLifecycleServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let (committed_outcome, response_projection) =
            project_credential_lifecycle_runtime_execution(
                runtime_execution,
                MountedDelayedCredentialLifecycleCommittedOutcome::from_committed_runtime_execution,
            )?;
        Ok(Self {
            committed_outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn committed_outcome(
        &self,
    ) -> &MountedDelayedCredentialLifecycleCommittedOutcome {
        &self.committed_outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedDelayedCredentialLifecycleRouteResponseBody {
        MountedDelayedCredentialLifecycleRouteResponseBody::from_committed_outcome(
            &self.committed_outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    pub(crate) fn into_generated_recovery_codes_route_response_after_commit(
        self,
    ) -> Option<MountedGeneratedRecoveryCodeSetRouteResponseBody> {
        generated_recovery_codes_route_response_from_projection(self.response_projection)
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedDelayedCredentialLifecycleCommittedOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.committed_outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Error returned by mounted delayed credential lifecycle execution.
#[derive(Debug)]
pub(crate) enum MountedCredentialLifecycleServiceError {
    Runtime(AuthPostgresWebRuntimeExecutionError),
    Core(Error),
    NoSessionRecoveryRouteNotFound {
        method: http::Method,
        path: String,
    },
    NoSessionRecoveryRouteBodyMismatch {
        route_step: MountedNoSessionCredentialRecoveryRouteStep,
        body_step: MountedNoSessionCredentialRecoveryRouteStep,
    },
    UnexpectedRuntimeOutcome,
}

impl From<AuthPostgresWebRuntimeExecutionError> for MountedCredentialLifecycleServiceError {
    fn from(error: AuthPostgresWebRuntimeExecutionError) -> Self {
        Self::Runtime(error)
    }
}

impl std::fmt::Display for MountedCredentialLifecycleServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "{error}"),
            Self::Core(error) => write!(f, "{error}"),
            Self::NoSessionRecoveryRouteNotFound { method, path } => write!(
                f,
                "auth core: no-session credential recovery route not found for {method} {path}"
            ),
            Self::NoSessionRecoveryRouteBodyMismatch {
                route_step,
                body_step,
            } => write!(
                f,
                "auth core: no-session credential recovery route body mismatch: route expects {route_step:?}, body is {body_step:?}"
            ),
            Self::UnexpectedRuntimeOutcome => {
                write!(
                    f,
                    "auth core: unexpected mounted credential lifecycle outcome"
                )
            }
        }
    }
}

impl std::error::Error for MountedCredentialLifecycleServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Core(error) => Some(error),
            Self::NoSessionRecoveryRouteNotFound { .. } => None,
            Self::NoSessionRecoveryRouteBodyMismatch { .. } => None,
            Self::UnexpectedRuntimeOutcome => None,
        }
    }
}
