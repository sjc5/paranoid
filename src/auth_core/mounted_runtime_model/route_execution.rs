use super::*;

impl<'a> MountedAuthPostgresRouteService<'a> {
    pub(super) async fn handle_collected_http_request_after_guard_and_render_committed_response(
        &self,
        request: Request<Vec<u8>>,
        guarded_route: MountedAuthGuardedRoute,
        now: UnixSeconds,
    ) -> Result<Response<Vec<u8>>, MountedAuthRouteServiceError> {
        let response = self
            .handle_collected_http_request_after_guard_for_route_body_projection(
                request,
                guarded_route,
                now,
            )
            .await?;
        Ok(render_mounted_auth_route_response(response))
    }

    async fn handle_collected_http_request_after_guard_for_route_body_projection(
        &self,
        request: Request<Vec<u8>>,
        guarded_route: MountedAuthGuardedRoute,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        let (parts, body) = request.into_parts();
        match guarded_route {
            MountedAuthGuardedRoute::FullAuthentication(endpoint) => {
                let body = full_authentication_submitted_body_from_collected_http_request(
                    endpoint,
                    &parts.headers,
                    body,
                )?;
                self.handle_submitted_full_authentication_request(parts, body, endpoint, now)
                    .await
            }
            MountedAuthGuardedRoute::NoSessionCredentialRecovery(no_session_endpoint) => {
                let body = no_session_recovery_submitted_body_from_collected_http_request(
                    no_session_endpoint.endpoint(),
                    &parts.headers,
                    body,
                )?;
                self.handle_submitted_no_session_recovery_request(
                    parts,
                    body,
                    no_session_endpoint,
                    now,
                )
                .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialInventory => {
                parse_mounted_auth_empty_body(body, "authenticated credential inventory body")?;
                self.handle_submitted_credential_inventory_request(parts, now)
                    .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialAddition(route) => {
                let body = credential_addition_submitted_body_from_collected_http_request(
                    &parts.headers,
                    body,
                )?;
                self.handle_submitted_credential_addition_request(parts, body, route, now)
                    .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialReset(endpoint) => {
                let body =
                    authenticated_credential_reset_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_credential_reset_request(parts, body, endpoint, now)
                    .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialReplacement(endpoint) => {
                let body =
                    authenticated_credential_replacement_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_credential_replacement_request(parts, body, endpoint, now)
                    .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialRemoval(endpoint) => {
                let body =
                    authenticated_credential_removal_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_credential_removal_request(parts, body, endpoint, now)
                    .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialRegeneration(endpoint) => {
                let body =
                    authenticated_credential_regeneration_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_credential_regeneration_request(parts, body, endpoint, now)
                    .await
            }
            MountedAuthGuardedRoute::AuthenticatedCredentialRotation(endpoint) => {
                let body =
                    authenticated_credential_rotation_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_credential_rotation_request(parts, body, endpoint, now)
                    .await
            }
            MountedAuthGuardedRoute::DelayedCredentialLifecycle(endpoint) => {
                let body = delayed_credential_lifecycle_submitted_body_from_collected_http_request(
                    endpoint,
                    &parts.headers,
                    body,
                )?;
                self.handle_submitted_delayed_credential_lifecycle_request(
                    parts, body, endpoint, now,
                )
                .await
            }
            MountedAuthGuardedRoute::AuthenticatedOutOfBandIdentifierChange(endpoint) => {
                let body =
                    authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_out_of_band_identifier_change_request(
                    parts, body, endpoint, now,
                )
                .await
            }
            MountedAuthGuardedRoute::DelayedOutOfBandIdentifierChange(endpoint) => {
                let body =
                    delayed_out_of_band_identifier_change_submitted_body_from_collected_http_request(
                        endpoint,
                        &parts.headers,
                        body,
                    )?;
                self.handle_submitted_delayed_out_of_band_identifier_change_request(
                    parts, body, endpoint, now,
                )
                .await
            }
            MountedAuthGuardedRoute::DelayedSubjectAuthStateDeletion(endpoint) => {
                let body = subject_auth_state_deletion_submitted_body_from_collected_http_request(
                    endpoint,
                    &parts.headers,
                    body,
                )?;
                self.handle_submitted_subject_auth_state_deletion_request(
                    parts, body, endpoint, now,
                )
                .await
            }
            MountedAuthGuardedRoute::AdminSupport(endpoint) => {
                let body = admin_support_submitted_body_from_collected_http_request(
                    endpoint,
                    &parts.headers,
                    body,
                )?;
                self.handle_submitted_admin_support_request(parts, body, endpoint, now)
                    .await
            }
        }
    }

    async fn handle_submitted_full_authentication_request(
        &self,
        parts: http::request::Parts,
        body: MountedFullAuthenticationSubmittedRouteBody,
        endpoint: MountedFullAuthenticationEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        let configured_method = self
            .services
            .config()
            .full_authentication_out_of_band_method()
            .ok_or(MountedAuthRuntimeError::FullAuthenticationOutOfBandMethodNotConfigured)?
            .clone();
        let runtime = self.services.postgres_runtime();
        let execution = match (endpoint, body) {
            (
                MountedFullAuthenticationEndpoint::StartOutOfBandChallenge,
                MountedFullAuthenticationSubmittedRouteBody::StartOutOfBandChallenge {
                    method_payload,
                    preflight_gate_kind,
                    preflight_gate_method_label,
                    preflight_gate_payload,
                },
            ) => {
                let preflight_response = ChallengeIssuePreflightResponse::try_from_bytes(
                    preflight_gate_kind,
                    preflight_gate_method_label,
                    preflight_gate_payload,
                )
                .map_err(MountedCredentialLifecycleServiceError::Core)?;
                let request = StartAndIssueMethodDerivedOutOfBandChallengeInput {
                    now,
                    proof_use: ProofUse::ContributeToFullAuthentication,
                    method: configured_method,
                    method_payload,
                };
                match runtime
                    .execute_method_derived_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
                        &parts.headers,
                        request,
                        preflight_response,
                    )
                    .await
                {
                    Ok(execution) => execution,
                    Err(error)
                        if auth_postgres_error_is_live_open_out_of_band_dedupe_collision(
                            &error,
                        ) =>
                    {
                        return mounted_full_authentication_duplicate_start_response(runtime, now);
                    }
                    Err(error) => {
                        return Err(MountedCredentialLifecycleServiceError::from(error).into());
                    }
                }
            }
            (
                MountedFullAuthenticationEndpoint::SubmitOutOfBandProof,
                MountedFullAuthenticationSubmittedRouteBody::SubmitOutOfBandProof {
                    secret_response,
                    weak_proof_gate_response,
                },
            ) => {
                return handle_full_authentication_out_of_band_proof_submission_route(
                    runtime,
                    &parts.headers,
                    now,
                    weak_proof_gate_response,
                    secret_response,
                )
                .await;
            }
            (
                MountedFullAuthenticationEndpoint::CompleteFullAuthentication,
                MountedFullAuthenticationSubmittedRouteBody::CompleteFullAuthentication {
                    trust_device,
                    trusted_device_display_label,
                },
            ) => {
                let request = CompleteFullAuthenticationInput {
                    now,
                    trust_device: trust_device.then_some(TrustDeviceAfterFullAuthenticationInput {
                        display_label: trusted_device_display_label,
                    }),
                };
                runtime
                    .execute_full_authentication_completion_from_headers(&parts.headers, request)
                    .await
                    .map_err(MountedCredentialLifecycleServiceError::from)?
            }
            (endpoint, body) => {
                return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                    route_kind: match endpoint {
                        MountedFullAuthenticationEndpoint::StartOutOfBandChallenge => {
                            "full_authentication_start_out_of_band"
                        }
                        MountedFullAuthenticationEndpoint::SubmitOutOfBandProof => {
                            "full_authentication_submit_out_of_band_proof"
                        }
                        MountedFullAuthenticationEndpoint::CompleteFullAuthentication => {
                            "full_authentication_complete"
                        }
                    },
                    body_kind: match body {
                        MountedFullAuthenticationSubmittedRouteBody::StartOutOfBandChallenge {
                            ..
                        } => "full_authentication_start_out_of_band",
                        MountedFullAuthenticationSubmittedRouteBody::SubmitOutOfBandProof {
                            ..
                        } => "full_authentication_submit_out_of_band_proof",
                        MountedFullAuthenticationSubmittedRouteBody::CompleteFullAuthentication {
                            ..
                        } => "full_authentication_complete",
                    },
                });
            }
        };
        let execution = MountedFullAuthenticationRouteExecution::from_runtime_execution(execution)?;
        let set_cookie_headers = execution.set_cookie_headers().clone();
        let body = execution.route_response_body();
        let mut response = Response::new(MountedAuthRouteResponseBody::FullAuthentication(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_selected_no_session_recovery_request(
        &self,
        parts: http::request::Parts,
        body: MountedNoSessionCredentialRecoveryEndpointRequestBody,
        no_session_endpoint: MountedAuthRouteGuardedNoSessionRecoveryEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        let request = Request::from_parts(parts, body);
        let response = self
            .services
            .configured_no_session_credential_recovery_routes()?
            .handle_selected_recovery_endpoint_request_after_mounted_auth_route_guard(
                request,
                no_session_endpoint,
                now,
            )
            .await?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            MountedAuthRouteResponseBody::NoSessionCredentialRecovery(body),
        ))
    }

    async fn handle_submitted_no_session_recovery_request(
        &self,
        parts: http::request::Parts,
        body: MountedNoSessionCredentialRecoverySubmittedRouteBody,
        no_session_endpoint: MountedAuthRouteGuardedNoSessionRecoveryEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        let route_step = no_session_endpoint.step();
        let body_step = body.step();
        if body_step != route_step {
            return Err(
                MountedCredentialLifecycleServiceError::NoSessionRecoveryRouteBodyMismatch {
                    route_step,
                    body_step,
                }
                .into(),
            );
        }
        let body = body
            .into_endpoint_request_body()
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        self.handle_selected_no_session_recovery_request(parts, body, no_session_endpoint, now)
            .await
    }

    async fn handle_submitted_credential_addition_request(
        &self,
        parts: http::request::Parts,
        body: MountedCredentialAdditionSubmittedRouteBody,
        route: MountedCredentialAdditionRoute,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        let request_body = body
            .into_endpoint_request_body()
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let request = request_body.into_route_request(now);
        let execution =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime())
                .execute_authenticated_credential_addition_from_headers(
                    &parts.headers,
                    route.method_config(),
                    request,
                )
                .await?;
        let set_cookie_headers = execution.set_cookie_headers().clone();
        let body = execution.into_route_response_body_after_commit();
        let mut response =
            Response::new(MountedAuthRouteResponseBody::AuthenticatedCredentialAddition(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_credential_inventory_request(
        &self,
        parts: http::request::Parts,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        let lifecycle_service =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime());
        let outcome = lifecycle_service
            .load_authenticated_credential_inventory_from_headers(&parts.headers, now)
            .await?;
        Ok(Response::new(
            MountedAuthRouteResponseBody::AuthenticatedCredentialInventory(
                MountedCredentialInventoryRouteResponseBody::from_service_outcome(outcome),
            ),
        ))
    }

    async fn handle_submitted_credential_reset_request(
        &self,
        parts: http::request::Parts,
        body: MountedAuthenticatedCredentialResetSubmittedRouteBody,
        endpoint: MountedAuthenticatedCredentialResetEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "authenticated_credential_reset",
                body_kind: "authenticated_credential_reset",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let lifecycle_service =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedAuthenticatedCredentialResetRouteRequest::PlanReset(request) => {
                let execution = lifecycle_service
                    .plan_authenticated_credential_reset_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedAuthenticatedCredentialResetRouteRequest::ExecuteImmediateReset(request) => {
                let execution = lifecycle_service
                    .execute_authenticated_credential_reset_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
        };
        let mut response = Response::new(
            MountedAuthRouteResponseBody::AuthenticatedCredentialReset(body),
        );
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_credential_replacement_request(
        &self,
        parts: http::request::Parts,
        body: MountedAuthenticatedCredentialReplacementSubmittedRouteBody,
        endpoint: MountedAuthenticatedCredentialReplacementEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "authenticated_credential_replacement",
                body_kind: "authenticated_credential_replacement",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let lifecycle_service =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedAuthenticatedCredentialReplacementRouteRequest::PlanReplacement(request) => {
                let execution = lifecycle_service
                    .plan_authenticated_credential_replacement_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedAuthenticatedCredentialReplacementRouteRequest::ExecuteImmediateReplacement(
                request,
            ) => {
                let execution = lifecycle_service
                    .execute_authenticated_credential_replacement_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
        };
        let mut response =
            Response::new(MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_credential_removal_request(
        &self,
        parts: http::request::Parts,
        body: MountedAuthenticatedCredentialRemovalSubmittedRouteBody,
        endpoint: MountedAuthenticatedCredentialRemovalEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "authenticated_credential_removal",
                body_kind: "authenticated_credential_removal",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let lifecycle_service =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedAuthenticatedCredentialRemovalRouteRequest::PlanRemoval(request) => {
                let execution = lifecycle_service
                    .plan_authenticated_credential_removal_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedAuthenticatedCredentialRemovalRouteRequest::ExecuteImmediateRemoval(request) => {
                let execution = lifecycle_service
                    .execute_authenticated_credential_removal_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
        };
        let mut response =
            Response::new(MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_credential_regeneration_request(
        &self,
        parts: http::request::Parts,
        body: MountedAuthenticatedCredentialRegenerationSubmittedRouteBody,
        endpoint: MountedAuthenticatedCredentialRegenerationEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "authenticated_credential_regeneration",
                body_kind: "authenticated_credential_regeneration",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let lifecycle_service =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedAuthenticatedCredentialRegenerationRouteRequest::PlanRegeneration(request) => {
                let execution = lifecycle_service
                    .plan_authenticated_credential_regeneration_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedAuthenticatedCredentialRegenerationRouteRequest::ExecuteImmediateRegeneration(
                request,
            ) => {
                let execution = lifecycle_service
                    .execute_authenticated_credential_regeneration_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                let set_cookie_headers = execution.set_cookie_headers().clone();
                (
                    execution.into_route_response_body_after_commit(),
                    set_cookie_headers,
                )
            }
        };
        let mut response =
            Response::new(MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_credential_rotation_request(
        &self,
        parts: http::request::Parts,
        body: MountedAuthenticatedCredentialRotationSubmittedRouteBody,
        endpoint: MountedAuthenticatedCredentialRotationEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "authenticated_credential_rotation",
                body_kind: "authenticated_credential_rotation",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let lifecycle_service =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedAuthenticatedCredentialRotationRouteRequest::ExecuteImmediateRotation(
                request,
            ) => {
                let execution = lifecycle_service
                    .execute_authenticated_credential_rotation_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
        };
        let mut response =
            Response::new(MountedAuthRouteResponseBody::AuthenticatedCredentialRotation(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_delayed_credential_lifecycle_request(
        &self,
        parts: http::request::Parts,
        body: MountedDelayedCredentialLifecycleSubmittedRouteBody,
        endpoint: MountedDelayedCredentialLifecycleEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "delayed_credential_lifecycle",
                body_kind: "delayed_credential_lifecycle",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedCredentialLifecycleServiceError::Core)?;
        let MountedDelayedCredentialLifecycleRouteRequest::Execute(request) = route_request;
        let execution =
            MountedCredentialLifecyclePostgresService::new(self.services.postgres_runtime())
                .execute_delayed_credential_lifecycle_action_from_headers(&parts.headers, request)
                .await?;
        let body = execution.route_response_body();
        let set_cookie_headers = execution.set_cookie_headers().clone();
        let mut response = Response::new(MountedAuthRouteResponseBody::DelayedCredentialLifecycle(
            body,
        ));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_out_of_band_identifier_change_request(
        &self,
        parts: http::request::Parts,
        body: MountedAuthenticatedOutOfBandIdentifierChangeSubmittedRouteBody,
        endpoint: MountedAuthenticatedOutOfBandIdentifierChangeEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "authenticated_out_of_band_identifier_change",
                body_kind: "authenticated_out_of_band_identifier_change",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedSubjectLifecycleServiceError::Core)?;
        let subject_lifecycle_service =
            MountedSubjectLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest::PlanChange(request) => {
                let execution = subject_lifecycle_service
                    .plan_authenticated_out_of_band_identifier_change_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest::ExecuteImmediateChange(
                request,
            ) => {
                let execution = subject_lifecycle_service
                    .execute_authenticated_out_of_band_identifier_change_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
        };
        let mut response = Response::new(
            MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(body),
        );
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_delayed_out_of_band_identifier_change_request(
        &self,
        parts: http::request::Parts,
        body: MountedDelayedOutOfBandIdentifierChangeSubmittedRouteBody,
        endpoint: MountedDelayedOutOfBandIdentifierChangeEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "delayed_out_of_band_identifier_change",
                body_kind: "delayed_out_of_band_identifier_change",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedSubjectLifecycleServiceError::Core)?;
        let subject_lifecycle_service =
            MountedSubjectLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedDelayedOutOfBandIdentifierChangeRouteRequest::ExecuteChange(request) => {
                let execution = subject_lifecycle_service
                    .execute_out_of_band_identifier_change_from_pending_action_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedDelayedOutOfBandIdentifierChangeRouteRequest::CancelChange(request) => {
                let cancellation = subject_lifecycle_service
                    .cancel_out_of_band_identifier_change_from_pending_action_from_headers(
                        &parts.headers,
                        request,
                    )
                    .await?;
                (
                    cancellation.route_response_body(),
                    cancellation.set_cookie_headers().clone(),
                )
            }
        };
        let mut response =
            Response::new(MountedAuthRouteResponseBody::DelayedOutOfBandIdentifierChange(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_subject_auth_state_deletion_request(
        &self,
        parts: http::request::Parts,
        body: MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody,
        endpoint: MountedDelayedSubjectAuthStateDeletionEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "delayed_subject_auth_state_deletion",
                body_kind: "delayed_subject_auth_state_deletion",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedSubjectLifecycleServiceError::Core)?;
        let subject_lifecycle_service =
            MountedSubjectLifecyclePostgresService::new(self.services.postgres_runtime());
        let (body, set_cookie_headers) = match route_request {
            MountedDelayedSubjectAuthStateDeletionRouteRequest::ScheduleDeletion(request) => {
                let scheduling = subject_lifecycle_service
                    .schedule_subject_auth_state_deletion_from_headers(&parts.headers, request)
                    .await?;
                (
                    scheduling.route_response_body(),
                    scheduling.set_cookie_headers().clone(),
                )
            }
            MountedDelayedSubjectAuthStateDeletionRouteRequest::ExecuteDeletion(request) => {
                let execution = subject_lifecycle_service
                    .execute_subject_auth_state_deletion_from_headers(&parts.headers, request)
                    .await?;
                (
                    execution.route_response_body(),
                    execution.set_cookie_headers().clone(),
                )
            }
            MountedDelayedSubjectAuthStateDeletionRouteRequest::CancelDeletion(request) => {
                let cancellation = subject_lifecycle_service
                    .cancel_subject_auth_state_deletion_from_headers(&parts.headers, request)
                    .await?;
                (
                    cancellation.route_response_body(),
                    cancellation.set_cookie_headers().clone(),
                )
            }
        };
        let mut response =
            Response::new(MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }

    async fn handle_submitted_admin_support_request(
        &self,
        parts: http::request::Parts,
        body: MountedAdminSupportSubmittedRouteBody,
        endpoint: MountedAdminSupportEndpoint,
        now: UnixSeconds,
    ) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
        if body.endpoint() != endpoint {
            return Err(MountedAuthRouteServiceError::RouteBodyMismatch {
                route_kind: "admin_support",
                body_kind: "admin_support",
            });
        }
        let route_request = body
            .into_route_request(now)
            .map_err(MountedAdminSupportServiceError::Core)?;
        let admin_support_service =
            MountedAdminSupportPostgresService::new(self.services.postgres_runtime());
        let staff_authorizer = self.services.configured_admin_support_staff_authorizer()?;
        let execution = match route_request {
            MountedAdminSupportRouteRequest::RequestIntervention(request) => {
                let verification_request =
                    MountedAdminSupportInterventionRequestVerificationRequest::new(&request);
                let staff_authorization = staff_authorizer
                    .authorize_admin_support_intervention_request(
                        &parts.headers,
                        verification_request,
                    )
                    .await;
                if staff_authorization == MountedAdminSupportStaffAuthorization::Rejected {
                    return Err(MountedAdminSupportServiceError::StaffAuthorizationRejected.into());
                }
                admin_support_service
                    .request_intervention_from_headers(&parts.headers, request)
                    .await?
            }
            MountedAdminSupportRouteRequest::ApproveIntervention(request) => {
                admin_support_service
                    .approve_intervention_from_headers(&parts.headers, request, staff_authorizer)
                    .await?
            }
            MountedAdminSupportRouteRequest::DenyIntervention(request) => {
                admin_support_service
                    .deny_intervention_from_headers(&parts.headers, request, staff_authorizer)
                    .await?
            }
            MountedAdminSupportRouteRequest::ExpireIntervention(request) => {
                admin_support_service
                    .expire_intervention_from_headers(&parts.headers, request)
                    .await?
            }
        };
        let set_cookie_headers = execution.set_cookie_headers().clone();
        let body = execution.route_response_body();
        let mut response = Response::new(MountedAuthRouteResponseBody::AdminSupport(body));
        set_cookie_headers.append_to_headers(response.headers_mut());
        Ok(response)
    }
}

async fn handle_full_authentication_out_of_band_proof_submission_route(
    runtime: &PostgresAuthWebRuntime,
    headers: &HeaderMap,
    now: UnixSeconds,
    weak_proof_gate_response: Option<MountedWeakProofGateSubmittedHttpBody>,
    secret_response: Vec<u8>,
) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
    let weak_proof_gate_response = weak_proof_gate_response
        .map(MountedWeakProofGateSubmittedHttpBody::into_response)
        .transpose()
        .map_err(MountedCredentialLifecycleServiceError::Core)?;
    let response = CompleteOutOfBandChallengeResponse {
        now,
        secret_response: ActiveProofChallengeResponseSecret::try_from_bytes(&secret_response)
            .map_err(MountedCredentialLifecycleServiceError::Core)?,
        weak_proof_gate_response,
    };
    let execution = match runtime
        .execute_out_of_band_challenge_response_from_headers(headers, response)
        .await
    {
        Ok(runtime_execution) => {
            MountedFullAuthenticationRouteExecution::from_runtime_execution(runtime_execution)?
        }
        Err(AuthPostgresWebRuntimeExecutionError::Core(
            Error::StatelessFastFailVerificationFailed,
        )) => MountedFullAuthenticationRouteExecution::from_pre_state_out_of_band_proof_rejection(),
        Err(error) => {
            return Err(MountedCredentialLifecycleServiceError::from(error).into());
        }
    };
    Ok(execution.into_full_authentication_response())
}

fn mounted_full_authentication_duplicate_start_response(
    runtime: &PostgresAuthWebRuntime,
    now: UnixSeconds,
) -> Result<Response<MountedAuthRouteResponseBody>, MountedAuthRouteServiceError> {
    let config = runtime.core_config();
    let challenge_expires_at = now
        .checked_add_duration(config.out_of_band_challenge_lifetime)
        .map_err(MountedCredentialLifecycleServiceError::Core)?;
    let attempt_expires_at = now
        .checked_add_duration(config.active_proof_attempt_lifetime)
        .map_err(MountedCredentialLifecycleServiceError::Core)?;
    let expires_at = if challenge_expires_at <= attempt_expires_at {
        challenge_expires_at
    } else {
        attempt_expires_at
    };
    Ok(Response::new(
        MountedAuthRouteResponseBody::FullAuthentication(
            MountedFullAuthenticationRouteResponseBody::OutOfBandChallengeAccepted { expires_at },
        ),
    ))
}

fn auth_postgres_error_is_live_open_out_of_band_dedupe_collision(
    error: &AuthPostgresWebRuntimeExecutionError,
) -> bool {
    matches!(
        error,
        AuthPostgresWebRuntimeExecutionError::Store(
            super::postgres_store::PostgresAuthStoreError::PreconditionFailed(
                "open out-of-band challenge dedupe key already exists"
            )
        )
    )
}

struct MountedFullAuthenticationRouteExecution {
    response_body: MountedFullAuthenticationRouteResponseBody,
    set_cookie_headers: AuthSetCookieHeaders,
}

impl MountedFullAuthenticationRouteExecution {
    fn from_pre_state_out_of_band_proof_rejection() -> Self {
        Self {
            response_body: MountedFullAuthenticationRouteResponseBody::OutOfBandProofRejected,
            set_cookie_headers: AuthSetCookieHeaders::default(),
        }
    }

    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedCredentialLifecycleServiceError> {
        let response_body = Self::response_body_from_runtime_execution(&runtime_execution)?;
        let response_projection =
            AuthWebRuntimeResponseProjection::from_runtime_execution(runtime_execution);
        debug_assert!(
            response_projection
                .post_commit_method_response_material()
                .is_empty()
        );
        let set_cookie_headers = response_projection.set_cookie_headers().clone();
        Ok(Self {
            response_body,
            set_cookie_headers,
        })
    }

    fn into_full_authentication_response(self) -> Response<MountedAuthRouteResponseBody> {
        let mut response = Response::new(MountedAuthRouteResponseBody::FullAuthentication(
            self.response_body,
        ));
        self.set_cookie_headers
            .append_to_headers(response.headers_mut());
        response
    }

    fn route_response_body(self) -> MountedFullAuthenticationRouteResponseBody {
        self.response_body
    }

    fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        &self.set_cookie_headers
    }

    fn response_body_from_runtime_execution(
        execution: &AuthWebRuntimeExecution,
    ) -> Result<MountedFullAuthenticationRouteResponseBody, MountedCredentialLifecycleServiceError>
    {
        match execution.outcome() {
            Outcome::OutOfBandChallengeIssued { expires_at, .. } => Ok(
                MountedFullAuthenticationRouteResponseBody::OutOfBandChallengeAccepted {
                    expires_at: *expires_at,
                },
            ),
            Outcome::ActiveProofCompleted { .. } => {
                Ok(MountedFullAuthenticationRouteResponseBody::OutOfBandProofAccepted)
            }
            Outcome::ActiveProofFailureRecorded { .. } => {
                Ok(MountedFullAuthenticationRouteResponseBody::OutOfBandProofRejected)
            }
            Outcome::Authenticated(_) => {
                Ok(MountedFullAuthenticationRouteResponseBody::FullAuthenticationCompleted)
            }
            Outcome::NeedsFullAuthentication => {
                Ok(MountedFullAuthenticationRouteResponseBody::FullAuthenticationNotReady)
            }
            _ => Err(MountedCredentialLifecycleServiceError::UnexpectedRuntimeOutcome),
        }
    }
}
