use super::*;

#[tokio::test]
async fn mounted_auth_http_admin_support_routes_use_staff_authorization_and_coarse_outcomes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let request_subject_id: SubjectId = id("mounted-http-support-request-subject");
    let request_target_credential_id = id("mounted-http-support-request-target");
    let approval_subject_id: SubjectId = id("mounted-http-support-approval-subject");
    let approval_target_credential_id = id("mounted-http-support-approval-target");
    let denial_subject_id: SubjectId = id("mounted-http-support-denial-subject");
    let denial_target_credential_id = id("mounted-http-support-denial-target");
    let expiry_subject_id: SubjectId = id("mounted-http-support-expiry-subject");
    let expiry_target_credential_id = id("mounted-http-support-expiry-target");
    for (subject_id, target_credential_id) in [
        (
            request_subject_id.clone(),
            request_target_credential_id.clone(),
        ),
        (
            approval_subject_id.clone(),
            approval_target_credential_id.clone(),
        ),
        (
            denial_subject_id.clone(),
            denial_target_credential_id.clone(),
        ),
        (
            expiry_subject_id.clone(),
            expiry_target_credential_id.clone(),
        ),
    ] {
        seed_admin_support_target_credential_for_runtime_test(
            &harness.pool,
            &harness.store_config,
            subject_id,
            target_credential_id,
            RecoveryAuthorityTiming::Immediate,
            at(10),
        )
        .await;
    }

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let staff_authorizer = Arc::new(RecordingMountedSupportStaffAuthorizer::new(
        MountedAdminSupportStaffAuthorization::Rejected,
    ));
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_admin_support_routes(staff_authorizer.clone()),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for admin support route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value")
        .to_owned();
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1
        .to_owned();

    let request_subject_id_base64url = BASE64URL_NOPAD.encode(request_subject_id.as_bytes());
    let request_target_credential_id_base64url =
        BASE64URL_NOPAD.encode(request_target_credential_id.as_bytes());
    let mut missing_csrf_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(20));
    database_operation_observer.clear();
    let missing_csrf_response = missing_csrf_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/request")
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF admin support request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted admin support route must not emit Set-Cookie headers",
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on admin support request must reject before body parsing or database operation",
    );

    let mut rejected_request_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(20));
    database_operation_observer.clear();
    let rejected_request_response = rejected_request_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/request")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "subject_id_base64url": "{}",
                            "target_credential_instance_id_base64url": "{}",
                            "credential_lifecycle_action": "reset"
                        }}"#,
                        request_subject_id_base64url, request_target_credential_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("staff-rejected admin support request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(rejected_request_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &rejected_request_response,
        "staff-rejected admin support request must not emit Set-Cookie headers",
    );
    assert_no_database_operations(
        &database_operation_observer,
        "staff-rejected admin support request must not create intervention state",
    );
    let recorded_request_authorizations =
        staff_authorizer.recorded_intervention_request_authorizations();
    assert_eq!(recorded_request_authorizations.len(), 1);
    assert_eq!(
        recorded_request_authorizations[0].subject_id(),
        &request_subject_id
    );
    assert_eq!(
        recorded_request_authorizations[0].target_credential_instance_id(),
        &request_target_credential_id
    );
    assert_eq!(
        recorded_request_authorizations[0].action(),
        CredentialLifecycleAction::Reset
    );

    staff_authorizer.set_authorization(MountedAdminSupportStaffAuthorization::Authorized);
    let approval_subject_id_base64url = BASE64URL_NOPAD.encode(approval_subject_id.as_bytes());
    let approval_target_credential_id_base64url =
        BASE64URL_NOPAD.encode(approval_target_credential_id.as_bytes());
    let mut request_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(20));
    database_operation_observer.clear();
    let request_response = request_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/request")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "subject_id_base64url": "{}",
                            "target_credential_instance_id_base64url": "{}",
                            "credential_lifecycle_action": "reset"
                        }}"#,
                        approval_subject_id_base64url, approval_target_credential_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("admin support request route"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.close_expired_admin_support_interventions",
            "auth_core.precondition.no_open_admin_support_intervention",
            "auth_core.mutation.create_admin_support_intervention",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted admin/support request route must stay inside one target-active guard, open-candidate guard, candidate creation, audit, notice, and commit",
    );
    assert_eq!(request_response.status(), StatusCode::OK);
    let request_response_text =
        String::from_utf8(request_response.body().clone()).expect("support response UTF-8");
    let request_response_body = auth_runtime_test_json_response_body(&request_response);
    assert_eq!(
        request_response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("admin_support_intervention_requested")
    );
    assert!(
        !request_response_text.contains("subject_id")
            && !request_response_text.contains("target_credential_instance_id"),
        "mounted support request response must not expose subject or target credential ids"
    );
    let intervention_handle_base64url = request_response_body
        .get("intervention_handle_base64url")
        .and_then(serde_json::Value::as_str)
        .expect("support request response carries intervention handle");
    let approval_intervention_id = AdminSupportInterventionId::from_bytes(
        BASE64URL_NOPAD
            .decode(intervention_handle_base64url.as_bytes())
            .expect("decode intervention handle"),
    )
    .expect("intervention handle id");
    let mut approve_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(30));
    database_operation_observer.clear();
    let approve_response = approve_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/approve")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "intervention_handle_base64url": "{}"
                        }}"#,
                        intervention_handle_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("admin support approval route"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "db.tx.rollback",
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.precondition.admin_support_intervention_still_open",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.mutation.record_credential_lifecycle_action_authorized",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted admin/support approval route must stay inside one candidate load, lifecycle-context load, open-candidate guard, authorization record, auth-state revocation, notices, and commit",
    );
    assert_eq!(approve_response.status(), StatusCode::OK);
    let approve_response_text =
        String::from_utf8(approve_response.body().clone()).expect("approval response UTF-8");
    assert_eq!(
        auth_runtime_test_json_response_body(&approve_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("admin_support_approval_immediate_authorized")
    );
    assert!(
        !approve_response_text.contains("intervention_handle")
            && !approve_response_text.contains("subject_id")
            && !approve_response_text.contains("target_credential_instance_id"),
        "mounted support approval response must not expose internal lifecycle ids"
    );
    assert_eq!(
        load_admin_support_intervention_for_runtime_test(
            &pool,
            &store_config,
            &approval_intervention_id
        )
        .await
        .expect("approved support intervention row")
        .status,
        AdminSupportInterventionStatus::Approved
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &approval_subject_id)
            .await,
        3,
        "mounted support approval route must commit request, approval, and lifecycle notices"
    );
    assert_eq!(
        staff_authorizer.recorded_requests()[0].staff_action(),
        MountedAdminSupportStaffAction::ApproveIntervention
    );

    let denial_subject_id_base64url = BASE64URL_NOPAD.encode(denial_subject_id.as_bytes());
    let denial_target_credential_id_base64url =
        BASE64URL_NOPAD.encode(denial_target_credential_id.as_bytes());
    let mut denial_request_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(40));
    let denial_request_response = denial_request_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/request")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "subject_id_base64url": "{}",
                            "target_credential_instance_id_base64url": "{}",
                            "credential_lifecycle_action": "remove"
                        }}"#,
                        denial_subject_id_base64url, denial_target_credential_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("admin support denial candidate request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    let denial_handle = auth_runtime_test_json_response_body(&denial_request_response)
        .get("intervention_handle_base64url")
        .and_then(serde_json::Value::as_str)
        .expect("denial candidate handle")
        .to_owned();
    let denial_intervention_id = AdminSupportInterventionId::from_bytes(
        BASE64URL_NOPAD
            .decode(denial_handle.as_bytes())
            .expect("decode denial handle"),
    )
    .expect("denial intervention id");
    let mut deny_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(50));
    database_operation_observer.clear();
    let deny_response = deny_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/deny")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "intervention_handle_base64url": "{}"
                        }}"#,
                        denial_handle,
                    )
                    .into_bytes(),
                )))
                .expect("admin support denial route"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "db.tx.rollback",
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.precondition.admin_support_intervention_still_open",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted admin/support denial route must stay inside one candidate load, open-candidate guard, close, audit, notice, and commit",
    );
    assert_eq!(deny_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&deny_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("admin_support_intervention_denied")
    );
    assert_eq!(
        load_admin_support_intervention_for_runtime_test(
            &pool,
            &store_config,
            &denial_intervention_id
        )
        .await
        .expect("denied support intervention row")
        .status,
        AdminSupportInterventionStatus::Denied
    );

    let expiry_subject_id_base64url = BASE64URL_NOPAD.encode(expiry_subject_id.as_bytes());
    let expiry_target_credential_id_base64url =
        BASE64URL_NOPAD.encode(expiry_target_credential_id.as_bytes());
    let mut expiry_request_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(60));
    let expiry_request_response = expiry_request_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/request")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "subject_id_base64url": "{}",
                            "target_credential_instance_id_base64url": "{}",
                            "credential_lifecycle_action": "reset"
                        }}"#,
                        expiry_subject_id_base64url, expiry_target_credential_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("admin support expiry candidate request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    let expiry_handle = auth_runtime_test_json_response_body(&expiry_request_response)
        .get("intervention_handle_base64url")
        .and_then(serde_json::Value::as_str)
        .expect("expiry candidate handle")
        .to_owned();
    let expiry_intervention_id = AdminSupportInterventionId::from_bytes(
        BASE64URL_NOPAD
            .decode(expiry_handle.as_bytes())
            .expect("decode expiry handle"),
    )
    .expect("expiry intervention id");
    let mut expire_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(660));
    database_operation_observer.clear();
    let expire_response = expire_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/admin-support/interventions/expire")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "intervention_handle_base64url": "{}"
                        }}"#,
                        expiry_handle,
                    )
                    .into_bytes(),
                )))
                .expect("admin support expiry route"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "db.tx.rollback",
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.precondition.admin_support_intervention_still_expired_open",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted admin/support expiry route must stay inside one candidate load, expired-open guard, close, audit, notice, and commit",
    );
    assert_eq!(expire_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&expire_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("admin_support_intervention_expired")
    );
    assert_eq!(
        load_admin_support_intervention_for_runtime_test(
            &pool,
            &store_config,
            &expiry_intervention_id
        )
        .await
        .expect("expired support intervention row")
        .status,
        AdminSupportInterventionStatus::Expired
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_mounted_delayed_credential_lifecycle_executes_support_scheduled_reset() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let support_service = MountedAdminSupportPostgresService::new(runtime);
    let delayed_execution_service = MountedCredentialLifecyclePostgresService::new(runtime);
    let subject_id = id("mounted-delayed-support-reset-subject");
    let target_credential_id = id("mounted-delayed-support-reset-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Delayed,
        at(10),
    )
    .await;

    let pending_action_id = request_and_approve_delayed_support_reset_for_runtime_test(
        &support_service,
        &subject_id,
        &target_credential_id,
        at(20),
        at(30),
    )
    .await;
    let execution_request = ExecuteMountedDelayedCredentialLifecycleActionInput {
        now: at(160),
        pending_action_id: pending_action_id.clone(),
        method_payload: MountedDelayedCredentialLifecycleMethodPayload::Reset(
            CredentialResetMethodPayload::try_from_bytes(
                b"mounted-delayed-reset-verifier".as_slice(),
            )
            .expect("reset payload"),
        ),
    };

    let executable_action = runtime
        .mounted_delayed_credential_lifecycle_action_execution_request(&execution_request)
        .await
        .expect("mounted delayed lifecycle helper should derive action from stored pending row");
    assert_eq!(executable_action.pending_action_id(), &pending_action_id);
    assert_eq!(executable_action.subject_id(), &subject_id);
    assert_eq!(
        executable_action.target_credential_instance_id(),
        &target_credential_id
    );
    assert_eq!(executable_action.action(), CredentialLifecycleAction::Reset);
    assert_eq!(executable_action.requested_at(), at(30));
    assert_eq!(executable_action.earliest_execute_at(), at(150));
    assert_eq!(executable_action.expires_at(), at(250));
    assert_eq!(
        executable_action
            .runtime_execution_input(execution_request.clone())
            .expect("stored reset action should map to reset runtime input"),
        MountedDelayedCredentialLifecycleRuntimeInput::Reset(
            ExecuteMaturePendingCredentialResetInput {
                now: at(160),
                pending_action_id: pending_action_id.clone(),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"mounted-delayed-reset-verifier".as_slice(),
                )
                .expect("reset payload"),
            }
        )
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "mounted delayed lifecycle helper is a pre-dispatch read and must not close the pending action"
    );

    let executed = delayed_execution_service
        .execute_delayed_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            execution_request,
        )
        .await
        .expect("execute support-scheduled delayed reset through mounted lifecycle service");

    assert_eq!(
        executed.committed_outcome(),
        &MountedDelayedCredentialLifecycleCommittedOutcome::CredentialResetExecuted {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: pending_action_id.clone(),
        }
    );
    assert!(executed.runtime_execution().set_cookie_headers().is_empty());
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "mounted delayed reset must delegate method mutation work to the registered plugin"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        0,
        "mounted delayed reset execution must close the pending action"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(160),
        "mounted delayed reset execution must revoke existing subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        4,
        "mounted delayed reset execution must commit request, approval, scheduled-action, and execution notices"
    );

    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(())));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(())));
    let mounted_worker_service = mounted_auth_durable_effect_worker_service_for_test(
        &harness,
        &queue_test_store,
        out_of_band_deliverer.clone(),
        security_notification_deliverer.clone(),
    );
    let dispatch_summary = mounted_worker_service
        .dispatch_available_durable_effects_to_queue(MountedAuthDurableEffectDispatchRequest::new(
            NonZeroU32::new(10).expect("nonzero core dispatch limit"),
            NonZeroU32::new(10).expect("nonzero method dispatch limit"),
            at(170),
        ))
        .await
        .expect("mounted durable-effect worker should dispatch mounted lifecycle notices");
    assert_eq!(
        dispatch_summary.core_summary().enqueued_effect_count(),
        4,
        "all mounted delayed reset security notices must be dispatched through the mounted worker"
    );
    assert_eq!(dispatch_summary.method_summary().enqueued_effect_count(), 0);
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
        )
        .await,
        4
    );
    let worker_summary = mounted_worker_service
        .process_available_delivery_jobs_once_for_worker(
            "mounted-delayed-reset-notice-delivery",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("mounted durable-effect worker should deliver mounted lifecycle notices");
    assert_eq!(worker_summary.claimed_count, 4);
    assert_eq!(worker_summary.succeeded_count, 4);
    assert_eq!(worker_summary.dead_lettered_count, 0);
    assert!(
        out_of_band_deliverer.recorded_requests().is_empty(),
        "security notices must not leak into the out-of-band delivery callback"
    );
    let mut delivered_notification_kinds = security_notification_deliverer
        .recorded_requests()
        .iter()
        .map(|request| request.notification_kind().to_owned())
        .collect::<Vec<_>>();
    delivered_notification_kinds.sort();
    assert_eq!(
        delivered_notification_kinds,
        vec![
            "admin_support_credential_lifecycle_intervention_pending_action_scheduled",
            "admin_support_intervention_approved",
            "admin_support_intervention_requested",
            "credential_reset_executed",
        ]
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_http_delayed_credential_lifecycle_route_executes_support_scheduled_reset() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let subject_id = id("mounted-http-delayed-support-reset-subject");
    let target_credential_id = id("mounted-http-delayed-support-reset-target");
    seed_admin_support_target_credential_for_runtime_test(
        &harness.pool,
        &harness.store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Delayed,
        at(10),
    )
    .await;

    let pending_action_id = {
        let support_service = MountedAdminSupportPostgresService::new(&harness.runtime);
        request_and_approve_delayed_support_reset_for_runtime_test(
            &support_service,
            &subject_id,
            &target_credential_id,
            at(20),
            at(30),
        )
        .await
    };

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let method_plugin = harness
        .method_plugin
        .expect("message-signature reset method plugin");
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_delayed_credential_lifecycle_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut missing_csrf_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(160));

    database_operation_observer.clear();
    let missing_csrf_response = missing_csrf_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/delayed/reset/execute")
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF delayed credential lifecycle request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted delayed credential lifecycle route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on delayed credential lifecycle execution must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for delayed credential lifecycle route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value")
        .to_owned();
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1
        .to_owned();
    let pending_action_id_base64url = BASE64URL_NOPAD.encode(pending_action_id.as_bytes());
    let method_payload_base64url =
        BASE64URL_NOPAD.encode(b"mounted-http-delayed-reset-verifier".as_slice());
    let mut execute_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(160));
    database_operation_observer.clear();
    let response = execute_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/delayed/reset/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}",
                            "method_payload_base64url": "{}"
                        }}"#,
                        pending_action_id_base64url, method_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("delayed credential lifecycle reset route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "db.tx.rollback",
            "db.begin_transaction",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.close_pending_credential_lifecycle_action",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted delayed credential reset route must stay inside one bounded pending-action load, method-work, pending closure, auth-state revocation, and commit",
    );

    assert_eq!(response.status(), StatusCode::OK);
    let response_text =
        String::from_utf8(response.body().clone()).expect("delayed reset response is UTF-8");
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("delayed_credential_reset_executed")
    );
    assert!(
        !response_text.contains("subject_id")
            && !response_text.contains("target_credential_instance_id")
            && !response_text.contains("pending_action_id"),
        "mounted delayed credential lifecycle response must not expose internal lifecycle ids"
    );
    assert_eq!(
        method_plugin.count_state_rows(&pool).await,
        1,
        "mounted delayed reset route must delegate method mutation work to the registered plugin"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            &pool,
            &store_config,
            &pending_action_id,
        )
        .await,
        0,
        "mounted delayed reset route must close the pending action"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(160),
        "mounted delayed reset route must revoke existing subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        4,
        "mounted delayed reset route must preserve request, approval, scheduled-action, and execution notices"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_mounted_delayed_credential_lifecycle_rejects_wrong_payload_before_runtime_dispatch()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let support_service = MountedAdminSupportPostgresService::new(runtime);
    let delayed_execution_service = MountedCredentialLifecyclePostgresService::new(runtime);
    let subject_id = id("mounted-delayed-wrong-payload-subject");
    let target_credential_id = id("mounted-delayed-wrong-payload-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Delayed,
        at(10),
    )
    .await;

    let pending_action_id = request_and_approve_delayed_support_reset_for_runtime_test(
        &support_service,
        &subject_id,
        &target_credential_id,
        at(20),
        at(30),
    )
    .await;

    let error = delayed_execution_service
        .execute_delayed_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(160),
                pending_action_id: pending_action_id.clone(),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            },
        )
        .await
        .expect_err("mounted reset execution must reject missing method payload");

    assert!(matches!(
        error,
        MountedCredentialLifecycleServiceError::Core(
            Error::CredentialLifecycleExecutionMissingMethodCommitWork
        )
    ));
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "mounted payload-shape rejection must not dispatch method mutation work"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "mounted payload-shape rejection must not close the pending action"
    );

    harness.drop_schema().await;
}
