use super::*;

#[tokio::test]
async fn postgres_runtime_authenticated_lifecycle_facades_without_live_session_return_needs_full_authentication_before_storage_work()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let identifier_plan = runtime
        .execute_authenticated_out_of_band_identifier_change_planning_from_headers(
            &headers,
            PlanAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(70),
                current_identifier_source_id: id("missing-session-current-source"),
                candidate_identifier_source_id: id("missing-session-candidate-source"),
            },
        )
        .await
        .expect("missing-session identifier-change planning returns a route outcome");
    assert_eq!(identifier_plan.outcome(), &Outcome::NeedsFullAuthentication);
    assert!(identifier_plan.set_cookie_headers().is_empty());
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session identifier-change planning",
    );

    harness.database_operation_observer.clear();
    let identifier_execution = runtime
        .execute_authenticated_out_of_band_identifier_change_from_headers(
            &headers,
            ExecuteAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(70),
                current_identifier_source_id: id("missing-session-execute-current-source"),
                candidate_identifier_source_id: id("missing-session-execute-candidate-source"),
            },
        )
        .await
        .expect("missing-session identifier-change execution returns a route outcome");
    assert_eq!(
        identifier_execution.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(identifier_execution.set_cookie_headers().is_empty());
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session identifier-change execution",
    );

    harness.database_operation_observer.clear();
    let credential_reset_cancellation = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(70),
                pending_action_id: id("missing-session-pending-reset-cancel"),
            },
        )
        .await
        .expect("missing-session pending reset cancellation returns a route outcome");
    assert_eq!(
        credential_reset_cancellation.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        credential_reset_cancellation
            .set_cookie_headers()
            .is_empty()
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session pending reset cancellation",
    );

    harness.database_operation_observer.clear();
    let credential_lifecycle_cancellation = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(70),
                pending_action_id: id("missing-session-pending-credential-cancel"),
            },
        )
        .await
        .expect("missing-session pending credential cancellation returns a route outcome");
    assert_eq!(
        credential_lifecycle_cancellation.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        credential_lifecycle_cancellation
            .set_cookie_headers()
            .is_empty()
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session pending credential lifecycle cancellation",
    );

    harness.database_operation_observer.clear();
    let subject_deletion_schedule = runtime
        .schedule_authenticated_subject_auth_state_deletion_from_headers(
            &headers,
            ScheduleAuthenticatedSubjectAuthStateDeletionInput { now: at(70) },
        )
        .await
        .expect("missing-session subject deletion scheduling returns a route outcome");
    assert_eq!(
        subject_deletion_schedule.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(subject_deletion_schedule.set_cookie_headers().is_empty());
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session subject deletion scheduling",
    );

    harness.database_operation_observer.clear();
    let subject_deletion_cancellation = runtime
        .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                now: at(70),
                pending_action_id: id("missing-session-pending-subject-cancel"),
            },
        )
        .await
        .expect("missing-session subject deletion cancellation returns a route outcome");
    assert_eq!(
        subject_deletion_cancellation.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        subject_deletion_cancellation
            .set_cookie_headers()
            .is_empty()
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session subject deletion cancellation",
    );

    harness.database_operation_observer.clear();
    let identifier_change_cancellation = runtime
        .execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
                now: at(70),
                pending_action_id: id("missing-session-pending-identifier-cancel"),
            },
        )
        .await
        .expect("missing-session identifier-change cancellation returns a route outcome");
    assert_eq!(
        identifier_change_cancellation.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        identifier_change_cancellation
            .set_cookie_headers()
            .is_empty()
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing-session identifier-change cancellation",
    );

    let expired_session_cookie_pair =
        rendered_session_cookie_pair_for_runtime_test(session_cookie(60), at(20));
    let expired_headers = headers_from_cookie_pairs(&[expired_session_cookie_pair.as_str()]);

    fn assert_expired_session_lifecycle_response(
        execution: &AuthWebRuntimeExecution,
        context: &str,
    ) {
        assert_eq!(
            execution.outcome(),
            &Outcome::NeedsFullAuthentication,
            "{context}"
        );
        assert!(
            execution
                .set_cookie_headers()
                .as_slice()
                .iter()
                .any(|header| header
                    .as_str()
                    .starts_with("__Host-__paranoid_auth_session=")
                    && header.as_str().contains("Max-Age=0")),
            "{context} must clear the expired session cookie"
        );
    }

    macro_rules! assert_expired_session_lifecycle_case {
        ($context:literal, $future:expr) => {{
            harness.database_operation_observer.clear();
            let execution = $future.await.expect($context);
            assert_expired_session_lifecycle_response(&execution, $context);
            assert_no_database_operations(&harness.database_operation_observer, $context);
        }};
    }

    assert_expired_session_lifecycle_case!(
        "expired-session identifier-change planning",
        runtime.execute_authenticated_out_of_band_identifier_change_planning_from_headers(
            &expired_headers,
            PlanAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(70),
                current_identifier_source_id: id("expired-session-current-source"),
                candidate_identifier_source_id: id("expired-session-candidate-source"),
            },
        )
    );

    assert_expired_session_lifecycle_case!(
        "expired-session identifier-change execution",
        runtime.execute_authenticated_out_of_band_identifier_change_from_headers(
            &expired_headers,
            ExecuteAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(70),
                current_identifier_source_id: id("expired-session-execute-current-source"),
                candidate_identifier_source_id: id("expired-session-execute-candidate-source"),
            },
        )
    );

    assert_expired_session_lifecycle_case!(
        "expired-session pending reset cancellation",
        runtime.execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &expired_headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(70),
                pending_action_id: id("expired-session-pending-reset-cancel"),
            },
        )
    );

    assert_expired_session_lifecycle_case!(
        "expired-session pending credential lifecycle cancellation",
        runtime
            .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
                &expired_headers,
                CancelAuthenticatedPendingCredentialLifecycleActionInput {
                    now: at(70),
                    pending_action_id: id("expired-session-pending-credential-cancel"),
                },
            )
    );

    assert_expired_session_lifecycle_case!(
        "expired-session subject deletion scheduling",
        runtime.schedule_authenticated_subject_auth_state_deletion_from_headers(
            &expired_headers,
            ScheduleAuthenticatedSubjectAuthStateDeletionInput { now: at(70) },
        )
    );

    assert_expired_session_lifecycle_case!(
        "expired-session subject deletion cancellation",
        runtime
            .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
                &expired_headers,
                CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                    now: at(70),
                    pending_action_id: id("expired-session-pending-subject-cancel"),
                },
            )
    );

    assert_expired_session_lifecycle_case!(
        "expired-session identifier-change cancellation",
        runtime
            .execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
                &expired_headers,
                CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
                    now: at(70),
                    pending_action_id: id("expired-session-pending-identifier-cancel"),
                },
            )
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_http_credential_reset_route_builds_method_work_and_uses_csrf_guard() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let subject_id = id("mounted-http-reset-subject");
    let target_credential_id = id("mounted-http-reset-password");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-reset-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-http-reset-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-reset.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed reset credential lifecycle authority");
    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let method_plugin = harness.method_plugin;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_reset_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));

    database_operation_observer.clear();
    let missing_csrf_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/reset/execute")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF credential reset request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted credential reset route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on credential reset must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for credential reset route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value");
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1;
    let credential_handle_base64url = BASE64URL_NOPAD.encode(target_credential_id.as_bytes());
    let method_payload_base64url =
        BASE64URL_NOPAD.encode(b"mounted-http-reset-password-verifier".as_slice());
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/reset/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "credential_handle_base64url": "{}",
                            "method_payload_base64url": "{}"
                        }}"#,
                        credential_handle_base64url, method_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("credential reset route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted credential reset HTTP route must parse and validate route input without extra storage work, then execute the same bounded credential-reset transaction as the private runtime facade",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_reset_executed")
    );
    assert_eq!(
        method_plugin
            .as_ref()
            .expect("message-signature reset method plugin")
            .count_state_rows(&pool)
            .await,
        1,
        "mounted credential reset route must delegate method reset work to the registered plugin"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted credential reset route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(70),
        "mounted credential reset route must revoke existing subject auth state"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(&pool, &store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "mounted credential reset route must preserve target credential metadata state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_authenticated_credential_reset_rejects_target_owned_by_another_subject_before_method_work()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let actor_subject_id = id("mounted-reset-cross-subject-actor");
    let target_owner_subject_id = id("mounted-reset-cross-subject-owner");
    let target_credential_id = id("mounted-reset-cross-subject-target");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-reset-cross-subject-actor-bootstrap",
        50,
        actor_subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-reset-cross-subject-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-cross-subject-reset.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                target_owner_subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("target credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed cross-subject reset credential lifecycle authority");
    let mounted_service = MountedCredentialLifecyclePostgresService::new(&harness.runtime);
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let error = mounted_service
        .execute_authenticated_credential_reset_from_headers(
            &headers,
            ExecuteMountedAuthenticatedCredentialResetInput {
                now: at(70),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(
                    target_credential_id.clone(),
                ),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"must-not-reset-other-subject".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("authenticated reset must reject a target owned by another subject");

    assert!(matches!(
        error,
        MountedCredentialLifecycleServiceError::Runtime(
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
                Error::CredentialLifecycleActionNotAuthorized
            )
        )
    ));
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "cross-subject reset rejection must not run method-owned verifier work"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &actor_subject_id)
            .await,
        0,
        "cross-subject reset rejection must not schedule notices for the authenticated subject"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(
            pool,
            store_config,
            &target_owner_subject_id
        )
        .await,
        0,
        "cross-subject reset rejection must not schedule notices for the credential owner"
    );
    assert_eq!(
        fetch_optional_subject_revocation_cutoff_for_runtime_test(
            pool,
            store_config,
            &target_owner_subject_id,
        )
        .await,
        None,
        "cross-subject reset rejection must not revoke the credential owner's auth state"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "cross-subject reset rejection must leave the target credential active"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_http_credential_replacement_route_builds_method_work_and_uses_csrf_guard() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let subject_id = id("mounted-http-replacement-subject");
    let target_credential_id = id("mounted-http-replacement-password");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-replacement-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-http-replacement-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-replacement.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[
                LifecycleAuthorityEvidence::authenticated_session(
                    issued_auth.session_id.clone(),
                    [session_authority],
                )
                .expect("session lifecycle evidence"),
                credential_instance_lifecycle_evidence(
                    "mounted-http-replacement-password",
                    [id("mounted-http-replacement-password-authority")],
                ),
            ],
            at(50),
        )
        .await
        .expect("seed replacement credential lifecycle authority");
    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let method_plugin = harness.method_plugin;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_replacement_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));

    database_operation_observer.clear();
    let missing_csrf_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/replace/execute")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF credential replacement request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted credential replacement route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on credential replacement must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for credential replacement route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value");
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1;
    let credential_handle_base64url = BASE64URL_NOPAD.encode(target_credential_id.as_bytes());
    let method_payload_base64url =
        BASE64URL_NOPAD.encode(b"mounted-http-replacement-password-verifier".as_slice());
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/replace/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "credential_handle_base64url": "{}",
                            "method_payload_base64url": "{}"
                        }}"#,
                        credential_handle_base64url, method_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("credential replacement route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.insert_credential_instance_metadata",
            "auth_core.mutation.insert_credential_recovery_authority",
            "auth_core.mutation.insert_lifecycle_authority_source",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.mutation.set_credential_lifecycle_state",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted credential replacement HTTP route must parse and validate route input without extra storage work, then execute the same bounded credential-replacement transaction as the private runtime facade",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_replaced")
    );
    assert_eq!(
        method_plugin
            .as_ref()
            .expect("message-signature replacement method plugin")
            .count_state_rows(&pool)
            .await,
        1,
        "mounted credential replacement route must delegate method replacement work to the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(&pool, &store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Superseded,
        "mounted credential replacement route must supersede the target credential metadata"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            &pool,
            &store_config,
            &subject_id,
        )
        .await,
        1,
        "mounted credential replacement route must create one active successor credential"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted credential replacement route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(70),
        "mounted credential replacement route must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_credential_removal_route_revokes_target_and_uses_csrf_guard() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let subject_id = id("mounted-http-removal-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-removal-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("mounted-http-removal-totp");
    let survivor_credential_id = id("mounted-http-removal-passkey-survivor");
    let session_authority = id("mounted-http-removal-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-removal.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target credential metadata"),
                CredentialInstanceMetadata::new(
                    survivor_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    "webauthn_passkey",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("survivor credential metadata"),
            ],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed removal credential lifecycle authority");
    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_removal_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));

    database_operation_observer.clear();
    let missing_csrf_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/remove/execute")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF credential removal request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted credential removal route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on credential removal must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for credential removal route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value");
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1;
    let credential_handle_base64url = BASE64URL_NOPAD.encode(target_credential_id.as_bytes());
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/remove/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "credential_handle_base64url": "{}"
                        }}"#,
                        credential_handle_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("credential removal route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.mutation.set_credential_lifecycle_state",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted credential removal HTTP route must parse and validate route input without extra storage work, then execute the same bounded credential-removal transaction as the private runtime facade",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_removed")
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(&pool, &store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Revoked,
        "mounted credential removal route must revoke the target credential metadata"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(&pool, &store_config, &survivor_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "mounted credential removal route must leave the independent survivor active"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted credential removal route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(70),
        "mounted credential removal route must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_credential_rotation_route_builds_method_work_and_uses_csrf_guard() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let subject_id = id("mounted-http-rotation-subject");
    let target_credential_id = id("mounted-http-rotation-password");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-rotation-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-http-rotation-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-rotation.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Rotate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed rotation credential lifecycle authority");
    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let method_plugin = harness.method_plugin;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_rotation_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));

    database_operation_observer.clear();
    let missing_csrf_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/rotate/execute")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF credential rotation request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted credential rotation route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on credential rotation must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for credential rotation route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value");
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1;
    let credential_handle_base64url = BASE64URL_NOPAD.encode(target_credential_id.as_bytes());
    let method_payload_base64url =
        BASE64URL_NOPAD.encode(b"mounted-http-rotation-password-verifier".as_slice());
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/rotate/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "credential_handle_base64url": "{}",
                            "method_payload_base64url": "{}"
                        }}"#,
                        credential_handle_base64url, method_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("credential rotation route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted credential rotation HTTP route must parse and validate route input without extra storage work, then execute the same bounded credential-rotation transaction as the private runtime facade",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_rotated")
    );
    assert_eq!(
        method_plugin
            .as_ref()
            .expect("message-signature rotation method plugin")
            .count_state_rows(&pool)
            .await,
        1,
        "mounted credential rotation route must delegate method rotation work to the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(&pool, &store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "mounted credential rotation route must preserve target credential metadata state"
    );
    assert_eq!(
        fetch_credential_recovery_authorities_for_runtime_test(
            &pool,
            &store_config,
            &target_credential_id,
        )
        .await,
        vec![CredentialRecoveryAuthority::new(
            target_credential_id.clone(),
            CredentialLifecycleAction::Rotate,
            session_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        "mounted credential rotation route must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted credential rotation route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(70),
        "mounted credential rotation route must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_credential_regeneration_route_projects_codes_after_commit_and_uses_csrf_guard()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let subject_id = id("mounted-http-regeneration-subject");
    let recovery_code_credential_id = id("mounted-http-regeneration-recovery-code-set");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-regeneration-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-http-regeneration-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-regeneration.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[CredentialInstanceMetadata::new(
                recovery_code_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::RecoveryCodeCredential,
                "recovery_code",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("recovery-code credential metadata")],
            &[CredentialRecoveryAuthority::new(
                recovery_code_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed regeneration credential lifecycle authority");
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    recovery_code_plugin
        .store_recovery_code_for_test(
            &harness.pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id_for_runtime_test(0x05),
            b"mounted-http-old-recovery-code-secret",
            at(55),
        )
        .await
        .expect("seed old recovery-code verifier");

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_regeneration_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));

    database_operation_observer.clear();
    let missing_csrf_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/regenerate/execute")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF credential regeneration request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted credential regeneration route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on credential regeneration must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for credential regeneration route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value");
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1;
    let credential_handle_base64url =
        BASE64URL_NOPAD.encode(recovery_code_credential_id.as_bytes());
    let method_payload = PostgresRecoveryCodeMethodPlugin::regeneration_payload_for_test(2)
        .expect("recovery-code regeneration payload");
    let method_payload_base64url = BASE64URL_NOPAD.encode(method_payload.as_bytes());
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/regenerate/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "credential_handle_base64url": "{}",
                            "method_payload_base64url": "{}"
                        }}"#,
                        credential_handle_base64url, method_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("credential regeneration route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.recovery_code.precondition.lock_set",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.recovery_code.mutation.supersede_unused_set",
            "auth_core.recovery_code.mutation.insert_set",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted credential regeneration HTTP route must parse and validate route input without extra storage work, then execute the same bounded recovery-code regeneration transaction as the private runtime facade before projecting generated codes",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_regenerated")
    );
    let generated_codes = response_body
        .get("generated_recovery_codes")
        .and_then(|value| value.get("codes"))
        .and_then(serde_json::Value::as_array)
        .expect("mounted regeneration route must return generated recovery codes");
    assert_eq!(generated_codes.len(), 2);
    assert!(
        response_body.get("subject_id").is_none()
            && response_body.get("target_credential_instance_id").is_none(),
        "mounted regeneration response must not expose internal subject or credential ids"
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(&pool, &subject_id)
            .await
            .expect("count regenerated recovery codes"),
        2,
        "mounted credential regeneration route must replace the usable recovery-code set"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            &pool,
            &store_config,
            &recovery_code_credential_id,
        )
        .await,
        CredentialLifecycleState::Active,
        "mounted credential regeneration route must preserve target credential metadata state"
    );
    assert_eq!(
        fetch_credential_recovery_authorities_for_runtime_test(
            &pool,
            &store_config,
            &recovery_code_credential_id,
        )
        .await,
        vec![CredentialRecoveryAuthority::new(
            recovery_code_credential_id.clone(),
            CredentialLifecycleAction::Regenerate,
            session_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        "mounted credential regeneration route must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted credential regeneration route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(70),
        "mounted credential regeneration route must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}
