use super::*;

#[tokio::test]
async fn mounted_auth_protected_route_layer_resolves_and_enforces_route_requirement() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let subject_id: SubjectId = id("mounted-protected-route-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-protected-route-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;

    let pool = harness.pool.clone();
    let database_operation_observer = harness.database_operation_observer.clone();
    let schema = harness.schema.clone();
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default(),
        );
    let http_mount = mounted_runtime
        .services()
        .http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let mut protected_service = http_mount
        .protected_route_layer(
            MountedAuthProtectedRoutePolicy::authenticated_subject_for_safe_read(),
        )
        .with_fixed_now_for_tests(at(70))
        .layer(MountedAuthRequestStateEchoService);
    database_operation_observer.clear();
    let missing_session_error = protected_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/app/protected")
                .body(Full::new(Bytes::new()))
                .expect("mounted protected route request without auth cookies"),
        )
        .await
        .expect_err("missing auth cookies must not call protected app service");
    assert!(matches!(
        missing_session_error,
        MountedAuthProtectedRouteServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsFullAuthentication
        )
    ));
    assert_no_database_operations(
        &database_operation_observer,
        "missing auth cookies on mounted protected route must reject before database operation",
    );

    let mut protected_service = http_mount
        .protected_route_layer(
            MountedAuthProtectedRoutePolicy::authenticated_subject_for_safe_read(),
        )
        .with_fixed_now_for_tests(at(70))
        .layer(MountedAuthRequestStateEchoService);
    let response = protected_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/app/protected")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::new()))
                .expect("mounted protected route request with auth cookies"),
        )
        .await
        .expect("authenticated protected route should call app service");
    assert_eq!(
        response.body().as_slice(),
        b"authenticated",
        "protected route layer must insert resolved auth state before calling the app service"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_protected_application_subject_mapping_layer_maps_after_auth_requirement() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let subject_id: SubjectId = id("mounted-protected-mapping-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-protected-mapping-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;

    let pool = harness.pool.clone();
    let database_operation_observer = harness.database_operation_observer.clone();
    let schema = harness.schema.clone();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mapper = RecordingPostgresMountedSubjectMapper::new(Arc::clone(&recorded));
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default(),
        );
    let http_mount = mounted_runtime
        .services()
        .http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let mut mapped_service = http_mount
        .protected_application_subject_mapping_layer(
            MountedAuthProtectedRoutePolicy::authenticated_subject_for_safe_read(),
            mapper.clone(),
        )
        .with_fixed_now_for_tests(at(70))
        .layer(MountedAuthMappedApplicationSubjectEchoService);
    database_operation_observer.clear();
    let missing_session_error = mapped_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/app/mapped")
                .body(Full::new(Bytes::new()))
                .expect("mapped protected route request without auth cookies"),
        )
        .await
        .expect_err("missing auth cookies must not call subject mapper or app service");
    assert!(matches!(
        missing_session_error,
        MountedAuthProtectedApplicationSubjectMappingServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsFullAuthentication
        )
    ));
    assert!(
        recorded
            .lock()
            .expect("recorded mapped subject requests")
            .is_empty(),
        "protected application-subject layer must not call mapper when auth requirement fails"
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing auth cookies on protected application-subject layer must reject before database operation",
    );

    let mut mapped_service = http_mount
        .protected_application_subject_mapping_layer(
            MountedAuthProtectedRoutePolicy::authenticated_subject_for_safe_read(),
            mapper,
        )
        .with_fixed_now_for_tests(at(70))
        .layer(MountedAuthMappedApplicationSubjectEchoService);
    let response = mapped_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/app/mapped")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::new()))
                .expect("mapped protected route request with auth cookies"),
        )
        .await
        .expect("authenticated mapped protected route should call app service");
    assert_eq!(response.body().as_slice(), b"mapped-application-subject");
    let recorded = recorded.lock().expect("recorded mapped subject requests");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].subject_id(), &subject_id);
    assert_eq!(recorded[0].session_id(), &issued_auth.session_id);
    assert_eq!(
        recorded[0].source(),
        &AuthenticationSource::AuthoritativeSession
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_recovery_reset_commit_failure_emits_no_set_cookie() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            Some(TestMethodCommitFailureMode::FailMutation),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_recovery_code_plugin: true,
                ..FirstPartyMethodSelection::default()
            },
            config_with_divergent_credential_reset_role_policies(),
            None,
        )
        .await;
    let subject_id: SubjectId = id("mounted-reset-commit-failure-subject");
    let target_credential_id = id("mounted-reset-commit-failure-password");
    let recovery_authority = id("mounted-reset-commit-failure-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-reset-commit-failure-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x31);
    let recovery_code_secret = b"mounted-reset-commit-failure-recovery";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin")
        .clone();
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin")
        .clone();

    recovery_code_plugin
        .store_recovery_code_for_test(
            &harness.pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
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
                recovery_authority,
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::from_verified_proof_source(
                recovery_code_source,
                [id("mounted-reset-commit-failure-authority")],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let _issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-reset-commit-failure-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;

    let pool = harness.pool;
    let database_operation_observer = harness.database_operation_observer;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let runtime = harness.runtime;
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            runtime,
            MountedAuthRuntimeConfig::default().with_no_session_credential_recovery_flow(
                MountedNoSessionCredentialRecoveryFlow::new(
                    recovery_method.clone(),
                    proof_method(ProofFamily::MessageSignature),
                )
                .expect("mounted no-session recovery flow"),
            ),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    let preflight_payload_base64url = BASE64URL_NOPAD.encode(preflight_response.payload());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));
    let start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        preflight_response.summary().method_label(),
                        preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(start_response.status(), StatusCode::OK);
    let continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &start_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );

    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let recovery_secret_base64url = BASE64URL_NOPAD.encode(sealed_response.expose_secret());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(80));
    let proof_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, continuation_cookie_pair.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "secret_response_base64url": "{}"
                        }}"#,
                        recovery_secret_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-proof request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(proof_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&proof_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_proof_accepted")
    );
    let csrf_cookie_pair =
        cookie_pair_from_http_response_set_cookie(&proof_response, "__Host-csrf_token=");
    let accepted_continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &proof_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1;

    let initial_revocation_cutoff =
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await;
    database_operation_observer.clear();
    let reset_payload_base64url =
        BASE64URL_NOPAD.encode(b"commit-failure-reset-payload".as_slice());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let failed_reset_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        accepted_continuation_cookie_pair, csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "method_payload_base64url": "{}"
                        }}"#,
                        reset_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-reset request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(
        failed_reset_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_http_response_has_no_set_cookie(
        &failed_reset_response,
        "failed mounted recovery reset commit must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&failed_reset_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("internal_error")
    );
    assert_eq!(
        method_plugin.count_state_rows(&pool).await,
        0,
        "failed mounted recovery reset commit must not persist method mutation work"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        0,
        "failed mounted recovery reset commit must not schedule notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        initial_revocation_cutoff,
        "failed mounted recovery reset commit must not change subject auth-state revocation"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_recovery_reset_success_commits_runtime_owned_transition() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_recovery_code_plugin: true,
                ..FirstPartyMethodSelection::default()
            },
            config_with_divergent_credential_reset_role_policies(),
            None,
        )
        .await;
    let subject_id: SubjectId = id("mounted-reset-success-subject");
    let target_credential_id = id("mounted-reset-success-password");
    let recovery_authority = id("mounted-reset-success-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-reset-success-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x34);
    let recovery_code_secret = b"mounted-reset-success-recovery";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin")
        .clone();
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin")
        .clone();

    recovery_code_plugin
        .store_recovery_code_for_test(
            &harness.pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
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
                recovery_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::from_verified_proof_source(
                recovery_code_source,
                [recovery_authority.clone()],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let _issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-reset-success-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let runtime = harness.runtime;
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            runtime,
            MountedAuthRuntimeConfig::default().with_no_session_credential_recovery_flow(
                MountedNoSessionCredentialRecoveryFlow::new(
                    recovery_method.clone(),
                    proof_method(ProofFamily::MessageSignature),
                )
                .expect("mounted no-session recovery flow"),
            ),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    let preflight_payload_base64url = BASE64URL_NOPAD.encode(preflight_response.payload());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));
    let start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        preflight_response.summary().method_label(),
                        preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(start_response.status(), StatusCode::OK);
    let continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &start_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );

    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let recovery_secret_base64url = BASE64URL_NOPAD.encode(sealed_response.expose_secret());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(80));
    let proof_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, continuation_cookie_pair.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "secret_response_base64url": "{}"
                        }}"#,
                        recovery_secret_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-proof request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(proof_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&proof_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_proof_accepted")
    );
    let csrf_cookie_pair =
        cookie_pair_from_http_response_set_cookie(&proof_response, "__Host-csrf_token=");
    let accepted_continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &proof_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1;

    let reset_payload_base64url =
        BASE64URL_NOPAD.encode(b"successful-mounted-recovery-reset-payload".as_slice());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let reset_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        accepted_continuation_cookie_pair, csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "method_payload_base64url": "{}"
                        }}"#,
                        reset_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-reset request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(reset_response.status(), StatusCode::OK);
    let response_body = auth_runtime_test_json_response_body(&reset_response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_immediate_reset_executed")
    );
    assert!(
        response_body.get("subject_id").is_none()
            && response_body.get("target_credential_instance_id").is_none()
            && response_body.get("pending_action_id").is_none(),
        "mounted recovery reset response must not expose internal lifecycle ids"
    );
    assert_eq!(
        method_plugin.count_state_rows(&pool).await,
        1,
        "mounted recovery reset must build verifier work through the registered target method"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(&pool, &store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "mounted recovery reset must preserve target credential metadata state"
    );
    assert_eq!(
        fetch_credential_recovery_authorities_for_runtime_test(
            &pool,
            &store_config,
            &target_credential_id,
        )
        .await,
        vec![CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Reset,
            recovery_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        "mounted recovery reset must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        0,
        "mounted recovery reset must consume the recovery attempt in the reset commit"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted recovery reset execution must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(90),
        "mounted recovery reset execution must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_recovery_reset_schedule_success_commits_runtime_owned_transition() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let subject_id: SubjectId = id("mounted-reset-schedule-success-subject");
    let target_credential_id = id("mounted-reset-schedule-success-password");
    let recovery_authority = id("mounted-reset-schedule-success-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-reset-schedule-success-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x35);
    let recovery_code_secret = b"mounted-reset-schedule-success-recovery";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin")
        .clone();

    recovery_code_plugin
        .store_recovery_code_for_test(
            &harness.pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
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
                recovery_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::from_verified_proof_source(
                recovery_code_source,
                [recovery_authority],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let _issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-reset-schedule-success-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let runtime = harness.runtime;
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            runtime,
            MountedAuthRuntimeConfig::default().with_no_session_credential_recovery_flow(
                MountedNoSessionCredentialRecoveryFlow::new(
                    recovery_method.clone(),
                    proof_method(ProofFamily::MessageSignature),
                )
                .expect("mounted no-session recovery flow"),
            ),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    let preflight_payload_base64url = BASE64URL_NOPAD.encode(preflight_response.payload());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));
    let start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        preflight_response.summary().method_label(),
                        preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(start_response.status(), StatusCode::OK);
    let continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &start_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );

    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let recovery_secret_base64url = BASE64URL_NOPAD.encode(sealed_response.expose_secret());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(80));
    let proof_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, continuation_cookie_pair.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "secret_response_base64url": "{}"
                        }}"#,
                        recovery_secret_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-proof request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(proof_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&proof_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_proof_accepted")
    );
    let csrf_cookie_pair =
        cookie_pair_from_http_response_set_cookie(&proof_response, "__Host-csrf_token=");
    let accepted_continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &proof_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1;

    let initial_revocation_cutoff =
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await;
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let schedule_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
                ))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        accepted_continuation_cookie_pair, csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::new()))
                .expect("mounted recovery-reset scheduling request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(
        schedule_response.status(),
        StatusCode::OK,
        "mounted recovery reset scheduling returned body: {}",
        String::from_utf8_lossy(schedule_response.body())
    );
    let response_body = auth_runtime_test_json_response_body(&schedule_response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_delayed_reset_scheduled")
    );
    assert!(
        response_body
            .get("earliest_execute_at_unix_seconds")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|earliest_execute_at| earliest_execute_at > at(90).get()),
        "mounted recovery reset scheduling response must expose only the user-facing execution window"
    );
    assert!(
        response_body.get("subject_id").is_none()
            && response_body.get("target_credential_instance_id").is_none()
            && response_body.get("pending_action_id").is_none(),
        "mounted recovery reset scheduling response must not expose internal lifecycle ids"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_subject_and_target(
            &pool,
            &store_config,
            &subject_id,
            &target_credential_id,
        )
        .await,
        1,
        "mounted recovery reset scheduling must create one delayed reset for the recovered subject and configured target"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        0,
        "mounted recovery reset scheduling must consume the accepted recovery attempt in the schedule commit"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted recovery reset scheduling must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        initial_revocation_cutoff,
        "mounted recovery reset scheduling must not revoke subject auth state before the delayed reset executes"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_recovery_reset_schedule_precondition_failure_emits_no_set_cookie() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let subject_id: SubjectId = id("mounted-reset-schedule-failure-subject");
    let target_credential_id = id("mounted-reset-schedule-failure-password");
    let recovery_authority = id("mounted-reset-schedule-failure-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-reset-schedule-failure-recovery-set");
    let pending_action_id: PendingCredentialLifecycleActionId =
        id("mounted-reset-schedule-failure-existing-pending");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x32);
    let recovery_code_secret = b"mounted-reset-schedule-failure-recovery";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin")
        .clone();

    recovery_code_plugin
        .store_recovery_code_for_test(
            &harness.pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
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
                recovery_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::from_verified_proof_source(
                recovery_code_source,
                [recovery_authority],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            &harness.pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                at(60),
                at(200),
                at(300),
            )
            .expect("open pending reset action")],
        )
        .await
        .expect("seed open pending reset action");
    let _issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-reset-schedule-failure-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;

    let pool = harness.pool;
    let database_operation_observer = harness.database_operation_observer;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let runtime = harness.runtime;
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            runtime,
            MountedAuthRuntimeConfig::default().with_no_session_credential_recovery_flow(
                MountedNoSessionCredentialRecoveryFlow::new(
                    recovery_method.clone(),
                    proof_method(ProofFamily::MessageSignature),
                )
                .expect("mounted no-session recovery flow"),
            ),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    let preflight_payload_base64url = BASE64URL_NOPAD.encode(preflight_response.payload());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(70));
    let start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        preflight_response.summary().method_label(),
                        preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(start_response.status(), StatusCode::OK);
    let continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &start_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );

    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let recovery_secret_base64url = BASE64URL_NOPAD.encode(sealed_response.expose_secret());
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(80));
    let proof_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
                ))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, continuation_cookie_pair.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "secret_response_base64url": "{}"
                        }}"#,
                        recovery_secret_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted recovery-proof request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(proof_response.status(), StatusCode::OK);
    let csrf_cookie_pair =
        cookie_pair_from_http_response_set_cookie(&proof_response, "__Host-csrf_token=");
    let accepted_continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &proof_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1;

    let initial_revocation_cutoff =
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await;
    database_operation_observer.clear();
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let failed_schedule_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://example.com/auth{}",
                    MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
                ))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        accepted_continuation_cookie_pair, csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
                .body(Full::new(Bytes::new()))
                .expect("mounted recovery-reset scheduling request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(
        failed_schedule_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_http_response_has_no_set_cookie(
        &failed_schedule_response,
        "failed mounted recovery reset scheduling must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&failed_schedule_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("internal_error")
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            &pool,
            &store_config,
            &target_credential_id,
        )
        .await,
        1,
        "failed mounted recovery reset scheduling must leave only the existing open pending action"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "failed mounted recovery reset scheduling must not consume the recovery attempt"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        0,
        "failed mounted recovery reset scheduling must not schedule notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        initial_revocation_cutoff,
        "failed mounted recovery reset scheduling must not change subject auth-state revocation"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}
