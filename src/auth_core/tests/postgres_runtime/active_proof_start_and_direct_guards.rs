use super::*;

#[tokio::test]
async fn postgres_runtime_rejects_direct_active_proof_attempt_start() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let attempt_id: ActiveProofAttemptId = id("totp-unbound-attempt");

    let error = runtime
        .execute_from_headers(
            &empty_headers,
            Command::StartActiveProofAttempt(StartActiveProofAttempt {
                now: at(20),
                attempt_id: attempt_id.clone(),
                proof_use: ProofUse::SatisfyStepUp,
                subject_id: None,
            }),
        )
        .await
        .expect_err("direct attempt start must require runtime fresh ID generation");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration
        )
    ));
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_current_session_active_proof_start_without_session_does_not_write() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    let execution = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &empty_headers,
            StartCurrentSessionActiveProofAttemptInput {
                now: at(20),
                proof_use: ProofUse::SatisfyStepUp,
            },
        )
        .await
        .expect("missing session resolves without writes");

    assert_eq!(execution.outcome(), &Outcome::NeedsFullAuthentication);
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_current_trusted_device_active_proof_start_without_device_does_not_write()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_current_trusted_device_active_proof_attempt_start_from_headers(
            &empty_headers,
            StartCurrentTrustedDeviceActiveProofAttemptInput {
                now: at(20),
                proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
            },
        )
        .await
        .expect("missing trusted-device cookie resolves without writes");

    assert_eq!(execution.outcome(), &Outcome::NeedsFullAuthentication);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "trusted-device active-proof start without device must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_unbound_challenge_issue_preflight_before_writes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("preflight-rejected:email-hash:window"),
                recipient_handle: "preflight-rejected-recipient".to_owned(),
                idempotency_key: "preflight-rejected-delivery".to_owned(),
            },
            invalid_challenge_issue_preflight_response(),
        )
        .await
        .expect_err("invalid challenge issue preflight must reject before writes");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid challenge issue preflight must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands after rejected preflight"),
        0,
        "invalid challenge issue preflight must not enqueue method-owned delivery commands",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_unbound_challenge_issue_preflight_gate_mismatch_before_writes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
                    .expect("method declaration"),
                method_challenge_request_payload: None,
            },
            mismatched_challenge_issue_preflight_response(),
        )
        .await
        .expect_err("mismatched challenge issue preflight gate must reject before writes");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ChallengeIssuePreflightGateMismatch
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "mismatched challenge issue preflight gate must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_method_derived_email_otp_start_rejects_bad_payload_before_writes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_method_derived_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueMethodDerivedOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                method_payload: vec![0xff],
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect_err("invalid method-derived email OTP start payload must reject before writes");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                operation: "out_of_band_challenge_start_derivation",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid method-derived email OTP start payload must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email OTP delivery commands after bad method payload"),
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_method_derived_email_otp_start_derives_dedupe_and_delivery_facts() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("method-derived-email-otp-start-subject");
    let recipient_handle =
        recipient_handle_for_test_subject("method-derived-email-otp-start", &subject_id);
    let method =
        ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp").expect("method");

    let first_issued = runtime
        .execute_method_derived_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueMethodDerivedOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_payload: recipient_handle.as_bytes().to_vec(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue method-derived email OTP challenge");
    let first_challenge_id = match first_issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected method-derived email OTP challenge issue, got {outcome:?}"),
    };
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 1);
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &first_challenge_id)
            .await,
        1
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email OTP method challenges"),
        1
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email OTP delivery commands after method-derived issue"),
        1
    );

    let duplicate_error = runtime
        .execute_method_derived_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueMethodDerivedOutOfBandChallengeInput {
                now: at(30),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method,
                method_payload: recipient_handle.as_bytes().to_vec(),
            },
            email_otp_challenge_issue_preflight_response_at(at(30)),
        )
        .await
        .expect_err("same method-derived recipient must reuse the same live dedupe bucket");
    assert!(matches!(
        duplicate_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            super::super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(
                "open out-of-band challenge dedupe key already exists"
            )
        )
    ));
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        1,
        "duplicate method-derived challenge issue must roll back the fresh attempt"
    );
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        1,
        "duplicate method-derived challenge issue must not create a second challenge"
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email OTP delivery commands after method-derived duplicate"),
        1,
        "duplicate method-derived challenge issue must not enqueue a second delivery"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_http_full_authentication_email_otp_route_executes_end_to_end() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = harness.pool.clone();
    let store_config = harness.store_config.clone();
    let schema = harness.schema.clone();
    let database_operation_observer = harness.database_operation_observer.clone();
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin")
        .clone();
    let method =
        ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp").expect("method");
    let mounted_runtime = MountedAuthPostgresRuntime::try_new(
        harness.runtime,
        MountedAuthRuntimeConfig::default()
            .with_full_authentication_out_of_band_method(method.clone())
            .expect("configured full-authentication method")
            .with_durable_effect_worker_integrations(
                MountedAuthDurableEffectWorkerIntegrations::new(
                    Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(()))),
                    Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(()))),
                    Arc::new(
                        RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())),
                    ),
                ),
            ),
    )
    .expect("mounted runtime validates full-authentication dependencies");
    let http_mount = mounted_runtime
        .services()
        .http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let route_manifest = http_mount.route_manifest();
    assert!(
        MountedFullAuthenticationEndpoint::all()
            .into_iter()
            .all(|endpoint| route_manifest
                .routes()
                .iter()
                .any(|route| route.kind() == MountedAuthRouteKind::FullAuthentication(endpoint))),
        "configured mounted runtime must advertise every full-authentication endpoint"
    );
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(20));
    let subject_id: SubjectId = id("mounted-full-auth-email-otp-subject");
    let recipient_handle =
        recipient_handle_for_test_subject("mounted-full-auth-email-otp", &subject_id);
    let preflight_response = email_otp_challenge_issue_preflight_response_at(at(20));
    let method_payload_base64url = BASE64URL_NOPAD.encode(recipient_handle.as_bytes());
    let preflight_payload_base64url = BASE64URL_NOPAD.encode(preflight_response.payload());

    database_operation_observer.clear();
    let start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/authentication/out-of-band/start")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "method_payload_base64url": "{}",
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        method_payload_base64url,
                        preflight_response.summary().method_label(),
                        preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted full-authentication start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(start_response.status(), StatusCode::OK);
    let start_body = auth_runtime_test_json_response_body(&start_response);
    assert_eq!(
        start_body.get("type").and_then(serde_json::Value::as_str),
        Some("full_authentication_out_of_band_challenge_accepted")
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.secret.insert_active_proof_continuation_mac",
            "auth_core.mutation.create_active_proof_attempt",
            "auth_core.audit.append_event",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.precondition.close_replaceable_open_challenges_for_dedupe_key",
            "auth_core.email_otp.precondition.close_replaceable_challenges_for_recipient",
            "auth_core.mutation.create_active_proof_challenge",
            "auth_core.mutation.insert_challenge_delivery_key",
            "auth_core.email_otp.mutation.store_challenge",
            "auth_core.audit.append_event",
            "auth_core.effect.append_out_of_band_message",
            "auth_core.email_otp.effect.queue_delivery",
            "db.tx.commit",
        ],
        "mounted full-authentication start must execute the same bounded method-derived email OTP transaction as the private runtime facade",
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1
    );
    assert_eq!(
        count_all_active_proof_challenges(&pool, &store_config).await,
        1
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(&pool)
            .await
            .expect("count email OTP delivery commands after mounted full-auth start"),
        1
    );
    database_operation_observer.clear();
    let duplicate_start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/authentication/out-of-band/start")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "method_payload_base64url": "{}",
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        method_payload_base64url,
                        preflight_response.summary().method_label(),
                        preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("duplicate mounted full-authentication start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(duplicate_start_response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &duplicate_start_response,
        "duplicate mounted full-authentication start must not emit new cookies",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&duplicate_start_response),
        start_body,
        "duplicate mounted full-authentication start must be indistinguishable from an accepted fresh start at the public body layer"
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.secret.insert_active_proof_continuation_mac",
            "auth_core.mutation.create_active_proof_attempt",
            "auth_core.audit.append_event",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.precondition.close_replaceable_open_challenges_for_dedupe_key",
            "auth_core.email_otp.precondition.close_replaceable_challenges_for_recipient",
            "auth_core.mutation.create_active_proof_challenge",
            "db.tx.rollback",
        ],
        "duplicate mounted full-authentication start must stop at the live dedupe guard and roll back all fresh attempt work",
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "duplicate mounted full-authentication start must not persist another attempt"
    );
    assert_eq!(
        count_all_active_proof_challenges(&pool, &store_config).await,
        1,
        "duplicate mounted full-authentication start must not persist another challenge"
    );
    assert_eq!(
        count_core_durable_effect_commands(&pool, &store_config).await,
        1,
        "duplicate mounted full-authentication start must not enqueue another core delivery effect"
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(&pool)
            .await
            .expect("count email OTP delivery commands after mounted duplicate start"),
        1,
        "duplicate mounted full-authentication start must not enqueue another method delivery"
    );
    let first_challenge_id = fetch_only_active_proof_challenge_id(&pool, &store_config).await;

    http_route_service = http_route_service.with_fixed_now_for_tests(at(45));
    let replacement_preflight_response = email_otp_challenge_issue_preflight_response_at(at(45));
    let replacement_preflight_payload_base64url =
        BASE64URL_NOPAD.encode(replacement_preflight_response.payload());

    database_operation_observer.clear();
    let replacement_start_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/authentication/out-of-band/start")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "method_payload_base64url": "{}",
                            "preflight_gate_kind": "proof_of_work",
                            "preflight_gate_method_label": "{}",
                            "preflight_gate_payload_base64url": "{}"
                        }}"#,
                        method_payload_base64url,
                        replacement_preflight_response.summary().method_label(),
                        replacement_preflight_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("replacement mounted full-authentication start request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(replacement_start_response.status(), StatusCode::OK);
    let replacement_start_body = auth_runtime_test_json_response_body(&replacement_start_response);
    assert_eq!(
        replacement_start_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("full_authentication_out_of_band_challenge_accepted")
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.secret.insert_active_proof_continuation_mac",
            "auth_core.mutation.create_active_proof_attempt",
            "auth_core.audit.append_event",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.precondition.close_replaceable_open_challenges_for_dedupe_key",
            "auth_core.email_otp.precondition.close_replaceable_challenges_for_recipient",
            "auth_core.mutation.create_active_proof_challenge",
            "auth_core.mutation.insert_challenge_delivery_key",
            "auth_core.email_otp.mutation.store_challenge",
            "auth_core.audit.append_event",
            "auth_core.effect.append_out_of_band_message",
            "auth_core.email_otp.effect.queue_delivery",
            "db.tx.commit",
        ],
        "mounted full-authentication start after replacement cooldown must atomically close and replace the previous challenge before its TTL expires",
    );
    assert_eq!(
        count_open_challenges_for_challenge(&pool, &store_config, &first_challenge_id).await,
        0,
        "mounted replacement start must close the old core challenge before its TTL expires"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        2,
        "mounted replacement start must persist one replacement attempt"
    );
    assert_eq!(
        count_all_active_proof_challenges(&pool, &store_config).await,
        2,
        "mounted replacement start must keep the closed old challenge and persist the replacement challenge"
    );
    assert_eq!(
        count_core_durable_effect_commands(&pool, &store_config).await,
        2,
        "mounted replacement start must enqueue exactly one additional core delivery effect"
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(&pool)
            .await
            .expect("count open email OTP method challenges after mounted replacement start"),
        1,
        "mounted replacement start must close the replaced method-owned challenge"
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(&pool)
            .await
            .expect("count email OTP delivery commands after mounted replacement start"),
        2,
        "mounted replacement start must enqueue exactly one additional method delivery"
    );

    let continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &replacement_start_response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );
    let challenge_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &replacement_start_response,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let challenge_id = fetch_only_open_active_proof_challenge_id(&pool, &store_config).await;
    let response_secret = email_otp
        .fetch_response_secret_for_test(&pool, &challenge_id)
        .await
        .expect("fetch mounted email OTP response secret");
    let response_secret_base64url = BASE64URL_NOPAD.encode(response_secret.expose_secret());
    let wrong_response_secret_base64url =
        BASE64URL_NOPAD.encode(b"definitely wrong mounted full-authentication proof");

    database_operation_observer.clear();
    let rejected_proof_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/authentication/out-of-band/proof")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, challenge_cookie_pair.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "secret_response_base64url": "{}"
                        }}"#,
                        wrong_response_secret_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted full-authentication rejected proof request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(rejected_proof_response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &rejected_proof_response,
        "mounted full-authentication pre-state proof rejection must not emit Set-Cookie",
    );
    let rejected_proof_body = auth_runtime_test_json_response_body(&rejected_proof_response);
    assert_eq!(
        rejected_proof_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("full_authentication_out_of_band_proof_rejected")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "mounted full-authentication wrong out-of-band proof must reject before any database operation",
    );

    database_operation_observer.clear();
    let proof_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/authentication/out-of-band/proof")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, challenge_cookie_pair.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "secret_response_base64url": "{}"
                        }}"#,
                        response_secret_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("mounted full-authentication proof request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(proof_response.status(), StatusCode::OK);
    let proof_body = auth_runtime_test_json_response_body(&proof_response);
    assert_eq!(
        proof_body.get("type").and_then(serde_json::Value::as_str),
        Some("full_authentication_out_of_band_proof_accepted")
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.email_otp.load_open_challenge_recipient_handle",
            "auth_core.load.active_proof_attempt",
            "auth_core.load.active_proof_satisfied_proofs",
            "auth_core.load.subject_revocation",
            "auth_core.load.active_proof_challenge",
            "auth_core.load.active_proof_challenge_delivery_keys",
            "auth_core.precondition.active_proof_challenge_still_open",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.fetch_subject_cutoff",
            "auth_core.email_otp.precondition.challenge_open",
            "auth_core.mutation.close_open_challenges_for_proof_family",
            "auth_core.mutation.bind_active_proof_attempt_subject",
            "auth_core.mutation.insert_satisfied_proof",
            "auth_core.email_otp.mutation.consume_challenge",
            "auth_core.audit.append_event",
            "db.tx.commit",
        ],
        "mounted full-authentication proof completion must execute the same bounded email OTP completion transaction as the private runtime facade",
    );

    database_operation_observer.clear();
    let complete_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/authentication/complete")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, continuation_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    br#"{
                        "trust_device": true,
                        "trusted_device_display_label": "Mounted full-auth browser"
                    }"#,
                )))
                .expect("mounted full-authentication completion request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(complete_response.status(), StatusCode::OK);
    let complete_body = auth_runtime_test_json_response_body(&complete_response);
    assert_eq!(
        complete_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("full_authentication_completed")
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.active_proof_attempt",
            "auth_core.load.active_proof_satisfied_proofs",
            "auth_core.load.active_proof_continuation_secret_mac",
            "auth_core.load.subject_revocation",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.fetch_subject_cutoff",
            "auth_core.secret.insert_session_mac",
            "auth_core.secret.insert_trusted_device_mac",
            "auth_core.mutation.delete_active_proof_delivery_keys",
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            "auth_core.mutation.delete_active_proof_challenges",
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            "auth_core.mutation.delete_active_proof_attempt",
            "auth_core.mutation.create_session",
            "auth_core.mutation.create_trusted_device",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted full-authentication completion must execute the same bounded session/trusted-device transaction as the private runtime facade",
    );
    assert!(
        complete_response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .any(|header| header
                .to_str()
                .expect("set-cookie header is valid ASCII")
                .starts_with("__Host-__paranoid_auth_session=")),
        "mounted full-authentication completion must render the committed session cookie"
    );
    assert!(
        complete_response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .any(|header| header
                .to_str()
                .expect("set-cookie header is valid ASCII")
                .starts_with("__Host-__paranoid_auth_trusted_device=")),
        "mounted full-authentication completion must render the committed trusted-device cookie"
    );
    assert!(
        complete_response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .any(|header| header
                .to_str()
                .expect("set-cookie header is valid ASCII")
                .starts_with("__Host-csrf_token=")),
        "mounted full-authentication completion must cycle CSRF with the committed session"
    );
    assert_eq!(count_all_sessions(&pool, &store_config).await, 1);
    assert_eq!(count_all_trusted_devices(&pool, &store_config).await, 1);
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "full authentication completion deletes the replacement attempt while the superseded start attempt remains bounded by its own active-proof TTL"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_runtime_rejects_configured_secret_challenge_issue_path() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-challenge-path-bootstrap",
        20,
        id("totp-challenge-path-subject"),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    let error = runtime
        .execute_active_proof_method_challenge_issue_from_headers(
            &continuation_headers,
            IssueActiveProofMethodChallengeInput {
                now: at(80),
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect_err("TOTP must not use active-proof challenge cookie issuance");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ProofMethodCannotIssueActiveProofMethodChallenge {
                family: ProofFamily::SharedSecretOtp
            }
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_active_proof_completion() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let proof = ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof");
    let direct_command = Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
        now: at(30),
        attempt_id: id("direct-message-signature-attempt"),
        challenge_id: None,
        verified_proof: VerifiedActiveProof::from_summary(proof, Some(id("direct-subject")))
            .expect("verified proof"),
        stateless_fast_fail: StatelessFastFailStatus::NotRequired,
        weak_proof_gate: WeakProofGateStatus::NotRequired,
        method_commit_work: Vec::new(),
    });

    let error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_command)
        .await
        .expect_err("runtime must not accept caller-provided verified active proofs");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofCompletionRequiresRuntimeMethodDispatch
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_active_proof_failure_recording() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let direct_command = Command::RecordActiveProofFailure(RecordActiveProofFailure {
        now: at(30),
        attempt_id: id("direct-failure-attempt"),
        challenge_id: None,
        method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
            .expect("TOTP method"),
        weak_proof_gate: verified_proof_of_work_gate(),
    });

    let error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_command)
        .await
        .expect_err("runtime must not accept caller-provided active-proof failures");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofFailureRequiresRuntimeMethodDispatch
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_direct_credential_reset_commands() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let database_operation_observer = harness.database_operation_observer.clone();
    let target_credential_id = id("direct-reset-password-credential");
    let direct_plan = Command::PlanCredentialReset(PlanCredentialReset {
        now: at(30),
        lifecycle_context: credential_lifecycle_context(
            message_signature_credential_metadata("direct-reset-password-credential"),
            [CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                id("direct-reset-authority"),
                RecoveryAuthorityTiming::Immediate,
            )],
            [credential_instance_lifecycle_evidence(
                "direct-reset-source",
                [id("direct-reset-authority")],
            )],
        ),
        active_proof_attempt_to_close: None,
        independent_evidence_required:
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        pending_action: None,
    });

    database_operation_observer.clear();
    let plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_plan)
        .await
        .expect_err("runtime must not accept caller-provided credential reset lifecycle context");

    assert!(matches!(
        plan_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetPlanningRequiresRuntimeLifecycleDecision
        )
    ));
    assert_no_database_operations(
        &database_operation_observer,
        "direct credential reset planning must reject before any database operation",
    );

    let direct_recovery_plan = Command::PlanCredentialReset(PlanCredentialReset {
        now: at(30),
        lifecycle_context: credential_lifecycle_context(
            message_signature_credential_metadata("direct-recovery-reset-password-credential"),
            [CredentialRecoveryAuthority::new(
                id("direct-recovery-reset-password-credential"),
                CredentialLifecycleAction::Reset,
                id("direct-recovery-reset-authority"),
                RecoveryAuthorityTiming::Delayed,
            )],
            [credential_instance_lifecycle_evidence(
                "direct-recovery-reset-source",
                [id("direct-recovery-reset-authority")],
            )],
        ),
        active_proof_attempt_to_close: Some(active_attempt(ProofUse::RecoverOrReplaceCredential)),
        independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement::Required,
        pending_action: Some(PendingCredentialLifecycleActionSchedule {
            pending_action_id: id("direct-recovery-reset-pending"),
            earliest_execute_at: at(100),
            expires_at: at(200),
        }),
    });

    database_operation_observer.clear();
    let recovery_plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_recovery_plan)
        .await
        .expect_err("runtime must not accept caller-provided recovery reset attempt facts");

    assert!(matches!(
        recovery_plan_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetPlanningRequiresRuntimeLifecycleDecision
        )
    ));
    assert_no_database_operations(
        &database_operation_observer,
        "direct unauthenticated recovery reset planning must reject before any database operation",
    );

    let direct_execute = Command::ExecuteCredentialReset(ExecuteCredentialReset {
        now: at(30),
        execution_authority: CredentialResetExecutionAuthority::Immediate {
            lifecycle_context: credential_lifecycle_context(
                message_signature_credential_metadata("direct-reset-password-credential"),
                [CredentialRecoveryAuthority::new(
                    target_credential_id,
                    CredentialLifecycleAction::Reset,
                    id("direct-reset-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [credential_instance_lifecycle_evidence(
                    "direct-reset-source",
                    [id("direct-reset-authority")],
                )],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        },
        active_proof_attempt_to_close: None,
        method_commit_work: vec![password_reset_method_commit_work(b"direct-reset-verifier")],
    });

    database_operation_observer.clear();
    let execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_execute)
        .await
        .expect_err("runtime must not accept caller-provided credential reset method work");

    assert!(matches!(
        execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetExecutionRequiresRuntimeMethodDispatch
        )
    ));
    assert_no_database_operations(
        &database_operation_observer,
        "direct credential reset execution must reject before any database operation",
    );

    let direct_recovery_execute = Command::ExecuteCredentialReset(ExecuteCredentialReset {
        now: at(30),
        execution_authority: CredentialResetExecutionAuthority::Immediate {
            lifecycle_context: credential_lifecycle_context(
                message_signature_credential_metadata("direct-recovery-reset-password-credential"),
                [CredentialRecoveryAuthority::new(
                    id("direct-recovery-reset-password-credential"),
                    CredentialLifecycleAction::Reset,
                    id("direct-recovery-reset-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [credential_instance_lifecycle_evidence(
                    "direct-recovery-reset-source",
                    [id("direct-recovery-reset-authority")],
                )],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
        },
        active_proof_attempt_to_close: Some(active_attempt(ProofUse::RecoverOrReplaceCredential)),
        method_commit_work: vec![password_reset_method_commit_work(
            b"direct-recovery-reset-verifier",
        )],
    });

    database_operation_observer.clear();
    let recovery_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_recovery_execute)
        .await
        .expect_err("runtime must not accept caller-provided recovery reset method work");

    assert!(matches!(
        recovery_execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetExecutionRequiresRuntimeMethodDispatch
        )
    ));
    assert_no_database_operations(
        &database_operation_observer,
        "direct unauthenticated recovery reset execution must reject before any database operation",
    );

    let direct_replacement_target_credential_id = id("direct-replacement-password-credential");
    let direct_replacement_target =
        message_signature_credential_metadata("direct-replacement-password-credential");
    let direct_replacement_authority = CredentialRecoveryAuthority::new(
        direct_replacement_target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        id("direct-replacement-authority"),
        RecoveryAuthorityTiming::Immediate,
    );
    let direct_replacement_successor = replacement_successor_inheriting_target_policy(
        "direct-replacement-password-credential-successor",
        &direct_replacement_target,
        [direct_replacement_authority.clone()],
        [id("direct-replacement-successor-authority")],
    );
    let direct_replacement_plan = Command::PlanCredentialReplacement(PlanCredentialReplacement {
        now: at(30),
        lifecycle_context: credential_lifecycle_context(
            direct_replacement_target.clone(),
            [direct_replacement_authority.clone()],
            [credential_instance_lifecycle_evidence(
                "direct-replacement-source",
                [id("direct-replacement-authority")],
            )],
        ),
        independent_evidence_required:
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        pending_action: None,
    });

    let replacement_plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_replacement_plan)
        .await
        .expect_err(
            "runtime must not accept caller-provided credential replacement lifecycle context",
        );

    assert!(matches!(
        replacement_plan_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialReplacementPlanningRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_replacement_execute =
        Command::ExecuteCredentialReplacement(ExecuteCredentialReplacement {
            now: at(30),
            execution_authority: CredentialReplacementExecutionAuthority {
                lifecycle_context: credential_lifecycle_context(
                    direct_replacement_target.clone(),
                    [direct_replacement_authority],
                    [credential_instance_lifecycle_evidence(
                        "direct-replacement-source",
                        [id("direct-replacement-authority")],
                    )],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            successor: direct_replacement_successor.clone(),
            method_commit_work: vec![password_reset_method_commit_work(
                b"direct-replacement-verifier",
            )],
        });

    let replacement_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_replacement_execute)
        .await
        .expect_err("runtime must not accept caller-provided credential replacement method work");

    assert!(matches!(
        replacement_execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialReplacementExecutionRequiresRuntimeMethodDispatch
        )
    ));

    let direct_regeneration_plan =
        Command::PlanCredentialRegeneration(PlanCredentialRegeneration {
            now: at(30),
            lifecycle_context: credential_lifecycle_context(
                direct_replacement_target.clone(),
                [CredentialRecoveryAuthority::new(
                    direct_replacement_target_credential_id.clone(),
                    CredentialLifecycleAction::Regenerate,
                    id("direct-regeneration-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [credential_instance_lifecycle_evidence(
                    "direct-regeneration-source",
                    [id("direct-regeneration-authority")],
                )],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        });

    let regeneration_plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_regeneration_plan)
        .await
        .expect_err(
            "runtime must not accept caller-provided credential regeneration lifecycle context",
        );

    assert!(matches!(
        regeneration_plan_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialRegenerationPlanningRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_regeneration_execute =
        Command::ExecuteCredentialRegeneration(ExecuteCredentialRegeneration {
            now: at(30),
            execution_authority: CredentialRegenerationExecutionAuthority {
                lifecycle_context: credential_lifecycle_context(
                    direct_replacement_target.clone(),
                    [CredentialRecoveryAuthority::new(
                        direct_replacement_target_credential_id.clone(),
                        CredentialLifecycleAction::Regenerate,
                        id("direct-regeneration-execute-authority"),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [credential_instance_lifecycle_evidence(
                        "direct-regeneration-execute-source",
                        [id("direct-regeneration-execute-authority")],
                    )],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: vec![password_reset_method_commit_work(
                b"direct-regeneration-verifier",
            )],
        });

    let regeneration_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_regeneration_execute)
        .await
        .expect_err("runtime must not accept caller-provided credential regeneration method work");

    assert!(matches!(
        regeneration_execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialRegenerationExecutionRequiresRuntimeMethodDispatch
        )
    ));

    let direct_add_target_credential_id = id("direct-add-password-credential");
    let direct_add = Command::AddCredential(AddCredential {
        now: at(30),
        lifecycle_context: credential_lifecycle_context(
            message_signature_credential_metadata("direct-add-password-credential"),
            [CredentialRecoveryAuthority::new(
                direct_add_target_credential_id,
                CredentialLifecycleAction::Create,
                id("direct-add-authority"),
                RecoveryAuthorityTiming::Immediate,
            )],
            [credential_instance_lifecycle_evidence(
                "direct-add-source",
                [id("direct-add-authority")],
            )],
        ),
        independent_evidence_required:
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        new_credential_authority_ids: vec![id("direct-add-new-authority")],
        method_commit_work: vec![password_creation_method_commit_work(b"direct-add-verifier")],
    });

    let add_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_add)
        .await
        .expect_err("runtime must not accept caller-provided credential addition facts");

    assert!(matches!(
        add_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialAdditionRequiresRuntimeMethodDispatch
        )
    ));

    let direct_cancel = Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
        now: at(30),
        target_credential: message_signature_credential_metadata(
            "direct-reset-password-credential",
        ),
        pending_action: PendingCredentialLifecycleActionRecord::new_open(
            id("direct-reset-pending-action"),
            id("subject"),
            id("direct-reset-password-credential"),
            CredentialLifecycleAction::Reset,
            at(10),
            at(100),
            at(200),
        )
        .expect("pending reset action"),
    });

    let cancel_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_cancel)
        .await
        .expect_err("runtime must not accept caller-provided credential reset cancellation facts");

    assert!(matches!(
        cancel_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialResetCancellationRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_lifecycle_execute = Command::ExecuteNonResetPendingCredentialLifecycleAction(
        ExecuteNonResetPendingCredentialLifecycleAction {
            now: at(30),
            target_credential: direct_replacement_target,
            pending_action: PendingCredentialLifecycleActionRecord::new_open(
                id("direct-replacement-pending-action"),
                id("subject"),
                id("direct-replacement-password-credential"),
                CredentialLifecycleAction::Replace,
                at(10),
                at(20),
                at(200),
            )
            .expect("pending replacement action"),
            replacement_successor: Some(direct_replacement_successor),
            method_commit_work: vec![password_reset_method_commit_work(
                b"direct-replacement-verifier",
            )],
        },
    );

    let lifecycle_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_lifecycle_execute)
        .await
        .expect_err("runtime must not accept caller-provided lifecycle execution facts");

    assert!(matches!(
        lifecycle_execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleExecutionRequiresRuntimeMethodDispatch
        )
    ));

    let direct_lifecycle_cancel = Command::CancelNonResetPendingCredentialLifecycleAction(
        CancelNonResetPendingCredentialLifecycleAction {
            now: at(30),
            target_credential: message_signature_credential_metadata(
                "direct-replacement-password-credential",
            ),
            pending_action: PendingCredentialLifecycleActionRecord::new_open(
                id("direct-replacement-pending-action"),
                id("subject"),
                id("direct-replacement-password-credential"),
                CredentialLifecycleAction::Replace,
                at(10),
                at(100),
                at(200),
            )
            .expect("pending replacement action"),
        },
    );

    let lifecycle_cancel_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_lifecycle_cancel)
        .await
        .expect_err("runtime must not accept caller-provided lifecycle cancellation facts");

    assert!(matches!(
        lifecycle_cancel_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleCancellationRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_support_intervention = VerifiedAdminSupportCredentialLifecycleIntervention::new(
        id("direct-support-intervention"),
        id("subject"),
        id("direct-support-password-credential"),
        CredentialLifecycleAction::Reset,
        at(10),
        at(60),
    )
    .expect("direct support intervention");
    let direct_support_plan = Command::PlanAdminSupportCredentialLifecycleIntervention(
        PlanAdminSupportCredentialLifecycleIntervention {
            now: at(30),
            intervention: direct_support_intervention.clone(),
            lifecycle_context: credential_lifecycle_context(
                message_signature_credential_metadata("direct-support-password-credential"),
                [CredentialRecoveryAuthority::new(
                    id("direct-support-password-credential"),
                    CredentialLifecycleAction::Reset,
                    id("direct-support-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [LifecycleAuthorityEvidence::admin_support_intervention(
                    direct_support_intervention,
                    [id("direct-support-authority")],
                )
                .expect("direct support evidence")],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        },
    );

    let support_plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_support_plan)
        .await
        .expect_err("runtime must not accept caller-provided support intervention facts");

    assert!(matches!(
        support_plan_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionPlanningRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_support_request =
        Command::RequestAdminSupportIntervention(RequestAdminSupportIntervention {
            now: at(30),
            intervention_id: id("direct-support-request"),
            subject_id: id("subject"),
            target_credential_instance_id: id("direct-support-password-credential"),
            action: CredentialLifecycleAction::Reset,
            expires_at: at(90),
        });

    let support_request_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_support_request)
        .await
        .expect_err("runtime must not accept caller-provided support request ids");

    assert!(matches!(
        support_request_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionWorkflowRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_support_record = AdminSupportInterventionRecord::new_requested(
        id("direct-support-record"),
        id("subject"),
        id("direct-support-password-credential"),
        CredentialLifecycleAction::Reset,
        at(10),
        at(90),
    )
    .expect("direct support record");
    let direct_support_approval =
        Command::ApproveAdminSupportIntervention(ApproveAdminSupportIntervention {
            now: at(30),
            intervention: direct_support_record.clone(),
            lifecycle_context: credential_lifecycle_context(
                message_signature_credential_metadata("direct-support-password-credential"),
                [CredentialRecoveryAuthority::new(
                    id("direct-support-password-credential"),
                    CredentialLifecycleAction::Reset,
                    id("direct-support-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [LifecycleAuthorityEvidence::admin_support_intervention(
                    VerifiedAdminSupportCredentialLifecycleIntervention::new(
                        id("direct-support-record"),
                        id("subject"),
                        id("direct-support-password-credential"),
                        CredentialLifecycleAction::Reset,
                        at(10),
                        at(60),
                    )
                    .expect("direct support intervention record proof"),
                    [id("direct-support-authority")],
                )
                .expect("direct support intervention record evidence")],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        });

    let support_approval_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_support_approval)
        .await
        .expect_err("runtime must not accept caller-provided support approval facts");

    assert!(matches!(
        support_approval_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionWorkflowRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_support_denial =
        Command::DenyAdminSupportIntervention(DenyAdminSupportIntervention {
            now: at(30),
            intervention: direct_support_record.clone(),
        });

    let support_denial_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_support_denial)
        .await
        .expect_err("runtime must not accept caller-provided support denial facts");

    assert!(matches!(
        support_denial_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionWorkflowRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_support_expiry =
        Command::ExpireAdminSupportIntervention(ExpireAdminSupportIntervention {
            now: at(90),
            intervention: direct_support_record,
        });

    let support_expiry_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_support_expiry)
        .await
        .expect_err("runtime must not accept caller-provided support expiry facts");

    assert!(matches!(
        support_expiry_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionWorkflowRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_subject_deletion_schedule =
        Command::ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion {
            now: at(30),
            subject_id: id("subject"),
            pending_action: PendingSubjectLifecycleActionSchedule {
                pending_action_id: id("direct-subject-deletion-pending-action"),
                earliest_execute_at: at(100),
                expires_at: at(200),
            },
        });

    let subject_deletion_schedule_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_subject_deletion_schedule)
        .await
        .expect_err("runtime must not accept caller-provided subject deletion schedule facts");

    assert!(matches!(
        subject_deletion_schedule_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::SubjectAuthStateDeletionSchedulingRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_subject_deletion_pending_action = PendingSubjectLifecycleActionRecord::new_open(
        id("direct-subject-deletion-pending-action"),
        id("subject"),
        SubjectLifecycleAction::DeleteSubjectAuthState,
        at(10),
        at(20),
        at(200),
    )
    .expect("pending subject deletion action");

    let direct_subject_deletion_execute =
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(30),
            pending_action: direct_subject_deletion_pending_action.clone(),
            application_subject_data_lifecycle_action: None,
        });

    let subject_deletion_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_subject_deletion_execute)
        .await
        .expect_err("runtime must not accept caller-provided subject deletion execution facts");

    assert!(matches!(
        subject_deletion_execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::SubjectAuthStateDeletionExecutionRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_subject_deletion_cancel =
        Command::CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion {
            now: at(30),
            pending_action: direct_subject_deletion_pending_action,
        });

    let subject_deletion_cancel_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_subject_deletion_cancel)
        .await
        .expect_err("runtime must not accept caller-provided subject deletion cancellation facts");

    assert!(matches!(
        subject_deletion_cancel_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::SubjectAuthStateDeletionCancellationRequiresRuntimeLifecycleDecision
        )
    ));

    let identifier_change_subject_id = id("direct-identifier-change-subject");
    let identifier_change_current_source_id = id("direct-identifier-change-current");
    let identifier_change_candidate_source_id = id("direct-identifier-change-candidate");
    let identifier_change_authority = id("direct-identifier-change-authority");
    let identifier_change_context = identifier_change_context_for_runtime_boundary_test(
        identifier_change_subject_id.clone(),
        identifier_change_current_source_id,
        identifier_change_candidate_source_id.clone(),
        [SubjectLifecycleAuthority::new(
            identifier_change_subject_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
            identifier_change_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        [out_of_band_identifier_lifecycle_evidence(
            "direct-identifier-change-current",
            [identifier_change_authority],
        )],
    );
    let direct_identifier_change_plan =
        Command::PlanOutOfBandIdentifierChange(PlanOutOfBandIdentifierChange {
            now: at(30),
            change_context: identifier_change_context.clone(),
            independent_evidence_required:
                SubjectLifecycleIndependentEvidenceRequirement::NotRequired,
            candidate_authority_ids: vec![id("direct-identifier-change-candidate-authority")],
            pending_action: None,
        });

    let identifier_change_plan_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_identifier_change_plan)
        .await
        .expect_err("runtime must not accept caller-provided identifier-change planning facts");

    assert!(matches!(
        identifier_change_plan_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_identifier_change_candidate_reservation =
        Command::ReserveOutOfBandIdentifierChangeCandidateBinding(
            ReserveOutOfBandIdentifierChangeCandidateBinding {
                now: at(30),
                attempt_id: id("direct-identifier-change-attempt"),
                challenge_id: id("direct-identifier-change-challenge"),
                candidate_identifier_source: VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    identifier_change_candidate_source_id,
                ),
                stateless_fast_fail: verified_stateless_fast_fail(),
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            },
        );

    let identifier_change_reservation_error = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            direct_identifier_change_candidate_reservation,
        )
        .await
        .expect_err("runtime must not accept caller-provided identifier-change candidate binding");

    assert!(matches!(
        identifier_change_reservation_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision
        )
    ));

    let direct_identifier_change_execute =
        Command::ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange {
            now: at(30),
            change_context: identifier_change_context,
            independent_evidence_required:
                SubjectLifecycleIndependentEvidenceRequirement::NotRequired,
            candidate_authority_ids: vec![id("direct-identifier-change-candidate-authority")],
        });

    let identifier_change_execute_error = runtime
        .execute_from_headers(&HeaderMap::new(), direct_identifier_change_execute)
        .await
        .expect_err("runtime must not accept caller-provided identifier-change execution facts");

    assert!(matches!(
        identifier_change_execute_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::OutOfBandIdentifierChangeRequiresRuntimeLifecycleDecision
        )
    ));

    harness.drop_schema().await;
}
