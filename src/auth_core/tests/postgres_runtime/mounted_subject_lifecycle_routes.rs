use super::*;

#[tokio::test]
async fn mounted_auth_http_out_of_band_identifier_change_route_activates_candidate_and_uses_csrf_guard()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let subject_id: SubjectId = id("mounted-http-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-identifier-change-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let current_identifier_source_id = id("mounted-http-identifier-change-current");
    let candidate_identifier_source_id = id("mounted-http-identifier-change-candidate");
    let current_identifier_authority = id("mounted-http-identifier-change-current-authority");
    let stale_candidate_identifier_authority =
        id("mounted-http-identifier-change-stale-candidate-authority");
    let session_authority = id("mounted-http-identifier-change-session-authority");
    seed_out_of_band_identifier_change_runtime_state(
        &harness.pool,
        &harness.store_config,
        &subject_id,
        &issued_auth.session_id,
        &current_identifier_source_id,
        &candidate_identifier_source_id,
        current_identifier_authority.clone(),
        session_authority,
        RecoveryAuthorityTiming::Immediate,
    )
    .await;
    let stale_candidate_authority_store =
        super::super::super::postgres_store::PostgresAuthStore::new(
            harness.store_config.clone(),
            test_keyset("tests.auth.postgres-runtime.mounted-http-identifier-change.v1"),
        );
    stale_candidate_authority_store
        .store_subject_lifecycle_metadata_for_test(
            &harness.pool,
            &[],
            &[LifecycleAuthorityEvidence::from_verified_proof_source(
                VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    candidate_identifier_source_id.clone(),
                ),
                [stale_candidate_identifier_authority.clone()],
            )
            .expect("stale candidate identifier lifecycle evidence")],
            at(55),
        )
        .await
        .expect("seed stale candidate authority mapping");

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default()
                .with_authenticated_out_of_band_identifier_change_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(80));

    database_operation_observer.clear();
    let missing_csrf_response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/out-of-band-identifiers/change/execute")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF identifier-change request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted identifier-change route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on identifier change must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for identifier-change route test")
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
    let current_identifier_source_id_base64url =
        BASE64URL_NOPAD.encode(current_identifier_source_id.as_bytes());
    let candidate_identifier_source_id_base64url =
        BASE64URL_NOPAD.encode(candidate_identifier_source_id.as_bytes());
    database_operation_observer.clear();
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/out-of-band-identifiers/change/execute")
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
                            "current_identifier_source_id_base64url": "{}",
                            "candidate_identifier_source_id_base64url": "{}"
                        }}"#,
                        current_identifier_source_id_base64url,
                        candidate_identifier_source_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("identifier-change route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.out_of_band_identifier_binding",
            "auth_core.load.out_of_band_identifier_binding",
            "auth_core.load.subject_lifecycle_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.out_of_band_identifier_binding_still_active",
            "auth_core.precondition.out_of_band_identifier_binding_still_pending_activation",
            "auth_core.mutation.set_out_of_band_identifier_binding_lifecycle_state",
            "auth_core.mutation.set_out_of_band_identifier_binding_lifecycle_state",
            "auth_core.mutation.delete_lifecycle_authority_sources_for_source",
            "auth_core.mutation.insert_lifecycle_authority_source",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted identifier-change execution route must stay inside one live-session load, binding-state guards, candidate activation, authority replacement, auth-state revocation, notice, and commit",
    );

    assert_eq!(response.status(), StatusCode::OK);
    let response_body_text =
        String::from_utf8(response.body().clone()).expect("identifier-change response is UTF-8");
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("out_of_band_identifier_changed")
    );
    assert!(
        !response_body_text.contains("subject_id")
            && !response_body_text.contains("current_identifier_source_id")
            && !response_body_text.contains("candidate_identifier_source_id")
            && !response_body_text.contains("pending_action_id"),
        "mounted identifier-change route response must not expose internal lifecycle ids"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            &pool,
            &store_config,
            &current_identifier_source_id,
        )
        .await
        .expect("current identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Superseded,
        "mounted identifier-change route must supersede the old binding"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            &pool,
            &store_config,
            &candidate_identifier_source_id,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Active,
        "mounted identifier-change route must activate the candidate binding"
    );
    assert_eq!(
        fetch_lifecycle_authority_ids_for_runtime_test(
            &pool,
            &store_config,
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
            &candidate_identifier_source_id,
        )
        .await,
        vec![current_identifier_authority],
        "mounted identifier-change route must preserve the current source authority mapping instead of stale candidate mapping"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted identifier-change route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(80),
        "mounted identifier-change route must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_delayed_out_of_band_identifier_change_routes_commit_only_coarse_outcomes()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let execute_subject_id: SubjectId = id("mounted-http-delayed-identifier-execute-subject");
    let execute_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-delayed-identifier-execute-bootstrap",
        50,
        execute_subject_id.clone(),
        false,
    )
    .await;
    let cancel_subject_id: SubjectId = id("mounted-http-delayed-identifier-cancel-subject");
    let cancel_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-delayed-identifier-cancel-bootstrap",
        50,
        cancel_subject_id.clone(),
        false,
    )
    .await;
    let stale_cancel_subject_id: SubjectId =
        id("mounted-http-delayed-identifier-stale-cancel-subject");
    let stale_cancel_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-delayed-identifier-stale-cancel-bootstrap",
        20,
        stale_cancel_subject_id.clone(),
        false,
    )
    .await;
    let execute_current_source = id("mounted-http-delayed-identifier-execute-current");
    let execute_candidate_source = id("mounted-http-delayed-identifier-execute-candidate");
    let cancel_current_source = id("mounted-http-delayed-identifier-cancel-current");
    let cancel_candidate_source = id("mounted-http-delayed-identifier-cancel-candidate");
    let stale_cancel_current_source = id("mounted-http-delayed-identifier-stale-current");
    let stale_cancel_candidate_source = id("mounted-http-delayed-identifier-stale-candidate");
    seed_out_of_band_identifier_change_runtime_state(
        &harness.pool,
        &harness.store_config,
        &execute_subject_id,
        &execute_issued_auth.session_id,
        &execute_current_source,
        &execute_candidate_source,
        id("mounted-http-delayed-identifier-execute-current-authority"),
        id("mounted-http-delayed-identifier-execute-session-authority"),
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    seed_out_of_band_identifier_change_runtime_state(
        &harness.pool,
        &harness.store_config,
        &cancel_subject_id,
        &cancel_issued_auth.session_id,
        &cancel_current_source,
        &cancel_candidate_source,
        id("mounted-http-delayed-identifier-cancel-current-authority"),
        id("mounted-http-delayed-identifier-cancel-session-authority"),
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    seed_out_of_band_identifier_change_runtime_state(
        &harness.pool,
        &harness.store_config,
        &stale_cancel_subject_id,
        &stale_cancel_issued_auth.session_id,
        &stale_cancel_current_source,
        &stale_cancel_candidate_source,
        id("mounted-http-delayed-identifier-stale-current-authority"),
        id("mounted-http-delayed-identifier-stale-session-authority"),
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    let execute_pending_action_id = id("mounted-http-delayed-identifier-execute-action");
    let cancel_pending_action_id = id("mounted-http-delayed-identifier-cancel-action");
    let stale_cancel_pending_action_id = id("mounted-http-delayed-identifier-stale-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-delayed-identifier.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            &harness.pool,
            &[
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    execute_pending_action_id.clone(),
                    execute_subject_id.clone(),
                    execute_current_source.clone(),
                    execute_candidate_source.clone(),
                    vec![id(
                        "mounted-http-delayed-identifier-execute-candidate-authority",
                    )],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("execute pending identifier-change action"),
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    cancel_pending_action_id.clone(),
                    cancel_subject_id.clone(),
                    cancel_current_source.clone(),
                    cancel_candidate_source.clone(),
                    vec![id(
                        "mounted-http-delayed-identifier-cancel-candidate-authority",
                    )],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("cancel pending identifier-change action"),
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    stale_cancel_pending_action_id.clone(),
                    stale_cancel_subject_id.clone(),
                    stale_cancel_current_source,
                    stale_cancel_candidate_source,
                    vec![id(
                        "mounted-http-delayed-identifier-stale-candidate-authority",
                    )],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("stale cancel pending identifier-change action"),
            ],
        )
        .await
        .expect("seed pending identifier-change actions");

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default()
                .with_authenticated_out_of_band_identifier_change_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut missing_csrf_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(250));

    database_operation_observer.clear();
    let missing_csrf_response = missing_csrf_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/out-of-band-identifiers/change/delayed/execute")
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF delayed identifier-change request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted delayed identifier-change route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on delayed identifier change must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for delayed identifier-change route test")
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

    let mut execute_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(250));
    let execute_pending_action_id_base64url =
        BASE64URL_NOPAD.encode(execute_pending_action_id.as_bytes());
    database_operation_observer.clear();
    let execute_response = execute_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/out-of-band-identifiers/change/delayed/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}"
                        }}"#,
                        execute_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("delayed identifier-change execution route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_subject_lifecycle_action",
            "auth_core.precondition.pending_subject_lifecycle_action_still_executable",
            "auth_core.precondition.out_of_band_identifier_binding_still_active",
            "auth_core.precondition.out_of_band_identifier_binding_still_pending_activation",
            "auth_core.mutation.close_pending_subject_lifecycle_action",
            "auth_core.mutation.set_out_of_band_identifier_binding_lifecycle_state",
            "auth_core.mutation.set_out_of_band_identifier_binding_lifecycle_state",
            "auth_core.mutation.delete_lifecycle_authority_sources_for_source",
            "auth_core.mutation.insert_lifecycle_authority_source",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted delayed identifier-change execution route must stay inside one pending-action load, binding-state guards, candidate activation, authority replacement, auth-state revocation, notice, and commit",
    );
    assert_eq!(execute_response.status(), StatusCode::OK);
    let execute_response_text = String::from_utf8(execute_response.body().clone())
        .expect("delayed identifier-change execute response is UTF-8");
    let execute_response_body = auth_runtime_test_json_response_body(&execute_response);
    assert_eq!(
        execute_response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("delayed_out_of_band_identifier_changed")
    );
    assert!(
        !execute_response_text.contains("subject_id")
            && !execute_response_text.contains("pending_action_id")
            && !execute_response_text.contains("current_identifier_source_id")
            && !execute_response_text.contains("candidate_identifier_source_id"),
        "mounted delayed identifier-change execution response must not expose internal lifecycle ids"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            &pool,
            &store_config,
            &execute_pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        0,
        "mounted delayed identifier-change route must close the pending action"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            &pool,
            &store_config,
            &execute_current_source,
        )
        .await
        .expect("current identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Superseded,
        "mounted delayed identifier-change route must supersede the old binding"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            &pool,
            &store_config,
            &execute_candidate_source,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Active,
        "mounted delayed identifier-change route must activate the candidate binding"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &execute_subject_id)
            .await,
        1,
        "mounted delayed identifier-change route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &execute_subject_id).await,
        Some(250),
        "mounted delayed identifier-change route must revoke existing subject auth state"
    );

    let mut cancel_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let cancel_pending_action_id_base64url =
        BASE64URL_NOPAD.encode(cancel_pending_action_id.as_bytes());
    database_operation_observer.clear();
    let cancel_response = cancel_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/out-of-band-identifiers/change/delayed/cancel")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        cancel_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}"
                        }}"#,
                        cancel_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("delayed identifier-change cancellation route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.pending_subject_lifecycle_action",
            "auth_core.precondition.pending_subject_lifecycle_action_still_cancellable_for_subject",
            "auth_core.mutation.close_pending_subject_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted delayed identifier-change cancellation route must stay inside one live-session load, pending-action load, cancellable guard, pending closure, audit, notice, and commit",
    );
    assert_eq!(cancel_response.status(), StatusCode::OK);
    let cancel_response_text = String::from_utf8(cancel_response.body().clone())
        .expect("delayed identifier-change cancel response is UTF-8");
    let cancel_response_body = auth_runtime_test_json_response_body(&cancel_response);
    assert_eq!(
        cancel_response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("delayed_out_of_band_identifier_change_cancelled")
    );
    assert!(
        !cancel_response_text.contains("subject_id")
            && !cancel_response_text.contains("pending_action_id")
            && !cancel_response_text.contains("current_identifier_source_id")
            && !cancel_response_text.contains("candidate_identifier_source_id"),
        "mounted delayed identifier-change cancellation response must not expose internal lifecycle ids"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            &pool,
            &store_config,
            &cancel_pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        0,
        "mounted delayed identifier-change cancellation route must close the pending action"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            &pool,
            &store_config,
            &cancel_candidate_source,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::PendingActivation,
        "mounted delayed identifier-change cancellation must not activate the candidate binding"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &cancel_subject_id)
            .await,
        1,
        "mounted delayed identifier-change cancellation route must atomically schedule the cancellation notice"
    );

    let mut stale_cancel_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let stale_cancel_pending_action_id_base64url =
        BASE64URL_NOPAD.encode(stale_cancel_pending_action_id.as_bytes());
    database_operation_observer.clear();
    let stale_cancel_response = stale_cancel_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/out-of-band-identifiers/change/delayed/cancel")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        stale_cancel_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}"
                        }}"#,
                        stale_cancel_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("stale delayed identifier-change cancellation route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(stale_cancel_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&stale_cancel_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("needs_step_up")
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "db.tx.rollback",
        ],
        "stale delayed identifier-change cancellation must reject after live-session freshness check and before pending-action load",
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            &pool,
            &store_config,
            &stale_cancel_pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        1,
        "stale mounted delayed identifier-change cancellation must not close the pending action"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_subject_auth_state_deletion_routes_commit_only_coarse_outcomes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let schedule_subject_id: SubjectId = id("mounted-http-subject-deletion-schedule-subject");
    let schedule_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-subject-deletion-schedule-bootstrap",
        50,
        schedule_subject_id.clone(),
        false,
    )
    .await;
    let stale_schedule_subject_id: SubjectId =
        id("mounted-http-subject-deletion-stale-schedule-subject");
    let stale_schedule_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-subject-deletion-stale-schedule-bootstrap",
        20,
        stale_schedule_subject_id.clone(),
        false,
    )
    .await;
    let execute_subject_id: SubjectId = id("mounted-http-subject-deletion-execute-subject");
    let _execute_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-subject-deletion-execute-bootstrap",
        20,
        execute_subject_id.clone(),
        false,
    )
    .await;
    let cancel_subject_id: SubjectId = id("mounted-http-subject-deletion-cancel-subject");
    let cancel_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-subject-deletion-cancel-bootstrap",
        50,
        cancel_subject_id.clone(),
        false,
    )
    .await;
    let stale_cancel_subject_id: SubjectId =
        id("mounted-http-subject-deletion-stale-cancel-subject");
    let stale_cancel_issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-subject-deletion-stale-cancel-bootstrap",
        20,
        stale_cancel_subject_id.clone(),
        false,
    )
    .await;
    let execute_pending_action_id = id("mounted-http-subject-deletion-execute-action");
    let cancel_pending_action_id = id("mounted-http-subject-deletion-cancel-action");
    let stale_cancel_pending_action_id = id("mounted-http-subject-deletion-stale-cancel-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-subject-deletion.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            &harness.pool,
            &[
                PendingSubjectLifecycleActionRecord::new_open(
                    execute_pending_action_id.clone(),
                    execute_subject_id.clone(),
                    SubjectLifecycleAction::DeleteSubjectAuthState,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("execute pending subject auth-state deletion action"),
                PendingSubjectLifecycleActionRecord::new_open(
                    cancel_pending_action_id.clone(),
                    cancel_subject_id.clone(),
                    SubjectLifecycleAction::DeleteSubjectAuthState,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("cancel pending subject auth-state deletion action"),
                PendingSubjectLifecycleActionRecord::new_open(
                    stale_cancel_pending_action_id.clone(),
                    stale_cancel_subject_id.clone(),
                    SubjectLifecycleAction::DeleteSubjectAuthState,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("stale cancel pending subject auth-state deletion action"),
            ],
        )
        .await
        .expect("seed pending subject auth-state deletion actions");

    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_delayed_subject_auth_state_deletion_routes(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut missing_csrf_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(250));

    database_operation_observer.clear();
    let missing_csrf_response = missing_csrf_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/execute")
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF subject deletion request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted subject deletion route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on subject auth-state deletion execution must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for subject deletion route test")
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

    let mut non_empty_schedule_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    database_operation_observer.clear();
    let non_empty_schedule_response = non_empty_schedule_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/schedule")
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        schedule_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from_static(
                    b"schedule-body-must-be-empty",
                )))
                .expect("non-empty subject deletion schedule route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        non_empty_schedule_response.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_http_response_has_no_set_cookie(
        &non_empty_schedule_response,
        "non-empty subject deletion schedule body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&non_empty_schedule_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("payload_too_large")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "non-empty subject deletion schedule body must reject before any database operation",
    );

    let mut missing_content_type_execute_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(250));
    database_operation_observer.clear();
    let missing_content_type_execute_response = missing_content_type_execute_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/execute")
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from_static(b"{}")))
                .expect("missing content-type subject deletion execution request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        missing_content_type_execute_response.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_http_response_has_no_set_cookie(
        &missing_content_type_execute_response,
        "missing content-type subject deletion execution body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_content_type_execute_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("unsupported_media_type")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing content-type on subject deletion execution must reject before any database operation",
    );

    let mut invalid_cancel_body_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    database_operation_observer.clear();
    let invalid_cancel_body_response = invalid_cancel_body_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/cancel")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from_static(
                    br#"{"pending_action_id_base64url":"not base64"}"#,
                )))
                .expect("invalid subject deletion cancellation body request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        invalid_cancel_body_response.status(),
        StatusCode::BAD_REQUEST
    );
    assert_http_response_has_no_set_cookie(
        &invalid_cancel_body_response,
        "invalid subject deletion cancellation body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&invalid_cancel_body_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("bad_request")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "invalid subject deletion cancellation body must reject before any database operation",
    );

    let mut unknown_app_action_execute_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(250));
    database_operation_observer.clear();
    let execute_pending_action_id_base64url =
        BASE64URL_NOPAD.encode(execute_pending_action_id.as_bytes());
    let unknown_app_action_execute_response = unknown_app_action_execute_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}",
                            "application_subject_data_lifecycle_action": "destroy_everything"
                        }}"#,
                        execute_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("unknown app action subject deletion execution request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        unknown_app_action_execute_response.status(),
        StatusCode::BAD_REQUEST
    );
    assert_http_response_has_no_set_cookie(
        &unknown_app_action_execute_response,
        "unknown app action subject deletion execution body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&unknown_app_action_execute_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("bad_request")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "unknown app action on subject deletion execution must reject before any database operation",
    );

    let mut stale_schedule_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    database_operation_observer.clear();
    let stale_schedule_response = stale_schedule_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/schedule")
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        stale_schedule_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::new()))
                .expect("stale subject deletion schedule route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(stale_schedule_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&stale_schedule_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("needs_step_up")
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "db.tx.rollback",
        ],
        "stale subject-auth-state deletion scheduling must reject after live-session freshness check and before pending-action creation",
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_subject(
            &pool,
            &store_config,
            &stale_schedule_subject_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "stale mounted subject deletion scheduling must not create a pending action"
    );

    let mut schedule_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    database_operation_observer.clear();
    let schedule_response = schedule_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/schedule")
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        schedule_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::new()))
                .expect("subject deletion schedule route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.precondition.close_expired_pending_subject_lifecycle_actions",
            "auth_core.precondition.no_open_pending_subject_lifecycle_action",
            "auth_core.mutation.create_pending_subject_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted subject-auth-state deletion scheduling route must stay inside one live-session load, pending-action uniqueness guard, pending creation, audit, notice, and commit",
    );
    assert_eq!(schedule_response.status(), StatusCode::OK);
    let schedule_response_text = String::from_utf8(schedule_response.body().clone())
        .expect("subject deletion schedule response is UTF-8");
    let schedule_response_body = auth_runtime_test_json_response_body(&schedule_response);
    assert_eq!(
        schedule_response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("subject_auth_state_deletion_scheduled")
    );
    assert_eq!(
        schedule_response_body
            .get("earliest_execute_at_unix_seconds")
            .and_then(serde_json::Value::as_i64),
        Some(1090),
        "schedule route must use Paranoid-owned deletion delay policy"
    );
    assert_eq!(
        schedule_response_body
            .get("expires_at_unix_seconds")
            .and_then(serde_json::Value::as_i64),
        Some(10090),
        "schedule route must use Paranoid-owned deletion expiry policy"
    );
    assert!(
        !schedule_response_text.contains("subject_id")
            && !schedule_response_text.contains("pending_action_id"),
        "mounted subject deletion scheduling response must not expose internal lifecycle ids"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_subject(
            &pool,
            &store_config,
            &schedule_subject_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "mounted subject deletion scheduling route must create one pending action for the authenticated subject"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &schedule_subject_id)
            .await,
        1,
        "mounted subject deletion scheduling route must atomically schedule the security notice"
    );

    let mut execute_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(250));
    database_operation_observer.clear();
    let execute_response = execute_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/execute")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, csrf_cookie_pair.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}",
                            "application_subject_data_lifecycle_action": "disable_subject_data"
                        }}"#,
                        execute_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("subject deletion execute route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_subject_lifecycle_action",
            "auth_core.precondition.pending_subject_lifecycle_action_still_executable",
            "auth_core.mutation.close_pending_subject_lifecycle_action",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "auth_core.effect.append_application_subject_data_lifecycle",
            "db.tx.commit",
        ],
        "mounted subject-auth-state deletion execution route must stay inside one pending-action load, executable guard, pending closure, auth-state revocation, durable effects, and commit",
    );
    assert_eq!(execute_response.status(), StatusCode::OK);
    let execute_response_text = String::from_utf8(execute_response.body().clone())
        .expect("subject deletion execute response is UTF-8");
    let execute_response_body = auth_runtime_test_json_response_body(&execute_response);
    assert_eq!(
        execute_response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("subject_auth_state_deleted")
    );
    assert!(
        !execute_response_text.contains("subject_id")
            && !execute_response_text.contains("pending_action_id"),
        "mounted subject deletion execution response must not expose internal lifecycle ids"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            &pool,
            &store_config,
            &execute_pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "mounted subject deletion route must close the pending action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &execute_subject_id)
            .await,
        1,
        "mounted subject deletion route must atomically schedule the security notice"
    );
    assert_eq!(
        count_application_subject_data_lifecycle_effects_for_subject_and_kind(
            &pool,
            &store_config,
            &execute_subject_id,
            super::super::super::postgres_store::DURABLE_EFFECT_KIND_DISABLE_APPLICATION_SUBJECT_DATA,
        )
        .await,
        1,
        "mounted subject deletion route must atomically request the configured app-owned data lifecycle action"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &execute_subject_id).await,
        Some(250),
        "mounted subject deletion route must revoke existing subject auth state"
    );
    let mut cancel_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let cancel_pending_action_id_base64url =
        BASE64URL_NOPAD.encode(cancel_pending_action_id.as_bytes());
    database_operation_observer.clear();
    let cancel_response = cancel_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/cancel")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        cancel_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}"
                        }}"#,
                        cancel_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("subject deletion cancellation route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.pending_subject_lifecycle_action",
            "auth_core.precondition.pending_subject_lifecycle_action_still_cancellable_for_subject",
            "auth_core.mutation.close_pending_subject_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted subject-auth-state deletion cancellation route must stay inside one live-session load, pending-action load, cancellable guard, pending closure, audit, notice, and commit",
    );
    assert_eq!(cancel_response.status(), StatusCode::OK);
    let cancel_response_text = String::from_utf8(cancel_response.body().clone())
        .expect("subject deletion cancel response is UTF-8");
    let cancel_response_body = auth_runtime_test_json_response_body(&cancel_response);
    assert_eq!(
        cancel_response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("subject_auth_state_deletion_cancelled")
    );
    assert!(
        !cancel_response_text.contains("subject_id")
            && !cancel_response_text.contains("pending_action_id"),
        "mounted subject deletion cancellation response must not expose internal lifecycle ids"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            &pool,
            &store_config,
            &cancel_pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "mounted subject deletion cancellation route must close the pending action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &cancel_subject_id)
            .await,
        1,
        "mounted subject deletion cancellation route must atomically schedule the cancellation notice"
    );

    let mut stale_cancel_http_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(90));
    let stale_cancel_pending_action_id_base64url =
        BASE64URL_NOPAD.encode(stale_cancel_pending_action_id.as_bytes());
    database_operation_observer.clear();
    let stale_cancel_response = stale_cancel_http_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/subject-auth-state/delete/cancel")
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(
                    COOKIE,
                    format!(
                        "{}; {}",
                        stale_cancel_issued_auth.session_cookie_pair.as_str(),
                        csrf_cookie_pair
                    ),
                )
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(
                    format!(
                        r#"{{
                            "pending_action_id_base64url": "{}"
                        }}"#,
                        stale_cancel_pending_action_id_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("stale subject deletion cancellation route request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(stale_cancel_response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&stale_cancel_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("needs_step_up"),
        "stale cancellation should render a normal route outcome instead of an internal route error"
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "db.tx.rollback",
        ],
        "stale subject-auth-state deletion cancellation must reject after live-session freshness check and before pending-action load",
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            &pool,
            &store_config,
            &stale_cancel_pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "stale mounted subject deletion cancellation must leave the pending action open"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}
