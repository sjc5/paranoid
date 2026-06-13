use super::*;

#[tokio::test]
async fn mounted_auth_http_lifecycle_routes_reject_malformed_bodies_before_storage_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let database_operation_observer = harness.database_operation_observer.clone();
    let addition_route = MountedCredentialAdditionRoute::new(
        "password-signature",
        MountedCredentialAdditionMethod::new(
            proof_method(ProofFamily::MessageSignature),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Create,
                authority_id: id("malformed-mounted-add-session-authority"),
                timing: RecoveryAuthorityTiming::Immediate,
            }],
            vec![id("malformed-mounted-add-new-authority")],
        )
        .expect("mounted addition method"),
    )
    .expect("mounted credential addition route");
    let staff_authorizer = Arc::new(RecordingMountedSupportStaffAuthorizer::new(
        MountedAdminSupportStaffAuthorization::Authorized,
    ));
    let mounted_config = MountedAuthRuntimeConfig::default()
        .try_with_credential_addition_route(addition_route)
        .expect("configured credential addition route")
        .with_authenticated_credential_reset_routes()
        .with_authenticated_credential_replacement_routes()
        .with_authenticated_credential_removal_routes()
        .with_authenticated_credential_regeneration_routes()
        .with_authenticated_credential_rotation_routes()
        .with_authenticated_credential_inventory_route()
        .with_delayed_credential_lifecycle_routes()
        .with_authenticated_out_of_band_identifier_change_routes()
        .with_delayed_subject_auth_state_deletion_routes()
        .with_admin_support_routes(staff_authorizer.clone());
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            mounted_config,
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
        .expect("issue CSRF cookie for malformed route test")
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
    let route_manifest = http_mount.route_manifest();

    for route in route_manifest
        .routes()
        .iter()
        .filter(|route| route.requires_csrf())
    {
        let case_name = route.path().to_owned();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{}", route.path()))
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .body(Full::new(Bytes::from_static(
                b"body-must-not-be-parsed-before-csrf",
            )))
            .expect("missing-CSRF mounted route request");
        let mut http_route_service = http_mount
            .http_route_service()
            .with_fixed_now_for_tests(at(70));

        database_operation_observer.clear();
        let response = http_route_service
            .call(request)
            .await
            .expect("mounted auth Tower service is infallible");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{case_name}");
        assert_http_response_has_no_set_cookie(&response, &case_name);
        assert_eq!(
            auth_runtime_test_json_response_body(&response)
                .get("error")
                .and_then(serde_json::Value::as_str),
            Some("forbidden"),
            "{case_name}"
        );
        let observed = database_operation_observer.records();
        assert!(
            observed.is_empty(),
            "{case_name}; observed database operations: {observed:?}"
        );
    }

    struct MalformedMountedRouteCase {
        name: &'static str,
        uri: &'static str,
        content_type: Option<&'static str>,
        body: &'static [u8],
        status: StatusCode,
        error_code: &'static str,
    }

    let cases = [
        MalformedMountedRouteCase {
            name: "credential addition missing content type",
            uri: "https://example.com/auth/credentials/add/password-signature",
            content_type: None,
            body: b"{}",
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            error_code: "unsupported_media_type",
        },
        MalformedMountedRouteCase {
            name: "credential reset invalid credential handle",
            uri: "https://example.com/auth/credentials/reset/execute",
            content_type: Some("application/json"),
            body: br#"{
                "credential_handle_base64url": "not base64",
                "method_payload_base64url": "cGF5bG9hZA"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "credential replacement invalid method payload",
            uri: "https://example.com/auth/credentials/replace/execute",
            content_type: Some("application/json"),
            body: br#"{
                "credential_handle_base64url": "dGFyZ2V0",
                "method_payload_base64url": "not base64"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "credential removal missing content type",
            uri: "https://example.com/auth/credentials/remove/execute",
            content_type: None,
            body: b"{}",
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            error_code: "unsupported_media_type",
        },
        MalformedMountedRouteCase {
            name: "credential regeneration invalid credential handle",
            uri: "https://example.com/auth/credentials/regenerate/execute",
            content_type: Some("application/json"),
            body: br#"{
                "credential_handle_base64url": "not base64",
                "method_payload_base64url": "cGF5bG9hZA"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "credential rotation invalid method payload",
            uri: "https://example.com/auth/credentials/rotate/execute",
            content_type: Some("application/json"),
            body: br#"{
                "credential_handle_base64url": "dGFyZ2V0",
                "method_payload_base64url": "not base64"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "delayed credential reset invalid pending action id",
            uri: "https://example.com/auth/credentials/delayed/reset/execute",
            content_type: Some("application/json"),
            body: br#"{
                "pending_action_id_base64url": "not base64",
                "method_payload_base64url": "cGF5bG9hZA"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "delayed credential removal unexpected method payload",
            uri: "https://example.com/auth/credentials/delayed/remove/execute",
            content_type: Some("application/json"),
            body: br#"{
                "pending_action_id_base64url": "cGVuZGluZw",
                "method_payload_base64url": "cGF5bG9hZA"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "authenticated identifier change invalid current source",
            uri: "https://example.com/auth/out-of-band-identifiers/change/execute",
            content_type: Some("application/json"),
            body: br#"{
                "current_identifier_source_id_base64url": "not base64",
                "candidate_identifier_source_id_base64url": "Y2FuZGlkYXRl"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "delayed identifier change invalid pending action",
            uri: "https://example.com/auth/out-of-band-identifiers/change/delayed/execute",
            content_type: Some("application/json"),
            body: br#"{"pending_action_id_base64url":"not base64"}"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "admin support unknown lifecycle action",
            uri: "https://example.com/auth/admin-support/interventions/request",
            content_type: Some("application/json"),
            body: br#"{
                "subject_id_base64url": "c3ViamVjdA",
                "credential_handle_base64url": "dGFyZ2V0",
                "credential_lifecycle_action": "invented"
            }"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
        MalformedMountedRouteCase {
            name: "admin support approval invalid intervention handle",
            uri: "https://example.com/auth/admin-support/interventions/approve",
            content_type: Some("application/json"),
            body: br#"{"intervention_handle_base64url":"not base64"}"#,
            status: StatusCode::BAD_REQUEST,
            error_code: "bad_request",
        },
    ];

    for case in cases {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(case.uri)
            .header(COOKIE, csrf_cookie_pair.as_str())
            .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str());
        if let Some(content_type) = case.content_type {
            builder = builder.header(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        let request = builder
            .body(Full::new(Bytes::from_static(case.body)))
            .expect("malformed mounted route request");
        let mut http_route_service = http_mount
            .http_route_service()
            .with_fixed_now_for_tests(at(70));

        database_operation_observer.clear();
        let response = http_route_service
            .call(request)
            .await
            .expect("mounted auth Tower service is infallible");
        assert_eq!(response.status(), case.status, "{}", case.name);
        assert_http_response_has_no_set_cookie(&response, case.name);
        assert_eq!(
            auth_runtime_test_json_response_body(&response)
                .get("error")
                .and_then(serde_json::Value::as_str),
            Some(case.error_code),
            "{}",
            case.name
        );
        assert_no_database_operations(&database_operation_observer, case.name);
    }

    for route in route_manifest
        .routes()
        .iter()
        .filter(|route| route.requires_csrf() && route.max_collected_body_bytes() > 0)
    {
        let case_name = route.path().to_owned();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{}", route.path()))
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .header(COOKIE, csrf_cookie_pair.as_str())
            .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
            .body(Full::new(Bytes::from_static(b"{}")))
            .expect("missing-field mounted route request");
        let mut http_route_service = http_mount
            .http_route_service()
            .with_fixed_now_for_tests(at(70));

        database_operation_observer.clear();
        let response = http_route_service
            .call(request)
            .await
            .expect("mounted auth Tower service is infallible");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case_name}");
        assert_http_response_has_no_set_cookie(&response, &case_name);
        assert_eq!(
            auth_runtime_test_json_response_body(&response)
                .get("error")
                .and_then(serde_json::Value::as_str),
            Some("bad_request"),
            "{case_name}"
        );
        let observed = database_operation_observer.records();
        assert!(
            observed.is_empty(),
            "{case_name}; observed database operations: {observed:?}"
        );
    }

    for route in route_manifest
        .routes()
        .iter()
        .filter(|route| route.requires_csrf() && route.max_collected_body_bytes() == 0)
    {
        let case_name = route.path().to_owned();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{}", route.path()))
            .header(COOKIE, csrf_cookie_pair.as_str())
            .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
            .body(Full::new(Bytes::from_static(
                b"body-for-route-that-must-be-empty",
            )))
            .expect("non-empty zero-limit mounted route request");
        let mut http_route_service = http_mount
            .http_route_service()
            .with_fixed_now_for_tests(at(70));

        database_operation_observer.clear();
        let response = http_route_service
            .call(request)
            .await
            .expect("mounted auth Tower service is infallible");
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{case_name}"
        );
        assert_http_response_has_no_set_cookie(&response, &case_name);
        assert_eq!(
            auth_runtime_test_json_response_body(&response)
                .get("error")
                .and_then(serde_json::Value::as_str),
            Some("payload_too_large"),
            "{case_name}"
        );
        let observed = database_operation_observer.records();
        assert!(
            observed.is_empty(),
            "{case_name}; observed database operations: {observed:?}"
        );
    }

    for route in route_manifest
        .routes()
        .iter()
        .filter(|route| route.max_collected_body_bytes() > 0)
    {
        let case_name = route.path().to_owned();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{}", route.path()))
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .header(COOKIE, csrf_cookie_pair.as_str())
            .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
            .body(Full::new(Bytes::from(vec![
                b' ';
                route.max_collected_body_bytes()
                    + 1
            ])))
            .expect("oversized mounted route request");
        let mut http_route_service = http_mount
            .http_route_service()
            .with_fixed_now_for_tests(at(70));

        database_operation_observer.clear();
        let response = http_route_service
            .call(request)
            .await
            .expect("mounted auth Tower service is infallible");
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{case_name}"
        );
        assert_http_response_has_no_set_cookie(&response, &case_name);
        assert_eq!(
            auth_runtime_test_json_response_body(&response)
                .get("error")
                .and_then(serde_json::Value::as_str),
            Some("payload_too_large"),
            "{case_name}"
        );
        let observed = database_operation_observer.records();
        assert!(
            observed.is_empty(),
            "{case_name}; observed database operations: {observed:?}"
        );
    }

    assert!(
        staff_authorizer
            .recorded_intervention_request_authorizations()
            .is_empty(),
        "malformed admin/support route bodies must reject before staff authorization"
    );
    assert!(
        staff_authorizer.recorded_requests().is_empty(),
        "malformed or missing-CSRF admin/support route bodies must reject before staff authorization"
    );

    let pool = harness.pool;
    let schema = harness.schema;
    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_authenticated_credential_routes_without_live_session_return_needs_full_authentication_before_storage_work()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let database_operation_observer = harness.database_operation_observer.clone();
    let addition_route = MountedCredentialAdditionRoute::new(
        "password-signature",
        MountedCredentialAdditionMethod::new(
            proof_method(ProofFamily::MessageSignature),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Create,
                authority_id: id("missing-session-mounted-add-session-authority"),
                timing: RecoveryAuthorityTiming::Immediate,
            }],
            vec![id("missing-session-mounted-add-new-authority")],
        )
        .expect("mounted addition method"),
    )
    .expect("mounted credential addition route");
    let addition_route_path = addition_route.relative_path();
    let mounted_config = MountedAuthRuntimeConfig::default()
        .try_with_credential_addition_route(addition_route)
        .expect("configured credential addition route")
        .with_authenticated_credential_reset_routes()
        .with_authenticated_credential_replacement_routes()
        .with_authenticated_credential_removal_routes()
        .with_authenticated_credential_regeneration_routes()
        .with_authenticated_credential_rotation_routes();
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            mounted_config,
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
        .expect("issue CSRF cookie for missing-session lifecycle route test")
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
    let credential_handle_base64url =
        BASE64URL_NOPAD.encode(b"missing-session-target-credential".as_slice());
    let method_payload_base64url =
        BASE64URL_NOPAD.encode(b"missing-session-method-payload".as_slice());
    let target_body = format!(
        r#"{{
            "credential_handle_base64url": "{}"
        }}"#,
        credential_handle_base64url,
    );
    let target_and_method_body = format!(
        r#"{{
            "credential_handle_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        credential_handle_base64url, method_payload_base64url,
    );
    let addition_body = format!(
        r#"{{
            "method_payload_base64url": "{}"
        }}"#,
        method_payload_base64url,
    );

    struct MountedCredentialRouteCase<'a> {
        name: &'static str,
        relative_path: &'a str,
        body: &'a str,
    }

    let cases = [
        MountedCredentialRouteCase {
            name: "credential addition",
            relative_path: addition_route_path.as_str(),
            body: addition_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential reset planning",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_PLAN_ROUTE_PATH,
            body: target_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential reset execution",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_EXECUTE_ROUTE_PATH,
            body: target_and_method_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential replacement planning",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_PLAN_ROUTE_PATH,
            body: target_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential replacement execution",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_EXECUTE_ROUTE_PATH,
            body: target_and_method_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential removal planning",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_PLAN_ROUTE_PATH,
            body: target_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential removal execution",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_EXECUTE_ROUTE_PATH,
            body: target_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential regeneration planning",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_PLAN_ROUTE_PATH,
            body: target_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential regeneration execution",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_EXECUTE_ROUTE_PATH,
            body: target_and_method_body.as_str(),
        },
        MountedCredentialRouteCase {
            name: "credential rotation execution",
            relative_path: MOUNTED_AUTHENTICATED_CREDENTIAL_ROTATION_EXECUTE_ROUTE_PATH,
            body: target_and_method_body.as_str(),
        },
    ];

    struct MountedLifecycleCookieCase {
        name: &'static str,
        cookie_header: String,
        expect_session_cookie_deletion: bool,
    }

    let expired_session_cookie_pair =
        rendered_session_cookie_pair_for_runtime_test(session_cookie(60), at(20));
    let route_cookie_cases = [
        MountedLifecycleCookieCase {
            name: "missing session",
            cookie_header: csrf_cookie_pair.clone(),
            expect_session_cookie_deletion: false,
        },
        MountedLifecycleCookieCase {
            name: "expired session",
            cookie_header: format!("{csrf_cookie_pair}; {expired_session_cookie_pair}"),
            expect_session_cookie_deletion: true,
        },
    ];

    for cookie_case in route_cookie_cases {
        for case in &cases {
            let context = format!("{} with {}", case.name, cookie_case.name);
            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("https://example.com/auth{}", case.relative_path))
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .header(COOKIE, cookie_case.cookie_header.as_str())
                .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token.as_str())
                .body(Full::new(Bytes::from(case.body.as_bytes().to_vec())))
                .expect("authenticated credential route request without live session");
            let mut http_route_service = http_mount
                .http_route_service()
                .with_fixed_now_for_tests(at(70));

            database_operation_observer.clear();
            let response = http_route_service
                .call(request)
                .await
                .expect("mounted auth Tower service is infallible");
            assert_eq!(response.status(), StatusCode::OK, "{context}");
            if cookie_case.expect_session_cookie_deletion {
                assert!(
                    response
                        .headers()
                        .get_all(http::header::SET_COOKIE)
                        .iter()
                        .any(|header| header
                            .to_str()
                            .expect("Set-Cookie header is valid UTF-8")
                            .starts_with("__Host-__paranoid_auth_session=")
                            && header
                                .to_str()
                                .expect("Set-Cookie header is valid UTF-8")
                                .contains("Max-Age=0")),
                    "{context} must clear the expired session cookie"
                );
            } else {
                assert_http_response_has_no_set_cookie(&response, &context);
            }
            assert_eq!(
                auth_runtime_test_json_response_body(&response)
                    .get("type")
                    .and_then(serde_json::Value::as_str),
                Some("needs_full_authentication"),
                "{context}",
            );
            assert_no_database_operations(&database_operation_observer, &context);
        }
    }

    let pool = harness.pool;
    let schema = harness.schema;
    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}
