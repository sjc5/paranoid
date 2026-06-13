use super::*;

#[tokio::test]
async fn postgres_mounted_credential_lifecycle_adds_authenticated_credential_through_private_runtime()
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
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature creation method plugin");
    let subject_id = id("mounted-add-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-add-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-add-session-authority");
    let new_credential_authority = id("mounted-add-new-credential-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-add.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[],
            &[],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed session lifecycle authority");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let service = MountedCredentialLifecyclePostgresService::new(runtime);
    let addition_method = MountedCredentialAdditionMethod::new(
        proof_method(ProofFamily::MessageSignature),
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![
            CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Create,
                authority_id: session_authority,
                timing: RecoveryAuthorityTiming::Immediate,
            },
            CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Reset,
                authority_id: new_credential_authority.clone(),
                timing: RecoveryAuthorityTiming::Immediate,
            },
        ],
        vec![new_credential_authority],
    )
    .expect("mounted addition method");

    let execution = service
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            &addition_method,
            ExecuteMountedAuthenticatedCredentialAdditionInput {
                now: at(70),
                method_payload: CredentialCreationMethodPayload::try_from_bytes(
                    b"mounted-created-password-verifier".as_slice(),
                )
                .expect("creation payload"),
            },
        )
        .await
        .expect("execute mounted authenticated credential addition");

    let added_credential_id = match execution.outcome() {
        MountedCredentialAdditionServiceOutcome::CredentialAdded {
            subject_id: outcome_subject_id,
            credential_instance_id,
        } => {
            assert_eq!(outcome_subject_id, &subject_id);
            credential_instance_id.clone()
        }
        outcome => panic!("expected mounted credential addition, got {outcome:?}"),
    };
    assert_eq!(
        execution.committed_outcome(),
        Some(MountedCredentialAdditionCommittedOutcome::CredentialAdded {
            subject_id: subject_id.clone(),
            credential_instance_id: added_credential_id.clone(),
        })
    );
    assert_eq!(
        execution.runtime_execution().outcome(),
        &Outcome::CredentialAdded(CredentialAdditionOutcome {
            subject_id: subject_id.clone(),
            credential_instance_id: added_credential_id.clone(),
        })
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "mounted credential addition must delegate method creation work to the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &added_credential_id).await,
        CredentialLifecycleState::Active,
        "mounted credential addition must create active core credential metadata"
    );
    assert_eq!(
        count_credential_recovery_authorities_for_runtime_test(
            pool,
            store_config,
            &added_credential_id,
        )
        .await,
        2,
        "mounted credential addition must persist the configured recovery-authority graph"
    );
    assert_eq!(
        count_lifecycle_authority_sources_for_runtime_test(
            pool,
            store_config,
            LifecycleAuthoritySourceKind::CredentialInstance,
            &added_credential_id,
        )
        .await,
        1,
        "mounted credential addition must map the new credential source to its recovery authority"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "mounted credential addition must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(70),
        "mounted credential addition must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_mounted_credential_lifecycle_addition_requires_fresh_step_up_before_method_work()
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
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature creation method plugin");
    let subject_id = id("mounted-stale-step-up-add-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-stale-step-up-add-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let addition_method = MountedCredentialAdditionMethod::new(
        proof_method(ProofFamily::MessageSignature),
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-stale-step-up-add-session-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-stale-step-up-add-new-authority")],
    )
    .expect("mounted addition method");
    let service = MountedCredentialLifecyclePostgresService::new(runtime);
    harness.database_operation_observer.clear();

    let execution = service
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            &addition_method,
            ExecuteMountedAuthenticatedCredentialAdditionInput {
                now: at(80),
                method_payload: CredentialCreationMethodPayload::try_from_bytes(
                    b"mounted-stale-step-up-add-payload".as_slice(),
                )
                .expect("creation payload"),
            },
        )
        .await
        .expect("mounted stale lifecycle addition returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &MountedCredentialAdditionServiceOutcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    assert_eq!(execution.committed_outcome(), None);
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "mounted stale credential addition must not run method-owned verifier work"
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.lifecycle_authority_evidence"),
        "mounted stale credential addition must not load lifecycle authority evidence; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_http_credential_addition_route_uses_configured_method_and_csrf_guard() {
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
    let subject_id = id("mounted-http-add-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-http-add-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("mounted-http-add-session-authority");
    let new_credential_authority = id("mounted-http-add-new-credential-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        harness.store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.mounted-http-add.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[],
            &[],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed session lifecycle authority");
    let addition_route = MountedCredentialAdditionRoute::new(
        "password-signature",
        MountedCredentialAdditionMethod::new(
            proof_method(ProofFamily::MessageSignature),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![
                CredentialAdditionRecoveryAuthorityRule {
                    action: CredentialLifecycleAction::Create,
                    authority_id: session_authority,
                    timing: RecoveryAuthorityTiming::Immediate,
                },
                CredentialAdditionRecoveryAuthorityRule {
                    action: CredentialLifecycleAction::Reset,
                    authority_id: new_credential_authority.clone(),
                    timing: RecoveryAuthorityTiming::Immediate,
                },
            ],
            vec![new_credential_authority],
        )
        .expect("mounted addition method"),
    )
    .expect("mounted credential addition route");
    let pool = harness.pool;
    let store_config = harness.store_config;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let method_plugin = harness.method_plugin;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default()
                .try_with_credential_addition_route(addition_route)
                .expect("configured credential addition route"),
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
                .uri("https://example.com/auth/credentials/add/password-signature")
                .header(COOKIE, issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::from_static(
                    b"body-must-not-be-parsed-before-csrf",
                )))
                .expect("missing-CSRF credential addition request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &missing_csrf_response,
        "missing CSRF on mounted credential addition route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on credential addition must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for credential addition route test")
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
    let method_payload_base64url =
        BASE64URL_NOPAD.encode(b"mounted-http-add-password-verifier".as_slice());
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::POST)
                .uri("https://example.com/auth/credentials/add/password-signature")
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
                            "method_payload_base64url": "{}"
                        }}"#,
                        method_payload_base64url,
                    )
                    .into_bytes(),
                )))
                .expect("credential addition route request"),
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
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.insert_credential_instance_metadata",
            "auth_core.mutation.insert_credential_recovery_authority",
            "auth_core.mutation.insert_credential_recovery_authority",
            "auth_core.mutation.insert_lifecycle_authority_source",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mounted credential addition HTTP route must parse and validate route input without extra storage work, then execute the same bounded credential-addition transaction as the private runtime facade",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_added")
    );
    assert!(
        response_body
            .get("generated_recovery_codes")
            .is_some_and(serde_json::Value::is_null),
        "password-derived credential addition should not return generated recovery codes"
    );
    assert_eq!(
        method_plugin
            .as_ref()
            .expect("message-signature creation method plugin")
            .count_state_rows(&pool)
            .await,
        1,
        "mounted credential addition route must delegate method creation work to the registered plugin"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(&pool, &store_config, &subject_id).await,
        1,
        "mounted credential addition route must atomically schedule the security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(&pool, &store_config, &subject_id).await,
        Some(70),
        "mounted credential addition route must revoke existing subject auth state"
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

struct CredentialInventoryRuntimeTestSeed {
    subject_id: SubjectId,
    active_password_credential_id: VerifiedProofSourceId,
    active_totp_credential_id: VerifiedProofSourceId,
    revoked_credential_id: VerifiedProofSourceId,
    other_subject_credential_id: VerifiedProofSourceId,
    issued_auth: IssuedRuntimeAuth,
}

async fn seed_authenticated_credential_inventory_for_runtime_test(
    harness: &PostgresRuntimeTestHarness,
    flow_label: &'static str,
) -> CredentialInventoryRuntimeTestSeed {
    let subject_id: SubjectId = id(&format!("{flow_label}-subject"));
    let other_subject_id: SubjectId = id(&format!("{flow_label}-other-subject"));
    let active_password_credential_id: VerifiedProofSourceId =
        id(&format!("{flow_label}-active-password"));
    let active_totp_credential_id: VerifiedProofSourceId = id(&format!("{flow_label}-active-totp"));
    let revoked_credential_id: VerifiedProofSourceId =
        id(&format!("{flow_label}-revoked-password"));
    let other_subject_credential_id: VerifiedProofSourceId =
        id(&format!("{flow_label}-other-password"));
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        flow_label,
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let seed_store = postgres_runtime_test_store(&harness.store_config);
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            &harness.pool,
            &[
                CredentialInstanceMetadata::new(
                    active_password_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("active password credential metadata"),
                CredentialInstanceMetadata::new(
                    active_totp_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("active TOTP credential metadata"),
                CredentialInstanceMetadata::new(
                    revoked_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "revoked_password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Revoked,
                )
                .expect("revoked credential metadata"),
                CredentialInstanceMetadata::new(
                    other_subject_credential_id.clone(),
                    other_subject_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "other_password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("other subject credential metadata"),
            ],
            &[],
            &[],
            at(45),
        )
        .await
        .expect("seed credential inventory metadata");

    CredentialInventoryRuntimeTestSeed {
        subject_id,
        active_password_credential_id,
        active_totp_credential_id,
        revoked_credential_id,
        other_subject_credential_id,
        issued_auth,
    }
}

#[tokio::test]
async fn postgres_runtime_credential_inventory_lists_authenticated_subject_active_credentials() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let seed =
        seed_authenticated_credential_inventory_for_runtime_test(&harness, "runtime-inventory")
            .await;
    let headers = headers_from_cookie_pairs(&[seed.issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let outcome = harness
        .runtime
        .load_authenticated_credential_inventory_from_headers(&headers, at(50))
        .await
        .expect("load authenticated credential inventory through Postgres runtime");

    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.active_subject_credential_inventory",
            "db.tx.rollback",
        ],
        "direct credential inventory runtime must validate the live session, load only the authenticated subject inventory, and roll back the read-only transaction",
    );
    let credentials = match outcome {
        MountedCredentialInventoryServiceOutcome::Credentials { credentials } => credentials,
        MountedCredentialInventoryServiceOutcome::NeedsFullAuthentication => {
            panic!("expected authenticated credential inventory")
        }
    };
    assert_eq!(credentials.len(), 2);
    let mut observed_handles = credentials
        .iter()
        .map(|entry| {
            entry
                .credential_handle()
                .credential_instance_id_for_test()
                .clone()
        })
        .collect::<Vec<_>>();
    observed_handles.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut expected_handles = vec![
        seed.active_password_credential_id.clone(),
        seed.active_totp_credential_id.clone(),
    ];
    expected_handles.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    assert_eq!(observed_handles, expected_handles);
    assert!(
        !observed_handles.contains(&seed.revoked_credential_id),
        "direct credential inventory must not expose inactive credentials"
    );
    assert!(
        !observed_handles.contains(&seed.other_subject_credential_id),
        "direct credential inventory must not expose another subject's credentials"
    );
    let password_entry = credentials
        .iter()
        .find(|entry| {
            entry.credential_handle().credential_instance_id_for_test()
                == &seed.active_password_credential_id
        })
        .expect("password inventory entry");
    assert_eq!(
        password_entry.kind(),
        CredentialInstanceKind::MessageSignatureVerifier
    );
    assert_eq!(password_entry.method_label(), "password_signature");
    assert_eq!(
        password_entry.reset_policy_role(),
        CredentialResetPolicyRole::OrdinaryCredential
    );
    let totp_entry = credentials
        .iter()
        .find(|entry| {
            entry.credential_handle().credential_instance_id_for_test()
                == &seed.active_totp_credential_id
        })
        .expect("TOTP inventory entry");
    assert_eq!(
        totp_entry.kind(),
        CredentialInstanceKind::SharedSecretOtpVerifier
    );
    assert_eq!(totp_entry.method_label(), "totp_app");
    assert_eq!(
        totp_entry.reset_policy_role(),
        CredentialResetPolicyRole::SecondFactorCredential
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_http_credential_inventory_route_lists_authenticated_subject_active_credentials()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let seed =
        seed_authenticated_credential_inventory_for_runtime_test(&harness, "mounted-inventory")
            .await;
    let pool = harness.pool;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_inventory_route(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));
    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(50));

    database_operation_observer.clear();
    let response = http_route_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/auth/credentials")
                .header(COOKIE, seed.issued_auth.session_cookie_pair.as_str())
                .body(Full::new(Bytes::new()))
                .expect("credential inventory request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &response,
        "credential inventory route must not emit Set-Cookie headers",
    );
    assert_database_operation_labels_exact(
        &database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.active_subject_credential_inventory",
            "db.tx.rollback",
        ],
        "credential inventory route must validate the live session, load only the authenticated subject inventory, and roll back the read-only transaction",
    );
    let response_body = auth_runtime_test_json_response_body(&response);
    assert_eq!(
        response_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_inventory")
    );
    let credentials = response_body
        .get("credentials")
        .and_then(serde_json::Value::as_array)
        .expect("credential inventory array");
    assert_eq!(credentials.len(), 2);

    let active_password_handle =
        BASE64URL_NOPAD.encode(seed.active_password_credential_id.as_bytes());
    let active_totp_handle = BASE64URL_NOPAD.encode(seed.active_totp_credential_id.as_bytes());
    let revoked_handle = BASE64URL_NOPAD.encode(seed.revoked_credential_id.as_bytes());
    let other_subject_handle = BASE64URL_NOPAD.encode(seed.other_subject_credential_id.as_bytes());
    let mut observed_handles = credentials
        .iter()
        .map(|entry| {
            entry
                .get("credential_handle_base64url")
                .and_then(serde_json::Value::as_str)
                .expect("credential handle")
                .to_owned()
        })
        .collect::<Vec<_>>();
    observed_handles.sort();
    let mut expected_handles = vec![active_password_handle.clone(), active_totp_handle.clone()];
    expected_handles.sort();
    assert_eq!(observed_handles, expected_handles);
    assert!(
        !observed_handles.contains(&revoked_handle),
        "credential inventory must not expose inactive credentials"
    );
    assert!(
        !observed_handles.contains(&other_subject_handle),
        "credential inventory must not expose another subject's credentials"
    );

    let password_entry = credentials
        .iter()
        .find(|entry| {
            entry
                .get("credential_handle_base64url")
                .and_then(serde_json::Value::as_str)
                == Some(active_password_handle.as_str())
        })
        .expect("password inventory entry");
    assert_eq!(
        password_entry
            .get("credential_kind")
            .and_then(serde_json::Value::as_str),
        Some("message_signature_verifier")
    );
    assert_eq!(
        password_entry
            .get("method_label")
            .and_then(serde_json::Value::as_str),
        Some("password_signature")
    );
    assert_eq!(
        password_entry
            .get("reset_policy_role")
            .and_then(serde_json::Value::as_str),
        Some("ordinary_credential")
    );

    let totp_entry = credentials
        .iter()
        .find(|entry| {
            entry
                .get("credential_handle_base64url")
                .and_then(serde_json::Value::as_str)
                == Some(active_totp_handle.as_str())
        })
        .expect("TOTP inventory entry");
    assert_eq!(
        totp_entry
            .get("credential_kind")
            .and_then(serde_json::Value::as_str),
        Some("shared_secret_otp_verifier")
    );
    assert_eq!(
        totp_entry
            .get("method_label")
            .and_then(serde_json::Value::as_str),
        Some("totp_app")
    );
    assert_eq!(
        totp_entry
            .get("reset_policy_role")
            .and_then(serde_json::Value::as_str),
        Some("second_factor_credential")
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_http_credential_inventory_route_rejects_missing_session_and_nonempty_body_before_storage_work()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = harness.pool;
    let schema = harness.schema;
    let database_operation_observer = harness.database_operation_observer;
    let mounted_runtime =
        MountedAuthPostgresRuntime::new_for_test_without_runtime_dependency_validation(
            harness.runtime,
            MountedAuthRuntimeConfig::default().with_authenticated_credential_inventory_route(),
        );
    let mounted_services = mounted_runtime.services();
    let http_mount =
        mounted_services.http_mount(MountedAuthRouteMountPath::new("/auth").expect("mount path"));

    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(50));
    database_operation_observer.clear();
    let missing_session_response = http_route_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/auth/credentials")
                .body(Full::new(Bytes::new()))
                .expect("credential inventory missing-session request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(missing_session_response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &missing_session_response,
        "missing-session credential inventory must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&missing_session_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("needs_full_authentication")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing-session credential inventory must reject before database operation",
    );

    let mut http_route_service = http_mount
        .http_route_service()
        .with_fixed_now_for_tests(at(50));
    database_operation_observer.clear();
    let nonempty_body_response = http_route_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/auth/credentials")
                .body(Full::new(Bytes::from_static(
                    b"credential-inventory-must-be-empty-body",
                )))
                .expect("credential inventory nonempty-body request"),
        )
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        nonempty_body_response.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_http_response_has_no_set_cookie(
        &nonempty_body_response,
        "nonempty credential inventory body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&nonempty_body_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("payload_too_large")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "nonempty credential inventory body must reject before database operation",
    );

    drop(mounted_runtime);
    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_runtime_constructor_rejects_mutation_routes_without_durable_effect_workers() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = harness.pool.clone();
    let schema = harness.schema.clone();
    let error = match MountedAuthPostgresRuntime::try_new(
        harness.runtime,
        MountedAuthRuntimeConfig::default().with_authenticated_credential_reset_routes(),
    ) {
        Ok(_) => {
            panic!("mounted credential reset routes require durable effect worker integrations")
        }
        Err(error) => error,
    };

    assert_eq!(
        error,
        MountedAuthRuntimeError::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes
    );

    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn mounted_auth_runtime_constructor_rejects_dynamic_method_mutation_routes_without_method_registry()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_without_method_registry().await;
    let pool = harness.pool.clone();
    let schema = harness.schema.clone();
    let addition_route = MountedCredentialAdditionRoute::new(
        "password-signature",
        MountedCredentialAdditionMethod::new(
            proof_method(ProofFamily::MessageSignature),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Create,
                authority_id: id("constructor-add-session-authority"),
                timing: RecoveryAuthorityTiming::Immediate,
            }],
            vec![id("constructor-add-new-authority")],
        )
        .expect("mounted addition method"),
    )
    .expect("mounted credential addition route");
    let error = match MountedAuthPostgresRuntime::try_new(
        harness.runtime,
        MountedAuthRuntimeConfig::default()
            .try_with_credential_addition_route(addition_route)
            .expect("configured credential addition route")
            .with_durable_effect_worker_integrations(
                MountedAuthDurableEffectWorkerIntegrations::new(
                    Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(()))),
                    Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(()))),
                    Arc::new(
                        RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())),
                    ),
                ),
            ),
    ) {
        Ok(_) => panic!("mounted credential addition routes require an auth method registry"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );

    drop_auth_runtime_test_schema(&pool, &schema).await;
}
