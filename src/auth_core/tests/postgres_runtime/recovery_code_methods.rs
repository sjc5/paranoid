use super::*;

#[tokio::test]
async fn postgres_runtime_completes_recovery_code_through_known_subject_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("recovery-known-subject");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("recovery-known-subject-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x01);
    let recovery_code_secret = b"correct-recovery-code";
    let method = ProofMethodDeclaration::new(ProofFamily::RecoveryCode, "recovery_code")
        .expect("recovery code method");

    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "recovery-known-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::RecoverOrReplaceCredential,
    )
    .await;
    let attempt_id = started.attempt_id.clone();
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let pre_state_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: method.clone(),
                secret_response: mismatched_recovery_code_test_method_response_payload(),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("malformed sealed recovery code must reject before state load");
    assert!(
        matches!(
            pre_state_rejected,
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected method pre-state rejection, got {pre_state_rejected:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "malformed sealed recovery code must reject before any database operation",
    );
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count recovery codes"),
        1
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes"),
        1
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    harness.database_operation_observer.clear();
    let guessed_sealed_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(81),
                method: method.clone(),
                secret_response: guessed_recovery_code_test_method_response_payload(),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("guessed sealed recovery code must reject before state load");
    assert!(
        matches!(
            guessed_sealed_rejected,
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected guessed sealed code method pre-state rejection, got {guessed_sealed_rejected:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "guessed sealed recovery code must reject before any database operation",
    );
    let wrong_subject_sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&id("other-recovery-subject"), recovery_code_secret)
        .expect("wrong-subject sealed recovery code response");
    harness.database_operation_observer.clear();
    let wrong_subject_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(82),
                method: method.clone(),
                secret_response: wrong_subject_sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("wrong-subject sealed recovery code must reject before state load");
    assert!(
        matches!(
            wrong_subject_rejected,
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected wrong-subject method pre-state rejection, got {wrong_subject_rejected:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong-subject sealed recovery code must reject before any database operation",
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes"),
        1
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    let unused_sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, b"unused-recovery-code")
        .expect("unused sealed recovery code response");
    harness.database_operation_observer.clear();
    let unused_sealed_rejection = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(83),
                method: method.clone(),
                secret_response: unused_sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("unused sealed recovery code must reject authoritatively");
    assert_eq!(
        unused_sealed_rejection.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.recovery_code.verify.fetch_locked_unused_code",
        "well-formed unused recovery code must perform authoritative one-time lookup",
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes after unused sealed rejection"),
        1,
        "unused sealed recovery code must not consume any stored recovery code"
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0,
        "unused sealed recovery code must not record a satisfied proof"
    );
    assert_eq!(
        fetch_active_proof_attempt_weak_failures(pool, store_config, &attempt_id).await,
        Some(0),
        "unused sealed recovery code must not spend online-guessing weak-failure budget"
    );
    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");

    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(85),
                method,
                secret_response: sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete recovery code through known-subject method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::RecoveryCode, "recovery_code").expect("proof"),
        }
    );
    assert_eq!(
        completed.set_cookie_headers().as_slice().len(),
        1,
        "accepted recovery proof must issue exactly the proof-bound continuation handoff cookie"
    );
    let proof_bound_continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(completed.set_cookie_headers());
    let proof_bound_continuation_headers =
        headers_from_cookie_pairs(&[proof_bound_continuation_cookie_pair]);
    let decoded_proof_bound_continuation = auth_web_transport()
        .decode_presented_cookies_from_headers(&proof_bound_continuation_headers)
        .expect("decode proof-bound recovery continuation cookie");
    let proof_bound_continuation = decoded_proof_bound_continuation
        .presented_cookies()
        .active_proof_continuation_cookie
        .as_ref()
        .expect("accepted recovery proof must reissue active-proof continuation");
    assert_eq!(proof_bound_continuation.attempt_id, attempt_id);
    assert_eq!(
        proof_bound_continuation.proof_use,
        ProofUse::RecoverOrReplaceCredential
    );
    assert_eq!(
        proof_bound_continuation.subject_binding,
        ActiveProofContinuationSubjectBinding::VerifiedProofBoundSubject
    );
    assert_eq!(
        proof_bound_continuation.subject_id,
        Some(subject_id.clone())
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            recovery_code_credential_id,
        ))
    );
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count recovery codes"),
        1
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes"),
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_start_rejects_invalid_preflight_before_writes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_unauthenticated_recovery_active_proof_attempt_start_from_headers(
            &empty_headers,
            StartUnauthenticatedRecoveryActiveProofAttemptInput {
                now: at(20),
                method: proof_method(ProofFamily::RecoveryCode),
            },
            invalid_challenge_issue_preflight_response(),
        )
        .await
        .expect_err("invalid recovery start preflight must reject before writes");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid recovery start preflight must reject before any database operation",
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_start_route_returns_public_response() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let route_service = MountedNoSessionCredentialRecoveryPostgresRouteService::new(
        runtime,
        MountedNoSessionCredentialRecoveryFlow::new(
            recovery_method.clone(),
            proof_method(ProofFamily::MessageSignature),
        )
        .expect("mounted no-session recovery flow"),
    );
    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    let request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[],
        MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
            preflight_response.summary().kind(),
            preflight_response.summary().method_label(),
            preflight_response.payload().to_vec(),
        )
        .expect("no-session recovery route body"),
    );

    let response = route_service
        .start_recovery_attempt(request, at(70))
        .await
        .expect("start no-session recovery route");

    let MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryAttemptStarted { expires_at } =
        response.body()
    else {
        panic!(
            "normal route executor must return only the mounted route body, got {:?}",
            response.body()
        );
    };
    assert!(expires_at > at(70));
    let mut response_headers = HeaderMap::new();
    response.append_set_cookie_headers_to(&mut response_headers);
    assert!(
        response_headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .next()
            .is_some(),
        "normal route executor must return rendered auth cookie headers"
    );
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        1,
        "normal route executor must still commit the recovery attempt behind the response"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_route_rejected_proof_does_not_issue_csrf_handoff() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let route_service = MountedNoSessionCredentialRecoveryPostgresRouteService::new(
        runtime,
        MountedNoSessionCredentialRecoveryFlow::new(
            recovery_method.clone(),
            proof_method(ProofFamily::MessageSignature),
        )
        .expect("mounted no-session recovery flow"),
    );
    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    let start_request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[],
        MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
            preflight_response.summary().kind(),
            preflight_response.summary().method_label(),
            preflight_response.payload().to_vec(),
        )
        .expect("no-session recovery route body"),
    );
    let started = route_service
        .start_recovery_attempt(start_request, at(70))
        .await
        .expect("start no-session recovery route");
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started.set_cookie_headers())
            .to_owned();
    let malformed_proof_request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[continuation_cookie_pair.as_str()],
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
            b"not-a-sealed-recovery-code".as_slice(),
        )
        .expect("malformed route recovery proof body"),
    );

    harness.database_operation_observer.clear();
    let malformed_rejected = route_service
        .submit_recovery_proof(malformed_proof_request, at(80))
        .await
        .expect("malformed recovery proof still maps to mounted rejection body");

    assert_eq!(
        malformed_rejected.body(),
        MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryProofRejected
    );
    assert!(
        !set_cookie_headers_contain_prefix(
            malformed_rejected.set_cookie_headers(),
            "__Host-csrf_token="
        ),
        "malformed no-session recovery proof must not receive the accepted-proof CSRF handoff cookie"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "malformed no-session recovery proof must reject before any database operation",
    );

    let unused_sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(
            &id("no-session-recovery-rejected-proof-subject"),
            b"unused-no-session-recovery-code",
        )
        .expect("unused sealed recovery code response");
    let proof_request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[continuation_cookie_pair.as_str()],
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
            unused_sealed_response.expose_secret().to_vec(),
        )
        .expect("route recovery proof body"),
    );

    let rejected = route_service
        .submit_recovery_proof(proof_request, at(80))
        .await
        .expect("reject unused recovery code through mounted route");

    assert_eq!(
        rejected.body(),
        malformed_rejected.body(),
        "malformed and plausible-but-unused recovery proofs must have the same mounted response body"
    );
    assert!(
        !set_cookie_headers_contain_prefix(rejected.set_cookie_headers(), "__Host-csrf_token="),
        "rejected no-session recovery proof must not receive the accepted-proof CSRF handoff cookie"
    );
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        1,
        "rejected no-session recovery proof must not turn into a successful recovery ceremony"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_proof_rejects_subject_bound_continuation_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let subject_bound_continuation =
        rendered_active_proof_continuation_cookie_pair_for_runtime_test(
            ProofUse::RecoverOrReplaceCredential,
            Some(id("subject-bound-recovery-continuation-subject")),
            at(20),
            at(100),
        );
    let continuation_headers = headers_from_cookie_pairs(&[subject_bound_continuation.as_str()]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_recovery_credential_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteRecoveryCredentialActiveProofMethodResponse {
                now: at(30),
                method: proof_method(ProofFamily::RecoveryCode),
                secret_response: KnownSubjectActiveProofSecretResponse::try_from_bytes(
                    b"not-inspected".as_slice(),
                )
                .expect("recovery proof placeholder"),
            },
        )
        .await
        .expect_err("subject-bound recovery continuation must reject before state load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::LoadedStateContradiction(
                "unauthenticated recovery credential proof requires an unbound active-proof continuation",
            )
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "subject-bound recovery continuation must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_malformed_no_session_recovery_code_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let started =
        start_unauthenticated_recovery_active_proof_attempt_through_runtime(runtime, at(20)).await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_recovery_credential_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteRecoveryCredentialActiveProofMethodResponse {
                now: at(30),
                method: proof_method(ProofFamily::RecoveryCode),
                secret_response: mismatched_recovery_code_test_method_response_payload(),
            },
        )
        .await
        .expect_err("malformed no-session recovery code must reject before state load");

    assert!(
        matches!(
            error,
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
        ),
        "expected method pre-state rejection, got {error:?}"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "malformed no-session recovery code must reject before any database operation",
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        1,
        "malformed no-session recovery completion must not consume the attempt"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_code_completion_binds_attempt_and_schedules_reset() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("no-session-recovery-subject");
    let target_credential_id = id("no-session-recovery-password");
    let recovery_authority = id("no-session-recovery-authority");
    let recovery_code_credential_id: VerifiedProofSourceId = id("no-session-recovery-code-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x02);
    let recovery_code_secret = b"no-session-correct-recovery-code";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );
    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(10),
        )
        .await
        .expect("store recovery code verifier state");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
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
                [recovery_authority.clone()],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");

    let mounted_service = MountedCredentialLifecyclePostgresService::new(runtime);
    let mounted_recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    let route_service = MountedNoSessionCredentialRecoveryPostgresRouteService::new(
        runtime,
        mounted_recovery_flow.clone(),
    );
    let recovery_method = mounted_recovery_flow.recovery_method().clone();
    let start_request = request_with_cookie_pairs(Method::POST, &[]);
    let started = mounted_service
        .execute_no_session_credential_recovery_route_request_and_return_runtime_execution(
            &start_request,
            &mounted_recovery_flow,
            MountedNoSessionCredentialRecoveryRouteRequest::start_recovery_attempt(
                at(70),
                challenge_issue_preflight_response_for_test(
                    at(70),
                    ProofUse::RecoverOrReplaceCredential,
                    &recovery_method,
                ),
            ),
        )
        .await
        .expect("start no-session mounted recovery attempt");
    let started_route_response = started.route_response();
    let MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryAttemptStarted { expires_at } =
        started_route_response.outcome()
    else {
        panic!(
            "route response must expose the mounted recovery-start outcome, got {:?}",
            started_route_response.outcome()
        );
    };
    assert!(
        *expires_at > at(70),
        "route response must expose the recovery ceremony expiry without exposing the lower runtime outcome"
    );
    assert!(
        !started_route_response.set_cookie_headers().is_empty(),
        "route response must carry rendered auth cookies needed to continue the ceremony"
    );
    let mut started_response_headers = HeaderMap::new();
    started_route_response.append_set_cookie_headers_to(&mut started_response_headers);
    assert!(
        started_response_headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .next()
            .is_some(),
        "route response should append Set-Cookie headers without exposing runtime execution"
    );
    let started_attempt_id = match started.runtime_execution().outcome() {
        Outcome::ActiveProofAttemptStarted { attempt_id, .. } => attempt_id.clone(),
        other => panic!("unexpected no-session route start outcome: {other:?}"),
    };
    let continuation_cookie_pair = active_proof_continuation_cookie_pair_from_set_cookie(
        started.runtime_execution().set_cookie_headers(),
    )
    .to_owned();
    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");

    let proof_request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[continuation_cookie_pair.as_str()],
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
            sealed_response.expose_secret().to_vec(),
        )
        .expect("route recovery proof body"),
    );
    let completed = route_service
        .submit_recovery_proof(proof_request, at(80))
        .await
        .expect("complete no-session recovery code proof");

    assert_eq!(
        completed.body(),
        MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryProofAccepted
    );
    let csrf_cookie_pair = csrf_cookie_pair_from_set_cookie(completed.set_cookie_headers());
    let accepted_continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(completed.set_cookie_headers())
            .to_owned();
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1;
    assert_eq!(
        fetch_active_proof_attempt_subject_id(pool, store_config, &started_attempt_id).await,
        Some(subject_id.clone()),
        "no-session recovery completion must bind the attempt subject after authoritative consume"
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &started_attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            recovery_code_credential_id.clone(),
        ))
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count unused recovery codes after no-session completion"),
        0,
        "successful no-session recovery completion must consume the one-time code"
    );

    let csrf_protected_continuation_request = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/auth")
        .header(
            COOKIE,
            format!(
                "{}; {}",
                accepted_continuation_cookie_pair.as_str(),
                csrf_cookie_pair
            ),
        )
        .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
        .body(
        MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody::from_empty_route_body_bytes(
            b"",
        )
        .expect("route schedule body"),
        )
        .expect("csrf-protected no-session recovery schedule request");
    let scheduled = route_service
        .schedule_delayed_reset(csrf_protected_continuation_request, at(90))
        .await
        .expect("schedule delayed reset from no-session recovery proof");

    match scheduled.body() {
        MountedNoSessionCredentialRecoveryRouteResponseBody::DelayedResetScheduled {
            earliest_execute_at,
            expires_at,
        } => {
            assert!(earliest_execute_at > at(90));
            assert!(expires_at > earliest_execute_at);
        }
        other => panic!("unexpected no-session route scheduling outcome: {other:?}"),
    };
    assert_eq!(
        count_open_pending_credential_reset_actions_for_subject_and_target(
            pool,
            store_config,
            &subject_id,
            &target_credential_id,
        )
        .await,
        1,
        "route scheduling must commit one pending reset for the recovered subject and configured target without exposing its id"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started_attempt_id).await,
        0,
        "reset scheduling must consume the recovery attempt after it uses it as lifecycle evidence"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_recovery_code_addition_generates_post_commit_codes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("recovery-code-addition-subject");
    let session_authority = id("recovery-code-addition-session-authority");
    let recovery_code_authority = id("recovery-code-addition-code-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "recovery-code-addition-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
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

    let execution = runtime
        .execute_authenticated_credential_addition_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            ExecuteAuthenticatedCredentialAdditionInput {
                now: at(70),
                method: proof_method(ProofFamily::RecoveryCode),
                reset_policy_role: CredentialResetPolicyRole::SecondFactorCredential,
                recovery_authority_rules: vec![
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Create,
                        authority_id: session_authority,
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Regenerate,
                        authority_id: recovery_code_authority.clone(),
                        timing: RecoveryAuthorityTiming::Delayed,
                    },
                ],
                new_credential_authority_ids: vec![recovery_code_authority],
                method_payload: PostgresRecoveryCodeMethodPlugin::generation_payload_for_test(3)
                    .expect("recovery code generation payload"),
            },
        )
        .await
        .expect("execute authenticated recovery-code addition");

    let added_credential_id = match execution.outcome() {
        Outcome::CredentialAdded(outcome) => {
            assert_eq!(&outcome.subject_id, &subject_id);
            outcome.credential_instance_id.clone()
        }
        outcome => panic!("expected recovery-code credential addition, got {outcome:?}"),
    };
    let generated = execution
        .post_commit_method_response_material()
        .generated_recovery_codes()
        .expect("recovery-code addition must return generated display codes after commit");
    assert_eq!(generated.credential_instance_id(), &added_credential_id);
    assert_eq!(generated.len(), 3);
    let debug_output = format!("{generated:?}");
    for code in generated.codes() {
        assert!(
            !debug_output.contains(String::from_utf8_lossy(code.expose_secret()).as_ref()),
            "generated recovery-code debug output must not contain display tokens"
        );
        assert!(
            !format!("{code:?}").contains(String::from_utf8_lossy(code.expose_secret()).as_ref()),
            "individual generated recovery-code debug output must not contain display tokens"
        );
    }
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count generated recovery codes"),
        3
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count active generated recovery codes"),
        3
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &added_credential_id).await,
        CredentialLifecycleState::Active
    );

    let fresh_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "recovery-code-addition-after-add",
        90,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        fresh_auth.session_cookie_pair.as_str(),
        at(100),
        ProofUse::RecoverOrReplaceCredential,
    )
    .await;
    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]),
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(110),
                method: proof_method(ProofFamily::RecoveryCode),
                secret_response: generated_recovery_code_test_method_response_payload(
                    &generated.codes()[0],
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("generated recovery code should complete known-subject proof");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: started.attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::RecoveryCode, "recovery_code").expect("proof"),
        }
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &started.attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            added_credential_id,
        ))
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count remaining generated recovery codes"),
        2
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_mounted_recovery_code_addition_projects_generated_codes_after_commit() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("mounted-recovery-code-add-subject");
    let session_authority = id("mounted-recovery-code-add-session-authority");
    let recovery_code_authority = id("mounted-recovery-code-add-code-authority");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "mounted-recovery-code-add-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
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
    let service = MountedCredentialLifecyclePostgresService::new(runtime);
    let addition_method = MountedCredentialAdditionMethod::new(
        proof_method(ProofFamily::RecoveryCode),
        CredentialResetPolicyRole::SecondFactorCredential,
        vec![
            CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Create,
                authority_id: session_authority,
                timing: RecoveryAuthorityTiming::Immediate,
            },
            CredentialAdditionRecoveryAuthorityRule {
                action: CredentialLifecycleAction::Regenerate,
                authority_id: recovery_code_authority.clone(),
                timing: RecoveryAuthorityTiming::Delayed,
            },
        ],
        vec![recovery_code_authority],
    )
    .expect("mounted recovery-code addition method");

    let execution = service
        .execute_authenticated_credential_addition_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            &addition_method,
            ExecuteMountedAuthenticatedCredentialAdditionInput {
                now: at(70),
                method_payload: PostgresRecoveryCodeMethodPlugin::generation_payload_for_test(2)
                    .expect("recovery code generation payload"),
            },
        )
        .await
        .expect("execute mounted recovery-code addition");

    let added_credential_id = match execution.outcome() {
        MountedCredentialAdditionServiceOutcome::CredentialAdded {
            subject_id: outcome_subject_id,
            credential_instance_id,
        } => {
            assert_eq!(outcome_subject_id, &subject_id);
            credential_instance_id.clone()
        }
        outcome => panic!("expected mounted recovery-code addition, got {outcome:?}"),
    };
    let generated = execution
        .into_generated_recovery_codes_route_response_after_commit()
        .expect("mounted addition must consume generated recovery codes into a route response body after commit");
    assert_eq!(generated.credential_instance_id(), &added_credential_id);
    assert_eq!(generated.len(), 2);
    let generated_debug = format!("{generated:?}");
    let (generated_credential_id, generated_codes) = generated.into_parts();
    assert_eq!(generated_credential_id, added_credential_id);
    assert_eq!(generated_codes.len(), 2);
    for code in generated_codes {
        let display_token =
            std::str::from_utf8(code.expose_secret()).expect("generated recovery code is UTF-8");
        assert!(
            !generated_debug.contains(display_token),
            "mounted generated-code route response debug output must not contain display tokens"
        );
    }
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count mounted generated recovery codes"),
        2
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_pending_recovery_code_regeneration_replaces_active_set_at_execution() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("recovery-code-regeneration-subject");
    let recovery_code_credential_id: VerifiedProofSourceId = id("recovery-code-regeneration-set");
    let pending_action_id = id("recovery-code-regeneration-pending-action");
    let old_recovery_code_id = recovery_code_id_for_runtime_test(0x03);
    let old_recovery_code_secret = b"old-recovery-code-secret";
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                recovery_code_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::RecoveryCodeCredential,
                "recovery_code",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("recovery-code credential metadata")],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed recovery-code credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                recovery_code_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending regeneration action")],
        )
        .await
        .expect("seed pending regeneration action");
    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            &recovery_code_credential_id,
            &old_recovery_code_id,
            old_recovery_code_secret,
            at(60),
        )
        .await
        .expect("seed old recovery-code verifier");

    let execution = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    PostgresRecoveryCodeMethodPlugin::regeneration_payload_for_test(2)
                        .expect("recovery code regeneration payload"),
                ),
            },
        )
        .await
        .expect("execute mature pending recovery-code regeneration");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: subject_id.clone(),
                target_credential_instance_id: recovery_code_credential_id.clone(),
                action: CredentialLifecycleAction::Regenerate,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    let generated = execution
        .post_commit_method_response_material()
        .generated_recovery_codes()
        .expect("recovery-code regeneration must return generated display codes after commit");
    assert_eq!(
        generated.credential_instance_id(),
        &recovery_code_credential_id
    );
    assert_eq!(generated.len(), 2);
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count all recovery code rows after regeneration"),
        3,
        "regeneration keeps historical old rows but adds the new set"
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count active unused recovery codes after regeneration"),
        2,
        "regeneration must supersede old unused codes and leave only the new set active"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Regenerate,
        )
        .await,
        0
    );

    let fresh_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "recovery-code-regeneration-after-execute",
        270,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        fresh_auth.session_cookie_pair.as_str(),
        at(280),
        ProofUse::RecoverOrReplaceCredential,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let old_code_rejected = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(290),
                method: proof_method(ProofFamily::RecoveryCode),
                secret_response: recovery_code_plugin
                    .sealed_recovery_code_response_for_test(&subject_id, old_recovery_code_secret)
                    .expect("old sealed recovery code response"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("superseded recovery code should be rejected authoritatively");
    assert_eq!(
        old_code_rejected.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: started.attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count active unused recovery codes after old code rejection"),
        2,
        "rejected superseded code must not consume a new code"
    );
    let new_code_completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(291),
                method: proof_method(ProofFamily::RecoveryCode),
                secret_response: generated_recovery_code_test_method_response_payload(
                    &generated.codes()[0],
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("new generated recovery code should complete after regeneration");
    assert_eq!(
        new_code_completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: started.attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::RecoveryCode, "recovery_code").expect("proof"),
        }
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &started.attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            recovery_code_credential_id,
        ))
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count active unused recovery codes after new code consumption"),
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_recovery_code_regeneration_rejects_missing_method_owned_set() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("missing-recovery-code-set-subject");
    let recovery_code_credential_id: VerifiedProofSourceId = id("missing-recovery-code-set");
    let pending_action_id = id("missing-recovery-code-set-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                recovery_code_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::RecoveryCodeCredential,
                "recovery_code",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("recovery-code credential metadata")],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed recovery-code credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                recovery_code_credential_id,
                CredentialLifecycleAction::Regenerate,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending regeneration action")],
        )
        .await
        .expect("seed pending regeneration action");

    let error = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    PostgresRecoveryCodeMethodPlugin::regeneration_payload_for_test(2)
                        .expect("recovery code regeneration payload"),
                ),
            },
        )
        .await
        .expect_err("missing recovery-code method-owned state must not regenerate a set");

    assert_method_commit_work_failed(
        &error,
        super::super::super::postgres_store::PostgresAuthMethodCommitStage::EnforcePrecondition,
        "recovery_code_set_lock",
    );
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count recovery code rows after failed regeneration"),
        0,
        "failed regeneration must not insert fresh generated recovery-code rows"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Regenerate,
        )
        .await,
        1,
        "failed regeneration must leave the pending action open"
    );
    assert_eq!(
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await,
        None,
        "failed regeneration must not revoke subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        0,
        "failed regeneration must not schedule security notices"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_mounted_delayed_recovery_code_regeneration_projects_generated_codes_after_commit()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("mounted-recovery-code-regenerate-subject");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-recovery-code-regenerate-set");
    let pending_action_id = id("mounted-recovery-code-regenerate-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                recovery_code_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::RecoveryCodeCredential,
                "recovery_code",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("recovery-code credential metadata")],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed recovery-code credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                recovery_code_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending regeneration action")],
        )
        .await
        .expect("seed pending regeneration action");
    let old_recovery_code_id = recovery_code_id_for_runtime_test(0x04);
    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            &recovery_code_credential_id,
            &old_recovery_code_id,
            b"mounted-old-recovery-code-secret",
            at(60),
        )
        .await
        .expect("seed old recovery-code verifier");
    let service = MountedCredentialLifecyclePostgresService::new(runtime);

    let execution = service
        .execute_delayed_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(
                    PostgresRecoveryCodeMethodPlugin::regeneration_payload_for_test(2)
                        .expect("recovery code regeneration payload"),
                ),
            },
        )
        .await
        .expect("execute mounted delayed recovery-code regeneration");

    assert_eq!(
        execution.committed_outcome(),
        &MountedDelayedCredentialLifecycleCommittedOutcome::NonResetCredentialLifecycleActionExecuted {
            subject_id: subject_id.clone(),
            target_credential_instance_id: recovery_code_credential_id.clone(),
            action: CredentialLifecycleAction::Regenerate,
            pending_action_id: pending_action_id.clone(),
        }
    );
    let generated = execution
        .into_generated_recovery_codes_route_response_after_commit()
        .expect("mounted regeneration must consume generated recovery codes into a route response body after commit");
    assert_eq!(
        generated.credential_instance_id(),
        &recovery_code_credential_id
    );
    assert_eq!(generated.len(), 2);
    let generated_debug = format!("{generated:?}");
    let (generated_credential_id, generated_codes) = generated.into_parts();
    assert_eq!(generated_credential_id, recovery_code_credential_id);
    assert_eq!(generated_codes.len(), 2);
    for code in generated_codes {
        let display_token =
            std::str::from_utf8(code.expose_secret()).expect("generated recovery code is UTF-8");
        assert!(
            !generated_debug.contains(display_token),
            "mounted regenerated-code route response debug output must not contain display tokens"
        );
    }
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count mounted regenerated recovery codes"),
        2,
        "mounted regeneration must supersede old unused recovery codes and leave only the new set active"
    );

    harness.drop_schema().await;
}
