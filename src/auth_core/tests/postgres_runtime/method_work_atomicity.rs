use super::*;

#[tokio::test]
async fn postgres_runtime_rejects_method_facades_until_registry_is_configured() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let registry_runtime = &harness.runtime;
    let no_registry_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    let no_registry_runtime = super::super::super::postgres_runtime::PostgresAuthWebRuntime::new(
        AuthWebRuntime::new(config(), auth_web_transport()),
        pool.clone(),
        no_registry_store,
        Arc::new(hashcash_verifier_for_test()),
    );
    let runtime = &no_registry_runtime;
    let empty_headers = HeaderMap::new();
    let session_state_for_registry_errors = complete_full_authentication_through_runtime(
        registry_runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "method-registry-errors-bootstrap",
        10,
        id("method-registry-errors-subject"),
        false,
    )
    .await;
    let durable_effect_count_after_bootstrap =
        count_core_durable_effect_commands(pool, store_config).await;

    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_state_for_registry_errors
            .session_cookie_pair
            .as_str(),
        at(60),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);
    let issue_error = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(70),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-issue:email-hash:window"),
                recipient_handle: "method-issue-opaque-email-handle".to_owned(),
                idempotency_key: "method-issue-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("registered method must be required on challenge issue");
    assert_method_registry_not_configured(&issue_error);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        durable_effect_count_after_bootstrap
    );

    let fused_issue_error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(40),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-fused-issue:email-hash:window"),
                recipient_handle: "method-fused-issue-opaque-email-handle".to_owned(),
                idempotency_key: "method-fused-issue-mail-idempotency-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(40)),
        )
        .await
        .expect_err("fused unbound start and issue must roll back when method registry is missing");
    assert_method_registry_not_configured(&fused_issue_error);
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 1);
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );

    harness.database_operation_observer.clear();
    let missing_cookie_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &empty_headers,
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "method-resend-missing-cookie-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("challenge resend must require the encrypted challenge cookie");
    assert!(matches!(
        missing_cookie_resend_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofChallengeCookie
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing out-of-band resend challenge cookie must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let malformed_cookie_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[
                "__Host-__paranoid_auth_active_proof_challenge=not-a-valid-encrypted-cookie",
            ]),
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "method-resend-malformed-cookie-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("malformed challenge cookie must fail during transport decode");
    assert!(matches!(
        malformed_cookie_resend_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Web(_)
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "malformed out-of-band resend challenge cookie must reject before any database operation",
    );

    let message_signature_challenge_cookie =
        ActiveProofChallengeCookieDraft::new_without_response_mac(
            ActiveProofChallengeCookieContext::new(
                id("wrong-family-resend-attempt"),
                id("wrong-family-resend-challenge"),
                ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
                at(30),
                at(70),
                ActiveProofChallengeFastFailNonce::from_bytes(
                    &[88_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
                )
                .expect("nonce"),
            )
            .expect("message-signature challenge-cookie context"),
        )
        .expect("message-signature challenge cookie");
    let message_signature_challenge_effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(
            message_signature_challenge_cookie,
        ),
    ]);
    let message_signature_challenge_headers = auth_web_transport()
        .render_set_cookie_headers(at(30), message_signature_challenge_effects)
        .expect("message-signature challenge set-cookie headers");
    let message_signature_challenge_cookie_pair = cookie_pair_from_set_cookie(
        &message_signature_challenge_headers,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    harness.database_operation_observer.clear();
    let wrong_family_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[message_signature_challenge_cookie_pair]),
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "method-resend-wrong-family-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("non-out-of-band challenge cookie must fail before resend state load");
    assert!(matches!(
        wrong_family_resend_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                family: ProofFamily::MessageSignature
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "non-out-of-band resend challenge cookie must reject before any database operation",
    );

    let resend = start_and_issue_out_of_band_challenge_through_runtime(
        registry_runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "method-resend",
        60,
        id("method-resend-subject"),
    )
    .await;
    let resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[resend.challenge_cookie_pair.as_str()]),
            ResendOutOfBandChallengeRequest {
                now: at(80),
                idempotency_key: "method-resend-mail-idempotency-key-2".to_owned(),
            },
        )
        .await
        .expect_err("registered method must be required on challenge resend");
    assert_method_registry_not_configured(&resend_error);
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &resend.challenge_id).await,
        0
    );
    assert_eq!(
        count_challenge_delivery_keys(pool, store_config, &resend.challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &resend.challenge_id)
            .await,
        1
    );

    harness.database_operation_observer.clear();
    let expired_cookie_resend_error = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[resend.challenge_cookie_pair.as_str()]),
            ResendOutOfBandChallengeRequest {
                now: at(111),
                idempotency_key: "method-resend-expired-cookie-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect_err("expired challenge cookie must fail before method dispatch");
    assert!(matches!(
        expired_cookie_resend_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieExpired
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired out-of-band resend challenge cookie must reject before any database operation",
    );
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &resend.challenge_id).await,
        0
    );
    assert_eq!(
        count_challenge_delivery_keys(pool, store_config, &resend.challenge_id).await,
        1
    );

    let completion = start_and_issue_out_of_band_challenge_through_runtime(
        registry_runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "method-completion",
        100,
        id("method-completion-subject"),
    )
    .await;
    let completion_headers =
        headers_from_cookie_pairs(&[completion.challenge_cookie_pair.as_str()]);
    let completion_error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &completion_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(120),
                secret_response: ActiveProofChallengeResponseSecret::try_from(
                    completion.response_secret.expose_secret(),
                )
                .expect("challenge response secret"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("registered method must be required on challenge completion");
    assert_method_registry_not_configured(&completion_error);
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &completion.attempt_id).await,
        0
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &completion.challenge_id).await,
        1
    );

    let known_subject_started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_state_for_registry_errors
            .session_cookie_pair
            .as_str(),
        at(130),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let known_subject_attempt_id = known_subject_started.attempt_id.clone();
    let known_subject_continuation_cookie_pair = known_subject_started.continuation_cookie_pair;
    let known_subject_headers =
        headers_from_cookie_pairs(&[known_subject_continuation_cookie_pair.as_str()]);
    let known_subject_method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");
    let known_subject_secret_response =
        known_subject_test_method_response_payload(&id("method-known-subject"));
    let known_subject_weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_known_subject_completion(
            &known_subject_headers,
            &known_subject_method,
            &known_subject_secret_response,
            at(140),
        );
    let known_subject_error = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &known_subject_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(140),
                method: known_subject_method,
                secret_response: known_subject_secret_response,
                weak_proof_gate_response: Some(known_subject_weak_proof_gate_response),
            },
        )
        .await
        .expect_err("registered method must be required on known-subject completion");
    assert_method_registry_not_configured(&known_subject_error);
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &known_subject_attempt_id,).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_commits_method_work_atomically_with_core_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_method_plugin(Some(
        TestMethodCommitFailureMode::None,
    ))
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness.method_plugin.as_ref().expect("test method plugin");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-atomic-success:email-hash:window"),
                recipient_handle: "method-atomic-success-recipient".to_owned(),
                idempotency_key: "method-atomic-success-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue challenge with method registry");
    let success_challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &success_challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &success_challenge_id)
            .await,
        1
    );
    assert_eq!(method_plugin.count_state_rows(pool).await, 1);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 1);

    let precondition_error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(40),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(
                    "method-atomic-precondition-failure:email-hash:window",
                ),
                recipient_handle: "method-atomic-precondition-failure-recipient".to_owned(),
                idempotency_key: "method-atomic-precondition-failure-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(40)),
        )
        .await
        .expect_err("method precondition failure must abort the whole commit");
    assert_method_commit_work_failed(
        &precondition_error,
        super::super::super::postgres_store::PostgresAuthMethodCommitStage::EnforcePrecondition,
        "otp_state_absent",
    );
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        1
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        1
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 1);
    assert_eq!(method_plugin.count_state_rows(pool).await, 1);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 1);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rolls_back_core_work_when_method_mutation_fails() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_method_plugin(Some(
        TestMethodCommitFailureMode::FailMutation,
    ))
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness.method_plugin.as_ref().expect("test method plugin");

    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-mutation-failure:email-hash:window"),
                recipient_handle: "method-mutation-failure-recipient".to_owned(),
                idempotency_key: "method-mutation-failure-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect_err("method mutation failure must abort the whole commit");
    assert_method_commit_work_failed(
        &error,
        super::super::super::postgres_store::PostgresAuthMethodCommitStage::ApplyMutation,
        "store_otp_state",
    );
    assert_eq!(
        count_all_active_proof_challenges(pool, store_config).await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(method_plugin.count_state_rows(pool).await, 0);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rolls_back_core_work_when_method_durable_effect_fails() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_method_plugin(Some(
        TestMethodCommitFailureMode::FailDurableEffectCommand,
    ))
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness.method_plugin.as_ref().expect("test method plugin");

    let error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &HeaderMap::new(),
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("method-effect-failure:email-hash:window"),
                recipient_handle: "method-effect-failure-recipient".to_owned(),
                idempotency_key: "method-effect-failure-mail-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect_err("method durable effect failure must abort the whole commit");
    assert_method_commit_work_failed(
        &error,
        super::super::super::postgres_store::PostgresAuthMethodCommitStage::AppendDurableEffectCommand,
        "queue_email_body",
    );
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &id("method-effect-failure-challenge"))
            .await,
        0
    );
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        0
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 0);
    assert_eq!(method_plugin.count_state_rows(pool).await, 0);
    assert_eq!(method_plugin.count_durable_effect_rows(pool).await, 0);

    harness.drop_schema().await;
}
