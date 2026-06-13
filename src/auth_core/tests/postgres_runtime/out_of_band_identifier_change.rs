use super::*;

#[tokio::test]
async fn postgres_runtime_rejects_out_of_band_completion_without_challenge_runtime() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &HeaderMap::new(),
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: ActiveProofMethodResponsePayload::try_from_bytes(
                    b"out-of-band-response".as_slice(),
                )
                .expect("out-of-band response payload"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("active-proof method completion must use a challenge cookie");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofChallengeCookie
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_email_otp_method_lifecycle() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin");
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("email-otp-method-subject");

    harness.database_operation_observer.clear();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("email-otp-method:recipient-hash:window"),
                recipient_handle: recipient_handle_for_test_subject(
                    "email-otp-method",
                    &subject_id,
                ),
                idempotency_key: "email-otp-method-delivery-1".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue email otp challenge");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected email otp challenge issue, got {outcome:?}"),
    };
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &challenge_id).await,
        1
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges"),
        1
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands"),
        1
    );

    let resend_request = email_otp
        .resend_challenge_request(EmailOtpResendChallenge {
            now: at(40),
            delivery_idempotency_key: "email-otp-method-delivery-2".to_owned(),
        })
        .expect("build email otp resend request");
    let resend_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let resent = runtime
        .execute_out_of_band_challenge_resend_from_headers(&resend_headers, resend_request)
        .await
        .expect("resend email otp challenge");
    assert!(matches!(
        resent.outcome(),
        Outcome::OutOfBandChallengeResent {
            resend_count: 1,
            ..
        }
    ));
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &challenge_id).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &challenge_id).await,
        2
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands after resend"),
        2
    );

    harness.database_operation_observer.clear();
    let wrong_response = email_otp
        .complete_challenge_response(EmailOtpCompleteChallengeResponse {
            now: at(45),
            secret_response: ActiveProofChallengeResponseSecret::try_from(
                b"wrong-email-otp-code".as_slice(),
            )
            .expect("wrong email otp response secret"),
            weak_proof_gate_response: None,
        })
        .expect("build wrong email otp response completion");
    let wrong_completion_error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
            wrong_response,
        )
        .await
        .expect_err("wrong email otp code must reject before state load");
    assert!(matches!(
        wrong_completion_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::StatelessFastFailVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong email otp code must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "wrong email otp code must leave the authoritative challenge open"
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges after wrong code"),
        1,
        "wrong email otp code must not consume method-owned challenge state"
    );

    let response = email_otp
        .complete_challenge_response(EmailOtpCompleteChallengeResponse {
            now: at(50),
            secret_response: response_secret,
            weak_proof_gate_response: None,
        })
        .expect("build email otp response completion");
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(&completion_headers, response)
        .await
        .expect("complete email otp challenge");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge="
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges after completion"),
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_out_of_band_dedupe_cooldown_replaces_without_identifier_lockout() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("email-otp-dedupe-preserves-access-subject");
    let challenge_dedupe_key = dedupe_key("email-otp-dedupe-preserves-access:recipient:window");
    let recipient_handle =
        recipient_handle_for_test_subject("email-otp-dedupe-preserves-access", &subject_id);
    let method = ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
        .expect("method declaration");

    let first_issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                challenge_dedupe_key: challenge_dedupe_key.clone(),
                recipient_handle: recipient_handle.clone(),
                idempotency_key: "email-otp-dedupe-preserves-access-delivery-1".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue first email OTP challenge");
    let first_challenge_id = match first_issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected first challenge issue, got {outcome:?}"),
    };
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 1);
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(pool, store_config, &first_challenge_id,)
            .await,
        1
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email OTP delivery commands after first issue"),
        1
    );

    let live_duplicate_error = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(30),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                challenge_dedupe_key: challenge_dedupe_key.clone(),
                recipient_handle: recipient_handle.clone(),
                idempotency_key: "email-otp-dedupe-preserves-access-delivery-2".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(30)),
        )
        .await
        .expect_err("live dedupe bucket must reject a duplicate challenge");
    assert!(matches!(
        live_duplicate_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            super::super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(
                "open out-of-band challenge dedupe key already exists"
            )
        )
    ));
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        1,
        "failed live dedupe issue must not persist a new attempt"
    );
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email OTP delivery commands after live duplicate"),
        1,
        "failed live dedupe issue must not enqueue method-owned delivery"
    );

    let second_issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(45),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method,
                challenge_dedupe_key,
                recipient_handle,
                idempotency_key: "email-otp-dedupe-preserves-access-delivery-3".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(45)),
        )
        .await
        .expect("dedupe bucket past replacement cooldown must allow a new challenge");
    let (second_attempt_id, second_challenge_id) = match second_issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected replacement challenge issue, got {outcome:?}"),
    };
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &first_challenge_id).await,
        0,
        "issuing after replacement cooldown must close the previous dedupe challenge before its TTL"
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &second_challenge_id).await,
        1
    );
    assert_eq!(count_all_active_proof_attempts(pool, store_config).await, 2);
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email OTP delivery commands after replacement issue"),
        2
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email OTP method challenges after replacement issue"),
        1,
        "method-owned email OTP state must close the replaced challenge in the same atomic issue transaction"
    );

    let second_response_secret = email_otp
        .fetch_response_secret_for_test(pool, &second_challenge_id)
        .await
        .expect("fetch replacement response secret");
    let second_challenge_cookie_pair = cookie_pair_from_set_cookie(
        second_issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let second_continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(second_issued.set_cookie_headers())
            .to_owned();
    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[second_challenge_cookie_pair.as_str()]),
            CompleteOutOfBandChallengeResponse {
                now: at(50),
                secret_response: second_response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete replacement email OTP challenge");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &second_attempt_id).await,
        1
    );

    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &headers_from_cookie_pairs(&[second_continuation_cookie_pair.as_str()]),
            CompleteFullAuthenticationInput {
                now: at(55),
                trust_device: None,
            },
        )
        .await
        .expect("complete full authentication after replacement challenge");
    let Outcome::Authenticated(authenticated) = full_authentication.outcome() else {
        panic!(
            "expected full authentication after expired dedupe replacement, got {:?}",
            full_authentication.outcome()
        );
    };
    assert_eq!(
        authenticated.subject_id, subject_id,
        "expired delivery dedupe must not become an identifier-level lockout"
    );
    assert_eq!(
        authenticated.source,
        AuthenticationSource::FullAuthentication
    );
    assert!(authenticated.step_up_is_fresh);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_derives_email_otp_subject_from_method_state() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let recipient_handle = "subject-resolving-email-otp-recipient";
    let subject_id: SubjectId = id("subject-resolved-by-email-otp-plugin");
    let source_id: VerifiedProofSourceId = id("verified-email-identifier-binding");
    let subject_resolver = Arc::new(StaticEmailOtpSubjectResolver::new(
        recipient_handle,
        subject_id.clone(),
        source_id.clone(),
    ));
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_subject_resolver(
        subject_resolver.clone(),
    )
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin");
    let empty_headers = HeaderMap::new();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("subject-resolving-email-otp:window"),
                recipient_handle: recipient_handle.to_owned(),
                idempotency_key: "subject-resolving-email-otp-delivery".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue email otp challenge");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected email otp challenge issue, got {outcome:?}"),
    };
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
            email_otp
                .complete_challenge_response(EmailOtpCompleteChallengeResponse {
                    now: at(40),
                    secret_response: response_secret,
                    weak_proof_gate_response: None,
                })
                .expect("build email otp response"),
        )
        .await
        .expect("complete email otp challenge");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );
    assert_eq!(
        fetch_active_proof_attempt_subject_id(pool, store_config, &attempt_id).await,
        Some(subject_id),
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            source_id,
        )),
    );
    assert_eq!(subject_resolver.call_count(), 1);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_bad_email_otp_before_subject_resolution() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let recipient_handle = "bad-email-otp-fast-fail-recipient";
    let subject_resolver = Arc::new(StaticEmailOtpSubjectResolver::new(
        recipient_handle,
        id("bad-email-otp-fast-fail-subject"),
        id("bad-email-otp-fast-fail-source"),
    ));
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_subject_resolver(
        subject_resolver.clone(),
    )
    .await;
    let runtime = &harness.runtime;
    let email_otp = harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin");
    let empty_headers = HeaderMap::new();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("bad-email-otp-fast-fail:window"),
                recipient_handle: recipient_handle.to_owned(),
                idempotency_key: "bad-email-otp-fast-fail-delivery".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue email otp challenge");
    assert!(matches!(
        issued.outcome(),
        Outcome::OutOfBandChallengeIssued { .. }
    ));
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let wrong_response_secret = ActiveProofChallengeResponseSecret::try_from(b"wrong".as_slice())
        .expect("wrong challenge response secret");

    let error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
            email_otp
                .complete_challenge_response(EmailOtpCompleteChallengeResponse {
                    now: at(40),
                    secret_response: wrong_response_secret,
                    weak_proof_gate_response: None,
                })
                .expect("build email otp response"),
        )
        .await
        .expect_err("bad OTP must fail before subject resolution");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::StatelessFastFailVerificationFailed
        )
    ));
    assert_eq!(subject_resolver.call_count(), 0);

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_reserves_out_of_band_identifier_change_candidate_binding() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("identifier-change-candidate-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "identifier-change-candidate-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(100),
        ProofUse::ProveOutOfBandIdentifierChangeCandidate,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let candidate_recipient_handle = "identifier-change-candidate-recipient";

    let issued = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(110),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("identifier-change-candidate:email:window"),
                recipient_handle: candidate_recipient_handle.to_owned(),
                idempotency_key: "identifier-change-candidate-mail-key".to_owned(),
            },
        )
        .await
        .expect("issue identifier-change candidate challenge");
    let challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected identifier-change candidate challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch identifier-change candidate response secret");
    let completion_headers = headers_from_cookie_pairs(&[
        started.continuation_cookie_pair.as_str(),
        challenge_cookie_pair.as_str(),
    ]);

    harness.database_operation_observer.clear();
    let wrong_response_error = runtime
        .execute_out_of_band_identifier_change_candidate_binding_from_headers(
            &completion_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(120),
                secret_response: ActiveProofChallengeResponseSecret::try_from(
                    b"wrong-candidate-code".as_slice(),
                )
                .expect("wrong candidate code"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("wrong candidate code must reject before state load");
    assert!(matches!(
        wrong_response_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::StatelessFastFailVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong identifier-change candidate code must reject before any database operation",
    );

    let completed = runtime
        .execute_out_of_band_identifier_change_candidate_binding_from_headers(
            &completion_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(130),
                secret_response: response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("reserve identifier-change candidate binding");
    let candidate_identifier_source_id = match completed.outcome() {
        Outcome::OutOfBandIdentifierChangeCandidateBindingReserved(outcome) => {
            assert_eq!(outcome.subject_id, subject_id);
            outcome.candidate_identifier_source_id.clone()
        }
        outcome => panic!("expected identifier-change candidate reservation, got {outcome:?}"),
    };
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge="
    ));
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_continuation="
    ));
    let stored_binding = fetch_out_of_band_identifier_binding_for_source(
        pool,
        store_config,
        &candidate_identifier_source_id,
    )
    .await
    .expect("candidate identifier binding should be stored");
    assert_eq!(stored_binding.0, subject_id);
    assert_eq!(stored_binding.1, "email_otp");
    assert_eq!(
        stored_binding.2,
        OutOfBandIdentifierBindingLifecycleState::PendingActivation
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &started.attempt_id).await,
        0,
        "candidate binding proof must not be recorded as a reusable satisfied proof"
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );
    assert_eq!(
        email_otp
            .count_open_method_challenges_for_test(pool)
            .await
            .expect("count open email otp challenges after candidate reservation"),
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_out_of_band_identifier_change_executes_from_session_and_bindings()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("authenticated-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-identifier-change-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let current_identifier_source_id = id("authenticated-identifier-change-current");
    let candidate_identifier_source_id = id("authenticated-identifier-change-candidate");
    let current_identifier_authority = id("authenticated-identifier-change-current-authority");
    let stale_candidate_identifier_authority =
        id("authenticated-identifier-change-stale-candidate-authority");
    let session_authority = id("authenticated-identifier-change-session-authority");
    seed_out_of_band_identifier_change_runtime_state(
        pool,
        store_config,
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
            store_config.clone(),
            test_keyset("tests.auth.postgres-runtime.identifier-change-stale-authority.v1"),
        );
    stale_candidate_authority_store
        .store_subject_lifecycle_metadata_for_test(
            pool,
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
    assert_eq!(
        fetch_lifecycle_authority_ids_for_runtime_test(
            pool,
            store_config,
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
            &candidate_identifier_source_id,
        )
        .await,
        vec![stale_candidate_identifier_authority],
        "test setup must prove the pending candidate starts with a stale authority mapping"
    );
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let mounted_service = MountedSubjectLifecyclePostgresService::new(runtime);

    let execution = mounted_service
        .execute_authenticated_out_of_band_identifier_change_from_headers(
            &headers,
            ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(80),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
            },
        )
        .await
        .expect("execute authenticated identifier change");

    assert_eq!(
        execution.outcome(),
        &MountedOutOfBandIdentifierChangeExecutionOutcome::IdentifierChanged {
            subject_id: subject_id.clone(),
            current_identifier_source_id: current_identifier_source_id.clone(),
            candidate_identifier_source_id: candidate_identifier_source_id.clone(),
        }
    );
    assert_eq!(
        execution.runtime_execution().outcome(),
        &Outcome::OutOfBandIdentifierChanged(OutOfBandIdentifierChangeOutcome {
            subject_id: subject_id.clone(),
            current_identifier_source_id: current_identifier_source_id.clone(),
            candidate_identifier_source_id: candidate_identifier_source_id.clone(),
        })
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            pool,
            store_config,
            &current_identifier_source_id,
        )
        .await
        .expect("current identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Superseded,
        "identifier change must supersede the old binding"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            pool,
            store_config,
            &candidate_identifier_source_id,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Active,
        "identifier change must activate the pre-proven candidate binding"
    );
    assert_eq!(
        count_lifecycle_authority_sources_for_runtime_test(
            pool,
            store_config,
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
            &candidate_identifier_source_id,
        )
        .await,
        1,
        "identifier change must bind the activated candidate source as lifecycle authority"
    );
    assert_eq!(
        fetch_lifecycle_authority_ids_for_runtime_test(
            pool,
            store_config,
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
            &candidate_identifier_source_id,
        )
        .await,
        vec![current_identifier_authority],
        "identifier change must preserve the current source recovery-authority mapping"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "identifier change must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "identifier change must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_out_of_band_identifier_change_planning_generates_pending_subject_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("authenticated-delayed-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-delayed-identifier-change-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let current_identifier_source_id = id("authenticated-delayed-identifier-change-current");
    let candidate_identifier_source_id = id("authenticated-delayed-identifier-change-candidate");
    let current_identifier_authority =
        id("authenticated-delayed-identifier-change-current-authority");
    let session_authority = id("authenticated-delayed-identifier-change-session-authority");
    seed_out_of_band_identifier_change_runtime_state(
        pool,
        store_config,
        &subject_id,
        &issued_auth.session_id,
        &current_identifier_source_id,
        &candidate_identifier_source_id,
        current_identifier_authority.clone(),
        session_authority,
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let mounted_service = MountedSubjectLifecyclePostgresService::new(runtime);

    let execution = mounted_service
        .plan_authenticated_out_of_band_identifier_change_from_headers(
            &headers,
            PlanMountedAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(80),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
            },
        )
        .await
        .expect("plan authenticated delayed identifier change");

    let pending_action_id = match execution.outcome() {
        MountedOutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
            subject_id: actual_subject_id,
            current_identifier_source_id: actual_current_source_id,
            candidate_identifier_source_id: actual_candidate_source_id,
            pending_action_id,
            earliest_execute_at,
            expires_at,
        } => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(actual_current_source_id, &current_identifier_source_id);
            assert_eq!(actual_candidate_source_id, &candidate_identifier_source_id);
            assert_eq!(earliest_execute_at, &at(200));
            assert_eq!(expires_at, &at(300));
            pending_action_id.clone()
        }
        outcome => panic!("expected pending identifier-change action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        1,
        "runtime-generated pending identifier-change action id must be committed"
    );
    let stored_pending_action = load_pending_subject_lifecycle_action_for_runtime_test(
        pool,
        store_config,
        &pending_action_id,
    )
    .await
    .expect("stored pending identifier-change action");
    assert_eq!(stored_pending_action.subject_id, subject_id);
    assert_eq!(
        stored_pending_action.action,
        SubjectLifecycleAction::ChangeOutOfBandIdentifier
    );
    assert_eq!(
        stored_pending_action.current_identifier_source_id,
        Some(current_identifier_source_id.clone())
    );
    assert_eq!(
        stored_pending_action.candidate_identifier_source_id,
        Some(candidate_identifier_source_id.clone())
    );
    assert_eq!(
        stored_pending_action.candidate_identifier_authority_ids,
        vec![current_identifier_authority.clone()]
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "identifier-change scheduling must atomically schedule a security notice"
    );

    let execution = mounted_service
        .execute_delayed_out_of_band_identifier_change_from_headers(
            &HeaderMap::new(),
            ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("execute runtime-planned delayed identifier change");

    assert_eq!(
        execution.committed_outcome(),
        &MountedSubjectLifecycleCommittedOutcome::OutOfBandIdentifierChangeExecuted {
            subject_id: subject_id.clone(),
            pending_action_id: pending_action_id.clone(),
            current_identifier_source_id: current_identifier_source_id.clone(),
            candidate_identifier_source_id: candidate_identifier_source_id.clone(),
        }
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            pool,
            store_config,
            &candidate_identifier_source_id,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Active,
        "runtime-planned delayed identifier change must activate the pre-proven candidate"
    );
    assert_eq!(
        fetch_lifecycle_authority_ids_for_runtime_test(
            pool,
            store_config,
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
            &candidate_identifier_source_id,
        )
        .await,
        vec![current_identifier_authority],
        "runtime-planned delayed identifier change must preserve the current source recovery-authority mapping"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        0,
        "execution must close the runtime-planned pending identifier-change action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        2,
        "identifier-change scheduling and execution must each commit their security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_out_of_band_identifier_change_executes_from_pending_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("mature-pending-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "mature-pending-identifier-change-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let current_identifier_source_id = id("mature-pending-identifier-change-current");
    let candidate_identifier_source_id = id("mature-pending-identifier-change-candidate");
    let current_identifier_authority = id("mature-pending-identifier-change-current-authority");
    let session_authority = id("mature-pending-identifier-change-session-authority");
    let candidate_authority = id("mature-pending-identifier-change-candidate-authority");
    seed_out_of_band_identifier_change_runtime_state(
        pool,
        store_config,
        &subject_id,
        &issued_auth.session_id,
        &current_identifier_source_id,
        &candidate_identifier_source_id,
        current_identifier_authority,
        session_authority,
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    let pending_action_id = id("mature-pending-identifier-change-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.pending-identifier-change.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    pending_action_id.clone(),
                    subject_id.clone(),
                    current_identifier_source_id.clone(),
                    candidate_identifier_source_id.clone(),
                    vec![candidate_authority.clone()],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending identifier-change action"),
            ],
        )
        .await
        .expect("seed pending identifier-change action");
    let mounted_service = MountedSubjectLifecyclePostgresService::new(runtime);
    harness.database_operation_observer.clear();

    let execution = mounted_service
        .execute_delayed_out_of_band_identifier_change_from_headers(
            &HeaderMap::new(),
            ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("execute mature pending identifier change");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
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
        "mature pending out-of-band identifier change must stay inside one pending-action load, binding-state guards, candidate activation, authority replacement, auth-state revocation, notice, and commit",
    );

    assert_eq!(
        execution.committed_outcome(),
        &MountedSubjectLifecycleCommittedOutcome::OutOfBandIdentifierChangeExecuted {
            subject_id: subject_id.clone(),
            pending_action_id: pending_action_id.clone(),
            current_identifier_source_id: current_identifier_source_id.clone(),
            candidate_identifier_source_id: candidate_identifier_source_id.clone(),
        }
    );
    assert_eq!(
        execution.runtime_execution().outcome(),
        &Outcome::PendingOutOfBandIdentifierChangeExecuted(
            PendingOutOfBandIdentifierChangeExecutionOutcome {
                subject_id: subject_id.clone(),
                pending_action_id: pending_action_id.clone(),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
            },
        )
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        0,
        "execution must close the pending identifier-change action"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            pool,
            store_config,
            &current_identifier_source_id,
        )
        .await
        .expect("current identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Superseded
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            pool,
            store_config,
            &candidate_identifier_source_id,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::Active
    );
    assert_eq!(
        count_lifecycle_authority_sources_for_runtime_test(
            pool,
            store_config,
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
            &candidate_identifier_source_id,
        )
        .await,
        1,
        "delayed identifier-change execution must bind candidate authority"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(250),
        "delayed identifier-change execution must revoke older subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "delayed identifier-change execution must commit a security notice"
    );

    let replay_error = runtime
        .execute_mature_pending_out_of_band_identifier_change_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingOutOfBandIdentifierChangeInput {
                now: at(260),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending identifier-change execution must not replay");
    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingSubjectLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_out_of_band_identifier_change_cancellation_closes_open_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("cancel-pending-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "cancel-pending-identifier-change-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let current_identifier_source_id = id("cancel-pending-identifier-change-current");
    let candidate_identifier_source_id = id("cancel-pending-identifier-change-candidate");
    let current_identifier_authority = id("cancel-pending-identifier-change-current-authority");
    let session_authority = id("cancel-pending-identifier-change-session-authority");
    let candidate_authority = id("cancel-pending-identifier-change-candidate-authority");
    seed_out_of_band_identifier_change_runtime_state(
        pool,
        store_config,
        &subject_id,
        &issued_auth.session_id,
        &current_identifier_source_id,
        &candidate_identifier_source_id,
        current_identifier_authority,
        session_authority,
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    let pending_action_id = id("cancel-pending-identifier-change-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.pending-identifier-change-cancel.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    pending_action_id.clone(),
                    subject_id.clone(),
                    current_identifier_source_id.clone(),
                    candidate_identifier_source_id.clone(),
                    vec![candidate_authority],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending identifier-change action"),
            ],
        )
        .await
        .expect("seed pending identifier-change action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let mounted_service = MountedSubjectLifecyclePostgresService::new(runtime);
    harness.database_operation_observer.clear();

    let cancellation = mounted_service
        .cancel_delayed_out_of_band_identifier_change_from_headers(
            &headers,
            CancelMountedDelayedOutOfBandIdentifierChangeInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending identifier change");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
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
        "authenticated pending out-of-band identifier change cancellation must stay inside one live-session load, pending-action load, cancellable guard, pending closure, audit, notice, and commit",
    );

    assert_eq!(
        cancellation.committed_outcome(),
        &MountedSubjectLifecycleCommittedOutcome::OutOfBandIdentifierChangeCancelled {
            subject_id: subject_id.clone(),
            pending_action_id: pending_action_id.clone(),
            current_identifier_source_id: current_identifier_source_id.clone(),
            candidate_identifier_source_id: candidate_identifier_source_id.clone(),
        }
    );
    assert_eq!(
        cancellation.runtime_execution().outcome(),
        &Outcome::PendingOutOfBandIdentifierChangeCancelled(
            PendingOutOfBandIdentifierChangeCancellationOutcome {
                subject_id: subject_id.clone(),
                pending_action_id: pending_action_id.clone(),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
            },
        )
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        0,
        "cancellation must close the pending identifier-change action"
    );
    assert_eq!(
        fetch_out_of_band_identifier_binding_for_source(
            pool,
            store_config,
            &candidate_identifier_source_id,
        )
        .await
        .expect("candidate identifier binding")
        .2,
        OutOfBandIdentifierBindingLifecycleState::PendingActivation,
        "cancellation must not activate the candidate binding"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "cancellation must commit an identifier-change cancellation notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_out_of_band_identifier_change_cancellation_rejects_wrong_subject_session()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let pending_subject_id: SubjectId = id("wrong-subject-identifier-change-owner");
    let session_subject_id: SubjectId = id("wrong-subject-identifier-change-session");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "wrong-subject-identifier-change-bootstrap",
        50,
        session_subject_id.clone(),
        false,
    )
    .await;
    let pending_action_id = id("wrong-subject-identifier-change-action");
    let current_identifier_source_id = id("wrong-subject-identifier-change-current");
    let candidate_identifier_source_id = id("wrong-subject-identifier-change-candidate");
    let candidate_authority = id("wrong-subject-identifier-change-candidate-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.pending-identifier-change-wrong-subject.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    pending_action_id.clone(),
                    pending_subject_id.clone(),
                    current_identifier_source_id,
                    candidate_identifier_source_id,
                    vec![candidate_authority],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending identifier-change action"),
            ],
        )
        .await
        .expect("seed pending identifier-change action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let cancellation_error = runtime
        .execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending identifier change");

    assert!(matches!(
        cancellation_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        1,
        "wrong-subject cancellation must leave the pending identifier-change action open"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &pending_subject_id)
            .await,
        0,
        "wrong-subject cancellation must not commit an owner security notice"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &session_subject_id)
            .await,
        0,
        "wrong-subject cancellation must not commit an actor security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_out_of_band_identifier_change_cancellation_requires_fresh_step_up_before_pending_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("stale-cancel-pending-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-cancel-pending-identifier-change-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let current_identifier_source_id = id("stale-cancel-pending-identifier-change-current");
    let candidate_identifier_source_id = id("stale-cancel-pending-identifier-change-candidate");
    let current_identifier_authority =
        id("stale-cancel-pending-identifier-change-current-authority");
    let session_authority = id("stale-cancel-pending-identifier-change-session-authority");
    let candidate_authority = id("stale-cancel-pending-identifier-change-candidate-authority");
    seed_out_of_band_identifier_change_runtime_state(
        pool,
        store_config,
        &subject_id,
        &issued_auth.session_id,
        &current_identifier_source_id,
        &candidate_identifier_source_id,
        current_identifier_authority,
        session_authority,
        RecoveryAuthorityTiming::Delayed,
    )
    .await;
    let pending_action_id = id("stale-cancel-pending-identifier-change-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.pending-identifier-change-stale-cancel.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[
                PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                    pending_action_id.clone(),
                    subject_id.clone(),
                    current_identifier_source_id,
                    candidate_identifier_source_id,
                    vec![candidate_authority],
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending identifier-change action"),
            ],
        )
        .await
        .expect("seed pending identifier-change action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("stale identifier-change cancellation returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.pending_subject_lifecycle_action"),
        "stale identifier-change cancellation must not load pending action state; observed database operations: {observed:?}"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        )
        .await,
        1,
        "stale cancellation must leave the pending identifier-change action open"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_out_of_band_identifier_change_requires_fresh_step_up_before_binding_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("stale-step-up-identifier-change-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-identifier-change-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_out_of_band_identifier_change_planning_from_headers(
            &headers,
            PlanAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(80),
                current_identifier_source_id: id("stale-step-up-identifier-change-current"),
                candidate_identifier_source_id: id("stale-step-up-identifier-change-candidate"),
            },
        )
        .await
        .expect("stale identifier-change planning returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.out_of_band_identifier_binding"),
        "stale identifier-change planning must not load identifier bindings; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}
