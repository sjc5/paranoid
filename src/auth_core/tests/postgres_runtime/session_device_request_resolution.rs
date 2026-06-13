use super::*;

#[tokio::test]
async fn postgres_runtime_executes_session_and_trusted_device_lifecycle() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key("login:email-hash:window"),
                recipient_handle: recipient_handle_for_test_subject("login", &id("subject")),
                idempotency_key: "mail-idempotency-key".to_owned(),
            },
            email_otp_challenge_issue_preflight_response_at(at(20)),
        )
        .await
        .expect("issue challenge through Postgres runtime");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id,
            expires_at,
        } => {
            assert_eq!(expires_at, &at(60));
            (issued_attempt_id.clone(), challenge_id.clone())
        }
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
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
        "unbound out-of-band challenge issue must stay inside one bounded start-and-issue transaction",
    );
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(issued.set_cookie_headers())
            .to_owned();
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let mut challenge_headers = HeaderMap::new();
    challenge_headers.insert(
        COOKIE,
        HeaderValue::from_str(challenge_cookie_pair).expect("cookie header"),
    );

    harness.database_operation_observer.clear();
    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(40),
                secret_response: response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete challenge through Postgres runtime");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );
    assert_eq!(completed.set_cookie_headers().as_slice().len(), 1);
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
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
        "out-of-band challenge completion must stay inside one bounded loaded-state commit",
    );

    let satisfied_proof_count =
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await;
    assert_eq!(satisfied_proof_count, 1);
    let open_challenge_count = count_open_challenges(pool, store_config).await;
    assert_eq!(open_challenge_count, 0);

    harness.database_operation_observer.clear();
    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &continuation_headers,
            CompleteFullAuthenticationInput {
                now: at(45),
                trust_device: Some(TrustDeviceAfterFullAuthenticationInput {
                    display_label: Some("test browser".to_owned()),
                }),
            },
        )
        .await
        .expect("complete full authentication through Postgres runtime");
    let session_id = match full_authentication.outcome() {
        Outcome::Authenticated(authenticated) => {
            assert_eq!(authenticated.subject_id, id("subject"));
            assert_eq!(
                authenticated.source,
                AuthenticationSource::FullAuthentication
            );
            assert!(authenticated.step_up_is_fresh);
            authenticated.session_id.clone()
        }
        outcome => panic!("expected full authentication, got {outcome:?}"),
    };
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
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
        "full authentication completion must stay inside one bounded loaded-state commit",
    );
    let device_id = fetch_trusted_device_id_by_display_label(pool, store_config, "test browser")
        .await
        .expect("trusted device id");
    let session_cookie_pair = cookie_pair_from_set_cookie(
        full_authentication.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    );
    let trusted_device_cookie_pair = cookie_pair_from_set_cookie(
        full_authentication.set_cookie_headers(),
        "__Host-__paranoid_auth_trusted_device=",
    );
    assert!(
        set_cookie_headers_contain_prefix(
            full_authentication.set_cookie_headers(),
            "__Host-csrf_token="
        ),
        "full authentication must cycle CSRF with the newly issued session"
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 1);
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &session_id).await,
        1
    );
    assert_eq!(count_all_trusted_devices(pool, store_config).await, 1);
    assert_eq!(
        count_trusted_device_secret_macs_for_device(pool, store_config, &device_id).await,
        1
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        0,
        "full authentication must close and delete the active-proof attempt"
    );
    let mut session_headers = HeaderMap::new();
    session_headers.insert(
        COOKIE,
        HeaderValue::from_str(session_cookie_pair).expect("session cookie header"),
    );
    harness.database_operation_observer.clear();
    let resolved = runtime
        .execute_request_resolution_from_headers(
            &session_headers,
            ResolveRequestInput {
                now: at(50),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve issued session through Postgres runtime");
    assert_eq!(
        resolved.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("subject"),
            session_id: session_id.clone(),
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
        })
    );
    assert!(
        resolved
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "authoritative request resolution should reissue a safe-read-capable session cookie"
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.session_still_matches",
            "auth_core.precondition.fetch_subject_cutoff",
            "db.tx.commit",
        ],
        "authoritative non-refresh session resolution must preserve the loaded-state commit boundary without extra operations",
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &session_id).await,
        1,
        "non-refresh request resolution must reuse the presented session secret without creating another MAC row"
    );

    let mut trusted_device_headers = HeaderMap::new();
    trusted_device_headers.insert(
        COOKIE,
        HeaderValue::from_str(trusted_device_cookie_pair).expect("trusted-device cookie header"),
    );
    harness.database_operation_observer.clear();
    let revived = runtime
        .execute_request_resolution_from_headers(
            &trusted_device_headers,
            ResolveRequestInput {
                now: at(60),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("silently revive session from trusted-device cookie through Postgres runtime");
    let revived_session_id = match revived.outcome() {
        Outcome::Authenticated(authenticated) => {
            assert_eq!(authenticated.subject_id, id("subject"));
            assert_eq!(
                authenticated.source,
                AuthenticationSource::SilentTrustedDeviceRevival
            );
            assert!(!authenticated.step_up_is_fresh);
            authenticated.session_id.clone()
        }
        outcome => panic!("expected silent trusted-device revival, got {outcome:?}"),
    };
    assert!(
        revived
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "trusted-device silent revival must issue a fresh session cookie"
    );
    assert!(
        revived
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_trusted_device=")),
        "trusted-device silent revival must rotate and reissue the trusted-device cookie"
    );
    assert!(
        set_cookie_headers_contain_prefix(revived.set_cookie_headers(), "__Host-csrf_token="),
        "trusted-device silent revival must cycle CSRF with the newly issued session"
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.trusted_device_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.trusted_device_still_matches",
            "auth_core.precondition.fetch_subject_cutoff",
            "auth_core.secret.insert_session_mac",
            "auth_core.secret.insert_trusted_device_mac",
            "auth_core.mutation.create_session",
            "auth_core.mutation.rotate_trusted_device",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "db.tx.commit",
        ],
        "trusted-device silent revival must stay inside one bounded load/rotate/session-create transaction",
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 2);
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &revived_session_id).await,
        1
    );
    assert_eq!(
        count_trusted_device_secret_macs_for_device(pool, store_config, &device_id).await,
        2
    );
    assert_eq!(
        fetch_trusted_device_current_secret_version(pool, store_config, &device_id).await,
        2
    );

    let rotated_trusted_device_cookie_pair = cookie_pair_from_set_cookie(
        revived.set_cookie_headers(),
        "__Host-__paranoid_auth_trusted_device=",
    );
    let mut rotated_trusted_device_headers = HeaderMap::new();
    rotated_trusted_device_headers.insert(
        COOKIE,
        HeaderValue::from_str(rotated_trusted_device_cookie_pair)
            .expect("rotated trusted-device cookie header"),
    );
    let needs_active_proof = runtime
        .execute_request_resolution_from_headers(
            &rotated_trusted_device_headers,
            ResolveRequestInput {
                now: at(600),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve trusted-device cookie after silent revival window");
    assert_eq!(
        needs_active_proof.outcome(),
        &Outcome::NeedsActiveProofFromTrustedDevice {
            device_credential_id: device_id.clone(),
            subject_id: id("subject"),
        }
    );
    assert!(needs_active_proof.set_cookie_headers().is_empty());

    let active_revival_attempt = runtime
        .execute_current_trusted_device_active_proof_attempt_start_from_headers(
            &rotated_trusted_device_headers,
            StartCurrentTrustedDeviceActiveProofAttemptInput {
                now: at(610),
                proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
            },
        )
        .await
        .expect("start trusted-device active-proof revival attempt through Postgres runtime");
    let revival_attempt_id = match active_revival_attempt.outcome() {
        Outcome::ActiveProofAttemptStarted {
            attempt_id,
            expires_at,
        } => {
            assert_eq!(expires_at, &at(730));
            attempt_id.clone()
        }
        outcome => panic!("expected revival active proof attempt start, got {outcome:?}"),
    };
    let revival_continuation_cookie_pair = active_proof_continuation_cookie_pair_from_set_cookie(
        active_revival_attempt.set_cookie_headers(),
    )
    .to_owned();
    let revival_continuation_headers =
        headers_from_cookie_pairs(&[revival_continuation_cookie_pair.as_str()]);

    let active_revival_challenge = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &revival_continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(620),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("active-revival method declaration"),
                challenge_dedupe_key: dedupe_key("revival:email-hash:window"),
                recipient_handle: "opaque-email-handle".to_owned(),
                idempotency_key: "revival-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect("issue trusted-device active-revival challenge through Postgres runtime");
    let revival_challenge_id = match active_revival_challenge.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            expires_at,
        } => {
            assert_eq!(attempt_id, &revival_attempt_id);
            assert_eq!(expires_at, &at(660));
            challenge_id.clone()
        }
        outcome => panic!("expected active-revival challenge issue, got {outcome:?}"),
    };
    let active_revival_response_secret = email_otp
        .fetch_response_secret_for_test(pool, &revival_challenge_id)
        .await
        .expect("fetch generated active-revival email otp response secret");
    let active_revival_challenge_cookie_pair = cookie_pair_from_set_cookie(
        active_revival_challenge.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let mut active_revival_challenge_headers = HeaderMap::new();
    active_revival_challenge_headers.insert(
        COOKIE,
        HeaderValue::from_str(active_revival_challenge_cookie_pair)
            .expect("active-revival challenge cookie header"),
    );

    let active_revival_proof = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &active_revival_challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(630),
                secret_response: active_revival_response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete trusted-device active-revival proof through Postgres runtime");
    assert_eq!(
        active_revival_proof.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: revival_attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );

    harness.database_operation_observer.clear();
    let active_revival = runtime
        .execute_trusted_device_revival_completion_from_headers(
            &headers_from_cookie_pairs(&[
                rotated_trusted_device_cookie_pair,
                revival_continuation_cookie_pair.as_str(),
            ]),
            CompleteTrustedDeviceRevivalWithActiveProofInput { now: at(640) },
        )
        .await
        .expect("complete trusted-device active-proof revival through Postgres runtime");
    let active_revival_session_id = match active_revival.outcome() {
        Outcome::Authenticated(authenticated) => {
            assert_eq!(authenticated.subject_id, id("subject"));
            assert_eq!(
                authenticated.source,
                AuthenticationSource::TrustedDeviceRevivalWithActiveProof
            );
            assert!(authenticated.step_up_is_fresh);
            authenticated.session_id.clone()
        }
        outcome => panic!("expected active trusted-device revival, got {outcome:?}"),
    };
    assert!(
        active_revival
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "trusted-device active-proof revival must issue a fresh session cookie"
    );
    assert!(
        active_revival
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_trusted_device=")),
        "trusted-device active-proof revival must rotate and reissue the trusted-device cookie"
    );
    assert!(
        set_cookie_headers_contain_prefix(
            active_revival.set_cookie_headers(),
            "__Host-csrf_token="
        ),
        "trusted-device active-proof revival must cycle CSRF with the newly issued session"
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.trusted_device_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.active_proof_attempt",
            "auth_core.load.active_proof_satisfied_proofs",
            "auth_core.load.active_proof_continuation_secret_mac",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.trusted_device_still_matches",
            "auth_core.precondition.fetch_subject_cutoff",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.secret.insert_session_mac",
            "auth_core.secret.insert_trusted_device_mac",
            "auth_core.mutation.delete_active_proof_delivery_keys",
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            "auth_core.mutation.delete_active_proof_challenges",
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            "auth_core.mutation.delete_active_proof_attempt",
            "auth_core.mutation.create_session",
            "auth_core.mutation.rotate_trusted_device",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "db.tx.commit",
        ],
        "trusted-device active-proof revival completion must stay inside one bounded loaded-state commit",
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 3);
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &active_revival_session_id).await,
        1
    );
    assert_eq!(
        count_trusted_device_secret_macs_for_device(pool, store_config, &device_id).await,
        3
    );
    assert_eq!(
        fetch_trusted_device_current_secret_version(pool, store_config, &device_id).await,
        3
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &revival_attempt_id).await,
        0,
        "trusted-device active-proof revival must close and delete the revival attempt"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completion_facades_reject_missing_continuation_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let full_auth_error = runtime
        .execute_full_authentication_completion_from_headers(
            &empty_headers,
            CompleteFullAuthenticationInput {
                now: at(30),
                trust_device: None,
            },
        )
        .await
        .expect_err("full authentication completion must require continuation cookie");
    assert_missing_active_proof_continuation_error(full_auth_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "full authentication completion missing continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let step_up_error = runtime
        .execute_step_up_completion_from_headers(
            &empty_headers,
            CompleteStepUpInput { now: at(30) },
        )
        .await
        .expect_err("step-up completion must require continuation cookie");
    assert_missing_active_proof_continuation_error(step_up_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "step-up completion missing continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let trusted_device_revival_error = runtime
        .execute_trusted_device_revival_completion_from_headers(
            &empty_headers,
            CompleteTrustedDeviceRevivalWithActiveProofInput { now: at(30) },
        )
        .await
        .expect_err("trusted-device active revival completion must require continuation cookie");
    assert_missing_active_proof_continuation_error(trusted_device_revival_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "trusted-device active revival completion missing continuation must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completion_facades_reject_wrong_continuation_use_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    let step_up_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::SatisfyStepUp,
        Some(id("wrong-use-continuation-subject")),
        at(20),
        at(90),
    );
    harness.database_operation_observer.clear();
    let full_auth_error = runtime
        .execute_full_authentication_completion_from_headers(
            &headers_from_cookie_pairs(&[step_up_continuation.as_str()]),
            CompleteFullAuthenticationInput {
                now: at(30),
                trust_device: None,
            },
        )
        .await
        .expect_err("full authentication completion must reject a step-up continuation");
    assert_invalid_active_proof_continuation_payload_error(full_auth_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "full authentication completion wrong-use continuation must reject before any database operation",
    );

    let full_auth_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::ContributeToFullAuthentication,
        None,
        at(20),
        at(90),
    );
    harness.database_operation_observer.clear();
    let step_up_error = runtime
        .execute_step_up_completion_from_headers(
            &headers_from_cookie_pairs(&[full_auth_continuation.as_str()]),
            CompleteStepUpInput { now: at(30) },
        )
        .await
        .expect_err("step-up completion must reject a full-authentication continuation");
    assert_invalid_active_proof_continuation_payload_error(step_up_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "step-up completion wrong-use continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let trusted_device_revival_error = runtime
        .execute_trusted_device_revival_completion_from_headers(
            &headers_from_cookie_pairs(&[full_auth_continuation.as_str()]),
            CompleteTrustedDeviceRevivalWithActiveProofInput { now: at(30) },
        )
        .await
        .expect_err("trusted-device active revival completion must reject a full-authentication continuation");
    assert_invalid_active_proof_continuation_payload_error(trusted_device_revival_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "trusted-device active revival completion wrong-use continuation must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completion_facades_reject_expired_continuation_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    let full_auth_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::ContributeToFullAuthentication,
        None,
        at(20),
        at(90),
    );
    harness.database_operation_observer.clear();
    let full_auth_error = runtime
        .execute_full_authentication_completion_from_headers(
            &headers_from_cookie_pairs(&[full_auth_continuation.as_str()]),
            CompleteFullAuthenticationInput {
                now: at(90),
                trust_device: None,
            },
        )
        .await
        .expect_err("full authentication completion must reject an expired continuation");
    assert_expired_active_proof_continuation_error(full_auth_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "full authentication completion expired continuation must reject before any database operation",
    );

    let step_up_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::SatisfyStepUp,
        Some(id("expired-step-up-continuation-subject")),
        at(20),
        at(90),
    );
    harness.database_operation_observer.clear();
    let step_up_error = runtime
        .execute_step_up_completion_from_headers(
            &headers_from_cookie_pairs(&[step_up_continuation.as_str()]),
            CompleteStepUpInput { now: at(90) },
        )
        .await
        .expect_err("step-up completion must reject an expired continuation");
    assert_expired_active_proof_continuation_error(step_up_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "step-up completion expired continuation must reject before any database operation",
    );

    let trusted_device_revival_continuation =
        rendered_active_proof_continuation_cookie_pair_for_runtime_test(
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            Some(id("expired-revival-continuation-subject")),
            at(20),
            at(90),
        );
    harness.database_operation_observer.clear();
    let trusted_device_revival_error = runtime
        .execute_trusted_device_revival_completion_from_headers(
            &headers_from_cookie_pairs(&[trusted_device_revival_continuation.as_str()]),
            CompleteTrustedDeviceRevivalWithActiveProofInput { now: at(90) },
        )
        .await
        .expect_err("trusted-device active revival completion must reject an expired continuation");
    assert_expired_active_proof_continuation_error(trusted_device_revival_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "trusted-device active revival completion expired continuation must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_request_resolution_rejects_expired_passive_cookies_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    let expired_session_cookie_pair =
        rendered_session_cookie_pair_for_runtime_test(session_cookie(90), at(20));
    harness.database_operation_observer.clear();
    let expired_session = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[expired_session_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(90),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("expired session cookie should resolve without storage work");
    assert_eq!(expired_session.outcome(), &Outcome::NeedsFullAuthentication);
    assert!(
        set_cookie_headers_contain_deletion(
            expired_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "expired session cookie must be cleared"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired session cookie must reject before any database operation",
    );

    let expired_trusted_device_cookie_pair =
        rendered_trusted_device_cookie_pair_for_runtime_test(trusted_device_cookie(60, 90), at(20));
    harness.database_operation_observer.clear();
    let expired_trusted_device = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[expired_trusted_device_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(90),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("expired trusted-device cookie should resolve without storage work");
    assert_eq!(
        expired_trusted_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            expired_trusted_device.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "expired trusted-device cookie must be cleared"
    );
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired trusted-device cookie must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_safe_read_cache_hit_avoids_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("safe-read-cache-postgres-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "safe-read-cache-postgres",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let authoritative_resolution = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(50),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("authoritative resolution should mint safe-read cache state");
    assert!(matches!(
        authoritative_resolution.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            ..
        })
    ));
    let safe_read_cookie_pair = cookie_pair_from_set_cookie(
        authoritative_resolution.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    )
    .to_owned();
    let audit_event_count_before_safe_read = count_auth_audit_events(pool, store_config).await;

    harness.database_operation_observer.clear();
    let safe_read = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[safe_read_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(55),
                request_kind: RequestKind::SafeRead,
            },
        )
        .await
        .expect("safe-read cache hit should resolve without storage work");
    assert_eq!(
        safe_read.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id,
            session_id: issued_auth.session_id,
            source: AuthenticationSource::SafeReadCache,
            step_up_is_fresh: false,
        })
    );
    assert!(safe_read.set_cookie_headers().is_empty());
    assert_no_database_operations(
        &harness.database_operation_observer,
        "safe-read cache hit must authenticate without any database operation",
    );
    assert_eq!(
        count_auth_audit_events(pool, store_config).await,
        audit_event_count_before_safe_read,
        "safe-read cache hit must not append lifecycle audit events"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_issue_facades_reject_missing_or_expired_continuation_before_db()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();

    harness.database_operation_observer.clear();
    let out_of_band_missing_error = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            IssueOutOfBandChallengeInput {
                now: at(30),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("out-of-band method"),
                challenge_dedupe_key: dedupe_key("missing-continuation-email:window"),
                recipient_handle: "missing-continuation-email-handle".to_owned(),
                idempotency_key: "missing-continuation-email-idempotency".to_owned(),
            },
        )
        .await
        .expect_err("out-of-band challenge issue must require a continuation cookie");
    assert_missing_active_proof_continuation_error(out_of_band_missing_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "out-of-band challenge issue missing continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let active_method_missing_error = runtime
        .execute_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            IssueActiveProofMethodChallengeInput {
                now: at(30),
                method: ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
                    .expect("message-signature method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect_err("active-method challenge issue must require a continuation cookie");
    assert_missing_active_proof_continuation_error(active_method_missing_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "active-method challenge issue missing continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let challenge_bound_totp_missing_error = runtime
        .execute_challenge_bound_known_subject_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            IssueChallengeBoundKnownSubjectActiveProofMethodChallengeInput {
                now: at(30),
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect_err("challenge-bound TOTP challenge issue must require a continuation cookie");
    assert_missing_active_proof_continuation_error(challenge_bound_totp_missing_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "challenge-bound TOTP issue missing continuation must reject before any database operation",
    );

    let expired_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::SatisfyStepUp,
        Some(id("expired-challenge-issue-continuation-subject")),
        at(20),
        at(90),
    );
    let expired_headers = headers_from_cookie_pairs(&[expired_continuation.as_str()]);

    harness.database_operation_observer.clear();
    let out_of_band_expired_error = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &expired_headers,
            IssueOutOfBandChallengeInput {
                now: at(90),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("out-of-band method"),
                challenge_dedupe_key: dedupe_key("expired-continuation-email:window"),
                recipient_handle: "expired-continuation-email-handle".to_owned(),
                idempotency_key: "expired-continuation-email-idempotency".to_owned(),
            },
        )
        .await
        .expect_err("out-of-band challenge issue must reject an expired continuation cookie");
    assert_expired_active_proof_continuation_error(out_of_band_expired_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "out-of-band challenge issue expired continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let active_method_expired_error = runtime
        .execute_active_proof_method_challenge_issue_from_headers(
            &expired_headers,
            IssueActiveProofMethodChallengeInput {
                now: at(90),
                method: ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
                    .expect("message-signature method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect_err("active-method challenge issue must reject an expired continuation cookie");
    assert_expired_active_proof_continuation_error(active_method_expired_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "active-method challenge issue expired continuation must reject before any database operation",
    );

    harness.database_operation_observer.clear();
    let challenge_bound_totp_expired_error = runtime
        .execute_challenge_bound_known_subject_active_proof_method_challenge_issue_from_headers(
            &expired_headers,
            IssueChallengeBoundKnownSubjectActiveProofMethodChallengeInput {
                now: at(90),
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect_err(
            "challenge-bound TOTP challenge issue must reject an expired continuation cookie",
        );
    assert_expired_active_proof_continuation_error(challenge_bound_totp_expired_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "challenge-bound TOTP issue expired continuation must reject before any database operation",
    );

    harness.drop_schema().await;
}
