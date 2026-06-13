use super::*;

#[tokio::test]
async fn postgres_runtime_tripwires_replayed_previous_secrets_after_grace() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let session_tripwire_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "session-tripwire",
        20,
        id("session-tripwire-subject"),
        true,
    )
    .await;
    let session_tripwire_device_id = session_tripwire_state
        .trusted_device_credential_id
        .clone()
        .expect("session-tripwire trusted device id");
    let original_session_cookie_pair = session_tripwire_state.session_cookie_pair.as_str();
    let original_trusted_device_cookie_pair = session_tripwire_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("session-tripwire trusted-device cookie");

    let refreshed = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[original_session_cookie_pair]),
            ResolveRequestInput {
                now: at(130),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("refresh session before session tripwire replay");
    assert!(matches!(
        refreshed.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::RefreshedSession,
            ..
        })
    ));
    assert_eq!(
        count_session_secret_macs_for_session(
            pool,
            store_config,
            &session_tripwire_state.session_id
        )
        .await,
        2,
        "session refresh must leave one current and one previous secret MAC"
    );

    let replayed_old_session = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[
                original_session_cookie_pair,
                original_trusted_device_cookie_pair,
            ]),
            ResolveRequestInput {
                now: at(136),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("replay old session cookie after grace through Postgres runtime");
    assert_eq!(
        replayed_old_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            replayed_old_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "session tripwire must delete the presented session cookie"
    );
    assert!(
        set_cookie_headers_contain_deletion(
            replayed_old_session.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "session tripwire must delete the associated trusted-device cookie"
    );
    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &session_tripwire_state.session_id).await,
        Some(136)
    );
    assert_eq!(
        fetch_trusted_device_revoked_at(pool, store_config, &session_tripwire_device_id).await,
        Some(136)
    );

    let trusted_device_tripwire_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "trusted-device-tripwire",
        180,
        id("trusted-device-tripwire-subject"),
        true,
    )
    .await;
    let trusted_device_tripwire_device_id = trusted_device_tripwire_state
        .trusted_device_credential_id
        .clone()
        .expect("trusted-device-tripwire trusted device id");
    let original_device_cookie_pair = trusted_device_tripwire_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("trusted-device-tripwire trusted-device cookie");

    let revived_from_device = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[original_device_cookie_pair]),
            ResolveRequestInput {
                now: at(220),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("silently revive from trusted-device before device tripwire replay");
    assert!(matches!(
        revived_from_device.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            ..
        })
    ));
    assert_eq!(
        count_trusted_device_secret_macs_for_device(
            pool,
            store_config,
            &trusted_device_tripwire_device_id
        )
        .await,
        2,
        "trusted-device rotation must leave one current and one previous secret MAC"
    );
    let session_count_before_device_tripwire = count_all_sessions(pool, store_config).await;

    let replayed_old_device = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[original_device_cookie_pair]),
            ResolveRequestInput {
                now: at(226),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("replay old trusted-device cookie after grace through Postgres runtime");
    assert_eq!(
        replayed_old_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            replayed_old_device.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "trusted-device tripwire must delete the presented trusted-device cookie"
    );
    assert_eq!(
        fetch_trusted_device_revoked_at(pool, store_config, &trusted_device_tripwire_device_id)
            .await,
        Some(226)
    );
    assert_eq!(
        count_all_sessions(pool, store_config).await,
        session_count_before_device_tripwire,
        "trusted-device tripwire must not create a replacement session"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_step_up_completion() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("step-up-postgres-subject");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "step-up-postgres",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let session_headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let sensitive_before_step_up = runtime
        .execute_request_resolution_from_headers(
            &session_headers,
            ResolveRequestInput {
                now: at(80),
                request_kind: RequestKind::Sensitive,
            },
        )
        .await
        .expect("sensitive request should resolve through Postgres runtime");
    assert_eq!(
        sensitive_before_step_up.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id.clone(),
            subject_id: subject_id.clone(),
        }
    );

    let started_step_up = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &session_headers,
            StartCurrentSessionActiveProofAttemptInput {
                now: at(85),
                proof_use: ProofUse::SatisfyStepUp,
            },
        )
        .await
        .expect("start step-up active proof attempt through Postgres runtime");
    let step_up_attempt_id = match started_step_up.outcome() {
        Outcome::ActiveProofAttemptStarted { attempt_id, .. } => attempt_id.clone(),
        outcome => panic!("expected active proof attempt start, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started_step_up.set_cookie_headers())
            .to_owned();
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let issued_challenge = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(90),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("step-up method declaration"),
                challenge_dedupe_key: dedupe_key("step-up-postgres:email-hash:window"),
                recipient_handle: "step-up-postgres-opaque-email-handle".to_owned(),
                idempotency_key: "step-up-postgres-mail-idempotency-key".to_owned(),
            },
        )
        .await
        .expect("issue step-up challenge through Postgres runtime");
    let step_up_challenge_id = match issued_challenge.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => {
            assert_eq!(attempt_id, &step_up_attempt_id);
            challenge_id.clone()
        }
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
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
        "subject-bound out-of-band challenge issue must stay inside one bounded loaded-state commit",
    );
    let step_up_response_secret = email_otp
        .fetch_response_secret_for_test(pool, &step_up_challenge_id)
        .await
        .expect("fetch generated step-up email otp response secret");
    let step_up_challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued_challenge.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let step_up_challenge_headers = headers_from_cookie_pairs(&[step_up_challenge_cookie_pair]);
    harness.database_operation_observer.clear();
    let completed_step_up_proof = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &step_up_challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(95),
                secret_response: step_up_response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete step-up challenge through Postgres runtime");
    assert_eq!(
        completed_step_up_proof.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: step_up_attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );
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
        "subject-bound out-of-band challenge completion must stay inside one bounded loaded-state commit",
    );

    let step_up_headers = headers_from_cookie_pairs(&[
        issued_auth.session_cookie_pair.as_str(),
        continuation_cookie_pair.as_str(),
    ]);
    harness.database_operation_observer.clear();
    let step_up = runtime
        .execute_step_up_completion_from_headers(
            &step_up_headers,
            CompleteStepUpInput { now: at(100) },
        )
        .await
        .expect("complete step-up through Postgres runtime");
    assert_eq!(
        step_up.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: subject_id.clone(),
            session_id: issued_auth.session_id.clone(),
            source: AuthenticationSource::StepUp,
            step_up_is_fresh: true,
        })
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.active_proof_attempt",
            "auth_core.load.active_proof_satisfied_proofs",
            "auth_core.load.active_proof_continuation_secret_mac",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.session_still_matches",
            "auth_core.precondition.fetch_subject_cutoff",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.secret.insert_session_mac",
            "auth_core.mutation.delete_active_proof_delivery_keys",
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            "auth_core.mutation.delete_active_proof_challenges",
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            "auth_core.mutation.delete_active_proof_attempt",
            "auth_core.mutation.record_step_up",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "db.tx.commit",
        ],
        "step-up completion must stay inside one bounded loaded-state commit",
    );
    assert!(
        step_up
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")),
        "step-up must rotate and reissue the session cookie"
    );
    assert!(
        set_cookie_headers_contain_prefix(step_up.set_cookie_headers(), "__Host-csrf_token="),
        "step-up must cycle CSRF with the refreshed session freshness"
    );
    assert!(
        set_cookie_headers_contain_deletion(
            step_up.set_cookie_headers(),
            "__Host-__paranoid_auth_active_proof_continuation="
        ),
        "step-up must clear the active-proof continuation cookie"
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &issued_auth.session_id).await,
        2,
        "step-up must store the newly rotated session secret MAC"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &step_up_attempt_id).await,
        0,
        "step-up must close and delete the active-proof attempt"
    );

    let stepped_up_session_cookie_pair = cookie_pair_from_set_cookie(
        step_up.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    );
    let sensitive_after_step_up = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[stepped_up_session_cookie_pair]),
            ResolveRequestInput {
                now: at(105),
                request_kind: RequestKind::Sensitive,
            },
        )
        .await
        .expect("resolve sensitive request after step-up through Postgres runtime");
    assert_eq!(
        sensitive_after_step_up.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id,
            session_id: issued_auth.session_id,
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
        })
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_executes_revocation_paths() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let logout_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "logout",
        20,
        id("subject"),
        false,
    )
    .await;
    let logout_headers = headers_from_cookie_pairs(&[logout_state.session_cookie_pair.as_str()]);
    let logout = runtime
        .execute_from_headers(
            &logout_headers,
            Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
        )
        .await
        .expect("logout current session through Postgres runtime");
    assert_eq!(
        logout.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::CurrentSession,
        })
    );
    assert!(
        set_cookie_headers_contain_deletion(
            logout.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "logout must delete the current session cookie"
    );
    assert!(
        set_cookie_headers_contain_prefix(logout.set_cookie_headers(), "__Host-csrf_token="),
        "logout must cycle CSRF back to anonymous binding"
    );
    let stale_logged_out_session = runtime
        .execute_request_resolution_from_headers(
            &logout_headers,
            ResolveRequestInput {
                now: at(55),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve logged-out session through Postgres runtime");
    assert_eq!(
        stale_logged_out_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            stale_logged_out_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "stale logged-out session cookie must be cleared"
    );
    assert!(
        set_cookie_headers_contain_prefix(
            stale_logged_out_session.set_cookie_headers(),
            "__Host-csrf_token="
        ),
        "stale logged-out session cookie clearing must cycle CSRF back to anonymous binding"
    );

    let targeted_session_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "targeted-session",
        60,
        id("subject"),
        false,
    )
    .await;
    let targeted_session_revocation = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSession(RevokeSession {
                now: at(90),
                subject_id: id("subject"),
                session_id: targeted_session_state.session_id.clone(),
                reason: RevocationReason::RemoteRevocation,
            }),
        )
        .await
        .expect("targeted session revocation through Postgres runtime");
    assert_eq!(
        targeted_session_revocation.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::Session(targeted_session_state.session_id.clone()),
        })
    );
    let targeted_session_headers =
        headers_from_cookie_pairs(&[targeted_session_state.session_cookie_pair.as_str()]);
    let stale_targeted_session = runtime
        .execute_request_resolution_from_headers(
            &targeted_session_headers,
            ResolveRequestInput {
                now: at(95),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve targeted-revoked session through Postgres runtime");
    assert_eq!(
        stale_targeted_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            stale_targeted_session.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "targeted-revoked session cookie must be cleared on reuse"
    );
    assert!(
        set_cookie_headers_contain_prefix(
            stale_targeted_session.set_cookie_headers(),
            "__Host-csrf_token="
        ),
        "targeted-revoked session cookie clearing must cycle CSRF back to anonymous binding"
    );

    let targeted_device_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "targeted-device",
        100,
        id("subject"),
        true,
    )
    .await;
    let targeted_device_cookie_pair = targeted_device_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("trusted-device cookie");
    let targeted_device_headers = headers_from_cookie_pairs(&[targeted_device_cookie_pair]);
    let targeted_device_revocation = runtime
        .execute_from_headers(
            &targeted_device_headers,
            Command::RevokeTrustedDevice(RevokeTrustedDevice {
                now: at(130),
                subject_id: id("subject"),
                device_credential_id: targeted_device_state
                    .trusted_device_credential_id
                    .clone()
                    .expect("targeted device id"),
                reason: RevocationReason::RemoteRevocation,
            }),
        )
        .await
        .expect("targeted trusted-device revocation through Postgres runtime");
    assert_eq!(
        targeted_device_revocation.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::TrustedDevice(
                targeted_device_state
                    .trusted_device_credential_id
                    .clone()
                    .expect("targeted device id"),
            ),
        })
    );
    assert!(
        set_cookie_headers_contain_deletion(
            targeted_device_revocation.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "targeted trusted-device revocation must delete the presented device cookie"
    );
    let stale_targeted_device = runtime
        .execute_request_resolution_from_headers(
            &targeted_device_headers,
            ResolveRequestInput {
                now: at(135),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve targeted-revoked trusted device through Postgres runtime");
    assert_eq!(
        stale_targeted_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    assert!(
        set_cookie_headers_contain_deletion(
            stale_targeted_device.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "targeted-revoked trusted-device cookie must be cleared on reuse"
    );

    let subject_wide_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "subject-wide",
        140,
        id("subject"),
        true,
    )
    .await;
    let subject_wide_device_cookie_pair = subject_wide_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("subject-wide trusted-device cookie");
    let subject_wide_headers = headers_from_cookie_pairs(&[
        subject_wide_state.session_cookie_pair.as_str(),
        subject_wide_device_cookie_pair,
    ]);
    let subject_wide_revocation = runtime
        .execute_from_headers(
            &subject_wide_headers,
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(170),
                subject_id: id("subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("subject-wide revocation through Postgres runtime");
    assert_eq!(
        subject_wide_revocation.outcome(),
        &Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::SubjectAuthState(id("subject")),
        })
    );
    assert!(
        set_cookie_headers_contain_deletion(
            subject_wide_revocation.set_cookie_headers(),
            "__Host-__paranoid_auth_session="
        ),
        "subject-wide revocation must delete the presented session cookie"
    );
    assert!(
        set_cookie_headers_contain_deletion(
            subject_wide_revocation.set_cookie_headers(),
            "__Host-__paranoid_auth_trusted_device="
        ),
        "subject-wide revocation must delete the presented trusted-device cookie"
    );
    assert!(
        set_cookie_headers_contain_prefix(
            subject_wide_revocation.set_cookie_headers(),
            "__Host-csrf_token="
        ),
        "subject-wide revocation must cycle CSRF back to anonymous binding"
    );
    let stale_subject_wide_session_headers =
        headers_from_cookie_pairs(&[subject_wide_state.session_cookie_pair.as_str()]);
    let stale_subject_wide_session = runtime
        .execute_request_resolution_from_headers(
            &stale_subject_wide_session_headers,
            ResolveRequestInput {
                now: at(175),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve subject-wide-revoked session through Postgres runtime");
    assert_eq!(
        stale_subject_wide_session.outcome(),
        &Outcome::NeedsFullAuthentication
    );
    let stale_subject_wide_device_headers =
        headers_from_cookie_pairs(&[subject_wide_device_cookie_pair]);
    let stale_subject_wide_device = runtime
        .execute_request_resolution_from_headers(
            &stale_subject_wide_device_headers,
            ResolveRequestInput {
                now: at(175),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve subject-wide-revoked trusted device through Postgres runtime");
    assert_eq!(
        stale_subject_wide_device.outcome(),
        &Outcome::NeedsFullAuthentication
    );

    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &logout_state.session_id).await,
        Some(50)
    );
    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &targeted_session_state.session_id).await,
        Some(90)
    );
    assert_eq!(
        fetch_trusted_device_revoked_at(
            pool,
            store_config,
            &targeted_device_state
                .trusted_device_credential_id
                .clone()
                .expect("targeted device id"),
        )
        .await,
        Some(130)
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &id("subject")).await,
        Some(170)
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_stale_loaded_state_commits_after_revocation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let store = postgres_runtime_test_store(store_config);

    let logout_race_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "logout-race",
        20,
        id("subject"),
        false,
    )
    .await;
    let logout_race_headers =
        headers_from_cookie_pairs(&[logout_race_state.session_cookie_pair.as_str()]);
    let mut stale_logout_refresh_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale logout-refresh transaction");
    let stale_logout_refresh_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_logout_refresh_tx,
        &store,
        &logout_race_headers,
        Command::ResolveRequest(ResolveRequest {
            now: at(130),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
    )
    .await;
    assert_eq!(
        stale_logout_refresh_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("subject"),
            session_id: logout_race_state.session_id.clone(),
            source: AuthenticationSource::RefreshedSession,
            step_up_is_fresh: false,
        })
    );
    runtime
        .execute_from_headers(
            &logout_race_headers,
            Command::LogoutCurrentSession(LogoutCurrentSession { now: at(131) }),
        )
        .await
        .expect("commit logout racing stale session refresh");
    let logout_refresh_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_logout_refresh_tx,
            &store,
            &stale_logout_refresh_plan,
        )
        .await;
    assert_precondition_failed(
        &logout_refresh_error,
        "session no longer matches loaded state",
    );
    stale_logout_refresh_tx
        .rollback()
        .await
        .expect("roll back failed stale logout-refresh transaction");
    assert_eq!(
        fetch_session_revoked_at(pool, store_config, &logout_race_state.session_id).await,
        Some(131)
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &logout_race_state.session_id)
            .await,
        1,
        "failed stale refresh must not insert a replacement session secret MAC"
    );

    let subject_race_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "subject-race",
        140,
        id("subject"),
        false,
    )
    .await;
    let subject_race_headers =
        headers_from_cookie_pairs(&[subject_race_state.session_cookie_pair.as_str()]);
    let mut stale_subject_refresh_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale subject-refresh transaction");
    let stale_subject_refresh_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_subject_refresh_tx,
        &store,
        &subject_race_headers,
        Command::ResolveRequest(ResolveRequest {
            now: at(250),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
    )
    .await;
    assert_eq!(
        stale_subject_refresh_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("subject"),
            session_id: subject_race_state.session_id.clone(),
            source: AuthenticationSource::RefreshedSession,
            step_up_is_fresh: false,
        })
    );
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(251),
                subject_id: id("subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject-wide revocation racing stale session refresh");
    let subject_refresh_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_subject_refresh_tx,
            &store,
            &stale_subject_refresh_plan,
        )
        .await;
    assert_precondition_failed(
        &subject_refresh_error,
        "subject auth state invalidates target",
    );
    stale_subject_refresh_tx
        .rollback()
        .await
        .expect("roll back failed stale subject-refresh transaction");
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &id("subject")).await,
        Some(251)
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &subject_race_state.session_id)
            .await,
        1,
        "failed stale subject-revoked refresh must not insert a replacement session secret MAC"
    );

    let device_race_state = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "device-race",
        300,
        id("device-race-subject"),
        true,
    )
    .await;
    let device_race_cookie_pair = device_race_state
        .trusted_device_cookie_pair
        .as_deref()
        .expect("device-race trusted-device cookie");
    let device_race_headers = headers_from_cookie_pairs(&[device_race_cookie_pair]);
    let mut stale_device_rotation_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale device-rotation transaction");
    let stale_device_rotation_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_device_rotation_tx,
        &store,
        &device_race_headers,
        Command::ResolveRequest(ResolveRequest {
            now: at(360),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("device-race-stale-revival-session")),
        }),
    )
    .await;
    assert_eq!(
        stale_device_rotation_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("device-race-subject"),
            session_id: id("device-race-stale-revival-session"),
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            step_up_is_fresh: false,
        })
    );
    runtime
        .execute_from_headers(
            &device_race_headers,
            Command::RevokeTrustedDevice(RevokeTrustedDevice {
                now: at(361),
                subject_id: id("device-race-subject"),
                device_credential_id: device_race_state
                    .trusted_device_credential_id
                    .clone()
                    .expect("device-race device id"),
                reason: RevocationReason::RemoteRevocation,
            }),
        )
        .await
        .expect("commit trusted-device revocation racing stale device rotation");
    let device_rotation_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_device_rotation_tx,
            &store,
            &stale_device_rotation_plan,
        )
        .await;
    assert_precondition_failed(
        &device_rotation_error,
        "trusted device no longer matches loaded state",
    );
    stale_device_rotation_tx
        .rollback()
        .await
        .expect("roll back failed stale device-rotation transaction");
    assert_eq!(
        fetch_trusted_device_revoked_at(
            pool,
            store_config,
            &device_race_state
                .trusted_device_credential_id
                .clone()
                .expect("device-race device id"),
        )
        .await,
        Some(361)
    );
    assert_eq!(
        fetch_trusted_device_current_secret_version(
            pool,
            store_config,
            &device_race_state
                .trusted_device_credential_id
                .clone()
                .expect("device-race device id"),
        )
        .await,
        1,
        "failed stale device rotation must not advance the credential version"
    );
    assert_eq!(
        count_trusted_device_secret_macs_for_device(
            pool,
            store_config,
            &device_race_state
                .trusted_device_credential_id
                .clone()
                .expect("device-race device id"),
        )
        .await,
        1,
        "failed stale device rotation must not insert a replacement trusted-device secret MAC"
    );
    assert_eq!(
        count_sessions_for_session(pool, store_config, &id("device-race-stale-revival-session"))
            .await,
        0,
        "failed stale device rotation must not create its replacement session"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_stale_active_proof_commits() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let store = postgres_runtime_test_store(store_config);

    let challenge_completion_race = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "challenge-completion-race",
        20,
        id("challenge-completion-race-subject"),
    )
    .await;
    let challenge_completion_headers =
        headers_from_cookie_pairs(&[challenge_completion_race.challenge_cookie_pair.as_str()]);
    let mut stale_challenge_completion_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale challenge-completion transaction");
    let stale_challenge_completion_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_challenge_completion_tx,
        &store,
        &challenge_completion_headers,
        complete_out_of_band_challenge_command(
            &challenge_completion_race,
            at(40),
            id("challenge-completion-race-subject"),
        ),
    )
    .await;
    assert!(matches!(
        stale_challenge_completion_plan.planned.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(41),
                subject_id: id("challenge-completion-race-subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject revocation racing challenge completion");
    let challenge_completion_error =
        commit_planned_work_in_current_transaction_expect_precondition_error(
            &mut stale_challenge_completion_tx,
            &store,
            &stale_challenge_completion_plan,
        )
        .await;
    assert_precondition_failed(
        &challenge_completion_error,
        "subject auth state invalidates target",
    );
    stale_challenge_completion_tx
        .rollback()
        .await
        .expect("roll back failed stale challenge-completion transaction");
    assert_eq!(
        count_satisfied_proofs_for_attempt(
            pool,
            store_config,
            &challenge_completion_race.attempt_id
        )
        .await,
        0,
        "failed stale challenge completion must not record a proof"
    );
    assert_eq!(
        count_open_challenges_for_challenge(
            pool,
            store_config,
            &challenge_completion_race.challenge_id
        )
        .await,
        1,
        "failed stale challenge completion must not close the challenge"
    );

    let resend_race_subject: SubjectId = id("resend-race-subject");
    let resend_race_session = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "resend-race-bootstrap",
        60,
        resend_race_subject.clone(),
        false,
    )
    .await;
    let resend_race = start_current_session_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "resend-race",
        90,
        resend_race_subject.clone(),
        resend_race_session.session_cookie_pair.as_str(),
    )
    .await;
    let mut stale_resend_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale resend transaction");
    let stale_resend_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_resend_tx,
        &store,
        &HeaderMap::new(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(110),
            attempt_id: resend_race.attempt_id.clone(),
            challenge_id: resend_race.challenge_id.clone(),
            idempotency_key: "resend-race-mail-idempotency-key-2".to_owned(),
            method_commit_work: Vec::new(),
        }),
    )
    .await;
    assert_eq!(
        stale_resend_plan.planned.outcome(),
        &Outcome::OutOfBandChallengeResent {
            attempt_id: resend_race.attempt_id.clone(),
            challenge_id: resend_race.challenge_id.clone(),
            resend_count: 1,
            expires_at: at(140),
        }
    );
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(111),
                subject_id: resend_race_subject,
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject revocation racing challenge resend");
    let resend_error = commit_planned_work_in_current_transaction_expect_precondition_error(
        &mut stale_resend_tx,
        &store,
        &stale_resend_plan,
    )
    .await;
    assert_precondition_failed(&resend_error, "subject auth state invalidates target");
    stale_resend_tx
        .rollback()
        .await
        .expect("roll back failed stale resend transaction");
    assert_eq!(
        fetch_out_of_band_challenge_resend_count(pool, store_config, &resend_race.challenge_id)
            .await,
        0,
        "failed stale resend must not advance resend count"
    );
    assert_eq!(
        count_challenge_delivery_keys(pool, store_config, &resend_race.challenge_id).await,
        1,
        "failed stale resend must not record a new delivery key"
    );

    let full_auth_race = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "full-auth-race",
        100,
        id("full-auth-race-subject"),
    )
    .await;
    complete_out_of_band_challenge_response_through_runtime(runtime, &full_auth_race, at(120))
        .await;
    let mut stale_full_auth_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale full-authentication transaction");
    let stale_full_auth_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_full_auth_tx,
        &store,
        &HeaderMap::new(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(125),
            attempt_id: full_auth_race.attempt_id.clone(),
            fresh_session_id: id("full-auth-race-session"),
            trust_device: None,
        }),
    )
    .await;
    assert_eq!(
        stale_full_auth_plan.planned.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id: id("full-auth-race-subject"),
            session_id: id("full-auth-race-session"),
            source: AuthenticationSource::FullAuthentication,
            step_up_is_fresh: true,
        })
    );
    runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(126),
                subject_id: id("full-auth-race-subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject revocation racing full authentication");
    let full_auth_error = commit_planned_work_in_current_transaction_expect_precondition_error(
        &mut stale_full_auth_tx,
        &store,
        &stale_full_auth_plan,
    )
    .await;
    assert_precondition_failed(&full_auth_error, "subject auth state invalidates target");
    stale_full_auth_tx
        .rollback()
        .await
        .expect("roll back failed stale full-authentication transaction");
    assert_eq!(
        count_sessions_for_session(pool, store_config, &id("full-auth-race-session")).await,
        0,
        "failed stale full authentication must not create a session"
    );
    assert_eq!(
        count_session_secret_macs_for_session(pool, store_config, &id("full-auth-race-session"))
            .await,
        0,
        "failed stale full authentication must not insert a session secret MAC"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &full_auth_race.attempt_id)
            .await,
        1,
        "failed stale full authentication must not delete the attempt"
    );

    let replay_race = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "replay-race",
        140,
        id("replay-race-subject"),
    )
    .await;
    let replay_headers = headers_from_cookie_pairs(&[replay_race.challenge_cookie_pair.as_str()]);
    let mut stale_replay_tx = pool
        .begin_transaction()
        .await
        .expect("begin stale replay transaction");
    let stale_replay_plan = plan_loaded_state_command_in_current_transaction(
        &mut stale_replay_tx,
        &store,
        &replay_headers,
        complete_out_of_band_challenge_command(&replay_race, at(160), id("replay-race-subject")),
    )
    .await;
    assert!(matches!(
        stale_replay_plan.planned.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    complete_out_of_band_challenge_response_through_runtime(runtime, &replay_race, at(161)).await;
    let replay_error = commit_planned_work_in_current_transaction_expect_precondition_error(
        &mut stale_replay_tx,
        &store,
        &stale_replay_plan,
    )
    .await;
    assert_precondition_failed(&replay_error, "active proof challenge is no longer open");
    stale_replay_tx
        .rollback()
        .await
        .expect("roll back failed stale replay transaction");
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &replay_race.attempt_id).await,
        1,
        "stale replay must not duplicate the satisfied proof"
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &replay_race.challenge_id).await,
        0,
        "successful first completion must be the only challenge closure"
    );

    harness.drop_schema().await;
}
