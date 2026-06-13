use super::*;

#[tokio::test]
async fn postgres_runtime_authenticated_addition_creates_usable_totp_verifier() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = totp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-add-subject");
    let totp_secret = b"totp-add-secret-material";
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-add-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("totp-add-session-authority");
    let totp_authority = id("totp-add-authority");
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
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let addition = runtime
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialAdditionInput {
                now: at(70),
                method: plugin.method().clone(),
                reset_policy_role: CredentialResetPolicyRole::OrdinaryCredential,
                recovery_authority_rules: vec![
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Create,
                        authority_id: session_authority,
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Reset,
                        authority_id: totp_authority.clone(),
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                ],
                new_credential_authority_ids: vec![totp_authority],
                method_payload: PostgresTotpMethodPlugin::<TestTotpCodeVerifier>::verifier_creation_payload_for_test(
                    totp_secret,
                )
                .expect("TOTP verifier creation payload"),
            },
        )
        .await
        .expect("execute TOTP credential addition");
    let added_credential_id = match addition.outcome() {
        Outcome::CredentialAdded(outcome) => {
            assert_eq!(&outcome.subject_id, &subject_id);
            outcome.credential_instance_id.clone()
        }
        outcome => panic!("expected TOTP credential addition, got {outcome:?}"),
    };
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count TOTP verifiers"),
        1,
        "TOTP addition must create exactly one verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch TOTP verifier version"),
        Some(1),
        "new TOTP verifier starts at version 1"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &added_credential_id).await,
        CredentialLifecycleState::Active,
        "TOTP addition must create active core credential metadata"
    );

    let attempt_id = complete_totp_step_up_proof_for_runtime_test(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        plugin,
        subject_id,
        "totp-add-after-add",
        90,
        at(100),
        at(110),
        totp_secret,
    )
    .await;
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            added_credential_id,
        )),
        "proof from added TOTP verifier must source from the runtime-generated credential"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_reset_replaces_real_totp_verifier() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = totp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-reset-subject");
    let target_credential_id = id("totp-reset-target");
    let session_authority = id("totp-reset-session-authority");
    let old_secret = b"totp-reset-old-secret-material";
    let new_secret = b"totp-reset-new-secret-material";

    plugin
        .store_secret_for_test(pool, &subject_id, &target_credential_id, old_secret, at(10))
        .await
        .expect("store old TOTP verifier");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-reset-bootstrap",
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
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::SharedSecretOtpVerifier,
                plugin.method().method_label(),
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("TOTP credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_reset_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: PostgresTotpMethodPlugin::<TestTotpCodeVerifier>::verifier_reset_payload_for_test(
                    new_secret,
                )
                .expect("TOTP verifier reset payload"),
            },
        )
        .await
        .expect("execute authenticated TOTP reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: None,
        })
    );
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count TOTP verifiers"),
        1,
        "TOTP reset must replace the existing verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch TOTP verifier version"),
        Some(2),
        "TOTP reset of the same credential must advance verifier version"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "TOTP reset must preserve the target credential metadata state"
    );
    assert_eq!(
        fetch_credential_recovery_authorities_for_runtime_test(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        vec![CredentialRecoveryAuthority::new(
            target_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            session_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        "TOTP reset must preserve the target recovery-authority graph"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "TOTP reset execution must revoke existing subject auth state"
    );

    let attempt_id = complete_totp_step_up_proof_for_runtime_test(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        plugin,
        subject_id,
        "totp-reset-after-reset",
        90,
        at(100),
        at(110),
        new_secret,
    )
    .await;
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            target_credential_id,
        )),
        "proof from reset TOTP verifier must still source from the target credential"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_replacement_replaces_real_totp_verifier() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = totp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-replace-subject");
    let target_credential_id = id("totp-replace-target");
    let session_authority = id("totp-replace-session-authority");
    let old_secret = b"totp-replace-old-secret-material";
    let new_secret = b"totp-replace-new-secret-material";

    plugin
        .store_secret_for_test(pool, &subject_id, &target_credential_id, old_secret, at(10))
        .await
        .expect("store old TOTP verifier");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-replace-bootstrap",
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
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::SharedSecretOtpVerifier,
                plugin.method().method_label(),
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("TOTP credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[
                LifecycleAuthorityEvidence::authenticated_session(
                    issued_auth.session_id.clone(),
                    [session_authority],
                )
                .expect("session lifecycle evidence"),
                credential_instance_lifecycle_evidence(
                    "totp-replace-target",
                    [id("totp-replace-target-authority")],
                ),
            ],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_replacement_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: PostgresTotpMethodPlugin::<TestTotpCodeVerifier>::verifier_lifecycle_payload_for_test(
                    new_secret,
                )
                .expect("TOTP verifier replacement payload"),
            },
        )
        .await
        .expect("execute authenticated TOTP replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count TOTP verifiers"),
        1,
        "TOTP replacement must leave exactly one verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch TOTP verifier version"),
        Some(1),
        "TOTP replacement successor starts verifier version at 1"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Superseded,
        "TOTP replacement must supersede the old target credential"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "TOTP replacement execution must revoke existing subject auth state"
    );

    let attempt_id = complete_totp_step_up_proof_for_runtime_test(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        plugin,
        subject_id,
        "totp-replace-after-replace",
        90,
        at(100),
        at(110),
        new_secret,
    )
    .await;
    let proof_source = fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id)
        .await
        .expect("TOTP replacement proof source");
    assert_eq!(
        proof_source.kind(),
        VerifiedProofSourceKind::CredentialInstance
    );
    assert_ne!(
        proof_source.source_id(),
        &target_credential_id,
        "replacement proof must come from the runtime-generated successor credential"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, proof_source.source_id())
            .await,
        CredentialLifecycleState::Active,
        "TOTP replacement proof source must be the active successor credential"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_rotation_rotates_real_totp_verifier() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = totp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-rotate-subject");
    let target_credential_id = id("totp-rotate-target");
    let session_authority = id("totp-rotate-session-authority");
    let old_secret = b"totp-rotate-old-secret-material";
    let new_secret = b"totp-rotate-new-secret-material";

    plugin
        .store_secret_for_test(pool, &subject_id, &target_credential_id, old_secret, at(10))
        .await
        .expect("store old TOTP verifier");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "totp-rotate-bootstrap",
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
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::SharedSecretOtpVerifier,
                plugin.method().method_label(),
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("TOTP credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Rotate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_rotation_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRotationInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: PostgresTotpMethodPlugin::<TestTotpCodeVerifier>::verifier_lifecycle_payload_for_test(
                    new_secret,
                )
                .expect("TOTP verifier rotation payload"),
            },
        )
        .await
        .expect("execute authenticated TOTP rotation");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRotated(CredentialRotationExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count TOTP verifiers"),
        1,
        "TOTP rotation must leave exactly one verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch TOTP verifier version"),
        Some(2),
        "TOTP rotation must increment verifier version for the same credential"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "TOTP rotation must preserve the target credential metadata"
    );
    assert_eq!(
        fetch_credential_recovery_authorities_for_runtime_test(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        vec![CredentialRecoveryAuthority::new(
            target_credential_id.clone(),
            CredentialLifecycleAction::Rotate,
            session_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        "TOTP rotation must preserve the target recovery-authority graph"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "TOTP rotation execution must revoke existing subject auth state"
    );

    let attempt_id = complete_totp_step_up_proof_for_runtime_test(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        plugin,
        subject_id,
        "totp-rotate-after-rotate",
        90,
        at(100),
        at(110),
        new_secret,
    )
    .await;
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            target_credential_id,
        )),
        "proof from rotated TOTP verifier must still source from the target credential"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authoritative_active_method_loads_resolved_subject_revocation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let method = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("message signature method");
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_authoritative_test_method(
            method.clone(),
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("authoritative-revoked-subject");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue authoritative message signature challenge through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), challenge_id.clone(), method_challenge),
        outcome => panic!("expected message signature challenge issue, got {outcome:?}"),
    };
    let message_signature_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::MessageSignature);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    runtime
        .execute_from_headers(
            &empty_headers,
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(25),
                subject_id: subject_id.clone(),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
        )
        .await
        .expect("commit subject-wide revocation before authoritative method completion");
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);

    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("resolved subject revocation must reject active method completion");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofAttemptNotOpen
        )
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_active_method_cookie_without_sealed_method_state() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_message_signature_method().await;
    let runtime = &harness.runtime;
    let nonce = ActiveProofChallengeFastFailNonce::from_bytes(
        &[77_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
    )
    .expect("nonce");
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_without_response_mac(
        ActiveProofChallengeCookieContext::new(
            id("missing-method-state-attempt"),
            id("missing-method-state-challenge"),
            ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            at(20),
            at(60),
            nonce.clone(),
        )
        .expect("challenge cookie context"),
    )
    .expect("challenge cookie without method state");
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie),
    ]);
    let set_cookie_headers = auth_web_transport()
        .render_set_cookie_headers(at(20), effects)
        .expect("set cookie headers");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        &set_cookie_headers,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    nonce.as_bytes(),
                    &id("missing-method-state-subject"),
                ),
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("active method cookie without sealed state must be rejected");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofMethodChallengeState
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "active method cookie without sealed method state must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_expired_active_method_cookie_before_plugin_dispatch() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_message_signature_method().await;
    let runtime = &harness.runtime;
    let nonce = ActiveProofChallengeFastFailNonce::from_bytes(
        &[78_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
    )
    .expect("nonce");
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_with_method_challenge_state(
        ActiveProofChallengeCookieContext::new(
            id("expired-active-method-attempt"),
            id("expired-active-method-challenge"),
            ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            at(20),
            at(30),
            nonce,
        )
        .expect("challenge cookie context"),
        ActiveProofMethodChallengeState::try_from_bytes(b"expired-active-method-state".as_slice())
            .expect("method challenge state"),
    )
    .expect("expired active-method challenge cookie");
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie),
    ]);
    let set_cookie_headers = auth_web_transport()
        .render_set_cookie_headers(at(20), effects)
        .expect("set cookie headers");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        &set_cookie_headers,
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair]);

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(31),
                response_payload: ActiveProofMethodResponsePayload::try_from_bytes(
                    b"malformed-response".as_slice(),
                )
                .expect("method response payload"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("expired active-method cookie must be rejected before plugin dispatch");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieExpired
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired active method cookie must reject before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_origin_bound_public_key_through_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_origin_bound_public_key_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("origin-bound-public-key-subject");
    let method = ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
        .expect("origin-bound public-key method");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue origin-bound public-key challenge through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id: issued_challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
                    .expect("proof"),
            );
            (
                issued_attempt_id.clone(),
                issued_challenge_id.clone(),
                method_challenge,
            )
        }
        outcome => panic!("expected origin-bound public-key challenge issue, got {outcome:?}"),
    };
    assert!(
        method_challenge.as_bytes().starts_with(
            test_challenge_presentation_prefix(ProofFamily::OriginBoundPublicKey)
                .expect("origin-bound public-key challenge prefix")
        )
    );
    let origin_bound_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::OriginBoundPublicKey);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let mismatched_nonce_error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: mismatched_runtime_challenge_test_method_response_payload(
                    ProofFamily::OriginBoundPublicKey,
                    origin_bound_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("origin-bound public-key assertion must bind the runtime nonce");
    assert!(matches!(
        mismatched_nonce_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
    ));
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(35),
                response_payload: test_method_response_payload(
                    ProofFamily::OriginBoundPublicKey,
                    origin_bound_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete origin-bound public-key proof through method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
                .expect("proof"),
        }
    );
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::OriginBoundPublicKey,
            test_active_method_source_id(ProofFamily::OriginBoundPublicKey, &subject_id),
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_federated_identity_through_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_federated_identity_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("federated-identity-subject");
    let method =
        ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
            .expect("federated identity method");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue federated identity state through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id: issued_challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
                    .expect("proof"),
            );
            (
                issued_attempt_id.clone(),
                issued_challenge_id.clone(),
                method_challenge,
            )
        }
        outcome => panic!("expected federated identity state issue, got {outcome:?}"),
    };
    assert!(
        method_challenge.as_bytes().starts_with(
            test_challenge_presentation_prefix(ProofFamily::FederatedIdentityAssertion)
                .expect("federated identity state prefix")
        )
    );
    let federated_state = test_method_runtime_challenge_bytes(
        method_challenge,
        ProofFamily::FederatedIdentityAssertion,
    );
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let mismatched_issuer_error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: mismatched_federated_issuer_test_method_response_payload(
                    federated_state,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("federated identity assertion must bind issuer, audience, redirect, and state");
    assert!(matches!(
        mismatched_issuer_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(_)
    ));
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(35),
                response_payload: test_method_response_payload(
                    ProofFamily::FederatedIdentityAssertion,
                    federated_state,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete federated identity proof through method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
                .expect("proof"),
        }
    );
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::FederatedIdentityAssertion,
            test_active_method_source_id(ProofFamily::FederatedIdentityAssertion, &subject_id),
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_totp_through_known_subject_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-known-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-known-credential");
    let totp_secret = b"totp-known-subject-secret";
    let method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-known-bootstrap",
        20,
        subject_id.clone(),
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
    let attempt_id = started.attempt_id.clone();
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let failed_secret_response = mismatched_totp_test_method_response_payload();
    let failed_weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_known_subject_completion(
            &continuation_headers,
            &method,
            &failed_secret_response,
            at(30),
        );
    let failed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(30),
                method: method.clone(),
                secret_response: failed_secret_response,
                weak_proof_gate_response: Some(failed_weak_proof_gate_response),
            },
        )
        .await
        .expect("failed TOTP proof should be recorded through the weak-proof budget");
    assert_eq!(
        failed.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.totp.verify.fetch_locked_verifier",
        "wrong direct TOTP with a valid weak gate must perform authoritative verifier lookup",
    );
    assert!(failed.set_cookie_headers().is_empty());
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        fetch_active_proof_attempt_weak_failures(pool, store_config, &attempt_id).await,
        Some(1),
    );

    let completed_secret_response = totp_test_method_response_payload(totp_secret, at(85));
    let completed_weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_known_subject_completion(
            &continuation_headers,
            &method,
            &completed_secret_response,
            at(85),
        );
    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(85),
                method,
                secret_response: completed_secret_response,
                weak_proof_gate_response: Some(completed_weak_proof_gate_response),
            },
        )
        .await
        .expect("complete TOTP through known-subject method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::SharedSecretOtp, "totp").expect("proof"),
        }
    );
    assert!(completed.set_cookie_headers().is_empty());
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            totp_credential_id,
        ))
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_rejects_definite_miss_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-definite-miss-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-definite-miss-credential");
    let totp_secret = b"totp-bloom-definite-miss-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-definite-miss-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = mismatched_totp_test_method_response_payload();
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(85),
        );

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("definite Bloom miss must reject before authoritative state load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::SharedSecretOtp,
                operation: "challenge_bound_known_subject_active_proof_completion",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "definite TOTP Bloom miss must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge.challenge_id).await,
        1,
        "definite Bloom miss must leave the authoritative challenge open"
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_invalid_challenge_bound_totp_weak_gate_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-invalid-gate-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-invalid-gate-credential");
    let totp_secret = b"totp-bloom-invalid-gate-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-invalid-gate-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(totp_secret, at(85));

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("invalid challenge-bound TOTP weak gate must reject before state load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid challenge-bound TOTP weak gate must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge.challenge_id).await,
        1,
        "invalid challenge-bound TOTP weak gate must leave the authoritative challenge open",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_possible_hit_completes_authoritatively() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-authoritative-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-authoritative-credential");
    let totp_secret = b"totp-bloom-authoritative-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-authoritative-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    assert!(
        challenge.challenge_cookie_pair.len() < 2048,
        "challenge-bound TOTP Bloom cookie pair should stay comfortably below one 4KiB cookie"
    );
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(totp_secret, at(85));
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(85),
        );

    harness.database_operation_observer.clear();
    let completed = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete challenge-bound TOTP through Bloom lane");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: challenge.attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::SharedSecretOtp, "totp").expect("proof"),
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.totp.verify.fetch_locked_verifier",
        "possible TOTP Bloom hit must perform authoritative verifier lookup",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge.challenge_id).await,
        0
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &challenge.attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            totp_credential_id,
        ))
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_possible_hit_rechecks_verifier_version() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-stale-verifier-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-stale-verifier-credential");
    let old_totp_secret = b"totp-bloom-stale-verifier-old-secret";
    let new_totp_secret = b"totp-bloom-stale-verifier-new-secret";

    totp_plugin
        .store_secret_for_test(
            pool,
            &subject_id,
            &totp_credential_id,
            old_totp_secret,
            at(10),
        )
        .await
        .expect("store old TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-stale-verifier-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(old_totp_secret, at(85));
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(85),
        );

    totp_plugin
        .store_secret_for_test(
            pool,
            &subject_id,
            &totp_credential_id,
            new_totp_secret,
            at(82),
        )
        .await
        .expect("rotate TOTP verifier state");

    harness.database_operation_observer.clear();
    let failed = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(85),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("stale verifier Bloom possible hit should record a proof failure");

    assert_eq!(
        failed.outcome(),
        &Outcome::ActiveProofFailureRecorded {
            attempt_id: challenge.attempt_id.clone(),
            attempt_was_deleted: false,
        }
    );
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.totp.verify.fetch_locked_verifier",
        "stale TOTP Bloom possible hit must perform authoritative verifier/version recheck",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        0
    );
    assert_eq!(
        fetch_active_proof_attempt_weak_failures(pool, store_config, &challenge.attempt_id).await,
        Some(1)
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_challenge_bound_totp_bloom_has_no_false_negative_for_late_window_code() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-bloom-late-window-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-bloom-late-window-credential");
    let totp_secret = b"totp-bloom-late-window-secret";

    totp_plugin
        .store_secret_for_test(pool, &subject_id, &totp_credential_id, totp_secret, at(10))
        .await
        .expect("store TOTP verifier state");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-bloom-late-window-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let challenge = start_current_session_and_issue_challenge_bound_totp_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        at(80),
    )
    .await;
    let completion_headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(totp_secret, at(115));
    let weak_proof_gate_response =
        bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
            &completion_headers,
            &secret_response,
            at(115),
        );

    let completed = runtime
        .execute_challenge_bound_known_subject_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
                now: at(115),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("late-window TOTP code must not be a Bloom false negative");

    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &challenge.attempt_id).await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_deletes_attempt_after_totp_failure_budget() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let totp_plugin = harness.totp_plugin.as_ref().expect("TOTP method plugin");
    let email_otp = email_otp_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("totp-budget-subject");
    let totp_credential_id: VerifiedProofSourceId = id("totp-budget-credential");
    let method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");

    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        "totp-budget-bootstrap",
        20,
        subject_id.clone(),
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
    let attempt_id = started.attempt_id.clone();
    let continuation_cookie_pair = started.continuation_cookie_pair;
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);

    totp_plugin
        .store_secret_for_test(
            pool,
            &subject_id,
            &totp_credential_id,
            b"totp-budget-secret",
            at(10),
        )
        .await
        .expect("store TOTP verifier state");

    let subject_revocation_cutoff_before_failures =
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await;
    let security_notification_count_before_failures =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    for (now, attempt_was_deleted) in [(80, false), (81, false), (82, true)] {
        let secret_response = mismatched_totp_test_method_response_payload();
        let weak_proof_gate_response =
            bound_proof_of_work_gate_response_for_known_subject_completion(
                &continuation_headers,
                &method,
                &secret_response,
                at(now),
            );
        let failed = runtime
            .execute_known_subject_active_proof_method_response_from_headers(
                &continuation_headers,
                CompleteKnownSubjectActiveProofMethodResponse {
                    now: at(now),
                    method: method.clone(),
                    secret_response,
                    weak_proof_gate_response: Some(weak_proof_gate_response),
                },
            )
            .await
            .expect("failed TOTP proof should record or delete by weak-proof budget");
        assert_eq!(
            failed.outcome(),
            &Outcome::ActiveProofFailureRecorded {
                attempt_id: attempt_id.clone(),
                attempt_was_deleted,
            }
        );
    }

    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await,
        subject_revocation_cutoff_before_failures,
        "exhausting a weak-proof budget must not create subject-level lockout or revocation state",
    );
    assert_eq!(
        totp_plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count TOTP verifier after weak-proof budget exhaustion"),
        1,
        "exhausting a TOTP proof ceremony must not consume or delete the configured TOTP verifier",
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notification_count_before_failures,
        "exhausting a weak-proof budget must not create account-level security notice state",
    );
    assert_eq!(count_all_sessions(pool, store_config).await, 1);
    let resolved_existing_session = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(83),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve existing session after weak-proof budget exhaustion");
    assert_eq!(
        resolved_existing_session.outcome(),
        &Outcome::Authenticated(Authenticated {
            subject_id,
            session_id: issued_auth.session_id,
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: false,
        }),
        "exhausting a TOTP proof ceremony must not lock or revoke the live session",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_invalid_totp_weak_gate_before_state_load() {
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
        "totp-invalid-gate-bootstrap",
        20,
        id("unused-invalid-gate-subject"),
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

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                secret_response: mismatched_totp_test_method_response_payload(),
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("invalid weak gate must fail before loading the active proof attempt");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid TOTP weak gate must reject before any database operation",
    );

    harness.drop_schema().await;
}
