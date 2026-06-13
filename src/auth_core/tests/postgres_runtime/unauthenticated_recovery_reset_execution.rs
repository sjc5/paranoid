use super::*;

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_executes_immediate_recovery_inside_runtime()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_recovery_code_plugin: true,
                ..FirstPartyMethodSelection::default()
            },
            config_with_divergent_credential_reset_role_policies(),
            None,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("unauthenticated-reset-execute-subject");
    let target_credential_id = id("unauthenticated-reset-execute-password");
    let recovery_authority = id("unauthenticated-reset-execute-recovery-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("unauthenticated-reset-execute-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x0a);
    let recovery_code_secret = b"correct-recovery-execute";
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
                RecoveryAuthorityTiming::Immediate,
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
    let _issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-reset-execute-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
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
    let csrf_protected_continuation_request = Request::from_parts(
        Request::builder()
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
            .body(())
            .expect("csrf-protected no-session recovery reset request")
            .into_parts()
            .0,
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
            b"new-unauthenticated-recovery-password-verifier".as_slice(),
        )
        .expect("route reset body"),
    );
    harness.database_operation_observer.clear();
    let execution = route_service
        .execute_immediate_reset(csrf_protected_continuation_request, at(90))
        .await
        .expect("execute unauthenticated recovery reset");

    assert_eq!(
        execution.body(),
        MountedNoSessionCredentialRecoveryRouteResponseBody::ImmediateResetExecuted
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.active_proof_attempt",
            "auth_core.load.active_proof_satisfied_proofs",
            "auth_core.load.active_proof_continuation_secret_mac",
            "auth_core.load.subject_revocation",
            "auth_core.load.active_credential_instance_for_subject_and_method",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.active_proof_attempt_still_open",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.precondition.fetch_subject_cutoff",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.delete_active_proof_delivery_keys",
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            "auth_core.mutation.delete_active_proof_challenges",
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            "auth_core.mutation.delete_active_proof_attempt",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "unauthenticated recovery reset execution must stay inside one recovery-attempt load, configured-target lifecycle load, method work, attempt close, auth-state revocation, notice, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "unauthenticated recovery reset must build verifier work through the registered target method"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "unauthenticated recovery reset must preserve the target credential metadata state"
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
            recovery_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        "unauthenticated recovery reset must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        0,
        "unauthenticated recovery reset must consume the recovery attempt in the reset commit"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "unauthenticated recovery reset execution must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(90),
        "unauthenticated recovery reset execution must revoke existing subject auth state"
    );

    let replay_request = Request::from_parts(
        Request::builder()
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
            .body(())
            .expect("csrf-protected replayed no-session recovery reset request")
            .into_parts()
            .0,
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
            b"replayed-unauthenticated-recovery-password-verifier".as_slice(),
        )
        .expect("route reset body"),
    );
    let replay_error = route_service
        .execute_immediate_reset(replay_request, at(91))
        .await
        .expect_err("consumed recovery continuation must not execute reset twice");
    assert!(
        matches!(
            replay_error,
            MountedCredentialLifecycleServiceError::Runtime(
                super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(_)
                    | super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
                        _
                    )
            )
        ),
        "expected replay to reject through mounted runtime/core/store boundary, got {replay_error:?}"
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "replaying a consumed recovery continuation must not commit duplicate verifier work"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "replaying a consumed recovery continuation must not schedule duplicate notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(90),
        "replaying a consumed recovery continuation must not advance subject revocation"
    );
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        0,
        "replaying a consumed recovery continuation must not recreate the recovery attempt"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_reset_replaces_real_password_derived_signature_verifier()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
        None,
        true,
        None,
        None,
        TestActiveMethodVerificationMode::BeforeStateLoad,
        FirstPartyMethodSelection {
            include_recovery_code_plugin: true,
            include_password_derived_signature_plugin: true,
            ..FirstPartyMethodSelection::default()
        },
        config_with_divergent_credential_reset_role_policies(),
        None,
    )
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let password_plugin = password_derived_signature_plugin_for_harness(&harness);
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("no-session-password-reset-subject");
    let target_credential_id = id("no-session-password-reset-target");
    let recovery_authority = id("no-session-password-reset-authority");
    let recovery_code_credential_id: VerifiedProofSourceId = id("no-session-password-reset-codes");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x33);
    let recovery_code_secret = b"no-session-password-reset-recovery";
    let old_lookup_handle = b"no-session-password-reset-old-lookup";
    let new_lookup_handle = b"no-session-password-reset-new-lookup";
    let old_password = b"old-no-session-password";
    let new_password = b"new-no-session-password";
    let old_salt =
        PasswordKdfSalt::from_bytes(&[22_u8; PASSWORD_KDF_SALT_SIZE]).expect("old KDF salt");
    let new_salt =
        PasswordKdfSalt::from_bytes(&[23_u8; PASSWORD_KDF_SALT_SIZE]).expect("new KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );

    password_plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &target_credential_id,
                lookup_handle: old_lookup_handle,
                password: old_password,
                salt: old_salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store old password-derived verifier");
    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &subject_id,
            &recovery_code_credential_id,
            &recovery_code_id,
            recovery_code_secret,
            at(12),
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
                password_plugin.method().method_label(),
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("password-derived credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                recovery_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
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
    let _issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "no-session-password-reset-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;

    let route_service = MountedNoSessionCredentialRecoveryPostgresRouteService::new(
        runtime,
        MountedNoSessionCredentialRecoveryFlow::new(
            recovery_code_plugin.method().clone(),
            password_plugin.method().clone(),
        )
        .expect("mounted no-session recovery flow"),
    );
    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        recovery_code_plugin.method(),
    );
    let started = route_service
        .start_recovery_attempt(
            request_with_body_and_cookie_pairs(
                Method::POST,
                &[],
                MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
                    preflight_response.summary().kind(),
                    preflight_response.summary().method_label(),
                    preflight_response.payload().to_vec(),
                )
                .expect("no-session recovery route body"),
            ),
            at(70),
        )
        .await
        .expect("start no-session recovery route");
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started.set_cookie_headers())
            .to_owned();
    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let completed = route_service
        .submit_recovery_proof(
            request_with_body_and_cookie_pairs(
                Method::POST,
                &[continuation_cookie_pair.as_str()],
                MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
                    sealed_response.expose_secret().to_vec(),
                )
                .expect("route recovery proof body"),
            ),
            at(80),
        )
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
    let reset_payload =
        PostgresPasswordDerivedSignatureMethodPlugin::verifier_reset_payload_for_test(
            new_lookup_handle,
            new_password,
            new_salt,
            params,
        )
        .expect("password-derived verifier reset payload");
    let reset_request = Request::from_parts(
        Request::builder()
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
            .body(())
            .expect("csrf-protected no-session recovery reset request")
            .into_parts()
            .0,
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
            reset_payload.as_bytes().to_vec(),
        )
        .expect("route reset body"),
    );
    let execution = route_service
        .execute_immediate_reset(reset_request, at(90))
        .await
        .expect("execute no-session password-derived recovery reset");
    assert_eq!(
        execution.body(),
        MountedNoSessionCredentialRecoveryRouteResponseBody::ImmediateResetExecuted
    );
    assert_eq!(
        password_plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count password-derived verifiers"),
        1,
        "recovery reset must replace the existing verifier instead of creating a second row"
    );
    assert_eq!(
        password_plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch password-derived verifier version"),
        Some(2),
        "recovery reset of the same password-derived credential must advance verifier version"
    );
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        0,
        "recovery reset must consume the recovery attempt in the reset commit"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(90),
        "recovery reset must revoke existing subject auth state after verifier mutation"
    );

    let empty_headers = HeaderMap::new();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(100),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: password_plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        new_lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(100),
                ProofUse::ContributeToFullAuthentication,
                password_plugin.method(),
            ),
        )
        .await
        .expect("issue challenge against reset password verifier");
    let (attempt_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), method_challenge),
        outcome => panic!("expected password-derived challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        new_password,
        method_challenge,
    )
    .expect("password-derived signature response after reset");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &response_payload,
        at(110),
    );
    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(110),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete proof with reset password verifier");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: password_plugin.method().verified_proof_summary(),
        }
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            target_credential_id,
        )),
        "proof after recovery reset must still source from the configured target credential"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_execution_rejects_delayed_only_recovery_policy()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::MessageSignature)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_recovery_code_plugin: true,
                ..FirstPartyMethodSelection::default()
            },
            config_with_divergent_credential_reset_role_policies(),
            None,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("message-signature reset method plugin");
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("unauthenticated-reset-delayed-policy-subject");
    let target_credential_id = id("unauthenticated-reset-delayed-policy-password");
    let recovery_authority = id("unauthenticated-reset-delayed-policy-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("unauthenticated-reset-delayed-policy-code-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x0b);
    let recovery_code_secret = b"delayed-policy-recovery";
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
                [recovery_authority],
            )
            .expect("recovery code lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-reset-delayed-policy-bootstrap",
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
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let sealed_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(&subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: proof_method(ProofFamily::RecoveryCode),
                secret_response: sealed_response,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete recovery code proof");
    let accepted_continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(completed.set_cookie_headers())
            .to_owned();
    let continuation_headers =
        headers_from_cookie_pairs(&[accepted_continuation_cookie_pair.as_str()]);
    let initial_revocation_cutoff =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"must-not-be-committed".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("delayed-only recovery policy must not execute immediately");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "delayed-only recovery execution must not build or commit verifier work"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        1,
        "rejected delayed-only recovery execution must not consume the recovery attempt"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        0,
        "immediate execution facade must not silently schedule delayed reset work"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        0,
        "rejected delayed-only recovery execution must not schedule notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        initial_revocation_cutoff,
        "rejected delayed-only recovery execution must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_execution_rejects_wrong_continuation_use_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("wrong-recovery-execute-use-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "wrong-recovery-execute-use-bootstrap",
        20,
        subject_id,
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::ContributeToFullAuthentication,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let error = runtime
        .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"wrong-use-payload".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("wrong proof-use continuation must reject before recovery reset execution");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong proof-use continuation must reject before any recovery reset execution database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_execution_rejects_unaccepted_recovery_continuation_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let started =
        start_unauthenticated_recovery_active_proof_attempt_through_runtime(runtime, at(70)).await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let error = runtime
        .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"unaccepted-continuation-reset-payload".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("unaccepted recovery continuation must reject before reset execution load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "unaccepted recovery continuation must reject before any reset execution database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_execution_rejects_runtime_bound_recovery_continuation_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let runtime = &harness.runtime;
    let continuation_headers = runtime_bound_recovery_continuation_headers_for_runtime_test(
        &harness,
        "runtime-bound-recovery-execute-subject",
        "runtime-bound-recovery-execute-bootstrap",
    )
    .await;
    harness.database_operation_observer.clear();

    let error = runtime
        .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"runtime-bound-continuation-reset-payload".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("runtime-bound recovery continuation must reject before reset execution load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "runtime-bound recovery continuation must reject before any reset execution database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_execution_rejects_missing_or_expired_continuation_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    harness.database_operation_observer.clear();
    let missing_error = runtime
        .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
            &HeaderMap::new(),
            ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"missing-continuation-reset-payload".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("missing recovery continuation must reject before reset execution");
    assert_missing_active_proof_continuation_error(missing_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing recovery continuation must reject before any reset execution database operation",
    );

    let expired_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::RecoverOrReplaceCredential,
        Some(id("expired-recovery-reset-execution-subject")),
        at(40),
        at(60),
    );
    let expired_headers = headers_from_cookie_pairs(&[expired_continuation.as_str()]);
    harness.database_operation_observer.clear();
    let expired_error = runtime
        .execute_unauthenticated_credential_reset_for_configured_method_from_headers(
            &expired_headers,
            ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"expired-continuation-reset-payload".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("expired recovery continuation must reject before reset execution");
    assert_expired_active_proof_continuation_error(expired_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired recovery continuation must reject before any reset execution database operation",
    );

    harness.drop_schema().await;
}
