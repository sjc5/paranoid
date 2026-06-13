use super::*;

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_consumes_recovery_attempt() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let recovery_code_plugin = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code method plugin");
    let subject_id: SubjectId = id("unauthenticated-reset-plan-subject");
    let target_credential_id = id("unauthenticated-reset-plan-password");
    let recovery_authority = id("unauthenticated-reset-plan-recovery-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("unauthenticated-reset-plan-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x05);
    let recovery_code_secret = b"correct-recovery";
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
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-reset-plan-bootstrap",
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
                method: ProofMethodDeclaration::new(ProofFamily::RecoveryCode, "recovery_code")
                    .expect("recovery code method"),
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

    harness.database_operation_observer.clear();
    let execution = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect("schedule unauthenticated credential reset");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: actual_subject_id,
            target_credential_instance_id,
            pending_action_id,
            ..
        }) => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            pending_action_id.clone()
        }
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };
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
            "auth_core.precondition.close_expired_pending_credential_lifecycle_actions",
            "auth_core.precondition.no_open_pending_credential_lifecycle_action",
            "auth_core.mutation.delete_active_proof_delivery_keys",
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            "auth_core.mutation.delete_active_proof_challenges",
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            "auth_core.mutation.delete_active_proof_attempt",
            "auth_core.mutation.create_pending_credential_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "unauthenticated recovery reset scheduling must stay inside one recovery-attempt load, configured-target lifecycle load, pending-action schedule, attempt close, notice, and commit",
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "recovery reset scheduling must create the pending action inside the runtime commit"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        0,
        "recovery reset scheduling must consume the active-proof attempt it used as lifecycle evidence"
    );

    harness.database_operation_observer.clear();
    let replay_error = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(91),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("consumed recovery continuation must not schedule another reset");
    assert!(
        matches!(
            replay_error,
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(_)
                | super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(_)
        ),
        "expected replay to reject through runtime/core/store boundary, got {replay_error:?}"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "replaying a consumed recovery continuation must not duplicate the original pending reset"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        1,
        "replaying a consumed recovery continuation must not create any additional pending reset"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        0,
        "replaying a consumed recovery continuation must not resurrect the consumed recovery attempt"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_configured_target_rejects_ambiguous_method_target()
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
    let subject_id: SubjectId = id("unauthenticated-reset-ambiguous-subject");
    let first_target_credential_id = id("unauthenticated-reset-ambiguous-first-password");
    let second_target_credential_id = id("unauthenticated-reset-ambiguous-second-password");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("unauthenticated-reset-ambiguous-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x06);
    let recovery_code_secret = b"ambiguous-recovery-code";
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
            &[
                CredentialInstanceMetadata::new(
                    first_target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("first credential metadata"),
                CredentialInstanceMetadata::new(
                    second_target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("second credential metadata"),
            ],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed ambiguous credential lifecycle metadata");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-reset-ambiguous-bootstrap",
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

    let error = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("ambiguous configured reset target must reject");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            super::super::super::postgres_store::PostgresAuthStoreError::Core(
                Error::LoadedStateContradiction(
                    "configured credential reset target matched more than one active credential",
                )
            )
        )
    ));
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &first_target_credential_id,
        )
        .await,
        0,
        "ambiguous configured recovery reset must not schedule the first matching target"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &second_target_credential_id,
        )
        .await,
        0,
        "ambiguous configured recovery reset must not schedule the second matching target"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        1,
        "ambiguous configured recovery reset must not consume the recovery proof attempt"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_execution_rejects_ambiguous_configured_method_target_before_method_work()
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
    let subject_id: SubjectId = id("unauthenticated-execute-ambiguous-subject");
    let first_target_credential_id = id("unauthenticated-execute-ambiguous-first-password");
    let second_target_credential_id = id("unauthenticated-execute-ambiguous-second-password");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("unauthenticated-execute-ambiguous-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x07);
    let recovery_code_secret = b"execute-ambiguous-recovery-code";
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
            &[
                CredentialInstanceMetadata::new(
                    first_target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("first credential metadata"),
                CredentialInstanceMetadata::new(
                    second_target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("second credential metadata"),
            ],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed ambiguous credential lifecycle metadata");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-execute-ambiguous-bootstrap",
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
                    b"must-not-build-method-work".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("ambiguous configured reset target must reject before method work");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            super::super::super::postgres_store::PostgresAuthStoreError::Core(
                Error::LoadedStateContradiction(
                    "configured credential reset target matched more than one active credential",
                )
            )
        )
    ));
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "ambiguous configured recovery reset must not build or commit verifier work"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        1,
        "ambiguous configured recovery reset must not consume the recovery proof attempt"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        0,
        "ambiguous configured recovery reset must not schedule notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        initial_revocation_cutoff,
        "ambiguous configured recovery reset must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_rejects_immediate_policy_without_consuming_recovery_attempt()
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
    let subject_id: SubjectId = id("unauthenticated-reset-schedule-immediate-subject");
    let target_credential_id = id("unauthenticated-reset-schedule-immediate-password");
    let recovery_authority = id("unauthenticated-reset-schedule-immediate-authority");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("unauthenticated-reset-schedule-immediate-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x08);
    let recovery_code_secret = b"recovery-schedule-immediate-secret";
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
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "unauthenticated-reset-schedule-immediate-bootstrap",
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
                method: ProofMethodDeclaration::new(ProofFamily::RecoveryCode, "recovery_code")
                    .expect("recovery code method"),
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
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("immediate recovery policy must use reset execution, not scheduling");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::UnauthenticatedCredentialRecoveryResetSchedulingRequiresDelayedAction
        )
    ));
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        1,
        "immediate-policy scheduling rejection must not consume the recovery attempt"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        0,
        "immediate-policy scheduling rejection must not create a pending reset action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        0,
        "immediate-policy scheduling rejection must not schedule notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        initial_revocation_cutoff,
        "immediate-policy scheduling rejection must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_rejects_wrong_continuation_use_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id: SubjectId = id("wrong-recovery-use-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "wrong-recovery-use-bootstrap",
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
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err(
            "wrong proof-use continuation must reject before recovery reset scheduling load",
        );

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong proof-use continuation must reject before any recovery reset scheduling database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_rejects_unaccepted_recovery_continuation_before_db()
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
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("unaccepted recovery continuation must reject before reset scheduling load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "unaccepted recovery continuation must reject before any reset scheduling database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_rejects_runtime_bound_recovery_continuation_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let runtime = &harness.runtime;
    let continuation_headers = runtime_bound_recovery_continuation_headers_for_runtime_test(
        &harness,
        "runtime-bound-recovery-schedule-subject",
        "runtime-bound-recovery-schedule-bootstrap",
    )
    .await;
    harness.database_operation_observer.clear();

    let error = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("runtime-bound recovery continuation must reject before reset scheduling load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "runtime-bound recovery continuation must reject before any reset scheduling database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_rejects_missing_or_expired_continuation_before_db()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;

    harness.database_operation_observer.clear();
    let missing_error = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &HeaderMap::new(),
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("missing recovery continuation must reject before reset scheduling");
    assert_missing_active_proof_continuation_error(missing_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing recovery continuation must reject before any reset scheduling database operation",
    );

    let expired_continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::RecoverOrReplaceCredential,
        Some(id("expired-recovery-reset-scheduling-subject")),
        at(40),
        at(60),
    );
    let expired_headers = headers_from_cookie_pairs(&[expired_continuation.as_str()]);
    harness.database_operation_observer.clear();
    let expired_error = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &expired_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("expired recovery continuation must reject before reset scheduling");
    assert_expired_active_proof_continuation_error(expired_error);
    assert_no_database_operations(
        &harness.database_operation_observer,
        "expired recovery continuation must reject before any reset scheduling database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_reset_route_rejects_missing_csrf_before_db() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let runtime = &harness.runtime;
    let route_service = MountedNoSessionCredentialRecoveryPostgresRouteService::new(
        runtime,
        MountedNoSessionCredentialRecoveryFlow::new(
            proof_method(ProofFamily::RecoveryCode),
            proof_method(ProofFamily::MessageSignature),
        )
        .expect("mounted no-session recovery flow"),
    );
    let continuation = rendered_active_proof_continuation_cookie_pair_for_runtime_test(
        ProofUse::RecoverOrReplaceCredential,
        Some(id("csrf-required-no-session-recovery-subject")),
        at(40),
        at(120),
    );
    let route_body_mismatch_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
        ))
        .body(MountedNoSessionCredentialRecoveryEndpointRequestBody::from(
            MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
                b"sealed-recovery-code".as_slice(),
            )
            .expect("proof route body"),
        ))
        .expect("route body mismatch request");

    harness.database_operation_observer.clear();
    let mismatch_error = route_service
        .handle_recovery_endpoint_request(route_body_mismatch_request, at(90))
        .await
        .expect_err("route/body mismatch must reject before CSRF and storage");
    assert!(matches!(
        mismatch_error,
        MountedCredentialLifecycleServiceError::NoSessionRecoveryRouteBodyMismatch {
            route_step: MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset,
            body_step: MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof,
        }
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "route/body mismatch must reject before any no-session recovery database operation",
    );

    let schedule_csrf_missing_request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[continuation.as_str()],
        MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody::from_empty_route_body_bytes(
            b"",
        )
        .expect("route schedule body"),
    );

    harness.database_operation_observer.clear();
    let schedule_error = route_service
        .schedule_delayed_reset(schedule_csrf_missing_request, at(90))
        .await
        .expect_err("missing CSRF must reject delayed no-session recovery reset scheduling");
    assert!(matches!(
        schedule_error,
        MountedCredentialLifecycleServiceError::Runtime(
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Web(
                AuthWebTransportError::Web(crate::web::Error::MissingCookie { .. })
                    | AuthWebTransportError::Web(crate::web::Error::CsrfTokenMissing)
            )
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing CSRF must reject delayed no-session recovery reset scheduling before any database operation",
    );

    harness.database_operation_observer.clear();
    let execute_csrf_missing_request = request_with_body_and_cookie_pairs(
        Method::POST,
        &[continuation.as_str()],
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
            b"csrf-required-reset-payload".as_slice(),
        )
        .expect("route reset body"),
    );
    let execute_error = route_service
        .execute_immediate_reset(execute_csrf_missing_request, at(90))
        .await
        .expect_err("missing CSRF must reject immediate no-session recovery reset execution");
    assert!(matches!(
        execute_error,
        MountedCredentialLifecycleServiceError::Runtime(
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Web(
                AuthWebTransportError::Web(crate::web::Error::MissingCookie { .. })
                    | AuthWebTransportError::Web(crate::web::Error::CsrfTokenMissing)
            )
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "missing CSRF must reject immediate no-session recovery reset execution before any database operation",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_no_session_recovery_reset_route_rejects_ambiguous_configured_target_without_side_effects()
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
    let subject_id: SubjectId = id("mounted-no-session-ambiguous-subject");
    let first_target_credential_id = id("mounted-no-session-ambiguous-first-password");
    let second_target_credential_id = id("mounted-no-session-ambiguous-second-password");
    let recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-no-session-ambiguous-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x36);
    let recovery_code_secret = b"mounted-no-session-ambiguous-recovery";
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
            &[
                CredentialInstanceMetadata::new(
                    first_target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("first credential metadata"),
                CredentialInstanceMetadata::new(
                    second_target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("second credential metadata"),
            ],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed ambiguous credential lifecycle metadata");

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
    let csrf_cookie_pair = csrf_cookie_pair_from_set_cookie(completed.set_cookie_headers());
    let accepted_continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(completed.set_cookie_headers())
            .to_owned();
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1;
    let initial_revocation_cutoff =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let execute_request = Request::from_parts(
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
            b"must-not-build-route-method-work".as_slice(),
        )
        .expect("route reset body"),
    );

    let error = route_service
        .execute_immediate_reset(execute_request, at(90))
        .await
        .expect_err("ambiguous configured route target must reject");

    assert!(matches!(
        error,
        MountedCredentialLifecycleServiceError::Runtime(
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
                super::super::super::postgres_store::PostgresAuthStoreError::Core(
                    Error::LoadedStateContradiction(
                        "configured credential reset target matched more than one active credential",
                    )
                )
            )
        )
    ));
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "ambiguous mounted recovery reset must not build or commit verifier work"
    );
    assert_eq!(
        count_all_active_proof_attempts(pool, store_config).await,
        1,
        "ambiguous mounted recovery reset must not consume the accepted recovery proof attempt"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        0,
        "ambiguous mounted recovery reset must not schedule notices"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        initial_revocation_cutoff,
        "ambiguous mounted recovery reset must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_unauthenticated_credential_reset_scheduling_uses_recovered_subject_for_configured_target()
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
    let proof_subject_id: SubjectId = id("recovery-mismatch-proof-subject");
    let target_subject_id: SubjectId = id("recovery-mismatch-target-subject");
    let target_credential_id = id("recovery-mismatch-target-password");
    let recovery_authority = id("recovery-mismatch-authority");
    let recovery_code_credential_id: VerifiedProofSourceId = id("recovery-mismatch-recovery-set");
    let recovery_code_id = recovery_code_id_for_runtime_test(0x09);
    let recovery_code_secret = b"recovery-mismatch-secret";
    let recovery_code_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        recovery_code_credential_id.clone(),
    );
    recovery_code_plugin
        .store_recovery_code_for_test(
            pool,
            &proof_subject_id,
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
                target_subject_id.clone(),
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
        .expect("seed target credential lifecycle metadata");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "recovery-mismatch-bootstrap",
        20,
        proof_subject_id.clone(),
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
        .sealed_recovery_code_response_for_test(&proof_subject_id, recovery_code_secret)
        .expect("sealed recovery code response");
    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: at(80),
                method: ProofMethodDeclaration::new(ProofFamily::RecoveryCode, "recovery_code")
                    .expect("recovery code method"),
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

    let error = runtime
        .schedule_unauthenticated_credential_reset_for_configured_method_from_headers(
            &continuation_headers,
            ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
                now: at(90),
                target_method: proof_method(ProofFamily::MessageSignature),
            },
        )
        .await
        .expect_err("configured recovery target must be resolved for the recovered subject only");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        0,
        "configured recovery reset must not schedule a target credential owned by another subject"
    );
    assert_eq!(
        count_active_proof_attempts_for_attempt(pool, store_config, &started.attempt_id).await,
        1,
        "failed configured recovery reset target resolution must not consume the proof attempt"
    );

    harness.drop_schema().await;
}
