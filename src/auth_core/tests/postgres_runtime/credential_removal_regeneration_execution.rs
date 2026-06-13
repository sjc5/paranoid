use super::*;

#[tokio::test]
async fn postgres_runtime_authenticated_credential_removal_planning_authorizes_immediate_without_revocation()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-removal-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-removal-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-removal-plan-totp");
    let session_authority = id("authenticated-removal-plan-session-authority");
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
                "totp_app",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_planning =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_removal_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan authenticated credential removal");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::AuthorizedImmediate {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
        })
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.mutation.record_credential_lifecycle_action_authorized",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential removal planning must stay inside one bounded lifecycle authorization and commit without auth-state revocation",
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential removal planning must atomically schedule an authorization notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_planning,
        "credential removal planning must not revoke auth state before removal execution"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_removal_planning_generates_pending_action_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-delayed-removal-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-delayed-removal-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-delayed-removal-totp");
    let session_authority = id("authenticated-delayed-removal-session-authority");
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
                "totp_app",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                session_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_removal_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan delayed authenticated credential removal");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::PendingActionCreated {
            subject_id: actual_subject_id,
            target_credential_instance_id,
            pending_action_id,
            earliest_execute_at,
            expires_at,
        }) => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            assert_eq!(earliest_execute_at, &at(200));
            assert_eq!(expires_at, &at(300));
            pending_action_id.clone()
        }
        outcome => panic!("expected pending removal action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Remove,
        )
        .await,
        1,
        "runtime-generated pending removal action id must be committed"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential removal scheduling must atomically schedule a security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_regeneration_planning_authorizes_immediate_without_revocation()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-regeneration-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-regeneration-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-regeneration-plan-recovery-codes");
    let session_authority = id("authenticated-regeneration-plan-session-authority");
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
                CredentialInstanceKind::RecoveryCodeCredential,
                "recovery_code",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_planning =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_regeneration_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialRegenerationInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan authenticated credential regeneration");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRegenerationPlanned(
            CredentialRegenerationOutcome::AuthorizedImmediate {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id,
            }
        )
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.mutation.record_credential_lifecycle_action_authorized",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential regeneration planning must stay inside one bounded lifecycle authorization and commit without auth-state revocation",
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential regeneration planning must atomically schedule an authorization notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_planning,
        "credential regeneration planning must not revoke auth state before regeneration execution"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_recovery_code_regeneration_executes_immediately_and_projects_generated_codes()
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
    let subject_id = id("authenticated-regeneration-execute-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-regeneration-execute-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let recovery_code_credential_id = id("authenticated-regeneration-execute-recovery-code-set");
    let old_recovery_code_id = recovery_code_id_for_runtime_test(0x31);
    let old_recovery_code_secret = b"old-authenticated-regeneration-code";
    let session_authority = id("authenticated-regeneration-execute-session-authority");
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
            &[CredentialRecoveryAuthority::new(
                recovery_code_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed recovery-code credential lifecycle metadata");
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
    let revocation_cutoff_before_execution =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_regeneration_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRegenerationInput {
                now: at(80),
                target_credential_instance_id: recovery_code_credential_id.clone(),
                method_payload: PostgresRecoveryCodeMethodPlugin::regeneration_payload_for_test(2)
                    .expect("recovery code regeneration payload"),
            },
        )
        .await
        .expect("execute authenticated recovery-code regeneration");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRegenerated(CredentialRegenerationExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: recovery_code_credential_id.clone(),
        })
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.recovery_code.precondition.lock_set",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.recovery_code.mutation.supersede_unused_set",
            "auth_core.recovery_code.mutation.insert_set",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated recovery-code regeneration execution must stay inside one bounded lifecycle load, existing-set lock, regenerated-set mutation, auth-state revocation, and commit",
    );
    let generated = execution
        .post_commit_method_response_material()
        .generated_recovery_codes()
        .expect("immediate regeneration must return generated display codes after commit");
    assert_eq!(
        generated.credential_instance_id(),
        &recovery_code_credential_id
    );
    assert_eq!(generated.len(), 2);
    assert_eq!(
        recovery_code_plugin
            .count_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count all recovery code rows after immediate regeneration"),
        3,
        "immediate regeneration keeps historical rows and adds the new set"
    );
    assert_eq!(
        recovery_code_plugin
            .count_unused_recovery_codes_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count active unused recovery codes after immediate regeneration"),
        2,
        "immediate regeneration must supersede old unused codes and leave only the new set active"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "immediate regeneration must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "immediate regeneration must revoke existing subject auth state"
    );
    assert_ne!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_execution,
        "immediate regeneration must advance subject auth-state revocation"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_regeneration_execution_requires_fresh_step_up_before_lifecycle_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-regeneration-execute-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-regeneration-execute-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_regeneration_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRegenerationInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-regeneration-execute-target"),
                method_payload: PostgresRecoveryCodeMethodPlugin::regeneration_payload_for_test(2)
                    .expect("recovery code regeneration payload"),
            },
        )
        .await
        .expect("stale lifecycle regeneration execution returns step-up outcome");

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
            .any(|record| record.label == "auth_core.load.credential_instance_metadata"),
        "stale regeneration execution must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_regeneration_planning_requires_fresh_step_up_before_lifecycle_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-regeneration-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-regeneration-plan-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_regeneration_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialRegenerationInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-regeneration-plan-target"),
            },
        )
        .await
        .expect("stale lifecycle regeneration planning returns step-up outcome");

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
            .any(|record| record.label == "auth_core.load.credential_instance_metadata"),
        "stale regeneration planning must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_regeneration_planning_generates_pending_action_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-delayed-regeneration-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-delayed-regeneration-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-delayed-regeneration-codes");
    let session_authority = id("authenticated-delayed-regeneration-session-authority");
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
                CredentialInstanceKind::RecoveryCodeCredential,
                "recovery_code",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_regeneration_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialRegenerationInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan delayed authenticated credential regeneration");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialRegenerationPlanned(
            CredentialRegenerationOutcome::PendingActionCreated {
                subject_id: actual_subject_id,
                target_credential_instance_id,
                pending_action_id,
                earliest_execute_at,
                expires_at,
            },
        ) => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            assert_eq!(earliest_execute_at, &at(200));
            assert_eq!(expires_at, &at(300));
            pending_action_id.clone()
        }
        outcome => panic!("expected pending regeneration action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Regenerate,
        )
        .await,
        1,
        "runtime-generated pending regeneration action id must be committed"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential regeneration scheduling must atomically schedule a security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_removal_revokes_target_without_method_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-removal-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-removal-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-removal-totp");
    let survivor_credential_id = id("authenticated-removal-passkey-survivor");
    let session_authority = id("authenticated-removal-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target credential metadata"),
                CredentialInstanceMetadata::new(
                    survivor_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    "webauthn_passkey",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("survivor credential metadata"),
            ],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_removal_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("execute authenticated credential removal");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRemovalExecuted(CredentialRemovalExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.mutation.set_credential_lifecycle_state",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential removal execution must stay inside one bounded lifecycle load, posture guard, target revocation, auth-state revocation, and commit",
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Revoked,
        "credential removal must revoke the target credential metadata"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &survivor_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "credential removal must leave the independent survivor active"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential removal execution must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "credential removal execution must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_second_factor_removal_rejects_ordinary_only_survivor() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-removal-downgrade-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-removal-downgrade-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-removal-downgrade-totp");
    let survivor_credential_id = id("authenticated-removal-downgrade-password");
    let session_authority = id("authenticated-removal-downgrade-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target credential metadata"),
                CredentialInstanceMetadata::new(
                    survivor_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("survivor credential metadata"),
            ],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_removal =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_removal_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect_err("second-factor removal with ordinary-only survivor must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after removal",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed posture check must leave the removed credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &survivor_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed posture check must leave the ordinary survivor unchanged"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_removal,
        "failed posture check must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_ordinary_removal_rejects_same_authority_survivor_collapse() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-ordinary-removal-collapse-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-ordinary-removal-collapse-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-ordinary-removal-collapse-password-device");
    let ordinary_survivor_id = id("authenticated-ordinary-removal-collapse-password-email");
    let second_factor_survivor_id = id("authenticated-ordinary-removal-collapse-totp-email");
    let session_authority = id("authenticated-ordinary-removal-collapse-session-authority");
    let shared_recovery_authority = id("authenticated-ordinary-removal-collapse-email-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target credential metadata"),
                CredentialInstanceMetadata::new(
                    ordinary_survivor_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("ordinary survivor metadata"),
                CredentialInstanceMetadata::new(
                    second_factor_survivor_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("second-factor survivor metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    ordinary_survivor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_recovery_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    second_factor_survivor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_recovery_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_removal =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let security_notice_count_before_removal =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_removal_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect_err("ordinary removal with same-authority survivor collapse must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after removal",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    for credential_id in [
        &target_credential_id,
        &ordinary_survivor_id,
        &second_factor_survivor_id,
    ] {
        assert_eq!(
            credential_lifecycle_state_for_runtime_test(pool, store_config, credential_id).await,
            CredentialLifecycleState::Active,
            "failed ordinary-removal posture check must leave all credentials active"
        );
    }
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_removal,
        "failed ordinary-removal posture check must not revoke subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_removal,
        "failed ordinary-removal posture check must not schedule a security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_second_factor_removal_rejects_same_authority_survivor_collapse() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-removal-collapse-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-removal-collapse-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-removal-collapse-totp");
    let password_survivor_id = id("authenticated-removal-collapse-password");
    let passkey_survivor_id = id("authenticated-removal-collapse-passkey");
    let session_authority = id("authenticated-removal-collapse-session-authority");
    let shared_recovery_authority = id("authenticated-removal-collapse-shared-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target credential metadata"),
                CredentialInstanceMetadata::new(
                    password_survivor_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("password survivor metadata"),
                CredentialInstanceMetadata::new(
                    passkey_survivor_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    "webauthn_passkey",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("passkey survivor metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    password_survivor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_recovery_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    passkey_survivor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_recovery_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_removal =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let security_notice_count_before_removal =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_removal_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect_err("second-factor removal with same-authority survivor collapse must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after removal",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed same-authority posture check must leave the removed credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &password_survivor_id)
            .await,
        CredentialLifecycleState::Active,
        "failed same-authority posture check must leave the ordinary survivor unchanged"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &passkey_survivor_id).await,
        CredentialLifecycleState::Active,
        "failed same-authority posture check must leave the second-factor survivor unchanged"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_removal,
        "failed same-authority posture check must not revoke subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_removal,
        "failed same-authority posture check must not schedule a security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_second_factor_removal_rejects_partial_same_authority_survivor_collapse() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-removal-partial-collapse-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-removal-partial-collapse-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-removal-partial-collapse-totp");
    let same_authority_password_id = id("authenticated-removal-partial-collapse-password-email");
    let distinct_authority_password_id =
        id("authenticated-removal-partial-collapse-password-device");
    let passkey_survivor_id = id("authenticated-removal-partial-collapse-passkey");
    let session_authority = id("authenticated-removal-partial-collapse-session-authority");
    let shared_recovery_authority = id("authenticated-removal-partial-collapse-email-authority");
    let distinct_recovery_authority = id("authenticated-removal-partial-collapse-device-authority");
    let passkey_distinct_authority = id("authenticated-removal-partial-collapse-passkey-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target credential metadata"),
                CredentialInstanceMetadata::new(
                    same_authority_password_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("same-authority password metadata"),
                CredentialInstanceMetadata::new(
                    distinct_authority_password_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("distinct-authority password metadata"),
                CredentialInstanceMetadata::new(
                    passkey_survivor_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    "webauthn_passkey",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("passkey survivor metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    same_authority_password_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_recovery_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    distinct_authority_password_id.clone(),
                    CredentialLifecycleAction::Reset,
                    distinct_recovery_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    passkey_survivor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_recovery_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    passkey_survivor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    passkey_distinct_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_removal =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let security_notice_count_before_removal =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_removal_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect_err("partial same-authority survivor collapse must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after removal",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    for credential_id in [
        &target_credential_id,
        &same_authority_password_id,
        &distinct_authority_password_id,
        &passkey_survivor_id,
    ] {
        assert_eq!(
            credential_lifecycle_state_for_runtime_test(pool, store_config, credential_id).await,
            CredentialLifecycleState::Active,
            "failed partial-collapse posture check must leave all credential metadata unchanged"
        );
    }
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_removal,
        "failed partial-collapse posture check must not revoke subject auth state"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_removal,
        "failed partial-collapse posture check must not schedule a security notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_removal_rejects_last_active_credential() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-removal-last-active-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-removal-last-active-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-removal-last-active-totp");
    let session_authority = id("authenticated-removal-last-active-session-authority");
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
                "totp_app",
                CredentialResetPolicyRole::SecondFactorCredential,
                CredentialLifecycleState::Active,
            )
            .expect("credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_removal =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_removal_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRemovalInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect_err("last active credential removal must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after removal",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed last-active removal must leave the credential active"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_removal,
        "failed last-active removal must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_addition_builds_method_work_internally() {
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
    let subject_id = id("authenticated-add-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-add-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("authenticated-add-session-authority");
    let new_credential_authority = id("authenticated-add-new-credential-authority");
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

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialAdditionInput {
                now: at(70),
                method: proof_method(ProofFamily::MessageSignature),
                reset_policy_role: CredentialResetPolicyRole::OrdinaryCredential,
                recovery_authority_rules: vec![
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
                new_credential_authority_ids: vec![new_credential_authority],
                method_payload: CredentialCreationMethodPayload::try_from_bytes(
                    b"created-password-verifier".as_slice(),
                )
                .expect("creation payload"),
            },
        )
        .await
        .expect("execute authenticated credential addition");

    let added_credential_id = match execution.outcome() {
        Outcome::CredentialAdded(outcome) => {
            assert_eq!(&outcome.subject_id, &subject_id);
            outcome.credential_instance_id.clone()
        }
        outcome => panic!("expected credential addition, got {outcome:?}"),
    };
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
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
        "authenticated credential addition execution must stay inside one bounded session/evidence load, posture guard, credential creation, method-work, auth-state revocation, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "credential addition method work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &added_credential_id).await,
        CredentialLifecycleState::Active,
        "credential addition must create active core credential metadata"
    );
    assert_eq!(
        count_credential_recovery_authorities_for_runtime_test(
            pool,
            store_config,
            &added_credential_id,
        )
        .await,
        2,
        "credential addition must persist the configured recovery-authority graph"
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
        "credential addition must map the new credential source to its recovery authority"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential addition must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(70),
        "credential addition must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_addition_rejects_same_authority_factor_collapse()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            true,
            None,
            Some(proof_method(ProofFamily::SharedSecretOtp)),
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let method_plugin = harness
        .method_plugin
        .as_ref()
        .expect("shared-secret creation method plugin");
    let subject_id = id("authenticated-add-collapse-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-add-collapse-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let existing_password_id = id("authenticated-add-collapse-password");
    let session_authority = id("authenticated-add-collapse-session-authority");
    let shared_authority = id("authenticated-add-collapse-shared-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                existing_password_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("existing password metadata")],
            &[CredentialRecoveryAuthority::new(
                existing_password_id,
                CredentialLifecycleAction::Reset,
                shared_authority.clone(),
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
    let revocation_cutoff_before_addition =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let security_notice_count_before_addition =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialAdditionInput {
                now: at(70),
                method: proof_method(ProofFamily::SharedSecretOtp),
                reset_policy_role: CredentialResetPolicyRole::SecondFactorCredential,
                recovery_authority_rules: vec![
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Create,
                        authority_id: session_authority,
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Reset,
                        authority_id: shared_authority,
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                ],
                new_credential_authority_ids: vec![id("authenticated-add-collapse-new-factor")],
                method_payload: CredentialCreationMethodPayload::try_from_bytes(
                    b"created-totp-secret".as_slice(),
                )
                .expect("creation payload"),
            },
        )
        .await
        .expect_err("same-authority second-factor addition must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after addition",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "failed addition posture check must not commit method-owned verifier state"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        1,
        "failed addition posture check must not create a new credential row"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_addition,
        "failed addition posture check must not schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_addition,
        "failed addition posture check must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_execution_requires_fresh_step_up_before_method_work()
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
        .expect("message-signature reset method plugin");
    let subject_id = id("stale-step-up-reset-execute-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-reset-execute-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_reset_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-reset-execute-target"),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"stale-step-up-reset-payload".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect("stale lifecycle reset execution returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "stale reset execution must not run method-owned verifier work"
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.credential_instance_metadata"),
        "stale reset execution must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_replacement_execution_requires_fresh_step_up_before_method_work()
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
        .expect("message-signature replacement method plugin");
    let subject_id = id("stale-step-up-replacement-execute-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-replacement-execute-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_replacement_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-replacement-execute-target"),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    b"stale-step-up-replacement-payload".as_slice(),
                )
                .expect("replacement payload"),
            },
        )
        .await
        .expect("stale lifecycle replacement execution returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "stale replacement execution must not run method-owned verifier work"
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.credential_instance_metadata"),
        "stale replacement execution must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_rotation_execution_requires_fresh_step_up_before_method_work()
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
        .expect("message-signature rotation method plugin");
    let subject_id = id("stale-step-up-rotation-execute-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-rotation-execute-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_rotation_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRotationInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-rotation-execute-target"),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    b"stale-step-up-rotation-payload".as_slice(),
                )
                .expect("rotation payload"),
            },
        )
        .await
        .expect("stale lifecycle rotation execution returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "stale rotation execution must not run method-owned verifier work"
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.credential_instance_metadata"),
        "stale rotation execution must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_addition_requires_fresh_step_up_before_method_work()
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
    let subject_id = id("stale-step-up-add-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-add-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialAdditionInput {
                now: at(80),
                method: proof_method(ProofFamily::MessageSignature),
                reset_policy_role: CredentialResetPolicyRole::OrdinaryCredential,
                recovery_authority_rules: vec![CredentialAdditionRecoveryAuthorityRule {
                    action: CredentialLifecycleAction::Create,
                    authority_id: id("stale-step-up-add-session-authority"),
                    timing: RecoveryAuthorityTiming::Immediate,
                }],
                new_credential_authority_ids: vec![id("stale-step-up-add-new-authority")],
                method_payload: CredentialCreationMethodPayload::try_from_bytes(
                    b"stale-step-up-add-payload".as_slice(),
                )
                .expect("creation payload"),
            },
        )
        .await
        .expect("stale lifecycle addition returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "stale credential addition must not run method-owned verifier work"
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.lifecycle_authority_evidence"),
        "stale credential addition must not load lifecycle authority evidence; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}
