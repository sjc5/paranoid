use super::*;

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_reset_builds_method_work_internally() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
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
    let subject_id = id("pending-reset-subject");
    let target_credential_id = id("pending-reset-password-credential");
    let email_authority = id("pending-reset-email-authority");
    let pending_action_id = id("pending-reset-action");
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
                email_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_pending_credential_reset_for_runtime_test(
        pool,
        &seed_store,
        target_credential_id.clone(),
        email_authority,
        pending_action_id.clone(),
    )
    .await;

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_mature_pending_credential_reset_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialResetInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"new-pending-password-verifier".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect("execute mature pending credential reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            pending_action_id: Some(pending_action_id.clone()),
        })
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.close_pending_credential_lifecycle_action",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mature pending credential reset execution must stay inside one bounded pending-action load, method-work, pending closure, auth-state revocation, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "pending reset method work must be committed through the registered plugin"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(250),
        "pending reset execution must revoke existing subject auth state"
    );

    let replay_error = runtime
        .execute_mature_pending_credential_reset_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialResetInput {
                now: at(260),
                pending_action_id,
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"new-pending-password-verifier".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect_err("closed pending credential reset must not replay");

    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_replacement_builds_method_work_internally() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
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
        .expect("message-signature lifecycle method plugin");
    let subject_id = id("pending-replacement-subject");
    let target_credential_id = id("pending-replacement-password-credential");
    let pending_action_id = id("pending-replacement-action");
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
            &[],
            &[credential_instance_lifecycle_evidence(
                "pending-replacement-password-credential",
                [id("pending-replacement-password-authority")],
            )],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"replacement-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        )
        .await
        .expect("execute mature pending credential replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.insert_credential_instance_metadata",
            "auth_core.mutation.insert_lifecycle_authority_source",
            "auth_core.mutation.close_pending_credential_lifecycle_action",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.mutation.set_credential_lifecycle_state",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mature pending credential replacement execution must stay inside one bounded pending-action load, successor creation, posture guard, method-work, pending closure, auth-state revocation, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "pending replacement method work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Superseded,
        "replacement execution must supersede the old target credential"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        1,
        "pending replacement must create one active core-visible successor"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        0,
        "replacement execution must close the pending action"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(250),
        "replacement execution must revoke existing subject auth state"
    );

    let replay_error = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(260),
                pending_action_id,
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"replacement-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        )
        .await
        .expect_err("closed pending credential replacement must not replay");

    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_ordinary_replacement_rejects_same_authority_factor_collapse()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
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
        .expect("message-signature lifecycle method plugin");
    let subject_id = id("pending-replacement-collapse-subject");
    let target_credential_id = id("pending-replacement-collapse-password");
    let second_factor_credential_id = id("pending-replacement-collapse-totp");
    let pending_action_id = id("pending-replacement-collapse-action");
    let shared_reset_authority = id("pending-replacement-collapse-shared-authority");
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
                    second_factor_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("second-factor credential metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_reset_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    second_factor_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_reset_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[credential_instance_lifecycle_evidence(
                "pending-replacement-collapse-password",
                [id("pending-replacement-collapse-password-authority")],
            )],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");
    let revocation_cutoff_before_replacement =
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await;
    let security_notice_count_before_replacement =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"replacement-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        )
        .await
        .expect_err("same-authority pending ordinary replacement must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after replacement",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "failed pending replacement posture check must not commit method-owned verifier state"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        1,
        "failed pending replacement posture check must leave the pending action open"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed pending replacement posture check must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            pool,
            store_config,
            &second_factor_credential_id,
        )
        .await,
        CredentialLifecycleState::Active,
        "failed pending replacement posture check must leave the second-factor credential active"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        2,
        "failed pending replacement posture check must not create a successor credential row"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_replacement,
        "failed pending replacement posture check must not schedule a security notice"
    );
    assert_eq!(
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await,
        revocation_cutoff_before_replacement,
        "failed pending replacement posture check must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_second_factor_replacement_rejects_same_authority_factor_collapse()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
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
        .expect("shared-secret lifecycle method plugin");
    let subject_id = id("pending-second-factor-replacement-collapse-subject");
    let target_credential_id = id("pending-second-factor-replacement-collapse-totp");
    let ordinary_credential_id = id("pending-second-factor-replacement-collapse-password");
    let pending_action_id = id("pending-second-factor-replacement-collapse-action");
    let shared_reset_authority = id("pending-second-factor-replacement-collapse-shared-authority");
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
                    "totp",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("target second-factor credential metadata"),
                CredentialInstanceMetadata::new(
                    ordinary_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("ordinary credential metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_reset_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    ordinary_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    shared_reset_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[credential_instance_lifecycle_evidence(
                "pending-second-factor-replacement-collapse-totp",
                [id(
                    "pending-second-factor-replacement-collapse-totp-authority",
                )],
            )],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");
    let revocation_cutoff_before_replacement =
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await;
    let security_notice_count_before_replacement =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"replacement-totp-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        )
        .await
        .expect_err("same-authority pending second-factor replacement must fail");

    match error {
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            error,
        ) => {
            assert_precondition_failed(
                &error,
                "subject does not retain required credential posture after replacement",
            );
        }
        other => panic!("expected posture precondition failure, got {other:?}"),
    }
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        0,
        "failed pending second-factor replacement posture check must not commit method-owned verifier state"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        1,
        "failed pending second-factor replacement posture check must leave the pending action open"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed pending second-factor replacement posture check must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &ordinary_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed pending second-factor replacement posture check must leave the ordinary credential active"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        2,
        "failed pending second-factor replacement posture check must not create a successor credential row"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_replacement,
        "failed pending second-factor replacement posture check must not schedule a security notice"
    );
    assert_eq!(
        fetch_optional_subject_revocation_cutoff_for_runtime_test(pool, store_config, &subject_id)
            .await,
        revocation_cutoff_before_replacement,
        "failed pending second-factor replacement posture check must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_regeneration_builds_method_work_internally() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
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
        .expect("message-signature lifecycle method plugin");
    let subject_id = id("pending-regeneration-subject");
    let target_credential_id = id("pending-regeneration-password-credential");
    let pending_action_id = id("pending-regeneration-action");
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
                CredentialLifecycleAction::Regenerate,
                id("pending-regeneration-recovery-authority"),
                RecoveryAuthorityTiming::Delayed,
            )],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Regenerate,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending regeneration action")],
        )
        .await
        .expect("seed pending regeneration action");

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: Some(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"regenerated-verifier".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        )
        .await
        .expect("execute mature pending credential regeneration");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Regenerate,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.close_pending_credential_lifecycle_action",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mature pending credential regeneration execution must stay inside one bounded pending-action load, method-work, pending closure, auth-state revocation, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "pending regeneration method work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "regeneration execution must preserve the target credential metadata state"
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
            CredentialLifecycleAction::Regenerate,
            id("pending-regeneration-recovery-authority"),
            RecoveryAuthorityTiming::Delayed,
        )],
        "regeneration execution must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Regenerate,
        )
        .await,
        0,
        "regeneration execution must close the pending action"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(250),
        "regeneration execution must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_credential_removal_is_core_owned() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-removal-subject");
    let target_credential_id = id("pending-removal-totp-credential");
    let survivor_credential_id = id("pending-removal-totp-survivor");
    let pending_action_id = id("pending-removal-action");
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
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("survivor credential metadata"),
            ],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending removal action")],
        )
        .await
        .expect("seed pending removal action");

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_mature_pending_credential_lifecycle_action_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                method_payload: None,
            },
        )
        .await
        .expect("execute mature pending credential removal");

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
            "auth_core.mutation.close_pending_credential_lifecycle_action",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.mutation.set_credential_lifecycle_state",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "mature pending credential removal execution must stay inside one bounded pending-action load, posture guard, pending closure, target revocation, auth-state revocation, and commit",
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Revoked,
        "removal execution must revoke the target credential metadata"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &survivor_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "pending removal execution must leave the independent survivor active"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Remove,
        )
        .await,
        0,
        "removal execution must close the pending action"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(250),
        "removal execution must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_replacement_cancellation_closes_open_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-replacement-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-replacement-cancel-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("pending-replacement-cancel-credential");
    let pending_action_id = id("pending-replacement-cancel-action");
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
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(80),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending credential replacement");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.pending_credential_lifecycle_action",
            "auth_core.load.credential_instance_metadata",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.pending_credential_lifecycle_action_still_cancellable_for_target",
            "auth_core.mutation.close_pending_credential_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated pending credential replacement cancellation must stay inside one live-session load, pending-action load, target guard, pending closure, audit, notice, and commit",
    );

    assert_eq!(
        execution.outcome(),
        &Outcome::NonResetPendingCredentialLifecycleActionCancelled(
            NonResetPendingCredentialLifecycleActionCancellationOutcome {
                subject_id,
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Replace,
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        0,
        "cancellation must close the pending replacement action"
    );

    let replay_error = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(90),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending credential replacement cancellation must not replay");

    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotCancellable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_lifecycle_cancellation_requires_fresh_step_up_before_pending_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-pending-replacement-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-pending-replacement-cancel-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("stale-step-up-pending-replacement-cancel-credential");
    let pending_action_id = id("stale-step-up-pending-replacement-cancel-action");
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
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed credential metadata");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id,
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending replacement action")],
        )
        .await
        .expect("seed pending replacement action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("stale lifecycle cancellation returns step-up outcome");

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
            .any(|record| record.label == "auth_core.load.pending_credential_lifecycle_action"),
        "stale credential lifecycle cancellation must not load pending action state; observed database operations: {observed:?}"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        1,
        "stale cancellation must leave the pending replacement action open"
    );

    harness.drop_schema().await;
}
