use super::*;

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_builds_method_work_internally() {
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
    let subject_id = id("authenticated-reset-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-reset-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-reset-password-credential");
    let session_authority = id("authenticated-reset-session-authority");
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
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    b"new-authenticated-password-verifier".as_slice(),
                )
                .expect("reset payload"),
            },
        )
        .await
        .expect("execute authenticated credential reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: None,
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
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential reset execution must stay inside one bounded lifecycle load, method-work, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "method-owned verifier work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "credential reset must preserve the target credential metadata state"
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
            session_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        "credential reset must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential reset execution must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "credential reset execution must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_replacement_builds_method_work_internally() {
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
    let subject_id = id("authenticated-replacement-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-replacement-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-replacement-password-credential");
    let session_authority = id("authenticated-replacement-session-authority");
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
                    "authenticated-replacement-password-credential",
                    [id("authenticated-replacement-password-authority")],
                ),
            ],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_replacement_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    b"replacement-password-verifier".as_slice(),
                )
                .expect("replacement payload"),
            },
        )
        .await
        .expect("execute authenticated credential replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
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
            "auth_core.load.lifecycle_authority_evidence",
            "auth_core.precondition.active_subject_credential_instances_for_update",
            "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.insert_credential_instance_metadata",
            "auth_core.mutation.insert_credential_recovery_authority",
            "auth_core.mutation.insert_lifecycle_authority_source",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.mutation.set_credential_lifecycle_state",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential replacement execution must stay inside one bounded lifecycle load, posture guard, successor creation, method-work, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "credential replacement method work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Superseded,
        "credential replacement must supersede the old target credential"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        1,
        "credential replacement must create one active core-visible successor"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential replacement execution must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "credential replacement execution must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_ordinary_replacement_rejects_same_authority_factor_collapse()
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
    let subject_id = id("authenticated-replacement-collapse-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-replacement-collapse-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-replacement-collapse-password");
    let second_factor_credential_id = id("authenticated-replacement-collapse-totp");
    let session_authority = id("authenticated-replacement-collapse-session-authority");
    let shared_reset_authority = id("authenticated-replacement-collapse-shared-authority");
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
                    CredentialLifecycleAction::Replace,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
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
            &[
                LifecycleAuthorityEvidence::authenticated_session(
                    issued_auth.session_id.clone(),
                    [session_authority],
                )
                .expect("session lifecycle evidence"),
                credential_instance_lifecycle_evidence(
                    "authenticated-replacement-collapse-password",
                    [id("authenticated-replacement-collapse-password-authority")],
                ),
            ],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_replacement =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let security_notice_count_before_replacement =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_replacement_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    b"replacement-password-verifier".as_slice(),
                )
                .expect("replacement payload"),
            },
        )
        .await
        .expect_err("same-authority ordinary replacement must fail");

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
        "failed replacement posture check must not commit method-owned verifier state"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed replacement posture check must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            pool,
            store_config,
            &second_factor_credential_id,
        )
        .await,
        CredentialLifecycleState::Active,
        "failed replacement posture check must leave the second-factor credential active"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        2,
        "failed replacement posture check must not create a successor credential row"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_replacement,
        "failed replacement posture check must not schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_replacement,
        "failed replacement posture check must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_second_factor_replacement_rejects_same_authority_factor_collapse()
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
        .expect("shared-secret replacement method plugin");
    let subject_id = id("authenticated-second-factor-replacement-collapse-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-second-factor-replacement-collapse-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-second-factor-replacement-collapse-totp");
    let ordinary_credential_id = id("authenticated-second-factor-replacement-collapse-password");
    let session_authority =
        id("authenticated-second-factor-replacement-collapse-session-authority");
    let shared_reset_authority =
        id("authenticated-second-factor-replacement-collapse-shared-authority");
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
                    CredentialLifecycleAction::Replace,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
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
            &[
                LifecycleAuthorityEvidence::authenticated_session(
                    issued_auth.session_id.clone(),
                    [session_authority],
                )
                .expect("session lifecycle evidence"),
                credential_instance_lifecycle_evidence(
                    "authenticated-second-factor-replacement-collapse-totp",
                    [id(
                        "authenticated-second-factor-replacement-collapse-totp-authority",
                    )],
                ),
            ],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let revocation_cutoff_before_replacement =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;
    let security_notice_count_before_replacement =
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await;

    let error = runtime
        .execute_authenticated_credential_replacement_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    b"replacement-totp-verifier".as_slice(),
                )
                .expect("replacement payload"),
            },
        )
        .await
        .expect_err("same-authority second-factor replacement must fail");

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
        "failed second-factor replacement posture check must not commit method-owned verifier state"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed second-factor replacement posture check must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &ordinary_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "failed second-factor replacement posture check must leave the ordinary credential active"
    );
    assert_eq!(
        count_active_credential_instances_for_subject_for_runtime_test(
            pool,
            store_config,
            &subject_id,
        )
        .await,
        2,
        "failed second-factor replacement posture check must not create a successor credential row"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        security_notice_count_before_replacement,
        "failed second-factor replacement posture check must not schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_replacement,
        "failed second-factor replacement posture check must not revoke subject auth state"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_rotation_builds_method_work_internally() {
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
    let subject_id = id("authenticated-rotation-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-rotation-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-rotation-password-credential");
    let session_authority = id("authenticated-rotation-session-authority");
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
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    b"rotated-password-verifier".as_slice(),
                )
                .expect("rotation payload"),
            },
        )
        .await
        .expect("execute authenticated credential rotation");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRotated(CredentialRotationExecutionOutcome {
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
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.test_method_commit.precondition.otp_state_absent",
            "auth_core.mutation.record_credential_lifecycle_action_executed",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.test_method_commit.mutation.store_otp_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential rotation execution must stay inside one bounded lifecycle load, method-work, auth-state revocation, and commit",
    );
    assert_eq!(
        method_plugin.count_state_rows(pool).await,
        1,
        "credential rotation method work must be committed through the registered plugin"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "credential rotation must preserve the target credential lifecycle state"
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
            session_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        "credential rotation must preserve the target recovery-authority graph"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential rotation execution must atomically schedule a security notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "credential rotation execution must revoke existing subject auth state"
    );

    harness.drop_schema().await;
}
