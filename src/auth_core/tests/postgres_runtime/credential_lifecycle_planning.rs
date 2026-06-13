use super::*;

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_planning_builds_lifecycle_context_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-reset-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-reset-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-reset-plan-password");
    let session_authority = id("authenticated-reset-plan-session-authority");
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
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan authenticated credential reset");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
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
            "auth_core.mutation.record_credential_lifecycle_action_authorized",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated credential reset planning must stay inside one bounded lifecycle load and commit",
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential reset planning must atomically schedule an authorization notice"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        0,
        "immediate reset planning must not create a pending action"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_planning_requires_fresh_step_up_before_lifecycle_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-reset-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-reset-plan-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-reset-plan-target"),
            },
        )
        .await
        .expect("stale lifecycle reset planning returns step-up outcome");

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
        "stale reset planning must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_replacement_planning_builds_lifecycle_context_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-replacement-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-replacement-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-replacement-plan-password");
    let session_authority = id("authenticated-replacement-plan-session-authority");
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
    let revocation_cutoff_before_planning =
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await;

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_replacement_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan authenticated credential replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialReplacementPlanned(CredentialReplacementOutcome::AuthorizedImmediate {
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
        "authenticated credential replacement planning must stay inside one bounded lifecycle load and commit",
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "credential replacement planning must atomically schedule an authorization notice"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        revocation_cutoff_before_planning,
        "credential replacement planning must not revoke auth state before replacement execution"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_replacement_planning_requires_fresh_step_up_before_lifecycle_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-replacement-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-replacement-plan-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_credential_replacement_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: id("stale-step-up-replacement-plan-target"),
            },
        )
        .await
        .expect("stale lifecycle replacement planning returns step-up outcome");

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
        "stale replacement planning must not load target credential lifecycle state; observed database operations: {observed:?}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_credential_reset_policy_role_is_loaded_metadata_not_credential_kind() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
        None,
        true,
        None,
        None,
        TestActiveMethodVerificationMode::BeforeStateLoad,
        FirstPartyMethodSelection::default(),
        config_with_divergent_credential_reset_role_policies(),
        None,
    )
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("reset-role-metadata-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "reset-role-metadata-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let message_signature_second_factor_id = id("message-signature-second-factor");
    let totp_ordinary_id = id("totp-ordinary-reset-role");
    let session_authority = id("reset-role-metadata-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    message_signature_second_factor_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("message-signature second-factor metadata"),
                CredentialInstanceMetadata::new(
                    totp_ordinary_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    "totp_app",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("TOTP ordinary metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    message_signature_second_factor_id.clone(),
                    CredentialLifecycleAction::Reset,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    totp_ordinary_id.clone(),
                    CredentialLifecycleAction::Reset,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
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

    let second_factor_execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(60),
                target_credential_instance_id: message_signature_second_factor_id.clone(),
            },
        )
        .await
        .expect("plan second-factor credential reset");
    let second_factor_pending_action_id = match second_factor_execution.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: actual_subject_id,
            target_credential_instance_id,
            pending_action_id,
            earliest_execute_at,
            expires_at,
        }) => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(
                target_credential_instance_id,
                &message_signature_second_factor_id
            );
            assert_eq!(earliest_execute_at, &at(360));
            assert_eq!(expires_at, &at(560));
            pending_action_id.clone()
        }
        outcome => panic!("expected second-factor reset to become delayed, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &second_factor_pending_action_id,
        )
        .await,
        1,
        "second-factor role must select the delayed second-factor reset policy"
    );

    let ordinary_execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(61),
                target_credential_instance_id: totp_ordinary_id.clone(),
            },
        )
        .await
        .expect("plan ordinary credential reset");
    assert_eq!(
        ordinary_execution.outcome(),
        &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
            subject_id,
            target_credential_instance_id: totp_ordinary_id,
        }),
        "ordinary role must not become second-factor reset merely because the credential kind is TOTP-shaped"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_credential_reset_policy_role_selects_freshness_requirement() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
        None,
        true,
        None,
        None,
        TestActiveMethodVerificationMode::BeforeStateLoad,
        FirstPartyMethodSelection::default(),
        config_with_divergent_credential_reset_role_policies(),
        None,
    )
    .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("reset-role-freshness-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "reset-role-freshness-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let ordinary_credential_id = id("ordinary-reset-freshness-target");
    let second_factor_credential_id = id("second-factor-reset-freshness-target");
    let session_authority = id("reset-role-freshness-session-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    ordinary_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("ordinary credential metadata"),
                CredentialInstanceMetadata::new(
                    second_factor_credential_id.clone(),
                    subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("second-factor credential metadata"),
            ],
            &[
                CredentialRecoveryAuthority::new(
                    ordinary_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    second_factor_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    session_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(20),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let second_factor_execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: second_factor_credential_id,
            },
        )
        .await
        .expect("second-factor reset planning should require fresh step-up");
    assert_eq!(
        second_factor_execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id.clone(),
            subject_id: subject_id.clone(),
        },
        "second-factor role must select stricter reset freshness even when credential kind is unchanged"
    );

    let ordinary_execution = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: ordinary_credential_id.clone(),
            },
        )
        .await
        .expect("ordinary reset planning should not require fresh step-up");
    assert_eq!(
        ordinary_execution.outcome(),
        &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
            subject_id,
            target_credential_instance_id: ordinary_credential_id,
        })
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_reset_planning_generates_pending_action_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-delayed-reset-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-delayed-reset-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-delayed-reset-password");
    let session_authority = id("authenticated-delayed-reset-session-authority");
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
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan delayed authenticated credential reset");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
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
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "runtime-generated pending action id must be committed"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_credential_replacement_planning_generates_pending_action_internally()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-delayed-replacement-plan-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-delayed-replacement-plan-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-delayed-replacement-password");
    let session_authority = id("authenticated-delayed-replacement-session-authority");
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
        .execute_authenticated_credential_replacement_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan delayed authenticated credential replacement");

    let pending_action_id = match execution.outcome() {
        Outcome::CredentialReplacementPlanned(
            CredentialReplacementOutcome::PendingActionCreated {
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
        outcome => panic!("expected pending replacement action, got {outcome:?}"),
    };
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        1,
        "runtime-generated pending replacement action id must be committed"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_reschedules_reset_after_expiry_with_quiet_cleanup() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-expired-reset-reschedule-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-expired-reset-reschedule-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-expired-reset-password");
    let session_authority = id("authenticated-expired-reset-session-authority");
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
    let expired_pending_action_id: PendingCredentialLifecycleActionId =
        id("authenticated-expired-reset-pending-action");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[PendingCredentialLifecycleActionRecord::new_open(
                expired_pending_action_id.clone(),
                subject_id.clone(),
                target_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                at(80),
                at(82),
                at(83),
            )
            .expect("expired pending reset action")],
        )
        .await
        .expect("seed expired pending reset action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &expired_pending_action_id,
        )
        .await,
        1,
        "first pending reset starts open"
    );

    let replacement_planned = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(84),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("expired pending reset must not block replacement scheduling");
    let replacement_pending_action_id = match replacement_planned.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            pending_action_id,
            ..
        }) => pending_action_id.clone(),
        outcome => panic!("expected replacement pending reset action, got {outcome:?}"),
    };

    assert_eq!(
        pending_credential_reset_closed_at_for_pending_action(
            pool,
            store_config,
            &expired_pending_action_id,
        )
        .await,
        Some(84),
        "expired pending reset cleanup is a quiet close at transition time"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &replacement_pending_action_id,
        )
        .await,
        1,
        "replacement pending reset remains open"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_reset_cancellation_closes_open_action() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("authenticated-reset-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "authenticated-reset-cancel-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("authenticated-reset-cancel-password");
    let session_authority = id("authenticated-reset-cancel-session-authority");
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

    let planned = runtime
        .execute_authenticated_credential_reset_planning_from_headers(
            &headers,
            PlanAuthenticatedCredentialResetInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
        .await
        .expect("plan delayed authenticated credential reset");
    let pending_action_id = match planned.outcome() {
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            pending_action_id,
            ..
        }) => pending_action_id.clone(),
        outcome => panic!("expected pending reset action, got {outcome:?}"),
    };
    harness.database_operation_observer.clear();

    let cancellation = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending credential reset");
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
        "authenticated pending credential reset cancellation must stay inside one live-session load, pending-action load, target guard, pending closure, audit, notice, and commit",
    );

    assert_eq!(
        cancellation.outcome(),
        &Outcome::CredentialResetPendingActionCancelled(CredentialResetCancellationOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            pending_action_id: pending_action_id.clone(),
        })
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        0,
        "cancellation must close the pending reset action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        2,
        "scheduling and cancellation must both commit security notices"
    );

    let replay_error = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(95),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending reset cancellation must not replay");

    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingCredentialLifecycleActionNotCancellable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_reset_cancellation_requires_fresh_step_up_before_pending_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-reset-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-reset-cancel-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let target_credential_id = id("stale-step-up-reset-cancel-password");
    let pending_action_id = id("stale-step-up-reset-cancel-action");
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
                CredentialLifecycleAction::Reset,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending reset action")],
        )
        .await
        .expect("seed pending reset action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("stale reset cancellation returns step-up outcome");

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
        "stale reset cancellation must not load pending action state; observed database operations: {observed:?}"
    );
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "stale cancellation must leave the pending reset action open"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_credential_cancellations_reject_wrong_subject_session()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let actor_subject_id = id("pending-credential-cancel-wrong-subject-actor");
    let owner_subject_id = id("pending-credential-cancel-wrong-subject-owner");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-credential-cancel-wrong-subject-bootstrap",
        50,
        actor_subject_id.clone(),
        false,
    )
    .await;
    let reset_target_credential_id = id("pending-reset-cancel-wrong-subject-target");
    let reset_pending_action_id = id("pending-reset-cancel-wrong-subject-action");
    let replacement_target_credential_id = id("pending-replace-cancel-wrong-subject-target");
    let replacement_pending_action_id = id("pending-replace-cancel-wrong-subject-action");
    let removal_target_credential_id = id("pending-remove-cancel-wrong-subject-target");
    let removal_pending_action_id = id("pending-remove-cancel-wrong-subject-action");
    let regeneration_target_credential_id = id("pending-regenerate-cancel-wrong-subject-target");
    let regeneration_pending_action_id = id("pending-regenerate-cancel-wrong-subject-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.pending-wrong-subject-cancel.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[
                CredentialInstanceMetadata::new(
                    reset_target_credential_id.clone(),
                    owner_subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("reset target credential metadata"),
                CredentialInstanceMetadata::new(
                    replacement_target_credential_id.clone(),
                    owner_subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("replacement target credential metadata"),
                CredentialInstanceMetadata::new(
                    removal_target_credential_id.clone(),
                    owner_subject_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("removal target credential metadata"),
                CredentialInstanceMetadata::new(
                    regeneration_target_credential_id.clone(),
                    owner_subject_id.clone(),
                    CredentialInstanceKind::RecoveryCodeCredential,
                    "recovery_code",
                    CredentialResetPolicyRole::SecondFactorCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("regeneration target credential metadata"),
            ],
            &[],
            &[],
            at(50),
        )
        .await
        .expect("seed wrong-subject pending cancellation credentials");
    seed_store
        .store_pending_credential_lifecycle_actions_for_test(
            pool,
            &[
                PendingCredentialLifecycleActionRecord::new_open(
                    reset_pending_action_id.clone(),
                    owner_subject_id.clone(),
                    reset_target_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending reset action"),
                PendingCredentialLifecycleActionRecord::new_open(
                    replacement_pending_action_id.clone(),
                    owner_subject_id.clone(),
                    replacement_target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending replacement action"),
                PendingCredentialLifecycleActionRecord::new_open(
                    removal_pending_action_id.clone(),
                    owner_subject_id.clone(),
                    removal_target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending removal action"),
                PendingCredentialLifecycleActionRecord::new_open(
                    regeneration_pending_action_id.clone(),
                    owner_subject_id.clone(),
                    regeneration_target_credential_id.clone(),
                    CredentialLifecycleAction::Regenerate,
                    at(100),
                    at(200),
                    at(300),
                )
                .expect("pending regeneration action"),
            ],
        )
        .await
        .expect("seed wrong-subject pending cancellation actions");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let reset_error = runtime
        .execute_authenticated_pending_credential_reset_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialResetInput {
                now: at(90),
                pending_action_id: reset_pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending credential reset");
    assert!(matches!(
        reset_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));

    let replacement_error = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(90),
                pending_action_id: replacement_pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending credential replacement");
    assert!(matches!(
        replacement_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));

    let removal_error = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(90),
                pending_action_id: removal_pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending credential removal");
    assert!(matches!(
        removal_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));

    let regeneration_error = runtime
        .execute_authenticated_pending_credential_lifecycle_action_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingCredentialLifecycleActionInput {
                now: at(90),
                pending_action_id: regeneration_pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending credential regeneration");
    assert!(matches!(
        regeneration_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));

    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &reset_pending_action_id,
        )
        .await,
        1,
        "wrong-subject reset cancellation must leave the pending reset open"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &replacement_pending_action_id,
            CredentialLifecycleAction::Replace,
        )
        .await,
        1,
        "wrong-subject replacement cancellation must leave the pending replacement open"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &removal_pending_action_id,
            CredentialLifecycleAction::Remove,
        )
        .await,
        1,
        "wrong-subject removal cancellation must leave the pending removal open"
    );
    assert_eq!(
        count_open_pending_credential_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &regeneration_pending_action_id,
            CredentialLifecycleAction::Regenerate,
        )
        .await,
        1,
        "wrong-subject regeneration cancellation must leave the pending regeneration open"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &owner_subject_id)
            .await,
        0,
        "wrong-subject pending cancellations must not schedule notices for the action owner"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &actor_subject_id)
            .await,
        0,
        "wrong-subject pending cancellations must not schedule notices for the actor"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            pool,
            store_config,
            &reset_target_credential_id
        )
        .await,
        CredentialLifecycleState::Active,
        "wrong-subject reset cancellation must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            pool,
            store_config,
            &replacement_target_credential_id,
        )
        .await,
        CredentialLifecycleState::Active,
        "wrong-subject replacement cancellation must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            pool,
            store_config,
            &removal_target_credential_id,
        )
        .await,
        CredentialLifecycleState::Active,
        "wrong-subject removal cancellation must leave the target credential active"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(
            pool,
            store_config,
            &regeneration_target_credential_id,
        )
        .await,
        CredentialLifecycleState::Active,
        "wrong-subject regeneration cancellation must leave the target credential active"
    );

    harness.drop_schema().await;
}
