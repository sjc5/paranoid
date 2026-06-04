use super::*;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::db::{
    BootstrapConfig, PgIdentifier, PgSchemaName, Pool, PoolConfig, pooler_safe_query,
    pooler_safe_query_scalar, unparameterized_simple_query,
};
use secrecy::SecretString;

static AUTH_POSTGRES_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn default_auth_store_config_uses_db_bootstrap_schema_and_ledger() {
    let bootstrap_config = BootstrapConfig::default();
    let store_config =
        super::super::postgres_store::PostgresAuthStoreConfig::for_db_bootstrap_config(
            &bootstrap_config,
        )
        .expect("auth store config");

    assert_eq!(
        store_config
            .schema_ledger_table_name()
            .expect("schema ledger table"),
        bootstrap_config.table_names().schema_ledger
    );

    let session_table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    assert_eq!(session_table.schema(), Some(bootstrap_config.schema_name()));
    assert_eq!(session_table.table().as_str(), "auth_sessions");
    assert!(
        !session_table.table().as_str().starts_with("__paranoid_"),
        "dedicated-schema auth tables must not repeat the global Paranoid namespace prefix"
    );

    assert_eq!(
        super::super::postgres_store::PostgresAuthStoreConfig::default(),
        store_config
    );
    assert!(
        super::super::postgres_store::schema_instance_key(&store_config).len() <= 1024,
        "auth schema ledger instance key must fit the DB schema-ledger domain"
    );
}

#[test]
fn postgres_store_persists_stable_wire_mappings() {
    assert_eq!(
        super::super::postgres_store::i32_from_proof_family(ProofFamily::OutOfBandCode),
        1
    );
    assert_eq!(
        super::super::postgres_store::proof_family_from_i32(7).expect("recovery code"),
        ProofFamily::RecoveryCode
    );
    assert!(
        super::super::postgres_store::proof_family_from_i32(0).is_err(),
        "invalid stored proof-family ids must not be accepted"
    );

    assert_eq!(
        super::super::postgres_store::i32_from_proof_use(ProofUse::BindSubjectToActiveProofAttempt),
        1
    );
    assert_eq!(
        super::super::postgres_store::proof_use_from_i32(7).expect("recover or replace"),
        ProofUse::RecoverOrReplaceCredential
    );
    assert!(
        super::super::postgres_store::proof_use_from_i32(8).is_err(),
        "invalid stored proof-use ids must not be accepted"
    );

    assert_eq!(
        super::super::postgres_store::i32_from_verified_proof_source_kind(
            VerifiedProofSourceKind::CredentialInstance,
        ),
        1
    );
    assert_eq!(
        super::super::postgres_store::verified_proof_source_kind_from_i32(2)
            .expect("out-of-band identifier source"),
        VerifiedProofSourceKind::OutOfBandIdentifier
    );
    assert_eq!(
        super::super::postgres_store::verified_proof_source_kind_from_i32(3)
            .expect("external authority source"),
        VerifiedProofSourceKind::ExternalAuthority
    );
    assert!(
        super::super::postgres_store::verified_proof_source_kind_from_i32(4).is_err(),
        "invalid stored proof-source kind ids must not be accepted"
    );

    assert_eq!(
        super::super::postgres_store::i32_from_credential_instance_kind(
            CredentialInstanceKind::SharedSecretOtpVerifier,
        ),
        2
    );
    assert_eq!(
        super::super::postgres_store::credential_instance_kind_from_i32(5)
            .expect("trusted device credential kind"),
        CredentialInstanceKind::TrustedDeviceCredential
    );

    assert_eq!(
        super::super::postgres_store::i32_from_credential_lifecycle_state(
            CredentialLifecycleState::AdminSuspended,
        ),
        10
    );
    assert_eq!(
        super::super::postgres_store::credential_lifecycle_state_from_i32(1)
            .expect("active lifecycle state"),
        CredentialLifecycleState::Active
    );

    assert_eq!(
        super::super::postgres_store::i32_from_credential_lifecycle_action(
            CredentialLifecycleAction::Reset,
        ),
        2
    );
    assert_eq!(
        super::super::postgres_store::credential_lifecycle_action_from_i32(7)
            .expect("recover subject access action"),
        CredentialLifecycleAction::RecoverSubjectAccess
    );

    assert_eq!(
        super::super::postgres_store::i32_from_recovery_authority_timing(
            RecoveryAuthorityTiming::Delayed,
        ),
        2
    );
    assert_eq!(
        super::super::postgres_store::recovery_authority_timing_from_i32(1)
            .expect("immediate authority timing"),
        RecoveryAuthorityTiming::Immediate
    );

    assert_eq!(
        super::super::postgres_store::i32_from_lifecycle_authority_source_kind(
            LifecycleAuthoritySourceKind::AuthenticatedSession,
        ),
        4
    );
    assert_eq!(
        super::super::postgres_store::lifecycle_authority_source_kind_from_i32(5)
            .expect("admin support source kind"),
        LifecycleAuthoritySourceKind::AdminSupportIntervention
    );

    assert_eq!(
        super::super::postgres_store::i32_from_security_notification_kind(
            SecurityNotificationKind::CredentialResetAuthorized,
        ),
        2
    );
    assert_eq!(
        super::super::postgres_store::i32_from_security_notification_kind(
            SecurityNotificationKind::CredentialResetPendingActionScheduled,
        ),
        3
    );
    assert_eq!(
        super::super::postgres_store::i32_from_security_notification_kind(
            SecurityNotificationKind::CredentialResetExecuted,
        ),
        4
    );
}

#[test]
fn credential_secret_macs_are_bound_to_storage_target() {
    let keyset = test_keyset("tests.auth.postgres-store.secret-macs.v1");
    let secret = AuthCredentialSecret::try_from(b"session-secret".as_slice()).expect("secret");
    let session_one_target = CoreStorageTarget::SessionCredentialSecret {
        session_id: id("session-one"),
        secret_version: version(1),
    };
    let session_two_target = CoreStorageTarget::SessionCredentialSecret {
        session_id: id("session-two"),
        secret_version: version(1),
    };
    let mac = secret
        .to_mac(
            &keyset,
            &super::super::postgres_store::credential_secret_mac_context(&session_one_target),
        )
        .expect("mac");

    assert!(mac.verify(
        &keyset,
        secret.expose_secret(),
        &super::super::postgres_store::credential_secret_mac_context(&session_one_target),
    ));
    assert!(
        !mac.verify(
            &keyset,
            secret.expose_secret(),
            &super::super::postgres_store::credential_secret_mac_context(&session_two_target),
        ),
        "credential MACs must not verify when copied to a different target"
    );
}

#[tokio::test]
async fn postgres_store_migrates_and_validates_schema_when_database_is_available() {
    let database_url = std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .expect("auth Postgres store test requires TEST_DSN or PARANOID_TEST_DATABASE_URL");

    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let schema_name = unique_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let create_schema = format!("CREATE SCHEMA {}", schema_name.quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(create_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("create auth test schema");

    let store_config = super::super::postgres_store::PostgresAuthStoreConfig::new(
        Some(schema.clone()),
        PgIdentifier::new("__paranoid_auth_").expect("table prefix"),
    )
    .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-store.credentials.v1"),
    );

    store
        .migrate_schema(&pool)
        .await
        .expect("migrate auth schema");
    store
        .validate_schema(&pool)
        .await
        .expect("validate migrated auth schema");

    let mut remove_ledger_row_tx = pool
        .begin_transaction()
        .await
        .expect("begin remove schema ledger row transaction");
    let remove_ledger_row_statement = format!(
        "DELETE FROM {} WHERE component = $1 AND instance_key = $2",
        store_config
            .schema_ledger_table_name()
            .expect("auth schema ledger table name")
            .quoted()
    );
    pooler_safe_query(sqlx::AssertSqlSafe(remove_ledger_row_statement.as_str()))
        .bind("auth_core")
        .bind(super::super::postgres_store::schema_instance_key(
            &store_config,
        ))
        .execute(remove_ledger_row_tx.sqlx_transaction().as_mut())
        .await
        .expect("remove schema ledger row");
    remove_ledger_row_tx
        .commit()
        .await
        .expect("commit remove schema ledger row transaction");
    store
        .validate_schema(&pool)
        .await
        .expect_err("auth schema validation must require its schema ledger row");

    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth test schema");
}

#[tokio::test]
async fn postgres_store_loads_persisted_recovery_authority_policy_when_database_is_available() {
    let database_url = std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .expect("auth Postgres store test requires TEST_DSN or PARANOID_TEST_DATABASE_URL");

    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let schema_name = unique_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let create_schema = format!("CREATE SCHEMA {}", schema_name.quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(create_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("create auth test schema");

    let store_config = super::super::postgres_store::PostgresAuthStoreConfig::new(
        Some(schema.clone()),
        PgIdentifier::new("__paranoid_auth_").expect("table prefix"),
    )
    .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config,
        test_keyset("tests.auth.postgres-store.lifecycle-policy.v1"),
    );
    store
        .migrate_schema(&pool)
        .await
        .expect("migrate auth schema");

    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let password_metadata = CredentialInstanceMetadata::new(
        password_credential_id.clone(),
        id("subject"),
        CredentialInstanceKind::MessageSignatureVerifier,
        "password_signature",
        CredentialLifecycleState::Active,
    )
    .expect("password credential metadata");
    let email_source = LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            id("primary-email"),
        ),
        [email_authority.clone()],
    )
    .expect("email lifecycle evidence");
    let device_source = LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            id("trusted-device"),
        ),
        [device_authority],
    )
    .expect("device lifecycle evidence");
    store
        .store_credential_lifecycle_metadata_for_test(
            &pool,
            &[password_metadata],
            &[CredentialRecoveryAuthority::new(
                password_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                email_authority,
                RecoveryAuthorityTiming::Immediate,
            )],
            &[email_source.clone(), device_source.clone()],
            at(10),
        )
        .await
        .expect("seed lifecycle metadata");

    let mut tx = pool.begin_transaction().await.expect("begin load tx");
    let email_only = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            &password_credential_id,
            &[email_source.source().clone()],
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        )
        .await
        .expect("load email-only decision");
    assert_eq!(
        email_only,
        Some(CredentialLifecycleActionDecision::RequiresDelayedAction),
        "email-only password reset should route to delayed action when independence is required"
    );

    let email_without_independence_required = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            &password_credential_id,
            &[email_source.source().clone()],
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        )
        .await
        .expect("load single-factor email decision");
    assert_eq!(
        email_without_independence_required,
        Some(CredentialLifecycleActionDecision::AuthorizedImmediate),
        "single-effective-factor subjects may use the configured email recovery authority directly"
    );

    let email_plus_device = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            &password_credential_id,
            &[
                email_source.source().clone(),
                device_source.source().clone(),
            ],
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        )
        .await
        .expect("load email plus device decision");
    assert_eq!(
        email_plus_device,
        Some(CredentialLifecycleActionDecision::AuthorizedImmediate),
        "email authorizes reset and trusted-device evidence prevents factor collapse"
    );

    let device_only = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            &password_credential_id,
            &[device_source.source().clone()],
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        )
        .await
        .expect("load device-only decision");
    assert_eq!(
        device_only,
        Some(CredentialLifecycleActionDecision::Rejected),
        "independent evidence alone cannot reset a target unless a configured authority authorizes the action"
    );

    let missing_target = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            &id("missing-password-credential"),
            &[email_source.source().clone()],
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        )
        .await
        .expect("load missing target decision");
    assert_eq!(missing_target, None);
    tx.rollback().await.expect("rollback load tx");

    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth test schema");
}

#[tokio::test]
async fn postgres_store_commits_credential_reset_planning_when_database_is_available() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.credential-reset.v1").await;

    let immediate_credential_id: VerifiedProofSourceId = id("password-immediate");
    let delayed_credential_id: VerifiedProofSourceId = id("password-delayed");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    store
        .store_credential_lifecycle_metadata_for_test(
            &pool,
            &[
                CredentialInstanceMetadata::new(
                    immediate_credential_id.clone(),
                    id("subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialLifecycleState::Active,
                )
                .expect("immediate credential metadata"),
                CredentialInstanceMetadata::new(
                    delayed_credential_id.clone(),
                    id("subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialLifecycleState::Active,
                )
                .expect("delayed credential metadata"),
            ],
            &[],
            &[],
            at(10),
        )
        .await
        .expect("seed credential metadata");

    let immediate_transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_lifecycle_context(
                CredentialInstanceMetadata::new(
                    immediate_credential_id.clone(),
                    id("subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialLifecycleState::Active,
                )
                .expect("immediate credential metadata"),
                [CredentialRecoveryAuthority::new(
                    immediate_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_lifecycle_evidence(
                        "primary-email",
                        [email_authority.clone()],
                    ),
                    credential_instance_lifecycle_evidence(
                        "trusted-device",
                        [device_authority.clone()],
                    ),
                ],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: None,
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("immediate reset transition");
    commit_transition_to_postgres(&pool, &store, immediate_transition).await;

    let subject_state_table = store_config
        .table_name(PostgresAuthCoreTable::SubjectAuthState)
        .expect("subject state table");
    let mut read_subject_state_tx = pool
        .begin_transaction()
        .await
        .expect("begin subject state read tx");
    let stored_subject_cutoff = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        format!(
            r#"SELECT revoke_records_created_at_or_before FROM {} WHERE subject_id = $1"#,
            subject_state_table.quoted(),
        )
        .as_str(),
    ))
    .bind(id::<SubjectId>("subject").as_bytes())
    .fetch_one(read_subject_state_tx.sqlx_transaction().as_mut())
    .await
    .expect("subject revocation cutoff");
    read_subject_state_tx
        .rollback()
        .await
        .expect("rollback subject state read tx");
    assert_eq!(
        stored_subject_cutoff, 100,
        "immediate reset with revoke policy must atomically raise subject auth revocation cutoff"
    );

    let durable_effect_table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("durable effect table");
    let authorized_notice_count = security_notification_count(
        &pool,
        &durable_effect_table,
        SecurityNotificationKind::CredentialResetAuthorized,
    )
    .await;
    assert_eq!(
        authorized_notice_count, 1,
        "immediate reset must atomically schedule a security notice"
    );

    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-reset");
    let delayed_transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(110),
            lifecycle_context: credential_lifecycle_context(
                CredentialInstanceMetadata::new(
                    delayed_credential_id.clone(),
                    id("subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialLifecycleState::Active,
                )
                .expect("delayed credential metadata"),
                [CredentialRecoveryAuthority::new(
                    delayed_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [out_of_band_identifier_lifecycle_evidence(
                    "primary-email",
                    [email_authority],
                )],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("delayed reset transition");
    commit_transition_to_postgres(&pool, &store, delayed_transition).await;

    let pending_action_table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending action table");
    let mut read_pending_tx = pool
        .begin_transaction()
        .await
        .expect("begin pending action read tx");
    let open_pending_count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        format!(
            r#"
            SELECT count(*)
            FROM {}
            WHERE pending_action_id = $1
              AND subject_id = $2
              AND target_credential_instance_id = $3
              AND lifecycle_action = $4
              AND requested_at = $5
              AND earliest_execute_at = $6
              AND expires_at = $7
              AND closed_at IS NULL
            "#,
            pending_action_table.quoted(),
        )
        .as_str(),
    ))
    .bind(pending_action_id.as_bytes())
    .bind(id::<SubjectId>("subject").as_bytes())
    .bind(delayed_credential_id.as_bytes())
    .bind(
        super::super::postgres_store::i32_from_credential_lifecycle_action(
            CredentialLifecycleAction::Reset,
        ),
    )
    .bind(110_i64)
    .bind(200_i64)
    .bind(300_i64)
    .fetch_one(read_pending_tx.sqlx_transaction().as_mut())
    .await
    .expect("pending action row count");
    read_pending_tx
        .rollback()
        .await
        .expect("rollback pending action read tx");
    assert_eq!(open_pending_count, 1);

    let pending_notice_count = security_notification_count(
        &pool,
        &durable_effect_table,
        SecurityNotificationKind::CredentialResetPendingActionScheduled,
    )
    .await;
    assert_eq!(
        pending_notice_count, 1,
        "delayed reset must atomically schedule a pending-action notice"
    );

    let duplicate_pending_transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(120),
            lifecycle_context: credential_lifecycle_context(
                CredentialInstanceMetadata::new(
                    delayed_credential_id.clone(),
                    id("subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialLifecycleState::Active,
                )
                .expect("delayed credential metadata"),
                [CredentialRecoveryAuthority::new(
                    delayed_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    id("primary-email-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [out_of_band_identifier_lifecycle_evidence(
                    "primary-email",
                    [id("primary-email-authority")],
                )],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-reset-duplicate"),
                earliest_execute_at: at(220),
                expires_at: at(320),
            }),
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("duplicate pending transition");
    let duplicate_error =
        try_commit_transition_to_postgres(&pool, &store, duplicate_pending_transition)
            .await
            .expect_err("second open pending reset must fail its commit precondition");
    assert!(matches!(
        duplicate_error,
        super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(_)
    ));

    let execution_work = AtomicCommitWork {
        preconditions: vec![
            Precondition::CredentialInstanceStillActive {
                credential_instance_id: delayed_credential_id.clone(),
                subject_id: id("subject"),
            },
            Precondition::PendingCredentialLifecycleActionStillExecutable {
                pending_action_id: pending_action_id.clone(),
                subject_id: id("subject"),
                target_credential_instance_id: delayed_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
                now: at(250),
            },
        ],
        mutations: vec![
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id: pending_action_id.clone(),
                closed_at: at(250),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: delayed_credential_id,
                action: CredentialLifecycleAction::Reset,
                executed_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ],
        audit_events: vec![AuditEvent {
            kind: AuditEventKind::CredentialResetExecuted,
            subject_id: Some(id("subject")),
            session_id: None,
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(250),
        }],
        durable_effects: vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetExecuted,
                subject_id: id("subject"),
            },
        )],
        ..AtomicCommitWork::default()
    };
    try_commit_atomic_work_to_postgres(&pool, &store, execution_work.clone())
        .await
        .expect("commit matured pending reset execution");

    let mut read_executed_pending_tx = pool
        .begin_transaction()
        .await
        .expect("begin executed pending action read tx");
    let closed_at = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        format!(
            r#"
            SELECT closed_at
            FROM {}
            WHERE pending_action_id = $1
            "#,
            pending_action_table.quoted(),
        )
        .as_str(),
    ))
    .bind(pending_action_id.as_bytes())
    .fetch_one(read_executed_pending_tx.sqlx_transaction().as_mut())
    .await
    .expect("closed pending action timestamp");
    read_executed_pending_tx
        .rollback()
        .await
        .expect("rollback executed pending action read tx");
    assert_eq!(closed_at, 250);

    let executed_notice_count = security_notification_count(
        &pool,
        &durable_effect_table,
        SecurityNotificationKind::CredentialResetExecuted,
    )
    .await;
    assert_eq!(
        executed_notice_count, 1,
        "pending reset execution must atomically schedule an execution notice"
    );

    let replay_error = try_commit_atomic_work_to_postgres(&pool, &store, execution_work)
        .await
        .expect_err("closed pending reset must not execute twice");
    assert!(matches!(
        replay_error,
        super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(_)
    ));

    drop_auth_test_schema(&pool, &schema).await;
}

fn unique_test_schema_name() -> PgIdentifier {
    let counter = AUTH_POSTGRES_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    PgIdentifier::new(format!(
        "__paranoid_auth_test_{}_{}",
        std::process::id(),
        counter
    ))
    .expect("test schema name")
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([29_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}

async fn migrated_auth_store_for_test(
    purpose: &str,
) -> (
    Pool,
    PgSchemaName,
    super::super::postgres_store::PostgresAuthStoreConfig,
    super::super::postgres_store::PostgresAuthStore,
) {
    let database_url = std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .expect("auth Postgres store test requires TEST_DSN or PARANOID_TEST_DATABASE_URL");
    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let schema_name = unique_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let create_schema = format!("CREATE SCHEMA {}", schema_name.quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(create_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("create auth test schema");
    let store_config = super::super::postgres_store::PostgresAuthStoreConfig::new(
        Some(schema.clone()),
        PgIdentifier::new("__paranoid_auth_").expect("table prefix"),
    )
    .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset(purpose),
    );
    store
        .migrate_schema(&pool)
        .await
        .expect("migrate auth schema");
    (pool, schema, store_config, store)
}

async fn commit_transition_to_postgres(
    pool: &Pool,
    store: &super::super::postgres_store::PostgresAuthStore,
    transition: Transition,
) {
    try_commit_transition_to_postgres(pool, store, transition)
        .await
        .expect("commit transition");
}

async fn try_commit_transition_to_postgres(
    pool: &Pool,
    store: &super::super::postgres_store::PostgresAuthStore,
    transition: Transition,
) -> Result<(), super::super::postgres_store::PostgresAuthStoreError> {
    let (atomic_work, response_effects) = transition
        .commit_plan
        .try_into_validated_atomic_work_and_response_effects()
        .expect("valid atomic work");
    assert!(
        response_effects.is_empty(),
        "credential reset planning should not emit response-local effects"
    );
    let mut tx = pool.begin_transaction().await.expect("begin commit tx");
    let request = AtomicCommitRequest::for_atomic_work(&atomic_work).expect("commit request");
    let commit_result = store
        .commit_atomic_work_in_current_transaction(&mut tx, request)
        .await;
    match commit_result {
        Ok(_) => {
            tx.commit().await.expect("commit auth transition");
            Ok(())
        }
        Err(error) => {
            tx.rollback().await.expect("rollback auth transition");
            Err(error)
        }
    }
}

async fn try_commit_atomic_work_to_postgres(
    pool: &Pool,
    store: &super::super::postgres_store::PostgresAuthStore,
    atomic_work: AtomicCommitWork,
) -> Result<(), super::super::postgres_store::PostgresAuthStoreError> {
    let mut tx = pool.begin_transaction().await.expect("begin commit tx");
    let request = AtomicCommitRequest::for_atomic_work(&atomic_work).expect("commit request");
    let commit_result = store
        .commit_atomic_work_in_current_transaction(&mut tx, request)
        .await;
    match commit_result {
        Ok(_) => {
            tx.commit().await.expect("commit auth transition");
            Ok(())
        }
        Err(error) => {
            tx.rollback().await.expect("rollback auth transition");
            Err(error)
        }
    }
}

async fn security_notification_count(
    pool: &Pool,
    durable_effect_table: &crate::db::PgQualifiedTableName,
    kind: SecurityNotificationKind,
) -> i64 {
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin security notification read tx");
    let count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        format!(
            r#"
            SELECT count(*)
            FROM {}
            WHERE kind = 2
              AND security_notification_kind = $1
              AND subject_id = $2
            "#,
            durable_effect_table.quoted(),
        )
        .as_str(),
    ))
    .bind(super::super::postgres_store::i32_from_security_notification_kind(kind))
    .bind(id::<SubjectId>("subject").as_bytes())
    .fetch_one(tx.sqlx_transaction().as_mut())
    .await
    .expect("security notification count");
    tx.rollback()
        .await
        .expect("rollback security notification read tx");
    count
}

async fn drop_auth_test_schema(pool: &Pool, schema: &PgSchemaName) {
    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth test schema");
}
