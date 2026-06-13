use super::*;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::db::{
    BootstrapConfig, PgIdentifier, PgSchemaName, Pool, PoolConfig, WritePool, pooler_safe_query,
    pooler_safe_query_as, pooler_safe_query_scalar, unparameterized_simple_query,
};
use secrecy::SecretString;

static AUTH_POSTGRES_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn auth_store_config_for_db_bootstrap_uses_db_bootstrap_schema_and_ledger() {
    let bootstrap_config =
        BootstrapConfig::from_schema_name_text("__paranoid").expect("bootstrap config");
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
    assert_eq!(
        super::super::postgres_store::proof_use_from_i32(8).expect("identifier change candidate"),
        ProofUse::ProveOutOfBandIdentifierChangeCandidate
    );
    assert!(
        super::super::postgres_store::proof_use_from_i32(9).is_err(),
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
        super::super::postgres_store::i32_from_credential_reset_policy_role(
            CredentialResetPolicyRole::SecondFactorCredential,
        ),
        2
    );
    assert_eq!(
        super::super::postgres_store::credential_reset_policy_role_from_i32(1)
            .expect("ordinary credential reset policy role"),
        CredentialResetPolicyRole::OrdinaryCredential
    );
    assert!(
        super::super::postgres_store::credential_reset_policy_role_from_i32(3).is_err(),
        "invalid stored credential reset policy role ids must not be accepted"
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
        super::super::postgres_store::i32_from_out_of_band_identifier_binding_lifecycle_state(
            OutOfBandIdentifierBindingLifecycleState::Active,
        ),
        2
    );
    assert_eq!(
        super::super::postgres_store::out_of_band_identifier_binding_lifecycle_state_from_i32(1)
            .expect("pending out-of-band identifier binding state"),
        OutOfBandIdentifierBindingLifecycleState::PendingActivation
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
        super::super::postgres_store::i32_from_credential_lifecycle_action(
            CredentialLifecycleAction::Rotate,
        ),
        8
    );
    assert_eq!(
        super::super::postgres_store::credential_lifecycle_action_from_i32(8)
            .expect("credential rotation action"),
        CredentialLifecycleAction::Rotate
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
    assert_eq!(
        super::super::postgres_store::i32_from_security_notification_kind(
            SecurityNotificationKind::CredentialAdded,
        ),
        21
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
async fn postgres_store_migrates_and_validates_schema() {
    let database_url = required_auth_postgres_store_test_database_url();

    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let db_bootstrap_config = BootstrapConfig::new(PgSchemaName::new(unique_test_schema_name()));
    let schema = db_bootstrap_config.schema_name().clone();
    db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth schema");

    let store_config =
        super::super::postgres_store::PostgresAuthStoreConfig::for_db_bootstrap_config(
            &db_bootstrap_config,
        )
        .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-store.credentials.v1"),
    );

    store
        .migrate_schema(&write_pool)
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
async fn postgres_store_validate_schema_rejects_missing_column_check_constraints() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.schema-checks.v1").await;
    store
        .validate_schema(&pool)
        .await
        .expect("validate migrated auth schema before constraint drift");

    let secret_mac_table = store_config
        .table_name(PostgresAuthCoreTable::SessionCredentialSecretMac)
        .expect("session secret mac table");
    let find_constraint_statement = r#"
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND pg_get_expr(con.conbin, con.conrelid) LIKE '%secret_mac%'
        LIMIT 1
        "#;
    let mut find_constraint_tx = pool
        .begin_transaction()
        .await
        .expect("begin find constraint tx");
    let constraint_name = pooler_safe_query_scalar::<String>(find_constraint_statement)
        .bind(secret_mac_table.quoted().to_string())
        .fetch_one(find_constraint_tx.sqlx_transaction().as_mut())
        .await
        .expect("find secret MAC check constraint");
    find_constraint_tx
        .rollback()
        .await
        .expect("rollback find constraint tx");

    let constraint_name = PgIdentifier::new(constraint_name).expect("constraint identifier");
    let drop_constraint_statement = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        secret_mac_table.quoted(),
        constraint_name.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_constraint_statement.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop generated secret MAC check constraint");

    let validate_error = store
        .validate_schema(&pool)
        .await
        .expect_err("auth schema validation must reject missing generated check constraints");
    let validate_error = validate_error.to_string();
    assert!(
        validate_error.contains("secret_mac") && validate_error.contains("CHECK"),
        "unexpected validation error: {validate_error}"
    );

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_migrate_schema_does_not_record_component_version_after_physical_validation_failure()
 {
    let database_url = required_auth_postgres_store_test_database_url();
    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let db_bootstrap_config = BootstrapConfig::new(PgSchemaName::new(unique_test_schema_name()));
    let schema = db_bootstrap_config.schema_name().clone();
    db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth schema");

    let store_config =
        super::super::postgres_store::PostgresAuthStoreConfig::for_db_bootstrap_config(
            &db_bootstrap_config,
        )
        .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-store.failed-migration-ledger.v1"),
    );
    let trusted_device_table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let create_malformed_table_statement = format!(
        "CREATE TABLE {} (device_credential_id BYTEA NOT NULL)",
        trusted_device_table.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(
        create_malformed_table_statement.as_str(),
    ))
    .execute(pool.sqlx_pool())
    .await
    .expect("create malformed adopted trusted-device table");

    let migrate_error = store
        .migrate_schema(&write_pool)
        .await
        .expect_err("auth migration must reject adopted malformed physical auth tables");
    let migrate_error = migrate_error.to_string();
    assert!(
        migrate_error.contains("auth_trusted_device_credentials")
            || migrate_error.contains("trusted_device"),
        "unexpected migration error: {migrate_error}"
    );

    let ledger_table = store_config
        .schema_ledger_table_name()
        .expect("auth schema ledger table name");
    let instance_key = super::super::postgres_store::schema_instance_key(&store_config);
    let count_statement = format!(
        "SELECT count(*) FROM {} WHERE component = $1 AND instance_key = $2",
        ledger_table.quoted()
    );
    let mut count_tx = pool
        .begin_transaction()
        .await
        .expect("begin auth ledger count transaction");
    let recorded_rows =
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(count_statement.as_str()))
            .bind("auth_core")
            .bind(instance_key.as_str())
            .fetch_one(count_tx.sqlx_transaction().as_mut())
            .await
            .expect("count auth schema ledger rows after failed migration");
    count_tx
        .rollback()
        .await
        .expect("rollback auth ledger count transaction");
    assert_eq!(
        recorded_rows, 0,
        "failed auth physical validation must not record a trusted component schema version"
    );

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_validate_schema_rejects_missing_unique_indexes() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.unique-indexes.v1").await;
    store
        .validate_schema(&pool)
        .await
        .expect("validate migrated auth schema before index drift");

    let challenge_table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("active proof challenge table");
    let find_index_statement = r#"
        SELECT cls.relname
        FROM pg_index idx
        JOIN pg_class cls ON cls.oid = idx.indexrelid
        WHERE idx.indrelid = to_regclass($1)
          AND idx.indisunique
          AND idx.indexprs IS NULL
          AND pg_get_expr(idx.indpred, idx.indrelid) IS NOT NULL
          AND ARRAY(
              SELECT attr.attname::text
              FROM unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinality)
              JOIN pg_attribute attr
                ON attr.attrelid = idx.indrelid
               AND attr.attnum = key.attnum
               AND NOT attr.attisdropped
              WHERE key.ordinality <= idx.indnkeyatts
              ORDER BY key.ordinality
          ) = ARRAY['challenge_dedupe_key']
        LIMIT 1
        "#;
    let mut find_index_tx = pool.begin_transaction().await.expect("begin find index tx");
    let index_name = pooler_safe_query_scalar::<String>(find_index_statement)
        .bind(challenge_table.quoted().to_string())
        .fetch_one(find_index_tx.sqlx_transaction().as_mut())
        .await
        .expect("find open challenge dedupe index");
    find_index_tx
        .rollback()
        .await
        .expect("rollback find index tx");

    let index_name = PgIdentifier::new(index_name).expect("index identifier");
    let qualified_index = crate::db::PgQualifiedTableName::new(Some(schema.clone()), index_name);
    let drop_index_statement = format!("DROP INDEX {}", qualified_index.quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_index_statement.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop generated open challenge dedupe index");

    let validate_error = store
        .validate_schema(&pool)
        .await
        .expect_err("auth schema validation must reject missing unique indexes");
    let validate_error = validate_error.to_string();
    assert!(
        validate_error.contains("unique contract")
            && validate_error.contains("challenge_dedupe_key"),
        "unexpected validation error: {validate_error}"
    );

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_validate_schema_rejects_default_collation_core_text_columns() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.core-text-collation.v1").await;
    store
        .validate_schema(&pool)
        .await
        .expect("validate migrated auth schema before core text collation drift");

    let trusted_device_table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let alter_collation_statement = format!(
        "ALTER TABLE {} ALTER COLUMN display_label TYPE text COLLATE \"default\"",
        trusted_device_table.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(alter_collation_statement.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("change core text column to database-default collation");

    let validate_error = store
        .validate_schema(&pool)
        .await
        .expect_err("auth schema validation must reject default-collation core text columns");
    let validate_error = validate_error.to_string();
    assert!(
        validate_error.contains("display_label") && validate_error.contains("collation"),
        "unexpected validation error: {validate_error}"
    );

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_validate_schema_rejects_unexpected_core_columns() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.unexpected-column.v1").await;
    store
        .validate_schema(&pool)
        .await
        .expect("validate migrated auth schema before unexpected column drift");

    let session_table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let alter_statement = format!(
        "ALTER TABLE {} ADD COLUMN unexpected_extra BYTEA",
        session_table.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(alter_statement.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("add unexpected core auth table column");

    let validate_error = store
        .validate_schema(&pool)
        .await
        .expect_err("auth schema validation must reject unexpected core columns");
    let validate_error = validate_error.to_string();
    assert!(
        validate_error.contains("unexpected_extra") && validate_error.contains("unexpected column"),
        "unexpected validation error: {validate_error}"
    );

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_migrate_schema_upgrades_previous_auth_schema_ledger_version() {
    let (pool, write_pool, schema, store_config, store) =
        migrated_auth_store_with_write_pool_for_test("tests.auth.postgres-store.schema-upgrade.v1")
            .await;
    store
        .validate_schema(&pool)
        .await
        .expect("validate current auth schema before recorded downgrade");

    let ledger_table = store_config
        .schema_ledger_table_name()
        .expect("auth schema ledger table name");
    let instance_key = super::super::postgres_store::schema_instance_key(&store_config);
    let downgrade_statement = format!(
        r#"
        UPDATE {}
        SET schema_version = 3,
            schema_fingerprint = 'auth-core-postgres-v3'
        WHERE component = $1
          AND instance_key = $2
        "#,
        ledger_table.quoted()
    );
    let mut downgrade_tx = pool
        .begin_transaction()
        .await
        .expect("begin auth schema ledger downgrade transaction");
    let downgraded_rows = pooler_safe_query(sqlx::AssertSqlSafe(downgrade_statement.as_str()))
        .bind("auth_core")
        .bind(instance_key.as_str())
        .execute(downgrade_tx.sqlx_transaction().as_mut())
        .await
        .expect("downgrade recorded auth schema ledger row")
        .rows_affected();
    assert_eq!(downgraded_rows, 1);
    downgrade_tx
        .commit()
        .await
        .expect("commit recorded auth schema ledger downgrade");

    let stale_ledger_error = store
        .validate_schema(&pool)
        .await
        .expect_err("auth validation must reject previous recorded schema version");
    let stale_ledger_error = stale_ledger_error.to_string();
    assert!(
        stale_ledger_error.contains("recorded version 3")
            && stale_ledger_error.contains("expected 4"),
        "unexpected stale ledger validation error: {stale_ledger_error}"
    );

    store
        .migrate_schema(&write_pool)
        .await
        .expect("auth migration must upgrade previous recorded schema version");
    store
        .validate_schema(&pool)
        .await
        .expect("validate auth schema after recorded upgrade");

    let fetch_statement = format!(
        r#"
        SELECT schema_version, schema_fingerprint
        FROM {}
        WHERE component = $1
          AND instance_key = $2
        "#,
        ledger_table.quoted()
    );
    let mut fetch_tx = pool
        .begin_transaction()
        .await
        .expect("begin fetch upgraded auth schema ledger transaction");
    let recorded =
        pooler_safe_query_as::<(i32, String)>(sqlx::AssertSqlSafe(fetch_statement.as_str()))
            .bind("auth_core")
            .bind(instance_key.as_str())
            .fetch_one(fetch_tx.sqlx_transaction().as_mut())
            .await
            .expect("fetch upgraded auth schema ledger row");
    fetch_tx
        .rollback()
        .await
        .expect("rollback fetch upgraded auth schema ledger transaction");
    assert_eq!(recorded, (4, "auth-core-postgres-v4".to_owned()));

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_loads_persisted_recovery_authority_policy() {
    let database_url = required_auth_postgres_store_test_database_url();

    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let db_bootstrap_config = BootstrapConfig::new(PgSchemaName::new(unique_test_schema_name()));
    let schema = db_bootstrap_config.schema_name().clone();
    db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth schema");

    let store_config =
        super::super::postgres_store::PostgresAuthStoreConfig::for_db_bootstrap_config(
            &db_bootstrap_config,
        )
        .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config,
        test_keyset("tests.auth.postgres-store.lifecycle-policy.v1"),
    );
    store
        .migrate_schema(&write_pool)
        .await
        .expect("migrate auth schema");

    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let support_authority: RecoveryAuthorityId = id("support-team-authority");
    let password_metadata = CredentialInstanceMetadata::new(
        password_credential_id.clone(),
        id("subject"),
        CredentialInstanceKind::MessageSignatureVerifier,
        "password_signature",
        CredentialResetPolicyRole::OrdinaryCredential,
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
    let support_source = LifecycleAuthorityEvidence::admin_support_intervention(
        VerifiedAdminSupportCredentialLifecycleIntervention::new(
            id("support-intervention"),
            password_metadata.subject_id().clone(),
            password_credential_id.clone(),
            CredentialLifecycleAction::Replace,
            at(10),
            at(30),
        )
        .expect("support intervention"),
        [support_authority.clone()],
    )
    .expect("support lifecycle evidence");
    store
        .store_credential_lifecycle_metadata_for_test(
            &pool,
            &[password_metadata],
            &[
                CredentialRecoveryAuthority::new(
                    password_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    email_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
                CredentialRecoveryAuthority::new(
                    password_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                    support_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[
                email_source.clone(),
                device_source.clone(),
                support_source.clone(),
            ],
            at(10),
        )
        .await
        .expect("seed lifecycle metadata");

    let mut tx = pool.begin_transaction().await.expect("begin load tx");
    let email_only = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            at(20),
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
            at(20),
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
            at(20),
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
            at(20),
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

    let support_replace = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            at(20),
            &password_credential_id,
            &[support_source.source().clone()],
            CredentialLifecycleAction::Replace,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        )
        .await
        .expect("load support replace decision");
    assert_eq!(
        support_replace,
        Some(CredentialLifecycleActionDecision::AuthorizedImmediate),
        "support intervention should authorize only its scoped credential action while live"
    );

    let support_wrong_action = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            at(20),
            &password_credential_id,
            &[support_source.source().clone()],
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        )
        .await
        .expect("load support wrong-action decision");
    assert_eq!(
        support_wrong_action,
        Some(CredentialLifecycleActionDecision::Rejected),
        "support intervention scoped to replacement must not authorize reset"
    );

    let support_expired = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            at(30),
            &password_credential_id,
            &[support_source.source().clone()],
            CredentialLifecycleAction::Replace,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        )
        .await
        .expect("load support expired decision");
    assert_eq!(
        support_expired,
        Some(CredentialLifecycleActionDecision::Rejected),
        "support intervention must stop authorizing at its expiry instant"
    );

    let missing_target = store
        .load_and_evaluate_credential_lifecycle_action_in_current_transaction(
            &mut tx,
            at(20),
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
async fn postgres_store_loads_persisted_out_of_band_identifier_change_context() {
    let (pool, schema, _store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.identifier-change.v1").await;
    let subject_id: SubjectId = id("subject");
    let current_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        id("primary-email-source"),
    );
    let candidate_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        id("candidate-email-source"),
    );
    let current_authority: RecoveryAuthorityId = id("primary-email-authority");
    let candidate_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let current_evidence = out_of_band_identifier_lifecycle_evidence(
        "primary-email-source",
        [current_authority.clone()],
    );
    let candidate_evidence = out_of_band_identifier_lifecycle_evidence(
        "candidate-email-source",
        [candidate_authority.clone()],
    );
    let device_evidence =
        credential_instance_lifecycle_evidence("trusted-device", [device_authority.clone()]);
    store
        .store_subject_lifecycle_metadata_for_test(
            &pool,
            &[
                SubjectLifecycleAuthority::new(
                    subject_id.clone(),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    current_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
                SubjectLifecycleAuthority::new(
                    subject_id.clone(),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    candidate_authority,
                    RecoveryAuthorityTiming::Immediate,
                ),
            ],
            &[
                current_evidence.clone(),
                candidate_evidence.clone(),
                device_evidence.clone(),
            ],
            at(10),
        )
        .await
        .expect("seed subject lifecycle metadata");
    store
        .store_out_of_band_identifier_bindings_for_test(
            &pool,
            &[
                OutOfBandIdentifierBindingRecord::new(
                    current_source.clone(),
                    subject_id.clone(),
                    "email_otp",
                    OutOfBandIdentifierBindingLifecycleState::Active,
                )
                .expect("current binding"),
                OutOfBandIdentifierBindingRecord::new(
                    candidate_source.clone(),
                    subject_id.clone(),
                    "email_otp",
                    OutOfBandIdentifierBindingLifecycleState::PendingActivation,
                )
                .expect("candidate binding"),
            ],
            at(10),
        )
        .await
        .expect("seed out-of-band identifier bindings");

    let mut tx = pool.begin_transaction().await.expect("begin load tx");
    let current_only_context = store
        .load_out_of_band_identifier_change_context_in_current_transaction(
            &mut tx,
            &subject_id,
            current_source.clone(),
            candidate_source.clone(),
            &[current_evidence.source().clone()],
        )
        .await
        .expect("load current-only identifier-change context")
        .expect("current-only identifier-change context should load");
    assert_eq!(
        current_only_context.evaluate_action_at(
            at(20),
            SubjectLifecycleIndependentEvidenceRequirement::Required,
        ),
        SubjectLifecycleActionDecision::RequiresDelayedAction,
        "current identifier proof alone may schedule but must not immediately change the binding when independent evidence is required"
    );

    let current_plus_device_context = store
        .load_out_of_band_identifier_change_context_in_current_transaction(
            &mut tx,
            &subject_id,
            current_source.clone(),
            candidate_source.clone(),
            &[
                current_evidence.source().clone(),
                device_evidence.source().clone(),
            ],
        )
        .await
        .expect("load current plus device identifier-change context")
        .expect("current plus device identifier-change context should load");
    assert_eq!(
        current_plus_device_context.evaluate_action_at(
            at(20),
            SubjectLifecycleIndependentEvidenceRequirement::Required,
        ),
        SubjectLifecycleActionDecision::AuthorizedImmediate,
        "independent device evidence prevents the current identifier authority from collapsing into itself"
    );

    let candidate_authority_error = store
        .load_out_of_band_identifier_change_context_in_current_transaction(
            &mut tx,
            &subject_id,
            current_source,
            candidate_source,
            &[candidate_evidence.source().clone()],
        )
        .await
        .expect_err("candidate identifier proof must not authorize its own binding");
    assert!(
        matches!(
            candidate_authority_error,
            super::super::postgres_store::PostgresAuthStoreError::Core(Error::InvalidConfig(
                "candidate identifier proof cannot authorize its own binding"
            ))
        ),
        "unexpected candidate-authority error: {candidate_authority_error:?}"
    );
    tx.rollback().await.expect("rollback load tx");

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_commits_immediate_out_of_band_identifier_change() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.identifier-change-commit.v1").await;
    let subject_id: SubjectId = id("subject");
    let current_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        id("primary-email-source"),
    );
    let candidate_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        id("candidate-email-source"),
    );
    let current_authority: RecoveryAuthorityId = id("primary-email-authority");
    let candidate_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let stale_candidate_authority: RecoveryAuthorityId = id("stale-candidate-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let current_evidence = out_of_band_identifier_lifecycle_evidence(
        "primary-email-source",
        [current_authority.clone()],
    );
    let device_evidence =
        credential_instance_lifecycle_evidence("trusted-device", [device_authority]);
    store
        .store_subject_lifecycle_metadata_for_test(
            &pool,
            &[SubjectLifecycleAuthority::new(
                subject_id.clone(),
                SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                current_authority,
                RecoveryAuthorityTiming::Immediate,
            )],
            &[current_evidence.clone(), device_evidence.clone()],
            at(10),
        )
        .await
        .expect("seed subject lifecycle metadata");
    store
        .store_subject_lifecycle_metadata_for_test(
            &pool,
            &[],
            &[out_of_band_identifier_lifecycle_evidence(
                "candidate-email-source",
                [stale_candidate_authority.clone()],
            )],
            at(11),
        )
        .await
        .expect("seed stale candidate source authority metadata");
    store
        .store_out_of_band_identifier_bindings_for_test(
            &pool,
            &[
                OutOfBandIdentifierBindingRecord::new(
                    current_source.clone(),
                    subject_id.clone(),
                    "email_otp",
                    OutOfBandIdentifierBindingLifecycleState::Active,
                )
                .expect("current binding"),
                OutOfBandIdentifierBindingRecord::new(
                    candidate_source.clone(),
                    subject_id.clone(),
                    "email_otp",
                    OutOfBandIdentifierBindingLifecycleState::PendingActivation,
                )
                .expect("candidate binding"),
            ],
            at(10),
        )
        .await
        .expect("seed out-of-band identifier bindings");

    let mut load_tx = pool
        .begin_transaction()
        .await
        .expect("begin identifier-change load tx");
    let change_context = store
        .load_out_of_band_identifier_change_context_in_current_transaction(
            &mut load_tx,
            &subject_id,
            current_source.clone(),
            candidate_source.clone(),
            &[
                current_evidence.source().clone(),
                device_evidence.source().clone(),
            ],
        )
        .await
        .expect("load identifier-change context")
        .expect("identifier-change context should load");
    load_tx
        .rollback()
        .await
        .expect("rollback identifier-change load tx");
    let transition = reduce_command(
        &config(),
        Command::ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange {
            now: at(100),
            change_context,
            independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement::Required,
            candidate_authority_ids: vec![candidate_authority.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("identifier-change transition");
    let replay_transition = transition.clone();
    commit_transition_to_postgres(&pool, &store, transition).await;

    let binding_table = store_config
        .table_name(PostgresAuthCoreTable::OutOfBandIdentifierBinding)
        .expect("binding table");
    let authority_source_table = store_config
        .table_name(PostgresAuthCoreTable::LifecycleAuthoritySource)
        .expect("authority source table");
    let subject_state_table = store_config
        .table_name(PostgresAuthCoreTable::SubjectAuthState)
        .expect("subject state table");
    let durable_effect_table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("durable effect table");

    let current_state =
        out_of_band_identifier_binding_state(&pool, &binding_table, current_source.source_id())
            .await;
    let candidate_state =
        out_of_band_identifier_binding_state(&pool, &binding_table, candidate_source.source_id())
            .await;
    assert_eq!(
        current_state,
        OutOfBandIdentifierBindingLifecycleState::Superseded
    );
    assert_eq!(
        candidate_state,
        OutOfBandIdentifierBindingLifecycleState::Active
    );

    let mut read_authority_tx = pool
        .begin_transaction()
        .await
        .expect("begin authority-source read tx");
    let candidate_authority_count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        format!(
            r#"
            SELECT count(*)
            FROM {}
            WHERE source_kind = $1
              AND source_id = $2
              AND authority_id = $3
            "#,
            authority_source_table.quoted(),
        )
        .as_str(),
    ))
    .bind(
        super::super::postgres_store::i32_from_lifecycle_authority_source_kind(
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
        ),
    )
    .bind(candidate_source.source_id().as_bytes())
    .bind(candidate_authority.as_bytes())
    .fetch_one(read_authority_tx.sqlx_transaction().as_mut())
    .await
    .expect("candidate authority source count");
    let stale_candidate_authority_count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        format!(
            r#"
            SELECT count(*)
            FROM {}
            WHERE source_kind = $1
              AND source_id = $2
              AND authority_id = $3
            "#,
            authority_source_table.quoted(),
        )
        .as_str(),
    ))
    .bind(
        super::super::postgres_store::i32_from_lifecycle_authority_source_kind(
            LifecycleAuthoritySourceKind::OutOfBandIdentifier,
        ),
    )
    .bind(candidate_source.source_id().as_bytes())
    .bind(stale_candidate_authority.as_bytes())
    .fetch_one(read_authority_tx.sqlx_transaction().as_mut())
    .await
    .expect("stale candidate authority source count");
    read_authority_tx
        .rollback()
        .await
        .expect("rollback authority-source read tx");
    assert_eq!(
        candidate_authority_count, 1,
        "identifier change must bind the activated candidate source to its recovery authority"
    );
    assert_eq!(
        stale_candidate_authority_count, 0,
        "identifier change must replace stale candidate-source recovery-authority mappings"
    );

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
    .bind(subject_id.as_bytes())
    .fetch_one(read_subject_state_tx.sqlx_transaction().as_mut())
    .await
    .expect("subject revocation cutoff");
    read_subject_state_tx
        .rollback()
        .await
        .expect("rollback subject state read tx");
    assert_eq!(
        stored_subject_cutoff, 100,
        "identifier change must revoke existing subject auth state"
    );
    assert_eq!(
        security_notification_count(
            &pool,
            &durable_effect_table,
            SecurityNotificationKind::OutOfBandIdentifierChanged,
        )
        .await,
        1,
        "identifier change must schedule a security notice"
    );

    let replay_error = try_commit_transition_to_postgres(&pool, &store, replay_transition)
        .await
        .expect_err("replayed identifier-change commit must fail stale binding precondition");
    assert!(matches!(
        replay_error,
        super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(_)
    ));

    drop_auth_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_store_commits_credential_reset_planning() {
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
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("immediate credential metadata"),
                CredentialInstanceMetadata::new(
                    delayed_credential_id.clone(),
                    id("subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
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
                    CredentialResetPolicyRole::OrdinaryCredential,
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
                    CredentialResetPolicyRole::OrdinaryCredential,
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
                    CredentialResetPolicyRole::OrdinaryCredential,
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

#[tokio::test]
async fn postgres_store_commits_credential_addition_core_rows() {
    let (pool, schema, store_config, store) =
        migrated_auth_store_for_test("tests.auth.postgres-store.credential-addition.v1").await;

    let new_credential = message_signature_credential_metadata("new-password-credential");
    let new_credential_id = new_credential.credential_instance_id().clone();
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let new_password_authority: RecoveryAuthorityId = id("new-password-authority");
    let create_authority = CredentialRecoveryAuthority::new(
        new_credential_id.clone(),
        CredentialLifecycleAction::Create,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    let reset_authority = CredentialRecoveryAuthority::new(
        new_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        email_authority,
        RecoveryAuthorityTiming::Delayed,
    );
    let remove_authority = CredentialRecoveryAuthority::new(
        new_credential_id.clone(),
        CredentialLifecycleAction::Remove,
        new_password_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    let new_credential_source =
        LifecycleAuthoritySource::VerifiedProofSource(new_credential.verified_proof_source());
    let addition_work = AtomicCommitWork {
        mutations: vec![
            Mutation::CreateCredentialInstanceMetadata {
                metadata: new_credential.clone(),
                created_at: at(100),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: create_authority.clone(),
                created_at: at(100),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: reset_authority.clone(),
                created_at: at(100),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: remove_authority.clone(),
                created_at: at(100),
            },
            Mutation::CreateLifecycleAuthoritySource {
                source: new_credential_source.clone(),
                authority_id: new_password_authority.clone(),
                created_at: at(100),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: new_credential_id.clone(),
                action: CredentialLifecycleAction::Create,
                executed_at: at(100),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(100),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ],
        audit_events: vec![AuditEvent {
            kind: AuditEventKind::CredentialAdded,
            subject_id: Some(id("subject")),
            session_id: None,
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(100),
        }],
        durable_effects: vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialAdded,
                subject_id: id("subject"),
            },
        )],
        ..AtomicCommitWork::default()
    };
    try_commit_atomic_work_to_postgres(&pool, &store, addition_work)
        .await
        .expect("commit credential addition core rows");

    let mut load_tx = pool
        .begin_transaction()
        .await
        .expect("begin credential addition read tx");
    let loaded_context = store
        .load_credential_lifecycle_action_context_in_current_transaction(
            &mut load_tx,
            &new_credential_id,
            &[new_credential_source.clone()],
        )
        .await
        .expect("load credential addition lifecycle context")
        .expect("new credential metadata");
    assert_eq!(loaded_context.target_credential(), &new_credential);
    assert_eq!(
        loaded_context.recovery_authority_graph().authorities(),
        &[
            create_authority.clone(),
            reset_authority.clone(),
            remove_authority.clone(),
        ]
    );
    assert_eq!(
        loaded_context.presented_evidence(),
        &[
            LifecycleAuthorityEvidence::new(new_credential_source, [new_password_authority])
                .expect("new credential authority evidence")
        ]
    );
    assert_eq!(
        loaded_context.evaluate_action_at(
            at(101),
            CredentialLifecycleAction::Remove,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        ),
        CredentialLifecycleActionDecision::AuthorizedImmediate
    );
    load_tx
        .rollback()
        .await
        .expect("rollback credential addition read tx");

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
        "credential addition must atomically raise subject auth revocation cutoff"
    );

    let durable_effect_table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("durable effect table");
    let added_notice_count = security_notification_count(
        &pool,
        &durable_effect_table,
        SecurityNotificationKind::CredentialAdded,
    )
    .await;
    assert_eq!(
        added_notice_count, 1,
        "credential addition must atomically schedule a security notice"
    );

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

fn required_auth_postgres_store_test_database_url() -> String {
    std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .expect("required auth Postgres store test database URL missing; run through the isolated DB harness so TEST_DSN or PARANOID_TEST_DATABASE_URL is set")
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
    let (pool, _write_pool, schema, store_config, store) =
        migrated_auth_store_with_write_pool_for_test(purpose).await;
    (pool, schema, store_config, store)
}

async fn migrated_auth_store_with_write_pool_for_test(
    purpose: &str,
) -> (
    Pool,
    WritePool,
    PgSchemaName,
    super::super::postgres_store::PostgresAuthStoreConfig,
    super::super::postgres_store::PostgresAuthStore,
) {
    let database_url = required_auth_postgres_store_test_database_url();
    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let db_bootstrap_config = BootstrapConfig::new(PgSchemaName::new(unique_test_schema_name()));
    let schema = db_bootstrap_config.schema_name().clone();
    db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth schema");
    let store_config =
        super::super::postgres_store::PostgresAuthStoreConfig::for_db_bootstrap_config(
            &db_bootstrap_config,
        )
        .expect("store config");
    let store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset(purpose),
    );
    store
        .migrate_schema(&write_pool)
        .await
        .expect("migrate auth schema");
    (pool, write_pool, schema, store_config, store)
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

async fn out_of_band_identifier_binding_state(
    pool: &Pool,
    binding_table: &crate::db::PgQualifiedTableName,
    source_id: &VerifiedProofSourceId,
) -> OutOfBandIdentifierBindingLifecycleState {
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin out-of-band identifier binding read tx");
    let state = pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(
        format!(
            r#"SELECT lifecycle_state FROM {} WHERE source_id = $1"#,
            binding_table.quoted(),
        )
        .as_str(),
    ))
    .bind(source_id.as_bytes())
    .fetch_one(tx.sqlx_transaction().as_mut())
    .await
    .expect("out-of-band identifier binding state");
    tx.rollback()
        .await
        .expect("rollback out-of-band identifier binding read tx");
    super::super::postgres_store::out_of_band_identifier_binding_lifecycle_state_from_i32(state)
        .expect("out-of-band identifier binding lifecycle state")
}

async fn drop_auth_test_schema(pool: &Pool, schema: &PgSchemaName) {
    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth test schema");
}
