use super::*;

async fn create_incompatible_placeholder_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE {} (id BIGINT PRIMARY KEY)",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create incompatible placeholder table");
}

#[tokio::test]
async fn lease_migration_creates_schema_that_validation_accepts() {
    let test_database = TestDatabase::connect().await;

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
    migrate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate");
    migrate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("second migrate");
    validate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("validate");

    let key_collation = fetch_column_collation(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "key",
    )
    .await;
    assert!(
        matches!(key_collation.as_deref(), Some("C" | "POSIX")),
        "key column collation = {key_collation:?}"
    );
    let holder_collation = fetch_column_collation(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "holder_id",
    )
    .await;
    assert!(
        matches!(holder_collation.as_deref(), Some("C" | "POSIX")),
        "holder_id column collation = {holder_collation:?}"
    );
    assert!(fetch_has_expires_at_index(&test_database.sqlx_pool, &test_database.config).await);
    assert!(
        fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.fencing_counter_table_name
        )
        .await,
        "migration should create durable fencing counter table"
    );
    let counter_key_collation = fetch_column_collation(
        &test_database.sqlx_pool,
        &test_database.config.fencing_counter_table_name,
        "key",
    )
    .await;
    assert!(
        matches!(counter_key_collation.as_deref(), Some("C" | "POSIX")),
        "fencing counter key column collation = {counter_key_collation:?}"
    );

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn lease_validate_schema_uses_one_rollback_transaction() {
    let test_database = TestDatabase::connect().await;

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
    migrate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate");

    let observer = DatabaseOperationObserver::default();
    let observed_pool = test_database
        .paranoid_pool
        .clone_with_database_operation_observer(observer.clone());
    validate_lease_schema(&observed_pool, &test_database.config)
        .await
        .expect("validate");

    let operation_shapes = observer
        .records()
        .into_iter()
        .map(|record| (record.kind, record.label))
        .collect::<Vec<_>>();
    assert_eq!(
        operation_shapes,
        vec![
            (
                DatabaseOperationKind::BeginTransaction,
                "db.begin_transaction"
            ),
            (
                DatabaseOperationKind::FetchAll,
                LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
            ),
            (
                DatabaseOperationKind::FetchOne,
                LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
            ),
            (
                DatabaseOperationKind::FetchAll,
                LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
            ),
            (
                DatabaseOperationKind::FetchOne,
                LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
            ),
            (
                DatabaseOperationKind::FetchAll,
                LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
            ),
            (
                DatabaseOperationKind::FetchOne,
                LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
            ),
            (
                DatabaseOperationKind::FetchAll,
                LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
            ),
            (DatabaseOperationKind::RollbackTransaction, "db.tx.rollback"),
        ]
    );

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn lease_migration_rolls_back_when_existing_schema_is_incompatible() {
    let test_database = TestDatabase::connect().await;

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
    create_incompatible_placeholder_table(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
    )
    .await;

    let observer = DatabaseOperationObserver::default();
    let observed_pool = test_database
        .paranoid_pool
        .clone_with_database_operation_observer(observer.clone());
    migrate_lease_schema(&observed_pool, &test_database.config)
        .await
        .expect_err("incompatible lease schema should fail migration");

    let records = observer.records();
    assert_eq!(
        records.first().map(|record| record.kind),
        Some(DatabaseOperationKind::BeginTransaction),
        "operation should begin an explicit transaction"
    );
    assert_eq!(
        records.last().map(|record| record.kind),
        Some(DatabaseOperationKind::RollbackTransaction),
        "failed operation should explicitly roll back"
    );
    assert!(
        records
            .iter()
            .all(|record| record.kind != DatabaseOperationKind::CommitTransaction),
        "failed operation must not commit"
    );
    assert!(
        !fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.fencing_counter_table_name
        )
        .await,
        "failed migration must not leave fencing counter table behind"
    );

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn lease_migration_in_current_transaction_is_usable_before_commit_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let config = LeaseStoreConfig::new(unique_test_table_name());
    let store = LeaseStore::new(config.clone());
    let key = LeaseKey::from_parts(["migration", "transactional"]).expect("key");
    let holder = LeaseHolderId::new("worker-a").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_lease_tables(&test_database.sqlx_pool, &config).await;

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    store
        .migrate_schema_in_current_transaction(&mut rollback_tx)
        .await
        .expect("migrate inside rollback transaction");
    store
        .validate_schema_in_current_transaction(&mut rollback_tx)
        .await
        .expect("validate inside rollback transaction");
    let rollback_claim = store
        .try_claim_lease_in_current_transaction(&mut rollback_tx, &key, &holder, duration)
        .await
        .expect("claim inside rollback transaction")
        .expect("rollback transaction should claim absent lease");
    assert_eq!(rollback_claim.fencing_token().as_i64(), 1);
    assert_eq!(
        store
            .fetch_live_lease_holder_in_current_transaction(&mut rollback_tx, &key)
            .await
            .expect("fetch holder inside rollback transaction")
            .expect("rollback transaction should see its own lease")
            .holder_id(),
        &holder
    );
    rollback_tx.rollback().await.expect("rollback transaction");

    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "rolled-back migration should leave no table behind"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.fencing_counter_table_name).await,
        "rolled-back migration should leave no fencing counter table behind"
    );
    let err = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &holder, duration)
        .await
        .expect_err("rolled-back migration should leave no usable table");
    assert!(
        matches!(err, LeaseError::Database(DbError::Query { .. })),
        "claim after rolled-back migration error = {err:?}"
    );

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit transaction");
    store
        .migrate_schema_in_current_transaction(&mut commit_tx)
        .await
        .expect("migrate inside commit transaction");
    store
        .validate_schema_in_current_transaction(&mut commit_tx)
        .await
        .expect("validate inside commit transaction");
    let commit_claim = store
        .try_claim_lease_in_current_transaction(&mut commit_tx, &key, &holder, duration)
        .await
        .expect("claim inside commit transaction")
        .expect("commit transaction should claim absent lease");
    assert_eq!(commit_claim.fencing_token().as_i64(), 1);
    commit_tx.commit().await.expect("commit transaction");

    assert!(
        fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "committed migration should leave the table available"
    );
    assert!(
        fetch_table_exists(&test_database.sqlx_pool, &config.fencing_counter_table_name).await,
        "committed migration should leave the fencing counter table available"
    );
    assert_eq!(
        store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch committed holder")
            .expect("committed lease should be live")
            .holder_id(),
        &holder
    );

    drop_test_lease_tables(&test_database.sqlx_pool, &config).await;
}

#[tokio::test]
async fn lease_validation_rejects_wrong_token_column_type() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            holder_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512),
            fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
            lease_token TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        test_database.config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create incompatible table");

    let err = validate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject incompatible lease_token column");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_validation_rejects_missing_required_check_constraints() {
    let test_database = TestDatabase::connect().await;

    let missing_key_length_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_key_length_check_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_key_length_check_config.table_name,
        r#"TEXT COLLATE "C" PRIMARY KEY"#,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(
        &test_database.paranoid_pool,
        &missing_key_length_check_config,
    )
    .await
    .expect_err("migration should reject table without key length check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_key_length_check_config.table_name,
    )
    .await;

    let missing_nonempty_key_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_nonempty_key_check_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_nonempty_key_check_config.table_name,
        r#"TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) <= 2048)"#,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(
        &test_database.paranoid_pool,
        &missing_nonempty_key_check_config,
    )
    .await
    .expect_err("migration should reject table without nonempty key length check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_nonempty_key_check_config.table_name,
    )
    .await;

    let missing_holder_length_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_holder_length_check_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_holder_length_check_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        r#"TEXT COLLATE "C" NOT NULL"#,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(
        &test_database.paranoid_pool,
        &missing_holder_length_check_config,
    )
    .await
    .expect_err("migration should reject table without holder_id length check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_holder_length_check_config.table_name,
    )
    .await;

    let missing_nonempty_holder_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_nonempty_holder_check_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_nonempty_holder_check_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        r#"TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) <= 512)"#,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(
        &test_database.paranoid_pool,
        &missing_nonempty_holder_check_config,
    )
    .await
    .expect_err("migration should reject table without nonempty holder_id length check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_nonempty_holder_check_config.table_name,
    )
    .await;

    let missing_fencing_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_fencing_check_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_fencing_check_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        "BIGINT NOT NULL",
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(&test_database.paranoid_pool, &missing_fencing_check_config)
        .await
        .expect_err("migration should reject table without positive fencing token check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_fencing_check_config.table_name,
    )
    .await;

    let missing_token_length_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_token_length_check_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_token_length_check_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        "BYTEA NOT NULL",
        None,
    )
    .await;
    let err = migrate_lease_schema(
        &test_database.paranoid_pool,
        &missing_token_length_check_config,
    )
    .await
    .expect_err("migration should reject table without lease token length check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_token_length_check_config.table_name,
    )
    .await;
}

#[tokio::test]
async fn lease_validation_rejects_incompatible_fencing_counter_schema() {
    let test_database = TestDatabase::connect().await;

    let missing_counter_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_lease_tables(&test_database.sqlx_pool, &missing_counter_config).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_counter_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    create_test_expires_at_index(&test_database.sqlx_pool, &missing_counter_config).await;
    let err = validate_lease_schema(&test_database.paranoid_pool, &missing_counter_config)
        .await
        .expect_err("validation should reject missing fencing counter table");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_lease_tables(&test_database.sqlx_pool, &missing_counter_config).await;

    let missing_counter_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_lease_tables(&test_database.sqlx_pool, &missing_counter_check_config).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_counter_check_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    create_test_expires_at_index(&test_database.sqlx_pool, &missing_counter_check_config).await;
    create_test_fencing_counter_table(
        &test_database.sqlx_pool,
        &missing_counter_check_config.fencing_counter_table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        "BIGINT NOT NULL",
    )
    .await;
    let err = validate_lease_schema(&test_database.paranoid_pool, &missing_counter_check_config)
        .await
        .expect_err("validation should reject counter without positive fencing check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_lease_tables(&test_database.sqlx_pool, &missing_counter_check_config).await;

    let missing_counter_nonempty_key_check_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_lease_tables(
        &test_database.sqlx_pool,
        &missing_counter_nonempty_key_check_config,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_counter_nonempty_key_check_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    create_test_expires_at_index(
        &test_database.sqlx_pool,
        &missing_counter_nonempty_key_check_config,
    )
    .await;
    create_test_fencing_counter_table(
        &test_database.sqlx_pool,
        &missing_counter_nonempty_key_check_config.fencing_counter_table_name,
        r#"TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) <= 2048)"#,
        COMPATIBLE_LAST_FENCING_TOKEN_COLUMN_DEFINITION,
    )
    .await;
    let err = validate_lease_schema(
        &test_database.paranoid_pool,
        &missing_counter_nonempty_key_check_config,
    )
    .await
    .expect_err("validation should reject counter without nonempty key check");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_lease_tables(
        &test_database.sqlx_pool,
        &missing_counter_nonempty_key_check_config,
    )
    .await;

    let non_c_counter_key_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_lease_tables(&test_database.sqlx_pool, &non_c_counter_key_config).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &non_c_counter_key_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    create_test_expires_at_index(&test_database.sqlx_pool, &non_c_counter_key_config).await;
    create_test_fencing_counter_table(
        &test_database.sqlx_pool,
        &non_c_counter_key_config.fencing_counter_table_name,
        r#"TEXT COLLATE "default" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#,
        COMPATIBLE_LAST_FENCING_TOKEN_COLUMN_DEFINITION,
    )
    .await;
    let err = validate_lease_schema(&test_database.paranoid_pool, &non_c_counter_key_config)
        .await
        .expect_err("validation should reject non-C counter key collation");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_lease_tables(&test_database.sqlx_pool, &non_c_counter_key_config).await;
}

#[tokio::test]
async fn lease_validation_rejects_wrong_timestamp_column_shapes() {
    let test_database = TestDatabase::connect().await;

    let wrong_expires_at_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &wrong_expires_at_config.table_name,
    )
    .await;
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            holder_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512),
            fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
            lease_token BYTEA NOT NULL CHECK (octet_length(lease_token) = 32),
            expires_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        wrong_expires_at_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with wrong expires_at type");
    let err = migrate_lease_schema(&test_database.paranoid_pool, &wrong_expires_at_config)
        .await
        .expect_err("migration should reject non-timestamptz expires_at");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &wrong_expires_at_config.table_name,
    )
    .await;

    let nullable_updated_at_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &nullable_updated_at_config.table_name,
    )
    .await;
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            holder_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512),
            fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
            lease_token BYTEA NOT NULL CHECK (octet_length(lease_token) = 32),
            expires_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ
        )
        "#,
        nullable_updated_at_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with nullable updated_at");
    let err = migrate_lease_schema(&test_database.paranoid_pool, &nullable_updated_at_config)
        .await
        .expect_err("migration should reject nullable updated_at");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &nullable_updated_at_config.table_name,
    )
    .await;
}

#[tokio::test]
async fn lease_validation_rejects_missing_expires_at_index() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;

    let err = validate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject missing expires_at index");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_validation_rejects_partial_expires_at_index() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    migrate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate");

    let expires_at_index_name = fetch_single_column_index_name(
        &test_database.sqlx_pool,
        &test_database.config,
        "expires_at",
    )
    .await
    .expect("expires_at index should exist after migration");
    drop_test_index(&test_database.sqlx_pool, &expires_at_index_name).await;
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE INDEX {} ON {} (expires_at) WHERE expires_at IS NOT NULL",
        expires_at_index_name.quoted(),
        test_database.config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create partial expires_at index");

    let err = validate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject partial expires_at index");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_migration_accepts_existing_usable_unique_key() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        COMPATIBLE_KEY_UNIQUE_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;

    migrate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate existing compatible table");
    validate_lease_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("validate existing compatible table");
    assert!(fetch_has_expires_at_index(&test_database.sqlx_pool, &test_database.config).await);

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_validation_rejects_unusable_key_uniqueness_and_non_c_collations() {
    let test_database = TestDatabase::connect().await;

    let missing_unique_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(&test_database.sqlx_pool, &missing_unique_config.table_name).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &missing_unique_config.table_name,
        COMPATIBLE_KEY_NOT_NULL_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(&test_database.paranoid_pool, &missing_unique_config)
        .await
        .expect_err("migration should reject table without usable key uniqueness");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &missing_unique_config.table_name).await;

    let deferrable_unique_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &deferrable_unique_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &deferrable_unique_config.table_name,
        COMPATIBLE_KEY_NOT_NULL_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        Some("CONSTRAINT key_unique UNIQUE (key) DEFERRABLE INITIALLY DEFERRED"),
    )
    .await;
    let err = migrate_lease_schema(&test_database.paranoid_pool, &deferrable_unique_config)
        .await
        .expect_err("migration should reject deferrable key uniqueness");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &deferrable_unique_config.table_name,
    )
    .await;

    let partial_unique_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(&test_database.sqlx_pool, &partial_unique_config.table_name).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &partial_unique_config.table_name,
        COMPATIBLE_KEY_NOT_NULL_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE UNIQUE INDEX partial_unique_key ON {} (key) WHERE expires_at IS NOT NULL",
        partial_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create partial unique key index");
    let err = migrate_lease_schema(&test_database.paranoid_pool, &partial_unique_config)
        .await
        .expect_err("migration should reject partial unique key index");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &partial_unique_config.table_name).await;

    let expression_unique_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(
        &test_database.sqlx_pool,
        &expression_unique_config.table_name,
    )
    .await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &expression_unique_config.table_name,
        COMPATIBLE_KEY_NOT_NULL_COLUMN_DEFINITION,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE UNIQUE INDEX expression_unique_key ON {} ((lower(key)))",
        expression_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create expression unique key index");
    let err = migrate_lease_schema(&test_database.paranoid_pool, &expression_unique_config)
        .await
        .expect_err("migration should reject expression unique key index");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &expression_unique_config.table_name,
    )
    .await;

    let non_c_key_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(&test_database.sqlx_pool, &non_c_key_config.table_name).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &non_c_key_config.table_name,
        r#"TEXT COLLATE "default" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#,
        COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(&test_database.paranoid_pool, &non_c_key_config)
        .await
        .expect_err("migration should reject non-C key collation");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &non_c_key_config.table_name).await;

    let non_c_holder_config = LeaseStoreConfig::new(unique_test_table_name());
    drop_test_table(&test_database.sqlx_pool, &non_c_holder_config.table_name).await;
    create_test_lease_table(
        &test_database.sqlx_pool,
        &non_c_holder_config.table_name,
        COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION,
        r#"TEXT COLLATE "default" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512)"#,
        COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION,
        COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION,
        None,
    )
    .await;
    let err = migrate_lease_schema(&test_database.paranoid_pool, &non_c_holder_config)
        .await
        .expect_err("migration should reject non-C holder_id collation");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &non_c_holder_config.table_name).await;
}

#[tokio::test]
async fn lease_migration_case_distinct_tables_get_independent_indexes() {
    let test_database = TestDatabase::connect().await;

    let mixed_case_table = format!(
        "__lease_rs_Case_{}",
        UniqueTestId::new().expect("id").to_text()
    );
    let lower_case_table = mixed_case_table.to_ascii_lowercase();
    let mixed_case_config = LeaseStoreConfig::new(
        PgQualifiedTableName::unqualified(mixed_case_table.as_str()).expect("mixed case table"),
    );
    let lower_case_config = LeaseStoreConfig::new(
        PgQualifiedTableName::unqualified(lower_case_table.as_str()).expect("lower case table"),
    );

    drop_test_table(&test_database.sqlx_pool, &mixed_case_config.table_name).await;
    drop_test_table(&test_database.sqlx_pool, &lower_case_config.table_name).await;
    migrate_lease_schema(&test_database.paranoid_pool, &mixed_case_config)
        .await
        .expect("migrate mixed case table");
    migrate_lease_schema(&test_database.paranoid_pool, &lower_case_config)
        .await
        .expect("migrate lower case table");

    assert!(fetch_has_expires_at_index(&test_database.sqlx_pool, &mixed_case_config).await);
    assert!(fetch_has_expires_at_index(&test_database.sqlx_pool, &lower_case_config).await);

    drop_test_table(&test_database.sqlx_pool, &mixed_case_config.table_name).await;
    drop_test_table(&test_database.sqlx_pool, &lower_case_config.table_name).await;
}

#[tokio::test]
async fn lease_schema_qualified_table_names_are_migrated_and_used_without_public_schema_bleed() {
    let test_database = TestDatabase::connect().await;

    let unqualified_table_name = unique_test_unqualified_table_name_text();
    let schema_name = unique_test_schema_name();
    let unqualified_config = LeaseStoreConfig::new(
        PgQualifiedTableName::unqualified(unqualified_table_name.as_str()).expect("table"),
    );
    let qualified_config = LeaseStoreConfig::new(
        PgQualifiedTableName::with_schema(schema_name.as_str(), unqualified_table_name.as_str())
            .expect("schema-qualified table"),
    );
    let unqualified_store = LeaseStore::new(unqualified_config.clone());
    let qualified_store = LeaseStore::new(qualified_config.clone());
    let key = LeaseKey::from_parts(["schema", "lease"]).expect("key");
    let public_holder = LeaseHolderId::new("public-worker").expect("holder");
    let schema_holder = LeaseHolderId::new("schema-worker").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &unqualified_config.table_name).await;
    create_test_schema(&test_database.sqlx_pool, &schema_name).await;

    migrate_lease_schema(&test_database.paranoid_pool, &qualified_config)
        .await
        .expect("migrate schema-qualified table");
    migrate_lease_schema(&test_database.paranoid_pool, &unqualified_config)
        .await
        .expect("migrate unqualified table with same table name");

    qualified_store
        .try_claim_lease(&test_database.paranoid_pool, &key, &schema_holder, duration)
        .await
        .expect("claim schema-qualified lease")
        .expect("schema-qualified lease should be claimable");
    unqualified_store
        .try_claim_lease(&test_database.paranoid_pool, &key, &public_holder, duration)
        .await
        .expect("claim public lease")
        .expect("public lease should be claimable");

    assert_eq!(
        qualified_store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch schema-qualified holder")
            .expect("schema-qualified holder should be live")
            .holder_id(),
        &schema_holder
    );
    assert_eq!(
        unqualified_store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch public holder")
            .expect("public holder should be live")
            .holder_id(),
        &public_holder
    );
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &qualified_config.table_name).await,
        1
    );
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &unqualified_config.table_name).await,
        1
    );

    drop_test_table(&test_database.sqlx_pool, &unqualified_config.table_name).await;
    drop_test_schema(&test_database.sqlx_pool, &schema_name).await;
}
