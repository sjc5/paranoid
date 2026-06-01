use super::*;

#[tokio::test]
async fn kv_migration_creates_schema_that_validation_accepts() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate");
    migrate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("second migrate");
    validate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("validate");
    assert_eq!(
        fetch_schema_ledger_fingerprint(
            &test_database.sqlx_pool,
            &test_database.config.schema_ledger_table_name,
            "kv",
            &format!("table={}", test_database.config.table_name.quoted()),
        )
        .await,
        Some("paranoid.kv.v1".to_owned())
    );

    let key_collation =
        fetch_key_column_collation(&test_database.sqlx_pool, &test_database.config.table_name)
            .await;
    assert!(
        matches!(key_collation.as_deref(), Some("C" | "POSIX")),
        "key column collation = {key_collation:?}"
    );

    let has_text_pattern_index = fetch_has_key_text_pattern_ops_index(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
    )
    .await;
    assert!(has_text_pattern_index);
    assert!(
        fetch_has_expires_at_partial_index(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
        )
        .await
    );
    assert!(
        fetch_has_updated_at_index(&test_database.sqlx_pool, &test_database.config.table_name,)
            .await
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_validation_rejects_missing_schema_ledger_row() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate");

    let instance_key = format!("table={}", test_database.config.table_name.quoted());
    delete_schema_ledger_row(
        &test_database.sqlx_pool,
        &test_database.config.schema_ledger_table_name,
        "kv",
        &instance_key,
    )
    .await;

    let err = validate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject missing schema ledger row");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_migration_rejects_conflicting_schema_ledger_row_without_overwriting_it() {
    let test_database = TestDatabase::connect().await;

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate");

    let instance_key = format!("table={}", test_database.config.table_name.quoted());
    overwrite_schema_ledger_fingerprint(
        &test_database.sqlx_pool,
        &test_database.config.schema_ledger_table_name,
        "kv",
        &instance_key,
        "not.paranoid.kv.v1",
    )
    .await;

    let err = migrate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("migration should reject conflicting schema ledger row");
    let message = err.to_string();
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    assert!(
        message.contains("recorded fingerprint")
            && message.contains("not.paranoid.kv.v1")
            && message.contains("paranoid.kv.v1"),
        "error message should describe the schema ledger fingerprint conflict: {message}"
    );
    assert_eq!(
        fetch_schema_ledger_fingerprint(
            &test_database.sqlx_pool,
            &test_database.config.schema_ledger_table_name,
            "kv",
            &instance_key,
        )
        .await,
        Some("not.paranoid.kv.v1".to_owned())
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_migration_rejects_default_collation_schema_ledger_text_columns() {
    let test_database = TestDatabase::connect().await;

    for default_collation_column in ["component", "instance_key", "schema_fingerprint"] {
        let mut config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
        config.schema_ledger_table_name = unique_test_table_name();

        drop_test_table(&test_database.sqlx_pool, &config.table_name).await;
        drop_test_table(&test_database.sqlx_pool, &config.schema_ledger_table_name).await;
        create_schema_ledger_with_default_collation_column(
            &test_database.sqlx_pool,
            &config.schema_ledger_table_name,
            default_collation_column,
        )
        .await;

        let error = migrate_kv_schema(&test_database.paranoid_pool, &config)
            .await
            .expect_err("migration should reject default-collation schema ledger text");
        let message = error.to_string();
        assert!(
            matches!(error, DbError::SchemaMismatch { .. }),
            "error = {error:?}"
        );
        assert!(
            message.contains(default_collation_column) && message.contains("collation"),
            "error message should name the bad schema ledger collation: {message}"
        );

        drop_test_table(&test_database.sqlx_pool, &config.table_name).await;
        drop_test_table(&test_database.sqlx_pool, &config.schema_ledger_table_name).await;
    }
}

#[tokio::test]
async fn kv_schema_ledger_migration_is_safe_under_concurrent_startup() {
    let test_database = TestDatabase::connect().await;

    let configs = (0..12)
        .map(|_| KvStoreConfig::new(unique_test_table_name()).expect("kv config"))
        .collect::<Vec<_>>();
    for config in &configs {
        drop_test_table(&test_database.sqlx_pool, &config.table_name).await;
    }

    let handles = configs
        .iter()
        .cloned()
        .map(|config| {
            let pool = test_database.paranoid_pool.clone();
            tokio::spawn(async move {
                migrate_kv_schema(&pool, &config)
                    .await
                    .expect("concurrent migrate");
                config
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        let config = handle.await.expect("join concurrent migrate");
        validate_kv_schema(&test_database.paranoid_pool, &config)
            .await
            .expect("validate concurrently migrated schema");
        assert_eq!(
            fetch_schema_ledger_fingerprint(
                &test_database.sqlx_pool,
                &config.schema_ledger_table_name,
                "kv",
                &format!("table={}", config.table_name.quoted()),
            )
            .await,
            Some("paranoid.kv.v1".to_owned())
        );
        drop_test_table(&test_database.sqlx_pool, &config.table_name).await;
    }
}

async fn create_schema_ledger_with_default_collation_column(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    default_collation_column: &str,
) {
    let component_collation = schema_ledger_test_collation(default_collation_column, "component");
    let instance_key_collation =
        schema_ledger_test_collation(default_collation_column, "instance_key");
    let schema_fingerprint_collation =
        schema_ledger_test_collation(default_collation_column, "schema_fingerprint");
    let statement = format!(
        r#"
        CREATE TABLE {} (
            component TEXT {component_collation} NOT NULL CHECK (
                octet_length(component) > 0
                AND octet_length(component) <= 128
            ),
            instance_key TEXT {instance_key_collation} NOT NULL CHECK (
                octet_length(instance_key) > 0
                AND octet_length(instance_key) <= 1024
            ),
            schema_version INTEGER NOT NULL CHECK (schema_version > 0),
            schema_fingerprint TEXT {schema_fingerprint_collation} NOT NULL CHECK (
                octet_length(schema_fingerprint) > 0
                AND octet_length(schema_fingerprint) <= 256
            ),
            applied_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (component, instance_key)
        )
        "#,
        table_name.quoted()
    );

    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .execute(pool)
        .await
        .expect("create incompatible schema ledger");
}

fn schema_ledger_test_collation(default_collation_column: &str, column_name: &str) -> &'static str {
    if default_collation_column == column_name {
        r#"COLLATE "default""#
    } else {
        r#"COLLATE "C""#
    }
}

#[tokio::test]
async fn kv_migration_in_current_transaction_is_usable_before_commit_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let key = KvKey::from_parts(["migration", "transactional"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &config.table_name).await;

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
    store
        .set_bytes_in_current_transaction(
            &mut rollback_tx,
            &key,
            b"inside-rollback",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set value inside rollback transaction");
    assert_eq!(
        store
            .get_bytes_in_current_transaction(&mut rollback_tx, &key)
            .await
            .expect("get value inside rollback transaction"),
        b"inside-rollback"
    );
    rollback_tx.rollback().await.expect("rollback transaction");

    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "rolled-back migration should leave no table behind"
    );
    assert_kv_database_error(
        "set_bytes after rolled-back migration",
        store
            .set_bytes(
                &test_database.paranoid_pool,
                &key,
                b"after-rollback",
                KvTtl::no_expiration(),
            )
            .await
            .expect_err("rolled-back migration should leave no usable table"),
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
    store
        .set_bytes_in_current_transaction(
            &mut commit_tx,
            &key,
            b"inside-commit",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set value inside commit transaction");
    commit_tx.commit().await.expect("commit transaction");

    assert!(
        fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "committed migration should leave the table available"
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get committed value"),
        b"inside-commit"
    );

    drop_test_table(&test_database.sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_operations_report_database_errors_for_missing_table() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["missing-table", "key"]).expect("key");
    let other_key = KvKey::from_parts(["missing-table", "other"]).expect("other key");
    let prefix = KvKeyPrefix::from_parts(["missing-table"]).expect("prefix");
    let item = KvItem::<TestKvPayload>::new_plain(store.clone(), prefix.clone());

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;

    assert_kv_database_error(
        "get_bytes",
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect_err("get_bytes should report missing table"),
    );
    assert_kv_database_error(
        "set_bytes",
        store
            .set_bytes(
                &test_database.paranoid_pool,
                &key,
                b"value",
                KvTtl::no_expiration(),
            )
            .await
            .expect_err("set_bytes should report missing table"),
    );
    assert_kv_database_error(
        "get_bytes_multi",
        store
            .get_bytes_multi(
                &test_database.paranoid_pool,
                &[key.clone(), other_key.clone()],
            )
            .await
            .expect_err("get_bytes_multi should report missing table"),
    );
    assert_kv_database_error(
        "set_bytes_multi",
        store
            .set_bytes_multi(
                &test_database.paranoid_pool,
                &[KvBytesSetEntry::new(key.clone(), b"value".to_vec())],
                KvTtl::no_expiration(),
            )
            .await
            .expect_err("set_bytes_multi should report missing table"),
    );
    assert_kv_database_error(
        "get_bytes_and_return_database_timestamp",
        store
            .get_bytes_and_return_database_timestamp(&test_database.paranoid_pool, &key)
            .await
            .expect_err("get timestamp should report missing table"),
    );
    assert_kv_database_error(
        "set_bytes_and_return_database_timestamp",
        store
            .set_bytes_and_return_database_timestamp(
                &test_database.paranoid_pool,
                &key,
                b"value",
                KvTtl::no_expiration(),
            )
            .await
            .expect_err("set timestamp should report missing table"),
    );
    assert_kv_database_error(
        "set_bytes_if_not_exists",
        store
            .set_bytes_if_not_exists(
                &test_database.paranoid_pool,
                &key,
                b"value",
                KvTtl::no_expiration(),
            )
            .await
            .expect_err("set_if_not_exists should report missing table"),
    );
    assert_kv_database_error(
        "set_bytes_if_not_exists_and_return_database_timestamp",
        store
            .set_bytes_if_not_exists_and_return_database_timestamp(
                &test_database.paranoid_pool,
                &key,
                b"value",
                KvTtl::no_expiration(),
            )
            .await
            .expect_err("set_if_not_exists timestamp should report missing table"),
    );
    assert_kv_database_error(
        "touch_key",
        store
            .touch_key(&test_database.paranoid_pool, &key)
            .await
            .expect_err("touch_key should report missing table"),
    );
    assert_kv_database_error(
        "set_key_ttl",
        store
            .set_key_ttl(
                &test_database.paranoid_pool,
                &key,
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await
            .expect_err("set_key_ttl should report missing table"),
    );
    assert_kv_database_error(
        "expire_key",
        store
            .expire_key(&test_database.paranoid_pool, &key)
            .await
            .expect_err("expire_key should report missing table"),
    );
    assert_kv_database_error(
        "delete_key",
        store
            .delete_key(&test_database.paranoid_pool, &key)
            .await
            .expect_err("delete_key should report missing table"),
    );
    assert_kv_database_error(
        "delete_expired_keys_once",
        store
            .delete_expired_keys_once(&test_database.paranoid_pool, 10)
            .await
            .expect_err("delete_expired_keys_once should report missing table"),
    );
    assert_kv_database_error(
        "delete_expired_keys_until_empty",
        store
            .delete_expired_keys_until_empty(&test_database.paranoid_pool, 10)
            .await
            .expect_err("delete_expired_keys_until_empty should report missing table"),
    );
    assert_kv_database_error(
        "check_key_exists",
        store
            .check_key_exists(&test_database.paranoid_pool, &key)
            .await
            .expect_err("check_key_exists should report missing table"),
    );
    assert_kv_database_error(
        "count_live_keys_with_prefix",
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &prefix)
            .await
            .expect_err("count_live_keys_with_prefix should report missing table"),
    );
    assert_kv_database_error(
        "scan_bytes_with_prefix",
        store
            .scan_bytes_with_prefix(&test_database.paranoid_pool, &prefix, None, 10)
            .await
            .expect_err("scan_bytes_with_prefix should report missing table"),
    );
    assert_kv_database_error(
        "scan_keys_with_prefix",
        store
            .scan_keys_with_prefix(&test_database.paranoid_pool, &prefix, None, 10)
            .await
            .expect_err("scan_keys_with_prefix should report missing table"),
    );
    assert_kv_database_error(
        "delete_keys_with_prefix_once",
        store
            .delete_keys_with_prefix_once(&test_database.paranoid_pool, &prefix, 10)
            .await
            .expect_err("delete_keys_with_prefix_once should report missing table"),
    );
    assert_kv_database_error(
        "acquire_slot_bytes",
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                std::slice::from_ref(&key),
                b"value",
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await
            .expect_err("acquire_slot_bytes should report missing table"),
    );
    assert_kv_database_error(
        "mutate_key_atomically",
        store
            .mutate_key_atomically(&test_database.paranoid_pool, &key, |_| {
                Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
            })
            .await
            .expect_err("mutate_key_atomically should report missing table"),
    );
    assert_kv_database_error(
        "item get",
        item.get(&test_database.paranoid_pool, ["key"])
            .await
            .expect_err("typed get should report missing table"),
    );
    assert_kv_database_error(
        "item set",
        item.set(
            &test_database.paranoid_pool,
            ["key"],
            &TestKvPayload {
                label: "value".to_owned(),
                count: 1,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect_err("typed set should report missing table"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

async fn fetch_schema_ledger_fingerprint(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
) -> Option<String> {
    let statement = format!(
        "SELECT schema_fingerprint FROM {} WHERE component = $1 AND instance_key = $2",
        table_name.quoted()
    );
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(component)
        .bind(instance_key)
        .fetch_optional(pool)
        .await
        .expect("fetch schema ledger fingerprint")
}

async fn delete_schema_ledger_row(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
) {
    let statement = format!(
        "DELETE FROM {} WHERE component = $1 AND instance_key = $2",
        table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(component)
        .bind(instance_key)
        .execute(pool)
        .await
        .expect("delete schema ledger row");
}

async fn overwrite_schema_ledger_fingerprint(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
    fingerprint: &str,
) {
    let statement = format!(
        "UPDATE {} SET schema_fingerprint = $1 WHERE component = $2 AND instance_key = $3",
        table_name.quoted()
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(fingerprint)
        .bind(component)
        .bind(instance_key)
        .execute(pool)
        .await
        .expect("overwrite schema ledger fingerprint")
        .rows_affected();
    assert_eq!(rows, 1, "schema ledger row should exist before overwrite");
}
