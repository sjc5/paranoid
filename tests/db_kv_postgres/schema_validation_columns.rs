use super::*;

#[tokio::test]
async fn kv_validation_rejects_wrong_value_column_type() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value TEXT NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        test_database.config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create incompatible table");

    let err = validate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject incompatible value column");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_validation_rejects_missing_key_length_check_constraint() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let missing_key_length_check_config =
        KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_key_length_check_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY,
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        missing_key_length_check_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table without key length check");

    let err = migrate_kv_schema(
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

    let missing_nonempty_key_check_config =
        KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &missing_nonempty_key_check_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        missing_nonempty_key_check_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table without nonempty key length check");

    let err = migrate_kv_schema(
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

    let compatible_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &compatible_config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            {},
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        compatible_config.table_name.quoted(),
        COMPATIBLE_KV_KEY_PRIMARY_KEY_COLUMN_DEFINITION
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with key length check");
    migrate_kv_schema(&test_database.paranoid_pool, &compatible_config)
        .await
        .expect("migration should accept key length check");

    drop_test_table(&test_database.sqlx_pool, &compatible_config.table_name).await;
}

#[tokio::test]
async fn kv_validation_rejects_wrong_timestamp_column_shapes() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let wrong_expires_at_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &wrong_expires_at_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        wrong_expires_at_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with wrong expires_at type");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &wrong_expires_at_config)
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

    let nullable_updated_at_config =
        KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &nullable_updated_at_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ
        )
        "#,
        nullable_updated_at_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with nullable updated_at");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &nullable_updated_at_config)
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
async fn kv_validation_rejects_missing_text_pattern_ops_index() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        test_database.config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table without indexes");

    let err = validate_kv_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject missing index");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
