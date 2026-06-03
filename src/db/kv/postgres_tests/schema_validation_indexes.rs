use super::*;

#[tokio::test]
async fn kv_migration_accepts_existing_usable_unique_key_and_optional_updated_at_index() {
    let test_database = TestDatabase::connect().await;

    let mut no_updated_at_index_config =
        KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    no_updated_at_index_config.create_updated_at_index = false;
    drop_test_table(
        &test_database.sqlx_pool,
        &no_updated_at_index_config.table_name,
    )
    .await;
    migrate_kv_schema(&test_database.paranoid_pool, &no_updated_at_index_config)
        .await
        .expect("migrate without updated_at index");
    validate_kv_schema(&test_database.paranoid_pool, &no_updated_at_index_config)
        .await
        .expect("validate without updated_at index");
    assert!(
        fetch_has_expires_at_partial_index(
            &test_database.sqlx_pool,
            &no_updated_at_index_config.table_name,
        )
        .await
    );
    assert!(
        !fetch_has_updated_at_index(
            &test_database.sqlx_pool,
            &no_updated_at_index_config.table_name,
        )
        .await
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &no_updated_at_index_config.table_name,
    )
    .await;

    let existing_unique_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &existing_unique_config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" NOT NULL UNIQUE CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        existing_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with compatible unique key");
    migrate_kv_schema(&test_database.paranoid_pool, &existing_unique_config)
        .await
        .expect("migrate existing compatible table");
    validate_kv_schema(&test_database.paranoid_pool, &existing_unique_config)
        .await
        .expect("validate existing compatible table");
    drop_test_table(&test_database.sqlx_pool, &existing_unique_config.table_name).await;
}

#[tokio::test]
async fn kv_migration_rejects_expected_index_names_with_wrong_definitions() {
    let test_database = TestDatabase::connect().await;

    let expires_at_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &expires_at_config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &expires_at_config)
        .await
        .expect("migrate expires_at index setup");
    let expires_at_index_name = fetch_expires_at_partial_index_name(
        &test_database.sqlx_pool,
        &expires_at_config.table_name,
    )
    .await;
    replace_index_definition(
        &test_database.sqlx_pool,
        &expires_at_index_name,
        &format!(
            "CREATE INDEX {} ON {} (expires_at)",
            expires_at_index_name.quoted(),
            expires_at_config.table_name.quoted()
        ),
    )
    .await;
    let err = migrate_kv_schema(&test_database.paranoid_pool, &expires_at_config)
        .await
        .expect_err("migration should reject same-name expires_at index with wrong definition");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &expires_at_config.table_name).await;

    let key_pattern_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &key_pattern_config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &key_pattern_config)
        .await
        .expect("migrate key_pattern index setup");
    let key_pattern_index_name = fetch_key_text_pattern_ops_index_name(
        &test_database.sqlx_pool,
        &key_pattern_config.table_name,
    )
    .await;
    replace_index_definition(
        &test_database.sqlx_pool,
        &key_pattern_index_name,
        &format!(
            "CREATE INDEX {} ON {} (key)",
            key_pattern_index_name.quoted(),
            key_pattern_config.table_name.quoted()
        ),
    )
    .await;
    let err = migrate_kv_schema(&test_database.paranoid_pool, &key_pattern_config)
        .await
        .expect_err("migration should reject same-name key index without text_pattern_ops");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &key_pattern_config.table_name).await;

    let updated_at_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &updated_at_config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &updated_at_config)
        .await
        .expect("migrate updated_at index setup");
    let updated_at_index_name =
        fetch_updated_at_index_name(&test_database.sqlx_pool, &updated_at_config.table_name).await;
    replace_index_definition(
        &test_database.sqlx_pool,
        &updated_at_index_name,
        &format!(
            "CREATE INDEX {} ON {} (expires_at)",
            updated_at_index_name.quoted(),
            updated_at_config.table_name.quoted()
        ),
    )
    .await;
    let err = migrate_kv_schema(&test_database.paranoid_pool, &updated_at_config)
        .await
        .expect_err("migration should reject same-name updated_at index on wrong column");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &updated_at_config.table_name).await;
}

#[tokio::test]
async fn kv_validation_rejects_unusable_key_uniqueness_and_non_c_key_collation() {
    let test_database = TestDatabase::connect().await;

    let missing_unique_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &missing_unique_config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" NOT NULL CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        missing_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table without key uniqueness");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &missing_unique_config)
        .await
        .expect_err("migration should reject table without usable key uniqueness");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &missing_unique_config.table_name).await;

    let deferrable_unique_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &deferrable_unique_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" NOT NULL CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT key_unique UNIQUE (key) DEFERRABLE INITIALLY DEFERRED
        )
        "#,
        deferrable_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with deferrable key uniqueness");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &deferrable_unique_config)
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

    let nullable_unique_key_config =
        KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &nullable_unique_key_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" UNIQUE CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        nullable_unique_key_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with nullable unique key");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &nullable_unique_key_config)
        .await
        .expect_err("migration should reject nullable unique key column");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(
        &test_database.sqlx_pool,
        &nullable_unique_key_config.table_name,
    )
    .await;

    let partial_unique_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &partial_unique_config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" NOT NULL CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        partial_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table for partial unique key");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE UNIQUE INDEX partial_unique_key ON {} (key) WHERE expires_at IS NULL",
        partial_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create partial unique key index");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &partial_unique_config)
        .await
        .expect_err("migration should reject partial unique key index");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &partial_unique_config.table_name).await;

    let expression_unique_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(
        &test_database.sqlx_pool,
        &expression_unique_config.table_name,
    )
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "C" NOT NULL CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        expression_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table for expression unique key");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE UNIQUE INDEX expression_unique_key ON {} ((lower(key)))",
        expression_unique_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create expression unique key index");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &expression_unique_config)
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

    let missing_key_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &missing_key_config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        missing_key_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table without key column");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &missing_key_config)
        .await
        .expect_err("migration should reject missing key column");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &missing_key_config.table_name).await;

    let non_c_collation_config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    drop_test_table(&test_database.sqlx_pool, &non_c_collation_config.table_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key TEXT COLLATE "default" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048),
            value BYTEA NOT NULL,
            expires_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        non_c_collation_config.table_name.quoted()
    )))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create table with non-C key collation");
    let err = migrate_kv_schema(&test_database.paranoid_pool, &non_c_collation_config)
        .await
        .expect_err("migration should reject non-C key collation");
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    drop_test_table(&test_database.sqlx_pool, &non_c_collation_config.table_name).await;
}

#[tokio::test]
async fn kv_migration_case_distinct_tables_get_independent_indexes() {
    let test_database = TestDatabase::connect().await;

    let mixed_case_table = format!(
        "__kv_rs_Case_{}",
        UniqueTestId::new().expect("id").to_text()
    );
    let lower_case_table = mixed_case_table.to_ascii_lowercase();
    let mixed_case_config = KvStoreConfig::new(
        PgQualifiedTableName::unqualified(mixed_case_table.as_str()).expect("mixed case table"),
    )
    .expect("kv config");
    let lower_case_config = KvStoreConfig::new(
        PgQualifiedTableName::unqualified(lower_case_table.as_str()).expect("lower case table"),
    )
    .expect("kv config");

    drop_test_table(&test_database.sqlx_pool, &mixed_case_config.table_name).await;
    drop_test_table(&test_database.sqlx_pool, &lower_case_config.table_name).await;
    migrate_kv_schema(&test_database.paranoid_pool, &mixed_case_config)
        .await
        .expect("migrate mixed case table");
    migrate_kv_schema(&test_database.paranoid_pool, &lower_case_config)
        .await
        .expect("migrate lower case table");

    for config in [&mixed_case_config, &lower_case_config] {
        assert!(
            fetch_has_key_text_pattern_ops_index(&test_database.sqlx_pool, &config.table_name)
                .await
        );
        assert!(fetch_has_updated_at_index(&test_database.sqlx_pool, &config.table_name).await);
    }

    drop_test_table(&test_database.sqlx_pool, &mixed_case_config.table_name).await;
    drop_test_table(&test_database.sqlx_pool, &lower_case_config.table_name).await;
}

#[tokio::test]
async fn kv_schema_qualified_table_names_are_migrated_and_used_without_public_schema_bleed() {
    let test_database = TestDatabase::connect().await;

    let schema_name = unique_test_schema_name();
    let table_name = unique_test_unqualified_table_name_text();
    let qualified_config = KvStoreConfig::new(
        PgQualifiedTableName::with_schema(schema_name.as_str(), table_name.as_str())
            .expect("schema-qualified table name"),
    )
    .expect("kv config");
    let unqualified_config = KvStoreConfig::new(
        PgQualifiedTableName::unqualified(table_name.as_str()).expect("unqualified table name"),
    )
    .expect("kv config");
    let qualified_store = KvStore::new(qualified_config.clone()).expect("kv store");
    let unqualified_store = KvStore::new(unqualified_config.clone()).expect("kv store");
    let key = KvKey::from_parts(["schema-qualified", "same-key"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &unqualified_config.table_name).await;
    drop_test_schema(&test_database.sqlx_pool, &schema_name).await;
    create_test_schema(&test_database.sqlx_pool, &schema_name).await;

    qualified_store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate schema-qualified table");
    qualified_store
        .validate_schema(&test_database.paranoid_pool)
        .await
        .expect("validate schema-qualified table");
    unqualified_store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate unqualified table");
    unqualified_store
        .validate_schema(&test_database.paranoid_pool)
        .await
        .expect("validate unqualified table");

    qualified_store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"qualified-value",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set qualified value");
    unqualified_store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"unqualified-value",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set unqualified value");

    assert_eq!(
        qualified_store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get qualified value"),
        b"qualified-value"
    );
    assert_eq!(
        unqualified_store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get unqualified value"),
        b"unqualified-value"
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
