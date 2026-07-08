use super::*;

#[tokio::test]
async fn fleet_migration_creates_and_validates_backing_kv_and_lease_schema() {
    let test_database = TestDatabase::connect().await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate Fleet schema");
    validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("validate Fleet schema");
    assert_eq!(
        fetch_schema_ledger_fingerprint(
            &test_database.sqlx_pool,
            &test_database.config.schema_ledger_table_name,
            "fleet",
            &format!(
                "root={};state_table={};coordination_table={};fencing_counter_table={}",
                test_database.config.root_key.as_str(),
                test_database.config.state_table_name.quoted(),
                test_database.config.coordination_table_name.quoted(),
                test_database.config.fencing_counter_table_name.quoted()
            ),
        )
        .await,
        Some("paranoid.fleet.v1".to_owned())
    );

    assert!(
        fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.state_table_name
        )
        .await,
        "Fleet migration should create durable KV table"
    );
    assert!(
        fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.coordination_table_name
        )
        .await,
        "Fleet migration should create live lease state table"
    );
    assert!(
        fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.fencing_counter_table_name
        )
        .await,
        "Fleet migration should create durable fencing counter table"
    );
    for (table_name, column_name) in fleet_correctness_text_columns(&test_database.config) {
        let collation = fetch_column_collation(&test_database.sqlx_pool, table_name, column_name)
            .await
            .unwrap_or_else(|| panic!("{table_name:?}.{column_name} should have a collation"));
        assert!(
            matches!(collation.as_str(), "C" | "POSIX"),
            "{table_name:?}.{column_name} collation = {collation:?}"
        );
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_migration_rejects_future_schema_ledger_row_before_backing_schema_ddl() {
    let test_database = TestDatabase::connect().await;
    let mut config = test_database.config.clone();
    config.schema_ledger_table_name = unique_test_table_name();

    drop_fleet_test_tables(&test_database.sqlx_pool, &config).await;
    drop_test_table(&test_database.sqlx_pool, &config.schema_ledger_table_name).await;
    migrate_schema(&test_database.paranoid_pool, &config)
        .await
        .expect("migrate Fleet schema");

    let instance_key = format!(
        "root={};state_table={};coordination_table={};fencing_counter_table={}",
        config.root_key.as_str(),
        config.state_table_name.quoted(),
        config.coordination_table_name.quoted(),
        config.fencing_counter_table_name.quoted()
    );
    overwrite_schema_ledger_version_and_fingerprint(
        &test_database.sqlx_pool,
        &config.schema_ledger_table_name,
        "fleet",
        &instance_key,
        2,
        "paranoid.fleet.v2",
    )
    .await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &config).await;

    let err = migrate_schema(&test_database.paranoid_pool, &config)
        .await
        .expect_err("migration should reject a future Fleet schema ledger row");
    let message = err.to_string();
    assert!(
        matches!(err, DbError::SchemaMismatch { .. }),
        "error = {err:?}"
    );
    assert!(
        message.contains("newer than supported"),
        "error message should describe the future schema version: {message}"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.state_table_name,).await,
        "migration must reject the future ledger row before recreating the Fleet state table"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.coordination_table_name,).await,
        "migration must reject the future ledger row before recreating the Fleet coordination table"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.fencing_counter_table_name,).await,
        "migration must reject the future ledger row before recreating the Fleet fencing table"
    );

    drop_test_table(&test_database.sqlx_pool, &config.schema_ledger_table_name).await;
}

#[tokio::test]
async fn fleet_validation_rejects_default_collation_backing_text_columns() {
    let test_database = TestDatabase::connect().await;

    for (table_name, column_name) in fleet_correctness_text_columns(&test_database.config) {
        drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
        migrate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect("migrate Fleet schema");
        alter_column_to_default_collation(&test_database.sqlx_pool, table_name, column_name).await;

        let err = match validate_schema(&test_database.paranoid_pool, &test_database.config).await {
            Ok(()) => {
                panic!(
                    "validation should reject default collation for {table_name:?}.{column_name}"
                )
            }
            Err(err) => err,
        };
        assert!(
            matches!(err, DbError::SchemaMismatch { .. }),
            "error for {table_name:?}.{column_name} = {err:?}"
        );
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
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

async fn overwrite_schema_ledger_version_and_fingerprint(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
    version: i32,
    fingerprint: &str,
) {
    let statement = format!(
        "UPDATE {} SET schema_version = $1, schema_fingerprint = $2 WHERE component = $3 AND instance_key = $4",
        table_name.quoted()
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(version)
        .bind(fingerprint)
        .bind(component)
        .bind(instance_key)
        .execute(pool)
        .await
        .expect("overwrite schema ledger version and fingerprint")
        .rows_affected();
    assert_eq!(rows, 1, "schema ledger row should exist before overwrite");
}

fn fleet_correctness_text_columns(config: &StoreConfig) -> [(&PgQualifiedTableName, &str); 4] {
    [
        (&config.state_table_name, "key"),
        (&config.coordination_table_name, "key"),
        (&config.coordination_table_name, "holder_id"),
        (&config.fencing_counter_table_name, "key"),
    ]
}

async fn fetch_column_collation(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    column_name: &str,
) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT coll.collname
        FROM pg_attribute attr
        JOIN pg_collation coll ON coll.oid = attr.attcollation
        WHERE attr.attrelid = to_regclass($1)
          AND attr.attname = $2
          AND NOT attr.attisdropped
        "#,
    )
    .bind(table_name.quoted().to_string())
    .bind(column_name)
    .fetch_one(pool)
    .await
    .expect("fetch column collation")
}

async fn alter_column_to_default_collation(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    column_name: &str,
) {
    let column_name = PgIdentifier::new(column_name).expect("test column identifier");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE {} ALTER COLUMN {} TYPE TEXT COLLATE \"default\"",
        table_name.quoted(),
        column_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("alter column to default collation");
}
