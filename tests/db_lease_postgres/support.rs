use super::*;

pub(super) async fn abort_blocked_task<T>(handle: tokio::task::JoinHandle<T>, task_name: &str) {
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !handle.is_finished(),
        "{task_name} task should still be blocked"
    );
    handle.abort();
    match handle.await {
        Err(join_error) => assert!(
            join_error.is_cancelled(),
            "{task_name} task join error = {join_error}"
        ),
        Ok(_) => panic!("{task_name} task completed after abort"),
    }
}

pub(super) struct TestDatabase {
    pub(super) paranoid_pool: WritePool,
    pub(super) sqlx_pool: PgPool,
    pub(super) config: LeaseStoreConfig,
}

impl TestDatabase {
    pub(super) async fn connect() -> Self {
        let database_url = test_database_url();
        let paranoid_pool = connect_paranoid_pool(&database_url).await;
        let sqlx_pool = connect_sqlx_pool(&database_url).await;
        let config = LeaseStoreConfig::new(unique_test_table_name());

        Self {
            paranoid_pool,
            sqlx_pool,
            config,
        }
    }
}

pub(super) fn test_database_url() -> String {
    ["TEST_DSN", "PARANOID_TEST_DATABASE_URL"]
        .into_iter()
        .find_map(|env_name| {
            let value = std::env::var(env_name).ok()?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        })
        .expect("required Postgres test database URL missing; set TEST_DSN or PARANOID_TEST_DATABASE_URL")
}

pub(super) async fn connect_paranoid_pool(database_url: &str) -> WritePool {
    connect_paranoid_pool_with_max_connections(database_url, 2).await
}

pub(super) async fn connect_paranoid_pool_with_max_connections(
    database_url: &str,
    max_connections: u32,
) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = max_connections;
    config.application_name = Some("paranoid_db_lease_postgres_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

pub(super) async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    let connect_options = PgConnectOptions::from_str(database_url)
        .expect("parse test database URL")
        .statement_cache_capacity(0);
    PgPoolOptions::new()
        .max_connections(2)
        .connect_with(connect_options)
        .await
        .expect("connect sqlx pool")
}

pub(super) fn unique_test_table_name() -> PgQualifiedTableName {
    PgQualifiedTableName::unqualified(unique_test_unqualified_table_name_text())
        .expect("test table name")
}

pub(super) fn unique_test_unqualified_table_name_text() -> String {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    format!("__lease_rs_{id}")
}

pub(super) fn unique_test_schema_name() -> PgIdentifier {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgIdentifier::new(format!("__lease_rs_schema_{id}")).expect("test schema name")
}

pub(super) async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP TABLE IF EXISTS {} CASCADE",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test table");
}

pub(super) async fn drop_test_lease_tables(pool: &PgPool, config: &LeaseStoreConfig) {
    drop_test_table(pool, &config.table_name).await;
    drop_test_table(pool, &config.fencing_counter_table_name).await;
}

pub(super) async fn drop_test_index(pool: &PgPool, index_name: &PgIdentifier) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP INDEX IF EXISTS {}",
        index_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test index");
}

pub(super) async fn create_test_lease_table(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key_column_definition: &str,
    holder_id_column_definition: &str,
    fencing_token_column_definition: &str,
    lease_token_column_definition: &str,
    table_constraint: Option<&str>,
) {
    let table_constraint_sql = table_constraint
        .map(|constraint| format!(",\n            {constraint}"))
        .unwrap_or_default();
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key {},
            holder_id {},
            fencing_token {},
            lease_token {},
            expires_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL{}
        )
        "#,
        table_name.quoted(),
        key_column_definition,
        holder_id_column_definition,
        fencing_token_column_definition,
        lease_token_column_definition,
        table_constraint_sql
    )))
    .execute(pool)
    .await
    .expect("create test lease table");
}

pub(super) async fn create_test_fencing_counter_table(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key_column_definition: &str,
    last_fencing_token_column_definition: &str,
) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE TABLE {} (
            key {},
            last_fencing_token {},
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        table_name.quoted(),
        key_column_definition,
        last_fencing_token_column_definition
    )))
    .execute(pool)
    .await
    .expect("create test fencing counter table");
}

pub(super) async fn create_test_expires_at_index(pool: &PgPool, config: &LeaseStoreConfig) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE INDEX ON {} (expires_at)",
        config.table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create test expires_at index");
}

pub(super) async fn delete_test_lease_state_row(
    pool: &PgPool,
    config: &LeaseStoreConfig,
    key: &LeaseKey,
) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM {} WHERE key = $1",
        config.table_name.quoted()
    )))
    .bind(key.as_str())
    .execute(pool)
    .await
    .expect("delete test lease state row");
}

pub(super) async fn delete_test_lease_fencing_counter_row(
    pool: &PgPool,
    config: &LeaseStoreConfig,
    key: &LeaseKey,
) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM {} WHERE key = $1",
        config.fencing_counter_table_name.quoted()
    )))
    .bind(key.as_str())
    .execute(pool)
    .await
    .expect("delete test lease fencing counter row");
}

pub(super) async fn create_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA {}",
        schema_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create test schema");
}

pub(super) async fn drop_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {} CASCADE",
        schema_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test schema");
}

pub(super) async fn fetch_column_collation(
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

pub(super) async fn fetch_single_column_index_name(
    pool: &PgPool,
    config: &LeaseStoreConfig,
    column_name: &str,
) -> Option<PgIdentifier> {
    let index_name = sqlx::query_scalar::<_, String>(
        r#"
        SELECT index_class.relname
        FROM pg_index idx
        JOIN pg_class index_class ON index_class.oid = idx.indexrelid
        JOIN pg_attribute attr
          ON attr.attrelid = idx.indrelid
         AND attr.attnum = idx.indkey[0]
         AND NOT attr.attisdropped
        WHERE idx.indrelid = to_regclass($1)
          AND idx.indisvalid
          AND idx.indnkeyatts = 1
          AND idx.indexprs IS NULL
          AND attr.attname = $2
        LIMIT 1
        "#,
    )
    .bind(config.table_name.quoted().to_string())
    .bind(column_name)
    .fetch_optional(pool)
    .await
    .expect("fetch single-column index name")?;

    Some(PgIdentifier::new(index_name).expect("persisted index name should be valid"))
}

pub(super) async fn fetch_has_expires_at_index(pool: &PgPool, config: &LeaseStoreConfig) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_attribute attr
              ON attr.attrelid = idx.indrelid
             AND attr.attnum = idx.indkey[0]
             AND NOT attr.attisdropped
            WHERE idx.indrelid = to_regclass($1)
              AND idx.indisvalid
              AND idx.indnkeyatts = 1
              AND idx.indpred IS NULL
              AND idx.indexprs IS NULL
              AND attr.attname = 'expires_at'
        )
        "#,
    )
    .bind(config.table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch expires_at index")
}

pub(super) async fn fetch_table_row_count(pool: &PgPool, table_name: &PgQualifiedTableName) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM {}",
        table_name.quoted()
    )))
    .fetch_one(pool)
    .await
    .expect("fetch row count")
}
