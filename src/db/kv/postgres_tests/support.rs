use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct TestKvPayload {
    pub(super) label: String,
    pub(super) count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(super) struct MaybeFailingKvPayload {
    pub(super) label: String,
    pub(super) fail_serialize: bool,
}

impl Serialize for MaybeFailingKvPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.fail_serialize {
            return Err(serde::ser::Error::custom(
                "intentional test serialization failure",
            ));
        }

        let mut state = serializer.serialize_struct("MaybeFailingKvPayload", 2)?;
        state.serialize_field("label", &self.label)?;
        state.serialize_field("fail_serialize", &self.fail_serialize)?;
        state.end()
    }
}

pub(super) fn test_kv_item_keyset() -> Arc<Keyset> {
    let key = Key32::try_from(&[42_u8; 32][..]).expect("key");
    Arc::new(
        derive_keyset_from_latest_first_keys([key], "paranoid.tests.kv-item.v1").expect("keyset"),
    )
}

pub(super) struct TestDatabase {
    pub(super) paranoid_pool: WritePool,
    pub(super) sqlx_pool: PgPool,
    pub(super) config: KvStoreConfig,
}

impl TestDatabase {
    pub(super) async fn connect() -> Self {
        let database_url = standard_test_database_url();
        let paranoid_pool = connect_paranoid_pool(&database_url).await;
        let sqlx_pool = connect_sqlx_pool(&database_url).await;
        let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");

        Self {
            paranoid_pool,
            sqlx_pool,
            config,
        }
    }
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
    config.application_name = Some("paranoid_db_kv_postgres_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

pub(super) async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 2, "paranoid_db_kv_postgres_test").await
}

pub(super) fn unique_test_table_name() -> PgQualifiedTableName {
    PgQualifiedTableName::unqualified(unique_test_unqualified_table_name_text())
        .expect("test table name")
}

pub(super) fn unique_test_unqualified_table_name_text() -> String {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    format!("__kv_rs_{id}")
}

pub(super) fn unique_test_schema_name() -> PgIdentifier {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgIdentifier::new(format!("__kv_rs_schema_{id}")).expect("test schema name")
}

pub(super) async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    common_drop_test_table(pool, table_name).await;
}

pub(super) async fn create_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    common_create_test_schema(pool, schema_name).await;
}

pub(super) async fn drop_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    common_drop_test_schema(pool, schema_name).await;
}

pub(super) async fn fetch_key_has_null_expiration(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &KvKey,
) -> bool {
    sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
        "SELECT expires_at IS NULL FROM {} WHERE key = $1",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_one(pool)
    .await
    .expect("fetch expires_at nullness")
}

pub(super) async fn fetch_key_updated_at_text(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &KvKey,
) -> String {
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
        "SELECT updated_at::text FROM {} WHERE key = $1",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_one(pool)
    .await
    .expect("fetch updated_at")
}

pub(super) async fn fetch_key_expires_at_text(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &KvKey,
) -> String {
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
        "SELECT expires_at::text FROM {} WHERE key = $1",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_one(pool)
    .await
    .expect("fetch expires_at")
}

pub(super) async fn fetch_key_raw_value(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &KvKey,
) -> Vec<u8> {
    sqlx::query_scalar::<_, Vec<u8>>(sqlx::AssertSqlSafe(format!(
        "SELECT value FROM {} WHERE key = $1",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_one(pool)
    .await
    .expect("fetch raw value")
}

pub(super) async fn fetch_key_expiration_delta_microseconds(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &KvKey,
) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT (EXTRACT(EPOCH FROM (expires_at - updated_at)) * 1000000)::bigint \
         FROM {} WHERE key = $1",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_one(pool)
    .await
    .expect("fetch expiration delta")
}

pub(super) async fn fetch_statement_timestamp_microseconds(pool: &PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT (EXTRACT(EPOCH FROM statement_timestamp()) * 1000000)::bigint",
    )
    .fetch_one(pool)
    .await
    .expect("fetch statement timestamp")
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

pub(super) fn assert_kv_database_error(operation: &str, err: KvError) {
    assert!(
        matches!(err, KvError::Database(_)),
        "{operation} error = {err:?}"
    );
}

pub(super) async fn fetch_physical_key_row_count(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &KvKey,
) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM {} WHERE key = $1",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_one(pool)
    .await
    .expect("fetch physical key row count")
}

pub(super) async fn fetch_key_column_collation(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT coll.collname
        FROM pg_attribute attr
        JOIN pg_collation coll ON coll.oid = attr.attcollation
        WHERE attr.attrelid = to_regclass($1)
          AND attr.attname = 'key'
          AND NOT attr.attisdropped
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch key column collation")
}

pub(super) async fn fetch_has_key_text_pattern_ops_index(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_attribute attr
              ON attr.attrelid = idx.indrelid
             AND attr.attnum = idx.indkey[0]
             AND NOT attr.attisdropped
            JOIN pg_opclass opclass ON opclass.oid = idx.indclass[0]
            WHERE idx.indrelid = to_regclass($1)
              AND idx.indisvalid
              AND idx.indnkeyatts = 1
              AND idx.indpred IS NULL
              AND idx.indexprs IS NULL
              AND attr.attname = 'key'
              AND opclass.opcname = 'text_pattern_ops'
        )
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch key pattern index")
}

pub(super) async fn fetch_key_text_pattern_ops_index_name(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> PgIdentifier {
    let index_name = sqlx::query_scalar::<_, String>(
        r#"
        SELECT index_class.relname
        FROM pg_index idx
        JOIN pg_class index_class ON index_class.oid = idx.indexrelid
        JOIN pg_attribute attr
          ON attr.attrelid = idx.indrelid
         AND attr.attnum = idx.indkey[0]
         AND NOT attr.attisdropped
        JOIN pg_opclass opclass ON opclass.oid = idx.indclass[0]
        WHERE idx.indrelid = to_regclass($1)
          AND idx.indisvalid
          AND idx.indnkeyatts = 1
          AND idx.indpred IS NULL
          AND idx.indexprs IS NULL
          AND attr.attname = 'key'
          AND opclass.opcname = 'text_pattern_ops'
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch key pattern index name");
    PgIdentifier::new(index_name).expect("index name must be a valid identifier")
}

pub(super) async fn fetch_has_expires_at_partial_index(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> bool {
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
              AND idx.indexprs IS NULL
              AND attr.attname = 'expires_at'
              AND pg_get_expr(idx.indpred, idx.indrelid) IN (
                  'expires_at IS NOT NULL',
                  '(expires_at IS NOT NULL)'
              )
        )
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch expires_at partial index")
}

pub(super) async fn fetch_expires_at_partial_index_name(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> PgIdentifier {
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
          AND attr.attname = 'expires_at'
          AND pg_get_expr(idx.indpred, idx.indrelid) IN (
              'expires_at IS NOT NULL',
              '(expires_at IS NOT NULL)'
          )
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch expires_at partial index name");
    PgIdentifier::new(index_name).expect("index name must be a valid identifier")
}

pub(super) async fn fetch_has_updated_at_index(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> bool {
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
              AND attr.attname = 'updated_at'
        )
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch updated_at index")
}

pub(super) async fn fetch_updated_at_index_name(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> PgIdentifier {
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
          AND idx.indpred IS NULL
          AND idx.indexprs IS NULL
          AND attr.attname = 'updated_at'
        "#,
    )
    .bind(table_name.quoted().to_string())
    .fetch_one(pool)
    .await
    .expect("fetch updated_at index name");
    PgIdentifier::new(index_name).expect("index name must be a valid identifier")
}

pub(super) async fn replace_index_definition(
    pool: &PgPool,
    index_name: &PgIdentifier,
    create_index_statement: &str,
) {
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP INDEX {}",
        index_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop index");
    db_unparameterized_simple_query(sqlx::AssertSqlSafe(create_index_statement.to_owned()))
        .execute(pool)
        .await
        .expect("create replacement index");
}
