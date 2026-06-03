use crate::db::{PgIdentifier, PgQualifiedTableName, unparameterized_simple_query};
use sqlx::PgPool;
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;

pub(crate) fn test_database_url_from_env(env_names: &[&str]) -> Option<String> {
    env_names.iter().find_map(|env_name| {
        let value = std::env::var(env_name).ok()?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn required_test_env_value(env_names: &[&str]) -> String {
    test_database_url_from_env(env_names).unwrap_or_else(|| {
        panic!(
            "required Postgres test environment value missing; set one of: {}",
            env_names.join(", ")
        )
    })
}

pub(crate) fn standard_test_database_url() -> String {
    required_test_env_value(&["TEST_DSN", "PARANOID_TEST_DATABASE_URL"])
}

pub(crate) fn queue_test_database_url() -> String {
    required_test_env_value(&[
        "TEST_DATABASE_URL",
        "TEST_DSN",
        "PARANOID_TEST_DATABASE_URL",
    ])
}

pub(crate) fn non_bypass_test_database_url() -> String {
    required_test_env_value(&["PARANOID_TEST_NON_BYPASS_DATABASE_URL"])
}

pub(crate) fn non_bypass_test_role_name() -> String {
    required_test_env_value(&["PARANOID_TEST_NON_BYPASS_ROLE"])
}

pub(crate) fn read_only_test_database_url() -> String {
    required_test_env_value(&["PARANOID_TEST_READ_ONLY_DATABASE_URL"])
}

pub(crate) fn read_only_test_role_name() -> String {
    required_test_env_value(&["PARANOID_TEST_READ_ONLY_ROLE"])
}

pub(crate) fn statement_timeout_test_database_url() -> String {
    required_test_env_value(&["PARANOID_TEST_STATEMENT_TIMEOUT_DATABASE_URL"])
}

pub(crate) async fn connect_sqlx_pool_for_harness(
    database_url: &str,
    max_connections: u32,
    application_name: &str,
) -> PgPool {
    let connect_options = PgConnectOptions::from_str(database_url)
        .expect("parse test database URL")
        .application_name(application_name)
        .statement_cache_capacity(0);
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(connect_options)
        .await
        .expect("connect SQLx harness pool")
}

pub(crate) async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP TABLE IF EXISTS {} CASCADE",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test table");
}

pub(crate) async fn create_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA {}",
        schema_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create test schema");
}

pub(crate) async fn drop_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {} CASCADE",
        schema_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test schema");
}

pub(crate) async fn fetch_table_exists(pool: &PgPool, table_name: &PgQualifiedTableName) -> bool {
    let schema_expression = table_name
        .schema()
        .map(|schema| postgres_string_literal(schema.as_str()))
        .unwrap_or_else(|| "current_schema()".to_owned());
    let table_expression = postgres_string_literal(table_name.table().as_str());
    let row = unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = {schema_expression}
              AND c.relname = {table_expression}
              AND c.relkind IN ('r', 'p')
        )
        "#,
    )))
    .fetch_one(pool)
    .await
    .expect("fetch table existence");
    row.try_get(0).expect("decode table existence")
}

fn postgres_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
