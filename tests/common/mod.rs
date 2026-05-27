#![allow(dead_code)]

use paranoid::db::{PgIdentifier, PgQualifiedTableName, unparameterized_simple_query};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;

pub fn test_database_url_from_env(env_names: &[&str]) -> Option<String> {
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

pub fn standard_test_database_url() -> Option<String> {
    test_database_url_from_env(&["TEST_DSN", "PARANOID_TEST_DATABASE_URL"])
}

pub fn queue_test_database_url() -> Option<String> {
    test_database_url_from_env(&[
        "TEST_DATABASE_URL",
        "TEST_DSN",
        "PARANOID_TEST_DATABASE_URL",
    ])
}

pub fn direct_test_database_url() -> Option<String> {
    test_database_url_from_env(&["TEST_DSN_DIRECT", "PARANOID_TEST_DATABASE_DIRECT_URL"])
}

pub async fn connect_sqlx_pool_for_harness(
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

pub async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP TABLE IF EXISTS {} CASCADE",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test table");
}

pub async fn create_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA {}",
        schema_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create test schema");
}

pub async fn drop_test_schema(pool: &PgPool, schema_name: &PgIdentifier) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {} CASCADE",
        schema_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test schema");
}

pub async fn fetch_table_exists(pool: &PgPool, table_name: &PgQualifiedTableName) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = COALESCE($1, current_schema())
              AND c.relname = $2
              AND c.relkind IN ('r', 'p')
        )
        "#,
    )
    .bind(table_name.schema().map(|schema| schema.as_str()))
    .bind(table_name.table().as_str())
    .fetch_one(pool)
    .await
    .expect("fetch table existence")
}
