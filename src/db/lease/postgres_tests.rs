use super::{
    ClaimDuration as LeaseDuration, Error as LeaseError, HolderId as LeaseHolderId,
    HolderSnapshot as LeaseHolderSnapshot, Key as LeaseKey,
    LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS, LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
    LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
    LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER, Store as LeaseStore,
    StoreConfig as LeaseStoreConfig, migrate_schema as migrate_lease_schema,
    validate_schema as validate_lease_schema,
};
use crate::db::postgres_test_support::{connect_sqlx_pool_for_harness, standard_test_database_url};
use crate::db::{
    DatabaseOperationKind, DatabaseOperationObserver, DbError, PgIdentifier, PgQualifiedTableName,
    PoolConfig, WritePool, unparameterized_simple_query as db_unparameterized_simple_query,
};
use crate::id::SortableId as UniqueTestId;
use secrecy::SecretString;
use sqlx::PgPool;
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

async fn fetch_table_exists(pool: &PgPool, table_name: &PgQualifiedTableName) -> bool {
    let schema_expression = table_name
        .schema()
        .map(|schema| postgres_string_literal(schema.as_str()))
        .unwrap_or_else(|| "current_schema()".to_owned());
    let table_expression = postgres_string_literal(table_name.table().as_str());
    let row = db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
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

const COMPATIBLE_KEY_PRIMARY_KEY_COLUMN_DEFINITION: &str =
    r#"TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#;
const COMPATIBLE_KEY_NOT_NULL_COLUMN_DEFINITION: &str =
    r#"TEXT COLLATE "C" NOT NULL CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#;
const COMPATIBLE_KEY_UNIQUE_COLUMN_DEFINITION: &str = r#"TEXT COLLATE "C" NOT NULL UNIQUE CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#;
const COMPATIBLE_HOLDER_ID_COLUMN_DEFINITION: &str = r#"TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512)"#;
const COMPATIBLE_FENCING_TOKEN_COLUMN_DEFINITION: &str =
    "BIGINT NOT NULL CHECK (fencing_token > 0)";
const COMPATIBLE_LAST_FENCING_TOKEN_COLUMN_DEFINITION: &str =
    "BIGINT NOT NULL CHECK (last_fencing_token > 0)";
const COMPATIBLE_LEASE_TOKEN_COLUMN_DEFINITION: &str =
    "BYTEA NOT NULL CHECK (octet_length(lease_token) = 32)";

#[path = "postgres_tests/support.rs"]
mod support;

use support::*;

#[path = "postgres_tests/lifecycle.rs"]
mod lifecycle;
#[path = "postgres_tests/schema.rs"]
mod schema;
#[path = "postgres_tests/transactions_and_concurrency.rs"]
mod transactions_and_concurrency;
