use super::{
    ClaimDuration as LeaseDuration, Error as LeaseError, HolderId as LeaseHolderId,
    HolderSnapshot as LeaseHolderSnapshot, Key as LeaseKey,
    LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS, LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
    LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
    LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER, Store as LeaseStore,
    StoreConfig as LeaseStoreConfig, migrate_schema as migrate_lease_schema,
    validate_schema as validate_lease_schema,
};
use crate::db::{
    DatabaseOperationKind, DatabaseOperationObserver, DbError, PgIdentifier, PgQualifiedTableName,
    Pool, PoolConfig, unparameterized_simple_query as db_unparameterized_simple_query,
};
use crate::id::SortableId as UniqueTestId;
use secrecy::SecretString;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

async fn fetch_table_exists(pool: &PgPool, table_name: &PgQualifiedTableName) -> bool {
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

#[path = "../../../tests/db_lease_postgres/support.rs"]
mod support;

use support::*;

#[path = "../../../tests/db_lease_postgres/lifecycle.rs"]
mod lifecycle;
#[path = "../../../tests/db_lease_postgres/schema.rs"]
mod schema;
#[path = "../../../tests/db_lease_postgres/transactions_and_concurrency.rs"]
mod transactions_and_concurrency;
