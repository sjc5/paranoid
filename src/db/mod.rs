//! Postgres-only, SQLx-backed database foundation primitives.
//!
//! This module is available behind the `db` feature. It provides the small
//! Postgres substrate that Paranoid-owned storage primitives build on.
//!
//! Paranoid constructs its own Postgres pools through [`Pool::connect`] and
//! [`WritePool::connect`] so its storage primitives keep their conservative
//! connection configuration. [`Pool`] and [`Tx`] are neutral DB handles; they do
//! not imply any particular database privileges. [`WritePool`] and [`WriteTx`]
//! are marker wrappers for APIs that require write authority from the
//! credentials used to connect. They do not inspect, reduce, or enforce
//! Postgres privileges.
//!
//! Apps may also use the exposed SQLx pool and active Paranoid transactions for
//! app-owned tables and queries via [`Pool::sqlx_pool`],
//! [`WritePool::sqlx_pool`], [`Tx::sqlx_transaction`], and
//! [`WriteTx::sqlx_transaction`].
//!
//! For app-owned SQL that should stay portable to transaction-mode connection
//! poolers, use [`portable_query`],
//! [`portable_query_as`], and
//! [`portable_query_scalar`] inside an explicit [`Tx`].
//! These constructors disable persistent server-side prepared statements.
//! App-owned SQL may also use raw SQLx through [`Pool::sqlx_pool`] and
//! [`Tx::sqlx_transaction`] directly.
//!
//! Use [`unparameterized_simple_query`] for unparameterized DDL or
//! administration statements that must run through Postgres simple-query
//! protocol.
//!
//! ```rust,no_run
//! # #[cfg(feature = "db")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use paranoid::db::{
//!     portable_query_scalar, Pool, PoolConfig,
//! };
//! use secrecy::SecretString;
//!
//! let pool = Pool::connect(PoolConfig::new(SecretString::from(
//!     "postgres://app:secret@localhost/app",
//! )))
//! .await?;
//!
//! let mut tx = pool.begin_transaction().await?;
//! let _count = portable_query_scalar::<i64>("SELECT $1")
//!     .bind(1_i64)
//!     .fetch_one(tx.sqlx_transaction().as_mut())
//!     .await?;
//! tx.commit().await?;
//! # Ok(())
//! # }
//! ```

mod error;
pub(crate) mod fleet;
mod identifier;
pub(crate) mod kv;
#[allow(dead_code)]
pub(crate) mod lease;
mod operation_observer;
mod pool;
mod portable_query;
pub(crate) mod queue;
mod schema;
mod schema_ledger;
mod sql_state;
mod time;

pub use error::Error;
pub use identifier::{
    InvalidPgIdentifier, MAX_PG_IDENTIFIER_BYTES, PgIdentifier, PgQualifiedTableName, PgSchemaName,
    QuotedPgIdentifier, QuotedPgQualifiedTableName,
};
pub use pool::{Pool, PoolConfig, SslMode, Tx, WritePool, WriteTx};
pub use portable_query::{
    portable_query, portable_query_as, portable_query_scalar, unparameterized_simple_query,
};
pub use schema_ledger::{
    DEFAULT_RESERVED_DB_OBJECT_PREFIX, DEFAULT_RESERVED_KV_KEY_PREFIX,
    DEFAULT_SCHEMA_LEDGER_TABLE_NAME,
};
pub use sql_state::PgSqlState;

pub(crate) use error::Error as DbError;
pub(crate) use error::sql_state_from_sqlx_error;
pub(crate) use identifier::pg_table_name_set_could_contain_same_relation;
#[cfg(test)]
pub(crate) use operation_observer::DatabaseOperationRecord;
pub(crate) use operation_observer::{
    DatabaseOperationKind, DatabaseOperationObserver, record_database_operation,
};
pub(crate) use portable_query::{
    portable_query as pooler_safe_query, portable_query_as as pooler_safe_query_as,
    portable_query_scalar as pooler_safe_query_scalar,
};
pub(crate) use schema::normalize_check_constraint_expression;
pub(crate) use schema_ledger::{
    ComponentSchemaVersion, SchemaLedgerConfig,
    record_component_schema_version_in_current_transaction, schema_instance_key_for_parts,
    validate_component_schema_version_in_current_transaction,
};
#[cfg(test)]
pub(crate) use schema_ledger::{
    SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT, SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
    SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS, SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
    SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
};
pub(crate) use sql_state::{
    SQLSTATE_ADMIN_SHUTDOWN, SQLSTATE_CANNOT_CONNECT_NOW, SQLSTATE_CRASH_SHUTDOWN,
    SQLSTATE_LOCK_NOT_AVAILABLE, SQLSTATE_QUERY_CANCELED,
};
pub(crate) use time::{duration_from_nonnegative_f64_seconds, random_unit_f64_from_system};

pub(crate) fn first_8_bytes_as_lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(16);
    for byte in &bytes[..8] {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

pub(crate) async fn finish_db_pool_transaction<T>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, DbError>,
) -> Result<T, DbError> {
    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        std::convert::identity,
        |operation, error, rollback_error| DbError::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error: Box::new(rollback_error),
        },
    )
    .await
}

pub(crate) async fn finish_db_pool_validation_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, DbError>,
) -> Result<T, DbError> {
    finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        std::convert::identity,
        |operation, error, rollback_error| DbError::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error: Box::new(rollback_error),
        },
    )
    .await
}

pub(crate) async fn finish_pool_owned_write_transaction_and_preserve_rollback_error<T, E>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, E>,
    build_database_error: impl FnOnce(DbError) -> E,
    build_rollback_error: impl FnOnce(&'static str, E, DbError) -> E,
) -> Result<T, E> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(build_database_error)?;
            Ok(value)
        }
        Err(error) => match tx.rollback().await {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(build_rollback_error(operation, error, rollback_error)),
        },
    }
}

pub(crate) async fn finish_pool_owned_write_rollback_only_transaction_and_preserve_rollback_error<
    T,
    E,
>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, E>,
    build_database_error: impl FnOnce(DbError) -> E,
    build_rollback_error: impl FnOnce(&'static str, E, DbError) -> E,
) -> Result<T, E> {
    match result {
        Ok(value) => {
            tx.rollback().await.map_err(build_database_error)?;
            Ok(value)
        }
        Err(error) => match tx.rollback().await {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(build_rollback_error(operation, error, rollback_error)),
        },
    }
}

pub(crate) async fn finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error<
    T,
    E,
>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, E>,
    build_database_error: impl FnOnce(DbError) -> E,
    build_rollback_error: impl FnOnce(&'static str, E, DbError) -> E,
) -> Result<T, E> {
    match result {
        Ok(value) => {
            tx.rollback().await.map_err(build_database_error)?;
            Ok(value)
        }
        Err(error) => match tx.rollback().await {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(build_rollback_error(operation, error, rollback_error)),
        },
    }
}

#[cfg(test)]
pub(crate) use pool::{build_pg_pool_options, build_pooler_safe_pg_connect_options};
#[cfg(test)]
pub(crate) use schema_ledger::build_migrate_schema_ledger_statement_for_test;

#[cfg(test)]
mod tests;
