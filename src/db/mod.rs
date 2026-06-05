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
//! protocol. Use [`AuditedSql`] for generated SQL text after validating and
//! quoting every dynamic identifier.
//!
//! For app-owned or crate-owned table families that want Paranoid's schema
//! version ledger and loud drift detection, use
//! [`migrate_component_schema_in_current_transaction`] and
//! [`validate_component_schema_in_current_transaction`]. Component schemas use
//! validated [`PgQualifiedTableName`] values, so ledger tables and component
//! tables may live in any Postgres schema.
//!
//! For crates and applications that want the same isolated Postgres plus
//! transaction-mode PgBouncer test substrate Paranoid uses internally, enable
//! the `db-test-harness` feature and use `paranoid::db::testing`.
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

mod bootstrap;
mod component_schema;
mod error;
pub(crate) mod fleet;
mod identifier;
pub(crate) mod kv;
pub(crate) mod lease;
mod operation_observer;
mod pool;
mod portable_query;
#[cfg(test)]
pub(crate) mod postgres_test_support;
pub(crate) mod queue;
mod schema;
mod schema_ledger;
mod schema_migration;
mod sql_state;
#[cfg(feature = "db-test-harness")]
pub mod testing;
mod time;

pub use bootstrap::{
    BOOTSTRAP_FLEET_COORDINATION_TABLE_NAME, BOOTSTRAP_FLEET_FENCING_COUNTER_TABLE_NAME,
    BOOTSTRAP_FLEET_STATE_TABLE_NAME, BOOTSTRAP_KV_TABLE_NAME,
    BOOTSTRAP_QUEUE_DEAD_LETTER_TABLE_NAME, BOOTSTRAP_QUEUE_JOBS_TABLE_NAME,
    BOOTSTRAP_QUEUE_PAUSE_TABLE_NAME, BOOTSTRAP_SCHEMA_LEDGER_TABLE_NAME, BootstrapConfig,
    BootstrapError, BootstrapStores, BootstrapTableNames, DEFAULT_BOOTSTRAP_SCHEMA_NAME,
};
pub use component_schema::{
    ComponentSchema, ComponentSchemaMigration, ComponentSchemaMigrationOutcome,
    ComponentSchemaStatement, ComponentSchemaValidationCheck,
    migrate_component_schema_in_current_transaction,
    validate_component_schema_in_current_transaction,
};
pub use error::Error;
pub use identifier::{
    InvalidPgIdentifier, MAX_PG_IDENTIFIER_BYTES, PgIdentifier, PgQualifiedTableName, PgSchemaName,
    QuotedPgIdentifier, QuotedPgQualifiedTableName,
};
pub use pool::{Pool, PoolConfig, SslMode, Tx, WritePool, WriteTx};
pub use portable_query::{
    AuditedSql, portable_query, portable_query_as, portable_query_scalar,
    unparameterized_simple_query,
};
pub use schema_ledger::{ComponentSchemaVersion, component_schema_instance_key_for_tables};
pub use schema_migration::{ComponentSchemaMigrationStep, ComponentSchemaMigrationTarget};
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
#[cfg(test)]
pub(crate) use schema_ledger::{
    SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT, SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
    SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS, SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
    SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY, test_schema_ledger_config,
    test_schema_ledger_table_name,
};
pub(crate) use schema_ledger::{
    plan_component_schema_migration_in_current_transaction,
    record_component_schema_migration_completion_in_current_transaction,
    schema_instance_key_for_parts, validate_component_schema_version,
    validate_component_schema_version_in_current_transaction,
};
pub(crate) use schema_migration::{
    ComponentSchemaMigrationPlan, RecordedComponentSchemaVersion, plan_component_schema_migration,
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
#[cfg(test)]
mod write_pool_marker_postgres_tests;
