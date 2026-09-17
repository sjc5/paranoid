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
//! For app-owned SQL, use [`portable_query`], [`portable_query_as`], and
//! [`portable_query_scalar`]. App-owned SQL may also use raw SQLx through
//! [`Pool::sqlx_pool`] and [`Tx::sqlx_transaction`] directly.
//!
//! # Pooler independence
//!
//! [`portable_query`], [`portable_query_as`], and [`portable_query_scalar`] never use the
//! Postgres extended protocol (`Parse` then `Bind`/`Execute`): every bound value is rendered
//! as a safely-escaped Postgres literal and substituted into the SQL before it is sent, as a
//! single simple-protocol `Query` with no bind parameters at all. There is no `Parse`/`Bind`
//! split for a connection pooler to land on two different backends, so these constructors
//! are safe to execute directly on a [`Pool`]/[`WritePool`], as well as inside a
//! [`Tx`]/[`WriteTx`], under **every** connection-pooler mode, including statement-mode
//! pooling. Raw SQLx queries built directly through [`Pool::sqlx_pool`]/
//! [`Tx::sqlx_transaction`] use the extended protocol and do not carry this guarantee; run
//! those inside an explicit [`Tx`]/[`WriteTx`] instead.
//!
//! Use [`unparameterized_simple_query`] for unparameterized DDL or
//! administration statements that must run through Postgres simple-query
//! protocol. Use [`AuditedSql`] for generated SQL text after validating and
//! quoting every dynamic identifier.
//!
//! For table families registered by code that already uses Paranoid's DB
//! foundation, use [`BootstrapStores::migrate_component_schema`] after
//! [`BootstrapConfig::migrate_schema`]. Component schemas use validated
//! [`PgQualifiedTableName`] values, so component tables may live in any
//! Postgres schema while Paranoid owns the shared schema ledger and migration
//! coordination.
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
//! // Just as safe directly on `pool` itself, without an explicit transaction: there is no
//! // extended-protocol Parse/Bind split for a pooler to land on two different backends.
//! let _count = portable_query_scalar::<i64>("SELECT $1")
//!     .bind(1_i64)
//!     .fetch_one(tx.sqlx_transaction().as_mut())
//!     .await?;
//! tx.commit().await?;
//! # Ok(())
//! # }
//! ```

mod bootstrap;
mod bytea;
mod component_schema;
mod error;
pub(crate) mod fleet;
mod identifier;
pub(crate) mod kv;
pub(crate) mod lease;
mod operation_observer;
mod pool;
mod portable_query;
mod portable_query_literal;
mod portable_query_template;
#[cfg(test)]
pub(crate) mod postgres_test_support;
mod protocol;
mod protocol_schema;
pub(crate) mod queue;
mod schema;
mod schema_ledger;
mod schema_migration;
mod simple_query;
mod sql_state;
#[cfg(feature = "db-test-harness")]
pub mod testing;
mod time;

pub use bootstrap::{
    BOOTSTRAP_FLEET_COORDINATION_TABLE_NAME, BOOTSTRAP_FLEET_FENCING_COUNTER_TABLE_NAME,
    BOOTSTRAP_FLEET_STATE_TABLE_NAME, BOOTSTRAP_KV_TABLE_NAME, BOOTSTRAP_PROTOCOL_TABLE_NAME,
    BOOTSTRAP_QUEUE_DEAD_LETTER_TABLE_NAME, BOOTSTRAP_QUEUE_JOBS_TABLE_NAME,
    BOOTSTRAP_QUEUE_PAUSE_TABLE_NAME, BOOTSTRAP_SCHEMA_LEDGER_TABLE_NAME, BootstrapConfig,
    BootstrapError, BootstrapStores, BootstrapTableNames,
};
pub use component_schema::{
    ComponentSchema, ComponentSchemaMigration, ComponentSchemaMigrationOutcome,
    ComponentSchemaStatement, ComponentSchemaValidationCheck,
};
pub use error::Error;
pub use identifier::{
    InvalidPgIdentifier, MAX_PG_IDENTIFIER_BYTES, PgIdentifier, PgQualifiedTableName, PgSchemaName,
    QuotedPgIdentifier, QuotedPgQualifiedTableName,
};
pub use pool::{Pool, PoolConfig, SslMode, Tx, WritePool, WriteTx};
pub use portable_query::{
    AuditedSql, PortableQuery, PortableQueryAs, PortableQueryScalar, portable_query,
    portable_query_as, portable_query_scalar, unparameterized_simple_query,
};
pub use portable_query_literal::IntoPortableQueryLiteral;
pub use protocol::{Protocol, ProtocolError, contains_protocol_failure};
pub use schema_ledger::{ComponentSchemaVersion, component_schema_instance_key_for_tables};
pub use schema_migration::{ComponentSchemaMigrationStep, ComponentSchemaMigrationTarget};
pub use simple_query::{PostgresLiteral, SimpleQuery};
pub use sql_state::PgSqlState;

#[cfg(feature = "component-authoring")]
pub use component_schema::validate_component_schema_in_current_transaction;
#[cfg(test)]
pub(crate) use component_schema::{
    COMPONENT_SCHEMA_OPERATION_EXECUTE_FRESH_INSTALL_STATEMENT,
    COMPONENT_SCHEMA_OPERATION_EXECUTE_UPGRADE_STATEMENT,
    COMPONENT_SCHEMA_OPERATION_EXECUTE_VALIDATION_CHECK,
};
#[cfg(feature = "component-authoring")]
pub use error::Error as DbError;
#[cfg(not(feature = "component-authoring"))]
pub(crate) use error::Error as DbError;
#[cfg(feature = "component-authoring")]
pub use error::sql_state_from_sqlx_error;
#[cfg(not(feature = "component-authoring"))]
pub(crate) use error::sql_state_from_sqlx_error;
pub(crate) use identifier::pg_table_name_set_could_contain_same_relation;
#[cfg(test)]
pub(crate) use operation_observer::DatabaseOperationRecord;
pub(crate) use operation_observer::record_database_operation;
#[cfg(feature = "component-authoring")]
pub use operation_observer::{DatabaseOperationKind, DatabaseOperationObserver};
#[cfg(not(feature = "component-authoring"))]
pub(crate) use operation_observer::{DatabaseOperationKind, DatabaseOperationObserver};
#[cfg(feature = "component-authoring")]
/// Pooler-safe query constructor aliases for component authors.
///
/// Unstable component-authoring surface for component harnesses. No stability promise. Identical to [`portable_query`] /
/// [`portable_query_as`] / [`portable_query_scalar`]; an alias so component code
/// and its source guards can keep a single, explicit simple-protocol constructor
/// vocabulary.
pub use portable_query::{
    portable_query as pooler_safe_query, portable_query_as as pooler_safe_query_as,
    portable_query_scalar as pooler_safe_query_scalar,
};
#[cfg(not(feature = "component-authoring"))]
pub(crate) use portable_query::{
    portable_query as pooler_safe_query, portable_query_as as pooler_safe_query_as,
    portable_query_scalar as pooler_safe_query_scalar,
};
#[cfg(fuzzing)]
pub(crate) use portable_query_template::render_portable_query_sql as fuzz_render_portable_query_sql;
#[cfg(feature = "component-authoring")]
pub use schema::normalize_check_constraint_expression;
#[cfg(not(feature = "component-authoring"))]
pub(crate) use schema::normalize_check_constraint_expression;
#[cfg(test)]
pub(crate) use schema_ledger::{
    SCHEMA_LEDGER_OPERATION_CLAIM_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_CREATE_TABLE, SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_LOCK_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_UPDATE_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS, SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
    SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY, test_schema_ledger_config,
    test_schema_ledger_table_name,
};
pub(crate) use schema_ledger::{
    migrate_schema_ledger_schema_in_current_transaction, validate_component_schema_version,
    validate_component_schema_version_in_current_transaction,
};
#[cfg(feature = "component-authoring")]
pub use schema_ledger::{
    plan_component_schema_migration_in_current_transaction,
    record_component_schema_migration_completion_in_current_transaction,
    schema_instance_key_for_parts,
};
#[cfg(not(feature = "component-authoring"))]
pub(crate) use schema_ledger::{
    plan_component_schema_migration_in_current_transaction,
    record_component_schema_migration_completion_in_current_transaction,
    schema_instance_key_for_parts,
};
pub(crate) use schema_migration::plan_component_schema_migration;
#[cfg(feature = "component-authoring")]
pub use schema_migration::{ComponentSchemaMigrationPlan, RecordedComponentSchemaVersion};
#[cfg(not(feature = "component-authoring"))]
pub(crate) use schema_migration::{ComponentSchemaMigrationPlan, RecordedComponentSchemaVersion};
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

#[cfg(any(test, feature = "component-authoring"))]
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
mod portable_query_postgres_tests;
#[cfg(test)]
mod simple_query_postgres_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_pool_marker_postgres_tests;
