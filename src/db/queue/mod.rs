use super::fleet::{
    Cron, CronConfig, CronKey, CronRunError, CronTaskErrorAction, Error as FleetPrimitiveError,
    MIN_FLEET_CRON_INTERVAL,
};
use super::{
    ComponentSchemaVersion, DatabaseOperationKind, DatabaseOperationObserver, DbError,
    PgIdentifier, PgQualifiedTableName, PgSqlState, Pool, SchemaLedgerConfig, Tx,
    duration_from_nonnegative_f64_seconds,
    finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error,
    finish_pool_owned_write_transaction_and_preserve_rollback_error,
    normalize_check_constraint_expression, pg_table_name_set_could_contain_same_relation,
    pooler_safe_query, pooler_safe_query_scalar, random_unit_f64_from_system,
    record_component_schema_version_in_current_transaction, record_database_operation,
    schema_instance_key_for_parts, validate_component_schema_version_in_current_transaction,
};
use crate::id;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sqlx::{Executor, Row};
use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::Notify;

mod api;
mod job_model;
mod operations;
mod pause;
mod preparation;
mod rows;
mod runtime_helpers;
mod schema;
mod schema_constraint_probes;
mod schema_migration;
mod schema_model;
mod schema_validation;
mod sql;
mod validation;
mod worker_config;
mod worker_job;
mod worker_loop;
mod worker_maintenance;
mod worker_model;
mod worker_once;
mod worker_runtime_model;
mod worker_summary;

use operations::*;
use pause::*;
use preparation::*;
use rows::*;
use runtime_helpers::*;
use schema::{
    migrate_schema, migrate_schema_in_current_transaction, validate_schema,
    validate_schema_in_current_transaction,
};
pub(in crate::db::queue) use schema_model::*;
use sql::*;
use validation::*;
use worker_job::*;
use worker_loop::*;
use worker_maintenance::*;
pub(in crate::db::queue) use worker_model::*;
use worker_once::*;

mod constants;
mod error;

pub use constants::*;
pub use error::Error;
pub use job_model::*;
pub use worker_model::{
    JobExecutionContext, ManualWorkerProtocol, RegisteredJsonTask, RetryBackoffFn,
    RetryBackoffStrategy, RetryPolicy, TaskError, TaskRegistry, WorkerConfig,
    WorkerDefaultJobTimeout, WorkerHandle, WorkerMaintenanceConfig, WorkerOwnerId,
    WorkerRunLoopSummary, WorkerRunOnceSummary,
};

async fn finish_queue_pool_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, Error>,
) -> Result<T, Error> {
    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}

async fn finish_queue_validation_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, Error>,
) -> Result<T, Error> {
    finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}

async fn finish_queue_read_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, Error>,
) -> Result<T, Error> {
    finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}

/// Postgres-backed durable queue configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    /// Jobs table.
    pub table_name: PgQualifiedTableName,
    /// Dead-letter jobs table.
    pub dead_letter_table_name: PgQualifiedTableName,
    /// Pause-state table.
    pub pause_table_name: PgQualifiedTableName,
    /// Schema ledger table for this queue.
    pub schema_ledger_table_name: PgQualifiedTableName,
    /// Maximum serialized JSON payload size per queued job.
    pub payload_json_limit_bytes: usize,
}

/// Postgres-backed durable queue primitive.
#[derive(Clone, Debug)]
pub struct Store {
    config: StoreConfig,
    sql_catalog: Arc<SqlCatalog>,
}

pub(in crate::db::queue) const QUEUE_OPERATION_BATCH_ENQUEUE: &str = "queue.batch_enqueue";
pub(in crate::db::queue) const QUEUE_OPERATION_CANCEL_PENDING_JOB: &str =
    "queue.cancel_pending_job";
pub(in crate::db::queue) const QUEUE_OPERATION_CLAIM_AVAILABLE_JOBS: &str =
    "queue.claim_available_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_CLEANUP_DEAD_LETTER_ONCE: &str =
    "queue.cleanup_dead_letter_once";
pub(in crate::db::queue) const QUEUE_OPERATION_CLEANUP_JOBS_ONCE: &str = "queue.cleanup_jobs_once";
pub(in crate::db::queue) const QUEUE_OPERATION_COUNT_WORKER_OWNED_RUNNING_JOBS: &str =
    "queue.count_worker_owned_running_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_DEDUPE_ENQUEUE: &str = "queue.dedupe_enqueue";
pub(in crate::db::queue) const QUEUE_OPERATION_DELETE_DEAD_LETTER_JOB: &str =
    "queue.delete_dead_letter_job";
pub(in crate::db::queue) const QUEUE_OPERATION_DELETE_PAUSE_KEY: &str = "queue.delete_pause_key";
pub(in crate::db::queue) const QUEUE_OPERATION_ENQUEUE: &str = "queue.enqueue";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_JOB_BY_ID: &str = "queue.fetch_job_by_id";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_JOB_COUNT_BY_STATUS: &str =
    "queue.fetch_job_count_by_status";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_ORPHANED_TASK_NAMES: &str =
    "queue.fetch_orphaned_task_names";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_PAUSE_ENTRIES: &str =
    "queue.fetch_pause_entries";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_PAUSE_KEY_EXISTS: &str =
    "queue.fetch_pause_key_exists";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_STATUS_COUNTS: &str =
    "queue.fetch_status_counts";
pub(in crate::db::queue) const QUEUE_OPERATION_FETCH_WORKER_PRESSURE_COUNTS: &str =
    "queue.fetch_worker_pressure_counts";
pub(in crate::db::queue) const QUEUE_OPERATION_FORCE_REQUEUE_RUNNING_JOB: &str =
    "queue.force_requeue_running_job";
pub(in crate::db::queue) const QUEUE_OPERATION_LIST_DEAD_LETTER_JOBS: &str =
    "queue.list_dead_letter_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_LIST_JOBS: &str = "queue.list_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_MARK_JOB_COMPLETED: &str =
    "queue.mark_job_completed";
pub(in crate::db::queue) const QUEUE_OPERATION_MARK_JOB_FAILED: &str = "queue.mark_job_failed";
pub(in crate::db::queue) const QUEUE_OPERATION_MARK_JOB_STARTED: &str = "queue.mark_job_started";
pub(in crate::db::queue) const QUEUE_OPERATION_MOVE_FAILED_JOB_TO_DEAD_LETTER: &str =
    "queue.move_failed_job_to_dead_letter";
pub(in crate::db::queue) const QUEUE_OPERATION_MOVE_FAILED_JOBS_TO_DEAD_LETTER_BATCH: &str =
    "queue.move_failed_jobs_to_dead_letter_batch";
pub(in crate::db::queue) const QUEUE_OPERATION_MOVE_OWNED_RUNNING_JOB_TO_DEAD_LETTER: &str =
    "queue.move_owned_running_job_to_dead_letter";
pub(in crate::db::queue) const QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_FAILED: &str =
    "queue.reclaim_expired_running_jobs_to_failed";
pub(in crate::db::queue) const QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_PENDING: &str =
    "queue.reclaim_expired_running_jobs_to_pending";
pub(in crate::db::queue) const QUEUE_OPERATION_RECLAIM_NEVER_STARTED_RUNNING_JOBS: &str =
    "queue.reclaim_never_started_running_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_REQUEUE_DEAD_LETTER_JOB: &str =
    "queue.requeue_dead_letter_job";
pub(in crate::db::queue) const QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS: &str =
    "queue.retry_available_failed_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_RETRY_FAILED_JOB: &str = "queue.retry_failed_job";
pub(in crate::db::queue) const QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_STARTED_JOBS: &str =
    "queue.return_available_owned_started_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_UNSTARTED_JOBS: &str =
    "queue.return_available_owned_unstarted_jobs";
pub(in crate::db::queue) const QUEUE_OPERATION_RETURN_OWNED_STARTED_JOB: &str =
    "queue.return_owned_started_job";
pub(in crate::db::queue) const QUEUE_OPERATION_RETURN_OWNED_UNSTARTED_JOB: &str =
    "queue.return_owned_unstarted_job";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEDULE_OWNED_RUNNING_JOB_RETRY: &str =
    "queue.schedule_owned_running_job_retry";
pub(in crate::db::queue) const QUEUE_OPERATION_SET_LOCAL_STATEMENT_TIMEOUT: &str =
    "queue.set_local_statement_timeout";
pub(in crate::db::queue) const QUEUE_OPERATION_TOUCH_JOB_HEARTBEAT: &str =
    "queue.touch_job_heartbeat";
pub(in crate::db::queue) const QUEUE_OPERATION_UPSERT_PAUSE_KEY: &str = "queue.upsert_pause_key";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_MIGRATE: &str = "queue.schema.migrate";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_VALIDATE: &str = "queue.schema.validate";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_MIGRATE_STATEMENT: &str =
    "queue.schema.migrate_statement";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_VALIDATE_TABLE_COLUMNS: &str =
    "queue.schema.validate_table_columns";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_CHECK_CONSTRAINT: &str =
    "queue.schema.validate_named_check_constraint";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_INDEX: &str =
    "queue.schema.validate_named_index";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_VALIDATE_ACTIVE_DEDUPE_ARBITER: &str =
    "queue.schema.validate_active_dedupe_arbiter";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_PROBE_SAVEPOINT: &str =
    "queue.schema.probe_savepoint";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_PROBE_INSERT: &str =
    "queue.schema.probe_insert";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_PROBE_ROLLBACK: &str =
    "queue.schema.probe_rollback";
pub(in crate::db::queue) const QUEUE_OPERATION_SCHEMA_PROBE_RELEASE: &str =
    "queue.schema.probe_release";

#[cfg(test)]
mod postgres_operation_count_tests;
#[cfg(test)]
mod tests;
