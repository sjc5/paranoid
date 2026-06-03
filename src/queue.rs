//! Postgres-backed durable queue primitives.
//!
//! Queue task names are explicit stable protocol strings. Enqueue calls are
//! available directly on `queue::Store`, and transaction-scoped variants are
//! available when enqueueing must commit with app-owned state changes.
//!
//! ```rust,no_run
//! # #[cfg(feature = "db")]
//! # async fn example(pool: paranoid::db::WritePool) -> Result<(), Box<dyn std::error::Error>> {
//! use paranoid::db::BootstrapConfig;
//! use paranoid::queue::EnqueueOptions;
//!
//! let stores = BootstrapConfig::default().migrate_schema(&pool).await?;
//! let queue = stores.queue;
//!
//! let result = queue
//!     .enqueue_json(
//!         &pool,
//!         "billing.rollup.v1",
//!         &"acct_123",
//!         EnqueueOptions::default(),
//!     )
//!     .await?;
//! assert!(!result.deduplicated);
//! # Ok(())
//! # }
//! ```

pub use crate::db::queue::{
    DEFAULT_QUEUE_CLEANUP_BATCH_DELAY as DEFAULT_CLEANUP_BATCH_DELAY,
    DEFAULT_QUEUE_CLEANUP_BATCH_SIZE as DEFAULT_CLEANUP_BATCH_SIZE,
    DEFAULT_QUEUE_COMPLETED_JOB_RETENTION as DEFAULT_COMPLETED_JOB_RETENTION,
    DEFAULT_QUEUE_DEAD_LETTER_JOB_RETENTION as DEFAULT_DEAD_LETTER_JOB_RETENTION,
    DEFAULT_QUEUE_FAILED_JOB_RETENTION as DEFAULT_FAILED_JOB_RETENTION,
    DEFAULT_QUEUE_LIST_LIMIT as DEFAULT_LIST_LIMIT,
    DEFAULT_QUEUE_MAX_RETRIES as DEFAULT_MAX_RETRIES,
    DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES as DEFAULT_PAYLOAD_JSON_LIMIT_BYTES,
    DEFAULT_QUEUE_RECLAIM_BATCH_SIZE as DEFAULT_RECLAIM_BATCH_SIZE,
    DEFAULT_QUEUE_RETRY_EXPONENTIAL_BASE as DEFAULT_RETRY_EXPONENTIAL_BASE,
    DEFAULT_QUEUE_RETRY_JITTER_FRACTION as DEFAULT_RETRY_JITTER_FRACTION,
    DEFAULT_QUEUE_RETRY_MAX_BACKOFF as DEFAULT_RETRY_MAX_BACKOFF,
    DEFAULT_QUEUE_WORKER_CLEANUP_INTERVAL as DEFAULT_WORKER_CLEANUP_INTERVAL,
    DEFAULT_QUEUE_WORKER_CONCURRENCY as DEFAULT_WORKER_CONCURRENCY,
    DEFAULT_QUEUE_WORKER_DATABASE_OPERATION_TIMEOUT as DEFAULT_WORKER_DATABASE_OPERATION_TIMEOUT,
    DEFAULT_QUEUE_WORKER_EXECUTION_HEARTBEAT_INTERVAL as DEFAULT_WORKER_EXECUTION_HEARTBEAT_INTERVAL,
    DEFAULT_QUEUE_WORKER_JOB_TIMEOUT as DEFAULT_WORKER_JOB_TIMEOUT,
    DEFAULT_QUEUE_WORKER_POLL_INTERVAL as DEFAULT_WORKER_POLL_INTERVAL,
    DEFAULT_QUEUE_WORKER_RECLAIM_INTERVAL as DEFAULT_WORKER_RECLAIM_INTERVAL,
    DEFAULT_QUEUE_WORKER_SHUTDOWN_GRACE_PERIOD as DEFAULT_WORKER_SHUTDOWN_GRACE_PERIOD,
    DEFAULT_QUEUE_WORKER_STALE_THRESHOLD as DEFAULT_WORKER_STALE_THRESHOLD,
    DEFAULT_QUEUE_WORKER_STARTUP_JITTER_FRACTION as DEFAULT_WORKER_STARTUP_JITTER_FRACTION,
    DeadLetterJob, DeadLetterReason, EnqueueBatchOptions, EnqueueOptions, EnqueueResult, Error,
    JOB_ID_SIZE, Job, JobExecutionContext, JobId, JobRunAtOrAfter, JobStatus, JobTimeout,
    ListDeadLetterJobsOptions, ListDeadLetterJobsResult, ListJobsOptions, ListJobsResult,
    MAX_QUEUE_CLAIM_LIMIT as MAX_CLAIM_LIMIT,
    MAX_QUEUE_CLEANUP_BATCH_SIZE as MAX_CLEANUP_BATCH_SIZE,
    MAX_QUEUE_DEAD_LETTER_MOVE_BATCH_SIZE as MAX_DEAD_LETTER_MOVE_BATCH_SIZE,
    MAX_QUEUE_DEDUPE_KEY_BYTES as MAX_DEDUPE_KEY_BYTES,
    MAX_QUEUE_ENQUEUE_BATCH_SIZE as MAX_ENQUEUE_BATCH_SIZE, MAX_QUEUE_LIST_LIMIT as MAX_LIST_LIMIT,
    MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES as MAX_PAYLOAD_JSON_LIMIT_BYTES,
    MAX_QUEUE_RECLAIM_BATCH_SIZE as MAX_RECLAIM_BATCH_SIZE,
    MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT as MAX_RETRY_AVAILABLE_FAILED_JOBS_LIMIT,
    MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS as MAX_RUN_AT_OR_AFTER_UNIX_MICROSECONDS,
    MAX_QUEUE_TASK_NAME_BYTES as MAX_TASK_NAME_BYTES,
    MAX_QUEUE_WORKER_CONCURRENCY as MAX_WORKER_CONCURRENCY,
    MAX_QUEUE_WORKER_OWNER_ID_BYTES as MAX_WORKER_OWNER_ID_BYTES,
    MIN_QUEUE_RETRY_BACKOFF as MIN_RETRY_BACKOFF, MoveFailedJobsToDeadLetterBatchResult,
    MovedToDeadLetterJob, ReclaimStaleRunningJobsResult, ReclaimedFailedJob, ReclaimedJob,
    RegisteredJsonTask, RetryBackoffFn, RetryBackoffStrategy, RetryPolicy, StatusCounts, Store,
    TaskError, TaskRegistry, WorkerConfig, WorkerDefaultJobTimeout, WorkerHandle,
    WorkerMaintenanceConfig, WorkerOwnerId, WorkerPressure, WorkerRunLoopSummary,
    WorkerRunOnceSummary,
};

/// Manual Queue protocols for callers that need to drive worker ownership directly.
pub mod manual {
    pub use crate::db::queue::ManualWorkerProtocol;
}
