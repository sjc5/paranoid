use super::*;

/// Errors returned by the Postgres-backed queue primitive.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Queue-owned table names must be pairwise distinct.
    #[error("queue jobs, dead-letter, pause, and schema ledger table names must be distinct")]
    TableNamesMustBeDistinct,
    /// A task name was empty.
    #[error("queue task name is required")]
    TaskNameRequired,
    /// A task name had an invalid byte.
    #[error(
        "queue task name must contain only ASCII letters, digits, underscores, hyphens, or dots, and must start with an ASCII letter, digit, or underscore"
    )]
    InvalidTaskName,
    /// A task name exceeded [`crate::queue::MAX_TASK_NAME_BYTES`].
    #[error("queue task name is {actual} bytes, maximum is {max}")]
    TaskNameTooLong {
        /// Actual task name byte length.
        actual: usize,
        /// Maximum accepted task name byte length.
        max: usize,
    },
    /// A dedupe key contained a null byte.
    #[error("queue dedupe key must not contain null bytes")]
    InvalidDedupeKey,
    /// A dedupe key exceeded [`crate::queue::MAX_DEDUPE_KEY_BYTES`].
    #[error("queue dedupe key is {actual} bytes, maximum is {max}")]
    DedupeKeyTooLong {
        /// Actual dedupe key byte length.
        actual: usize,
        /// Maximum accepted dedupe key byte length.
        max: usize,
    },
    /// An enqueue batch exceeded [`crate::queue::MAX_ENQUEUE_BATCH_SIZE`].
    #[error("queue enqueue batch size is {actual}, maximum is {max}")]
    EnqueueBatchSizeTooLarge {
        /// Actual requested enqueue batch size.
        actual: usize,
        /// Maximum accepted enqueue batch size.
        max: u32,
    },
    /// The configured payload JSON limit was zero.
    #[error("queue payload JSON limit cannot be zero")]
    PayloadJsonLimitIsZero,
    /// The configured payload JSON limit exceeded [`crate::queue::MAX_PAYLOAD_JSON_LIMIT_BYTES`].
    #[error("queue payload JSON limit is {actual} bytes, maximum is {max}")]
    PayloadJsonLimitTooLarge {
        /// Actual configured payload JSON byte limit.
        actual: usize,
        /// Maximum accepted payload JSON byte limit.
        max: usize,
    },
    /// A scheduled run time was before the Unix epoch.
    #[error("queue scheduled run time cannot be before the Unix epoch")]
    RunAtOrAfterBeforeUnixEpoch,
    /// A scheduled run time was negative.
    #[error("queue scheduled run time is {actual} Unix microseconds, minimum is 0")]
    RunAtOrAfterUnixMicrosecondsIsNegative {
        /// Actual requested Unix microsecond timestamp.
        actual: i64,
    },
    /// A scheduled run time exceeded [`crate::queue::MAX_RUN_AT_OR_AFTER_UNIX_MICROSECONDS`].
    #[error("queue scheduled run time is {actual} Unix microseconds, maximum is {max}")]
    RunAtOrAfterUnixMicrosecondsTooLarge {
        /// Actual requested Unix microsecond timestamp.
        actual: u128,
        /// Maximum accepted Unix microsecond timestamp.
        max: i64,
    },
    /// The requested max retry count exceeded the database column domain.
    #[error("queue max retries must fit into a non-negative Postgres INT")]
    InvalidMaxRetries,
    /// A job timeout was too large to store as nanoseconds.
    #[error("queue job timeout is too large")]
    InvalidTimeout,
    /// A claim limit must be at least one.
    #[error("queue claim limit cannot be zero")]
    ClaimLimitIsZero,
    /// A claim limit exceeded [`crate::queue::MAX_CLAIM_LIMIT`].
    #[error("queue claim limit is {actual}, maximum is {max}")]
    ClaimLimitTooLarge {
        /// Actual requested claim limit.
        actual: u32,
        /// Maximum accepted claim limit.
        max: u32,
    },
    /// A worker owner ID was empty.
    #[error("queue worker owner id is required")]
    WorkerOwnerIdRequired,
    /// A worker owner ID contained a null byte.
    #[error("queue worker owner id must not contain null bytes")]
    InvalidWorkerOwnerId,
    /// A worker owner ID exceeded [`crate::queue::MAX_WORKER_OWNER_ID_BYTES`].
    #[error("queue worker owner id is {actual} bytes, maximum is {max}")]
    WorkerOwnerIdTooLong {
        /// Actual worker owner ID byte length.
        actual: usize,
        /// Maximum accepted worker owner ID byte length.
        max: usize,
    },
    /// A logical worker name was empty.
    #[error("queue worker name is required")]
    WorkerNameRequired,
    /// A logical worker name contained a null byte.
    #[error("queue worker name must not contain null bytes")]
    InvalidWorkerName,
    /// A logical worker name was too long to derive a unique worker owner ID.
    #[error("queue worker name is {actual} bytes, maximum is {max}")]
    WorkerNameTooLong {
        /// Actual worker name byte length.
        actual: usize,
        /// Maximum accepted worker name byte length.
        max: usize,
    },
    /// Worker owner ID generation failed.
    #[error("queue worker owner id generation failed")]
    WorkerOwnerIdGeneration {
        /// Underlying ID error.
        #[source]
        source: id::Error,
    },
    /// A task was registered more than once.
    #[error("queue task is already registered")]
    TaskAlreadyRegistered,
    /// Worker concurrency exceeded [`crate::queue::MAX_WORKER_CONCURRENCY`].
    #[error("queue worker concurrency is {actual}, maximum is {max}")]
    WorkerConcurrencyTooLarge {
        /// Actual requested concurrency.
        actual: u32,
        /// Maximum accepted concurrency.
        max: u32,
    },
    /// Worker timing configuration is internally unsafe.
    #[error("queue worker config is invalid: {reason}")]
    InvalidWorkerConfig {
        /// Human-readable reason.
        reason: &'static str,
    },
    /// Retry policy configuration is internally invalid.
    #[error("queue retry policy is invalid: {reason}")]
    InvalidRetryPolicy {
        /// Human-readable reason.
        reason: &'static str,
    },
    /// A worker task panicked or was cancelled at the Tokio task boundary.
    #[error("queue worker task failed to join: {reason}")]
    WorkerTaskJoinFailed {
        /// Human-readable join failure reason.
        reason: String,
    },
    /// A worker heartbeat task panicked or was cancelled at the Tokio task boundary.
    #[error("queue worker heartbeat task failed to join")]
    WorkerHeartbeatTaskJoinFailed {
        /// Join error.
        #[source]
        source: tokio::task::JoinError,
    },
    /// A worker heartbeat failed and job finalization also failed.
    #[error("queue worker heartbeat failed, then job finalization also failed")]
    WorkerHeartbeatFailureAndJobFinalizationFailed {
        /// Heartbeat failure.
        heartbeat_error: Box<Error>,
        /// Finalization failure.
        finalization_error: Box<Error>,
    },
    /// A Fleet-backed queue maintenance cron failed.
    #[error("queue maintenance cron {cron_name} failed")]
    MaintenanceCronRunFailed {
        /// Maintenance cron name.
        cron_name: &'static str,
        /// Underlying cron error.
        #[source]
        source: Box<CronRunError<Error>>,
    },
    /// A Fleet-backed queue maintenance cron task panicked or was cancelled.
    #[error("queue maintenance cron {cron_name} failed to join: {reason}")]
    MaintenanceCronTaskJoinFailed {
        /// Maintenance cron name.
        cron_name: &'static str,
        /// Human-readable join failure reason.
        reason: String,
    },
    /// A Fleet-backed queue maintenance cron stopped before worker shutdown was requested.
    #[error("queue maintenance cron {cron_name} stopped unexpectedly")]
    MaintenanceCronStoppedUnexpectedly {
        /// Maintenance cron name.
        cron_name: &'static str,
    },
    /// More than one worker-runtime component failed during the same shutdown.
    #[error("queue worker runtime had multiple failures")]
    WorkerRuntimeMultipleFailures {
        /// Collected runtime failures.
        failures: Vec<Error>,
    },
    /// A worker-owned database operation exceeded its configured timeout.
    #[error("queue worker database operation {operation} timed out after {timeout:?}")]
    WorkerDatabaseOperationTimedOut {
        /// Operation being executed.
        operation: &'static str,
        /// Configured timeout.
        timeout: Duration,
    },
    /// A worker-owned database operation failed and its cleanup rollback also failed.
    #[error("queue worker database operation {operation} failed, then transaction rollback failed")]
    WorkerDatabaseOperationRollbackFailed {
        /// Operation being executed.
        operation: &'static str,
        /// Original operation error.
        operation_error: Box<Error>,
        /// Rollback error.
        #[source]
        rollback_error: crate::db::Error,
    },
    /// A queue database operation failed and its cleanup rollback also failed.
    #[error("queue database operation {operation} failed, then transaction rollback failed")]
    DatabaseOperationRollbackFailed {
        /// Operation being executed.
        operation: &'static str,
        /// Original operation error.
        operation_error: Box<Error>,
        /// Rollback error.
        #[source]
        rollback_error: crate::db::Error,
    },
    /// A worker failed to persist a terminal job state and then failed to requeue the job.
    #[error("queue worker failed to persist job state, then failed to requeue the job")]
    WorkerJobPersistenceFailureAndRequeueFailed {
        /// Original persistence error.
        persistence_error: Box<Error>,
        /// Requeue error.
        requeue_error: Box<Error>,
    },
    /// A worker task failed and then failed to return worker-owned jobs to pending.
    #[error("queue worker task failed, then failed to return worker-owned jobs to pending")]
    WorkerRuntimeFailureAndClaimedJobCleanupFailed {
        /// Original worker-runtime error.
        worker_error: Box<Error>,
        /// Claimed-job cleanup error.
        cleanup_error: Box<Error>,
    },
    /// Retry jitter random generation failed.
    #[error("queue retry jitter random generation failed: {reason}")]
    RetryJitterRandom {
        /// Human-readable randomness error.
        reason: String,
    },
    /// Worker startup jitter random generation failed.
    #[error("queue worker startup jitter random generation failed: {reason}")]
    WorkerStartupJitterRandom {
        /// Human-readable randomness error.
        reason: String,
    },
    /// The whole queue is paused.
    #[error("queue is paused")]
    QueuePaused,
    /// The task is paused.
    #[error("queue task is paused")]
    TaskPaused,
    /// A job row does not exist.
    #[error("queue job not found")]
    JobNotFound,
    /// A job row is currently locked by another transaction.
    #[error("queue job is locked by a concurrent transaction")]
    JobLockedByConcurrentTransaction,
    /// A dead-letter row does not exist.
    #[error("queue dead-letter job not found")]
    DeadLetterJobNotFound,
    /// A dead-letter row is currently locked by another transaction.
    #[error("queue dead-letter job is locked by a concurrent transaction")]
    DeadLetterJobLockedByConcurrentTransaction,
    /// A job was present but not pending.
    #[error("queue job is not pending")]
    JobNotPending,
    /// A job was present but not running.
    #[error("queue job is not running")]
    JobNotRunning,
    /// A job was present but not failed.
    #[error("queue job is not failed")]
    JobNotFailed,
    /// Retrying would violate active dedupe semantics.
    #[error("queue retry would conflict with an active job using the same task and dedupe key")]
    RetryConflictWithActiveDedupeJob,
    /// A list limit must be at least one.
    #[error("queue list limit cannot be zero")]
    ListLimitIsZero,
    /// A list limit exceeded [`crate::queue::MAX_LIST_LIMIT`].
    #[error("queue list limit is {actual}, maximum is {max}")]
    ListLimitTooLarge {
        /// Actual requested list limit.
        actual: u32,
        /// Maximum accepted list limit.
        max: u32,
    },
    /// A failed-job retry limit must be at least one.
    #[error("queue retry available failed jobs limit cannot be zero")]
    RetryAvailableFailedJobsLimitIsZero,
    /// A failed-job retry limit exceeded [`crate::queue::MAX_RETRY_AVAILABLE_FAILED_JOBS_LIMIT`].
    #[error("queue retry available failed jobs limit is {actual}, maximum is {max}")]
    RetryAvailableFailedJobsLimitTooLarge {
        /// Actual requested retry limit.
        actual: u32,
        /// Maximum accepted retry limit.
        max: u32,
    },
    /// A stale-job reclaim batch size must be at least one.
    #[error("queue reclaim batch size cannot be zero")]
    ReclaimBatchSizeIsZero,
    /// A stale-job reclaim batch size exceeded [`crate::queue::MAX_RECLAIM_BATCH_SIZE`].
    #[error("queue reclaim batch size is {actual}, maximum is {max}")]
    ReclaimBatchSizeTooLarge {
        /// Actual requested reclaim batch size.
        actual: u32,
        /// Maximum accepted reclaim batch size.
        max: u32,
    },
    /// Cleanup age must be positive.
    #[error("queue cleanup age must be positive")]
    CleanupAgeIsZero,
    /// Cleanup age was too large to represent as microseconds.
    #[error("queue cleanup age is too large")]
    CleanupAgeTooLarge,
    /// Stale threshold must be positive.
    #[error("queue stale threshold must be positive")]
    StaleThresholdIsZero,
    /// Stale threshold was too large to represent as microseconds.
    #[error("queue stale threshold is too large")]
    StaleThresholdTooLarge,
    /// Retry backoff was too large to represent as microseconds.
    #[error("queue retry backoff is too large")]
    RetryBackoffTooLarge,
    /// A cleanup batch size must be at least one.
    #[error("queue cleanup batch size cannot be zero")]
    CleanupBatchSizeIsZero,
    /// A cleanup batch size exceeded [`crate::queue::MAX_CLEANUP_BATCH_SIZE`].
    #[error("queue cleanup batch size is {actual}, maximum is {max}")]
    CleanupBatchSizeTooLarge {
        /// Actual requested cleanup batch size.
        actual: u32,
        /// Maximum accepted cleanup batch size.
        max: u32,
    },
    /// A dead-letter move batch exceeded [`crate::queue::MAX_DEAD_LETTER_MOVE_BATCH_SIZE`].
    #[error("queue dead-letter move batch size is {actual}, maximum is {max}")]
    DeadLetterMoveBatchSizeTooLarge {
        /// Actual requested dead-letter move batch size.
        actual: usize,
        /// Maximum accepted dead-letter move batch size.
        max: u32,
    },
    /// A dead-letter move batch contained the same job ID more than once.
    #[error("queue dead-letter move batch contains duplicate job id {job_id}")]
    DuplicateJobIdInDeadLetterMoveBatch {
        /// Duplicated source job ID.
        job_id: JobId,
    },
    /// Persisted job status did not match the queue contract.
    #[error("queue persisted invalid job status {status:?}")]
    InvalidPersistedJobStatus {
        /// Persisted status text.
        status: String,
    },
    /// Persisted dead-letter reason did not match the queue contract.
    #[error("queue persisted invalid dead-letter reason {reason:?}")]
    InvalidPersistedDeadLetterReason {
        /// Persisted reason text.
        reason: String,
    },
    /// Persisted timeout sentinel did not match the queue contract.
    #[error("queue persisted invalid timeout_nanos {timeout_nanos}")]
    InvalidPersistedJobTimeout {
        /// Persisted timeout value.
        timeout_nanos: i64,
    },
    /// Persisted retry count was outside the queue contract.
    #[error("queue persisted invalid retry_count {retry_count}")]
    InvalidPersistedRetryCount {
        /// Persisted retry count.
        retry_count: i32,
    },
    /// Persisted max retry count was outside the queue contract.
    #[error("queue persisted invalid max_retries {max_retries}")]
    InvalidPersistedMaxRetries {
        /// Persisted max retry count.
        max_retries: i32,
    },
    /// A JSON payload could not be serialized.
    #[error("queue payload could not be encoded as JSON")]
    PayloadJson {
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// A JSON payload exceeded the queue payload-size limit.
    #[error("queue payload JSON is at least {actual_minimum} bytes, maximum is {max}")]
    PayloadJsonTooLarge {
        /// Lower bound on the serialized payload size.
        actual_minimum: usize,
        /// Configured maximum serialized payload size.
        max: usize,
    },
    /// A batch enqueue payload could not be serialized.
    #[error("queue batch payload at index {payload_index} could not be encoded as JSON")]
    EnqueueBatchPayloadJson {
        /// Zero-based payload index.
        payload_index: usize,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// A batch enqueue payload exceeded the queue payload-size limit.
    #[error(
        "queue batch payload at index {payload_index} is at least {actual_minimum} bytes, maximum is {max}"
    )]
    EnqueueBatchPayloadJsonTooLarge {
        /// Zero-based payload index.
        payload_index: usize,
        /// Lower bound on the serialized payload size.
        actual_minimum: usize,
        /// Configured maximum serialized payload size.
        max: usize,
    },
    /// A database row could not be decoded.
    #[error("queue database row could not be decoded")]
    DecodeRow {
        /// Underlying row decoding error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The database returned an impossible transition outcome.
    #[error("queue operation {operation} returned unexpected outcome {outcome:?}")]
    UnexpectedOutcome {
        /// Operation being executed.
        operation: &'static str,
        /// Returned outcome text.
        outcome: String,
    },
    /// A database operation failed.
    #[error(transparent)]
    Database(#[from] crate::db::Error),
    /// A Fleet primitive operation failed.
    #[error(transparent)]
    Fleet(#[from] FleetPrimitiveError),
    /// Job ID generation or parsing failed.
    #[error(transparent)]
    JobId(#[from] id::Error),
}
impl Error {
    pub(crate) fn decode_row(source: sqlx::Error) -> Self {
        Self::DecodeRow {
            source: Box::new(source),
        }
    }
}
