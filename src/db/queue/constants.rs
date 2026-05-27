use super::*;

/// Size, in bytes, of queue job identifiers.
pub const JOB_ID_SIZE: usize = id::SORTABLE_ID_SIZE;

/// Default queue jobs table name.
pub const DEFAULT_QUEUE_TABLE_NAME: &str = "__paranoid_queue_jobs";

/// Default queue dead-letter table name.
pub const DEFAULT_QUEUE_DEAD_LETTER_TABLE_NAME: &str = "__paranoid_queue_dead_letters";

/// Default queue pause-state table name.
pub const DEFAULT_QUEUE_PAUSE_TABLE_NAME: &str = "__paranoid_queue_pauses";

pub(crate) const QUEUE_SCHEMA_COMPONENT: &str = "queue";
pub(crate) const QUEUE_SCHEMA_VERSION: i32 = 1;
pub(crate) const QUEUE_SCHEMA_FINGERPRINT: &str = "paranoid.queue.v1";

/// Default number of retries for newly enqueued jobs.
pub const DEFAULT_QUEUE_MAX_RETRIES: u32 = 5;

/// Maximum task name length in bytes.
pub const MAX_QUEUE_TASK_NAME_BYTES: usize = 128;

/// Maximum active dedupe key length in bytes.
pub const MAX_QUEUE_DEDUPE_KEY_BYTES: usize = 512;

/// Maximum worker owner ID length in bytes.
pub const MAX_QUEUE_WORKER_OWNER_ID_BYTES: usize = 512;

/// Maximum logical worker name length in bytes.
pub const MAX_QUEUE_WORKER_NAME_BYTES: usize =
    MAX_QUEUE_WORKER_OWNER_ID_BYTES - QUEUE_WORKER_OWNER_ID_SUFFIX_BYTES;

pub(crate) const QUEUE_WORKER_OWNER_ID_SEPARATOR: &str = ".";
pub(crate) const QUEUE_WORKER_OWNER_ID_SUFFIX_BYTES: usize = 1 + id::SORTABLE_ID_TEXT_LEN;

/// Maximum number of jobs inserted by one batch enqueue call.
pub const MAX_QUEUE_ENQUEUE_BATCH_SIZE: u32 = 1000;

/// Default maximum serialized JSON payload size per queued job.
pub const DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES: usize = 1 << 20;

/// Maximum configurable serialized JSON payload size per queued job.
pub const MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES: usize = 16 << 20;

/// Maximum accepted queued-job schedule time, as Unix microseconds.
///
/// This is `9999-12-31T23:59:59.999999Z`, which gives applications an
/// effectively-future scheduling bound without accepting nonsensical or
/// database-hostile timestamp values.
pub const MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS: i64 = 253_402_300_799_999_999;

/// Maximum number of jobs that can be claimed in one call.
pub const MAX_QUEUE_CLAIM_LIMIT: u32 = 1000;

/// Default page size for queue list operations.
pub const DEFAULT_QUEUE_LIST_LIMIT: u32 = 100;

/// Maximum page size for queue list operations.
pub const MAX_QUEUE_LIST_LIMIT: u32 = 1000;

/// Maximum number of failed jobs that can be retried in one call.
pub const MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT: u32 = 1000;

/// Default maximum number of stale running jobs reclaimed in one pass per reclaim category.
pub const DEFAULT_QUEUE_RECLAIM_BATCH_SIZE: u32 = 1000;

/// Maximum number of stale running jobs reclaimed in one pass per reclaim category.
pub const MAX_QUEUE_RECLAIM_BATCH_SIZE: u32 = MAX_QUEUE_DEAD_LETTER_MOVE_BATCH_SIZE;

/// Default number of rows deleted by one cleanup call.
pub const DEFAULT_QUEUE_CLEANUP_BATCH_SIZE: u32 = 1000;

/// Default delay between cleanup batches when draining old terminal rows.
pub const DEFAULT_QUEUE_CLEANUP_BATCH_DELAY: Duration = Duration::from_millis(10);

/// Maximum number of rows deleted by one cleanup call.
pub const MAX_QUEUE_CLEANUP_BATCH_SIZE: u32 = 10_000;

/// Maximum number of failed jobs moved to dead-letter storage in one batch.
pub const MAX_QUEUE_DEAD_LETTER_MOVE_BATCH_SIZE: u32 = 2048;

/// Default maximum number of jobs processed by one worker pass.
pub const DEFAULT_QUEUE_WORKER_CONCURRENCY: u32 = 10;

/// Maximum number of jobs processed by one worker pass.
pub const MAX_QUEUE_WORKER_CONCURRENCY: u32 = MAX_QUEUE_CLAIM_LIMIT;

/// Default idle worker polling interval.
pub const DEFAULT_QUEUE_WORKER_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Default maximum startup jitter as a fraction of the worker polling interval.
pub const DEFAULT_QUEUE_WORKER_STARTUP_JITTER_FRACTION: f64 = 0.25;

/// Default timeout for jobs that request the worker default timeout.
pub const DEFAULT_QUEUE_WORKER_JOB_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Default stale running-job threshold used for worker timing validation.
pub const DEFAULT_QUEUE_WORKER_STALE_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Default execution heartbeat cadence for running jobs.
pub const DEFAULT_QUEUE_WORKER_EXECUTION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Default maximum wait for in-flight jobs after a worker stop request.
pub const DEFAULT_QUEUE_WORKER_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Default maximum wait for one worker-owned database operation.
pub const DEFAULT_QUEUE_WORKER_DATABASE_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default Fleet cron interval for reclaiming stale queue jobs.
pub const DEFAULT_QUEUE_WORKER_RECLAIM_INTERVAL: Duration = Duration::from_secs(30);

/// Default Fleet cron interval for cleaning terminal queue rows.
pub const DEFAULT_QUEUE_WORKER_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Default retention for completed queue jobs.
pub const DEFAULT_QUEUE_COMPLETED_JOB_RETENTION: Duration = Duration::from_secs(60 * 60);

/// Default retention for failed queue jobs.
pub const DEFAULT_QUEUE_FAILED_JOB_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Default retention for dead-letter queue jobs.
pub const DEFAULT_QUEUE_DEAD_LETTER_JOB_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Minimum retry backoff returned by queue retry policies.
pub const MIN_QUEUE_RETRY_BACKOFF: Duration = Duration::from_millis(1);

/// Default maximum retry backoff.
pub const DEFAULT_QUEUE_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// Default exponential retry base.
pub const DEFAULT_QUEUE_RETRY_EXPONENTIAL_BASE: f64 = 2.0;

/// Default symmetric retry jitter fraction.
pub const DEFAULT_QUEUE_RETRY_JITTER_FRACTION: f64 = 0.2;

pub(crate) const MIN_QUEUE_STALE_THRESHOLD_TO_JOB_TIMEOUT_RATIO: u32 = 2;
pub(crate) const GLOBAL_PAUSE_KEY: &str = "__global__";
pub(crate) const TASK_PAUSE_KEY_PREFIX: &str = "task:";
pub(crate) const STALE_EXECUTION_ERROR: &str = "execution expired (stale threshold exceeded)";

pub(crate) const INDEX_KIND: &str = "idx";
pub(crate) const UNIQUE_INDEX_KIND: &str = "uidx";
pub(crate) const CHECK_KIND: &str = "chk";

pub(crate) const PENDING_RUN_AT_INDEX_SUFFIX: &str = "pending_run_at";
pub(crate) const PENDING_TASK_RUN_AT_INDEX_SUFFIX: &str = "pending_task_run_at";
pub(crate) const TASK_STATUS_INDEX_SUFFIX: &str = "task_status";
pub(crate) const WORKER_INDEX_SUFFIX: &str = "worker";
pub(crate) const EXECUTION_HEARTBEAT_INDEX_SUFFIX: &str = "execution_heartbeat";
pub(crate) const CLEANUP_INDEX_SUFFIX: &str = "cleanup";
pub(crate) const ACTIVE_DEDUPE_INDEX_SUFFIX: &str = "dedupe_active";
pub(crate) const DEAD_LETTERED_AT_INDEX_SUFFIX: &str = "dead_lettered_at";
pub(crate) const TASK_DEAD_LETTERED_AT_INDEX_SUFFIX: &str = "task_dead_lettered_at";
pub(crate) const ORIGINAL_JOB_INDEX_SUFFIX: &str = "original_job";
pub(crate) const PAUSE_TASK_INDEX_SUFFIX: &str = "task_name";
pub(crate) const JOB_STATUS_CONSTRAINT_SUFFIX: &str = "status_allowed";
pub(crate) const JOB_LIFECYCLE_CONSTRAINT_SUFFIX: &str = "status_lifecycle_shape";
pub(crate) const JOB_NUMERIC_CONSTRAINT_SUFFIX: &str = "numeric_domains";
pub(crate) const JOB_TEXT_CONSTRAINT_SUFFIX: &str = "text_domains";
pub(crate) const DEAD_LETTER_REASON_CONSTRAINT_SUFFIX: &str = "reason_allowed";
pub(crate) const DEAD_LETTER_NUMERIC_CONSTRAINT_SUFFIX: &str = "numeric_domains";
pub(crate) const DEAD_LETTER_TEXT_CONSTRAINT_SUFFIX: &str = "text_domains";
pub(crate) const PAUSE_KEY_TASK_CONSTRAINT_SUFFIX: &str = "key_task_match";
pub(crate) const PAUSE_TEXT_CONSTRAINT_SUFFIX: &str = "text_domains";

pub(crate) const ENQUEUE_OUTCOME_INSERTED: &str = "inserted";
pub(crate) const ENQUEUE_OUTCOME_QUEUE_PAUSED: &str = "queue_paused";
pub(crate) const ENQUEUE_OUTCOME_TASK_PAUSED: &str = "task_paused";
pub(crate) const ENQUEUE_OUTCOME_NOT_INSERTED: &str = "not_inserted";
pub(crate) const MAX_QUEUE_DEDUPE_INSERT_ATTEMPTS: usize = 5;
pub(crate) const TRANSITION_OUTCOME_APPLIED: &str = "applied";
pub(crate) const TRANSITION_OUTCOME_NOT_FOUND: &str = "not_found";
pub(crate) const TRANSITION_OUTCOME_STATE_MISMATCH: &str = "state_mismatch";
pub(crate) const TRANSITION_OUTCOME_DEDUPE_CONFLICT: &str = "dedupe_conflict";
pub(crate) const TRANSITION_OUTCOME_LOCKED: &str = "locked";
pub(crate) const MIN_QUEUE_WORKER_CLAIM_ERROR_BACKOFF: Duration = Duration::from_secs(1);
pub(crate) const MAX_QUEUE_WORKER_CLAIM_ERROR_BACKOFF: Duration = Duration::from_secs(30);
