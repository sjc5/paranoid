use super::*;

/// Retry backoff strategy for worker-executed jobs.
#[derive(Clone)]
pub enum RetryBackoffStrategy {
    /// Exponential backoff using `base ^ retry_count`, capped by [`RetryPolicy::max_backoff`].
    Exponential {
        /// Exponential base. Must be finite and greater than one.
        base: f64,
    },
    /// Fixed backoff.
    Fixed {
        /// Fixed retry delay. Must be positive.
        backoff: Duration,
    },
    /// Caller-supplied backoff function, capped by [`RetryPolicy::max_backoff`].
    Custom(RetryBackoffFn),
}

/// Custom retry backoff function.
pub type RetryBackoffFn = Arc<dyn Fn(u32, &TaskError) -> Duration + Send + Sync + 'static>;

/// Retry policy for worker-executed jobs.
#[derive(Clone)]
pub struct RetryPolicy {
    /// Backoff strategy and strategy-specific parameters.
    pub strategy: RetryBackoffStrategy,
    /// Maximum backoff for exponential and custom strategies.
    pub max_backoff: Duration,
    /// Symmetric jitter fraction. `0.2` means +/-20%.
    pub jitter_fraction: f64,
}

/// Worker default timeout behavior for jobs that do not carry their own timeout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WorkerDefaultJobTimeout {
    /// Use [`crate::queue::DEFAULT_WORKER_JOB_TIMEOUT`].
    #[default]
    Default,
    /// Run jobs without a worker-level timeout.
    NoTimeout,
    /// Use this worker-level timeout.
    ExpiresAfter(Duration),
}

/// Configuration for one queue worker pass.
#[derive(Clone)]
pub struct WorkerConfig {
    /// How often an idle long-running worker polls for due jobs.
    pub poll_interval: Duration,
    /// Maximum random delay before the first long-running worker claim. `None` uses the default fraction of `poll_interval`; `Some(Duration::ZERO)` disables startup jitter.
    pub startup_jitter_max_delay: Option<Duration>,
    /// Maximum jobs claimed by one worker pass.
    pub concurrency: u32,
    /// Stale threshold used to validate heartbeat timing.
    pub stale_threshold: Duration,
    /// Automatic heartbeat cadence.
    pub execution_heartbeat_interval: Duration,
    /// Timeout used when a job asks for the worker default.
    pub default_job_timeout: WorkerDefaultJobTimeout,
    /// Retry policy.
    pub retry_policy: RetryPolicy,
    /// Whether worker failures should move terminal jobs to dead-letter storage.
    pub dead_letter_enabled: bool,
    /// Maximum graceful wait after a long-running worker receives a stop request.
    pub shutdown_grace_period: Duration,
    /// Maximum wait for one worker-owned database operation.
    pub database_operation_timeout: Duration,
}

/// Fleet-backed maintenance configuration for a long-running queue worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerMaintenanceConfig {
    /// Optional namespace used to derive distinct reclaim and cleanup Fleet cron keys.
    pub cron_key_namespace: Option<CronKey>,
    /// How often the single maintenance leader reclaims stale running jobs.
    pub reclaim_interval: Duration,
    /// How often the single maintenance leader cleans terminal rows.
    pub cleanup_interval: Duration,
    /// Completed-job retention before cleanup may delete rows.
    pub completed_job_retention: Duration,
    /// Failed-job retention before cleanup may delete rows.
    pub failed_job_retention: Duration,
    /// Dead-letter retention before cleanup may delete rows.
    pub dead_letter_job_retention: Duration,
    /// Maximum stale running jobs reclaimed in one pass per reclaim category.
    pub reclaim_batch_size: u32,
    /// Maximum terminal rows deleted by one cleanup batch.
    pub cleanup_batch_size: u32,
    /// Delay between cleanup batches. `Duration::ZERO` means no delay.
    pub delay_between_cleanup_batches: Duration,
}

/// Error returned by a queue task handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskError {
    pub(in crate::db::queue) message: String,
    pub(in crate::db::queue) permanent: bool,
}

/// Context passed to queue task handlers.
#[derive(Clone)]
pub struct JobExecutionContext {
    pub(in crate::db::queue) queue: Store,
    pub(in crate::db::queue) pool: WritePool,
    pub(in crate::db::queue) job_id: JobId,
    pub(in crate::db::queue) task_name: String,
    pub(in crate::db::queue) worker_owner_id: WorkerOwnerId,
    pub(in crate::db::queue) retry_count: u32,
    pub(in crate::db::queue) max_retries: u32,
    pub(in crate::db::queue) worker_shutdown_signal: RuntimeCancellationSignal,
    pub(in crate::db::queue) job_cancellation_signal: RuntimeCancellationSignal,
    pub(in crate::db::queue) database_operation_timeout: Duration,
}

pub(in crate::db::queue) type TaskFuture =
    Pin<Box<dyn Future<Output = Result<(), TaskError>> + Send + 'static>>;

pub(in crate::db::queue) type TaskHandler =
    Arc<dyn Fn(JobExecutionContext, String) -> TaskFuture + Send + Sync + 'static>;

/// Registered worker task handlers.
#[derive(Clone, Default)]
pub struct TaskRegistry {
    pub(in crate::db::queue) handlers: Arc<HashMap<String, TaskHandler>>,
}

/// Explicit opt-in handle for manually driving the queue worker protocol.
#[must_use = "use this handle to claim jobs and complete their manual worker lifecycle"]
pub struct ManualWorkerProtocol<'a> {
    pub(in crate::db::queue) queue: &'a Store,
}

/// Unique owner token for one manually driven worker lifecycle.
///
/// This is not a stable logical worker name. Create a fresh owner ID for each
/// independent manual worker run, then use that same value for claim,
/// heartbeat, completion, retry, failure, dead-letter, and cleanup operations
/// belonging to that run.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WorkerOwnerId {
    value: String,
}

impl WorkerOwnerId {
    /// Creates a fresh worker owner ID derived from a logical worker name.
    pub fn new_unique_for_worker_name(worker_name: impl AsRef<str>) -> Result<Self, Error> {
        Self::from_validated_text(new_unique_worker_owner_id(worker_name.as_ref())?)
    }

    /// Creates a worker owner ID from caller-managed manual lifecycle text.
    ///
    /// Prefer [`Self::new_unique_for_worker_name`] unless an application is
    /// deliberately continuing an owner ID it already controls.
    pub fn from_manual_worker_lifecycle_owner_id_text(
        worker_owner_id: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::from_validated_text(worker_owner_id.into())
    }

    /// Returns the worker owner ID text stored in running queue rows.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub(in crate::db::queue) fn from_validated_text(value: String) -> Result<Self, Error> {
        validate_worker_owner_id(&value)?;
        Ok(Self { value })
    }
}

impl AsRef<str> for WorkerOwnerId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for WorkerOwnerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Queue-bound handle for a registered typed JSON task.
#[derive(Debug)]
pub struct RegisteredJsonTask<T> {
    pub(in crate::db::queue) queue: Store,
    pub(in crate::db::queue) task_name: String,
    pub(in crate::db::queue) payload_type: PhantomData<fn() -> T>,
}

/// Summary returned after one worker pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerRunOnceSummary {
    /// Claimed jobs count.
    pub claimed_count: u32,
    /// Jobs completed successfully.
    pub succeeded_count: u32,
    /// Jobs scheduled for retry.
    pub retried_count: u32,
    /// Jobs marked failed without dead-lettering.
    pub failed_count: u32,
    /// Jobs moved to dead-letter storage.
    pub dead_lettered_count: u32,
    /// Jobs whose ownership disappeared before a terminal worker update.
    pub lost_ownership_count: u32,
}

/// Summary returned after a long-running worker stops.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerRunLoopSummary {
    /// Claimed jobs count.
    pub claimed_count: u32,
    /// Jobs completed successfully.
    pub succeeded_count: u32,
    /// Jobs scheduled for retry.
    pub retried_count: u32,
    /// Jobs marked failed without dead-lettering.
    pub failed_count: u32,
    /// Jobs moved to dead-letter storage.
    pub dead_lettered_count: u32,
    /// Jobs whose ownership disappeared before a terminal worker update.
    pub lost_ownership_count: u32,
}

/// Handle for a long-running queue worker.
#[must_use = "call stop_and_wait or request_stop followed by wait so the long-running queue worker lifecycle is observed"]
pub struct WorkerHandle {
    pub(in crate::db::queue) worker_shutdown_signal: RuntimeCancellationSignal,
    pub(in crate::db::queue) join_handle:
        Option<tokio::task::JoinHandle<Result<WorkerRunLoopSummary, Error>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) enum ProcessedJobOutcome {
    Succeeded,
    Retried,
    Failed,
    DeadLettered,
    LostOwnership,
}

#[derive(Clone)]
pub(in crate::db::queue) struct ResolvedWorkerConfig {
    pub(in crate::db::queue) poll_interval: Duration,
    pub(in crate::db::queue) startup_jitter_max_delay: Duration,
    pub(in crate::db::queue) concurrency: u32,
    pub(in crate::db::queue) stale_threshold: Duration,
    pub(in crate::db::queue) execution_heartbeat_interval: Duration,
    pub(in crate::db::queue) default_job_timeout: WorkerDefaultJobTimeout,
    pub(in crate::db::queue) retry_policy: RetryPolicy,
    pub(in crate::db::queue) dead_letter_enabled: bool,
    pub(in crate::db::queue) shutdown_grace_period: Duration,
    pub(in crate::db::queue) database_operation_timeout: Duration,
}

#[derive(Clone)]
pub(in crate::db::queue) struct WorkerRuntime {
    pub(in crate::db::queue) queue: Store,
    pub(in crate::db::queue) pool: WritePool,
    pub(in crate::db::queue) task_registry: TaskRegistry,
    pub(in crate::db::queue) worker_owner_id: WorkerOwnerId,
    pub(in crate::db::queue) config: ResolvedWorkerConfig,
    pub(in crate::db::queue) worker_shutdown_signal: RuntimeCancellationSignal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::db::queue) struct ResolvedWorkerMaintenanceConfig {
    pub(in crate::db::queue) reclaim_cron_key: CronKey,
    pub(in crate::db::queue) cleanup_cron_key: CronKey,
    pub(in crate::db::queue) reclaim_interval: Duration,
    pub(in crate::db::queue) cleanup_interval: Duration,
    pub(in crate::db::queue) completed_job_retention: Duration,
    pub(in crate::db::queue) failed_job_retention: Duration,
    pub(in crate::db::queue) dead_letter_job_retention: Duration,
    pub(in crate::db::queue) reclaim_batch_size: u32,
    pub(in crate::db::queue) cleanup_batch_size: u32,
    pub(in crate::db::queue) delay_between_cleanup_batches: Duration,
}

pub(in crate::db::queue) struct WorkerPressureCounts {
    pub(in crate::db::queue) pending_job_count: i64,
    pub(in crate::db::queue) running_job_count: i64,
}

#[derive(Clone)]
pub(in crate::db::queue) struct RuntimeCancellationSignal {
    pub(in crate::db::queue) requested: Arc<AtomicBool>,
    pub(in crate::db::queue) notify: Arc<Notify>,
}
