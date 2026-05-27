use super::*;

/// Queue job identifier.
pub type JobId = crate::id::SortableId;

/// Persisted queue job lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStatus {
    /// Job is waiting to be claimed.
    Pending,
    /// Job is owned by a worker.
    Running,
    /// Job finished successfully.
    Completed,
    /// Job failed terminally or is awaiting operator retry.
    Failed,
}

/// Execution timeout stored on a queue job.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum JobTimeout {
    /// Use the worker's configured default timeout.
    #[default]
    WorkerDefault,
    /// Run without a queue-enforced timeout.
    NoTimeout,
    /// Use this job-specific execution timeout.
    ExpiresAfter(Duration),
}

/// Earliest time at which a queued job may be claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobRunAtOrAfter {
    unix_microseconds: i64,
}

impl JobRunAtOrAfter {
    /// Creates a schedule time from Unix microseconds.
    pub fn from_unix_microseconds(unix_microseconds: i64) -> Result<Self, Error> {
        if unix_microseconds < 0 {
            return Err(Error::RunAtOrAfterUnixMicrosecondsIsNegative {
                actual: unix_microseconds,
            });
        }
        if unix_microseconds > MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS {
            return Err(Error::RunAtOrAfterUnixMicrosecondsTooLarge {
                actual: unix_microseconds as u128,
                max: MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS,
            });
        }
        Ok(Self { unix_microseconds })
    }

    /// Creates a schedule time from a [`SystemTime`].
    pub fn from_system_time(system_time: SystemTime) -> Result<Self, Error> {
        let duration = system_time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::RunAtOrAfterBeforeUnixEpoch)?;
        let unix_microseconds = duration.as_micros();
        if unix_microseconds > MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS as u128 {
            return Err(Error::RunAtOrAfterUnixMicrosecondsTooLarge {
                actual: unix_microseconds,
                max: MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS,
            });
        }
        Ok(Self {
            unix_microseconds: unix_microseconds as i64,
        })
    }

    /// Returns this schedule time as Unix microseconds.
    pub fn as_unix_microseconds(self) -> i64 {
        self.unix_microseconds
    }
}

/// Options for enqueuing a job.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnqueueOptions {
    /// Optional earliest claim time.
    pub run_at_or_after: Option<JobRunAtOrAfter>,
    /// Optional max retry count. `None` uses [`crate::queue::DEFAULT_MAX_RETRIES`].
    pub max_retries: Option<u32>,
    /// Job timeout behavior.
    pub timeout: JobTimeout,
    /// Optional active dedupe key.
    pub dedupe_key: Option<String>,
}

/// Options for batch-enqueuing jobs for one task.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnqueueBatchOptions {
    /// Optional earliest claim time.
    pub run_at_or_after: Option<JobRunAtOrAfter>,
    /// Optional max retry count. `None` uses [`crate::queue::DEFAULT_MAX_RETRIES`].
    pub max_retries: Option<u32>,
    /// Job timeout behavior.
    pub timeout: JobTimeout,
}

/// Result of an enqueue operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnqueueResult {
    /// Inserted or reused job identifier.
    pub job_id: JobId,
    /// Whether an existing active job was reused.
    pub deduplicated: bool,
}

/// Queue job loaded from the database.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Job {
    /// Job identifier.
    pub id: JobId,
    /// Task name.
    pub task_name: String,
    /// Raw JSON payload text.
    pub payload_json: String,
    /// Lifecycle state.
    pub status: JobStatus,
    /// Earliest run time as Unix microseconds.
    pub run_at_or_after_unix_microseconds: i64,
    /// Last error text, when present.
    pub last_error: Option<String>,
    /// Number of retry attempts already consumed.
    pub retry_count: u32,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Job timeout behavior.
    pub timeout: JobTimeout,
    /// Active dedupe key, when present.
    pub dedupe_key: Option<String>,
    /// Unique worker owner ID, when running.
    pub worker_owner_id: Option<WorkerOwnerId>,
    /// Claim timestamp as Unix microseconds.
    pub claimed_by_worker_at_unix_microseconds: Option<i64>,
    /// Handler start timestamp as Unix microseconds.
    pub execution_started_at_unix_microseconds: Option<i64>,
    /// Execution heartbeat timestamp as Unix microseconds.
    pub execution_heartbeat_at_unix_microseconds: Option<i64>,
    /// Terminal timestamp as Unix microseconds.
    pub finished_at_unix_microseconds: Option<i64>,
    /// Creation timestamp as Unix microseconds.
    pub created_at_unix_microseconds: i64,
    /// Last update timestamp as Unix microseconds.
    pub updated_at_unix_microseconds: i64,
}

/// Reason a job was moved into dead-letter storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadLetterReason {
    /// The job exhausted its retry budget.
    MaxRetriesExceeded,
    /// The handler declared the error permanent.
    PermanentError,
    /// An operator explicitly moved the job.
    OperatorAction,
    /// Execution exceeded reclaim safety bounds.
    ExecutionExpired,
}

/// Queue job loaded from dead-letter storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeadLetterJob {
    /// Dead-letter row identifier.
    pub id: JobId,
    /// Source job identifier from the main jobs table.
    pub original_job_id: JobId,
    /// Task name.
    pub task_name: String,
    /// Raw JSON payload text.
    pub payload_json: String,
    /// Error text captured at dead-letter time.
    pub last_error: String,
    /// Number of retry attempts consumed before dead-lettering.
    pub retry_count: u32,
    /// Maximum retry attempts configured on the original job.
    pub max_retries: u32,
    /// Job timeout behavior carried by the original job.
    pub timeout: JobTimeout,
    /// Active dedupe key carried by the original job, when present.
    pub dedupe_key: Option<String>,
    /// Why the job was dead-lettered.
    pub reason: DeadLetterReason,
    /// Dead-letter timestamp as Unix microseconds.
    pub dead_lettered_at_unix_microseconds: i64,
    /// Original job creation timestamp as Unix microseconds.
    pub created_at_unix_microseconds: i64,
    /// Original job update timestamp as Unix microseconds.
    pub updated_at_unix_microseconds: i64,
}

/// Options for listing queue jobs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListJobsOptions {
    /// Optional status filters. Duplicate values are ignored.
    pub statuses: Vec<JobStatus>,
    /// Optional task filter.
    pub task_name: Option<String>,
    /// Optional positive page size. Defaults to [`crate::queue::DEFAULT_LIST_LIMIT`].
    pub limit: Option<u32>,
    /// Optional cursor. Results start strictly after this job ID.
    pub cursor_id: Option<JobId>,
}

/// Page of listed queue jobs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListJobsResult {
    /// Listed jobs.
    pub jobs: Vec<Job>,
    /// Cursor for the next page, when more rows exist.
    pub next_cursor_id: Option<JobId>,
}

/// Options for listing dead-letter jobs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListDeadLetterJobsOptions {
    /// Optional task filter.
    pub task_name: Option<String>,
    /// Optional positive page size. Defaults to [`crate::queue::DEFAULT_LIST_LIMIT`].
    pub limit: Option<u32>,
    /// Optional cursor. Results start strictly after this dead-letter row ID.
    pub cursor_id: Option<JobId>,
}

/// Page of listed dead-letter jobs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListDeadLetterJobsResult {
    /// Listed dead-letter jobs.
    pub jobs: Vec<DeadLetterJob>,
    /// Cursor for the next page, when more rows exist.
    pub next_cursor_id: Option<JobId>,
}

/// Job reclaimed from stale running state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReclaimedJob {
    /// Reclaimed job identifier.
    pub id: JobId,
    /// Reclaimed job task name.
    pub task_name: String,
}

/// Job reclaimed into failed state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReclaimedFailedJob {
    /// Reclaimed job identifier.
    pub id: JobId,
    /// Reclaimed job task name.
    pub task_name: String,
    /// Failure text persisted during reclaim.
    pub last_error: String,
}

/// Failed job moved into dead-letter storage by a batch operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MovedToDeadLetterJob {
    /// Dead-letter row identifier.
    pub dead_letter_id: JobId,
    /// Source failed job identifier.
    pub original_job_id: JobId,
    /// Source task name.
    pub task_name: String,
    /// Source failure text at dead-letter time.
    pub last_error: String,
}

/// Result of moving a bounded batch of available failed jobs into dead-letter storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveFailedJobsToDeadLetterBatchResult {
    /// Number of job IDs supplied to the batch operation.
    pub requested_count: usize,
    /// Jobs that were actually moved.
    pub moved_jobs: Vec<MovedToDeadLetterJob>,
}

/// Result of one available stale-running-job reclaim pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStaleRunningJobsResult {
    /// Running jobs claimed by dead workers before handler start and returned to pending.
    pub never_started_jobs_returned_to_pending: Vec<ReclaimedJob>,
    /// Started running jobs that exhausted retry budget and were moved to failed state.
    pub expired_jobs_moved_to_failed: Vec<ReclaimedFailedJob>,
    /// Failed jobs moved to dead-letter storage after stale execution expiry.
    pub expired_jobs_moved_to_dead_letter: Vec<MovedToDeadLetterJob>,
    /// Started running jobs with remaining retry budget and returned to pending.
    pub expired_jobs_returned_to_pending_for_retry: Vec<ReclaimedJob>,
}

/// Aggregated queue status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusCounts {
    /// Pending jobs count.
    pub pending_count: i64,
    /// Running jobs count.
    pub running_count: i64,
    /// Completed jobs count.
    pub completed_count: i64,
    /// Failed jobs count.
    pub failed_count: i64,
    /// Dead-letter jobs count.
    pub dead_letter_count: i64,
}

/// Queue load and pause-state summary for worker/admin views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerPressure {
    /// Whether global queue execution is paused.
    pub queue_paused: bool,
    /// Task names currently paused, sorted ascending.
    pub paused_task_names: Vec<String>,
    /// Number of handlers registered in the supplied task registry.
    pub registered_task_count: usize,
    /// Pending jobs count.
    pub pending_job_count: i64,
    /// Running jobs count.
    pub running_job_count: i64,
}

impl StatusCounts {
    /// Returns the sum of all queue and dead-letter status buckets.
    pub fn total_count(&self) -> i64 {
        self.pending_count
            + self.running_count
            + self.completed_count
            + self.failed_count
            + self.dead_letter_count
    }
}

impl MoveFailedJobsToDeadLetterBatchResult {
    /// Returns how many requested rows were not moved because they were absent, locked, or not failed.
    pub fn skipped_count(&self) -> usize {
        self.requested_count.saturating_sub(self.moved_jobs.len())
    }
}

impl JobStatus {
    /// Returns the persisted status text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub(in crate::db::queue) fn parse(input: &str) -> Result<Self, Error> {
        match input {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            other => Err(Error::InvalidPersistedJobStatus {
                status: other.to_owned(),
            }),
        }
    }
}

impl DeadLetterReason {
    /// Returns the persisted reason text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxRetriesExceeded => "max_retries_exceeded",
            Self::PermanentError => "permanent_error",
            Self::OperatorAction => "operator_action",
            Self::ExecutionExpired => "execution_expired",
        }
    }

    pub(in crate::db::queue) fn parse(input: &str) -> Result<Self, Error> {
        match input {
            "max_retries_exceeded" => Ok(Self::MaxRetriesExceeded),
            "permanent_error" => Ok(Self::PermanentError),
            "operator_action" => Ok(Self::OperatorAction),
            "execution_expired" => Ok(Self::ExecutionExpired),
            other => Err(Error::InvalidPersistedDeadLetterReason {
                reason: other.to_owned(),
            }),
        }
    }
}
