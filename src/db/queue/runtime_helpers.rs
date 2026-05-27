use super::*;

pub(in crate::db::queue) const QUEUE_SET_LOCAL_STATEMENT_TIMEOUT_QUERY: &str =
    "SELECT set_config('statement_timeout', $1, true)";

pub(super) fn timeout_from_persisted_nanos(timeout_nanos: i64) -> Result<JobTimeout, Error> {
    match timeout_nanos {
        -1 => Ok(JobTimeout::NoTimeout),
        0 => Ok(JobTimeout::WorkerDefault),
        value if value > 0 => Ok(JobTimeout::ExpiresAfter(Duration::from_nanos(value as u64))),
        value => Err(Error::InvalidPersistedJobTimeout {
            timeout_nanos: value,
        }),
    }
}

pub(super) fn retry_count_from_persisted_i32(retry_count: i32) -> Result<u32, Error> {
    retry_count
        .try_into()
        .map_err(|_| Error::InvalidPersistedRetryCount { retry_count })
}

pub(super) fn max_retries_from_persisted_i32(max_retries: i32) -> Result<u32, Error> {
    max_retries
        .try_into()
        .map_err(|_| Error::InvalidPersistedMaxRetries { max_retries })
}

pub(super) fn resolve_queue_job_timeout(
    timeout: JobTimeout,
    default_job_timeout: WorkerDefaultJobTimeout,
) -> Option<Duration> {
    match timeout {
        JobTimeout::NoTimeout => None,
        JobTimeout::WorkerDefault => match default_job_timeout {
            WorkerDefaultJobTimeout::Default => Some(DEFAULT_QUEUE_WORKER_JOB_TIMEOUT),
            WorkerDefaultJobTimeout::NoTimeout => None,
            WorkerDefaultJobTimeout::ExpiresAfter(timeout) => Some(timeout),
        },
        JobTimeout::ExpiresAfter(timeout) => Some(timeout),
    }
}

pub(super) fn resolve_queue_worker_default_job_timeout(
    default_job_timeout: WorkerDefaultJobTimeout,
) -> Result<WorkerDefaultJobTimeout, Error> {
    match default_job_timeout {
        WorkerDefaultJobTimeout::Default => Ok(WorkerDefaultJobTimeout::ExpiresAfter(
            DEFAULT_QUEUE_WORKER_JOB_TIMEOUT,
        )),
        WorkerDefaultJobTimeout::NoTimeout => Ok(WorkerDefaultJobTimeout::NoTimeout),
        WorkerDefaultJobTimeout::ExpiresAfter(duration) if duration.is_zero() => {
            Err(Error::InvalidWorkerConfig {
                reason: "default job timeout must be positive or disabled",
            })
        }
        WorkerDefaultJobTimeout::ExpiresAfter(duration) => {
            Ok(WorkerDefaultJobTimeout::ExpiresAfter(duration))
        }
    }
}

pub(super) async fn claim_available_jobs_for_worker_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    registered_task_names: &[String],
    claim_limit: u32,
    worker_id: &str,
    timeout: Duration,
) -> Result<Vec<Job>, Error> {
    let operation = "claim available jobs";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .claim_available_jobs_for_worker_in_current_transaction(
            &mut tx,
            registered_task_names,
            claim_limit,
            worker_id,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn mark_owned_running_job_started_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let operation = "mark owned running job started";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .mark_owned_running_job_started_in_current_transaction(&mut tx, job_id, worker_id)
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn mark_owned_running_job_completed_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let operation = "mark owned running job completed";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .mark_owned_running_job_completed_in_current_transaction(&mut tx, job_id, worker_id)
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn touch_owned_running_job_execution_heartbeat_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let operation = "touch owned running job execution heartbeat";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .touch_owned_running_job_execution_heartbeat_in_current_transaction(
            &mut tx, job_id, worker_id,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn schedule_owned_running_job_retry_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    new_retry_count: u32,
    retry_after: Duration,
    error_message: &str,
    timeout: Duration,
) -> Result<i64, Error> {
    let operation = "schedule owned running job retry";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .schedule_owned_running_job_retry_in_current_transaction(
            &mut tx,
            job_id,
            worker_id,
            new_retry_count,
            retry_after,
            error_message,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn move_owned_running_job_to_dead_letter_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    error_message: &str,
    increment_retry_count: bool,
    reason: DeadLetterReason,
    timeout: Duration,
) -> Result<JobId, Error> {
    let operation = "move owned running job to dead letter";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .move_owned_running_job_to_dead_letter_in_current_transaction(
            &mut tx,
            job_id,
            worker_id,
            error_message,
            increment_retry_count,
            reason,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn mark_owned_running_job_failed_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    error_message: &str,
    increment_retry_count: bool,
    timeout: Duration,
) -> Result<(), Error> {
    let operation = "mark owned running job failed";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .mark_owned_running_job_failed_in_current_transaction(
            &mut tx,
            job_id,
            worker_id,
            error_message,
            increment_retry_count,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn return_owned_started_running_job_to_pending_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let operation = "return owned started running job to pending";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .return_owned_started_running_job_to_pending_in_current_transaction(
            &mut tx, job_id, worker_id,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn return_available_owned_unstarted_running_jobs_to_pending_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    worker_id: &str,
    timeout: Duration,
) -> Result<u64, Error> {
    let operation = "return available owned unstarted running jobs to pending";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
            &mut tx, worker_id,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn return_available_owned_started_running_jobs_to_pending_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    worker_id: &str,
    timeout: Duration,
) -> Result<u64, Error> {
    let operation = "return available owned started running jobs to pending";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let result = queue
        .return_available_owned_started_running_jobs_to_pending_in_current_transaction(
            &mut tx, worker_id,
        )
        .await;
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn count_worker_owned_running_jobs_with_database_operation_timeout(
    queue: &Store,
    pool: &Pool,
    worker_id: &str,
    timeout: Duration,
) -> Result<i64, Error> {
    let operation = "count worker-owned running jobs";
    let mut tx = begin_worker_database_operation(pool, operation, timeout).await?;
    let statement = format!(
        "SELECT COUNT(*) FROM {} WHERE worker_id = $1 AND status = $2",
        queue.config().table_name.quoted()
    );
    record_database_operation(
        tx.database_operation_observer(),
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_COUNT_WORKER_OWNED_RUNNING_JOBS,
        Some(statement.as_str()),
    );
    let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(worker_id)
        .bind(JobStatus::Running.as_str())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)
        .map_err(Error::from);
    finish_worker_database_operation(tx, operation, timeout, result).await
}

pub(super) async fn retry_worker_database_operation_while_job_locked<T, Fut, F>(
    operation: &'static str,
    timeout: Duration,
    mut run_operation: F,
) -> Result<T, Error>
where
    F: FnMut(Duration) -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let started_at = std::time::Instant::now();
    loop {
        let operation_timeout =
            remaining_worker_database_operation_timeout(started_at, timeout, operation)?;
        match run_operation(operation_timeout).await {
            Err(Error::JobLockedByConcurrentTransaction) if started_at.elapsed() < timeout => {
                let remaining = timeout.saturating_sub(started_at.elapsed());
                tokio::time::sleep(remaining.min(Duration::from_millis(10))).await;
            }
            Err(Error::JobLockedByConcurrentTransaction) => {
                return Err(Error::WorkerDatabaseOperationTimedOut { operation, timeout });
            }
            result => return result,
        }
    }
}

async fn begin_worker_database_operation<'a>(
    pool: &'a Pool,
    operation: &'static str,
    operation_timeout: Duration,
) -> Result<Tx<'a>, Error> {
    let started_at = std::time::Instant::now();
    let mut tx = tokio::time::timeout(operation_timeout, pool.begin_transaction())
        .await
        .map_err(|_| Error::WorkerDatabaseOperationTimedOut {
            operation,
            timeout: operation_timeout,
        })?
        .map_err(Error::from)?;

    let remaining_timeout =
        remaining_worker_database_operation_timeout(started_at, operation_timeout, operation)?;
    let timeout_value = postgres_statement_timeout_value(remaining_timeout);
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SET_LOCAL_STATEMENT_TIMEOUT,
        Some(QUEUE_SET_LOCAL_STATEMENT_TIMEOUT_QUERY),
    );
    tokio::time::timeout(
        remaining_timeout,
        pooler_safe_query(QUEUE_SET_LOCAL_STATEMENT_TIMEOUT_QUERY)
            .bind(timeout_value)
            .execute(tx.inner.as_mut()),
    )
    .await
    .map_err(|_| Error::WorkerDatabaseOperationTimedOut {
        operation,
        timeout: operation_timeout,
    })?
    .map_err(DbError::query)?;
    Ok(tx)
}

pub(in crate::db::queue) fn remaining_worker_database_operation_timeout(
    started_at: std::time::Instant,
    operation_timeout: Duration,
    operation: &'static str,
) -> Result<Duration, Error> {
    let elapsed = started_at.elapsed();
    if elapsed >= operation_timeout {
        return Err(Error::WorkerDatabaseOperationTimedOut {
            operation,
            timeout: operation_timeout,
        });
    }
    Ok(operation_timeout - elapsed)
}

async fn finish_worker_database_operation<T>(
    tx: Tx<'_>,
    operation: &'static str,
    timeout: Duration,
    result: Result<T, Error>,
) -> Result<T, Error> {
    let result = result.map_err(|error| {
        if error_is_postgres_statement_timeout(&error) {
            Error::WorkerDatabaseOperationTimedOut { operation, timeout }
        } else {
            error
        }
    });

    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::WorkerDatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}

pub(in crate::db::queue) fn postgres_statement_timeout_value(timeout: Duration) -> String {
    let milliseconds = timeout.as_millis().clamp(1, i64::MAX as u128);
    format!("{milliseconds}ms")
}

fn error_is_postgres_statement_timeout(error: &Error) -> bool {
    matches!(
        error,
        Error::Database(DbError::Query {
            sql_state: Some(PgSqlState::Other(code)),
            ..
        }) if code == "57014"
    )
}

pub(super) fn resolve_queue_worker_concurrency(concurrency: u32) -> Result<u32, Error> {
    if concurrency == 0 {
        return Err(Error::InvalidWorkerConfig {
            reason: "concurrency must be positive",
        });
    }
    if concurrency > MAX_QUEUE_WORKER_CONCURRENCY {
        return Err(Error::WorkerConcurrencyTooLarge {
            actual: concurrency,
            max: MAX_QUEUE_WORKER_CONCURRENCY,
        });
    }
    Ok(concurrency)
}

pub(super) fn validate_positive_worker_duration(
    duration: Duration,
    reason: &'static str,
) -> Result<Duration, Error> {
    if duration.is_zero() {
        return Err(Error::InvalidWorkerConfig { reason });
    }
    Ok(duration)
}

pub(super) fn resolve_queue_worker_startup_jitter_max_delay(
    poll_interval: Duration,
    configured_startup_jitter_max_delay: Option<Duration>,
) -> Duration {
    if let Some(configured_startup_jitter_max_delay) = configured_startup_jitter_max_delay {
        return configured_startup_jitter_max_delay;
    }
    duration_from_nonnegative_seconds(
        poll_interval.as_secs_f64() * DEFAULT_QUEUE_WORKER_STARTUP_JITTER_FRACTION,
        None,
    )
}

pub(super) fn resolve_queue_maintenance_cron_key_namespace(
    queue_config: &StoreConfig,
    configured: Option<CronKey>,
) -> Result<CronKey, Error> {
    if let Some(configured) = configured {
        return Ok(configured);
    }
    let schema_part = queue_config
        .table_name
        .schema()
        .map(|schema| schema.as_str())
        .unwrap_or("default_schema");
    CronKey::new(format!(
        "queue.{}.{}",
        schema_part,
        queue_config.table_name.table().as_str()
    ))
    .map_err(Error::from)
}

pub(super) fn resolve_queue_maintenance_interval(duration: Duration) -> Result<Duration, Error> {
    if duration < MIN_FLEET_CRON_INTERVAL {
        return Err(FleetPrimitiveError::InvalidCronInterval {
            minimum: MIN_FLEET_CRON_INTERVAL,
        }
        .into());
    }
    Ok(duration)
}

pub(super) fn resolve_queue_maintenance_retention(duration: Duration) -> Result<Duration, Error> {
    duration_to_rounded_microseconds(duration)?;
    Ok(duration)
}

pub(super) fn validate_worker_timing(
    stale_threshold: Duration,
    execution_heartbeat_interval: Duration,
    configured_default_job_timeout: WorkerDefaultJobTimeout,
    resolved_default_job_timeout: WorkerDefaultJobTimeout,
) -> Result<(), Error> {
    if stale_threshold.is_zero() {
        return Err(Error::InvalidWorkerConfig {
            reason: "stale threshold must be positive",
        });
    }
    if execution_heartbeat_interval.is_zero() {
        return Err(Error::InvalidWorkerConfig {
            reason: "execution heartbeat interval must be positive",
        });
    }
    if matches!(
        resolved_default_job_timeout,
        WorkerDefaultJobTimeout::ExpiresAfter(duration) if duration.is_zero()
    ) {
        return Err(Error::InvalidWorkerConfig {
            reason: "default job timeout must be positive or disabled",
        });
    }
    if let (
        WorkerDefaultJobTimeout::ExpiresAfter(_),
        WorkerDefaultJobTimeout::ExpiresAfter(default_job_timeout),
    ) = (configured_default_job_timeout, resolved_default_job_timeout)
    {
        let minimum_stale_threshold = default_job_timeout
            .checked_mul(MIN_QUEUE_STALE_THRESHOLD_TO_JOB_TIMEOUT_RATIO)
            .unwrap_or(Duration::MAX);
        if stale_threshold != DEFAULT_QUEUE_WORKER_STALE_THRESHOLD
            && stale_threshold < minimum_stale_threshold
        {
            return Err(Error::InvalidWorkerConfig {
                reason: "stale threshold must be at least 2x explicit default job timeout",
            });
        }
    }
    if execution_heartbeat_interval >= stale_threshold {
        return Err(Error::InvalidWorkerConfig {
            reason: "execution heartbeat interval must be less than stale threshold",
        });
    }
    Ok(())
}

pub(super) fn resolve_queue_retry_policy(retry_policy: RetryPolicy) -> Result<RetryPolicy, Error> {
    if !retry_policy.jitter_fraction.is_finite() || retry_policy.jitter_fraction < 0.0 {
        return Err(Error::InvalidRetryPolicy {
            reason: "jitter fraction must be finite and non-negative",
        });
    }

    match &retry_policy.strategy {
        RetryBackoffStrategy::Exponential { base } => {
            if !base.is_finite() || *base <= 1.0 {
                return Err(Error::InvalidRetryPolicy {
                    reason: "exponential base must be finite and greater than one",
                });
            }
            if retry_policy.max_backoff.is_zero() {
                return Err(Error::InvalidRetryPolicy {
                    reason: "max backoff must be positive",
                });
            }
            if retry_policy.max_backoff < MIN_QUEUE_RETRY_BACKOFF {
                return Err(Error::InvalidRetryPolicy {
                    reason: "max backoff must be at least the minimum retry backoff",
                });
            }
        }
        RetryBackoffStrategy::Fixed { backoff } => {
            if backoff.is_zero() {
                return Err(Error::InvalidRetryPolicy {
                    reason: "fixed backoff must be positive",
                });
            }
        }
        RetryBackoffStrategy::Custom(_) => {
            if retry_policy.max_backoff < MIN_QUEUE_RETRY_BACKOFF {
                return Err(Error::InvalidRetryPolicy {
                    reason: "max backoff must be at least the minimum retry backoff",
                });
            }
        }
    }

    Ok(retry_policy)
}

pub(super) fn compute_queue_retry_backoff(
    retry_policy: &RetryPolicy,
    retry_count: u32,
    error: &TaskError,
) -> Result<Duration, Error> {
    match &retry_policy.strategy {
        RetryBackoffStrategy::Fixed { backoff } => {
            let jittered = apply_symmetric_duration_jitter(*backoff, retry_policy)?;
            Ok(normalize_queue_retry_backoff(jittered, None))
        }
        RetryBackoffStrategy::Custom(custom_backoff) => {
            let normalized = normalize_queue_retry_backoff(
                custom_backoff(retry_count, error),
                Some(retry_policy.max_backoff),
            );
            let jittered = apply_symmetric_duration_jitter(normalized, retry_policy)?;
            Ok(normalize_queue_retry_backoff(
                jittered,
                Some(retry_policy.max_backoff),
            ))
        }
        RetryBackoffStrategy::Exponential { base } => {
            let max_backoff_seconds = retry_policy.max_backoff.as_secs_f64();
            let mut backoff_seconds = base.powf(f64::from(retry_count));
            if !backoff_seconds.is_finite() || backoff_seconds > max_backoff_seconds {
                backoff_seconds = max_backoff_seconds;
            }
            if retry_policy.jitter_fraction > 0.0 {
                backoff_seconds =
                    apply_symmetric_f64_jitter(backoff_seconds, retry_policy.jitter_fraction)?;
            }
            Ok(normalize_queue_retry_backoff(
                duration_from_retry_backoff_seconds(
                    backoff_seconds,
                    Some(retry_policy.max_backoff),
                ),
                Some(retry_policy.max_backoff),
            ))
        }
    }
}

pub(super) fn normalize_queue_retry_backoff(
    backoff: Duration,
    max_backoff: Option<Duration>,
) -> Duration {
    let backoff = backoff.max(MIN_QUEUE_RETRY_BACKOFF);
    if let Some(max_backoff) = max_backoff
        && !max_backoff.is_zero()
    {
        return backoff.min(max_backoff);
    }
    backoff
}

pub(super) fn apply_symmetric_duration_jitter(
    duration: Duration,
    retry_policy: &RetryPolicy,
) -> Result<Duration, Error> {
    if retry_policy.jitter_fraction == 0.0 {
        return Ok(duration);
    }
    let jittered_seconds =
        apply_symmetric_f64_jitter(duration.as_secs_f64(), retry_policy.jitter_fraction)?;
    Ok(duration_from_nonnegative_seconds(jittered_seconds, None))
}

pub(super) fn apply_symmetric_f64_jitter(value: f64, jitter_fraction: f64) -> Result<f64, Error> {
    if jitter_fraction == 0.0 {
        return Ok(value);
    }
    let unit = random_unit_f64()?;
    Ok(value + (value * jitter_fraction * ((2.0 * unit) - 1.0)))
}

pub(super) fn random_unit_f64() -> Result<f64, Error> {
    random_unit_f64_from_system().map_err(|reason| Error::RetryJitterRandom { reason })
}

pub(super) fn duration_from_retry_backoff_seconds(
    seconds: f64,
    max_backoff: Option<Duration>,
) -> Duration {
    duration_from_nonnegative_seconds(seconds, max_backoff)
}

pub(super) fn duration_from_nonnegative_seconds(
    seconds: f64,
    max_backoff: Option<Duration>,
) -> Duration {
    duration_from_nonnegative_f64_seconds(seconds, max_backoff)
}
