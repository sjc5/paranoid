use super::*;

const CLAIMED_JOB_CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(10);

pub(super) async fn process_claimed_queue_job(
    runtime: WorkerRuntime,
    job: Job,
) -> Result<ProcessedJobOutcome, Error> {
    let Some(handler) = runtime.task_registry.handler(&job.task_name) else {
        return move_running_job_to_dead_letter_or_fail(
            &runtime,
            &job,
            "unknown task",
            false,
            DeadLetterReason::OperatorAction,
        )
        .await;
    };

    if job.retry_count > job.max_retries {
        return move_running_job_to_dead_letter_or_fail(
            &runtime,
            &job,
            "max retries exceeded",
            false,
            DeadLetterReason::MaxRetriesExceeded,
        )
        .await;
    }

    match retry_worker_database_operation_while_job_locked(
        "mark owned running job started",
        runtime.config.database_operation_timeout,
        |operation_timeout| {
            mark_owned_running_job_started_with_database_operation_timeout(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                operation_timeout,
            )
        },
    )
    .await
    {
        Ok(()) => {}
        Err(Error::JobNotRunning) => return Ok(ProcessedJobOutcome::LostOwnership),
        Err(error) => return Err(error),
    }

    let job_cancellation_signal = RuntimeCancellationSignal::new();
    let context = JobExecutionContext {
        queue: runtime.queue.clone(),
        pool: runtime.pool.clone(),
        job_id: job.id,
        task_name: job.task_name.clone(),
        worker_owner_id: runtime.worker_owner_id.clone(),
        retry_count: job.retry_count,
        max_retries: job.max_retries,
        worker_shutdown_signal: runtime.worker_shutdown_signal.clone(),
        job_cancellation_signal: job_cancellation_signal.clone(),
        database_operation_timeout: runtime.config.database_operation_timeout,
    };
    let heartbeat_handle = start_worker_heartbeat_loop_if_enabled(
        context.clone(),
        job_cancellation_signal,
        runtime.config.execution_heartbeat_interval,
    );
    let handler_result = run_queue_task_handler(
        handler,
        context,
        job.payload_json.clone(),
        runtime.config.default_job_timeout,
        &job,
    )
    .await;
    let heartbeat_result = stop_worker_heartbeat_loop(heartbeat_handle).await;

    let finalization_result = match handler_result {
        Ok(()) => complete_processed_queue_job(&runtime, &job).await,
        Err(error) => handle_processed_queue_job_error(&runtime, &job, error).await,
    };
    combine_worker_heartbeat_and_job_finalization_results(heartbeat_result, finalization_result)
}

pub(super) async fn run_queue_task_handler(
    handler: TaskHandler,
    context: JobExecutionContext,
    payload_json: String,
    default_job_timeout: WorkerDefaultJobTimeout,
    job: &Job,
) -> Result<(), TaskError> {
    let job_cancellation_signal = context.job_cancellation_signal.clone();
    let mut handler_task = AbortOnDropJoinHandle::new(tokio::spawn(handler(context, payload_json)));
    match resolve_queue_job_timeout(job.timeout, default_job_timeout) {
        None => {
            tokio::select! {
                result = &mut handler_task.join_handle => queue_task_result_from_join_result(result),
                _ = job_cancellation_signal.wait_until_cancellation_requested() => {
                    abort_queue_handler_task(handler_task).await;
                    Err(TaskError::retryable("queue job ownership lost"))
                }
            }
        }
        Some(timeout) => {
            tokio::select! {
                result = &mut handler_task.join_handle => queue_task_result_from_join_result(result),
                _ = tokio::time::sleep(timeout) => {
                    abort_queue_handler_task(handler_task).await;
                    Err(TaskError::retryable("queue job timed out"))
                }
                _ = job_cancellation_signal.wait_until_cancellation_requested() => {
                    abort_queue_handler_task(handler_task).await;
                    Err(TaskError::retryable("queue job ownership lost"))
                }
            }
        }
    }
}

pub(super) struct AbortOnDropJoinHandle<T> {
    join_handle: tokio::task::JoinHandle<T>,
}

impl<T> AbortOnDropJoinHandle<T> {
    pub(super) fn new(join_handle: tokio::task::JoinHandle<T>) -> Self {
        Self { join_handle }
    }
}

impl<T> Drop for AbortOnDropJoinHandle<T> {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

pub(super) fn queue_task_result_from_join_result(
    join_result: Result<Result<(), TaskError>, tokio::task::JoinError>,
) -> Result<(), TaskError> {
    match join_result {
        Ok(result) => result,
        Err(error) if error.is_panic() => Err(TaskError::permanent("queue task handler panicked")),
        Err(error) => Err(TaskError::retryable(format!(
            "queue task handler was cancelled: {error}"
        ))),
    }
}

async fn abort_queue_handler_task(mut handler_task: AbortOnDropJoinHandle<Result<(), TaskError>>) {
    handler_task.join_handle.abort();
    let _ = (&mut handler_task.join_handle).await;
}

fn start_worker_heartbeat_loop_if_enabled(
    context: JobExecutionContext,
    job_cancellation_signal: RuntimeCancellationSignal,
    execution_heartbeat_interval: Duration,
) -> Option<WorkerHeartbeatLoopHandle> {
    if execution_heartbeat_interval.is_zero() {
        return None;
    }
    let (stop_sender, mut stop_receiver) = tokio::sync::oneshot::channel();
    Some(WorkerHeartbeatLoopHandle::new(
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(execution_heartbeat_interval);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut stop_receiver => return,
                    _ = interval.tick() => {
                        match context.touch_execution_heartbeat().await {
                            Ok(()) => {}
                            Err(Error::JobNotRunning) => {
                                job_cancellation_signal.request_cancellation();
                                return;
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }),
        stop_sender,
    ))
}

pub(super) async fn stop_worker_heartbeat_loop(
    handle: Option<WorkerHeartbeatLoopHandle>,
) -> Result<(), Error> {
    let Some(mut handle) = handle else {
        return Ok(());
    };
    handle.request_stop();
    handle.await_stop().await
}

pub(super) struct WorkerHeartbeatLoopHandle {
    join_handle: Option<tokio::task::JoinHandle<()>>,
    stop_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl WorkerHeartbeatLoopHandle {
    pub(in crate::db::queue) fn new(
        join_handle: tokio::task::JoinHandle<()>,
        stop_sender: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            join_handle: Some(join_handle),
            stop_sender: Some(stop_sender),
        }
    }

    fn request_stop(&mut self) {
        if let Some(stop_sender) = self.stop_sender.take() {
            let _ = stop_sender.send(());
        }
    }

    async fn await_stop(&mut self) -> Result<(), Error> {
        if let Some(mut join_handle) = self.join_handle.take() {
            (&mut join_handle)
                .await
                .map_err(|source| Error::WorkerHeartbeatTaskJoinFailed { source })?;
        }
        Ok(())
    }
}

impl Drop for WorkerHeartbeatLoopHandle {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(join_handle) = &self.join_handle {
            join_handle.abort();
        }
    }
}

pub(super) async fn complete_processed_queue_job(
    runtime: &WorkerRuntime,
    job: &Job,
) -> Result<ProcessedJobOutcome, Error> {
    match retry_worker_database_operation_while_job_locked(
        "mark owned running job completed",
        runtime.config.database_operation_timeout,
        |operation_timeout| {
            mark_owned_running_job_completed_with_database_operation_timeout(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                operation_timeout,
            )
        },
    )
    .await
    {
        Ok(()) => Ok(ProcessedJobOutcome::Succeeded),
        Err(Error::JobNotRunning) => Ok(ProcessedJobOutcome::LostOwnership),
        Err(error) => {
            let requeue_result = requeue_started_job_after_worker_persistence_failure(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                runtime.config.database_operation_timeout,
            )
            .await;
            Err(worker_job_persistence_error_after_requeue(
                error,
                requeue_result,
            ))
        }
    }
}

pub(super) async fn handle_processed_queue_job_error(
    runtime: &WorkerRuntime,
    job: &Job,
    error: TaskError,
) -> Result<ProcessedJobOutcome, Error> {
    let next_retry_count =
        job.retry_count
            .checked_add(1)
            .ok_or_else(|| Error::UnexpectedOutcome {
                operation: "process queue job failure",
                outcome: "retry count overflowed".to_owned(),
            })?;
    let retries_exhausted = next_retry_count > job.max_retries;
    if error.is_permanent() || retries_exhausted {
        let reason = if error.is_permanent() {
            DeadLetterReason::PermanentError
        } else {
            DeadLetterReason::MaxRetriesExceeded
        };
        return move_running_job_to_dead_letter_or_fail(
            runtime,
            job,
            error.message(),
            !error.is_permanent(),
            reason,
        )
        .await;
    }

    let retry_after =
        compute_queue_retry_backoff(&runtime.config.retry_policy, next_retry_count, &error)?;
    match retry_worker_database_operation_while_job_locked(
        "schedule owned running job retry",
        runtime.config.database_operation_timeout,
        |operation_timeout| {
            schedule_owned_running_job_retry_with_database_operation_timeout(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                next_retry_count,
                retry_after,
                error.message(),
                operation_timeout,
            )
        },
    )
    .await
    {
        Ok(_) => Ok(ProcessedJobOutcome::Retried),
        Err(Error::JobNotRunning) => Ok(ProcessedJobOutcome::LostOwnership),
        Err(error) => {
            let requeue_result = requeue_started_job_after_worker_persistence_failure(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                runtime.config.database_operation_timeout,
            )
            .await;
            Err(worker_job_persistence_error_after_requeue(
                error,
                requeue_result,
            ))
        }
    }
}

pub(super) async fn move_running_job_to_dead_letter_or_fail(
    runtime: &WorkerRuntime,
    job: &Job,
    error_message: &str,
    increment_retry_count: bool,
    reason: DeadLetterReason,
) -> Result<ProcessedJobOutcome, Error> {
    if runtime.config.dead_letter_enabled {
        match retry_worker_database_operation_while_job_locked(
            "move owned running job to dead letter",
            runtime.config.database_operation_timeout,
            |operation_timeout| {
                move_owned_running_job_to_dead_letter_with_database_operation_timeout(
                    &runtime.queue,
                    &runtime.pool,
                    job.id,
                    runtime.worker_owner_id.as_str(),
                    error_message,
                    increment_retry_count,
                    reason,
                    operation_timeout,
                )
            },
        )
        .await
        {
            Ok(_) => return Ok(ProcessedJobOutcome::DeadLettered),
            Err(Error::JobNotRunning) => return Ok(ProcessedJobOutcome::LostOwnership),
            Err(error) => {
                let requeue_result = requeue_started_job_after_worker_persistence_failure(
                    &runtime.queue,
                    &runtime.pool,
                    job.id,
                    runtime.worker_owner_id.as_str(),
                    runtime.config.database_operation_timeout,
                )
                .await;
                return Err(worker_job_persistence_error_after_requeue(
                    error,
                    requeue_result,
                ));
            }
        }
    }

    match retry_worker_database_operation_while_job_locked(
        "mark owned running job failed",
        runtime.config.database_operation_timeout,
        |operation_timeout| {
            mark_owned_running_job_failed_with_database_operation_timeout(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                error_message,
                increment_retry_count,
                operation_timeout,
            )
        },
    )
    .await
    {
        Ok(()) => Ok(ProcessedJobOutcome::Failed),
        Err(Error::JobNotRunning) => Ok(ProcessedJobOutcome::LostOwnership),
        Err(error) => {
            let requeue_result = requeue_started_job_after_worker_persistence_failure(
                &runtime.queue,
                &runtime.pool,
                job.id,
                runtime.worker_owner_id.as_str(),
                runtime.config.database_operation_timeout,
            )
            .await;
            Err(worker_job_persistence_error_after_requeue(
                error,
                requeue_result,
            ))
        }
    }
}

pub(super) async fn requeue_started_job_after_worker_persistence_failure(
    queue: &Store,
    pool: &Pool,
    job_id: JobId,
    worker_id: &str,
    database_operation_timeout: Duration,
) -> Result<(), Error> {
    match return_owned_started_running_job_to_pending_with_database_operation_timeout(
        queue,
        pool,
        job_id,
        worker_id,
        database_operation_timeout,
    )
    .await
    {
        Ok(()) | Err(Error::JobNotRunning) => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn worker_job_persistence_error_after_requeue(
    persistence_error: Error,
    requeue_result: Result<(), Error>,
) -> Error {
    match requeue_result {
        Ok(()) => persistence_error,
        Err(requeue_error) => Error::WorkerJobPersistenceFailureAndRequeueFailed {
            persistence_error: Box::new(persistence_error),
            requeue_error: Box::new(requeue_error),
        },
    }
}

pub(super) fn combine_worker_heartbeat_and_job_finalization_results(
    heartbeat_result: Result<(), Error>,
    finalization_result: Result<ProcessedJobOutcome, Error>,
) -> Result<ProcessedJobOutcome, Error> {
    match (heartbeat_result, finalization_result) {
        (Ok(()), result) => result,
        (Err(heartbeat_error), Ok(_)) => Err(heartbeat_error),
        (Err(heartbeat_error), Err(finalization_error)) => {
            Err(Error::WorkerHeartbeatFailureAndJobFinalizationFailed {
                heartbeat_error: Box::new(heartbeat_error),
                finalization_error: Box::new(finalization_error),
            })
        }
    }
}

pub(super) fn worker_runtime_error_after_claimed_job_cleanup(
    worker_error: Error,
    cleanup_result: Result<(), Error>,
) -> Error {
    match cleanup_result {
        Ok(()) => worker_error,
        Err(cleanup_error) => Error::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
            worker_error: Box::new(worker_error),
            cleanup_error: Box::new(cleanup_error),
        },
    }
}

pub(super) fn worker_runtime_error_after_in_flight_abort_and_claimed_job_cleanup(
    worker_error: Error,
    mut in_flight_errors: Vec<Error>,
    cleanup_result: Result<(), Error>,
) -> Error {
    let primary_error =
        worker_runtime_error_after_claimed_job_cleanup(worker_error, cleanup_result);
    if in_flight_errors.is_empty() {
        return primary_error;
    }

    let mut failures = Vec::with_capacity(in_flight_errors.len() + 1);
    failures.push(primary_error);
    failures.append(&mut in_flight_errors);
    Error::WorkerRuntimeMultipleFailures { failures }
}

pub(super) fn worker_runtime_shutdown_timeout_result_after_in_flight_abort_and_claimed_job_cleanup(
    summary: WorkerRunLoopSummary,
    mut in_flight_errors: Vec<Error>,
    cleanup_result: Result<(), Error>,
) -> Result<WorkerRunLoopSummary, Error> {
    match (cleanup_result, in_flight_errors.len()) {
        (Ok(()), 0) => Ok(summary),
        (Err(cleanup_error), 0) => Err(cleanup_error),
        (Ok(()), 1) => Err(in_flight_errors.remove(0)),
        (Err(cleanup_error), _) => {
            let mut failures = Vec::with_capacity(in_flight_errors.len() + 1);
            failures.push(cleanup_error);
            failures.append(&mut in_flight_errors);
            Err(Error::WorkerRuntimeMultipleFailures { failures })
        }
        (Ok(()), _) => Err(Error::WorkerRuntimeMultipleFailures {
            failures: in_flight_errors,
        }),
    }
}

pub(super) async fn abort_and_collect_in_flight_job_errors(
    in_flight_jobs: &mut tokio::task::JoinSet<Result<ProcessedJobOutcome, Error>>,
) -> Vec<Error> {
    in_flight_jobs.abort_all();
    let mut errors = Vec::new();
    while let Some(joined) = in_flight_jobs.join_next().await {
        if let Some(error) = worker_runtime_error_from_joined_in_flight_job_after_abort(joined) {
            errors.push(error);
        }
    }
    errors
}

pub(super) fn worker_runtime_error_from_joined_in_flight_job_after_abort(
    joined: Result<Result<ProcessedJobOutcome, Error>, tokio::task::JoinError>,
) -> Option<Error> {
    match joined {
        Ok(Ok(_)) => None,
        Ok(Err(error)) => Some(error),
        Err(error) if error.is_cancelled() => None,
        Err(error) => Some(Error::WorkerTaskJoinFailed {
            reason: error.to_string(),
        }),
    }
}

pub(super) async fn return_claimed_jobs_after_worker_task_failure(
    queue: &Store,
    pool: &Pool,
    worker_id: &str,
    database_operation_timeout: Duration,
) -> Result<(), Error> {
    let cleanup_started_at = std::time::Instant::now();
    let cleanup_timeout = database_operation_timeout
        .checked_mul(2)
        .unwrap_or(Duration::MAX);

    loop {
        let operation_timeout = remaining_claimed_job_cleanup_timeout(
            cleanup_started_at,
            cleanup_timeout,
            "return claimed jobs after worker task failure",
        )?;
        return_available_owned_unstarted_running_jobs_to_pending_with_database_operation_timeout(
            queue,
            pool,
            worker_id,
            operation_timeout,
        )
        .await?;

        let operation_timeout = remaining_claimed_job_cleanup_timeout(
            cleanup_started_at,
            cleanup_timeout,
            "return claimed jobs after worker task failure",
        )?;
        return_available_owned_started_running_jobs_to_pending_with_database_operation_timeout(
            queue,
            pool,
            worker_id,
            operation_timeout,
        )
        .await?;

        let operation_timeout = remaining_claimed_job_cleanup_timeout(
            cleanup_started_at,
            cleanup_timeout,
            "return claimed jobs after worker task failure",
        )?;
        let remaining_running_jobs =
            count_worker_owned_running_jobs_with_database_operation_timeout(
                queue,
                pool,
                worker_id,
                operation_timeout,
            )
            .await?;
        if remaining_running_jobs == 0 {
            return Ok(());
        }

        let operation_timeout = remaining_claimed_job_cleanup_timeout(
            cleanup_started_at,
            cleanup_timeout,
            "return claimed jobs after worker task failure",
        )?;
        tokio::time::sleep(operation_timeout.min(CLAIMED_JOB_CLEANUP_RETRY_DELAY)).await;
    }
}

fn remaining_claimed_job_cleanup_timeout(
    cleanup_started_at: std::time::Instant,
    cleanup_timeout: Duration,
    operation: &'static str,
) -> Result<Duration, Error> {
    let elapsed = cleanup_started_at.elapsed();
    if elapsed >= cleanup_timeout {
        return Err(Error::WorkerDatabaseOperationTimedOut {
            operation,
            timeout: cleanup_timeout,
        });
    }
    Ok(cleanup_timeout - elapsed)
}
