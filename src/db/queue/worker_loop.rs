use super::*;

pub(super) async fn run_queue_worker_loop(
    runtime: WorkerRuntime,
) -> Result<WorkerRunLoopSummary, Error> {
    if !wait_for_queue_worker_startup_jitter_before_run_loop(
        &runtime.worker_shutdown_signal,
        runtime.config.startup_jitter_max_delay,
    )
    .await?
    {
        return Ok(WorkerRunLoopSummary::default());
    }

    let registered_task_names = runtime.task_registry.registered_task_names();
    let mut in_flight_jobs = tokio::task::JoinSet::new();
    let mut summary = WorkerRunLoopSummary::default();
    let mut claim_error_backoff = MIN_QUEUE_WORKER_CLAIM_ERROR_BACKOFF;

    loop {
        if runtime.worker_shutdown_signal.is_cancellation_requested() {
            break;
        }

        match claim_and_spawn_jobs_up_to_worker_capacity(
            &runtime,
            &registered_task_names,
            &mut in_flight_jobs,
        )
        .await
        {
            Ok(claimed_count) => {
                claim_error_backoff = MIN_QUEUE_WORKER_CLAIM_ERROR_BACKOFF;
                summary.record_claimed_count(claimed_count)?;
            }
            Err(_) => {
                wait_for_worker_claim_retry_backoff_or_shutdown(
                    &runtime.worker_shutdown_signal,
                    claim_error_backoff,
                )
                .await;
                claim_error_backoff = claim_error_backoff
                    .saturating_mul(2)
                    .min(MAX_QUEUE_WORKER_CLAIM_ERROR_BACKOFF);
                if runtime.worker_shutdown_signal.is_cancellation_requested() {
                    break;
                }
                continue;
            }
        }

        if in_flight_jobs.is_empty() {
            tokio::select! {
                _ = runtime.worker_shutdown_signal.wait_until_cancellation_requested() => break,
                _ = tokio::time::sleep(runtime.config.poll_interval) => {}
            }
            continue;
        }

        tokio::select! {
            joined = in_flight_jobs.join_next() => {
                if let Some(joined) = joined {
                    handle_queue_worker_joined_job(
                        &runtime,
                        &mut in_flight_jobs,
                        &mut summary,
                        joined,
                    )
                    .await?;
                }
            }
            _ = runtime.worker_shutdown_signal.wait_until_cancellation_requested() => break,
            _ = tokio::time::sleep(runtime.config.poll_interval) => {}
        }
    }

    runtime.worker_shutdown_signal.request_cancellation();
    finish_queue_worker_shutdown(runtime, in_flight_jobs, summary).await
}

pub(super) async fn claim_and_spawn_jobs_up_to_worker_capacity(
    runtime: &WorkerRuntime,
    registered_task_names: &[String],
    in_flight_jobs: &mut tokio::task::JoinSet<Result<ProcessedJobOutcome, Error>>,
) -> Result<usize, Error> {
    let in_flight_count = u32::try_from(in_flight_jobs.len()).unwrap_or(u32::MAX);
    let available_capacity = runtime.config.concurrency.saturating_sub(in_flight_count);
    if available_capacity == 0 || registered_task_names.is_empty() {
        return Ok(0);
    }

    let jobs = claim_available_jobs_for_worker_with_database_operation_timeout(
        &runtime.queue,
        &runtime.pool,
        registered_task_names,
        available_capacity,
        runtime.worker_owner_id.as_str(),
        runtime.config.database_operation_timeout,
    )
    .await?;
    let claimed_count = jobs.len();
    for job in jobs {
        in_flight_jobs.spawn(process_claimed_queue_job(runtime.clone(), job));
    }
    Ok(claimed_count)
}

pub(super) async fn wait_for_queue_worker_startup_jitter_before_run_loop(
    worker_shutdown_signal: &RuntimeCancellationSignal,
    startup_jitter_max_delay: Duration,
) -> Result<bool, Error> {
    let startup_jitter_delay = compute_queue_worker_startup_jitter_delay(startup_jitter_max_delay)?;
    wait_for_queue_worker_startup_jitter_delay_or_shutdown(
        worker_shutdown_signal,
        startup_jitter_delay,
    )
    .await
}

pub(super) async fn wait_for_queue_worker_startup_jitter_delay_or_shutdown(
    worker_shutdown_signal: &RuntimeCancellationSignal,
    startup_jitter_delay: Duration,
) -> Result<bool, Error> {
    if startup_jitter_delay.is_zero() {
        return Ok(!worker_shutdown_signal.is_cancellation_requested());
    }
    tokio::select! {
        _ = worker_shutdown_signal.wait_until_cancellation_requested() => Ok(false),
        _ = tokio::time::sleep(startup_jitter_delay) => Ok(true),
    }
}

pub(super) fn compute_queue_worker_startup_jitter_delay(
    startup_jitter_max_delay: Duration,
) -> Result<Duration, Error> {
    if startup_jitter_max_delay.is_zero() {
        return Ok(Duration::ZERO);
    }
    let unit = random_unit_f64_from_system()
        .map_err(|reason| Error::WorkerStartupJitterRandom { reason })?;
    Ok(duration_from_nonnegative_seconds(
        startup_jitter_max_delay.as_secs_f64() * unit,
        Some(startup_jitter_max_delay),
    ))
}

pub(super) async fn wait_for_worker_claim_retry_backoff_or_shutdown(
    worker_shutdown_signal: &RuntimeCancellationSignal,
    backoff: Duration,
) {
    tokio::select! {
        _ = worker_shutdown_signal.wait_until_cancellation_requested() => {}
        _ = tokio::time::sleep(backoff) => {}
    }
}

pub(super) async fn handle_queue_worker_joined_job(
    runtime: &WorkerRuntime,
    in_flight_jobs: &mut tokio::task::JoinSet<Result<ProcessedJobOutcome, Error>>,
    summary: &mut WorkerRunLoopSummary,
    joined: Result<Result<ProcessedJobOutcome, Error>, tokio::task::JoinError>,
) -> Result<(), Error> {
    match joined {
        Ok(Ok(outcome)) => summary.record_processed_job_outcome(outcome),
        Ok(Err(error)) => {
            let (in_flight_errors, cleanup_result) =
                handle_queue_worker_runtime_error(runtime, in_flight_jobs).await;
            Err(
                worker_runtime_error_after_in_flight_abort_and_claimed_job_cleanup(
                    error,
                    in_flight_errors,
                    cleanup_result,
                ),
            )
        }
        Err(error) => {
            let (in_flight_errors, cleanup_result) =
                handle_queue_worker_runtime_error(runtime, in_flight_jobs).await;
            let worker_error = Error::WorkerTaskJoinFailed {
                reason: error.to_string(),
            };
            Err(
                worker_runtime_error_after_in_flight_abort_and_claimed_job_cleanup(
                    worker_error,
                    in_flight_errors,
                    cleanup_result,
                ),
            )
        }
    }
}

pub(super) async fn handle_queue_worker_runtime_error(
    runtime: &WorkerRuntime,
    in_flight_jobs: &mut tokio::task::JoinSet<Result<ProcessedJobOutcome, Error>>,
) -> (Vec<Error>, Result<(), Error>) {
    runtime.worker_shutdown_signal.request_cancellation();
    let in_flight_errors = abort_and_collect_in_flight_job_errors(in_flight_jobs).await;
    let cleanup_result = return_claimed_jobs_after_worker_task_failure(
        &runtime.queue,
        &runtime.pool,
        runtime.worker_owner_id.as_str(),
        runtime.config.database_operation_timeout,
    )
    .await;
    (in_flight_errors, cleanup_result)
}

pub(super) async fn finish_queue_worker_shutdown(
    runtime: WorkerRuntime,
    mut in_flight_jobs: tokio::task::JoinSet<Result<ProcessedJobOutcome, Error>>,
    mut summary: WorkerRunLoopSummary,
) -> Result<WorkerRunLoopSummary, Error> {
    let summary_before_shutdown_drain = summary.clone();
    let drain = async {
        while let Some(joined) = in_flight_jobs.join_next().await {
            handle_queue_worker_joined_job(&runtime, &mut in_flight_jobs, &mut summary, joined)
                .await?;
        }
        Ok::<WorkerRunLoopSummary, Error>(summary)
    };

    let summary = match tokio::time::timeout(runtime.config.shutdown_grace_period, drain).await {
        Ok(result) => result?,
        Err(_) => {
            let in_flight_errors =
                abort_and_collect_in_flight_job_errors(&mut in_flight_jobs).await;
            let cleanup_result = return_claimed_jobs_after_worker_task_failure(
                &runtime.queue,
                &runtime.pool,
                runtime.worker_owner_id.as_str(),
                runtime.config.database_operation_timeout,
            )
            .await;
            return worker_runtime_shutdown_timeout_result_after_in_flight_abort_and_claimed_job_cleanup(
                summary_before_shutdown_drain,
                in_flight_errors,
                cleanup_result,
            );
        }
    };

    return_claimed_jobs_after_worker_task_failure(
        &runtime.queue,
        &runtime.pool,
        runtime.worker_owner_id.as_str(),
        runtime.config.database_operation_timeout,
    )
    .await?;
    Ok(summary)
}
