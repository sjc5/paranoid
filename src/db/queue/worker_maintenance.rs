use super::worker_loop::run_queue_worker_loop;
use super::*;

pub(super) async fn run_queue_worker_loop_with_fleet_maintenance(
    runtime: WorkerRuntime,
    reclaim_cron: Cron,
    cleanup_cron: Cron,
    maintenance_config: ResolvedWorkerMaintenanceConfig,
) -> Result<WorkerRunLoopSummary, Error> {
    let mut worker_join_handle = tokio::spawn(run_queue_worker_loop(runtime.clone()));
    let mut reclaim_join_handle = spawn_queue_reclaim_maintenance_cron(
        runtime.queue.clone(),
        runtime.pool.clone(),
        runtime.worker_shutdown_signal.clone(),
        reclaim_cron,
        runtime.config.stale_threshold,
        maintenance_config.reclaim_batch_size,
        runtime.config.dead_letter_enabled,
    );
    let mut cleanup_join_handle = spawn_queue_cleanup_maintenance_cron(
        runtime.queue.clone(),
        runtime.pool.clone(),
        runtime.worker_shutdown_signal.clone(),
        cleanup_cron,
        maintenance_config,
    );

    tokio::select! {
        worker_join_result = &mut worker_join_handle => {
            finish_queue_worker_after_worker_stopped(
                runtime,
                worker_join_result,
                reclaim_join_handle,
                cleanup_join_handle,
            )
            .await
        }
        reclaim_join_result = &mut reclaim_join_handle => {
            finish_queue_worker_after_maintenance_cron_stopped(
                runtime,
                "reclaim",
                reclaim_join_result,
                worker_join_handle,
                "cleanup",
                cleanup_join_handle,
            )
            .await
        }
        cleanup_join_result = &mut cleanup_join_handle => {
            finish_queue_worker_after_maintenance_cron_stopped(
                runtime,
                "cleanup",
                cleanup_join_result,
                worker_join_handle,
                "reclaim",
                reclaim_join_handle,
            )
            .await
        }
    }
}

pub(super) fn spawn_queue_reclaim_maintenance_cron(
    queue: Store,
    pool: Pool,
    worker_shutdown_signal: RuntimeCancellationSignal,
    cron: Cron,
    stale_threshold: Duration,
    reclaim_batch_size: u32,
    dead_letter_enabled: bool,
) -> tokio::task::JoinHandle<Result<(), CronRunError<Error>>> {
    tokio::spawn(async move {
        let stop_signal = worker_shutdown_signal.clone();
        let task_pool = pool.clone();
        cron.run_continuously_until_stopped_with_task_error_policy(
            &pool,
            stop_signal.wait_until_cancellation_requested(),
            move |_| {
                let queue = queue.clone();
                let pool = task_pool.clone();
                async move {
                    queue
                        .reclaim_available_stale_running_jobs_once(
                            &pool,
                            stale_threshold,
                            reclaim_batch_size,
                            dead_letter_enabled,
                        )
                        .await?;
                    Ok(())
                }
            },
            |_| CronTaskErrorAction::Stop,
        )
        .await
    })
}

pub(super) fn spawn_queue_cleanup_maintenance_cron(
    queue: Store,
    pool: Pool,
    worker_shutdown_signal: RuntimeCancellationSignal,
    cron: Cron,
    config: ResolvedWorkerMaintenanceConfig,
) -> tokio::task::JoinHandle<Result<(), CronRunError<Error>>> {
    tokio::spawn(async move {
        let stop_signal = worker_shutdown_signal.clone();
        let cleanup_cancellation_signal = worker_shutdown_signal.clone();
        let task_pool = pool.clone();
        cron.run_continuously_until_stopped_with_task_error_policy(
            &pool,
            stop_signal.wait_until_cancellation_requested(),
            move |_| {
                let queue = queue.clone();
                let pool = task_pool.clone();
                let config = config.clone();
                let cancellation_signal = cleanup_cancellation_signal.clone();
                async move {
                    queue
                        .cleanup_available_completed_jobs_older_than_until_empty_or_cancelled(
                            &pool,
                            config.completed_job_retention,
                            config.cleanup_batch_size,
                            config.delay_between_cleanup_batches,
                            &cancellation_signal,
                        )
                        .await?;
                    queue
                        .cleanup_available_failed_jobs_older_than_until_empty_or_cancelled(
                            &pool,
                            config.failed_job_retention,
                            config.cleanup_batch_size,
                            config.delay_between_cleanup_batches,
                            &cancellation_signal,
                        )
                        .await?;
                    queue
                        .cleanup_available_dead_letter_jobs_older_than_until_empty_or_cancelled(
                            &pool,
                            config.dead_letter_job_retention,
                            config.cleanup_batch_size,
                            config.delay_between_cleanup_batches,
                            &cancellation_signal,
                        )
                        .await?;
                    Ok(())
                }
            },
            |_| CronTaskErrorAction::Stop,
        )
        .await
    })
}

pub(super) async fn finish_queue_worker_after_worker_stopped(
    runtime: WorkerRuntime,
    worker_join_result: Result<Result<WorkerRunLoopSummary, Error>, tokio::task::JoinError>,
    reclaim_join_handle: tokio::task::JoinHandle<Result<(), CronRunError<Error>>>,
    cleanup_join_handle: tokio::task::JoinHandle<Result<(), CronRunError<Error>>>,
) -> Result<WorkerRunLoopSummary, Error> {
    runtime.worker_shutdown_signal.request_cancellation();
    let worker_result = queue_worker_run_loop_result_from_join_result(worker_join_result);
    let reclaim_result =
        queue_maintenance_cron_result_from_join_result("reclaim", reclaim_join_handle.await);
    let cleanup_result =
        queue_maintenance_cron_result_from_join_result("cleanup", cleanup_join_handle.await);

    combine_queue_worker_completed_first_runtime_stop_results(
        worker_result,
        reclaim_result,
        cleanup_result,
    )
}

pub(super) async fn finish_queue_worker_after_maintenance_cron_stopped(
    runtime: WorkerRuntime,
    stopped_cron_name: &'static str,
    stopped_cron_join_result: Result<Result<(), CronRunError<Error>>, tokio::task::JoinError>,
    worker_join_handle: tokio::task::JoinHandle<Result<WorkerRunLoopSummary, Error>>,
    other_cron_name: &'static str,
    other_cron_join_handle: tokio::task::JoinHandle<Result<(), CronRunError<Error>>>,
) -> Result<WorkerRunLoopSummary, Error> {
    let shutdown_was_already_requested = runtime.worker_shutdown_signal.is_cancellation_requested();
    runtime.worker_shutdown_signal.request_cancellation();
    let worker_result = queue_worker_run_loop_result_from_join_result(worker_join_handle.await);
    let stopped_cron_result =
        queue_maintenance_cron_result_from_join_result(stopped_cron_name, stopped_cron_join_result);
    let other_cron_result = queue_maintenance_cron_result_from_join_result(
        other_cron_name,
        other_cron_join_handle.await,
    );

    combine_queue_worker_runtime_stop_results(
        shutdown_was_already_requested,
        stopped_cron_name,
        worker_result,
        stopped_cron_result,
        other_cron_result,
    )
}

pub(super) fn combine_queue_worker_runtime_stop_results(
    shutdown_was_already_requested: bool,
    stopped_cron_name: &'static str,
    worker_result: Result<WorkerRunLoopSummary, Error>,
    stopped_cron_result: Result<(), Error>,
    other_cron_result: Result<(), Error>,
) -> Result<WorkerRunLoopSummary, Error> {
    let stopped_cron_finished_cleanly = stopped_cron_result.is_ok();
    let (summary, mut failures) = collect_queue_worker_runtime_component_failures(
        worker_result,
        stopped_cron_result,
        other_cron_result,
    );
    if !shutdown_was_already_requested && stopped_cron_finished_cleanly {
        failures.push(Error::MaintenanceCronStoppedUnexpectedly {
            cron_name: stopped_cron_name,
        });
    }

    queue_worker_summary_or_runtime_failures(summary, failures)
}

pub(super) fn combine_queue_worker_completed_first_runtime_stop_results(
    worker_result: Result<WorkerRunLoopSummary, Error>,
    reclaim_result: Result<(), Error>,
    cleanup_result: Result<(), Error>,
) -> Result<WorkerRunLoopSummary, Error> {
    let (summary, failures) = collect_queue_worker_runtime_component_failures(
        worker_result,
        reclaim_result,
        cleanup_result,
    );
    queue_worker_summary_or_runtime_failures(summary, failures)
}

fn collect_queue_worker_runtime_component_failures(
    worker_result: Result<WorkerRunLoopSummary, Error>,
    first_maintenance_result: Result<(), Error>,
    second_maintenance_result: Result<(), Error>,
) -> (Option<WorkerRunLoopSummary>, Vec<Error>) {
    let mut failures = Vec::new();
    let summary = match worker_result {
        Ok(summary) => Some(summary),
        Err(error) => {
            failures.push(error);
            None
        }
    };
    if let Err(error) = first_maintenance_result {
        failures.push(error);
    }
    if let Err(error) = second_maintenance_result {
        failures.push(error);
    }

    (summary, failures)
}

fn queue_worker_summary_or_runtime_failures(
    summary: Option<WorkerRunLoopSummary>,
    mut failures: Vec<Error>,
) -> Result<WorkerRunLoopSummary, Error> {
    match failures.len() {
        0 => Ok(summary.expect("worker summary exists when no runtime failures were collected")),
        1 => Err(failures.remove(0)),
        _ => Err(Error::WorkerRuntimeMultipleFailures { failures }),
    }
}

pub(super) fn queue_worker_run_loop_result_from_join_result(
    join_result: Result<Result<WorkerRunLoopSummary, Error>, tokio::task::JoinError>,
) -> Result<WorkerRunLoopSummary, Error> {
    match join_result {
        Ok(result) => result,
        Err(error) => Err(Error::WorkerTaskJoinFailed {
            reason: error.to_string(),
        }),
    }
}

pub(super) fn queue_maintenance_cron_result_from_join_result(
    cron_name: &'static str,
    join_result: Result<Result<(), CronRunError<Error>>, tokio::task::JoinError>,
) -> Result<(), Error> {
    match join_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => Err(Error::MaintenanceCronRunFailed {
            cron_name,
            source: Box::new(source),
        }),
        Err(error) => Err(Error::MaintenanceCronTaskJoinFailed {
            cron_name,
            reason: error.to_string(),
        }),
    }
}
