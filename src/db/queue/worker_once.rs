use super::*;

pub(super) async fn process_available_jobs_once_for_worker(
    queue: Store,
    pool: WritePool,
    task_registry: TaskRegistry,
    worker_owner_id: WorkerOwnerId,
    resolved_config: ResolvedWorkerConfig,
) -> Result<WorkerRunOnceSummary, Error> {
    let registered_task_names = task_registry.registered_task_names();
    if registered_task_names.is_empty() {
        return Ok(WorkerRunOnceSummary::default());
    }

    let jobs = claim_available_jobs_for_worker_with_database_operation_timeout(
        &queue,
        &pool,
        &registered_task_names,
        resolved_config.concurrency,
        worker_owner_id.as_str(),
        resolved_config.database_operation_timeout,
    )
    .await?;
    let mut summary = WorkerRunOnceSummary {
        claimed_count: jobs
            .len()
            .try_into()
            .map_err(|_| Error::UnexpectedOutcome {
                operation: "process available jobs once",
                outcome: "claimed more jobs than fit in u32".to_owned(),
            })?,
        ..WorkerRunOnceSummary::default()
    };

    let mut cleanup_on_drop = BestEffortClaimedJobsCleanupOnDrop::new(
        queue.clone(),
        pool.clone(),
        worker_owner_id.clone(),
        resolved_config.database_operation_timeout,
        summary.claimed_count > 0,
    );

    let runtime = WorkerRuntime {
        queue,
        pool,
        task_registry,
        worker_owner_id,
        config: resolved_config,
        worker_shutdown_signal: RuntimeCancellationSignal::new(),
    };
    let mut tasks = tokio::task::JoinSet::new();
    for job in jobs {
        tasks.spawn(process_claimed_queue_job(runtime.clone(), job));
    }

    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(outcome)) => summary.record_processed_job_outcome(outcome),
            Ok(Err(error)) => {
                let in_flight_errors = abort_and_collect_in_flight_job_errors(&mut tasks).await;
                let cleanup_result = return_claimed_jobs_after_worker_task_failure(
                    &runtime.queue,
                    &runtime.pool,
                    runtime.worker_owner_id.as_str(),
                    runtime.config.database_operation_timeout,
                )
                .await;
                cleanup_on_drop.disarm();
                return Err(
                    worker_runtime_error_after_in_flight_abort_and_claimed_job_cleanup(
                        error,
                        in_flight_errors,
                        cleanup_result,
                    ),
                );
            }
            Err(error) => {
                let in_flight_errors = abort_and_collect_in_flight_job_errors(&mut tasks).await;
                let cleanup_result = return_claimed_jobs_after_worker_task_failure(
                    &runtime.queue,
                    &runtime.pool,
                    runtime.worker_owner_id.as_str(),
                    runtime.config.database_operation_timeout,
                )
                .await;
                cleanup_on_drop.disarm();
                let worker_error = Error::WorkerTaskJoinFailed {
                    reason: error.to_string(),
                };
                return Err(
                    worker_runtime_error_after_in_flight_abort_and_claimed_job_cleanup(
                        worker_error,
                        in_flight_errors,
                        cleanup_result,
                    ),
                );
            }
        }
    }

    cleanup_on_drop.disarm();
    Ok(summary)
}

struct BestEffortClaimedJobsCleanupOnDrop {
    cleanup: Option<ClaimedJobsCleanup>,
}

struct ClaimedJobsCleanup {
    queue: Store,
    pool: WritePool,
    runtime_handle: RuntimeHandle,
    worker_owner_id: WorkerOwnerId,
    database_operation_timeout: Duration,
}

impl BestEffortClaimedJobsCleanupOnDrop {
    fn new(
        queue: Store,
        pool: WritePool,
        worker_owner_id: WorkerOwnerId,
        database_operation_timeout: Duration,
        armed: bool,
    ) -> Self {
        let cleanup = armed.then_some(ClaimedJobsCleanup {
            queue,
            pool,
            runtime_handle: RuntimeHandle::current(),
            worker_owner_id,
            database_operation_timeout,
        });
        Self { cleanup }
    }

    fn disarm(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for BestEffortClaimedJobsCleanupOnDrop {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        cleanup.runtime_handle.spawn(async move {
            // Drop cannot await. Stale-job reclamation remains the durable recovery
            // path if this best-effort cleanup cannot complete.
            let _cleanup_result = return_claimed_jobs_after_worker_task_failure(
                &cleanup.queue,
                &cleanup.pool,
                cleanup.worker_owner_id.as_str(),
                cleanup.database_operation_timeout,
            )
            .await;
        });
    }
}
