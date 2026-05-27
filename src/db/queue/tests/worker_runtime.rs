use super::*;

async fn panic_worker_runtime() -> Result<WorkerRunLoopSummary, Error> {
    panic!("worker runtime panic")
}

async fn panic_worker_handle() -> Result<WorkerRunLoopSummary, Error> {
    panic!("worker handle panic")
}

async fn panic_maintenance_cron() -> Result<(), CronRunError<Error>> {
    panic!("maintenance cron panic")
}

async fn panic_queue_task_handler() -> Result<(), TaskError> {
    panic!("queue task panic payload must not be persisted")
}

#[tokio::test]
async fn queue_worker_lock_retry_passes_remaining_budget_to_retried_operations() {
    let seen_timeouts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let operation_timeout = Duration::from_millis(200);

    retry_worker_database_operation_while_job_locked("test retry budget", operation_timeout, {
        let seen_timeouts = seen_timeouts.clone();
        let attempts = attempts.clone();
        move |attempt_timeout| {
            let seen_timeouts = seen_timeouts.clone();
            let attempts = attempts.clone();
            async move {
                seen_timeouts
                    .lock()
                    .expect("seen timeouts mutex")
                    .push(attempt_timeout);
                if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    Err(Error::JobLockedByConcurrentTransaction)
                } else {
                    Ok(())
                }
            }
        }
    })
    .await
    .expect("second retry should succeed");

    let seen_timeouts = seen_timeouts.lock().expect("seen timeouts mutex");
    assert_eq!(seen_timeouts.len(), 2);
    assert!(seen_timeouts[0] <= operation_timeout);
    assert!(
        seen_timeouts[1] < seen_timeouts[0],
        "retried database operation must receive only the remaining retry budget"
    );
}

#[tokio::test]
async fn queue_worker_join_result_helpers_preserve_success_and_map_join_failures() {
    let expected_summary = WorkerRunLoopSummary {
        claimed_count: 3,
        succeeded_count: 2,
        retried_count: 1,
        failed_count: 0,
        dead_lettered_count: 0,
        lost_ownership_count: 0,
    };
    let successful_worker = tokio::spawn({
        let expected_summary = expected_summary.clone();
        async move { Ok::<WorkerRunLoopSummary, Error>(expected_summary) }
    });

    assert_eq!(
        queue_worker_run_loop_result_from_join_result(successful_worker.await)
            .expect("successful worker join"),
        expected_summary
    );

    let panicking_worker = tokio::spawn(panic_worker_runtime());
    let panic_error = queue_worker_run_loop_result_from_join_result(panicking_worker.await)
        .expect_err("worker task panic should be converted to a queue error");
    assert!(
        matches!(panic_error, Error::WorkerTaskJoinFailed { ref reason } if reason.contains("panic")),
        "unexpected worker panic join error: {panic_error:?}"
    );

    let pending_worker =
        tokio::spawn(async { std::future::pending::<Result<WorkerRunLoopSummary, Error>>().await });
    pending_worker.abort();
    let cancelled_error = queue_worker_run_loop_result_from_join_result(pending_worker.await)
        .expect_err("worker task cancellation should be converted to a queue error");
    assert!(
        matches!(cancelled_error, Error::WorkerTaskJoinFailed { ref reason } if reason.contains("cancelled")),
        "unexpected worker cancellation join error: {cancelled_error:?}"
    );
}

#[tokio::test]
async fn queue_task_join_result_helper_preserves_task_errors_and_sanitizes_join_failures() {
    let successful_task = tokio::spawn(async { Ok::<(), TaskError>(()) });
    queue_task_result_from_join_result(successful_task.await).expect("successful task join");

    let retryable_task =
        tokio::spawn(async { Err::<(), TaskError>(TaskError::retryable("retryable")) });
    let retryable_error = queue_task_result_from_join_result(retryable_task.await)
        .expect_err("task-level retryable error should be preserved");
    assert_eq!(retryable_error.message(), "retryable");
    assert!(!retryable_error.is_permanent());

    let permanent_task =
        tokio::spawn(async { Err::<(), TaskError>(TaskError::permanent("permanent")) });
    let permanent_error = queue_task_result_from_join_result(permanent_task.await)
        .expect_err("task-level permanent error should be preserved");
    assert_eq!(permanent_error.message(), "permanent");
    assert!(permanent_error.is_permanent());

    let panicking_task = tokio::spawn(panic_queue_task_handler());
    let panic_error = queue_task_result_from_join_result(panicking_task.await)
        .expect_err("handler panic should become a permanent task error");
    assert!(panic_error.is_permanent());
    assert_eq!(panic_error.message(), "queue task handler panicked");

    let pending_task =
        tokio::spawn(async { std::future::pending::<Result<(), TaskError>>().await });
    pending_task.abort();
    let cancellation_error = queue_task_result_from_join_result(pending_task.await)
        .expect_err("handler task cancellation should become retryable");
    assert!(!cancellation_error.is_permanent());
    assert!(
        cancellation_error.message().contains("cancelled"),
        "unexpected cancellation error: {cancellation_error:?}"
    );
}

#[test]
fn queue_worker_job_recovery_error_combiner_preserves_primary_and_recovery_errors() {
    let primary_error = worker_job_persistence_error_after_requeue(Error::TaskNameRequired, Ok(()));
    assert!(
        matches!(primary_error, Error::TaskNameRequired),
        "clean requeue should preserve primary error: {primary_error:?}"
    );

    let combined_error = worker_job_persistence_error_after_requeue(
        Error::TaskNameRequired,
        Err(Error::JobLockedByConcurrentTransaction),
    );
    let Error::WorkerJobPersistenceFailureAndRequeueFailed {
        persistence_error,
        requeue_error,
    } = combined_error
    else {
        panic!("unexpected combined persistence/requeue error: {combined_error:?}");
    };
    assert!(matches!(*persistence_error, Error::TaskNameRequired));
    assert!(matches!(
        *requeue_error,
        Error::JobLockedByConcurrentTransaction
    ));
}

#[test]
fn queue_worker_claimed_job_cleanup_error_combiner_preserves_worker_and_cleanup_errors() {
    let worker_error = Error::WorkerTaskJoinFailed {
        reason: "worker panic".to_owned(),
    };
    let primary_error = worker_runtime_error_after_claimed_job_cleanup(worker_error, Ok(()));
    assert!(
        matches!(primary_error, Error::WorkerTaskJoinFailed { ref reason } if reason == "worker panic"),
        "clean cleanup should preserve worker error: {primary_error:?}"
    );

    let combined_error = worker_runtime_error_after_claimed_job_cleanup(
        Error::WorkerTaskJoinFailed {
            reason: "worker cancellation".to_owned(),
        },
        Err(Error::JobLockedByConcurrentTransaction),
    );
    let Error::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
        worker_error,
        cleanup_error,
    } = combined_error
    else {
        panic!("unexpected combined worker/cleanup error: {combined_error:?}");
    };
    assert!(
        matches!(*worker_error, Error::WorkerTaskJoinFailed { ref reason } if reason == "worker cancellation")
    );
    assert!(matches!(
        *cleanup_error,
        Error::JobLockedByConcurrentTransaction
    ));
}

#[test]
fn queue_worker_abort_cleanup_combiner_preserves_primary_cleanup_and_sibling_failures() {
    let combined_error = worker_runtime_error_after_in_flight_abort_and_claimed_job_cleanup(
        Error::WorkerTaskJoinFailed {
            reason: "primary".to_owned(),
        },
        vec![Error::TaskNameRequired],
        Err(Error::JobLockedByConcurrentTransaction),
    );

    let Error::WorkerRuntimeMultipleFailures { failures } = combined_error else {
        panic!("unexpected combined worker/sibling/cleanup error: {combined_error:?}");
    };
    assert_eq!(failures.len(), 2);

    let Error::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
        worker_error,
        cleanup_error,
    } = &failures[0]
    else {
        panic!(
            "primary failure should preserve cleanup failure before sibling failures: {:?}",
            failures[0]
        );
    };
    assert!(
        matches!(**worker_error, Error::WorkerTaskJoinFailed { ref reason } if reason == "primary")
    );
    assert!(matches!(
        **cleanup_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert!(matches!(failures[1], Error::TaskNameRequired));
}

#[test]
fn queue_worker_shutdown_timeout_combiner_preserves_cleanup_and_sibling_failures() {
    let summary = WorkerRunLoopSummary {
        claimed_count: 3,
        succeeded_count: 1,
        ..WorkerRunLoopSummary::default()
    };

    assert_eq!(
        worker_runtime_shutdown_timeout_result_after_in_flight_abort_and_claimed_job_cleanup(
            summary.clone(),
            Vec::new(),
            Ok(())
        )
        .expect("clean shutdown-timeout cleanup should return summary"),
        summary
    );

    let single_sibling_error =
        worker_runtime_shutdown_timeout_result_after_in_flight_abort_and_claimed_job_cleanup(
            summary.clone(),
            vec![Error::TaskNameRequired],
            Ok(()),
        )
        .expect_err("single sibling failure should be preserved");
    assert!(matches!(single_sibling_error, Error::TaskNameRequired));

    let combined =
        worker_runtime_shutdown_timeout_result_after_in_flight_abort_and_claimed_job_cleanup(
            summary,
            vec![Error::TaskNameRequired, Error::InvalidTaskName],
            Err(Error::JobLockedByConcurrentTransaction),
        )
        .expect_err("cleanup plus sibling failures should be preserved together");
    let Error::WorkerRuntimeMultipleFailures { failures } = combined else {
        panic!("unexpected shutdown-timeout combined error: {combined:?}");
    };
    assert_eq!(failures.len(), 3);
    assert!(matches!(
        failures[0],
        Error::JobLockedByConcurrentTransaction
    ));
    assert!(matches!(failures[1], Error::TaskNameRequired));
    assert!(matches!(failures[2], Error::InvalidTaskName));
}

#[tokio::test]
async fn queue_worker_abort_join_result_filter_ignores_expected_cancellation_and_collects_failures()
{
    let task_error =
        tokio::spawn(async { Err::<ProcessedJobOutcome, Error>(Error::TaskNameRequired) })
            .await
            .expect("task error join should not panic");
    let collected_task_error =
        worker_runtime_error_from_joined_in_flight_job_after_abort(Ok(task_error))
            .expect("completed task error should be collected");
    assert!(matches!(collected_task_error, Error::TaskNameRequired));

    let pending_task =
        tokio::spawn(async { std::future::pending::<Result<ProcessedJobOutcome, Error>>().await });
    pending_task.abort();
    let cancellation = pending_task.await;
    assert!(
        worker_runtime_error_from_joined_in_flight_job_after_abort(cancellation).is_none(),
        "expected abort cancellation should not be reported as a sibling worker failure"
    );

    let panicking_task = tokio::spawn(async {
        panic!("joined in-flight queue worker task panic");
        #[allow(unreachable_code)]
        Ok::<ProcessedJobOutcome, Error>(ProcessedJobOutcome::Succeeded)
    });
    let panic_error = panicking_task
        .await
        .expect_err("panic should surface as a join error");
    let collected_panic =
        worker_runtime_error_from_joined_in_flight_job_after_abort(Err(panic_error))
            .expect("panic join error should be collected");
    assert!(
        matches!(collected_panic, Error::WorkerTaskJoinFailed { ref reason } if reason.contains("panic")),
        "unexpected collected panic error: {collected_panic:?}"
    );
}

#[tokio::test]
async fn queue_worker_stop_heartbeat_loop_reports_heartbeat_task_join_errors() {
    let (stop_sender, _stop_receiver) = tokio::sync::oneshot::channel();
    let heartbeat_task = tokio::spawn(std::future::pending::<()>());
    heartbeat_task.abort();
    let heartbeat_handle = WorkerHeartbeatLoopHandle::new(heartbeat_task, stop_sender);
    let error = stop_worker_heartbeat_loop(Some(heartbeat_handle))
        .await
        .expect_err("heartbeat join error should be reported");
    assert!(
        matches!(error, Error::WorkerHeartbeatTaskJoinFailed { .. }),
        "unexpected heartbeat join error: {error:?}"
    );
}

#[test]
fn queue_worker_heartbeat_and_finalization_combiner_preserves_failures() {
    assert!(matches!(
        combine_worker_heartbeat_and_job_finalization_results(
            Ok(()),
            Ok(ProcessedJobOutcome::Succeeded),
        ),
        Ok(ProcessedJobOutcome::Succeeded)
    ));

    assert!(matches!(
        combine_worker_heartbeat_and_job_finalization_results(Ok(()), Err(Error::JobNotRunning)),
        Err(Error::JobNotRunning)
    ));

    assert!(matches!(
        combine_worker_heartbeat_and_job_finalization_results(
            Err(Error::WorkerTaskJoinFailed {
                reason: "heartbeat".to_owned()
            }),
            Ok(ProcessedJobOutcome::Succeeded),
        ),
        Err(Error::WorkerTaskJoinFailed { ref reason }) if reason == "heartbeat"
    ));

    let combined = combine_worker_heartbeat_and_job_finalization_results(
        Err(Error::WorkerTaskJoinFailed {
            reason: "heartbeat".to_owned(),
        }),
        Err(Error::JobNotRunning),
    )
    .expect_err("both heartbeat and finalization failures should be preserved");
    let Error::WorkerHeartbeatFailureAndJobFinalizationFailed {
        heartbeat_error,
        finalization_error,
    } = combined
    else {
        panic!("unexpected combined heartbeat/finalization error: {combined:?}");
    };
    assert!(
        matches!(*heartbeat_error, Error::WorkerTaskJoinFailed { ref reason } if reason == "heartbeat")
    );
    assert!(matches!(*finalization_error, Error::JobNotRunning));
}

#[test]
fn queue_worker_run_loop_summary_rejects_counter_overflow() {
    let mut claimed_overflow = WorkerRunLoopSummary {
        claimed_count: u32::MAX,
        ..WorkerRunLoopSummary::default()
    };
    let claimed_error = claimed_overflow
        .record_claimed_count(1)
        .expect_err("claimed count overflow should be rejected");
    assert!(
        matches!(claimed_error, Error::UnexpectedOutcome { operation: "queue worker run loop", ref outcome } if outcome == "claimed job count overflowed"),
        "unexpected claimed overflow error: {claimed_error:?}"
    );

    let mut processed_overflow = WorkerRunLoopSummary {
        succeeded_count: u32::MAX,
        ..WorkerRunLoopSummary::default()
    };
    let processed_error = processed_overflow
        .record_processed_job_outcome(ProcessedJobOutcome::Succeeded)
        .expect_err("processed count overflow should be rejected");
    assert!(
        matches!(processed_error, Error::UnexpectedOutcome { operation: "queue worker run loop", ref outcome } if outcome == "processed job count overflowed"),
        "unexpected processed overflow error: {processed_error:?}"
    );
}

#[tokio::test]
async fn queue_worker_handle_wait_maps_worker_task_join_failure() {
    let handle = WorkerHandle {
        worker_shutdown_signal: RuntimeCancellationSignal::new(),
        join_handle: Some(tokio::spawn(panic_worker_handle())),
    };

    let error = handle
        .wait()
        .await
        .expect_err("worker handle wait should surface worker task panic");
    assert!(
        matches!(error, Error::WorkerTaskJoinFailed { ref reason } if reason.contains("panic")),
        "unexpected worker handle wait error: {error:?}"
    );
}

#[tokio::test]
async fn queue_worker_handle_reports_stop_and_finished_state() {
    let worker_shutdown_signal = RuntimeCancellationSignal::new();
    let worker_task_shutdown_signal = worker_shutdown_signal.clone();
    let handle = WorkerHandle {
        worker_shutdown_signal,
        join_handle: Some(tokio::spawn(async move {
            worker_task_shutdown_signal
                .wait_until_cancellation_requested()
                .await;
            Ok::<WorkerRunLoopSummary, Error>(WorkerRunLoopSummary::default())
        })),
    };

    assert!(!handle.is_finished());
    assert!(handle.request_stop());
    assert!(!handle.request_stop());
    let summary = tokio::time::timeout(Duration::from_millis(50), handle.wait())
        .await
        .expect("stopped worker should finish promptly")
        .expect("stopped worker should return a summary");
    assert_eq!(summary, WorkerRunLoopSummary::default());

    let completed_handle = WorkerHandle {
        worker_shutdown_signal: RuntimeCancellationSignal::new(),
        join_handle: Some(tokio::spawn(async {
            Ok::<WorkerRunLoopSummary, Error>(WorkerRunLoopSummary::default())
        })),
    };
    tokio::time::timeout(Duration::from_millis(50), async {
        while !completed_handle.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed worker handle should report finished");
    let summary = completed_handle
        .wait()
        .await
        .expect("completed worker should still be waitable after is_finished");
    assert_eq!(summary, WorkerRunLoopSummary::default());
}

#[tokio::test]
async fn dropping_queue_worker_handle_requests_worker_shutdown() {
    let worker_shutdown_signal = RuntimeCancellationSignal::new();
    let observed_shutdown_signal = worker_shutdown_signal.clone();
    let worker_task_shutdown_signal = worker_shutdown_signal.clone();
    let handle = WorkerHandle {
        worker_shutdown_signal,
        join_handle: Some(tokio::spawn(async move {
            worker_task_shutdown_signal
                .wait_until_cancellation_requested()
                .await;
            Ok::<WorkerRunLoopSummary, Error>(WorkerRunLoopSummary::default())
        })),
    };

    drop(handle);

    tokio::time::timeout(
        Duration::from_millis(50),
        observed_shutdown_signal.wait_until_cancellation_requested(),
    )
    .await
    .expect("dropping worker handle should request worker shutdown");
}

#[tokio::test]
async fn queue_runtime_cancellation_signal_wakes_pre_requested_and_live_waiters() {
    let pre_requested = RuntimeCancellationSignal::new();
    assert!(pre_requested.request_cancellation());
    assert!(!pre_requested.request_cancellation());
    tokio::time::timeout(
        Duration::from_millis(50),
        pre_requested.wait_until_cancellation_requested(),
    )
    .await
    .expect("pre-requested cancellation signal should not wait");

    let live_signal = RuntimeCancellationSignal::new();
    let waiter_signal = live_signal.clone();
    let waiter = tokio::spawn(async move {
        waiter_signal.wait_until_cancellation_requested().await;
    });
    tokio::task::yield_now().await;
    assert!(live_signal.request_cancellation());
    assert!(!live_signal.request_cancellation());
    tokio::time::timeout(Duration::from_millis(50), waiter)
        .await
        .expect("live cancellation signal should wake waiter")
        .expect("waiter task should not panic");
}

#[tokio::test]
async fn queue_maintenance_cron_join_result_helper_preserves_success_and_maps_failures() {
    let successful_cron = tokio::spawn(async { Ok::<(), CronRunError<Error>>(()) });
    queue_maintenance_cron_result_from_join_result("cleanup", successful_cron.await)
        .expect("successful maintenance cron join");

    let task_failing_cron = tokio::spawn(async {
        Err::<(), CronRunError<Error>>(CronRunError::Task {
            source: Error::TaskNameRequired,
        })
    });
    let task_error =
        queue_maintenance_cron_result_from_join_result("reclaim", task_failing_cron.await)
            .expect_err("maintenance cron task error should be preserved");
    assert!(
        matches!(
            task_error,
            Error::MaintenanceCronRunFailed {
                cron_name: "reclaim",
                ..
            }
        ),
        "unexpected maintenance task error: {task_error:?}"
    );

    let panicking_cron = tokio::spawn(panic_maintenance_cron());
    let panic_error =
        queue_maintenance_cron_result_from_join_result("cleanup", panicking_cron.await)
            .expect_err("maintenance cron panic should be converted to a queue error");
    assert!(
        matches!(
            panic_error,
            Error::MaintenanceCronTaskJoinFailed {
                cron_name: "cleanup",
                ref reason,
            } if reason.contains("panic")
        ),
        "unexpected maintenance panic join error: {panic_error:?}"
    );
}

#[test]
fn queue_worker_runtime_stop_result_combiner_preserves_single_and_multiple_failures() {
    let expected_summary = WorkerRunLoopSummary {
        claimed_count: 1,
        succeeded_count: 1,
        failed_count: 0,
        retried_count: 0,
        dead_lettered_count: 0,
        lost_ownership_count: 0,
    };
    assert_eq!(
        combine_queue_worker_runtime_stop_results(
            true,
            "cleanup",
            Ok(expected_summary.clone()),
            Ok(()),
            Ok(())
        )
        .expect("already-requested shutdown with clean tasks should return summary"),
        expected_summary
    );

    let unexpected_stop = combine_queue_worker_runtime_stop_results(
        false,
        "cleanup",
        Ok(WorkerRunLoopSummary::default()),
        Ok(()),
        Ok(()),
    )
    .expect_err("unexpected clean maintenance stop should be an error");
    assert!(
        matches!(
            unexpected_stop,
            Error::MaintenanceCronStoppedUnexpectedly {
                cron_name: "cleanup"
            }
        ),
        "unexpected single runtime error: {unexpected_stop:?}"
    );

    let multiple_after_unexpected_stop = combine_queue_worker_runtime_stop_results(
        false,
        "cleanup",
        Err(Error::WorkerTaskJoinFailed {
            reason: "worker closed".to_owned(),
        }),
        Ok(()),
        Err(Error::MaintenanceCronTaskJoinFailed {
            cron_name: "reclaim",
            reason: "reclaim closed".to_owned(),
        }),
    )
    .expect_err("worker failure plus unexpected maintenance stop should preserve both failures");
    let Error::WorkerRuntimeMultipleFailures { failures } = multiple_after_unexpected_stop else {
        panic!("unexpected combined runtime error: {multiple_after_unexpected_stop:?}");
    };
    assert_eq!(failures.len(), 3);
    assert!(matches!(failures[0], Error::WorkerTaskJoinFailed { .. }));
    assert!(matches!(
        failures[1],
        Error::MaintenanceCronTaskJoinFailed {
            cron_name: "reclaim",
            ..
        }
    ));
    assert!(matches!(
        failures[2],
        Error::MaintenanceCronStoppedUnexpectedly {
            cron_name: "cleanup",
        }
    ));

    let multiple_after_requested_shutdown = combine_queue_worker_runtime_stop_results(
        true,
        "cleanup",
        Err(Error::WorkerTaskJoinFailed {
            reason: "worker closed".to_owned(),
        }),
        Err(Error::MaintenanceCronTaskJoinFailed {
            cron_name: "cleanup",
            reason: "cleanup closed".to_owned(),
        }),
        Ok(()),
    )
    .expect_err("requested shutdown should still preserve simultaneous failures");
    let Error::WorkerRuntimeMultipleFailures { failures } = multiple_after_requested_shutdown
    else {
        panic!(
            "unexpected requested-shutdown runtime error: {multiple_after_requested_shutdown:?}"
        );
    };
    assert_eq!(failures.len(), 2);
    assert!(matches!(failures[0], Error::WorkerTaskJoinFailed { .. }));
    assert!(matches!(
        failures[1],
        Error::MaintenanceCronTaskJoinFailed {
            cron_name: "cleanup",
            ..
        }
    ));
}

#[test]
fn queue_worker_completed_first_runtime_stop_result_combiner_preserves_maintenance_failures() {
    let expected_summary = WorkerRunLoopSummary {
        claimed_count: 2,
        succeeded_count: 1,
        failed_count: 1,
        retried_count: 0,
        dead_lettered_count: 0,
        lost_ownership_count: 0,
    };
    assert_eq!(
        combine_queue_worker_completed_first_runtime_stop_results(
            Ok(expected_summary.clone()),
            Ok(()),
            Ok(())
        )
        .expect("clean maintenance shutdown after worker completion should return summary"),
        expected_summary
    );

    let maintenance_error = combine_queue_worker_completed_first_runtime_stop_results(
        Ok(WorkerRunLoopSummary::default()),
        Err(Error::MaintenanceCronTaskJoinFailed {
            cron_name: "reclaim",
            reason: "reclaim closed".to_owned(),
        }),
        Ok(()),
    )
    .expect_err("worker-first shutdown should preserve single maintenance failure");
    assert!(
        matches!(
            maintenance_error,
            Error::MaintenanceCronTaskJoinFailed {
                cron_name: "reclaim",
                ..
            }
        ),
        "unexpected single worker-first runtime error: {maintenance_error:?}"
    );

    let combined_error = combine_queue_worker_completed_first_runtime_stop_results(
        Err(Error::WorkerTaskJoinFailed {
            reason: "worker closed".to_owned(),
        }),
        Err(Error::MaintenanceCronTaskJoinFailed {
            cron_name: "reclaim",
            reason: "reclaim closed".to_owned(),
        }),
        Err(Error::MaintenanceCronTaskJoinFailed {
            cron_name: "cleanup",
            reason: "cleanup closed".to_owned(),
        }),
    )
    .expect_err("worker-first shutdown should preserve worker and maintenance failures together");
    let Error::WorkerRuntimeMultipleFailures { failures } = combined_error else {
        panic!("unexpected worker-first runtime error: {combined_error:?}");
    };
    assert_eq!(failures.len(), 3);
    assert!(matches!(failures[0], Error::WorkerTaskJoinFailed { .. }));
    assert!(matches!(
        failures[1],
        Error::MaintenanceCronTaskJoinFailed {
            cron_name: "reclaim",
            ..
        }
    ));
    assert!(matches!(
        failures[2],
        Error::MaintenanceCronTaskJoinFailed {
            cron_name: "cleanup",
            ..
        }
    ));
}

#[test]
fn queue_worker_database_operation_statement_timeout_uses_remaining_budget() {
    let operation_timeout = Duration::from_secs(60);
    let started_at = std::time::Instant::now() - Duration::from_millis(25);

    let remaining_timeout = remaining_worker_database_operation_timeout(
        started_at,
        operation_timeout,
        "test worker database operation",
    )
    .expect("remaining timeout");

    assert!(
        remaining_timeout < operation_timeout,
        "remaining timeout should account for work already spent before statement timeout setup"
    );
    assert_ne!(
        postgres_statement_timeout_value(remaining_timeout),
        postgres_statement_timeout_value(operation_timeout),
        "Postgres statement timeout must be derived from the remaining worker DB-operation budget"
    );
}
