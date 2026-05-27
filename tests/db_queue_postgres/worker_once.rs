use super::worker_once_support::*;
use super::*;

#[tokio::test]
async fn queue_worker_run_once_processes_success_retry_permanent_and_exhausted_outcomes() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let success = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_success",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue success job");
    let retryable = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_retry",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue retryable job");
    let permanent = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_permanent",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue permanent job");
    let exhausted = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_exhausted",
            &TestPayload { value: 4 },
            EnqueueOptions {
                max_retries: Some(0),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue exhausted job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.runtime_success",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 1);
                Ok(())
            },
        )
        .expect("register success handler");
    registry
        .register_json_task_handler(
            "task.worker.runtime_retry",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 2);
                Err(TaskError::retryable("retry me"))
            },
        )
        .expect("register retry handler");
    registry
        .register_json_task_handler(
            "task.worker.runtime_permanent",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 3);
                Err(TaskError::permanent("permanent failure"))
            },
        )
        .expect("register permanent handler");
    registry
        .register_json_task_handler(
            "task.worker.runtime_exhausted",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 4);
                Err(TaskError::retryable("exhausted failure"))
            },
        )
        .expect("register exhausted handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-runtime",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect("process worker batch");
    assert_eq!(summary.claimed_count, 4);
    assert_eq!(summary.succeeded_count, 1);
    assert_eq!(summary.retried_count, 1);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 2);
    assert_eq!(summary.lost_ownership_count, 0);

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, success.job_id)
            .await
            .expect("success status"),
        JobStatus::Completed
    );
    let retryable_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, retryable.job_id)
        .await
        .expect("fetch retryable after worker pass");
    assert_eq!(retryable_after.status, JobStatus::Pending);
    assert_eq!(retryable_after.retry_count, 1);
    assert_eq!(retryable_after.last_error.as_deref(), Some("retry me"));
    assert!(retryable_after.worker_owner_id.is_none());

    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, permanent.job_id)
            .await
            .expect_err("permanent job should leave main table"),
        Error::JobNotFound
    ));
    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, exhausted.job_id)
            .await
            .expect_err("exhausted job should leave main table"),
        Error::JobNotFound
    ));
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list worker dead letters");
    assert_eq!(dead_letters.jobs.len(), 2);
    let permanent_dead_letter = dead_letters
        .jobs
        .iter()
        .find(|job| job.original_job_id == permanent.job_id)
        .expect("permanent dead letter");
    assert_eq!(
        permanent_dead_letter.reason,
        DeadLetterReason::PermanentError
    );
    assert_eq!(permanent_dead_letter.last_error, "permanent failure");
    assert_eq!(permanent_dead_letter.retry_count, 0);
    let exhausted_dead_letter = dead_letters
        .jobs
        .iter()
        .find(|job| job.original_job_id == exhausted.job_id)
        .expect("exhausted dead letter");
    assert_eq!(
        exhausted_dead_letter.reason,
        DeadLetterReason::MaxRetriesExceeded
    );
    assert_eq!(exhausted_dead_letter.last_error, "exhausted failure");
    assert_eq!(exhausted_dead_letter.retry_count, 1);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_handler_panic_is_job_level_permanent_failure_not_worker_failure() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let panicking_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_panic",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue panicking job");
    let succeeding_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_survives_panic",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue surviving job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.runtime_panic",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 1);
                panic!("intentional queue handler panic for test");
                #[allow(unreachable_code)]
                Ok(())
            },
        )
        .expect("register panicking handler");
    registry
        .register_json_task_handler(
            "task.worker.runtime_survives_panic",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 2);
                Ok(())
            },
        )
        .expect("register surviving handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-panic",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect("worker batch should survive handler panic");
    assert_eq!(summary.claimed_count, 2);
    assert_eq!(summary.succeeded_count, 1);
    assert_eq!(summary.dead_lettered_count, 1);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, succeeding_job.job_id)
            .await
            .expect("surviving job status"),
        JobStatus::Completed
    );
    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, panicking_job.job_id)
            .await
            .expect_err("panicking job should leave main table"),
        Error::JobNotFound
    ));

    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list panic dead letters");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(dead_letters.jobs[0].original_job_id, panicking_job.job_id);
    assert_eq!(
        dead_letters.jobs[0].reason,
        DeadLetterReason::PermanentError
    );
    assert_eq!(
        dead_letters.jobs[0].last_error,
        "queue task handler panicked"
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_internal_task_panic_after_start_returns_job_to_pending() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.internal_panic_after_start",
            &TestPayload { value: 9 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue internal-panic job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.internal_panic_after_start", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    assert_eq!(payload.value, 9);
                    handler_called.store(true, Ordering::SeqCst);
                    Err(TaskError::retryable("trigger custom backoff"))
                }
            }
        })
        .expect("register internal-panic handler");

    let error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-internal-panic-after-start",
            WorkerConfig {
                retry_policy: RetryPolicy {
                    strategy: RetryBackoffStrategy::Custom(Arc::new(|_, _| {
                        panic!("intentional custom retry backoff panic for test")
                    })),
                    jitter_fraction: 0.0,
                    ..RetryPolicy::default()
                },
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect_err("internal worker panic should surface as worker task join failure");
    assert!(matches!(error, Error::WorkerTaskJoinFailed { .. }));
    assert!(handler_called.load(Ordering::SeqCst));

    let job_after_panic = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch internal-panic job after cleanup");
    assert_eq!(job_after_panic.status, JobStatus::Pending);
    assert_eq!(job_after_panic.retry_count, 0);
    assert!(job_after_panic.last_error.is_none());
    assert!(job_after_panic.worker_owner_id.is_none());
    assert!(
        job_after_panic
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_panic
            .execution_started_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_once_can_fail_without_dead_letter_and_handlers_can_touch_heartbeat() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let failed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_no_dead_letter",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue failed job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.runtime_no_dead_letter",
            |context, payload: TestPayload| async move {
                assert_eq!(payload.value, 1);
                context
                    .touch_execution_heartbeat()
                    .await
                    .map_err(|error| TaskError::retryable(error.to_string()))?;
                Err(TaskError::permanent("dead letter disabled"))
            },
        )
        .expect("register no-dead-letter handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-no-dead-letter",
            fixed_retry_worker_config(Duration::from_millis(1), false),
        )
        .await
        .expect("process no-dead-letter batch");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.failed_count, 1);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    let failed_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, failed.job_id)
        .await
        .expect("fetch failed job");
    assert_eq!(failed_after.status, JobStatus::Failed);
    assert_eq!(failed_after.retry_count, 0);
    assert_eq!(
        failed_after.last_error.as_deref(),
        Some("dead letter disabled")
    );
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters");
    assert!(dead_letters.jobs.is_empty());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_stops_heartbeating_before_completion_and_clears_runtime_columns() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let completed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.heartbeat_completion",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue heartbeat-completion job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.heartbeat_completion",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 1);
                tokio::time::sleep(Duration::from_millis(40)).await;
                Ok(())
            },
        )
        .expect("register heartbeat-completion handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-heartbeat-completion",
            WorkerConfig {
                execution_heartbeat_interval: Duration::from_millis(5),
                stale_threshold: Duration::from_secs(1),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect("process heartbeat-completion batch");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 1);

    tokio::time::sleep(Duration::from_millis(25)).await;
    let completed_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, completed.job_id)
        .await
        .expect("fetch completed heartbeat job");
    assert_eq!(completed_after.status, JobStatus::Completed);
    assert!(completed_after.worker_owner_id.is_none());
    assert!(
        completed_after
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        completed_after
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        completed_after
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_ignores_unexpected_heartbeat_write_errors_until_terminal_transition() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_heartbeat_write_failure_trigger(&test_database).await;

    let completed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.heartbeat_write_fails",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue heartbeat write-failure job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.heartbeat_write_fails",
            |_context, payload: TestPayload| async move {
                assert_eq!(payload.value, 1);
                tokio::time::sleep(Duration::from_millis(40)).await;
                Ok(())
            },
        )
        .expect("register heartbeat write-failure handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-heartbeat-write-failure",
            WorkerConfig {
                execution_heartbeat_interval: Duration::from_millis(5),
                stale_threshold: Duration::from_secs(1),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect("heartbeat write failure should not fail the job");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 1);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    let completed_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, completed.job_id)
        .await
        .expect("fetch completed heartbeat write-failure job");
    assert_eq!(completed_after.status, JobStatus::Completed);
    assert!(completed_after.worker_owner_id.is_none());
    assert!(
        completed_after
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        completed_after
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_dead_letter_write_failure_returns_job_to_pending_and_surfaces_error() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let permanent = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.dead_letter_unavailable",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue permanent job with unavailable dead-letter table");
    let sibling = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.dead_letter_unavailable_sibling",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue sibling job affected by worker-level cleanup");
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
    )
    .await;

    let both_handlers_started = Arc::new(tokio::sync::Barrier::new(2));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.dead_letter_unavailable", {
            let both_handlers_started = Arc::clone(&both_handlers_started);
            move |_context, payload: TestPayload| {
                let both_handlers_started = Arc::clone(&both_handlers_started);
                async move {
                    assert_eq!(payload.value, 1);
                    both_handlers_started.wait().await;
                    Err(TaskError::permanent("must be dead-lettered"))
                }
            }
        })
        .expect("register dead-letter unavailable handler");
    registry
        .register_json_task_handler("task.worker.dead_letter_unavailable_sibling", {
            let both_handlers_started = Arc::clone(&both_handlers_started);
            move |_context, payload: TestPayload| {
                let both_handlers_started = Arc::clone(&both_handlers_started);
                async move {
                    assert_eq!(payload.value, 2);
                    both_handlers_started.wait().await;
                    std::future::pending::<Result<(), TaskError>>().await
                }
            }
        })
        .expect("register sibling handler");

    let error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-dead-letter-unavailable",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect_err("dead-letter write failure should be surfaced");
    assert!(matches!(error, Error::Database(_)));

    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, permanent.job_id)
        .await
        .expect("failed dead-letter write should return job to pending");
    assert_eq!(job_after_error.status, JobStatus::Pending);
    assert_eq!(job_after_error.retry_count, 0);
    assert!(job_after_error.last_error.is_none());
    assert!(job_after_error.worker_owner_id.is_none());
    assert!(
        job_after_error
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_error
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    let sibling_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, sibling.job_id)
        .await
        .expect("worker-level cleanup should return sibling job to pending");
    assert_eq!(sibling_after_error.status, JobStatus::Pending);
    assert_eq!(sibling_after_error.retry_count, 0);
    assert!(sibling_after_error.last_error.is_none());
    assert!(sibling_after_error.worker_owner_id.is_none());
    assert!(
        sibling_after_error
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        sibling_after_error
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        sibling_after_error
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_terminal_write_failures_return_started_jobs_to_pending() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_terminal_write_failure_triggers(&test_database).await;

    let completed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.complete_write_fails",
            &TestPayload { value: 10 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue completion write-failure job");
    let complete_handler_calls = Arc::new(AtomicUsize::new(0));
    let mut complete_registry = TaskRegistry::new();
    complete_registry
        .register_json_task_handler("task.worker.complete_write_fails", {
            let complete_handler_calls = Arc::clone(&complete_handler_calls);
            move |_context, _payload: TestPayload| {
                let complete_handler_calls = Arc::clone(&complete_handler_calls);
                async move {
                    complete_handler_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register completion write-failure handler");
    let complete_error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &complete_registry,
            "worker-terminal-write-failure",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect_err("completion write failure should surface");
    assert!(matches!(complete_error, Error::Database(_)));
    assert_job_returned_to_pending_after_terminal_write_failure(
        &queue,
        &test_database,
        completed.job_id,
    )
    .await;
    assert_eq!(
        complete_handler_calls.load(Ordering::SeqCst),
        1,
        "completion finalization failure must not rerun the handler"
    );

    let retry = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.retry_write_fails",
            &TestPayload { value: 11 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue retry write-failure job");
    let retry_handler_calls = Arc::new(AtomicUsize::new(0));
    let mut retry_registry = TaskRegistry::new();
    retry_registry
        .register_json_task_handler("task.worker.retry_write_fails", {
            let retry_handler_calls = Arc::clone(&retry_handler_calls);
            move |_context, _payload: TestPayload| {
                let retry_handler_calls = Arc::clone(&retry_handler_calls);
                async move {
                    retry_handler_calls.fetch_add(1, Ordering::SeqCst);
                    Err(TaskError::retryable("retry"))
                }
            }
        })
        .expect("register retry write-failure handler");
    let retry_error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &retry_registry,
            "worker-terminal-write-failure",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect_err("retry write failure should surface");
    assert!(matches!(retry_error, Error::Database(_)));
    assert_job_returned_to_pending_after_terminal_write_failure(
        &queue,
        &test_database,
        retry.job_id,
    )
    .await;
    assert_eq!(
        retry_handler_calls.load(Ordering::SeqCst),
        1,
        "retry finalization failure must not rerun the handler"
    );

    let failed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.failed_write_fails",
            &TestPayload { value: 12 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue failed write-failure job");
    let failed_handler_calls = Arc::new(AtomicUsize::new(0));
    let mut failed_registry = TaskRegistry::new();
    failed_registry
        .register_json_task_handler("task.worker.failed_write_fails", {
            let failed_handler_calls = Arc::clone(&failed_handler_calls);
            move |_context, _payload: TestPayload| {
                let failed_handler_calls = Arc::clone(&failed_handler_calls);
                async move {
                    failed_handler_calls.fetch_add(1, Ordering::SeqCst);
                    Err(TaskError::permanent("failed"))
                }
            }
        })
        .expect("register failed write-failure handler");
    let failed_error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &failed_registry,
            "worker-terminal-write-failure",
            fixed_retry_worker_config(Duration::from_millis(1), false),
        )
        .await
        .expect_err("failed write failure should surface");
    assert!(matches!(failed_error, Error::Database(_)));
    assert_job_returned_to_pending_after_terminal_write_failure(
        &queue,
        &test_database,
        failed.job_id,
    )
    .await;
    assert_eq!(
        failed_handler_calls.load(Ordering::SeqCst),
        1,
        "failed-job finalization failure must not rerun the handler"
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_manual_heartbeat_caller_timeout_does_not_leave_job_stuck() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_slow_heartbeat_trigger(&test_database).await;

    let heartbeat_timed_out = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.slow_manual_heartbeat", {
            let heartbeat_timed_out = Arc::clone(&heartbeat_timed_out);
            move |context, _payload: TestPayload| {
                let heartbeat_timed_out = Arc::clone(&heartbeat_timed_out);
                async move {
                    match tokio::time::timeout(
                        Duration::from_millis(180),
                        context.touch_execution_heartbeat(),
                    )
                    .await
                    {
                        Ok(Ok(())) => Err(TaskError::permanent(
                            "manual heartbeat unexpectedly completed before caller timeout",
                        )),
                        Ok(Err(error)) => Err(TaskError::permanent(format!(
                            "manual heartbeat failed before caller timeout: {error}"
                        ))),
                        Err(_) => {
                            heartbeat_timed_out.store(true, Ordering::SeqCst);
                            Ok(())
                        }
                    }
                }
            }
        })
        .expect("register slow manual heartbeat handler");

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.slow_manual_heartbeat",
            &TestPayload { value: 33 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue slow manual heartbeat job");

    let summary = tokio::time::timeout(
        Duration::from_millis(750),
        queue.process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-slow-manual-heartbeat",
            WorkerConfig {
                database_operation_timeout: Duration::from_millis(200),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        ),
    )
    .await
    .expect("worker should not wait for the full slow heartbeat statement")
    .expect("process slow manual heartbeat job");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 1);
    assert!(heartbeat_timed_out.load(Ordering::SeqCst));

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, enqueued.job_id)
            .await
            .expect("fetch slow manual heartbeat job status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_return_to_pending_write_failure_surfaces_without_panicking() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_completion_and_return_to_pending_failure_trigger(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.return_to_pending_write_fails",
            &TestPayload { value: 13 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue return-to-pending write-failure job");
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.return_to_pending_write_fails",
            |_context, _payload: TestPayload| async move { Ok(()) },
        )
        .expect("register return-to-pending write-failure handler");

    let worker_task = tokio::spawn({
        let queue = queue.clone();
        let pool = test_database.paranoid_pool.clone();
        async move {
            queue
                .process_available_jobs_once_for_worker(
                    &pool,
                    &registry,
                    "worker-return-to-pending-write-failure",
                    fixed_retry_worker_config(Duration::from_millis(1), true),
                )
                .await
        }
    });
    let error = worker_task
        .await
        .expect("worker task should not panic")
        .expect_err("cleanup write failure should surface");
    let Error::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
        worker_error,
        cleanup_error,
    } = error
    else {
        panic!("unexpected completion/cleanup error: {error:?}");
    };
    let Error::WorkerJobPersistenceFailureAndRequeueFailed {
        persistence_error,
        requeue_error,
    } = *worker_error
    else {
        panic!("unexpected worker error after cleanup failure: {worker_error:?}");
    };
    assert!(
        matches!(*persistence_error, Error::Database(_)),
        "unexpected completion persistence error: {persistence_error:?}"
    );
    assert!(
        matches!(*requeue_error, Error::Database(_)),
        "unexpected return-to-pending error: {requeue_error:?}"
    );
    assert!(
        matches!(*cleanup_error, Error::Database(_)),
        "unexpected worker cleanup error: {cleanup_error:?}"
    );

    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch job after failed cleanup");
    assert_eq!(job_after_error.status, JobStatus::Running);
    assert_worker_owner_id_was_derived_from_worker_name(
        worker_owner_id_text(job_after_error.worker_owner_id.as_ref()),
        "worker-return-to-pending-write-failure",
    );
    assert!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_some()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_workers_with_same_logical_name_use_distinct_owner_ids_for_cleanup() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let long_running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.same_name_long_running",
            &TestPayload { value: 50 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue long-running same-name job");
    let failing = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.same_name_failing",
            &TestPayload { value: 51 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue failing same-name job");

    let release_long_running = Arc::new(tokio::sync::Notify::new());
    let long_running_started = Arc::new(tokio::sync::Notify::new());
    let mut long_running_registry = TaskRegistry::new();
    long_running_registry
        .register_json_task_handler("task.worker.same_name_long_running", {
            let release_long_running = Arc::clone(&release_long_running);
            let long_running_started = Arc::clone(&long_running_started);
            move |_context, payload: TestPayload| {
                let release_long_running = Arc::clone(&release_long_running);
                let long_running_started = Arc::clone(&long_running_started);
                async move {
                    assert_eq!(payload.value, 50);
                    long_running_started.notify_waiters();
                    release_long_running.notified().await;
                    Ok(())
                }
            }
        })
        .expect("register long-running same-name handler");

    let long_running_worker = tokio::spawn({
        let queue = queue.clone();
        let pool = test_database.paranoid_pool.clone();
        async move {
            queue
                .process_available_jobs_once_for_worker(
                    &pool,
                    &long_running_registry,
                    "shared-worker-name",
                    WorkerConfig {
                        concurrency: 1,
                        default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                        ..fixed_retry_worker_config(Duration::from_millis(1), true)
                    },
                )
                .await
        }
    });

    tokio::time::timeout(Duration::from_secs(2), long_running_started.notified())
        .await
        .expect("long-running handler should start");
    let long_running_during_other_worker_failure = queue
        .fetch_job_by_id(&test_database.paranoid_pool, long_running.job_id)
        .await
        .expect("fetch long-running same-name job");
    assert_eq!(
        long_running_during_other_worker_failure.status,
        JobStatus::Running
    );
    let long_running_owner_id = assert_worker_owner_id_was_derived_from_worker_name(
        worker_owner_id_text(
            long_running_during_other_worker_failure
                .worker_owner_id
                .as_ref(),
        ),
        "shared-worker-name",
    );

    let failing_handler_called = Arc::new(AtomicBool::new(false));
    let mut failing_registry = TaskRegistry::new();
    failing_registry
        .register_json_task_handler("task.worker.same_name_failing", {
            let failing_handler_called = Arc::clone(&failing_handler_called);
            move |_context, payload: TestPayload| {
                let failing_handler_called = Arc::clone(&failing_handler_called);
                async move {
                    assert_eq!(payload.value, 51);
                    failing_handler_called.store(true, Ordering::SeqCst);
                    Err(TaskError::retryable("trigger same-name cleanup"))
                }
            }
        })
        .expect("register failing same-name handler");

    let failing_error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &failing_registry,
            "shared-worker-name",
            WorkerConfig {
                concurrency: 1,
                retry_policy: RetryPolicy {
                    strategy: RetryBackoffStrategy::Custom(Arc::new(|_, _| {
                        panic!("intentional same-name cleanup panic")
                    })),
                    jitter_fraction: 0.0,
                    ..RetryPolicy::default()
                },
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect_err("failing same-name worker should surface worker task error");
    assert!(matches!(failing_error, Error::WorkerTaskJoinFailed { .. }));
    assert!(failing_handler_called.load(Ordering::SeqCst));

    let long_running_after_other_worker_cleanup = queue
        .fetch_job_by_id(&test_database.paranoid_pool, long_running.job_id)
        .await
        .expect("fetch long-running same-name job after other worker cleanup");
    assert_eq!(
        long_running_after_other_worker_cleanup.status,
        JobStatus::Running
    );
    assert_eq!(
        worker_owner_id_text(
            long_running_after_other_worker_cleanup
                .worker_owner_id
                .as_ref()
        ),
        Some(long_running_owner_id.as_str())
    );

    let failing_after_cleanup = queue
        .fetch_job_by_id(&test_database.paranoid_pool, failing.job_id)
        .await
        .expect("fetch failing same-name job after cleanup");
    assert_eq!(failing_after_cleanup.status, JobStatus::Pending);
    assert!(failing_after_cleanup.worker_owner_id.is_none());

    release_long_running.notify_waiters();
    let long_running_summary = tokio::time::timeout(Duration::from_secs(2), long_running_worker)
        .await
        .expect("long-running same-name worker should finish")
        .expect("long-running same-name worker task should not panic")
        .expect("long-running same-name worker should succeed");
    assert_eq!(long_running_summary.claimed_count, 1);
    assert_eq!(long_running_summary.succeeded_count, 1);

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, long_running.job_id)
            .await
            .expect("fetch long-running same-name completed status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_start_write_failure_returns_unstarted_job_to_pending() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_start_write_failure_trigger(&test_database).await;

    let started = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.start_write_fails",
            &TestPayload { value: 20 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue start write-failure job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.start_write_fails", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register start write-failure handler");

    let start_error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-start-write-failure",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect_err("start write failure should surface");
    assert!(matches!(start_error, Error::Database(_)));
    assert!(!handler_called.load(Ordering::SeqCst));

    assert_job_returned_to_pending_after_terminal_write_failure(
        &queue,
        &test_database,
        started.job_id,
    )
    .await;

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
