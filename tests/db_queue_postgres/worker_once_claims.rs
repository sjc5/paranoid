use super::worker_once_support::*;
use super::*;

#[tokio::test]
async fn queue_worker_lost_ownership_before_start_skips_handler_execution() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_claim_ownership_steal_trigger(&test_database).await;

    let stolen = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.claim_stolen_before_start",
            &TestPayload { value: 21 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue ownership-steal job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.claim_stolen_before_start", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register ownership-steal handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-claim-stolen-before-start",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect("ownership loss before start should be a job outcome");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.lost_ownership_count, 1);
    assert_eq!(summary.succeeded_count, 0);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert!(!handler_called.load(Ordering::SeqCst));

    let job_after_loss = queue
        .fetch_job_by_id(&test_database.paranoid_pool, stolen.job_id)
        .await
        .expect("fetch ownership-steal job");
    assert_eq!(job_after_loss.status, JobStatus::Running);
    assert_eq!(
        worker_owner_id_text(job_after_loss.worker_owner_id.as_ref()),
        Some("different-worker")
    );
    assert!(
        job_after_loss
            .execution_started_at_unix_microseconds
            .is_none()
    );

    let returned = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_unstarted_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &new_manual_worker_owner_id("different-worker"),
        )
        .await
        .expect("return stolen job");
    assert_eq!(returned, 1);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_claim_database_operation_timeout_leaves_job_pending() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_slow_claim_trigger(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.slow_claim",
            &TestPayload { value: 30 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue slow-claim job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.slow_claim",
            |_context, _payload: TestPayload| async move { Ok(()) },
        )
        .expect("register slow-claim handler");

    let error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-slow-claim-timeout",
            WorkerConfig {
                database_operation_timeout: Duration::from_millis(20),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect_err("slow claim should hit worker database operation timeout");
    assert!(matches!(
        error,
        Error::WorkerDatabaseOperationTimedOut {
            operation: "claim available jobs",
            ..
        }
    ));

    tokio::time::sleep(Duration::from_millis(250)).await;
    let job_after_timeout = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch slow-claim job after timeout");
    assert_eq!(job_after_timeout.status, JobStatus::Pending);
    assert!(job_after_timeout.worker_owner_id.is_none());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_claim_future_cancellation_leaves_job_pending() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_slow_claim_trigger(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.slow_claim",
            &TestPayload { value: 31 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue slow-claim cancellation job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.slow_claim",
            |_context, _payload: TestPayload| async move { Ok(()) },
        )
        .expect("register slow-claim cancellation handler");

    let canceled = tokio::time::timeout(
        Duration::from_millis(20),
        queue.process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-slow-claim-canceled",
            WorkerConfig {
                database_operation_timeout: Duration::from_secs(5),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        ),
    )
    .await;
    assert!(canceled.is_err());

    tokio::time::sleep(Duration::from_millis(250)).await;
    let job_after_cancellation = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch slow-claim job after cancellation");
    assert_eq!(job_after_cancellation.status, JobStatus::Pending);
    assert!(job_after_cancellation.worker_owner_id.is_none());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_cancellation_after_claim_returns_unstarted_job_to_pending() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_slow_start_trigger(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.slow_start",
            &TestPayload { value: 32 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue slow-start job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.slow_start", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register slow-start handler");

    let worker = tokio::spawn({
        let queue = queue.clone();
        let pool = test_database.paranoid_pool.clone();
        async move {
            queue
                .process_available_jobs_once_for_worker(
                    &pool,
                    &registry,
                    "worker-slow-start-canceled",
                    WorkerConfig {
                        database_operation_timeout: Duration::from_millis(150),
                        ..fixed_retry_worker_config(Duration::from_millis(1), true)
                    },
                )
                .await
        }
    });

    wait_until(
        "slow-start job is claimed before start finishes",
        Duration::from_secs(2),
        || {
            let queue = queue.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                let job = queue
                    .fetch_job_by_id(&pool, enqueued.job_id)
                    .await
                    .expect("fetch slow-start job while worker is running");
                job.status == JobStatus::Running
                    && worker_owner_id_text(job.worker_owner_id.as_ref()).is_some_and(
                        |worker_owner_id| {
                            worker_owner_id.starts_with("worker-slow-start-canceled.")
                        },
                    )
                    && job.execution_started_at_unix_microseconds.is_none()
            }
        },
    )
    .await;

    worker.abort();
    match worker.await {
        Err(join_error) => assert!(join_error.is_cancelled()),
        Ok(result) => panic!("worker finished before test cancellation: {result:?}"),
    }

    tokio::time::sleep(Duration::from_millis(350)).await;
    let job_after_cancellation = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch slow-start job after cancellation");
    assert_eq!(job_after_cancellation.status, JobStatus::Pending);
    assert!(job_after_cancellation.worker_owner_id.is_none());
    assert!(
        job_after_cancellation
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_cancellation
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(!handler_called.load(Ordering::SeqCst));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_once_times_out_noncooperative_job_and_clears_worker_ownership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let timed_out = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_timeout",
            &TestPayload { value: 1 },
            EnqueueOptions {
                timeout: JobTimeout::ExpiresAfter(Duration::from_millis(25)),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue timeout job");

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.runtime_timeout",
            move |_context, payload: TestPayload| {
                let started_tx = started_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    started_tx.send(()).expect("record timeout handler start");
                    std::future::pending::<Result<(), TaskError>>().await
                }
            },
        )
        .expect("register timeout handler");

    let worker = tokio::spawn({
        let queue = queue.clone();
        let pool = test_database.paranoid_pool.clone();
        async move {
            queue
                .process_available_jobs_once_for_worker(
                    &pool,
                    &registry,
                    "worker-timeout",
                    WorkerConfig {
                        stale_threshold: Duration::from_secs(1),
                        execution_heartbeat_interval: Duration::from_millis(5),
                        ..fixed_retry_worker_config(Duration::from_millis(1), true)
                    },
                )
                .await
        }
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("timeout handler should start")
        .expect("started channel should stay open");
    let summary = tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("worker pass should finish after job timeout")
        .expect("worker pass task should not panic")
        .expect("worker pass");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 0);
    assert_eq!(summary.retried_count, 1);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    let timed_out_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, timed_out.job_id)
        .await
        .expect("fetch timed out job");
    assert_eq!(timed_out_after.status, JobStatus::Pending);
    assert_eq!(timed_out_after.retry_count, 1);
    assert_eq!(
        timed_out_after.last_error.as_deref(),
        Some("queue job timed out")
    );
    assert!(timed_out_after.worker_owner_id.is_none());
    assert!(
        timed_out_after
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        timed_out_after
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        timed_out_after
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_once_dead_letters_preexhausted_job_before_calling_handler() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let preexhausted = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.runtime_preexhausted",
            &TestPayload { value: 1 },
            EnqueueOptions {
                max_retries: Some(0),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue preexhausted job");
    set_job_retry_counts(&test_database, preexhausted.job_id, 1, 0).await;

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.runtime_preexhausted", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register preexhausted handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-preexhausted",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect("process preexhausted job");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 0);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 1);
    assert_eq!(summary.lost_ownership_count, 0);
    assert!(!handler_called.load(Ordering::SeqCst));

    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, preexhausted.job_id)
            .await
            .expect_err("preexhausted job should leave main table"),
        Error::JobNotFound
    ));
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list preexhausted dead letters");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(dead_letters.jobs[0].original_job_id, preexhausted.job_id);
    assert_eq!(
        dead_letters.jobs[0].reason,
        DeadLetterReason::MaxRetriesExceeded
    );
    assert_eq!(dead_letters.jobs[0].retry_count, 1);
    assert_eq!(dead_letters.jobs[0].last_error, "max retries exceeded");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_dead_letters_unknown_task_returned_from_claim() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_claim_unknown_task_trigger(&test_database).await;

    let unknown_after_claim = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.known_then_unknown",
            &TestPayload { value: 22 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue job whose task name is changed after claim");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.known_then_unknown", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register known task handler");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-unknown-after-claim",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect("unknown task returned by claim should be dead-lettered");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.dead_lettered_count, 1);
    assert_eq!(summary.succeeded_count, 0);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);
    assert!(!handler_called.load(Ordering::SeqCst));

    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, unknown_after_claim.job_id)
            .await
            .expect_err("unknown task should leave main queue"),
        Error::JobNotFound
    ));
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list unknown-task dead letter");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(
        dead_letters.jobs[0].original_job_id,
        unknown_after_claim.job_id
    );
    assert_eq!(
        dead_letters.jobs[0].task_name,
        "task.worker.unknown_after_claim"
    );
    assert_eq!(
        dead_letters.jobs[0].reason,
        DeadLetterReason::OperatorAction
    );
    assert_eq!(dead_letters.jobs[0].last_error, "unknown task");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_registry_and_config_validation_reject_ambiguous_runtime_shapes() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.validation",
            |_context, _payload: TestPayload| async move { Ok(()) },
        )
        .expect("register validation handler");
    let duplicate = registry
        .register_json_task_handler(
            "task.worker.validation",
            |_context, _payload: TestPayload| async move { Ok(()) },
        )
        .expect_err("duplicate registration should fail");
    assert!(matches!(duplicate, Error::TaskAlreadyRegistered));

    let empty_registry = TaskRegistry::new();
    let empty_summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &empty_registry,
            "worker-empty",
            WorkerConfig::default(),
        )
        .await
        .expect("empty registry should not touch storage");
    assert_eq!(empty_summary.claimed_count, 0);

    let too_much_concurrency = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-invalid-concurrency",
            WorkerConfig {
                concurrency: paranoid::queue::MAX_WORKER_CONCURRENCY + 1,
                ..WorkerConfig::default()
            },
        )
        .await
        .expect_err("worker concurrency above maximum should fail");
    assert!(matches!(
        too_much_concurrency,
        Error::WorkerConcurrencyTooLarge { .. }
    ));

    let invalid_timing = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-invalid-timing",
            WorkerConfig {
                stale_threshold: Duration::from_secs(5),
                execution_heartbeat_interval: Duration::from_secs(5),
                ..WorkerConfig::default()
            },
        )
        .await
        .expect_err("heartbeat interval must be below stale threshold");
    assert!(matches!(invalid_timing, Error::InvalidWorkerConfig { .. }));

    let invalid_fixed_retry = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-invalid-fixed-retry",
            WorkerConfig {
                retry_policy: RetryPolicy {
                    strategy: RetryBackoffStrategy::Fixed {
                        backoff: Duration::ZERO,
                    },
                    jitter_fraction: 0.0,
                    ..RetryPolicy::default()
                },
                ..WorkerConfig::default()
            },
        )
        .await
        .expect_err("zero fixed retry backoff should fail");
    assert!(matches!(
        invalid_fixed_retry,
        Error::InvalidRetryPolicy { .. }
    ));

    let invalid_custom_retry = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-invalid-custom-retry",
            WorkerConfig {
                retry_policy: RetryPolicy {
                    strategy: RetryBackoffStrategy::Custom(Arc::new(|_, _| Duration::ZERO)),
                    max_backoff: Duration::from_nanos(1),
                    jitter_fraction: 0.0,
                    ..RetryPolicy::default()
                },
                ..WorkerConfig::default()
            },
        )
        .await
        .expect_err("custom retry with invalid max backoff should fail");
    assert!(matches!(
        invalid_custom_retry,
        Error::InvalidRetryPolicy { .. }
    ));
}
