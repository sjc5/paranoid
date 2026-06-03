use super::*;

#[tokio::test]
async fn queue_worker_stop_before_startup_jitter_does_not_claim_pending_job() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.stop_before_startup",
            &TestPayload { value: 0 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue stop-before-startup job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.stop_before_startup", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register stop-before-startup handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-stop-before-startup",
            WorkerConfig {
                startup_jitter_max_delay: Some(Duration::from_secs(60)),
                poll_interval: Duration::from_millis(1),
                concurrency: 1,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start stop-before-startup worker");
    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_millis(500), worker_handle.wait())
        .await
        .expect("worker should stop during startup jitter")
        .expect("stop-before-startup worker wait");
    assert_eq!(summary.claimed_count, 0);
    assert_eq!(summary.succeeded_count, 0);
    assert!(!handler_called.load(Ordering::SeqCst));

    let job_after_stop = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch stop-before-startup job");
    assert_eq!(job_after_stop.status, JobStatus::Pending);
    assert!(job_after_stop.worker_owner_id.is_none());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_churn_claim_retry_heartbeat_high_contention_completes_each_job() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    const TOTAL_JOBS: i32 = 60;
    let attempts = Arc::new(
        (0..TOTAL_JOBS)
            .map(|_| AtomicI64::new(0))
            .collect::<Vec<_>>(),
    );
    let handler_attempts = Arc::clone(&attempts);
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.churn",
            move |_context, payload: TestPayload| {
                let attempts = Arc::clone(&handler_attempts);
                async move {
                    let attempt_number =
                        attempts[payload.value as usize].fetch_add(1, Ordering::SeqCst) + 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    if attempt_number == 1 {
                        Err(TaskError::retryable("transient churn failure"))
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .expect("register churn handler");

    let payloads = (0..TOTAL_JOBS)
        .map(|value| TestPayload { value })
        .collect::<Vec<_>>();
    queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.worker.churn",
            &payloads,
            EnqueueBatchOptions {
                max_retries: Some(6),
                ..EnqueueBatchOptions::default()
            },
        )
        .await
        .expect("enqueue worker churn jobs");

    let start_worker = |worker_id: &'static str| {
        queue
            .start_worker(
                test_database.paranoid_pool.clone(),
                registry.clone(),
                worker_id,
                WorkerConfig {
                    concurrency: 6,
                    poll_interval: Duration::from_millis(2),
                    execution_heartbeat_interval: Duration::from_millis(5),
                    shutdown_grace_period: Duration::from_secs(2),
                    default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                    ..fixed_retry_worker_config(Duration::from_millis(5), true)
                },
            )
            .expect("start churn worker")
    };

    let worker_one = start_worker("churn-worker-1");
    let worker_two = start_worker("churn-worker-2");
    let worker_three = start_worker("churn-worker-3");

    tokio::time::sleep(Duration::from_millis(150)).await;
    worker_two.request_stop();
    tokio::time::timeout(Duration::from_secs(5), worker_two.wait())
        .await
        .expect("worker two should stop during churn window")
        .expect("worker two wait");
    let worker_four = start_worker("churn-worker-4");

    let overall_deadline = Instant::now() + Duration::from_secs(45);
    let mut stalled_deadline = Instant::now() + Duration::from_secs(10);
    let mut last_counts: Option<crate::queue::StatusCounts> = None;
    loop {
        let counts = queue
            .fetch_status_counts(&test_database.paranoid_pool, Some("task.worker.churn"))
            .await
            .expect("fetch churn status counts");
        if last_counts.as_ref() != Some(&counts) {
            last_counts = Some(counts.clone());
            stalled_deadline = Instant::now() + Duration::from_secs(10);
        }
        if counts.completed_count == i64::from(TOTAL_JOBS) {
            assert_eq!(counts.pending_count, 0);
            assert_eq!(counts.running_count, 0);
            assert_eq!(counts.failed_count, 0);
            assert_eq!(counts.dead_letter_count, 0);
            break;
        }
        assert!(
            Instant::now() <= stalled_deadline,
            "stalled waiting for worker churn completion; last counts = {counts:?}"
        );
        assert!(
            Instant::now() <= overall_deadline,
            "timed out waiting for worker churn completion; last counts = {counts:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    for worker in [worker_one, worker_three, worker_four] {
        worker.request_stop();
        tokio::time::timeout(Duration::from_secs(5), worker.wait())
            .await
            .expect("worker should stop after churn completion")
            .expect("worker wait after churn completion");
    }

    for (job_index, attempt_counter) in attempts.iter().enumerate() {
        assert!(
            attempt_counter.load(Ordering::SeqCst) >= 2,
            "job {job_index} should have been retried at least once"
        );
    }

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_refills_capacity_without_waiting_for_poll_tick_and_stops_cleanly() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    for value in 1..=3 {
        queue
            .enqueue_json(
                &test_database.paranoid_pool,
                "task.worker.loop_success",
                &TestPayload { value },
                EnqueueOptions::default(),
            )
            .await
            .expect("enqueue loop job");
    }

    let (processed_tx, mut processed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_success",
            move |_context, payload: TestPayload| {
                let processed_tx = processed_tx.clone();
                async move {
                    processed_tx
                        .send(payload.value)
                        .expect("record processed payload value");
                    Ok(())
                }
            },
        )
        .expect("register loop success handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-success",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                concurrency: 1,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start queue worker");

    let mut processed_values = Vec::new();
    for _ in 0..3 {
        let processed_value = tokio::time::timeout(Duration::from_secs(2), processed_rx.recv())
            .await
            .expect("worker should refill capacity without waiting for poll tick")
            .expect("processed channel should stay open");
        processed_values.push(processed_value);
    }
    processed_values.sort_unstable();
    assert_eq!(processed_values, vec![1, 2, 3]);

    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("worker should stop promptly")
        .expect("worker wait");
    assert_eq!(summary.claimed_count, 3);
    assert_eq!(summary.succeeded_count, 3);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    let counts = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.worker.loop_success"),
        )
        .await
        .expect("fetch loop status counts");
    assert_eq!(counts.completed_count, 3);
    assert_eq!(counts.pending_count, 0);
    assert_eq!(counts.running_count, 0);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_does_not_claim_past_configured_capacity() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let first_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.capacity_gate",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue first capacity-gate job");
    let second_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.capacity_gate",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue second capacity-gate job");

    let release_first_handler = Arc::new(tokio::sync::Notify::new());
    let release_first_handler_for_task = Arc::clone(&release_first_handler);
    let (first_started_tx, mut first_started_rx) = tokio::sync::mpsc::unbounded_channel();
    let (second_started_tx, mut second_started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.capacity_gate",
            move |_context, payload: TestPayload| {
                let release_first_handler = Arc::clone(&release_first_handler_for_task);
                let first_started_tx = first_started_tx.clone();
                let second_started_tx = second_started_tx.clone();
                async move {
                    match payload.value {
                        1 => {
                            first_started_tx
                                .send(())
                                .expect("record first capacity-gate start");
                            release_first_handler.notified().await;
                        }
                        2 => {
                            second_started_tx
                                .send(())
                                .expect("record second capacity-gate start");
                        }
                        other => panic!("unexpected capacity-gate payload {other}"),
                    }
                    Ok(())
                }
            },
        )
        .expect("register capacity-gate handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-capacity-gate",
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                startup_jitter_max_delay: Some(Duration::ZERO),
                concurrency: 1,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start capacity-gate worker");

    tokio::time::timeout(Duration::from_secs(2), first_started_rx.recv())
        .await
        .expect("first capacity-gate job should start")
        .expect("first started channel should stay open");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        second_started_rx.try_recv().is_err(),
        "second job started while the only worker slot was still occupied"
    );
    let second_while_first_is_running = queue
        .fetch_job_by_id(&test_database.paranoid_pool, second_job.job_id)
        .await
        .expect("fetch second capacity-gate job while first is running");
    assert_eq!(second_while_first_is_running.status, JobStatus::Pending);
    assert!(second_while_first_is_running.worker_owner_id.is_none());

    release_first_handler.notify_waiters();
    tokio::time::timeout(Duration::from_secs(2), second_started_rx.recv())
        .await
        .expect("second capacity-gate job should start after first releases capacity")
        .expect("second started channel should stay open");

    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("capacity-gate worker should stop")
        .expect("capacity-gate worker wait");
    assert_eq!(summary.claimed_count, 2);
    assert_eq!(summary.succeeded_count, 2);

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, first_job.job_id)
            .await
            .expect("fetch first capacity-gate status"),
        JobStatus::Completed
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, second_job.job_id)
            .await
            .expect("fetch second capacity-gate status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_accepts_tiny_poll_interval_without_panicking() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.tiny_poll",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue tiny-poll job");

    let (processed_tx, mut processed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.tiny_poll",
            move |_context, payload: TestPayload| {
                let processed_tx = processed_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    processed_tx.send(()).expect("record tiny-poll job");
                    Ok(())
                }
            },
        )
        .expect("register tiny-poll handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-tiny-poll",
            WorkerConfig {
                poll_interval: Duration::from_nanos(1),
                startup_jitter_max_delay: Some(Duration::ZERO),
                concurrency: 1,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start tiny-poll worker");

    tokio::time::timeout(Duration::from_secs(2), processed_rx.recv())
        .await
        .expect("tiny-poll worker should process job")
        .expect("processed channel should stay open");
    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("tiny-poll worker should stop")
        .expect("tiny-poll worker wait");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 1);

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, enqueued.job_id)
            .await
            .expect("fetch tiny-poll status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_backs_off_after_claim_error_and_recovers_after_schema_repair() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_claim_recovery",
            &TestPayload { value: 7 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue claim-recovery job");
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.pause_table_name,
    )
    .await;

    let (processed_tx, mut processed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_claim_recovery",
            move |_context, payload: TestPayload| {
                let processed_tx = processed_tx.clone();
                async move {
                    processed_tx
                        .send(payload.value)
                        .expect("record claim-recovery processing");
                    Ok(())
                }
            },
        )
        .expect("register claim-recovery handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-claim-recovery",
            WorkerConfig {
                poll_interval: Duration::from_millis(10),
                concurrency: 1,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start claim-recovery worker");

    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        processed_rx.try_recv().is_err(),
        "worker processed a job while claim query schema was broken"
    );
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("repair queue schema");

    let processed_value = tokio::time::timeout(Duration::from_secs(4), processed_rx.recv())
        .await
        .expect("worker should recover after claim schema repair")
        .expect("processed channel should stay open");
    assert_eq!(processed_value, 7);

    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("claim-recovery worker should stop promptly")
        .expect("claim-recovery worker wait");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, enqueued.job_id)
            .await
            .expect("fetch claim-recovery job status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_stop_during_claim_backoff_does_not_claim_after_repair() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_claim_backoff_stop",
            &TestPayload { value: 8 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue claim-backoff-stop job");
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.pause_table_name,
    )
    .await;

    let (processed_tx, mut processed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_claim_backoff_stop",
            move |_context, payload: TestPayload| {
                let processed_tx = processed_tx.clone();
                async move {
                    processed_tx
                        .send(payload.value)
                        .expect("record claim-backoff-stop processing");
                    Ok(())
                }
            },
        )
        .expect("register claim-backoff-stop handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-claim-backoff-stop",
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                startup_jitter_max_delay: Some(Duration::ZERO),
                concurrency: 1,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start claim-backoff-stop worker");

    tokio::time::sleep(Duration::from_millis(250)).await;
    worker_handle.request_stop();
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("repair queue schema while worker is stopping");

    let summary = tokio::time::timeout(Duration::from_millis(750), worker_handle.wait())
        .await
        .expect("worker should stop without waiting out the full claim backoff")
        .expect("claim-backoff-stop worker wait");
    assert_eq!(summary.claimed_count, 0);
    assert!(processed_rx.try_recv().is_err());

    let job_after_stop = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch claim-backoff-stop job");
    assert_eq!(job_after_stop.status, JobStatus::Pending);
    assert!(job_after_stop.worker_owner_id.is_none());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
