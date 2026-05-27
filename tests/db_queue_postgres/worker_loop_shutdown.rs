use super::*;

#[tokio::test]
async fn queue_worker_run_loop_stop_signal_retries_in_flight_job_and_clears_worker_ownership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_shutdown",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue shutdown job");

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_shutdown",
            move |context, payload: TestPayload| {
                let started_tx = started_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    assert!(!context.worker_shutdown_has_been_requested());
                    started_tx.send(()).expect("record handler start");
                    context.wait_for_worker_shutdown_requested().await;
                    Err(TaskError::retryable("handler observed shutdown"))
                }
            },
        )
        .expect("register shutdown handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-shutdown",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                concurrency: 1,
                shutdown_grace_period: Duration::from_secs(2),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start shutdown worker");

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("handler should start")
        .expect("started channel should stay open");
    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("worker should stop after shutdown signal")
        .expect("worker wait");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 0);
    assert_eq!(summary.retried_count, 1);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    let job_after_shutdown = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch shutdown job");
    assert_eq!(job_after_shutdown.status, JobStatus::Pending);
    assert_eq!(job_after_shutdown.retry_count, 1);
    assert!(job_after_shutdown.worker_owner_id.is_none());
    assert!(
        job_after_shutdown
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_shutdown
            .last_error
            .as_deref()
            .expect("shutdown retry should store an error")
            .contains("shutdown")
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_shutdown_grace_returns_noncooperative_job_without_retrying() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_shutdown_noncooperative",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue noncooperative shutdown job");

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_shutdown_noncooperative",
            move |_context, payload: TestPayload| {
                let started_tx = started_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    started_tx
                        .send(())
                        .expect("record noncooperative handler start");
                    std::future::pending::<Result<(), TaskError>>().await
                }
            },
        )
        .expect("register noncooperative shutdown handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-shutdown-noncooperative",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                concurrency: 1,
                shutdown_grace_period: Duration::from_millis(25),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start noncooperative shutdown worker");

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("noncooperative handler should start")
        .expect("started channel should stay open");
    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("worker should stop after shutdown grace")
        .expect("worker wait");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 0);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    let job_after_shutdown = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch noncooperative shutdown job");
    assert_eq!(job_after_shutdown.status, JobStatus::Pending);
    assert_eq!(job_after_shutdown.retry_count, 0);
    assert!(job_after_shutdown.last_error.is_none());
    assert!(job_after_shutdown.worker_owner_id.is_none());
    assert!(
        job_after_shutdown
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_shutdown
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_shutdown
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_shutdown_grace_waits_for_cooperative_handler_before_finishing() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_shutdown_graceful_completion",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue graceful shutdown completion job");

    let release_handler = Arc::new(tokio::sync::Notify::new());
    let release_handler_for_task = Arc::clone(&release_handler);
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let (shutdown_observed_tx, mut shutdown_observed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_shutdown_graceful_completion",
            move |context, payload: TestPayload| {
                let release_handler = Arc::clone(&release_handler_for_task);
                let started_tx = started_tx.clone();
                let shutdown_observed_tx = shutdown_observed_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    started_tx
                        .send(())
                        .expect("record graceful shutdown handler start");
                    context.wait_for_worker_shutdown_requested().await;
                    shutdown_observed_tx
                        .send(())
                        .expect("record handler shutdown observation");
                    release_handler.notified().await;
                    Ok(())
                }
            },
        )
        .expect("register graceful shutdown completion handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-shutdown-graceful-completion",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                concurrency: 1,
                shutdown_grace_period: Duration::from_secs(2),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start graceful shutdown completion worker");

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("graceful shutdown handler should start")
        .expect("started channel should stay open");
    worker_handle.request_stop();
    tokio::time::timeout(Duration::from_secs(2), shutdown_observed_rx.recv())
        .await
        .expect("handler should observe worker shutdown")
        .expect("shutdown observation channel should stay open");

    let release_handler_after_wait_check = Arc::clone(&release_handler);
    let mut wait_task = tokio::spawn(async move { worker_handle.wait().await });
    tokio::time::timeout(Duration::from_millis(50), &mut wait_task)
        .await
        .expect_err("worker should wait inside shutdown grace for cooperative handler");
    release_handler_after_wait_check.notify_waiters();
    let summary = tokio::time::timeout(Duration::from_secs(2), wait_task)
        .await
        .expect("worker should finish after cooperative handler release")
        .expect("worker wait task should not panic")
        .expect("worker wait");
    assert_eq!(summary.claimed_count, 1);
    assert_eq!(summary.succeeded_count, 1);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 0);

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, enqueued.job_id)
            .await
            .expect("fetch graceful shutdown completion status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_run_loop_heartbeat_ownership_loss_cancels_handler_and_frees_capacity() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let ownership_lost_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_ownership_lost",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue ownership-lost job");
    let success_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.loop_after_ownership_loss",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue success job");

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let (processed_tx, mut processed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.worker.loop_ownership_lost",
            move |_context, payload: TestPayload| {
                let started_tx = started_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    started_tx.send(()).expect("record ownership-lost start");
                    std::future::pending::<Result<(), TaskError>>().await
                }
            },
        )
        .expect("register ownership-lost handler");
    registry
        .register_json_task_handler(
            "task.worker.loop_after_ownership_loss",
            move |_context, payload: TestPayload| {
                let processed_tx = processed_tx.clone();
                async move {
                    assert_eq!(payload.value, 2);
                    processed_tx.send(()).expect("record success after loss");
                    Ok(())
                }
            },
        )
        .expect("register success-after-loss handler");

    let worker_handle = queue
        .start_worker(
            test_database.paranoid_pool.clone(),
            registry,
            "worker-loop-ownership-loss",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                concurrency: 1,
                stale_threshold: Duration::from_secs(1),
                execution_heartbeat_interval: Duration::from_millis(10),
                shutdown_grace_period: Duration::from_secs(2),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .expect("start ownership-loss worker");

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("ownership-lost handler should start")
        .expect("started channel should stay open");
    queue
        .pause_task(
            &test_database.paranoid_pool,
            "task.worker.loop_ownership_lost",
        )
        .await
        .expect("pause ownership-lost task before requeue");
    force_requeue_running_job_by_id_retrying_concurrent_row_locks(
        &queue,
        &test_database.paranoid_pool,
        ownership_lost_job.job_id,
        Duration::from_secs(2),
    )
    .await;

    tokio::time::timeout(Duration::from_secs(2), processed_rx.recv())
        .await
        .expect("worker should free capacity after heartbeat ownership loss")
        .expect("processed channel should stay open");

    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("worker should stop after ownership-loss path")
        .expect("worker wait");
    assert_eq!(summary.claimed_count, 2);
    assert_eq!(summary.succeeded_count, 1);
    assert_eq!(summary.retried_count, 0);
    assert_eq!(summary.failed_count, 0);
    assert_eq!(summary.dead_lettered_count, 0);
    assert_eq!(summary.lost_ownership_count, 1);

    let ownership_lost_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, ownership_lost_job.job_id)
        .await
        .expect("fetch ownership-lost job");
    assert_eq!(ownership_lost_after.status, JobStatus::Pending);
    assert!(ownership_lost_after.worker_owner_id.is_none());
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, success_job.job_id)
            .await
            .expect("fetch success status"),
        JobStatus::Completed
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

async fn force_requeue_running_job_by_id_retrying_concurrent_row_locks(
    queue: &Store,
    pool: &Pool,
    job_id: paranoid::queue::JobId,
    timeout: Duration,
) {
    let started_at = Instant::now();
    loop {
        match queue.force_requeue_running_job_by_id(pool, job_id).await {
            Ok(()) => return,
            Err(Error::JobLockedByConcurrentTransaction) if started_at.elapsed() < timeout => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("force requeue running job failed: {error:?}"),
        }
    }
}
