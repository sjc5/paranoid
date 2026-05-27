use super::*;

#[tokio::test]
async fn queue_process_available_jobs_once_emits_expected_worker_database_operation_records() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres Queue operation-count test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let queue = Store::new(config.clone()).expect("queue");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_queue_test_tables(&sqlx_pool, &config).await;
    queue
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate Queue schema");
    observer.clear();

    queue
        .enqueue_json(
            &pool,
            "task.operation_count.worker_once",
            &TestPayload { value: 60 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue worker test job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler::<TestPayload, _, _>(
            "task.operation_count.worker_once",
            |context, payload| async move {
                assert_eq!(payload.value, 60);
                context
                    .touch_execution_heartbeat()
                    .await
                    .map_err(|error| TaskError::retryable(format!("heartbeat failed: {error}")))?;
                Ok(())
            },
        )
        .expect("register worker test task");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &observed_pool,
            &registry,
            "worker.operation_count.worker_once",
            WorkerConfig {
                concurrency: 1,
                startup_jitter_max_delay: Some(Duration::ZERO),
                ..WorkerConfig::default()
            },
        )
        .await
        .expect("process one job");
    assert_eq!(
        summary,
        WorkerRunOnceSummary {
            claimed_count: 1,
            succeeded_count: 1,
            ..WorkerRunOnceSummary::default()
        }
    );

    let expected_records = [
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchAll,
            label: QUEUE_OPERATION_CLAIM_AVAILABLE_JOBS,
            statement: Some(queue.sql_catalog().claim_available_jobs_query().to_owned()),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: QUEUE_OPERATION_MARK_JOB_STARTED,
            statement: Some(queue.sql_catalog().mark_job_started_query().to_owned()),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: QUEUE_OPERATION_TOUCH_JOB_HEARTBEAT,
            statement: Some(
                queue
                    .sql_catalog()
                    .touch_execution_heartbeat_query()
                    .to_owned(),
            ),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: QUEUE_OPERATION_MARK_JOB_COMPLETED,
            statement: Some(queue.sql_catalog().mark_job_completed_query().to_owned()),
        }]),
    ]
    .concat();
    expect_operation_records(&observer, &expected_records);

    drop_queue_test_tables(&sqlx_pool, &config).await;
}

#[tokio::test]
async fn queue_long_running_worker_loop_emits_expected_worker_database_operation_records() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres Queue operation-count test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let queue = Store::new(config.clone()).expect("queue");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_queue_test_tables(&sqlx_pool, &config).await;
    queue
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate Queue schema");
    observer.clear();

    queue
        .enqueue_json(
            &pool,
            "task.operation_count.worker_loop",
            &TestPayload { value: 61 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue worker-loop test job");

    let handler_started = Arc::new(Notify::new());
    let handler_finish = Arc::new(Notify::new());
    let mut registry = TaskRegistry::new();
    {
        let handler_started = Arc::clone(&handler_started);
        let handler_finish = Arc::clone(&handler_finish);
        registry
            .register_json_task_handler::<TestPayload, _, _>(
                "task.operation_count.worker_loop",
                move |_context, payload| {
                    let handler_started = Arc::clone(&handler_started);
                    let handler_finish = Arc::clone(&handler_finish);
                    async move {
                        assert_eq!(payload.value, 61);
                        handler_started.notify_one();
                        handler_finish.notified().await;
                        Ok(())
                    }
                },
            )
            .expect("register worker-loop test task");
    }

    let worker_handle = queue
        .start_worker(
            observed_pool.clone(),
            registry,
            "worker.operation_count.worker_loop",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                startup_jitter_max_delay: Some(Duration::ZERO),
                concurrency: 1,
                stale_threshold: Duration::from_secs(60 * 60),
                execution_heartbeat_interval: Duration::from_secs(30 * 60),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                shutdown_grace_period: Duration::from_secs(5),
                database_operation_timeout: Duration::from_secs(5),
                ..WorkerConfig::default()
            },
        )
        .expect("start long-running worker");

    tokio::time::timeout(Duration::from_secs(5), handler_started.notified())
        .await
        .expect("worker handler should start");
    assert!(worker_handle.request_stop());
    handler_finish.notify_one();
    let summary = worker_handle
        .wait()
        .await
        .expect("worker should stop cleanly");
    assert_eq!(
        summary,
        WorkerRunLoopSummary {
            claimed_count: 1,
            succeeded_count: 1,
            ..WorkerRunLoopSummary::default()
        }
    );

    let expected_records = [
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchAll,
            label: QUEUE_OPERATION_CLAIM_AVAILABLE_JOBS,
            statement: Some(queue.sql_catalog().claim_available_jobs_query().to_owned()),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: QUEUE_OPERATION_MARK_JOB_STARTED,
            statement: Some(queue.sql_catalog().mark_job_started_query().to_owned()),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: QUEUE_OPERATION_MARK_JOB_COMPLETED,
            statement: Some(queue.sql_catalog().mark_job_completed_query().to_owned()),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_UNSTARTED_JOBS,
            statement: Some(
                queue
                    .sql_catalog()
                    .return_available_owned_unstarted_running_jobs_to_pending_query()
                    .to_owned(),
            ),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_STARTED_JOBS,
            statement: Some(
                queue
                    .sql_catalog()
                    .return_available_owned_started_running_jobs_to_pending_query()
                    .to_owned(),
            ),
        }]),
        worker_database_operation_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: QUEUE_OPERATION_COUNT_WORKER_OWNED_RUNNING_JOBS,
            statement: Some(worker_owned_running_jobs_count_query(&queue)),
        }]),
    ]
    .concat();
    expect_operation_records(&observer, &expected_records);

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
