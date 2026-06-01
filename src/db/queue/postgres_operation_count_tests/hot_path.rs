use super::*;

#[tokio::test]
async fn queue_common_hot_path_operations_emit_exact_database_operation_records() {
    let database_url = test_database_url();

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

    let enqueued = queue
        .enqueue_json(
            &observed_pool,
            "task.operation_count",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_ENQUEUE,
        queue.sql_catalog().single_enqueue_query(),
    );

    let inserted_dedupe = queue
        .enqueue_json(
            &observed_pool,
            "task.operation_count",
            &TestPayload { value: 2 },
            EnqueueOptions {
                dedupe_key: Some("same-work".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("dedupe enqueue insert");
    assert!(!inserted_dedupe.deduplicated);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_DEDUPE_ENQUEUE,
        queue.sql_catalog().dedupe_enqueue_query(),
    );

    let reused_dedupe = queue
        .enqueue_json(
            &observed_pool,
            "task.operation_count",
            &TestPayload { value: 3 },
            EnqueueOptions {
                dedupe_key: Some("same-work".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("dedupe enqueue reuse");
    assert_eq!(reused_dedupe.job_id, inserted_dedupe.job_id);
    assert!(reused_dedupe.deduplicated);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_DEDUPE_ENQUEUE,
        queue.sql_catalog().dedupe_enqueue_query(),
    );

    queue
        .enqueue_json_batch(
            &observed_pool,
            "task.operation_count",
            &[TestPayload { value: 4 }, TestPayload { value: 5 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("batch enqueue");
    let batch_statement = queue.sql_catalog().batch_enqueue_query(2);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_BATCH_ENQUEUE,
        batch_statement.as_ref(),
    );

    let loaded = queue
        .fetch_job_by_id(&observed_pool, enqueued.job_id)
        .await
        .expect("fetch job by id");
    assert_eq!(loaded.id, enqueued.job_id);
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_FETCH_JOB_BY_ID,
        queue.sql_catalog().select_job_by_id_query(),
    );

    let status_counts = queue
        .fetch_status_counts(&observed_pool, Some("task.operation_count"))
        .await
        .expect("fetch status counts");
    assert_eq!(status_counts.pending_count, 4);
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_STATUS_COUNTS,
        queue.sql_catalog().fetch_status_counts_query(),
    );

    assert_eq!(
        queue
            .fetch_pending_job_count(&observed_pool, Some("task.operation_count"))
            .await
            .expect("fetch pending count"),
        4
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_JOB_COUNT_BY_STATUS,
        queue.sql_catalog().fetch_job_count_by_status_query(),
    );

    queue
        .pause_queue(&observed_pool)
        .await
        .expect("pause queue");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_UPSERT_PAUSE_KEY,
        queue.sql_catalog().upsert_pause_key_query(),
    );

    assert!(
        queue
            .fetch_queue_is_paused(&observed_pool)
            .await
            .expect("fetch queue paused")
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_PAUSE_KEY_EXISTS,
        queue.sql_catalog().pause_key_exists_query(),
    );

    let worker_pressure = queue
        .fetch_worker_pressure(&observed_pool, &TaskRegistry::new())
        .await
        .expect("fetch worker pressure");
    assert!(worker_pressure.queue_paused);
    assert_eq!(
        observer.records(),
        read_transaction_records([
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOne,
                label: QUEUE_OPERATION_FETCH_WORKER_PRESSURE_COUNTS,
                statement: Some(
                    queue
                        .sql_catalog()
                        .fetch_worker_pressure_counts_query()
                        .to_owned()
                ),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchAll,
                label: QUEUE_OPERATION_FETCH_PAUSE_ENTRIES,
                statement: Some(queue.sql_catalog().fetch_pause_entries_query().to_owned()),
            },
        ])
    );
    observer.clear();

    queue
        .resume_queue(&observed_pool)
        .await
        .expect("resume queue");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_DELETE_PAUSE_KEY,
        queue.sql_catalog().delete_pause_key_query(),
    );

    let listed = queue
        .list_jobs(&observed_pool, ListJobsOptions::default())
        .await
        .expect("list jobs");
    assert_eq!(listed.jobs.len(), 4);
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_LIST_JOBS,
        queue.sql_catalog().list_jobs_query(),
    );

    let worker_owner_id = WorkerOwnerId::new_unique_for_worker_name("worker.operation_count")
        .expect("worker owner id");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &observed_pool,
            &["task.operation_count".to_owned()],
            1,
            &worker_owner_id,
        )
        .await
        .expect("claim available jobs");
    assert_eq!(claimed.len(), 1);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_CLAIM_AVAILABLE_JOBS,
        queue.sql_catalog().claim_available_jobs_query(),
    );

    let claimed_job_id = claimed[0].id;
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(&observed_pool, claimed_job_id, &worker_owner_id)
        .await
        .expect("mark claimed job started");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MARK_JOB_STARTED,
        queue.sql_catalog().mark_job_started_query(),
    );

    queue
        .begin_manual_worker_lifecycle()
        .touch_owned_running_job_execution_heartbeat(
            &observed_pool,
            claimed_job_id,
            &worker_owner_id,
        )
        .await
        .expect("touch job heartbeat");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_TOUCH_JOB_HEARTBEAT,
        queue.sql_catalog().touch_execution_heartbeat_query(),
    );

    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(&observed_pool, claimed_job_id, &worker_owner_id)
        .await
        .expect("mark claimed job completed");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MARK_JOB_COMPLETED,
        queue.sql_catalog().mark_job_completed_query(),
    );

    queue
        .cleanup_available_completed_jobs_older_than_once(
            &observed_pool,
            Duration::from_micros(1),
            10,
        )
        .await
        .expect("cleanup completed jobs once");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
        queue.sql_catalog().cleanup_jobs_older_than_once_query(),
    );

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
