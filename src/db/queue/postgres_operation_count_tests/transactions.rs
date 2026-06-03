use super::*;

#[tokio::test]
async fn queue_in_current_transaction_operations_emit_only_inner_database_operation_records() {
    let database_url = standard_test_database_url();

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

    let mut tx = observed_pool
        .begin_transaction()
        .await
        .expect("begin caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::BeginTransaction,
            label: "db.begin_transaction",
            statement: None,
        }]
    );
    observer.clear();

    let enqueued = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.operation_count.tx",
            &TestPayload { value: 50 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue in caller transaction");
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_ENQUEUE,
        queue.sql_catalog().single_enqueue_query(),
    );

    assert_eq!(
        queue
            .fetch_job_status_in_current_transaction(&mut tx, enqueued.job_id)
            .await
            .expect("fetch job status in caller transaction"),
        JobStatus::Pending
    );
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_FETCH_JOB_BY_ID,
        queue.sql_catalog().select_job_by_id_query(),
    );

    queue
        .pause_task_in_current_transaction(&mut tx, "task.operation_count.tx")
        .await
        .expect("pause task in caller transaction");
    expect_single_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_UPSERT_PAUSE_KEY,
        queue.sql_catalog().upsert_pause_key_query(),
    );

    assert!(
        queue
            .fetch_task_is_paused_in_current_transaction(&mut tx, "task.operation_count.tx")
            .await
            .expect("fetch task pause status in caller transaction")
    );
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_PAUSE_KEY_EXISTS,
        queue.sql_catalog().pause_key_exists_query(),
    );

    queue
        .resume_task_in_current_transaction(&mut tx, "task.operation_count.tx")
        .await
        .expect("resume task in caller transaction");
    expect_single_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_DELETE_PAUSE_KEY,
        queue.sql_catalog().delete_pause_key_query(),
    );

    let transaction_worker_owner_id =
        worker_owner_id_for_operation_count_test("worker.operation_count.tx");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &["task.operation_count.tx".to_owned()],
            1,
            &transaction_worker_owner_id,
        )
        .await
        .expect("claim in caller transaction");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, enqueued.job_id);
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_CLAIM_AVAILABLE_JOBS,
        queue.sql_catalog().claim_available_jobs_query(),
    );

    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started_in_current_transaction(
            &mut tx,
            enqueued.job_id,
            &transaction_worker_owner_id,
        )
        .await
        .expect("mark started in caller transaction");
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MARK_JOB_STARTED,
        queue.sql_catalog().mark_job_started_query(),
    );

    tx.commit().await.expect("commit caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::CommitTransaction,
            label: "db.tx.commit",
            statement: None,
        }]
    );
    observer.clear();

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
