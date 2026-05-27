use super::*;

#[tokio::test]
async fn queue_auxiliary_public_operations_emit_exact_database_operation_records() {
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

    let status_job_id = enqueue_test_job(&queue, &pool, "task.operation_count.status", 30).await;
    let status = queue
        .fetch_job_status(&observed_pool, status_job_id)
        .await
        .expect("fetch job status");
    assert_eq!(status, JobStatus::Pending);
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_FETCH_JOB_BY_ID,
        queue.sql_catalog().select_job_by_id_query(),
    );

    queue
        .pause_task(&observed_pool, "task.operation_count.status")
        .await
        .expect("pause task");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_UPSERT_PAUSE_KEY,
        queue.sql_catalog().upsert_pause_key_query(),
    );

    assert!(
        queue
            .fetch_task_is_paused(&observed_pool, "task.operation_count.status")
            .await
            .expect("fetch task paused")
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_PAUSE_KEY_EXISTS,
        queue.sql_catalog().pause_key_exists_query(),
    );

    assert_eq!(
        queue
            .fetch_paused_task_names(&observed_pool)
            .await
            .expect("fetch paused task names"),
        vec!["task.operation_count.status".to_owned()]
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_FETCH_PAUSE_ENTRIES,
        queue.sql_catalog().fetch_pause_entries_query(),
    );

    queue
        .resume_task(&observed_pool, "task.operation_count.status")
        .await
        .expect("resume task");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_DELETE_PAUSE_KEY,
        queue.sql_catalog().delete_pause_key_query(),
    );

    assert_eq!(
        queue
            .fetch_orphaned_task_names(&observed_pool, &TaskRegistry::new())
            .await
            .expect("fetch orphaned task names"),
        vec!["task.operation_count.status".to_owned()]
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_FETCH_ORPHANED_TASK_NAMES,
        queue
            .sql_catalog()
            .fetch_pending_or_running_task_names_query(),
    );

    let status_worker_owner_id =
        worker_owner_id_for_operation_count_test("worker.operation_count.status");
    let claimed_status_job = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &pool,
            &["task.operation_count.status".to_owned()],
            1,
            &status_worker_owner_id,
        )
        .await
        .expect("claim status job");
    assert_eq!(claimed_status_job.len(), 1);
    assert_eq!(claimed_status_job[0].id, status_job_id);
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &observed_pool,
            status_job_id,
            &status_worker_owner_id,
            "observed failure",
            true,
        )
        .await
        .expect("mark owned running job failed");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MARK_JOB_FAILED,
        queue.sql_catalog().mark_job_failed_query(),
    );

    let return_available_unstarted_owner = worker_owner_id_for_operation_count_test(
        "worker.operation_count.return_available_unstarted",
    );
    let running_unstarted_for_bulk_return = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.return_available_unstarted",
        31,
        "worker.operation_count.return_available_unstarted",
    )
    .await;
    assert_eq!(
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_unstarted_running_jobs_to_pending(
                &observed_pool,
                &return_available_unstarted_owner,
            )
            .await
            .expect("return available unstarted running jobs"),
        1
    );
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_UNSTARTED_JOBS,
        queue
            .sql_catalog()
            .return_available_owned_unstarted_running_jobs_to_pending_query(),
    );
    let returned_unstarted_status = queue
        .fetch_job_status(&pool, running_unstarted_for_bulk_return)
        .await
        .expect("fetch returned unstarted status");
    assert_eq!(returned_unstarted_status, JobStatus::Pending);

    let return_available_started_owner =
        worker_owner_id_for_operation_count_test("worker.operation_count.return_available_started");
    let running_started_for_bulk_return = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.return_available_started",
        32,
        "worker.operation_count.return_available_started",
    )
    .await;
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &pool,
            running_started_for_bulk_return,
            &return_available_started_owner,
        )
        .await
        .expect("mark setup job started");
    assert_eq!(
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_started_running_jobs_to_pending(
                &observed_pool,
                &return_available_started_owner,
            )
            .await
            .expect("return available started running jobs"),
        1
    );
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_STARTED_JOBS,
        queue
            .sql_catalog()
            .return_available_owned_started_running_jobs_to_pending_query(),
    );
    let returned_started_status = queue
        .fetch_job_status(&pool, running_started_for_bulk_return)
        .await
        .expect("fetch returned started status");
    assert_eq!(returned_started_status, JobStatus::Pending);

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
