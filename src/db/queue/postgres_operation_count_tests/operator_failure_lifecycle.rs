use super::*;

#[tokio::test]
async fn queue_operator_and_failure_lifecycle_operations_emit_exact_database_operation_records() {
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

    let cancel_job_id = enqueue_test_job(&queue, &pool, "task.operation_count.cancel", 10).await;
    queue
        .cancel_pending_job(&observed_pool, cancel_job_id)
        .await
        .expect("cancel pending job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_CANCEL_PENDING_JOB,
        queue.sql_catalog().cancel_pending_job_query(),
    );

    let failed_for_count_and_retry = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.retry_one",
        11,
        "worker.operation_count.retry_one",
    )
    .await;
    assert_eq!(
        queue
            .fetch_failed_job_count(&observed_pool, Some("task.operation_count.retry_one"))
            .await
            .expect("fetch failed job count"),
        1
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_JOB_COUNT_BY_STATUS,
        queue.sql_catalog().fetch_job_count_by_status_query(),
    );

    queue
        .retry_failed_job(&observed_pool, failed_for_count_and_retry, None)
        .await
        .expect("retry failed job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_RETRY_FAILED_JOB,
        queue.sql_catalog().retry_failed_job_by_id_query(),
    );

    let _failed_for_bulk_retry = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.retry_many",
        12,
        "worker.operation_count.retry_many",
    )
    .await;
    assert_eq!(
        queue
            .retry_available_failed_jobs(
                &observed_pool,
                Some("task.operation_count.retry_many"),
                10,
                None,
            )
            .await
            .expect("retry available failed jobs"),
        1
    );
    expect_operation_records(
        &observer,
        &transaction_records([
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                statement: Some(
                    "SAVEPOINT __paranoid_queue_retry_available_failed_jobs".to_owned(),
                ),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                statement: Some(
                    queue
                        .sql_catalog()
                        .retry_available_failed_jobs_query()
                        .to_owned(),
                ),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                statement: Some(
                    "RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs".to_owned(),
                ),
            },
        ]),
    );

    let running_for_force_requeue = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.force_requeue",
        13,
        "worker.operation_count.force_requeue",
    )
    .await;
    queue
        .force_requeue_running_job_by_id(&observed_pool, running_for_force_requeue)
        .await
        .expect("force requeue running job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FORCE_REQUEUE_RUNNING_JOB,
        queue.sql_catalog().force_requeue_running_job_by_id_query(),
    );

    let running_for_scheduled_retry = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.schedule_retry",
        14,
        "worker.operation_count.schedule_retry",
    )
    .await;
    let scheduled_retry_owner =
        worker_owner_id_for_operation_count_test("worker.operation_count.schedule_retry");
    queue
        .begin_manual_worker_lifecycle()
        .schedule_owned_running_job_retry(
            &observed_pool,
            running_for_scheduled_retry,
            &scheduled_retry_owner,
            1,
            Duration::from_millis(1),
            "scheduled retry",
        )
        .await
        .expect("schedule owned running job retry");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_SCHEDULE_OWNED_RUNNING_JOB_RETRY,
        queue.sql_catalog().schedule_owned_running_job_retry_query(),
    );

    let running_unstarted_for_return = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.return_unstarted",
        15,
        "worker.operation_count.return_unstarted",
    )
    .await;
    let return_unstarted_owner =
        worker_owner_id_for_operation_count_test("worker.operation_count.return_unstarted");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_unstarted_running_job_to_pending(
            &observed_pool,
            running_unstarted_for_return,
            &return_unstarted_owner,
        )
        .await
        .expect("return unstarted running job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_RETURN_OWNED_UNSTARTED_JOB,
        queue
            .sql_catalog()
            .return_owned_unstarted_running_job_to_pending_query(),
    );

    let running_started_for_return = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.return_started",
        16,
        "worker.operation_count.return_started",
    )
    .await;
    let return_started_owner =
        worker_owner_id_for_operation_count_test("worker.operation_count.return_started");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(&pool, running_started_for_return, &return_started_owner)
        .await
        .expect("mark setup job started");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_started_running_job_to_pending(
            &observed_pool,
            running_started_for_return,
            &return_started_owner,
        )
        .await
        .expect("return started running job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_RETURN_OWNED_STARTED_JOB,
        queue
            .sql_catalog()
            .return_owned_started_running_job_to_pending_query(),
    );

    let running_for_owned_dead_letter = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.owned_dead",
        17,
        "worker.operation_count.owned_dead",
    )
    .await;
    let owned_dead_letter_owner =
        worker_owner_id_for_operation_count_test("worker.operation_count.owned_dead");
    let owned_dead_letter_id = queue
        .begin_manual_worker_lifecycle()
        .move_owned_running_job_to_dead_letter(
            &observed_pool,
            running_for_owned_dead_letter,
            &owned_dead_letter_owner,
            "owned dead letter",
            true,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move owned running job to dead letter");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MOVE_OWNED_RUNNING_JOB_TO_DEAD_LETTER,
        queue
            .sql_catalog()
            .move_owned_running_job_to_dead_letter_query(),
    );

    let failed_for_dead_letter = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.dead_one",
        18,
        "worker.operation_count.dead_one",
    )
    .await;
    let dead_letter_id = queue
        .move_failed_job_to_dead_letter(
            &observed_pool,
            failed_for_dead_letter,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move failed job to dead letter");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MOVE_FAILED_JOB_TO_DEAD_LETTER,
        queue.sql_catalog().move_failed_job_to_dead_letter_query(),
    );

    assert!(
        !queue
            .list_dead_letter_jobs(&observed_pool, ListDeadLetterJobsOptions::default())
            .await
            .expect("list dead-letter jobs")
            .jobs
            .is_empty()
    );
    expect_single_pool_read_transaction_record(
        &observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_LIST_DEAD_LETTER_JOBS,
        queue.sql_catalog().list_dead_letter_jobs_query(),
    );

    let requeued_dead_letter_id = queue
        .requeue_dead_letter_job(&observed_pool, dead_letter_id, None)
        .await
        .expect("requeue dead-letter job");
    assert_ne!(requeued_dead_letter_id, dead_letter_id);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_REQUEUE_DEAD_LETTER_JOB,
        queue.sql_catalog().requeue_dead_letter_job_query(),
    );

    queue
        .delete_dead_letter_job(&observed_pool, owned_dead_letter_id)
        .await
        .expect("delete dead-letter job");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_DELETE_DEAD_LETTER_JOB,
        queue.sql_catalog().delete_dead_letter_job_query(),
    );

    let failed_for_dead_letter_batch_a = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.dead_batch",
        19,
        "worker.operation_count.dead_batch_a",
    )
    .await;
    let failed_for_dead_letter_batch_b = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.dead_batch",
        20,
        "worker.operation_count.dead_batch_b",
    )
    .await;
    let batch_result = queue
        .move_failed_jobs_to_dead_letter_batch(
            &observed_pool,
            &[
                failed_for_dead_letter_batch_a,
                failed_for_dead_letter_batch_b,
            ],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move failed jobs to dead letter batch");
    assert_eq!(batch_result.moved_jobs.len(), 2);
    let batch_statement = queue
        .sql_catalog()
        .move_failed_jobs_to_dead_letter_batch_query(2);
    expect_operation_records(
        &observer,
        &transaction_records([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchAll,
            label: QUEUE_OPERATION_MOVE_FAILED_JOBS_TO_DEAD_LETTER_BATCH,
            statement: Some(batch_statement.as_ref().to_owned()),
        }]),
    );

    queue
        .cleanup_available_failed_jobs_older_than_once(&observed_pool, Duration::from_micros(1), 10)
        .await
        .expect("cleanup failed jobs once");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
        queue.sql_catalog().cleanup_jobs_older_than_once_query(),
    );

    queue
        .cleanup_available_dead_letter_jobs_older_than_once(
            &observed_pool,
            Duration::from_micros(1),
            10,
        )
        .await
        .expect("cleanup dead-letter jobs once");
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_CLEANUP_DEAD_LETTER_ONCE,
        queue
            .sql_catalog()
            .cleanup_available_dead_letter_jobs_older_than_once_query(),
    );

    let _running_for_reclaim = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.reclaim",
        21,
        "worker.operation_count.reclaim",
    )
    .await;
    queue
        .reclaim_available_stale_running_jobs_once(
            &observed_pool,
            Duration::from_micros(1),
            10,
            false,
        )
        .await
        .expect("reclaim stale running jobs");
    expect_operation_records(
        &observer,
        &transaction_records([
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchAll,
                label: QUEUE_OPERATION_RECLAIM_NEVER_STARTED_RUNNING_JOBS,
                statement: Some(
                    queue
                        .sql_catalog()
                        .reclaim_never_started_running_jobs_query()
                        .to_owned(),
                ),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchAll,
                label: QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_FAILED,
                statement: Some(
                    queue
                        .sql_catalog()
                        .reclaim_expired_running_jobs_to_failed_query()
                        .to_owned(),
                ),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchAll,
                label: QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_PENDING,
                statement: Some(
                    queue
                        .sql_catalog()
                        .reclaim_expired_running_jobs_to_pending_for_retry_query()
                        .to_owned(),
                ),
            },
        ]),
    );

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
