use super::*;

#[tokio::test]
async fn queue_cleanup_until_empty_operations_emit_one_cleanup_operation_per_batch() {
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

    for (value, worker_id) in [
        (40, "worker.operation_count.completed_a"),
        (41, "worker.operation_count.completed_b"),
        (42, "worker.operation_count.completed_c"),
    ] {
        let worker_owner_id = worker_owner_id_for_operation_count_test(worker_id);
        let job_id = claim_test_job(
            &queue,
            &pool,
            "task.operation_count.cleanup_completed",
            value,
            worker_id,
        )
        .await;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_started(&pool, job_id, &worker_owner_id)
            .await
            .expect("mark setup job started");
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed(&pool, job_id, &worker_owner_id)
            .await
            .expect("mark setup job completed");
    }
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        queue
            .cleanup_available_completed_jobs_older_than_until_empty(
                &observed_pool,
                Duration::from_micros(1),
                2,
                Duration::ZERO,
            )
            .await
            .expect("cleanup completed jobs until empty"),
        3
    );
    expect_operation_records(
        &observer,
        &repeated_pool_transaction_records(
            2,
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
                statement: Some(
                    queue
                        .sql_catalog()
                        .cleanup_jobs_older_than_once_query()
                        .to_owned(),
                ),
            },
        ),
    );

    for (value, worker_id) in [
        (43, "worker.operation_count.failed_a"),
        (44, "worker.operation_count.failed_b"),
        (45, "worker.operation_count.failed_c"),
    ] {
        fail_test_job(
            &queue,
            &pool,
            "task.operation_count.cleanup_failed",
            value,
            worker_id,
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        queue
            .cleanup_available_failed_jobs_older_than_until_empty(
                &observed_pool,
                Duration::from_micros(1),
                2,
                Duration::ZERO,
            )
            .await
            .expect("cleanup failed jobs until empty"),
        3
    );
    expect_operation_records(
        &observer,
        &repeated_pool_transaction_records(
            2,
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
                statement: Some(
                    queue
                        .sql_catalog()
                        .cleanup_jobs_older_than_once_query()
                        .to_owned(),
                ),
            },
        ),
    );

    for (value, worker_id) in [
        (46, "worker.operation_count.dead_letter_a"),
        (47, "worker.operation_count.dead_letter_b"),
        (48, "worker.operation_count.dead_letter_c"),
    ] {
        let failed_job_id = fail_test_job(
            &queue,
            &pool,
            "task.operation_count.cleanup_dead_letter",
            value,
            worker_id,
        )
        .await;
        queue
            .move_failed_job_to_dead_letter(&pool, failed_job_id, DeadLetterReason::OperatorAction)
            .await
            .expect("move setup failed job to dead letter");
    }
    tokio::time::sleep(Duration::from_millis(1)).await;

    assert_eq!(
        queue
            .cleanup_available_dead_letter_jobs_older_than_until_empty(
                &observed_pool,
                Duration::from_micros(1),
                2,
                Duration::ZERO,
            )
            .await
            .expect("cleanup dead-letter jobs until empty"),
        3
    );
    expect_operation_records(
        &observer,
        &repeated_pool_transaction_records(
            2,
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: QUEUE_OPERATION_CLEANUP_DEAD_LETTER_ONCE,
                statement: Some(
                    queue
                        .sql_catalog()
                        .cleanup_available_dead_letter_jobs_older_than_once_query()
                        .to_owned(),
                ),
            },
        ),
    );

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
