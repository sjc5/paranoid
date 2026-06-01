use super::*;

#[tokio::test]
async fn queue_enqueue_future_abort_while_waiting_for_pool_connection_does_not_write_later() {
    let database_url = test_database_url();

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let queue = Store::new(config.clone()).expect("queue");

    drop_queue_test_tables(&sqlx_pool, &config).await;
    migrate_schema(&paranoid_pool, &config)
        .await
        .expect("migrate queue schema");

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (enqueue_started_tx, enqueue_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_queue = queue.clone();
    let enqueue_handle = tokio::spawn(async move {
        enqueue_started_tx.send(()).expect("send enqueue started");
        task_queue
            .enqueue_json(
                &task_pool,
                "task.cancel.pool",
                &TestPayload { value: 1 },
                EnqueueOptions::default(),
            )
            .await
            .expect("enqueue after waiting for pool connection");
    });

    enqueue_started_rx.await.expect("enqueue task started");
    abort_blocked_task(enqueue_handle, "enqueue").await;
    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        fetch_queue_table_row_count(&sqlx_pool, &config.table_name).await,
        0
    );

    drop_queue_test_tables(&sqlx_pool, &config).await;
}

#[tokio::test]
async fn queue_cancel_pending_job_returns_locked_without_waiting_for_row_lock() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    let pending = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.cancel.row_lock",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue pending job");

    let lock_tx = lock_queue_job_row(&test_database, pending.job_id).await;
    let locked_error = queue
        .cancel_pending_job(&test_database.paranoid_pool, pending.job_id)
        .await
        .expect_err("locked pending job should not block or delete");
    assert!(matches!(
        locked_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, pending.job_id)
            .await
            .expect("locked cancellation should leave pending job"),
        JobStatus::Pending
    );
    lock_tx.rollback().await.expect("rollback row lock");

    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, pending.job_id)
            .await
            .expect("aborted cancellation should leave pending job"),
        JobStatus::Pending
    );
    queue
        .cancel_pending_job(&test_database.paranoid_pool, pending.job_id)
        .await
        .expect("cancel should still work after aborted cancellation");
    let fetch_after_cancel = queue
        .fetch_job_by_id(&test_database.paranoid_pool, pending.job_id)
        .await
        .expect_err("cancelled job should be absent");
    assert!(matches!(fetch_after_cancel, Error::JobNotFound));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_by_id_operator_mutations_return_locked_without_mutating_locked_rows() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let failed_for_retry =
        fail_new_job(&queue, &test_database, "task.lock.retry", 1, "worker-lock").await;
    let retry_lock_tx = lock_queue_job_row(&test_database, failed_for_retry).await;
    let retry_error = queue
        .retry_failed_job(&test_database.paranoid_pool, failed_for_retry, None)
        .await
        .expect_err("locked failed job should not retry");
    assert!(matches!(
        retry_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, failed_for_retry)
            .await
            .expect("locked retry should leave failed job"),
        JobStatus::Failed
    );
    retry_lock_tx.rollback().await.expect("release retry lock");
    queue
        .retry_failed_job(&test_database.paranoid_pool, failed_for_retry, None)
        .await
        .expect("retry should work after lock release");

    let running_for_requeue = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.lock.requeue",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue running job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.lock.requeue"],
        1,
        "worker-lock",
    )
    .await
    .expect("claim running job");
    let requeue_lock_tx = lock_queue_job_row(&test_database, running_for_requeue.job_id).await;
    let requeue_error = queue
        .force_requeue_running_job_by_id(&test_database.paranoid_pool, running_for_requeue.job_id)
        .await
        .expect_err("locked running job should not force requeue");
    assert!(matches!(
        requeue_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, running_for_requeue.job_id)
            .await
            .expect("locked force requeue should leave running job"),
        JobStatus::Running
    );
    requeue_lock_tx
        .rollback()
        .await
        .expect("release requeue lock");
    queue
        .force_requeue_running_job_by_id(&test_database.paranoid_pool, running_for_requeue.job_id)
        .await
        .expect("force requeue should work after lock release");

    let failed_for_dead_letter =
        fail_new_job(&queue, &test_database, "task.lock.dead", 3, "worker-lock").await;
    let dead_letter_lock_tx = lock_queue_job_row(&test_database, failed_for_dead_letter).await;
    let dead_letter_error = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_for_dead_letter,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect_err("locked failed job should not move to dead letter");
    assert!(matches!(
        dead_letter_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, failed_for_dead_letter)
            .await
            .expect("locked dead-letter move should leave failed job"),
        JobStatus::Failed
    );
    dead_letter_lock_tx
        .rollback()
        .await
        .expect("release dead-letter move lock");
    queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_for_dead_letter,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("dead-letter move should work after lock release");

    let failed_for_requeue_dead = fail_new_job(
        &queue,
        &test_database,
        "task.lock.dead_requeue",
        4,
        "worker-lock",
    )
    .await;
    let dead_letter_for_requeue = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_for_requeue_dead,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move dead-letter source");
    let requeue_dead_lock_tx =
        lock_dead_letter_job_row(&test_database, dead_letter_for_requeue).await;
    let requeue_dead_error = queue
        .requeue_dead_letter_job(&test_database.paranoid_pool, dead_letter_for_requeue, None)
        .await
        .expect_err("locked dead-letter row should not requeue");
    assert!(matches!(
        requeue_dead_error,
        Error::DeadLetterJobLockedByConcurrentTransaction
    ));
    requeue_dead_lock_tx
        .rollback()
        .await
        .expect("release dead-letter requeue lock");
    queue
        .requeue_dead_letter_job(&test_database.paranoid_pool, dead_letter_for_requeue, None)
        .await
        .expect("dead-letter requeue should work after lock release");

    let failed_for_delete_dead = fail_new_job(
        &queue,
        &test_database,
        "task.lock.dead_delete",
        5,
        "worker-lock",
    )
    .await;
    let dead_letter_for_delete = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_for_delete_dead,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move dead-letter source for delete");
    let delete_dead_lock_tx =
        lock_dead_letter_job_row(&test_database, dead_letter_for_delete).await;
    let delete_dead_error = queue
        .delete_dead_letter_job(&test_database.paranoid_pool, dead_letter_for_delete)
        .await
        .expect_err("locked dead-letter row should not delete");
    assert!(matches!(
        delete_dead_error,
        Error::DeadLetterJobLockedByConcurrentTransaction
    ));
    delete_dead_lock_tx
        .rollback()
        .await
        .expect("release dead-letter delete lock");
    queue
        .delete_dead_letter_job(&test_database.paranoid_pool, dead_letter_for_delete)
        .await
        .expect("dead-letter delete should work after lock release");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_bulk_retry_and_dead_letter_skip_locked_rows_and_apply_after_release() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let locked_retry_job = fail_new_job(
        &queue,
        &test_database,
        "task.bulk.lock.retry",
        1,
        "worker-bulk",
    )
    .await;
    let free_retry_job = fail_new_job(
        &queue,
        &test_database,
        "task.bulk.lock.retry",
        2,
        "worker-bulk",
    )
    .await;
    let retry_lock_tx = lock_queue_job_row(&test_database, locked_retry_job).await;
    let retried_while_locked = queue
        .retry_available_failed_jobs(
            &test_database.paranoid_pool,
            Some("task.bulk.lock.retry"),
            10,
            None,
        )
        .await
        .expect("bulk retry should skip locked failed rows");
    assert_eq!(retried_while_locked, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_retry_job)
            .await
            .expect("locked bulk retry job should remain failed"),
        JobStatus::Failed
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, free_retry_job)
            .await
            .expect("free bulk retry job should become pending"),
        JobStatus::Pending
    );
    retry_lock_tx
        .rollback()
        .await
        .expect("release bulk retry lock");
    let retried_after_release = queue
        .retry_available_failed_jobs(
            &test_database.paranoid_pool,
            Some("task.bulk.lock.retry"),
            10,
            None,
        )
        .await
        .expect("bulk retry should process released failed row");
    assert_eq!(retried_after_release, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_retry_job)
            .await
            .expect("released bulk retry job should become pending"),
        JobStatus::Pending
    );

    let locked_dead_letter_job = fail_new_job(
        &queue,
        &test_database,
        "task.bulk.lock.dead",
        3,
        "worker-bulk",
    )
    .await;
    let free_dead_letter_job = fail_new_job(
        &queue,
        &test_database,
        "task.bulk.lock.dead",
        4,
        "worker-bulk",
    )
    .await;
    let dead_letter_lock_tx = lock_queue_job_row(&test_database, locked_dead_letter_job).await;
    let moved_while_locked = queue
        .move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &[locked_dead_letter_job, free_dead_letter_job],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("bulk dead-letter should skip locked failed rows");
    assert_eq!(moved_while_locked.requested_count, 2);
    assert_eq!(moved_while_locked.skipped_count(), 1);
    assert_eq!(
        moved_while_locked.moved_jobs[0].original_job_id,
        free_dead_letter_job
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_dead_letter_job)
            .await
            .expect("locked bulk dead-letter job should remain failed"),
        JobStatus::Failed
    );
    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, free_dead_letter_job)
            .await
            .expect_err("free bulk dead-letter job should leave main table"),
        Error::JobNotFound
    ));
    dead_letter_lock_tx
        .rollback()
        .await
        .expect("release bulk dead-letter lock");
    let moved_after_release = queue
        .move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &[locked_dead_letter_job],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("bulk dead-letter should process released failed row");
    assert_eq!(moved_after_release.requested_count, 1);
    assert_eq!(moved_after_release.skipped_count(), 0);
    assert_eq!(
        moved_after_release.moved_jobs[0].original_job_id,
        locked_dead_letter_job
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
