use super::*;

#[tokio::test]
async fn queue_owned_worker_mutations_return_locked_without_mutating_locked_rows() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    let worker_owned_owner_id = new_manual_worker_owner_id("worker-owned");

    let started_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.started",
        1,
        &worker_owned_owner_id,
    )
    .await;
    let started_lock_tx = lock_queue_job_row(&test_database, started_job).await;
    let started_error = queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            started_job,
            &worker_owned_owner_id,
        )
        .await
        .expect_err("locked owned job should not mark started");
    assert!(matches!(
        started_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, started_job)
            .await
            .expect("fetch locked started job")
            .execution_started_at_unix_microseconds
            .is_none()
    );
    started_lock_tx
        .rollback()
        .await
        .expect("release started lock");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            started_job,
            &worker_owned_owner_id,
        )
        .await
        .expect("mark started after lock release");

    let completed_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.completed",
        2,
        &worker_owned_owner_id,
    )
    .await;
    let completed_lock_tx = lock_queue_job_row(&test_database, completed_job).await;
    let completed_error = queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            completed_job,
            &worker_owned_owner_id,
        )
        .await
        .expect_err("locked owned job should not complete");
    assert!(matches!(
        completed_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, completed_job)
            .await
            .expect("locked complete should leave running job"),
        JobStatus::Running
    );
    completed_lock_tx
        .rollback()
        .await
        .expect("release completed lock");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            completed_job,
            &worker_owned_owner_id,
        )
        .await
        .expect("complete after lock release");

    let heartbeat_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.heartbeat",
        3,
        &worker_owned_owner_id,
    )
    .await;
    let heartbeat_lock_tx = lock_queue_job_row(&test_database, heartbeat_job).await;
    let heartbeat_error = queue
        .begin_manual_worker_lifecycle()
        .touch_owned_running_job_execution_heartbeat(
            &test_database.paranoid_pool,
            heartbeat_job,
            &worker_owned_owner_id,
        )
        .await
        .expect_err("locked owned job should not heartbeat");
    assert!(matches!(
        heartbeat_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, heartbeat_job)
            .await
            .expect("locked heartbeat should leave running job"),
        JobStatus::Running
    );
    heartbeat_lock_tx
        .rollback()
        .await
        .expect("release heartbeat lock");
    queue
        .begin_manual_worker_lifecycle()
        .touch_owned_running_job_execution_heartbeat(
            &test_database.paranoid_pool,
            heartbeat_job,
            &worker_owned_owner_id,
        )
        .await
        .expect("heartbeat after lock release");

    let retry_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.retry",
        4,
        &worker_owned_owner_id,
    )
    .await;
    let retry_lock_tx = lock_queue_job_row(&test_database, retry_job).await;
    let retry_error = queue
        .begin_manual_worker_lifecycle()
        .schedule_owned_running_job_retry(
            &test_database.paranoid_pool,
            retry_job,
            &worker_owned_owner_id,
            1,
            Duration::from_secs(1),
            "retry later",
        )
        .await
        .expect_err("locked owned job should not schedule retry");
    assert!(matches!(
        retry_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, retry_job)
            .await
            .expect("locked retry should leave running job"),
        JobStatus::Running
    );
    retry_lock_tx.rollback().await.expect("release retry lock");
    queue
        .begin_manual_worker_lifecycle()
        .schedule_owned_running_job_retry(
            &test_database.paranoid_pool,
            retry_job,
            &worker_owned_owner_id,
            1,
            Duration::from_secs(1),
            "retry later",
        )
        .await
        .expect("schedule retry after lock release");

    let failed_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.failed",
        5,
        &worker_owned_owner_id,
    )
    .await;
    let failed_lock_tx = lock_queue_job_row(&test_database, failed_job).await;
    let failed_error = queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            failed_job,
            &worker_owned_owner_id,
            "failed",
            true,
        )
        .await
        .expect_err("locked owned job should not fail");
    assert!(matches!(
        failed_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, failed_job)
            .await
            .expect("locked failure should leave running job"),
        JobStatus::Running
    );
    failed_lock_tx
        .rollback()
        .await
        .expect("release failed lock");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            failed_job,
            &worker_owned_owner_id,
            "failed",
            true,
        )
        .await
        .expect("mark failed after lock release");

    let dead_letter_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.dead",
        6,
        &worker_owned_owner_id,
    )
    .await;
    let dead_letter_lock_tx = lock_queue_job_row(&test_database, dead_letter_job).await;
    let dead_letter_error = queue
        .begin_manual_worker_lifecycle()
        .move_owned_running_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_job,
            &worker_owned_owner_id,
            "dead",
            true,
            DeadLetterReason::PermanentError,
        )
        .await
        .expect_err("locked owned job should not move to dead letter");
    assert!(matches!(
        dead_letter_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, dead_letter_job)
            .await
            .expect("locked owned dead-letter move should leave running job"),
        JobStatus::Running
    );
    dead_letter_lock_tx
        .rollback()
        .await
        .expect("release owned dead-letter lock");
    queue
        .begin_manual_worker_lifecycle()
        .move_owned_running_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_job,
            &worker_owned_owner_id,
            "dead",
            true,
            DeadLetterReason::PermanentError,
        )
        .await
        .expect("move owned job to dead letter after lock release");

    let unstarted_return_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.return_unstarted",
        7,
        &worker_owned_owner_id,
    )
    .await;
    let unstarted_return_lock_tx = lock_queue_job_row(&test_database, unstarted_return_job).await;
    let unstarted_return_error = queue
        .begin_manual_worker_lifecycle()
        .return_owned_unstarted_running_job_to_pending(
            &test_database.paranoid_pool,
            unstarted_return_job,
            &worker_owned_owner_id,
        )
        .await
        .expect_err("locked unstarted owned job should not return to pending");
    assert!(matches!(
        unstarted_return_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, unstarted_return_job)
            .await
            .expect("locked unstarted return should leave running job"),
        JobStatus::Running
    );
    unstarted_return_lock_tx
        .rollback()
        .await
        .expect("release unstarted return lock");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_unstarted_running_job_to_pending(
            &test_database.paranoid_pool,
            unstarted_return_job,
            &worker_owned_owner_id,
        )
        .await
        .expect("return unstarted job after lock release");

    let started_return_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.owned.lock.return_started",
        8,
        &worker_owned_owner_id,
    )
    .await;
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            started_return_job,
            &worker_owned_owner_id,
        )
        .await
        .expect("mark return-started job started");
    let started_return_lock_tx = lock_queue_job_row(&test_database, started_return_job).await;
    let started_return_error = queue
        .begin_manual_worker_lifecycle()
        .return_owned_started_running_job_to_pending(
            &test_database.paranoid_pool,
            started_return_job,
            &worker_owned_owner_id,
        )
        .await
        .expect_err("locked started owned job should not return to pending");
    assert!(matches!(
        started_return_error,
        Error::JobLockedByConcurrentTransaction
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, started_return_job)
            .await
            .expect("locked started return should leave running job"),
        JobStatus::Running
    );
    started_return_lock_tx
        .rollback()
        .await
        .expect("release started return lock");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_started_running_job_to_pending(
            &test_database.paranoid_pool,
            started_return_job,
            &worker_owned_owner_id,
        )
        .await
        .expect("return started job after lock release");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_bulk_owned_worker_returns_skip_locked_rows_and_return_them_after_release() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    let worker_bulk_locked_owner_id = new_manual_worker_owner_id("worker-bulk-locked");

    let locked_unstarted_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.bulk.owned.locked_unstarted",
        1,
        &worker_bulk_locked_owner_id,
    )
    .await;
    let free_unstarted_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.bulk.owned.free_unstarted",
        2,
        &worker_bulk_locked_owner_id,
    )
    .await;
    let locked_unstarted_tx = lock_queue_job_row(&test_database, locked_unstarted_job).await;
    let returned_unstarted_count = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_unstarted_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &worker_bulk_locked_owner_id,
        )
        .await
        .expect("bulk unstarted return should skip locked rows");
    assert_eq!(returned_unstarted_count, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_unstarted_job)
            .await
            .expect("locked unstarted bulk return should leave job running"),
        JobStatus::Running
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, free_unstarted_job)
            .await
            .expect("free unstarted bulk return should return job"),
        JobStatus::Pending
    );
    locked_unstarted_tx
        .rollback()
        .await
        .expect("release locked unstarted bulk row");
    let returned_unstarted_after_release = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_unstarted_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &worker_bulk_locked_owner_id,
        )
        .await
        .expect("bulk unstarted return should work after lock release");
    assert_eq!(returned_unstarted_after_release, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_unstarted_job)
            .await
            .expect("released unstarted bulk return should return job"),
        JobStatus::Pending
    );

    let locked_started_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.bulk.owned.locked_started",
        3,
        &worker_bulk_locked_owner_id,
    )
    .await;
    let free_started_job = enqueue_and_claim_one(
        &queue,
        &test_database,
        "task.bulk.owned.free_started",
        4,
        &worker_bulk_locked_owner_id,
    )
    .await;
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            locked_started_job,
            &worker_bulk_locked_owner_id,
        )
        .await
        .expect("mark locked bulk-started job started");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            free_started_job,
            &worker_bulk_locked_owner_id,
        )
        .await
        .expect("mark free bulk-started job started");
    let locked_started_tx = lock_queue_job_row(&test_database, locked_started_job).await;
    let returned_started_count = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_started_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &worker_bulk_locked_owner_id,
        )
        .await
        .expect("bulk started return should skip locked rows");
    assert_eq!(returned_started_count, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_started_job)
            .await
            .expect("locked started bulk return should leave job running"),
        JobStatus::Running
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, free_started_job)
            .await
            .expect("free started bulk return should return job"),
        JobStatus::Pending
    );
    locked_started_tx
        .rollback()
        .await
        .expect("release locked started bulk row");
    let returned_started_after_release = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_started_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &worker_bulk_locked_owner_id,
        )
        .await
        .expect("bulk started return should work after lock release");
    assert_eq!(returned_started_after_release, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_started_job)
            .await
            .expect("released started bulk return should return job"),
        JobStatus::Pending
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
