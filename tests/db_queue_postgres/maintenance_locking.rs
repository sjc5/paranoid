use super::*;

#[tokio::test]
async fn queue_cleanup_completed_jobs_skips_locked_rows_and_deletes_them_after_release() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    let locked_completed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.cleanup.locked",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue locked completed job");
    let unlocked_completed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.cleanup.unlocked",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue unlocked completed job");
    let worker_cleanup_owner_id = new_manual_worker_owner_id("worker-cleanup");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.cleanup.locked", "task.cleanup.unlocked"],
        2,
        &worker_cleanup_owner_id,
    )
    .await
    .expect("claim completed jobs");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            locked_completed.job_id,
            &worker_cleanup_owner_id,
        )
        .await
        .expect("complete locked job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            unlocked_completed.job_id,
            &worker_cleanup_owner_id,
        )
        .await
        .expect("complete unlocked job");
    set_job_finished_age(
        &test_database,
        locked_completed.job_id,
        Duration::from_secs(120),
    )
    .await;
    set_job_finished_age(
        &test_database,
        unlocked_completed.job_id,
        Duration::from_secs(90),
    )
    .await;

    let lock_tx = lock_queue_job_row(&test_database, locked_completed.job_id).await;
    let deleted_while_locked = queue
        .cleanup_available_completed_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
        )
        .await
        .expect("cleanup should skip locked completed job");
    assert_eq!(deleted_while_locked, 1);
    queue
        .fetch_job_by_id(&test_database.paranoid_pool, locked_completed.job_id)
        .await
        .expect("locked completed job should remain");
    let unlocked_fetch = queue
        .fetch_job_by_id(&test_database.paranoid_pool, unlocked_completed.job_id)
        .await
        .expect_err("unlocked completed job should be deleted");
    assert!(matches!(unlocked_fetch, Error::JobNotFound));

    lock_tx.rollback().await.expect("rollback row lock");
    let deleted_after_release = queue
        .cleanup_available_completed_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
        )
        .await
        .expect("cleanup after release");
    assert_eq!(deleted_after_release, 1);
    let locked_fetch = queue
        .fetch_job_by_id(&test_database.paranoid_pool, locked_completed.job_id)
        .await
        .expect_err("released completed job should be deleted");
    assert!(matches!(locked_fetch, Error::JobNotFound));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_cleanup_dead_letter_jobs_skips_locked_rows_and_deletes_them_after_release() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let locked_source = fail_new_job(
        &queue,
        &test_database,
        "task.dead_cleanup.locked",
        1,
        "worker-clean",
    )
    .await;
    let unlocked_source = fail_new_job(
        &queue,
        &test_database,
        "task.dead_cleanup.unlocked",
        2,
        "worker-clean",
    )
    .await;
    let locked_dead_letter = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            locked_source,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move locked cleanup source to dead letter");
    let unlocked_dead_letter = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            unlocked_source,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move unlocked cleanup source to dead letter");
    set_dead_letter_age(&test_database, locked_dead_letter, Duration::from_secs(120)).await;
    set_dead_letter_age(
        &test_database,
        unlocked_dead_letter,
        Duration::from_secs(90),
    )
    .await;

    let lock_tx = lock_dead_letter_job_row(&test_database, locked_dead_letter).await;
    let deleted_while_locked = queue
        .cleanup_available_dead_letter_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
        )
        .await
        .expect("dead-letter cleanup should skip locked rows");
    assert_eq!(deleted_while_locked, 1);
    let dead_letters_while_locked = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters after locked cleanup");
    assert!(
        dead_letters_while_locked
            .jobs
            .iter()
            .any(|job| job.id == locked_dead_letter)
    );
    assert!(
        dead_letters_while_locked
            .jobs
            .iter()
            .all(|job| job.id != unlocked_dead_letter)
    );

    lock_tx.rollback().await.expect("rollback dead-letter lock");
    let deleted_after_release = queue
        .cleanup_available_dead_letter_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
        )
        .await
        .expect("dead-letter cleanup after release");
    assert_eq!(deleted_after_release, 1);
    let dead_letters_after_release = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters after released cleanup");
    assert!(dead_letters_after_release.jobs.is_empty());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_reclaim_stale_running_jobs_skips_locked_rows_and_reclaims_them_after_release() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    let locked_running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.reclaim.locked",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue locked running job");
    let unlocked_running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.reclaim.unlocked",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue unlocked running job");
    let worker_reclaim_owner_id = new_manual_worker_owner_id("worker-reclaim");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.reclaim.locked", "task.reclaim.unlocked"],
        2,
        &worker_reclaim_owner_id,
    )
    .await
    .expect("claim running jobs");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            locked_running.job_id,
            &worker_reclaim_owner_id,
        )
        .await
        .expect("start locked running job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            unlocked_running.job_id,
            &worker_reclaim_owner_id,
        )
        .await
        .expect("start unlocked running job");
    set_running_job_staleness(
        &test_database,
        locked_running.job_id,
        Duration::from_secs(120),
        Some(Duration::from_secs(120)),
        Duration::from_secs(120),
        0,
        5,
    )
    .await;
    set_running_job_staleness(
        &test_database,
        unlocked_running.job_id,
        Duration::from_secs(90),
        Some(Duration::from_secs(90)),
        Duration::from_secs(90),
        0,
        5,
    )
    .await;

    let lock_tx = lock_queue_job_row(&test_database, locked_running.job_id).await;
    let reclaim_while_locked = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            false,
        )
        .await
        .expect("reclaim should skip locked running job");
    assert_eq!(
        reclaim_while_locked.expired_jobs_returned_to_pending_for_retry,
        vec![paranoid::queue::ReclaimedJob {
            id: unlocked_running.job_id,
            task_name: "task.reclaim.unlocked".to_owned(),
        }]
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_running.job_id)
            .await
            .expect("locked stale job should remain running"),
        JobStatus::Running
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, unlocked_running.job_id)
            .await
            .expect("unlocked stale job should be returned to pending"),
        JobStatus::Pending
    );

    lock_tx.rollback().await.expect("rollback row lock");
    let reclaim_after_release = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            false,
        )
        .await
        .expect("reclaim after release");
    assert_eq!(
        reclaim_after_release.expired_jobs_returned_to_pending_for_retry,
        vec![paranoid::queue::ReclaimedJob {
            id: locked_running.job_id,
            task_name: "task.reclaim.locked".to_owned(),
        }]
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, locked_running.job_id)
            .await
            .expect("released stale job should be returned to pending"),
        JobStatus::Pending
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
