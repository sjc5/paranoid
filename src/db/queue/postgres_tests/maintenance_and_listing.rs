use super::*;

#[tokio::test]
async fn queue_reclaims_stale_running_jobs_without_touching_fresh_running_jobs() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    let worker_stale_owner_id = new_manual_worker_owner_id("worker-stale");

    let never_started = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.stale.never_started",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue never-started stale job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.stale.never_started"],
        1,
        "worker-stale",
    )
    .await
    .expect("claim never-started stale job");
    set_running_job_staleness(
        &test_database,
        never_started.job_id,
        Duration::from_secs(120),
        None,
        Duration::from_secs(120),
        0,
        5,
    )
    .await;

    let retryable_expired = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.stale.retryable",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue retryable stale job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.stale.retryable"],
        1,
        "worker-stale",
    )
    .await
    .expect("claim retryable stale job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            retryable_expired.job_id,
            &worker_stale_owner_id,
        )
        .await
        .expect("start retryable stale job");
    set_running_job_staleness(
        &test_database,
        retryable_expired.job_id,
        Duration::from_secs(120),
        Some(Duration::from_secs(120)),
        Duration::from_secs(120),
        0,
        5,
    )
    .await;

    let exhausted_expired = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.stale.exhausted",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue exhausted stale job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.stale.exhausted"],
        1,
        "worker-stale",
    )
    .await
    .expect("claim exhausted stale job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            exhausted_expired.job_id,
            &worker_stale_owner_id,
        )
        .await
        .expect("start exhausted stale job");
    set_running_job_staleness(
        &test_database,
        exhausted_expired.job_id,
        Duration::from_secs(120),
        Some(Duration::from_secs(120)),
        Duration::from_secs(120),
        5,
        5,
    )
    .await;

    let fresh_running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.stale.fresh",
            &TestPayload { value: 4 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue fresh running job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.stale.fresh"],
        1,
        "worker-stale",
    )
    .await
    .expect("claim fresh running job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            fresh_running.job_id,
            &worker_stale_owner_id,
        )
        .await
        .expect("start fresh running job");
    set_running_job_staleness(
        &test_database,
        fresh_running.job_id,
        Duration::from_secs(120),
        Some(Duration::from_secs(120)),
        Duration::from_secs(5),
        0,
        5,
    )
    .await;

    let reclaim_result = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            true,
        )
        .await
        .expect("reclaim stale running jobs");
    assert_eq!(
        reclaim_result.never_started_jobs_returned_to_pending,
        vec![crate::queue::ReclaimedJob {
            id: never_started.job_id,
            task_name: "task.stale.never_started".to_owned(),
        }]
    );
    assert_eq!(reclaim_result.expired_jobs_moved_to_failed.len(), 1);
    assert_eq!(
        reclaim_result.expired_jobs_moved_to_failed[0].id,
        exhausted_expired.job_id
    );
    assert!(
        reclaim_result.expired_jobs_moved_to_failed[0]
            .last_error
            .contains("execution expired")
    );
    assert_eq!(reclaim_result.expired_jobs_moved_to_dead_letter.len(), 1);
    assert_eq!(
        reclaim_result.expired_jobs_moved_to_dead_letter[0].original_job_id,
        exhausted_expired.job_id
    );
    assert_eq!(
        reclaim_result.expired_jobs_returned_to_pending_for_retry,
        vec![crate::queue::ReclaimedJob {
            id: retryable_expired.job_id,
            task_name: "task.stale.retryable".to_owned(),
        }]
    );

    let never_started_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, never_started.job_id)
        .await
        .expect("fetch reclaimed never-started job");
    assert_eq!(never_started_after.status, JobStatus::Pending);
    assert!(never_started_after.worker_owner_id.is_none());

    let retryable_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, retryable_expired.job_id)
        .await
        .expect("fetch reclaimed retryable job");
    assert_eq!(retryable_after.status, JobStatus::Pending);
    assert_eq!(retryable_after.retry_count, 1);
    assert!(
        retryable_after
            .last_error
            .as_deref()
            .expect("retryable stale job records error")
            .contains("execution expired")
    );

    let exhausted_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, exhausted_expired.job_id)
        .await
        .expect_err("dead-lettered exhausted stale job should leave main table");
    assert!(matches!(exhausted_after, Error::JobNotFound));
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list stale dead letters");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(
        dead_letters.jobs[0].original_job_id,
        exhausted_expired.job_id
    );
    assert_eq!(
        dead_letters.jobs[0].reason,
        DeadLetterReason::ExecutionExpired
    );

    let fresh_after = queue
        .fetch_job_by_id(&test_database.paranoid_pool, fresh_running.job_id)
        .await
        .expect("fetch fresh running job");
    assert_eq!(fresh_after.status, JobStatus::Running);
    assert_eq!(
        worker_owner_id_text(fresh_after.worker_owner_id.as_ref()),
        Some("worker-stale")
    );

    let zero_threshold = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::ZERO,
            10,
            false,
        )
        .await
        .expect_err("zero stale threshold is invalid");
    assert!(matches!(zero_threshold, Error::StaleThresholdIsZero));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_reclaim_stale_running_jobs_respects_batch_size() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let mut stale_job_ids = Vec::new();
    for value in 0..3 {
        let enqueued = queue
            .enqueue_json(
                &test_database.paranoid_pool,
                "task.stale.batch_limited",
                &TestPayload { value },
                EnqueueOptions::default(),
            )
            .await
            .expect("enqueue stale batch-limited job");
        stale_job_ids.push(enqueued.job_id);
    }
    let worker_stale_batch_owner_id = new_manual_worker_owner_id("worker-stale-batch");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.stale.batch_limited"],
        stale_job_ids.len(),
        &worker_stale_batch_owner_id,
    )
    .await
    .expect("claim stale batch-limited jobs");
    for job_id in &stale_job_ids {
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_started(
                &test_database.paranoid_pool,
                *job_id,
                &worker_stale_batch_owner_id,
            )
            .await
            .expect("start stale batch-limited job");
        set_running_job_staleness(
            &test_database,
            *job_id,
            Duration::from_secs(120),
            Some(Duration::from_secs(120)),
            Duration::from_secs(120),
            0,
            5,
        )
        .await;
    }

    let first_reclaim = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            2,
            false,
        )
        .await
        .expect("first bounded reclaim");
    assert_eq!(
        first_reclaim
            .expired_jobs_returned_to_pending_for_retry
            .len(),
        2
    );
    let counts_after_first = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.stale.batch_limited"),
        )
        .await
        .expect("fetch counts after first reclaim");
    assert_eq!(counts_after_first.pending_count, 2);
    assert_eq!(counts_after_first.running_count, 1);

    let second_reclaim = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            2,
            false,
        )
        .await
        .expect("second bounded reclaim");
    assert_eq!(
        second_reclaim
            .expired_jobs_returned_to_pending_for_retry
            .len(),
        1
    );
    let counts_after_second = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.stale.batch_limited"),
        )
        .await
        .expect("fetch counts after second reclaim");
    assert_eq!(counts_after_second.pending_count, 3);
    assert_eq!(counts_after_second.running_count, 0);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_dead_letter_round_trip_preserves_payload_and_blocks_active_dedupe_conflicts() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let failed_job = fail_new_job(&queue, &test_database, "task.dead", 10, "worker-a").await;
    let dead_letter_id = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_job,
            DeadLetterReason::PermanentError,
        )
        .await
        .expect("move failed job to dead letter");
    let missing_job = queue
        .fetch_job_by_id(&test_database.paranoid_pool, failed_job)
        .await
        .expect_err("dead-lettered job should leave main table");
    assert!(matches!(missing_job, Error::JobNotFound));

    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(dead_letters.jobs[0].id, dead_letter_id);
    assert_eq!(dead_letters.jobs[0].original_job_id, failed_job);
    assert_eq!(dead_letters.jobs[0].task_name, "task.dead");
    assert_payload_json_value(&dead_letters.jobs[0].payload_json, 10);
    assert_eq!(
        dead_letters.jobs[0].reason,
        DeadLetterReason::PermanentError
    );

    let requeued_id = queue
        .requeue_dead_letter_job(
            &test_database.paranoid_pool,
            dead_letter_id,
            Some(
                JobRunAtOrAfter::from_unix_microseconds(4_102_444_900_000_000)
                    .expect("scheduled run time"),
            ),
        )
        .await
        .expect("requeue dead-letter job");
    assert_ne!(requeued_id, failed_job);
    let requeued = queue
        .fetch_job_by_id(&test_database.paranoid_pool, requeued_id)
        .await
        .expect("fetch requeued job");
    assert_eq!(requeued.status, JobStatus::Pending);
    assert_payload_json_value(&requeued.payload_json, 10);
    assert_eq!(
        requeued.run_at_or_after_unix_microseconds,
        4_102_444_900_000_000
    );
    let dead_letters_after_requeue = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list after requeue");
    assert!(dead_letters_after_requeue.jobs.is_empty());
    let requeue_again = queue
        .requeue_dead_letter_job(&test_database.paranoid_pool, dead_letter_id, None)
        .await
        .expect_err("requeued dead-letter job should be missing");
    assert!(matches!(requeue_again, Error::DeadLetterJobNotFound));

    let failed_with_dedupe = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.dead",
            &TestPayload { value: 11 },
            EnqueueOptions {
                dedupe_key: Some("dead-dedupe".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue dedupe dead-letter source");
    let worker_b_owner_id = new_manual_worker_owner_id("worker-b");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.dead"],
        1,
        &worker_b_owner_id,
    )
    .await
    .expect("claim dedupe dead-letter source");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            failed_with_dedupe.job_id,
            &worker_b_owner_id,
            "dedupe failure",
            false,
        )
        .await
        .expect("fail dedupe source");
    let blocked_dead_letter_id = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_with_dedupe.job_id,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move dedupe source to dead letter");
    queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.dead",
            &TestPayload { value: 12 },
            EnqueueOptions {
                dedupe_key: Some("dead-dedupe".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue active dedupe blocker");
    let requeue_conflict = queue
        .requeue_dead_letter_job(&test_database.paranoid_pool, blocked_dead_letter_id, None)
        .await
        .expect_err("active dedupe blocker should prevent dead-letter requeue");
    assert!(matches!(
        requeue_conflict,
        Error::RetryConflictWithActiveDedupeJob
    ));
    queue
        .delete_dead_letter_job(&test_database.paranoid_pool, blocked_dead_letter_id)
        .await
        .expect("delete blocked dead-letter job");
    let delete_again = queue
        .delete_dead_letter_job(&test_database.paranoid_pool, blocked_dead_letter_id)
        .await
        .expect_err("deleted dead-letter job should be missing");
    assert!(matches!(delete_again, Error::DeadLetterJobNotFound));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_list_jobs_and_dead_letters_filter_page_and_deduplicate_statuses() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let pending_alpha_one = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.list.alpha",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue pending alpha one");
    let _pending_beta = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.list.beta",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue pending beta");
    let pending_alpha_two = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.list.alpha",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue pending alpha two");
    let failed_alpha =
        fail_new_job(&queue, &test_database, "task.list.alpha", 4, "worker-list").await;

    let first_page = queue
        .list_jobs(
            &test_database.paranoid_pool,
            ListJobsOptions {
                statuses: vec![JobStatus::Pending, JobStatus::Pending, JobStatus::Failed],
                task_name: Some("task.list.alpha".to_owned()),
                limit: Some(2),
                cursor_id: None,
            },
        )
        .await
        .expect("list first page");
    assert_eq!(first_page.jobs.len(), 2);
    assert!(first_page.next_cursor_id.is_some());
    assert!(
        first_page
            .jobs
            .iter()
            .all(|job| job.task_name == "task.list.alpha")
    );
    assert!(
        first_page
            .jobs
            .iter()
            .any(|job| job.id == pending_alpha_one.job_id)
    );

    let second_page = queue
        .list_jobs(
            &test_database.paranoid_pool,
            ListJobsOptions {
                statuses: vec![JobStatus::Pending, JobStatus::Failed],
                task_name: Some("task.list.alpha".to_owned()),
                limit: Some(2),
                cursor_id: first_page.next_cursor_id,
            },
        )
        .await
        .expect("list second page");
    assert_eq!(second_page.jobs.len(), 1);
    let listed_ids = first_page
        .jobs
        .iter()
        .chain(second_page.jobs.iter())
        .map(|job| job.id)
        .collect::<HashSet<_>>();
    assert_eq!(listed_ids.len(), 3);
    assert!(listed_ids.contains(&pending_alpha_one.job_id));
    assert!(listed_ids.contains(&pending_alpha_two.job_id));
    assert!(listed_ids.contains(&failed_alpha));
    assert!(second_page.next_cursor_id.is_none());

    let dead_letter_id = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_alpha,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move list failed job to dead letter");
    let dead_letter_page = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions {
                task_name: Some("task.list.alpha".to_owned()),
                limit: Some(1),
                cursor_id: None,
            },
        )
        .await
        .expect("list dead-letter page");
    assert_eq!(dead_letter_page.jobs.len(), 1);
    assert_eq!(dead_letter_page.jobs[0].id, dead_letter_id);
    assert!(dead_letter_page.next_cursor_id.is_none());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_dead_letter_batch_moves_only_failed_rows_and_rejects_oversized_inputs() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let empty_batch = queue
        .move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &[],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("empty batch should be a no-op");
    assert_eq!(empty_batch.requested_count, 0);
    assert!(empty_batch.moved_jobs.is_empty());
    assert_eq!(empty_batch.skipped_count(), 0);

    let failed_one =
        fail_new_job(&queue, &test_database, "task.dead.batch", 1, "worker-batch").await;
    let failed_two =
        fail_new_job(&queue, &test_database, "task.dead.batch", 2, "worker-batch").await;
    let pending = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.dead.batch",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue pending batch non-match");
    let missing = crate::queue::JobId::new().expect("missing id");

    let duplicate_id_error = queue
        .move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &[failed_one, failed_one],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect_err("duplicate dead-letter batch ids should be rejected");
    assert!(matches!(
        duplicate_id_error,
        Error::DuplicateJobIdInDeadLetterMoveBatch { .. }
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, failed_one)
            .await
            .expect("duplicate-id rejection should not mutate failed job"),
        JobStatus::Failed
    );

    let moved = queue
        .move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &[failed_one, pending.job_id, missing, failed_two],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move failed jobs in batch");
    assert_eq!(moved.requested_count, 4);
    assert_eq!(moved.skipped_count(), 2);
    let moved_original_ids = moved
        .moved_jobs
        .iter()
        .map(|job| job.original_job_id)
        .collect::<HashSet<_>>();
    assert_eq!(moved_original_ids, HashSet::from([failed_one, failed_two]));

    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, failed_one)
            .await
            .expect_err("first failed job should leave main table"),
        Error::JobNotFound
    ));
    assert!(matches!(
        queue
            .fetch_job_by_id(&test_database.paranoid_pool, failed_two)
            .await
            .expect_err("second failed job should leave main table"),
        Error::JobNotFound
    ));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, pending.job_id)
            .await
            .expect("pending non-match should remain pending"),
        JobStatus::Pending
    );

    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list batch dead letters");
    assert_eq!(dead_letters.jobs.len(), 2);
    assert!(
        dead_letters
            .jobs
            .iter()
            .all(|job| job.reason == DeadLetterReason::OperatorAction)
    );

    let oversized_ids = (0..=crate::queue::MAX_DEAD_LETTER_MOVE_BATCH_SIZE)
        .map(|_| crate::queue::JobId::new().expect("oversized id"))
        .collect::<Vec<_>>();
    let oversized_error = queue
        .move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &oversized_ids,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect_err("oversized dead-letter batch should be rejected");
    assert!(matches!(
        oversized_error,
        Error::DeadLetterMoveBatchSizeTooLarge { .. }
    ));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_job_status_and_single_dead_letter_miss_paths_are_exact() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let missing = crate::queue::JobId::new().expect("missing job id");
    let missing_status_error = queue
        .fetch_job_status(&test_database.paranoid_pool, missing)
        .await
        .expect_err("missing job status should return JobNotFound");
    assert!(matches!(missing_status_error, Error::JobNotFound));

    let missing_dead_letter_error = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            missing,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect_err("missing failed job should not move to dead letter");
    assert!(matches!(missing_dead_letter_error, Error::JobNotFound));

    let pending = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.dead.single-miss",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue pending single dead-letter non-match");
    let pending_dead_letter_error = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            pending.job_id,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect_err("pending job should not move to dead letter");
    assert!(matches!(pending_dead_letter_error, Error::JobNotFailed));
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, pending.job_id)
            .await
            .expect("pending job should remain queryable"),
        JobStatus::Pending
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_cleanup_deletes_only_terminal_rows_older_than_age_in_bounded_batches() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let completed_old = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.cleanup",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue completed old");
    let completed_new = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.cleanup",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue completed new");
    let worker_clean_owner_id = new_manual_worker_owner_id("worker-clean");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.cleanup"],
        2,
        &worker_clean_owner_id,
    )
    .await
    .expect("claim cleanup jobs");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            completed_old.job_id,
            &worker_clean_owner_id,
        )
        .await
        .expect("complete old job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            completed_new.job_id,
            &worker_clean_owner_id,
        )
        .await
        .expect("complete new job");
    set_job_finished_age(
        &test_database,
        completed_old.job_id,
        Duration::from_secs(7200),
    )
    .await;
    set_job_finished_age(
        &test_database,
        completed_new.job_id,
        Duration::from_secs(60),
    )
    .await;

    let failed_cleanup_old =
        fail_new_job(&queue, &test_database, "task.cleanup", 3, "worker-clean").await;
    let failed_cleanup_new =
        fail_new_job(&queue, &test_database, "task.cleanup", 4, "worker-clean").await;
    set_job_finished_age(
        &test_database,
        failed_cleanup_old,
        Duration::from_secs(7200),
    )
    .await;
    set_job_finished_age(&test_database, failed_cleanup_new, Duration::from_secs(60)).await;

    let dead_letter_source_old =
        fail_new_job(&queue, &test_database, "task.cleanup", 5, "worker-clean").await;
    let dead_letter_source_new =
        fail_new_job(&queue, &test_database, "task.cleanup", 6, "worker-clean").await;

    let dead_letter_old = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_source_old,
            DeadLetterReason::MaxRetriesExceeded,
        )
        .await
        .expect("dead-letter old failed job");
    let dead_letter_new = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_source_new,
            DeadLetterReason::MaxRetriesExceeded,
        )
        .await
        .expect("dead-letter new failed job");
    set_dead_letter_age(&test_database, dead_letter_old, Duration::from_secs(7200)).await;
    set_dead_letter_age(&test_database, dead_letter_new, Duration::from_secs(60)).await;

    let cleaned_completed = queue
        .cleanup_available_completed_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            1,
        )
        .await
        .expect("cleanup completed old");
    assert_eq!(cleaned_completed, 1);
    let cleaned_failed = queue
        .cleanup_available_failed_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            10,
        )
        .await
        .expect("cleanup failed old");
    assert_eq!(cleaned_failed, 1);
    let cleaned_dead_letters = queue
        .cleanup_available_dead_letter_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            10,
        )
        .await
        .expect("cleanup dead-letter old");
    assert_eq!(cleaned_dead_letters, 1);

    let remaining_completed_old = queue
        .fetch_job_by_id(&test_database.paranoid_pool, completed_old.job_id)
        .await
        .expect_err("old completed job should be deleted");
    assert!(matches!(remaining_completed_old, Error::JobNotFound));
    queue
        .fetch_job_by_id(&test_database.paranoid_pool, completed_new.job_id)
        .await
        .expect("new completed job should remain");
    let remaining_failed_old = queue
        .fetch_job_by_id(&test_database.paranoid_pool, failed_cleanup_old)
        .await
        .expect_err("old failed job should be deleted");
    assert!(matches!(remaining_failed_old, Error::JobNotFound));
    queue
        .fetch_job_by_id(&test_database.paranoid_pool, failed_cleanup_new)
        .await
        .expect("new failed job should remain");
    let remaining_dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list remaining dead letters");
    assert_eq!(remaining_dead_letters.jobs.len(), 1);
    assert_eq!(remaining_dead_letters.jobs[0].id, dead_letter_new);

    let zero_age = queue
        .cleanup_available_completed_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::ZERO,
            1,
        )
        .await
        .expect_err("zero cleanup age is invalid");
    assert!(matches!(zero_age, Error::CleanupAgeIsZero));
    let zero_batch = queue
        .cleanup_available_completed_jobs_older_than_once(
            &test_database.paranoid_pool,
            Duration::from_secs(1),
            0,
        )
        .await
        .expect_err("zero cleanup batch is invalid");
    assert!(matches!(zero_batch, Error::CleanupBatchSizeIsZero));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_cleanup_until_empty_drains_multiple_batches_without_a_caller_transaction() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let mut completed_job_ids = Vec::new();
    for payload_value in 0..5 {
        let enqueued = queue
            .enqueue_json(
                &test_database.paranoid_pool,
                "task.cleanup_until_empty.completed",
                &TestPayload {
                    value: payload_value,
                },
                EnqueueOptions::default(),
            )
            .await
            .expect("enqueue completed cleanup job");
        completed_job_ids.push(enqueued.job_id);
    }
    let cleanup_until_empty_owner_id = new_manual_worker_owner_id("worker-cleanup-until-empty");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.cleanup_until_empty.completed"],
        completed_job_ids.len(),
        &cleanup_until_empty_owner_id,
    )
    .await
    .expect("claim completed cleanup jobs");
    for job_id in &completed_job_ids {
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed(
                &test_database.paranoid_pool,
                *job_id,
                &cleanup_until_empty_owner_id,
            )
            .await
            .expect("complete cleanup job");
        set_job_finished_age(&test_database, *job_id, Duration::from_secs(7200)).await;
    }

    let mut failed_job_ids = Vec::new();
    for payload_value in 0..3 {
        let job_id = fail_new_job(
            &queue,
            &test_database,
            "task.cleanup_until_empty.failed",
            payload_value,
            "worker-cleanup-until-empty",
        )
        .await;
        set_job_finished_age(&test_database, job_id, Duration::from_secs(7200)).await;
        failed_job_ids.push(job_id);
    }

    let mut dead_letter_ids = Vec::new();
    for payload_value in 0..4 {
        let job_id = fail_new_job(
            &queue,
            &test_database,
            "task.cleanup_until_empty.dead_letter",
            payload_value,
            "worker-cleanup-until-empty",
        )
        .await;
        let dead_letter_id = queue
            .move_failed_job_to_dead_letter(
                &test_database.paranoid_pool,
                job_id,
                DeadLetterReason::OperatorAction,
            )
            .await
            .expect("move cleanup job to dead letter");
        set_dead_letter_age(&test_database, dead_letter_id, Duration::from_secs(7200)).await;
        dead_letter_ids.push(dead_letter_id);
    }

    let completed_deleted = queue
        .cleanup_available_completed_jobs_older_than_until_empty(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            2,
            Duration::ZERO,
        )
        .await
        .expect("cleanup all old completed jobs");
    assert_eq!(completed_deleted, completed_job_ids.len() as u64);

    let failed_deleted = queue
        .cleanup_available_failed_jobs_older_than_until_empty(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            2,
            Duration::ZERO,
        )
        .await
        .expect("cleanup all old failed jobs");
    assert_eq!(failed_deleted, failed_job_ids.len() as u64);

    let dead_letter_deleted = queue
        .cleanup_available_dead_letter_jobs_older_than_until_empty(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            2,
            Duration::ZERO,
        )
        .await
        .expect("cleanup all old dead-letter jobs");
    assert_eq!(dead_letter_deleted, dead_letter_ids.len() as u64);

    for job_id in completed_job_ids.into_iter().chain(failed_job_ids) {
        let fetch_error = queue
            .fetch_job_by_id(&test_database.paranoid_pool, job_id)
            .await
            .expect_err("old terminal job should be deleted");
        assert!(matches!(fetch_error, Error::JobNotFound));
    }
    let remaining_dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters after cleanup until empty");
    assert!(remaining_dead_letters.jobs.is_empty());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_cleanup_dead_letter_until_empty_future_abort_after_first_batch_does_not_continue() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    for payload_value in 0..3 {
        let job_id = fail_new_job(
            &queue,
            &test_database,
            "task.cleanup_cancel.dead_letter",
            payload_value,
            "worker-cleanup-cancel",
        )
        .await;
        let dead_letter_id = queue
            .move_failed_job_to_dead_letter(
                &test_database.paranoid_pool,
                job_id,
                DeadLetterReason::OperatorAction,
            )
            .await
            .expect("move cleanup cancellation fixture to dead letter");
        set_dead_letter_age(&test_database, dead_letter_id, Duration::from_secs(7200)).await;
    }

    let cleanup_queue = queue.clone();
    let cleanup_pool = test_database.paranoid_pool.clone();
    let cleanup_handle = tokio::spawn(async move {
        cleanup_queue
            .cleanup_available_dead_letter_jobs_older_than_until_empty(
                &cleanup_pool,
                Duration::from_secs(3600),
                1,
                Duration::from_millis(500),
            )
            .await
            .expect("cleanup should run until aborted");
    });

    wait_until(
        "first dead-letter cleanup batch finished",
        Duration::from_secs(3),
        || {
            let queue = queue.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                let remaining = queue
                    .list_dead_letter_jobs(&pool, ListDeadLetterJobsOptions::default())
                    .await
                    .expect("list dead letters while cleanup is sleeping");
                remaining.jobs.len() == 2
            }
        },
    )
    .await;

    cleanup_handle.abort();
    match cleanup_handle.await {
        Err(join_error) => assert!(
            join_error.is_cancelled(),
            "cleanup task join error = {join_error}"
        ),
        Ok(_) => panic!("cleanup task completed instead of being aborted during batch delay"),
    }

    tokio::time::sleep(Duration::from_millis(700)).await;
    let remaining_after_abort = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters after aborted cleanup");
    assert_eq!(remaining_after_abort.jobs.len(), 2);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_cleanup_and_reclaim_high_cardinality_smoke_stays_bounded() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    const COUNT: usize = 300;

    let completed_payloads = (0..COUNT)
        .map(|value| TestPayload {
            value: value as i32,
        })
        .collect::<Vec<_>>();
    let completed_jobs = queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.high_cardinality.completed",
            &completed_payloads,
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("batch enqueue completed fixtures");
    let high_cardinality_completed_owner_id =
        new_manual_worker_owner_id("worker-high-cardinality-completed");
    let completed_claims = claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.high_cardinality.completed"],
        COUNT,
        &high_cardinality_completed_owner_id,
    )
    .await
    .expect("claim completed fixtures");
    assert_eq!(completed_claims.len(), completed_jobs.len());
    for job in completed_claims {
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed(
                &test_database.paranoid_pool,
                job.id,
                &high_cardinality_completed_owner_id,
            )
            .await
            .expect("complete high-cardinality fixture");
    }
    set_finished_age_for_task(
        &test_database,
        "task.high_cardinality.completed",
        Duration::from_secs(7200),
    )
    .await;

    let stale_payloads = (0..COUNT)
        .map(|value| TestPayload {
            value: value as i32,
        })
        .collect::<Vec<_>>();
    queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.high_cardinality.stale",
            &stale_payloads,
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("batch enqueue stale fixtures");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.high_cardinality.stale"],
        COUNT,
        "worker-high-cardinality-stale",
    )
    .await
    .expect("claim stale fixtures");
    set_running_staleness_for_task(
        &test_database,
        "task.high_cardinality.stale",
        Duration::from_secs(600),
    )
    .await;

    let cleanup_started_at = Instant::now();
    let cleaned = queue
        .cleanup_available_completed_jobs_older_than_until_empty(
            &test_database.paranoid_pool,
            Duration::from_secs(3600),
            50,
            Duration::ZERO,
        )
        .await
        .expect("cleanup high-cardinality completed jobs");
    assert_eq!(cleaned, COUNT as u64);
    assert!(
        cleanup_started_at.elapsed() <= Duration::from_secs(10),
        "high-cardinality cleanup took {:?}",
        cleanup_started_at.elapsed()
    );

    let reclaim_started_at = Instant::now();
    let reclaimed = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(1),
            COUNT as u32,
            false,
        )
        .await
        .expect("reclaim high-cardinality stale running jobs");
    assert_eq!(
        reclaimed.expired_jobs_returned_to_pending_for_retry.len(),
        COUNT
    );
    assert!(
        reclaim_started_at.elapsed() <= Duration::from_secs(10),
        "high-cardinality reclaim took {:?}",
        reclaim_started_at.elapsed()
    );

    let stale_counts = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.high_cardinality.stale"),
        )
        .await
        .expect("fetch stale task counts");
    assert_eq!(stale_counts.pending_count, COUNT as i64);
    assert_eq!(stale_counts.running_count, 0);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

async fn set_finished_age_for_task(test_database: &TestDatabase, task_name: &str, age: Duration) {
    let statement = format!(
        r#"
        UPDATE {}
        SET finished_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            updated_at = statement_timestamp()
        WHERE task_name = $1 AND status = 'completed'
        "#,
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(task_name)
        .bind(duration_microseconds_for_test(age))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("set finished age for task");
}

async fn set_running_staleness_for_task(
    test_database: &TestDatabase,
    task_name: &str,
    age: Duration,
) {
    let statement = format!(
        r#"
        UPDATE {}
        SET claimed_by_worker_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            execution_started_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            execution_heartbeat_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            retry_count = 0,
            max_retries = 5,
            updated_at = statement_timestamp()
        WHERE task_name = $1 AND status = 'running'
        "#,
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(task_name)
        .bind(duration_microseconds_for_test(age))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("set running staleness for task");
}
