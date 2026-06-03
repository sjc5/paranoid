use super::*;

#[tokio::test]
async fn queue_claim_retry_and_stale_reclaim_high_contention_keep_single_ownership() {
    let test_database = TestDatabase::connect().await;

    let queue = Arc::new(Store::new(test_database.config.clone()).expect("queue"));
    reset_queue_schema(&test_database).await;

    const CLAIM_RETRY_JOB_COUNT: i32 = 80;
    let claim_retry_payloads = (0..CLAIM_RETRY_JOB_COUNT)
        .map(|value| TestPayload { value })
        .collect::<Vec<_>>();
    queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.claim_retry_contention",
            &claim_retry_payloads,
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("enqueue claim/retry contention jobs");

    let pool = Arc::new(test_database.paranoid_pool.clone());
    let registered_task_names = Arc::new(vec!["task.claim_retry_contention".to_owned()]);
    let mut claim_tasks = JoinSet::new();
    for worker_id in ["claim-retry-worker-1", "claim-retry-worker-2"] {
        let queue = Arc::clone(&queue);
        let pool = Arc::clone(&pool);
        let registered_task_names = Arc::clone(&registered_task_names);
        claim_tasks.spawn(async move {
            let worker_owner_id =
                crate::queue::WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text(worker_id)
                    .expect("worker owner id");
            queue
                .begin_manual_worker_lifecycle()
                .claim_available_jobs_for_worker_owner(
                    &pool,
                    registered_task_names.as_slice(),
                    CLAIM_RETRY_JOB_COUNT as u32,
                    &worker_owner_id,
                )
                .await
                .expect("contended claim")
        });
    }

    let mut claimed_jobs = Vec::new();
    while let Some(result) = claim_tasks.join_next().await {
        claimed_jobs.extend(result.expect("claim task should join"));
    }
    assert_eq!(claimed_jobs.len(), CLAIM_RETRY_JOB_COUNT as usize);
    let claimed_job_ids = claimed_jobs
        .iter()
        .map(|job| job.id)
        .collect::<HashSet<_>>();
    assert_eq!(claimed_job_ids.len(), CLAIM_RETRY_JOB_COUNT as usize);

    for job in &claimed_jobs {
        let worker_owner_id = job
            .worker_owner_id
            .as_ref()
            .expect("claimed running job should have owner");
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_failed(
                &test_database.paranoid_pool,
                job.id,
                worker_owner_id,
                "contention failure",
                false,
            )
            .await
            .expect("mark claimed job failed");
    }

    let mut retry_tasks = JoinSet::new();
    for _ in 0..2 {
        let queue = Arc::clone(&queue);
        let pool = Arc::clone(&pool);
        retry_tasks.spawn(async move {
            queue
                .retry_available_failed_jobs(
                    &pool,
                    Some("task.claim_retry_contention"),
                    CLAIM_RETRY_JOB_COUNT as u32,
                    None,
                )
                .await
                .expect("contended retry")
        });
    }

    let mut retried_count = 0;
    while let Some(result) = retry_tasks.join_next().await {
        retried_count += result.expect("retry task should join");
    }
    assert_eq!(retried_count, CLAIM_RETRY_JOB_COUNT as u64);
    let counts_after_retry = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.claim_retry_contention"),
        )
        .await
        .expect("fetch claim/retry counts");
    assert_eq!(
        counts_after_retry.pending_count,
        CLAIM_RETRY_JOB_COUNT as i64
    );
    assert_eq!(counts_after_retry.running_count, 0);
    assert_eq!(counts_after_retry.failed_count, 0);

    const RECLAIM_JOB_COUNT: i32 = 50;
    let reclaim_payloads = (0..RECLAIM_JOB_COUNT)
        .map(|value| TestPayload { value })
        .collect::<Vec<_>>();
    queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.reclaim_contention",
            &reclaim_payloads,
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("enqueue reclaim contention jobs");
    let dead_worker_owner_id = new_manual_worker_owner_id("dead-worker");
    let stale_jobs = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &["task.reclaim_contention".to_owned()],
            RECLAIM_JOB_COUNT as u32,
            &dead_worker_owner_id,
        )
        .await
        .expect("claim stale jobs");
    assert_eq!(stale_jobs.len(), RECLAIM_JOB_COUNT as usize);
    for job in &stale_jobs {
        set_running_job_staleness(
            &test_database,
            job.id,
            Duration::from_secs(600),
            None,
            Duration::from_secs(600),
            0,
            5,
        )
        .await;
    }

    let mut reclaim_tasks = JoinSet::new();
    for _ in 0..2 {
        let queue = Arc::clone(&queue);
        let pool = Arc::clone(&pool);
        reclaim_tasks.spawn(async move {
            queue
                .reclaim_available_stale_running_jobs_once(
                    &pool,
                    Duration::from_secs(1),
                    RECLAIM_JOB_COUNT as u32,
                    false,
                )
                .await
                .expect("contended stale reclaim")
        });
    }

    let mut reclaimed_job_ids = HashSet::new();
    while let Some(result) = reclaim_tasks.join_next().await {
        let reclaim_result = result.expect("reclaim task should join");
        for reclaimed in reclaim_result.never_started_jobs_returned_to_pending {
            reclaimed_job_ids.insert(reclaimed.id);
        }
        assert!(
            reclaim_result.expired_jobs_moved_to_failed.is_empty(),
            "never-started stale jobs should not be marked failed"
        );
        assert!(
            reclaim_result
                .expired_jobs_returned_to_pending_for_retry
                .is_empty(),
            "never-started stale jobs should be reclaimed by the never-started branch"
        );
        assert!(
            reclaim_result.expired_jobs_moved_to_dead_letter.is_empty(),
            "never-started stale jobs should not be dead-lettered"
        );
    }
    assert_eq!(reclaimed_job_ids.len(), RECLAIM_JOB_COUNT as usize);
    let counts_after_reclaim = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.reclaim_contention"),
        )
        .await
        .expect("fetch reclaim counts");
    assert_eq!(counts_after_reclaim.pending_count, RECLAIM_JOB_COUNT as i64);
    assert_eq!(counts_after_reclaim.running_count, 0);
    assert_eq!(counts_after_reclaim.failed_count, 0);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_retry_and_force_requeue_preserve_state_and_active_dedupe_rules() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let failed_with_dedupe = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.retry",
            &TestPayload { value: 1 },
            EnqueueOptions {
                dedupe_key: Some("dedupe-a".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue dedupe job");
    let worker_a_owner_id = new_manual_worker_owner_id("worker-a");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.retry"],
        1,
        &worker_a_owner_id,
    )
    .await
    .expect("claim dedupe job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            failed_with_dedupe.job_id,
            &worker_a_owner_id,
            "first failure",
            true,
        )
        .await
        .expect("fail dedupe job");

    let active_same_dedupe = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.retry",
            &TestPayload { value: 2 },
            EnqueueOptions {
                dedupe_key: Some("dedupe-a".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue active dedupe job");
    let conflict = queue
        .retry_failed_job(
            &test_database.paranoid_pool,
            failed_with_dedupe.job_id,
            Some(
                JobRunAtOrAfter::from_unix_microseconds(4_102_444_800_000_000)
                    .expect("scheduled run time"),
            ),
        )
        .await
        .expect_err("active dedupe job should block retry");
    assert!(matches!(conflict, Error::RetryConflictWithActiveDedupeJob));

    queue
        .cancel_pending_job(&test_database.paranoid_pool, active_same_dedupe.job_id)
        .await
        .expect("cancel active dedupe job");
    queue
        .retry_failed_job(
            &test_database.paranoid_pool,
            failed_with_dedupe.job_id,
            Some(
                JobRunAtOrAfter::from_unix_microseconds(4_102_444_800_000_000)
                    .expect("scheduled run time"),
            ),
        )
        .await
        .expect("retry failed job after active dedupe clears");
    let retried = queue
        .fetch_job_by_id(&test_database.paranoid_pool, failed_with_dedupe.job_id)
        .await
        .expect("fetch retried job");
    assert_eq!(retried.status, JobStatus::Pending);
    assert_eq!(retried.retry_count, 0);
    assert!(retried.last_error.is_none());
    assert_eq!(
        retried.run_at_or_after_unix_microseconds,
        4_102_444_800_000_000
    );

    let running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.requeue",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue running job");
    claim_exact_jobs(&queue, &test_database, &["task.requeue"], 1, "worker-b")
        .await
        .expect("claim running job");
    queue
        .force_requeue_running_job_by_id(&test_database.paranoid_pool, running.job_id)
        .await
        .expect("force requeue running job");
    let requeued = queue
        .fetch_job_by_id(&test_database.paranoid_pool, running.job_id)
        .await
        .expect("fetch force requeued job");
    assert_eq!(requeued.status, JobStatus::Pending);
    assert!(requeued.worker_owner_id.is_none());
    assert!(requeued.claimed_by_worker_at_unix_microseconds.is_none());

    let pending_error = queue
        .force_requeue_running_job_by_id(&test_database.paranoid_pool, running.job_id)
        .await
        .expect_err("pending job is not running");
    assert!(matches!(pending_error, Error::JobNotRunning));
    let missing_error = queue
        .force_requeue_running_job_by_id(
            &test_database.paranoid_pool,
            crate::queue::JobId::new().expect("unknown id"),
        )
        .await
        .expect_err("unknown job is missing");
    assert!(matches!(missing_error, Error::JobNotFound));

    let failed_batch_one = fail_new_job(&queue, &test_database, "task.batch", 4, "worker-c").await;
    let failed_batch_two = fail_new_job(&queue, &test_database, "task.batch", 5, "worker-c").await;
    let retried_count = queue
        .retry_available_failed_jobs(&test_database.paranoid_pool, Some("task.batch"), 1, None)
        .await
        .expect("retry one failed batch job");
    assert_eq!(retried_count, 1);
    let statuses = [
        queue
            .fetch_job_status(&test_database.paranoid_pool, failed_batch_one)
            .await
            .expect("fetch batch status one"),
        queue
            .fetch_job_status(&test_database.paranoid_pool, failed_batch_two)
            .await
            .expect("fetch batch status two"),
    ];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == JobStatus::Pending)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == JobStatus::Failed)
            .count(),
        1
    );

    let duplicate_failed_one = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.batch.dedupe",
            &TestPayload { value: 6 },
            EnqueueOptions {
                dedupe_key: Some("batch-duplicate-dedupe".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue first duplicate failed job");
    let worker_dedupe_a_owner_id = new_manual_worker_owner_id("worker-dedupe-a");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.batch.dedupe"],
        1,
        &worker_dedupe_a_owner_id,
    )
    .await
    .expect("claim first duplicate failed job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            duplicate_failed_one.job_id,
            &worker_dedupe_a_owner_id,
            "duplicate failure one",
            false,
        )
        .await
        .expect("fail first duplicate job");
    let duplicate_failed_two = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.batch.dedupe",
            &TestPayload { value: 7 },
            EnqueueOptions {
                dedupe_key: Some("batch-duplicate-dedupe".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue second duplicate failed job");
    let worker_dedupe_b_owner_id = new_manual_worker_owner_id("worker-dedupe-b");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.batch.dedupe"],
        1,
        &worker_dedupe_b_owner_id,
    )
    .await
    .expect("claim second duplicate failed job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            duplicate_failed_two.job_id,
            &worker_dedupe_b_owner_id,
            "duplicate failure two",
            false,
        )
        .await
        .expect("fail second duplicate job");

    let retried_duplicate_count = queue
        .retry_available_failed_jobs(
            &test_database.paranoid_pool,
            Some("task.batch.dedupe"),
            10,
            None,
        )
        .await
        .expect("retry one duplicate dedupe group member");
    assert_eq!(retried_duplicate_count, 1);
    let duplicate_status_one = queue
        .fetch_job_status(&test_database.paranoid_pool, duplicate_failed_one.job_id)
        .await
        .expect("fetch first duplicate status");
    let duplicate_status_two = queue
        .fetch_job_status(&test_database.paranoid_pool, duplicate_failed_two.job_id)
        .await
        .expect("fetch second duplicate status");
    assert_eq!(
        [duplicate_status_one, duplicate_status_two]
            .iter()
            .filter(|status| **status == JobStatus::Pending)
            .count(),
        1
    );
    assert_eq!(
        [duplicate_status_one, duplicate_status_two]
            .iter()
            .filter(|status| **status == JobStatus::Failed)
            .count(),
        1
    );
    let retry_duplicate_blocked_by_active = queue
        .retry_available_failed_jobs(
            &test_database.paranoid_pool,
            Some("task.batch.dedupe"),
            10,
            None,
        )
        .await
        .expect("active duplicate should make remaining failed duplicate ineligible");
    assert_eq!(retry_duplicate_blocked_by_active, 0);

    let (active_duplicate_job_id, remaining_failed_duplicate_job_id) =
        if duplicate_status_one == JobStatus::Pending {
            (duplicate_failed_one.job_id, duplicate_failed_two.job_id)
        } else {
            (duplicate_failed_two.job_id, duplicate_failed_one.job_id)
        };
    queue
        .cancel_pending_job(&test_database.paranoid_pool, active_duplicate_job_id)
        .await
        .expect("clear active duplicate dedupe blocker");
    let retry_duplicate_after_active_clear = queue
        .retry_available_failed_jobs(
            &test_database.paranoid_pool,
            Some("task.batch.dedupe"),
            10,
            None,
        )
        .await
        .expect("retry remaining duplicate after active blocker clears");
    assert_eq!(retry_duplicate_after_active_clear, 1);
    assert_eq!(
        queue
            .fetch_job_status(
                &test_database.paranoid_pool,
                remaining_failed_duplicate_job_id
            )
            .await
            .expect("remaining duplicate should become pending"),
        JobStatus::Pending
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_retry_and_dead_letter_requeue_preserve_unrelated_unique_violation_as_database_error()
{
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let failed_job = fail_new_job(
        &queue,
        &test_database,
        "task.retry.unrelated.unique",
        1,
        "worker-unique",
    )
    .await;
    let dead_letter_source_job = fail_new_job(
        &queue,
        &test_database,
        "task.requeue.unrelated.unique",
        2,
        "worker-unique",
    )
    .await;
    let dead_letter_job_id = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_source_job,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move source to dead letter");
    let _active_pending_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.active.unrelated.unique",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue active pending job");

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let unrelated_unique_index_name =
        PgIdentifier::new(format!("__queue_test_pending_once_{suffix}"))
            .expect("unique index name");
    let create_index_statement = format!(
        "CREATE UNIQUE INDEX {} ON {} (status) WHERE status = 'pending'",
        unrelated_unique_index_name.quoted(),
        test_database.config.table_name.quoted(),
    );
    sqlx::query(sqlx::AssertSqlSafe(create_index_statement.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("create unrelated unique index");

    let error = queue
        .retry_failed_job(&test_database.paranoid_pool, failed_job, None)
        .await
        .expect_err("unrelated unique index should block retry");
    assert!(
        matches!(error, Error::Database(_)),
        "queue error = {error:?}, want database error"
    );

    let error = queue
        .requeue_dead_letter_job(&test_database.paranoid_pool, dead_letter_job_id, None)
        .await
        .expect_err("unrelated unique index should block dead-letter requeue");
    assert!(
        matches!(error, Error::Database(_)),
        "queue error = {error:?}, want database error"
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_owned_worker_retry_dead_letter_and_return_paths_are_state_exact() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let retry_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.retry",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue retry job");
    let worker_transitions_owner_id = new_manual_worker_owner_id("worker-transitions");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.worker.retry"],
        1,
        &worker_transitions_owner_id,
    )
    .await
    .expect("claim retry job");
    let next_run_at = queue
        .begin_manual_worker_lifecycle()
        .schedule_owned_running_job_retry(
            &test_database.paranoid_pool,
            retry_job.job_id,
            &worker_transitions_owner_id,
            1,
            Duration::from_millis(25),
            "transient failure",
        )
        .await
        .expect("schedule owned retry");
    let retried = queue
        .fetch_job_by_id(&test_database.paranoid_pool, retry_job.job_id)
        .await
        .expect("fetch scheduled retry");
    assert_eq!(retried.status, JobStatus::Pending);
    assert_eq!(retried.retry_count, 1);
    assert_eq!(retried.run_at_or_after_unix_microseconds, next_run_at);
    assert_eq!(retried.last_error.as_deref(), Some("transient failure"));
    assert!(retried.worker_owner_id.is_none());
    assert!(retried.claimed_by_worker_at_unix_microseconds.is_none());

    let dead_letter_source = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.dead",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue owned dead-letter job");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.worker.dead"],
        1,
        &worker_transitions_owner_id,
    )
    .await
    .expect("claim owned dead-letter job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            dead_letter_source.job_id,
            &worker_transitions_owner_id,
        )
        .await
        .expect("start owned dead-letter job");
    let dead_letter_id = queue
        .begin_manual_worker_lifecycle()
        .move_owned_running_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_source.job_id,
            &worker_transitions_owner_id,
            "permanent failure",
            true,
            DeadLetterReason::PermanentError,
        )
        .await
        .expect("move owned running job to dead letter");
    let source_after_dead_letter = queue
        .fetch_job_by_id(&test_database.paranoid_pool, dead_letter_source.job_id)
        .await
        .expect_err("owned dead-lettered job should leave main table");
    assert!(matches!(source_after_dead_letter, Error::JobNotFound));
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list owned dead letter");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(dead_letters.jobs[0].id, dead_letter_id);
    assert_eq!(
        dead_letters.jobs[0].original_job_id,
        dead_letter_source.job_id
    );
    assert_eq!(dead_letters.jobs[0].last_error, "permanent failure");
    assert_eq!(dead_letters.jobs[0].retry_count, 1);

    let unstarted = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.return_unstarted",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue unstarted return job");
    let worker_return_owner_id = new_manual_worker_owner_id("worker-return");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.worker.return_unstarted"],
        1,
        &worker_return_owner_id,
    )
    .await
    .expect("claim unstarted return job");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_unstarted_running_job_to_pending(
            &test_database.paranoid_pool,
            unstarted.job_id,
            &worker_return_owner_id,
        )
        .await
        .expect("return unstarted job");
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, unstarted.job_id)
            .await
            .expect("fetch unstarted return status"),
        JobStatus::Pending
    );

    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.worker.return_unstarted"],
        1,
        &worker_return_owner_id,
    )
    .await
    .expect("claim started return job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            unstarted.job_id,
            &worker_return_owner_id,
        )
        .await
        .expect("start return job");
    let unstarted_return_error = queue
        .begin_manual_worker_lifecycle()
        .return_owned_unstarted_running_job_to_pending(
            &test_database.paranoid_pool,
            unstarted.job_id,
            &worker_return_owner_id,
        )
        .await
        .expect_err("started job should not match unstarted return");
    assert!(matches!(unstarted_return_error, Error::JobNotRunning));
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_started_running_job_to_pending(
            &test_database.paranoid_pool,
            unstarted.job_id,
            &worker_return_owner_id,
        )
        .await
        .expect("return started job");

    let bulk_unstarted = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.bulk_return",
            &TestPayload { value: 4 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue bulk unstarted");
    let bulk_started = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.bulk_return",
            &TestPayload { value: 5 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue bulk started");
    let worker_bulk_return_owner_id = new_manual_worker_owner_id("worker-bulk-return");
    let claimed_bulk = claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.worker.bulk_return"],
        2,
        &worker_bulk_return_owner_id,
    )
    .await
    .expect("claim bulk return jobs");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            claimed_bulk[0].id,
            &worker_bulk_return_owner_id,
        )
        .await
        .expect("start one bulk return job");
    let returned_unstarted_count = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_unstarted_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &worker_bulk_return_owner_id,
        )
        .await
        .expect("return available unstarted");
    assert_eq!(returned_unstarted_count, 1);
    let returned_started_count = queue
        .begin_manual_worker_lifecycle()
        .return_available_owned_started_running_jobs_to_pending(
            &test_database.paranoid_pool,
            &worker_bulk_return_owner_id,
        )
        .await
        .expect("return available started");
    assert_eq!(returned_started_count, 1);
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, bulk_unstarted.job_id)
            .await
            .expect("fetch bulk unstarted status"),
        JobStatus::Pending
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, bulk_started.job_id)
            .await
            .expect("fetch bulk started status"),
        JobStatus::Pending
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
