use super::*;

#[tokio::test]
async fn queue_enqueue_deduplicates_active_jobs_and_allows_new_after_terminal_state() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let options = EnqueueOptions {
        dedupe_key: Some("same-active-work".to_owned()),
        ..EnqueueOptions::default()
    };
    let first = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 1 },
            options.clone(),
        )
        .await
        .expect("first enqueue");
    let second = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 2 },
            options.clone(),
        )
        .await
        .expect("dedupe enqueue");
    assert_eq!(second.job_id, first.job_id);
    assert!(second.deduplicated);

    let worker_a_owner_id = new_manual_worker_owner_id("worker-a");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &["task.alpha".to_owned()],
            1,
            &worker_a_owner_id,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            first.job_id,
            &worker_a_owner_id,
        )
        .await
        .expect("complete job");

    let third = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 3 },
            options,
        )
        .await
        .expect("enqueue after terminal state");
    assert_ne!(third.job_id, first.job_id);
    assert!(!third.deduplicated);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_dedupe_enqueue_retries_after_conflicting_transaction_commits() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let options = EnqueueOptions {
        dedupe_key: Some("same-uncommitted-work".to_owned()),
        ..EnqueueOptions::default()
    };
    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin blocking transaction");
    let uncommitted = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.dedupe.uncommitted",
            &TestPayload { value: 1 },
            options.clone(),
        )
        .await
        .expect("enqueue uncommitted dedupe job");

    let (started_tx, started_rx) = oneshot::channel();
    let queue_for_task = queue.clone();
    let pool_for_task = test_database.paranoid_pool.clone();
    let options_for_task = options.clone();
    let enqueue_handle = tokio::spawn(async move {
        started_tx
            .send(())
            .expect("send concurrent enqueue started");
        queue_for_task
            .enqueue_json(
                &pool_for_task,
                "task.dedupe.uncommitted",
                &TestPayload { value: 2 },
                options_for_task,
            )
            .await
    });
    started_rx.await.expect("concurrent enqueue started");
    tokio::time::sleep(Duration::from_millis(50)).await;

    tx.commit().await.expect("commit conflicting dedupe job");
    let deduplicated = enqueue_handle
        .await
        .expect("join concurrent enqueue")
        .expect("concurrent enqueue should retry after conflict commit");
    assert_eq!(deduplicated.job_id, uncommitted.job_id);
    assert!(deduplicated.deduplicated);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_batch_enqueue_inserts_all_jobs_in_one_pause_gated_operation() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let empty_results = queue
        .enqueue_json_batch::<TestPayload>(
            &test_database.paranoid_pool,
            "task.batch",
            &[],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("empty batch enqueue");
    assert!(empty_results.is_empty());

    let run_at_or_after_unix_microseconds = 1_900_000_000_000_000;
    let results = queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.batch",
            &[
                TestPayload { value: 10 },
                TestPayload { value: 11 },
                TestPayload { value: 12 },
            ],
            EnqueueBatchOptions {
                run_at_or_after: Some(
                    JobRunAtOrAfter::from_unix_microseconds(run_at_or_after_unix_microseconds)
                        .expect("scheduled run time"),
                ),
                max_retries: Some(2),
                timeout: JobTimeout::ExpiresAfter(Duration::from_secs(7)),
            },
        )
        .await
        .expect("batch enqueue");
    assert_eq!(results.len(), 3);
    assert!(results.iter().all(|result| !result.deduplicated));
    assert_eq!(
        results
            .iter()
            .map(|result| result.job_id)
            .collect::<HashSet<_>>()
            .len(),
        3
    );

    for (index, result) in results.iter().enumerate() {
        let job = queue
            .fetch_job_by_id(&test_database.paranoid_pool, result.job_id)
            .await
            .expect("fetch batch job");
        assert_eq!(job.task_name, "task.batch");
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(
            job.run_at_or_after_unix_microseconds,
            run_at_or_after_unix_microseconds
        );
        assert_eq!(job.max_retries, 2);
        assert_eq!(
            job.timeout,
            JobTimeout::ExpiresAfter(Duration::from_secs(7))
        );
        assert_eq!(job.dedupe_key, None);
        assert_payload_json_value(&job.payload_json, 10 + index as i32);
    }

    queue
        .pause_task(&test_database.paranoid_pool, "task.batch")
        .await
        .expect("pause task");
    let task_pause_error = queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.batch",
            &[TestPayload { value: 13 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect_err("task pause should block batch enqueue");
    assert!(matches!(task_pause_error, Error::TaskPaused));
    queue
        .resume_task(&test_database.paranoid_pool, "task.batch")
        .await
        .expect("resume task");

    queue
        .pause_queue(&test_database.paranoid_pool)
        .await
        .expect("pause queue");
    let queue_pause_error = queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.batch",
            &[TestPayload { value: 14 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect_err("queue pause should block batch enqueue");
    assert!(matches!(queue_pause_error, Error::QueuePaused));

    let pending_count = queue
        .fetch_pending_job_count(&test_database.paranoid_pool, Some("task.batch"))
        .await
        .expect("pending count");
    assert_eq!(pending_count, 3);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_pause_blocks_enqueue_and_claim_without_races_in_the_operation_query() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    queue
        .pause_task(&test_database.paranoid_pool, "task.alpha")
        .await
        .expect("pause task");
    let enqueue_error = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect_err("task pause should block enqueue");
    assert!(matches!(enqueue_error, Error::TaskPaused));
    queue
        .resume_task(&test_database.paranoid_pool, "task.alpha")
        .await
        .expect("resume task");

    queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue after resume");
    queue
        .pause_queue(&test_database.paranoid_pool)
        .await
        .expect("pause queue");
    let worker_a_owner_id = new_manual_worker_owner_id("worker-a");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &["task.alpha".to_owned()],
            10,
            &worker_a_owner_id,
        )
        .await
        .expect("claim while globally paused");
    assert!(claimed.is_empty());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_claim_with_no_registered_tasks_returns_empty_without_touching_schema() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let worker_empty_registry_owner_id = new_manual_worker_owner_id("worker-empty-registry");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &[],
            1,
            &worker_empty_registry_owner_id,
        )
        .await
        .expect("empty registered task set should short-circuit");
    assert!(claimed.is_empty());
}

#[tokio::test]
async fn queue_claim_and_owned_transitions_enforce_worker_ownership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let future_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 1 },
            EnqueueOptions {
                run_at_or_after: Some(
                    JobRunAtOrAfter::from_unix_microseconds(4_102_444_800_000_000)
                        .expect("scheduled run time"),
                ),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("future enqueue");
    let due_job = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 2 },
            EnqueueOptions {
                timeout: JobTimeout::ExpiresAfter(Duration::from_secs(30)),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("due enqueue");

    let worker_a_owner_id = new_manual_worker_owner_id("worker-a");
    let worker_b_owner_id = new_manual_worker_owner_id("worker-b");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &["task.alpha".to_owned()],
            10,
            &worker_a_owner_id,
        )
        .await
        .expect("claim due jobs");
    assert_eq!(
        claimed.iter().map(|job| job.id).collect::<Vec<_>>(),
        vec![due_job.job_id]
    );
    assert_eq!(claimed[0].status, JobStatus::Running);
    assert_eq!(
        worker_owner_id_text(claimed[0].worker_owner_id.as_ref()),
        Some("worker-a")
    );
    assert_eq!(
        claimed[0].timeout,
        JobTimeout::ExpiresAfter(Duration::from_secs(30))
    );

    let wrong_worker_error = queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            due_job.job_id,
            &worker_b_owner_id,
        )
        .await
        .expect_err("wrong worker should not start job");
    assert!(matches!(wrong_worker_error, Error::JobNotRunning));

    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            due_job.job_id,
            &worker_a_owner_id,
        )
        .await
        .expect("start job");
    queue
        .begin_manual_worker_lifecycle()
        .touch_owned_running_job_execution_heartbeat(
            &test_database.paranoid_pool,
            due_job.job_id,
            &worker_a_owner_id,
        )
        .await
        .expect("heartbeat job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            due_job.job_id,
            &worker_a_owner_id,
            "boom",
            true,
        )
        .await
        .expect("fail job");
    let failed_job = queue
        .fetch_job_by_id(&test_database.paranoid_pool, due_job.job_id)
        .await
        .expect("fetch failed job");
    assert_eq!(failed_job.status, JobStatus::Failed);
    assert_eq!(failed_job.retry_count, 1);
    assert_eq!(failed_job.last_error.as_deref(), Some("boom"));
    assert!(failed_job.worker_owner_id.is_none());

    let future_loaded = queue
        .fetch_job_by_id(&test_database.paranoid_pool, future_job.job_id)
        .await
        .expect("fetch future job");
    assert_eq!(future_loaded.status, JobStatus::Pending);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_database_constraints_reject_invalid_lifecycle_and_pause_shapes() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    reset_queue_schema(&test_database).await;

    let invalid_job_insert = format!(
        r#"
        INSERT INTO {} (
            id, task_name, payload, status, run_at_or_after,
            worker_id, claimed_by_worker_at, execution_heartbeat_at,
            created_at, updated_at
        )
        VALUES (
            decode(repeat('00', 16), 'hex'),
            'task.alpha',
            '{{}}'::jsonb,
            'pending',
            statement_timestamp(),
            'worker-a',
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        test_database.config.table_name.quoted()
    );
    assert!(
        sqlx::query(sqlx::AssertSqlSafe(invalid_job_insert.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .is_err(),
        "pending jobs must not carry running ownership fields"
    );

    let invalid_running_insert = format!(
        r#"
        INSERT INTO {} (
            id, task_name, payload, status, run_at_or_after,
            created_at, updated_at
        )
        VALUES (
            decode(repeat('01', 16), 'hex'),
            'task.alpha',
            '{{}}'::jsonb,
            'running',
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        test_database.config.table_name.quoted()
    );
    assert!(
        sqlx::query(sqlx::AssertSqlSafe(invalid_running_insert.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .is_err(),
        "running jobs must carry worker ownership fields"
    );

    let invalid_failed_insert = format!(
        r#"
        INSERT INTO {} (
            id, task_name, payload, status, run_at_or_after,
            worker_id, claimed_by_worker_at, created_at, updated_at
        )
        VALUES (
            decode(repeat('02', 16), 'hex'),
            'task.alpha',
            '{{}}'::jsonb,
            'failed',
            statement_timestamp(),
            'worker-a',
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        test_database.config.table_name.quoted()
    );
    assert!(
        sqlx::query(sqlx::AssertSqlSafe(invalid_failed_insert.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .is_err(),
        "failed jobs must be terminal and must not carry worker ownership fields"
    );

    let invalid_pause_insert = format!(
        r#"
        INSERT INTO {} (key, task_name, paused_at, updated_at)
        VALUES ('task:task.alpha', 'task.beta', statement_timestamp(), statement_timestamp())
        "#,
        test_database.config.pause_table_name.quoted()
    );
    assert!(
        sqlx::query(sqlx::AssertSqlSafe(invalid_pause_insert.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .is_err(),
        "task pause key and task_name must match"
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
