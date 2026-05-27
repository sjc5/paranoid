use super::*;

#[tokio::test]
async fn queue_registered_json_task_handle_binds_task_name_for_enqueue_and_worker_processing() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let (processed_tx, mut processed_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    let typed_task = queue
        .register_json_task_handler(
            &mut registry,
            "task.typed_handle",
            move |_context, payload: TestPayload| {
                let processed_tx = processed_tx.clone();
                async move {
                    processed_tx
                        .send(payload.value)
                        .expect("record typed task payload");
                    Ok(())
                }
            },
        )
        .expect("register typed task handle");
    assert_eq!(typed_task.task_name(), "task.typed_handle");

    typed_task
        .enqueue(
            &test_database.paranoid_pool,
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue typed task payload");
    typed_task
        .enqueue_batch(
            &test_database.paranoid_pool,
            &[TestPayload { value: 2 }, TestPayload { value: 3 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("enqueue typed task payload batch");

    let summary = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "typed-task-worker",
            WorkerConfig {
                concurrency: 3,
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect("process typed task jobs");
    assert_eq!(summary.claimed_count, 3);
    assert_eq!(summary.succeeded_count, 3);

    let mut processed_values = Vec::new();
    for _ in 0..3 {
        processed_values.push(
            tokio::time::timeout(Duration::from_secs(1), processed_rx.recv())
                .await
                .expect("typed task handler should run")
                .expect("processed channel should stay open"),
        );
    }
    processed_values.sort_unstable();
    assert_eq!(processed_values, vec![1, 2, 3]);

    let counts = queue
        .fetch_status_counts(&test_database.paranoid_pool, Some("task.typed_handle"))
        .await
        .expect("fetch typed task counts");
    assert_eq!(counts.completed_count, 3);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_active_dedupe_is_single_winner_under_contention() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Arc::new(Store::new(test_database.config.clone()).expect("queue"));
    let pool = Arc::new(test_database.paranoid_pool.clone());
    reset_queue_schema(&test_database).await;

    let mut tasks = JoinSet::new();
    for index in 0..24 {
        let queue = Arc::clone(&queue);
        let pool = Arc::clone(&pool);
        tasks.spawn(async move {
            queue
                .enqueue_json(
                    &pool,
                    "task.alpha",
                    &TestPayload { value: index },
                    EnqueueOptions {
                        dedupe_key: Some("same-work".to_owned()),
                        ..EnqueueOptions::default()
                    },
                )
                .await
                .expect("contended dedupe enqueue")
        });
    }

    let mut ids = HashSet::new();
    let mut inserted_count = 0;
    let mut deduplicated_count = 0;
    while let Some(result) = tasks.join_next().await {
        let result = result.expect("join contended enqueue");
        ids.insert(result.job_id);
        if result.deduplicated {
            deduplicated_count += 1;
        } else {
            inserted_count += 1;
        }
    }

    assert_eq!(ids.len(), 1);
    assert_eq!(inserted_count, 1);
    assert_eq!(deduplicated_count, 23);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_enqueue_classifies_suppressed_insert_rows_without_losing_control_flow() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_enqueue_suppressed_insert_trigger(&test_database).await;

    let single_error = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.enqueue.suppressed_single",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect_err("suppressed single insert should be classified");
    assert!(matches!(
        single_error,
        Error::UnexpectedOutcome {
            operation: "enqueue",
            ref outcome,
        } if outcome == "not_inserted"
    ));

    let dedupe_error = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.enqueue.suppressed_dedupe",
            &TestPayload { value: 2 },
            EnqueueOptions {
                dedupe_key: Some("suppressed".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect_err("suppressed dedupe insert should retry and then fail closed");
    assert!(matches!(
        dedupe_error,
        Error::UnexpectedOutcome {
            operation: "dedupe enqueue",
            ref outcome,
        } if outcome == "not inserted without existing active job"
    ));

    let single_count = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.enqueue.suppressed_single"),
        )
        .await
        .expect("fetch suppressed single counts");
    assert_eq!(single_count.total_count(), 0);
    let dedupe_count = queue
        .fetch_status_counts(
            &test_database.paranoid_pool,
            Some("task.enqueue.suppressed_dedupe"),
        )
        .await
        .expect("fetch suppressed dedupe counts");
    assert_eq!(dedupe_count.total_count(), 0);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_status_counts_track_core_lifecycle_states() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let pending = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("pending enqueue");
    let running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 2 },
            EnqueueOptions {
                run_at_or_after: Some(
                    JobRunAtOrAfter::from_unix_microseconds(0).expect("scheduled run time"),
                ),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("running enqueue");
    let completed = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.beta",
            &TestPayload { value: 3 },
            EnqueueOptions {
                run_at_or_after: Some(
                    JobRunAtOrAfter::from_unix_microseconds(0).expect("scheduled run time"),
                ),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("completed enqueue");

    let worker_a_owner_id = new_manual_worker_owner_id("worker-a");
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &["task.beta".to_owned(), "task.alpha".to_owned()],
            2,
            &worker_a_owner_id,
        )
        .await
        .expect("claim two jobs");
    assert_eq!(claimed.len(), 2);
    for job in claimed {
        if job.id == completed.job_id {
            queue
                .begin_manual_worker_lifecycle()
                .mark_owned_running_job_completed(
                    &test_database.paranoid_pool,
                    job.id,
                    &worker_a_owner_id,
                )
                .await
                .expect("complete job");
        } else if job.id == running.job_id {
            queue
                .begin_manual_worker_lifecycle()
                .mark_owned_running_job_failed(
                    &test_database.paranoid_pool,
                    job.id,
                    &worker_a_owner_id,
                    "boom",
                    false,
                )
                .await
                .expect("fail job");
        }
    }

    let all_counts = queue
        .fetch_status_counts(&test_database.paranoid_pool, None)
        .await
        .expect("fetch all status counts");
    assert_eq!(all_counts.pending_count, 1);
    assert_eq!(all_counts.running_count, 0);
    assert_eq!(all_counts.completed_count, 1);
    assert_eq!(all_counts.failed_count, 1);
    assert_eq!(all_counts.dead_letter_count, 0);
    assert_eq!(all_counts.total_count(), 3);

    let alpha_counts = queue
        .fetch_status_counts(&test_database.paranoid_pool, Some("task.alpha"))
        .await
        .expect("fetch task status counts");
    assert_eq!(alpha_counts.pending_count, 1);
    assert_eq!(alpha_counts.failed_count, 1);
    assert_eq!(alpha_counts.completed_count, 0);

    let pending_count = queue
        .fetch_pending_job_count(&test_database.paranoid_pool, None)
        .await
        .expect("fetch pending count");
    assert_eq!(pending_count, 1);
    let failed_alpha_count = queue
        .fetch_failed_job_count(&test_database.paranoid_pool, Some("task.alpha"))
        .await
        .expect("fetch task failed count");
    assert_eq!(failed_alpha_count, 1);

    let pending_job = queue
        .fetch_job_by_id(&test_database.paranoid_pool, pending.job_id)
        .await
        .expect("fetch still-pending job");
    assert_eq!(pending_job.status, JobStatus::Pending);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

async fn install_enqueue_suppressed_insert_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function =
        PgIdentifier::new(format!("qesi_suppress_{suffix}")).expect("suppress function name");
    let trigger =
        PgIdentifier::new(format!("qesi_suppress_t_{suffix}")).expect("suppress trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.task_name IN (
                    'task.enqueue.suppressed_single',
                    'task.enqueue.suppressed_dedupe'
                ) THEN
                    RETURN NULL;
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            function.quoted()
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE INSERT ON {}
            FOR EACH ROW
            EXECUTE FUNCTION {}()
            "#,
            trigger.quoted(),
            test_database.config.table_name.quoted(),
            function.quoted()
        ),
    ];

    for statement in statements {
        sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .expect("install enqueue suppressed insert trigger");
    }
}

#[tokio::test]
async fn queue_worker_pressure_and_task_introspection_follow_registered_handler_state() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue registered pending job");
    queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.alpha",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue registered running job");
    queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "orphan_task",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue orphaned pending job");
    let completed_orphan = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "completed_orphan",
            &TestPayload { value: 4 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue completed orphan");

    let worker_pressure_owner_id = new_manual_worker_owner_id("worker-pressure");
    let claimed_registered_jobs = claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["task.alpha"],
        1,
        &worker_pressure_owner_id,
    )
    .await
    .expect("claim registered job");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(
            &test_database.paranoid_pool,
            claimed_registered_jobs[0].id,
            &worker_pressure_owner_id,
        )
        .await
        .expect("start running job");
    claim_exact_jobs_with_worker_owner_id(
        &queue,
        &test_database,
        &["completed_orphan"],
        1,
        &worker_pressure_owner_id,
    )
    .await
    .expect("claim completed orphan");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            completed_orphan.job_id,
            &worker_pressure_owner_id,
        )
        .await
        .expect("complete orphaned task job");

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.alpha", |_context, _payload: TestPayload| async {
            Ok(())
        })
        .expect("register task alpha");
    registry
        .register_json_task_handler("task.beta", |_context, _payload: TestPayload| async {
            Ok(())
        })
        .expect("register task beta");
    assert_eq!(
        registry.registered_task_names(),
        vec!["task.alpha".to_owned(), "task.beta".to_owned()]
    );
    assert_eq!(registry.registered_task_count(), 2);

    queue
        .pause_queue(&test_database.paranoid_pool)
        .await
        .expect("pause queue");
    queue
        .pause_task(&test_database.paranoid_pool, "task.beta")
        .await
        .expect("pause task beta");
    assert!(
        queue
            .fetch_queue_is_paused(&test_database.paranoid_pool)
            .await
            .expect("fetch queue pause state")
    );
    assert!(
        queue
            .fetch_task_is_paused(&test_database.paranoid_pool, "task.beta")
            .await
            .expect("fetch task pause state")
    );

    let paused_task_names = queue
        .fetch_paused_task_names(&test_database.paranoid_pool)
        .await
        .expect("fetch paused task names");
    assert_eq!(paused_task_names, vec!["task.beta"]);

    let orphaned_task_names = queue
        .fetch_orphaned_task_names(&test_database.paranoid_pool, &registry)
        .await
        .expect("fetch orphaned task names");
    assert_eq!(orphaned_task_names, vec!["orphan_task"]);

    let pressure = queue
        .fetch_worker_pressure(&test_database.paranoid_pool, &registry)
        .await
        .expect("fetch worker pressure");
    assert!(pressure.queue_paused);
    assert_eq!(pressure.paused_task_names, vec!["task.beta"]);
    assert_eq!(pressure.registered_task_count, 2);
    assert_eq!(pressure.pending_job_count, 2);
    assert_eq!(pressure.running_job_count, 1);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_observability_methods_report_missing_backing_tables() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let registry = TaskRegistry::new();

    reset_queue_schema(&test_database).await;
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
    )
    .await;
    let status_error = queue
        .fetch_status_counts(&test_database.paranoid_pool, None)
        .await
        .expect_err("missing dead-letter table should fail status counts");
    assert!(matches!(status_error, Error::Database(_)));

    reset_queue_schema(&test_database).await;
    let failed_job = fail_new_job(
        &queue,
        &test_database,
        "task.missing_dead_letter",
        40,
        "worker-missing-dead-letter",
    )
    .await;
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
    )
    .await;
    let move_dead_letter_error = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            failed_job,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect_err("missing dead-letter table should fail move");
    assert!(matches!(move_dead_letter_error, Error::Database(_)));

    reset_queue_schema(&test_database).await;
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.pause_table_name,
    )
    .await;
    let paused_tasks_error = queue
        .fetch_paused_task_names(&test_database.paranoid_pool)
        .await
        .expect_err("missing pause table should fail paused task listing");
    assert!(matches!(paused_tasks_error, Error::Database(_)));
    let pause_queue_error = queue
        .pause_queue(&test_database.paranoid_pool)
        .await
        .expect_err("missing pause table should fail global pause");
    assert!(matches!(pause_queue_error, Error::Database(_)));
    let resume_queue_error = queue
        .resume_queue(&test_database.paranoid_pool)
        .await
        .expect_err("missing pause table should fail global resume");
    assert!(matches!(resume_queue_error, Error::Database(_)));
    let pause_task_error = queue
        .pause_task(&test_database.paranoid_pool, "task.missing_pause")
        .await
        .expect_err("missing pause table should fail task pause");
    assert!(matches!(pause_task_error, Error::Database(_)));
    let resume_task_error = queue
        .resume_task(&test_database.paranoid_pool, "task.missing_pause")
        .await
        .expect_err("missing pause table should fail task resume");
    assert!(matches!(resume_task_error, Error::Database(_)));
    let worker_pressure_error = queue
        .fetch_worker_pressure(&test_database.paranoid_pool, &registry)
        .await
        .expect_err("missing pause table should fail worker pressure");
    assert!(matches!(worker_pressure_error, Error::Database(_)));

    reset_queue_schema(&test_database).await;
    let job_id_before_drop = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.missing_jobs",
            &TestPayload { value: 41 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue job before dropping jobs table")
        .job_id;
    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    let single_enqueue_error = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.missing_jobs",
            &TestPayload { value: 42 },
            EnqueueOptions::default(),
        )
        .await
        .expect_err("missing jobs table should fail single enqueue");
    assert!(matches!(single_enqueue_error, Error::Database(_)));
    let dedupe_enqueue_error = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.missing_jobs",
            &TestPayload { value: 43 },
            EnqueueOptions {
                dedupe_key: Some("same".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect_err("missing jobs table should fail dedupe enqueue");
    assert!(matches!(dedupe_enqueue_error, Error::Database(_)));
    let batch_enqueue_error = queue
        .enqueue_json_batch(
            &test_database.paranoid_pool,
            "task.missing_jobs",
            &[TestPayload { value: 44 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect_err("missing jobs table should fail batch enqueue");
    assert!(matches!(batch_enqueue_error, Error::Database(_)));
    let fetch_job_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, job_id_before_drop)
        .await
        .expect_err("missing jobs table should fail job fetch");
    assert!(matches!(fetch_job_error, Error::Database(_)));
    let pending_count_error = queue
        .fetch_pending_job_count(&test_database.paranoid_pool, None)
        .await
        .expect_err("missing jobs table should fail pending count");
    assert!(matches!(pending_count_error, Error::Database(_)));
    let orphaned_tasks_error = queue
        .fetch_orphaned_task_names(&test_database.paranoid_pool, &registry)
        .await
        .expect_err("missing jobs table should fail orphaned task listing");
    assert!(matches!(orphaned_tasks_error, Error::Database(_)));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
