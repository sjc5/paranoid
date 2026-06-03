use super::*;
use proptest::prelude::*;

fn valid_queue_task_name_strategy() -> impl Strategy<Value = String> {
    let first_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        .chars()
        .collect::<Vec<_>>();
    let trailing_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        .chars()
        .collect::<Vec<_>>();

    (
        prop::sample::select(first_chars),
        prop::collection::vec(
            prop::sample::select(trailing_chars),
            0..MAX_QUEUE_TASK_NAME_BYTES.min(64),
        ),
    )
        .prop_map(|(first, trailing)| {
            let mut task_name = String::with_capacity(1 + trailing.len());
            task_name.push(first);
            task_name.extend(trailing);
            task_name
        })
}

fn invalid_queue_task_name_strategy() -> impl Strategy<Value = String> {
    let invalid_first_chars = ".- /:\0é".chars().collect::<Vec<_>>();
    let invalid_trailing_chars = " /:\0é".chars().collect::<Vec<_>>();

    prop_oneof![
        Just(String::new()),
        prop::sample::select(invalid_first_chars).prop_map(|first| first.to_string()),
        (
            valid_queue_task_name_strategy(),
            prop::sample::select(invalid_trailing_chars)
        )
            .prop_map(|(mut task_name, invalid)| {
                task_name.push(invalid);
                task_name
            }),
        Just("a".repeat(MAX_QUEUE_TASK_NAME_BYTES + 1)),
    ]
}

#[test]
fn queue_migration_sql_uses_bytea_ids_and_c_collation_for_correctness_text() {
    let config = default_queue_config_for_sql_tests();
    let migration_sql = build_queue_schema_migration_statements(&config).join("\n");

    for expected_fragment in [
        "id BYTEA PRIMARY KEY CHECK",
        "original_job_id BYTEA NOT NULL CHECK",
        r#"task_name TEXT COLLATE "C" NOT NULL"#,
        r#"status TEXT COLLATE "C" NOT NULL"#,
        r#"last_error TEXT COLLATE "C""#,
        r#"dedupe_key TEXT COLLATE "C""#,
        r#"worker_id TEXT COLLATE "C""#,
        r#"reason TEXT COLLATE "C" NOT NULL"#,
        r#"key TEXT COLLATE "C" PRIMARY KEY"#,
        r#"task_name TEXT COLLATE "C""#,
    ] {
        assert!(
            migration_sql.contains(expected_fragment),
            "queue migration SQL missing {expected_fragment:?}"
        );
    }

    assert!(
        !migration_sql.contains(" id TEXT"),
        "queue migration must not store job IDs as text"
    );
    assert!(
        !migration_sql.contains("original_job_id TEXT"),
        "queue migration must not store original job IDs as text"
    );
    assert!(
        !migration_sql.contains(r#"COLLATE "default""#),
        "queue migration must not use default collation for internal text"
    );

    for expected_fragment in [
        "(status, run_at_or_after, id) WHERE status = 'pending'",
        "(task_name, run_at_or_after, id) WHERE status = 'pending'",
        "(status, execution_heartbeat_at, id) WHERE status = 'running' AND execution_heartbeat_at IS NOT NULL",
        "(finished_at, id) WHERE status IN ('completed', 'failed') AND finished_at IS NOT NULL",
        "(dead_lettered_at, id)",
        "(task_name, dead_lettered_at, id)",
    ] {
        assert!(
            migration_sql.contains(expected_fragment),
            "queue migration SQL missing ordered candidate index {expected_fragment:?}"
        );
    }
}

#[test]
fn queue_public_primitives_are_available_through_namespaced_modules() {
    let _: Duration = crate::queue::DEFAULT_COMPLETED_JOB_RETENTION;
    let _: Duration = crate::queue::DEFAULT_CLEANUP_BATCH_DELAY;
    let _: Duration = crate::queue::DEFAULT_WORKER_DATABASE_OPERATION_TIMEOUT;
    let _: u32 = crate::queue::MAX_ENQUEUE_BATCH_SIZE;
    let _: usize = crate::queue::DEFAULT_PAYLOAD_JSON_LIMIT_BYTES;
    let _: usize = crate::queue::MAX_PAYLOAD_JSON_LIMIT_BYTES;
    let _: i64 = crate::queue::MAX_RUN_AT_OR_AFTER_UNIX_MICROSECONDS;
    let _: usize = crate::queue::MAX_WORKER_OWNER_ID_BYTES;
    let _: Option<crate::queue::WorkerOwnerId> = None;
    let _: Option<crate::queue::manual::ManualWorkerProtocol<'static>> = None;
    let _: Option<crate::queue::EnqueueBatchOptions> = None;
    let _: Option<crate::queue::JobRunAtOrAfter> = None;
    let _: Option<crate::queue::MoveFailedJobsToDeadLetterBatchResult> = None;
    let _: Option<crate::kv::Store> = None;
    let _: Option<crate::db::fleet::StoreConfig> = None;
    let _: Option<crate::fleet::CoalescingCacheConfig> = None;
    let _: Option<crate::fleet::CoalescingCache<String>> = None;
    let _: Option<crate::fleet::CoalescingCacheFetchError<Error>> = None;
    let _: Option<crate::fleet::Cron> = None;
    let _: Option<crate::fleet::CronConfig> = None;
    let _: Option<crate::fleet::CronRunHandle<std::io::Error>> = None;
    let _: fn(
        &crate::fleet::Store,
        crate::fleet::CronConfig,
    ) -> Result<crate::fleet::Cron, crate::fleet::Error> = crate::fleet::Store::new_cron;
    let _: Option<crate::fleet::TopicConfig> = None;
    let _: Option<crate::fleet::Topic<String>> = None;
    let _: Option<crate::fleet::SubscriptionConfig> = None;
    let _: Option<crate::fleet::Subscription<String>> = None;
    let _: Option<crate::queue::RegisteredJsonTask<String>> = None;

    async fn exercise_queue_public_method_surface(
        queue: crate::queue::Store,
        pool: &crate::db::WritePool,
        tx: &mut crate::db::WriteTx<'_>,
        fleet_store: crate::fleet::Store,
        registry: &crate::queue::TaskRegistry,
        job_id: crate::queue::JobId,
    ) -> Result<(), crate::queue::Error> {
        queue.migrate_schema(pool).await?;
        queue.migrate_schema_in_current_transaction(tx).await?;
        queue.validate_schema(pool).await?;
        queue.validate_schema_in_current_transaction(tx).await?;

        let payload = "payload".to_owned();
        queue
            .enqueue_json(
                pool,
                "task.public",
                &payload,
                crate::queue::EnqueueOptions::default(),
            )
            .await?;
        queue
            .enqueue_json_in_current_transaction(
                tx,
                "task.public",
                &payload,
                crate::queue::EnqueueOptions::default(),
            )
            .await?;
        queue
            .enqueue_json_batch(
                pool,
                "task.public",
                std::slice::from_ref(&payload),
                crate::queue::EnqueueBatchOptions::default(),
            )
            .await?;
        queue
            .enqueue_json_batch_in_current_transaction(
                tx,
                "task.public",
                &[payload],
                crate::queue::EnqueueBatchOptions::default(),
            )
            .await?;

        queue.fetch_job_by_id(pool, job_id).await?;
        queue
            .fetch_job_by_id_in_current_transaction(tx, job_id)
            .await?;
        queue.fetch_job_status(pool, job_id).await?;
        queue
            .fetch_job_status_in_current_transaction(tx, job_id)
            .await?;
        queue.fetch_status_counts(pool, Some("task.public")).await?;
        queue
            .fetch_status_counts_in_current_transaction(tx, Some("task.public"))
            .await?;
        queue
            .fetch_pending_job_count(pool, Some("task.public"))
            .await?;
        queue
            .fetch_pending_job_count_in_current_transaction(tx, Some("task.public"))
            .await?;
        queue
            .fetch_failed_job_count(pool, Some("task.public"))
            .await?;
        queue
            .fetch_failed_job_count_in_current_transaction(tx, Some("task.public"))
            .await?;

        queue.pause_queue(pool).await?;
        queue.pause_queue_in_current_transaction(tx).await?;
        queue.resume_queue(pool).await?;
        queue.resume_queue_in_current_transaction(tx).await?;
        queue.fetch_queue_is_paused(pool).await?;
        queue
            .fetch_queue_is_paused_in_current_transaction(tx)
            .await?;
        queue.pause_task(pool, "task.public").await?;
        queue
            .pause_task_in_current_transaction(tx, "task.public")
            .await?;
        queue.resume_task(pool, "task.public").await?;
        queue
            .resume_task_in_current_transaction(tx, "task.public")
            .await?;
        queue.fetch_task_is_paused(pool, "task.public").await?;
        queue
            .fetch_task_is_paused_in_current_transaction(tx, "task.public")
            .await?;
        queue.fetch_paused_task_names(pool).await?;
        queue
            .fetch_paused_task_names_in_current_transaction(tx)
            .await?;
        queue.fetch_orphaned_task_names(pool, registry).await?;
        queue
            .fetch_orphaned_task_names_in_current_transaction(tx, registry)
            .await?;
        queue.fetch_worker_pressure(pool, registry).await?;
        queue
            .fetch_worker_pressure_in_current_transaction(tx, registry)
            .await?;

        queue
            .list_jobs(pool, crate::queue::ListJobsOptions::default())
            .await?;
        queue
            .list_jobs_in_current_transaction(tx, crate::queue::ListJobsOptions::default())
            .await?;
        queue
            .list_dead_letter_jobs(pool, crate::queue::ListDeadLetterJobsOptions::default())
            .await?;
        queue
            .list_dead_letter_jobs_in_current_transaction(
                tx,
                crate::queue::ListDeadLetterJobsOptions::default(),
            )
            .await?;
        queue.requeue_dead_letter_job(pool, job_id, None).await?;
        queue
            .requeue_dead_letter_job_in_current_transaction(tx, job_id, None)
            .await?;
        queue.delete_dead_letter_job(pool, job_id).await?;
        queue
            .delete_dead_letter_job_in_current_transaction(tx, job_id)
            .await?;

        queue
            .cleanup_available_completed_jobs_older_than_once(pool, Duration::from_secs(1), 1)
            .await?;
        queue
            .cleanup_available_completed_jobs_older_than_until_empty(
                pool,
                Duration::from_secs(1),
                1,
                Duration::ZERO,
            )
            .await?;
        queue
            .cleanup_available_completed_jobs_older_than_once_in_current_transaction(
                tx,
                Duration::from_secs(1),
                1,
            )
            .await?;
        queue
            .cleanup_available_failed_jobs_older_than_once(pool, Duration::from_secs(1), 1)
            .await?;
        queue
            .cleanup_available_failed_jobs_older_than_until_empty(
                pool,
                Duration::from_secs(1),
                1,
                Duration::ZERO,
            )
            .await?;
        queue
            .cleanup_available_failed_jobs_older_than_once_in_current_transaction(
                tx,
                Duration::from_secs(1),
                1,
            )
            .await?;
        queue
            .cleanup_available_dead_letter_jobs_older_than_once(pool, Duration::from_secs(1), 1)
            .await?;
        queue
            .cleanup_available_dead_letter_jobs_older_than_until_empty(
                pool,
                Duration::from_secs(1),
                1,
                Duration::ZERO,
            )
            .await?;
        queue
            .cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction(
                tx,
                Duration::from_secs(1),
                1,
            )
            .await?;
        queue
            .reclaim_available_stale_running_jobs_once(pool, Duration::from_secs(1), 1, true)
            .await?;
        queue
            .reclaim_available_stale_running_jobs_once_in_current_transaction(
                tx,
                Duration::from_secs(1),
                1,
                true,
            )
            .await?;

        queue.cancel_pending_job(pool, job_id).await?;
        queue
            .cancel_pending_job_in_current_transaction(tx, job_id)
            .await?;
        queue.retry_failed_job(pool, job_id, None).await?;
        queue
            .retry_failed_job_in_current_transaction(tx, job_id, None)
            .await?;
        queue
            .retry_available_failed_jobs(pool, Some("task.public"), 1, None)
            .await?;
        queue
            .retry_available_failed_jobs_in_current_transaction(tx, Some("task.public"), 1, None)
            .await?;
        queue.force_requeue_running_job_by_id(pool, job_id).await?;
        queue
            .force_requeue_running_job_by_id_in_current_transaction(tx, job_id)
            .await?;
        queue
            .move_failed_job_to_dead_letter(
                pool,
                job_id,
                crate::queue::DeadLetterReason::OperatorAction,
            )
            .await?;
        queue
            .move_failed_job_to_dead_letter_in_current_transaction(
                tx,
                job_id,
                crate::queue::DeadLetterReason::OperatorAction,
            )
            .await?;
        queue
            .move_failed_jobs_to_dead_letter_batch(
                pool,
                &[job_id],
                crate::queue::DeadLetterReason::OperatorAction,
            )
            .await?;
        queue
            .move_failed_jobs_to_dead_letter_batch_in_current_transaction(
                tx,
                &[job_id],
                crate::queue::DeadLetterReason::OperatorAction,
            )
            .await?;

        let worker_owner_id =
            crate::queue::WorkerOwnerId::new_unique_for_worker_name("worker.public")?;

        queue
            .begin_manual_worker_lifecycle()
            .claim_available_jobs_for_worker_owner(
                pool,
                &["task.public".to_owned()],
                1,
                &worker_owner_id,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .claim_available_jobs_for_worker_owner_in_current_transaction(
                tx,
                &["task.public".to_owned()],
                1,
                &worker_owner_id,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_started(pool, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_started_in_current_transaction(tx, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed(pool, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed_in_current_transaction(tx, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .touch_owned_running_job_execution_heartbeat(pool, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .touch_owned_running_job_execution_heartbeat_in_current_transaction(
                tx,
                job_id,
                &worker_owner_id,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .schedule_owned_running_job_retry(
                pool,
                job_id,
                &worker_owner_id,
                1,
                Duration::from_secs(1),
                "retry",
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .schedule_owned_running_job_retry_in_current_transaction(
                tx,
                job_id,
                &worker_owner_id,
                1,
                Duration::from_secs(1),
                "retry",
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_failed(pool, job_id, &worker_owner_id, "failed", true)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_failed_in_current_transaction(
                tx,
                job_id,
                &worker_owner_id,
                "failed",
                true,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .move_owned_running_job_to_dead_letter(
                pool,
                job_id,
                &worker_owner_id,
                "dead",
                true,
                crate::queue::DeadLetterReason::OperatorAction,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .move_owned_running_job_to_dead_letter_in_current_transaction(
                tx,
                job_id,
                &worker_owner_id,
                "dead",
                true,
                crate::queue::DeadLetterReason::OperatorAction,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_owned_unstarted_running_job_to_pending(pool, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_owned_unstarted_running_job_to_pending_in_current_transaction(
                tx,
                job_id,
                &worker_owner_id,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_owned_started_running_job_to_pending(pool, job_id, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_owned_started_running_job_to_pending_in_current_transaction(
                tx,
                job_id,
                &worker_owner_id,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_unstarted_running_jobs_to_pending(pool, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
                tx,
                &worker_owner_id,
            )
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_started_running_jobs_to_pending(pool, &worker_owner_id)
            .await?;
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_started_running_jobs_to_pending_in_current_transaction(
                tx,
                &worker_owner_id,
            )
            .await?;

        queue
            .process_available_jobs_once_for_worker(
                pool,
                registry,
                "worker",
                crate::queue::WorkerConfig::default(),
            )
            .await?;
        let worker = queue.start_worker(
            pool.clone(),
            registry.clone(),
            "worker",
            crate::queue::WorkerConfig::default(),
        )?;
        worker.request_stop();
        worker.wait().await?;
        let worker = queue.start_worker_with_fleet_maintenance(
            pool.clone(),
            fleet_store,
            registry.clone(),
            "worker",
            crate::queue::WorkerConfig::default(),
            crate::queue::WorkerMaintenanceConfig::default(),
        )?;
        worker.request_stop();
        worker.wait().await?;

        let mut task_registry = crate::queue::TaskRegistry::new();
        let task = queue.register_json_task_handler(
            &mut task_registry,
            "task.public",
            |_context, _payload: String| async move { Ok(()) },
        )?;
        task.task_name();
        task.enqueue(
            pool,
            &"payload".to_owned(),
            crate::queue::EnqueueOptions::default(),
        )
        .await?;
        task.enqueue_in_current_transaction(
            tx,
            &"payload".to_owned(),
            crate::queue::EnqueueOptions::default(),
        )
        .await?;
        task.enqueue_batch(
            pool,
            &["payload".to_owned()],
            crate::queue::EnqueueBatchOptions::default(),
        )
        .await?;
        task.enqueue_batch_in_current_transaction(
            tx,
            &["payload".to_owned()],
            crate::queue::EnqueueBatchOptions::default(),
        )
        .await?;

        let retryable = crate::queue::TaskError::retryable("retryable");
        retryable.message();
        retryable.is_permanent();
        retryable.to_string();
        let permanent = crate::queue::TaskError::permanent("permanent");
        permanent.message();
        permanent.is_permanent();
        permanent.to_string();
        Ok(())
    }

    let _ = exercise_queue_public_method_surface;
}

fn test_table_name(input: &str) -> PgQualifiedTableName {
    PgQualifiedTableName::unqualified(input).expect("test table name should be valid")
}

fn valid_pg_identifier_text_strategy() -> impl Strategy<Value = String> {
    let first_chars = "abcdefghijklmnopqrstuvwxyz_".chars().collect::<Vec<_>>();
    let trailing_chars = "abcdefghijklmnopqrstuvwxyz0123456789_"
        .chars()
        .collect::<Vec<_>>();

    (
        prop::sample::select(first_chars),
        prop::collection::vec(prop::sample::select(trailing_chars), 0..32),
    )
        .prop_map(|(first, trailing)| {
            let mut identifier = String::with_capacity(1 + trailing.len());
            identifier.push(first);
            identifier.extend(trailing);
            identifier
        })
}

fn generated_table_name(
    identifier: &str,
    schema_selector: u8,
) -> (PgQualifiedTableName, Option<&'static str>) {
    match schema_selector % 4 {
        0 => (
            PgQualifiedTableName::unqualified(identifier).expect("generated unqualified table"),
            None,
        ),
        1 => (
            PgQualifiedTableName::with_schema("public", identifier)
                .expect("generated public table"),
            Some("public"),
        ),
        2 => (
            PgQualifiedTableName::with_schema("tenant_a", identifier)
                .expect("generated tenant_a table"),
            Some("tenant_a"),
        ),
        _ => (
            PgQualifiedTableName::with_schema("tenant_b", identifier)
                .expect("generated tenant_b table"),
            Some("tenant_b"),
        ),
    }
}

fn generated_table_names_can_collide_under_default_search_path(
    left_name: &str,
    left_schema: Option<&str>,
    right_name: &str,
    right_schema: Option<&str>,
) -> bool {
    left_name == right_name
        && (left_schema.is_none() || right_schema.is_none() || left_schema == right_schema)
}

#[test]
fn queue_config_and_input_validators_reject_ambiguous_protocol_values() {
    let default_config = StoreConfig::default();
    assert_eq!(
        default_config.table_name,
        test_table_name(TEST_QUEUE_JOBS_TABLE_NAME)
    );
    assert_eq!(
        default_config.dead_letter_table_name,
        test_table_name(TEST_QUEUE_DEAD_LETTER_TABLE_NAME)
    );
    assert_eq!(
        default_config.pause_table_name,
        test_table_name(TEST_QUEUE_PAUSE_TABLE_NAME)
    );
    assert_eq!(
        default_config.payload_json_limit_bytes,
        DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES
    );
    let default_queue = Store::new(default_config.clone()).expect("default queue");
    assert_eq!(default_queue.config(), &default_config);

    let jobs = test_table_name("__queue_test_jobs");
    let dead = test_table_name("__queue_test_dead");
    let pauses = test_table_name("__queue_test_pauses");
    let config =
        StoreConfig::new(jobs.clone(), dead.clone(), pauses.clone()).expect("distinct tables");
    assert_eq!(config.table_name, jobs);
    assert!(Store::new(config).is_ok());

    assert!(matches!(
        StoreConfig::new(jobs.clone(), jobs.clone(), pauses.clone()),
        Err(Error::TableNamesMustBeDistinct)
    ));
    assert!(matches!(
        Store::new(StoreConfig {
            table_name: jobs.clone(),
            dead_letter_table_name: dead.clone(),
            pause_table_name: dead.clone(),
            schema_ledger_table_name: test_schema_ledger_table_name(),
            payload_json_limit_bytes: DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
        }),
        Err(Error::TableNamesMustBeDistinct)
    ));
    assert!(matches!(
        Store::new(StoreConfig {
            table_name: jobs.clone(),
            dead_letter_table_name: dead.clone(),
            pause_table_name: pauses.clone(),
            schema_ledger_table_name: test_schema_ledger_table_name(),
            payload_json_limit_bytes: 0,
        }),
        Err(Error::PayloadJsonLimitIsZero)
    ));
    assert!(matches!(
        Store::new(StoreConfig {
            table_name: jobs.clone(),
            dead_letter_table_name: dead.clone(),
            pause_table_name: pauses.clone(),
            schema_ledger_table_name: test_schema_ledger_table_name(),
            payload_json_limit_bytes: MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES + 1,
        }),
        Err(Error::PayloadJsonLimitTooLarge { actual, max })
            if actual == MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES + 1
                && max == MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES
    ));

    let explicitly_qualified_jobs =
        PgQualifiedTableName::with_schema("public", "__queue_test_jobs").expect("qualified jobs");
    assert!(matches!(
        StoreConfig::new(
            test_table_name("__queue_test_jobs"),
            explicitly_qualified_jobs,
            pauses.clone()
        ),
        Err(Error::TableNamesMustBeDistinct)
    ));
    assert!(
        StoreConfig::new(
            PgQualifiedTableName::with_schema("schema_a", "__queue_test_same")
                .expect("schema a table"),
            PgQualifiedTableName::with_schema("schema_b", "__queue_test_same")
                .expect("schema b table"),
            pauses,
        )
        .is_ok()
    );

    for task_name in ["task", "_task", "Task-1.ok", "task_123"] {
        validate_task_name(task_name).expect("valid task name");
    }
    for task_name in ["", ".bad", "-bad", "bad task", "bad\0task"] {
        assert!(
            matches!(
                validate_task_name(task_name),
                Err(Error::TaskNameRequired | Error::InvalidTaskName)
            ),
            "task name {task_name:?} should be rejected"
        );
    }
    assert!(matches!(
        validate_task_name(&"a".repeat(MAX_QUEUE_TASK_NAME_BYTES + 1)),
        Err(Error::TaskNameTooLong { .. })
    ));

    validate_optional_dedupe_key(None).expect("absent dedupe key");
    validate_optional_dedupe_key(Some(&"a".repeat(MAX_QUEUE_DEDUPE_KEY_BYTES)))
        .expect("maximum-size dedupe key");
    for dedupe_key in ["", "has\0null"] {
        assert!(
            matches!(
                validate_optional_dedupe_key(Some(dedupe_key)),
                Err(Error::InvalidDedupeKey)
            ),
            "dedupe key {dedupe_key:?} should be rejected"
        );
    }
    assert!(matches!(
        validate_optional_dedupe_key(Some(&"a".repeat(MAX_QUEUE_DEDUPE_KEY_BYTES + 1))),
        Err(Error::DedupeKeyTooLong { .. })
    ));

    validate_payload_json_limit_bytes(1).expect("minimum payload limit");
    validate_payload_json_limit_bytes(DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES)
        .expect("default payload limit");
    validate_payload_json_limit_bytes(MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES)
        .expect("maximum payload limit");
    assert!(matches!(
        validate_payload_json_limit_bytes(0),
        Err(Error::PayloadJsonLimitIsZero)
    ));
    assert!(matches!(
        validate_payload_json_limit_bytes(MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES + 1),
        Err(Error::PayloadJsonLimitTooLarge { actual, max })
            if actual == MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES + 1
                && max == MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES
    ));

    validate_worker_owner_id("worker-1").expect("valid worker owner id");
    validate_worker_owner_id(&"w".repeat(MAX_QUEUE_WORKER_OWNER_ID_BYTES))
        .expect("maximum-size worker owner id");
    assert!(matches!(
        validate_worker_owner_id(""),
        Err(Error::WorkerOwnerIdRequired)
    ));
    assert!(matches!(
        validate_worker_owner_id(&"w".repeat(MAX_QUEUE_WORKER_OWNER_ID_BYTES + 1)),
        Err(Error::WorkerOwnerIdTooLong { .. })
    ));
    assert!(matches!(
        validate_worker_owner_id("worker\0id"),
        Err(Error::InvalidWorkerOwnerId)
    ));

    validate_worker_name("worker-1").expect("valid worker name");
    validate_worker_name(&"w".repeat(MAX_QUEUE_WORKER_NAME_BYTES))
        .expect("maximum-size worker name");
    assert!(matches!(
        validate_worker_name(""),
        Err(Error::WorkerNameRequired)
    ));
    assert!(matches!(
        validate_worker_name(&"w".repeat(MAX_QUEUE_WORKER_NAME_BYTES + 1)),
        Err(Error::WorkerNameTooLong { .. })
    ));
    assert!(matches!(
        validate_worker_name("worker\0name"),
        Err(Error::InvalidWorkerName)
    ));

    let worker_owner_id =
        new_unique_worker_owner_id("logical-worker").expect("unique worker owner id");
    assert!(worker_owner_id.starts_with("logical-worker."));
    assert_eq!(
        worker_owner_id.len(),
        "logical-worker".len() + 1 + crate::id::SORTABLE_ID_TEXT_LEN
    );
    assert!(validate_worker_owner_id(&worker_owner_id).is_ok());

    let public_worker_owner_id =
        crate::queue::WorkerOwnerId::new_unique_for_worker_name("logical-public-worker")
            .expect("public unique worker owner id");
    assert!(
        public_worker_owner_id
            .as_str()
            .starts_with("logical-public-worker.")
    );
    let manual_worker_owner_id =
        crate::queue::WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text("manual-owner-1")
            .expect("manual worker owner id");
    assert_eq!(manual_worker_owner_id.as_str(), "manual-owner-1");
    assert!(matches!(
        crate::queue::WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text(""),
        Err(Error::WorkerOwnerIdRequired)
    ));
}

#[test]
fn queue_table_name_distinctness_matches_postgres_search_path_ambiguity() {
    let schemas = [None, Some("public"), Some("tenant_a"), Some("tenant_b")];
    for left_schema in schemas {
        for right_schema in schemas {
            let left = match left_schema {
                Some(schema) => PgQualifiedTableName::with_schema(schema, "__queue_test_same")
                    .expect("qualified left"),
                None => test_table_name("__queue_test_same"),
            };
            let right = match right_schema {
                Some(schema) => PgQualifiedTableName::with_schema(schema, "__queue_test_same")
                    .expect("qualified right"),
                None => test_table_name("__queue_test_same"),
            };
            let pauses = test_table_name("__queue_test_pauses");
            let config_result = StoreConfig::new(left, right, pauses);
            let should_collide =
                left_schema.is_none() || right_schema.is_none() || left_schema == right_schema;
            assert_eq!(
                config_result.is_err(),
                should_collide,
                "schema pair {left_schema:?}/{right_schema:?} should collide: {should_collide}"
            );
        }
    }
}

#[test]
fn queue_task_name_validation_matches_ascii_protocol_language() {
    for byte in 0_u8..=127 {
        let first_candidate = char::from(byte).to_string();
        let first_should_be_valid = byte == b'_' || byte.is_ascii_alphanumeric();
        assert_eq!(
            validate_task_name(&first_candidate).is_ok(),
            first_should_be_valid,
            "first byte 0x{byte:02x} should have validity {first_should_be_valid}"
        );

        let trailing_candidate = format!("a{}", char::from(byte));
        let trailing_should_be_valid = first_should_be_valid || byte == b'.' || byte == b'-';
        assert_eq!(
            validate_task_name(&trailing_candidate).is_ok(),
            trailing_should_be_valid,
            "trailing byte 0x{byte:02x} should have validity {trailing_should_be_valid}"
        );
    }

    assert!(matches!(
        validate_task_name("éclair"),
        Err(Error::InvalidTaskName)
    ));
    assert!(matches!(
        validate_task_name("task/name"),
        Err(Error::InvalidTaskName)
    ));
}

#[test]
fn queue_pause_key_round_trips_exactly_over_valid_task_name_domain() {
    for byte in 0_u8..=127 {
        let candidate = format!("task{}", char::from(byte));
        let candidate_is_valid = validate_task_name(&candidate).is_ok();
        let pause_key = paused_task_key(&candidate);

        if candidate_is_valid {
            assert_eq!(
                paused_task_name_from_pause_key(&pause_key),
                Some(candidate),
                "valid task name with trailing byte 0x{byte:02x} should round-trip"
            );
        } else {
            assert_eq!(
                paused_task_name_from_pause_key(&pause_key),
                None,
                "invalid task name with trailing byte 0x{byte:02x} should not decode"
            );
        }
    }

    for non_task_key in ["", "task", "task:", "task::alpha", "global", "__global__"] {
        assert_eq!(paused_task_name_from_pause_key(non_task_key), None);
    }
}

proptest! {
    #[test]
    fn queue_generated_valid_task_names_validate_and_pause_keys_round_trip(
        task_name in valid_queue_task_name_strategy(),
    ) {
        validate_task_name(&task_name).expect("generated valid task name");

        let pause_key = paused_task_key(&task_name);
        prop_assert_eq!(
            paused_task_name_from_pause_key(&pause_key),
            Some(task_name)
        );
    }

    #[test]
    fn queue_generated_invalid_task_names_are_rejected_and_do_not_decode_from_pause_keys(
        task_name in invalid_queue_task_name_strategy(),
    ) {
        prop_assert!(validate_task_name(&task_name).is_err());
        prop_assert_eq!(paused_task_name_from_pause_key(&paused_task_key(&task_name)), None);
    }

    #[test]
    fn queue_task_name_byte_predicates_match_validator_for_generated_ascii_bytes(
        first in any::<u8>(),
        trailing in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut bytes = Vec::with_capacity(1 + trailing.len());
        bytes.push(first);
        bytes.extend_from_slice(&trailing);

        if let Ok(task_name) = String::from_utf8(bytes.clone()) {
            let expected = is_task_name_first_byte(first)
                && trailing.iter().copied().all(is_task_name_trailing_byte)
                && task_name.len() <= MAX_QUEUE_TASK_NAME_BYTES;

            prop_assert_eq!(
                validate_task_name(&task_name).is_ok(),
                expected,
                "task_name={:?} bytes={:?}",
                task_name,
                bytes
            );
        } else {
            prop_assert!(validate_task_name(&String::from_utf8_lossy(&bytes)).is_err());
        }
    }

    #[test]
    fn queue_generated_store_configs_enforce_distinct_postgres_table_names(
        jobs_name in valid_pg_identifier_text_strategy(),
        dead_name in valid_pg_identifier_text_strategy(),
        pause_name in valid_pg_identifier_text_strategy(),
        jobs_schema_selector in any::<u8>(),
        dead_schema_selector in any::<u8>(),
        pause_schema_selector in any::<u8>(),
    ) {
        let (jobs, jobs_schema) = generated_table_name(&jobs_name, jobs_schema_selector);
        let (dead, dead_schema) = generated_table_name(&dead_name, dead_schema_selector);
        let (pauses, pauses_schema) = generated_table_name(&pause_name, pause_schema_selector);

        let config = StoreConfig::new(jobs, dead, pauses);
        let expected_collision =
            generated_table_names_can_collide_under_default_search_path(
                &jobs_name,
                jobs_schema,
                &dead_name,
                dead_schema,
            )
                || generated_table_names_can_collide_under_default_search_path(
                    &jobs_name,
                    jobs_schema,
                    &pause_name,
                    pauses_schema,
                )
                || generated_table_names_can_collide_under_default_search_path(
                    &dead_name,
                    dead_schema,
                    &pause_name,
                    pauses_schema,
                );

        prop_assert_eq!(
            config.is_err(),
            expected_collision,
            "jobs={:?}/{:?} dead={:?}/{:?} pause={:?}/{:?}",
            jobs_name,
            jobs_schema,
            dead_name,
            dead_schema,
            pause_name,
            pauses_schema
        );
    }

    #[test]
    fn queue_generated_limit_validators_preserve_configured_bounds(
        limit in any::<u32>(),
        payload_json_limit_bytes in any::<usize>(),
    ) {
        let list_limit = validate_list_limit(Some(limit));
        match limit {
            0 => prop_assert!(matches!(list_limit, Err(Error::ListLimitIsZero))),
            1..=MAX_QUEUE_LIST_LIMIT => {
                prop_assert_eq!(list_limit.expect("valid list limit"), limit);
            }
            _ => prop_assert_eq!(
                matches!(
                    list_limit,
                    Err(Error::ListLimitTooLarge { actual, max })
                        if actual == limit && max == MAX_QUEUE_LIST_LIMIT
                ),
                true
            ),
        }

        let retry_limit = validate_retry_available_failed_jobs_limit(limit);
        match limit {
            0 => prop_assert!(matches!(
                retry_limit,
                Err(Error::RetryAvailableFailedJobsLimitIsZero)
            )),
            1..=MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT => {
                retry_limit.expect("valid retry limit");
            }
            _ => prop_assert_eq!(
                matches!(
                    retry_limit,
                    Err(Error::RetryAvailableFailedJobsLimitTooLarge { actual, max })
                        if actual == limit && max == MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT
                ),
                true
            ),
        }

        let reclaim_limit = validate_reclaim_batch_size(limit);
        match limit {
            0 => prop_assert!(matches!(reclaim_limit, Err(Error::ReclaimBatchSizeIsZero))),
            1..=MAX_QUEUE_RECLAIM_BATCH_SIZE => {
                reclaim_limit.expect("valid reclaim batch limit");
            }
            _ => prop_assert_eq!(
                matches!(
                    reclaim_limit,
                    Err(Error::ReclaimBatchSizeTooLarge { actual, max })
                        if actual == limit && max == MAX_QUEUE_RECLAIM_BATCH_SIZE
                ),
                true
            ),
        }

        let cleanup_limit = validate_cleanup_batch_size(limit);
        match limit {
            0 => prop_assert!(matches!(cleanup_limit, Err(Error::CleanupBatchSizeIsZero))),
            1..=MAX_QUEUE_CLEANUP_BATCH_SIZE => {
                cleanup_limit.expect("valid cleanup batch limit");
            }
            _ => prop_assert_eq!(
                matches!(
                    cleanup_limit,
                    Err(Error::CleanupBatchSizeTooLarge { actual, max })
                        if actual == limit && max == MAX_QUEUE_CLEANUP_BATCH_SIZE
                ),
                true
            ),
        }

        let payload_limit = validate_payload_json_limit_bytes(payload_json_limit_bytes);
        match payload_json_limit_bytes {
            0 => prop_assert!(matches!(payload_limit, Err(Error::PayloadJsonLimitIsZero))),
            1..=MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES => {
                payload_limit.expect("valid payload JSON limit");
            }
            _ => {
                let rejected_oversized_payload_limit = matches!(
                    payload_limit,
                    Err(Error::PayloadJsonLimitTooLarge { actual, max })
                        if actual == payload_json_limit_bytes
                            && max == MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES
                );
                prop_assert!(rejected_oversized_payload_limit);
            }
        }
    }

    #[test]
    fn queue_generated_persisted_status_and_dead_letter_reason_parsers_accept_only_protocol_literals(
        status_text in prop::collection::vec(any::<u8>(), 0..64)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        reason_text in prop::collection::vec(any::<u8>(), 0..64)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
    ) {
        let status = JobStatus::parse(&status_text);
        let expected_status = match status_text.as_str() {
            "pending" => Some(JobStatus::Pending),
            "running" => Some(JobStatus::Running),
            "completed" => Some(JobStatus::Completed),
            "failed" => Some(JobStatus::Failed),
            _ => None,
        };
        prop_assert_eq!(status.ok(), expected_status);

        let reason = DeadLetterReason::parse(&reason_text);
        let expected_reason = match reason_text.as_str() {
            "max_retries_exceeded" => Some(DeadLetterReason::MaxRetriesExceeded),
            "permanent_error" => Some(DeadLetterReason::PermanentError),
            "operator_action" => Some(DeadLetterReason::OperatorAction),
            "execution_expired" => Some(DeadLetterReason::ExecutionExpired),
            _ => None,
        };
        prop_assert_eq!(reason.ok(), expected_reason);
    }

    #[test]
    fn queue_generated_enqueue_option_domains_preserve_postgres_bindings(
        max_retries in any::<u32>(),
        timeout_nanos in any::<u64>(),
        timeout_kind in any::<u8>(),
    ) {
        let timeout = match timeout_kind % 3 {
            0 => JobTimeout::WorkerDefault,
            1 => JobTimeout::NoTimeout,
            _ => JobTimeout::ExpiresAfter(Duration::from_nanos(timeout_nanos)),
        };
        let prepared = PreparedEnqueue::new(
            "task.enqueue",
            &123_u16,
            EnqueueOptions {
                max_retries: Some(max_retries),
                timeout,
                ..EnqueueOptions::default()
            },
        );

        let retry_count_fits_postgres_int = max_retries <= i32::MAX as u32;
        let timeout_fits_postgres_bigint = match timeout {
            JobTimeout::WorkerDefault | JobTimeout::NoTimeout => true,
            JobTimeout::ExpiresAfter(duration) => {
                !duration.is_zero() && duration.as_nanos() <= i64::MAX as u128
            }
        };

        prop_assert_eq!(
            prepared.is_ok(),
            retry_count_fits_postgres_int && timeout_fits_postgres_bigint,
            "max_retries={} timeout={:?}",
            max_retries,
            timeout
        );

        if let Ok(prepared) = prepared {
            prop_assert_eq!(prepared.max_retries, max_retries as i32);
            match timeout {
                JobTimeout::WorkerDefault => prop_assert_eq!(prepared.timeout_nanos, 0),
                JobTimeout::NoTimeout => prop_assert_eq!(prepared.timeout_nanos, -1),
                JobTimeout::ExpiresAfter(duration) => {
                    prop_assert_eq!(prepared.timeout_nanos, duration.as_nanos() as i64);
                }
            }
        }
    }

    #[test]
    fn queue_generated_schedule_times_preserve_database_timestamp_domain(
        unix_microseconds in any::<i64>(),
    ) {
        let schedule = JobRunAtOrAfter::from_unix_microseconds(unix_microseconds);
        if (0..=MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS).contains(&unix_microseconds) {
            prop_assert_eq!(
                schedule.expect("valid scheduled run time").as_unix_microseconds(),
                unix_microseconds
            );
        } else if unix_microseconds < 0 {
            let rejected_negative_schedule = matches!(
                schedule,
                Err(Error::RunAtOrAfterUnixMicrosecondsIsNegative { actual })
                    if actual == unix_microseconds
            );
            prop_assert!(rejected_negative_schedule);
        } else {
            let rejected_oversized_schedule = matches!(
                schedule,
                Err(Error::RunAtOrAfterUnixMicrosecondsTooLarge { actual, max })
                    if actual == unix_microseconds as u128
                        && max == MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS
            );
            prop_assert!(rejected_oversized_schedule);
        }
    }
}

#[test]
fn queue_job_run_at_or_after_converts_only_unambiguous_times() {
    assert_eq!(
        JobRunAtOrAfter::from_unix_microseconds(0)
            .expect("Unix epoch")
            .as_unix_microseconds(),
        0
    );
    assert_eq!(
        JobRunAtOrAfter::from_unix_microseconds(MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS)
            .expect("maximum schedule time")
            .as_unix_microseconds(),
        MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS
    );
    assert!(matches!(
        JobRunAtOrAfter::from_unix_microseconds(-1),
        Err(Error::RunAtOrAfterUnixMicrosecondsIsNegative { actual }) if actual == -1
    ));
    assert!(matches!(
        JobRunAtOrAfter::from_unix_microseconds(
            MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS + 1
        ),
        Err(Error::RunAtOrAfterUnixMicrosecondsTooLarge { actual, max })
            if actual == (MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS + 1) as u128
                && max == MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS
    ));
    assert_eq!(
        JobRunAtOrAfter::from_system_time(std::time::UNIX_EPOCH + Duration::from_micros(7))
            .expect("system time schedule")
            .as_unix_microseconds(),
        7
    );
    assert!(matches!(
        JobRunAtOrAfter::from_system_time(std::time::UNIX_EPOCH - Duration::from_micros(1)),
        Err(Error::RunAtOrAfterBeforeUnixEpoch)
    ));
    assert!(matches!(
        JobRunAtOrAfter::from_system_time(
            std::time::UNIX_EPOCH
                + Duration::from_micros(
                    (MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS + 1) as u64
                )
        ),
        Err(Error::RunAtOrAfterUnixMicrosecondsTooLarge { actual, max })
            if actual == (MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS + 1) as u128
                && max == MAX_QUEUE_RUN_AT_OR_AFTER_UNIX_MICROSECONDS
    ));
}

#[test]
fn queue_limit_and_duration_validators_preserve_database_domains() {
    validate_claim_limit(1).expect("minimum claim limit");
    validate_claim_limit(MAX_QUEUE_CLAIM_LIMIT).expect("maximum claim limit");
    assert!(matches!(
        validate_claim_limit(0),
        Err(Error::ClaimLimitIsZero)
    ));
    assert!(matches!(
        validate_claim_limit(MAX_QUEUE_CLAIM_LIMIT + 1),
        Err(Error::ClaimLimitTooLarge { .. })
    ));

    assert_eq!(
        validate_list_limit(None).expect("default list limit"),
        DEFAULT_QUEUE_LIST_LIMIT
    );
    assert_eq!(
        validate_list_limit(Some(MAX_QUEUE_LIST_LIMIT)).expect("maximum list limit"),
        MAX_QUEUE_LIST_LIMIT
    );
    assert!(matches!(
        validate_list_limit(Some(0)),
        Err(Error::ListLimitIsZero)
    ));
    assert!(matches!(
        validate_list_limit(Some(MAX_QUEUE_LIST_LIMIT + 1)),
        Err(Error::ListLimitTooLarge { .. })
    ));
    for limit in 0..=(MAX_QUEUE_LIST_LIMIT + 2) {
        let normalized = validate_list_limit(Some(limit));
        match limit {
            0 => assert!(matches!(normalized, Err(Error::ListLimitIsZero))),
            1..=MAX_QUEUE_LIST_LIMIT => assert_eq!(normalized.expect("valid limit"), limit),
            _ => assert!(matches!(
                normalized,
                Err(Error::ListLimitTooLarge { actual, max })
                    if actual == limit && max == MAX_QUEUE_LIST_LIMIT
            )),
        }
    }

    validate_retry_available_failed_jobs_limit(1).expect("minimum retry limit");
    assert!(matches!(
        validate_retry_available_failed_jobs_limit(0),
        Err(Error::RetryAvailableFailedJobsLimitIsZero)
    ));
    assert!(matches!(
        validate_retry_available_failed_jobs_limit(MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT + 1),
        Err(Error::RetryAvailableFailedJobsLimitTooLarge { .. })
    ));

    validate_reclaim_batch_size(1).expect("minimum reclaim batch");
    validate_reclaim_batch_size(MAX_QUEUE_RECLAIM_BATCH_SIZE).expect("maximum reclaim batch");
    assert!(matches!(
        validate_reclaim_batch_size(0),
        Err(Error::ReclaimBatchSizeIsZero)
    ));
    assert!(matches!(
        validate_reclaim_batch_size(MAX_QUEUE_RECLAIM_BATCH_SIZE + 1),
        Err(Error::ReclaimBatchSizeTooLarge { .. })
    ));

    validate_cleanup_batch_size(1).expect("minimum cleanup batch");
    validate_cleanup_batch_size(MAX_QUEUE_CLEANUP_BATCH_SIZE).expect("maximum cleanup batch");
    assert!(matches!(
        validate_cleanup_batch_size(0),
        Err(Error::CleanupBatchSizeIsZero)
    ));
    assert!(matches!(
        validate_cleanup_batch_size(MAX_QUEUE_CLEANUP_BATCH_SIZE + 1),
        Err(Error::CleanupBatchSizeTooLarge { .. })
    ));

    assert_eq!(
        duration_to_rounded_microseconds(Duration::from_nanos(1))
            .expect("sub-microsecond duration rounds up"),
        1
    );
    assert!(matches!(
        duration_to_rounded_microseconds(Duration::ZERO),
        Err(Error::CleanupAgeIsZero)
    ));
    assert_eq!(
        stale_threshold_to_microseconds(Duration::from_nanos(1))
            .expect("sub-microsecond stale threshold rounds up"),
        1
    );
    assert!(matches!(
        stale_threshold_to_microseconds(Duration::ZERO),
        Err(Error::StaleThresholdIsZero)
    ));

    for limit in 0..=(MAX_QUEUE_CLAIM_LIMIT + 2) {
        let result = validate_claim_limit(limit);
        match limit {
            0 => assert!(matches!(result, Err(Error::ClaimLimitIsZero))),
            1..=MAX_QUEUE_CLAIM_LIMIT => result.expect("valid claim limit"),
            _ => assert!(matches!(
                result,
                Err(Error::ClaimLimitTooLarge { actual, max })
                    if actual == limit && max == MAX_QUEUE_CLAIM_LIMIT
            )),
        }
    }

    for limit in 0..=(MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT + 2) {
        let result = validate_retry_available_failed_jobs_limit(limit);
        match limit {
            0 => assert!(matches!(
                result,
                Err(Error::RetryAvailableFailedJobsLimitIsZero)
            )),
            1..=MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT => {
                result.expect("valid retry failed jobs limit");
            }
            _ => assert!(matches!(
                result,
                Err(Error::RetryAvailableFailedJobsLimitTooLarge { actual, max })
                    if actual == limit && max == MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT
            )),
        }
    }
}

#[test]
fn queue_filter_and_pause_helpers_preserve_unambiguous_runtime_state() {
    assert_eq!(
        deduplicated_status_filter_texts(&[
            JobStatus::Pending,
            JobStatus::Pending,
            JobStatus::Failed,
            JobStatus::Running,
            JobStatus::Failed,
        ]),
        vec![
            JobStatus::Pending.as_str().to_owned(),
            JobStatus::Failed.as_str().to_owned(),
            JobStatus::Running.as_str().to_owned(),
        ]
    );

    assert_eq!(paused_task_key("task.alpha"), "task:task.alpha");
    assert_eq!(
        paused_task_name_from_pause_key("task:task.alpha"),
        Some("task.alpha".to_owned())
    );
    assert_eq!(paused_task_name_from_pause_key("task:"), None);
    assert_eq!(paused_task_name_from_pause_key("task:bad task"), None);
    assert_eq!(paused_task_name_from_pause_key("__global__"), None);

    let (queue_paused, paused_task_names) = aggregate_pause_entries(vec![
        "task:task.zeta".to_owned(),
        "malformed".to_owned(),
        "__global__".to_owned(),
        "task:bad task".to_owned(),
        "task:task.alpha".to_owned(),
    ]);
    assert!(queue_paused);
    assert_eq!(paused_task_names, vec!["task.alpha", "task.zeta"]);
}
