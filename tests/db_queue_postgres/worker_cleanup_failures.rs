use super::*;

#[tokio::test]
async fn queue_worker_internal_task_panic_cleanup_failure_surfaces_database_error_without_panic() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_started_return_failure_trigger(
        &test_database,
        "task.worker.internal_panic_cleanup_return_fails",
        "intentional panic cleanup return failure",
    )
    .await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.internal_panic_cleanup_return_fails",
            &TestPayload { value: 41 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue internal panic cleanup-failure job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.internal_panic_cleanup_return_fails", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    assert_eq!(payload.value, 41);
                    handler_called.store(true, Ordering::SeqCst);
                    Err(TaskError::retryable("trigger custom backoff panic"))
                }
            }
        })
        .expect("register internal panic cleanup-failure handler");

    let error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-internal-panic-cleanup-fails",
            WorkerConfig {
                retry_policy: RetryPolicy {
                    strategy: RetryBackoffStrategy::Custom(Arc::new(|_, _| {
                        panic!("intentional custom retry backoff panic for cleanup test")
                    })),
                    jitter_fraction: 0.0,
                    ..RetryPolicy::default()
                },
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
        )
        .await
        .expect_err("cleanup write failure should be surfaced");
    assert_queue_error_debug_contains(&error, "intentional custom retry backoff panic");
    assert_queue_error_debug_contains(&error, "intentional panic cleanup return failure");
    assert!(handler_called.load(Ordering::SeqCst));

    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch internal panic cleanup-failure job");
    assert_eq!(job_after_error.status, JobStatus::Running);
    assert_worker_owner_id_was_derived_from_worker_name(
        worker_owner_id_text(job_after_error.worker_owner_id.as_ref()),
        "worker-internal-panic-cleanup-fails",
    );
    assert!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_some()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_worker_start_failure_cleanup_failure_surfaces_database_error_without_panic() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;
    install_worker_start_and_unstarted_return_failure_trigger(
        &test_database,
        "task.worker.start_cleanup_return_fails",
        "intentional start transition failure before cleanup",
        "intentional unstarted cleanup return failure",
    )
    .await;

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.worker.start_cleanup_return_fails",
            &TestPayload { value: 42 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue start cleanup-failure job");

    let handler_called = Arc::new(AtomicBool::new(false));
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler("task.worker.start_cleanup_return_fails", {
            let handler_called = Arc::clone(&handler_called);
            move |_context, _payload: TestPayload| {
                let handler_called = Arc::clone(&handler_called);
                async move {
                    handler_called.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .expect("register start cleanup-failure handler");

    let error = queue
        .process_available_jobs_once_for_worker(
            &test_database.paranoid_pool,
            &registry,
            "worker-start-cleanup-fails",
            fixed_retry_worker_config(Duration::from_millis(1), true),
        )
        .await
        .expect_err("unstarted cleanup write failure should be surfaced");
    assert_queue_error_debug_contains(
        &error,
        "intentional start transition failure before cleanup",
    );
    assert_queue_error_debug_contains(&error, "intentional unstarted cleanup return failure");
    assert!(!handler_called.load(Ordering::SeqCst));

    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("fetch start cleanup-failure job");
    assert_eq!(job_after_error.status, JobStatus::Running);
    assert_worker_owner_id_was_derived_from_worker_name(
        worker_owner_id_text(job_after_error.worker_owner_id.as_ref()),
        "worker-start-cleanup-fails",
    );
    assert!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

async fn install_worker_started_return_failure_trigger(
    test_database: &TestDatabase,
    task_name: &str,
    error_message: &str,
) {
    let suffix = trigger_suffix();
    let function =
        PgIdentifier::new(format!("qwsrf_return_{suffix}")).expect("return function name");
    let trigger =
        PgIdentifier::new(format!("qwsrf_return_t_{suffix}")).expect("return trigger name");
    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.task_name = '{}'
                    AND OLD.status = 'running'
                    AND NEW.status = 'pending'
                THEN
                    RAISE EXCEPTION '{}';
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            function.quoted(),
            task_name,
            error_message
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE UPDATE ON {}
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
            .expect("install started return failure trigger");
    }
}

async fn install_worker_start_and_unstarted_return_failure_trigger(
    test_database: &TestDatabase,
    task_name: &str,
    start_error_message: &str,
    return_error_message: &str,
) {
    let suffix = trigger_suffix();
    let function = PgIdentifier::new(format!("qwsurf_return_{suffix}"))
        .expect("start and return function name");
    let trigger = PgIdentifier::new(format!("qwsurf_return_t_{suffix}"))
        .expect("start and return trigger name");
    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.task_name = '{}'
                    AND NEW.status = 'running'
                    AND OLD.execution_started_at IS NULL
                    AND NEW.execution_started_at IS NOT NULL
                THEN
                    RAISE EXCEPTION '{}';
                END IF;
                IF NEW.task_name = '{}'
                    AND OLD.status = 'running'
                    AND NEW.status = 'pending'
                    AND OLD.execution_started_at IS NULL
                THEN
                    RAISE EXCEPTION '{}';
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            function.quoted(),
            task_name,
            start_error_message,
            task_name,
            return_error_message
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE UPDATE ON {}
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
            .expect("install start and unstarted return failure trigger");
    }
}

fn trigger_suffix() -> String {
    paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn assert_queue_error_debug_contains(error: &Error, expected: &str) {
    let debug_text = format!("{error:?}");
    assert!(
        debug_text.contains(expected),
        "queue error = {debug_text:?}, want substring {expected:?}"
    );
}
