use super::*;

#[tokio::test]
async fn queue_reclaim_stage_errors_surface_and_roll_back_prior_stage_changes() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    assert_never_started_reclaim_stage_error_rolls_back(&test_database).await;
    assert_expired_to_failed_reclaim_stage_error_rolls_back(&test_database).await;
    assert_expired_to_pending_reclaim_stage_error_rolls_back(&test_database).await;
    assert_dead_letter_reclaim_stage_error_rolls_back(&test_database).await;
}

async fn assert_never_started_reclaim_stage_error_rolls_back(test_database: &TestDatabase) {
    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(test_database).await;
    install_reclaim_update_failure_trigger(
        test_database,
        "task.reclaim.error.never_started",
        "pending",
        false,
        "intentional never-started reclaim failure",
    )
    .await;

    let job_id = enqueue_claim_and_stale_running_job(
        &queue,
        test_database,
        "task.reclaim.error.never_started",
        false,
        0,
        5,
    )
    .await;
    let error = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            false,
        )
        .await
        .expect_err("never-started reclaim stage should fail");
    assert_database_error_debug_contains(&error, "intentional never-started reclaim failure");
    assert_stale_job_still_running(&queue, test_database, job_id, false).await;
}

async fn assert_expired_to_failed_reclaim_stage_error_rolls_back(test_database: &TestDatabase) {
    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(test_database).await;
    install_reclaim_update_failure_trigger(
        test_database,
        "task.reclaim.error.failed",
        "failed",
        true,
        "intentional expired-to-failed reclaim failure",
    )
    .await;

    let job_id = enqueue_claim_and_stale_running_job(
        &queue,
        test_database,
        "task.reclaim.error.failed",
        true,
        5,
        5,
    )
    .await;
    let error = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            false,
        )
        .await
        .expect_err("expired-to-failed reclaim stage should fail");
    assert_database_error_debug_contains(&error, "intentional expired-to-failed reclaim failure");
    assert_stale_job_still_running(&queue, test_database, job_id, true).await;
}

async fn assert_expired_to_pending_reclaim_stage_error_rolls_back(test_database: &TestDatabase) {
    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(test_database).await;
    install_reclaim_update_failure_trigger(
        test_database,
        "task.reclaim.error.pending",
        "pending",
        true,
        "intentional expired-to-pending reclaim failure",
    )
    .await;

    let job_id = enqueue_claim_and_stale_running_job(
        &queue,
        test_database,
        "task.reclaim.error.pending",
        true,
        0,
        5,
    )
    .await;
    let error = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            false,
        )
        .await
        .expect_err("expired-to-pending reclaim stage should fail");
    assert_database_error_debug_contains(&error, "intentional expired-to-pending reclaim failure");
    assert_stale_job_still_running(&queue, test_database, job_id, true).await;
}

async fn assert_dead_letter_reclaim_stage_error_rolls_back(test_database: &TestDatabase) {
    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(test_database).await;
    let job_id = enqueue_claim_and_stale_running_job(
        &queue,
        test_database,
        "task.reclaim.error.dead_letter",
        true,
        5,
        5,
    )
    .await;
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
    )
    .await;

    let error = queue
        .reclaim_available_stale_running_jobs_once(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            10,
            true,
        )
        .await
        .expect_err("dead-letter reclaim stage should fail");
    assert!(matches!(error, Error::Database(_)));
    assert_stale_job_still_running(&queue, test_database, job_id, true).await;
}

async fn enqueue_claim_and_stale_running_job(
    queue: &Store,
    test_database: &TestDatabase,
    task_name: &str,
    started: bool,
    retry_count: i32,
    max_retries: i32,
) -> paranoid::queue::JobId {
    let worker_owner_id = new_manual_worker_owner_id("worker-reclaim-error");
    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            task_name,
            &TestPayload { value: 61 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue stale reclaim error job");
    claim_exact_jobs_with_worker_owner_id(queue, test_database, &[task_name], 1, &worker_owner_id)
        .await
        .expect("claim stale reclaim error job");
    if started {
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_started(
                &test_database.paranoid_pool,
                enqueued.job_id,
                &worker_owner_id,
            )
            .await
            .expect("start stale reclaim error job");
    }
    set_running_job_staleness(
        test_database,
        enqueued.job_id,
        Duration::from_secs(120),
        started.then_some(Duration::from_secs(120)),
        Duration::from_secs(120),
        retry_count,
        max_retries,
    )
    .await;
    enqueued.job_id
}

async fn assert_stale_job_still_running(
    queue: &Store,
    test_database: &TestDatabase,
    job_id: paranoid::queue::JobId,
    started: bool,
) {
    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, job_id)
        .await
        .expect("fetch stale job after failed reclaim");
    assert_eq!(job_after_error.status, JobStatus::Running);
    assert_eq!(
        worker_owner_id_text(job_after_error.worker_owner_id.as_ref()),
        Some("worker-reclaim-error")
    );
    assert_eq!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_some(),
        started
    );
}

async fn install_reclaim_update_failure_trigger(
    test_database: &TestDatabase,
    task_name: &str,
    new_status: &str,
    old_execution_started_at_is_some: bool,
    error_message: &str,
) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qrse_stage_{suffix}")).expect("stage function name");
    let trigger = PgIdentifier::new(format!("qrse_stage_t_{suffix}")).expect("stage trigger name");
    let started_predicate = if old_execution_started_at_is_some {
        "OLD.execution_started_at IS NOT NULL"
    } else {
        "OLD.execution_started_at IS NULL"
    };
    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.task_name = '{}'
                    AND NEW.status = '{}'
                    AND {}
                THEN
                    RAISE EXCEPTION '{}';
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            function.quoted(),
            task_name,
            new_status,
            started_predicate,
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
            .expect("install reclaim stage failure trigger");
    }
}

fn assert_database_error_debug_contains(error: &Error, expected: &str) {
    assert!(
        matches!(error, Error::Database(_)),
        "queue error = {error:?}, want database error"
    );
    let debug_text = format!("{error:?}");
    assert!(
        debug_text.contains(expected),
        "queue database error = {debug_text:?}, want substring {expected:?}"
    );
}
