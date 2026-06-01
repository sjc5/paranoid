use super::*;

#[tokio::test]
async fn queue_dead_letter_batch_future_cancellation_does_not_move_failed_jobs() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let first_failed = fail_new_job(
        &queue,
        &test_database,
        "task.dead_letter_batch_cancel",
        51,
        "worker-dead-letter-batch-cancel",
    )
    .await;
    let second_failed = fail_new_job(
        &queue,
        &test_database,
        "task.dead_letter_batch_cancel",
        52,
        "worker-dead-letter-batch-cancel",
    )
    .await;
    install_slow_failed_job_delete_trigger(
        &test_database,
        "task.dead_letter_batch_cancel",
        Duration::from_millis(250),
    )
    .await;

    let cancelled = tokio::time::timeout(
        Duration::from_millis(20),
        queue.move_failed_jobs_to_dead_letter_batch(
            &test_database.paranoid_pool,
            &[first_failed, second_failed],
            DeadLetterReason::OperatorAction,
        ),
    )
    .await;
    assert!(cancelled.is_err());

    tokio::time::sleep(Duration::from_millis(650)).await;
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, first_failed)
            .await
            .expect("first failed job should remain visible"),
        JobStatus::Failed
    );
    assert_eq!(
        queue
            .fetch_job_status(&test_database.paranoid_pool, second_failed)
            .await
            .expect("second failed job should remain visible"),
        JobStatus::Failed
    );
    let dead_letters = queue
        .list_dead_letter_jobs(
            &test_database.paranoid_pool,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list dead letters after cancelled batch");
    assert!(dead_letters.jobs.is_empty());

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

async fn install_slow_failed_job_delete_trigger(
    test_database: &TestDatabase,
    task_name: &str,
    sleep_duration: Duration,
) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qdfbc_slow_delete_{suffix}"))
        .expect("slow delete function name");
    let trigger = PgIdentifier::new(format!("qdfbc_slow_delete_t_{suffix}"))
        .expect("slow delete trigger name");
    let sleep_seconds = sleep_duration.as_secs_f64();
    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.task_name = '{}' THEN
                    PERFORM pg_sleep({});
                END IF;
                RETURN OLD;
            END;
            $$
            "#,
            function.quoted(),
            task_name,
            sleep_seconds
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE DELETE ON {}
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
            .expect("install slow failed-job delete trigger");
    }
}
