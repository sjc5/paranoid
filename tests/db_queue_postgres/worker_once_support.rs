use super::*;

pub(super) async fn install_worker_terminal_write_failure_triggers(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let complete_function =
        PgIdentifier::new(format!("qtwf_complete_{suffix}")).expect("complete function name");
    let retry_function =
        PgIdentifier::new(format!("qtwf_retry_{suffix}")).expect("retry function name");
    let failed_function =
        PgIdentifier::new(format!("qtwf_failed_{suffix}")).expect("failed function name");
    let complete_trigger =
        PgIdentifier::new(format!("qtwf_complete_t_{suffix}")).expect("complete trigger name");
    let retry_trigger =
        PgIdentifier::new(format!("qtwf_retry_t_{suffix}")).expect("retry trigger name");
    let failed_trigger =
        PgIdentifier::new(format!("qtwf_failed_t_{suffix}")).expect("failed trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'completed' THEN
                    RAISE EXCEPTION 'intentional completed write failure';
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            complete_function.quoted()
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE UPDATE ON {}
            FOR EACH ROW
            EXECUTE FUNCTION {}()
            "#,
            complete_trigger.quoted(),
            test_database.config.table_name.quoted(),
            complete_function.quoted()
        ),
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'pending' AND NEW.retry_count > OLD.retry_count THEN
                    RAISE EXCEPTION 'intentional retry schedule write failure';
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            retry_function.quoted()
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE UPDATE ON {}
            FOR EACH ROW
            EXECUTE FUNCTION {}()
            "#,
            retry_trigger.quoted(),
            test_database.config.table_name.quoted(),
            retry_function.quoted()
        ),
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'failed' THEN
                    RAISE EXCEPTION 'intentional failed write failure';
                END IF;
                RETURN NEW;
            END;
            $$
            "#,
            failed_function.quoted()
        ),
        format!(
            r#"
            CREATE TRIGGER {}
            BEFORE UPDATE ON {}
            FOR EACH ROW
            EXECUTE FUNCTION {}()
            "#,
            failed_trigger.quoted(),
            test_database.config.table_name.quoted(),
            failed_function.quoted()
        ),
    ];

    for statement in statements {
        sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .expect("install worker terminal write failure trigger");
    }
}

pub(super) async fn install_worker_completion_and_return_to_pending_failure_trigger(
    test_database: &TestDatabase,
) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function =
        PgIdentifier::new(format!("qcrp_return_{suffix}")).expect("return function name");
    let trigger =
        PgIdentifier::new(format!("qcrp_return_t_{suffix}")).expect("return trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.task_name = 'task.worker.return_to_pending_write_fails'
                    AND NEW.status = 'completed'
                THEN
                    RAISE EXCEPTION 'intentional completion write failure before cleanup';
                END IF;
                IF NEW.task_name = 'task.worker.return_to_pending_write_fails'
                    AND OLD.status = 'running'
                    AND NEW.status = 'pending'
                THEN
                    RAISE EXCEPTION 'intentional return-to-pending write failure';
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
            .expect("install worker return-to-pending write failure trigger");
    }
}

pub(super) async fn install_worker_start_write_failure_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qswf_start_{suffix}")).expect("start function name");
    let trigger = PgIdentifier::new(format!("qswf_start_t_{suffix}")).expect("start trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'running'
                    AND OLD.execution_started_at IS NULL
                    AND NEW.execution_started_at IS NOT NULL
                THEN
                    RAISE EXCEPTION 'intentional start write failure';
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
            .expect("install worker start write failure trigger");
    }
}

pub(super) async fn install_worker_claim_ownership_steal_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qcos_claim_{suffix}")).expect("claim function name");
    let trigger = PgIdentifier::new(format!("qcos_claim_t_{suffix}")).expect("claim trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.status = 'pending'
                    AND NEW.status = 'running'
                    AND NEW.task_name = 'task.worker.claim_stolen_before_start'
                THEN
                    NEW.worker_id := 'different-worker';
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
            .expect("install worker ownership steal trigger");
    }
}

pub(super) async fn install_worker_claim_unknown_task_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qcut_claim_{suffix}")).expect("claim function name");
    let trigger = PgIdentifier::new(format!("qcut_claim_t_{suffix}")).expect("claim trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.status = 'pending'
                    AND NEW.status = 'running'
                    AND NEW.task_name = 'task.worker.known_then_unknown'
                THEN
                    NEW.task_name := 'task.worker.unknown_after_claim';
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
            .expect("install worker unknown task trigger");
    }
}

pub(super) async fn install_worker_slow_claim_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qsc_slow_{suffix}")).expect("slow function name");
    let trigger = PgIdentifier::new(format!("qsc_slow_t_{suffix}")).expect("slow trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.status = 'pending'
                    AND NEW.status = 'running'
                    AND NEW.task_name = 'task.worker.slow_claim'
                THEN
                    PERFORM pg_sleep(0.15);
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
            .expect("install worker slow claim trigger");
    }
}

pub(super) async fn install_worker_slow_start_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function = PgIdentifier::new(format!("qss_start_{suffix}")).expect("start function name");
    let trigger = PgIdentifier::new(format!("qss_start_t_{suffix}")).expect("start trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'running'
                    AND NEW.task_name = 'task.worker.slow_start'
                    AND OLD.execution_started_at IS NULL
                    AND NEW.execution_started_at IS NOT NULL
                THEN
                    PERFORM pg_sleep(1.0);
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
            .expect("install worker slow start trigger");
    }
}

pub(super) async fn install_worker_heartbeat_write_failure_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function =
        PgIdentifier::new(format!("qhwf_heartbeat_{suffix}")).expect("heartbeat function name");
    let trigger =
        PgIdentifier::new(format!("qhwf_heartbeat_t_{suffix}")).expect("heartbeat trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'running'
                    AND NEW.task_name = 'task.worker.heartbeat_write_fails'
                    AND OLD.execution_started_at IS NOT NULL
                    AND NEW.execution_started_at IS NOT NULL
                    AND NEW.execution_heartbeat_at IS DISTINCT FROM OLD.execution_heartbeat_at
                THEN
                    RAISE EXCEPTION 'intentional heartbeat write failure';
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
            .expect("install worker heartbeat write failure trigger");
    }
}

pub(super) async fn install_worker_slow_heartbeat_trigger(test_database: &TestDatabase) {
    let suffix = paranoid::queue::JobId::new()
        .expect("new trigger suffix")
        .to_string()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    let function =
        PgIdentifier::new(format!("qsh_heartbeat_{suffix}")).expect("heartbeat function name");
    let trigger =
        PgIdentifier::new(format!("qsh_heartbeat_t_{suffix}")).expect("heartbeat trigger name");

    let statements = [
        format!(
            r#"
            CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF NEW.status = 'running'
                    AND NEW.task_name = 'task.worker.slow_manual_heartbeat'
                    AND OLD.execution_started_at IS NOT NULL
                    AND NEW.execution_started_at IS NOT NULL
                    AND NEW.execution_heartbeat_at IS DISTINCT FROM OLD.execution_heartbeat_at
                THEN
                    PERFORM pg_sleep(1.0);
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
            .expect("install worker slow heartbeat trigger");
    }
}

pub(super) async fn assert_job_returned_to_pending_after_terminal_write_failure(
    queue: &Store,
    test_database: &TestDatabase,
    job_id: paranoid::queue::JobId,
) {
    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, job_id)
        .await
        .expect("fetch job after terminal write failure");
    assert_eq!(job_after_error.status, JobStatus::Pending);
    assert_eq!(job_after_error.retry_count, 0);
    assert!(job_after_error.last_error.is_none());
    assert!(job_after_error.worker_owner_id.is_none());
    assert!(
        job_after_error
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_error
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );
}
