use super::*;

#[tokio::test]
async fn queue_validation_rejects_missing_or_incompatible_active_dedupe_unique_index() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;

    let index_name =
        fetch_active_dedupe_index_name(&test_database.sqlx_pool, &test_database.config)
            .await
            .expect("active dedupe index should exist");
    let drop_index = format!(
        "DROP INDEX {}",
        PgIdentifier::new(index_name).expect("index name").quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_index.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop active dedupe index");

    let validate_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject missing dedupe conflict arbiter");
    assert!(matches!(validate_error, Error::Database(_)));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let index_name =
        fetch_active_dedupe_index_name(&test_database.sqlx_pool, &test_database.config)
            .await
            .expect("active dedupe index should exist");
    let index_identifier = PgIdentifier::new(index_name).expect("index name");
    let drop_index = format!("DROP INDEX {}", index_identifier.quoted());
    sqlx::query(sqlx::AssertSqlSafe(drop_index.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop active dedupe index before incompatible replacement");
    let create_incompatible_index = format!(
        r#"
        CREATE UNIQUE INDEX {}
        ON {} (task_name, dedupe_key)
        WHERE dedupe_key IS NOT NULL AND status = 'pending'
        "#,
        index_identifier.quoted(),
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(create_incompatible_index.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("create incompatible active dedupe index");
    let validate_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject incompatible dedupe conflict arbiter");
    assert!(matches!(validate_error, Error::Database(_)));

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_missing_or_incompatible_required_performance_index() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;

    let index_name = fetch_queue_index_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "(status, execution_heartbeat_at, id)",
    )
    .await;
    let index_identifier = PgIdentifier::new(index_name).expect("heartbeat index name");
    let drop_index = format!("DROP INDEX {}", index_identifier.quoted());
    sqlx::query(sqlx::AssertSqlSafe(drop_index.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop heartbeat index");

    let missing_index_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject missing heartbeat index");
    assert_queue_database_error_contains(&missing_index_error, "missing required index");

    reset_queue_schema(&test_database).await;
    let index_name = fetch_queue_index_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "(status, execution_heartbeat_at, id)",
    )
    .await;
    let index_identifier = PgIdentifier::new(index_name).expect("heartbeat index name");
    let drop_index = format!("DROP INDEX {}", index_identifier.quoted());
    sqlx::query(sqlx::AssertSqlSafe(drop_index.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop heartbeat index before incompatible replacement");
    let create_incompatible_index = format!(
        r#"
        CREATE INDEX {}
        ON {} (status, execution_heartbeat_at, id)
        WHERE status = 'running'
        "#,
        index_identifier.quoted(),
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(create_incompatible_index.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("create incompatible heartbeat index");

    let incompatible_index_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject incompatible heartbeat index");
    assert_queue_database_error_contains(&incompatible_index_error, "incompatible predicate");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_incompatible_job_column_shape() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    let alter_type = format!(
        "ALTER TABLE {} ALTER COLUMN execution_heartbeat_at TYPE TEXT",
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(alter_type.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("alter execution heartbeat type");
    let wrong_type_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject wrong execution heartbeat type");
    assert_queue_database_error_contains(&wrong_type_error, "execution_heartbeat_at has type text");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let drop_column = format!(
        "ALTER TABLE {} DROP COLUMN updated_at",
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_column.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop updated_at column");
    let missing_column_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject missing updated_at");
    assert_queue_database_error_contains(&missing_column_error, "missing column updated_at");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_incompatible_dead_letter_and_pause_columns() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
    )
    .await;
    let create_incompatible_dead_letter_table = format!(
        r#"
        CREATE TABLE {} (
            id BYTEA PRIMARY KEY CHECK (octet_length(id) = {}),
            original_job_id BYTEA NOT NULL CHECK (octet_length(original_job_id) = {}),
            task_name TEXT COLLATE "C" NOT NULL,
            payload JSONB NOT NULL,
            last_error TEXT COLLATE "C" NOT NULL,
            retry_count INT NOT NULL,
            max_retries INT NOT NULL,
            timeout_nanos BIGINT NOT NULL DEFAULT 0,
            dedupe_key TEXT COLLATE "C",
            reason BIGINT NOT NULL,
            dead_lettered_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        test_database.config.dead_letter_table_name.quoted(),
        paranoid::queue::JOB_ID_SIZE,
        paranoid::queue::JOB_ID_SIZE
    );
    sqlx::query(sqlx::AssertSqlSafe(
        create_incompatible_dead_letter_table.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("create incompatible dead-letter table");
    let dead_letter_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject wrong dead-letter reason type");
    assert_queue_database_error_contains(&dead_letter_error, "reason has type bigint");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let reason_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
        "reason_allowed",
    )
    .await;
    let reason_constraint_identifier =
        PgIdentifier::new(reason_constraint_name).expect("reason constraint name");
    let quoted_reason_constraint_name = reason_constraint_identifier.quoted();
    let drop_reason_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.dead_letter_table_name.quoted(),
        quoted_reason_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_reason_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop reason constraint before replacement");
    let add_broadened_reason_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            reason IN (
                'max_retries_exceeded',
                'permanent_error',
                'operator_action',
                'execution_expired',
                'manual_review'
            )
        )
        "#,
        test_database.config.dead_letter_table_name.quoted(),
        quoted_reason_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_reason_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened reason constraint");
    let broadened_reason_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened dead-letter reason constraint");
    assert_queue_database_error_contains(&broadened_reason_error, "incompatible definition");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let alter_pause_key_collation = format!(
        r#"ALTER TABLE {} ALTER COLUMN key TYPE TEXT COLLATE "default""#,
        test_database.config.pause_table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(alter_pause_key_collation.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("alter pause key collation");
    let pause_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect_err("validation should reject wrong pause key collation");
    assert_queue_database_error_contains(&pause_error, "key must use C/POSIX collation");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_non_c_collation_on_every_correctness_text_column() {
    let test_database = TestDatabase::connect().await;

    let text_columns = [
        (test_database.config.table_name.clone(), "task_name"),
        (test_database.config.table_name.clone(), "status"),
        (test_database.config.table_name.clone(), "last_error"),
        (test_database.config.table_name.clone(), "dedupe_key"),
        (test_database.config.table_name.clone(), "worker_id"),
        (
            test_database.config.dead_letter_table_name.clone(),
            "task_name",
        ),
        (
            test_database.config.dead_letter_table_name.clone(),
            "last_error",
        ),
        (
            test_database.config.dead_letter_table_name.clone(),
            "dedupe_key",
        ),
        (
            test_database.config.dead_letter_table_name.clone(),
            "reason",
        ),
        (test_database.config.pause_table_name.clone(), "key"),
        (test_database.config.pause_table_name.clone(), "task_name"),
    ];

    for (table_name, column_name) in text_columns {
        reset_queue_schema(&test_database).await;
        let column_identifier = PgIdentifier::new(column_name).expect("column name");
        let alter_column_collation = format!(
            r#"ALTER TABLE {} ALTER COLUMN {} TYPE TEXT COLLATE "default""#,
            table_name.quoted(),
            column_identifier.quoted()
        );
        sqlx::query(sqlx::AssertSqlSafe(alter_column_collation.as_str()))
            .execute(&test_database.sqlx_pool)
            .await
            .expect("alter queue text column collation");

        let validation_error = validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject non-C queue text column collation");
        assert_queue_database_error_contains(
            &validation_error,
            &format!("{column_name} must use C/POSIX collation"),
        );
    }

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_missing_or_broadened_job_status_constraint() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    let status_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "status_allowed",
    )
    .await;
    let drop_status_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        PgIdentifier::new(status_constraint_name.clone())
            .expect("status constraint name")
            .quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_status_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop status constraint");
    let missing_constraint_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject missing status constraint");
    assert_queue_database_error_contains(&missing_constraint_error, "missing check constraint");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let status_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "status_allowed",
    )
    .await;
    let status_constraint_identifier =
        PgIdentifier::new(status_constraint_name).expect("status constraint name");
    let quoted_status_constraint_name = status_constraint_identifier.quoted();
    let drop_status_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_status_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_status_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop status constraint before replacement");
    let add_broadened_status_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            status IN ('pending', 'running', 'completed', 'failed', 'paused')
        )
        "#,
        test_database.config.table_name.quoted(),
        quoted_status_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_status_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened status constraint");
    let broadened_constraint_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened status constraint");
    assert_queue_database_error_contains(&broadened_constraint_error, "incompatible definition");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_missing_or_broadened_job_lifecycle_constraint() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    let lifecycle_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "status_lifecycle_shape",
    )
    .await;
    let lifecycle_constraint_identifier =
        PgIdentifier::new(lifecycle_constraint_name).expect("lifecycle constraint name");
    let quoted_lifecycle_constraint_name = lifecycle_constraint_identifier.quoted();
    let drop_lifecycle_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_lifecycle_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_lifecycle_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop lifecycle constraint");
    let missing_lifecycle_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject missing lifecycle constraint");
    assert_queue_database_error_contains(&missing_lifecycle_error, "missing check constraint");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let lifecycle_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "status_lifecycle_shape",
    )
    .await;
    let lifecycle_constraint_identifier =
        PgIdentifier::new(lifecycle_constraint_name).expect("lifecycle constraint name");
    let quoted_lifecycle_constraint_name = lifecycle_constraint_identifier.quoted();
    let drop_lifecycle_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_lifecycle_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_lifecycle_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop lifecycle constraint before replacement");
    let add_broadened_lifecycle_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            (
                status = 'pending'
                AND worker_id IS NULL
                AND claimed_by_worker_at IS NULL
                AND execution_started_at IS NULL
                AND execution_heartbeat_at IS NULL
                AND finished_at IS NULL
            )
            OR
            (
                status = 'running'
                AND worker_id IS NOT NULL
                AND claimed_by_worker_at IS NOT NULL
                AND execution_heartbeat_at IS NOT NULL
                AND finished_at IS NULL
            )
            OR
            (
                status IN ('completed', 'failed')
                AND worker_id IS NULL
                AND claimed_by_worker_at IS NULL
                AND execution_started_at IS NULL
                AND execution_heartbeat_at IS NULL
                AND finished_at IS NOT NULL
            )
            OR
            (
                status = 'pending'
                AND worker_id IS NOT NULL
            )
        )
        "#,
        test_database.config.table_name.quoted(),
        quoted_lifecycle_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_lifecycle_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened lifecycle constraint");
    let broadened_lifecycle_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened lifecycle constraint");
    assert_queue_database_error_contains(
        &broadened_lifecycle_error,
        "accepted invalid pending row",
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_broadened_pause_key_task_constraint() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    let pause_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.pause_table_name,
        "key_task_match",
    )
    .await;
    let pause_constraint_identifier =
        PgIdentifier::new(pause_constraint_name).expect("pause constraint name");
    let quoted_pause_constraint_name = pause_constraint_identifier.quoted();
    let drop_pause_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.pause_table_name.quoted(),
        quoted_pause_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_pause_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop pause constraint before replacement");
    let add_broadened_pause_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            (
                key = '__global__'
                AND task_name IS NULL
            )
            OR
            (
                task_name IS NOT NULL
                AND key = 'task:' || task_name
            )
            OR
            (
                key <> ''
            )
        )
        "#,
        test_database.config.pause_table_name.quoted(),
        quoted_pause_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(add_broadened_pause_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("add broadened pause constraint");
    let broadened_pause_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened pause constraint");
    assert_queue_database_error_contains(&broadened_pause_error, "accepted invalid task pause row");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_missing_or_broadened_numeric_domain_constraints() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    let job_numeric_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "numeric_domains",
    )
    .await;
    let job_numeric_constraint_identifier =
        PgIdentifier::new(job_numeric_constraint_name).expect("job numeric constraint name");
    let quoted_job_numeric_constraint_name = job_numeric_constraint_identifier.quoted();
    let drop_job_numeric_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_job_numeric_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_job_numeric_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop job numeric constraint");
    let missing_job_numeric_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject missing job numeric constraint");
    assert_queue_database_error_contains(&missing_job_numeric_error, "missing check constraint");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let job_numeric_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "numeric_domains",
    )
    .await;
    let job_numeric_constraint_identifier =
        PgIdentifier::new(job_numeric_constraint_name).expect("job numeric constraint name");
    let quoted_job_numeric_constraint_name = job_numeric_constraint_identifier.quoted();
    let drop_job_numeric_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_job_numeric_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_job_numeric_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop job numeric constraint before replacement");
    let add_broadened_job_numeric_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            (
                retry_count >= 0
                AND max_retries >= 0
                AND timeout_nanos >= -1
            )
            OR retry_count = -1
        )
        "#,
        test_database.config.table_name.quoted(),
        quoted_job_numeric_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_job_numeric_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened job numeric constraint");
    let broadened_job_numeric_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened job numeric constraint");
    assert_queue_database_error_contains(&broadened_job_numeric_error, "accepted invalid job row");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let dead_letter_numeric_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
        "numeric_domains",
    )
    .await;
    let dead_letter_numeric_constraint_identifier =
        PgIdentifier::new(dead_letter_numeric_constraint_name)
            .expect("dead-letter numeric constraint name");
    let quoted_dead_letter_numeric_constraint_name =
        dead_letter_numeric_constraint_identifier.quoted();
    let drop_dead_letter_numeric_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.dead_letter_table_name.quoted(),
        quoted_dead_letter_numeric_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        drop_dead_letter_numeric_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("drop dead-letter numeric constraint before replacement");
    let add_broadened_dead_letter_numeric_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            (
                retry_count >= 0
                AND max_retries >= 0
                AND timeout_nanos >= -1
            )
            OR retry_count = -1
        )
        "#,
        test_database.config.dead_letter_table_name.quoted(),
        quoted_dead_letter_numeric_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_dead_letter_numeric_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened dead-letter numeric constraint");
    let broadened_dead_letter_numeric_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened dead-letter numeric constraint");
    assert_queue_database_error_contains(
        &broadened_dead_letter_numeric_error,
        "accepted invalid dead-letter row",
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_validation_rejects_missing_or_broadened_text_domain_constraints() {
    let test_database = TestDatabase::connect().await;

    reset_queue_schema(&test_database).await;
    let job_text_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "text_domains",
    )
    .await;
    let job_text_constraint_identifier =
        PgIdentifier::new(job_text_constraint_name).expect("job text constraint name");
    let quoted_job_text_constraint_name = job_text_constraint_identifier.quoted();
    let drop_job_text_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_job_text_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_job_text_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop job text constraint");
    let missing_job_text_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject missing job text constraint");
    assert_queue_database_error_contains(&missing_job_text_error, "missing check constraint");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let job_text_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        "text_domains",
    )
    .await;
    let job_text_constraint_identifier =
        PgIdentifier::new(job_text_constraint_name).expect("job text constraint name");
    let quoted_job_text_constraint_name = job_text_constraint_identifier.quoted();
    let drop_job_text_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.table_name.quoted(),
        quoted_job_text_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_job_text_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop job text constraint before replacement");
    let add_broadened_job_text_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            (
                task_name ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length(task_name) <= {}
                AND (
                    dedupe_key IS NULL
                    OR (
                        dedupe_key <> ''
                        AND octet_length(dedupe_key) <= {}
                    )
                )
                AND (
                    worker_id IS NULL
                    OR (
                        worker_id <> ''
                        AND octet_length(worker_id) <= {}
                    )
                )
            )
            OR COALESCE(worker_id = '', false)
        )
        "#,
        test_database.config.table_name.quoted(),
        quoted_job_text_constraint_name,
        paranoid::queue::MAX_TASK_NAME_BYTES,
        paranoid::queue::MAX_DEDUPE_KEY_BYTES,
        paranoid::queue::MAX_WORKER_OWNER_ID_BYTES
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_job_text_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened job text constraint");
    let broadened_job_text_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened job text constraint");
    assert_queue_database_error_contains(&broadened_job_text_error, "empty worker_id");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let dead_letter_text_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
        "text_domains",
    )
    .await;
    let dead_letter_text_constraint_identifier =
        PgIdentifier::new(dead_letter_text_constraint_name).expect("dead-letter text constraint");
    let quoted_dead_letter_text_constraint_name = dead_letter_text_constraint_identifier.quoted();
    let drop_dead_letter_text_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.dead_letter_table_name.quoted(),
        quoted_dead_letter_text_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(
        drop_dead_letter_text_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("drop dead-letter text constraint before replacement");
    let add_broadened_dead_letter_text_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            (
                task_name ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length(task_name) <= {}
                AND (
                    dedupe_key IS NULL
                    OR (
                        dedupe_key <> ''
                        AND octet_length(dedupe_key) <= {}
                    )
                )
            )
            OR COALESCE(dedupe_key = '', false)
        )
        "#,
        test_database.config.dead_letter_table_name.quoted(),
        quoted_dead_letter_text_constraint_name,
        paranoid::queue::MAX_TASK_NAME_BYTES,
        paranoid::queue::MAX_DEDUPE_KEY_BYTES
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_dead_letter_text_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened dead-letter text constraint");
    let broadened_dead_letter_text_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened dead-letter text constraint");
    assert_queue_database_error_contains(&broadened_dead_letter_text_error, "empty dedupe_key");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    reset_queue_schema(&test_database).await;
    let pause_text_constraint_name = fetch_check_constraint_name_containing(
        &test_database.sqlx_pool,
        &test_database.config.pause_table_name,
        "text_domains",
    )
    .await;
    let pause_text_constraint_identifier =
        PgIdentifier::new(pause_text_constraint_name).expect("pause text constraint name");
    let quoted_pause_text_constraint_name = pause_text_constraint_identifier.quoted();
    let drop_pause_text_constraint = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        test_database.config.pause_table_name.quoted(),
        quoted_pause_text_constraint_name
    );
    sqlx::query(sqlx::AssertSqlSafe(drop_pause_text_constraint.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop pause text constraint before replacement");
    let add_broadened_pause_text_constraint = format!(
        r#"
        ALTER TABLE {} ADD CONSTRAINT {} CHECK (
            task_name IS NULL
            OR (
                task_name IS NOT NULL
                AND task_name ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length(task_name) <= {}
            )
            OR task_name = ''
        )
        "#,
        test_database.config.pause_table_name.quoted(),
        quoted_pause_text_constraint_name,
        paranoid::queue::MAX_TASK_NAME_BYTES
    );
    sqlx::query(sqlx::AssertSqlSafe(
        add_broadened_pause_text_constraint.as_str(),
    ))
    .execute(&test_database.sqlx_pool)
    .await
    .expect("add broadened pause text constraint");
    let broadened_pause_text_error =
        validate_schema(&test_database.paranoid_pool, &test_database.config)
            .await
            .expect_err("validation should reject broadened pause text constraint");
    assert_queue_database_error_contains(&broadened_pause_text_error, "empty task_name");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
