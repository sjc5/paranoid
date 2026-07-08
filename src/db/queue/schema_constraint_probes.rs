use super::sql::*;
use super::*;

const QUEUE_SCHEMA_VALIDATION_PROBE_SAVEPOINT_QUERY: &str =
    "SAVEPOINT __paranoid_queue_schema_validation_probe";
const QUEUE_SCHEMA_VALIDATION_PROBE_ROLLBACK_QUERY: &str =
    "ROLLBACK TO SAVEPOINT __paranoid_queue_schema_validation_probe";
const QUEUE_SCHEMA_VALIDATION_PROBE_RELEASE_QUERY: &str =
    "RELEASE SAVEPOINT __paranoid_queue_schema_validation_probe";

fn job_lifecycle_probe_insert_columns() -> String {
    QueueColumn::list(&[
        QueueColumn::Id,
        QueueColumn::TaskName,
        QueueColumn::Payload,
        QueueColumn::Status,
        QueueColumn::RunAtOrAfter,
        QueueColumn::WorkerId,
        QueueColumn::ClaimedByWorkerAt,
        QueueColumn::ExecutionHeartbeatAt,
        QueueColumn::CreatedAt,
        QueueColumn::UpdatedAt,
    ])
}

fn job_numeric_probe_insert_columns() -> String {
    QueueColumn::list(&[
        QueueColumn::Id,
        QueueColumn::TaskName,
        QueueColumn::Payload,
        QueueColumn::Status,
        QueueColumn::RunAtOrAfter,
        QueueColumn::RetryCount,
        QueueColumn::MaxRetries,
        QueueColumn::TimeoutNanos,
        QueueColumn::CreatedAt,
        QueueColumn::UpdatedAt,
    ])
}

fn job_text_probe_insert_columns() -> String {
    QueueColumn::list(&[
        QueueColumn::Id,
        QueueColumn::TaskName,
        QueueColumn::Payload,
        QueueColumn::Status,
        QueueColumn::RunAtOrAfter,
        QueueColumn::DedupeKey,
        QueueColumn::WorkerId,
        QueueColumn::ClaimedByWorkerAt,
        QueueColumn::ExecutionHeartbeatAt,
        QueueColumn::CreatedAt,
        QueueColumn::UpdatedAt,
    ])
}

fn dead_letter_numeric_probe_insert_columns() -> String {
    QueueColumn::list(&[
        QueueColumn::Id,
        QueueColumn::OriginalJobId,
        QueueColumn::TaskName,
        QueueColumn::Payload,
        QueueColumn::LastError,
        QueueColumn::RetryCount,
        QueueColumn::MaxRetries,
        QueueColumn::TimeoutNanos,
        QueueColumn::Reason,
        QueueColumn::DeadLetteredAt,
        QueueColumn::CreatedAt,
        QueueColumn::UpdatedAt,
    ])
}

fn dead_letter_text_probe_insert_columns() -> String {
    QueueColumn::list(&[
        QueueColumn::Id,
        QueueColumn::OriginalJobId,
        QueueColumn::TaskName,
        QueueColumn::Payload,
        QueueColumn::LastError,
        QueueColumn::RetryCount,
        QueueColumn::MaxRetries,
        QueueColumn::TimeoutNanos,
        QueueColumn::DedupeKey,
        QueueColumn::Reason,
        QueueColumn::DeadLetteredAt,
        QueueColumn::CreatedAt,
        QueueColumn::UpdatedAt,
    ])
}

fn pause_probe_insert_columns() -> String {
    QueueColumn::list(&[
        QueueColumn::Key,
        QueueColumn::TaskName,
        QueueColumn::PausedAt,
        QueueColumn::UpdatedAt,
    ])
}

pub(super) async fn validate_job_lifecycle_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let invalid_id = id::SortableId::new()?;
    create_semantic_constraint_probe_savepoint(tx).await?;
    let insert_columns = job_lifecycle_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES (
            $1,
            '__paranoid_queue_invalid_lifecycle_probe',
            '{{}}'::jsonb,
            'pending',
            statement_timestamp(),
            'worker-invalid',
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        config.table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(invalid_id.as_bytes().as_slice())
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.table_name,
        &job_lifecycle_constraint_identifier(config),
        "pending row with worker ownership fields",
    )
    .await
}

pub(super) async fn validate_pause_key_task_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    create_semantic_constraint_probe_savepoint(tx).await?;
    let insert_columns = pause_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES (
            'task:__paranoid_queue_probe_a',
            '__paranoid_queue_probe_b',
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        config.pause_table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.pause_table_name,
        &pause_key_task_constraint_identifier(config),
        "task pause row whose key does not match task_name",
    )
    .await
}

pub(super) async fn validate_job_numeric_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    validate_job_numeric_constraint_rejects_values(
        tx,
        config,
        -1,
        5,
        0,
        "job row with negative retry_count",
    )
    .await?;
    validate_job_numeric_constraint_rejects_values(
        tx,
        config,
        0,
        -1,
        0,
        "job row with negative max_retries",
    )
    .await?;
    validate_job_numeric_constraint_rejects_values(
        tx,
        config,
        0,
        5,
        -2,
        "job row with invalid negative timeout_nanos",
    )
    .await
}

async fn validate_job_numeric_constraint_rejects_values(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    retry_count: i32,
    max_retries: i32,
    timeout_nanos: i64,
    invalid_shape: &'static str,
) -> Result<(), Error> {
    let invalid_id = id::SortableId::new()?;
    create_semantic_constraint_probe_savepoint(tx).await?;
    let insert_columns = job_numeric_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES (
            $1,
            '__paranoid_queue_invalid_numeric_probe',
            '{{}}'::jsonb,
            'pending',
            statement_timestamp(),
            $2,
            $3,
            $4,
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        config.table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(invalid_id.as_bytes().as_slice())
        .bind(retry_count)
        .bind(max_retries)
        .bind(timeout_nanos)
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.table_name,
        &job_numeric_constraint_identifier(config),
        invalid_shape,
    )
    .await
}

pub(super) async fn validate_dead_letter_numeric_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    validate_dead_letter_numeric_constraint_rejects_values(
        tx,
        config,
        -1,
        5,
        0,
        "dead-letter row with negative retry_count",
    )
    .await?;
    validate_dead_letter_numeric_constraint_rejects_values(
        tx,
        config,
        0,
        -1,
        0,
        "dead-letter row with negative max_retries",
    )
    .await?;
    validate_dead_letter_numeric_constraint_rejects_values(
        tx,
        config,
        0,
        5,
        -2,
        "dead-letter row with invalid negative timeout_nanos",
    )
    .await
}

async fn validate_dead_letter_numeric_constraint_rejects_values(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    retry_count: i32,
    max_retries: i32,
    timeout_nanos: i64,
    invalid_shape: &'static str,
) -> Result<(), Error> {
    let invalid_id = id::SortableId::new()?;
    let original_job_id = id::SortableId::new()?;
    create_semantic_constraint_probe_savepoint(tx).await?;
    let insert_columns = dead_letter_numeric_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES (
            $1,
            $2,
            '__paranoid_queue_invalid_dead_letter_numeric_probe',
            '{{}}'::jsonb,
            'failed',
            $3,
            $4,
            $5,
            'permanent_error',
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        config.dead_letter_table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(invalid_id.as_bytes().as_slice())
        .bind(original_job_id.as_bytes().as_slice())
        .bind(retry_count)
        .bind(max_retries)
        .bind(timeout_nanos)
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.dead_letter_table_name,
        &dead_letter_numeric_constraint_identifier(config),
        invalid_shape,
    )
    .await
}

pub(super) async fn validate_job_text_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let too_long_task_name = "a".repeat(MAX_QUEUE_TASK_NAME_BYTES + 1);
    let too_long_dedupe_key = "d".repeat(MAX_QUEUE_DEDUPE_KEY_BYTES + 1);
    let too_long_worker_id = "w".repeat(MAX_QUEUE_WORKER_OWNER_ID_BYTES + 1);
    validate_job_text_constraint_rejects_values(
        tx,
        config,
        ".invalid",
        None,
        None,
        "job row with invalid task_name",
    )
    .await?;
    validate_job_text_constraint_rejects_values(
        tx,
        config,
        &too_long_task_name,
        None,
        None,
        "job row with too-long task_name",
    )
    .await?;
    validate_job_text_constraint_rejects_values(
        tx,
        config,
        "task.valid",
        Some(""),
        None,
        "job row with empty dedupe_key",
    )
    .await?;
    validate_job_text_constraint_rejects_values(
        tx,
        config,
        "task.valid",
        Some(&too_long_dedupe_key),
        None,
        "job row with too-long dedupe_key",
    )
    .await?;
    validate_job_text_constraint_rejects_values(
        tx,
        config,
        "task.valid",
        None,
        Some(""),
        "job row with empty worker_id",
    )
    .await?;
    validate_job_text_constraint_rejects_values(
        tx,
        config,
        "task.valid",
        None,
        Some(&too_long_worker_id),
        "job row with too-long worker_id",
    )
    .await
}

async fn validate_job_text_constraint_rejects_values(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    task_name: &str,
    dedupe_key: Option<&str>,
    worker_id: Option<&str>,
    invalid_shape: &'static str,
) -> Result<(), Error> {
    let invalid_id = id::SortableId::new()?;
    create_semantic_constraint_probe_savepoint(tx).await?;
    let status = if worker_id.is_some() {
        "running"
    } else {
        "pending"
    };
    let insert_columns = job_text_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES (
            $1,
            $2,
            '{{}}'::jsonb,
            $3,
            statement_timestamp(),
            $4,
            $5,
            CASE WHEN $5::text IS NULL THEN NULL ELSE statement_timestamp() END,
            CASE WHEN $5::text IS NULL THEN NULL ELSE statement_timestamp() END,
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        config.table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(invalid_id.as_bytes().as_slice())
        .bind(task_name)
        .bind(status)
        .bind(dedupe_key)
        .bind(worker_id)
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.table_name,
        &job_text_constraint_identifier(config),
        invalid_shape,
    )
    .await
}

pub(super) async fn validate_dead_letter_text_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let too_long_task_name = "a".repeat(MAX_QUEUE_TASK_NAME_BYTES + 1);
    let too_long_dedupe_key = "d".repeat(MAX_QUEUE_DEDUPE_KEY_BYTES + 1);
    validate_dead_letter_text_constraint_rejects_values(
        tx,
        config,
        ".invalid",
        None,
        "dead-letter row with invalid task_name",
    )
    .await?;
    validate_dead_letter_text_constraint_rejects_values(
        tx,
        config,
        &too_long_task_name,
        None,
        "dead-letter row with too-long task_name",
    )
    .await?;
    validate_dead_letter_text_constraint_rejects_values(
        tx,
        config,
        "task.valid",
        Some(""),
        "dead-letter row with empty dedupe_key",
    )
    .await?;
    validate_dead_letter_text_constraint_rejects_values(
        tx,
        config,
        "task.valid",
        Some(&too_long_dedupe_key),
        "dead-letter row with too-long dedupe_key",
    )
    .await
}

async fn validate_dead_letter_text_constraint_rejects_values(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    task_name: &str,
    dedupe_key: Option<&str>,
    invalid_shape: &'static str,
) -> Result<(), Error> {
    let invalid_id = id::SortableId::new()?;
    let original_job_id = id::SortableId::new()?;
    create_semantic_constraint_probe_savepoint(tx).await?;
    let insert_columns = dead_letter_text_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES (
            $1,
            $2,
            $3,
            '{{}}'::jsonb,
            'failed',
            0,
            5,
            0,
            $4,
            'permanent_error',
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        )
        "#,
        config.dead_letter_table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(invalid_id.as_bytes().as_slice())
        .bind(original_job_id.as_bytes().as_slice())
        .bind(task_name)
        .bind(dedupe_key)
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.dead_letter_table_name,
        &dead_letter_text_constraint_identifier(config),
        invalid_shape,
    )
    .await
}

pub(super) async fn validate_pause_text_constraint_rejects_invalid_shape(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let too_long_task_name = "a".repeat(MAX_QUEUE_TASK_NAME_BYTES + 1);
    validate_pause_text_constraint_rejects_values(
        tx,
        config,
        "task:.invalid",
        Some(".invalid"),
        "pause row with invalid task_name",
    )
    .await?;
    validate_pause_text_constraint_rejects_values(
        tx,
        config,
        "task:",
        Some(""),
        "pause row with empty task_name",
    )
    .await?;
    validate_pause_text_constraint_rejects_values(
        tx,
        config,
        &format!("task:{too_long_task_name}"),
        Some(&too_long_task_name),
        "pause row with too-long task_name",
    )
    .await
}

async fn validate_pause_text_constraint_rejects_values(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    key: &str,
    task_name: Option<&str>,
    invalid_shape: &'static str,
) -> Result<(), Error> {
    create_semantic_constraint_probe_savepoint(tx).await?;
    let insert_columns = pause_probe_insert_columns();
    let statement = format!(
        r#"
        INSERT INTO {} ({insert_columns})
        VALUES ($1, $2, statement_timestamp(), statement_timestamp())
        "#,
        config.pause_table_name.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
        Some(statement.as_str()),
    );
    let probe_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(key)
        .bind(task_name)
        .execute(tx.inner.as_mut())
        .await;
    finish_semantic_constraint_probe(
        tx,
        probe_result,
        &config.pause_table_name,
        &pause_text_constraint_identifier(config),
        invalid_shape,
    )
    .await
}

async fn finish_semantic_constraint_probe(
    tx: &mut Tx<'_>,
    probe_result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    table_name: &PgQualifiedTableName,
    constraint_name: &PgIdentifier,
    invalid_shape: &'static str,
) -> Result<(), Error> {
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_ROLLBACK,
        Some(QUEUE_SCHEMA_VALIDATION_PROBE_ROLLBACK_QUERY),
    );
    pooler_safe_query(QUEUE_SCHEMA_VALIDATION_PROBE_ROLLBACK_QUERY)
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_RELEASE,
        Some(QUEUE_SCHEMA_VALIDATION_PROBE_RELEASE_QUERY),
    );
    pooler_safe_query(QUEUE_SCHEMA_VALIDATION_PROBE_RELEASE_QUERY)
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    match probe_result {
        Ok(_) => Err(DbError::schema_mismatch(format!(
            "table {} check constraint {} accepted invalid {}",
            table_name.quoted(),
            constraint_name.quoted(),
            invalid_shape
        ))
        .into()),
        Err(error)
            if sqlx_error_is_check_violation_for_constraint(&error, constraint_name.as_str()) =>
        {
            Ok(())
        }
        Err(error) if sqlx_error_is_check_violation(&error) => {
            Err(DbError::schema_mismatch(format!(
                "table {} check constraint {} did not reject invalid {}",
                table_name.quoted(),
                constraint_name.quoted(),
                invalid_shape
            ))
            .into())
        }
        Err(error) => Err(DbError::query(error).into()),
    }
}

fn sqlx_error_is_check_violation_for_constraint(error: &sqlx::Error, constraint: &str) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| {
            let sql_state = database_error.code().map(PgSqlState::from_code)?;
            let violated_constraint = database_error.constraint()?;
            Some((sql_state, violated_constraint))
        })
        .is_some_and(|(sql_state, violated_constraint)| {
            sql_state == PgSqlState::CheckViolation && violated_constraint == constraint
        })
}

fn sqlx_error_is_check_violation(error: &sqlx::Error) -> bool {
    matches!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .map(PgSqlState::from_code),
        Some(PgSqlState::CheckViolation)
    )
}

async fn create_semantic_constraint_probe_savepoint(tx: &mut Tx<'_>) -> Result<(), Error> {
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_PROBE_SAVEPOINT,
        Some(QUEUE_SCHEMA_VALIDATION_PROBE_SAVEPOINT_QUERY),
    );
    pooler_safe_query(QUEUE_SCHEMA_VALIDATION_PROBE_SAVEPOINT_QUERY)
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}
