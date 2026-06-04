use super::schema_constraint_probes::*;
use super::sql::*;
use super::*;

pub(super) async fn validate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    validate_table_columns(tx, &config.table_name, &required_job_columns()).await?;
    validate_table_columns(
        tx,
        &config.dead_letter_table_name,
        &required_dead_letter_columns(),
    )
    .await?;
    validate_table_columns(tx, &config.pause_table_name, &required_pause_columns()).await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_status_constraint_identifier(config),
        job_status_constraint_fragments(),
        Some(job_status_constraint_literals()),
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_lifecycle_constraint_identifier(config),
        job_lifecycle_constraint_fragments(),
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_numeric_constraint_identifier(config),
        numeric_constraint_fragments(),
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_text_constraint_identifier(config),
        job_text_constraint_fragments(),
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.dead_letter_table_name,
        &dead_letter_reason_constraint_identifier(config),
        dead_letter_reason_constraint_fragments(),
        Some(dead_letter_reason_constraint_literals()),
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.dead_letter_table_name,
        &dead_letter_numeric_constraint_identifier(config),
        numeric_constraint_fragments(),
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.dead_letter_table_name,
        &dead_letter_text_constraint_identifier(config),
        dead_letter_text_constraint_fragments(),
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.pause_table_name,
        &pause_key_task_constraint_identifier(config),
        pause_key_task_constraint_fragments(),
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.pause_table_name,
        &pause_text_constraint_identifier(config),
        pause_text_constraint_fragments(),
        None,
    )
    .await?;
    validate_job_lifecycle_constraint_rejects_invalid_shape(tx, config).await?;
    validate_job_numeric_constraint_rejects_invalid_shape(tx, config).await?;
    validate_job_text_constraint_rejects_invalid_shape(tx, config).await?;
    validate_dead_letter_numeric_constraint_rejects_invalid_shape(tx, config).await?;
    validate_dead_letter_text_constraint_rejects_invalid_shape(tx, config).await?;
    validate_pause_key_task_constraint_rejects_invalid_shape(tx, config).await?;
    validate_pause_text_constraint_rejects_invalid_shape(tx, config).await?;
    validate_required_indexes(tx, config).await?;
    validate_active_dedupe_conflict_arbiter(tx, config).await
}

async fn validate_table_columns(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    required_columns: &[RequiredColumn],
) -> Result<(), Error> {
    let statement = r#"
        SELECT
            column_name,
            data_type,
            is_nullable = 'YES' AS is_nullable,
            collation_name
        FROM information_schema.columns
        WHERE table_schema = COALESCE($1, current_schema())
          AND table_name = $2
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_SCHEMA_VALIDATE_TABLE_COLUMNS,
        Some(statement),
    );
    let rows = pooler_safe_query(statement)
        .bind(table_name.schema().map(|schema| schema.as_str()))
        .bind(table_name.table().as_str())
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    let actual_columns = rows
        .into_iter()
        .map(|row| {
            Ok(ActualColumn {
                name: row.try_get("column_name").map_err(Error::decode_row)?,
                data_type: row.try_get("data_type").map_err(Error::decode_row)?,
                is_nullable: row.try_get("is_nullable").map_err(Error::decode_row)?,
                collation: row.try_get("collation_name").map_err(Error::decode_row)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    for required_column in required_columns {
        let required_column_name = required_column.column.name();
        let Some(actual_column) = actual_columns
            .iter()
            .find(|column| column.name == required_column_name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "table {} is missing column {}",
                table_name.quoted(),
                required_column_name
            ))
            .into());
        };
        validate_required_column(table_name, *required_column, actual_column)?;
    }

    Ok(())
}

async fn validate_named_check_constraint(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    constraint_name: &PgIdentifier,
    required_fragments_after_normalization: Vec<String>,
    exact_single_quoted_literals_after_normalization: Option<Vec<String>>,
) -> Result<(), Error> {
    let statement = r#"
        SELECT pg_get_constraintdef(con.oid)
        FROM pg_constraint AS con
        JOIN pg_class AS cls ON cls.oid = con.conrelid
        JOIN pg_namespace AS ns ON ns.oid = cls.relnamespace
        WHERE ns.nspname = COALESCE($1, current_schema())
          AND cls.relname = $2
          AND con.conname = $3
          AND con.contype = 'c'
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_CHECK_CONSTRAINT,
        Some(statement),
    );
    let definition = pooler_safe_query_scalar::<Option<String>>(statement)
        .bind(table_name.schema().map(|schema| schema.as_str()))
        .bind(table_name.table().as_str())
        .bind(constraint_name.as_str())
        .fetch_optional(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?
        .flatten();

    let Some(definition) = definition else {
        return Err(DbError::schema_mismatch(format!(
            "table {} is missing check constraint {}",
            table_name.quoted(),
            constraint_name.quoted()
        ))
        .into());
    };

    let normalized = normalize_check_constraint_expression(&definition).to_ascii_lowercase();
    for fragment in &required_fragments_after_normalization {
        if !normalized.contains(fragment) {
            return Err(DbError::schema_mismatch(format!(
                "table {} check constraint {} has incompatible definition",
                table_name.quoted(),
                constraint_name.quoted()
            ))
            .into());
        }
    }
    if let Some(expected_literals) = exact_single_quoted_literals_after_normalization {
        let actual_literals = single_quoted_literals_from_normalized_expression(&normalized);
        let expected_literals = expected_literals.into_iter().collect::<HashSet<_>>();
        if actual_literals.len() != expected_literals.len()
            || !actual_literals
                .iter()
                .all(|literal| expected_literals.contains(literal))
        {
            return Err(DbError::schema_mismatch(format!(
                "table {} check constraint {} has incompatible definition",
                table_name.quoted(),
                constraint_name.quoted()
            ))
            .into());
        }
    }
    Ok(())
}

fn single_quoted_literals_from_normalized_expression(expression: &str) -> HashSet<String> {
    let mut literals = HashSet::new();
    let mut literal_start = None;
    for (index, character) in expression.char_indices() {
        if character != '\'' {
            continue;
        }
        if let Some(start_index) = literal_start.take() {
            literals.insert(expression[start_index..index].to_owned());
        } else {
            literal_start = Some(index + character.len_utf8());
        }
    }
    literals
}

fn job_status_constraint_fragments() -> Vec<String> {
    vec![
        quoted_job_status_fragment(JobStatus::Pending),
        quoted_job_status_fragment(JobStatus::Running),
        quoted_job_status_fragment(JobStatus::Completed),
        quoted_job_status_fragment(JobStatus::Failed),
        QueueColumn::Status.name().to_owned(),
    ]
}

fn job_status_constraint_literals() -> Vec<String> {
    vec![
        JobStatus::Pending.as_str().to_owned(),
        JobStatus::Running.as_str().to_owned(),
        JobStatus::Completed.as_str().to_owned(),
        JobStatus::Failed.as_str().to_owned(),
    ]
}

fn job_lifecycle_constraint_fragments() -> Vec<String> {
    let status = QueueColumn::Status.name();
    vec![
        format!("{}='{}'", status, JobStatus::Pending.as_str()),
        format!("{}='{}'", status, JobStatus::Running.as_str()),
        normalized_is_null_fragment(QueueColumn::WorkerId),
        normalized_is_not_null_fragment(QueueColumn::WorkerId),
        normalized_is_null_fragment(QueueColumn::ClaimedByWorkerAt),
        normalized_is_not_null_fragment(QueueColumn::ClaimedByWorkerAt),
        normalized_is_null_fragment(QueueColumn::ExecutionStartedAt),
        normalized_is_null_fragment(QueueColumn::ExecutionHeartbeatAt),
        normalized_is_not_null_fragment(QueueColumn::ExecutionHeartbeatAt),
        normalized_is_null_fragment(QueueColumn::FinishedAt),
        normalized_is_not_null_fragment(QueueColumn::FinishedAt),
    ]
}

fn numeric_constraint_fragments() -> Vec<String> {
    vec![
        format!("{}>=0", QueueColumn::RetryCount.name()),
        format!("{}>=0", QueueColumn::MaxRetries.name()),
        QueueColumn::TimeoutNanos.name().to_owned(),
    ]
}

fn job_text_constraint_fragments() -> Vec<String> {
    vec![
        QueueColumn::TaskName.name().to_owned(),
        QueueColumn::DedupeKey.name().to_owned(),
        QueueColumn::WorkerId.name().to_owned(),
        "octet_length".to_owned(),
    ]
}

fn dead_letter_reason_constraint_fragments() -> Vec<String> {
    vec![
        quoted_dead_letter_reason_fragment(DeadLetterReason::MaxRetriesExceeded),
        quoted_dead_letter_reason_fragment(DeadLetterReason::PermanentError),
        quoted_dead_letter_reason_fragment(DeadLetterReason::OperatorAction),
        quoted_dead_letter_reason_fragment(DeadLetterReason::ExecutionExpired),
        QueueColumn::Reason.name().to_owned(),
    ]
}

fn dead_letter_reason_constraint_literals() -> Vec<String> {
    vec![
        DeadLetterReason::MaxRetriesExceeded.as_str().to_owned(),
        DeadLetterReason::PermanentError.as_str().to_owned(),
        DeadLetterReason::OperatorAction.as_str().to_owned(),
        DeadLetterReason::ExecutionExpired.as_str().to_owned(),
    ]
}

fn dead_letter_text_constraint_fragments() -> Vec<String> {
    vec![
        QueueColumn::TaskName.name().to_owned(),
        QueueColumn::DedupeKey.name().to_owned(),
        "octet_length".to_owned(),
    ]
}

fn pause_key_task_constraint_fragments() -> Vec<String> {
    let key = QueueColumn::Key.name();
    let task_name = QueueColumn::TaskName.name();
    vec![
        format!("{key}='{GLOBAL_PAUSE_KEY}'"),
        normalized_is_null_fragment(QueueColumn::TaskName),
        normalized_is_not_null_fragment(QueueColumn::TaskName),
        format!("{key}=('task:'::text||{task_name})"),
    ]
}

fn pause_text_constraint_fragments() -> Vec<String> {
    vec![
        QueueColumn::TaskName.name().to_owned(),
        "octet_length".to_owned(),
    ]
}

fn quoted_job_status_fragment(status: JobStatus) -> String {
    format!("'{}'", status.as_str())
}

fn quoted_dead_letter_reason_fragment(reason: DeadLetterReason) -> String {
    format!("'{}'", reason.as_str())
}

fn normalized_is_null_fragment(column: QueueColumn) -> String {
    format!("{}isnull", column.name())
}

fn normalized_is_not_null_fragment(column: QueueColumn) -> String {
    format!("{}isnotnull", column.name())
}

async fn validate_required_indexes(tx: &mut Tx<'_>, config: &StoreConfig) -> Result<(), Error> {
    for required_index in queue_schema_index_definitions()
        .into_iter()
        .filter(|definition| definition.predicate != QueueIndexPredicate::ActiveDedupe)
        .map(|definition| RequiredQueueIndex::from_definition(config, definition))
    {
        validate_required_index(tx, required_index).await?;
    }
    Ok(())
}

struct RequiredQueueIndex<'a> {
    table_name: &'a PgQualifiedTableName,
    index_name: PgIdentifier,
    columns: Vec<&'static str>,
    predicate_fragments_after_normalization: Vec<String>,
    unique: bool,
}

impl<'a> RequiredQueueIndex<'a> {
    fn from_definition(config: &'a StoreConfig, definition: QueueIndexDefinition) -> Self {
        let table_name = definition.table.table_name(config);
        Self {
            table_name,
            index_name: migration_index_identifier(definition.kind, table_name, definition.suffix),
            columns: definition
                .columns
                .iter()
                .map(|column| column.name())
                .collect(),
            predicate_fragments_after_normalization: definition
                .predicate
                .fragments_after_normalization(),
            unique: definition.unique,
        }
    }
}

#[derive(Clone, Copy)]
enum QueueIndexValidationField {
    Column0,
    Column1,
    Column2,
    Predicate,
}

impl QueueIndexValidationField {
    const fn name(self) -> &'static str {
        match self {
            Self::Column0 => "column_0",
            Self::Column1 => "column_1",
            Self::Column2 => "column_2",
            Self::Predicate => "predicate",
        }
    }
}

async fn validate_required_index(
    tx: &mut Tx<'_>,
    required_index: RequiredQueueIndex<'_>,
) -> Result<(), Error> {
    let column_0 = QueueIndexValidationField::Column0.name();
    let column_1 = QueueIndexValidationField::Column1.name();
    let column_2 = QueueIndexValidationField::Column2.name();
    let predicate = QueueIndexValidationField::Predicate.name();
    let statement = format!(
        r#"
        SELECT
            attr0.attname AS {column_0},
            attr1.attname AS {column_1},
            attr2.attname AS {column_2},
            pg_get_expr(idx.indpred, idx.indrelid) AS {predicate}
        FROM pg_index idx
        JOIN pg_class table_class ON table_class.oid = idx.indrelid
        JOIN pg_namespace table_namespace ON table_namespace.oid = table_class.relnamespace
        JOIN pg_class index_class ON index_class.oid = idx.indexrelid
        LEFT JOIN pg_attribute attr0
          ON attr0.attrelid = idx.indrelid
         AND attr0.attnum = idx.indkey[0]
         AND NOT attr0.attisdropped
        LEFT JOIN pg_attribute attr1
          ON attr1.attrelid = idx.indrelid
         AND attr1.attnum = idx.indkey[1]
         AND NOT attr1.attisdropped
        LEFT JOIN pg_attribute attr2
          ON attr2.attrelid = idx.indrelid
         AND attr2.attnum = idx.indkey[2]
         AND NOT attr2.attisdropped
        WHERE table_namespace.nspname = COALESCE($1, current_schema())
          AND table_class.relname = $2
          AND index_class.relname = $3
          AND idx.indisvalid
          AND idx.indisunique = $4
          AND idx.indnkeyatts = $5
          AND idx.indexprs IS NULL
        "#
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_INDEX,
        Some(statement.as_str()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(
            required_index
                .table_name
                .schema()
                .map(|schema| schema.as_str()),
        )
        .bind(required_index.table_name.table().as_str())
        .bind(required_index.index_name.as_str())
        .bind(required_index.unique)
        .bind(
            i16::try_from(required_index.columns.len())
                .expect("required queue index arity must fit in i16"),
        )
        .fetch_optional(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    let Some(row) = row else {
        return Err(DbError::schema_mismatch(format!(
            "table {} is missing required index {}",
            required_index.table_name.quoted(),
            required_index.index_name.quoted()
        ))
        .into());
    };

    let actual_columns = [
        row.try_get::<Option<String>, _>(QueueIndexValidationField::Column0.name())
            .map_err(Error::decode_row)?,
        row.try_get::<Option<String>, _>(QueueIndexValidationField::Column1.name())
            .map_err(Error::decode_row)?,
        row.try_get::<Option<String>, _>(QueueIndexValidationField::Column2.name())
            .map_err(Error::decode_row)?,
    ];
    let actual_columns = actual_columns
        .iter()
        .filter_map(Option::as_deref)
        .collect::<Vec<_>>();
    if actual_columns.as_slice() != required_index.columns.as_slice() {
        return Err(DbError::schema_mismatch(format!(
            "index {} on table {} has incompatible columns",
            required_index.index_name.quoted(),
            required_index.table_name.quoted()
        ))
        .into());
    }

    let predicate = row
        .try_get::<Option<String>, _>(QueueIndexValidationField::Predicate.name())
        .map_err(Error::decode_row)?
        .unwrap_or_default();
    let normalized_predicate =
        normalize_check_constraint_expression(&predicate).to_ascii_lowercase();
    for fragment in &required_index.predicate_fragments_after_normalization {
        if !normalized_predicate.contains(fragment) {
            return Err(DbError::schema_mismatch(format!(
                "index {} on table {} has incompatible predicate",
                required_index.index_name.quoted(),
                required_index.table_name.quoted()
            ))
            .into());
        }
    }
    if required_index
        .predicate_fragments_after_normalization
        .is_empty()
        && !normalized_predicate.is_empty()
    {
        return Err(DbError::schema_mismatch(format!(
            "index {} on table {} must not have a predicate",
            required_index.index_name.quoted(),
            required_index.table_name.quoted()
        ))
        .into());
    }

    Ok(())
}

async fn validate_active_dedupe_conflict_arbiter(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let insert_columns = enqueue_with_dedupe_insert_columns_sql();
    let conflict_columns = active_dedupe_conflict_columns_sql();
    let conflict_predicate = active_dedupe_conflict_predicate_sql();
    let statement = format!(
        r#"
        EXPLAIN (COSTS OFF)
        INSERT INTO {} ({}) VALUES (
            decode(repeat('00', {}), 'hex'),
            '__paranoid_queue_dedupe_contract_validation',
            '{{}}'::jsonb,
            'pending',
            statement_timestamp(),
            0,
            0,
            statement_timestamp(),
            statement_timestamp(),
            '__paranoid_queue_dedupe_contract_validation'
        )
        ON CONFLICT ({})
        WHERE {}
        DO NOTHING
        "#,
        config.table_name.quoted(),
        insert_columns,
        JOB_ID_SIZE,
        conflict_columns,
        conflict_predicate
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_SCHEMA_VALIDATE_ACTIVE_DEDUPE_ARBITER,
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

fn validate_required_column(
    table_name: &PgQualifiedTableName,
    required_column: RequiredColumn,
    actual_column: &ActualColumn,
) -> Result<(), Error> {
    let required_column_name = required_column.column.name();
    let required_data_type = required_column.column.validation_type();
    if actual_column.data_type != required_data_type {
        return Err(DbError::schema_mismatch(format!(
            "table {} column {} has type {}, expected {}",
            table_name.quoted(),
            required_column_name,
            actual_column.data_type,
            required_data_type
        ))
        .into());
    }
    if actual_column.is_nullable != required_column.is_nullable {
        return Err(DbError::schema_mismatch(format!(
            "table {} column {} nullability does not match queue schema",
            table_name.quoted(),
            required_column_name
        ))
        .into());
    }
    if required_column.column.requires_bytewise_collation()
        && !matches!(actual_column.collation.as_deref(), Some("C" | "POSIX"))
    {
        return Err(DbError::schema_mismatch(format!(
            "table {} column {} must use C/POSIX collation",
            table_name.quoted(),
            required_column_name
        ))
        .into());
    }
    Ok(())
}
