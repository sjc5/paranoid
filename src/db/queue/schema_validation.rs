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
        &[
            "'pending'",
            "'running'",
            "'completed'",
            "'failed'",
            "status",
        ],
        Some(&["pending", "running", "completed", "failed"]),
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_lifecycle_constraint_identifier(config),
        &[
            "status='pending'",
            "status='running'",
            "worker_idisnull",
            "worker_idisnotnull",
            "claimed_by_worker_atisnull",
            "claimed_by_worker_atisnotnull",
            "execution_started_atisnull",
            "execution_heartbeat_atisnull",
            "execution_heartbeat_atisnotnull",
            "finished_atisnull",
            "finished_atisnotnull",
        ],
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_numeric_constraint_identifier(config),
        &["retry_count>=0", "max_retries>=0", "timeout_nanos"],
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.table_name,
        &job_text_constraint_identifier(config),
        &["task_name", "dedupe_key", "worker_id", "octet_length"],
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.dead_letter_table_name,
        &dead_letter_reason_constraint_identifier(config),
        &[
            "'max_retries_exceeded'",
            "'permanent_error'",
            "'operator_action'",
            "'execution_expired'",
            "reason",
        ],
        Some(&[
            "max_retries_exceeded",
            "permanent_error",
            "operator_action",
            "execution_expired",
        ]),
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.dead_letter_table_name,
        &dead_letter_numeric_constraint_identifier(config),
        &["retry_count>=0", "max_retries>=0", "timeout_nanos"],
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.dead_letter_table_name,
        &dead_letter_text_constraint_identifier(config),
        &["task_name", "dedupe_key", "octet_length"],
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.pause_table_name,
        &pause_key_task_constraint_identifier(config),
        &[
            "key='__global__'",
            "task_nameisnull",
            "task_nameisnotnull",
            "key=('task:'::text||task_name)",
        ],
        None,
    )
    .await?;
    validate_named_check_constraint(
        tx,
        &config.pause_table_name,
        &pause_text_constraint_identifier(config),
        &["task_name", "octet_length"],
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
        let Some(actual_column) = actual_columns
            .iter()
            .find(|column| column.name == required_column.name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "table {} is missing column {}",
                table_name.quoted(),
                required_column.name
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
    required_fragments_after_normalization: &[&str],
    exact_single_quoted_literals_after_normalization: Option<&[&str]>,
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
    for fragment in required_fragments_after_normalization {
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
        let expected_literals = expected_literals.iter().copied().collect::<HashSet<_>>();
        if actual_literals.len() != expected_literals.len()
            || !actual_literals
                .iter()
                .all(|literal| expected_literals.contains(literal.as_str()))
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

async fn validate_required_indexes(tx: &mut Tx<'_>, config: &StoreConfig) -> Result<(), Error> {
    for required_index in [
        RequiredQueueIndex {
            table_name: &config.table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                PENDING_RUN_AT_INDEX_SUFFIX,
            ),
            columns: &["status", "run_at_or_after", "id"],
            predicate_fragments_after_normalization: &["status='pending'"],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                PENDING_TASK_RUN_AT_INDEX_SUFFIX,
            ),
            columns: &["task_name", "run_at_or_after", "id"],
            predicate_fragments_after_normalization: &["status='pending'"],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                TASK_STATUS_INDEX_SUFFIX,
            ),
            columns: &["task_name", "status"],
            predicate_fragments_after_normalization: &[],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                WORKER_INDEX_SUFFIX,
            ),
            columns: &["worker_id"],
            predicate_fragments_after_normalization: &["worker_idisnotnull"],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                EXECUTION_HEARTBEAT_INDEX_SUFFIX,
            ),
            columns: &["status", "execution_heartbeat_at", "id"],
            predicate_fragments_after_normalization: &[
                "status='running'",
                "execution_heartbeat_atisnotnull",
            ],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                CLEANUP_INDEX_SUFFIX,
            ),
            columns: &["finished_at", "id"],
            predicate_fragments_after_normalization: &[
                "status",
                "'completed'",
                "'failed'",
                "finished_atisnotnull",
            ],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.dead_letter_table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.dead_letter_table_name,
                DEAD_LETTERED_AT_INDEX_SUFFIX,
            ),
            columns: &["dead_lettered_at", "id"],
            predicate_fragments_after_normalization: &[],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.dead_letter_table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.dead_letter_table_name,
                TASK_DEAD_LETTERED_AT_INDEX_SUFFIX,
            ),
            columns: &["task_name", "dead_lettered_at", "id"],
            predicate_fragments_after_normalization: &[],
            unique: false,
        },
        RequiredQueueIndex {
            table_name: &config.dead_letter_table_name,
            index_name: migration_index_identifier(
                UNIQUE_INDEX_KIND,
                &config.dead_letter_table_name,
                ORIGINAL_JOB_INDEX_SUFFIX,
            ),
            columns: &["original_job_id"],
            predicate_fragments_after_normalization: &[],
            unique: true,
        },
        RequiredQueueIndex {
            table_name: &config.pause_table_name,
            index_name: migration_index_identifier(
                INDEX_KIND,
                &config.pause_table_name,
                PAUSE_TASK_INDEX_SUFFIX,
            ),
            columns: &["task_name"],
            predicate_fragments_after_normalization: &["task_nameisnotnull"],
            unique: false,
        },
    ] {
        validate_required_index(tx, required_index).await?;
    }
    Ok(())
}

struct RequiredQueueIndex<'a> {
    table_name: &'a PgQualifiedTableName,
    index_name: PgIdentifier,
    columns: &'a [&'a str],
    predicate_fragments_after_normalization: &'a [&'a str],
    unique: bool,
}

async fn validate_required_index(
    tx: &mut Tx<'_>,
    required_index: RequiredQueueIndex<'_>,
) -> Result<(), Error> {
    let statement = r#"
        SELECT
            attr0.attname AS column_0,
            attr1.attname AS column_1,
            attr2.attname AS column_2,
            pg_get_expr(idx.indpred, idx.indrelid) AS predicate
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
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_INDEX,
        Some(statement),
    );
    let row = pooler_safe_query(statement)
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
        row.try_get::<Option<String>, _>("column_0")
            .map_err(Error::decode_row)?,
        row.try_get::<Option<String>, _>("column_1")
            .map_err(Error::decode_row)?,
        row.try_get::<Option<String>, _>("column_2")
            .map_err(Error::decode_row)?,
    ];
    let actual_columns = actual_columns
        .iter()
        .filter_map(Option::as_deref)
        .collect::<Vec<_>>();
    if actual_columns != required_index.columns {
        return Err(DbError::schema_mismatch(format!(
            "index {} on table {} has incompatible columns",
            required_index.index_name.quoted(),
            required_index.table_name.quoted()
        ))
        .into());
    }

    let predicate = row
        .try_get::<Option<String>, _>("predicate")
        .map_err(Error::decode_row)?
        .unwrap_or_default();
    let normalized_predicate =
        normalize_check_constraint_expression(&predicate).to_ascii_lowercase();
    for fragment in required_index.predicate_fragments_after_normalization {
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
    let statement = format!(
        r#"
        EXPLAIN (COSTS OFF)
        INSERT INTO {} (
            id, task_name, payload, status, run_at_or_after,
            max_retries, timeout_nanos, created_at, updated_at, dedupe_key
        ) VALUES (
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
        ON CONFLICT (task_name, dedupe_key)
        WHERE dedupe_key IS NOT NULL AND status IN ('pending', 'running')
        DO NOTHING
        "#,
        config.table_name.quoted(),
        JOB_ID_SIZE
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
    if actual_column.data_type != required_column.data_type {
        return Err(DbError::schema_mismatch(format!(
            "table {} column {} has type {}, expected {}",
            table_name.quoted(),
            required_column.name,
            actual_column.data_type,
            required_column.data_type
        ))
        .into());
    }
    if actual_column.is_nullable != required_column.is_nullable {
        return Err(DbError::schema_mismatch(format!(
            "table {} column {} nullability does not match queue schema",
            table_name.quoted(),
            required_column.name
        ))
        .into());
    }
    if required_column.collation_required
        && !matches!(actual_column.collation.as_deref(), Some("C" | "POSIX"))
    {
        return Err(DbError::schema_mismatch(format!(
            "table {} column {} must use C/POSIX collation",
            table_name.quoted(),
            required_column.name
        ))
        .into());
    }
    Ok(())
}
