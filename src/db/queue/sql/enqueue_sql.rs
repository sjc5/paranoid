use super::*;

pub(in crate::db::queue) fn build_single_enqueue_query(config: &StoreConfig) -> String {
    let pause_key = QueueColumn::Key.name();
    let insert_columns = enqueue_without_dedupe_insert_columns_sql();
    let returning_id = QueueColumn::Id.name();
    let inserted_id = QueueQueryField::InsertedId.name();
    let insert_outcome = QueueQueryField::InsertOutcome.name();
    format!(
        r#"
        WITH pause_state AS (
            SELECT
                COALESCE(BOOL_OR({pause_key} = $8), FALSE) AS queue_paused,
                COALESCE(BOOL_OR({pause_key} = $9), FALSE) AS task_paused
            FROM {}
            WHERE {pause_key} IN ($8, $9)
        ),
        inserted AS (
            INSERT INTO {} ({insert_columns})
            SELECT
                $1, $2, $3::jsonb, $4, COALESCE(TIMESTAMPTZ 'epoch' + ($5::bigint * INTERVAL '1 microsecond'), statement_timestamp()), $6, $7, statement_timestamp(), statement_timestamp()
            FROM pause_state
            WHERE NOT pause_state.queue_paused AND NOT pause_state.task_paused
            RETURNING {returning_id}
        )
        SELECT
            (SELECT {returning_id} FROM inserted) AS {inserted_id},
            CASE
                WHEN EXISTS (SELECT 1 FROM inserted) THEN '{}'
                WHEN (SELECT queue_paused FROM pause_state) THEN '{}'
                WHEN (SELECT task_paused FROM pause_state) THEN '{}'
                ELSE '{}'
            END AS {insert_outcome}
        "#,
        config.pause_table_name.quoted(),
        config.table_name.quoted(),
        ENQUEUE_OUTCOME_INSERTED,
        ENQUEUE_OUTCOME_QUEUE_PAUSED,
        ENQUEUE_OUTCOME_TASK_PAUSED,
        ENQUEUE_OUTCOME_NOT_INSERTED,
    )
}

pub(in crate::db::queue) fn build_batch_enqueue_query(
    config: &StoreConfig,
    batch_size: usize,
) -> String {
    let values = build_batch_enqueue_values(batch_size);
    let pause_key = QueueColumn::Key.name();
    let insert_columns = enqueue_without_dedupe_insert_columns_sql();
    let returning_id = QueueColumn::Id.name();
    let task_name_placeholder = batch_size * 2 + 1;
    let status_placeholder = task_name_placeholder + 1;
    let run_at_placeholder = status_placeholder + 1;
    let max_retries_placeholder = run_at_placeholder + 1;
    let timeout_placeholder = max_retries_placeholder + 1;
    let global_pause_placeholder = timeout_placeholder + 1;
    let task_pause_placeholder = global_pause_placeholder + 1;
    let inserted_count = QueueQueryField::InsertedCount.name();
    let insert_outcome = QueueQueryField::InsertOutcome.name();

    format!(
        r#"
        WITH pause_state AS (
            SELECT
                COALESCE(BOOL_OR({pause_key} = ${global_pause_placeholder}), FALSE) AS queue_paused,
                COALESCE(BOOL_OR({pause_key} = ${task_pause_placeholder}), FALSE) AS task_paused
            FROM {}
            WHERE {pause_key} IN (${global_pause_placeholder}, ${task_pause_placeholder})
        ),
        pending_jobs(id, payload) AS (
            VALUES {values}
        ),
        inserted AS (
            INSERT INTO {} ({insert_columns})
            SELECT
                pending_jobs.id,
                ${task_name_placeholder},
                pending_jobs.payload,
                ${status_placeholder},
                COALESCE(TIMESTAMPTZ 'epoch' + (${run_at_placeholder}::bigint * INTERVAL '1 microsecond'), statement_timestamp()),
                ${max_retries_placeholder},
                ${timeout_placeholder},
                statement_timestamp(),
                statement_timestamp()
            FROM pending_jobs
            CROSS JOIN pause_state
            WHERE NOT pause_state.queue_paused AND NOT pause_state.task_paused
            RETURNING {returning_id}
        )
        SELECT
            (SELECT COUNT(*)::bigint FROM inserted) AS {inserted_count},
            CASE
                WHEN EXISTS (SELECT 1 FROM inserted) THEN '{}'
                WHEN (SELECT queue_paused FROM pause_state) THEN '{}'
                WHEN (SELECT task_paused FROM pause_state) THEN '{}'
                ELSE '{}'
            END AS {insert_outcome}
        "#,
        config.pause_table_name.quoted(),
        config.table_name.quoted(),
        ENQUEUE_OUTCOME_INSERTED,
        ENQUEUE_OUTCOME_QUEUE_PAUSED,
        ENQUEUE_OUTCOME_TASK_PAUSED,
        ENQUEUE_OUTCOME_NOT_INSERTED,
    )
}

pub(in crate::db::queue) fn build_batch_enqueue_values(batch_size: usize) -> String {
    (0..batch_size)
        .map(|index| {
            let id_placeholder = index * 2 + 1;
            let payload_placeholder = id_placeholder + 1;
            format!("(${id_placeholder}::bytea, ${payload_placeholder}::jsonb)")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(in crate::db::queue) fn build_dedupe_enqueue_query(config: &StoreConfig) -> String {
    let pause_key = QueueColumn::Key.name();
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let status = QueueColumn::Status.name();
    let pending = JobStatus::Pending.as_str();
    let running = JobStatus::Running.as_str();
    let insert_columns = enqueue_with_dedupe_insert_columns_sql();
    let active_dedupe_conflict_columns = active_dedupe_conflict_columns_sql();
    let active_dedupe_conflict_predicate = active_dedupe_conflict_predicate_sql();
    let inserted_id = QueueQueryField::InsertedId.name();
    let existing_id = QueueQueryField::ExistingId.name();
    let insert_outcome = QueueQueryField::InsertOutcome.name();
    format!(
        r#"
        WITH pause_state AS (
            SELECT
                COALESCE(BOOL_OR({pause_key} = $9), FALSE) AS queue_paused,
                COALESCE(BOOL_OR({pause_key} = $10), FALSE) AS task_paused
            FROM {}
            WHERE {pause_key} IN ($9, $10)
        ),
        existing_active AS (
            SELECT {id}
            FROM {}
            WHERE {task_name} = $2 AND {dedupe_key} = $8 AND {status} IN ('{pending}', '{running}')
            LIMIT 1
        ),
        inserted AS (
            INSERT INTO {} ({insert_columns})
            SELECT
                $1, $2, $3::jsonb, $4, COALESCE(TIMESTAMPTZ 'epoch' + ($5::bigint * INTERVAL '1 microsecond'), statement_timestamp()), $6, $7, statement_timestamp(), statement_timestamp(), $8
            FROM pause_state
            WHERE NOT pause_state.queue_paused
              AND NOT pause_state.task_paused
            ON CONFLICT ({active_dedupe_conflict_columns})
            WHERE {active_dedupe_conflict_predicate}
            DO NOTHING
            RETURNING {id}
        )
        SELECT
            (SELECT {id} FROM inserted) AS {inserted_id},
            (SELECT {id} FROM existing_active) AS {existing_id},
            CASE
                WHEN (SELECT queue_paused FROM pause_state) THEN '{}'
                WHEN (SELECT task_paused FROM pause_state) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM inserted) THEN '{}'
                ELSE '{}'
            END AS {insert_outcome}
        "#,
        config.pause_table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        ENQUEUE_OUTCOME_QUEUE_PAUSED,
        ENQUEUE_OUTCOME_TASK_PAUSED,
        ENQUEUE_OUTCOME_INSERTED,
        ENQUEUE_OUTCOME_NOT_INSERTED,
    )
}
