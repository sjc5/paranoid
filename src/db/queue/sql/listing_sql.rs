use super::*;

pub(in crate::db::queue) fn build_list_jobs_query(config: &StoreConfig) -> String {
    let status = QueueColumn::Status.name();
    let task_name = QueueColumn::TaskName.name();
    let id = QueueColumn::Id.name();
    format!(
        r#"
        SELECT {}
        FROM {}
        WHERE (CARDINALITY($1::text[]) = 0 OR {status} = ANY($1::text[]))
          AND ($2::text IS NULL OR {task_name} = $2)
          AND ($3::bytea IS NULL OR {id} > $3)
        ORDER BY {id} ASC
        LIMIT $4
        "#,
        queue_job_projection(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn dead_letter_job_projection() -> String {
    sql_projection(&[
        QueueColumn::Id.name().to_owned(),
        QueueColumn::OriginalJobId.name().to_owned(),
        QueueColumn::TaskName.name().to_owned(),
        text_projection(QueueColumn::Payload, QueueProjectionField::PayloadJson),
        QueueColumn::LastError.name().to_owned(),
        QueueColumn::RetryCount.name().to_owned(),
        QueueColumn::MaxRetries.name().to_owned(),
        QueueColumn::TimeoutNanos.name().to_owned(),
        QueueColumn::DedupeKey.name().to_owned(),
        QueueColumn::Reason.name().to_owned(),
        unix_microseconds_projection(
            QueueColumn::DeadLetteredAt,
            QueueProjectionField::DeadLetteredAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::CreatedAt,
            QueueProjectionField::CreatedAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::UpdatedAt,
            QueueProjectionField::UpdatedAtUnixMicroseconds,
        ),
    ])
}

pub(in crate::db::queue) fn build_list_dead_letter_jobs_query(config: &StoreConfig) -> String {
    let task_name = QueueColumn::TaskName.name();
    let id = QueueColumn::Id.name();
    format!(
        r#"
        SELECT {}
        FROM {}
        WHERE ($1::text IS NULL OR {task_name} = $1)
          AND ($2::bytea IS NULL OR {id} > $2)
        ORDER BY {id} ASC
        LIMIT $3
        "#,
        dead_letter_job_projection(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_requeue_dead_letter_job_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let payload = QueueColumn::Payload.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let timeout_nanos = QueueColumn::TimeoutNanos.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let insert_columns = dead_letter_requeue_insert_columns_sql();
    let active_dedupe_match = active_dedupe_match_predicate("active", "source");
    let active_dedupe_conflict_columns = active_dedupe_conflict_columns_sql();
    let active_dedupe_conflict_predicate = active_dedupe_conflict_predicate_sql();
    let inserted_id = QueueQueryField::InsertedId.name();
    let source_exists = QueueQueryField::SourceExists.name();
    let visible_exists = QueueQueryField::VisibleExists.name();
    let dedupe_conflict_exists = QueueQueryField::DedupeConflictExists.name();
    let deleted_source = QueueQueryField::DeletedSource.name();
    format!(
        r#"
        WITH visible AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $1
        ),
        source AS (
            SELECT {id}, {task_name}, {payload}, {max_retries}, {timeout_nanos}, {dedupe_key}
            FROM {}
            WHERE {id} = $1
            FOR UPDATE SKIP LOCKED
        ),
        dedupe_conflict AS (
            SELECT 1
            FROM source
            WHERE {dedupe_key} IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM {} AS active
                  WHERE {active_dedupe_match}
              )
        ),
        inserted AS (
            INSERT INTO {} ({insert_columns})
            SELECT
                $2, {task_name}, {payload}, $3,
                COALESCE(TIMESTAMPTZ 'epoch' + ($4::bigint * INTERVAL '1 microsecond'), statement_timestamp()),
                0, {max_retries}, {timeout_nanos}, {dedupe_key},
                statement_timestamp(), statement_timestamp()
            FROM source
            WHERE NOT EXISTS (SELECT 1 FROM dedupe_conflict)
            ON CONFLICT ({active_dedupe_conflict_columns})
            WHERE {active_dedupe_conflict_predicate}
            DO NOTHING
            RETURNING {id}
        ),
        deleted AS (
            DELETE FROM {}
            WHERE {id} IN (SELECT {id} FROM source)
              AND EXISTS (SELECT 1 FROM inserted)
            RETURNING 1
        )
        SELECT
            (SELECT {id} FROM inserted) AS {inserted_id},
            EXISTS(SELECT 1 FROM source) AS {source_exists},
            EXISTS(SELECT 1 FROM visible) AS {visible_exists},
            EXISTS(SELECT 1 FROM dedupe_conflict) AS {dedupe_conflict_exists},
            EXISTS(SELECT 1 FROM deleted) AS {deleted_source}
        "#,
        config.dead_letter_table_name.quoted(),
        config.dead_letter_table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_delete_dead_letter_job_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    format!(
        r#"
        WITH visible AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $1
            FOR UPDATE SKIP LOCKED
        ),
        deleted AS (
            DELETE FROM {}
            WHERE {id} IN (SELECT {id} FROM target)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM deleted) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
            ELSE '{}'
        END
        "#,
        config.dead_letter_table_name.quoted(),
        config.dead_letter_table_name.quoted(),
        config.dead_letter_table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}
