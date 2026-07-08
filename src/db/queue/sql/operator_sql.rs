use super::*;

pub(in crate::db::queue) fn build_cancel_pending_job_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    format!(
        r#"
        WITH visible AS (
            SELECT {status}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}, {status}
            FROM {}
            WHERE {id} = $1
            FOR UPDATE SKIP LOCKED
        ),
        deleted AS (
            DELETE FROM {}
            WHERE {id} IN (SELECT {id} FROM target WHERE {status} = $2)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM deleted) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM target) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE {status} <> $2) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
            ELSE '{}'
        END
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_retry_available_failed_jobs_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let finished_at = QueueColumn::FinishedAt.name();
    let failed_id = qualified_queue_column("failed", QueueColumn::Id);
    let failed_task_name = qualified_queue_column("failed", QueueColumn::TaskName);
    let failed_dedupe_key = qualified_queue_column("failed", QueueColumn::DedupeKey);
    let failed_status = qualified_queue_column("failed", QueueColumn::Status);
    let failed_finished_at = qualified_queue_column("failed", QueueColumn::FinishedAt);
    let active_id = qualified_queue_column("active", QueueColumn::Id);
    let active_dedupe_match = active_dedupe_match_predicate("active", "failed");
    let retry_set_clause = retry_failed_job_assignments(
        "$3",
        "COALESCE(TIMESTAMPTZ 'epoch' + ($4::bigint * INTERVAL '1 microsecond'), statement_timestamp())",
    );
    format!(
        r#"
        WITH lockable AS (
            SELECT {failed_id}, {failed_task_name}, {failed_dedupe_key}, {failed_finished_at}
            FROM {} AS failed
            WHERE {failed_status} = $1
              AND ($5::text IS NULL OR {failed_task_name} = $5)
              AND (
                  {failed_dedupe_key} IS NULL
                  OR NOT EXISTS (
                      SELECT 1
                      FROM {} AS active
                      WHERE {active_dedupe_match}
                        AND {active_id} <> {failed_id}
                  )
              )
            ORDER BY {failed_finished_at} ASC NULLS FIRST, {failed_id} ASC
            LIMIT $2
            FOR UPDATE OF failed SKIP LOCKED
        ),
        ranked AS (
            SELECT
                {id},
                {dedupe_key},
                {finished_at},
                ROW_NUMBER() OVER (
                    PARTITION BY {task_name}, {dedupe_key}
                    ORDER BY {finished_at} ASC NULLS FIRST, {id} ASC
                ) AS active_dedupe_retry_rank
            FROM lockable
        ),
        candidates AS (
            SELECT {id}
            FROM ranked
            WHERE {dedupe_key} IS NULL OR active_dedupe_retry_rank = 1
        )
        UPDATE {} SET
            {retry_set_clause}
        WHERE {id} IN (SELECT {id} FROM candidates)
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_retry_failed_job_by_id_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let task_name = QueueColumn::TaskName.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let active_id = qualified_queue_column("active", QueueColumn::Id);
    let target_id = qualified_queue_column("target", QueueColumn::Id);
    let active_dedupe_match = active_dedupe_match_predicate("active", "target");
    let retry_set_clause = retry_failed_job_assignments(
        "$3",
        "COALESCE(TIMESTAMPTZ 'epoch' + ($4::bigint * INTERVAL '1 microsecond'), statement_timestamp())",
    );
    format!(
        r#"
        WITH visible AS (
            SELECT {status}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}, {status}, {task_name}, {dedupe_key}
            FROM {}
            WHERE {id} = $1
            FOR UPDATE SKIP LOCKED
        ),
        dedupe_conflict AS (
            SELECT 1
            FROM target
            WHERE {status} = $2
              AND {dedupe_key} IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM {} AS active
                  WHERE {active_dedupe_match}
                    AND {active_id} <> {target_id}
              )
        ),
        updated AS (
            UPDATE {} SET
                {retry_set_clause}
            WHERE {id} IN (
                SELECT {id}
                FROM target
                WHERE {status} = $2
                  AND NOT EXISTS (SELECT 1 FROM dedupe_conflict)
            )
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM dedupe_conflict) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM target) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE {status} <> $2) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
            ELSE '{}'
        END
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_DEDUPE_CONFLICT,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_force_requeue_running_job_by_id_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let set_clause = return_to_pending_assignments(&format!("'{}'", JobStatus::Pending.as_str()));
    format!(
        r#"
        WITH visible AS (
            SELECT {status}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}, {status}
            FROM {}
            WHERE {id} = $1
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                {set_clause}
            WHERE {id} IN (SELECT {id} FROM target WHERE {status} = $2)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM target) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE {status} <> $2) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
            ELSE '{}'
        END
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_move_failed_job_to_dead_letter_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let payload = QueueColumn::Payload.name();
    let status = QueueColumn::Status.name();
    let last_error = QueueColumn::LastError.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let timeout_nanos = QueueColumn::TimeoutNanos.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let dead_letter_insert_columns = dead_letter_insert_columns_sql();
    let inserted_id = QueueQueryField::InsertedId.name();
    let target_exists = QueueQueryField::TargetExists.name();
    let target_matches_status = QueueQueryField::TargetMatchesStatus.name();
    let visible_exists = QueueQueryField::VisibleExists.name();
    let visible_matches_status = QueueQueryField::VisibleMatchesStatus.name();
    format!(
        r#"
        WITH visible AS (
            SELECT {status}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}, {status}
            FROM {}
            WHERE {id} = $1
            FOR UPDATE SKIP LOCKED
        ),
        moved AS (
            DELETE FROM {}
            WHERE {id} IN (SELECT {id} FROM target WHERE {status} = $2)
            RETURNING
                {id},
                {task_name},
                {payload},
                COALESCE({last_error}, '') AS {last_error},
                {retry_count},
                {max_retries},
                {timeout_nanos},
                {dedupe_key}
        ),
        inserted AS (
            INSERT INTO {} ({dead_letter_insert_columns})
            SELECT
                $3, {id}, {task_name}, {payload}, {last_error},
                {retry_count}, {max_retries}, {timeout_nanos}, {dedupe_key},
                $4, statement_timestamp(), statement_timestamp(), statement_timestamp()
            FROM moved
            RETURNING {id}
        )
        SELECT
            (SELECT {id} FROM inserted) AS {inserted_id},
            EXISTS(SELECT 1 FROM target) AS {target_exists},
            EXISTS(SELECT 1 FROM target WHERE {status} = $2) AS {target_matches_status},
            EXISTS(SELECT 1 FROM visible) AS {visible_exists},
            EXISTS(SELECT 1 FROM visible WHERE {status} = $2) AS {visible_matches_status}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_move_failed_jobs_to_dead_letter_batch_query(
    config: &StoreConfig,
    job_count: usize,
) -> String {
    let id_values = build_dead_letter_move_id_values(job_count);
    let failed_status_placeholder = job_count * 2 + 1;
    let reason_placeholder = failed_status_placeholder + 1;
    let id = QueueColumn::Id.name();
    let original_job_id = QueueColumn::OriginalJobId.name();
    let task_name = QueueColumn::TaskName.name();
    let payload = QueueColumn::Payload.name();
    let last_error = QueueColumn::LastError.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let timeout_nanos = QueueColumn::TimeoutNanos.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let jobs_id = qualified_queue_column("jobs", QueueColumn::Id);
    let jobs_task_name = qualified_queue_column("jobs", QueueColumn::TaskName);
    let jobs_payload = qualified_queue_column("jobs", QueueColumn::Payload);
    let jobs_status = qualified_queue_column("jobs", QueueColumn::Status);
    let jobs_last_error = qualified_queue_column("jobs", QueueColumn::LastError);
    let jobs_retry_count = qualified_queue_column("jobs", QueueColumn::RetryCount);
    let jobs_max_retries = qualified_queue_column("jobs", QueueColumn::MaxRetries);
    let jobs_timeout_nanos = qualified_queue_column("jobs", QueueColumn::TimeoutNanos);
    let jobs_dedupe_key = qualified_queue_column("jobs", QueueColumn::DedupeKey);
    let id_map_original_job_id = format!("id_map.{original_job_id}");
    let dead_letter_insert_columns = dead_letter_insert_columns_sql();
    format!(
        r#"
        WITH id_map({original_job_id}, dead_letter_id) AS (
            VALUES {id_values}
        ),
        candidates AS (
            SELECT {jobs_id}, id_map.dead_letter_id
            FROM {} AS jobs
            JOIN id_map ON {jobs_id} = {id_map_original_job_id}
            WHERE {jobs_status} = ${failed_status_placeholder}
            FOR UPDATE OF jobs SKIP LOCKED
        ),
        moved AS (
            DELETE FROM {} AS jobs
            USING candidates
            WHERE {jobs_id} = candidates.{id}
            RETURNING
                {jobs_id} AS {original_job_id},
                candidates.dead_letter_id,
                {jobs_task_name},
                {jobs_payload},
                COALESCE({jobs_last_error}, '') AS {last_error},
                {jobs_retry_count},
                {jobs_max_retries},
                {jobs_timeout_nanos},
                {jobs_dedupe_key}
        )
        INSERT INTO {} ({dead_letter_insert_columns})
        SELECT
            moved.dead_letter_id,
            moved.{original_job_id},
            moved.{task_name},
            moved.{payload},
            moved.{last_error},
            moved.{retry_count},
            moved.{max_retries},
            moved.{timeout_nanos},
            moved.{dedupe_key},
            ${reason_placeholder},
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        FROM moved
        RETURNING {id}, {original_job_id}, {task_name}, {last_error}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_dead_letter_move_id_values(job_count: usize) -> String {
    (0..job_count)
        .map(|index| {
            let original_placeholder = index * 2 + 1;
            let dead_letter_placeholder = original_placeholder + 1;
            format!("(${original_placeholder}::bytea, ${dead_letter_placeholder}::bytea)")
        })
        .collect::<Vec<_>>()
        .join(", ")
}
