use super::*;

pub(in crate::db::queue) fn build_claim_available_jobs_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let task_name = QueueColumn::TaskName.name();
    let run_at_or_after = QueueColumn::RunAtOrAfter.name();
    let worker_id = QueueColumn::WorkerId.name();
    let claimed_by_worker_at = QueueColumn::ClaimedByWorkerAt.name();
    let execution_heartbeat_at = QueueColumn::ExecutionHeartbeatAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    let pause_key = qualified_queue_column("p", QueueColumn::Key);
    let job_task_name = qualified_queue_column("j", QueueColumn::TaskName);
    format!(
        r#"
        WITH candidates AS (
            SELECT {id}
            FROM {} j
            WHERE {status} = $1
              AND {task_name} = ANY($2::text[])
              AND {run_at_or_after} <= statement_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM {} p WHERE {pause_key} = $6
              )
              AND NOT EXISTS (
                  SELECT 1 FROM {} p WHERE {pause_key} = '{}' || {job_task_name}
              )
            ORDER BY {run_at_or_after} ASC, {id} ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            {status} = $4,
            {worker_id} = $5,
            {claimed_by_worker_at} = statement_timestamp(),
            {execution_heartbeat_at} = statement_timestamp(),
            {updated_at} = statement_timestamp()
        WHERE {id} IN (SELECT {id} FROM candidates)
        RETURNING {}
        "#,
        config.table_name.quoted(),
        config.pause_table_name.quoted(),
        config.pause_table_name.quoted(),
        TASK_PAUSE_KEY_PREFIX,
        config.table_name.quoted(),
        queue_job_projection(),
    )
}

pub(in crate::db::queue) fn build_mark_job_started_query(config: &StoreConfig) -> String {
    let set_clause = sql_assignments(&[
        queue_column_assignment(QueueColumn::ExecutionStartedAt, "statement_timestamp()"),
        queue_column_assignment(QueueColumn::ExecutionHeartbeatAt, "statement_timestamp()"),
        queue_column_assignment(QueueColumn::UpdatedAt, "statement_timestamp()"),
    ]);
    build_owned_running_job_update_query(config, &set_clause, "", "")
}

pub(in crate::db::queue) fn build_mark_job_completed_query(config: &StoreConfig) -> String {
    let set_clause = sql_assignments(&[
        queue_column_assignment(
            QueueColumn::Status,
            &format!("'{}'", JobStatus::Completed.as_str()),
        ),
        clear_worker_runtime_assignments("statement_timestamp()"),
        queue_column_assignment(QueueColumn::UpdatedAt, "statement_timestamp()"),
    ]);
    build_owned_running_job_update_query(config, &set_clause, "", "")
}

pub(in crate::db::queue) fn build_touch_execution_heartbeat_query(config: &StoreConfig) -> String {
    let set_clause = sql_assignments(&[
        queue_column_assignment(QueueColumn::ExecutionHeartbeatAt, "statement_timestamp()"),
        queue_column_assignment(QueueColumn::UpdatedAt, "statement_timestamp()"),
    ]);
    build_owned_running_job_update_query(config, &set_clause, "", "")
}

pub(in crate::db::queue) fn build_mark_job_failed_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let worker_id = QueueColumn::WorkerId.name();
    let retry_count = QueueColumn::RetryCount.name();
    let set_clause = sql_assignments(&[
        queue_column_assignment(QueueColumn::Status, "$1"),
        queue_column_assignment(QueueColumn::LastError, "$2"),
        queue_column_assignment(
            QueueColumn::RetryCount,
            &format!("{retry_count} + CASE WHEN $3 THEN 1 ELSE 0 END"),
        ),
        clear_worker_runtime_assignments("statement_timestamp()"),
        queue_column_assignment(QueueColumn::UpdatedAt, "statement_timestamp()"),
    ]);
    format!(
        r#"
        WITH visible AS (
            SELECT {status}, {worker_id}
            FROM {}
            WHERE {id} = $4
        ),
        target AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $4 AND {status} = $5 AND {worker_id} = $6
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                {set_clause}
            WHERE {id} IN (SELECT {id} FROM target)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE {status} <> $5 OR {worker_id} IS DISTINCT FROM $6) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
            ELSE '{}'
        END
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_schedule_owned_running_job_retry_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let worker_id = QueueColumn::WorkerId.name();
    let run_at_or_after = QueueColumn::RunAtOrAfter.name();
    let next_run_at = QueueQueryField::NextRunAt.name();
    let outcome = QueueQueryField::Outcome.name();
    let set_clause = sql_assignments(&[
        queue_column_assignment(QueueColumn::Status, "$1"),
        queue_column_assignment(QueueColumn::RetryCount, "$2"),
        queue_column_assignment(
            QueueColumn::RunAtOrAfter,
            "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
        ),
        queue_column_assignment(QueueColumn::LastError, "$4"),
        clear_worker_runtime_assignments("NULL"),
        queue_column_assignment(QueueColumn::UpdatedAt, "statement_timestamp()"),
    ]);
    format!(
        r#"
        WITH visible AS (
            SELECT {status}, {worker_id}
            FROM {}
            WHERE {id} = $5
        ),
        target AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $5 AND {status} = $6 AND {worker_id} = $7
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                {set_clause}
            WHERE {id} IN (SELECT {id} FROM target)
            RETURNING ((EXTRACT(EPOCH FROM {run_at_or_after}) * 1000000)::bigint) AS {next_run_at}
        )
        SELECT
            CASE
                WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible WHERE {status} <> $6 OR {worker_id} IS DISTINCT FROM $7) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
                ELSE '{}'
            END AS {outcome},
            (SELECT {next_run_at} FROM updated) AS {next_run_at}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_move_owned_running_job_to_dead_letter_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let payload = QueueColumn::Payload.name();
    let status = QueueColumn::Status.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let timeout_nanos = QueueColumn::TimeoutNanos.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let worker_id = QueueColumn::WorkerId.name();
    let dead_letter_insert_columns = dead_letter_insert_columns_sql();
    let inserted_id = QueueQueryField::InsertedId.name();
    let outcome = QueueQueryField::Outcome.name();
    format!(
        r#"
        WITH visible AS (
            SELECT {status}, {worker_id}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $1 AND {status} = $2 AND {worker_id} = $3
            FOR UPDATE SKIP LOCKED
        ),
        moved AS (
            DELETE FROM {}
            WHERE {id} IN (SELECT {id} FROM target)
            RETURNING
                {id},
                {task_name},
                {payload},
                {retry_count} + CASE WHEN $6::boolean THEN 1 ELSE 0 END AS {retry_count},
                {max_retries},
                {timeout_nanos},
                {dedupe_key}
        ),
        inserted AS (
            INSERT INTO {} ({dead_letter_insert_columns})
            SELECT
                $4, {id}, {task_name}, {payload}, $5,
                {retry_count}, {max_retries}, {timeout_nanos}, {dedupe_key},
                $7, statement_timestamp(), statement_timestamp(), statement_timestamp()
            FROM moved
            RETURNING {id}
        )
        SELECT
            CASE
                WHEN EXISTS (SELECT 1 FROM inserted) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible WHERE {status} <> $2 OR {worker_id} IS DISTINCT FROM $3) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
                ELSE '{}'
            END AS {outcome},
            (SELECT {id} FROM inserted) AS {inserted_id}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.dead_letter_table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_return_owned_unstarted_running_job_to_pending_query(
    config: &StoreConfig,
) -> String {
    let set_clause = return_to_pending_assignments(&format!("'{}'", JobStatus::Pending.as_str()));
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    build_owned_running_job_update_query(
        config,
        &set_clause,
        &format!("AND {execution_started_at} IS NULL"),
        &format!("OR {execution_started_at} IS NOT NULL"),
    )
}

pub(in crate::db::queue) fn build_return_owned_started_running_job_to_pending_query(
    config: &StoreConfig,
) -> String {
    let set_clause = return_to_pending_assignments(&format!("'{}'", JobStatus::Pending.as_str()));
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    build_owned_running_job_update_query(
        config,
        &set_clause,
        &format!("AND {execution_started_at} IS NOT NULL"),
        &format!("OR {execution_started_at} IS NULL"),
    )
}

pub(in crate::db::queue) fn build_owned_running_job_update_query(
    config: &StoreConfig,
    set_clause: &str,
    target_extra_predicate: &str,
    visible_extra_mismatch_predicate: &str,
) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let worker_id = QueueColumn::WorkerId.name();
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    format!(
        r#"
        WITH visible AS (
            SELECT {status}, {worker_id}, {execution_started_at}
            FROM {}
            WHERE {id} = $1
        ),
        target AS (
            SELECT {id}
            FROM {}
            WHERE {id} = $1 AND {status} = $2 AND {worker_id} = $3 {target_extra_predicate}
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                {set_clause}
            WHERE {id} IN (SELECT {id} FROM target)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (
                SELECT 1 FROM visible
                WHERE {status} <> $2 OR {worker_id} IS DISTINCT FROM $3 {visible_extra_mismatch_predicate}
            ) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
            ELSE '{}'
        END
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        TRANSITION_OUTCOME_APPLIED,
        TRANSITION_OUTCOME_STATE_MISMATCH,
        TRANSITION_OUTCOME_LOCKED,
        TRANSITION_OUTCOME_NOT_FOUND,
    )
}

pub(in crate::db::queue) fn build_return_available_owned_unstarted_running_jobs_to_pending_query(
    config: &StoreConfig,
) -> String {
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    build_return_available_owned_running_jobs_to_pending_query(
        config,
        &format!("{execution_started_at} IS NULL"),
    )
}

pub(in crate::db::queue) fn build_return_available_owned_started_running_jobs_to_pending_query(
    config: &StoreConfig,
) -> String {
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    build_return_available_owned_running_jobs_to_pending_query(
        config,
        &format!("{execution_started_at} IS NOT NULL"),
    )
}

pub(in crate::db::queue) fn build_return_available_owned_running_jobs_to_pending_query(
    config: &StoreConfig,
    execution_started_predicate: &str,
) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let worker_id = QueueColumn::WorkerId.name();
    let set_clause = return_to_pending_assignments("$1");
    format!(
        r#"
        WITH candidates AS (
            SELECT {id}
            FROM {}
            WHERE {worker_id} = $2 AND {status} = $3 AND {execution_started_predicate}
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            {set_clause}
        WHERE {id} IN (SELECT {id} FROM candidates)
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}
