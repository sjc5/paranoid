use super::*;

pub(in crate::db::queue) fn build_cleanup_jobs_older_than_once_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let status = QueueColumn::Status.name();
    let finished_at = QueueColumn::FinishedAt.name();
    format!(
        r#"
        WITH to_delete AS (
            SELECT {id}
            FROM {}
            WHERE {status} = $1
              AND {finished_at} IS NOT NULL
              AND {finished_at} < statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond')
            ORDER BY {finished_at} ASC, {id} ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM {}
        WHERE {id} IN (SELECT {id} FROM to_delete)
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_cleanup_available_dead_letter_jobs_older_than_once_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let dead_lettered_at = QueueColumn::DeadLetteredAt.name();
    format!(
        r#"
        WITH to_delete AS (
            SELECT {id}
            FROM {}
            WHERE {dead_lettered_at} < statement_timestamp() - ($1::bigint * INTERVAL '1 microsecond')
            ORDER BY {dead_lettered_at} ASC, {id} ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM {}
        WHERE {id} IN (SELECT {id} FROM to_delete)
        "#,
        config.dead_letter_table_name.quoted(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_reclaim_never_started_running_jobs_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let status = QueueColumn::Status.name();
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    let execution_heartbeat_at = QueueColumn::ExecutionHeartbeatAt.name();
    let set_clause = return_to_pending_assignments("$1");
    format!(
        r#"
        WITH candidates AS (
            SELECT {id}
            FROM {}
            WHERE {status} = $2
              AND {execution_started_at} IS NULL
              AND {execution_heartbeat_at} < statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
            ORDER BY {execution_heartbeat_at} ASC, {id} ASC
            LIMIT $4
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            {set_clause}
        WHERE {id} IN (SELECT {id} FROM candidates)
        RETURNING {id}, {task_name}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_reclaim_expired_running_jobs_to_failed_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let status = QueueColumn::Status.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let last_error = QueueColumn::LastError.name();
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    let execution_heartbeat_at = QueueColumn::ExecutionHeartbeatAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    let clear_runtime_columns = clear_worker_runtime_assignments("statement_timestamp()");
    format!(
        r#"
        WITH candidates AS (
            SELECT {id}
            FROM {}
            WHERE {status} = $2
              AND {execution_started_at} IS NOT NULL
              AND {execution_heartbeat_at} < statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
              AND {retry_count} >= {max_retries}
            ORDER BY {execution_heartbeat_at} ASC, {id} ASC
            LIMIT $4
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            {status} = $1,
            {retry_count} = {retry_count} + 1,
            {last_error} = COALESCE({last_error} || ' | ', '') || '{}',
            {clear_runtime_columns},
            {updated_at} = statement_timestamp()
        WHERE {id} IN (SELECT {id} FROM candidates)
        RETURNING {id}, {task_name}, {last_error}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        STALE_EXECUTION_ERROR,
    )
}

pub(in crate::db::queue) fn build_reclaim_expired_running_jobs_to_pending_for_retry_query(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let status = QueueColumn::Status.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let last_error = QueueColumn::LastError.name();
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    let execution_heartbeat_at = QueueColumn::ExecutionHeartbeatAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    let clear_runtime_columns = clear_worker_runtime_assignments("NULL");
    format!(
        r#"
        WITH candidates AS (
            SELECT {id}
            FROM {}
            WHERE {status} = $2
              AND {execution_started_at} IS NOT NULL
              AND {execution_heartbeat_at} < statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
              AND {retry_count} < {max_retries}
            ORDER BY {execution_heartbeat_at} ASC, {id} ASC
            LIMIT $4
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            {status} = $1,
            {retry_count} = {retry_count} + 1,
            {last_error} = COALESCE({last_error} || ' | ', '') || '{}',
            {clear_runtime_columns},
            {updated_at} = statement_timestamp()
        WHERE {id} IN (SELECT {id} FROM candidates)
        RETURNING {id}, {task_name}
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        STALE_EXECUTION_ERROR,
    )
}
