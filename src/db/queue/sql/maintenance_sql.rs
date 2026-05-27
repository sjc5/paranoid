use super::*;

pub(in crate::db::queue) fn build_cleanup_jobs_older_than_once_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        WITH to_delete AS (
            SELECT id
            FROM {}
            WHERE status = $1
              AND finished_at IS NOT NULL
              AND finished_at < statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond')
            ORDER BY finished_at ASC, id ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM {}
        WHERE id IN (SELECT id FROM to_delete)
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_cleanup_available_dead_letter_jobs_older_than_once_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        WITH to_delete AS (
            SELECT id
            FROM {}
            WHERE dead_lettered_at < statement_timestamp() - ($1::bigint * INTERVAL '1 microsecond')
            ORDER BY dead_lettered_at ASC, id ASC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM {}
        WHERE id IN (SELECT id FROM to_delete)
        "#,
        config.dead_letter_table_name.quoted(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_reclaim_never_started_running_jobs_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        WITH candidates AS (
            SELECT id
            FROM {}
            WHERE status = $2
              AND execution_started_at IS NULL
              AND execution_heartbeat_at < statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
            ORDER BY execution_heartbeat_at ASC, id ASC
            LIMIT $4
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            status = $1,
            worker_id = NULL,
            claimed_by_worker_at = NULL,
            execution_started_at = NULL,
            execution_heartbeat_at = NULL,
            finished_at = NULL,
            updated_at = statement_timestamp()
        WHERE id IN (SELECT id FROM candidates)
        RETURNING id, task_name
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_reclaim_expired_running_jobs_to_failed_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        WITH candidates AS (
            SELECT id
            FROM {}
            WHERE status = $2
              AND execution_started_at IS NOT NULL
              AND execution_heartbeat_at < statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
              AND retry_count >= max_retries
            ORDER BY execution_heartbeat_at ASC, id ASC
            LIMIT $4
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            status = $1,
            retry_count = retry_count + 1,
            last_error = COALESCE(last_error || ' | ', '') || '{}',
            worker_id = NULL,
            claimed_by_worker_at = NULL,
            execution_started_at = NULL,
            execution_heartbeat_at = NULL,
            finished_at = statement_timestamp(),
            updated_at = statement_timestamp()
        WHERE id IN (SELECT id FROM candidates)
        RETURNING id, task_name, last_error
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        STALE_EXECUTION_ERROR,
    )
}

pub(in crate::db::queue) fn build_reclaim_expired_running_jobs_to_pending_for_retry_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        WITH candidates AS (
            SELECT id
            FROM {}
            WHERE status = $2
              AND execution_started_at IS NOT NULL
              AND execution_heartbeat_at < statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
              AND retry_count < max_retries
            ORDER BY execution_heartbeat_at ASC, id ASC
            LIMIT $4
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            status = $1,
            retry_count = retry_count + 1,
            last_error = COALESCE(last_error || ' | ', '') || '{}',
            worker_id = NULL,
            claimed_by_worker_at = NULL,
            execution_started_at = NULL,
            execution_heartbeat_at = NULL,
            finished_at = NULL,
            updated_at = statement_timestamp()
        WHERE id IN (SELECT id FROM candidates)
        RETURNING id, task_name
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        STALE_EXECUTION_ERROR,
    )
}
