use super::*;

pub(in crate::db::queue) fn queue_job_projection() -> &'static str {
    r#"
        id,
        task_name,
        payload::text AS payload_json,
        status,
        ((EXTRACT(EPOCH FROM run_at_or_after) * 1000000)::bigint) AS run_at_or_after_us,
        last_error,
        retry_count,
        max_retries,
        timeout_nanos,
        dedupe_key,
        worker_id,
        ((EXTRACT(EPOCH FROM claimed_by_worker_at) * 1000000)::bigint) AS claimed_by_worker_at_us,
        ((EXTRACT(EPOCH FROM execution_started_at) * 1000000)::bigint) AS execution_started_at_us,
        ((EXTRACT(EPOCH FROM execution_heartbeat_at) * 1000000)::bigint) AS execution_heartbeat_at_us,
        ((EXTRACT(EPOCH FROM finished_at) * 1000000)::bigint) AS finished_at_us,
        ((EXTRACT(EPOCH FROM created_at) * 1000000)::bigint) AS created_at_us,
        ((EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint) AS updated_at_us
    "#
}

pub(in crate::db::queue) fn build_select_job_by_id_query(config: &StoreConfig) -> String {
    format!(
        "SELECT {} FROM {} WHERE id = $1",
        queue_job_projection(),
        config.table_name.quoted()
    )
}

pub(in crate::db::queue) fn build_fetch_status_counts_query(config: &StoreConfig) -> String {
    format!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE j.status = 'pending')::bigint AS pending_count,
            COUNT(*) FILTER (WHERE j.status = 'running')::bigint AS running_count,
            COUNT(*) FILTER (WHERE j.status = 'completed')::bigint AS completed_count,
            COUNT(*) FILTER (WHERE j.status = 'failed')::bigint AS failed_count,
            (
                SELECT COUNT(*)::bigint
                FROM {} d
                WHERE ($1::text IS NULL OR d.task_name = $1)
            ) AS dead_letter_count
        FROM {} j
        WHERE ($1::text IS NULL OR j.task_name = $1)
        "#,
        config.dead_letter_table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_job_count_by_status_query(config: &StoreConfig) -> String {
    format!(
        r#"
        SELECT COUNT(*)::bigint
        FROM {}
        WHERE status = $1
          AND ($2::text IS NULL OR task_name = $2)
        "#,
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_worker_pressure_counts_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE status = 'pending')::bigint AS pending_job_count,
            COUNT(*) FILTER (WHERE status = 'running')::bigint AS running_job_count
        FROM {}
        "#,
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_pause_entries_query(config: &StoreConfig) -> String {
    format!(
        r#"
        SELECT key
        FROM {}
        WHERE key = $1 OR key LIKE $2
        ORDER BY key
        "#,
        config.pause_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_pending_or_running_task_names_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        SELECT DISTINCT task_name
        FROM {}
        WHERE status IN ($1, $2)
        ORDER BY task_name
        "#,
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_upsert_pause_key_query(config: &StoreConfig) -> String {
    format!(
        r#"
        INSERT INTO {} (key, task_name, paused_at, updated_at)
        VALUES ($1, $2, statement_timestamp(), statement_timestamp())
        ON CONFLICT (key) DO UPDATE
        SET task_name = EXCLUDED.task_name,
            paused_at = statement_timestamp(),
            updated_at = statement_timestamp()
        "#,
        config.pause_table_name.quoted()
    )
}

pub(in crate::db::queue) fn build_delete_pause_key_query(config: &StoreConfig) -> String {
    format!(
        "DELETE FROM {} WHERE key = $1",
        config.pause_table_name.quoted()
    )
}

pub(in crate::db::queue) fn build_pause_key_exists_query(config: &StoreConfig) -> String {
    format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE key = $1)",
        config.pause_table_name.quoted()
    )
}
