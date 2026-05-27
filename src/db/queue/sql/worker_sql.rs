use super::*;

pub(in crate::db::queue) fn build_claim_available_jobs_query(config: &StoreConfig) -> String {
    format!(
        r#"
        WITH candidates AS (
            SELECT id
            FROM {} j
            WHERE status = $1
              AND task_name = ANY($2::text[])
              AND run_at_or_after <= statement_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM {} p WHERE p.key = $6
              )
              AND NOT EXISTS (
                  SELECT 1 FROM {} p WHERE p.key = '{}' || j.task_name
              )
            ORDER BY run_at_or_after ASC, id ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        )
        UPDATE {} SET
            status = $4,
            worker_id = $5,
            claimed_by_worker_at = statement_timestamp(),
            execution_heartbeat_at = statement_timestamp(),
            updated_at = statement_timestamp()
        WHERE id IN (SELECT id FROM candidates)
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
    build_owned_running_job_update_query(
        config,
        r#"
        execution_started_at = statement_timestamp(),
        execution_heartbeat_at = statement_timestamp(),
        updated_at = statement_timestamp()
        "#,
        "",
        "",
    )
}

pub(in crate::db::queue) fn build_mark_job_completed_query(config: &StoreConfig) -> String {
    build_owned_running_job_update_query(
        config,
        r#"
        status = 'completed',
        worker_id = NULL,
        claimed_by_worker_at = NULL,
        execution_started_at = NULL,
        execution_heartbeat_at = NULL,
        finished_at = statement_timestamp(),
        updated_at = statement_timestamp()
        "#,
        "",
        "",
    )
}

pub(in crate::db::queue) fn build_touch_execution_heartbeat_query(config: &StoreConfig) -> String {
    build_owned_running_job_update_query(
        config,
        r#"
        execution_heartbeat_at = statement_timestamp(),
        updated_at = statement_timestamp()
        "#,
        "",
        "",
    )
}

pub(in crate::db::queue) fn build_mark_job_failed_query(config: &StoreConfig) -> String {
    format!(
        r#"
        WITH visible AS (
            SELECT status, worker_id
            FROM {}
            WHERE id = $4
        ),
        target AS (
            SELECT id
            FROM {}
            WHERE id = $4 AND status = $5 AND worker_id = $6
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                status = $1,
                last_error = $2,
                retry_count = retry_count + CASE WHEN $3 THEN 1 ELSE 0 END,
                worker_id = NULL,
                claimed_by_worker_at = NULL,
                execution_started_at = NULL,
                execution_heartbeat_at = NULL,
                finished_at = statement_timestamp(),
                updated_at = statement_timestamp()
            WHERE id IN (SELECT id FROM target)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE status <> $5 OR worker_id IS DISTINCT FROM $6) THEN '{}'
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
    format!(
        r#"
        WITH visible AS (
            SELECT status, worker_id
            FROM {}
            WHERE id = $5
        ),
        target AS (
            SELECT id
            FROM {}
            WHERE id = $5 AND status = $6 AND worker_id = $7
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                status = $1,
                retry_count = $2,
                run_at_or_after = statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond'),
                last_error = $4,
                worker_id = NULL,
                claimed_by_worker_at = NULL,
                execution_started_at = NULL,
                execution_heartbeat_at = NULL,
                finished_at = NULL,
                updated_at = statement_timestamp()
            WHERE id IN (SELECT id FROM target)
            RETURNING ((EXTRACT(EPOCH FROM run_at_or_after) * 1000000)::bigint) AS next_run_at
        )
        SELECT
            CASE
                WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible WHERE status <> $6 OR worker_id IS DISTINCT FROM $7) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
                ELSE '{}'
            END AS outcome,
            (SELECT next_run_at FROM updated) AS next_run_at
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
    format!(
        r#"
        WITH visible AS (
            SELECT status, worker_id
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id
            FROM {}
            WHERE id = $1 AND status = $2 AND worker_id = $3
            FOR UPDATE SKIP LOCKED
        ),
        moved AS (
            DELETE FROM {}
            WHERE id IN (SELECT id FROM target)
            RETURNING
                id,
                task_name,
                payload,
                retry_count + CASE WHEN $6::boolean THEN 1 ELSE 0 END AS retry_count,
                max_retries,
                timeout_nanos,
                dedupe_key
        ),
        inserted AS (
            INSERT INTO {} (
                id, original_job_id, task_name, payload, last_error,
                retry_count, max_retries, timeout_nanos, dedupe_key,
                reason, dead_lettered_at, created_at, updated_at
            )
            SELECT
                $4, id, task_name, payload, $5,
                retry_count, max_retries, timeout_nanos, dedupe_key,
                $7, statement_timestamp(), statement_timestamp(), statement_timestamp()
            FROM moved
            RETURNING id
        )
        SELECT
            CASE
                WHEN EXISTS (SELECT 1 FROM inserted) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible WHERE status <> $2 OR worker_id IS DISTINCT FROM $3) THEN '{}'
                WHEN EXISTS (SELECT 1 FROM visible) THEN '{}'
                ELSE '{}'
            END AS outcome,
            (SELECT id FROM inserted) AS inserted_id
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
    build_owned_running_job_update_query(
        config,
        r#"
        status = 'pending',
        worker_id = NULL,
        claimed_by_worker_at = NULL,
        execution_started_at = NULL,
        execution_heartbeat_at = NULL,
        finished_at = NULL,
        updated_at = statement_timestamp()
        "#,
        "AND execution_started_at IS NULL",
        "OR execution_started_at IS NOT NULL",
    )
}

pub(in crate::db::queue) fn build_return_owned_started_running_job_to_pending_query(
    config: &StoreConfig,
) -> String {
    build_owned_running_job_update_query(
        config,
        r#"
        status = 'pending',
        worker_id = NULL,
        claimed_by_worker_at = NULL,
        execution_started_at = NULL,
        execution_heartbeat_at = NULL,
        finished_at = NULL,
        updated_at = statement_timestamp()
        "#,
        "AND execution_started_at IS NOT NULL",
        "OR execution_started_at IS NULL",
    )
}

pub(in crate::db::queue) fn build_owned_running_job_update_query(
    config: &StoreConfig,
    set_clause: &str,
    target_extra_predicate: &str,
    visible_extra_mismatch_predicate: &str,
) -> String {
    format!(
        r#"
        WITH visible AS (
            SELECT status, worker_id, execution_started_at
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id
            FROM {}
            WHERE id = $1 AND status = $2 AND worker_id = $3 {target_extra_predicate}
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                {set_clause}
            WHERE id IN (SELECT id FROM target)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (
                SELECT 1 FROM visible
                WHERE status <> $2 OR worker_id IS DISTINCT FROM $3 {visible_extra_mismatch_predicate}
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
    build_return_available_owned_running_jobs_to_pending_query(
        config,
        "execution_started_at IS NULL",
    )
}

pub(in crate::db::queue) fn build_return_available_owned_started_running_jobs_to_pending_query(
    config: &StoreConfig,
) -> String {
    build_return_available_owned_running_jobs_to_pending_query(
        config,
        "execution_started_at IS NOT NULL",
    )
}

pub(in crate::db::queue) fn build_return_available_owned_running_jobs_to_pending_query(
    config: &StoreConfig,
    execution_started_predicate: &str,
) -> String {
    format!(
        r#"
        WITH candidates AS (
            SELECT id
            FROM {}
            WHERE worker_id = $2 AND status = $3 AND {}
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
        "#,
        config.table_name.quoted(),
        execution_started_predicate,
        config.table_name.quoted(),
    )
}
