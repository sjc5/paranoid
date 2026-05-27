use super::*;

pub(in crate::db::queue) fn build_cancel_pending_job_query(config: &StoreConfig) -> String {
    format!(
        r#"
        WITH visible AS (
            SELECT status
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id, status
            FROM {}
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
        ),
        deleted AS (
            DELETE FROM {}
            WHERE id IN (SELECT id FROM target WHERE status = $2)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM deleted) THEN 'applied'
            WHEN EXISTS (SELECT 1 FROM target) THEN 'state_mismatch'
            WHEN EXISTS (SELECT 1 FROM visible WHERE status <> $2) THEN 'state_mismatch'
            WHEN EXISTS (SELECT 1 FROM visible) THEN 'locked'
            ELSE 'not_found'
        END
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_retry_available_failed_jobs_query(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        WITH lockable AS (
            SELECT failed.id, failed.task_name, failed.dedupe_key, failed.finished_at
            FROM {} AS failed
            WHERE failed.status = $1
              AND ($5::text IS NULL OR failed.task_name = $5)
              AND (
                  failed.dedupe_key IS NULL
                  OR NOT EXISTS (
                      SELECT 1
                      FROM {} AS active
                      WHERE active.task_name = failed.task_name
                        AND active.dedupe_key = failed.dedupe_key
                        AND active.status IN ('pending', 'running')
                        AND active.id <> failed.id
                  )
              )
            ORDER BY failed.finished_at ASC NULLS FIRST, failed.id ASC
            LIMIT $2
            FOR UPDATE OF failed SKIP LOCKED
        ),
        ranked AS (
            SELECT
                id,
                dedupe_key,
                finished_at,
                ROW_NUMBER() OVER (
                    PARTITION BY task_name, dedupe_key
                    ORDER BY finished_at ASC NULLS FIRST, id ASC
                ) AS active_dedupe_retry_rank
            FROM lockable
        ),
        candidates AS (
            SELECT id
            FROM ranked
            WHERE dedupe_key IS NULL OR active_dedupe_retry_rank = 1
        )
        UPDATE {} SET
            status = $3,
            retry_count = 0,
            last_error = NULL,
            run_at_or_after = COALESCE(TIMESTAMPTZ 'epoch' + ($4::bigint * INTERVAL '1 microsecond'), statement_timestamp()),
            worker_id = NULL,
            claimed_by_worker_at = NULL,
            execution_started_at = NULL,
            execution_heartbeat_at = NULL,
            finished_at = NULL,
            updated_at = statement_timestamp()
        WHERE id IN (SELECT id FROM candidates)
        "#,
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_retry_failed_job_by_id_query(config: &StoreConfig) -> String {
    format!(
        r#"
        WITH visible AS (
            SELECT status
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id, status, task_name, dedupe_key
            FROM {}
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
        ),
        dedupe_conflict AS (
            SELECT 1
            FROM target
            WHERE status = $2
              AND dedupe_key IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM {} AS active
                  WHERE active.task_name = target.task_name
                    AND active.dedupe_key = target.dedupe_key
                    AND active.status IN ('pending', 'running')
                    AND active.id <> target.id
              )
        ),
        updated AS (
            UPDATE {} SET
                status = $3,
                retry_count = 0,
                last_error = NULL,
                run_at_or_after = COALESCE(TIMESTAMPTZ 'epoch' + ($4::bigint * INTERVAL '1 microsecond'), statement_timestamp()),
                worker_id = NULL,
                claimed_by_worker_at = NULL,
                execution_started_at = NULL,
                execution_heartbeat_at = NULL,
                finished_at = NULL,
                updated_at = statement_timestamp()
            WHERE id IN (
                SELECT id
                FROM target
                WHERE status = $2
                  AND NOT EXISTS (SELECT 1 FROM dedupe_conflict)
            )
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM dedupe_conflict) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM target) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE status <> $2) THEN '{}'
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
    format!(
        r#"
        WITH visible AS (
            SELECT status
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id, status
            FROM {}
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE {} SET
                status = 'pending',
                worker_id = NULL,
                claimed_by_worker_at = NULL,
                execution_started_at = NULL,
                execution_heartbeat_at = NULL,
                finished_at = NULL,
                updated_at = statement_timestamp()
            WHERE id IN (SELECT id FROM target WHERE status = $2)
            RETURNING 1
        )
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM updated) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM target) THEN '{}'
            WHEN EXISTS (SELECT 1 FROM visible WHERE status <> $2) THEN '{}'
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
    format!(
        r#"
        WITH visible AS (
            SELECT status
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id, status
            FROM {}
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
        ),
        moved AS (
            DELETE FROM {}
            WHERE id IN (SELECT id FROM target WHERE status = $2)
            RETURNING
                id,
                task_name,
                payload,
                COALESCE(last_error, '') AS last_error,
                retry_count,
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
                $3, id, task_name, payload, last_error,
                retry_count, max_retries, timeout_nanos, dedupe_key,
                $4, statement_timestamp(), statement_timestamp(), statement_timestamp()
            FROM moved
            RETURNING id
        )
        SELECT
            (SELECT id FROM inserted) AS inserted_id,
            EXISTS(SELECT 1 FROM target) AS target_exists,
            EXISTS(SELECT 1 FROM target WHERE status = $2) AS target_matches_status,
            EXISTS(SELECT 1 FROM visible) AS visible_exists,
            EXISTS(SELECT 1 FROM visible WHERE status = $2) AS visible_matches_status
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
    format!(
        r#"
        WITH id_map(original_job_id, dead_letter_id) AS (
            VALUES {id_values}
        ),
        candidates AS (
            SELECT jobs.id, id_map.dead_letter_id
            FROM {} AS jobs
            JOIN id_map ON jobs.id = id_map.original_job_id
            WHERE jobs.status = ${failed_status_placeholder}
            FOR UPDATE OF jobs SKIP LOCKED
        ),
        moved AS (
            DELETE FROM {} AS jobs
            USING candidates
            WHERE jobs.id = candidates.id
            RETURNING
                jobs.id AS original_job_id,
                candidates.dead_letter_id,
                jobs.task_name,
                jobs.payload,
                COALESCE(jobs.last_error, '') AS last_error,
                jobs.retry_count,
                jobs.max_retries,
                jobs.timeout_nanos,
                jobs.dedupe_key
        )
        INSERT INTO {} (
            id, original_job_id, task_name, payload, last_error,
            retry_count, max_retries, timeout_nanos, dedupe_key,
            reason, dead_lettered_at, created_at, updated_at
        )
        SELECT
            moved.dead_letter_id,
            moved.original_job_id,
            moved.task_name,
            moved.payload,
            moved.last_error,
            moved.retry_count,
            moved.max_retries,
            moved.timeout_nanos,
            moved.dedupe_key,
            ${reason_placeholder},
            statement_timestamp(),
            statement_timestamp(),
            statement_timestamp()
        FROM moved
        RETURNING id, original_job_id, task_name, last_error
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
