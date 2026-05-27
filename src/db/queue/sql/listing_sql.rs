use super::*;

pub(in crate::db::queue) fn build_list_jobs_query(config: &StoreConfig) -> String {
    format!(
        r#"
        SELECT {}
        FROM {}
        WHERE (CARDINALITY($1::text[]) = 0 OR status = ANY($1::text[]))
          AND ($2::text IS NULL OR task_name = $2)
          AND ($3::bytea IS NULL OR id > $3)
        ORDER BY id ASC
        LIMIT $4
        "#,
        queue_job_projection(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn dead_letter_job_projection() -> &'static str {
    r#"
        id,
        original_job_id,
        task_name,
        payload::text AS payload_json,
        last_error,
        retry_count,
        max_retries,
        timeout_nanos,
        dedupe_key,
        reason,
        ((EXTRACT(EPOCH FROM dead_lettered_at) * 1000000)::bigint) AS dead_lettered_at_us,
        ((EXTRACT(EPOCH FROM created_at) * 1000000)::bigint) AS created_at_us,
        ((EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint) AS updated_at_us
    "#
}

pub(in crate::db::queue) fn build_list_dead_letter_jobs_query(config: &StoreConfig) -> String {
    format!(
        r#"
        SELECT {}
        FROM {}
        WHERE ($1::text IS NULL OR task_name = $1)
          AND ($2::bytea IS NULL OR id > $2)
        ORDER BY id ASC
        LIMIT $3
        "#,
        dead_letter_job_projection(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_requeue_dead_letter_job_query(config: &StoreConfig) -> String {
    format!(
        r#"
        WITH visible AS (
            SELECT id
            FROM {}
            WHERE id = $1
        ),
        source AS (
            SELECT id, task_name, payload, max_retries, timeout_nanos, dedupe_key
            FROM {}
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
        ),
        dedupe_conflict AS (
            SELECT 1
            FROM source
            WHERE dedupe_key IS NOT NULL
              AND EXISTS (
                  SELECT 1
                  FROM {} AS active
                  WHERE active.task_name = source.task_name
                    AND active.dedupe_key = source.dedupe_key
                    AND active.status IN ('pending', 'running')
              )
        ),
        inserted AS (
            INSERT INTO {} (
                id, task_name, payload, status, run_at_or_after,
                retry_count, max_retries, timeout_nanos, dedupe_key,
                created_at, updated_at
            )
            SELECT
                $2, task_name, payload, $3,
                COALESCE(TIMESTAMPTZ 'epoch' + ($4::bigint * INTERVAL '1 microsecond'), statement_timestamp()),
                0, max_retries, timeout_nanos, dedupe_key,
                statement_timestamp(), statement_timestamp()
            FROM source
            WHERE NOT EXISTS (SELECT 1 FROM dedupe_conflict)
            ON CONFLICT (task_name, dedupe_key)
            WHERE dedupe_key IS NOT NULL AND status IN ('pending', 'running')
            DO NOTHING
            RETURNING id
        ),
        deleted AS (
            DELETE FROM {}
            WHERE id IN (SELECT id FROM source)
              AND EXISTS (SELECT 1 FROM inserted)
            RETURNING 1
        )
        SELECT
            (SELECT id FROM inserted) AS inserted_id,
            EXISTS(SELECT 1 FROM source) AS source_exists,
            EXISTS(SELECT 1 FROM visible) AS visible_exists,
            EXISTS(SELECT 1 FROM dedupe_conflict) AS dedupe_conflict_exists,
            EXISTS(SELECT 1 FROM deleted) AS deleted_source
        "#,
        config.dead_letter_table_name.quoted(),
        config.dead_letter_table_name.quoted(),
        config.table_name.quoted(),
        config.table_name.quoted(),
        config.dead_letter_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_delete_dead_letter_job_query(config: &StoreConfig) -> String {
    format!(
        r#"
        WITH visible AS (
            SELECT id
            FROM {}
            WHERE id = $1
        ),
        target AS (
            SELECT id
            FROM {}
            WHERE id = $1
            FOR UPDATE SKIP LOCKED
        ),
        deleted AS (
            DELETE FROM {}
            WHERE id IN (SELECT id FROM target)
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
