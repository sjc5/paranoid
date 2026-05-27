use super::*;

pub(in crate::db::queue) fn build_queue_schema_migration_statements(
    config: &StoreConfig,
) -> Vec<String> {
    vec![
        build_create_jobs_table_statement(config),
        build_create_dead_letter_table_statement(config),
        build_create_pause_table_statement(config),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                PENDING_RUN_AT_INDEX_SUFFIX,
            ),
            "status, run_at_or_after, id",
            Some("status = 'pending'"),
            false,
        ),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                PENDING_TASK_RUN_AT_INDEX_SUFFIX,
            ),
            "task_name, run_at_or_after, id",
            Some("status = 'pending'"),
            false,
        ),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(INDEX_KIND, &config.table_name, TASK_STATUS_INDEX_SUFFIX),
            "task_name, status",
            None,
            false,
        ),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(INDEX_KIND, &config.table_name, WORKER_INDEX_SUFFIX),
            "worker_id",
            Some("worker_id IS NOT NULL"),
            false,
        ),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(
                INDEX_KIND,
                &config.table_name,
                EXECUTION_HEARTBEAT_INDEX_SUFFIX,
            ),
            "status, execution_heartbeat_at, id",
            Some("status = 'running' AND execution_heartbeat_at IS NOT NULL"),
            false,
        ),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(INDEX_KIND, &config.table_name, CLEANUP_INDEX_SUFFIX),
            "finished_at, id",
            Some("status IN ('completed', 'failed') AND finished_at IS NOT NULL"),
            false,
        ),
        build_create_index_statement(
            &config.table_name,
            &migration_index_identifier(
                UNIQUE_INDEX_KIND,
                &config.table_name,
                ACTIVE_DEDUPE_INDEX_SUFFIX,
            ),
            "task_name, dedupe_key",
            Some("dedupe_key IS NOT NULL AND status IN ('pending', 'running')"),
            true,
        ),
        build_create_index_statement(
            &config.dead_letter_table_name,
            &migration_index_identifier(
                INDEX_KIND,
                &config.dead_letter_table_name,
                DEAD_LETTERED_AT_INDEX_SUFFIX,
            ),
            "dead_lettered_at, id",
            None,
            false,
        ),
        build_create_index_statement(
            &config.dead_letter_table_name,
            &migration_index_identifier(
                INDEX_KIND,
                &config.dead_letter_table_name,
                TASK_DEAD_LETTERED_AT_INDEX_SUFFIX,
            ),
            "task_name, dead_lettered_at, id",
            None,
            false,
        ),
        build_create_index_statement(
            &config.dead_letter_table_name,
            &migration_index_identifier(
                UNIQUE_INDEX_KIND,
                &config.dead_letter_table_name,
                ORIGINAL_JOB_INDEX_SUFFIX,
            ),
            "original_job_id",
            None,
            true,
        ),
        build_create_index_statement(
            &config.pause_table_name,
            &migration_index_identifier(
                INDEX_KIND,
                &config.pause_table_name,
                PAUSE_TASK_INDEX_SUFFIX,
            ),
            "task_name",
            Some("task_name IS NOT NULL"),
            false,
        ),
    ]
}

pub(in crate::db::queue) fn build_create_jobs_table_statement(config: &StoreConfig) -> String {
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id BYTEA PRIMARY KEY CHECK (octet_length(id) = {}),
            task_name TEXT COLLATE "C" NOT NULL,
            payload JSONB NOT NULL,
            status TEXT COLLATE "C" NOT NULL,
            run_at_or_after TIMESTAMPTZ NOT NULL,
            last_error TEXT COLLATE "C",
            retry_count INT NOT NULL DEFAULT 0,
            max_retries INT NOT NULL DEFAULT 5,
            timeout_nanos BIGINT NOT NULL DEFAULT 0,
            dedupe_key TEXT COLLATE "C",
            worker_id TEXT COLLATE "C",
            claimed_by_worker_at TIMESTAMPTZ,
            execution_started_at TIMESTAMPTZ,
            execution_heartbeat_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            CONSTRAINT {} CHECK (status IN ('pending', 'running', 'completed', 'failed')),
            CONSTRAINT {} CHECK (
                retry_count >= 0
                AND max_retries >= 0
                AND timeout_nanos >= -1
            ),
            CONSTRAINT {} CHECK (
                task_name ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length(task_name) <= {}
                AND (
                    dedupe_key IS NULL
                    OR (
                        dedupe_key <> ''
                        AND octet_length(dedupe_key) <= {}
                    )
                )
                AND (
                    worker_id IS NULL
                    OR (
                        worker_id <> ''
                        AND octet_length(worker_id) <= {}
                    )
                )
            ),
            CONSTRAINT {} CHECK (
                (
                    status = 'pending'
                    AND worker_id IS NULL
                    AND claimed_by_worker_at IS NULL
                    AND execution_started_at IS NULL
                    AND execution_heartbeat_at IS NULL
                    AND finished_at IS NULL
                )
                OR
                (
                    status = 'running'
                    AND worker_id IS NOT NULL
                    AND claimed_by_worker_at IS NOT NULL
                    AND execution_heartbeat_at IS NOT NULL
                    AND finished_at IS NULL
                )
                OR
                (
                    status IN ('completed', 'failed')
                    AND worker_id IS NULL
                    AND claimed_by_worker_at IS NULL
                    AND execution_started_at IS NULL
                    AND execution_heartbeat_at IS NULL
                    AND finished_at IS NOT NULL
                )
            ),
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        config.table_name.quoted(),
        JOB_ID_SIZE,
        job_status_constraint_identifier(config).quoted(),
        job_numeric_constraint_identifier(config).quoted(),
        job_text_constraint_identifier(config).quoted(),
        MAX_QUEUE_TASK_NAME_BYTES,
        MAX_QUEUE_DEDUPE_KEY_BYTES,
        MAX_QUEUE_WORKER_OWNER_ID_BYTES,
        job_lifecycle_constraint_identifier(config).quoted(),
    )
}

pub(in crate::db::queue) fn build_create_dead_letter_table_statement(
    config: &StoreConfig,
) -> String {
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id BYTEA PRIMARY KEY CHECK (octet_length(id) = {}),
            original_job_id BYTEA NOT NULL CHECK (octet_length(original_job_id) = {}),
            task_name TEXT COLLATE "C" NOT NULL,
            payload JSONB NOT NULL,
            last_error TEXT COLLATE "C" NOT NULL,
            retry_count INT NOT NULL,
            max_retries INT NOT NULL,
            timeout_nanos BIGINT NOT NULL DEFAULT 0,
            dedupe_key TEXT COLLATE "C",
            reason TEXT COLLATE "C" NOT NULL,
            dead_lettered_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT {} CHECK (
                retry_count >= 0
                AND max_retries >= 0
                AND timeout_nanos >= -1
            ),
            CONSTRAINT {} CHECK (
                task_name ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length(task_name) <= {}
                AND (
                    dedupe_key IS NULL
                    OR (
                        dedupe_key <> ''
                        AND octet_length(dedupe_key) <= {}
                    )
                )
            ),
            CONSTRAINT {} CHECK (
                reason IN (
                    'max_retries_exceeded',
                    'permanent_error',
                    'operator_action',
                    'execution_expired'
                )
            )
        )
        "#,
        config.dead_letter_table_name.quoted(),
        JOB_ID_SIZE,
        JOB_ID_SIZE,
        dead_letter_numeric_constraint_identifier(config).quoted(),
        dead_letter_text_constraint_identifier(config).quoted(),
        MAX_QUEUE_TASK_NAME_BYTES,
        MAX_QUEUE_DEDUPE_KEY_BYTES,
        dead_letter_reason_constraint_identifier(config).quoted(),
    )
}

pub(in crate::db::queue) fn build_create_pause_table_statement(config: &StoreConfig) -> String {
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            key TEXT COLLATE "C" PRIMARY KEY,
            task_name TEXT COLLATE "C",
            paused_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT {} CHECK (
                (key = '{}' AND task_name IS NULL)
                OR
                (task_name IS NOT NULL AND key = 'task:' || task_name)
            ),
            CONSTRAINT {} CHECK (
                task_name IS NULL
                OR (
                    task_name IS NOT NULL
                    AND task_name ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                    AND octet_length(task_name) <= {}
                )
            )
        )
        "#,
        config.pause_table_name.quoted(),
        pause_key_task_constraint_identifier(config).quoted(),
        GLOBAL_PAUSE_KEY,
        pause_text_constraint_identifier(config).quoted(),
        MAX_QUEUE_TASK_NAME_BYTES,
    )
}

pub(in crate::db::queue) fn build_create_index_statement(
    table_name: &PgQualifiedTableName,
    index_name: &PgIdentifier,
    columns: &str,
    where_clause: Option<&str>,
    unique: bool,
) -> String {
    let unique_keyword = if unique { "UNIQUE " } else { "" };
    let where_sql = where_clause
        .map(|clause| format!(" WHERE {clause}"))
        .unwrap_or_default();
    format!(
        "CREATE {unique_keyword}INDEX IF NOT EXISTS {} ON {} ({columns}){where_sql}",
        index_name.quoted(),
        table_name.quoted(),
    )
}
