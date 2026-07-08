use super::*;

const PENDING_RUN_AT_INDEX_COLUMNS: [QueueColumn; 3] = [
    QueueColumn::Status,
    QueueColumn::RunAtOrAfter,
    QueueColumn::Id,
];
const PENDING_TASK_RUN_AT_INDEX_COLUMNS: [QueueColumn; 3] = [
    QueueColumn::TaskName,
    QueueColumn::RunAtOrAfter,
    QueueColumn::Id,
];
const TASK_STATUS_INDEX_COLUMNS: [QueueColumn; 2] = [QueueColumn::TaskName, QueueColumn::Status];
const WORKER_INDEX_COLUMNS: [QueueColumn; 1] = [QueueColumn::WorkerId];
const EXECUTION_HEARTBEAT_INDEX_COLUMNS: [QueueColumn; 3] = [
    QueueColumn::Status,
    QueueColumn::ExecutionHeartbeatAt,
    QueueColumn::Id,
];
const CLEANUP_INDEX_COLUMNS: [QueueColumn; 2] = [QueueColumn::FinishedAt, QueueColumn::Id];
const ACTIVE_DEDUPE_INDEX_COLUMNS: [QueueColumn; 2] =
    [QueueColumn::TaskName, QueueColumn::DedupeKey];
const DEAD_LETTERED_AT_INDEX_COLUMNS: [QueueColumn; 2] =
    [QueueColumn::DeadLetteredAt, QueueColumn::Id];
const TASK_DEAD_LETTERED_AT_INDEX_COLUMNS: [QueueColumn; 3] = [
    QueueColumn::TaskName,
    QueueColumn::DeadLetteredAt,
    QueueColumn::Id,
];
const ORIGINAL_JOB_INDEX_COLUMNS: [QueueColumn; 1] = [QueueColumn::OriginalJobId];
const PAUSE_TASK_INDEX_COLUMNS: [QueueColumn; 1] = [QueueColumn::TaskName];

pub(in crate::db::queue) fn build_queue_schema_migration_statements(
    config: &StoreConfig,
) -> Vec<String> {
    let mut statements = vec![
        build_create_jobs_table_statement(config),
        build_create_dead_letter_table_statement(config),
        build_create_pause_table_statement(config),
    ];
    statements.extend(
        queue_schema_index_definitions()
            .into_iter()
            .map(|index| build_create_index_statement(config, index)),
    );
    statements
}

pub(in crate::db::queue) fn queue_schema_index_definitions() -> [QueueIndexDefinition; 11] {
    [
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: INDEX_KIND,
            suffix: PENDING_RUN_AT_INDEX_SUFFIX,
            columns: &PENDING_RUN_AT_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::PendingStatus,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: INDEX_KIND,
            suffix: PENDING_TASK_RUN_AT_INDEX_SUFFIX,
            columns: &PENDING_TASK_RUN_AT_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::PendingStatus,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: INDEX_KIND,
            suffix: TASK_STATUS_INDEX_SUFFIX,
            columns: &TASK_STATUS_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::None,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: INDEX_KIND,
            suffix: WORKER_INDEX_SUFFIX,
            columns: &WORKER_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::WorkerIdPresent,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: INDEX_KIND,
            suffix: EXECUTION_HEARTBEAT_INDEX_SUFFIX,
            columns: &EXECUTION_HEARTBEAT_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::RunningExecutionHeartbeatPresent,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: INDEX_KIND,
            suffix: CLEANUP_INDEX_SUFFIX,
            columns: &CLEANUP_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::TerminalFinishedAtPresent,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::Jobs,
            kind: UNIQUE_INDEX_KIND,
            suffix: ACTIVE_DEDUPE_INDEX_SUFFIX,
            columns: &ACTIVE_DEDUPE_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::ActiveDedupe,
            unique: true,
        },
        QueueIndexDefinition {
            table: QueueTable::DeadLetter,
            kind: INDEX_KIND,
            suffix: DEAD_LETTERED_AT_INDEX_SUFFIX,
            columns: &DEAD_LETTERED_AT_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::None,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::DeadLetter,
            kind: INDEX_KIND,
            suffix: TASK_DEAD_LETTERED_AT_INDEX_SUFFIX,
            columns: &TASK_DEAD_LETTERED_AT_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::None,
            unique: false,
        },
        QueueIndexDefinition {
            table: QueueTable::DeadLetter,
            kind: UNIQUE_INDEX_KIND,
            suffix: ORIGINAL_JOB_INDEX_SUFFIX,
            columns: &ORIGINAL_JOB_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::None,
            unique: true,
        },
        QueueIndexDefinition {
            table: QueueTable::Pause,
            kind: INDEX_KIND,
            suffix: PAUSE_TASK_INDEX_SUFFIX,
            columns: &PAUSE_TASK_INDEX_COLUMNS,
            predicate: QueueIndexPredicate::PauseTaskNamePresent,
            unique: false,
        },
    ]
}

pub(in crate::db::queue) fn active_dedupe_index_definition() -> QueueIndexDefinition {
    queue_schema_index_definitions()
        .into_iter()
        .find(|definition| definition.predicate == QueueIndexPredicate::ActiveDedupe)
        .expect("queue schema must define active-dedupe arbiter index")
}

pub(in crate::db::queue) fn active_dedupe_conflict_columns_sql() -> String {
    QueueColumn::list(active_dedupe_index_definition().columns)
}

pub(in crate::db::queue) fn active_dedupe_conflict_predicate_sql() -> String {
    active_dedupe_index_definition()
        .predicate
        .sql()
        .expect("active-dedupe index must have predicate")
}

pub(in crate::db::queue) fn build_create_jobs_table_statement(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    let task_name = QueueColumn::TaskName.name();
    let payload = QueueColumn::Payload.name();
    let status = QueueColumn::Status.name();
    let run_at_or_after = QueueColumn::RunAtOrAfter.name();
    let last_error = QueueColumn::LastError.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let timeout_nanos = QueueColumn::TimeoutNanos.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let worker_id = QueueColumn::WorkerId.name();
    let claimed_by_worker_at = QueueColumn::ClaimedByWorkerAt.name();
    let execution_started_at = QueueColumn::ExecutionStartedAt.name();
    let execution_heartbeat_at = QueueColumn::ExecutionHeartbeatAt.name();
    let finished_at = QueueColumn::FinishedAt.name();
    let created_at = QueueColumn::CreatedAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    let pending = JobStatus::Pending.as_str();
    let running = JobStatus::Running.as_str();
    let completed = JobStatus::Completed.as_str();
    let failed = JobStatus::Failed.as_str();
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            {id} {id_type} PRIMARY KEY CHECK (octet_length({id}) = {}),
            {task_name} {task_name_type} NOT NULL,
            {payload} {payload_type} NOT NULL,
            {status} {status_type} NOT NULL,
            {run_at_or_after} {run_at_or_after_type} NOT NULL,
            {last_error} {last_error_type},
            {retry_count} {retry_count_type} NOT NULL DEFAULT 0,
            {max_retries} {max_retries_type} NOT NULL DEFAULT 5,
            {timeout_nanos} {timeout_nanos_type} NOT NULL DEFAULT 0,
            {dedupe_key} {dedupe_key_type},
            {worker_id} {worker_id_type},
            {claimed_by_worker_at} {claimed_by_worker_at_type},
            {execution_started_at} {execution_started_at_type},
            {execution_heartbeat_at} {execution_heartbeat_at_type},
            {finished_at} {finished_at_type},
            CONSTRAINT {} CHECK ({status} IN ('{pending}', '{running}', '{completed}', '{failed}')),
            CONSTRAINT {} CHECK (
                {retry_count} >= 0
                AND {max_retries} >= 0
                AND {timeout_nanos} >= -1
            ),
            CONSTRAINT {} CHECK (
                {task_name} ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length({task_name}) <= {}
                AND (
                    {dedupe_key} IS NULL
                    OR (
                        {dedupe_key} <> ''
                        AND octet_length({dedupe_key}) <= {}
                    )
                )
                AND (
                    {worker_id} IS NULL
                    OR (
                        {worker_id} <> ''
                        AND octet_length({worker_id}) <= {}
                    )
                )
            ),
            CONSTRAINT {} CHECK (
                (
                    {status} = '{pending}'
                    AND {worker_id} IS NULL
                    AND {claimed_by_worker_at} IS NULL
                    AND {execution_started_at} IS NULL
                    AND {execution_heartbeat_at} IS NULL
                    AND {finished_at} IS NULL
                )
                OR
                (
                    {status} = '{running}'
                    AND {worker_id} IS NOT NULL
                    AND {claimed_by_worker_at} IS NOT NULL
                    AND {execution_heartbeat_at} IS NOT NULL
                    AND {finished_at} IS NULL
                )
                OR
                (
                    {status} IN ('{completed}', '{failed}')
                    AND {worker_id} IS NULL
                    AND {claimed_by_worker_at} IS NULL
                    AND {execution_started_at} IS NULL
                    AND {execution_heartbeat_at} IS NULL
                    AND {finished_at} IS NOT NULL
                )
            ),
            {created_at} {created_at_type} NOT NULL,
            {updated_at} {updated_at_type} NOT NULL
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
        id_type = column_type_sql(QueueColumn::Id),
        task_name_type = column_type_sql(QueueColumn::TaskName),
        payload_type = column_type_sql(QueueColumn::Payload),
        status_type = column_type_sql(QueueColumn::Status),
        run_at_or_after_type = column_type_sql(QueueColumn::RunAtOrAfter),
        last_error_type = column_type_sql(QueueColumn::LastError),
        retry_count_type = column_type_sql(QueueColumn::RetryCount),
        max_retries_type = column_type_sql(QueueColumn::MaxRetries),
        timeout_nanos_type = column_type_sql(QueueColumn::TimeoutNanos),
        dedupe_key_type = column_type_sql(QueueColumn::DedupeKey),
        worker_id_type = column_type_sql(QueueColumn::WorkerId),
        claimed_by_worker_at_type = column_type_sql(QueueColumn::ClaimedByWorkerAt),
        execution_started_at_type = column_type_sql(QueueColumn::ExecutionStartedAt),
        execution_heartbeat_at_type = column_type_sql(QueueColumn::ExecutionHeartbeatAt),
        finished_at_type = column_type_sql(QueueColumn::FinishedAt),
        created_at_type = column_type_sql(QueueColumn::CreatedAt),
        updated_at_type = column_type_sql(QueueColumn::UpdatedAt),
    )
}

pub(in crate::db::queue) fn build_create_dead_letter_table_statement(
    config: &StoreConfig,
) -> String {
    let id = QueueColumn::Id.name();
    let original_job_id = QueueColumn::OriginalJobId.name();
    let task_name = QueueColumn::TaskName.name();
    let payload = QueueColumn::Payload.name();
    let last_error = QueueColumn::LastError.name();
    let retry_count = QueueColumn::RetryCount.name();
    let max_retries = QueueColumn::MaxRetries.name();
    let timeout_nanos = QueueColumn::TimeoutNanos.name();
    let dedupe_key = QueueColumn::DedupeKey.name();
    let reason = QueueColumn::Reason.name();
    let dead_lettered_at = QueueColumn::DeadLetteredAt.name();
    let created_at = QueueColumn::CreatedAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            {id} {id_type} PRIMARY KEY CHECK (octet_length({id}) = {}),
            {original_job_id} {original_job_id_type} NOT NULL CHECK (octet_length({original_job_id}) = {}),
            {task_name} {task_name_type} NOT NULL,
            {payload} {payload_type} NOT NULL,
            {last_error} {last_error_type} NOT NULL,
            {retry_count} {retry_count_type} NOT NULL,
            {max_retries} {max_retries_type} NOT NULL,
            {timeout_nanos} {timeout_nanos_type} NOT NULL DEFAULT 0,
            {dedupe_key} {dedupe_key_type},
            {reason} {reason_type} NOT NULL,
            {dead_lettered_at} {dead_lettered_at_type} NOT NULL,
            {created_at} {created_at_type} NOT NULL,
            {updated_at} {updated_at_type} NOT NULL,
            CONSTRAINT {} CHECK (
                {retry_count} >= 0
                AND {max_retries} >= 0
                AND {timeout_nanos} >= -1
            ),
            CONSTRAINT {} CHECK (
                {task_name} ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                AND octet_length({task_name}) <= {}
                AND (
                    {dedupe_key} IS NULL
                    OR (
                        {dedupe_key} <> ''
                        AND octet_length({dedupe_key}) <= {}
                    )
                )
            ),
            CONSTRAINT {} CHECK (
                {reason} IN (
                    '{max_retries_exceeded}',
                    '{permanent_error}',
                    '{operator_action}',
                    '{execution_expired}'
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
        id_type = column_type_sql(QueueColumn::Id),
        original_job_id_type = column_type_sql(QueueColumn::OriginalJobId),
        task_name_type = column_type_sql(QueueColumn::TaskName),
        payload_type = column_type_sql(QueueColumn::Payload),
        last_error_type = column_type_sql(QueueColumn::LastError),
        retry_count_type = column_type_sql(QueueColumn::RetryCount),
        max_retries_type = column_type_sql(QueueColumn::MaxRetries),
        timeout_nanos_type = column_type_sql(QueueColumn::TimeoutNanos),
        dedupe_key_type = column_type_sql(QueueColumn::DedupeKey),
        reason_type = column_type_sql(QueueColumn::Reason),
        dead_lettered_at_type = column_type_sql(QueueColumn::DeadLetteredAt),
        created_at_type = column_type_sql(QueueColumn::CreatedAt),
        updated_at_type = column_type_sql(QueueColumn::UpdatedAt),
        max_retries_exceeded = DeadLetterReason::MaxRetriesExceeded.as_str(),
        permanent_error = DeadLetterReason::PermanentError.as_str(),
        operator_action = DeadLetterReason::OperatorAction.as_str(),
        execution_expired = DeadLetterReason::ExecutionExpired.as_str(),
    )
}

pub(in crate::db::queue) fn build_create_pause_table_statement(config: &StoreConfig) -> String {
    let key = QueueColumn::Key.name();
    let task_name = QueueColumn::TaskName.name();
    let paused_at = QueueColumn::PausedAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            {key} {key_type} PRIMARY KEY,
            {task_name} {task_name_type},
            {paused_at} {paused_at_type} NOT NULL,
            {updated_at} {updated_at_type} NOT NULL,
            CONSTRAINT {} CHECK (
                ({key} = '{}' AND {task_name} IS NULL)
                OR
                ({task_name} IS NOT NULL AND {key} = 'task:' || {task_name})
            ),
            CONSTRAINT {} CHECK (
                {task_name} IS NULL
                OR (
                    {task_name} IS NOT NULL
                    AND {task_name} ~ '^[A-Za-z0-9_][A-Za-z0-9_.-]*$'
                    AND octet_length({task_name}) <= {}
                )
            )
        )
        "#,
        config.pause_table_name.quoted(),
        pause_key_task_constraint_identifier(config).quoted(),
        GLOBAL_PAUSE_KEY,
        pause_text_constraint_identifier(config).quoted(),
        MAX_QUEUE_TASK_NAME_BYTES,
        key_type = column_type_sql(QueueColumn::Key),
        task_name_type = column_type_sql(QueueColumn::TaskName),
        paused_at_type = column_type_sql(QueueColumn::PausedAt),
        updated_at_type = column_type_sql(QueueColumn::UpdatedAt),
    )
}

fn column_type_sql(column: QueueColumn) -> String {
    let storage_type = column.create_table_type();
    if column.requires_bytewise_collation() {
        format!(r#"{storage_type} COLLATE "C""#)
    } else {
        storage_type.to_owned()
    }
}

pub(in crate::db::queue) fn build_create_index_statement(
    config: &StoreConfig,
    index: QueueIndexDefinition,
) -> String {
    let table_name = index.table.table_name(config);
    let index_name = migration_index_identifier(index.kind, table_name, index.suffix);
    let columns = QueueColumn::list(index.columns);
    let unique_keyword = if index.unique { "UNIQUE " } else { "" };
    let where_sql = index
        .predicate
        .sql()
        .map(|clause| format!(" WHERE {clause}"))
        .unwrap_or_default();
    format!(
        "CREATE {unique_keyword}INDEX IF NOT EXISTS {} ON {} ({columns}){where_sql}",
        index_name.quoted(),
        table_name.quoted(),
    )
}
