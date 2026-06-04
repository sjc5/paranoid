use super::*;

const DEAD_LETTER_INSERT_COLUMNS: [QueueColumn; 13] = [
    QueueColumn::Id,
    QueueColumn::OriginalJobId,
    QueueColumn::TaskName,
    QueueColumn::Payload,
    QueueColumn::LastError,
    QueueColumn::RetryCount,
    QueueColumn::MaxRetries,
    QueueColumn::TimeoutNanos,
    QueueColumn::DedupeKey,
    QueueColumn::Reason,
    QueueColumn::DeadLetteredAt,
    QueueColumn::CreatedAt,
    QueueColumn::UpdatedAt,
];

const ENQUEUE_WITHOUT_DEDUPE_INSERT_COLUMNS: [QueueColumn; 9] = [
    QueueColumn::Id,
    QueueColumn::TaskName,
    QueueColumn::Payload,
    QueueColumn::Status,
    QueueColumn::RunAtOrAfter,
    QueueColumn::MaxRetries,
    QueueColumn::TimeoutNanos,
    QueueColumn::CreatedAt,
    QueueColumn::UpdatedAt,
];

const ENQUEUE_WITH_DEDUPE_INSERT_COLUMNS: [QueueColumn; 10] = [
    QueueColumn::Id,
    QueueColumn::TaskName,
    QueueColumn::Payload,
    QueueColumn::Status,
    QueueColumn::RunAtOrAfter,
    QueueColumn::MaxRetries,
    QueueColumn::TimeoutNanos,
    QueueColumn::CreatedAt,
    QueueColumn::UpdatedAt,
    QueueColumn::DedupeKey,
];

const DEAD_LETTER_REQUEUE_INSERT_COLUMNS: [QueueColumn; 11] = [
    QueueColumn::Id,
    QueueColumn::TaskName,
    QueueColumn::Payload,
    QueueColumn::Status,
    QueueColumn::RunAtOrAfter,
    QueueColumn::RetryCount,
    QueueColumn::MaxRetries,
    QueueColumn::TimeoutNanos,
    QueueColumn::DedupeKey,
    QueueColumn::CreatedAt,
    QueueColumn::UpdatedAt,
];

pub(in crate::db::queue) fn qualified_queue_column(alias: &str, column: QueueColumn) -> String {
    format!("{alias}.{}", column.name())
}

pub(in crate::db::queue) fn queue_column_assignment(
    column: QueueColumn,
    expression: &str,
) -> String {
    format!("{} = {expression}", column.name())
}

pub(in crate::db::queue) fn sql_assignments(assignments: &[String]) -> String {
    assignments.join(",\n                ")
}

pub(in crate::db::queue) fn clear_worker_runtime_assignments(
    finished_at_expression: &str,
) -> String {
    sql_assignments(&clear_worker_runtime_assignment_parts(
        finished_at_expression,
    ))
}

pub(in crate::db::queue) fn return_to_pending_assignments(status_expression: &str) -> String {
    let mut assignments = vec![queue_column_assignment(
        QueueColumn::Status,
        status_expression,
    )];
    assignments.extend(clear_worker_runtime_assignment_parts("NULL"));
    assignments.push(queue_column_assignment(
        QueueColumn::UpdatedAt,
        "statement_timestamp()",
    ));
    sql_assignments(&assignments)
}

pub(in crate::db::queue) fn retry_failed_job_assignments(
    status_expression: &str,
    run_at_or_after_expression: &str,
) -> String {
    let mut assignments = vec![
        queue_column_assignment(QueueColumn::Status, status_expression),
        queue_column_assignment(QueueColumn::RetryCount, "0"),
        queue_column_assignment(QueueColumn::LastError, "NULL"),
        queue_column_assignment(QueueColumn::RunAtOrAfter, run_at_or_after_expression),
    ];
    assignments.extend(clear_worker_runtime_assignment_parts("NULL"));
    assignments.push(queue_column_assignment(
        QueueColumn::UpdatedAt,
        "statement_timestamp()",
    ));
    sql_assignments(&assignments)
}

fn clear_worker_runtime_assignment_parts(finished_at_expression: &str) -> Vec<String> {
    vec![
        queue_column_assignment(QueueColumn::WorkerId, "NULL"),
        queue_column_assignment(QueueColumn::ClaimedByWorkerAt, "NULL"),
        queue_column_assignment(QueueColumn::ExecutionStartedAt, "NULL"),
        queue_column_assignment(QueueColumn::ExecutionHeartbeatAt, "NULL"),
        queue_column_assignment(QueueColumn::FinishedAt, finished_at_expression),
    ]
}

pub(in crate::db::queue) fn active_dedupe_match_predicate(
    active_alias: &str,
    source_alias: &str,
) -> String {
    let active_task_name = qualified_queue_column(active_alias, QueueColumn::TaskName);
    let source_task_name = qualified_queue_column(source_alias, QueueColumn::TaskName);
    let active_dedupe_key = qualified_queue_column(active_alias, QueueColumn::DedupeKey);
    let source_dedupe_key = qualified_queue_column(source_alias, QueueColumn::DedupeKey);
    let active_status = qualified_queue_column(active_alias, QueueColumn::Status);
    format!(
        "{active_task_name} = {source_task_name}
                        AND {active_dedupe_key} = {source_dedupe_key}
                        AND {active_status} IN ('{}', '{}')",
        JobStatus::Pending.as_str(),
        JobStatus::Running.as_str()
    )
}

pub(in crate::db::queue) fn dead_letter_insert_columns_sql() -> String {
    QueueColumn::list(&DEAD_LETTER_INSERT_COLUMNS)
}

pub(in crate::db::queue) fn enqueue_without_dedupe_insert_columns_sql() -> String {
    QueueColumn::list(&ENQUEUE_WITHOUT_DEDUPE_INSERT_COLUMNS)
}

pub(in crate::db::queue) fn enqueue_with_dedupe_insert_columns_sql() -> String {
    QueueColumn::list(&ENQUEUE_WITH_DEDUPE_INSERT_COLUMNS)
}

pub(in crate::db::queue) fn dead_letter_requeue_insert_columns_sql() -> String {
    QueueColumn::list(&DEAD_LETTER_REQUEUE_INSERT_COLUMNS)
}
