use super::*;

pub(in crate::db::queue) fn queue_job_projection() -> String {
    sql_projection(&[
        QueueColumn::Id.name().to_owned(),
        QueueColumn::TaskName.name().to_owned(),
        text_projection(QueueColumn::Payload, QueueProjectionField::PayloadJson),
        QueueColumn::Status.name().to_owned(),
        unix_microseconds_projection(
            QueueColumn::RunAtOrAfter,
            QueueProjectionField::RunAtOrAfterUnixMicroseconds,
        ),
        QueueColumn::LastError.name().to_owned(),
        QueueColumn::RetryCount.name().to_owned(),
        QueueColumn::MaxRetries.name().to_owned(),
        QueueColumn::TimeoutNanos.name().to_owned(),
        QueueColumn::DedupeKey.name().to_owned(),
        QueueColumn::WorkerId.name().to_owned(),
        unix_microseconds_projection(
            QueueColumn::ClaimedByWorkerAt,
            QueueProjectionField::ClaimedByWorkerAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::ExecutionStartedAt,
            QueueProjectionField::ExecutionStartedAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::ExecutionHeartbeatAt,
            QueueProjectionField::ExecutionHeartbeatAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::FinishedAt,
            QueueProjectionField::FinishedAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::CreatedAt,
            QueueProjectionField::CreatedAtUnixMicroseconds,
        ),
        unix_microseconds_projection(
            QueueColumn::UpdatedAt,
            QueueProjectionField::UpdatedAtUnixMicroseconds,
        ),
    ])
}

pub(in crate::db::queue) fn build_select_job_by_id_query(config: &StoreConfig) -> String {
    let id = QueueColumn::Id.name();
    format!(
        "SELECT {} FROM {} WHERE {id} = $1",
        queue_job_projection(),
        config.table_name.quoted()
    )
}

pub(in crate::db::queue) fn build_fetch_status_counts_query(config: &StoreConfig) -> String {
    let status = QueueColumn::Status.name();
    let task_name = QueueColumn::TaskName.name();
    let pending = JobStatus::Pending.as_str();
    let running = JobStatus::Running.as_str();
    let completed = JobStatus::Completed.as_str();
    let failed = JobStatus::Failed.as_str();
    let pending_count = QueueQueryField::PendingCount.name();
    let running_count = QueueQueryField::RunningCount.name();
    let completed_count = QueueQueryField::CompletedCount.name();
    let failed_count = QueueQueryField::FailedCount.name();
    let dead_letter_count = QueueQueryField::DeadLetterCount.name();
    format!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE j.{status} = '{pending}')::bigint AS {pending_count},
            COUNT(*) FILTER (WHERE j.{status} = '{running}')::bigint AS {running_count},
            COUNT(*) FILTER (WHERE j.{status} = '{completed}')::bigint AS {completed_count},
            COUNT(*) FILTER (WHERE j.{status} = '{failed}')::bigint AS {failed_count},
            (
                SELECT COUNT(*)::bigint
                FROM {} d
                WHERE ($1::text IS NULL OR d.{task_name} = $1)
            ) AS {dead_letter_count}
        FROM {} j
        WHERE ($1::text IS NULL OR j.{task_name} = $1)
        "#,
        config.dead_letter_table_name.quoted(),
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_job_count_by_status_query(config: &StoreConfig) -> String {
    let status = QueueColumn::Status.name();
    let task_name = QueueColumn::TaskName.name();
    format!(
        r#"
        SELECT COUNT(*)::bigint
        FROM {}
        WHERE {status} = $1
          AND ($2::text IS NULL OR {task_name} = $2)
        "#,
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_worker_pressure_counts_query(
    config: &StoreConfig,
) -> String {
    let status = QueueColumn::Status.name();
    let pending = JobStatus::Pending.as_str();
    let running = JobStatus::Running.as_str();
    let pending_job_count = QueueQueryField::PendingJobCount.name();
    let running_job_count = QueueQueryField::RunningJobCount.name();
    format!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE {status} = '{pending}')::bigint AS {pending_job_count},
            COUNT(*) FILTER (WHERE {status} = '{running}')::bigint AS {running_job_count}
        FROM {}
        "#,
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_pause_entries_query(config: &StoreConfig) -> String {
    let key = QueueColumn::Key.name();
    format!(
        r#"
        SELECT {key}
        FROM {}
        WHERE {key} = $1 OR {key} LIKE $2
        ORDER BY {key}
        "#,
        config.pause_table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_fetch_pending_or_running_task_names_query(
    config: &StoreConfig,
) -> String {
    let task_name = QueueColumn::TaskName.name();
    let status = QueueColumn::Status.name();
    format!(
        r#"
        SELECT DISTINCT {task_name}
        FROM {}
        WHERE {status} IN ($1, $2)
        ORDER BY {task_name}
        "#,
        config.table_name.quoted(),
    )
}

pub(in crate::db::queue) fn build_upsert_pause_key_query(config: &StoreConfig) -> String {
    let key = QueueColumn::Key.name();
    let task_name = QueueColumn::TaskName.name();
    let paused_at = QueueColumn::PausedAt.name();
    let updated_at = QueueColumn::UpdatedAt.name();
    format!(
        r#"
        INSERT INTO {} ({key}, {task_name}, {paused_at}, {updated_at})
        VALUES ($1, $2, statement_timestamp(), statement_timestamp())
        ON CONFLICT ({key}) DO UPDATE
        SET {task_name} = EXCLUDED.{task_name},
            {paused_at} = statement_timestamp(),
            {updated_at} = statement_timestamp()
        "#,
        config.pause_table_name.quoted()
    )
}

pub(in crate::db::queue) fn build_delete_pause_key_query(config: &StoreConfig) -> String {
    let key = QueueColumn::Key.name();
    format!(
        "DELETE FROM {} WHERE {key} = $1",
        config.pause_table_name.quoted()
    )
}

pub(in crate::db::queue) fn build_pause_key_exists_query(config: &StoreConfig) -> String {
    let key = QueueColumn::Key.name();
    format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE {key} = $1)",
        config.pause_table_name.quoted()
    )
}

pub(in crate::db::queue) fn sql_projection(expressions: &[String]) -> String {
    format!("\n        {}\n    ", expressions.join(",\n        "))
}

pub(in crate::db::queue) fn text_projection(
    column: QueueColumn,
    alias: QueueProjectionField,
) -> String {
    format!("{}::text AS {}", column.name(), alias.name())
}

pub(in crate::db::queue) fn unix_microseconds_projection(
    column: QueueColumn,
    alias: QueueProjectionField,
) -> String {
    format!(
        "((EXTRACT(EPOCH FROM {}) * 1000000)::bigint) AS {}",
        column.name(),
        alias.name()
    )
}
