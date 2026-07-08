use super::*;

pub(in crate::db::queue) fn required_job_columns() -> [RequiredColumn; 17] {
    [
        required_column(QueueColumn::Id, false),
        required_column(QueueColumn::TaskName, false),
        required_column(QueueColumn::Payload, false),
        required_column(QueueColumn::Status, false),
        required_column(QueueColumn::RunAtOrAfter, false),
        required_column(QueueColumn::LastError, true),
        required_column(QueueColumn::RetryCount, false),
        required_column(QueueColumn::MaxRetries, false),
        required_column(QueueColumn::TimeoutNanos, false),
        required_column(QueueColumn::DedupeKey, true),
        required_column(QueueColumn::WorkerId, true),
        required_column(QueueColumn::ClaimedByWorkerAt, true),
        required_column(QueueColumn::ExecutionStartedAt, true),
        required_column(QueueColumn::ExecutionHeartbeatAt, true),
        required_column(QueueColumn::FinishedAt, true),
        required_column(QueueColumn::CreatedAt, false),
        required_column(QueueColumn::UpdatedAt, false),
    ]
}

pub(in crate::db::queue) fn required_dead_letter_columns() -> [RequiredColumn; 13] {
    [
        required_column(QueueColumn::Id, false),
        required_column(QueueColumn::OriginalJobId, false),
        required_column(QueueColumn::TaskName, false),
        required_column(QueueColumn::Payload, false),
        required_column(QueueColumn::LastError, false),
        required_column(QueueColumn::RetryCount, false),
        required_column(QueueColumn::MaxRetries, false),
        required_column(QueueColumn::TimeoutNanos, false),
        required_column(QueueColumn::DedupeKey, true),
        required_column(QueueColumn::Reason, false),
        required_column(QueueColumn::DeadLetteredAt, false),
        required_column(QueueColumn::CreatedAt, false),
        required_column(QueueColumn::UpdatedAt, false),
    ]
}

pub(in crate::db::queue) fn required_pause_columns() -> [RequiredColumn; 4] {
    [
        required_column(QueueColumn::Key, false),
        required_column(QueueColumn::TaskName, true),
        required_column(QueueColumn::PausedAt, false),
        required_column(QueueColumn::UpdatedAt, false),
    ]
}

fn required_column(column: QueueColumn, is_nullable: bool) -> RequiredColumn {
    RequiredColumn {
        is_nullable,
        column,
    }
}
