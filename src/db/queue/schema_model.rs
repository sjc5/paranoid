#[derive(Clone, Copy)]
pub(in crate::db::queue) struct RequiredColumn {
    pub(in crate::db::queue) column: QueueColumn,
    pub(in crate::db::queue) is_nullable: bool,
}

#[derive(Clone, Debug)]
pub(in crate::db::queue) struct ActualColumn {
    pub(in crate::db::queue) name: String,
    pub(in crate::db::queue) data_type: String,
    pub(in crate::db::queue) is_nullable: bool,
    pub(in crate::db::queue) collation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) enum QueueTable {
    Jobs,
    DeadLetter,
    Pause,
}

impl QueueTable {
    pub(in crate::db::queue) fn table_name(
        self,
        config: &super::StoreConfig,
    ) -> &crate::db::PgQualifiedTableName {
        match self {
            Self::Jobs => &config.table_name,
            Self::DeadLetter => &config.dead_letter_table_name,
            Self::Pause => &config.pause_table_name,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) enum QueueColumn {
    Id,
    OriginalJobId,
    TaskName,
    Payload,
    Status,
    RunAtOrAfter,
    LastError,
    RetryCount,
    MaxRetries,
    TimeoutNanos,
    DedupeKey,
    WorkerId,
    ClaimedByWorkerAt,
    ExecutionStartedAt,
    ExecutionHeartbeatAt,
    FinishedAt,
    Reason,
    DeadLetteredAt,
    Key,
    PausedAt,
    CreatedAt,
    UpdatedAt,
}

impl QueueColumn {
    pub(in crate::db::queue) const fn name(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::OriginalJobId => "original_job_id",
            Self::TaskName => "task_name",
            Self::Payload => "payload",
            Self::Status => "status",
            Self::RunAtOrAfter => "run_at_or_after",
            Self::LastError => "last_error",
            Self::RetryCount => "retry_count",
            Self::MaxRetries => "max_retries",
            Self::TimeoutNanos => "timeout_nanos",
            Self::DedupeKey => "dedupe_key",
            Self::WorkerId => "worker_id",
            Self::ClaimedByWorkerAt => "claimed_by_worker_at",
            Self::ExecutionStartedAt => "execution_started_at",
            Self::ExecutionHeartbeatAt => "execution_heartbeat_at",
            Self::FinishedAt => "finished_at",
            Self::Reason => "reason",
            Self::DeadLetteredAt => "dead_lettered_at",
            Self::Key => "key",
            Self::PausedAt => "paused_at",
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
        }
    }

    pub(in crate::db::queue) const fn create_table_type(self) -> &'static str {
        match self {
            Self::Id | Self::OriginalJobId => "BYTEA",
            Self::TaskName
            | Self::Status
            | Self::LastError
            | Self::DedupeKey
            | Self::WorkerId
            | Self::Reason
            | Self::Key => "TEXT",
            Self::Payload => "JSONB",
            Self::RetryCount | Self::MaxRetries => "INT",
            Self::TimeoutNanos => "BIGINT",
            Self::RunAtOrAfter
            | Self::ClaimedByWorkerAt
            | Self::ExecutionStartedAt
            | Self::ExecutionHeartbeatAt
            | Self::FinishedAt
            | Self::DeadLetteredAt
            | Self::PausedAt
            | Self::CreatedAt
            | Self::UpdatedAt => "TIMESTAMPTZ",
        }
    }

    pub(in crate::db::queue) const fn validation_type(self) -> &'static str {
        match self {
            Self::Id | Self::OriginalJobId => "bytea",
            Self::TaskName
            | Self::Status
            | Self::LastError
            | Self::DedupeKey
            | Self::WorkerId
            | Self::Reason
            | Self::Key => "text",
            Self::Payload => "jsonb",
            Self::RetryCount | Self::MaxRetries => "integer",
            Self::TimeoutNanos => "bigint",
            Self::RunAtOrAfter
            | Self::ClaimedByWorkerAt
            | Self::ExecutionStartedAt
            | Self::ExecutionHeartbeatAt
            | Self::FinishedAt
            | Self::DeadLetteredAt
            | Self::PausedAt
            | Self::CreatedAt
            | Self::UpdatedAt => "timestamp with time zone",
        }
    }

    pub(in crate::db::queue) const fn requires_bytewise_collation(self) -> bool {
        matches!(
            self,
            Self::TaskName
                | Self::Status
                | Self::LastError
                | Self::DedupeKey
                | Self::WorkerId
                | Self::Reason
                | Self::Key
        )
    }

    pub(in crate::db::queue) fn list(columns: &[Self]) -> String {
        columns
            .iter()
            .map(|column| column.name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) enum QueueProjectionField {
    PayloadJson,
    RunAtOrAfterUnixMicroseconds,
    ClaimedByWorkerAtUnixMicroseconds,
    ExecutionStartedAtUnixMicroseconds,
    ExecutionHeartbeatAtUnixMicroseconds,
    FinishedAtUnixMicroseconds,
    DeadLetteredAtUnixMicroseconds,
    CreatedAtUnixMicroseconds,
    UpdatedAtUnixMicroseconds,
}

impl QueueProjectionField {
    pub(in crate::db::queue) const fn name(self) -> &'static str {
        match self {
            Self::PayloadJson => "payload_json",
            Self::RunAtOrAfterUnixMicroseconds => "run_at_or_after_us",
            Self::ClaimedByWorkerAtUnixMicroseconds => "claimed_by_worker_at_us",
            Self::ExecutionStartedAtUnixMicroseconds => "execution_started_at_us",
            Self::ExecutionHeartbeatAtUnixMicroseconds => "execution_heartbeat_at_us",
            Self::FinishedAtUnixMicroseconds => "finished_at_us",
            Self::DeadLetteredAtUnixMicroseconds => "dead_lettered_at_us",
            Self::CreatedAtUnixMicroseconds => "created_at_us",
            Self::UpdatedAtUnixMicroseconds => "updated_at_us",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) enum QueueQueryField {
    InsertedId,
    InsertedCount,
    InsertOutcome,
    ExistingId,
    SourceExists,
    VisibleExists,
    DedupeConflictExists,
    DeletedSource,
    TargetExists,
    TargetMatchesStatus,
    VisibleMatchesStatus,
    PendingCount,
    RunningCount,
    CompletedCount,
    FailedCount,
    DeadLetterCount,
    PendingJobCount,
    RunningJobCount,
    Outcome,
    NextRunAt,
}

impl QueueQueryField {
    pub(in crate::db::queue) const fn name(self) -> &'static str {
        match self {
            Self::InsertedId => "inserted_id",
            Self::InsertedCount => "inserted_count",
            Self::InsertOutcome => "insert_outcome",
            Self::ExistingId => "existing_id",
            Self::SourceExists => "source_exists",
            Self::VisibleExists => "visible_exists",
            Self::DedupeConflictExists => "dedupe_conflict_exists",
            Self::DeletedSource => "deleted_source",
            Self::TargetExists => "target_exists",
            Self::TargetMatchesStatus => "target_matches_status",
            Self::VisibleMatchesStatus => "visible_matches_status",
            Self::PendingCount => "pending_count",
            Self::RunningCount => "running_count",
            Self::CompletedCount => "completed_count",
            Self::FailedCount => "failed_count",
            Self::DeadLetterCount => "dead_letter_count",
            Self::PendingJobCount => "pending_job_count",
            Self::RunningJobCount => "running_job_count",
            Self::Outcome => "outcome",
            Self::NextRunAt => "next_run_at",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) struct QueueIndexDefinition {
    pub(in crate::db::queue) table: QueueTable,
    pub(in crate::db::queue) kind: &'static str,
    pub(in crate::db::queue) suffix: &'static str,
    pub(in crate::db::queue) columns: &'static [QueueColumn],
    pub(in crate::db::queue) predicate: QueueIndexPredicate,
    pub(in crate::db::queue) unique: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::db::queue) enum QueueIndexPredicate {
    None,
    PendingStatus,
    WorkerIdPresent,
    RunningExecutionHeartbeatPresent,
    TerminalFinishedAtPresent,
    ActiveDedupe,
    PauseTaskNamePresent,
}

impl QueueIndexPredicate {
    pub(in crate::db::queue) fn sql(self) -> Option<String> {
        match self {
            Self::None => None,
            Self::PendingStatus => Some(format!(
                "{} = '{}'",
                QueueColumn::Status.name(),
                super::JobStatus::Pending.as_str()
            )),
            Self::WorkerIdPresent => Some(format!("{} IS NOT NULL", QueueColumn::WorkerId.name())),
            Self::RunningExecutionHeartbeatPresent => Some(format!(
                "{} = '{}' AND {} IS NOT NULL",
                QueueColumn::Status.name(),
                super::JobStatus::Running.as_str(),
                QueueColumn::ExecutionHeartbeatAt.name()
            )),
            Self::TerminalFinishedAtPresent => Some(format!(
                "{} IN ('{}', '{}') AND {} IS NOT NULL",
                QueueColumn::Status.name(),
                super::JobStatus::Completed.as_str(),
                super::JobStatus::Failed.as_str(),
                QueueColumn::FinishedAt.name()
            )),
            Self::ActiveDedupe => Some(format!(
                "{} IS NOT NULL AND {} IN ('{}', '{}')",
                QueueColumn::DedupeKey.name(),
                QueueColumn::Status.name(),
                super::JobStatus::Pending.as_str(),
                super::JobStatus::Running.as_str()
            )),
            Self::PauseTaskNamePresent => {
                Some(format!("{} IS NOT NULL", QueueColumn::TaskName.name()))
            }
        }
    }

    pub(in crate::db::queue) fn fragments_after_normalization(self) -> Vec<String> {
        match self {
            Self::None => Vec::new(),
            Self::PendingStatus => vec![format!(
                "{}='{}'",
                QueueColumn::Status.name(),
                super::JobStatus::Pending.as_str()
            )],
            Self::WorkerIdPresent => {
                vec![format!("{}isnotnull", QueueColumn::WorkerId.name())]
            }
            Self::RunningExecutionHeartbeatPresent => vec![
                format!(
                    "{}='{}'",
                    QueueColumn::Status.name(),
                    super::JobStatus::Running.as_str()
                ),
                format!("{}isnotnull", QueueColumn::ExecutionHeartbeatAt.name()),
            ],
            Self::TerminalFinishedAtPresent => vec![
                QueueColumn::Status.name().to_owned(),
                format!("'{}'", super::JobStatus::Completed.as_str()),
                format!("'{}'", super::JobStatus::Failed.as_str()),
                format!("{}isnotnull", QueueColumn::FinishedAt.name()),
            ],
            Self::ActiveDedupe => vec![
                format!("{}isnotnull", QueueColumn::DedupeKey.name()),
                QueueColumn::Status.name().to_owned(),
                format!("'{}'", super::JobStatus::Pending.as_str()),
                format!("'{}'", super::JobStatus::Running.as_str()),
            ],
            Self::PauseTaskNamePresent => {
                vec![format!("{}isnotnull", QueueColumn::TaskName.name())]
            }
        }
    }
}
