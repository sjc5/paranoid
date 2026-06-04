use super::*;

pub(super) fn queue_job_from_row(row: &sqlx::postgres::PgRow) -> Result<Job, Error> {
    let id_bytes: Vec<u8> = row
        .try_get(QueueColumn::Id.name())
        .map_err(Error::decode_row)?;
    let status_text: String = row
        .try_get(QueueColumn::Status.name())
        .map_err(Error::decode_row)?;
    Ok(Job {
        id: JobId::from_bytes(&id_bytes)?,
        task_name: row
            .try_get(QueueColumn::TaskName.name())
            .map_err(Error::decode_row)?,
        payload_json: row
            .try_get(QueueProjectionField::PayloadJson.name())
            .map_err(Error::decode_row)?,
        status: JobStatus::parse(&status_text)?,
        run_at_or_after_unix_microseconds: row
            .try_get(QueueProjectionField::RunAtOrAfterUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        last_error: row
            .try_get(QueueColumn::LastError.name())
            .map_err(Error::decode_row)?,
        retry_count: retry_count_from_persisted_i32(
            row.try_get(QueueColumn::RetryCount.name())
                .map_err(Error::decode_row)?,
        )?,
        max_retries: max_retries_from_persisted_i32(
            row.try_get(QueueColumn::MaxRetries.name())
                .map_err(Error::decode_row)?,
        )?,
        timeout: timeout_from_persisted_nanos(
            row.try_get(QueueColumn::TimeoutNanos.name())
                .map_err(Error::decode_row)?,
        )?,
        dedupe_key: row
            .try_get(QueueColumn::DedupeKey.name())
            .map_err(Error::decode_row)?,
        worker_owner_id: row
            .try_get::<Option<String>, _>(QueueColumn::WorkerId.name())
            .map_err(Error::decode_row)?
            .map(WorkerOwnerId::from_validated_text)
            .transpose()?,
        claimed_by_worker_at_unix_microseconds: row
            .try_get(QueueProjectionField::ClaimedByWorkerAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        execution_started_at_unix_microseconds: row
            .try_get(QueueProjectionField::ExecutionStartedAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        execution_heartbeat_at_unix_microseconds: row
            .try_get(QueueProjectionField::ExecutionHeartbeatAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        finished_at_unix_microseconds: row
            .try_get(QueueProjectionField::FinishedAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        created_at_unix_microseconds: row
            .try_get(QueueProjectionField::CreatedAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        updated_at_unix_microseconds: row
            .try_get(QueueProjectionField::UpdatedAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
    })
}

pub(super) fn queue_dead_letter_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<DeadLetterJob, Error> {
    let id_bytes: Vec<u8> = row
        .try_get(QueueColumn::Id.name())
        .map_err(Error::decode_row)?;
    let original_job_id_bytes: Vec<u8> = row
        .try_get(QueueColumn::OriginalJobId.name())
        .map_err(Error::decode_row)?;
    let reason_text: String = row
        .try_get(QueueColumn::Reason.name())
        .map_err(Error::decode_row)?;
    Ok(DeadLetterJob {
        id: JobId::from_bytes(&id_bytes)?,
        original_job_id: JobId::from_bytes(&original_job_id_bytes)?,
        task_name: row
            .try_get(QueueColumn::TaskName.name())
            .map_err(Error::decode_row)?,
        payload_json: row
            .try_get(QueueProjectionField::PayloadJson.name())
            .map_err(Error::decode_row)?,
        last_error: row
            .try_get(QueueColumn::LastError.name())
            .map_err(Error::decode_row)?,
        retry_count: retry_count_from_persisted_i32(
            row.try_get(QueueColumn::RetryCount.name())
                .map_err(Error::decode_row)?,
        )?,
        max_retries: max_retries_from_persisted_i32(
            row.try_get(QueueColumn::MaxRetries.name())
                .map_err(Error::decode_row)?,
        )?,
        timeout: timeout_from_persisted_nanos(
            row.try_get(QueueColumn::TimeoutNanos.name())
                .map_err(Error::decode_row)?,
        )?,
        dedupe_key: row
            .try_get(QueueColumn::DedupeKey.name())
            .map_err(Error::decode_row)?,
        reason: DeadLetterReason::parse(&reason_text)?,
        dead_lettered_at_unix_microseconds: row
            .try_get(QueueProjectionField::DeadLetteredAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        created_at_unix_microseconds: row
            .try_get(QueueProjectionField::CreatedAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
        updated_at_unix_microseconds: row
            .try_get(QueueProjectionField::UpdatedAtUnixMicroseconds.name())
            .map_err(Error::decode_row)?,
    })
}

pub(super) fn queue_reclaimed_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ReclaimedJob, Error> {
    let id_bytes: Vec<u8> = row
        .try_get(QueueColumn::Id.name())
        .map_err(Error::decode_row)?;
    Ok(ReclaimedJob {
        id: JobId::from_bytes(&id_bytes)?,
        task_name: row
            .try_get(QueueColumn::TaskName.name())
            .map_err(Error::decode_row)?,
    })
}

pub(super) fn queue_reclaimed_failed_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ReclaimedFailedJob, Error> {
    let id_bytes: Vec<u8> = row
        .try_get(QueueColumn::Id.name())
        .map_err(Error::decode_row)?;
    Ok(ReclaimedFailedJob {
        id: JobId::from_bytes(&id_bytes)?,
        task_name: row
            .try_get(QueueColumn::TaskName.name())
            .map_err(Error::decode_row)?,
        last_error: row
            .try_get(QueueColumn::LastError.name())
            .map_err(Error::decode_row)?,
    })
}

pub(super) fn queue_moved_to_dead_letter_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<MovedToDeadLetterJob, Error> {
    let dead_letter_id_bytes: Vec<u8> = row
        .try_get(QueueColumn::Id.name())
        .map_err(Error::decode_row)?;
    let original_job_id_bytes: Vec<u8> = row
        .try_get(QueueColumn::OriginalJobId.name())
        .map_err(Error::decode_row)?;
    Ok(MovedToDeadLetterJob {
        dead_letter_id: JobId::from_bytes(&dead_letter_id_bytes)?,
        original_job_id: JobId::from_bytes(&original_job_id_bytes)?,
        task_name: row
            .try_get(QueueColumn::TaskName.name())
            .map_err(Error::decode_row)?,
        last_error: row
            .try_get(QueueColumn::LastError.name())
            .map_err(Error::decode_row)?,
    })
}
