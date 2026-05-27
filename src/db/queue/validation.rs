use super::*;

pub(super) fn validate_store_config(config: &StoreConfig) -> Result<(), Error> {
    validate_distinct_table_names(config)?;
    validate_payload_json_limit_bytes(config.payload_json_limit_bytes)?;
    Ok(())
}

pub(super) fn validate_distinct_table_names(config: &StoreConfig) -> Result<(), Error> {
    if pg_table_name_set_could_contain_same_relation(&[
        &config.table_name,
        &config.dead_letter_table_name,
        &config.pause_table_name,
        &config.schema_ledger_table_name,
    ]) {
        return Err(Error::TableNamesMustBeDistinct);
    }
    Ok(())
}

pub(super) fn validate_payload_json_limit_bytes(limit: usize) -> Result<(), Error> {
    if limit == 0 {
        return Err(Error::PayloadJsonLimitIsZero);
    }
    if limit > MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES {
        return Err(Error::PayloadJsonLimitTooLarge {
            actual: limit,
            max: MAX_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
        });
    }
    Ok(())
}

pub(super) fn validate_task_name(task_name: &str) -> Result<(), Error> {
    if task_name.is_empty() {
        return Err(Error::TaskNameRequired);
    }
    if task_name.len() > MAX_QUEUE_TASK_NAME_BYTES {
        return Err(Error::TaskNameTooLong {
            actual: task_name.len(),
            max: MAX_QUEUE_TASK_NAME_BYTES,
        });
    }
    let mut bytes = task_name.bytes();
    let Some(first) = bytes.next() else {
        return Err(Error::TaskNameRequired);
    };
    if !is_task_name_first_byte(first) {
        return Err(Error::InvalidTaskName);
    }
    if !bytes.all(is_task_name_trailing_byte) {
        return Err(Error::InvalidTaskName);
    }
    Ok(())
}

pub(super) fn validate_registered_task_names(task_names: &[String]) -> Result<(), Error> {
    for task_name in task_names {
        validate_task_name(task_name)?;
    }
    Ok(())
}

pub(super) fn validate_optional_dedupe_key(dedupe_key: Option<&str>) -> Result<(), Error> {
    let Some(dedupe_key) = dedupe_key else {
        return Ok(());
    };
    if dedupe_key.is_empty() {
        return Err(Error::InvalidDedupeKey);
    }
    if dedupe_key.len() > MAX_QUEUE_DEDUPE_KEY_BYTES {
        return Err(Error::DedupeKeyTooLong {
            actual: dedupe_key.len(),
            max: MAX_QUEUE_DEDUPE_KEY_BYTES,
        });
    }
    if dedupe_key.as_bytes().contains(&0) {
        return Err(Error::InvalidDedupeKey);
    }
    Ok(())
}

pub(super) fn validate_enqueue_batch_size(batch_size: usize) -> Result<(), Error> {
    if batch_size > MAX_QUEUE_ENQUEUE_BATCH_SIZE as usize {
        return Err(Error::EnqueueBatchSizeTooLarge {
            actual: batch_size,
            max: MAX_QUEUE_ENQUEUE_BATCH_SIZE,
        });
    }
    Ok(())
}

pub(super) fn validate_claim_limit(claim_limit: u32) -> Result<(), Error> {
    if claim_limit == 0 {
        return Err(Error::ClaimLimitIsZero);
    }
    if claim_limit > MAX_QUEUE_CLAIM_LIMIT {
        return Err(Error::ClaimLimitTooLarge {
            actual: claim_limit,
            max: MAX_QUEUE_CLAIM_LIMIT,
        });
    }
    Ok(())
}

pub(super) fn validate_list_limit(limit: Option<u32>) -> Result<u32, Error> {
    let limit = limit.unwrap_or(DEFAULT_QUEUE_LIST_LIMIT);
    if limit == 0 {
        return Err(Error::ListLimitIsZero);
    }
    if limit > MAX_QUEUE_LIST_LIMIT {
        return Err(Error::ListLimitTooLarge {
            actual: limit,
            max: MAX_QUEUE_LIST_LIMIT,
        });
    }
    Ok(limit)
}

pub(super) fn validate_retry_available_failed_jobs_limit(limit: u32) -> Result<(), Error> {
    if limit == 0 {
        return Err(Error::RetryAvailableFailedJobsLimitIsZero);
    }
    if limit > MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT {
        return Err(Error::RetryAvailableFailedJobsLimitTooLarge {
            actual: limit,
            max: MAX_QUEUE_RETRY_AVAILABLE_FAILED_JOBS_LIMIT,
        });
    }
    Ok(())
}

pub(super) fn validate_reclaim_batch_size(batch_size: u32) -> Result<(), Error> {
    if batch_size == 0 {
        return Err(Error::ReclaimBatchSizeIsZero);
    }
    if batch_size > MAX_QUEUE_RECLAIM_BATCH_SIZE {
        return Err(Error::ReclaimBatchSizeTooLarge {
            actual: batch_size,
            max: MAX_QUEUE_RECLAIM_BATCH_SIZE,
        });
    }
    Ok(())
}

pub(super) fn validate_cleanup_batch_size(batch_size: u32) -> Result<(), Error> {
    if batch_size == 0 {
        return Err(Error::CleanupBatchSizeIsZero);
    }
    if batch_size > MAX_QUEUE_CLEANUP_BATCH_SIZE {
        return Err(Error::CleanupBatchSizeTooLarge {
            actual: batch_size,
            max: MAX_QUEUE_CLEANUP_BATCH_SIZE,
        });
    }
    Ok(())
}

pub(super) fn validate_worker_owner_id(worker_owner_id: &str) -> Result<(), Error> {
    if worker_owner_id.is_empty() {
        return Err(Error::WorkerOwnerIdRequired);
    }
    if worker_owner_id.len() > MAX_QUEUE_WORKER_OWNER_ID_BYTES {
        return Err(Error::WorkerOwnerIdTooLong {
            actual: worker_owner_id.len(),
            max: MAX_QUEUE_WORKER_OWNER_ID_BYTES,
        });
    }
    if worker_owner_id.as_bytes().contains(&0) {
        return Err(Error::InvalidWorkerOwnerId);
    }
    Ok(())
}

pub(super) fn validate_worker_name(worker_name: &str) -> Result<(), Error> {
    if worker_name.is_empty() {
        return Err(Error::WorkerNameRequired);
    }
    if worker_name.len() > MAX_QUEUE_WORKER_NAME_BYTES {
        return Err(Error::WorkerNameTooLong {
            actual: worker_name.len(),
            max: MAX_QUEUE_WORKER_NAME_BYTES,
        });
    }
    if worker_name.as_bytes().contains(&0) {
        return Err(Error::InvalidWorkerName);
    }
    Ok(())
}

pub(super) fn new_unique_worker_owner_id(worker_name: &str) -> Result<String, Error> {
    validate_worker_name(worker_name)?;
    let suffix = id::SortableId::new()
        .map_err(|source| Error::WorkerOwnerIdGeneration { source })?
        .to_text();
    let worker_owner_id = format!("{worker_name}{QUEUE_WORKER_OWNER_ID_SEPARATOR}{suffix}");
    validate_worker_owner_id(&worker_owner_id)?;
    Ok(worker_owner_id)
}

pub(super) fn duration_to_rounded_microseconds(duration: Duration) -> Result<i64, Error> {
    if duration.is_zero() {
        return Err(Error::CleanupAgeIsZero);
    }
    let micros = duration.as_micros().max(1);
    micros.try_into().map_err(|_| Error::CleanupAgeTooLarge)
}

pub(super) fn stale_threshold_to_microseconds(duration: Duration) -> Result<i64, Error> {
    if duration.is_zero() {
        return Err(Error::StaleThresholdIsZero);
    }
    let micros = duration.as_micros().max(1);
    micros.try_into().map_err(|_| Error::StaleThresholdTooLarge)
}

pub(super) fn retry_backoff_to_microseconds(duration: Duration) -> Result<i64, Error> {
    duration
        .as_micros()
        .try_into()
        .map_err(|_| Error::RetryBackoffTooLarge)
}

pub(super) fn deduplicated_status_filter_texts(statuses: &[JobStatus]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduplicated = Vec::with_capacity(statuses.len());
    for status in statuses {
        let status_text = status.as_str();
        if seen.insert(status_text) {
            deduplicated.push(status_text.to_owned());
        }
    }
    deduplicated
}

pub(super) fn sqlx_error_is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        super::super::sql_state_from_sqlx_error(error),
        Some(PgSqlState::UniqueViolation)
    )
}

pub(super) fn sqlx_error_is_active_dedupe_unique_violation(
    error: &sqlx::Error,
    config: &StoreConfig,
) -> bool {
    if !sqlx_error_is_unique_violation(error) {
        return false;
    }
    let active_dedupe_index_name = migration_index_identifier(
        UNIQUE_INDEX_KIND,
        &config.table_name,
        ACTIVE_DEDUPE_INDEX_SUFFIX,
    );
    error
        .as_database_error()
        .and_then(|database_error| database_error.constraint())
        .is_some_and(|constraint| constraint == active_dedupe_index_name.as_str())
}

pub(super) fn map_retry_query_error(error: sqlx::Error, config: &StoreConfig) -> Error {
    if sqlx_error_is_active_dedupe_unique_violation(&error, config) {
        return Error::RetryConflictWithActiveDedupeJob;
    }
    DbError::query(error).into()
}

pub(super) fn is_task_name_first_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

pub(super) fn is_task_name_trailing_byte(byte: u8) -> bool {
    is_task_name_first_byte(byte) || byte == b'.' || byte == b'-'
}

pub(super) fn timeout_to_nanos(timeout: JobTimeout) -> Result<i64, Error> {
    match timeout {
        JobTimeout::WorkerDefault => Ok(0),
        JobTimeout::NoTimeout => Ok(-1),
        JobTimeout::ExpiresAfter(duration) => {
            if duration.is_zero() {
                return Err(Error::InvalidTimeout);
            }
            duration
                .as_nanos()
                .try_into()
                .map_err(|_| Error::InvalidTimeout)
        }
    }
}
