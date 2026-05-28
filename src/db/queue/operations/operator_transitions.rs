use super::*;

pub(in crate::db::queue) struct ExpectedJobStateTransition<'a> {
    pub(in crate::db::queue) statement: &'a str,
    pub(in crate::db::queue) database_operation_label: &'static str,
    pub(in crate::db::queue) operation: &'static str,
    pub(in crate::db::queue) expected_status: JobStatus,
    pub(in crate::db::queue) state_mismatch_error: Error,
    pub(in crate::db::queue) job_id: JobId,
}

pub(in crate::db::queue) async fn execute_job_state_transition<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    statement: &str,
    database_operation_label: &'static str,
    operation: &'static str,
    state_mismatch_error: Error,
    job_id: JobId,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    execute_job_state_transition_for_expected_status(
        executor,
        database_operation_observer,
        ExpectedJobStateTransition {
            statement,
            database_operation_label,
            operation,
            expected_status: JobStatus::Pending,
            state_mismatch_error,
            job_id,
        },
    )
    .await
}

pub(in crate::db::queue) async fn execute_job_state_transition_for_expected_status<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    transition: ExpectedJobStateTransition<'_>,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let ExpectedJobStateTransition {
        statement,
        database_operation_label,
        operation,
        expected_status,
        state_mismatch_error,
        job_id,
    } = transition;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        database_operation_label,
        Some(statement),
    );
    let outcome = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(statement))
        .bind(job_id.as_bytes())
        .bind(expected_status.as_str())
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;
    queue_job_state_transition_result_from_outcome(operation, state_mismatch_error, &outcome)
}

pub(in crate::db::queue) async fn execute_retry_failed_job<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    job_id: JobId,
    run_at_or_after_unix_microseconds: Option<i64>,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_RETRY_FAILED_JOB,
        Some(sql_catalog.retry_failed_job_by_id_query()),
    );
    let row_result = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
        sql_catalog.retry_failed_job_by_id_query(),
    ))
    .bind(job_id.as_bytes())
    .bind(JobStatus::Failed.as_str())
    .bind(JobStatus::Pending.as_str())
    .bind(run_at_or_after_unix_microseconds)
    .fetch_one(executor)
    .await;
    let outcome = match row_result {
        Ok(outcome) => outcome,
        Err(error) => return Err(map_retry_query_error(error, sql_catalog.config())),
    };
    queue_retry_failed_job_result_from_outcome(&outcome)
}

pub(in crate::db::queue) async fn move_failed_job_to_dead_letter<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    job_id: JobId,
    reason: DeadLetterReason,
) -> Result<JobId, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let dead_letter_job_id = JobId::new()?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MOVE_FAILED_JOB_TO_DEAD_LETTER,
        Some(sql_catalog.move_failed_job_to_dead_letter_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.move_failed_job_to_dead_letter_query(),
    ))
    .bind(job_id.as_bytes())
    .bind(JobStatus::Failed.as_str())
    .bind(dead_letter_job_id.as_bytes())
    .bind(reason.as_str())
    .fetch_one(executor)
    .await
    .map_err(DbError::query)?;
    let inserted_id: Option<Vec<u8>> = row.try_get("inserted_id").map_err(Error::decode_row)?;
    let target_exists: bool = row.try_get("target_exists").map_err(Error::decode_row)?;
    let target_matches_status: bool = row
        .try_get("target_matches_status")
        .map_err(Error::decode_row)?;
    let visible_exists: bool = row.try_get("visible_exists").map_err(Error::decode_row)?;
    let visible_matches_status: bool = row
        .try_get("visible_matches_status")
        .map_err(Error::decode_row)?;
    move_failed_job_to_dead_letter_result_from_row_state(
        inserted_id,
        target_exists,
        target_matches_status,
        visible_exists,
        visible_matches_status,
    )
}

pub(in crate::db::queue) async fn move_failed_jobs_to_dead_letter_batch<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    job_ids: &[JobId],
    reason: DeadLetterReason,
) -> Result<MoveFailedJobsToDeadLetterBatchResult, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    if job_ids.is_empty() {
        return Ok(MoveFailedJobsToDeadLetterBatchResult {
            requested_count: 0,
            moved_jobs: Vec::new(),
        });
    }
    if job_ids.len() > MAX_QUEUE_DEAD_LETTER_MOVE_BATCH_SIZE as usize {
        return Err(Error::DeadLetterMoveBatchSizeTooLarge {
            actual: job_ids.len(),
            max: MAX_QUEUE_DEAD_LETTER_MOVE_BATCH_SIZE,
        });
    }
    let mut unique_job_ids = HashSet::with_capacity(job_ids.len());
    for job_id in job_ids {
        if !unique_job_ids.insert(*job_id) {
            return Err(Error::DuplicateJobIdInDeadLetterMoveBatch { job_id: *job_id });
        }
    }

    let dead_letter_ids = (0..job_ids.len())
        .map(|_| JobId::new())
        .collect::<Result<Vec<_>, _>>()?;
    let statement = sql_catalog.move_failed_jobs_to_dead_letter_batch_query(job_ids.len());
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_MOVE_FAILED_JOBS_TO_DEAD_LETTER_BATCH,
        Some(statement.as_ref()),
    );
    let mut query = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_ref()));
    for (job_id, dead_letter_id) in job_ids.iter().zip(dead_letter_ids.iter()) {
        query = query
            .bind(job_id.as_bytes())
            .bind(dead_letter_id.as_bytes());
    }
    let rows = query
        .bind(JobStatus::Failed.as_str())
        .bind(reason.as_str())
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?;
    let moved_jobs = rows
        .iter()
        .map(queue_moved_to_dead_letter_job_from_row)
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(MoveFailedJobsToDeadLetterBatchResult {
        requested_count: job_ids.len(),
        moved_jobs,
    })
}

pub(in crate::db::queue) fn queue_job_state_transition_result_from_outcome(
    operation: &'static str,
    state_mismatch_error: Error,
    outcome: &str,
) -> Result<(), Error> {
    match outcome {
        TRANSITION_OUTCOME_APPLIED => Ok(()),
        TRANSITION_OUTCOME_NOT_FOUND => Err(Error::JobNotFound),
        TRANSITION_OUTCOME_LOCKED => Err(Error::JobLockedByConcurrentTransaction),
        TRANSITION_OUTCOME_STATE_MISMATCH => Err(state_mismatch_error),
        other => Err(Error::UnexpectedOutcome {
            operation,
            outcome: other.to_owned(),
        }),
    }
}

pub(in crate::db::queue) fn queue_retry_failed_job_result_from_outcome(
    outcome: &str,
) -> Result<(), Error> {
    match outcome {
        TRANSITION_OUTCOME_APPLIED => Ok(()),
        TRANSITION_OUTCOME_NOT_FOUND => Err(Error::JobNotFound),
        TRANSITION_OUTCOME_LOCKED => Err(Error::JobLockedByConcurrentTransaction),
        TRANSITION_OUTCOME_STATE_MISMATCH => Err(Error::JobNotFailed),
        TRANSITION_OUTCOME_DEDUPE_CONFLICT => Err(Error::RetryConflictWithActiveDedupeJob),
        other => Err(Error::UnexpectedOutcome {
            operation: "retry failed job",
            outcome: other.to_owned(),
        }),
    }
}

pub(in crate::db::queue) fn move_failed_job_to_dead_letter_result_from_row_state(
    inserted_id: Option<Vec<u8>>,
    target_exists: bool,
    target_matches_status: bool,
    visible_exists: bool,
    visible_matches_status: bool,
) -> Result<JobId, Error> {
    if let Some(id_bytes) = inserted_id {
        return JobId::from_bytes(&id_bytes).map_err(Error::from);
    }
    if !visible_exists {
        return Err(Error::JobNotFound);
    }
    if !target_exists && visible_matches_status {
        return Err(Error::JobLockedByConcurrentTransaction);
    }
    if !target_matches_status {
        return Err(Error::JobNotFailed);
    }
    Err(Error::UnexpectedOutcome {
        operation: "move failed job to dead letter",
        outcome: "failed job matched but no dead-letter row was inserted".to_owned(),
    })
}
