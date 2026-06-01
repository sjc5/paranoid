use super::*;

pub(in crate::db::queue) struct OwnedRunningJobUpdate<'a> {
    pub(in crate::db::queue) statement: &'a str,
    pub(in crate::db::queue) database_operation_label: &'static str,
    pub(in crate::db::queue) operation: &'static str,
    pub(in crate::db::queue) state_mismatch_error: Error,
    pub(in crate::db::queue) job_id: JobId,
    pub(in crate::db::queue) worker_id: &'a str,
}

pub(in crate::db::queue) struct OwnedRunningJobRetrySchedule<'a> {
    pub(in crate::db::queue) job_id: JobId,
    pub(in crate::db::queue) worker_id: &'a str,
    pub(in crate::db::queue) new_retry_count: i32,
    pub(in crate::db::queue) retry_after_microseconds: i64,
    pub(in crate::db::queue) error_message: &'a str,
}

pub(in crate::db::queue) struct OwnedRunningJobDeadLetterMove<'a> {
    pub(in crate::db::queue) job_id: JobId,
    pub(in crate::db::queue) worker_id: &'a str,
    pub(in crate::db::queue) error_message: &'a str,
    pub(in crate::db::queue) increment_retry_count: bool,
    pub(in crate::db::queue) reason: DeadLetterReason,
}

pub(in crate::db::queue) async fn claim_available_jobs_for_worker<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    registered_task_names: &[String],
    claim_limit: u32,
    worker_id: &str,
) -> Result<Vec<Job>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    if registered_task_names.is_empty() {
        return Ok(Vec::new());
    }

    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_CLAIM_AVAILABLE_JOBS,
        Some(sql_catalog.claim_available_jobs_query()),
    );
    let rows = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.claim_available_jobs_query(),
    ))
    .bind(JobStatus::Pending.as_str())
    .bind(registered_task_names)
    .bind(i64::from(claim_limit))
    .bind(JobStatus::Running.as_str())
    .bind(worker_id)
    .bind(GLOBAL_PAUSE_KEY)
    .fetch_all(executor)
    .await
    .map_err(DbError::query)?;

    rows.iter().map(queue_job_from_row).collect()
}

pub(in crate::db::queue) async fn execute_owned_running_job_update<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    update: OwnedRunningJobUpdate<'_>,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let OwnedRunningJobUpdate {
        statement,
        database_operation_label,
        operation,
        state_mismatch_error,
        job_id,
        worker_id,
    } = update;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        database_operation_label,
        Some(statement),
    );
    let outcome = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(statement))
        .bind(job_id.as_bytes())
        .bind(JobStatus::Running.as_str())
        .bind(worker_id)
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;
    owned_running_job_update_result_from_outcome(operation, state_mismatch_error, &outcome)
}

pub(in crate::db::queue) async fn execute_mark_owned_running_job_failed<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    job_id: JobId,
    worker_id: &str,
    error_message: &str,
    increment_retry_count: bool,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MARK_JOB_FAILED,
        Some(sql_catalog.mark_job_failed_query()),
    );
    let outcome = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
        sql_catalog.mark_job_failed_query(),
    ))
    .bind(JobStatus::Failed.as_str())
    .bind(error_message)
    .bind(increment_retry_count)
    .bind(job_id.as_bytes())
    .bind(JobStatus::Running.as_str())
    .bind(worker_id)
    .fetch_one(executor)
    .await
    .map_err(DbError::query)?;
    owned_running_job_update_result_from_outcome(
        "mark owned running job failed",
        Error::JobNotRunning,
        &outcome,
    )
}

pub(in crate::db::queue) async fn schedule_owned_running_job_retry<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    retry_schedule: OwnedRunningJobRetrySchedule<'_>,
) -> Result<i64, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let OwnedRunningJobRetrySchedule {
        job_id,
        worker_id,
        new_retry_count,
        retry_after_microseconds,
        error_message,
    } = retry_schedule;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_SCHEDULE_OWNED_RUNNING_JOB_RETRY,
        Some(sql_catalog.schedule_owned_running_job_retry_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.schedule_owned_running_job_retry_query(),
    ))
    .bind(JobStatus::Pending.as_str())
    .bind(new_retry_count)
    .bind(retry_after_microseconds)
    .bind(error_message)
    .bind(job_id.as_bytes())
    .bind(JobStatus::Running.as_str())
    .bind(worker_id)
    .fetch_one(executor)
    .await
    .map_err(DbError::query)?;
    let outcome: String = row.try_get("outcome").map_err(Error::decode_row)?;
    schedule_owned_running_job_retry_result_from_outcome(
        outcome.as_str(),
        row.try_get("next_run_at").map_err(Error::decode_row)?,
    )
}

pub(in crate::db::queue) async fn move_owned_running_job_to_dead_letter<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    dead_letter_move: OwnedRunningJobDeadLetterMove<'_>,
) -> Result<JobId, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let OwnedRunningJobDeadLetterMove {
        job_id,
        worker_id,
        error_message,
        increment_retry_count,
        reason,
    } = dead_letter_move;
    let dead_letter_job_id = JobId::new()?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_MOVE_OWNED_RUNNING_JOB_TO_DEAD_LETTER,
        Some(sql_catalog.move_owned_running_job_to_dead_letter_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.move_owned_running_job_to_dead_letter_query(),
    ))
    .bind(job_id.as_bytes())
    .bind(JobStatus::Running.as_str())
    .bind(worker_id)
    .bind(dead_letter_job_id.as_bytes())
    .bind(error_message)
    .bind(increment_retry_count)
    .bind(reason.as_str())
    .fetch_one(executor)
    .await
    .map_err(DbError::query)?;
    let outcome: String = row.try_get("outcome").map_err(Error::decode_row)?;
    move_owned_running_job_to_dead_letter_result_from_outcome(
        &outcome,
        row.try_get("inserted_id").map_err(Error::decode_row)?,
    )
}

pub(in crate::db::queue) async fn return_available_owned_running_jobs_to_pending<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    statement: &str,
    database_operation_label: &'static str,
    worker_id: &str,
) -> Result<u64, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::Execute,
        database_operation_label,
        Some(statement),
    );
    let rows_affected = pooler_safe_query(sqlx::AssertSqlSafe(statement))
        .bind(JobStatus::Pending.as_str())
        .bind(worker_id)
        .bind(JobStatus::Running.as_str())
        .execute(executor)
        .await
        .map_err(DbError::query)?
        .rows_affected();
    Ok(rows_affected)
}

pub(in crate::db::queue) fn owned_running_job_update_result_from_outcome(
    operation: &'static str,
    state_mismatch_error: Error,
    outcome: &str,
) -> Result<(), Error> {
    match outcome {
        TRANSITION_OUTCOME_APPLIED => Ok(()),
        TRANSITION_OUTCOME_LOCKED => Err(Error::JobLockedByConcurrentTransaction),
        TRANSITION_OUTCOME_NOT_FOUND | TRANSITION_OUTCOME_STATE_MISMATCH => {
            Err(state_mismatch_error)
        }
        other => Err(Error::UnexpectedOutcome {
            operation,
            outcome: other.to_owned(),
        }),
    }
}

pub(in crate::db::queue) fn schedule_owned_running_job_retry_result_from_outcome(
    outcome: &str,
    next_run_at: Option<i64>,
) -> Result<i64, Error> {
    match outcome {
        TRANSITION_OUTCOME_APPLIED => next_run_at.ok_or_else(|| Error::UnexpectedOutcome {
            operation: "schedule owned running job retry",
            outcome: "applied without next run time".to_owned(),
        }),
        TRANSITION_OUTCOME_LOCKED => Err(Error::JobLockedByConcurrentTransaction),
        TRANSITION_OUTCOME_NOT_FOUND | TRANSITION_OUTCOME_STATE_MISMATCH => {
            Err(Error::JobNotRunning)
        }
        other => Err(Error::UnexpectedOutcome {
            operation: "schedule owned running job retry",
            outcome: other.to_owned(),
        }),
    }
}

pub(in crate::db::queue) fn move_owned_running_job_to_dead_letter_result_from_outcome(
    outcome: &str,
    inserted_id: Option<Vec<u8>>,
) -> Result<JobId, Error> {
    match outcome {
        TRANSITION_OUTCOME_APPLIED => {
            let id_bytes = inserted_id.ok_or_else(|| Error::UnexpectedOutcome {
                operation: "move owned running job to dead letter",
                outcome: "applied without inserted dead-letter id".to_owned(),
            })?;
            JobId::from_bytes(&id_bytes).map_err(Error::from)
        }
        TRANSITION_OUTCOME_LOCKED => Err(Error::JobLockedByConcurrentTransaction),
        TRANSITION_OUTCOME_NOT_FOUND | TRANSITION_OUTCOME_STATE_MISMATCH => {
            Err(Error::JobNotRunning)
        }
        other => Err(Error::UnexpectedOutcome {
            operation: "move owned running job to dead letter",
            outcome: other.to_owned(),
        }),
    }
}
