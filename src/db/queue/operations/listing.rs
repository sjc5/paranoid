use super::*;

pub(in crate::db::queue) async fn list_jobs<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    options: ListJobsOptions,
) -> Result<ListJobsResult, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    if let Some(task_name) = options.task_name.as_deref() {
        validate_task_name(task_name)?;
    }
    let limit = validate_list_limit(options.limit)?;
    let status_filters = deduplicated_status_filter_texts(&options.statuses);
    let cursor_bytes = options.cursor_id.map(|id| id.as_bytes().to_vec());
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_LIST_JOBS,
        Some(sql_catalog.list_jobs_query()),
    );
    let rows = pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.list_jobs_query()))
        .bind(status_filters)
        .bind(options.task_name.as_deref())
        .bind(cursor_bytes.as_deref())
        .bind(i64::from(limit) + 1)
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?;
    let mut jobs = rows
        .iter()
        .map(queue_job_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor_id = if jobs.len() > limit as usize {
        jobs.truncate(limit as usize);
        jobs.last().map(|job| job.id)
    } else {
        None
    };
    Ok(ListJobsResult {
        jobs,
        next_cursor_id,
    })
}

pub(in crate::db::queue) async fn list_dead_letter_jobs<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    options: ListDeadLetterJobsOptions,
) -> Result<ListDeadLetterJobsResult, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    if let Some(task_name) = options.task_name.as_deref() {
        validate_task_name(task_name)?;
    }
    let limit = validate_list_limit(options.limit)?;
    let cursor_bytes = options.cursor_id.map(|id| id.as_bytes().to_vec());
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_LIST_DEAD_LETTER_JOBS,
        Some(sql_catalog.list_dead_letter_jobs_query()),
    );
    let rows = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.list_dead_letter_jobs_query(),
    ))
    .bind(options.task_name.as_deref())
    .bind(cursor_bytes.as_deref())
    .bind(i64::from(limit) + 1)
    .fetch_all(executor)
    .await
    .map_err(DbError::query)?;
    let mut jobs = rows
        .iter()
        .map(queue_dead_letter_job_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor_id = if jobs.len() > limit as usize {
        jobs.truncate(limit as usize);
        jobs.last().map(|job| job.id)
    } else {
        None
    };
    Ok(ListDeadLetterJobsResult {
        jobs,
        next_cursor_id,
    })
}

pub(in crate::db::queue) async fn requeue_dead_letter_job<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    dead_letter_job_id: JobId,
    run_at_or_after_unix_microseconds: Option<i64>,
) -> Result<JobId, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let new_job_id = JobId::new()?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_REQUEUE_DEAD_LETTER_JOB,
        Some(sql_catalog.requeue_dead_letter_job_query()),
    );
    let row_result = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.requeue_dead_letter_job_query(),
    ))
    .bind(dead_letter_job_id.as_bytes())
    .bind(new_job_id.as_bytes())
    .bind(JobStatus::Pending.as_str())
    .bind(run_at_or_after_unix_microseconds)
    .fetch_one(executor)
    .await;
    let row = match row_result {
        Ok(row) => row,
        Err(error) => return Err(map_retry_query_error(error, sql_catalog.config())),
    };
    let inserted_id: Option<Vec<u8>> = row
        .try_get(QueueQueryField::InsertedId.name())
        .map_err(Error::decode_row)?;
    let source_exists: bool = row
        .try_get(QueueQueryField::SourceExists.name())
        .map_err(Error::decode_row)?;
    let visible_exists: bool = row
        .try_get(QueueQueryField::VisibleExists.name())
        .map_err(Error::decode_row)?;
    let conflict_exists: bool = row
        .try_get(QueueQueryField::DedupeConflictExists.name())
        .map_err(Error::decode_row)?;
    let deleted_source: bool = row
        .try_get(QueueQueryField::DeletedSource.name())
        .map_err(Error::decode_row)?;
    requeue_dead_letter_job_result_from_row_state(
        inserted_id,
        source_exists,
        visible_exists,
        conflict_exists,
        deleted_source,
    )
}

pub(in crate::db::queue) async fn delete_dead_letter_job<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    dead_letter_job_id: JobId,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_DELETE_DEAD_LETTER_JOB,
        Some(sql_catalog.delete_dead_letter_job_query()),
    );
    let outcome = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
        sql_catalog.delete_dead_letter_job_query(),
    ))
    .bind(dead_letter_job_id.as_bytes())
    .fetch_one(executor)
    .await
    .map_err(DbError::query)?;
    delete_dead_letter_job_result_from_outcome(&outcome)
}

pub(in crate::db::queue) fn requeue_dead_letter_job_result_from_row_state(
    inserted_id: Option<Vec<u8>>,
    source_exists: bool,
    visible_exists: bool,
    conflict_exists: bool,
    deleted_source: bool,
) -> Result<JobId, Error> {
    if let Some(id_bytes) = inserted_id {
        if !deleted_source {
            return Err(Error::UnexpectedOutcome {
                operation: "requeue dead-letter job",
                outcome: "inserted replacement job without deleting dead-letter source".to_owned(),
            });
        }
        return JobId::from_bytes(&id_bytes).map_err(Error::from);
    }
    if !visible_exists {
        return Err(Error::DeadLetterJobNotFound);
    }
    if !source_exists {
        return Err(Error::DeadLetterJobLockedByConcurrentTransaction);
    }
    if conflict_exists {
        return Err(Error::RetryConflictWithActiveDedupeJob);
    }
    Err(Error::UnexpectedOutcome {
        operation: "requeue dead-letter job",
        outcome: "dead-letter source matched but no replacement job was inserted".to_owned(),
    })
}

pub(in crate::db::queue) fn delete_dead_letter_job_result_from_outcome(
    outcome: &str,
) -> Result<(), Error> {
    match outcome {
        TRANSITION_OUTCOME_APPLIED => Ok(()),
        TRANSITION_OUTCOME_NOT_FOUND => Err(Error::DeadLetterJobNotFound),
        TRANSITION_OUTCOME_LOCKED => Err(Error::DeadLetterJobLockedByConcurrentTransaction),
        other => Err(Error::UnexpectedOutcome {
            operation: "delete dead-letter job",
            outcome: other.to_owned(),
        }),
    }
}
