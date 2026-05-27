use super::*;

pub(in crate::db::queue) async fn cleanup_jobs_older_than_once<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    status: JobStatus,
    older_than: Duration,
    batch_size: u32,
) -> Result<u64, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let older_than_microseconds = duration_to_rounded_microseconds(older_than)?;
    validate_cleanup_batch_size(batch_size)?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
        Some(sql_catalog.cleanup_jobs_older_than_once_query()),
    );
    let rows_affected = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.cleanup_jobs_older_than_once_query(),
    ))
    .bind(status.as_str())
    .bind(older_than_microseconds)
    .bind(i64::from(batch_size))
    .execute(executor)
    .await
    .map_err(DbError::query)?
    .rows_affected();
    Ok(rows_affected)
}

pub(in crate::db::queue) async fn cleanup_jobs_older_than_until_empty(
    pool: &Pool,
    sql_catalog: &SqlCatalog,
    status: JobStatus,
    older_than: Duration,
    batch_size: u32,
    delay_between_batches: Duration,
) -> Result<u64, Error> {
    cleanup_target_older_than_until_empty(
        pool,
        sql_catalog,
        CleanupTarget::Jobs(status),
        older_than,
        batch_size,
        delay_between_batches,
        None,
    )
    .await
}

pub(in crate::db::queue) async fn cleanup_available_dead_letter_jobs_older_than_once<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    older_than: Duration,
    batch_size: u32,
) -> Result<u64, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let older_than_microseconds = duration_to_rounded_microseconds(older_than)?;
    validate_cleanup_batch_size(batch_size)?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_CLEANUP_DEAD_LETTER_ONCE,
        Some(sql_catalog.cleanup_available_dead_letter_jobs_older_than_once_query()),
    );
    let rows_affected = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.cleanup_available_dead_letter_jobs_older_than_once_query(),
    ))
    .bind(older_than_microseconds)
    .bind(i64::from(batch_size))
    .execute(executor)
    .await
    .map_err(DbError::query)?
    .rows_affected();
    Ok(rows_affected)
}

pub(in crate::db::queue) async fn cleanup_available_dead_letter_jobs_older_than_until_empty(
    pool: &Pool,
    sql_catalog: &SqlCatalog,
    older_than: Duration,
    batch_size: u32,
    delay_between_batches: Duration,
) -> Result<u64, Error> {
    cleanup_target_older_than_until_empty(
        pool,
        sql_catalog,
        CleanupTarget::DeadLetterJobs,
        older_than,
        batch_size,
        delay_between_batches,
        None,
    )
    .await
}

pub(in crate::db::queue) async fn cleanup_jobs_older_than_until_empty_or_cancelled(
    pool: &Pool,
    sql_catalog: &SqlCatalog,
    status: JobStatus,
    older_than: Duration,
    batch_size: u32,
    delay_between_batches: Duration,
    cancellation_signal: &RuntimeCancellationSignal,
) -> Result<u64, Error> {
    cleanup_target_older_than_until_empty(
        pool,
        sql_catalog,
        CleanupTarget::Jobs(status),
        older_than,
        batch_size,
        delay_between_batches,
        Some(cancellation_signal),
    )
    .await
}

pub(in crate::db::queue) async fn cleanup_available_dead_letter_jobs_older_than_until_empty_or_cancelled(
    pool: &Pool,
    sql_catalog: &SqlCatalog,
    older_than: Duration,
    batch_size: u32,
    delay_between_batches: Duration,
    cancellation_signal: &RuntimeCancellationSignal,
) -> Result<u64, Error> {
    cleanup_target_older_than_until_empty(
        pool,
        sql_catalog,
        CleanupTarget::DeadLetterJobs,
        older_than,
        batch_size,
        delay_between_batches,
        Some(cancellation_signal),
    )
    .await
}

#[derive(Clone, Copy)]
enum CleanupTarget {
    Jobs(JobStatus),
    DeadLetterJobs,
}

async fn cleanup_target_older_than_until_empty(
    pool: &Pool,
    sql_catalog: &SqlCatalog,
    target: CleanupTarget,
    older_than: Duration,
    batch_size: u32,
    delay_between_batches: Duration,
    cancellation_signal: Option<&RuntimeCancellationSignal>,
) -> Result<u64, Error> {
    validate_cleanup_batch_size(batch_size)?;
    let mut total_deleted = 0_u64;
    loop {
        if cancellation_signal.is_some_and(RuntimeCancellationSignal::is_cancellation_requested) {
            return Ok(total_deleted);
        }

        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        let (operation, deleted) = match target {
            CleanupTarget::Jobs(status) => (
                "cleanup jobs until empty batch",
                cleanup_jobs_older_than_once(
                    tx.inner.as_mut(),
                    database_operation_observer.as_ref(),
                    sql_catalog,
                    status,
                    older_than,
                    batch_size,
                )
                .await,
            ),
            CleanupTarget::DeadLetterJobs => (
                "cleanup dead letter jobs until empty batch",
                cleanup_available_dead_letter_jobs_older_than_once(
                    tx.inner.as_mut(),
                    database_operation_observer.as_ref(),
                    sql_catalog,
                    older_than,
                    batch_size,
                )
                .await,
            ),
        };
        let deleted = finish_queue_pool_transaction(operation, tx, deleted).await?;
        total_deleted = checked_add_cleanup_total(total_deleted, deleted)?;
        if deleted < u64::from(batch_size) {
            return Ok(total_deleted);
        }
        if !sleep_before_next_cleanup_batch_or_cancellation(
            delay_between_batches,
            cancellation_signal,
        )
        .await
        {
            return Ok(total_deleted);
        }
    }
}

fn checked_add_cleanup_total(current: u64, deleted: u64) -> Result<u64, Error> {
    current
        .checked_add(deleted)
        .ok_or_else(|| Error::UnexpectedOutcome {
            operation: "queue cleanup",
            outcome: "deleted row count overflowed".to_owned(),
        })
}

async fn sleep_before_next_cleanup_batch_or_cancellation(
    delay_between_batches: Duration,
    cancellation_signal: Option<&RuntimeCancellationSignal>,
) -> bool {
    if delay_between_batches.is_zero() {
        return true;
    }
    let Some(cancellation_signal) = cancellation_signal else {
        tokio::time::sleep(delay_between_batches).await;
        return true;
    };
    tokio::select! {
        _ = cancellation_signal.wait_until_cancellation_requested() => false,
        _ = tokio::time::sleep(delay_between_batches) => true,
    }
}

pub(in crate::db::queue) async fn reclaim_available_stale_running_jobs_once_in_current_transaction(
    tx: &mut Tx<'_>,
    sql_catalog: &SqlCatalog,
    stale_threshold: Duration,
    reclaim_batch_size: u32,
    move_expired_max_retry_jobs_to_dead_letter: bool,
) -> Result<ReclaimStaleRunningJobsResult, Error> {
    let stale_threshold_microseconds = stale_threshold_to_microseconds(stale_threshold)?;
    validate_reclaim_batch_size(reclaim_batch_size)?;
    let database_operation_observer = tx.database_operation_observer().cloned();
    let never_started_jobs_returned_to_pending = reclaim_never_started_running_jobs(
        tx.inner.as_mut(),
        database_operation_observer.as_ref(),
        sql_catalog,
        stale_threshold_microseconds,
        reclaim_batch_size,
    )
    .await?;
    let expired_jobs_moved_to_failed = reclaim_expired_running_jobs_to_failed(
        tx.inner.as_mut(),
        database_operation_observer.as_ref(),
        sql_catalog,
        stale_threshold_microseconds,
        reclaim_batch_size,
    )
    .await?;
    let expired_jobs_moved_to_dead_letter = if move_expired_max_retry_jobs_to_dead_letter {
        let failed_job_ids = expired_jobs_moved_to_failed
            .iter()
            .map(|job| job.id)
            .collect::<Vec<_>>();
        let result = move_failed_jobs_to_dead_letter_batch(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            sql_catalog,
            &failed_job_ids,
            DeadLetterReason::ExecutionExpired,
        )
        .await?;
        result.moved_jobs
    } else {
        Vec::new()
    };
    let expired_jobs_returned_to_pending_for_retry =
        reclaim_expired_running_jobs_to_pending_for_retry(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            sql_catalog,
            stale_threshold_microseconds,
            reclaim_batch_size,
        )
        .await?;

    Ok(ReclaimStaleRunningJobsResult {
        never_started_jobs_returned_to_pending,
        expired_jobs_moved_to_failed,
        expired_jobs_moved_to_dead_letter,
        expired_jobs_returned_to_pending_for_retry,
    })
}

pub(in crate::db::queue) async fn reclaim_never_started_running_jobs<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    stale_threshold_microseconds: i64,
    reclaim_batch_size: u32,
) -> Result<Vec<ReclaimedJob>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    validate_reclaim_batch_size(reclaim_batch_size)?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_RECLAIM_NEVER_STARTED_RUNNING_JOBS,
        Some(sql_catalog.reclaim_never_started_running_jobs_query()),
    );
    let rows = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.reclaim_never_started_running_jobs_query(),
    ))
    .bind(JobStatus::Pending.as_str())
    .bind(JobStatus::Running.as_str())
    .bind(stale_threshold_microseconds)
    .bind(i64::from(reclaim_batch_size))
    .fetch_all(executor)
    .await
    .map_err(DbError::query)?;
    rows.iter().map(queue_reclaimed_job_from_row).collect()
}

pub(in crate::db::queue) async fn reclaim_expired_running_jobs_to_failed<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    stale_threshold_microseconds: i64,
    reclaim_batch_size: u32,
) -> Result<Vec<ReclaimedFailedJob>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    validate_reclaim_batch_size(reclaim_batch_size)?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_FAILED,
        Some(sql_catalog.reclaim_expired_running_jobs_to_failed_query()),
    );
    let rows = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.reclaim_expired_running_jobs_to_failed_query(),
    ))
    .bind(JobStatus::Failed.as_str())
    .bind(JobStatus::Running.as_str())
    .bind(stale_threshold_microseconds)
    .bind(i64::from(reclaim_batch_size))
    .fetch_all(executor)
    .await
    .map_err(DbError::query)?;
    rows.iter()
        .map(queue_reclaimed_failed_job_from_row)
        .collect()
}

pub(in crate::db::queue) async fn reclaim_expired_running_jobs_to_pending_for_retry<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    stale_threshold_microseconds: i64,
    reclaim_batch_size: u32,
) -> Result<Vec<ReclaimedJob>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    validate_reclaim_batch_size(reclaim_batch_size)?;
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_PENDING,
        Some(sql_catalog.reclaim_expired_running_jobs_to_pending_for_retry_query()),
    );
    let rows = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.reclaim_expired_running_jobs_to_pending_for_retry_query(),
    ))
    .bind(JobStatus::Pending.as_str())
    .bind(JobStatus::Running.as_str())
    .bind(stale_threshold_microseconds)
    .bind(i64::from(reclaim_batch_size))
    .fetch_all(executor)
    .await
    .map_err(DbError::query)?;
    rows.iter().map(queue_reclaimed_job_from_row).collect()
}
