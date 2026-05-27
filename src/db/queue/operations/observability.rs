use super::*;

pub(in crate::db::queue) async fn fetch_job_by_id<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    job_id: JobId,
) -> Result<Job, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOptional,
        QUEUE_OPERATION_FETCH_JOB_BY_ID,
        Some(sql_catalog.select_job_by_id_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.select_job_by_id_query()))
        .bind(job_id.as_bytes())
        .fetch_optional(executor)
        .await
        .map_err(DbError::query)?;
    let Some(row) = row else {
        return Err(Error::JobNotFound);
    };
    queue_job_from_row(&row)
}

pub(in crate::db::queue) async fn fetch_status_counts<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    optional_task_name: Option<&str>,
) -> Result<StatusCounts, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_STATUS_COUNTS,
        Some(sql_catalog.fetch_status_counts_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.fetch_status_counts_query()))
        .bind(optional_task_name)
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;
    Ok(StatusCounts {
        pending_count: row.try_get("pending_count").map_err(Error::decode_row)?,
        running_count: row.try_get("running_count").map_err(Error::decode_row)?,
        completed_count: row.try_get("completed_count").map_err(Error::decode_row)?,
        failed_count: row.try_get("failed_count").map_err(Error::decode_row)?,
        dead_letter_count: row
            .try_get("dead_letter_count")
            .map_err(Error::decode_row)?,
    })
}

pub(in crate::db::queue) async fn fetch_job_count_by_status<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    status: JobStatus,
    optional_task_name: Option<&str>,
) -> Result<i64, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_JOB_COUNT_BY_STATUS,
        Some(sql_catalog.fetch_job_count_by_status_query()),
    );
    pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
        sql_catalog.fetch_job_count_by_status_query(),
    ))
    .bind(status.as_str())
    .bind(optional_task_name)
    .fetch_one(executor)
    .await
    .map_err(DbError::query)
    .map_err(Into::into)
}

pub(in crate::db::queue) async fn fetch_worker_pressure_counts<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
) -> Result<WorkerPressureCounts, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_WORKER_PRESSURE_COUNTS,
        Some(sql_catalog.fetch_worker_pressure_counts_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(
        sql_catalog.fetch_worker_pressure_counts_query(),
    ))
    .fetch_one(executor)
    .await
    .map_err(DbError::query)?;
    Ok(WorkerPressureCounts {
        pending_job_count: row
            .try_get("pending_job_count")
            .map_err(Error::decode_row)?,
        running_job_count: row
            .try_get("running_job_count")
            .map_err(Error::decode_row)?,
    })
}

pub(in crate::db::queue) async fn fetch_pause_entries<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
) -> Result<Vec<String>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_FETCH_PAUSE_ENTRIES,
        Some(sql_catalog.fetch_pause_entries_query()),
    );
    pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(sql_catalog.fetch_pause_entries_query()))
        .bind(GLOBAL_PAUSE_KEY)
        .bind(format!("{TASK_PAUSE_KEY_PREFIX}%"))
        .fetch_all(executor)
        .await
        .map_err(DbError::query)
        .map_err(Into::into)
}

pub(in crate::db::queue) async fn fetch_paused_task_names<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
) -> Result<Vec<String>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    let pause_entries =
        fetch_pause_entries(executor, database_operation_observer, sql_catalog).await?;
    let (_, paused_task_names) = aggregate_pause_entries(pause_entries);
    Ok(paused_task_names)
}

pub(in crate::db::queue) async fn fetch_orphaned_task_names<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    registry: &TaskRegistry,
) -> Result<Vec<String>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchAll,
        QUEUE_OPERATION_FETCH_ORPHANED_TASK_NAMES,
        Some(sql_catalog.fetch_pending_or_running_task_names_query()),
    );
    let task_names = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
        sql_catalog.fetch_pending_or_running_task_names_query(),
    ))
    .bind(JobStatus::Pending.as_str())
    .bind(JobStatus::Running.as_str())
    .fetch_all(executor)
    .await
    .map_err(DbError::query)?;
    let registered_task_names = registry.registered_task_name_set();
    let mut orphaned_task_names = task_names
        .into_iter()
        .filter(|task_name| !registered_task_names.contains(task_name))
        .collect::<Vec<_>>();
    orphaned_task_names.sort();
    Ok(orphaned_task_names)
}

pub(in crate::db::queue) async fn upsert_pause_key<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    pause_key: &str,
    task_name: Option<&str>,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_UPSERT_PAUSE_KEY,
        Some(sql_catalog.upsert_pause_key_query()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.upsert_pause_key_query()))
        .bind(pause_key)
        .bind(task_name)
        .execute(executor)
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::db::queue) async fn delete_pause_key<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    pause_key: &str,
) -> Result<(), Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::Execute,
        QUEUE_OPERATION_DELETE_PAUSE_KEY,
        Some(sql_catalog.delete_pause_key_query()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.delete_pause_key_query()))
        .bind(pause_key)
        .execute(executor)
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::db::queue) async fn fetch_pause_key_exists<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    pause_key: &str,
) -> Result<bool, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_FETCH_PAUSE_KEY_EXISTS,
        Some(sql_catalog.pause_key_exists_query()),
    );
    let exists =
        pooler_safe_query_scalar::<bool>(sqlx::AssertSqlSafe(sql_catalog.pause_key_exists_query()))
            .bind(pause_key)
            .fetch_one(executor)
            .await
            .map_err(DbError::query)?;
    Ok(exists)
}
