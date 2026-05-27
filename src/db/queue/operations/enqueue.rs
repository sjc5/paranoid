use super::*;

pub(in crate::db::queue) async fn execute_enqueue_in_current_transaction(
    tx: &mut Tx<'_>,
    sql_catalog: &SqlCatalog,
    prepared: PreparedEnqueue,
) -> Result<EnqueueResult, Error> {
    let database_operation_observer = tx.database_operation_observer().cloned();
    if prepared.dedupe_key.is_some() {
        execute_dedupe_enqueue_in_current_transaction(tx, sql_catalog, prepared).await
    } else {
        execute_non_dedupe_enqueue(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            sql_catalog,
            prepared,
        )
        .await
    }
}

pub(in crate::db::queue) async fn execute_batch_enqueue<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    prepared: PreparedEnqueueBatch,
) -> Result<Vec<EnqueueResult>, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    if prepared.jobs.is_empty() {
        return Ok(Vec::new());
    }

    let statement = sql_catalog.batch_enqueue_query(prepared.jobs.len());
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_BATCH_ENQUEUE,
        Some(statement.as_ref()),
    );
    let mut query = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_ref()));
    for job in &prepared.jobs {
        query = query.bind(job.job_id.as_bytes()).bind(&job.payload_json);
    }
    let task_pause_key = paused_task_key(&prepared.task_name);
    let row = query
        .bind(&prepared.task_name)
        .bind(JobStatus::Pending.as_str())
        .bind(prepared.run_at_or_after_unix_microseconds)
        .bind(prepared.max_retries)
        .bind(prepared.timeout_nanos)
        .bind(GLOBAL_PAUSE_KEY)
        .bind(task_pause_key)
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

    let inserted_count: i64 = row.try_get("inserted_count").map_err(Error::decode_row)?;
    let outcome: String = row.try_get("insert_outcome").map_err(Error::decode_row)?;
    queue_batch_enqueue_results_from_insert_outcome(prepared.jobs, inserted_count, &outcome)
}

pub(in crate::db::queue) async fn execute_non_dedupe_enqueue<'e, E>(
    executor: E,
    database_operation_observer: Option<&DatabaseOperationObserver>,
    sql_catalog: &SqlCatalog,
    prepared: PreparedEnqueue,
) -> Result<EnqueueResult, Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    record_database_operation(
        database_operation_observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_ENQUEUE,
        Some(sql_catalog.single_enqueue_query()),
    );
    let row = pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.single_enqueue_query()))
        .bind(prepared.job_id.as_bytes())
        .bind(&prepared.task_name)
        .bind(&prepared.payload_json)
        .bind(JobStatus::Pending.as_str())
        .bind(prepared.run_at_or_after_unix_microseconds)
        .bind(prepared.max_retries)
        .bind(prepared.timeout_nanos)
        .bind(GLOBAL_PAUSE_KEY)
        .bind(paused_task_key(&prepared.task_name))
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

    let inserted_id: Option<Vec<u8>> = row.try_get("inserted_id").map_err(Error::decode_row)?;
    let outcome: String = row.try_get("insert_outcome").map_err(Error::decode_row)?;
    queue_enqueue_result_from_insert_outcome("enqueue", inserted_id, &outcome)
}

pub(in crate::db::queue) async fn execute_dedupe_enqueue_in_current_transaction(
    tx: &mut Tx<'_>,
    sql_catalog: &SqlCatalog,
    mut prepared: PreparedEnqueue,
) -> Result<EnqueueResult, Error> {
    let database_operation_observer = tx.database_operation_observer().cloned();
    for attempt_index in 0..MAX_QUEUE_DEDUPE_INSERT_ATTEMPTS {
        record_database_operation(
            database_operation_observer.as_ref(),
            DatabaseOperationKind::FetchOne,
            QUEUE_OPERATION_DEDUPE_ENQUEUE,
            Some(sql_catalog.dedupe_enqueue_query()),
        );
        let row = pooler_safe_query(sqlx::AssertSqlSafe(sql_catalog.dedupe_enqueue_query()))
            .bind(prepared.job_id.as_bytes())
            .bind(&prepared.task_name)
            .bind(&prepared.payload_json)
            .bind(JobStatus::Pending.as_str())
            .bind(prepared.run_at_or_after_unix_microseconds)
            .bind(prepared.max_retries)
            .bind(prepared.timeout_nanos)
            .bind(prepared.dedupe_key.as_deref())
            .bind(GLOBAL_PAUSE_KEY)
            .bind(paused_task_key(&prepared.task_name))
            .fetch_one(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?;

        let inserted_id: Option<Vec<u8>> = row.try_get("inserted_id").map_err(Error::decode_row)?;
        let existing_id: Option<Vec<u8>> = row.try_get("existing_id").map_err(Error::decode_row)?;
        let outcome: String = row.try_get("insert_outcome").map_err(Error::decode_row)?;
        match queue_dedupe_enqueue_result_from_insert_outcome(
            "dedupe enqueue",
            inserted_id,
            existing_id,
            &outcome,
        )? {
            DedupeEnqueueAttemptOutcome::Applied(result) => return Ok(result),
            DedupeEnqueueAttemptOutcome::RetryAfterInvisibleConflict => {
                if attempt_index + 1 < MAX_QUEUE_DEDUPE_INSERT_ATTEMPTS {
                    prepared.job_id = JobId::new()?;
                    continue;
                }
                return Err(Error::UnexpectedOutcome {
                    operation: "dedupe enqueue",
                    outcome: "not inserted without existing active job".to_owned(),
                });
            }
        }
    }

    Err(Error::UnexpectedOutcome {
        operation: "dedupe enqueue",
        outcome: "retry loop exhausted".to_owned(),
    })
}

pub(in crate::db::queue) enum DedupeEnqueueAttemptOutcome {
    Applied(EnqueueResult),
    RetryAfterInvisibleConflict,
}

pub(in crate::db::queue) fn queue_enqueue_result_from_insert_outcome(
    operation: &'static str,
    inserted_id: Option<Vec<u8>>,
    outcome: &str,
) -> Result<EnqueueResult, Error> {
    match outcome {
        ENQUEUE_OUTCOME_INSERTED => {
            let id_bytes = inserted_id.ok_or_else(|| Error::UnexpectedOutcome {
                operation,
                outcome: "inserted without id".to_owned(),
            })?;
            Ok(EnqueueResult {
                job_id: JobId::from_bytes(&id_bytes)?,
                deduplicated: false,
            })
        }
        ENQUEUE_OUTCOME_QUEUE_PAUSED => Err(Error::QueuePaused),
        ENQUEUE_OUTCOME_TASK_PAUSED => Err(Error::TaskPaused),
        other => Err(Error::UnexpectedOutcome {
            operation,
            outcome: other.to_owned(),
        }),
    }
}

pub(in crate::db::queue) fn queue_dedupe_enqueue_result_from_insert_outcome(
    operation: &'static str,
    inserted_id: Option<Vec<u8>>,
    existing_id: Option<Vec<u8>>,
    outcome: &str,
) -> Result<DedupeEnqueueAttemptOutcome, Error> {
    match outcome {
        ENQUEUE_OUTCOME_INSERTED => queue_enqueue_result_from_insert_outcome(
            operation,
            inserted_id,
            ENQUEUE_OUTCOME_INSERTED,
        )
        .map(DedupeEnqueueAttemptOutcome::Applied),
        ENQUEUE_OUTCOME_NOT_INSERTED => {
            if let Some(id_bytes) = existing_id {
                return Ok(DedupeEnqueueAttemptOutcome::Applied(EnqueueResult {
                    job_id: JobId::from_bytes(&id_bytes)?,
                    deduplicated: true,
                }));
            }
            Ok(DedupeEnqueueAttemptOutcome::RetryAfterInvisibleConflict)
        }
        ENQUEUE_OUTCOME_QUEUE_PAUSED => Err(Error::QueuePaused),
        ENQUEUE_OUTCOME_TASK_PAUSED => Err(Error::TaskPaused),
        other => Err(Error::UnexpectedOutcome {
            operation,
            outcome: other.to_owned(),
        }),
    }
}

pub(in crate::db::queue) fn queue_batch_enqueue_results_from_insert_outcome(
    jobs: Vec<PreparedBatchEnqueueJob>,
    inserted_count: i64,
    outcome: &str,
) -> Result<Vec<EnqueueResult>, Error> {
    match outcome {
        ENQUEUE_OUTCOME_INSERTED if inserted_count == jobs.len() as i64 => Ok(jobs
            .into_iter()
            .map(|job| EnqueueResult {
                job_id: job.job_id,
                deduplicated: false,
            })
            .collect()),
        ENQUEUE_OUTCOME_INSERTED => Err(Error::UnexpectedOutcome {
            operation: "batch enqueue",
            outcome: format!("inserted {inserted_count} rows, expected {}", jobs.len()),
        }),
        ENQUEUE_OUTCOME_QUEUE_PAUSED => Err(Error::QueuePaused),
        ENQUEUE_OUTCOME_TASK_PAUSED => Err(Error::TaskPaused),
        other => Err(Error::UnexpectedOutcome {
            operation: "batch enqueue",
            outcome: other.to_owned(),
        }),
    }
}
