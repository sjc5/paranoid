use super::*;

impl Store {
    /// Deletes a pending job by ID.
    pub async fn cancel_pending_job(&self, pool: &Pool, job_id: JobId) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .cancel_pending_job_in_current_transaction(&mut tx, job_id)
            .await;
        finish_queue_pool_transaction("cancel pending job", tx, result).await
    }

    /// Deletes a pending job by ID inside the caller's active transaction.
    pub async fn cancel_pending_job_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_job_state_transition(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog().cancel_pending_job_query(),
            QUEUE_OPERATION_CANCEL_PENDING_JOB,
            "cancel pending job",
            Error::JobNotPending,
            job_id,
        )
        .await
    }

    /// Resets one failed job to pending so it can be retried.
    pub async fn retry_failed_job(
        &self,
        pool: &Pool,
        job_id: JobId,
        run_at_or_after: Option<JobRunAtOrAfter>,
    ) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .retry_failed_job_in_current_transaction(&mut tx, job_id, run_at_or_after)
            .await;
        finish_queue_pool_transaction("retry failed job", tx, result).await
    }

    /// Resets one failed job to pending inside the caller's active transaction.
    pub async fn retry_failed_job_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        run_at_or_after: Option<JobRunAtOrAfter>,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_retry_failed_job(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_id,
            run_at_or_after.map(JobRunAtOrAfter::as_unix_microseconds),
        )
        .await
    }

    /// Resets up to `limit` currently available failed jobs to pending.
    pub async fn retry_available_failed_jobs(
        &self,
        pool: &Pool,
        optional_task_name: Option<&str>,
        limit: u32,
        run_at_or_after: Option<JobRunAtOrAfter>,
    ) -> Result<u64, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        validate_retry_available_failed_jobs_limit(limit)?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .retry_available_failed_jobs_in_current_transaction(
                &mut tx,
                optional_task_name,
                limit,
                run_at_or_after,
            )
            .await;
        finish_queue_pool_transaction("retry available failed jobs", tx, result).await
    }

    /// Resets available failed jobs to pending inside the caller's active transaction.
    pub async fn retry_available_failed_jobs_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        optional_task_name: Option<&str>,
        limit: u32,
        run_at_or_after: Option<JobRunAtOrAfter>,
    ) -> Result<u64, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        validate_retry_available_failed_jobs_limit(limit)?;
        let run_at_or_after_unix_microseconds =
            run_at_or_after.map(JobRunAtOrAfter::as_unix_microseconds);
        let database_operation_observer = tx.database_operation_observer().cloned();
        for attempt_index in 0..5 {
            record_database_operation(
                database_operation_observer.as_ref(),
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                Some("SAVEPOINT __paranoid_queue_retry_available_failed_jobs"),
            );
            pooler_safe_query("SAVEPOINT __paranoid_queue_retry_available_failed_jobs")
                .execute(tx.inner.as_mut())
                .await
                .map_err(DbError::query)?;
            record_database_operation(
                database_operation_observer.as_ref(),
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                Some(self.sql_catalog().retry_available_failed_jobs_query()),
            );
            let result = pooler_safe_query(sqlx::AssertSqlSafe(
                self.sql_catalog().retry_available_failed_jobs_query(),
            ))
            .bind(JobStatus::Failed.as_str())
            .bind(i64::from(limit))
            .bind(JobStatus::Pending.as_str())
            .bind(run_at_or_after_unix_microseconds)
            .bind(optional_task_name)
            .execute(tx.inner.as_mut())
            .await;
            match result {
                Ok(done) => {
                    record_database_operation(
                        database_operation_observer.as_ref(),
                        DatabaseOperationKind::Execute,
                        QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                        Some("RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs"),
                    );
                    pooler_safe_query(
                        "RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
                    )
                    .execute(tx.inner.as_mut())
                    .await
                    .map_err(DbError::query)?;
                    return Ok(done.rows_affected());
                }
                Err(error)
                    if sqlx_error_is_active_dedupe_unique_violation(&error, &self.config) =>
                {
                    record_database_operation(
                        database_operation_observer.as_ref(),
                        DatabaseOperationKind::Execute,
                        QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                        Some("ROLLBACK TO SAVEPOINT __paranoid_queue_retry_available_failed_jobs"),
                    );
                    pooler_safe_query(
                        "ROLLBACK TO SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
                    )
                    .execute(tx.inner.as_mut())
                    .await
                    .map_err(DbError::query)?;
                    record_database_operation(
                        database_operation_observer.as_ref(),
                        DatabaseOperationKind::Execute,
                        QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                        Some("RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs"),
                    );
                    pooler_safe_query(
                        "RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
                    )
                    .execute(tx.inner.as_mut())
                    .await
                    .map_err(DbError::query)?;
                    if attempt_index < 4 {
                        continue;
                    }
                    return Err(Error::RetryConflictWithActiveDedupeJob);
                }
                Err(error) => {
                    record_database_operation(
                        database_operation_observer.as_ref(),
                        DatabaseOperationKind::Execute,
                        QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                        Some("ROLLBACK TO SAVEPOINT __paranoid_queue_retry_available_failed_jobs"),
                    );
                    pooler_safe_query(
                        "ROLLBACK TO SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
                    )
                    .execute(tx.inner.as_mut())
                    .await
                    .map_err(DbError::query)?;
                    record_database_operation(
                        database_operation_observer.as_ref(),
                        DatabaseOperationKind::Execute,
                        QUEUE_OPERATION_RETRY_AVAILABLE_FAILED_JOBS,
                        Some("RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs"),
                    );
                    pooler_safe_query(
                        "RELEASE SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
                    )
                    .execute(tx.inner.as_mut())
                    .await
                    .map_err(DbError::query)?;
                    return Err(DbError::query(error).into());
                }
            }
        }
        Err(Error::UnexpectedOutcome {
            operation: "retry available failed jobs in current transaction",
            outcome: "retry loop exhausted".to_owned(),
        })
    }

    /// Moves a running job back to pending state.
    pub async fn force_requeue_running_job_by_id(
        &self,
        pool: &Pool,
        job_id: JobId,
    ) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .force_requeue_running_job_by_id_in_current_transaction(&mut tx, job_id)
            .await;
        finish_queue_pool_transaction("force requeue running job", tx, result).await
    }

    /// Moves a running job back to pending inside the caller's active transaction.
    pub async fn force_requeue_running_job_by_id_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_job_state_transition_for_expected_status(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            ExpectedJobStateTransition {
                statement: self.sql_catalog().force_requeue_running_job_by_id_query(),
                database_operation_label: QUEUE_OPERATION_FORCE_REQUEUE_RUNNING_JOB,
                operation: "force requeue running job",
                expected_status: JobStatus::Running,
                state_mismatch_error: Error::JobNotRunning,
                job_id,
            },
        )
        .await
    }

    /// Atomically moves a failed job into dead-letter storage.
    pub async fn move_failed_job_to_dead_letter(
        &self,
        pool: &Pool,
        job_id: JobId,
        reason: DeadLetterReason,
    ) -> Result<JobId, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .move_failed_job_to_dead_letter_in_current_transaction(&mut tx, job_id, reason)
            .await;
        finish_queue_pool_transaction("move failed job to dead letter", tx, result).await
    }

    /// Moves a failed job into dead-letter storage inside the caller's active transaction.
    pub async fn move_failed_job_to_dead_letter_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        reason: DeadLetterReason,
    ) -> Result<JobId, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        move_failed_job_to_dead_letter(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_id,
            reason,
        )
        .await
    }

    /// Moves available failed jobs into dead-letter storage in one bounded batch.
    pub async fn move_failed_jobs_to_dead_letter_batch(
        &self,
        pool: &Pool,
        job_ids: &[JobId],
        reason: DeadLetterReason,
    ) -> Result<MoveFailedJobsToDeadLetterBatchResult, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        let result = move_failed_jobs_to_dead_letter_batch(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_ids,
            reason,
        )
        .await;
        finish_queue_pool_transaction("move failed jobs to dead letter batch", tx, result).await
    }

    /// Moves available failed jobs into dead-letter storage inside the caller's transaction.
    pub async fn move_failed_jobs_to_dead_letter_batch_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_ids: &[JobId],
        reason: DeadLetterReason,
    ) -> Result<MoveFailedJobsToDeadLetterBatchResult, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        move_failed_jobs_to_dead_letter_batch(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_ids,
            reason,
        )
        .await
    }
}
