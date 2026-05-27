use super::*;

impl Store {
    /// Begins a manual worker lifecycle.
    pub fn begin_manual_worker_lifecycle(&self) -> ManualWorkerProtocol<'_> {
        ManualWorkerProtocol { queue: self }
    }

    /// Claims due pending jobs for the supplied registered task names.
    pub(crate) async fn claim_available_jobs_for_worker(
        &self,
        pool: &Pool,
        registered_task_names: &[String],
        claim_limit: u32,
        worker_id: impl AsRef<str>,
    ) -> Result<Vec<Job>, Error> {
        validate_registered_task_names(registered_task_names)?;
        validate_claim_limit(claim_limit)?;
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .claim_available_jobs_for_worker_in_current_transaction(
                &mut tx,
                registered_task_names,
                claim_limit,
                worker_id,
            )
            .await;
        finish_queue_pool_transaction("claim available jobs for worker", tx, result).await
    }

    /// Claims due pending jobs inside the caller's active transaction.
    pub(crate) async fn claim_available_jobs_for_worker_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        registered_task_names: &[String],
        claim_limit: u32,
        worker_id: impl AsRef<str>,
    ) -> Result<Vec<Job>, Error> {
        validate_registered_task_names(registered_task_names)?;
        validate_claim_limit(claim_limit)?;
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        claim_available_jobs_for_worker(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            registered_task_names,
            claim_limit,
            worker_id.as_ref(),
        )
        .await
    }

    /// Marks an owned running job as started.
    pub(crate) async fn mark_owned_running_job_started(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .mark_owned_running_job_started_in_current_transaction(&mut tx, job_id, worker_id)
            .await;
        finish_queue_pool_transaction("mark owned running job started", tx, result).await
    }

    /// Marks an owned running job as started inside the caller's active transaction.
    pub(crate) async fn mark_owned_running_job_started_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_owned_running_job_update(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog().mark_job_started_query(),
            QUEUE_OPERATION_MARK_JOB_STARTED,
            "mark owned running job started",
            Error::JobNotRunning,
            job_id,
            worker_id.as_ref(),
        )
        .await
    }

    /// Marks an owned running job as completed.
    pub(crate) async fn mark_owned_running_job_completed(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .mark_owned_running_job_completed_in_current_transaction(&mut tx, job_id, worker_id)
            .await;
        finish_queue_pool_transaction("mark owned running job completed", tx, result).await
    }

    /// Marks an owned running job as completed inside the caller's active transaction.
    pub(crate) async fn mark_owned_running_job_completed_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_owned_running_job_update(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog().mark_job_completed_query(),
            QUEUE_OPERATION_MARK_JOB_COMPLETED,
            "mark owned running job completed",
            Error::JobNotRunning,
            job_id,
            worker_id.as_ref(),
        )
        .await
    }

    /// Records an execution heartbeat for an owned running job.
    pub(crate) async fn touch_owned_running_job_execution_heartbeat(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .touch_owned_running_job_execution_heartbeat_in_current_transaction(
                &mut tx, job_id, worker_id,
            )
            .await;
        finish_queue_pool_transaction("touch owned running job heartbeat", tx, result).await
    }

    /// Records an execution heartbeat inside the caller's active transaction.
    pub(crate) async fn touch_owned_running_job_execution_heartbeat_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_owned_running_job_update(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog().touch_execution_heartbeat_query(),
            QUEUE_OPERATION_TOUCH_JOB_HEARTBEAT,
            "touch owned running job heartbeat",
            Error::JobNotRunning,
            job_id,
            worker_id.as_ref(),
        )
        .await
    }

    /// Schedules an owned running job for retry and clears worker ownership.
    pub(crate) async fn schedule_owned_running_job_retry(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
        new_retry_count: u32,
        retry_after: Duration,
        error_message: impl AsRef<str>,
    ) -> Result<i64, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .schedule_owned_running_job_retry_in_current_transaction(
                &mut tx,
                job_id,
                worker_id,
                new_retry_count,
                retry_after,
                error_message,
            )
            .await;
        finish_queue_pool_transaction("schedule owned running job retry", tx, result).await
    }

    /// Schedules an owned running job for retry inside the caller's active transaction.
    pub(crate) async fn schedule_owned_running_job_retry_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
        new_retry_count: u32,
        retry_after: Duration,
        error_message: impl AsRef<str>,
    ) -> Result<i64, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let new_retry_count = new_retry_count
            .try_into()
            .map_err(|_| Error::InvalidMaxRetries)?;
        let retry_after_microseconds = retry_backoff_to_microseconds(retry_after)?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        schedule_owned_running_job_retry(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_id,
            worker_id.as_ref(),
            new_retry_count,
            retry_after_microseconds,
            error_message.as_ref(),
        )
        .await
    }

    /// Marks an owned running job as failed.
    pub(crate) async fn mark_owned_running_job_failed(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .mark_owned_running_job_failed_in_current_transaction(
                &mut tx,
                job_id,
                worker_id,
                error_message,
                increment_retry_count,
            )
            .await;
        finish_queue_pool_transaction("mark owned running job failed", tx, result).await
    }

    /// Marks an owned running job as failed inside the caller's active transaction.
    pub(crate) async fn mark_owned_running_job_failed_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_mark_owned_running_job_failed(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_id,
            worker_id.as_ref(),
            error_message.as_ref(),
            increment_retry_count,
        )
        .await
    }

    /// Moves an owned running job into dead-letter storage.
    pub(crate) async fn move_owned_running_job_to_dead_letter(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
        reason: DeadLetterReason,
    ) -> Result<JobId, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .move_owned_running_job_to_dead_letter_in_current_transaction(
                &mut tx,
                job_id,
                worker_id,
                error_message,
                increment_retry_count,
                reason,
            )
            .await;
        finish_queue_pool_transaction("move owned running job to dead letter", tx, result).await
    }

    /// Moves an owned running job into dead-letter storage inside the caller's active transaction.
    pub(crate) async fn move_owned_running_job_to_dead_letter_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
        reason: DeadLetterReason,
    ) -> Result<JobId, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        move_owned_running_job_to_dead_letter(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_id,
            worker_id.as_ref(),
            error_message.as_ref(),
            increment_retry_count,
            reason,
        )
        .await
    }

    /// Returns an owned running job to pending only if handler execution never started.
    pub(crate) async fn return_owned_unstarted_running_job_to_pending(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .return_owned_unstarted_running_job_to_pending_in_current_transaction(
                &mut tx, job_id, worker_id,
            )
            .await;
        finish_queue_pool_transaction("return owned unstarted running job to pending", tx, result)
            .await
    }

    /// Returns an owned unstarted running job to pending inside the caller's active transaction.
    pub(crate) async fn return_owned_unstarted_running_job_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_owned_running_job_update(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog()
                .return_owned_unstarted_running_job_to_pending_query(),
            QUEUE_OPERATION_RETURN_OWNED_UNSTARTED_JOB,
            "return owned unstarted running job to pending",
            Error::JobNotRunning,
            job_id,
            worker_id.as_ref(),
        )
        .await
    }

    /// Returns an owned running job to pending only if handler execution started.
    pub(crate) async fn return_owned_started_running_job_to_pending(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .return_owned_started_running_job_to_pending_in_current_transaction(
                &mut tx, job_id, worker_id,
            )
            .await;
        finish_queue_pool_transaction("return owned started running job to pending", tx, result)
            .await
    }

    /// Returns an owned started running job to pending inside the caller's active transaction.
    pub(crate) async fn return_owned_started_running_job_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_id: impl AsRef<str>,
    ) -> Result<(), Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_owned_running_job_update(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog()
                .return_owned_started_running_job_to_pending_query(),
            QUEUE_OPERATION_RETURN_OWNED_STARTED_JOB,
            "return owned started running job to pending",
            Error::JobNotRunning,
            job_id,
            worker_id.as_ref(),
        )
        .await
    }

    /// Returns currently available unstarted running jobs owned by a worker to pending.
    pub(crate) async fn return_available_owned_unstarted_running_jobs_to_pending(
        &self,
        pool: &Pool,
        worker_id: impl AsRef<str>,
    ) -> Result<u64, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
                &mut tx, worker_id,
            )
            .await;
        finish_queue_pool_transaction(
            "return available owned unstarted running jobs to pending",
            tx,
            result,
        )
        .await
    }

    /// Returns available unstarted running jobs inside the caller's active transaction.
    pub(crate) async fn return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        worker_id: impl AsRef<str>,
    ) -> Result<u64, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        return_available_owned_running_jobs_to_pending(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog()
                .return_available_owned_unstarted_running_jobs_to_pending_query(),
            QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_UNSTARTED_JOBS,
            worker_id.as_ref(),
        )
        .await
    }

    /// Returns currently available started running jobs owned by a worker to pending.
    pub(crate) async fn return_available_owned_started_running_jobs_to_pending(
        &self,
        pool: &Pool,
        worker_id: impl AsRef<str>,
    ) -> Result<u64, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .return_available_owned_started_running_jobs_to_pending_in_current_transaction(
                &mut tx, worker_id,
            )
            .await;
        finish_queue_pool_transaction(
            "return available owned started running jobs to pending",
            tx,
            result,
        )
        .await
    }

    /// Returns available started running jobs inside the caller's active transaction.
    pub(crate) async fn return_available_owned_started_running_jobs_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        worker_id: impl AsRef<str>,
    ) -> Result<u64, Error> {
        validate_worker_owner_id(worker_id.as_ref())?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        return_available_owned_running_jobs_to_pending(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog()
                .return_available_owned_started_running_jobs_to_pending_query(),
            QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_STARTED_JOBS,
            worker_id.as_ref(),
        )
        .await
    }
}

impl ManualWorkerProtocol<'_> {
    /// Claims due pending jobs for the supplied registered task names and worker owner ID.
    pub async fn claim_available_jobs_for_worker_owner(
        &self,
        pool: &Pool,
        registered_task_names: &[String],
        claim_limit: u32,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<Vec<Job>, Error> {
        self.queue
            .claim_available_jobs_for_worker(
                pool,
                registered_task_names,
                claim_limit,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Claims due pending jobs for a worker owner ID inside the caller's active transaction.
    pub async fn claim_available_jobs_for_worker_owner_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        registered_task_names: &[String],
        claim_limit: u32,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<Vec<Job>, Error> {
        self.queue
            .claim_available_jobs_for_worker_in_current_transaction(
                tx,
                registered_task_names,
                claim_limit,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Marks an owned running job as started.
    pub async fn mark_owned_running_job_started(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .mark_owned_running_job_started(pool, job_id, worker_owner_id.as_str())
            .await
    }

    /// Marks an owned running job as started inside the caller's active transaction.
    pub async fn mark_owned_running_job_started_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .mark_owned_running_job_started_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Marks an owned running job as completed.
    pub async fn mark_owned_running_job_completed(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .mark_owned_running_job_completed(pool, job_id, worker_owner_id.as_str())
            .await
    }

    /// Marks an owned running job as completed inside the caller's active transaction.
    pub async fn mark_owned_running_job_completed_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .mark_owned_running_job_completed_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Records an execution heartbeat for an owned running job.
    pub async fn touch_owned_running_job_execution_heartbeat(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .touch_owned_running_job_execution_heartbeat(pool, job_id, worker_owner_id.as_str())
            .await
    }

    /// Records an execution heartbeat inside the caller's active transaction.
    pub async fn touch_owned_running_job_execution_heartbeat_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .touch_owned_running_job_execution_heartbeat_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Schedules an owned running job for retry and clears worker ownership.
    pub async fn schedule_owned_running_job_retry(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
        new_retry_count: u32,
        retry_after: Duration,
        error_message: impl AsRef<str>,
    ) -> Result<i64, Error> {
        self.queue
            .schedule_owned_running_job_retry(
                pool,
                job_id,
                worker_owner_id.as_str(),
                new_retry_count,
                retry_after,
                error_message,
            )
            .await
    }

    /// Schedules an owned running job for retry inside the caller's active transaction.
    pub async fn schedule_owned_running_job_retry_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
        new_retry_count: u32,
        retry_after: Duration,
        error_message: impl AsRef<str>,
    ) -> Result<i64, Error> {
        self.queue
            .schedule_owned_running_job_retry_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
                new_retry_count,
                retry_after,
                error_message,
            )
            .await
    }

    /// Marks an owned running job as failed.
    pub async fn mark_owned_running_job_failed(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
    ) -> Result<(), Error> {
        self.queue
            .mark_owned_running_job_failed(
                pool,
                job_id,
                worker_owner_id.as_str(),
                error_message,
                increment_retry_count,
            )
            .await
    }

    /// Marks an owned running job as failed inside the caller's active transaction.
    pub async fn mark_owned_running_job_failed_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
    ) -> Result<(), Error> {
        self.queue
            .mark_owned_running_job_failed_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
                error_message,
                increment_retry_count,
            )
            .await
    }

    /// Moves an owned running job into dead-letter storage.
    pub async fn move_owned_running_job_to_dead_letter(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
        reason: DeadLetterReason,
    ) -> Result<JobId, Error> {
        self.queue
            .move_owned_running_job_to_dead_letter(
                pool,
                job_id,
                worker_owner_id.as_str(),
                error_message,
                increment_retry_count,
                reason,
            )
            .await
    }

    /// Moves an owned running job into dead-letter storage inside the caller's active transaction.
    pub async fn move_owned_running_job_to_dead_letter_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
        error_message: impl AsRef<str>,
        increment_retry_count: bool,
        reason: DeadLetterReason,
    ) -> Result<JobId, Error> {
        self.queue
            .move_owned_running_job_to_dead_letter_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
                error_message,
                increment_retry_count,
                reason,
            )
            .await
    }

    /// Returns an owned running job to pending only if handler execution never started.
    pub async fn return_owned_unstarted_running_job_to_pending(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .return_owned_unstarted_running_job_to_pending(pool, job_id, worker_owner_id.as_str())
            .await
    }

    /// Returns an owned unstarted running job to pending inside the caller's active transaction.
    pub async fn return_owned_unstarted_running_job_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .return_owned_unstarted_running_job_to_pending_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Returns an owned running job to pending only if handler execution started.
    pub async fn return_owned_started_running_job_to_pending(
        &self,
        pool: &Pool,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .return_owned_started_running_job_to_pending(pool, job_id, worker_owner_id.as_str())
            .await
    }

    /// Returns an owned started running job to pending inside the caller's active transaction.
    pub async fn return_owned_started_running_job_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<(), Error> {
        self.queue
            .return_owned_started_running_job_to_pending_in_current_transaction(
                tx,
                job_id,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Returns currently available unstarted running jobs owned by a worker to pending.
    pub async fn return_available_owned_unstarted_running_jobs_to_pending(
        &self,
        pool: &Pool,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<u64, Error> {
        self.queue
            .return_available_owned_unstarted_running_jobs_to_pending(
                pool,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Returns available unstarted running jobs inside the caller's active transaction.
    pub async fn return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<u64, Error> {
        self.queue
            .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
                tx,
                worker_owner_id.as_str(),
            )
            .await
    }

    /// Returns currently available started running jobs owned by a worker to pending.
    pub async fn return_available_owned_started_running_jobs_to_pending(
        &self,
        pool: &Pool,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<u64, Error> {
        self.queue
            .return_available_owned_started_running_jobs_to_pending(pool, worker_owner_id.as_str())
            .await
    }

    /// Returns available started running jobs inside the caller's active transaction.
    pub async fn return_available_owned_started_running_jobs_to_pending_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        worker_owner_id: &WorkerOwnerId,
    ) -> Result<u64, Error> {
        self.queue
            .return_available_owned_started_running_jobs_to_pending_in_current_transaction(
                tx,
                worker_owner_id.as_str(),
            )
            .await
    }
}
