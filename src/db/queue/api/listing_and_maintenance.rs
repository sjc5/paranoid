use super::*;

impl Store {
    /// Lists jobs ordered by ID with cursor pagination.
    pub async fn list_jobs(
        &self,
        pool: &Pool,
        options: ListJobsOptions,
    ) -> Result<ListJobsResult, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .list_jobs_in_current_transaction(&mut tx, options)
            .await;
        finish_queue_read_transaction("list jobs", tx, result).await
    }

    /// Lists jobs inside the caller's active transaction.
    pub async fn list_jobs_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        options: ListJobsOptions,
    ) -> Result<ListJobsResult, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        list_jobs(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            options,
        )
        .await
    }

    /// Lists dead-letter jobs ordered by ID with cursor pagination.
    pub async fn list_dead_letter_jobs(
        &self,
        pool: &Pool,
        options: ListDeadLetterJobsOptions,
    ) -> Result<ListDeadLetterJobsResult, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .list_dead_letter_jobs_in_current_transaction(&mut tx, options)
            .await;
        finish_queue_read_transaction("list dead letter jobs", tx, result).await
    }

    /// Lists dead-letter jobs inside the caller's active transaction.
    pub async fn list_dead_letter_jobs_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        options: ListDeadLetterJobsOptions,
    ) -> Result<ListDeadLetterJobsResult, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        list_dead_letter_jobs(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            options,
        )
        .await
    }

    /// Requeues one dead-letter job as a new pending job.
    pub async fn requeue_dead_letter_job(
        &self,
        pool: &WritePool,
        dead_letter_job_id: JobId,
        run_at_or_after: Option<JobRunAtOrAfter>,
    ) -> Result<JobId, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .requeue_dead_letter_job_in_current_transaction(
                &mut tx,
                dead_letter_job_id,
                run_at_or_after,
            )
            .await;
        finish_queue_pool_transaction("requeue dead letter job", tx, result).await
    }

    /// Requeues one dead-letter job inside the caller's active transaction.
    pub async fn requeue_dead_letter_job_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        dead_letter_job_id: JobId,
        run_at_or_after: Option<JobRunAtOrAfter>,
    ) -> Result<JobId, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        requeue_dead_letter_job(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            dead_letter_job_id,
            run_at_or_after.map(JobRunAtOrAfter::as_unix_microseconds),
        )
        .await
    }

    /// Deletes one dead-letter row.
    pub async fn delete_dead_letter_job(
        &self,
        pool: &WritePool,
        dead_letter_job_id: JobId,
    ) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .delete_dead_letter_job_in_current_transaction(&mut tx, dead_letter_job_id)
            .await;
        finish_queue_pool_transaction("delete dead letter job", tx, result).await
    }

    /// Deletes one dead-letter row inside the caller's active transaction.
    pub async fn delete_dead_letter_job_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        dead_letter_job_id: JobId,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        delete_dead_letter_job(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            dead_letter_job_id,
        )
        .await
    }

    /// Deletes one bounded batch of available completed jobs older than `older_than`.
    pub async fn cleanup_available_completed_jobs_older_than_once(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .cleanup_available_completed_jobs_older_than_once_in_current_transaction(
                &mut tx, older_than, batch_size,
            )
            .await;
        finish_queue_pool_transaction("cleanup completed jobs once", tx, result).await
    }

    /// Deletes available completed jobs older than `older_than` in bounded batches until no full batch remains.
    pub async fn cleanup_available_completed_jobs_older_than_until_empty(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
        delay_between_batches: Duration,
    ) -> Result<u64, Error> {
        cleanup_jobs_older_than_until_empty(
            pool,
            self.sql_catalog(),
            JobStatus::Completed,
            older_than,
            batch_size,
            delay_between_batches,
        )
        .await
    }

    pub(in crate::db::queue) async fn cleanup_available_completed_jobs_older_than_until_empty_or_cancelled(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
        delay_between_batches: Duration,
        cancellation_signal: &RuntimeCancellationSignal,
    ) -> Result<u64, Error> {
        cleanup_jobs_older_than_until_empty_or_cancelled(
            pool,
            self.sql_catalog(),
            JobStatus::Completed,
            older_than,
            batch_size,
            delay_between_batches,
            cancellation_signal,
        )
        .await
    }

    /// Deletes one bounded completed-job cleanup batch inside the caller's transaction.
    pub async fn cleanup_available_completed_jobs_older_than_once_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        older_than: Duration,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        cleanup_jobs_older_than_once(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            JobStatus::Completed,
            older_than,
            batch_size,
        )
        .await
    }

    /// Deletes one bounded batch of available failed jobs older than `older_than`.
    pub async fn cleanup_available_failed_jobs_older_than_once(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .cleanup_available_failed_jobs_older_than_once_in_current_transaction(
                &mut tx, older_than, batch_size,
            )
            .await;
        finish_queue_pool_transaction("cleanup failed jobs once", tx, result).await
    }

    /// Deletes available failed jobs older than `older_than` in bounded batches until no full batch remains.
    pub async fn cleanup_available_failed_jobs_older_than_until_empty(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
        delay_between_batches: Duration,
    ) -> Result<u64, Error> {
        cleanup_jobs_older_than_until_empty(
            pool,
            self.sql_catalog(),
            JobStatus::Failed,
            older_than,
            batch_size,
            delay_between_batches,
        )
        .await
    }

    pub(in crate::db::queue) async fn cleanup_available_failed_jobs_older_than_until_empty_or_cancelled(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
        delay_between_batches: Duration,
        cancellation_signal: &RuntimeCancellationSignal,
    ) -> Result<u64, Error> {
        cleanup_jobs_older_than_until_empty_or_cancelled(
            pool,
            self.sql_catalog(),
            JobStatus::Failed,
            older_than,
            batch_size,
            delay_between_batches,
            cancellation_signal,
        )
        .await
    }

    /// Deletes one bounded failed-job cleanup batch inside the caller's transaction.
    pub async fn cleanup_available_failed_jobs_older_than_once_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        older_than: Duration,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        cleanup_jobs_older_than_once(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            JobStatus::Failed,
            older_than,
            batch_size,
        )
        .await
    }

    /// Deletes one bounded batch of available dead-letter jobs older than `older_than`.
    pub async fn cleanup_available_dead_letter_jobs_older_than_once(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction(
                &mut tx, older_than, batch_size,
            )
            .await;
        finish_queue_pool_transaction("cleanup dead letter jobs once", tx, result).await
    }

    /// Deletes available dead-letter jobs older than `older_than` in bounded batches until no full batch remains.
    pub async fn cleanup_available_dead_letter_jobs_older_than_until_empty(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
        delay_between_batches: Duration,
    ) -> Result<u64, Error> {
        cleanup_available_dead_letter_jobs_older_than_until_empty(
            pool,
            self.sql_catalog(),
            older_than,
            batch_size,
            delay_between_batches,
        )
        .await
    }

    pub(in crate::db::queue) async fn cleanup_available_dead_letter_jobs_older_than_until_empty_or_cancelled(
        &self,
        pool: &WritePool,
        older_than: Duration,
        batch_size: u32,
        delay_between_batches: Duration,
        cancellation_signal: &RuntimeCancellationSignal,
    ) -> Result<u64, Error> {
        cleanup_available_dead_letter_jobs_older_than_until_empty_or_cancelled(
            pool,
            self.sql_catalog(),
            older_than,
            batch_size,
            delay_between_batches,
            cancellation_signal,
        )
        .await
    }

    /// Deletes one bounded dead-letter cleanup batch inside the caller's transaction.
    pub async fn cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        older_than: Duration,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        cleanup_available_dead_letter_jobs_older_than_once(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            older_than,
            batch_size,
        )
        .await
    }

    /// Reclaims available stale running jobs in one pass.
    pub async fn reclaim_available_stale_running_jobs_once(
        &self,
        pool: &WritePool,
        stale_threshold: Duration,
        reclaim_batch_size: u32,
        move_expired_max_retry_jobs_to_dead_letter: bool,
    ) -> Result<ReclaimStaleRunningJobsResult, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = reclaim_available_stale_running_jobs_once_in_current_transaction(
            &mut tx,
            self.sql_catalog(),
            stale_threshold,
            reclaim_batch_size,
            move_expired_max_retry_jobs_to_dead_letter,
        )
        .await;
        finish_queue_pool_transaction("reclaim stale running jobs once", tx, result).await
    }

    /// Reclaims available stale running jobs inside the caller's active transaction.
    pub async fn reclaim_available_stale_running_jobs_once_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        stale_threshold: Duration,
        reclaim_batch_size: u32,
        move_expired_max_retry_jobs_to_dead_letter: bool,
    ) -> Result<ReclaimStaleRunningJobsResult, Error> {
        reclaim_available_stale_running_jobs_once_in_current_transaction(
            tx,
            self.sql_catalog(),
            stale_threshold,
            reclaim_batch_size,
            move_expired_max_retry_jobs_to_dead_letter,
        )
        .await
    }
}
