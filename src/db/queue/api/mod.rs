use super::*;

mod listing_and_maintenance;
mod operator_transitions;
mod worker_runtime;
mod worker_transitions;

#[cfg(test)]
impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            table_name: PgQualifiedTableName::unqualified(TEST_QUEUE_JOBS_TABLE_NAME)
                .expect("test queue jobs table name must be valid"),
            dead_letter_table_name: PgQualifiedTableName::unqualified(
                TEST_QUEUE_DEAD_LETTER_TABLE_NAME,
            )
            .expect("test queue dead-letter table name must be valid"),
            pause_table_name: PgQualifiedTableName::unqualified(TEST_QUEUE_PAUSE_TABLE_NAME)
                .expect("test queue pause table name must be valid"),
            schema_ledger_table_name: test_schema_ledger_table_name(),
            payload_json_limit_bytes: DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
        }
    }
}

impl<T> Clone for RegisteredJsonTask<T> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            task_name: self.task_name.clone(),
            payload_type: PhantomData,
        }
    }
}

impl<T> RegisteredJsonTask<T> {
    /// Returns this task helper's registered task name.
    pub fn task_name(&self) -> &str {
        &self.task_name
    }
}

impl<T: Serialize> RegisteredJsonTask<T> {
    /// Enqueues this task's JSON payload.
    pub async fn enqueue(
        &self,
        pool: &WritePool,
        payload: &T,
        options: EnqueueOptions,
    ) -> Result<EnqueueResult, Error> {
        self.queue
            .enqueue_json(pool, &self.task_name, payload, options)
            .await
    }

    /// Enqueues this task's JSON payload inside the caller's active transaction.
    pub async fn enqueue_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        payload: &T,
        options: EnqueueOptions,
    ) -> Result<EnqueueResult, Error> {
        self.queue
            .enqueue_json_in_current_transaction(tx, &self.task_name, payload, options)
            .await
    }

    /// Enqueues multiple payloads for this task in one statement.
    pub async fn enqueue_batch(
        &self,
        pool: &WritePool,
        payloads: &[T],
        options: EnqueueBatchOptions,
    ) -> Result<Vec<EnqueueResult>, Error> {
        self.queue
            .enqueue_json_batch(pool, &self.task_name, payloads, options)
            .await
    }

    /// Enqueues multiple payloads for this task inside the caller's active transaction.
    pub async fn enqueue_batch_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        payloads: &[T],
        options: EnqueueBatchOptions,
    ) -> Result<Vec<EnqueueResult>, Error> {
        self.queue
            .enqueue_json_batch_in_current_transaction(tx, &self.task_name, payloads, options)
            .await
    }
}

impl StoreConfig {
    /// Creates a queue config from explicit table names.
    #[cfg(test)]
    pub(crate) fn new(
        table_name: PgQualifiedTableName,
        dead_letter_table_name: PgQualifiedTableName,
        pause_table_name: PgQualifiedTableName,
    ) -> Result<Self, Error> {
        let config = Self {
            table_name,
            dead_letter_table_name,
            pause_table_name,
            schema_ledger_table_name: test_schema_ledger_table_name(),
            payload_json_limit_bytes: DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
        };
        validate_store_config(&config)?;
        Ok(config)
    }
}

impl Store {
    /// Creates a queue using validated configuration.
    #[cfg(test)]
    pub(crate) fn new(config: StoreConfig) -> Result<Self, Error> {
        Self::new_inner(config)
    }

    pub(crate) fn new_inner(config: StoreConfig) -> Result<Self, Error> {
        validate_store_config(&config)?;
        Ok(Self {
            sql_catalog: Arc::new(SqlCatalog::new(&config)),
            config,
        })
    }

    pub(crate) fn config_inner(&self) -> &StoreConfig {
        &self.config
    }

    /// Returns this queue's configuration.
    #[cfg(test)]
    pub(crate) fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Registers a typed JSON handler and returns a queue-bound enqueue helper for that task.
    pub fn register_json_task_handler<T, F, Fut>(
        &self,
        task_registry: &mut TaskRegistry,
        task_name: impl AsRef<str>,
        handler: F,
    ) -> Result<RegisteredJsonTask<T>, Error>
    where
        T: DeserializeOwned + Send + 'static,
        F: Fn(JobExecutionContext, T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), TaskError>> + Send + 'static,
    {
        let task_name = task_name.as_ref();
        task_registry.register_json_task_handler(task_name, handler)?;
        Ok(RegisteredJsonTask {
            queue: self.clone(),
            task_name: task_name.to_owned(),
            payload_type: PhantomData,
        })
    }

    pub(super) fn sql_catalog(&self) -> &SqlCatalog {
        &self.sql_catalog
    }

    /// Runs idempotent schema migration and validates the result.
    #[cfg(test)]
    pub(crate) async fn migrate_schema(&self, pool: &WritePool) -> Result<(), Error> {
        migrate_schema(pool, &self.config).await
    }

    /// Runs schema migration inside the caller's active transaction.
    #[cfg(test)]
    pub(crate) async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        self.migrate_schema_in_current_transaction_inner(tx).await
    }

    pub(crate) async fn migrate_schema_in_current_transaction_inner(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        migrate_schema_in_current_transaction(tx, &self.config).await
    }

    /// Validates that the existing schema matches the queue contract.
    #[cfg(test)]
    pub(crate) async fn validate_schema(&self, pool: &WritePool) -> Result<(), Error> {
        validate_schema(pool, &self.config).await
    }

    /// Validates schema inside the caller's active transaction.
    #[cfg(test)]
    pub(crate) async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        self.validate_schema_in_current_transaction_inner(tx).await
    }

    #[cfg(test)]
    pub(crate) async fn validate_schema_in_current_transaction_inner(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        validate_schema_in_current_transaction(tx, &self.config).await
    }

    /// Enqueues a JSON-serializable payload.
    pub async fn enqueue_json<T: Serialize + ?Sized>(
        &self,
        pool: &WritePool,
        task_name: impl AsRef<str>,
        payload: &T,
        options: EnqueueOptions,
    ) -> Result<EnqueueResult, Error> {
        let prepared = PreparedEnqueue::new_with_payload_json_limit(
            task_name.as_ref(),
            payload,
            options,
            self.config.payload_json_limit_bytes,
        )?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result =
            execute_enqueue_in_current_transaction(&mut tx, self.sql_catalog(), prepared).await;
        finish_queue_pool_transaction("enqueue", tx, result).await
    }

    /// Enqueues a JSON-serializable payload inside the caller's active transaction.
    pub async fn enqueue_json_in_current_transaction<T: Serialize + ?Sized>(
        &self,
        tx: &mut WriteTx<'_>,
        task_name: impl AsRef<str>,
        payload: &T,
        options: EnqueueOptions,
    ) -> Result<EnqueueResult, Error> {
        let prepared = PreparedEnqueue::new_with_payload_json_limit(
            task_name.as_ref(),
            payload,
            options,
            self.config.payload_json_limit_bytes,
        )?;
        execute_enqueue_in_current_transaction(tx, self.sql_catalog(), prepared).await
    }

    /// Enqueues multiple JSON-serializable payloads for one task in one statement.
    pub async fn enqueue_json_batch<T: Serialize>(
        &self,
        pool: &WritePool,
        task_name: impl AsRef<str>,
        payloads: &[T],
        options: EnqueueBatchOptions,
    ) -> Result<Vec<EnqueueResult>, Error> {
        let prepared = PreparedEnqueueBatch::new_with_payload_json_limit(
            task_name.as_ref(),
            payloads,
            options,
            self.config.payload_json_limit_bytes,
        )?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        let result = execute_batch_enqueue(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            prepared,
        )
        .await;
        finish_queue_pool_transaction("batch enqueue", tx, result).await
    }

    /// Enqueues multiple JSON-serializable payloads inside the caller's active transaction.
    pub async fn enqueue_json_batch_in_current_transaction<T: Serialize>(
        &self,
        tx: &mut WriteTx<'_>,
        task_name: impl AsRef<str>,
        payloads: &[T],
        options: EnqueueBatchOptions,
    ) -> Result<Vec<EnqueueResult>, Error> {
        let prepared = PreparedEnqueueBatch::new_with_payload_json_limit(
            task_name.as_ref(),
            payloads,
            options,
            self.config.payload_json_limit_bytes,
        )?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        execute_batch_enqueue(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            prepared,
        )
        .await
    }

    /// Loads a job by ID.
    pub async fn fetch_job_by_id(&self, pool: &Pool, job_id: JobId) -> Result<Job, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_job_by_id_in_current_transaction(&mut tx, job_id)
            .await;
        finish_queue_read_transaction("fetch job by id", tx, result).await
    }

    /// Loads a job by ID inside the caller's active transaction.
    pub async fn fetch_job_by_id_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
    ) -> Result<Job, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_job_by_id(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            job_id,
        )
        .await
    }

    /// Returns a job's status.
    pub async fn fetch_job_status(&self, pool: &Pool, job_id: JobId) -> Result<JobStatus, Error> {
        let job = self.fetch_job_by_id(pool, job_id).await?;
        Ok(job.status)
    }

    /// Returns a job's status inside the caller's active transaction.
    pub async fn fetch_job_status_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        job_id: JobId,
    ) -> Result<JobStatus, Error> {
        let job = self
            .fetch_job_by_id_in_current_transaction(tx, job_id)
            .await?;
        Ok(job.status)
    }

    /// Returns aggregate queue counts, optionally scoped to one task.
    pub async fn fetch_status_counts(
        &self,
        pool: &Pool,
        optional_task_name: Option<&str>,
    ) -> Result<StatusCounts, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_status_counts_in_current_transaction(&mut tx, optional_task_name)
            .await;
        finish_queue_read_transaction("fetch status counts", tx, result).await
    }

    /// Returns aggregate queue counts inside the caller's active transaction.
    pub async fn fetch_status_counts_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        optional_task_name: Option<&str>,
    ) -> Result<StatusCounts, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_status_counts(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            optional_task_name,
        )
        .await
    }

    /// Returns the number of pending jobs, optionally scoped to one task.
    pub async fn fetch_pending_job_count(
        &self,
        pool: &Pool,
        optional_task_name: Option<&str>,
    ) -> Result<i64, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_pending_job_count_in_current_transaction(&mut tx, optional_task_name)
            .await;
        finish_queue_read_transaction("fetch pending job count", tx, result).await
    }

    /// Returns the number of pending jobs inside the caller's active transaction.
    pub async fn fetch_pending_job_count_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        optional_task_name: Option<&str>,
    ) -> Result<i64, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_job_count_by_status(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            JobStatus::Pending,
            optional_task_name,
        )
        .await
    }

    /// Returns the number of failed jobs, optionally scoped to one task.
    pub async fn fetch_failed_job_count(
        &self,
        pool: &Pool,
        optional_task_name: Option<&str>,
    ) -> Result<i64, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_failed_job_count_in_current_transaction(&mut tx, optional_task_name)
            .await;
        finish_queue_read_transaction("fetch failed job count", tx, result).await
    }

    /// Returns the number of failed jobs inside the caller's active transaction.
    pub async fn fetch_failed_job_count_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        optional_task_name: Option<&str>,
    ) -> Result<i64, Error> {
        if let Some(task_name) = optional_task_name {
            validate_task_name(task_name)?;
        }
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_job_count_by_status(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            JobStatus::Failed,
            optional_task_name,
        )
        .await
    }

    /// Pauses all enqueues and claims for this queue.
    pub async fn pause_queue(&self, pool: &WritePool) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self.pause_queue_in_current_transaction(&mut tx).await;
        finish_queue_pool_transaction("pause queue", tx, result).await
    }

    /// Pauses all enqueues and claims inside the caller's active transaction.
    pub async fn pause_queue_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        upsert_pause_key(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            GLOBAL_PAUSE_KEY,
            None,
        )
        .await
    }

    /// Resumes all enqueues and claims for this queue.
    pub async fn resume_queue(&self, pool: &WritePool) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self.resume_queue_in_current_transaction(&mut tx).await;
        finish_queue_pool_transaction("resume queue", tx, result).await
    }

    /// Resumes all enqueues and claims inside the caller's active transaction.
    pub async fn resume_queue_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        delete_pause_key(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            GLOBAL_PAUSE_KEY,
        )
        .await
    }

    /// Returns whether the queue is globally paused.
    pub async fn fetch_queue_is_paused(&self, pool: &Pool) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_queue_is_paused_in_current_transaction(&mut tx)
            .await;
        finish_queue_read_transaction("fetch queue is paused", tx, result).await
    }

    /// Returns whether the queue is globally paused inside the caller's active transaction.
    pub async fn fetch_queue_is_paused_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<bool, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_pause_key_exists(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            GLOBAL_PAUSE_KEY,
        )
        .await
    }

    /// Pauses enqueues and claims for one task.
    pub async fn pause_task(
        &self,
        pool: &WritePool,
        task_name: impl AsRef<str>,
    ) -> Result<(), Error> {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .pause_task_in_current_transaction(&mut tx, task_name)
            .await;
        finish_queue_pool_transaction("pause task", tx, result).await
    }

    /// Resumes enqueues and claims for one task.
    pub async fn resume_task(
        &self,
        pool: &WritePool,
        task_name: impl AsRef<str>,
    ) -> Result<(), Error> {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .resume_task_in_current_transaction(&mut tx, task_name)
            .await;
        finish_queue_pool_transaction("resume task", tx, result).await
    }

    /// Pauses enqueues and claims for one task inside the caller's active transaction.
    pub async fn pause_task_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        task_name: impl AsRef<str>,
    ) -> Result<(), Error> {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        let pause_key = paused_task_key(task_name);
        let database_operation_observer = tx.database_operation_observer().cloned();
        upsert_pause_key(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            &pause_key,
            Some(task_name),
        )
        .await
    }

    /// Resumes enqueues and claims for one task inside the caller's active transaction.
    pub async fn resume_task_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        task_name: impl AsRef<str>,
    ) -> Result<(), Error> {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        let pause_key = paused_task_key(task_name);
        let database_operation_observer = tx.database_operation_observer().cloned();
        delete_pause_key(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            &pause_key,
        )
        .await
    }

    /// Returns whether one task is paused.
    pub async fn fetch_task_is_paused(
        &self,
        pool: &Pool,
        task_name: impl AsRef<str>,
    ) -> Result<bool, Error> {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_task_is_paused_in_current_transaction(&mut tx, task_name)
            .await;
        finish_queue_read_transaction("fetch task is paused", tx, result).await
    }

    /// Returns whether one task is paused inside the caller's active transaction.
    pub async fn fetch_task_is_paused_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        task_name: impl AsRef<str>,
    ) -> Result<bool, Error> {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        let pause_key = paused_task_key(task_name);
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_pause_key_exists(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            &pause_key,
        )
        .await
    }

    /// Returns all currently paused task names, sorted ascending.
    pub async fn fetch_paused_task_names(&self, pool: &Pool) -> Result<Vec<String>, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_paused_task_names_in_current_transaction(&mut tx)
            .await;
        finish_queue_read_transaction("fetch paused task names", tx, result).await
    }

    /// Returns paused task names inside the caller's active transaction.
    pub async fn fetch_paused_task_names_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<Vec<String>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_paused_task_names(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
        )
        .await
    }

    /// Returns pending/running task names that have no registered handler.
    pub async fn fetch_orphaned_task_names(
        &self,
        pool: &Pool,
        registry: &TaskRegistry,
    ) -> Result<Vec<String>, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_orphaned_task_names_in_current_transaction(&mut tx, registry)
            .await;
        finish_queue_read_transaction("fetch orphaned task names", tx, result).await
    }

    /// Returns orphaned task names inside the caller's active transaction.
    pub async fn fetch_orphaned_task_names_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        registry: &TaskRegistry,
    ) -> Result<Vec<String>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        fetch_orphaned_task_names(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
            registry,
        )
        .await
    }

    /// Returns pending/running load with pause-state and registry metadata.
    pub async fn fetch_worker_pressure(
        &self,
        pool: &Pool,
        registry: &TaskRegistry,
    ) -> Result<WorkerPressure, Error> {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        let result = self
            .fetch_worker_pressure_in_current_transaction(&mut tx, registry)
            .await;
        finish_queue_read_transaction("fetch worker pressure", tx, result).await
    }

    /// Returns worker pressure inside the caller's active transaction.
    pub async fn fetch_worker_pressure_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        registry: &TaskRegistry,
    ) -> Result<WorkerPressure, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        let counts = fetch_worker_pressure_counts(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
        )
        .await?;
        let pause_entries = fetch_pause_entries(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            self.sql_catalog(),
        )
        .await?;
        let (queue_paused, paused_task_names) = aggregate_pause_entries(pause_entries);
        Ok(WorkerPressure {
            queue_paused,
            paused_task_names,
            registered_task_count: registry.registered_task_count(),
            pending_job_count: counts.pending_job_count,
            running_job_count: counts.running_job_count,
        })
    }
}
