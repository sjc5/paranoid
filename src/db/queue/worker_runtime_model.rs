use super::*;

impl TaskError {
    /// Creates a retryable task error.
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
        }
    }

    /// Creates a permanent task error.
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: true,
        }
    }

    /// Returns the task error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns whether this error should skip retries.
    pub fn is_permanent(&self) -> bool {
        self.permanent
    }
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TaskError {}

impl JobExecutionContext {
    /// Returns the current job ID.
    pub fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the current task name.
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    /// Returns the unique worker owner ID for this worker run.
    pub fn worker_owner_id(&self) -> &WorkerOwnerId {
        &self.worker_owner_id
    }

    /// Returns the current retry count.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns the configured max retry count.
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns true when the owning long-running worker has been asked to stop.
    pub fn worker_shutdown_has_been_requested(&self) -> bool {
        self.worker_shutdown_signal.is_cancellation_requested()
    }

    /// Waits until the owning long-running worker has been asked to stop.
    pub async fn wait_for_worker_shutdown_requested(&self) {
        self.worker_shutdown_signal
            .wait_until_cancellation_requested()
            .await;
    }

    /// Returns true when this job should stop because ownership was lost.
    pub fn job_cancellation_has_been_requested(&self) -> bool {
        self.job_cancellation_signal.is_cancellation_requested()
    }

    /// Waits until this job should stop because ownership was lost.
    pub async fn wait_for_job_cancellation_requested(&self) {
        self.job_cancellation_signal
            .wait_until_cancellation_requested()
            .await;
    }

    /// Records an execution heartbeat for the current job if this worker still owns it.
    pub async fn touch_execution_heartbeat(&self) -> Result<(), Error> {
        touch_owned_running_job_execution_heartbeat_with_database_operation_timeout(
            &self.queue,
            &self.pool,
            self.job_id,
            self.worker_owner_id.as_str(),
            self.database_operation_timeout,
        )
        .await
    }
}

impl RuntimeCancellationSignal {
    pub(in crate::db::queue) fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub(in crate::db::queue) fn request_cancellation(&self) -> bool {
        if !self.requested.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
            true
        } else {
            false
        }
    }

    pub(in crate::db::queue) fn is_cancellation_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    pub(in crate::db::queue) async fn wait_until_cancellation_requested(&self) {
        while !self.is_cancellation_requested() {
            let notified = self.notify.notified();
            if self.is_cancellation_requested() {
                return;
            }
            notified.await;
        }
    }
}

impl TaskRegistry {
    /// Creates an empty task registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a JSON-decoded task handler.
    pub fn register_json_task_handler<T, F, Fut>(
        &mut self,
        task_name: impl AsRef<str>,
        handler: F,
    ) -> Result<(), Error>
    where
        T: DeserializeOwned + Send + 'static,
        F: Fn(JobExecutionContext, T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), TaskError>> + Send + 'static,
    {
        let task_name = task_name.as_ref();
        validate_task_name(task_name)?;
        if self.handlers.contains_key(task_name) {
            return Err(Error::TaskAlreadyRegistered);
        }

        let mut handlers = (*self.handlers).clone();
        let handler = Arc::new(handler);
        handlers.insert(
            task_name.to_owned(),
            Arc::new(move |context, payload_json| {
                let handler = Arc::clone(&handler);
                Box::pin(async move {
                    let payload = serde_json::from_str::<T>(&payload_json).map_err(|source| {
                        TaskError::permanent(format!(
                            "queue payload could not be decoded: {source}"
                        ))
                    })?;
                    handler(context, payload).await
                })
            }),
        );
        self.handlers = Arc::new(handlers);
        Ok(())
    }

    /// Returns true when the registry has no handlers.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Returns the number of registered task handlers.
    pub fn registered_task_count(&self) -> usize {
        self.handlers.len()
    }

    /// Returns registered task names, sorted ascending.
    pub fn registered_task_names(&self) -> Vec<String> {
        let mut task_names = self.handlers.keys().cloned().collect::<Vec<_>>();
        task_names.sort();
        task_names
    }

    pub(in crate::db::queue) fn registered_task_name_set(&self) -> HashSet<String> {
        self.handlers.keys().cloned().collect()
    }

    pub(in crate::db::queue) fn handler(&self, task_name: &str) -> Option<TaskHandler> {
        self.handlers.get(task_name).cloned()
    }
}
