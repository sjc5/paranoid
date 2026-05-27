use super::*;

impl Once {
    /// Returns this run-once task's key.
    pub fn key(&self) -> &OnceKey {
        &self.key
    }

    /// Returns this run-once task's mutex claim duration.
    pub fn claim_duration(&self) -> ClaimDuration {
        self.mutex.claim_duration()
    }

    /// Begins a manual run-once lifecycle.
    pub fn begin_manual_run_lifecycle(&self) -> OnceManualRunProtocol<'_> {
        OnceManualRunProtocol { once: self }
    }

    /// Fetches the durable completion marker if this task is already done.
    pub async fn check_done(&self, pool: &Pool) -> Result<Option<OnceCompletion>, Error> {
        match self
            .completion_item
            .get(pool, [FLEET_ONCE_DONE_KEY_PART])
            .await
        {
            Ok(completion) => Ok(Some(completion)),
            Err(KvError::KeyNotFound) => Ok(None),
            Err(err) => Err(Error::from(err)),
        }
    }

    /// Fetches the durable completion marker inside the caller's transaction.
    pub async fn check_done_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<Option<OnceCompletion>, Error> {
        match self
            .completion_item
            .get_in_current_transaction(tx, [FLEET_ONCE_DONE_KEY_PART])
            .await
        {
            Ok(completion) => Ok(Some(completion)),
            Err(KvError::KeyNotFound) => Ok(None),
            Err(err) => Err(Error::from(err)),
        }
    }

    /// Attempts to start this task with a generated holder identifier.
    pub(crate) async fn try_start_manual_run(
        &self,
        pool: &Pool,
    ) -> Result<Option<OnceManualRunClaim>, Error> {
        let holder_id = generate_holder_id()?;
        self.try_start_manual_run_for_holder(pool, &holder_id).await
    }

    /// Attempts to start this task with an explicit holder identifier.
    pub(crate) async fn try_start_manual_run_for_holder(
        &self,
        pool: &Pool,
        holder_id: &HolderId,
    ) -> Result<Option<OnceManualRunClaim>, Error> {
        if self.check_done(pool).await?.is_some() {
            return Ok(None);
        }

        let Some(mutex_claim) = self
            .mutex
            .try_claim_manual_renewal_for_holder(pool, holder_id)
            .await?
        else {
            return Ok(None);
        };

        if self.check_done(pool).await?.is_some() {
            if !self
                .mutex
                .release_manual_renewal_claim(pool, &mutex_claim)
                .await?
            {
                return Err(Error::RunOnceManualRunClaimNoLongerLive);
            }
            return Ok(None);
        }

        Ok(Some(OnceManualRunClaim {
            once_key: self.key.clone(),
            mutex_claim,
        }))
    }

    /// Attempts to acquire exclusive execution, run `task`, record completion, and release the claim.
    pub async fn try_run_task<T, E, TaskFuture, Task>(
        &self,
        pool: &Pool,
        task: Task,
    ) -> Result<OnceTryRunTaskResult<T>, OnceRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(OnceRunClaimSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(completion) = self.check_done(pool).await? {
            return Ok(OnceTryRunTaskResult::AlreadyDone(completion));
        }

        let Some(guard) = self
            .mutex
            .try_claim_guard(pool, MutexGuardConfig::default())
            .await?
        else {
            if let Some(completion) = self.check_done(pool).await? {
                return Ok(OnceTryRunTaskResult::AlreadyDone(completion));
            }
            return Ok(OnceTryRunTaskResult::AlreadyRunning);
        };

        self.run_task_after_acquiring_guard(pool, guard, task)
            .await
            .map(|result| match result {
                OnceRunTaskResult::Ran(value) => OnceTryRunTaskResult::Ran(value),
                OnceRunTaskResult::AlreadyDone(completion) => {
                    OnceTryRunTaskResult::AlreadyDone(completion)
                }
            })
    }

    /// Waits for exclusive execution, then runs `task` only if completion has not already been recorded.
    pub async fn run_task_when_available<T, E, TaskFuture, Task>(
        &self,
        pool: &Pool,
        task: Task,
    ) -> Result<OnceRunTaskResult<T>, OnceRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(OnceRunClaimSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(completion) = self.check_done(pool).await? {
            return Ok(OnceRunTaskResult::AlreadyDone(completion));
        }

        let guard = self
            .mutex
            .claim_guard_when_available(pool, MutexGuardConfig::default())
            .await?;
        self.run_task_after_acquiring_guard(pool, guard, task).await
    }

    /// Attempts to acquire exclusive execution and run `task` in the same transaction as completion.
    pub async fn try_run_task_atomically<T, E, Task>(
        &self,
        pool: &Pool,
        task: Task,
    ) -> Result<OnceTryRunTaskResult<T>, OnceTransactionalRunError<E>>
    where
        Task: for<'a, 'tx> FnOnce(
            OnceRunClaimSnapshot,
            &'a mut Tx<'tx>,
        ) -> OnceTransactionalTaskFuture<'a, T, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(completion) = self.check_done(pool).await? {
            return Ok(OnceTryRunTaskResult::AlreadyDone(completion));
        }

        let Some(guard) = self
            .mutex
            .try_claim_guard(pool, MutexGuardConfig::default())
            .await?
        else {
            if let Some(completion) = self.check_done(pool).await? {
                return Ok(OnceTryRunTaskResult::AlreadyDone(completion));
            }
            return Ok(OnceTryRunTaskResult::AlreadyRunning);
        };

        self.run_task_atomically_after_acquiring_guard(pool, guard, task)
            .await
            .map(|result| match result {
                OnceRunTaskResult::Ran(value) => OnceTryRunTaskResult::Ran(value),
                OnceRunTaskResult::AlreadyDone(completion) => {
                    OnceTryRunTaskResult::AlreadyDone(completion)
                }
            })
    }

    /// Waits for exclusive execution, then runs `task` in the same transaction as completion.
    pub async fn run_task_atomically_when_available<T, E, Task>(
        &self,
        pool: &Pool,
        task: Task,
    ) -> Result<OnceRunTaskResult<T>, OnceTransactionalRunError<E>>
    where
        Task: for<'a, 'tx> FnOnce(
            OnceRunClaimSnapshot,
            &'a mut Tx<'tx>,
        ) -> OnceTransactionalTaskFuture<'a, T, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(completion) = self.check_done(pool).await? {
            return Ok(OnceRunTaskResult::AlreadyDone(completion));
        }

        let guard = self
            .mutex
            .claim_guard_when_available(pool, MutexGuardConfig::default())
            .await?;
        self.run_task_atomically_after_acquiring_guard(pool, guard, task)
            .await
    }
}

impl OnceManualRunProtocol<'_> {
    /// Attempts to start this task through the manual run protocol.
    pub async fn try_start_run(&self, pool: &Pool) -> Result<Option<OnceManualRunClaim>, Error> {
        self.once.try_start_manual_run(pool).await
    }

    /// Attempts to start this task for an explicit holder through the manual run protocol.
    pub async fn try_start_run_for_holder(
        &self,
        pool: &Pool,
        holder_id: &HolderId,
    ) -> Result<Option<OnceManualRunClaim>, Error> {
        self.once
            .try_start_manual_run_for_holder(pool, holder_id)
            .await
    }
}
