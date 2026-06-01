use super::*;

impl RateLimiter {
    /// Returns this rate limiter's key.
    pub fn key(&self) -> &RateLimiterKey {
        &self.key
    }

    /// Begins a manual rate-limiter permit lifecycle.
    pub fn begin_manual_permit_lifecycle(&self) -> RateLimiterManualPermitProtocol<'_> {
        RateLimiterManualPermitProtocol { rate_limiter: self }
    }

    /// Attempts to acquire one rate-limiter permit without waiting.
    pub(crate) async fn try_acquire_manual_permit(
        &self,
        pool: &WritePool,
    ) -> Result<RateLimiterManualPermitAcquireResult, Error> {
        self.wrap_acquire_result(self.throttler.try_acquire_manual_permit(pool).await?)
    }

    /// Attempts to acquire one owned rate-limiter permit guard without waiting.
    pub async fn try_acquire_guard(
        &self,
        pool: &WritePool,
    ) -> Result<RateLimiterGuardAcquireResult, Error> {
        self.wrap_guard_acquire_result(self.throttler.try_acquire_guard(pool).await?)
    }

    /// Waits until a rate-limiter permit is acquired.
    pub(crate) async fn acquire_manual_permit_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<RateLimiterPermit, Error> {
        Ok(self.wrap_permit(
            self.throttler
                .acquire_manual_permit_when_ready(pool)
                .await?,
        ))
    }

    /// Waits until an owned rate-limiter permit guard is acquired.
    pub async fn acquire_guard_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<RateLimiterPermitGuard, Error> {
        Ok(self.wrap_guard(self.throttler.acquire_guard_when_ready(pool).await?))
    }

    /// Attempts to acquire one rate-limiter permit and run a guarded task.
    pub async fn try_run_task<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        task: F,
    ) -> Result<RateLimiterTryRunTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(RateLimiterPermit) -> Fut,
    {
        match self.try_acquire_guard(pool).await? {
            RateLimiterGuardAcquireResult::Acquired(guard) => {
                Ok(RateLimiterTryRunTaskResult::Ran(guard.run_task(task).await))
            }
            RateLimiterGuardAcquireResult::Throttled { retry_after } => {
                Ok(RateLimiterTryRunTaskResult::Throttled { retry_after })
            }
        }
    }

    /// Waits until a rate-limiter permit is acquired and runs a guarded task.
    pub async fn run_task_when_ready<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        task: F,
    ) -> Result<RateLimiterGuardedTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(RateLimiterPermit) -> Fut,
    {
        Ok(self
            .acquire_guard_when_ready(pool)
            .await?
            .run_task(task)
            .await)
    }

    fn wrap_acquire_result(
        &self,
        acquire_result: ThrottlerManualPermitAcquireResult,
    ) -> Result<RateLimiterManualPermitAcquireResult, Error> {
        match acquire_result {
            ThrottlerManualPermitAcquireResult::Acquired(permit) => Ok(
                RateLimiterManualPermitAcquireResult::Acquired(self.wrap_permit(permit)),
            ),
            ThrottlerManualPermitAcquireResult::Throttled { retry_after } => {
                Ok(RateLimiterManualPermitAcquireResult::Throttled { retry_after })
            }
            ThrottlerManualPermitAcquireResult::CircuitOpen => {
                Err(Error::RateLimiterUnexpectedCircuitOpen)
            }
        }
    }

    fn wrap_guard_acquire_result(
        &self,
        acquire_result: ThrottlerGuardAcquireResult,
    ) -> Result<RateLimiterGuardAcquireResult, Error> {
        match acquire_result {
            ThrottlerGuardAcquireResult::Acquired(guard) => Ok(
                RateLimiterGuardAcquireResult::Acquired(self.wrap_guard(guard)),
            ),
            ThrottlerGuardAcquireResult::Throttled { retry_after } => {
                Ok(RateLimiterGuardAcquireResult::Throttled { retry_after })
            }
            ThrottlerGuardAcquireResult::CircuitOpen => {
                Err(Error::RateLimiterUnexpectedCircuitOpen)
            }
        }
    }

    fn wrap_permit(&self, throttler_permit: ThrottlerPermit) -> RateLimiterPermit {
        RateLimiterPermit {
            key: self.key.clone(),
            throttler_permit,
        }
    }

    fn wrap_guard(&self, throttler_guard: ThrottlerPermitGuard) -> RateLimiterPermitGuard {
        RateLimiterPermitGuard {
            key: self.key.clone(),
            throttler_guard,
        }
    }

    /// Fetches current rate-limiter status.
    pub async fn fetch_status(&self, pool: &Pool) -> Result<RateLimiterStatus, Error> {
        let status = self.throttler.fetch_status(pool).await?;
        Ok(RateLimiterStatus {
            available_tokens: status.available_tokens(),
            max_tokens: status.max_tokens(),
        })
    }

    /// Deletes rate-limiter state.
    pub async fn reset(&self, pool: &WritePool) -> Result<(), Error> {
        self.throttler.reset(pool).await
    }
}

impl RateLimiterManualPermitProtocol<'_> {
    /// Attempts to acquire one rate-limiter permit through the manual permit protocol.
    pub async fn try_acquire_permit(
        &self,
        pool: &WritePool,
    ) -> Result<RateLimiterManualPermitAcquireResult, Error> {
        self.rate_limiter.try_acquire_manual_permit(pool).await
    }

    /// Waits until a rate-limiter permit is acquired through the manual permit protocol.
    pub async fn acquire_permit_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<RateLimiterPermit, Error> {
        self.rate_limiter
            .acquire_manual_permit_when_ready(pool)
            .await
    }
}

impl RateLimiterPermit {
    /// Returns the rate-limiter key.
    pub fn rate_limiter_key(&self) -> &RateLimiterKey {
        &self.key
    }
}

impl RateLimiterPermitGuard {
    /// Returns the permit while the guard still owns it.
    pub fn live_permit(&self) -> Option<RateLimiterPermit> {
        self.throttler_guard
            .live_permit()
            .cloned()
            .map(|throttler_permit| RateLimiterPermit {
                key: self.key.clone(),
                throttler_permit,
            })
    }

    /// Runs a task and releases the guard according to the task result.
    pub async fn run_task<T, E, Fut, F>(self, task: F) -> RateLimiterGuardedTaskResult<T, E>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(RateLimiterPermit) -> Fut,
    {
        let key = self.key.clone();
        match self
            .throttler_guard
            .run_task(|throttler_permit| {
                task(RateLimiterPermit {
                    key,
                    throttler_permit,
                })
            })
            .await
        {
            ThrottlerGuardedTaskResult::Succeeded {
                value,
                release_result,
            } => RateLimiterGuardedTaskResult::Succeeded {
                value,
                release_result: release_result.map(|_| ()),
            },
            ThrottlerGuardedTaskResult::Failed {
                error,
                release_result,
            } => RateLimiterGuardedTaskResult::Failed {
                error,
                release_result: release_result.map(|_| ()),
            },
        }
    }

    /// Releases the guarded permit without running a task.
    pub async fn release_without_task_outcome(self) -> Result<(), Error> {
        self.throttler_guard
            .release_without_task_outcome()
            .await
            .map(|_| ())
    }
}

impl RateLimiterStatus {
    /// Returns available rate-limit tokens.
    pub fn available_tokens(&self) -> f64 {
        self.available_tokens
    }

    /// Returns maximum rate-limit tokens.
    pub fn max_tokens(&self) -> f64 {
        self.max_tokens
    }
}
