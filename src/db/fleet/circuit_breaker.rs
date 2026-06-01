use super::*;

impl CircuitBreaker {
    /// Returns this circuit breaker's key.
    pub fn key(&self) -> &CircuitBreakerKey {
        &self.key
    }

    /// Begins a manual circuit-breaker permit lifecycle.
    pub fn begin_manual_permit_lifecycle(&self) -> CircuitBreakerManualPermitProtocol<'_> {
        CircuitBreakerManualPermitProtocol {
            circuit_breaker: self,
        }
    }

    /// Attempts to acquire circuit-breaker permission without waiting.
    pub(crate) async fn try_acquire_manual_permit(
        &self,
        pool: &WritePool,
    ) -> Result<CircuitBreakerManualPermitAcquireResult, Error> {
        match self.throttler.try_acquire_manual_permit(pool).await? {
            ThrottlerManualPermitAcquireResult::Acquired(permit) => Ok(
                CircuitBreakerManualPermitAcquireResult::Acquired(self.wrap_permit(permit)),
            ),
            ThrottlerManualPermitAcquireResult::CircuitOpen
            | ThrottlerManualPermitAcquireResult::Throttled { .. } => {
                Ok(CircuitBreakerManualPermitAcquireResult::CircuitOpen)
            }
        }
    }

    /// Attempts to acquire an owned circuit-breaker permit guard without waiting.
    pub async fn try_acquire_guard(
        &self,
        pool: &WritePool,
    ) -> Result<CircuitBreakerGuardAcquireResult, Error> {
        match self.throttler.try_acquire_guard(pool).await? {
            ThrottlerGuardAcquireResult::Acquired(guard) => Ok(
                CircuitBreakerGuardAcquireResult::Acquired(self.wrap_guard(guard)),
            ),
            ThrottlerGuardAcquireResult::CircuitOpen
            | ThrottlerGuardAcquireResult::Throttled { .. } => {
                Ok(CircuitBreakerGuardAcquireResult::CircuitOpen)
            }
        }
    }

    /// Waits until circuit-breaker permission is acquired.
    pub(crate) async fn acquire_manual_permit_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<CircuitBreakerPermit, Error> {
        Ok(self.wrap_permit(
            self.throttler
                .acquire_manual_permit_when_ready(pool)
                .await?,
        ))
    }

    /// Waits until an owned circuit-breaker permit guard is acquired.
    pub async fn acquire_guard_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<CircuitBreakerPermitGuard, Error> {
        Ok(self.wrap_guard(self.throttler.acquire_guard_when_ready(pool).await?))
    }

    /// Attempts to acquire circuit-breaker permission and run a guarded task.
    pub async fn try_run_task<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        task: F,
    ) -> Result<CircuitBreakerTryRunTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(CircuitBreakerPermit) -> Fut,
    {
        match self.try_acquire_guard(pool).await? {
            CircuitBreakerGuardAcquireResult::Acquired(guard) => Ok(
                CircuitBreakerTryRunTaskResult::Ran(guard.run_task(task).await),
            ),
            CircuitBreakerGuardAcquireResult::CircuitOpen => {
                Ok(CircuitBreakerTryRunTaskResult::CircuitOpen)
            }
        }
    }

    /// Waits until circuit-breaker permission is acquired and runs a guarded task.
    pub async fn run_task_when_ready<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        task: F,
    ) -> Result<CircuitBreakerGuardedTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(CircuitBreakerPermit) -> Fut,
    {
        Ok(self
            .acquire_guard_when_ready(pool)
            .await?
            .run_task(task)
            .await)
    }

    /// Releases a circuit-breaker permit after a successful task.
    pub(crate) async fn release_manual_permit_after_success(
        &self,
        pool: &WritePool,
        permit: &CircuitBreakerPermit,
    ) -> Result<CircuitBreakerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_after_success(pool, &permit.throttler_permit)
            .await
            .map(CircuitBreakerReleaseResult::from)
    }

    /// Releases a circuit-breaker permit after a failed task.
    pub(crate) async fn release_manual_permit_after_failure(
        &self,
        pool: &WritePool,
        permit: &CircuitBreakerPermit,
    ) -> Result<CircuitBreakerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_after_failure(pool, &permit.throttler_permit)
            .await
            .map(CircuitBreakerReleaseResult::from)
    }

    /// Releases a circuit-breaker permit when the protected task did not run.
    pub(crate) async fn release_manual_permit_without_task_outcome(
        &self,
        pool: &WritePool,
        permit: &CircuitBreakerPermit,
    ) -> Result<CircuitBreakerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_without_task_outcome(pool, &permit.throttler_permit)
            .await
            .map(CircuitBreakerReleaseResult::from)
    }

    fn wrap_permit(&self, throttler_permit: ThrottlerPermit) -> CircuitBreakerPermit {
        CircuitBreakerPermit {
            key: self.key.clone(),
            throttler_permit,
        }
    }

    fn wrap_guard(&self, throttler_guard: ThrottlerPermitGuard) -> CircuitBreakerPermitGuard {
        CircuitBreakerPermitGuard {
            key: self.key.clone(),
            throttler_guard,
        }
    }

    /// Fetches current circuit-breaker status.
    pub async fn fetch_status(&self, pool: &Pool) -> Result<CircuitBreakerStatus, Error> {
        let status = self.throttler.fetch_status(pool).await?;
        Ok(CircuitBreakerStatus {
            circuit_state: status.circuit_state(),
            consecutive_failures: status.consecutive_failures(),
        })
    }

    /// Deletes circuit-breaker state.
    pub async fn reset(&self, pool: &WritePool) -> Result<(), Error> {
        self.throttler.reset(pool).await
    }

    /// Opens the circuit.
    pub async fn open(&self, pool: &WritePool) -> Result<(), Error> {
        self.throttler.open_circuit(pool).await
    }

    /// Closes the circuit and resets failure count.
    pub async fn close(&self, pool: &WritePool) -> Result<(), Error> {
        self.throttler.close_circuit(pool).await
    }
}

impl CircuitBreakerManualPermitProtocol<'_> {
    /// Attempts to acquire circuit-breaker permission through the manual permit protocol.
    pub async fn try_acquire_permit(
        &self,
        pool: &WritePool,
    ) -> Result<CircuitBreakerManualPermitAcquireResult, Error> {
        self.circuit_breaker.try_acquire_manual_permit(pool).await
    }

    /// Waits until circuit-breaker permission is acquired through the manual permit protocol.
    pub async fn acquire_permit_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<CircuitBreakerPermit, Error> {
        self.circuit_breaker
            .acquire_manual_permit_when_ready(pool)
            .await
    }

    /// Releases a circuit-breaker permit acquired through the manual permit protocol after a successful task.
    pub async fn release_permit_after_success(
        &self,
        pool: &WritePool,
        permit: &CircuitBreakerPermit,
    ) -> Result<CircuitBreakerReleaseResult, Error> {
        self.circuit_breaker
            .release_manual_permit_after_success(pool, permit)
            .await
    }

    /// Releases a circuit-breaker permit acquired through the manual permit protocol after a failed task.
    pub async fn release_permit_after_failure(
        &self,
        pool: &WritePool,
        permit: &CircuitBreakerPermit,
    ) -> Result<CircuitBreakerReleaseResult, Error> {
        self.circuit_breaker
            .release_manual_permit_after_failure(pool, permit)
            .await
    }

    /// Releases a circuit-breaker permit acquired through the manual permit protocol when the protected task did not run.
    pub async fn release_permit_without_task_outcome(
        &self,
        pool: &WritePool,
        permit: &CircuitBreakerPermit,
    ) -> Result<CircuitBreakerReleaseResult, Error> {
        self.circuit_breaker
            .release_manual_permit_without_task_outcome(pool, permit)
            .await
    }
}

impl CircuitBreakerPermit {
    /// Returns the circuit-breaker key.
    pub fn circuit_breaker_key(&self) -> &CircuitBreakerKey {
        &self.key
    }

    /// Reports whether this permit reserved a half-open circuit probe.
    pub fn probe_acquired(&self) -> bool {
        self.throttler_permit.probe_acquired()
    }
}

impl CircuitBreakerPermitGuard {
    /// Returns the permit while the guard still owns it.
    pub fn live_permit(&self) -> Option<CircuitBreakerPermit> {
        self.throttler_guard
            .live_permit()
            .cloned()
            .map(|throttler_permit| CircuitBreakerPermit {
                key: self.key.clone(),
                throttler_permit,
            })
    }

    /// Runs a task and releases the guard according to the task result.
    pub async fn run_task<T, E, Fut, F>(self, task: F) -> CircuitBreakerGuardedTaskResult<T, E>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(CircuitBreakerPermit) -> Fut,
    {
        let key = self.key.clone();
        match self
            .throttler_guard
            .run_task(|throttler_permit| {
                task(CircuitBreakerPermit {
                    key,
                    throttler_permit,
                })
            })
            .await
        {
            ThrottlerGuardedTaskResult::Succeeded {
                value,
                release_result,
            } => CircuitBreakerGuardedTaskResult::Succeeded {
                value,
                release_result: release_result.map(CircuitBreakerReleaseResult::from),
            },
            ThrottlerGuardedTaskResult::Failed {
                error,
                release_result,
            } => CircuitBreakerGuardedTaskResult::Failed {
                error,
                release_result: release_result.map(CircuitBreakerReleaseResult::from),
            },
        }
    }

    /// Releases the guarded permit after a successful task.
    pub async fn release_after_success(self) -> Result<CircuitBreakerReleaseResult, Error> {
        self.throttler_guard
            .release_after_success()
            .await
            .map(CircuitBreakerReleaseResult::from)
    }

    /// Releases the guarded permit after a failed task.
    pub async fn release_after_failure(self) -> Result<CircuitBreakerReleaseResult, Error> {
        self.throttler_guard
            .release_after_failure()
            .await
            .map(CircuitBreakerReleaseResult::from)
    }

    /// Releases the guarded permit without recording task outcome.
    pub async fn release_without_task_outcome(self) -> Result<CircuitBreakerReleaseResult, Error> {
        self.throttler_guard
            .release_without_task_outcome()
            .await
            .map(CircuitBreakerReleaseResult::from)
    }
}

impl CircuitBreakerReleaseResult {
    /// Reports whether circuit state changed.
    pub fn circuit_state_updated(&self) -> bool {
        self.circuit_state_updated
    }

    /// Reports whether a half-open probe reservation was cleared.
    pub fn probe_released(&self) -> bool {
        self.probe_released
    }
}

impl From<ThrottlerReleaseResult> for CircuitBreakerReleaseResult {
    fn from(value: ThrottlerReleaseResult) -> Self {
        Self {
            circuit_state_updated: value.circuit_state_updated(),
            probe_released: value.probe_released(),
        }
    }
}

impl CircuitBreakerStatus {
    /// Returns the circuit state.
    pub fn circuit_state(&self) -> CircuitBreakerState {
        self.circuit_state
    }

    /// Returns the current consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}
