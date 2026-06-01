use super::*;

impl Throttler {
    /// Returns this throttler's key.
    pub fn key(&self) -> &ThrottlerKey {
        &self.key
    }

    /// Begins a manual throttler-permit lifecycle.
    pub fn begin_manual_permit_lifecycle(&self) -> ThrottlerManualPermitProtocol<'_> {
        ThrottlerManualPermitProtocol { throttler: self }
    }

    /// Attempts to acquire permission to run.
    pub(crate) async fn try_acquire_manual_permit(
        &self,
        pool: &WritePool,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        let holder_id = self.generate_holder_id_if_needed()?;
        self.try_acquire_with_optional_holder(pool, holder_id.as_ref())
            .await
    }

    /// Attempts to acquire an owned permit guard.
    pub async fn try_acquire_guard(
        &self,
        pool: &WritePool,
    ) -> Result<ThrottlerGuardAcquireResult, Error> {
        let holder_id = self.generate_holder_id_if_needed()?;
        self.try_acquire_guard_with_optional_holder(pool, holder_id.as_ref())
            .await
    }

    /// Waits until permission is acquired.
    pub(crate) async fn acquire_manual_permit_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<ThrottlerPermit, Error> {
        let holder_id = self.generate_holder_id_if_needed()?;
        self.acquire_with_optional_holder_when_ready(pool, holder_id.as_ref())
            .await
    }

    /// Waits until an owned permit guard is acquired.
    pub async fn acquire_guard_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<ThrottlerPermitGuard, Error> {
        let holder_id = self.generate_holder_id_if_needed()?;
        self.acquire_guard_with_optional_holder_when_ready(pool, holder_id.as_ref())
            .await
    }

    /// Attempts to acquire permission and run a guarded task.
    pub async fn try_run_task<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        task: F,
    ) -> Result<ThrottlerTryRunTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(ThrottlerPermit) -> Fut,
    {
        match self.try_acquire_guard(pool).await? {
            ThrottlerGuardAcquireResult::Acquired(guard) => {
                Ok(ThrottlerTryRunTaskResult::Ran(guard.run_task(task).await))
            }
            ThrottlerGuardAcquireResult::Throttled { retry_after } => {
                Ok(ThrottlerTryRunTaskResult::Throttled { retry_after })
            }
            ThrottlerGuardAcquireResult::CircuitOpen => Ok(ThrottlerTryRunTaskResult::CircuitOpen),
        }
    }

    /// Waits for permission and runs a guarded task.
    pub async fn run_task_when_ready<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        task: F,
    ) -> Result<ThrottlerGuardedTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(ThrottlerPermit) -> Fut,
    {
        let guard = self.acquire_guard_when_ready(pool).await?;
        Ok(guard.run_task(task).await)
    }

    /// Attempts to acquire permission with an explicit holder identifier.
    pub(crate) async fn try_acquire_manual_permit_for_holder(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        self.try_acquire_with_optional_holder(pool, Some(holder_id))
            .await
    }

    /// Attempts to acquire an owned permit guard with an explicit holder identifier.
    pub async fn try_acquire_guard_for_holder(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<ThrottlerGuardAcquireResult, Error> {
        self.try_acquire_guard_with_optional_holder(pool, Some(holder_id))
            .await
    }

    /// Waits until permission is acquired with an explicit holder identifier.
    pub(crate) async fn acquire_manual_permit_for_holder_when_ready(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<ThrottlerPermit, Error> {
        self.acquire_with_optional_holder_when_ready(pool, Some(holder_id))
            .await
    }

    /// Waits until an owned permit guard is acquired with an explicit holder identifier.
    pub async fn acquire_guard_for_holder_when_ready(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<ThrottlerPermitGuard, Error> {
        self.acquire_guard_with_optional_holder_when_ready(pool, Some(holder_id))
            .await
    }

    /// Attempts to acquire permission with an explicit holder identifier and run a guarded task.
    pub async fn try_run_task_for_holder<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
        task: F,
    ) -> Result<ThrottlerTryRunTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(ThrottlerPermit) -> Fut,
    {
        match self.try_acquire_guard_for_holder(pool, holder_id).await? {
            ThrottlerGuardAcquireResult::Acquired(guard) => {
                Ok(ThrottlerTryRunTaskResult::Ran(guard.run_task(task).await))
            }
            ThrottlerGuardAcquireResult::Throttled { retry_after } => {
                Ok(ThrottlerTryRunTaskResult::Throttled { retry_after })
            }
            ThrottlerGuardAcquireResult::CircuitOpen => Ok(ThrottlerTryRunTaskResult::CircuitOpen),
        }
    }

    /// Waits for permission with an explicit holder identifier and runs a guarded task.
    pub async fn run_task_for_holder_when_ready<T, E, Fut, F>(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
        task: F,
    ) -> Result<ThrottlerGuardedTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(ThrottlerPermit) -> Fut,
    {
        let guard = self
            .acquire_guard_for_holder_when_ready(pool, holder_id)
            .await?;
        Ok(guard.run_task(task).await)
    }

    /// Attempts to acquire permission inside the caller's transaction.
    pub(crate) async fn try_acquire_manual_permit_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        let holder_id = self.generate_holder_id_if_needed()?;
        self.try_acquire_with_optional_holder_in_current_transaction(tx, holder_id.as_ref())
            .await
    }

    /// Attempts to acquire permission with an explicit holder identifier inside a transaction.
    pub(crate) async fn try_acquire_manual_permit_for_holder_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        holder_id: &HolderId,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        self.try_acquire_with_optional_holder_in_current_transaction(tx, Some(holder_id))
            .await
    }

    /// Releases a permit after a successful task.
    pub(crate) async fn release_manual_permit_after_success(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.release_manual_permit_after_task_outcome(pool, permit, ThrottlerTaskOutcome::Succeeded)
            .await
    }

    /// Releases a permit after a failed task.
    pub(crate) async fn release_manual_permit_after_failure(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.release_manual_permit_after_task_outcome(pool, permit, ThrottlerTaskOutcome::Failed)
            .await
    }

    /// Releases a permit when the protected task did not run.
    pub(crate) async fn release_manual_permit_without_task_outcome(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.release_manual_permit_after_task_outcome(
            pool,
            permit,
            ThrottlerTaskOutcome::NotExecuted,
        )
        .await
    }

    /// Releases a permit and applies the supplied task outcome.
    pub(crate) async fn release_manual_permit_after_task_outcome(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
        outcome: ThrottlerTaskOutcome,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.require_permit_matches_throttler(permit)?;
        if !self.needs_state_cleanup(permit) {
            return Ok(ThrottlerReleaseResult::default());
        }

        let mut tx = pool.begin_transaction().await?;
        let result = self
            .release_manual_permit_after_task_outcome_in_current_transaction(
                &mut tx, permit, outcome,
            )
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_THROTTLER_RELEASE, tx, result).await
    }

    /// Releases a permit and applies a task outcome inside the caller's transaction.
    pub(crate) async fn release_manual_permit_after_task_outcome_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        permit: &ThrottlerPermit,
        outcome: ThrottlerTaskOutcome,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.require_permit_matches_throttler(permit)?;
        if !self.needs_state_cleanup(permit) {
            return Ok(ThrottlerReleaseResult::default());
        }

        let mut release_result = ThrottlerReleaseResult::default();
        let mutation_result = self
            .state_item
            .mutate_live_atomically_in_current_transaction(
                tx,
                [FLEET_THROTTLER_STATE_KEY_PART],
                |current| {
                    let now = current.database_timestamp().as_i64();
                    let mut state = current.live_value().clone();
                    release_result =
                        self.apply_release_and_outcome(&mut state, now, permit, outcome);
                    if release_result.state_was_modified() {
                        return Ok::<_, Error>(KvItemAtomicMutation::SetValue {
                            value: state,
                            ttl: self.state_ttl,
                        });
                    }
                    Ok(KvItemAtomicMutation::KeepExisting)
                },
            )
            .await;

        match mutation_result {
            Ok(_) => Ok(release_result),
            Err(Error::Kv(KvError::KeyNotFound)) => Ok(ThrottlerReleaseResult::default()),
            Err(err) => Err(err),
        }
    }

    /// Fetches current throttler status.
    pub async fn fetch_status(&self, pool: &Pool) -> Result<ThrottlerStatus, Error> {
        match self
            .state_item
            .get_and_return_database_timestamp(pool, [FLEET_THROTTLER_STATE_KEY_PART])
            .await
        {
            Ok(row) => Ok(self.status_from_state(&row.value, row.database_timestamp.as_i64())),
            Err(KvError::KeyNotFound) => Ok(self.empty_status()),
            Err(err) => Err(err.into()),
        }
    }

    /// Fetches current throttler status inside the caller's transaction.
    pub async fn fetch_status_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<ThrottlerStatus, Error> {
        match self
            .state_item
            .get_and_return_database_timestamp_in_current_transaction(
                tx,
                [FLEET_THROTTLER_STATE_KEY_PART],
            )
            .await
        {
            Ok(row) => Ok(self.status_from_state(&row.value, row.database_timestamp.as_i64())),
            Err(KvError::KeyNotFound) => Ok(self.empty_status()),
            Err(err) => Err(err.into()),
        }
    }

    /// Deletes all throttler state.
    pub async fn reset(&self, pool: &WritePool) -> Result<(), Error> {
        match self
            .state_item
            .delete(pool, [FLEET_THROTTLER_STATE_KEY_PART])
            .await
        {
            Ok(()) | Err(KvError::KeyNotFound) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Deletes all throttler state inside the caller's transaction.
    pub async fn reset_in_current_transaction(&self, tx: &mut WriteTx<'_>) -> Result<(), Error> {
        match self
            .state_item
            .delete_in_current_transaction(tx, [FLEET_THROTTLER_STATE_KEY_PART])
            .await
        {
            Ok(()) | Err(KvError::KeyNotFound) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Opens the circuit when circuit breaking is enabled.
    pub async fn open_circuit(&self, pool: &WritePool) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.open_circuit_in_current_transaction(&mut tx).await;
        finish_fleet_pool_transaction(FLEET_OPERATION_THROTTLER_OPEN_CIRCUIT, tx, result).await
    }

    /// Opens the circuit inside the caller's transaction when circuit breaking is enabled.
    pub async fn open_circuit_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        self.set_circuit_state_in_current_transaction(tx, ThrottlerCircuitState::Open, true, false)
            .await
    }

    /// Closes the circuit and resets failure count when circuit breaking is enabled.
    pub async fn close_circuit(&self, pool: &WritePool) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.close_circuit_in_current_transaction(&mut tx).await;
        finish_fleet_pool_transaction(FLEET_OPERATION_THROTTLER_CLOSE_CIRCUIT, tx, result).await
    }

    /// Closes the circuit inside the caller's transaction when circuit breaking is enabled.
    pub async fn close_circuit_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), Error> {
        self.set_circuit_state_in_current_transaction(
            tx,
            ThrottlerCircuitState::Closed,
            false,
            true,
        )
        .await
    }
}

impl ThrottlerReleaseResult {
    /// Reports whether a concurrency slot was released.
    pub fn concurrency_slot_released(&self) -> bool {
        self.concurrency_slot_released
    }

    /// Reports whether circuit state changed.
    pub fn circuit_state_updated(&self) -> bool {
        self.circuit_state_updated
    }

    /// Reports whether a half-open probe reservation was cleared.
    pub fn probe_released(&self) -> bool {
        self.probe_released
    }

    pub(super) fn state_was_modified(&self) -> bool {
        self.concurrency_slot_released || self.circuit_state_updated || self.probe_released
    }
}

impl ThrottlerManualPermitProtocol<'_> {
    /// Attempts to acquire a throttler permit through the manual permit protocol.
    pub async fn try_acquire_permit(
        &self,
        pool: &WritePool,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        self.throttler.try_acquire_manual_permit(pool).await
    }

    /// Waits until a throttler permit is acquired through the manual permit protocol.
    pub async fn acquire_permit_when_ready(
        &self,
        pool: &WritePool,
    ) -> Result<ThrottlerPermit, Error> {
        self.throttler.acquire_manual_permit_when_ready(pool).await
    }

    /// Attempts to acquire a throttler permit for an explicit holder through the manual permit protocol.
    pub async fn try_acquire_permit_for_holder(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        self.throttler
            .try_acquire_manual_permit_for_holder(pool, holder_id)
            .await
    }

    /// Waits until a throttler permit is acquired for an explicit holder through the manual permit protocol.
    pub async fn acquire_permit_for_holder_when_ready(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<ThrottlerPermit, Error> {
        self.throttler
            .acquire_manual_permit_for_holder_when_ready(pool, holder_id)
            .await
    }

    /// Attempts to acquire a throttler permit through the manual permit protocol inside the caller's transaction.
    pub async fn try_acquire_permit_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        self.throttler
            .try_acquire_manual_permit_in_current_transaction(tx)
            .await
    }

    /// Attempts to acquire a throttler permit for an explicit holder through the manual permit protocol inside the caller's transaction.
    pub async fn try_acquire_permit_for_holder_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        holder_id: &HolderId,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        self.throttler
            .try_acquire_manual_permit_for_holder_in_current_transaction(tx, holder_id)
            .await
    }

    /// Releases a permit acquired through the manual permit protocol after a successful task.
    pub async fn release_permit_after_success(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_after_success(pool, permit)
            .await
    }

    /// Releases a permit acquired through the manual permit protocol after a failed task.
    pub async fn release_permit_after_failure(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_after_failure(pool, permit)
            .await
    }

    /// Releases a permit acquired through the manual permit protocol when the protected task did not run.
    pub async fn release_permit_without_task_outcome(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_without_task_outcome(pool, permit)
            .await
    }

    /// Releases a permit acquired through the manual permit protocol and applies the supplied task outcome.
    pub async fn release_permit_after_task_outcome(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
        outcome: ThrottlerTaskOutcome,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_after_task_outcome(pool, permit, outcome)
            .await
    }

    /// Releases a permit acquired through the manual permit protocol and applies the supplied task outcome inside the caller's transaction.
    pub async fn release_permit_after_task_outcome_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        permit: &ThrottlerPermit,
        outcome: ThrottlerTaskOutcome,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.throttler
            .release_manual_permit_after_task_outcome_in_current_transaction(tx, permit, outcome)
            .await
    }
}

impl ThrottlerStatus {
    /// Returns available rate-limit tokens.
    pub fn available_tokens(&self) -> f64 {
        self.available_tokens
    }

    /// Returns maximum rate-limit tokens.
    pub fn max_tokens(&self) -> f64 {
        self.max_tokens
    }

    /// Returns the current number of live concurrency slots.
    pub fn current_concurrency(&self) -> u16 {
        self.current_concurrency
    }

    /// Returns the maximum configured concurrency.
    pub fn max_concurrency(&self) -> u16 {
        self.max_concurrency
    }

    /// Returns the circuit state.
    pub fn circuit_state(&self) -> ThrottlerCircuitState {
        self.circuit_state
    }

    /// Returns the current consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}
