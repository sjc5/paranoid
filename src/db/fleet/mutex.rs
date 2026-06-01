use super::mutex_guard::{run_mutex_guard_heartbeat, run_task_once_under_mutex_guard};
use super::*;

impl Mutex {
    /// Returns this mutex's key.
    pub fn key(&self) -> &MutexKey {
        &self.key
    }

    /// Returns this mutex's claim duration.
    pub fn claim_duration(&self) -> ClaimDuration {
        self.claim_duration
    }

    /// Begins a manual-renewal mutex lifecycle.
    pub fn begin_manual_renewal_lifecycle(&self) -> MutexManualRenewalProtocol<'_> {
        MutexManualRenewalProtocol { mutex: self }
    }

    /// Attempts to claim the mutex for manual renewal.
    pub(crate) async fn try_claim_manual_renewal(
        &self,
        pool: &WritePool,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        let holder_id = generate_holder_id()?;
        self.try_claim_manual_renewal_for_holder(pool, &holder_id)
            .await
    }

    /// Attempts to claim the mutex for manual renewal inside the caller's transaction.
    pub(crate) async fn try_claim_manual_renewal_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        let holder_id = generate_holder_id()?;
        self.try_claim_manual_renewal_for_holder_in_current_transaction(tx, &holder_id)
            .await
    }

    /// Attempts to claim the mutex for an explicit holder for manual renewal.
    pub(crate) async fn try_claim_manual_renewal_for_holder(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        let lease_claim = self
            .lease_store
            .try_claim_lease(pool, &self.lease_key, holder_id, self.claim_duration)
            .await?;
        Ok(lease_claim.map(|lease_claim| self.claim_from_lease_claim(lease_claim)))
    }

    /// Attempts to claim the mutex with a generated holder identifier and returns a renewing guard.
    pub async fn try_claim_guard(
        &self,
        pool: &WritePool,
        config: MutexGuardConfig,
    ) -> Result<Option<MutexGuard>, Error> {
        let holder_id = generate_holder_id()?;
        self.try_claim_guard_for_holder(pool, &holder_id, config)
            .await
    }

    /// Attempts to claim the mutex with an explicit holder identifier and returns a renewing guard.
    pub async fn try_claim_guard_for_holder(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
        config: MutexGuardConfig,
    ) -> Result<Option<MutexGuard>, Error> {
        let resolved_config = config.resolve_for_claim_duration(self.claim_duration)?;
        let Some(claim) = self
            .try_claim_manual_renewal_for_holder(pool, holder_id)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(self.guard_from_claim(pool, claim, resolved_config)))
    }

    /// Waits until the mutex can be claimed with a generated holder identifier and returns a renewing guard.
    pub async fn claim_guard_when_available(
        &self,
        pool: &WritePool,
        config: MutexGuardConfig,
    ) -> Result<MutexGuard, Error> {
        let holder_id = generate_holder_id()?;
        self.claim_guard_for_holder_when_available(pool, &holder_id, config)
            .await
    }

    /// Waits until the mutex can be claimed with an explicit holder identifier and returns a renewing guard.
    pub async fn claim_guard_for_holder_when_available(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
        config: MutexGuardConfig,
    ) -> Result<MutexGuard, Error> {
        let resolved_config = config.resolve_for_claim_duration(self.claim_duration)?;
        let mut acquire_retry_interval = resolved_config.acquire_retry_interval;
        loop {
            if let Some(claim) = self
                .try_claim_manual_renewal_for_holder(pool, holder_id)
                .await?
            {
                return Ok(self.guard_from_claim(pool, claim, resolved_config));
            }
            tokio::time::sleep(fleet_mutex_acquire_retry_delay_with_jitter(
                acquire_retry_interval,
            )?)
            .await;
            acquire_retry_interval = acquire_retry_interval
                .saturating_mul(2)
                .min(resolved_config.max_acquire_retry_interval);
        }
    }

    /// Attempts to acquire the mutex, run the task under a renewing guard, and release the guard.
    pub async fn try_run_task<T, E, TaskFuture, Task>(
        &self,
        pool: &WritePool,
        config: MutexGuardConfig,
        task: Task,
    ) -> Result<MutexTryRunTaskResult<T>, MutexRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let Some(guard) = self
            .try_claim_guard(pool, config)
            .await
            .map_err(MutexRunError::Fleet)?
        else {
            return Ok(MutexTryRunTaskResult::MutexHeld);
        };

        run_task_once_under_mutex_guard(guard, task)
            .await
            .map(MutexTryRunTaskResult::Ran)
    }

    /// Attempts to acquire the mutex for an explicit holder, run the task under a renewing guard, and release the guard.
    pub async fn try_run_task_for_holder<T, E, TaskFuture, Task>(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
        config: MutexGuardConfig,
        task: Task,
    ) -> Result<MutexTryRunTaskResult<T>, MutexRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let Some(guard) = self
            .try_claim_guard_for_holder(pool, holder_id, config)
            .await
            .map_err(MutexRunError::Fleet)?
        else {
            return Ok(MutexTryRunTaskResult::MutexHeld);
        };

        run_task_once_under_mutex_guard(guard, task)
            .await
            .map(MutexTryRunTaskResult::Ran)
    }

    /// Waits for the mutex, runs the task under a renewing guard, and releases the guard.
    pub async fn run_task_when_available<T, E, TaskFuture, Task>(
        &self,
        pool: &WritePool,
        config: MutexGuardConfig,
        task: Task,
    ) -> Result<T, MutexRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let guard = self
            .claim_guard_when_available(pool, config)
            .await
            .map_err(MutexRunError::Fleet)?;
        run_task_once_under_mutex_guard(guard, task).await
    }

    /// Waits for the mutex with an explicit holder, runs the task under a renewing guard, and releases the guard.
    pub async fn run_task_for_holder_when_available<T, E, TaskFuture, Task>(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
        config: MutexGuardConfig,
        task: Task,
    ) -> Result<T, MutexRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let guard = self
            .claim_guard_for_holder_when_available(pool, holder_id, config)
            .await
            .map_err(MutexRunError::Fleet)?;
        run_task_once_under_mutex_guard(guard, task).await
    }

    /// Attempts to claim the mutex for an explicit holder for manual renewal inside the caller's transaction.
    pub(crate) async fn try_claim_manual_renewal_for_holder_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        holder_id: &HolderId,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        let lease_claim = self
            .lease_store
            .try_claim_lease_in_current_transaction(
                tx,
                &self.lease_key,
                holder_id,
                self.claim_duration,
            )
            .await?;
        Ok(lease_claim.map(|lease_claim| self.claim_from_lease_claim(lease_claim)))
    }

    /// Attempts to renew a live mutex claim through the manual-renewal protocol once.
    pub(crate) async fn try_renew_manual_renewal_claim(
        &self,
        pool: &WritePool,
        claim: &MutexManualRenewalClaim,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.require_claim_matches_mutex(claim)?;
        let renewed_claim = self
            .lease_store
            .try_renew_lease(pool, &claim.lease_claim, self.claim_duration)
            .await?;
        Ok(renewed_claim.map(|lease_claim| self.claim_from_lease_claim(lease_claim)))
    }

    /// Attempts to renew a live mutex claim through the manual-renewal protocol once inside the caller's transaction.
    pub(crate) async fn try_renew_manual_renewal_claim_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        claim: &MutexManualRenewalClaim,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.require_claim_matches_mutex(claim)?;
        let renewed_claim = self
            .lease_store
            .try_renew_lease_in_current_transaction(tx, &claim.lease_claim, self.claim_duration)
            .await?;
        Ok(renewed_claim.map(|lease_claim| self.claim_from_lease_claim(lease_claim)))
    }

    /// Releases a live mutex claim through the manual-renewal protocol.
    pub(crate) async fn release_manual_renewal_claim(
        &self,
        pool: &WritePool,
        claim: &MutexManualRenewalClaim,
    ) -> Result<bool, Error> {
        self.require_claim_matches_mutex(claim)?;
        Ok(self
            .lease_store
            .release_lease(pool, &claim.lease_claim)
            .await?)
    }

    /// Releases a live mutex claim through the manual-renewal protocol inside the caller's transaction.
    pub(crate) async fn release_manual_renewal_claim_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        claim: &MutexManualRenewalClaim,
    ) -> Result<bool, Error> {
        self.require_claim_matches_mutex(claim)?;
        Ok(self
            .lease_store
            .release_lease_in_current_transaction(tx, &claim.lease_claim)
            .await?)
    }

    /// Fetches the current live mutex holder without exposing release or renewal authority.
    pub async fn fetch_live_holder(
        &self,
        pool: &Pool,
    ) -> Result<Option<MutexHolderSnapshot>, Error> {
        let holder = self
            .lease_store
            .fetch_live_lease_holder(pool, &self.lease_key)
            .await?;
        Ok(holder.map(|holder| self.holder_snapshot_from_lease_snapshot(holder)))
    }

    /// Fetches the current live mutex holder inside the caller's transaction.
    pub async fn fetch_live_holder_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<Option<MutexHolderSnapshot>, Error> {
        let holder = self
            .lease_store
            .fetch_live_lease_holder_in_current_transaction(tx, &self.lease_key)
            .await?;
        Ok(holder.map(|holder| self.holder_snapshot_from_lease_snapshot(holder)))
    }

    pub(super) fn claim_from_lease_claim(
        &self,
        lease_claim: LeaseClaim,
    ) -> MutexManualRenewalClaim {
        MutexManualRenewalClaim {
            mutex_key: self.key.clone(),
            lease_claim,
        }
    }

    pub(super) fn holder_snapshot_from_lease_snapshot(
        &self,
        lease_holder_snapshot: LeaseHolderSnapshot,
    ) -> MutexHolderSnapshot {
        MutexHolderSnapshot {
            mutex_key: self.key.clone(),
            lease_holder_snapshot,
        }
    }

    pub(super) fn guard_from_claim(
        &self,
        pool: &WritePool,
        claim: MutexManualRenewalClaim,
        config: ResolvedMutexGuardConfig,
    ) -> MutexGuard {
        let mutex = self.clone();
        let pool = pool.clone();
        let current_claim = Arc::new(tokio::sync::Mutex::new(Some(claim)));
        let stop_heartbeat = Arc::new(AtomicBool::new(false));
        let stop_heartbeat_notify = Arc::new(Notify::new());
        let leadership_lost = Arc::new(AtomicBool::new(false));
        let leadership_lost_notify = Arc::new(Notify::new());

        let heartbeat_task = tokio::spawn(run_mutex_guard_heartbeat(
            MutexHeartbeatRuntime {
                mutex: mutex.clone(),
                pool: pool.clone(),
                current_claim: Arc::clone(&current_claim),
                stop_heartbeat: Arc::clone(&stop_heartbeat),
                stop_heartbeat_notify: Arc::clone(&stop_heartbeat_notify),
                leadership_lost: Arc::clone(&leadership_lost),
                leadership_lost_notify: Arc::clone(&leadership_lost_notify),
            },
            config,
        ));

        MutexGuard {
            mutex,
            pool,
            runtime_handle: RuntimeHandle::current(),
            current_claim,
            stop_heartbeat,
            stop_heartbeat_notify,
            leadership_lost,
            leadership_lost_notify,
            heartbeat_task: Some(heartbeat_task),
        }
    }

    pub(super) fn require_claim_matches_mutex(
        &self,
        claim: &MutexManualRenewalClaim,
    ) -> Result<(), Error> {
        if claim.mutex_key != self.key || claim.lease_claim.key() != &self.lease_key {
            return Err(Error::MutexManualRenewalClaimBelongsToDifferentMutex);
        }
        Ok(())
    }
}

impl MutexManualRenewalProtocol<'_> {
    /// Attempts to claim the mutex through the manual-renewal protocol.
    pub async fn try_claim(
        &self,
        pool: &WritePool,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.mutex.try_claim_manual_renewal(pool).await
    }

    /// Attempts to claim the mutex through the manual-renewal protocol inside the caller's transaction.
    pub async fn try_claim_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.mutex
            .try_claim_manual_renewal_in_current_transaction(tx)
            .await
    }

    /// Attempts to claim the mutex for an explicit holder through the manual-renewal protocol.
    pub async fn try_claim_for_holder(
        &self,
        pool: &WritePool,
        holder_id: &HolderId,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.mutex
            .try_claim_manual_renewal_for_holder(pool, holder_id)
            .await
    }

    /// Attempts to claim the mutex for an explicit holder through the manual-renewal protocol inside the caller's transaction.
    pub async fn try_claim_for_holder_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        holder_id: &HolderId,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.mutex
            .try_claim_manual_renewal_for_holder_in_current_transaction(tx, holder_id)
            .await
    }

    /// Attempts to renew a live mutex claim through the manual-renewal protocol once.
    pub async fn try_renew_claim(
        &self,
        pool: &WritePool,
        claim: &MutexManualRenewalClaim,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.mutex.try_renew_manual_renewal_claim(pool, claim).await
    }

    /// Attempts to renew a live mutex claim through the manual-renewal protocol once inside the caller's transaction.
    pub async fn try_renew_claim_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        claim: &MutexManualRenewalClaim,
    ) -> Result<Option<MutexManualRenewalClaim>, Error> {
        self.mutex
            .try_renew_manual_renewal_claim_in_current_transaction(tx, claim)
            .await
    }

    /// Releases a live mutex claim through the manual-renewal protocol.
    pub async fn release_claim(
        &self,
        pool: &WritePool,
        claim: &MutexManualRenewalClaim,
    ) -> Result<bool, Error> {
        self.mutex.release_manual_renewal_claim(pool, claim).await
    }

    /// Releases a live mutex claim through the manual-renewal protocol inside the caller's transaction.
    pub async fn release_claim_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        claim: &MutexManualRenewalClaim,
    ) -> Result<bool, Error> {
        self.mutex
            .release_manual_renewal_claim_in_current_transaction(tx, claim)
            .await
    }
}

impl MutexManualRenewalClaim {
    /// Returns the mutex key.
    pub fn mutex_key(&self) -> &MutexKey {
        &self.mutex_key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        self.lease_claim.holder_id()
    }

    /// Returns this claim's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.lease_claim.fencing_token()
    }

    /// Returns the claim expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.lease_claim.expires_at_unix_microseconds()
    }

    pub(super) fn guard_snapshot(&self) -> MutexGuardSnapshot {
        MutexGuardSnapshot {
            mutex_key: self.mutex_key.clone(),
            holder_id: self.lease_claim.holder_id().clone(),
            fencing_token: self.lease_claim.fencing_token(),
            expires_at_unix_microseconds: self.lease_claim.expires_at_unix_microseconds(),
        }
    }
}

impl MutexHolderSnapshot {
    /// Returns the mutex key.
    pub fn mutex_key(&self) -> &MutexKey {
        &self.mutex_key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        self.lease_holder_snapshot.holder_id()
    }

    /// Returns the holder's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.lease_holder_snapshot.fencing_token()
    }

    /// Returns the holder snapshot expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.lease_holder_snapshot.expires_at_unix_microseconds()
    }
}

impl MutexGuardConfig {
    pub(super) fn resolve_for_claim_duration(
        self,
        claim_duration: ClaimDuration,
    ) -> Result<ResolvedMutexGuardConfig, Error> {
        let claim_duration = claim_duration.as_duration();
        let default_heartbeat_interval =
            (claim_duration / 3).max(MIN_FLEET_MUTEX_HEARTBEAT_INTERVAL);
        let heartbeat_interval = self
            .heartbeat_interval
            .unwrap_or(default_heartbeat_interval);
        if heartbeat_interval < MIN_FLEET_MUTEX_HEARTBEAT_INTERVAL {
            return Err(Error::InvalidMutexHeartbeatInterval {
                minimum: MIN_FLEET_MUTEX_HEARTBEAT_INTERVAL,
            });
        }

        let minimum_claim_duration = heartbeat_interval.checked_mul(2).ok_or(
            Error::MutexClaimDurationTooShortForHeartbeat {
                claim_duration,
                heartbeat_interval,
            },
        )?;
        if claim_duration < minimum_claim_duration {
            return Err(Error::MutexClaimDurationTooShortForHeartbeat {
                claim_duration,
                heartbeat_interval,
            });
        }

        let acquire_retry_interval = self
            .acquire_retry_interval
            .unwrap_or(DEFAULT_FLEET_MUTEX_ACQUIRE_RETRY_INTERVAL);
        if acquire_retry_interval.is_zero() {
            return Err(Error::InvalidMutexAcquireRetryInterval);
        }
        let max_acquire_retry_interval = self.max_acquire_retry_interval.unwrap_or_else(|| {
            DEFAULT_FLEET_MUTEX_MAX_ACQUIRE_RETRY_INTERVAL.max(acquire_retry_interval)
        });
        if max_acquire_retry_interval.is_zero()
            || max_acquire_retry_interval < acquire_retry_interval
        {
            return Err(Error::InvalidMutexMaxAcquireRetryInterval);
        }

        let max_consecutive_renewal_failures = self
            .max_consecutive_renewal_failures
            .unwrap_or(DEFAULT_FLEET_MUTEX_MAX_CONSECUTIVE_RENEWAL_FAILURES);
        if max_consecutive_renewal_failures == 0 {
            return Err(Error::InvalidMutexMaxConsecutiveRenewalFailures);
        }

        Ok(ResolvedMutexGuardConfig {
            heartbeat_interval,
            acquire_retry_interval,
            max_acquire_retry_interval,
            max_consecutive_renewal_failures,
        })
    }
}

pub(super) fn fleet_mutex_acquire_retry_delay_with_jitter(
    base_delay: Duration,
) -> Result<Duration, Error> {
    let unit = random_unit_f64_from_system()
        .map_err(|reason| Error::MutexAcquireRetryJitterRandom { reason })?;
    Ok(apply_fleet_mutex_acquire_retry_jitter_with_unit(
        base_delay, unit,
    ))
}

pub(super) fn apply_fleet_mutex_acquire_retry_jitter_with_unit(
    base_delay: Duration,
    unit: f64,
) -> Duration {
    if base_delay.is_zero() {
        return Duration::ZERO;
    }
    let normalized_unit = if unit.is_nan() {
        0.0
    } else {
        unit.clamp(0.0, 1.0)
    };
    let multiplier =
        1.0 + FLEET_MUTEX_ACQUIRE_RETRY_JITTER_FRACTION * ((2.0 * normalized_unit) - 1.0);
    duration_from_nonnegative_f64_seconds(base_delay.as_secs_f64() * multiplier, None)
}
