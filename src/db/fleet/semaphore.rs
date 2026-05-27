use super::*;

impl Semaphore {
    /// Returns this semaphore's key.
    pub fn key(&self) -> &SemaphoreKey {
        &self.key
    }

    /// Returns the maximum number of live slots.
    pub fn max_concurrent(&self) -> u16 {
        self.max_concurrent
    }

    /// Begins a manual semaphore-claim lifecycle.
    pub fn begin_manual_claim_lifecycle(&self) -> SemaphoreManualClaimProtocol<'_> {
        SemaphoreManualClaimProtocol { semaphore: self }
    }

    /// Attempts to acquire one semaphore slot with a generated holder identifier.
    pub(crate) async fn try_acquire_manual_claim(
        &self,
        pool: &Pool,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        let holder_id = generate_holder_id()?;
        self.try_acquire_manual_claim_for_holder(pool, &holder_id)
            .await
    }

    /// Attempts to acquire one owned semaphore claim guard without waiting.
    pub async fn try_acquire_guard(
        &self,
        pool: &Pool,
    ) -> Result<Option<SemaphoreClaimGuard>, Error> {
        Ok(self
            .try_acquire_manual_claim(pool)
            .await?
            .map(|claim| self.guard_from_claim(pool, claim)))
    }

    /// Attempts to acquire one semaphore slot with an explicit holder identifier.
    pub(crate) async fn try_acquire_manual_claim_for_holder(
        &self,
        pool: &Pool,
        holder_id: &HolderId,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .try_acquire_manual_claim_for_holder_in_current_transaction(&mut tx, holder_id)
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_SEMAPHORE_ACQUIRE, tx, result).await
    }

    /// Attempts to acquire one owned semaphore claim guard with an explicit holder identifier.
    pub async fn try_acquire_guard_for_holder(
        &self,
        pool: &Pool,
        holder_id: &HolderId,
    ) -> Result<Option<SemaphoreClaimGuard>, Error> {
        Ok(self
            .try_acquire_manual_claim_for_holder(pool, holder_id)
            .await?
            .map(|claim| self.guard_from_claim(pool, claim)))
    }

    /// Waits until one owned semaphore claim guard is acquired.
    pub async fn acquire_guard_when_available(
        &self,
        pool: &Pool,
    ) -> Result<SemaphoreClaimGuard, Error> {
        loop {
            if let Some(guard) = self.try_acquire_guard(pool).await? {
                return Ok(guard);
            }
            tokio::time::sleep(DEFAULT_FLEET_SEMAPHORE_ACQUIRE_RETRY_INTERVAL).await;
        }
    }

    /// Attempts to acquire one semaphore slot inside the caller's transaction.
    pub(crate) async fn try_acquire_manual_claim_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        let holder_id = generate_holder_id()?;
        self.try_acquire_manual_claim_for_holder_in_current_transaction(tx, &holder_id)
            .await
    }

    /// Attempts to acquire one semaphore slot with an explicit holder identifier inside the caller's transaction.
    pub(crate) async fn try_acquire_manual_claim_for_holder_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        holder_id: &HolderId,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        let slot = SemaphoreSlot {
            holder_id: holder_id.as_str().to_owned(),
        };
        let acquired_slot_suffix = self
            .slots_item
            .acquire_slot_in_current_transaction(tx, &self.slot_suffixes, &slot, self.max_hold_ttl)
            .await?;

        Ok(acquired_slot_suffix.map(|slot_suffix| SemaphoreClaim {
            semaphore_key: self.key.clone(),
            slot_suffix,
            holder_id: holder_id.clone(),
        }))
    }

    /// Releases a live semaphore claim.
    pub(crate) async fn release_manual_claim(
        &self,
        pool: &Pool,
        claim: &SemaphoreClaim,
    ) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .release_manual_claim_in_current_transaction(&mut tx, claim)
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_SEMAPHORE_RELEASE, tx, result).await
    }

    /// Releases a live semaphore claim inside the caller's transaction.
    pub(crate) async fn release_manual_claim_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &SemaphoreClaim,
    ) -> Result<bool, Error> {
        self.require_claim_matches_semaphore(claim)?;
        let mut released = false;
        let mutation_result = self
            .slots_item
            .mutate_live_atomically_in_current_transaction(
                tx,
                [claim.slot_suffix.as_str()],
                |current| {
                    if current.live_value().holder_id == claim.holder_id.as_str() {
                        released = true;
                        return Ok::<_, Error>(KvItemAtomicMutation::Delete);
                    }
                    Ok(KvItemAtomicMutation::KeepExisting)
                },
            )
            .await;

        match mutation_result {
            Ok(_) => Ok(released),
            Err(Error::Kv(KvError::KeyNotFound)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Fetches the current number of live slots and the configured slot limit.
    pub async fn fetch_status(&self, pool: &Pool) -> Result<SemaphoreStatus, Error> {
        Ok(SemaphoreStatus {
            current_count: self.slots_item.count(pool).await?,
            max_count: self.max_concurrent,
        })
    }

    /// Fetches semaphore status inside the caller's transaction.
    pub async fn fetch_status_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<SemaphoreStatus, Error> {
        Ok(SemaphoreStatus {
            current_count: self.slots_item.count_in_current_transaction(tx).await?,
            max_count: self.max_concurrent,
        })
    }

    /// Deletes all semaphore slots, expired or live.
    pub async fn reset(&self, pool: &Pool) -> Result<u64, Error> {
        Ok(self
            .slots_item
            .delete_entire_namespace_atomically(pool)
            .await?)
    }

    /// Deletes all semaphore slots inside the caller's transaction.
    pub async fn reset_in_current_transaction(&self, tx: &mut Tx<'_>) -> Result<u64, Error> {
        Ok(self
            .slots_item
            .delete_entire_namespace_in_current_transaction(tx)
            .await?)
    }

    /// Attempts to acquire a semaphore slot, run a guarded task, and release the slot.
    pub async fn try_run_task<T, E, Fut, F>(
        &self,
        pool: &Pool,
        task: F,
    ) -> Result<SemaphoreTryRunTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(SemaphoreClaim) -> Fut,
    {
        let Some(guard) = self.try_acquire_guard(pool).await? else {
            return Ok(SemaphoreTryRunTaskResult::NoSlotAvailable);
        };
        Ok(SemaphoreTryRunTaskResult::Ran(guard.run_task(task).await))
    }

    /// Waits for a semaphore slot, runs a guarded task, and releases the slot.
    pub async fn run_task_when_available<T, E, Fut, F>(
        &self,
        pool: &Pool,
        task: F,
    ) -> Result<SemaphoreGuardedTaskResult<T, E>, Error>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(SemaphoreClaim) -> Fut,
    {
        let mut pending_task = Some(task);
        loop {
            if let Some(guard) = self.try_acquire_guard(pool).await? {
                let task = pending_task
                    .take()
                    .expect("semaphore task must be present before execution");
                return Ok(guard.run_task(task).await);
            }
            tokio::time::sleep(DEFAULT_FLEET_SEMAPHORE_ACQUIRE_RETRY_INTERVAL).await;
        }
    }

    fn require_claim_matches_semaphore(&self, claim: &SemaphoreClaim) -> Result<(), Error> {
        if claim.semaphore_key != self.key {
            return Err(Error::SemaphoreClaimBelongsToDifferentSemaphore);
        }
        Ok(())
    }

    fn guard_from_claim(&self, pool: &Pool, claim: SemaphoreClaim) -> SemaphoreClaimGuard {
        SemaphoreClaimGuard {
            semaphore: self.clone(),
            pool: pool.clone(),
            runtime_handle: RuntimeHandle::current(),
            claim: Some(claim),
        }
    }
}

impl SemaphoreManualClaimProtocol<'_> {
    /// Attempts to acquire one semaphore claim with a generated holder identifier.
    pub async fn try_acquire_claim(&self, pool: &Pool) -> Result<Option<SemaphoreClaim>, Error> {
        self.semaphore.try_acquire_manual_claim(pool).await
    }

    /// Attempts to acquire one semaphore claim with an explicit holder identifier.
    pub async fn try_acquire_claim_for_holder(
        &self,
        pool: &Pool,
        holder_id: &HolderId,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        self.semaphore
            .try_acquire_manual_claim_for_holder(pool, holder_id)
            .await
    }

    /// Attempts to acquire one semaphore claim inside the caller's transaction.
    pub async fn try_acquire_claim_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        self.semaphore
            .try_acquire_manual_claim_in_current_transaction(tx)
            .await
    }

    /// Attempts to acquire one semaphore claim with an explicit holder identifier inside the caller's transaction.
    pub async fn try_acquire_claim_for_holder_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        holder_id: &HolderId,
    ) -> Result<Option<SemaphoreClaim>, Error> {
        self.semaphore
            .try_acquire_manual_claim_for_holder_in_current_transaction(tx, holder_id)
            .await
    }

    /// Releases a semaphore claim acquired through the manual claim protocol.
    pub async fn release_claim(&self, pool: &Pool, claim: &SemaphoreClaim) -> Result<bool, Error> {
        self.semaphore.release_manual_claim(pool, claim).await
    }

    /// Releases a semaphore claim acquired through the manual claim protocol inside the caller's transaction.
    pub async fn release_claim_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &SemaphoreClaim,
    ) -> Result<bool, Error> {
        self.semaphore
            .release_manual_claim_in_current_transaction(tx, claim)
            .await
    }
}

impl SemaphoreClaim {
    /// Returns the semaphore key.
    pub fn semaphore_key(&self) -> &SemaphoreKey {
        &self.semaphore_key
    }

    /// Returns the claimed slot suffix.
    pub fn slot_suffix(&self) -> &str {
        &self.slot_suffix
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        &self.holder_id
    }
}

impl SemaphoreStatus {
    /// Returns the current live slot count.
    pub fn current_count(&self) -> u64 {
        self.current_count
    }

    /// Returns the maximum live slot count.
    pub fn max_count(&self) -> u16 {
        self.max_count
    }
}

impl SemaphoreClaimGuard {
    /// Returns the claim while the guard still owns it.
    pub fn live_claim(&self) -> Option<&SemaphoreClaim> {
        self.claim.as_ref()
    }

    /// Releases the guarded semaphore claim.
    pub async fn release(mut self) -> Result<bool, Error> {
        self.try_release().await
    }

    /// Tries to release the guarded semaphore claim while retaining retry authority on release failure.
    pub async fn try_release(&mut self) -> Result<bool, Error> {
        self.release_live_claim().await
    }

    /// Runs a task and releases the semaphore claim after the task returns.
    pub async fn run_task<T, E, Fut, F>(mut self, task: F) -> SemaphoreGuardedTaskResult<T, E>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(SemaphoreClaim) -> Fut,
    {
        let Some(claim) = self.claim.clone() else {
            unreachable!("SemaphoreClaimGuard cannot run a task after consuming release")
        };

        match task(claim).await {
            Ok(value) => {
                let release_result = self.release_live_claim().await;
                SemaphoreGuardedTaskResult::Succeeded {
                    value,
                    release_result,
                }
            }
            Err(error) => {
                let release_result = self.release_live_claim().await;
                SemaphoreGuardedTaskResult::Failed {
                    error,
                    release_result,
                }
            }
        }
    }

    async fn release_live_claim(&mut self) -> Result<bool, Error> {
        let Some(claim) = self.claim.as_ref() else {
            return Ok(false);
        };
        let result = self
            .semaphore
            .release_manual_claim(&self.pool, claim)
            .await?;
        self.claim = None;
        Ok(result)
    }
}

impl Drop for SemaphoreClaimGuard {
    fn drop(&mut self) {
        let Some(claim) = self.claim.take() else {
            return;
        };
        let semaphore = self.semaphore.clone();
        let pool = self.pool.clone();
        self.runtime_handle.spawn(async move {
            let _ = semaphore.release_manual_claim(&pool, &claim).await;
        });
    }
}
