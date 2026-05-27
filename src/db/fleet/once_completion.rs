use super::*;

impl Once {
    /// Marks this task done while the claim is live, releases the claim, and commits both changes.
    pub(crate) async fn mark_done_and_release_manual_run(
        &self,
        pool: &Pool,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .mark_done_and_release_manual_run_in_current_transaction(&mut tx, claim)
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_ONCE_MARK_DONE_AND_RELEASE, tx, result).await
    }

    /// Transactional variant of `mark_done_and_release_manual_run`.
    pub(crate) async fn mark_done_and_release_manual_run_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.require_claim_matches_once(claim)?;
        let renewed_claim = self
            .mutex
            .try_renew_manual_renewal_claim_in_current_transaction(tx, &claim.mutex_claim)
            .await?
            .ok_or(Error::RunOnceManualRunClaimNoLongerLive)?;

        let holder_id = claim.holder_id().as_str().to_owned();
        let fencing_token = claim.fencing_token().as_i64();
        let marked_done = self
            .mark_completion_in_current_transaction(tx, holder_id, fencing_token)
            .await?;

        let released = self
            .mutex
            .release_manual_renewal_claim_in_current_transaction(tx, &renewed_claim)
            .await?;
        if !released {
            return Err(Error::RunOnceManualRunClaimNoLongerLive);
        }

        Ok(marked_done)
    }

    pub(super) async fn mark_completion(
        &self,
        pool: &Pool,
        snapshot: &OnceRunClaimSnapshot,
    ) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .mark_completion_in_current_transaction(
                &mut tx,
                snapshot.holder_id().as_str().to_owned(),
                snapshot.fencing_token().as_i64(),
            )
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_ONCE_MARK_COMPLETION, tx, result).await
    }

    pub(super) async fn mark_completion_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        holder_id: String,
        fencing_token: i64,
    ) -> Result<bool, Error> {
        let result = self
            .completion_item
            .mutate_atomically_in_current_transaction(tx, [FLEET_ONCE_DONE_KEY_PART], |current| {
                if current.has_live_value() {
                    return Ok::<_, Error>(KvItemAtomicMutation::KeepExisting);
                }

                Ok(KvItemAtomicMutation::SetValue {
                    value: OnceCompletion {
                        finished_at_unix_microseconds: current.database_timestamp().as_i64(),
                        holder_id,
                        fencing_token,
                    },
                    ttl: KvTtl::no_expiration(),
                })
            })
            .await?;
        Ok(matches!(result.outcome, KvAtomicMutationOutcome::SetBytes))
    }

    /// Releases a live run-once claim without marking the task done.
    pub(crate) async fn release_manual_run_without_marking_done(
        &self,
        pool: &Pool,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.require_claim_matches_once(claim)?;
        self.mutex
            .release_manual_renewal_claim(pool, &claim.mutex_claim)
            .await
    }

    /// Releases a live run-once claim without marking done inside the caller's transaction.
    pub(crate) async fn release_manual_run_without_marking_done_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.require_claim_matches_once(claim)?;
        self.mutex
            .release_manual_renewal_claim_in_current_transaction(tx, &claim.mutex_claim)
            .await
    }

    /// Attempts to delete this task's completion marker while holding its exclusion mutex.
    pub async fn try_reset(&self, pool: &Pool) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.try_reset_in_current_transaction(&mut tx).await;
        finish_fleet_pool_transaction(FLEET_OPERATION_ONCE_TRY_RESET, tx, result).await
    }

    async fn try_reset_in_current_transaction(&self, tx: &mut Tx<'_>) -> Result<bool, Error> {
        let Some(mutex_claim) = self
            .mutex
            .try_claim_manual_renewal_in_current_transaction(tx)
            .await?
        else {
            return Ok(false);
        };
        match self
            .completion_item
            .delete_in_current_transaction(tx, [FLEET_ONCE_DONE_KEY_PART])
            .await
        {
            Ok(()) | Err(KvError::KeyNotFound) => {}
            Err(error) => return Err(Error::from(error)),
        }
        let released = self
            .mutex
            .release_manual_renewal_claim_in_current_transaction(tx, &mutex_claim)
            .await?;
        if !released {
            return Err(Error::RunOnceManualRunClaimNoLongerLive);
        }
        Ok(true)
    }

    fn require_claim_matches_once(&self, claim: &OnceManualRunClaim) -> Result<(), Error> {
        if claim.once_key != self.key {
            return Err(Error::RunOnceManualRunClaimBelongsToDifferentTask);
        }
        self.mutex.require_claim_matches_mutex(&claim.mutex_claim)
    }

    pub(super) fn snapshot_from_mutex_guard_snapshot(
        &self,
        snapshot: MutexGuardSnapshot,
    ) -> OnceRunClaimSnapshot {
        OnceRunClaimSnapshot {
            once_key: self.key.clone(),
            holder_id: snapshot.holder_id().clone(),
            fencing_token: snapshot.fencing_token(),
            expires_at_unix_microseconds: snapshot.expires_at_unix_microseconds(),
        }
    }
}

impl OnceManualRunProtocol<'_> {
    /// Marks this task done while the claim is live, releases the claim, and commits both changes.
    pub async fn mark_done_and_release_run(
        &self,
        pool: &Pool,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.once
            .mark_done_and_release_manual_run(pool, claim)
            .await
    }

    /// Marks this task done and releases the claim inside the caller's transaction.
    pub async fn mark_done_and_release_run_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.once
            .mark_done_and_release_manual_run_in_current_transaction(tx, claim)
            .await
    }

    /// Releases a live run-once claim without marking the task done.
    pub async fn release_run_without_marking_done(
        &self,
        pool: &Pool,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.once
            .release_manual_run_without_marking_done(pool, claim)
            .await
    }

    /// Releases a live run-once claim without marking done inside the caller's transaction.
    pub async fn release_run_without_marking_done_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &OnceManualRunClaim,
    ) -> Result<bool, Error> {
        self.once
            .release_manual_run_without_marking_done_in_current_transaction(tx, claim)
            .await
    }
}
