use super::cache_model::CoalescingCacheEntry;
use super::*;

impl<T> CoalescingCache<T>
where
    T: Clone + Serialize + DeserializeOwned,
{
    /// Returns this cache's key.
    pub fn key(&self) -> &CoalescingCacheKey {
        &self.key
    }

    /// Returns this cache's value TTL.
    pub fn value_ttl(&self) -> KvTtl {
        self.value_ttl
    }

    /// Returns this cache's maximum lock wait duration.
    pub fn lock_wait_timeout(&self) -> Duration {
        self.lock_wait_timeout
    }

    /// Returns this cache's optional compute timeout.
    pub fn compute_timeout(&self) -> Option<Duration> {
        self.compute_timeout
    }

    /// Fetches a fresh cached value, or computes it while holding this key's distributed mutex.
    pub async fn fetch_or_compute<S, I, E, Fut, F>(
        &self,
        pool: &Pool,
        key_parts: I,
        compute_value: F,
    ) -> Result<T, CoalescingCacheFetchError<E>>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let key_parts = validated_cache_key_parts(key_parts)?;
        if let Some(value) = self.fetch_fresh_cached_value(pool, &key_parts).await? {
            return Ok(value);
        }

        let mutex = self.mutex_for_key_parts(&key_parts)?;
        let guard = self.acquire_compute_mutex_guard(pool, &mutex).await?;
        let result = self
            .fetch_or_compute_while_holding_mutex(pool, &key_parts, &guard, compute_value)
            .await;
        let release_result = require_coalescing_cache_mutex_released(guard.release().await);

        match (result, release_result) {
            (Ok(value), Ok(_)) => Ok(value),
            (Ok(_), Err(release_error)) => Err(CoalescingCacheFetchError::Fleet(release_error)),
            (Err(CoalescingCacheFetchError::Compute { source }), Ok(_)) => {
                Err(CoalescingCacheFetchError::Compute { source })
            }
            (Err(CoalescingCacheFetchError::Compute { source }), Err(release_error)) => {
                Err(CoalescingCacheFetchError::ComputeAndRelease {
                    source,
                    release_error,
                })
            }
            (Err(error), _) => Err(error),
        }
    }

    /// Stores a cache value manually for the given key parts.
    pub async fn set<S, I>(&self, pool: &Pool, key_parts: I, value: T) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key_parts = validated_cache_key_parts(key_parts)?;
        let mutex = self.mutex_for_key_parts(&key_parts)?;
        let guard = self.acquire_compute_mutex_guard(pool, &mutex).await?;
        let result = self.set_without_mutex(pool, &key_parts, value).await;
        let release_result = require_coalescing_cache_mutex_released(guard.release().await);
        match (result, release_result) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
        }
    }

    /// Deletes one cached value so the next fetch recomputes it.
    pub async fn invalidate<S, I>(&self, pool: &Pool, key_parts: I) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key_parts = validated_cache_key_parts(key_parts)?;
        let mutex = self.mutex_for_key_parts(&key_parts)?;
        let guard = self.acquire_compute_mutex_guard(pool, &mutex).await?;
        let result = self
            .value_item
            .delete(pool, key_parts.iter().map(String::as_str))
            .await;
        let release_result = require_coalescing_cache_mutex_released(guard.release().await);
        match (result, release_result) {
            (Ok(()) | Err(KvError::KeyNotFound), Ok(_)) => Ok(()),
            (Ok(()) | Err(KvError::KeyNotFound), Err(error)) => Err(error),
            (Err(error), _) => Err(Error::from(error)),
        }
    }

    /// Invalidates all values in this cache namespace by advancing its epoch.
    pub async fn invalidate_all(&self, pool: &Pool) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.invalidate_all_in_current_transaction(&mut tx).await;
        finish_fleet_pool_transaction(FLEET_OPERATION_CACHE_INVALIDATE_ALL, tx, result).await
    }

    /// Transactional variant of `invalidate_all`.
    pub async fn invalidate_all_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), Error> {
        self.epoch_item
            .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
                tx,
                std::iter::empty::<&str>(),
                |_| Ok::<_, Error>((1, KvTtl::no_expiration())),
                |current| {
                    let next_epoch = current
                        .live_value()
                        .checked_add(1)
                        .ok_or(Error::CounterArithmeticOverflow)?;
                    Ok(KvItemAtomicMutation::SetValue {
                        value: next_epoch,
                        ttl: KvTtl::no_expiration(),
                    })
                },
            )
            .await?;
        Ok(())
    }

    async fn fetch_or_compute_while_holding_mutex<E, Fut, F>(
        &self,
        pool: &Pool,
        key_parts: &[String],
        guard: &MutexGuard,
        compute_value: F,
    ) -> Result<T, CoalescingCacheFetchError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let (cached_value, current_epoch) = self
            .fetch_locked_cached_value_and_epoch(pool, key_parts)
            .await?;
        if let Some(cached_value) = cached_value {
            return Ok(cached_value);
        }

        let computed_value = match self.compute_timeout {
            Some(compute_timeout) => {
                match tokio::time::timeout(compute_timeout, compute_value()).await {
                    Ok(Ok(value)) => value,
                    Ok(Err(source)) => {
                        return Err(CoalescingCacheFetchError::Compute { source });
                    }
                    Err(_) => {
                        return Err(CoalescingCacheFetchError::Fleet(
                            Error::CoalescingCacheComputeTimedOut {
                                timeout: compute_timeout,
                            },
                        ));
                    }
                }
            }
            None => compute_value()
                .await
                .map_err(|source| CoalescingCacheFetchError::Compute { source })?,
        };

        if guard.leadership_lost() {
            return Err(CoalescingCacheFetchError::Fleet(
                Error::CoalescingCacheComputeMutexLost,
            ));
        }
        self.store_computed_value_best_effort(pool, key_parts, &computed_value, current_epoch)
            .await;
        Ok(computed_value)
    }

    async fn fetch_locked_cached_value_and_epoch(
        &self,
        pool: &Pool,
        key_parts: &[String],
    ) -> Result<(Option<T>, i64), Error> {
        match self.fetch_cached_entry(pool, key_parts).await? {
            Some(entry) => {
                let current_epoch = self.fetch_current_epoch(pool).await?;
                if entry.epoch >= current_epoch {
                    return Ok((Some(entry.value), current_epoch));
                }
                Ok((None, current_epoch))
            }
            None => Ok((None, self.fetch_current_epoch(pool).await?)),
        }
    }

    async fn fetch_fresh_cached_value(
        &self,
        pool: &Pool,
        key_parts: &[String],
    ) -> Result<Option<T>, Error> {
        let Some(entry) = self.fetch_cached_entry(pool, key_parts).await? else {
            return Ok(None);
        };
        let current_epoch = self.fetch_current_epoch(pool).await?;
        if entry.epoch < current_epoch {
            return Ok(None);
        }
        Ok(Some(entry.value))
    }

    async fn fetch_cached_entry(
        &self,
        pool: &Pool,
        key_parts: &[String],
    ) -> Result<Option<CoalescingCacheEntry<T>>, Error> {
        match self
            .value_item
            .get(pool, key_parts.iter().map(String::as_str))
            .await
        {
            Ok(entry) => Ok(Some(entry)),
            Err(KvError::KeyNotFound) => Ok(None),
            Err(error) => Err(Error::from(error)),
        }
    }

    async fn fetch_current_epoch(&self, pool: &Pool) -> Result<i64, Error> {
        match self.epoch_item.get(pool, std::iter::empty::<&str>()).await {
            Ok(epoch) => Ok(epoch),
            Err(KvError::KeyNotFound) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }

    async fn set_without_mutex(
        &self,
        pool: &Pool,
        key_parts: &[String],
        value: T,
    ) -> Result<(), Error> {
        let current_epoch = self.fetch_current_epoch(pool).await?;
        let entry = CoalescingCacheEntry {
            value,
            epoch: current_epoch,
        };
        self.value_item
            .set(
                pool,
                key_parts.iter().map(String::as_str),
                &entry,
                self.value_ttl,
            )
            .await?;
        Ok(())
    }

    async fn store_computed_value_best_effort(
        &self,
        pool: &Pool,
        key_parts: &[String],
        value: &T,
        epoch: i64,
    ) {
        let entry = CoalescingCacheEntry {
            value: value.clone(),
            epoch,
        };
        let _ = self
            .value_item
            .set(
                pool,
                key_parts.iter().map(String::as_str),
                &entry,
                self.value_ttl,
            )
            .await;
    }

    async fn acquire_compute_mutex_guard(
        &self,
        pool: &Pool,
        mutex: &Mutex,
    ) -> Result<MutexGuard, Error> {
        let started_at = tokio::time::Instant::now();
        let guard_config = MutexGuardConfig {
            acquire_retry_interval: Some(DEFAULT_COALESCING_CACHE_LOCK_RETRY_INTERVAL),
            ..MutexGuardConfig::default()
        };
        loop {
            if let Some(guard) = mutex.try_claim_guard(pool, guard_config).await? {
                return Ok(guard);
            }

            let elapsed = started_at.elapsed();
            if elapsed >= self.lock_wait_timeout {
                return Err(Error::CoalescingCacheLockWaitTimedOut {
                    timeout: self.lock_wait_timeout,
                });
            }

            let remaining = self.lock_wait_timeout - elapsed;
            tokio::time::sleep(remaining.min(DEFAULT_COALESCING_CACHE_LOCK_RETRY_INTERVAL)).await;
        }
    }

    fn mutex_for_key_parts(&self, key_parts: &[String]) -> Result<Mutex, Error> {
        let lease_key = build_coalescing_cache_mutex_lease_key(
            self.root_key.as_str(),
            self.key.as_str(),
            key_parts.iter().map(String::as_str),
        )
        .map_err(|source| Error::InvalidCoalescingCacheKeyForMutex { source })?;
        Ok(Mutex {
            lease_store: self.mutex_lease_store.clone(),
            key: MutexKey(self.key.as_str().to_owned()),
            lease_key,
            claim_duration: self.mutex_claim_duration,
        })
    }
}
