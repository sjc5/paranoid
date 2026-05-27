use super::*;

impl<T> Item<T>
where
    T: Plaintext,
{
    /// Deletes a typed item.
    pub async fn delete<S, I>(&self, pool: &Pool, key_parts: I) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.delete_key(pool, &key).await
    }

    /// Deletes a typed item inside the caller's current transaction.
    pub async fn delete_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.delete_key_in_current_transaction(tx, &key).await
    }

    /// Updates `updated_at` for a live typed item.
    pub async fn touch<S, I>(&self, pool: &Pool, key_parts: I) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.touch_key(pool, &key).await
    }

    /// Updates `updated_at` for a live typed item inside the caller's transaction.
    pub async fn touch_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.touch_key_in_current_transaction(tx, &key).await
    }

    /// Replaces the expiration for a live typed item.
    pub async fn set_ttl<S, I>(&self, pool: &Pool, key_parts: I, ttl: Ttl) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.set_key_ttl(pool, &key, ttl).await
    }

    /// Replaces the expiration for a live typed item inside the caller's transaction.
    pub async fn set_ttl_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store
            .set_key_ttl_in_current_transaction(tx, &key, ttl)
            .await
    }

    /// Marks a live typed item as expired.
    pub async fn expire<S, I>(&self, pool: &Pool, key_parts: I) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.expire_key(pool, &key).await
    }

    /// Marks a live typed item as expired inside the caller's transaction.
    pub async fn expire_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.expire_key_in_current_transaction(tx, &key).await
    }

    /// Physically deletes all rows under this item prefix inside one transaction.
    pub async fn delete_entire_namespace_atomically(&self, pool: &Pool) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .delete_entire_namespace_in_current_transaction(&mut tx)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_DELETE_ENTIRE_ITEM_NAMESPACE, tx, result).await
    }

    /// Physically deletes all rows under this item prefix inside a transaction.
    pub async fn delete_entire_namespace_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<u64, Error> {
        let mut total_deleted = 0;
        loop {
            let deleted = self
                .store
                .delete_namespace_keys_with_prefix_once_in_current_transaction(
                    tx,
                    &self.prefix,
                    MAX_KV_DELETE_BATCH_SIZE,
                )
                .await?;
            total_deleted += deleted;
            if deleted < u64::from(MAX_KV_DELETE_BATCH_SIZE) {
                return Ok(total_deleted);
            }
        }
    }

    /// Acquires one expired or absent suffix slot and stores a typed value in it.
    pub async fn acquire_slot<S>(
        &self,
        pool: &Pool,
        candidate_suffixes: &[S],
        value: &T,
        ttl: Ttl,
    ) -> Result<Option<String>, Error>
    where
        S: AsRef<str>,
    {
        let prepared = self.prepare_slot_candidate_keys(candidate_suffixes)?;
        positive_expiring_ttl_microseconds(ttl)?;
        if prepared.keys.is_empty() {
            return Ok(None);
        }
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .acquire_prepared_slot_in_current_transaction(&mut tx, prepared, value, ttl)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_ACQUIRE_ITEM_SLOT, tx, result).await
    }

    /// Acquires one expired or absent suffix slot inside the caller's transaction.
    pub async fn acquire_slot_in_current_transaction<S>(
        &self,
        tx: &mut Tx<'_>,
        candidate_suffixes: &[S],
        value: &T,
        ttl: Ttl,
    ) -> Result<Option<String>, Error>
    where
        S: AsRef<str>,
    {
        let prepared = self.prepare_slot_candidate_keys(candidate_suffixes)?;
        self.acquire_prepared_slot_in_current_transaction(tx, prepared, value, ttl)
            .await
    }
}
