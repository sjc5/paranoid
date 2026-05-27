use super::*;

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            table_name: PgQualifiedTableName::unqualified(DEFAULT_KV_TABLE_NAME)
                .expect("default KV table name must be a valid Postgres identifier"),
            schema_ledger_table_name: SchemaLedgerConfig::default().table_name,
            create_updated_at_index: true,
        }
    }
}

impl StoreConfig {
    /// Creates a KV store config for a validated table name.
    pub fn new(table_name: PgQualifiedTableName) -> Result<Self, Error> {
        let config = Self {
            table_name,
            schema_ledger_table_name: SchemaLedgerConfig::default().table_name,
            create_updated_at_index: true,
        };
        validate_distinct_table_names(&config)?;
        Ok(config)
    }
}

impl Store {
    /// Creates a KV store handle with precomputed SQL for the configured table.
    pub fn new(config: StoreConfig) -> Result<Self, Error> {
        validate_distinct_table_names(&config)?;
        let queries = Queries::new(&config.table_name);
        Ok(Self { config, queries })
    }

    /// Returns this store's config.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Creates and validates this store's schema inside one transaction.
    pub async fn migrate_schema(&self, pool: &Pool) -> Result<(), crate::db::Error> {
        migrate_schema(pool, &self.config).await
    }

    /// Runs schema migration inside the caller's active transaction.
    pub async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), crate::db::Error> {
        migrate_schema_in_current_transaction(tx, &self.config).await
    }

    /// Validates that this store's schema already exists and is compatible.
    pub async fn validate_schema(&self, pool: &Pool) -> Result<(), crate::db::Error> {
        validate_schema(pool, &self.config).await
    }

    /// Validates schema inside the caller's active transaction.
    pub async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), crate::db::Error> {
        validate_schema_in_current_transaction(tx, &self.config).await
    }

    /// Stores bytes for a key.
    pub async fn set_bytes(
        &self,
        pool: &Pool,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .set_bytes_in_current_transaction(&mut tx, key, value, ttl)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_SET_BYTES, tx, result).await
    }

    /// Stores bytes for a key inside the caller's current transaction.
    pub async fn set_bytes_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.set_bytes_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
            value,
            ttl,
        )
        .await
    }

    /// Stores bytes for a key and returns the database statement timestamp for the write.
    pub async fn set_bytes_and_return_database_timestamp(
        &self,
        pool: &Pool,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<DatabaseTimestampMicros, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .set_bytes_and_return_database_timestamp_in_current_transaction(
                &mut tx, key, value, ttl,
            )
            .await;
        finish_kv_pool_transaction(
            KV_OPERATION_SET_BYTES_RETURNING_DATABASE_TIMESTAMP,
            tx,
            result,
        )
        .await
    }

    /// Stores bytes for a key inside the caller's transaction and returns the database timestamp.
    pub async fn set_bytes_and_return_database_timestamp_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<DatabaseTimestampMicros, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.set_bytes_and_return_database_timestamp_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
            value,
            ttl,
        )
        .await
    }

    /// Stores bytes only when the key is absent or expired.
    pub async fn set_bytes_if_not_exists(
        &self,
        pool: &Pool,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .set_bytes_if_not_exists_in_current_transaction(&mut tx, key, value, ttl)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_SET_BYTES_IF_NOT_EXISTS, tx, result).await
    }

    /// Stores bytes only when the key is absent or expired inside the caller's transaction.
    pub async fn set_bytes_if_not_exists_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<bool, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.set_bytes_if_not_exists_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
            value,
            ttl,
        )
        .await
    }

    /// Stores bytes only when the key is absent or expired, returning write timestamp metadata.
    pub async fn set_bytes_if_not_exists_and_return_database_timestamp(
        &self,
        pool: &Pool,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<SetIfNotExistsResult, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .set_bytes_if_not_exists_and_return_database_timestamp_in_current_transaction(
                &mut tx, key, value, ttl,
            )
            .await;
        finish_kv_pool_transaction(
            KV_OPERATION_SET_BYTES_IF_NOT_EXISTS_RETURNING_DATABASE_TIMESTAMP,
            tx,
            result,
        )
        .await
    }

    /// Transactional variant of `set_bytes_if_not_exists_and_return_database_timestamp`.
    pub async fn set_bytes_if_not_exists_and_return_database_timestamp_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<SetIfNotExistsResult, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.set_bytes_if_not_exists_and_return_database_timestamp_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
            value,
            ttl,
        )
        .await
    }

    /// Fetches non-expired bytes for a key.
    pub async fn get_bytes(&self, pool: &Pool, key: &Key) -> Result<Vec<u8>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.get_bytes_in_current_transaction(&mut tx, key).await;
        finish_kv_read_transaction(KV_OPERATION_GET_BYTES, tx, result).await
    }

    /// Fetches non-expired bytes and returns the database statement timestamp for the read.
    pub async fn get_bytes_and_return_database_timestamp(
        &self,
        pool: &Pool,
        key: &Key,
    ) -> Result<BytesWithDatabaseTimestamp, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .get_bytes_and_return_database_timestamp_in_current_transaction(&mut tx, key)
            .await;
        finish_kv_read_transaction(
            KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
            tx,
            result,
        )
        .await
    }

    /// Fetches non-expired bytes for a key inside the caller's current transaction.
    pub async fn get_bytes_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<Vec<u8>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.get_bytes_with_executor(tx.inner.as_mut(), database_operation_observer.as_ref(), key)
            .await
    }

    /// Transactional variant of `get_bytes_and_return_database_timestamp`.
    pub async fn get_bytes_and_return_database_timestamp_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<BytesWithDatabaseTimestamp, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.get_bytes_and_return_database_timestamp_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
        )
        .await
    }

    /// Fetches non-expired bytes for many unique keys in the same order.
    pub async fn get_bytes_multi(
        &self,
        pool: &Pool,
        keys: &[Key],
    ) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .get_bytes_multi_in_current_transaction(&mut tx, keys)
            .await;
        finish_kv_read_transaction(KV_OPERATION_GET_BYTES_MULTI, tx, result).await
    }

    /// Fetches non-expired bytes for many unique keys inside the caller's transaction.
    pub async fn get_bytes_multi_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        keys: &[Key],
    ) -> Result<Vec<Option<Vec<u8>>>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.get_bytes_multi_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            keys,
        )
        .await
    }

    /// Stores bytes for many unique keys with one shared TTL.
    pub async fn set_bytes_multi(
        &self,
        pool: &Pool,
        entries: &[BytesSetEntry],
        ttl: Ttl,
    ) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .set_bytes_multi_in_current_transaction(&mut tx, entries, ttl)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_SET_BYTES_MULTI, tx, result).await
    }

    /// Stores bytes for many unique keys inside the caller's transaction.
    pub async fn set_bytes_multi_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        entries: &[BytesSetEntry],
        ttl: Ttl,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.set_bytes_multi_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            entries,
            ttl,
        )
        .await
    }

    /// Updates `updated_at` for a non-expired key without changing its value or expiration.
    pub async fn touch_key(&self, pool: &Pool, key: &Key) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.touch_key_in_current_transaction(&mut tx, key).await;
        finish_kv_pool_transaction(KV_OPERATION_TOUCH_KEY, tx, result).await
    }

    /// Updates `updated_at` for a non-expired key inside the caller's transaction.
    pub async fn touch_key_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.touch_key_with_executor(tx.inner.as_mut(), database_operation_observer.as_ref(), key)
            .await
    }

    /// Replaces the expiration for a non-expired key.
    pub async fn set_key_ttl(&self, pool: &Pool, key: &Key, ttl: Ttl) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .set_key_ttl_in_current_transaction(&mut tx, key, ttl)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_SET_KEY_TTL, tx, result).await
    }

    /// Replaces the expiration for a non-expired key inside the caller's transaction.
    pub async fn set_key_ttl_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        ttl: Ttl,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.set_key_ttl_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
            ttl,
        )
        .await
    }

    /// Marks a non-expired key as expired without physically deleting the row.
    pub async fn expire_key(&self, pool: &Pool, key: &Key) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.expire_key_in_current_transaction(&mut tx, key).await;
        finish_kv_pool_transaction(KV_OPERATION_EXPIRE_KEY, tx, result).await
    }

    /// Marks a non-expired key as expired inside the caller's transaction.
    pub async fn expire_key_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.expire_key_with_executor(tx.inner.as_mut(), database_operation_observer.as_ref(), key)
            .await
    }

    /// Deletes a non-expired key.
    pub async fn delete_key(&self, pool: &Pool, key: &Key) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.delete_key_in_current_transaction(&mut tx, key).await;
        finish_kv_pool_transaction(KV_OPERATION_DELETE_KEY, tx, result).await
    }

    /// Deletes a non-expired key inside the caller's current transaction.
    pub async fn delete_key_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<(), Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.delete_key_with_executor(tx.inner.as_mut(), database_operation_observer.as_ref(), key)
            .await
    }

    /// Reports whether a non-expired key exists.
    pub async fn check_key_exists(&self, pool: &Pool, key: &Key) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .check_key_exists_in_current_transaction(&mut tx, key)
            .await;
        finish_kv_read_transaction(KV_OPERATION_CHECK_KEY_EXISTS, tx, result).await
    }

    /// Reports whether a non-expired key exists inside the caller's current transaction.
    pub async fn check_key_exists_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<bool, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.check_key_exists_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
        )
        .await
    }

    /// Physically deletes at most `batch_size` expired keys.
    pub async fn delete_expired_keys_once(
        &self,
        pool: &Pool,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .delete_expired_keys_once_in_current_transaction(&mut tx, batch_size)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_DELETE_EXPIRED_KEYS_ONCE, tx, result).await
    }

    /// Physically deletes at most `batch_size` expired keys inside a transaction.
    pub async fn delete_expired_keys_once_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.delete_expired_keys_once_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            batch_size,
        )
        .await
    }

    /// Physically deletes expired keys in batches until one batch observes none remaining.
    pub async fn delete_expired_keys_until_empty(
        &self,
        pool: &Pool,
        batch_size: u32,
    ) -> Result<u64, Error> {
        self.delete_expired_keys_until_empty_with_delay_between_batches(
            pool,
            batch_size,
            DEFAULT_KV_DELETE_BATCH_DELAY,
        )
        .await
    }

    /// Physically deletes expired keys in batches until one batch observes none remaining.
    pub async fn delete_expired_keys_until_empty_with_delay_between_batches(
        &self,
        pool: &Pool,
        batch_size: u32,
        delay_between_full_batches: Duration,
    ) -> Result<u64, Error> {
        validate_delete_batch_size(batch_size)?;
        let mut total_deleted = 0;

        loop {
            let deleted = self.delete_expired_keys_once(pool, batch_size).await?;
            total_deleted += deleted;

            if deleted < u64::from(batch_size) {
                return Ok(total_deleted);
            }
            if !delay_between_full_batches.is_zero() {
                tokio::time::sleep(delay_between_full_batches).await;
            }
        }
    }

    /// Counts non-expired keys under a prefix.
    pub async fn count_live_keys_with_prefix(
        &self,
        pool: &Pool,
        prefix: &KeyPrefix,
    ) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .count_live_keys_with_prefix_in_current_transaction(&mut tx, prefix)
            .await;
        finish_kv_read_transaction(KV_OPERATION_COUNT_LIVE_KEYS_WITH_PREFIX, tx, result).await
    }

    /// Counts non-expired keys under a prefix inside the caller's current transaction.
    pub async fn count_live_keys_with_prefix_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        prefix: &KeyPrefix,
    ) -> Result<u64, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.count_live_keys_with_prefix_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            prefix,
        )
        .await
    }

    /// Scans non-expired bytes under a prefix in persisted-key order.
    pub async fn scan_bytes_with_prefix(
        &self,
        pool: &Pool,
        prefix: &KeyPrefix,
        after_key: Option<&Key>,
        limit: u32,
    ) -> Result<Vec<ScannedBytes>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .scan_bytes_with_prefix_in_current_transaction(&mut tx, prefix, after_key, limit)
            .await;
        finish_kv_read_transaction(KV_OPERATION_SCAN_BYTES_WITH_PREFIX, tx, result).await
    }

    /// Scans non-expired bytes under a prefix in persisted-key order inside a transaction.
    pub async fn scan_bytes_with_prefix_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        prefix: &KeyPrefix,
        after_key: Option<&Key>,
        limit: u32,
    ) -> Result<Vec<ScannedBytes>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.scan_bytes_with_prefix_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            prefix,
            after_key,
            limit,
        )
        .await
    }

    /// Scans non-expired keys under a prefix in persisted-key order.
    pub async fn scan_keys_with_prefix(
        &self,
        pool: &Pool,
        prefix: &KeyPrefix,
        after_key: Option<&Key>,
        limit: u32,
    ) -> Result<Vec<Key>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .scan_keys_with_prefix_in_current_transaction(&mut tx, prefix, after_key, limit)
            .await;
        finish_kv_read_transaction(KV_OPERATION_SCAN_KEYS_WITH_PREFIX, tx, result).await
    }

    /// Scans non-expired keys under a prefix in persisted-key order inside a transaction.
    pub async fn scan_keys_with_prefix_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        prefix: &KeyPrefix,
        after_key: Option<&Key>,
        limit: u32,
    ) -> Result<Vec<Key>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.scan_keys_with_prefix_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            prefix,
            after_key,
            limit,
        )
        .await
    }

    /// Physically deletes at most `batch_size` keys under a prefix, expired or live.
    pub async fn delete_keys_with_prefix_once(
        &self,
        pool: &Pool,
        prefix: &KeyPrefix,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .delete_keys_with_prefix_once_in_current_transaction(&mut tx, prefix, batch_size)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_DELETE_KEYS_WITH_PREFIX_ONCE, tx, result).await
    }

    /// Physically deletes at most `batch_size` keys under a prefix inside a transaction.
    pub async fn delete_keys_with_prefix_once_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        prefix: &KeyPrefix,
        batch_size: u32,
    ) -> Result<u64, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.delete_keys_with_prefix_once_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            prefix,
            batch_size,
        )
        .await
    }

    /// Acquires one expired or absent candidate slot and stores bytes in it.
    pub async fn acquire_slot_bytes(
        &self,
        pool: &Pool,
        candidate_keys: &[Key],
        value: &[u8],
        ttl: Ttl,
    ) -> Result<Option<Key>, Error> {
        let candidate_key_texts = prepare_unique_keys_for_slot_acquisition(candidate_keys)?;
        let ttl_microseconds = positive_expiring_ttl_microseconds(ttl)?;
        if candidate_key_texts.is_empty() {
            return Ok(None);
        }

        let mut tx = pool.begin_transaction().await?;
        let result = self
            .acquire_prepared_slot_bytes_in_current_transaction(
                &mut tx,
                &candidate_key_texts,
                value,
                ttl_microseconds,
            )
            .await;
        finish_kv_pool_transaction(KV_OPERATION_ACQUIRE_SLOT, tx, result).await
    }

    /// Acquires one expired or absent candidate slot inside the caller's transaction.
    pub async fn acquire_slot_bytes_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        candidate_keys: &[Key],
        value: &[u8],
        ttl: Ttl,
    ) -> Result<Option<Key>, Error> {
        let candidate_key_texts = prepare_unique_keys_for_slot_acquisition(candidate_keys)?;
        let ttl_microseconds = positive_expiring_ttl_microseconds(ttl)?;
        if candidate_key_texts.is_empty() {
            return Ok(None);
        }

        self.acquire_prepared_slot_bytes_in_current_transaction(
            tx,
            &candidate_key_texts,
            value,
            ttl_microseconds,
        )
        .await
    }
}
