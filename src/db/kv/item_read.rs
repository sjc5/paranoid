use super::*;

impl<T> Item<T>
where
    T: Plaintext,
{
    /// Fetches and decodes a typed value.
    pub async fn get<S, I>(&self, pool: &Pool, key_parts: I) -> Result<T, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let bytes = self.store.get_bytes(pool, &key).await?;
        self.decode_value_for_key(&key, &bytes)
    }

    /// Fetches and decodes a typed value inside the caller's current transaction.
    pub async fn get_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
    ) -> Result<T, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let bytes = self
            .store
            .get_bytes_in_current_transaction(tx, &key)
            .await?;
        self.decode_value_for_key(&key, &bytes)
    }

    /// Fetches and decodes a typed value with the database statement timestamp for the read.
    pub async fn get_and_return_database_timestamp<S, I>(
        &self,
        pool: &Pool,
        key_parts: I,
    ) -> Result<ItemWithDatabaseTimestamp<T>, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let row = self
            .store
            .get_bytes_and_return_database_timestamp(pool, &key)
            .await?;
        Ok(ItemWithDatabaseTimestamp {
            value: self.decode_value_for_key(&key, &row.value)?,
            database_timestamp: row.database_timestamp,
        })
    }

    /// Transactional variant of `get_and_return_database_timestamp`.
    pub async fn get_and_return_database_timestamp_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
    ) -> Result<ItemWithDatabaseTimestamp<T>, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let row = self
            .store
            .get_bytes_and_return_database_timestamp_in_current_transaction(tx, &key)
            .await?;
        Ok(ItemWithDatabaseTimestamp {
            value: self.decode_value_for_key(&key, &row.value)?,
            database_timestamp: row.database_timestamp,
        })
    }

    /// Fetches a typed value or returns the supplied fallback when absent or expired.
    pub async fn get_or_fallback<S, I>(
        &self,
        pool: &Pool,
        key_parts: I,
        fallback: T,
    ) -> Result<T, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        match self.get(pool, key_parts).await {
            Ok(value) => Ok(value),
            Err(Error::KeyNotFound) => Ok(fallback),
            Err(err) => Err(err),
        }
    }

    /// Fetches many typed values in the same order as the requested keys.
    pub async fn get_multi<S, K>(
        &self,
        pool: &Pool,
        key_parts_list: &[K],
    ) -> Result<Vec<Option<T>>, Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        let keys = self.keys_from_parts_list_for_multi_get(key_parts_list)?;
        let values = self.store.get_bytes_multi(pool, &keys).await?;
        self.decode_multi_values(&keys, values)
    }

    /// Fetches many typed values inside the caller's current transaction.
    pub async fn get_multi_in_current_transaction<S, K>(
        &self,
        tx: &mut Tx<'_>,
        key_parts_list: &[K],
    ) -> Result<Vec<Option<T>>, Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        let keys = self.keys_from_parts_list_for_multi_get(key_parts_list)?;
        let values = self
            .store
            .get_bytes_multi_in_current_transaction(tx, &keys)
            .await?;
        self.decode_multi_values(&keys, values)
    }

    /// Reports whether a live typed item exists.
    pub async fn check_exists<S, I>(&self, pool: &Pool, key_parts: I) -> Result<bool, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store.check_key_exists(pool, &key).await
    }

    /// Reports whether a live typed item exists inside the caller's current transaction.
    pub async fn check_exists_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
    ) -> Result<bool, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        self.store
            .check_key_exists_in_current_transaction(tx, &key)
            .await
    }

    /// Counts live typed items under this item prefix.
    pub async fn count(&self, pool: &Pool) -> Result<u64, Error> {
        self.store
            .count_live_keys_with_prefix(pool, &self.prefix)
            .await
    }

    /// Counts live typed items under this item prefix inside a transaction.
    pub async fn count_in_current_transaction(&self, tx: &mut Tx<'_>) -> Result<u64, Error> {
        self.store
            .count_live_keys_with_prefix_in_current_transaction(tx, &self.prefix)
            .await
    }

    /// Scans live typed items under this prefix in persisted-key order.
    pub async fn scan(
        &self,
        pool: &Pool,
        after_key_suffix: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ItemScannedValue<T>>, Error> {
        let after_key = self.after_key_from_optional_suffix(after_key_suffix)?;
        let rows = self
            .store
            .scan_bytes_with_prefix(pool, &self.prefix, after_key.as_ref(), limit)
            .await?;
        self.decode_scanned_rows(rows)
    }

    /// Scans live typed items under this prefix inside a transaction.
    pub async fn scan_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        after_key_suffix: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ItemScannedValue<T>>, Error> {
        let after_key = self.after_key_from_optional_suffix(after_key_suffix)?;
        let rows = self
            .store
            .scan_bytes_with_prefix_in_current_transaction(
                tx,
                &self.prefix,
                after_key.as_ref(),
                limit,
            )
            .await?;
        self.decode_scanned_rows(rows)
    }

    /// Scans live key suffixes under this prefix in persisted-key order.
    pub async fn scan_key_suffixes(
        &self,
        pool: &Pool,
        after_key_suffix: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, Error> {
        let after_key = self.after_key_from_optional_suffix(after_key_suffix)?;
        Ok(self
            .store
            .scan_keys_with_prefix(pool, &self.prefix, after_key.as_ref(), limit)
            .await?
            .into_iter()
            .map(|key| self.suffix_from_key(&key))
            .collect())
    }

    /// Scans live key suffixes under this prefix inside a transaction.
    pub async fn scan_key_suffixes_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        after_key_suffix: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, Error> {
        let after_key = self.after_key_from_optional_suffix(after_key_suffix)?;
        Ok(self
            .store
            .scan_keys_with_prefix_in_current_transaction(
                tx,
                &self.prefix,
                after_key.as_ref(),
                limit,
            )
            .await?
            .into_iter()
            .map(|key| self.suffix_from_key(&key))
            .collect())
    }
}
