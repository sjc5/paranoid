use super::*;

impl<T> Item<T>
where
    T: Plaintext,
{
    /// Stores a typed value.
    pub async fn set<S, I>(
        &self,
        pool: &Pool,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store.set_bytes(pool, &key, &encoded, ttl).await
    }

    /// Stores a typed value inside the caller's current transaction.
    pub async fn set_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_in_current_transaction(tx, &key, &encoded, ttl)
            .await
    }

    /// Stores a typed value and returns the database statement timestamp for the write.
    pub async fn set_and_return_database_timestamp<S, I>(
        &self,
        pool: &Pool,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<DatabaseTimestampMicros, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = Key::from_prefix_and_parts(&self.prefix, key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_and_return_database_timestamp(pool, &key, &encoded, ttl)
            .await
    }

    /// Transactional variant of `set_and_return_database_timestamp`.
    pub async fn set_and_return_database_timestamp_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<DatabaseTimestampMicros, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = Key::from_prefix_and_parts(&self.prefix, key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_and_return_database_timestamp_in_current_transaction(tx, &key, &encoded, ttl)
            .await
    }

    /// Stores a typed value only when the key is absent or expired.
    pub async fn set_if_not_exists<S, I>(
        &self,
        pool: &Pool,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<bool, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_if_not_exists(pool, &key, &encoded, ttl)
            .await
    }

    /// Stores a typed value only when the key is absent or expired inside a transaction.
    pub async fn set_if_not_exists_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<bool, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_if_not_exists_in_current_transaction(tx, &key, &encoded, ttl)
            .await
    }

    /// Stores a typed value only when absent or expired, returning write timestamp metadata.
    pub async fn set_if_not_exists_and_return_database_timestamp<S, I>(
        &self,
        pool: &Pool,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<SetIfNotExistsResult, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = Key::from_prefix_and_parts(&self.prefix, key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_if_not_exists_and_return_database_timestamp(pool, &key, &encoded, ttl)
            .await
    }

    /// Transactional variant of `set_if_not_exists_and_return_database_timestamp`.
    pub async fn set_if_not_exists_and_return_database_timestamp_in_current_transaction<S, I>(
        &self,
        tx: &mut Tx<'_>,
        key_parts: I,
        value: &T,
        ttl: Ttl,
    ) -> Result<SetIfNotExistsResult, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = Key::from_prefix_and_parts(&self.prefix, key_parts)?;
        let encoded = self.encode_value_for_key(&key, value)?;
        self.store
            .set_bytes_if_not_exists_and_return_database_timestamp_in_current_transaction(
                tx, &key, &encoded, ttl,
            )
            .await
    }

    /// Stores many typed values with one shared TTL.
    pub async fn set_multi<S, K>(
        &self,
        pool: &Pool,
        key_parts_list: &[K],
        values: &[T],
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        let entries = self.multi_set_entries(key_parts_list, values)?;
        self.store.set_bytes_multi(pool, &entries, ttl).await
    }

    /// Stores many typed values inside the caller's current transaction.
    pub async fn set_multi_in_current_transaction<S, K>(
        &self,
        tx: &mut Tx<'_>,
        key_parts_list: &[K],
        values: &[T],
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        let entries = self.multi_set_entries(key_parts_list, values)?;
        self.store
            .set_bytes_multi_in_current_transaction(tx, &entries, ttl)
            .await
    }
}
