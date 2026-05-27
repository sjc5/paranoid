use super::*;

impl Store {
    pub(super) async fn acquire_prepared_slot_bytes_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        candidate_key_texts: &[String],
        value: &[u8],
        ttl_microseconds: i64,
    ) -> Result<Option<Key>, Error> {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
            Some(self.queries.ensure_slot_keys_exist.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(
            self.queries.ensure_slot_keys_exist.as_str(),
        ))
        .bind(candidate_key_texts)
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_ACQUIRE_SLOT,
            Some(self.queries.acquire_slot.as_str()),
        );
        let acquired_key = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
            self.queries.acquire_slot.as_str(),
        ))
        .bind(value)
        .bind(ttl_microseconds)
        .bind(candidate_key_texts)
        .fetch_optional(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

        Ok(acquired_key.map(Key))
    }

    pub(super) async fn set_bytes_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        if let Some(ttl_microseconds) = ttl.positive_microseconds()? {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES,
                Some(self.queries.set_bytes_with_ttl.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries.set_bytes_with_ttl.as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .bind(ttl_microseconds)
            .execute(executor)
            .await
            .map_err(DbError::query)?;
        } else {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES,
                Some(self.queries.set_bytes_no_expiration.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries.set_bytes_no_expiration.as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .execute(executor)
            .await
            .map_err(DbError::query)?;
        }

        Ok(())
    }

    pub(super) async fn set_bytes_and_return_database_timestamp_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<DatabaseTimestampMicros, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let timestamp = if let Some(ttl_microseconds) = ttl.positive_microseconds()? {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::FetchOne,
                KV_OPERATION_SET_BYTES_RETURNING_DATABASE_TIMESTAMP,
                Some(
                    self.queries
                        .set_bytes_with_ttl_returning_database_timestamp
                        .as_str(),
                ),
            );
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
                self.queries
                    .set_bytes_with_ttl_returning_database_timestamp
                    .as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .bind(ttl_microseconds)
            .fetch_one(executor)
            .await
            .map_err(DbError::query)?
        } else {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::FetchOne,
                KV_OPERATION_SET_BYTES_RETURNING_DATABASE_TIMESTAMP,
                Some(
                    self.queries
                        .set_bytes_no_expiration_returning_database_timestamp
                        .as_str(),
                ),
            );
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
                self.queries
                    .set_bytes_no_expiration_returning_database_timestamp
                    .as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .fetch_one(executor)
            .await
            .map_err(DbError::query)?
        };

        Ok(DatabaseTimestampMicros(timestamp))
    }

    pub(super) async fn set_bytes_if_not_exists_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<bool, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let was_set = if let Some(ttl_microseconds) = ttl.positive_microseconds()? {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_SET_BYTES_IF_NOT_EXISTS,
                Some(self.queries.set_bytes_if_not_exists_with_ttl.as_str()),
            );
            pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(
                self.queries.set_bytes_if_not_exists_with_ttl.as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .bind(ttl_microseconds)
            .fetch_optional(executor)
            .await
            .map_err(DbError::query)?
            .is_some()
        } else {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_SET_BYTES_IF_NOT_EXISTS,
                Some(self.queries.set_bytes_if_not_exists_no_expiration.as_str()),
            );
            pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(
                self.queries.set_bytes_if_not_exists_no_expiration.as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .fetch_optional(executor)
            .await
            .map_err(DbError::query)?
            .is_some()
        };

        Ok(was_set)
    }

    pub(super) async fn set_bytes_if_not_exists_and_return_database_timestamp_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<SetIfNotExistsResult, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let timestamp = if let Some(ttl_microseconds) = ttl.positive_microseconds()? {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_SET_BYTES_IF_NOT_EXISTS_RETURNING_DATABASE_TIMESTAMP,
                Some(
                    self.queries
                        .set_bytes_if_not_exists_with_ttl_returning_database_timestamp
                        .as_str(),
                ),
            );
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
                self.queries
                    .set_bytes_if_not_exists_with_ttl_returning_database_timestamp
                    .as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .bind(ttl_microseconds)
            .fetch_optional(executor)
            .await
            .map_err(DbError::query)?
        } else {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_SET_BYTES_IF_NOT_EXISTS_RETURNING_DATABASE_TIMESTAMP,
                Some(
                    self.queries
                        .set_bytes_if_not_exists_no_expiration_returning_database_timestamp
                        .as_str(),
                ),
            );
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
                self.queries
                    .set_bytes_if_not_exists_no_expiration_returning_database_timestamp
                    .as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .fetch_optional(executor)
            .await
            .map_err(DbError::query)?
        };

        Ok(SetIfNotExistsResult {
            was_set: timestamp.is_some(),
            database_timestamp: timestamp.map(DatabaseTimestampMicros),
        })
    }

    pub(super) async fn get_bytes_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<Vec<u8>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES,
            Some(self.queries.get_bytes.as_str()),
        );
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(self.queries.get_bytes.as_str()))
            .bind(key.as_str())
            .fetch_optional(executor)
            .await
            .map_err(DbError::query)?
            .ok_or(Error::KeyNotFound)
    }

    pub(super) async fn get_bytes_and_return_database_timestamp_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<BytesWithDatabaseTimestamp, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
            Some(self.queries.get_bytes_returning_database_timestamp.as_str()),
        );
        let (value, database_timestamp) = pooler_safe_query_as::<(Vec<u8>, i64)>(
            sqlx::AssertSqlSafe(self.queries.get_bytes_returning_database_timestamp.as_str()),
        )
        .bind(key.as_str())
        .fetch_optional(executor)
        .await
        .map_err(DbError::query)?
        .ok_or(Error::KeyNotFound)?;

        Ok(BytesWithDatabaseTimestamp {
            value,
            database_timestamp: DatabaseTimestampMicros(database_timestamp),
        })
    }

    pub(super) async fn get_bytes_multi_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        keys: &[Key],
    ) -> Result<Vec<Option<Vec<u8>>>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let prepared_keys = prepare_unique_keys_for_multi_get(keys)?;
        if prepared_keys.keys.is_empty() {
            return Ok(Vec::new());
        }

        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchAll,
            KV_OPERATION_GET_BYTES_MULTI,
            Some(self.queries.get_bytes_multi.as_str()),
        );
        let rows = pooler_safe_query_as::<(String, Vec<u8>)>(sqlx::AssertSqlSafe(
            self.queries.get_bytes_multi.as_str(),
        ))
        .bind(&prepared_keys.keys)
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?;

        let mut results = vec![None; prepared_keys.keys.len()];
        for (key, value) in rows {
            if let Some(index) = prepared_keys.key_to_index.get(key.as_str()) {
                results[*index] = Some(value);
            }
        }

        Ok(results)
    }

    pub(super) async fn set_bytes_multi_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        entries: &[BytesSetEntry],
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        validate_set_multi_entry_count(entries.len())?;
        let ttl_microseconds = ttl.positive_microseconds()?;
        if entries.is_empty() {
            return Ok(());
        }

        let (keys, values) = prepare_unique_entries_for_multi_set(entries)?;

        if let Some(ttl_microseconds) = ttl_microseconds {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_MULTI,
                Some(self.queries.set_bytes_multi_with_ttl.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries.set_bytes_multi_with_ttl.as_str(),
            ))
            .bind(&keys)
            .bind(&values)
            .bind(ttl_microseconds)
            .execute(executor)
            .await
            .map_err(DbError::query)?;
        } else {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_MULTI,
                Some(self.queries.set_bytes_multi_no_expiration.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries.set_bytes_multi_no_expiration.as_str(),
            ))
            .bind(&keys)
            .bind(&values)
            .execute(executor)
            .await
            .map_err(DbError::query)?;
        }

        Ok(())
    }

    pub(super) async fn touch_key_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<(), Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::Execute,
            KV_OPERATION_TOUCH_KEY,
            Some(self.queries.touch_key.as_str()),
        );
        let result = pooler_safe_query(sqlx::AssertSqlSafe(self.queries.touch_key.as_str()))
            .bind(key.as_str())
            .execute(executor)
            .await
            .map_err(DbError::query)?;

        require_rows_affected(result.rows_affected())
    }

    pub(super) async fn set_key_ttl_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
        ttl: Ttl,
    ) -> Result<(), Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let rows_affected = if let Some(ttl_microseconds) = ttl.positive_microseconds()? {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_KEY_TTL,
                Some(self.queries.set_key_ttl_with_ttl.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries.set_key_ttl_with_ttl.as_str(),
            ))
            .bind(key.as_str())
            .bind(ttl_microseconds)
            .execute(executor)
            .await
            .map_err(DbError::query)?
            .rows_affected()
        } else {
            record_database_operation(
                database_operation_observer,
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_KEY_TTL,
                Some(self.queries.set_key_ttl_no_expiration.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries.set_key_ttl_no_expiration.as_str(),
            ))
            .bind(key.as_str())
            .execute(executor)
            .await
            .map_err(DbError::query)?
            .rows_affected()
        };

        require_rows_affected(rows_affected)
    }

    pub(super) async fn expire_key_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<(), Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::Execute,
            KV_OPERATION_EXPIRE_KEY,
            Some(self.queries.expire_key.as_str()),
        );
        let result = pooler_safe_query(sqlx::AssertSqlSafe(self.queries.expire_key.as_str()))
            .bind(key.as_str())
            .execute(executor)
            .await
            .map_err(DbError::query)?;

        require_rows_affected(result.rows_affected())
    }

    pub(super) async fn delete_key_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<(), Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::Execute,
            KV_OPERATION_DELETE_KEY,
            Some(self.queries.delete_key.as_str()),
        );
        let result = pooler_safe_query(sqlx::AssertSqlSafe(self.queries.delete_key.as_str()))
            .bind(key.as_str())
            .execute(executor)
            .await
            .map_err(DbError::query)?;

        require_rows_affected(result.rows_affected())
    }

    pub(super) async fn check_key_exists_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<bool, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_CHECK_KEY_EXISTS,
            Some(self.queries.check_key_exists.as_str()),
        );
        pooler_safe_query_scalar::<bool>(sqlx::AssertSqlSafe(
            self.queries.check_key_exists.as_str(),
        ))
        .bind(key.as_str())
        .fetch_one(executor)
        .await
        .map_err(DbError::query)
        .map_err(Error::from)
    }
}
