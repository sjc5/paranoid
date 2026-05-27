use super::*;

impl Store {
    pub(super) async fn count_live_keys_with_prefix_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        prefix: &KeyPrefix,
    ) -> Result<u64, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_COUNT_LIVE_KEYS_WITH_PREFIX,
            Some(self.queries.count_live_keys_with_prefix.as_str()),
        );
        let count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(
            self.queries.count_live_keys_with_prefix.as_str(),
        ))
        .bind(prefix_like_pattern(prefix))
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

        Ok(count as u64)
    }

    pub(super) async fn scan_bytes_with_prefix_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        prefix: &KeyPrefix,
        after_key: Option<&Key>,
        limit: u32,
    ) -> Result<Vec<ScannedBytes>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        validate_scan_limit(limit)?;
        let after_key_text = scan_after_key_text(prefix, after_key)?;
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchAll,
            KV_OPERATION_SCAN_BYTES_WITH_PREFIX,
            Some(self.queries.scan_bytes_with_prefix.as_str()),
        );
        let rows = pooler_safe_query_as::<(String, Vec<u8>)>(sqlx::AssertSqlSafe(
            self.queries.scan_bytes_with_prefix.as_str(),
        ))
        .bind(prefix_like_pattern(prefix))
        .bind(after_key_text)
        .bind(i64::from(limit))
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?;

        Ok(rows
            .into_iter()
            .map(|(key, value)| ScannedBytes {
                key: Key(key),
                value,
            })
            .collect())
    }

    pub(super) async fn scan_keys_with_prefix_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        prefix: &KeyPrefix,
        after_key: Option<&Key>,
        limit: u32,
    ) -> Result<Vec<Key>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        validate_scan_limit(limit)?;
        let after_key_text = scan_after_key_text(prefix, after_key)?;
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchAll,
            KV_OPERATION_SCAN_KEYS_WITH_PREFIX,
            Some(self.queries.scan_keys_with_prefix.as_str()),
        );
        let keys = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
            self.queries.scan_keys_with_prefix.as_str(),
        ))
        .bind(prefix_like_pattern(prefix))
        .bind(after_key_text)
        .bind(i64::from(limit))
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?;

        Ok(keys.into_iter().map(Key).collect())
    }

    pub(super) async fn delete_expired_keys_once_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        batch_size: u32,
    ) -> Result<u64, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        validate_delete_batch_size(batch_size)?;
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::Execute,
            KV_OPERATION_DELETE_EXPIRED_KEYS_ONCE,
            Some(self.queries.delete_expired_keys_once.as_str()),
        );
        let rows_deleted = pooler_safe_query(sqlx::AssertSqlSafe(
            self.queries.delete_expired_keys_once.as_str(),
        ))
        .bind(i64::from(batch_size))
        .execute(executor)
        .await
        .map_err(DbError::query)?
        .rows_affected();

        Ok(rows_deleted)
    }

    pub(super) async fn delete_keys_with_prefix_once_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        prefix: &KeyPrefix,
        batch_size: u32,
    ) -> Result<u64, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        validate_delete_batch_size(batch_size)?;
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::Execute,
            KV_OPERATION_DELETE_KEYS_WITH_PREFIX_ONCE,
            Some(self.queries.delete_keys_with_prefix_once.as_str()),
        );
        let rows_deleted = pooler_safe_query(sqlx::AssertSqlSafe(
            self.queries.delete_keys_with_prefix_once.as_str(),
        ))
        .bind(prefix_like_pattern(prefix))
        .bind(i64::from(batch_size))
        .execute(executor)
        .await
        .map_err(DbError::query)?
        .rows_affected();

        Ok(rows_deleted)
    }

    pub(super) async fn delete_namespace_keys_with_prefix_once_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        prefix: &KeyPrefix,
        batch_size: u32,
    ) -> Result<u64, Error> {
        validate_delete_batch_size(batch_size)?;
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            KV_OPERATION_DELETE_NAMESPACE_KEYS_WITH_PREFIX_ONCE,
            Some(self.queries.delete_namespace_keys_with_prefix_once.as_str()),
        );
        let rows_deleted = pooler_safe_query(sqlx::AssertSqlSafe(
            self.queries.delete_namespace_keys_with_prefix_once.as_str(),
        ))
        .bind(prefix_like_pattern(prefix))
        .bind(i64::from(batch_size))
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?
        .rows_affected();

        Ok(rows_deleted)
    }
}
