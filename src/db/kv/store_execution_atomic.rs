use super::*;

impl Store {
    pub(super) async fn lock_key_for_atomic_mutation(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<(bool, Option<LockedKvRow>), Error> {
        for _ in 0..8 {
            tx.record_database_operation(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                Some(self.queries.lock_key_for_atomic_mutation.as_str()),
            );
            let locked_row = pooler_safe_query_as::<(bool, Vec<u8>, bool, i64)>(
                sqlx::AssertSqlSafe(self.queries.lock_key_for_atomic_mutation.as_str()),
            )
            .bind(key.as_str())
            .fetch_optional(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?
            .map(
                |(inserted_absent_placeholder, value, is_live, database_timestamp)| {
                    (
                        inserted_absent_placeholder,
                        LockedKvRow {
                            value,
                            is_live,
                            database_timestamp: DatabaseTimestampMicros(database_timestamp),
                        },
                    )
                },
            );

            if let Some((inserted_absent_placeholder, locked_row)) = locked_row {
                return Ok((inserted_absent_placeholder, Some(locked_row)));
            }
        }

        Err(Error::AtomicMutationCouldNotLockKey)
    }

    pub(super) async fn apply_atomic_mutation(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        mutation: AtomicMutation,
        had_previous_live_value: bool,
        inserted_absent_placeholder: bool,
    ) -> Result<AtomicMutationOutcome, Error> {
        match mutation {
            AtomicMutation::KeepExisting => {
                if inserted_absent_placeholder {
                    self.delete_key_for_atomic_mutation(tx, key).await?;
                }
                if had_previous_live_value {
                    Ok(AtomicMutationOutcome::KeptLiveValue)
                } else {
                    Ok(AtomicMutationOutcome::KeptAbsent)
                }
            }
            AtomicMutation::SetBytes { value, ttl } => {
                self.update_key_value_and_ttl_for_atomic_mutation(tx, key, &value, ttl)
                    .await?;
                Ok(AtomicMutationOutcome::SetBytes)
            }
            AtomicMutation::SetBytesPreservingExpiration { value } => {
                if !had_previous_live_value {
                    if inserted_absent_placeholder {
                        self.delete_key_for_atomic_mutation(tx, key).await?;
                    }
                    return Err(Error::KeyNotFound);
                }
                self.update_key_value_preserving_expiration_for_atomic_mutation(tx, key, &value)
                    .await?;
                Ok(AtomicMutationOutcome::SetBytesPreservingExpiration)
            }
            AtomicMutation::Delete => {
                self.delete_key_for_atomic_mutation(tx, key).await?;
                if had_previous_live_value {
                    Ok(AtomicMutationOutcome::DeletedLiveValue)
                } else {
                    Ok(AtomicMutationOutcome::DeletedAbsent)
                }
            }
        }
    }

    pub(super) async fn delete_key_for_atomic_mutation(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<(), Error> {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION,
            Some(self.queries.delete_key_for_atomic_mutation.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(
            self.queries.delete_key_for_atomic_mutation.as_str(),
        ))
        .bind(key.as_str())
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

        Ok(())
    }

    pub(super) async fn update_key_value_and_ttl_for_atomic_mutation(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        value: &[u8],
        ttl: Ttl,
    ) -> Result<(), Error> {
        let rows_affected = if let Some(ttl_microseconds) = ttl.positive_microseconds()? {
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                Some(
                    self.queries
                        .update_key_value_with_ttl_for_atomic_mutation
                        .as_str(),
                ),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries
                    .update_key_value_with_ttl_for_atomic_mutation
                    .as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .bind(ttl_microseconds)
            .execute(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected()
        } else {
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                Some(
                    self.queries
                        .update_key_value_no_expiration_for_atomic_mutation
                        .as_str(),
                ),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(
                self.queries
                    .update_key_value_no_expiration_for_atomic_mutation
                    .as_str(),
            ))
            .bind(key.as_str())
            .bind(value)
            .execute(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected()
        };

        require_rows_affected(rows_affected)
    }

    pub(super) async fn update_key_value_preserving_expiration_for_atomic_mutation(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        value: &[u8],
    ) -> Result<(), Error> {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            KV_OPERATION_SET_BYTES_PRESERVING_EXPIRATION_FOR_ATOMIC_MUTATION,
            Some(
                self.queries
                    .update_key_value_preserving_expiration_for_atomic_mutation
                    .as_str(),
            ),
        );
        let result = pooler_safe_query(sqlx::AssertSqlSafe(
            self.queries
                .update_key_value_preserving_expiration_for_atomic_mutation
                .as_str(),
        ))
        .bind(key.as_str())
        .bind(value)
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

        require_rows_affected(result.rows_affected())
    }
}
