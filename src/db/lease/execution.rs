use super::*;

impl Store {
    pub(super) async fn try_claim_lease_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
        holder_id: &HolderId,
        lease_token: &Token,
        duration: ClaimDuration,
    ) -> Result<Option<Claim>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let duration_microseconds = duration.positive_microseconds()?;
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOptional,
            LEASE_OPERATION_CLAIM,
            Some(self.queries.claim_lease.as_str()),
        );
        let row = pooler_safe_query_as::<(String, i64, Vec<u8>, i64)>(sqlx::AssertSqlSafe(
            self.queries.claim_lease.as_str(),
        ))
        .bind(key.as_str())
        .bind(holder_id.as_str())
        .bind(lease_token.as_bytes())
        .bind(duration_microseconds)
        .fetch_optional(executor)
        .await
        .map_err(DbError::query)?;

        row.map(
            |(persisted_holder_id, fencing_token, persisted_lease_token, expires_at)| {
                lease_claim_from_persisted_parts(
                    key,
                    persisted_holder_id,
                    fencing_token,
                    persisted_lease_token,
                    expires_at,
                )
            },
        )
        .transpose()
    }

    pub(super) async fn try_renew_lease_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        claim: &Claim,
        next_lease_token: &Token,
        duration: ClaimDuration,
    ) -> Result<Option<Claim>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let duration_microseconds = duration.positive_microseconds()?;
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOptional,
            LEASE_OPERATION_RENEW,
            Some(self.queries.renew_lease.as_str()),
        );
        let row = pooler_safe_query_as::<(String, i64, Vec<u8>, i64)>(sqlx::AssertSqlSafe(
            self.queries.renew_lease.as_str(),
        ))
        .bind(claim.key.as_str())
        .bind(claim.holder_id.as_str())
        .bind(claim.fencing_token.as_i64())
        .bind(claim.lease_token.as_bytes())
        .bind(next_lease_token.as_bytes())
        .bind(duration_microseconds)
        .fetch_optional(executor)
        .await
        .map_err(DbError::query)?;

        row.map(
            |(persisted_holder_id, fencing_token, persisted_lease_token, expires_at)| {
                lease_claim_from_persisted_parts(
                    &claim.key,
                    persisted_holder_id,
                    fencing_token,
                    persisted_lease_token,
                    expires_at,
                )
            },
        )
        .transpose()
    }

    pub(super) async fn release_lease_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        claim: &Claim,
    ) -> Result<bool, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::Execute,
            LEASE_OPERATION_RELEASE,
            Some(self.queries.release_lease.as_str()),
        );
        let rows_updated =
            pooler_safe_query(sqlx::AssertSqlSafe(self.queries.release_lease.as_str()))
                .bind(claim.key.as_str())
                .bind(claim.holder_id.as_str())
                .bind(claim.fencing_token.as_i64())
                .bind(claim.lease_token.as_bytes())
                .execute(executor)
                .await
                .map_err(DbError::query)?
                .rows_affected();

        Ok(rows_updated != 0)
    }

    pub(super) async fn fetch_live_lease_holder_with_executor<'e, E>(
        &self,
        executor: E,
        database_operation_observer: Option<&DatabaseOperationObserver>,
        key: &Key,
    ) -> Result<Option<HolderSnapshot>, Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        record_database_operation(
            database_operation_observer,
            DatabaseOperationKind::FetchOptional,
            LEASE_OPERATION_FETCH_LIVE_HOLDER,
            Some(self.queries.fetch_live_lease_holder.as_str()),
        );
        let row = pooler_safe_query_as::<(String, i64, i64)>(sqlx::AssertSqlSafe(
            self.queries.fetch_live_lease_holder.as_str(),
        ))
        .bind(key.as_str())
        .fetch_optional(executor)
        .await
        .map_err(DbError::query)?;

        row.map(
            |(persisted_holder_id, fencing_token, expires_at_unix_microseconds)| {
                lease_holder_snapshot_from_persisted_parts(
                    key,
                    persisted_holder_id,
                    fencing_token,
                    expires_at_unix_microseconds,
                )
            },
        )
        .transpose()
    }
}

fn lease_claim_from_persisted_parts(
    key: &Key,
    holder_id: String,
    fencing_token: i64,
    lease_token: Vec<u8>,
    expires_at_unix_microseconds: i64,
) -> Result<Claim, Error> {
    Ok(Claim {
        key: key.clone(),
        holder_id: HolderId::new(holder_id)?,
        fencing_token: FencingToken::from_i64(fencing_token)?,
        lease_token: Token::from_persisted_bytes(lease_token)?,
        expires_at_unix_microseconds,
    })
}

fn lease_holder_snapshot_from_persisted_parts(
    key: &Key,
    holder_id: String,
    fencing_token: i64,
    expires_at_unix_microseconds: i64,
) -> Result<HolderSnapshot, Error> {
    Ok(HolderSnapshot {
        key: key.clone(),
        holder_id: HolderId::new(holder_id)?,
        fencing_token: FencingToken::from_i64(fencing_token)?,
        expires_at_unix_microseconds,
    })
}
