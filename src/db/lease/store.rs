use super::*;

/// Schema configuration for the Postgres-backed lease primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    /// Backing table for lease rows.
    pub table_name: PgQualifiedTableName,
    /// Backing table for durable per-key fencing counters.
    pub fencing_counter_table_name: PgQualifiedTableName,
}

/// Postgres-backed lease store bound to one configured table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store {
    pub(super) config: StoreConfig,
    pub(super) queries: Queries,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            table_name: PgQualifiedTableName::unqualified(DEFAULT_LEASE_TABLE_NAME)
                .expect("default lease table name must be a valid Postgres identifier"),
            fencing_counter_table_name: PgQualifiedTableName::unqualified(
                DEFAULT_LEASE_FENCING_COUNTER_TABLE_NAME,
            )
            .expect("default lease fencing counter table name must be a valid Postgres identifier"),
        }
    }
}

impl StoreConfig {
    /// Creates a lease store config for a validated table name.
    pub fn new(table_name: PgQualifiedTableName) -> Self {
        let fencing_counter_table_name = derive_fencing_counter_table_name(&table_name);
        Self {
            table_name,
            fencing_counter_table_name,
        }
    }

    /// Creates a lease store config with explicit validated table names.
    pub fn new_with_explicit_fencing_counter_table(
        table_name: PgQualifiedTableName,
        fencing_counter_table_name: PgQualifiedTableName,
    ) -> Self {
        Self {
            table_name,
            fencing_counter_table_name,
        }
    }
}

impl Store {
    /// Creates a lease store handle with precomputed SQL for the configured table.
    pub fn new(config: StoreConfig) -> Self {
        let queries = Queries::new(&config);
        Self { config, queries }
    }

    /// Returns this store's config.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Creates and validates this store's schema inside one transaction.
    pub async fn migrate_schema(&self, pool: &Pool) -> Result<(), DbError> {
        migrate_schema(pool, &self.config).await
    }

    /// Runs schema migration inside the caller's active transaction.
    pub async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), DbError> {
        migrate_schema_in_current_transaction(tx, &self.config).await
    }

    /// Validates that this store's schema already exists and is compatible.
    pub async fn validate_schema(&self, pool: &Pool) -> Result<(), DbError> {
        validate_schema(pool, &self.config).await
    }

    /// Validates schema inside the caller's active transaction.
    pub async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), DbError> {
        validate_schema_in_current_transaction(tx, &self.config).await
    }

    /// Attempts to claim an absent or expired lease.
    pub async fn try_claim_lease(
        &self,
        pool: &Pool,
        key: &Key,
        holder_id: &HolderId,
        duration: ClaimDuration,
    ) -> Result<Option<Claim>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .try_claim_lease_in_current_transaction(&mut tx, key, holder_id, duration)
            .await;
        finish_lease_pool_transaction(LEASE_OPERATION_CLAIM, tx, result).await
    }

    /// Attempts to claim an absent or expired lease inside the caller's transaction.
    pub async fn try_claim_lease_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        holder_id: &HolderId,
        duration: ClaimDuration,
    ) -> Result<Option<Claim>, Error> {
        let lease_token = Token::random()?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.try_claim_lease_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
            holder_id,
            &lease_token,
            duration,
        )
        .await
    }

    /// Attempts to renew a live lease claim, rotating the claim token on success.
    pub async fn try_renew_lease(
        &self,
        pool: &Pool,
        claim: &Claim,
        duration: ClaimDuration,
    ) -> Result<Option<Claim>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .try_renew_lease_in_current_transaction(&mut tx, claim, duration)
            .await;
        finish_lease_pool_transaction(LEASE_OPERATION_RENEW, tx, result).await
    }

    /// Attempts to renew a live lease claim inside the caller's transaction.
    pub async fn try_renew_lease_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &Claim,
        duration: ClaimDuration,
    ) -> Result<Option<Claim>, Error> {
        let next_lease_token = Token::random()?;
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.try_renew_lease_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            claim,
            &next_lease_token,
            duration,
        )
        .await
    }

    /// Releases a live lease by expiring it only when the full current claim token matches.
    pub async fn release_lease(&self, pool: &Pool, claim: &Claim) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .release_lease_in_current_transaction(&mut tx, claim)
            .await;
        finish_lease_pool_transaction(LEASE_OPERATION_RELEASE, tx, result).await
    }

    /// Releases a live lease by expiring it only when the full current claim token matches inside a transaction.
    pub async fn release_lease_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        claim: &Claim,
    ) -> Result<bool, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.release_lease_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            claim,
        )
        .await
    }

    /// Fetches the current live holder for a lease key without exposing release or renewal authority.
    pub async fn fetch_live_lease_holder(
        &self,
        pool: &Pool,
        key: &Key,
    ) -> Result<Option<HolderSnapshot>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .fetch_live_lease_holder_in_current_transaction(&mut tx, key)
            .await;
        finish_lease_read_transaction(LEASE_OPERATION_FETCH_LIVE_HOLDER, tx, result).await
    }

    /// Fetches the current live holder for a lease key inside the caller's transaction.
    pub async fn fetch_live_lease_holder_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
    ) -> Result<Option<HolderSnapshot>, Error> {
        let database_operation_observer = tx.database_operation_observer().cloned();
        self.fetch_live_lease_holder_with_executor(
            tx.inner.as_mut(),
            database_operation_observer.as_ref(),
            key,
        )
        .await
    }
}
