use super::*;

/// Schema configuration for Fleet coordination primitives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    /// Root key prefix for Fleet-owned records.
    pub root_key: RootKey,
    /// Backing table for Fleet-owned durable keyed state.
    pub state_table_name: PgQualifiedTableName,
    /// Backing table for Fleet-owned coordination claims.
    pub coordination_table_name: PgQualifiedTableName,
    /// Backing table for Fleet-owned fencing counters.
    pub fencing_counter_table_name: PgQualifiedTableName,
    /// Schema ledger table for this Fleet store.
    pub schema_ledger_table_name: PgQualifiedTableName,
    /// Whether migration should create and validation should require the Fleet state `updated_at` index.
    pub create_state_updated_at_index: bool,
}

/// Postgres-backed Fleet coordination store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store {
    config: StoreConfig,
    kv_store: KvStore,
    lease_store: LeaseStore,
}

impl StoreConfig {
    /// Creates a Fleet store config from validated table names.
    pub fn new(
        root_key: RootKey,
        state_table_name: PgQualifiedTableName,
        coordination_table_name: PgQualifiedTableName,
    ) -> Result<Self, Error> {
        let raw_coordination_config = RawLeaseStoreConfig::new(coordination_table_name);
        let config = Self {
            root_key,
            state_table_name,
            coordination_table_name: raw_coordination_config.table_name,
            fencing_counter_table_name: raw_coordination_config.fencing_counter_table_name,
            schema_ledger_table_name: SchemaLedgerConfig::default().table_name,
            create_state_updated_at_index: true,
        };
        validate_distinct_table_names(&config)?;
        Ok(config)
    }

    /// Creates a Fleet store config from explicit validated table names.
    pub fn new_with_explicit_fencing_counter_table(
        root_key: RootKey,
        state_table_name: PgQualifiedTableName,
        coordination_table_name: PgQualifiedTableName,
        fencing_counter_table_name: PgQualifiedTableName,
    ) -> Result<Self, Error> {
        let config = Self {
            root_key,
            state_table_name,
            coordination_table_name,
            fencing_counter_table_name,
            schema_ledger_table_name: SchemaLedgerConfig::default().table_name,
            create_state_updated_at_index: true,
        };
        validate_distinct_table_names(&config)?;
        Ok(config)
    }

    pub(crate) fn kv_store_config(&self) -> KvStoreConfig {
        KvStoreConfig {
            table_name: self.state_table_name.clone(),
            schema_ledger_table_name: self.schema_ledger_table_name.clone(),
            create_updated_at_index: self.create_state_updated_at_index,
        }
    }

    pub(crate) fn lease_store_config(&self) -> RawLeaseStoreConfig {
        RawLeaseStoreConfig::new_with_explicit_fencing_counter_table(
            self.coordination_table_name.clone(),
            self.fencing_counter_table_name.clone(),
        )
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            root_key: RootKey::default(),
            state_table_name: PgQualifiedTableName::unqualified(DEFAULT_FLEET_STATE_TABLE_NAME)
                .expect("default Fleet state table name must be a valid Postgres identifier"),
            coordination_table_name: PgQualifiedTableName::unqualified(
                DEFAULT_FLEET_COORDINATION_TABLE_NAME,
            )
            .expect("default Fleet coordination table name must be a valid Postgres identifier"),
            fencing_counter_table_name: PgQualifiedTableName::unqualified(
                DEFAULT_FLEET_FENCING_COUNTER_TABLE_NAME,
            )
            .expect("default Fleet fencing counter table name must be a valid Postgres identifier"),
            schema_ledger_table_name: SchemaLedgerConfig::default().table_name,
            create_state_updated_at_index: true,
        }
    }
}

impl Store {
    /// Creates a Fleet store handle with precomputed backing stores.
    pub fn new(config: StoreConfig) -> Result<Self, Error> {
        validate_distinct_table_names(&config)?;
        let kv_store = KvStore::new(config.kv_store_config())?;
        let lease_store = LeaseStore::new(config.lease_store_config());
        Ok(Self {
            config,
            kv_store,
            lease_store,
        })
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

    /// Creates a coordination-backed mutex handle.
    pub fn new_mutex(&self, key: MutexKey, claim_duration: ClaimDuration) -> Result<Mutex, Error> {
        let lease_key = LeaseKey::from_parts([
            self.config.root_key.as_str(),
            FLEET_MUTEX_COMPONENT_KEY,
            key.as_str(),
        ])
        .map_err(|source| Error::InvalidMutexKey { source })?;

        Ok(Mutex {
            lease_store: self.lease_store.clone(),
            key,
            lease_key,
            claim_duration,
        })
    }

    /// Creates a KV-backed atomic counter handle.
    pub fn new_counter(&self, key: CounterKey) -> Result<Counter, Error> {
        let prefix = build_counter_prefix(self.config.root_key.as_str(), key.as_str())?;
        Ok(Counter {
            item: KvItem::new_plain(self.kv_store.clone(), prefix),
            key,
        })
    }

    /// Creates a distributed cache that coalesces concurrent cache-miss computations.
    pub fn new_coalescing_cache<T>(
        &self,
        config: CoalescingCacheConfig,
    ) -> Result<CoalescingCache<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let lock_wait_timeout = config
            .lock_wait_timeout
            .unwrap_or(DEFAULT_COALESCING_CACHE_LOCK_WAIT_TIMEOUT);
        validate_positive_duration_for_coalescing_cache_lock_wait_timeout(lock_wait_timeout)?;
        if let Some(compute_timeout) = config.compute_timeout {
            validate_positive_duration_for_coalescing_cache_compute_timeout(compute_timeout)?;
        }

        let value_prefix =
            build_coalescing_cache_value_prefix(self.config.root_key.as_str(), config.key.as_str())
                .map_err(|source| Error::InvalidCoalescingCacheKeyForValue { source })?;
        let epoch_prefix =
            build_coalescing_cache_epoch_prefix(self.config.root_key.as_str(), config.key.as_str())
                .map_err(|source| Error::InvalidCoalescingCacheKeyForEpoch { source })?;
        build_coalescing_cache_mutex_lease_key(
            self.config.root_key.as_str(),
            config.key.as_str(),
            std::iter::empty::<&str>(),
        )
        .map_err(|source| Error::InvalidCoalescingCacheKeyForMutex { source })?;

        Ok(CoalescingCache {
            key: config.key,
            value_ttl: config.value_ttl,
            lock_wait_timeout,
            compute_timeout: config.compute_timeout,
            value_item: KvItem::new_plain(self.kv_store.clone(), value_prefix),
            epoch_item: KvItem::new_plain(self.kv_store.clone(), epoch_prefix),
            mutex_lease_store: self.lease_store.clone(),
            mutex_claim_duration: ClaimDuration::expires_after(
                DEFAULT_COALESCING_CACHE_MUTEX_CLAIM_DURATION,
            )
            .expect("default coalescing cache mutex claim duration must be valid"),
            root_key: self.config.root_key.clone(),
            marker: PhantomData,
        })
    }

    /// Creates a durable topic handle.
    pub fn new_topic<T>(&self, config: TopicConfig) -> Result<Topic<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let sequence_prefix =
            build_topic_sequence_prefix(self.config.root_key.as_str(), config.key.as_str())
                .map_err(|source| Error::InvalidTopicKeyForSequence { source })?;
        let events_prefix =
            build_topic_events_prefix(self.config.root_key.as_str(), config.key.as_str())
                .map_err(|source| Error::InvalidTopicKeyForEvents { source })?;

        Ok(Topic {
            key: config.key,
            event_ttl: config.event_ttl,
            sequence_item: KvItem::new_plain(self.kv_store.clone(), sequence_prefix),
            event_prefix: events_prefix.clone(),
            event_item: KvItem::new_plain(self.kv_store.clone(), events_prefix),
            cursor_store: self.kv_store.clone(),
            polling_mutex_lease_store: self.lease_store.clone(),
            root_key: self.config.root_key.clone(),
            marker: PhantomData,
        })
    }

    /// Creates a coordination-backed cron handle.
    pub fn new_cron(&self, config: CronConfig) -> Result<Cron, Error> {
        if config.interval < MIN_FLEET_CRON_INTERVAL {
            return Err(Error::InvalidCronInterval {
                minimum: MIN_FLEET_CRON_INTERVAL,
            });
        }

        let claim_duration = config.claim_duration.unwrap_or_else(|| {
            ClaimDuration::expires_after(DEFAULT_FLEET_CRON_CLAIM_DURATION)
                .expect("default Fleet cron claim duration must be valid")
        });
        let mutex_lease_key =
            build_cron_mutex_lease_key(self.config.root_key.as_str(), config.key.as_str())
                .map_err(|source| Error::InvalidCronKey { source })?;
        let heartbeat_interval = config
            .heartbeat_interval
            .unwrap_or(DEFAULT_FLEET_CRON_HEARTBEAT_INTERVAL);
        let acquire_retry_interval = config
            .acquire_retry_interval
            .unwrap_or(DEFAULT_FLEET_CRON_ACQUIRE_RETRY_INTERVAL);
        let guard_config = MutexGuardConfig {
            heartbeat_interval: Some(heartbeat_interval),
            acquire_retry_interval: Some(acquire_retry_interval),
            max_acquire_retry_interval: None,
            max_consecutive_renewal_failures: config.max_consecutive_renewal_failures,
        };
        guard_config.resolve_for_claim_duration(claim_duration)?;
        let mutex = Mutex {
            lease_store: self.lease_store.clone(),
            key: MutexKey(config.key.as_str().to_owned()),
            lease_key: mutex_lease_key,
            claim_duration,
        };

        Ok(Cron {
            key: config.key,
            interval: config.interval,
            mutex,
            guard_config,
        })
    }

    /// Creates a KV-slot-backed semaphore handle.
    pub fn new_semaphore(
        &self,
        key: SemaphoreKey,
        max_concurrent: u16,
        max_hold_duration: Duration,
    ) -> Result<Semaphore, Error> {
        if max_concurrent == 0 || max_concurrent > FLEET_MAX_CONCURRENT_LIMIT {
            return Err(Error::InvalidSemaphoreMaxConcurrent {
                value: max_concurrent,
                max: FLEET_MAX_CONCURRENT_LIMIT,
            });
        }
        let max_hold_ttl = KvTtl::expires_after(max_hold_duration)
            .map_err(|source| Error::InvalidSemaphoreMaxHoldDuration { source })?;
        let prefix = build_semaphore_slots_prefix(self.config.root_key.as_str(), key.as_str())?;
        let slot_suffixes = (1..=max_concurrent)
            .map(|slot_number| slot_number.to_string())
            .collect();

        Ok(Semaphore {
            key,
            max_concurrent,
            max_hold_ttl,
            slot_suffixes,
            slots_item: KvItem::new_plain(self.kv_store.clone(), prefix),
        })
    }

    /// Creates a KV-backed throttler handle.
    pub fn new_throttler(&self, config: ThrottlerConfig) -> Result<Throttler, Error> {
        let rate_limit = config
            .rate_limit
            .map(resolve_throttler_rate_limit)
            .transpose()?;
        let concurrency_limit = config
            .concurrency_limit
            .map(resolve_throttler_concurrency_limit)
            .transpose()?;
        let circuit_breaker = config
            .circuit_breaker
            .map(resolve_throttler_circuit_breaker)
            .transpose()?;

        if rate_limit.is_none() && concurrency_limit.is_none() && circuit_breaker.is_none() {
            return Err(Error::InvalidThrottlerHasNoControls);
        }

        let state_ttl = throttler_state_ttl(rate_limit, concurrency_limit, circuit_breaker)?;
        let prefix =
            build_throttler_state_prefix(self.config.root_key.as_str(), config.key.as_str())?;

        Ok(Throttler {
            key: config.key,
            rate_limit,
            concurrency_limit,
            circuit_breaker,
            state_ttl,
            state_item: KvItem::new_plain(self.kv_store.clone(), prefix),
        })
    }

    /// Creates a specialized rate-limiter handle.
    pub fn new_rate_limiter(
        &self,
        key: RateLimiterKey,
        rate_limit: RateLimitConfig,
    ) -> Result<RateLimiter, Error> {
        let throttler_key = ThrottlerKey(key.as_str().to_owned());
        Ok(RateLimiter {
            key,
            throttler: self.new_throttler(ThrottlerConfig {
                key: throttler_key,
                rate_limit: Some(ThrottlerRateLimit {
                    requests_per_interval: rate_limit.requests_per_interval,
                    interval: rate_limit.interval,
                }),
                concurrency_limit: None,
                circuit_breaker: None,
            })?,
        })
    }

    /// Creates a specialized circuit-breaker handle.
    pub fn new_circuit_breaker(
        &self,
        key: CircuitBreakerKey,
        circuit_breaker: CircuitBreakerConfig,
    ) -> Result<CircuitBreaker, Error> {
        let throttler_key = ThrottlerKey(key.as_str().to_owned());
        Ok(CircuitBreaker {
            key,
            throttler: self.new_throttler(ThrottlerConfig {
                key: throttler_key,
                rate_limit: None,
                concurrency_limit: None,
                circuit_breaker: Some(ThrottlerCircuitBreaker {
                    failure_threshold: circuit_breaker.failure_threshold,
                    recovery_timeout: circuit_breaker.recovery_timeout,
                }),
            })?,
        })
    }

    /// Creates a KV-and-mutex-backed run-once task handle.
    pub fn new_once(&self, key: OnceKey, claim_duration: ClaimDuration) -> Result<Once, Error> {
        let completion_prefix =
            build_once_completion_prefix(self.config.root_key.as_str(), key.as_str())?;
        let mutex_lease_key =
            build_once_mutex_lease_key(self.config.root_key.as_str(), key.as_str())?;
        let mutex = Mutex {
            lease_store: self.lease_store.clone(),
            key: MutexKey(key.as_str().to_owned()),
            lease_key: mutex_lease_key,
            claim_duration,
        };

        Ok(Once {
            completion_item: KvItem::new_plain(self.kv_store.clone(), completion_prefix),
            key,
            mutex,
        })
    }
}

fn validate_distinct_table_names(config: &StoreConfig) -> Result<(), Error> {
    if pg_table_name_set_could_contain_same_relation(&[
        &config.state_table_name,
        &config.coordination_table_name,
        &config.fencing_counter_table_name,
        &config.schema_ledger_table_name,
    ]) {
        return Err(Error::TableNamesMustBeDistinct);
    }
    Ok(())
}

/// Creates and validates the configured Fleet schema inside one transaction.
pub(crate) async fn migrate_schema(
    pool: &Pool,
    config: &StoreConfig,
) -> Result<(), crate::db::Error> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    let mut tx = pool.begin_transaction().await?;
    let result = migrate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_transaction(FLEET_OPERATION_SCHEMA_MIGRATE, tx, result).await
}

/// Creates and validates the configured Fleet schema inside the caller's transaction.
pub(crate) async fn migrate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), crate::db::Error> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    migrate_kv_schema_in_current_transaction(tx, &config.kv_store_config()).await?;
    migrate_lease_schema_in_current_transaction(tx, &config.lease_store_config()).await?;
    record_fleet_schema_version_in_current_transaction(tx, config).await?;
    validate_schema_in_current_transaction(tx, config).await
}

/// Validates that the configured Fleet schema already exists and is compatible.
pub(crate) async fn validate_schema(
    pool: &Pool,
    config: &StoreConfig,
) -> Result<(), crate::db::Error> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    let mut tx = pool.begin_transaction().await?;
    let validation_result = validate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_validation_transaction(FLEET_OPERATION_SCHEMA_VALIDATE, tx, validation_result)
        .await
}

async fn validate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    KvStore::new(config.kv_store_config())
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?
        .validate_schema_in_current_transaction(tx)
        .await?;
    LeaseStore::new(config.lease_store_config())
        .validate_schema_in_current_transaction(tx)
        .await?;
    validate_fleet_schema_version_in_current_transaction(tx, config).await
}

async fn record_fleet_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    let instance_key = fleet_schema_instance_key(config);
    record_component_schema_version_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        ComponentSchemaVersion {
            component: FLEET_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: FLEET_SCHEMA_VERSION,
            fingerprint: FLEET_SCHEMA_FINGERPRINT,
        },
    )
    .await
}

async fn validate_fleet_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    let instance_key = fleet_schema_instance_key(config);
    validate_component_schema_version_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        ComponentSchemaVersion {
            component: FLEET_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: FLEET_SCHEMA_VERSION,
            fingerprint: FLEET_SCHEMA_FINGERPRINT,
        },
    )
    .await
}

fn fleet_schema_instance_key(config: &StoreConfig) -> String {
    format!(
        "root={};{}",
        config.root_key.as_str(),
        schema_instance_key_for_parts([
            ("state_table", &config.state_table_name),
            ("coordination_table", &config.coordination_table_name),
            ("fencing_counter_table", &config.fencing_counter_table_name),
        ])
    )
}
