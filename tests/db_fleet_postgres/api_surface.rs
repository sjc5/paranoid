use super::*;

#[test]
fn fleet_constructor_api_surface_compiles_through_namespaced_exports() {
    let explicit_config = StoreConfig::new(
        RootKey::default(),
        unique_test_table_name(),
        unique_test_table_name(),
    )
    .expect("fleet config");
    let store = Store::new(explicit_config).expect("fleet store");
    let claim_duration = ClaimDuration::expires_after(Duration::from_secs(60)).expect("lease");

    let mutex: paranoid::fleet::Mutex = store
        .new_mutex(
            MutexKey::new("api-mutex").expect("mutex key"),
            claim_duration,
        )
        .expect("new mutex");
    let counter: paranoid::fleet::Counter = store
        .new_counter(CounterKey::new("api-counter").expect("counter key"))
        .expect("new counter");
    let cache: paranoid::fleet::CoalescingCache<String> = store
        .new_coalescing_cache(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("api-cache").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");
    let topic: paranoid::fleet::Topic<String> = store
        .new_topic(TopicConfig {
            key: TopicKey::new("api-topic").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        })
        .expect("new topic");
    let subscription: paranoid::fleet::Subscription<String> = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("api-subscription").expect("subscription key"),
            poll_limit: None,
        })
        .expect("new subscription");
    let cron: paranoid::fleet::Cron = store
        .new_cron(CronConfig {
            key: CronKey::new("api-cron").expect("cron key"),
            interval: MIN_CRON_INTERVAL,
            claim_duration: None,
            heartbeat_interval: None,
            acquire_retry_interval: None,
            max_consecutive_renewal_failures: None,
        })
        .expect("new cron");
    let semaphore: paranoid::fleet::Semaphore = store
        .new_semaphore(
            SemaphoreKey::new("api-semaphore").expect("semaphore key"),
            2,
            Duration::from_secs(60),
        )
        .expect("new semaphore");
    let throttler: paranoid::fleet::Throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("api-throttler").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 1,
                interval: Duration::from_secs(1),
            }),
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: None,
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(1),
            }),
        })
        .expect("new throttler");
    let rate_limiter: paranoid::fleet::RateLimiter = store
        .new_rate_limiter(
            RateLimiterKey::new("api-rate-limiter").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 1,
                interval: Duration::from_secs(1),
            },
        )
        .expect("new rate limiter");
    let circuit_breaker: paranoid::fleet::CircuitBreaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("api-circuit-breaker").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(1),
            },
        )
        .expect("new circuit breaker");
    let once: paranoid::fleet::Once = store
        .new_once(OnceKey::new("api-once").expect("once key"), claim_duration)
        .expect("new once");

    let _: paranoid::fleet::manual::MutexManualRenewalProtocol<'_> =
        mutex.begin_manual_renewal_lifecycle();
    let _: paranoid::fleet::manual::SemaphoreManualClaimProtocol<'_> =
        semaphore.begin_manual_claim_lifecycle();
    let _: paranoid::fleet::manual::ThrottlerManualPermitProtocol<'_> =
        throttler.begin_manual_permit_lifecycle();
    let _: paranoid::fleet::manual::RateLimiterManualPermitProtocol<'_> =
        rate_limiter.begin_manual_permit_lifecycle();
    let _: paranoid::fleet::manual::CircuitBreakerManualPermitProtocol<'_> =
        circuit_breaker.begin_manual_permit_lifecycle();
    let _: paranoid::fleet::manual::OnceManualRunProtocol<'_> = once.begin_manual_run_lifecycle();

    let _ = (
        mutex,
        counter,
        cache,
        topic,
        subscription,
        cron,
        semaphore,
        throttler,
        rate_limiter,
        circuit_breaker,
        once,
    );
}

#[test]
fn fleet_table_names_must_not_overlap() {
    let shared_table = unique_test_table_name();
    assert!(matches!(
        StoreConfig::new(RootKey::default(), shared_table.clone(), shared_table),
        Err(paranoid::fleet::Error::TableNamesMustBeDistinct)
    ));

    let state_table = unique_test_table_name();
    let coordination_table = unique_test_table_name();
    assert!(matches!(
        StoreConfig::new_with_explicit_fencing_counter_table(
            RootKey::default(),
            state_table.clone(),
            coordination_table.clone(),
            coordination_table,
        ),
        Err(paranoid::fleet::Error::TableNamesMustBeDistinct)
    ));

    let ambiguous_state_table =
        paranoid::db::PgQualifiedTableName::unqualified("__paranoid_same_fleet_table")
            .expect("table");
    let ambiguous_ledger_table =
        paranoid::db::PgQualifiedTableName::with_schema("public", "__paranoid_same_fleet_table")
            .expect("table");
    let config = StoreConfig {
        root_key: RootKey::default(),
        state_table_name: ambiguous_state_table,
        coordination_table_name: unique_test_table_name(),
        fencing_counter_table_name: unique_test_table_name(),
        schema_ledger_table_name: ambiguous_ledger_table,
        create_state_updated_at_index: true,
    };
    assert!(matches!(
        Store::new(config),
        Err(paranoid::fleet::Error::TableNamesMustBeDistinct)
    ));
}

#[test]
fn fleet_constructor_options_apply_defaults_without_database_work() {
    let store = Store::new(StoreConfig::default()).expect("fleet store");
    let cron = store
        .new_cron(CronConfig {
            key: CronKey::new("defaulted-cron").expect("cron key"),
            interval: MIN_CRON_INTERVAL,
            claim_duration: None,
            heartbeat_interval: None,
            acquire_retry_interval: None,
            max_consecutive_renewal_failures: None,
        })
        .expect("new cron with defaults");
    assert_eq!(cron.interval(), MIN_CRON_INTERVAL);
    assert_eq!(
        cron.claim_duration().as_duration(),
        paranoid::fleet::DEFAULT_CRON_CLAIM_DURATION
    );

    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("defaulted-cache").expect("cache key"),
            value_ttl: KvTtl::no_expiration(),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache with defaults");
    assert_eq!(
        cache.lock_wait_timeout(),
        paranoid::fleet::DEFAULT_COALESCING_CACHE_LOCK_WAIT_TIMEOUT
    );
    assert_eq!(cache.compute_timeout(), None);

    let _default_mutex_guard_config = MutexGuardConfig::default();
    let _: Duration = paranoid::fleet::DEFAULT_MUTEX_MAX_ACQUIRE_RETRY_INTERVAL;
}

#[test]
fn fleet_error_display_messages_are_specific_for_zero_source_variants() {
    let messages = [
        (
            Error::CounterArithmeticOverflow,
            "Fleet counter arithmetic overflow",
        ),
        (
            Error::InvalidCoalescingCacheLockWaitTimeout,
            "Fleet coalescing cache lock wait timeout must be positive and fit in microseconds",
        ),
        (
            Error::InvalidCoalescingCacheComputeTimeout,
            "Fleet coalescing cache compute timeout must be positive and fit in microseconds",
        ),
        (
            Error::TopicSequenceMustBeNonNegative,
            "Fleet topic sequence must be non-negative",
        ),
        (
            Error::TopicSequenceOverflow,
            "Fleet topic sequence overflow",
        ),
        (
            Error::InvalidThrottlerHasNoControls,
            "Fleet throttler must enable rate limiting, concurrency limiting, or circuit breaking",
        ),
        (
            Error::InvalidThrottlerRequestsPerInterval,
            "Fleet throttler rate limit requests-per-interval cannot be zero",
        ),
        (
            Error::InvalidThrottlerFailureThreshold,
            "Fleet throttler failure threshold cannot be zero",
        ),
        (
            Error::ThrottlerHolderIdRequired,
            "Fleet throttler holder identifier is required for this operation",
        ),
        (
            Error::RunOnceManualRunClaimNoLongerLive,
            "Fleet manual run-once claim is no longer live",
        ),
    ];

    for (error, expected_message) in messages {
        assert_eq!(error.to_string(), expected_message);
    }
}
