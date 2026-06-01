use super::*;

#[tokio::test]
async fn fleet_store_reports_missing_backing_schema_as_database_error() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("missing-schema").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let err = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim(&test_database.paranoid_pool)
        .await
        .expect_err("missing schema should be reported");
    assert!(
        matches!(
            err,
            Error::Coordination(CoordinationError::Database(DbError::Query { .. }))
        ),
        "error = {err:?}"
    );
}

#[tokio::test]
async fn fleet_keys_validate_before_database_work() {
    assert!(RootKey::new("__custom_fleet").is_ok());
    assert!(CounterKey::new("page_views").is_ok());
    assert!(CoalescingCacheKey::new("profiles").is_ok());
    assert!(TopicKey::new("notifications").is_ok());
    assert!(SubscriptionKey::new("worker").is_ok());
    assert!(MutexKey::new("daily_job").is_ok());
    assert!(OnceKey::new("schema_bootstrap").is_ok());
    assert!(SemaphoreKey::new("webhook_workers").is_ok());
    assert!(ThrottlerKey::new("login_attempts").is_ok());
    assert!(matches!(
        RootKey::new(""),
        Err(Error::InvalidRootKey { .. })
    ));
    assert!(matches!(
        RootKey::new("has:colon"),
        Err(Error::InvalidRootKey { .. })
    ));
    assert!(matches!(
        CounterKey::new(""),
        Err(Error::InvalidCounterKey { .. })
    ));
    assert!(matches!(
        CounterKey::new("has:colon"),
        Err(Error::InvalidCounterKey { .. })
    ));
    assert!(matches!(
        CoalescingCacheKey::new(""),
        Err(Error::InvalidCoalescingCacheKeyForValue { .. })
    ));
    assert!(matches!(
        CoalescingCacheKey::new("has:colon"),
        Err(Error::InvalidCoalescingCacheKeyForValue { .. })
    ));
    assert!(matches!(
        TopicKey::new(""),
        Err(Error::InvalidTopicKeyForSequence { .. })
    ));
    assert!(matches!(
        TopicKey::new("has:colon"),
        Err(Error::InvalidTopicKeyForSequence { .. })
    ));
    let oversized_key = "x".repeat(paranoid::kv::MAX_KEY_BYTES);
    assert!(matches!(
        TopicKey::new(&oversized_key),
        Err(Error::InvalidTopicKeyForSequence { .. })
    ));
    assert!(matches!(
        SubscriptionKey::new(""),
        Err(Error::InvalidSubscriptionKeyForCursor { .. })
    ));
    assert!(matches!(
        SubscriptionKey::new("has:colon"),
        Err(Error::InvalidSubscriptionKeyForCursor { .. })
    ));
    assert!(matches!(
        SubscriptionKey::new(&oversized_key),
        Err(Error::InvalidSubscriptionKeyForCursor { .. })
    ));
    assert!(matches!(
        MutexKey::new(""),
        Err(Error::InvalidMutexKey { .. })
    ));
    assert!(matches!(
        MutexKey::new("has:colon"),
        Err(Error::InvalidMutexKey { .. })
    ));
    assert!(matches!(
        OnceKey::new(""),
        Err(Error::InvalidOnceKeyForCompletionMarker { .. })
    ));
    assert!(matches!(
        OnceKey::new("has:colon"),
        Err(Error::InvalidOnceKeyForCompletionMarker { .. })
    ));
    assert!(matches!(
        SemaphoreKey::new(""),
        Err(Error::InvalidSemaphoreKey { .. })
    ));
    assert!(matches!(
        SemaphoreKey::new("has:colon"),
        Err(Error::InvalidSemaphoreKey { .. })
    ));
    assert!(matches!(
        ThrottlerKey::new(""),
        Err(Error::InvalidThrottlerKey { .. })
    ));
    assert!(matches!(
        ThrottlerKey::new("has:colon"),
        Err(Error::InvalidThrottlerKey { .. })
    ));

    let store = Store::new(StoreConfig::default()).expect("fleet store");
    assert!(matches!(
        store.new_semaphore(
            SemaphoreKey::new("zero_workers").expect("valid key"),
            0,
            Duration::from_secs(60)
        ),
        Err(Error::InvalidSemaphoreMaxConcurrent { .. })
    ));
    assert!(matches!(
        store.new_semaphore(
            SemaphoreKey::new("too_many_workers").expect("valid key"),
            MAX_CONCURRENT_LIMIT + 1,
            Duration::from_secs(60)
        ),
        Err(Error::InvalidSemaphoreMaxConcurrent { .. })
    ));
    assert!(matches!(
        store.new_semaphore(
            SemaphoreKey::new("zero_hold").expect("valid key"),
            1,
            Duration::ZERO
        ),
        Err(Error::InvalidSemaphoreMaxHoldDuration { .. })
    ));
    assert!(matches!(
        store.new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("no_controls").expect("valid key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: None,
        }),
        Err(Error::InvalidThrottlerHasNoControls)
    ));
    assert!(matches!(
        store.new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("zero_rate").expect("valid key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 0,
                interval: Duration::from_secs(1),
            }),
            concurrency_limit: None,
            circuit_breaker: None,
        }),
        Err(Error::InvalidThrottlerRequestsPerInterval)
    ));
    assert!(matches!(
        store.new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("zero_interval").expect("valid key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 1,
                interval: Duration::ZERO,
            }),
            concurrency_limit: None,
            circuit_breaker: None,
        }),
        Err(Error::InvalidThrottlerRateLimitInterval)
    ));
    assert!(matches!(
        store.new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("too_many_workers").expect("valid key"),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: MAX_CONCURRENT_LIMIT + 1,
                max_hold_duration: Some(Duration::from_secs(1)),
            }),
            circuit_breaker: None,
        }),
        Err(Error::InvalidThrottlerMaxConcurrent { .. })
    ));
    assert!(matches!(
        store.new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("zero_threshold").expect("valid key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 0,
                recovery_timeout: Duration::from_secs(1),
            }),
        }),
        Err(Error::InvalidThrottlerFailureThreshold)
    ));
    assert!(matches!(
        store.new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("zero_recovery").expect("valid key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::ZERO,
            }),
        }),
        Err(Error::InvalidThrottlerRecoveryTimeout)
    ));
    assert!(matches!(
        store.new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("bad_lock_timeout").expect("valid key"),
            value_ttl: KvTtl::no_expiration(),
            lock_wait_timeout: Some(Duration::ZERO),
            compute_timeout: None,
        }),
        Err(Error::InvalidCoalescingCacheLockWaitTimeout)
    ));
    assert!(matches!(
        store.new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("bad_compute_timeout").expect("valid key"),
            value_ttl: KvTtl::no_expiration(),
            lock_wait_timeout: None,
            compute_timeout: Some(Duration::ZERO),
        }),
        Err(Error::InvalidCoalescingCacheComputeTimeout)
    ));
    let topic = store
        .new_topic::<String>(TopicConfig {
            key: TopicKey::new("bad_subscription_config").expect("valid key"),
            event_ttl: KvTtl::no_expiration(),
        })
        .expect("new topic");
    assert!(matches!(
        topic.subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("zero_poll").expect("valid key"),
            poll_limit: Some(0),
        }),
        Err(Error::InvalidSubscriptionPollLimit { .. })
    ));
    assert!(matches!(
        topic.subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("excessive_poll").expect("valid key"),
            poll_limit: Some(MAX_SUBSCRIPTION_POLL_LIMIT + 1),
        }),
        Err(Error::InvalidSubscriptionPollLimit { .. })
    ));
}
