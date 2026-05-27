use super::throttler_support::duration_to_rounded_microseconds;
#[cfg(test)]
use super::throttler_support::{
    compute_rate_limit_retry_after_duration, max_kv_ttl_duration,
    resolve_throttler_circuit_breaker, resolve_throttler_concurrency_limit,
    resolve_throttler_rate_limit, throttler_state_ttl,
};
#[cfg(test)]
use super::topic_support::{
    is_retryable_subscription_poll_error, parse_topic_sequence_key_suffix,
    subscription_poll_error_retry_delay_from_policy, topic_sequence_key_suffix,
};
use super::*;

pub(super) fn generate_holder_id() -> Result<HolderId, Error> {
    let id = id::SortableId::new().map_err(|source| Error::HolderIdGeneration { source })?;
    HolderId::new(id.to_text()).map_err(|source| Error::GeneratedHolderIdRejected { source })
}

pub(super) fn is_retryable_database_operation_error(error: &DbError) -> bool {
    match error {
        DbError::Transaction { .. } => true,
        DbError::Query {
            sql_state: Some(PgSqlState::SerializationFailure | PgSqlState::DeadlockDetected),
            ..
        } => true,
        DbError::Query {
            sql_state: Some(PgSqlState::Other(code)),
            ..
        } => {
            matches!(code.get(..2), Some("08" | "53" | "58"))
                || matches!(
                    code.as_str(),
                    SQLSTATE_QUERY_CANCELED
                        | SQLSTATE_ADMIN_SHUTDOWN
                        | SQLSTATE_CRASH_SHUTDOWN
                        | SQLSTATE_CANNOT_CONNECT_NOW
                        | SQLSTATE_LOCK_NOT_AVAILABLE
                )
        }
        DbError::Query {
            sql_state: None, ..
        } => true,
        _ => false,
    }
}

pub(super) fn validate_positive_duration_for_coalescing_cache_lock_wait_timeout(
    duration: Duration,
) -> Result<(), Error> {
    if duration.is_zero() || duration_to_rounded_microseconds(duration).is_none() {
        return Err(Error::InvalidCoalescingCacheLockWaitTimeout);
    }
    Ok(())
}

pub(super) fn validate_positive_duration_for_coalescing_cache_compute_timeout(
    duration: Duration,
) -> Result<(), Error> {
    if duration.is_zero() || duration_to_rounded_microseconds(duration).is_none() {
        return Err(Error::InvalidCoalescingCacheComputeTimeout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::mutex::apply_fleet_mutex_acquire_retry_jitter_with_unit;
    use super::*;
    use crate::db::lease::{MAX_LEASE_KEY_BYTES, MIN_LEASE_DURATION};
    use proptest::prelude::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[derive(Debug, Eq, PartialEq)]
    struct TestHandlerError;

    impl std::fmt::Display for TestHandlerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test handler error")
        }
    }

    impl std::error::Error for TestHandlerError {}

    fn database_query_error(message: &'static str) -> Error {
        Error::Database(DbError::Query {
            sql_state: None,
            source: Box::new(std::io::Error::other(message)),
        })
    }

    fn database_query_error_with_sql_state(sql_state: PgSqlState) -> Error {
        Error::Database(DbError::Query {
            sql_state: Some(sql_state),
            source: Box::new(std::io::Error::other("query failed")),
        })
    }

    fn kv_database_query_error_with_sql_state(sql_state: PgSqlState) -> Error {
        Error::Kv(KvError::Database(DbError::Query {
            sql_state: Some(sql_state),
            source: Box::new(std::io::Error::other("KV query failed")),
        }))
    }

    fn generated_key_candidate(rng: &mut ChaCha20Rng, len: usize) -> String {
        const CANDIDATE_BYTES: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./";
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let idx = rng.random_range(0..CANDIDATE_BYTES.len());
            out.push(char::from(CANDIDATE_BYTES[idx]));
        }
        out
    }

    fn valid_fleet_key_text_strategy() -> impl Strategy<Value = String> {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./é日"
            .chars()
            .collect::<Vec<_>>();
        prop::collection::vec(prop::sample::select(chars), 1..=64)
            .prop_map(|chars| chars.into_iter().collect())
    }

    fn invalid_fleet_key_text_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            (
                valid_fleet_key_text_strategy(),
                valid_fleet_key_text_strategy()
            )
                .prop_map(|(left, right)| format!("{left}:{right}")),
            (
                valid_fleet_key_text_strategy(),
                valid_fleet_key_text_strategy()
            )
                .prop_map(|(left, right)| format!("{left}\0{right}")),
            Just("x".repeat(MAX_LEASE_KEY_BYTES)),
        ]
    }

    fn generated_duration_candidate(selector: u8) -> Duration {
        match selector % 7 {
            0 => Duration::ZERO,
            1 => Duration::from_nanos(1),
            2 => MIN_KV_TTL - Duration::from_nanos(1),
            3 => MIN_KV_TTL,
            4 => DEFAULT_FLEET_CRON_CLAIM_DURATION,
            5 => max_kv_ttl_duration(),
            _ => max_kv_ttl_duration()
                .checked_add(Duration::from_micros(1))
                .expect("test duration should fit"),
        }
    }

    fn duration_fits_postgres_microseconds(duration: Duration) -> bool {
        duration_to_rounded_microseconds(duration).is_some()
    }

    fn duration_is_valid_throttler_duration(duration: Duration) -> bool {
        !duration.is_zero() && duration_fits_postgres_microseconds(duration)
    }

    fn duration_is_valid_kv_ttl(duration: Duration) -> bool {
        duration >= MIN_KV_TTL && duration_fits_postgres_microseconds(duration)
    }

    fn duration_is_valid_claim_duration(duration: Duration) -> bool {
        duration >= MIN_LEASE_DURATION && duration_fits_postgres_microseconds(duration)
    }

    #[test]
    fn fleet_root_and_primitive_keys_validate_against_persisted_shapes() {
        assert!(RootKey::new(DEFAULT_FLEET_ROOT_KEY).is_ok());
        assert!(MutexKey::new("leader").is_ok());
        assert!(CounterKey::new("page-views").is_ok());
        assert!(TopicKey::new("notifications").is_ok());
        assert!(SubscriptionKey::new("worker").is_ok());
        assert!(SemaphoreKey::new("workers").is_ok());
        assert!(ThrottlerKey::new("api").is_ok());
        assert!(RateLimiterKey::new("api-rate").is_ok());
        assert!(CircuitBreakerKey::new("api-circuit").is_ok());
        assert!(OnceKey::new("schema-bootstrap").is_ok());
        assert!(matches!(
            RootKey::new(""),
            Err(Error::InvalidRootKey { .. })
        ));
        assert!(matches!(
            RootKey::new("has:colon"),
            Err(Error::InvalidRootKey { .. })
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
            CounterKey::new(""),
            Err(Error::InvalidCounterKey { .. })
        ));
        assert!(matches!(
            CounterKey::new("has:colon"),
            Err(Error::InvalidCounterKey { .. })
        ));
        assert!(matches!(
            TopicKey::new(""),
            Err(Error::InvalidTopicKeyForSequence { .. })
        ));
        assert!(matches!(
            TopicKey::new("has:colon"),
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
        assert!(matches!(
            RateLimiterKey::new(""),
            Err(Error::InvalidRateLimiterKey { .. })
        ));
        assert!(matches!(
            RateLimiterKey::new("has:colon"),
            Err(Error::InvalidRateLimiterKey { .. })
        ));
        assert!(matches!(
            CircuitBreakerKey::new(""),
            Err(Error::InvalidCircuitBreakerKey { .. })
        ));
        assert!(matches!(
            CircuitBreakerKey::new("has:colon"),
            Err(Error::InvalidCircuitBreakerKey { .. })
        ));
        assert!(matches!(
            OnceKey::new(""),
            Err(Error::InvalidOnceKeyForCompletionMarker { .. })
        ));
        assert!(matches!(
            OnceKey::new("has:colon"),
            Err(Error::InvalidOnceKeyForCompletionMarker { .. })
        ));

        let oversized_key = "a".repeat(MAX_LEASE_KEY_BYTES);
        assert!(matches!(
            MutexKey::new(&oversized_key),
            Err(Error::InvalidMutexKey { .. })
        ));
        assert!(matches!(
            CounterKey::new(&oversized_key),
            Err(Error::InvalidCounterKey { .. })
        ));
        assert!(matches!(
            SemaphoreKey::new(&oversized_key),
            Err(Error::InvalidSemaphoreKey { .. })
        ));
        assert!(matches!(
            ThrottlerKey::new(&oversized_key),
            Err(Error::InvalidThrottlerKey { .. })
        ));
        assert!(matches!(
            RateLimiterKey::new(&oversized_key),
            Err(Error::InvalidRateLimiterKey { .. })
        ));
        assert!(matches!(
            CircuitBreakerKey::new(&oversized_key),
            Err(Error::InvalidCircuitBreakerKey { .. })
        ));
        assert!(matches!(
            OnceKey::new(oversized_key),
            Err(Error::InvalidOnceKeyForCompletionMarker { .. })
                | Err(Error::InvalidOnceKeyForMutex { .. })
        ));
    }

    #[test]
    fn fleet_property_style_key_constructors_are_consistent_for_generated_inputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5eed_f1ee7);
        let mut candidates = vec![
            String::new(),
            "has:colon".to_owned(),
            "has\0null".to_owned(),
            "normal".to_owned(),
            "a".repeat(MAX_LEASE_KEY_BYTES),
        ];
        for _ in 0..512 {
            let len = rng.random_range(0..=128);
            candidates.push(generated_key_candidate(&mut rng, len));
        }

        for candidate in candidates {
            let must_reject = candidate.is_empty()
                || candidate.contains(':')
                || candidate.contains('\0')
                || candidate.len() >= MAX_LEASE_KEY_BYTES;
            let must_accept = !must_reject && candidate.len() <= 32;

            let root_key = RootKey::new(&candidate);
            let mutex_key = MutexKey::new(&candidate);
            let counter_key = CounterKey::new(&candidate);
            let cache_key = CoalescingCacheKey::new(&candidate);
            let topic_key = TopicKey::new(&candidate);
            let subscription_key = SubscriptionKey::new(&candidate);
            let cron_key = CronKey::new(&candidate);
            let semaphore_key = SemaphoreKey::new(&candidate);
            let throttler_key = ThrottlerKey::new(&candidate);
            let rate_limiter_key = RateLimiterKey::new(&candidate);
            let circuit_breaker_key = CircuitBreakerKey::new(&candidate);
            let once_key = OnceKey::new(&candidate);

            if must_reject {
                assert!(root_key.is_err(), "RootKey accepted {candidate:?}");
                assert!(mutex_key.is_err(), "MutexKey accepted {candidate:?}");
                assert!(counter_key.is_err(), "CounterKey accepted {candidate:?}");
                assert!(
                    cache_key.is_err(),
                    "CoalescingCacheKey accepted {candidate:?}"
                );
                assert!(topic_key.is_err(), "TopicKey accepted {candidate:?}");
                assert!(
                    subscription_key.is_err(),
                    "SubscriptionKey accepted {candidate:?}"
                );
                assert!(cron_key.is_err(), "CronKey accepted {candidate:?}");
                assert!(
                    semaphore_key.is_err(),
                    "SemaphoreKey accepted {candidate:?}"
                );
                assert!(
                    throttler_key.is_err(),
                    "ThrottlerKey accepted {candidate:?}"
                );
                assert!(
                    rate_limiter_key.is_err(),
                    "RateLimiterKey accepted {candidate:?}"
                );
                assert!(
                    circuit_breaker_key.is_err(),
                    "CircuitBreakerKey accepted {candidate:?}"
                );
                assert!(once_key.is_err(), "OnceKey accepted {candidate:?}");
            }
            if must_accept {
                assert_eq!(root_key.expect("root key").as_str(), candidate);
                assert_eq!(mutex_key.expect("mutex key").as_str(), candidate);
                assert_eq!(counter_key.expect("counter key").as_str(), candidate);
                assert_eq!(cache_key.expect("cache key").as_str(), candidate);
                assert_eq!(topic_key.expect("topic key").as_str(), candidate);
                assert_eq!(
                    subscription_key.expect("subscription key").as_str(),
                    candidate
                );
                assert_eq!(cron_key.expect("cron key").as_str(), candidate);
                assert_eq!(semaphore_key.expect("semaphore key").as_str(), candidate);
                assert_eq!(throttler_key.expect("throttler key").as_str(), candidate);
                assert_eq!(
                    rate_limiter_key.expect("rate limiter key").as_str(),
                    candidate
                );
                assert_eq!(
                    circuit_breaker_key.expect("circuit breaker key").as_str(),
                    candidate
                );
                assert_eq!(once_key.expect("once key").as_str(), candidate);
            }
        }
    }

    #[test]
    fn fleet_property_style_constructor_options_and_subscription_poll_limits_are_consistent() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5eed_0a71);
        let store = Store::new(StoreConfig::default()).expect("fleet store");
        let topic = store
            .new_topic::<String>(TopicConfig {
                key: TopicKey::new("property-topic").expect("topic key"),
                event_ttl: KvTtl::expires_after(MIN_KV_TTL).expect("event ttl"),
            })
            .expect("topic");

        let mut poll_limits = vec![
            0,
            1,
            MAX_SUBSCRIPTION_POLL_LIMIT,
            MAX_SUBSCRIPTION_POLL_LIMIT + 1,
            u32::MAX,
        ];
        for _ in 0..512 {
            poll_limits.push(rng.random_range(0..=MAX_SUBSCRIPTION_POLL_LIMIT + 256));
        }

        for poll_limit in poll_limits {
            let result = topic.subscribe(SubscriptionConfig {
                key: SubscriptionKey::new(format!("worker-{poll_limit}"))
                    .expect("subscription key"),
                poll_limit: Some(poll_limit),
            });
            if (1..=MAX_SUBSCRIPTION_POLL_LIMIT).contains(&poll_limit) {
                assert_eq!(
                    result.expect("subscription").poll_limit(),
                    poll_limit,
                    "poll_limit {poll_limit}"
                );
            } else {
                assert!(matches!(
                    result,
                    Err(Error::InvalidSubscriptionPollLimit { value, .. }) if value == poll_limit
                ));
            }
        }
    }

    #[test]
    fn mutex_guard_config_resolves_capped_acquire_backoff() {
        let claim_duration =
            ClaimDuration::expires_after(DEFAULT_FLEET_MUTEX_CLAIM_DURATION).expect("duration");
        let default_config = MutexGuardConfig::default()
            .resolve_for_claim_duration(claim_duration)
            .expect("default mutex guard config");
        assert_eq!(
            default_config.acquire_retry_interval,
            DEFAULT_FLEET_MUTEX_ACQUIRE_RETRY_INTERVAL
        );
        assert_eq!(
            default_config.max_acquire_retry_interval,
            DEFAULT_FLEET_MUTEX_MAX_ACQUIRE_RETRY_INTERVAL
        );

        let long_initial_retry = MutexGuardConfig {
            acquire_retry_interval: Some(Duration::from_secs(5)),
            ..MutexGuardConfig::default()
        }
        .resolve_for_claim_duration(claim_duration)
        .expect("long initial retry should raise the implicit cap");
        assert_eq!(
            long_initial_retry.acquire_retry_interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            long_initial_retry.max_acquire_retry_interval,
            Duration::from_secs(5)
        );

        let invalid_cap = MutexGuardConfig {
            acquire_retry_interval: Some(Duration::from_millis(200)),
            max_acquire_retry_interval: Some(Duration::from_millis(100)),
            ..MutexGuardConfig::default()
        }
        .resolve_for_claim_duration(claim_duration)
        .expect_err("max acquire retry below initial retry should be rejected");
        assert!(matches!(
            invalid_cap,
            Error::InvalidMutexMaxAcquireRetryInterval
        ));
    }

    #[test]
    fn mutex_acquire_retry_jitter_matches_symmetric_fraction_bounds() {
        let base_delay = Duration::from_millis(100);
        assert_eq!(
            apply_fleet_mutex_acquire_retry_jitter_with_unit(base_delay, 0.0),
            Duration::from_millis(75)
        );
        assert_eq!(
            apply_fleet_mutex_acquire_retry_jitter_with_unit(base_delay, 0.5),
            base_delay
        );
        assert_eq!(
            apply_fleet_mutex_acquire_retry_jitter_with_unit(base_delay, 1.0),
            Duration::from_millis(125)
        );
        assert_eq!(
            apply_fleet_mutex_acquire_retry_jitter_with_unit(Duration::ZERO, 1.0),
            Duration::ZERO
        );
    }

    #[test]
    fn throttler_retry_after_duration_matches_token_refill_math() {
        assert_eq!(
            compute_rate_limit_retry_after_duration(0.0, 0.0),
            max_kv_ttl_duration()
        );
        assert_eq!(
            compute_rate_limit_retry_after_duration(0.999_999_999, 1_000.0),
            Duration::from_millis(1)
        );
        assert_eq!(
            compute_rate_limit_retry_after_duration(0.25, 2.0),
            Duration::from_millis(375)
        );
    }

    #[test]
    fn throttler_circuit_open_wait_is_clamped_and_scaled_from_recovery_timeout() {
        let store = Store::new(StoreConfig::default()).expect("fleet store");
        let tiny_recovery = store
            .new_circuit_breaker(
                CircuitBreakerKey::new("tiny_recovery").expect("valid key"),
                CircuitBreakerConfig {
                    failure_threshold: 1,
                    recovery_timeout: Duration::from_micros(1),
                },
            )
            .expect("tiny recovery circuit breaker");
        assert_eq!(
            tiny_recovery.throttler.circuit_open_wait(),
            MIN_FLEET_THROTTLER_CIRCUIT_OPEN_WAIT
        );

        let normal_recovery = store
            .new_circuit_breaker(
                CircuitBreakerKey::new("normal_recovery").expect("valid key"),
                CircuitBreakerConfig {
                    failure_threshold: 1,
                    recovery_timeout: Duration::from_millis(200),
                },
            )
            .expect("normal recovery circuit breaker");
        assert_eq!(
            normal_recovery.throttler.circuit_open_wait(),
            Duration::from_millis(20)
        );
    }

    #[test]
    fn fleet_constructors_validate_boundary_inputs_without_database_work() {
        let store = Store::new(StoreConfig::default()).expect("fleet store");
        let too_large_duration = max_kv_ttl_duration()
            .checked_add(Duration::from_nanos(1))
            .expect("test duration should fit Rust Duration");

        assert!(
            store
                .new_rate_limiter(
                    RateLimiterKey::new("rate-valid").expect("valid key"),
                    RateLimitConfig {
                        requests_per_interval: 1,
                        interval: MIN_KV_TTL,
                    },
                )
                .is_ok()
        );
        assert!(matches!(
            store.new_rate_limiter(
                RateLimiterKey::new("rate-zero-requests").expect("valid key"),
                RateLimitConfig {
                    requests_per_interval: 0,
                    interval: MIN_KV_TTL,
                },
            ),
            Err(Error::InvalidThrottlerRequestsPerInterval)
        ));
        assert!(matches!(
            store.new_rate_limiter(
                RateLimiterKey::new("rate-zero-interval").expect("valid key"),
                RateLimitConfig {
                    requests_per_interval: 1,
                    interval: Duration::ZERO,
                },
            ),
            Err(Error::InvalidThrottlerRateLimitInterval)
        ));
        assert!(matches!(
            store.new_rate_limiter(
                RateLimiterKey::new("rate-overflow-interval").expect("valid key"),
                RateLimitConfig {
                    requests_per_interval: 1,
                    interval: too_large_duration,
                },
            ),
            Err(Error::InvalidThrottlerRateLimitInterval)
        ));

        assert!(
            store
                .new_semaphore(
                    SemaphoreKey::new("semaphore-valid").expect("valid key"),
                    FLEET_MAX_CONCURRENT_LIMIT,
                    MIN_KV_TTL,
                )
                .is_ok()
        );
        for max_concurrent in [0, FLEET_MAX_CONCURRENT_LIMIT + 1] {
            assert!(matches!(
                store.new_semaphore(
                    SemaphoreKey::new(format!("semaphore-invalid-{max_concurrent}"))
                        .expect("valid key"),
                    max_concurrent,
                    MIN_KV_TTL,
                ),
                Err(Error::InvalidSemaphoreMaxConcurrent { .. })
            ));
        }
        for max_hold_duration in [
            Duration::ZERO,
            MIN_KV_TTL - Duration::from_nanos(1),
            too_large_duration,
        ] {
            assert!(matches!(
                store.new_semaphore(
                    SemaphoreKey::new(format!(
                        "semaphore-invalid-hold-{}",
                        max_hold_duration.as_nanos()
                    ))
                    .expect("valid key"),
                    1,
                    max_hold_duration,
                ),
                Err(Error::InvalidSemaphoreMaxHoldDuration { .. })
            ));
        }

        assert!(
            store
                .new_circuit_breaker(
                    CircuitBreakerKey::new("circuit-valid").expect("valid key"),
                    CircuitBreakerConfig {
                        failure_threshold: 1,
                        recovery_timeout: MIN_KV_TTL,
                    },
                )
                .is_ok()
        );
        assert!(matches!(
            store.new_circuit_breaker(
                CircuitBreakerKey::new("circuit-zero-threshold").expect("valid key"),
                CircuitBreakerConfig {
                    failure_threshold: 0,
                    recovery_timeout: MIN_KV_TTL,
                },
            ),
            Err(Error::InvalidThrottlerFailureThreshold)
        ));
        for recovery_timeout in [Duration::ZERO, too_large_duration] {
            assert!(matches!(
                store.new_circuit_breaker(
                    CircuitBreakerKey::new(format!(
                        "circuit-invalid-recovery-{}",
                        recovery_timeout.as_nanos()
                    ))
                    .expect("valid key"),
                    CircuitBreakerConfig {
                        failure_threshold: 1,
                        recovery_timeout,
                    },
                ),
                Err(Error::InvalidThrottlerRecoveryTimeout)
            ));
        }

        assert!(
            store
                .new_throttler(ThrottlerConfig {
                    key: ThrottlerKey::new("throttler-valid").expect("valid key"),
                    rate_limit: Some(ThrottlerRateLimit {
                        requests_per_interval: 1,
                        interval: MIN_KV_TTL,
                    }),
                    concurrency_limit: Some(ThrottlerConcurrencyLimit {
                        max_concurrent: 1,
                        max_hold_duration: Some(MIN_KV_TTL),
                    }),
                    circuit_breaker: Some(ThrottlerCircuitBreaker {
                        failure_threshold: 1,
                        recovery_timeout: MIN_KV_TTL,
                    }),
                })
                .is_ok()
        );
        assert!(matches!(
            store.new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("throttler-no-controls").expect("valid key"),
                rate_limit: None,
                concurrency_limit: None,
                circuit_breaker: None,
            }),
            Err(Error::InvalidThrottlerHasNoControls)
        ));
        assert!(matches!(
            store.new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("throttler-zero-concurrency").expect("valid key"),
                rate_limit: None,
                concurrency_limit: Some(ThrottlerConcurrencyLimit {
                    max_concurrent: 0,
                    max_hold_duration: Some(MIN_KV_TTL),
                }),
                circuit_breaker: None,
            }),
            Err(Error::InvalidThrottlerMaxConcurrent { .. })
        ));
        assert!(matches!(
            store.new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("throttler-zero-hold").expect("valid key"),
                rate_limit: None,
                concurrency_limit: Some(ThrottlerConcurrencyLimit {
                    max_concurrent: 1,
                    max_hold_duration: Some(Duration::ZERO),
                }),
                circuit_breaker: None,
            }),
            Err(Error::InvalidThrottlerMaxHoldDuration)
        ));

        assert!(
            store
                .new_cron(CronConfig {
                    key: CronKey::new("cron-valid").expect("valid key"),
                    interval: MIN_FLEET_CRON_INTERVAL,
                    claim_duration: Some(
                        ClaimDuration::expires_after(DEFAULT_FLEET_CRON_CLAIM_DURATION)
                            .expect("valid claim duration")
                    ),
                    heartbeat_interval: Some(DEFAULT_FLEET_CRON_HEARTBEAT_INTERVAL),
                    acquire_retry_interval: Some(DEFAULT_FLEET_CRON_ACQUIRE_RETRY_INTERVAL),
                    max_consecutive_renewal_failures: Some(1),
                })
                .is_ok()
        );
        assert!(matches!(
            store.new_cron(CronConfig {
                key: CronKey::new("cron-too-fast").expect("valid key"),
                interval: MIN_FLEET_CRON_INTERVAL - Duration::from_nanos(1),
                claim_duration: None,
                heartbeat_interval: None,
                acquire_retry_interval: None,
                max_consecutive_renewal_failures: None,
            }),
            Err(Error::InvalidCronInterval { .. })
        ));
        assert!(matches!(
            store.new_cron(CronConfig {
                key: CronKey::new("cron-zero-retry").expect("valid key"),
                interval: MIN_FLEET_CRON_INTERVAL,
                claim_duration: None,
                heartbeat_interval: None,
                acquire_retry_interval: Some(Duration::ZERO),
                max_consecutive_renewal_failures: None,
            }),
            Err(Error::InvalidMutexAcquireRetryInterval)
        ));

        let valid_once_duration = ClaimDuration::expires_after(DEFAULT_FLEET_ONCE_CLAIM_DURATION)
            .expect("valid once claim duration");
        assert!(
            store
                .new_once(
                    OnceKey::new("once-valid").expect("valid key"),
                    valid_once_duration,
                )
                .is_ok()
        );
        for invalid_once_duration in [
            Duration::ZERO,
            MIN_LEASE_DURATION - Duration::from_nanos(1),
            too_large_duration,
        ] {
            assert!(ClaimDuration::expires_after(invalid_once_duration).is_err());
        }
    }

    proptest! {
        #[test]
        fn fleet_generated_key_constructors_accept_the_shared_safe_key_domain(
            key in valid_fleet_key_text_strategy(),
        ) {
            let root_key = RootKey::new(&key).expect("root key");
            let mutex_key = MutexKey::new(&key).expect("mutex key");
            let counter_key = CounterKey::new(&key).expect("counter key");
            let cache_key = CoalescingCacheKey::new(&key).expect("cache key");
            let topic_key = TopicKey::new(&key).expect("topic key");
            let subscription_key = SubscriptionKey::new(&key).expect("subscription key");
            let cron_key = CronKey::new(&key).expect("cron key");
            let semaphore_key = SemaphoreKey::new(&key).expect("semaphore key");
            let throttler_key = ThrottlerKey::new(&key).expect("throttler key");
            let once_key = OnceKey::new(&key).expect("once key");

            prop_assert_eq!(root_key.as_str(), key.as_str());
            prop_assert_eq!(mutex_key.as_str(), key.as_str());
            prop_assert_eq!(counter_key.as_str(), key.as_str());
            prop_assert_eq!(cache_key.as_str(), key.as_str());
            prop_assert_eq!(topic_key.as_str(), key.as_str());
            prop_assert_eq!(subscription_key.as_str(), key.as_str());
            prop_assert_eq!(cron_key.as_str(), key.as_str());
            prop_assert_eq!(semaphore_key.as_str(), key.as_str());
            prop_assert_eq!(throttler_key.as_str(), key.as_str());
            prop_assert_eq!(once_key.as_str(), key.as_str());
        }

        #[test]
        fn fleet_generated_key_constructors_reject_ambiguous_or_oversized_key_text(
            key in invalid_fleet_key_text_strategy(),
        ) {
            prop_assert!(RootKey::new(&key).is_err(), "RootKey accepted {key:?}");
            prop_assert!(MutexKey::new(&key).is_err(), "MutexKey accepted {key:?}");
            prop_assert!(CounterKey::new(&key).is_err(), "CounterKey accepted {key:?}");
            prop_assert!(
                CoalescingCacheKey::new(&key).is_err(),
                "CoalescingCacheKey accepted {key:?}"
            );
            prop_assert!(TopicKey::new(&key).is_err(), "TopicKey accepted {key:?}");
            prop_assert!(
                SubscriptionKey::new(&key).is_err(),
                "SubscriptionKey accepted {key:?}"
            );
            prop_assert!(CronKey::new(&key).is_err(), "CronKey accepted {key:?}");
            prop_assert!(SemaphoreKey::new(&key).is_err(), "SemaphoreKey accepted {key:?}");
            prop_assert!(ThrottlerKey::new(&key).is_err(), "ThrottlerKey accepted {key:?}");
            prop_assert!(OnceKey::new(&key).is_err(), "OnceKey accepted {key:?}");
        }

        #[test]
        fn fleet_generated_throttler_and_semaphore_constructor_domains_are_enforced(
            requests_per_interval in any::<u32>(),
            max_concurrent in any::<u16>(),
            failure_threshold in any::<u32>(),
            interval_selector in any::<u8>(),
            max_hold_selector in any::<u8>(),
            recovery_selector in any::<u8>(),
            include_rate_limit in any::<bool>(),
            include_concurrency_limit in any::<bool>(),
            include_circuit_breaker in any::<bool>(),
            use_default_concurrency_hold in any::<bool>(),
        ) {
            let store = Store::new(StoreConfig::default()).expect("fleet store");
            let interval = generated_duration_candidate(interval_selector);
            let max_hold_duration = generated_duration_candidate(max_hold_selector);
            let recovery_timeout = generated_duration_candidate(recovery_selector);

            let rate_limiter = store.new_rate_limiter(
                RateLimiterKey::new("generated-rate-limiter").expect("key"),
                RateLimitConfig {
                    requests_per_interval,
                    interval,
                },
            );
            prop_assert_eq!(
                rate_limiter.is_ok(),
                requests_per_interval > 0 && duration_is_valid_throttler_duration(interval),
                "rate limiter domain mismatch: requests={} interval={:?} result={:?}",
                requests_per_interval,
                interval,
                rate_limiter
            );

            let semaphore = store.new_semaphore(
                SemaphoreKey::new("generated-semaphore").expect("key"),
                max_concurrent,
                max_hold_duration,
            );
            prop_assert_eq!(
                semaphore.is_ok(),
                (1..=FLEET_MAX_CONCURRENT_LIMIT).contains(&max_concurrent)
                    && duration_is_valid_kv_ttl(max_hold_duration),
                "semaphore domain mismatch: max_concurrent={} hold={:?} result_ok={}",
                max_concurrent,
                max_hold_duration,
                semaphore.is_ok()
            );

            let circuit_breaker = store.new_circuit_breaker(
                CircuitBreakerKey::new("generated-circuit-breaker").expect("key"),
                CircuitBreakerConfig {
                    failure_threshold,
                    recovery_timeout,
                },
            );
            prop_assert_eq!(
                circuit_breaker.is_ok(),
                failure_threshold > 0 && duration_is_valid_throttler_duration(recovery_timeout),
                "circuit breaker domain mismatch: threshold={} recovery={:?} result={:?}",
                failure_threshold,
                recovery_timeout,
                circuit_breaker
            );

            let rate_limit = include_rate_limit.then_some(ThrottlerRateLimit {
                requests_per_interval,
                interval,
            });
            let concurrency_limit = include_concurrency_limit.then_some(
                ThrottlerConcurrencyLimit {
                    max_concurrent,
                    max_hold_duration: (!use_default_concurrency_hold).then_some(max_hold_duration),
                },
            );
            let circuit_breaker_config = include_circuit_breaker.then_some(ThrottlerCircuitBreaker {
                failure_threshold,
                recovery_timeout,
            });
            let throttler = store.new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("generated-throttler").expect("key"),
                rate_limit,
                concurrency_limit,
                circuit_breaker: circuit_breaker_config,
            });

            let included_rate_limit_is_valid = !include_rate_limit
                || (requests_per_interval > 0 && duration_is_valid_throttler_duration(interval));
            let included_concurrency_limit_is_valid = !include_concurrency_limit
                || ((1..=FLEET_MAX_CONCURRENT_LIMIT).contains(&max_concurrent)
                    && (use_default_concurrency_hold
                        || duration_is_valid_throttler_duration(max_hold_duration)));
            let included_circuit_breaker_is_valid = !include_circuit_breaker
                || (failure_threshold > 0 && duration_is_valid_throttler_duration(recovery_timeout));
            let has_any_control = include_rate_limit || include_concurrency_limit || include_circuit_breaker;

            prop_assert_eq!(
                throttler.is_ok(),
                has_any_control
                    && included_rate_limit_is_valid
                    && included_concurrency_limit_is_valid
                    && included_circuit_breaker_is_valid,
                "throttler domain mismatch: rate={:?} concurrency={:?} circuit={:?} result={:?}",
                rate_limit,
                concurrency_limit,
                circuit_breaker_config,
                throttler
            );
        }

        #[test]
        fn fleet_generated_once_and_cron_constructor_domains_are_enforced(
            once_claim_selector in any::<u8>(),
            cron_interval_selector in any::<u8>(),
            heartbeat_selector in any::<u8>(),
            acquire_retry_selector in any::<u8>(),
            include_heartbeat in any::<bool>(),
            include_acquire_retry in any::<bool>(),
            include_max_renewal_failures in any::<bool>(),
            max_renewal_failures in any::<u32>(),
        ) {
            let store = Store::new(StoreConfig::default()).expect("fleet store");
            let once_claim_duration = generated_duration_candidate(once_claim_selector);
            let once_claim = ClaimDuration::expires_after(once_claim_duration);
            prop_assert_eq!(
                once_claim.is_ok(),
                duration_is_valid_claim_duration(once_claim_duration),
                "claim duration domain mismatch: duration={:?} result={:?}",
                once_claim_duration,
                once_claim
            );
            if let Ok(claim_duration) = once_claim {
                prop_assert!(
                    store
                        .new_once(OnceKey::new("generated-once").expect("key"), claim_duration)
                        .is_ok()
                );
            }

            let cron_interval = generated_duration_candidate(cron_interval_selector);
            let heartbeat_interval = generated_duration_candidate(heartbeat_selector);
            let acquire_retry_interval = generated_duration_candidate(acquire_retry_selector);
            let heartbeat_config = include_heartbeat.then_some(heartbeat_interval);
            let acquire_retry_config = include_acquire_retry.then_some(acquire_retry_interval);
            let max_renewal_failure_config =
                include_max_renewal_failures.then_some(max_renewal_failures);
            let cron = store.new_cron(CronConfig {
                key: CronKey::new("generated-cron").expect("key"),
                interval: cron_interval,
                claim_duration: None,
                heartbeat_interval: heartbeat_config,
                acquire_retry_interval: acquire_retry_config,
                max_consecutive_renewal_failures: max_renewal_failure_config,
            });

            let resolved_heartbeat =
                heartbeat_config.unwrap_or(DEFAULT_FLEET_CRON_HEARTBEAT_INTERVAL);
            let claim_duration_can_cover_heartbeat = resolved_heartbeat
                .checked_mul(2)
                .is_some_and(|minimum_claim_duration| {
                    DEFAULT_FLEET_CRON_CLAIM_DURATION >= minimum_claim_duration
                });
            let cron_should_be_valid = cron_interval >= MIN_FLEET_CRON_INTERVAL
                && resolved_heartbeat >= MIN_FLEET_MUTEX_HEARTBEAT_INTERVAL
                && claim_duration_can_cover_heartbeat
                && acquire_retry_config.is_none_or(|interval| !interval.is_zero())
                && max_renewal_failure_config.is_none_or(|failures| failures > 0);

            prop_assert_eq!(
                cron.is_ok(),
                cron_should_be_valid,
                "cron domain mismatch: interval={:?} heartbeat={:?} acquire_retry={:?} max_failures={:?} result={:?}",
                cron_interval,
                heartbeat_config,
                acquire_retry_config,
                max_renewal_failure_config,
                cron
            );
        }
    }

    #[test]
    fn throttler_state_ttl_scales_from_each_configured_control() {
        let rate_limit = resolve_throttler_rate_limit(ThrottlerRateLimit {
            requests_per_interval: 1,
            interval: Duration::from_secs(3),
        })
        .expect("rate limit");
        let concurrency_limit = resolve_throttler_concurrency_limit(ThrottlerConcurrencyLimit {
            max_concurrent: 1,
            max_hold_duration: Some(Duration::from_secs(5)),
        })
        .expect("concurrency limit");
        let circuit_breaker = resolve_throttler_circuit_breaker(ThrottlerCircuitBreaker {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(7),
        })
        .expect("circuit breaker");

        let ttl = throttler_state_ttl(
            Some(rate_limit),
            Some(concurrency_limit),
            Some(circuit_breaker),
        )
        .expect("state ttl");
        assert_eq!(
            ttl,
            KvTtl::expires_after(Duration::from_secs(
                7 * u64::from(FLEET_THROTTLER_STATE_TTL_MULTIPLIER)
            ))
            .expect("expected ttl")
        );

        let short_ttl = throttler_state_ttl(Some(rate_limit), None, None).expect("short state ttl");
        assert_eq!(
            short_ttl,
            KvTtl::expires_after(Duration::from_secs(
                3 * u64::from(FLEET_THROTTLER_STATE_TTL_MULTIPLIER)
            ))
            .expect("expected short ttl")
        );
    }

    #[test]
    fn subscription_poll_error_retry_classification_rejects_semantic_failures() {
        assert!(is_retryable_subscription_poll_error(&Error::Database(
            DbError::Query {
                sql_state: None,
                source: Box::new(std::io::Error::other("query failed")),
            }
        )));
        assert!(is_retryable_subscription_poll_error(&Error::Kv(
            KvError::Database(DbError::Query {
                sql_state: None,
                source: Box::new(std::io::Error::other("KV query failed")),
            })
        )));
        assert!(is_retryable_subscription_poll_error(
            &database_query_error_with_sql_state(PgSqlState::SerializationFailure)
        ));
        assert!(is_retryable_subscription_poll_error(
            &database_query_error_with_sql_state(PgSqlState::DeadlockDetected)
        ));
        assert!(is_retryable_subscription_poll_error(
            &kv_database_query_error_with_sql_state(PgSqlState::Other("08006".to_owned()))
        ));
        for retryable_sql_state in [
            SQLSTATE_QUERY_CANCELED,
            SQLSTATE_ADMIN_SHUTDOWN,
            SQLSTATE_CRASH_SHUTDOWN,
            SQLSTATE_CANNOT_CONNECT_NOW,
            SQLSTATE_LOCK_NOT_AVAILABLE,
        ] {
            assert!(
                is_retryable_subscription_poll_error(&database_query_error_with_sql_state(
                    PgSqlState::Other(retryable_sql_state.to_owned())
                )),
                "SQLSTATE {retryable_sql_state} should be retryable"
            );
        }

        assert!(!is_retryable_subscription_poll_error(
            &database_query_error_with_sql_state(PgSqlState::UniqueViolation)
        ));
        assert!(!is_retryable_subscription_poll_error(
            &database_query_error_with_sql_state(PgSqlState::Other("42P01".to_owned()))
        ));
        assert!(!is_retryable_subscription_poll_error(
            &database_query_error_with_sql_state(PgSqlState::Other("57P04".to_owned()))
        ));
        assert!(!is_retryable_subscription_poll_error(&Error::Database(
            DbError::schema_mismatch("schema mismatch")
        )));
        assert!(!is_retryable_subscription_poll_error(&Error::Kv(
            KvError::Database(DbError::schema_mismatch("KV schema mismatch"))
        )));
        assert!(!is_retryable_subscription_poll_error(
            &Error::TopicSequenceMustBeNonNegative
        ));
        assert!(!is_retryable_subscription_poll_error(&Error::Kv(
            KvError::KeyNotFound
        )));
    }

    #[test]
    fn fleet_property_style_subscription_retry_classification_is_database_shaped() {
        for idx in 0..256 {
            let database_error = database_query_error("generated query failure");
            assert!(
                is_retryable_subscription_poll_error(&database_error),
                "database error {idx}"
            );
            let kv_database_error = Error::Kv(KvError::Database(DbError::Query {
                sql_state: None,
                source: Box::new(std::io::Error::other(format!("KV query failed {idx}"))),
            }));
            assert!(
                is_retryable_subscription_poll_error(&kv_database_error),
                "KV database error {idx}"
            );
        }

        for semantic_error in [
            Error::TopicSequenceMustBeNonNegative,
            Error::InvalidSubscriptionPollLimit {
                value: 0,
                max: MAX_SUBSCRIPTION_POLL_LIMIT,
            },
            Error::Database(DbError::schema_mismatch("schema mismatch")),
            Error::Kv(KvError::Database(DbError::schema_mismatch(
                "KV schema mismatch",
            ))),
            Error::Kv(KvError::KeyNotFound),
        ] {
            assert!(
                !is_retryable_subscription_poll_error(&semantic_error),
                "semantic error {semantic_error:?}"
            );
        }
    }

    #[test]
    fn subscription_poll_error_policy_only_retries_database_shaped_errors() {
        let mut retry_callback_calls = 0;
        let retry_delay = subscription_poll_error_retry_delay_from_policy::<TestHandlerError, _>(
            database_query_error("retryable query error"),
            &mut |error| {
                retry_callback_calls += 1;
                assert!(is_retryable_subscription_poll_error(error));
                SubscriptionPollErrorAction::ContinueAfter(Duration::ZERO)
            },
        )
        .expect("retryable error should produce retry delay");
        assert_eq!(retry_callback_calls, 1);
        assert_eq!(retry_delay, MIN_SUBSCRIPTION_POLL_INTERVAL);

        let mut stop_callback_calls = 0;
        let stop_result = subscription_poll_error_retry_delay_from_policy::<TestHandlerError, _>(
            database_query_error("stopped query error"),
            &mut |_| {
                stop_callback_calls += 1;
                SubscriptionPollErrorAction::Stop
            },
        );
        assert_eq!(stop_callback_calls, 1);
        assert!(matches!(
            stop_result,
            Err(SubscriptionRunError::Fleet(Error::Database(
                DbError::Query { .. }
            )))
        ));

        let mut semantic_callback_called = false;
        let semantic_result = subscription_poll_error_retry_delay_from_policy::<TestHandlerError, _>(
            Error::TopicSequenceMustBeNonNegative,
            &mut |_| {
                semantic_callback_called = true;
                SubscriptionPollErrorAction::ContinueAfter(MIN_SUBSCRIPTION_POLL_INTERVAL)
            },
        );
        assert!(!semantic_callback_called);
        assert!(matches!(
            semantic_result,
            Err(SubscriptionRunError::Fleet(
                Error::TopicSequenceMustBeNonNegative
            ))
        ));
    }

    #[test]
    fn topic_sequence_key_suffixes_are_fixed_width_parseable_and_lexically_ordered() {
        let examples = [
            (0_i64, "00000000000000000000"),
            (1, "00000000000000000001"),
            (10, "00000000000000000010"),
            (123_456_789, "00000000000123456789"),
            (i64::MAX, "09223372036854775807"),
        ];
        for (sequence, expected_key_suffix) in examples {
            let key_suffix = topic_sequence_key_suffix(sequence).expect("valid sequence");
            assert_eq!(key_suffix, expected_key_suffix);
            assert_eq!(key_suffix.len(), 20);
            assert_eq!(
                parse_topic_sequence_key_suffix(&key_suffix).expect("parse generated suffix"),
                sequence
            );
        }

        for first_sequence in [0_i64, 1, 10, 123_456_789] {
            for second_sequence in [0_i64, 1, 10, 123_456_789, i64::MAX] {
                let first_key_suffix =
                    topic_sequence_key_suffix(first_sequence).expect("first suffix");
                let second_key_suffix =
                    topic_sequence_key_suffix(second_sequence).expect("second suffix");
                assert_eq!(
                    first_sequence.cmp(&second_sequence),
                    first_key_suffix.cmp(&second_key_suffix)
                );
            }
        }

        assert!(matches!(
            topic_sequence_key_suffix(-1),
            Err(Error::TopicSequenceMustBeNonNegative)
        ));
        for invalid_key_suffix in [
            "",
            "1",
            "0000000000000000001",
            "000000000000000000001",
            "0000000000000000000a",
            "99999999999999999999",
        ] {
            assert!(matches!(
                parse_topic_sequence_key_suffix(invalid_key_suffix),
                Err(Error::InvalidTopicEventSequenceSuffix { .. })
            ));
        }
    }

    #[test]
    fn fleet_property_style_topic_sequence_suffixes_round_trip_and_sort_lexically() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5eed_70c1c);
        let mut sequences = vec![0_i64, 1, 10, 123_456_789, i64::MAX];
        for _ in 0..2048 {
            sequences.push((rng.random::<u64>() >> 1) as i64);
        }
        sequences.sort_unstable();
        sequences.dedup();

        let mut suffixes = Vec::with_capacity(sequences.len());
        for sequence in &sequences {
            let suffix = topic_sequence_key_suffix(*sequence).expect("sequence suffix");
            assert_eq!(suffix.len(), 20);
            assert!(suffix.bytes().all(|byte| byte.is_ascii_digit()));
            assert_eq!(
                parse_topic_sequence_key_suffix(&suffix).expect("parse suffix"),
                *sequence
            );
            suffixes.push(suffix);
        }

        let mut sorted_suffixes = suffixes.clone();
        sorted_suffixes.sort();
        assert_eq!(suffixes, sorted_suffixes);
    }
}
