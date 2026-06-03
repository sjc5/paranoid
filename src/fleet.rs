//! Postgres-backed distributed coordination primitives.
//!
//! Fleet is the coordination layer for mutexes, one-shot tasks, coalescing
//! caches, topics, semaphores, throttlers, cron loops, and circuit breakers.
//! Create the store through [`crate::db::BootstrapConfig`], then construct
//! high-level primitives from typed keys.
//!
//! ```rust,no_run
//! # #[cfg(feature = "db")]
//! # async fn example(pool: paranoid::db::WritePool) -> Result<(), Box<dyn std::error::Error>> {
//! use paranoid::db::BootstrapConfig;
//! use paranoid::fleet::{ClaimDuration, MutexGuardConfig, MutexKey, MutexTryRunTaskResult};
//! use std::time::Duration;
//!
//! let stores = BootstrapConfig::default().migrate_schema(&pool).await?;
//! let store = stores.fleet;
//!
//! let mutex = store.new_mutex(
//!     MutexKey::new("billing-rollup")?,
//!     ClaimDuration::expires_after(Duration::from_secs(30))?,
//! )?;
//!
//! let result = mutex
//!     .try_run_task(&pool, MutexGuardConfig::default(), |_snapshot| async {
//!         Ok::<_, std::io::Error>("rolled-up")
//!     })
//!     .await?;
//!
//! assert_eq!(result, MutexTryRunTaskResult::Ran("rolled-up"));
//! # Ok(())
//! # }
//! ```

pub use crate::db::fleet::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerGuardAcquireResult,
    CircuitBreakerGuardedTaskResult, CircuitBreakerKey, CircuitBreakerPermit,
    CircuitBreakerPermitGuard, CircuitBreakerReleaseResult, CircuitBreakerState,
    CircuitBreakerStatus, CircuitBreakerTryRunTaskResult, ClaimDuration, CoalescingCache,
    CoalescingCacheConfig, CoalescingCacheFetchError, CoalescingCacheKey, CoordinationError,
    Counter, CounterKey, Cron, CronConfig, CronKey, CronRunError, CronRunHandle,
    CronRunHandleError, CronTaskErrorAction, CronTryRunOnceResult,
    DEFAULT_COALESCING_CACHE_LOCK_RETRY_INTERVAL, DEFAULT_COALESCING_CACHE_LOCK_WAIT_TIMEOUT,
    DEFAULT_COALESCING_CACHE_MUTEX_CLAIM_DURATION,
    DEFAULT_FLEET_CRON_ACQUIRE_RETRY_INTERVAL as DEFAULT_CRON_ACQUIRE_RETRY_INTERVAL,
    DEFAULT_FLEET_CRON_CLAIM_DURATION as DEFAULT_CRON_CLAIM_DURATION,
    DEFAULT_FLEET_CRON_HEARTBEAT_INTERVAL as DEFAULT_CRON_HEARTBEAT_INTERVAL,
    DEFAULT_FLEET_MUTEX_ACQUIRE_RETRY_INTERVAL as DEFAULT_MUTEX_ACQUIRE_RETRY_INTERVAL,
    DEFAULT_FLEET_MUTEX_CLAIM_DURATION as DEFAULT_MUTEX_CLAIM_DURATION,
    DEFAULT_FLEET_MUTEX_MAX_ACQUIRE_RETRY_INTERVAL as DEFAULT_MUTEX_MAX_ACQUIRE_RETRY_INTERVAL,
    DEFAULT_FLEET_MUTEX_MAX_CONSECUTIVE_RENEWAL_FAILURES as DEFAULT_MUTEX_MAX_CONSECUTIVE_RENEWAL_FAILURES,
    DEFAULT_FLEET_ONCE_CLAIM_DURATION as DEFAULT_ONCE_CLAIM_DURATION,
    DEFAULT_FLEET_ROOT_KEY as DEFAULT_ROOT_KEY,
    DEFAULT_FLEET_SEMAPHORE_ACQUIRE_RETRY_INTERVAL as DEFAULT_SEMAPHORE_ACQUIRE_RETRY_INTERVAL,
    DEFAULT_FLEET_SEMAPHORE_MAX_HOLD_DURATION as DEFAULT_SEMAPHORE_MAX_HOLD_DURATION,
    DEFAULT_FLEET_THROTTLER_BLOCKING_RETRY_INTERVAL as DEFAULT_THROTTLER_BLOCKING_RETRY_INTERVAL,
    DEFAULT_FLEET_THROTTLER_MAX_HOLD_DURATION as DEFAULT_THROTTLER_MAX_HOLD_DURATION,
    DEFAULT_FLEET_THROTTLER_PROBE_WINDOW as DEFAULT_THROTTLER_PROBE_WINDOW,
    DEFAULT_FLEET_THROTTLER_STATE_TTL as DEFAULT_THROTTLER_STATE_TTL,
    DEFAULT_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL, DEFAULT_SUBSCRIPTION_POLL_LIMIT, Error,
    FLEET_MAX_CONCURRENT_LIMIT as MAX_CONCURRENT_LIMIT, FencingToken, HolderId,
    MAX_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL, MAX_SUBSCRIPTION_POLL_LIMIT,
    MIN_FLEET_CRON_INTERVAL as MIN_CRON_INTERVAL,
    MIN_FLEET_MUTEX_HEARTBEAT_INTERVAL as MIN_MUTEX_HEARTBEAT_INTERVAL,
    MIN_FLEET_THROTTLER_CIRCUIT_OPEN_WAIT as MIN_THROTTLER_CIRCUIT_OPEN_WAIT,
    MIN_SUBSCRIPTION_POLL_INTERVAL, Mutex, MutexGuard, MutexGuardConfig, MutexGuardSnapshot,
    MutexHolderSnapshot, MutexKey, MutexRunError, MutexTryRunTaskResult, Once, OnceCompletion,
    OnceKey, OnceRunClaimSnapshot, OnceRunError, OnceRunTaskResult, OnceTransactionalRunError,
    OnceTransactionalTaskFuture, OnceTryRunTaskResult, RateLimitConfig, RateLimiter,
    RateLimiterGuardAcquireResult, RateLimiterGuardedTaskResult, RateLimiterKey, RateLimiterPermit,
    RateLimiterPermitGuard, RateLimiterStatus, RateLimiterTryRunTaskResult, RootKey, Semaphore,
    SemaphoreClaim, SemaphoreClaimGuard, SemaphoreGuardedTaskResult, SemaphoreKey, SemaphoreStatus,
    SemaphoreTryRunTaskResult, Store, Subscription, SubscriptionConfig, SubscriptionKey,
    SubscriptionPollErrorAction, SubscriptionRunError, SubscriptionRunHandle,
    SubscriptionRunHandleError, Throttler, ThrottlerCircuitBreaker, ThrottlerCircuitState,
    ThrottlerConcurrencyLimit, ThrottlerConfig, ThrottlerGuardAcquireResult,
    ThrottlerGuardedTaskResult, ThrottlerKey, ThrottlerPermit, ThrottlerPermitGuard,
    ThrottlerRateLimit, ThrottlerReleaseResult, ThrottlerStatus, ThrottlerTaskOutcome,
    ThrottlerTryRunTaskResult, Topic, TopicConfig, TopicEvent, TopicKey,
};

/// Manual Fleet protocols for callers that need to own a coordination lifecycle directly.
pub mod manual {
    pub use crate::db::fleet::{
        CircuitBreakerManualPermitAcquireResult, CircuitBreakerManualPermitProtocol,
        MutexManualRenewalClaim, MutexManualRenewalProtocol, OnceManualRunClaim,
        OnceManualRunProtocol, RateLimiterManualPermitAcquireResult,
        RateLimiterManualPermitProtocol, SemaphoreManualClaimProtocol,
        ThrottlerManualPermitAcquireResult, ThrottlerManualPermitProtocol,
    };
}
