use super::*;

/// Configures Fleet throttler rate limiting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottlerRateLimit {
    /// Number of operations allowed per interval.
    pub requests_per_interval: u32,
    /// Interval over which tokens refill.
    pub interval: Duration,
}

/// Configures Fleet throttler concurrency limiting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottlerConcurrencyLimit {
    /// Maximum number of concurrently admitted operations.
    pub max_concurrent: u16,
    /// Maximum duration a concurrency slot may remain live.
    pub max_hold_duration: Option<Duration>,
}

/// Configures Fleet throttler circuit breaking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThrottlerCircuitBreaker {
    /// Number of consecutive failures that opens the circuit.
    pub failure_threshold: u32,
    /// Duration before an open circuit permits one half-open probe.
    pub recovery_timeout: Duration,
}

/// Configures a Fleet throttler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThrottlerConfig {
    /// Throttler key.
    pub key: ThrottlerKey,
    /// Optional token-bucket rate limit.
    pub rate_limit: Option<ThrottlerRateLimit>,
    /// Optional concurrent operation limit.
    pub concurrency_limit: Option<ThrottlerConcurrencyLimit>,
    /// Optional circuit breaker.
    pub circuit_breaker: Option<ThrottlerCircuitBreaker>,
}

/// Configures a specialized Fleet rate limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Number of operations allowed per interval.
    pub requests_per_interval: u32,
    /// Interval over which tokens refill.
    pub interval: Duration,
}

/// Configures a specialized Fleet circuit breaker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures that opens the circuit.
    pub failure_threshold: u32,
    /// Duration before an open circuit permits one half-open probe.
    pub recovery_timeout: Duration,
}

/// KV-backed Fleet throttler.
#[derive(Clone, Debug)]
pub struct Throttler {
    pub(super) key: ThrottlerKey,
    pub(super) rate_limit: Option<ResolvedThrottlerRateLimit>,
    pub(super) concurrency_limit: Option<ResolvedThrottlerConcurrencyLimit>,
    pub(super) circuit_breaker: Option<ResolvedThrottlerCircuitBreaker>,
    pub(super) state_ttl: KvTtl,
    pub(super) state_item: KvItem<ThrottlerState>,
}

/// Explicit opt-in handle for throttler permits managed manually by the caller.
#[must_use = "use this handle to acquire or release throttler permits manually"]
pub struct ThrottlerManualPermitProtocol<'a> {
    pub(super) throttler: &'a Throttler,
}

/// Result of a Fleet throttler acquisition attempt.
#[derive(Clone, Debug, PartialEq)]
pub enum ThrottlerManualPermitAcquireResult {
    /// The operation may proceed.
    Acquired(ThrottlerPermit),
    /// The operation was denied by rate or concurrency limiting.
    Throttled {
        /// Suggested wait before retrying when known.
        retry_after: Option<Duration>,
    },
    /// The operation was denied because the circuit is open.
    CircuitOpen,
}

/// Result of a Fleet throttler guarded acquisition attempt.
#[derive(Debug)]
pub enum ThrottlerGuardAcquireResult {
    /// The operation may proceed.
    Acquired(ThrottlerPermitGuard),
    /// The operation was denied by rate or concurrency limiting.
    Throttled {
        /// Suggested wait before retrying when known.
        retry_after: Option<Duration>,
    },
    /// The operation was denied because the circuit is open.
    CircuitOpen,
}

/// Fleet throttler permit returned by a successful acquisition.
#[derive(Clone, Debug, PartialEq)]
#[must_use = "a throttler permit acquired manually must be released explicitly"]
pub struct ThrottlerPermit {
    pub(super) throttler_key: ThrottlerKey,
    pub(super) holder_id: Option<HolderId>,
    pub(super) slot_suffix: Option<String>,
    pub(super) probe_acquired: bool,
}

/// Owned Fleet throttler permit with explicit release/task helpers and best-effort drop cleanup.
#[must_use = "a throttler permit guard holds live Fleet coordination state; call release or run_task to observe cleanup"]
pub struct ThrottlerPermitGuard {
    pub(super) throttler: Box<Throttler>,
    pub(super) pool: Pool,
    pub(super) runtime_handle: RuntimeHandle,
    pub(super) permit: Option<ThrottlerPermit>,
    pub(super) drop_outcome: ThrottlerTaskOutcome,
    pub(super) probe_heartbeat: Option<ThrottlerProbeHeartbeat>,
}

pub(super) struct ThrottlerProbeHeartbeat {
    pub(super) stop_heartbeat: Arc<AtomicBool>,
    pub(super) stop_heartbeat_notify: Arc<Notify>,
    pub(super) heartbeat_task: JoinHandle<()>,
}

/// Result of running a task behind a Fleet throttler guard.
#[derive(Debug)]
pub enum ThrottlerGuardedTaskResult<T, E> {
    /// The task returned `Ok`.
    Succeeded {
        /// Task output.
        value: T,
        /// Result of releasing the guard after success.
        release_result: Result<ThrottlerReleaseResult, Error>,
    },
    /// The task returned `Err`.
    Failed {
        /// Task error.
        error: E,
        /// Result of releasing the guard after failure.
        release_result: Result<ThrottlerReleaseResult, Error>,
    },
}

/// Result of trying to acquire and run a Fleet throttler guarded task.
#[derive(Debug)]
pub enum ThrottlerTryRunTaskResult<T, E> {
    /// The task ran.
    Ran(ThrottlerGuardedTaskResult<T, E>),
    /// The task was denied by rate or concurrency limiting.
    Throttled {
        /// Suggested wait before retrying when known.
        retry_after: Option<Duration>,
    },
    /// The task was denied because the circuit is open.
    CircuitOpen,
}

/// Task outcome to apply when releasing a Fleet throttler permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThrottlerTaskOutcome {
    /// The protected task did not execute.
    NotExecuted,
    /// The protected task executed successfully.
    Succeeded,
    /// The protected task executed and should count as a circuit-breaker failure.
    Failed,
}

/// Result of releasing a Fleet throttler permit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThrottlerReleaseResult {
    pub(super) concurrency_slot_released: bool,
    pub(super) circuit_state_updated: bool,
    pub(super) probe_released: bool,
}

/// Fleet throttler circuit state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ThrottlerCircuitState {
    /// The circuit is closed.
    Closed,
    /// The circuit is open.
    Open,
}

/// Fleet circuit-breaker state.
pub type CircuitBreakerState = ThrottlerCircuitState;

/// Current Fleet throttler status.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThrottlerStatus {
    pub(super) available_tokens: f64,
    pub(super) max_tokens: f64,
    pub(super) current_concurrency: u16,
    pub(super) max_concurrency: u16,
    pub(super) circuit_state: ThrottlerCircuitState,
    pub(super) consecutive_failures: u32,
}

/// Specialized rate-limiter handle backed by a Fleet throttler.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    pub(super) key: RateLimiterKey,
    pub(super) throttler: Throttler,
}

/// Explicit opt-in handle for rate-limiter permits managed manually by the caller.
#[must_use = "use this handle to acquire rate-limiter permits manually"]
pub struct RateLimiterManualPermitProtocol<'a> {
    pub(super) rate_limiter: &'a RateLimiter,
}

/// Result of a Fleet rate-limiter acquisition attempt.
#[derive(Clone, Debug, PartialEq)]
pub enum RateLimiterManualPermitAcquireResult {
    /// The operation may proceed.
    Acquired(RateLimiterPermit),
    /// The operation was denied by rate limiting.
    Throttled {
        /// Suggested wait before retrying when known.
        retry_after: Option<Duration>,
    },
}

/// Result of a Fleet rate-limiter guarded acquisition attempt.
#[derive(Debug)]
pub enum RateLimiterGuardAcquireResult {
    /// The operation may proceed.
    Acquired(RateLimiterPermitGuard),
    /// The operation was denied by rate limiting.
    Throttled {
        /// Suggested wait before retrying when known.
        retry_after: Option<Duration>,
    },
}

/// Fleet rate-limiter permit returned by a successful acquisition.
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimiterPermit {
    pub(super) key: RateLimiterKey,
    pub(super) throttler_permit: ThrottlerPermit,
}

/// Owned Fleet rate-limiter permit with explicit release/task helpers and best-effort drop cleanup.
#[derive(Debug)]
#[must_use = "a rate-limiter permit guard should be consumed by run_task or an explicit release method"]
pub struct RateLimiterPermitGuard {
    pub(super) key: RateLimiterKey,
    pub(super) throttler_guard: ThrottlerPermitGuard,
}

/// Result of running a task behind a Fleet rate-limiter guard.
#[derive(Debug)]
pub enum RateLimiterGuardedTaskResult<T, E> {
    /// The task returned `Ok`.
    Succeeded {
        /// Task output.
        value: T,
        /// Result of releasing the guard after success.
        release_result: Result<(), Error>,
    },
    /// The task returned `Err`.
    Failed {
        /// Task error.
        error: E,
        /// Result of releasing the guard after failure.
        release_result: Result<(), Error>,
    },
}

/// Current Fleet rate-limiter status.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimiterStatus {
    pub(super) available_tokens: f64,
    pub(super) max_tokens: f64,
}

/// Specialized circuit-breaker handle backed by a Fleet throttler.
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    pub(super) key: CircuitBreakerKey,
    pub(super) throttler: Throttler,
}

/// Explicit opt-in handle for circuit-breaker permits managed manually by the caller.
#[must_use = "use this handle to acquire or release circuit-breaker permits manually"]
pub struct CircuitBreakerManualPermitProtocol<'a> {
    pub(super) circuit_breaker: &'a CircuitBreaker,
}

/// Result of a Fleet circuit-breaker acquisition attempt.
#[derive(Clone, Debug, PartialEq)]
pub enum CircuitBreakerManualPermitAcquireResult {
    /// The operation may proceed.
    Acquired(CircuitBreakerPermit),
    /// The operation was denied because the circuit is open.
    CircuitOpen,
}

/// Result of a Fleet circuit-breaker guarded acquisition attempt.
#[derive(Debug)]
pub enum CircuitBreakerGuardAcquireResult {
    /// The operation may proceed.
    Acquired(CircuitBreakerPermitGuard),
    /// The operation was denied because the circuit is open.
    CircuitOpen,
}

/// Fleet circuit-breaker permit returned by a successful acquisition.
#[derive(Clone, Debug, PartialEq)]
#[must_use = "a circuit-breaker permit acquired manually must be released explicitly"]
pub struct CircuitBreakerPermit {
    pub(super) key: CircuitBreakerKey,
    pub(super) throttler_permit: ThrottlerPermit,
}

/// Owned Fleet circuit-breaker permit with explicit release/task helpers and best-effort drop cleanup.
#[derive(Debug)]
#[must_use = "a circuit-breaker permit guard holds live Fleet coordination state; call release or run_task to observe cleanup"]
pub struct CircuitBreakerPermitGuard {
    pub(super) key: CircuitBreakerKey,
    pub(super) throttler_guard: ThrottlerPermitGuard,
}

/// Result of releasing a Fleet circuit-breaker permit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CircuitBreakerReleaseResult {
    pub(super) circuit_state_updated: bool,
    pub(super) probe_released: bool,
}

/// Result of trying to acquire and run a Fleet rate-limited guarded task.
#[derive(Debug)]
pub enum RateLimiterTryRunTaskResult<T, E> {
    /// The task ran.
    Ran(RateLimiterGuardedTaskResult<T, E>),
    /// The task was denied by rate limiting.
    Throttled {
        /// Suggested wait before retrying when known.
        retry_after: Option<Duration>,
    },
}

/// Result of trying to acquire and run a Fleet circuit-breaker guarded task.
#[derive(Debug)]
pub enum CircuitBreakerTryRunTaskResult<T, E> {
    /// The task ran.
    Ran(CircuitBreakerGuardedTaskResult<T, E>),
    /// The task was denied because the circuit is open.
    CircuitOpen,
}

/// Result of running a task behind a Fleet circuit-breaker guard.
#[derive(Debug)]
pub enum CircuitBreakerGuardedTaskResult<T, E> {
    /// The task returned `Ok`.
    Succeeded {
        /// Task output.
        value: T,
        /// Result of releasing the guard after success.
        release_result: Result<CircuitBreakerReleaseResult, Error>,
    },
    /// The task returned `Err`.
    Failed {
        /// Task error.
        error: E,
        /// Result of releasing the guard after failure.
        release_result: Result<CircuitBreakerReleaseResult, Error>,
    },
}

/// Current Fleet circuit-breaker status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitBreakerStatus {
    pub(super) circuit_state: ThrottlerCircuitState,
    pub(super) consecutive_failures: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ResolvedThrottlerRateLimit {
    pub(super) requests_per_interval: u32,
    pub(super) interval: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolvedThrottlerConcurrencyLimit {
    pub(super) max_concurrent: u16,
    pub(super) max_hold_duration: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolvedThrottlerCircuitBreaker {
    pub(super) failure_threshold: u32,
    pub(super) recovery_timeout: Duration,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct ThrottlerState {
    pub(super) tokens: f64,
    pub(super) last_refill_unix_microseconds: i64,
    pub(super) slots: BTreeMap<String, ThrottlerSlot>,
    pub(super) consecutive_failures: u32,
    pub(super) circuit_state: ThrottlerCircuitState,
    pub(super) circuit_opened_at_unix_microseconds: Option<i64>,
    pub(super) probe_holder_id: Option<String>,
    pub(super) probe_expires_at_unix_microseconds: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct ThrottlerSlot {
    pub(super) holder_id: String,
    pub(super) expires_at_unix_microseconds: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ThrottlerMutationOutcome {
    pub(super) acquire_result: ThrottlerManualPermitAcquireResult,
    pub(super) state: ThrottlerState,
    pub(super) should_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ThrottlerConcurrencyAcquireOutcome {
    pub(super) state_was_modified: bool,
    pub(super) no_slot_available: bool,
    pub(super) acquired_slot_suffix: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ThrottlerRateLimitOutcome {
    pub(super) blocked_by_rate_limit: bool,
    pub(super) released_acquired_slot: bool,
    pub(super) retry_after: Duration,
}
