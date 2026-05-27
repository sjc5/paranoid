use super::*;

/// Errors returned by Fleet coordination primitives.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Fleet-owned table names must be pairwise distinct.
    #[error(
        "Fleet state, coordination, fencing counter, and schema ledger table names must be distinct"
    )]
    TableNamesMustBeDistinct,
    /// A Fleet root key was invalid.
    #[error("invalid Fleet root key")]
    InvalidRootKey {
        /// Underlying validation error.
        #[source]
        source: CoordinationError,
    },
    /// A Fleet root key was invalid for KV-backed Fleet records.
    #[error("invalid Fleet root key for KV-backed Fleet records")]
    InvalidRootKeyForKv {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet mutex key was invalid.
    #[error("invalid Fleet mutex key")]
    InvalidMutexKey {
        /// Underlying validation error.
        #[source]
        source: CoordinationError,
    },
    /// A Fleet counter key was invalid.
    #[error("invalid Fleet counter key")]
    InvalidCounterKey {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet counter addition would overflow or underflow `i64`.
    #[error("Fleet counter arithmetic overflow")]
    CounterArithmeticOverflow,
    /// A Fleet counter mutation completed without assigning its next value.
    #[error("Fleet counter mutation completed without assigning its next value")]
    CounterMutationDidNotAssignNextValue,
    /// A Fleet coalescing cache key was invalid for cached values.
    #[error("invalid Fleet coalescing cache key for cached values")]
    InvalidCoalescingCacheKeyForValue {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet coalescing cache key was invalid for its namespace epoch.
    #[error("invalid Fleet coalescing cache key for namespace epoch")]
    InvalidCoalescingCacheKeyForEpoch {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet coalescing cache key was invalid for its compute mutex.
    #[error("invalid Fleet coalescing cache key for compute mutex")]
    InvalidCoalescingCacheKeyForMutex {
        /// Underlying validation error.
        #[source]
        source: CoordinationError,
    },
    /// A Fleet coalescing cache lock wait timeout was invalid.
    #[error("Fleet coalescing cache lock wait timeout must be positive and fit in microseconds")]
    InvalidCoalescingCacheLockWaitTimeout,
    /// A Fleet coalescing cache compute timeout was invalid.
    #[error("Fleet coalescing cache compute timeout must be positive and fit in microseconds")]
    InvalidCoalescingCacheComputeTimeout,
    /// A Fleet coalescing cache waited too long for its compute mutex.
    #[error("timed out waiting for Fleet coalescing cache compute mutex after {timeout:?}")]
    CoalescingCacheLockWaitTimedOut {
        /// Configured timeout.
        timeout: Duration,
    },
    /// A Fleet coalescing cache computation exceeded its configured timeout.
    #[error("Fleet coalescing cache computation timed out after {timeout:?}")]
    CoalescingCacheComputeTimedOut {
        /// Configured timeout.
        timeout: Duration,
    },
    /// A Fleet coalescing cache compute mutex was lost before the operation could finish.
    #[error("Fleet coalescing cache compute mutex is no longer live")]
    CoalescingCacheComputeMutexLost,
    /// A Fleet topic key was invalid for its sequence state.
    #[error("invalid Fleet topic key for sequence state")]
    InvalidTopicKeyForSequence {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet topic key was invalid for its event namespace.
    #[error("invalid Fleet topic key for events")]
    InvalidTopicKeyForEvents {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet subscription key was invalid for its cursor state.
    #[error("invalid Fleet subscription key for cursor state")]
    InvalidSubscriptionKeyForCursor {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet subscription key was invalid for its guarded polling loop mutex.
    #[error("invalid Fleet subscription key for guarded polling loop mutex")]
    InvalidSubscriptionKeyForPollingMutex {
        /// Underlying validation error.
        #[source]
        source: CoordinationError,
    },
    /// A Fleet topic or subscription sequence was negative.
    #[error("Fleet topic sequence must be non-negative")]
    TopicSequenceMustBeNonNegative,
    /// A Fleet topic sequence would overflow `i64`.
    #[error("Fleet topic sequence overflow")]
    TopicSequenceOverflow,
    /// A Fleet topic publish mutation completed without assigning a sequence.
    #[error("Fleet topic publish mutation completed without assigning a sequence")]
    TopicPublishMutationDidNotAssignSequence,
    /// A Fleet topic publish mutation completed without observing a database timestamp.
    #[error("Fleet topic publish mutation completed without observing a database timestamp")]
    TopicPublishMutationDidNotObserveTimestamp,
    /// A persisted Fleet topic event key suffix was malformed.
    #[error("invalid Fleet topic event sequence suffix {key_suffix:?}")]
    InvalidTopicEventSequenceSuffix {
        /// Rejected key suffix.
        key_suffix: String,
    },
    /// A Fleet subscription poll limit was zero or above the maximum.
    #[error("invalid Fleet subscription poll limit {value}, maximum is {max}")]
    InvalidSubscriptionPollLimit {
        /// Rejected value.
        value: u32,
        /// Maximum accepted value.
        max: u32,
    },
    /// A Fleet cron key was invalid.
    #[error("invalid Fleet cron key")]
    InvalidCronKey {
        /// Underlying validation error.
        #[source]
        source: CoordinationError,
    },
    /// A Fleet cron interval was invalid.
    #[error("Fleet cron interval must be at least {minimum:?}")]
    InvalidCronInterval {
        /// Minimum accepted interval.
        minimum: Duration,
    },
    /// A Fleet semaphore key was invalid.
    #[error("invalid Fleet semaphore key")]
    InvalidSemaphoreKey {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet semaphore max-concurrent value was zero or above the maximum.
    #[error("invalid Fleet semaphore max-concurrent value {value}, maximum is {max}")]
    InvalidSemaphoreMaxConcurrent {
        /// Rejected value.
        value: u16,
        /// Maximum accepted value.
        max: u16,
    },
    /// A Fleet semaphore max-hold duration was invalid.
    #[error("invalid Fleet semaphore max-hold duration")]
    InvalidSemaphoreMaxHoldDuration {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A semaphore claim was used with a different semaphore than the one that created it.
    #[error("Fleet semaphore claim belongs to a different semaphore")]
    SemaphoreClaimBelongsToDifferentSemaphore,
    /// A Fleet throttler key was invalid.
    #[error("invalid Fleet throttler key")]
    InvalidThrottlerKey {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet rate-limiter key was invalid.
    #[error("invalid Fleet rate-limiter key")]
    InvalidRateLimiterKey {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet circuit-breaker key was invalid.
    #[error("invalid Fleet circuit-breaker key")]
    InvalidCircuitBreakerKey {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet throttler needs at least one enabled control.
    #[error("Fleet throttler must enable rate limiting, concurrency limiting, or circuit breaking")]
    InvalidThrottlerHasNoControls,
    /// A Fleet throttler rate limit requested zero operations per interval.
    #[error("Fleet throttler rate limit requests-per-interval cannot be zero")]
    InvalidThrottlerRequestsPerInterval,
    /// A Fleet throttler rate limit interval was invalid.
    #[error("Fleet throttler rate limit interval must be positive and fit in microseconds")]
    InvalidThrottlerRateLimitInterval,
    /// A Fleet throttler max-concurrent value was zero or above the maximum.
    #[error("invalid Fleet throttler max-concurrent value {value}, maximum is {max}")]
    InvalidThrottlerMaxConcurrent {
        /// Rejected value.
        value: u16,
        /// Maximum accepted value.
        max: u16,
    },
    /// A Fleet throttler max-hold duration was invalid.
    #[error("Fleet throttler max-hold duration must be positive and fit in microseconds")]
    InvalidThrottlerMaxHoldDuration,
    /// A Fleet throttler failure threshold was invalid.
    #[error("Fleet throttler failure threshold cannot be zero")]
    InvalidThrottlerFailureThreshold,
    /// A Fleet throttler recovery timeout was invalid.
    #[error("Fleet throttler recovery timeout must be positive and fit in microseconds")]
    InvalidThrottlerRecoveryTimeout,
    /// A Fleet throttler derived state TTL was invalid.
    #[error("Fleet throttler derived state TTL was invalid")]
    InvalidThrottlerStateTtl {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet throttler timestamp calculation overflowed.
    #[error("Fleet throttler timestamp calculation overflowed")]
    ThrottlerTimestampOverflow,
    /// A Fleet throttler holder identifier was required for this operation.
    #[error("Fleet throttler holder identifier is required for this operation")]
    ThrottlerHolderIdRequired,
    /// A throttler permit was used with a different throttler than the one that created it.
    #[error("Fleet throttler permit belongs to a different throttler")]
    ThrottlerPermitBelongsToDifferentThrottler,
    /// A guarded Fleet throttler probe heartbeat task failed.
    #[error("Fleet throttler probe heartbeat task failed")]
    ThrottlerProbeHeartbeatTaskFailed {
        /// Underlying task join error.
        #[source]
        source: tokio::task::JoinError,
    },
    /// A specialized rate limiter observed circuit-breaker state.
    #[error("Fleet rate limiter unexpectedly observed circuit-breaker state")]
    RateLimiterUnexpectedCircuitOpen,
    /// A Fleet run-once key was invalid for its completion marker.
    #[error("invalid Fleet run-once key for completion marker")]
    InvalidOnceKeyForCompletionMarker {
        /// Underlying validation error.
        #[source]
        source: KvError,
    },
    /// A Fleet run-once key was invalid for its exclusion mutex.
    #[error("invalid Fleet run-once key for mutex")]
    InvalidOnceKeyForMutex {
        /// Underlying validation error.
        #[source]
        source: CoordinationError,
    },
    /// A generated holder identifier could not be created.
    #[error("failed to generate Fleet holder identifier")]
    HolderIdGeneration {
        /// Underlying ID generation error.
        #[source]
        source: id::Error,
    },
    /// A generated holder identifier was rejected by coordination validation.
    #[error("generated Fleet holder identifier was invalid")]
    GeneratedHolderIdRejected {
        /// Underlying coordination validation error.
        #[source]
        source: CoordinationError,
    },
    /// A manual-renewal mutex claim was used with a different mutex than the one that created it.
    #[error("Fleet manual-renewal mutex claim belongs to a different mutex")]
    MutexManualRenewalClaimBelongsToDifferentMutex,
    /// A guarded Fleet mutex heartbeat interval was invalid.
    #[error("Fleet mutex heartbeat interval must be at least {minimum:?}")]
    InvalidMutexHeartbeatInterval {
        /// Minimum accepted interval.
        minimum: Duration,
    },
    /// A guarded Fleet mutex acquire retry interval was invalid.
    #[error("Fleet mutex acquire retry interval must be positive")]
    InvalidMutexAcquireRetryInterval,
    /// A guarded Fleet mutex maximum acquire retry interval was invalid.
    #[error(
        "Fleet mutex maximum acquire retry interval must be positive and at least the acquire retry interval"
    )]
    InvalidMutexMaxAcquireRetryInterval,
    /// Random generation for guarded Fleet mutex acquire retry jitter failed.
    #[error("Fleet mutex acquire retry jitter random generation failed: {reason}")]
    MutexAcquireRetryJitterRandom {
        /// Human-readable randomness error.
        reason: String,
    },
    /// A guarded Fleet mutex maximum renewal failure count was invalid.
    #[error("Fleet mutex maximum consecutive renewal failures must be positive")]
    InvalidMutexMaxConsecutiveRenewalFailures,
    /// A guarded Fleet mutex claim duration was too short for its heartbeat interval.
    #[error(
        "Fleet mutex claim duration {claim_duration:?} must be at least 2x heartbeat interval {heartbeat_interval:?}"
    )]
    MutexClaimDurationTooShortForHeartbeat {
        /// Configured claim duration.
        claim_duration: Duration,
        /// Configured heartbeat interval.
        heartbeat_interval: Duration,
    },
    /// A guarded Fleet mutex heartbeat task failed.
    #[error("Fleet mutex heartbeat task failed")]
    MutexHeartbeatTaskFailed {
        /// Underlying task join error.
        #[source]
        source: tokio::task::JoinError,
    },
    /// Stopping a guarded Fleet mutex failed and releasing its claim also failed.
    #[error("Fleet mutex guard stop failed and release also failed")]
    MutexGuardStopAndReleaseFailed {
        /// Stop error.
        stop_error: Box<Error>,
        /// Release error.
        release_error: Box<Error>,
    },
    /// A manual run-once claim was used with a different run-once task than the one that created it.
    #[error("Fleet manual run-once claim belongs to a different run-once task")]
    RunOnceManualRunClaimBelongsToDifferentTask,
    /// A manual run-once claim is no longer live and cannot complete the task.
    #[error("Fleet manual run-once claim is no longer live")]
    RunOnceManualRunClaimNoLongerLive,
    /// A run-once task observed an existing completion marker after acquiring exclusive execution.
    #[error("Fleet run-once completion was already recorded after exclusive execution started")]
    RunOnceCompletionAlreadyRecordedAfterStart,
    /// A KV operation failed.
    #[error(transparent)]
    Kv(#[from] KvError),
    /// A coordination operation failed.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
    /// A database operation failed.
    #[error(transparent)]
    Database(#[from] crate::db::Error),
    /// A Fleet database operation failed and its cleanup rollback also failed.
    #[error("Fleet database operation {operation} failed, then transaction rollback failed")]
    DatabaseOperationRollbackFailed {
        /// Operation being cleaned up.
        operation: &'static str,
        /// Original operation error.
        operation_error: Box<Error>,
        /// Rollback failure.
        rollback_error: crate::db::Error,
    },
}
