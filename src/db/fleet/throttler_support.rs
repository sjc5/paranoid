use super::*;

pub(super) fn resolve_throttler_rate_limit(
    rate_limit: ThrottlerRateLimit,
) -> Result<ResolvedThrottlerRateLimit, Error> {
    if rate_limit.requests_per_interval == 0 {
        return Err(Error::InvalidThrottlerRequestsPerInterval);
    }
    validate_duration_for_throttler(
        rate_limit.interval,
        Error::InvalidThrottlerRateLimitInterval,
    )?;
    Ok(ResolvedThrottlerRateLimit {
        requests_per_interval: rate_limit.requests_per_interval,
        interval: rate_limit.interval,
    })
}

pub(super) fn resolve_throttler_concurrency_limit(
    concurrency_limit: ThrottlerConcurrencyLimit,
) -> Result<ResolvedThrottlerConcurrencyLimit, Error> {
    if concurrency_limit.max_concurrent == 0
        || concurrency_limit.max_concurrent > FLEET_MAX_CONCURRENT_LIMIT
    {
        return Err(Error::InvalidThrottlerMaxConcurrent {
            value: concurrency_limit.max_concurrent,
            max: FLEET_MAX_CONCURRENT_LIMIT,
        });
    }
    let max_hold_duration = concurrency_limit
        .max_hold_duration
        .unwrap_or(DEFAULT_FLEET_THROTTLER_MAX_HOLD_DURATION);
    validate_duration_for_throttler(max_hold_duration, Error::InvalidThrottlerMaxHoldDuration)?;
    Ok(ResolvedThrottlerConcurrencyLimit {
        max_concurrent: concurrency_limit.max_concurrent,
        max_hold_duration,
    })
}

pub(super) fn resolve_throttler_circuit_breaker(
    circuit_breaker: ThrottlerCircuitBreaker,
) -> Result<ResolvedThrottlerCircuitBreaker, Error> {
    if circuit_breaker.failure_threshold == 0 {
        return Err(Error::InvalidThrottlerFailureThreshold);
    }
    validate_duration_for_throttler(
        circuit_breaker.recovery_timeout,
        Error::InvalidThrottlerRecoveryTimeout,
    )?;
    Ok(ResolvedThrottlerCircuitBreaker {
        failure_threshold: circuit_breaker.failure_threshold,
        recovery_timeout: circuit_breaker.recovery_timeout,
    })
}

pub(super) fn validate_duration_for_throttler(
    duration: Duration,
    error: Error,
) -> Result<(), Error> {
    if duration.is_zero() || duration_to_rounded_microseconds(duration).is_none() {
        return Err(error);
    }
    Ok(())
}

pub(super) fn throttler_state_ttl(
    rate_limit: Option<ResolvedThrottlerRateLimit>,
    concurrency_limit: Option<ResolvedThrottlerConcurrencyLimit>,
    circuit_breaker: Option<ResolvedThrottlerCircuitBreaker>,
) -> Result<KvTtl, Error> {
    let mut ttl = Duration::ZERO;
    if let Some(rate_limit) = rate_limit {
        ttl = ttl.max(scale_duration_for_throttler_state_ttl(rate_limit.interval));
    }
    if let Some(concurrency_limit) = concurrency_limit {
        ttl = ttl.max(scale_duration_for_throttler_state_ttl(
            concurrency_limit.max_hold_duration,
        ));
    }
    if let Some(circuit_breaker) = circuit_breaker {
        ttl = ttl.max(scale_duration_for_throttler_state_ttl(
            circuit_breaker.recovery_timeout,
        ));
        ttl = ttl.max(scale_duration_for_throttler_state_ttl(
            DEFAULT_FLEET_THROTTLER_PROBE_WINDOW,
        ));
    }
    if ttl.is_zero() {
        ttl = DEFAULT_FLEET_THROTTLER_STATE_TTL;
    }
    if ttl < MIN_KV_TTL {
        ttl = MIN_KV_TTL;
    }
    KvTtl::expires_after(ttl).map_err(|source| Error::InvalidThrottlerStateTtl { source })
}

pub(super) fn scale_duration_for_throttler_state_ttl(duration: Duration) -> Duration {
    if duration.is_zero() {
        return Duration::ZERO;
    }
    let max_duration = max_kv_ttl_duration();
    duration
        .checked_mul(FLEET_THROTTLER_STATE_TTL_MULTIPLIER)
        .unwrap_or(max_duration)
        .min(max_duration)
}

pub(super) fn max_kv_ttl_duration() -> Duration {
    Duration::from_micros(i64::MAX as u64)
}

pub(super) fn add_duration_to_timestamp(timestamp: i64, duration: Duration) -> Result<i64, Error> {
    let duration_microseconds =
        duration_to_rounded_microseconds(duration).ok_or(Error::ThrottlerTimestampOverflow)?;
    timestamp
        .checked_add(duration_microseconds)
        .ok_or(Error::ThrottlerTimestampOverflow)
}

pub(super) fn duration_to_rounded_microseconds(duration: Duration) -> Option<i64> {
    let nanoseconds = duration.as_nanos();
    let microseconds = (nanoseconds / 1_000) + u128::from(!nanoseconds.is_multiple_of(1_000));
    if microseconds > i64::MAX as u128 {
        return None;
    }
    Some(microseconds as i64)
}

pub(super) fn duration_to_microseconds_lossy(duration: Duration) -> i64 {
    duration_to_rounded_microseconds(duration).unwrap_or(i64::MAX)
}

pub(super) fn compute_rate_limit_retry_after_duration(
    current_tokens: f64,
    refill_rate_per_second: f64,
) -> Duration {
    if refill_rate_per_second <= 0.0 {
        return max_kv_ttl_duration();
    }

    let retry_after_seconds = (1.0 - current_tokens) / refill_rate_per_second;
    if retry_after_seconds <= 0.0 {
        return Duration::from_millis(1);
    }
    if !retry_after_seconds.is_finite() {
        return max_kv_ttl_duration();
    }

    let retry_after = Duration::from_secs_f64(retry_after_seconds);
    retry_after.max(Duration::from_millis(1))
}

pub(super) fn clear_probe_if_owned(state: &mut ThrottlerState, permit: &ThrottlerPermit) -> bool {
    let Some(holder_id) = permit.holder_id.as_ref() else {
        return false;
    };
    if state.probe_holder_id.as_deref() != Some(holder_id.as_str()) {
        return false;
    }
    state.probe_holder_id = None;
    state.probe_expires_at_unix_microseconds = None;
    true
}
