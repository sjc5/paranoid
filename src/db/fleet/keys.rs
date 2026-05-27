use super::*;

/// Validated Fleet root key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RootKey(pub(super) String);

/// Validated Fleet mutex key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MutexKey(pub(super) String);

/// Validated Fleet counter key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CounterKey(pub(super) String);

/// Validated Fleet coalescing cache key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoalescingCacheKey(pub(super) String);

/// Validated Fleet topic key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TopicKey(pub(super) String);

/// Validated Fleet subscription key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubscriptionKey(pub(super) String);

/// Validated Fleet cron key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CronKey(pub(super) String);

/// Validated Fleet semaphore key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SemaphoreKey(pub(super) String);

/// Validated Fleet throttler key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThrottlerKey(pub(super) String);

/// Validated Fleet rate-limiter key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RateLimiterKey(pub(super) String);

/// Validated Fleet circuit-breaker key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CircuitBreakerKey(pub(super) String);

/// Validated Fleet run-once key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OnceKey(pub(super) String);

impl Default for RootKey {
    fn default() -> Self {
        Self(DEFAULT_FLEET_ROOT_KEY.to_owned())
    }
}

impl RootKey {
    /// Validates and copies a Fleet root key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        LeaseKey::from_parts([input, FLEET_MUTEX_COMPONENT_KEY, "validation"])
            .map_err(|source| Error::InvalidRootKey { source })?;
        KvKeyPrefix::from_parts([input, FLEET_COUNTER_COMPONENT_KEY, "validation"])
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        build_coalescing_cache_value_prefix(input, "validation")
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        build_coalescing_cache_epoch_prefix(input, "validation")
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        build_coalescing_cache_mutex_lease_key(input, "validation", std::iter::empty::<&str>())
            .map_err(|source| Error::InvalidRootKey { source })?;
        build_topic_sequence_prefix(input, "validation")
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        build_topic_events_prefix(input, "validation")
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        build_subscription_cursor_prefix(input, "validation", "validation")
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        build_cron_mutex_lease_key(input, "validation")
            .map_err(|source| Error::InvalidRootKey { source })?;
        KvKeyPrefix::from_parts([input, FLEET_SEMAPHORE_COMPONENT_KEY, "validation"])
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        KvKeyPrefix::from_parts([input, FLEET_THROTTLER_COMPONENT_KEY, "validation"])
            .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        KvKeyPrefix::from_parts([
            input,
            FLEET_ONCE_COMPONENT_KEY,
            FLEET_ONCE_COMPLETION_COMPONENT_KEY,
            "validation",
        ])
        .map_err(|source| Error::InvalidRootKeyForKv { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated root key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl MutexKey {
    /// Validates and copies a Fleet mutex key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        LeaseKey::from_parts([DEFAULT_FLEET_ROOT_KEY, FLEET_MUTEX_COMPONENT_KEY, input])
            .map_err(|source| Error::InvalidMutexKey { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated mutex key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CounterKey {
    /// Validates and copies a Fleet counter key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_counter_prefix(DEFAULT_FLEET_ROOT_KEY, input)?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated counter key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CoalescingCacheKey {
    /// Validates and copies a Fleet coalescing cache key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_coalescing_cache_value_prefix(DEFAULT_FLEET_ROOT_KEY, input)
            .map_err(|source| Error::InvalidCoalescingCacheKeyForValue { source })?;
        build_coalescing_cache_epoch_prefix(DEFAULT_FLEET_ROOT_KEY, input)
            .map_err(|source| Error::InvalidCoalescingCacheKeyForEpoch { source })?;
        build_coalescing_cache_mutex_lease_key(
            DEFAULT_FLEET_ROOT_KEY,
            input,
            std::iter::empty::<&str>(),
        )
        .map_err(|source| Error::InvalidCoalescingCacheKeyForMutex { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated cache key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TopicKey {
    /// Validates and copies a Fleet topic key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_topic_sequence_prefix(DEFAULT_FLEET_ROOT_KEY, input)
            .map_err(|source| Error::InvalidTopicKeyForSequence { source })?;
        build_topic_events_prefix(DEFAULT_FLEET_ROOT_KEY, input)
            .map_err(|source| Error::InvalidTopicKeyForEvents { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated topic key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SubscriptionKey {
    /// Validates and copies a Fleet subscription key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_subscription_cursor_prefix(DEFAULT_FLEET_ROOT_KEY, "validation", input)
            .map_err(|source| Error::InvalidSubscriptionKeyForCursor { source })?;
        build_subscription_polling_mutex_lease_key(DEFAULT_FLEET_ROOT_KEY, "validation", input)
            .map_err(|source| Error::InvalidSubscriptionKeyForPollingMutex { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated subscription key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CronKey {
    /// Validates and copies a Fleet cron key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_cron_mutex_lease_key(DEFAULT_FLEET_ROOT_KEY, input)
            .map_err(|source| Error::InvalidCronKey { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated cron key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SemaphoreKey {
    /// Validates and copies a Fleet semaphore key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_semaphore_slots_prefix(DEFAULT_FLEET_ROOT_KEY, input)?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated semaphore key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ThrottlerKey {
    /// Validates and copies a Fleet throttler key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_throttler_state_prefix(DEFAULT_FLEET_ROOT_KEY, input)?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated throttler key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RateLimiterKey {
    /// Validates and copies a Fleet rate-limiter key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        KvKeyPrefix::from_parts([DEFAULT_FLEET_ROOT_KEY, FLEET_THROTTLER_COMPONENT_KEY, input])
            .map_err(|source| Error::InvalidRateLimiterKey { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated rate-limiter key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CircuitBreakerKey {
    /// Validates and copies a Fleet circuit-breaker key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        KvKeyPrefix::from_parts([DEFAULT_FLEET_ROOT_KEY, FLEET_THROTTLER_COMPONENT_KEY, input])
            .map_err(|source| Error::InvalidCircuitBreakerKey { source })?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated circuit-breaker key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl OnceKey {
    /// Validates and copies a Fleet run-once key.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        let input = input.as_ref();
        build_once_completion_prefix(DEFAULT_FLEET_ROOT_KEY, input)?;
        build_once_mutex_lease_key(DEFAULT_FLEET_ROOT_KEY, input)?;
        Ok(Self(input.to_owned()))
    }

    /// Returns the validated run-once key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
