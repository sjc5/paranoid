use super::*;

pub(super) fn build_counter_prefix(
    root_key: &str,
    counter_key: &str,
) -> Result<KvKeyPrefix, Error> {
    KvKeyPrefix::from_parts([root_key, FLEET_COUNTER_COMPONENT_KEY, counter_key])
        .map_err(|source| Error::InvalidCounterKey { source })
}

pub(super) fn build_topic_sequence_prefix(
    root_key: &str,
    topic_key: &str,
) -> Result<KvKeyPrefix, KvError> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_TOPIC_COMPONENT_KEY,
        topic_key,
        TOPIC_SEQUENCE_COMPONENT_KEY,
    ])
}

pub(super) fn build_topic_events_prefix(
    root_key: &str,
    topic_key: &str,
) -> Result<KvKeyPrefix, KvError> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_TOPIC_COMPONENT_KEY,
        topic_key,
        TOPIC_EVENTS_COMPONENT_KEY,
    ])
}

pub(super) fn build_subscription_cursor_prefix(
    root_key: &str,
    topic_key: &str,
    subscription_key: &str,
) -> Result<KvKeyPrefix, KvError> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_TOPIC_COMPONENT_KEY,
        topic_key,
        TOPIC_SUBSCRIPTIONS_COMPONENT_KEY,
        subscription_key,
        TOPIC_CURSOR_COMPONENT_KEY,
    ])
}

pub(super) fn build_subscription_polling_mutex_lease_key(
    root_key: &str,
    topic_key: &str,
    subscription_key: &str,
) -> Result<LeaseKey, CoordinationError> {
    LeaseKey::from_parts([
        root_key,
        FLEET_TOPIC_COMPONENT_KEY,
        topic_key,
        TOPIC_SUBSCRIPTIONS_COMPONENT_KEY,
        subscription_key,
        TOPIC_POLLING_MUTEX_COMPONENT_KEY,
    ])
}

pub(super) fn build_cron_mutex_lease_key(
    root_key: &str,
    cron_key: &str,
) -> Result<LeaseKey, CoordinationError> {
    LeaseKey::from_parts([root_key, FLEET_CRON_COMPONENT_KEY, cron_key])
}

pub(super) fn build_coalescing_cache_value_prefix(
    root_key: &str,
    cache_key: &str,
) -> Result<KvKeyPrefix, KvError> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_CACHE_COMPONENT_KEY,
        cache_key,
        COALESCING_CACHE_VALUE_COMPONENT_KEY,
    ])
}

pub(super) fn build_coalescing_cache_epoch_prefix(
    root_key: &str,
    cache_key: &str,
) -> Result<KvKeyPrefix, KvError> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_CACHE_COMPONENT_KEY,
        cache_key,
        COALESCING_CACHE_EPOCH_COMPONENT_KEY,
    ])
}

pub(super) fn build_coalescing_cache_mutex_lease_key<S, I>(
    root_key: &str,
    cache_key: &str,
    key_parts: I,
) -> Result<LeaseKey, CoordinationError>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut parts = vec![
        root_key.to_owned(),
        FLEET_CACHE_COMPONENT_KEY.to_owned(),
        cache_key.to_owned(),
        COALESCING_CACHE_MUTEX_COMPONENT_KEY.to_owned(),
    ];
    parts.extend(key_parts.into_iter().map(|part| part.as_ref().to_owned()));
    LeaseKey::from_parts(parts)
}

pub(super) fn validated_cache_key_parts<S, I>(key_parts: I) -> Result<Vec<String>, Error>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let key_parts = key_parts
        .into_iter()
        .map(|part| part.as_ref().to_owned())
        .collect::<Vec<_>>();
    KvKeyPrefix::from_parts(
        std::iter::once("validation").chain(key_parts.iter().map(String::as_str)),
    )
    .map_err(|source| Error::InvalidCoalescingCacheKeyForValue { source })?;
    Ok(key_parts)
}

pub(super) fn build_semaphore_slots_prefix(
    root_key: &str,
    semaphore_key: &str,
) -> Result<KvKeyPrefix, Error> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_SEMAPHORE_COMPONENT_KEY,
        FLEET_SEMAPHORE_SLOTS_COMPONENT_KEY,
        semaphore_key,
    ])
    .map_err(|source| Error::InvalidSemaphoreKey { source })
}

pub(super) fn build_throttler_state_prefix(
    root_key: &str,
    throttler_key: &str,
) -> Result<KvKeyPrefix, Error> {
    KvKeyPrefix::from_parts([root_key, FLEET_THROTTLER_COMPONENT_KEY, throttler_key])
        .map_err(|source| Error::InvalidThrottlerKey { source })
}

pub(super) fn build_once_completion_prefix(
    root_key: &str,
    once_key: &str,
) -> Result<KvKeyPrefix, Error> {
    KvKeyPrefix::from_parts([
        root_key,
        FLEET_ONCE_COMPONENT_KEY,
        FLEET_ONCE_COMPLETION_COMPONENT_KEY,
        once_key,
    ])
    .map_err(|source| Error::InvalidOnceKeyForCompletionMarker { source })
}

pub(super) fn build_once_mutex_lease_key(
    root_key: &str,
    once_key: &str,
) -> Result<LeaseKey, Error> {
    LeaseKey::from_parts([
        root_key,
        FLEET_ONCE_COMPONENT_KEY,
        FLEET_ONCE_MUTEX_COMPONENT_KEY,
        once_key,
    ])
    .map_err(|source| Error::InvalidOnceKeyForMutex { source })
}
