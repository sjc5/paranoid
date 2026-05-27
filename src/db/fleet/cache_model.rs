use super::*;

/// KV-backed Fleet atomic counter.
#[derive(Clone, Debug)]
pub struct Counter {
    pub(super) item: KvItem<i64>,
    pub(super) key: CounterKey,
}

/// Configures a Fleet coalescing cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalescingCacheConfig {
    /// Cache namespace key.
    pub key: CoalescingCacheKey,
    /// TTL used for cached values.
    pub value_ttl: KvTtl,
    /// Maximum duration to wait for another worker computing the same key.
    pub lock_wait_timeout: Option<Duration>,
    /// Maximum duration allowed for one cache-miss computation.
    pub compute_timeout: Option<Duration>,
}

/// KV-and-mutex-backed distributed cache that coalesces concurrent misses.
#[derive(Clone, Debug)]
pub struct CoalescingCache<T> {
    pub(super) key: CoalescingCacheKey,
    pub(super) value_ttl: KvTtl,
    pub(super) lock_wait_timeout: Duration,
    pub(super) compute_timeout: Option<Duration>,
    pub(super) value_item: KvItem<CoalescingCacheEntry<T>>,
    pub(super) epoch_item: KvItem<i64>,
    pub(super) mutex_lease_store: LeaseStore,
    pub(super) mutex_claim_duration: ClaimDuration,
    pub(super) root_key: RootKey,
    pub(super) marker: PhantomData<T>,
}

/// Error returned by `CoalescingCache::fetch_or_compute`.
#[derive(Debug, thiserror::Error)]
pub enum CoalescingCacheFetchError<E> {
    /// A Fleet operation failed.
    #[error(transparent)]
    Fleet(#[from] Error),
    /// The caller-supplied computation failed.
    #[error("Fleet coalescing cache computation failed")]
    Compute {
        /// Underlying computation error.
        #[source]
        source: E,
    },
    /// The caller-supplied computation failed and the compute mutex could not be released.
    #[error("Fleet coalescing cache computation failed and mutex release also failed")]
    ComputeAndRelease {
        /// Underlying computation error.
        #[source]
        source: E,
        /// Mutex release error.
        release_error: Error,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(bound(deserialize = "T: DeserializeOwned", serialize = "T: Serialize"))]
pub(super) struct CoalescingCacheEntry<T> {
    pub(super) value: T,
    pub(super) epoch: i64,
}
