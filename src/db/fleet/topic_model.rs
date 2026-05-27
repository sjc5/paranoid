use super::*;

/// Error returned by a Fleet subscription polling loop.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionRunError<E> {
    /// A Fleet operation failed.
    #[error(transparent)]
    Fleet(#[from] Error),
    /// The guarded polling loop lost its exclusive subscription claim.
    #[error("Fleet subscription polling guard was lost")]
    PollingGuardLost,
    /// Releasing the guarded polling loop's exclusive subscription claim failed.
    #[error("Fleet subscription polling guard release failed")]
    PollingGuardRelease {
        /// Release error.
        #[source]
        source: Error,
    },
    /// A Fleet operation failed and the guarded polling loop had also lost its exclusive claim.
    #[error("Fleet operation failed and subscription polling guard was lost")]
    FleetAndPollingGuardLost {
        /// Underlying Fleet error.
        #[source]
        source: Error,
    },
    /// A Fleet operation failed and releasing the guarded polling loop's exclusive claim also failed.
    #[error("Fleet operation failed and subscription polling guard release also failed")]
    FleetAndPollingGuardRelease {
        /// Underlying Fleet error.
        #[source]
        source: Error,
        /// Release error.
        release_error: Error,
    },
    /// The caller-supplied event handler failed.
    #[error("Fleet subscription event handler failed")]
    Handler {
        /// Underlying handler error.
        #[source]
        source: E,
    },
    /// The caller-supplied event handler failed and the guarded polling loop had also lost its exclusive claim.
    #[error("Fleet subscription event handler failed and polling guard was lost")]
    HandlerAndPollingGuardLost {
        /// Underlying handler error.
        #[source]
        source: E,
    },
    /// The caller-supplied event handler failed and releasing the guarded polling loop's exclusive claim also failed.
    #[error("Fleet subscription event handler failed and polling guard release also failed")]
    HandlerAndPollingGuardRelease {
        /// Underlying handler error.
        #[source]
        source: E,
        /// Release error.
        release_error: Error,
    },
    /// The guarded polling loop lost its exclusive subscription claim and releasing that claim also failed.
    #[error("Fleet subscription polling guard was lost and release also failed")]
    PollingGuardLostAndRelease {
        /// Release error.
        #[source]
        release_error: Error,
    },
}

/// Policy decision after a Fleet subscription polling operation returns a database-shaped error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionPollErrorAction {
    /// Retry polling after the supplied delay.
    ContinueAfter(Duration),
    /// Stop the polling loop and return the poll error.
    Stop,
}

/// Error returned while waiting for a Fleet subscription background polling task.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionRunHandleError<E> {
    /// The subscription polling loop returned an error.
    #[error(transparent)]
    Run {
        /// Polling loop error.
        #[from]
        source: SubscriptionRunError<E>,
    },
    /// The background task failed to join.
    #[error("Fleet subscription background task failed to join")]
    Join {
        /// Join error.
        #[source]
        source: tokio::task::JoinError,
    },
}

/// Handle for a Fleet subscription background polling task.
#[must_use = "call request_stop, wait, or stop_and_wait so the subscription loop lifecycle is observed"]
#[derive(Debug)]
pub struct SubscriptionRunHandle<E> {
    pub(super) stop_sender: Option<oneshot::Sender<()>>,
    pub(super) join_handle: Option<JoinHandle<Result<(), SubscriptionRunError<E>>>>,
}

/// Configures a durable Fleet topic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicConfig {
    /// Topic namespace key.
    pub key: TopicKey,
    /// TTL used for persisted events.
    pub event_ttl: KvTtl,
}

/// KV-backed durable topic with monotonic event sequencing.
#[derive(Clone, Debug)]
pub struct Topic<T> {
    pub(super) key: TopicKey,
    pub(super) event_ttl: KvTtl,
    pub(super) sequence_item: KvItem<i64>,
    pub(super) event_prefix: KvKeyPrefix,
    pub(super) event_item: KvItem<TopicEventEnvelope<T>>,
    pub(super) cursor_store: KvStore,
    pub(super) polling_mutex_lease_store: LeaseStore,
    pub(super) root_key: RootKey,
    pub(super) marker: PhantomData<T>,
}

/// Configures a Fleet topic subscription.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionConfig {
    /// Subscription namespace key.
    pub key: SubscriptionKey,
    /// Maximum events returned by one poll.
    pub poll_limit: Option<u32>,
}

/// Cursor-backed Fleet topic subscription.
#[derive(Debug)]
pub struct Subscription<T> {
    pub(super) topic_key: TopicKey,
    pub(super) key: SubscriptionKey,
    pub(super) poll_limit: u32,
    pub(super) event_item: KvItem<TopicEventEnvelope<T>>,
    pub(super) cursor_item: KvItem<i64>,
    pub(super) polling_mutex: Mutex,
    pub(super) polling_mutex_guard_config: MutexGuardConfig,
}

impl<T> Clone for Subscription<T> {
    fn clone(&self) -> Self {
        Self {
            topic_key: self.topic_key.clone(),
            key: self.key.clone(),
            poll_limit: self.poll_limit,
            event_item: self.event_item.clone(),
            cursor_item: self.cursor_item.clone(),
            polling_mutex: self.polling_mutex.clone(),
            polling_mutex_guard_config: self.polling_mutex_guard_config,
        }
    }
}

/// One event read from a Fleet topic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopicEvent<T> {
    pub(super) sequence: i64,
    pub(super) published_at_unix_microseconds: i64,
    pub(super) data: T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(bound(deserialize = "T: DeserializeOwned", serialize = "T: Serialize"))]
pub(super) struct TopicEventEnvelope<T> {
    pub(super) published_at_unix_microseconds: i64,
    pub(super) data: T,
}
