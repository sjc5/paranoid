use super::*;

/// Default Fleet root key used to namespace Fleet-owned records.
pub const DEFAULT_FLEET_ROOT_KEY: &str = "__paranoid_fleet";

/// Test-only unqualified Fleet state backing table name.
#[cfg(test)]
pub const TEST_FLEET_STATE_TABLE_NAME: &str = "__paranoid_fleet_state";

/// Test-only unqualified Fleet coordination backing table name.
#[cfg(test)]
pub const TEST_FLEET_COORDINATION_TABLE_NAME: &str = "__paranoid_fleet_coordination";

/// Test-only unqualified Fleet fencing counter backing table name.
#[cfg(test)]
pub const TEST_FLEET_FENCING_COUNTER_TABLE_NAME: &str = "__paranoid_fleet_fencing_counters";

pub(crate) const FLEET_SCHEMA_COMPONENT: &str = "fleet";
pub(crate) const FLEET_SCHEMA_VERSION: i32 = 1;
pub(crate) const FLEET_SCHEMA_FINGERPRINT: &str = "paranoid.fleet.v1";

pub(crate) const FLEET_MUTEX_COMPONENT_KEY: &str = "mutex";

pub(crate) const FLEET_COUNTER_COMPONENT_KEY: &str = "counter";

pub(crate) const FLEET_SEMAPHORE_COMPONENT_KEY: &str = "semaphore";

pub(crate) const FLEET_THROTTLER_COMPONENT_KEY: &str = "throttler";

pub(crate) const FLEET_ONCE_COMPONENT_KEY: &str = "once";

pub(crate) const FLEET_CACHE_COMPONENT_KEY: &str = "cache";

pub(crate) const FLEET_TOPIC_COMPONENT_KEY: &str = "topic";

pub(crate) const FLEET_CRON_COMPONENT_KEY: &str = "cron";

/// Maximum semaphore slot count accepted by Fleet.
pub const FLEET_MAX_CONCURRENT_LIMIT: u16 = 100;

/// Default number of topic events a subscription poll reads at once.
pub const DEFAULT_SUBSCRIPTION_POLL_LIMIT: u32 = 100;

/// Maximum number of topic events a subscription poll may read at once.
pub const MAX_SUBSCRIPTION_POLL_LIMIT: u32 = 1000;

/// Minimum wait used by a topic subscription polling loop when no events are found.
pub const MIN_SUBSCRIPTION_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Initial retry wait after a retryable Fleet subscription poll error.
pub const DEFAULT_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum retry wait after repeated Fleet subscription poll errors.
pub const MAX_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) const DEFAULT_SUBSCRIPTION_POLLING_LOOP_CLAIM_DURATION: Duration =
    Duration::from_secs(30);

/// Default Fleet run-once mutex claim duration.
pub const DEFAULT_FLEET_ONCE_CLAIM_DURATION: Duration = Duration::from_secs(5 * 60);

/// Default Fleet semaphore slot hold duration.
pub const DEFAULT_FLEET_SEMAPHORE_MAX_HOLD_DURATION: Duration = Duration::from_secs(5 * 60);

/// Default wait between blocking Fleet semaphore acquisition attempts.
pub const DEFAULT_FLEET_SEMAPHORE_ACQUIRE_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Default Fleet throttler concurrency slot hold duration.
pub const DEFAULT_FLEET_THROTTLER_MAX_HOLD_DURATION: Duration = Duration::from_secs(5 * 60);

/// Default Fleet throttler state TTL when no configured duration contributes one.
pub const DEFAULT_FLEET_THROTTLER_STATE_TTL: Duration = Duration::from_secs(10 * 60);

/// Default Fleet throttler half-open probe reservation window.
pub const DEFAULT_FLEET_THROTTLER_PROBE_WINDOW: Duration = Duration::from_secs(5);

pub(crate) const DEFAULT_FLEET_THROTTLER_PROBE_HEARTBEAT_INTERVAL: Duration =
    Duration::from_secs(1);
pub(crate) const DEFAULT_FLEET_THROTTLER_PROBE_MAX_CONSECUTIVE_HEARTBEAT_FAILURES: u32 = 3;

/// Default wait between blocking acquire attempts when no precise retry is known.
pub const DEFAULT_FLEET_THROTTLER_BLOCKING_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Minimum wait between blocking acquire attempts while a circuit is open.
pub const MIN_FLEET_THROTTLER_CIRCUIT_OPEN_WAIT: Duration = Duration::from_millis(1);

/// Default Fleet mutex claim duration.
pub const DEFAULT_FLEET_MUTEX_CLAIM_DURATION: Duration = Duration::from_secs(30);

/// Default wait between blocking Fleet mutex acquisition attempts.
pub const DEFAULT_FLEET_MUTEX_ACQUIRE_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Default cap for blocking Fleet mutex acquisition backoff.
pub const DEFAULT_FLEET_MUTEX_MAX_ACQUIRE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) const FLEET_MUTEX_ACQUIRE_RETRY_JITTER_FRACTION: f64 = 0.25;

/// Minimum Fleet mutex heartbeat interval.
pub const MIN_FLEET_MUTEX_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(100);

/// Default consecutive failed heartbeat count before a guarded mutex is considered lost.
pub const DEFAULT_FLEET_MUTEX_MAX_CONSECUTIVE_RENEWAL_FAILURES: u32 = 3;

/// Default Fleet cron leadership claim duration.
pub const DEFAULT_FLEET_CRON_CLAIM_DURATION: Duration = Duration::from_secs(30);

/// Default Fleet cron leadership heartbeat interval.
pub const DEFAULT_FLEET_CRON_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Default wait between Fleet cron leadership acquisition attempts.
pub const DEFAULT_FLEET_CRON_ACQUIRE_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Minimum Fleet cron task interval.
pub const MIN_FLEET_CRON_INTERVAL: Duration = Duration::from_secs(1);

/// Default Fleet coalescing cache mutex claim duration.
pub const DEFAULT_COALESCING_CACHE_MUTEX_CLAIM_DURATION: Duration = Duration::from_secs(30);

/// Default maximum time to wait for a Fleet coalescing cache compute mutex.
pub const DEFAULT_COALESCING_CACHE_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default wait between Fleet coalescing cache mutex acquisition attempts.
pub const DEFAULT_COALESCING_CACHE_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) const FLEET_THROTTLER_STATE_TTL_MULTIPLIER: u32 = 10;
pub(crate) const FLEET_ONCE_COMPLETION_COMPONENT_KEY: &str = "completion";
pub(crate) const FLEET_ONCE_MUTEX_COMPONENT_KEY: &str = "mutex";
pub(crate) const FLEET_ONCE_DONE_KEY_PART: &str = "done";
pub(crate) const FLEET_COUNTER_VALUE_KEY_PART: &str = "value";
pub(crate) const FLEET_SEMAPHORE_SLOTS_COMPONENT_KEY: &str = "slots";
pub(crate) const FLEET_THROTTLER_STATE_KEY_PART: &str = "state";
pub(crate) const COALESCING_CACHE_VALUE_COMPONENT_KEY: &str = "value";
pub(crate) const COALESCING_CACHE_EPOCH_COMPONENT_KEY: &str = "epoch";
pub(crate) const COALESCING_CACHE_MUTEX_COMPONENT_KEY: &str = "mutex";
pub(crate) const TOPIC_SEQUENCE_COMPONENT_KEY: &str = "sequence";
pub(crate) const TOPIC_EVENTS_COMPONENT_KEY: &str = "events";
pub(crate) const TOPIC_SUBSCRIPTIONS_COMPONENT_KEY: &str = "subscriptions";
pub(crate) const TOPIC_CURSOR_COMPONENT_KEY: &str = "cursor";
pub(crate) const TOPIC_POLLING_MUTEX_COMPONENT_KEY: &str = "polling_mutex";

pub(crate) const FLEET_OPERATION_COUNTER_ADD: &str = "fleet.counter.add";
pub(crate) const FLEET_OPERATION_CACHE_INVALIDATE_ALL: &str = "fleet.cache.invalidate_all";
pub(crate) const FLEET_OPERATION_SEMAPHORE_ACQUIRE: &str = "fleet.semaphore.acquire";
pub(crate) const FLEET_OPERATION_SEMAPHORE_RELEASE: &str = "fleet.semaphore.release";
pub(crate) const FLEET_OPERATION_ONCE_MARK_DONE_AND_RELEASE: &str =
    "fleet.once.mark_done_and_release";
pub(crate) const FLEET_OPERATION_ONCE_MARK_COMPLETION: &str = "fleet.once.mark_completion";
pub(crate) const FLEET_OPERATION_ONCE_TRY_RESET: &str = "fleet.once.try_reset";
pub(crate) const FLEET_OPERATION_THROTTLER_ACQUIRE: &str = "fleet.throttler.acquire";
pub(crate) const FLEET_OPERATION_THROTTLER_RELEASE: &str = "fleet.throttler.release";
pub(crate) const FLEET_OPERATION_THROTTLER_EXTEND_PROBE: &str = "fleet.throttler.extend_probe";
pub(crate) const FLEET_OPERATION_THROTTLER_OPEN_CIRCUIT: &str = "fleet.throttler.open_circuit";
pub(crate) const FLEET_OPERATION_THROTTLER_CLOSE_CIRCUIT: &str = "fleet.throttler.close_circuit";
pub(crate) const FLEET_OPERATION_TOPIC_PUBLISH: &str = "fleet.topic.publish";
pub(crate) const FLEET_OPERATION_TOPIC_READ_NEW_EVENTS_AND_ADVANCE_CURSOR: &str =
    "fleet.topic.read_new_events_and_advance_cursor";
pub(crate) const FLEET_OPERATION_TOPIC_ADVANCE_CURSOR: &str = "fleet.topic.advance_cursor";
