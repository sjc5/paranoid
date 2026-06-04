use super::kv::{
    AtomicMutationOutcome as KvAtomicMutationOutcome, Error as KvError, Item as KvItem,
    ItemAtomicMutation as KvItemAtomicMutation, ItemScannedValue as KvItemScannedValue,
    KeyPrefix as KvKeyPrefix, MIN_KV_TTL, Store as KvStore, StoreConfig as KvStoreConfig,
    Ttl as KvTtl,
    migrate_schema_in_current_transaction as migrate_kv_schema_in_current_transaction,
};
use super::lease::{
    Claim as LeaseClaim, HolderSnapshot as LeaseHolderSnapshot, Key as LeaseKey,
    Store as LeaseStore, StoreConfig as RawLeaseStoreConfig,
    migrate_schema_in_current_transaction as migrate_lease_schema_in_current_transaction,
};
pub use super::lease::{ClaimDuration, CoordinationError, FencingToken, HolderId};
use super::{
    ComponentSchemaMigrationPlan, ComponentSchemaMigrationStep, ComponentSchemaVersion, DbError,
    PgQualifiedTableName, PgSqlState, Pool, RecordedComponentSchemaVersion,
    SQLSTATE_ADMIN_SHUTDOWN, SQLSTATE_CANNOT_CONNECT_NOW, SQLSTATE_CRASH_SHUTDOWN,
    SQLSTATE_LOCK_NOT_AVAILABLE, SQLSTATE_QUERY_CANCELED, Tx, WritePool, WriteTx,
    duration_from_nonnegative_f64_seconds,
    finish_pool_owned_write_transaction_and_preserve_rollback_error,
    pg_table_name_set_could_contain_same_relation,
    plan_component_schema_migration_in_current_transaction, random_unit_f64_from_system,
    record_component_schema_migration_completion_in_current_transaction,
    schema_instance_key_for_parts, validate_component_schema_version_in_current_transaction,
};
#[cfg(test)]
use super::{
    finish_db_pool_transaction, finish_db_pool_validation_transaction,
    test_schema_ledger_table_name,
};
use crate::id;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;

mod constants;
mod error;

mod cache;
mod cache_model;
mod circuit_breaker;
mod counter;
mod cron;
mod cron_model;
mod handles;
mod keys;
mod mutex;
mod mutex_guard;
mod mutex_model;
mod namespace_keys;
mod once;
mod once_claim;
mod once_completion;
mod once_model;
mod once_task;
mod rate_limiter;
mod semaphore;
mod semaphore_model;
mod store;
mod throttler;
mod throttler_acquire;
mod throttler_guard;
mod throttler_model;
mod throttler_release;
mod throttler_state;
mod throttler_support;
mod topic;
mod topic_model;
mod topic_support;
mod util;

#[cfg(test)]
mod postgres_operation_count_tests;
#[cfg(test)]
mod postgres_tests;

pub use cache_model::{CoalescingCache, CoalescingCacheConfig, CoalescingCacheFetchError, Counter};
pub use constants::*;
pub use cron_model::{
    Cron, CronConfig, CronRunError, CronRunHandle, CronRunHandleError, CronTaskErrorAction,
    CronTryRunOnceResult,
};
pub use error::Error;
pub use keys::{
    CircuitBreakerKey, CoalescingCacheKey, CounterKey, CronKey, MutexKey, OnceKey, RateLimiterKey,
    RootKey, SemaphoreKey, SubscriptionKey, ThrottlerKey, TopicKey,
};
pub use mutex_model::{
    Mutex, MutexGuard, MutexGuardConfig, MutexGuardSnapshot, MutexHolderSnapshot,
    MutexManualRenewalClaim, MutexManualRenewalProtocol, MutexRunError, MutexTryRunTaskResult,
};
pub use once_model::{
    Once, OnceCompletion, OnceManualRunClaim, OnceManualRunProtocol, OnceRunClaimSnapshot,
    OnceRunError, OnceRunTaskResult, OnceTransactionalRunError, OnceTransactionalTaskFuture,
    OnceTryRunTaskResult,
};
pub use semaphore_model::{
    Semaphore, SemaphoreClaim, SemaphoreClaimGuard, SemaphoreGuardedTaskResult,
    SemaphoreManualClaimProtocol, SemaphoreStatus, SemaphoreTryRunTaskResult,
};
pub use store::Store;
pub(crate) use store::StoreConfig;
pub use throttler_model::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerGuardAcquireResult,
    CircuitBreakerGuardedTaskResult, CircuitBreakerManualPermitAcquireResult,
    CircuitBreakerManualPermitProtocol, CircuitBreakerPermit, CircuitBreakerPermitGuard,
    CircuitBreakerReleaseResult, CircuitBreakerState, CircuitBreakerStatus,
    CircuitBreakerTryRunTaskResult, RateLimitConfig, RateLimiter, RateLimiterGuardAcquireResult,
    RateLimiterGuardedTaskResult, RateLimiterManualPermitAcquireResult,
    RateLimiterManualPermitProtocol, RateLimiterPermit, RateLimiterPermitGuard, RateLimiterStatus,
    RateLimiterTryRunTaskResult, Throttler, ThrottlerCircuitBreaker, ThrottlerCircuitState,
    ThrottlerConcurrencyLimit, ThrottlerConfig, ThrottlerGuardAcquireResult,
    ThrottlerGuardedTaskResult, ThrottlerManualPermitAcquireResult, ThrottlerManualPermitProtocol,
    ThrottlerPermit, ThrottlerPermitGuard, ThrottlerRateLimit, ThrottlerReleaseResult,
    ThrottlerStatus, ThrottlerTaskOutcome, ThrottlerTryRunTaskResult,
};
pub use topic_model::{
    Subscription, SubscriptionConfig, SubscriptionPollErrorAction, SubscriptionRunError,
    SubscriptionRunHandle, SubscriptionRunHandleError, Topic, TopicConfig, TopicEvent,
};

use cron_model::CronLeadershipTenureOutcome;
use mutex::fleet_mutex_acquire_retry_delay_with_jitter;
use mutex_guard::{
    combine_cron_task_and_release_results, require_coalescing_cache_mutex_released,
    require_once_task_mutex_released, send_stop_signal,
};
use mutex_model::{MutexHeartbeatRuntime, ResolvedMutexGuardConfig};
use namespace_keys::*;
use semaphore_model::SemaphoreSlot;
use throttler_model::{
    ResolvedThrottlerCircuitBreaker, ResolvedThrottlerConcurrencyLimit, ResolvedThrottlerRateLimit,
    ThrottlerConcurrencyAcquireOutcome, ThrottlerMutationOutcome, ThrottlerProbeHeartbeat,
    ThrottlerRateLimitOutcome, ThrottlerSlot, ThrottlerState,
};
use throttler_support::*;
use topic_model::TopicEventEnvelope;
use topic_support::*;
use util::*;

#[cfg(test)]
pub(crate) const FLEET_OPERATION_SCHEMA_MIGRATE: &str = "fleet.schema.migrate";
#[cfg(test)]
pub(crate) const FLEET_OPERATION_SCHEMA_VALIDATE: &str = "fleet.schema.validate";

async fn finish_fleet_pool_transaction<T>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, Error>,
) -> Result<T, Error> {
    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}
