use crate::db::fleet::StoreConfig as FleetStoreConfig;
use crate::db::kv::StoreConfig as KvStoreConfig;
use crate::db::postgres_test_support::{
    connect_sqlx_pool_for_harness, drop_test_table as common_drop_test_table,
    read_only_test_database_url as common_read_only_test_database_url,
    read_only_test_role_name as common_read_only_test_role_name, standard_test_database_url,
};
use crate::db::queue::StoreConfig as QueueStoreConfig;
use crate::db::{
    Error as DbError, PgIdentifier, PgQualifiedTableName, PoolConfig, WritePool,
    unparameterized_simple_query,
};
use crate::fleet::{
    CircuitBreakerConfig, CircuitBreakerKey, ClaimDuration, CoalescingCacheConfig,
    CoalescingCacheKey, CoordinationError, CounterKey, CronConfig, CronKey, CronRunError,
    CronRunHandleError, CronTaskErrorAction, Error as FleetError, HolderId, MIN_CRON_INTERVAL,
    MIN_MUTEX_HEARTBEAT_INTERVAL, MutexGuardConfig, MutexKey, MutexRunError, OnceKey, OnceRunError,
    OnceTransactionalRunError, RateLimitConfig, RateLimiterKey, RootKey, SemaphoreKey,
    Store as FleetStore, SubscriptionConfig, SubscriptionKey, SubscriptionRunError,
    SubscriptionRunHandleError, ThrottlerCircuitBreaker, ThrottlerConcurrencyLimit,
    ThrottlerConfig, ThrottlerKey, ThrottlerRateLimit, TopicConfig, TopicKey,
};
use crate::id::SortableId as UniqueTestId;
use crate::kv::{
    AtomicMutation as KvAtomicMutation, BytesSetEntry as KvBytesSetEntry, Error as KvError,
    Item as KvItem, ItemAtomicMutation as KvItemAtomicMutation, Key as KvKey,
    KeyPrefix as KvKeyPrefix, Store as KvStore, Ttl as KvTtl,
};
use crate::queue::{
    DeadLetterReason, EnqueueBatchOptions, EnqueueOptions, Error as QueueError, JobId,
    ListDeadLetterJobsOptions, ListJobsOptions, Store as QueueStore, TaskRegistry, WorkerConfig,
    WorkerMaintenanceConfig, WorkerOwnerId,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

const TEST_TASK_NAME: &str = "marker_task";
const TEST_WORKER_NAME: &str = "marker_worker";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestPayload {
    value: i32,
}

#[derive(Debug)]
struct TestTaskError;

impl fmt::Display for TestTaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test task error")
    }
}

impl StdError for TestTaskError {}

macro_rules! assert_fails_with_insufficient_privilege {
    ($label:literal, $future:expr, $predicate:path) => {{
        let result = $future.await;
        let error = match result {
            Ok(_) => panic!(
                "{} unexpectedly succeeded with a read-only role hidden behind WritePool",
                $label
            ),
            Err(error) => error,
        };
        assert!(
            $predicate(&error),
            "{} did not fail with SQLSTATE 42501: {:?}",
            $label,
            error,
        );
    }};
}

macro_rules! assert_write_tx_fails_with_insufficient_privilege {
    ($pool:expr, $label:literal, $tx_name:ident, $future:expr, $predicate:path) => {{
        let mut tx = $pool
            .begin_transaction()
            .await
            .expect(concat!($label, " begin transaction"));
        let result = {
            let $tx_name = &mut tx;
            $future.await
        };
        let error = match result {
            Ok(_) => panic!(
                "{} unexpectedly succeeded with a read-only role hidden behind WriteTx",
                $label
            ),
            Err(error) => error,
        };
        assert!(
            $predicate(&error),
            "{} did not fail with SQLSTATE 42501: {:?}",
            $label,
            error,
        );
        tx.rollback()
            .await
            .expect(concat!($label, " rollback transaction"));
    }};
}

mod fleet_surface;
mod kv_surface;
mod queue_surface;

#[tokio::test]
async fn read_only_role_hidden_behind_write_pool_proves_public_db_handle_contract() {
    let database_url = standard_test_database_url();
    let admin_pool = connect_write_pool(&database_url, "paranoid_db_marker_admin").await;
    let admin_sqlx_pool =
        connect_sqlx_pool_for_harness(&database_url, 5, "paranoid_db_marker_harness").await;

    let kv_config = unique_kv_config();
    let fleet_config = unique_fleet_config();
    let queue_config = unique_queue_config();
    drop_marker_tables(&admin_sqlx_pool, &kv_config, &fleet_config, &queue_config).await;

    let kv_store = KvStore::new(kv_config.clone()).expect("KV store");
    let fleet_store = FleetStore::new(fleet_config.clone()).expect("Fleet store");
    let queue_store = QueueStore::new(queue_config.clone()).expect("queue store");

    kv_store
        .migrate_schema(&admin_pool)
        .await
        .expect("migrate KV schema");
    fleet_store
        .migrate_schema(&admin_pool)
        .await
        .expect("migrate Fleet schema");
    queue_store
        .migrate_schema(&admin_pool)
        .await
        .expect("migrate queue schema");

    seed_kv_marker_rows(&admin_pool, &kv_store).await;
    let seeded_queue_job_id = queue_store
        .enqueue_json(
            &admin_pool,
            TEST_TASK_NAME,
            &TestPayload { value: 7 },
            EnqueueOptions::default(),
        )
        .await
        .expect("seed queue job")
        .job_id;

    let topic = fleet_store
        .new_topic::<TestPayload>(TopicConfig {
            key: TopicKey::new("marker_topic").expect("topic key"),
            event_ttl: KvTtl::no_expiration(),
        })
        .expect("topic");
    topic
        .publish(&admin_pool, TestPayload { value: 11 })
        .await
        .expect("seed Fleet topic event");

    let read_only_role_name = read_only_test_role_name();
    grant_schema_read_access_to_login_role(&admin_sqlx_pool, &read_only_role_name).await;

    let read_only_database_url = common_read_only_test_database_url();
    let read_only_backed_write_pool =
        connect_write_pool(&read_only_database_url, "paranoid_db_marker_read_only").await;

    kv_surface::exercise_kv_public_db_handle_surface(&read_only_backed_write_pool, &kv_store).await;
    fleet_surface::exercise_fleet_public_db_handle_surface(
        &read_only_backed_write_pool,
        &fleet_store,
    )
    .await;
    queue_surface::exercise_queue_public_db_handle_surface(
        &read_only_backed_write_pool,
        &queue_store,
        &fleet_store,
        seeded_queue_job_id,
    )
    .await;

    read_only_backed_write_pool.sqlx_pool().close().await;
    drop_marker_tables(&admin_sqlx_pool, &kv_config, &fleet_config, &queue_config).await;
    revoke_schema_read_access_from_login_role(&admin_sqlx_pool, &read_only_role_name).await;
    admin_pool.sqlx_pool().close().await;
    admin_sqlx_pool.close().await;
}

async fn seed_kv_marker_rows(pool: &WritePool, store: &KvStore) {
    let key = KvKey::from_parts(["marker", "seed"]).expect("KV seed key");
    store
        .set_bytes(pool, &key, b"seed", KvTtl::no_expiration())
        .await
        .expect("seed KV bytes");

    let item_prefix = KvKeyPrefix::from_parts(["typed"]).expect("typed item prefix");
    let item = KvItem::<TestPayload>::new_plain(store.clone(), item_prefix);
    item.set(
        pool,
        ["seed"],
        &TestPayload { value: 42 },
        KvTtl::no_expiration(),
    )
    .await
    .expect("seed KV item");
}

fn fast_worker_config() -> WorkerConfig {
    WorkerConfig {
        poll_interval: Duration::from_millis(10),
        startup_jitter_max_delay: Some(Duration::ZERO),
        concurrency: 1,
        stale_threshold: Duration::from_secs(30),
        execution_heartbeat_interval: Duration::from_secs(5),
        default_job_timeout: crate::queue::WorkerDefaultJobTimeout::ExpiresAfter(
            Duration::from_secs(5),
        ),
        retry_policy: Default::default(),
        dead_letter_enabled: true,
        shutdown_grace_period: Duration::from_millis(100),
        database_operation_timeout: Duration::from_millis(500),
    }
}

fn fast_worker_maintenance_config() -> WorkerMaintenanceConfig {
    WorkerMaintenanceConfig {
        reclaim_interval: MIN_CRON_INTERVAL,
        cleanup_interval: MIN_CRON_INTERVAL,
        completed_job_retention: Duration::from_secs(1),
        failed_job_retention: Duration::from_secs(1),
        dead_letter_job_retention: Duration::from_secs(1),
        reclaim_batch_size: 1,
        cleanup_batch_size: 1,
        delay_between_cleanup_batches: Duration::ZERO,
        ..WorkerMaintenanceConfig::default()
    }
}

async fn assert_cron_handle_fails_with_insufficient_privilege(
    label: &str,
    handle: crate::fleet::CronRunHandle<TestTaskError>,
) {
    let result = match tokio::time::timeout(Duration::from_secs(2), handle.wait()).await {
        Ok(result) => result,
        Err(_) => panic!("{label} did not finish after privilege failure"),
    };
    let error = result.expect_err("cron handle unexpectedly succeeded");
    assert!(
        cron_handle_error_is_insufficient_privilege(&error),
        "{label} did not fail with SQLSTATE 42501: {error:?}",
    );
}

async fn assert_subscription_handle_fails_with_insufficient_privilege(
    label: &str,
    handle: crate::fleet::SubscriptionRunHandle<TestTaskError>,
) {
    let result = match tokio::time::timeout(Duration::from_secs(2), handle.wait()).await {
        Ok(result) => result,
        Err(_) => panic!("{label} did not finish after privilege failure"),
    };
    let error = result.expect_err("subscription handle unexpectedly succeeded");
    assert!(
        subscription_handle_error_is_insufficient_privilege(&error),
        "{label} did not fail with SQLSTATE 42501: {error:?}",
    );
}

fn db_error_is_insufficient_privilege(error: &DbError) -> bool {
    match error {
        DbError::Query {
            sql_state: Some(sql_state),
            ..
        } if sql_state.as_str() == "42501" => true,
        DbError::DatabaseOperationRollbackFailed {
            operation_error,
            rollback_error,
            ..
        } => {
            db_error_is_insufficient_privilege(operation_error)
                || db_error_is_insufficient_privilege(rollback_error)
        }
        _ => false,
    }
}

fn error_chain_has_insufficient_privilege(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(db_error) = error.downcast_ref::<DbError>()
            && db_error_is_insufficient_privilege(db_error)
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn kv_error_is_insufficient_privilege(error: &KvError) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        KvError::Database(source) => db_error_is_insufficient_privilege(source),
        KvError::DatabaseOperationRollbackFailed {
            operation_error,
            rollback_error,
            ..
        } => {
            kv_error_is_insufficient_privilege(operation_error)
                || db_error_is_insufficient_privilege(rollback_error)
        }
        KvError::DatabaseOperationRollbackFailedAfterCallerError { rollback_error, .. } => {
            db_error_is_insufficient_privilege(rollback_error)
        }
        _ => false,
    }
}

fn coordination_error_is_insufficient_privilege(error: &CoordinationError) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        CoordinationError::Database(source) => db_error_is_insufficient_privilege(source),
        CoordinationError::DatabaseOperationRollbackFailed {
            operation_error,
            rollback_error,
            ..
        } => {
            coordination_error_is_insufficient_privilege(operation_error)
                || db_error_is_insufficient_privilege(rollback_error)
        }
        _ => false,
    }
}

fn fleet_error_is_insufficient_privilege(error: &FleetError) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        FleetError::Kv(source) => kv_error_is_insufficient_privilege(source),
        FleetError::Coordination(source) => coordination_error_is_insufficient_privilege(source),
        FleetError::Database(source) => db_error_is_insufficient_privilege(source),
        FleetError::DatabaseOperationRollbackFailed {
            operation_error,
            rollback_error,
            ..
        } => {
            fleet_error_is_insufficient_privilege(operation_error)
                || db_error_is_insufficient_privilege(rollback_error)
        }
        FleetError::MutexGuardStopAndReleaseFailed {
            stop_error,
            release_error,
        } => {
            fleet_error_is_insufficient_privilege(stop_error)
                || fleet_error_is_insufficient_privilege(release_error)
        }
        _ => false,
    }
}

fn queue_error_is_insufficient_privilege(error: &QueueError) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        QueueError::Database(source) => db_error_is_insufficient_privilege(source),
        QueueError::Fleet(source) => fleet_error_is_insufficient_privilege(source),
        QueueError::DatabaseOperationRollbackFailed {
            operation_error,
            rollback_error,
            ..
        }
        | QueueError::WorkerDatabaseOperationRollbackFailed {
            operation_error,
            rollback_error,
            ..
        } => {
            queue_error_is_insufficient_privilege(operation_error)
                || db_error_is_insufficient_privilege(rollback_error)
        }
        QueueError::WorkerHeartbeatFailureAndJobFinalizationFailed {
            heartbeat_error,
            finalization_error,
        }
        | QueueError::WorkerJobPersistenceFailureAndRequeueFailed {
            persistence_error: heartbeat_error,
            requeue_error: finalization_error,
        }
        | QueueError::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
            worker_error: heartbeat_error,
            cleanup_error: finalization_error,
        } => {
            queue_error_is_insufficient_privilege(heartbeat_error)
                || queue_error_is_insufficient_privilege(finalization_error)
        }
        QueueError::WorkerRuntimeMultipleFailures { failures } => {
            failures.iter().any(queue_error_is_insufficient_privilege)
        }
        QueueError::MaintenanceCronRunFailed { source, .. } => {
            error_chain_has_insufficient_privilege(source.as_ref())
        }
        _ => false,
    }
}

fn mutex_run_error_is_insufficient_privilege(error: &MutexRunError<TestTaskError>) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        MutexRunError::Fleet(source)
        | MutexRunError::FleetAndLeadershipLost { source }
        | MutexRunError::Release { source } => fleet_error_is_insufficient_privilege(source),
        MutexRunError::FleetAndRelease {
            source,
            release_error,
        } => {
            fleet_error_is_insufficient_privilege(source)
                || fleet_error_is_insufficient_privilege(release_error)
        }
        MutexRunError::LeadershipLostAndRelease { release_error }
        | MutexRunError::TaskAndRelease { release_error, .. } => {
            fleet_error_is_insufficient_privilege(release_error)
        }
        MutexRunError::LeadershipLost
        | MutexRunError::Task { .. }
        | MutexRunError::TaskAndLeadershipLost { .. } => false,
    }
}

fn cron_run_error_is_insufficient_privilege(error: &CronRunError<TestTaskError>) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        CronRunError::Fleet(source)
        | CronRunError::FleetAndLeadershipLost { source }
        | CronRunError::Release { source } => fleet_error_is_insufficient_privilege(source),
        CronRunError::FleetAndRelease {
            source,
            release_error,
        } => {
            fleet_error_is_insufficient_privilege(source)
                || fleet_error_is_insufficient_privilege(release_error)
        }
        CronRunError::LeadershipLostAndRelease { release_error }
        | CronRunError::TaskAndRelease { release_error, .. } => {
            fleet_error_is_insufficient_privilege(release_error)
        }
        CronRunError::LeadershipLost
        | CronRunError::Task { .. }
        | CronRunError::TaskAndLeadershipLost { .. } => false,
    }
}

fn cron_handle_error_is_insufficient_privilege(error: &CronRunHandleError<TestTaskError>) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        CronRunHandleError::Run { source } => cron_run_error_is_insufficient_privilege(source),
        CronRunHandleError::Join { .. } => false,
    }
}

fn once_run_error_is_insufficient_privilege(error: &OnceRunError<TestTaskError>) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        OnceRunError::Fleet(source)
        | OnceRunError::TaskSucceededButCompletionFailed { source }
        | OnceRunError::Release { source } => fleet_error_is_insufficient_privilege(source),
        OnceRunError::TaskAndRelease { release_error, .. } => {
            fleet_error_is_insufficient_privilege(release_error)
        }
        OnceRunError::TaskSucceededButCompletionAndReleaseFailed {
            source,
            release_error,
        } => {
            fleet_error_is_insufficient_privilege(source)
                || fleet_error_is_insufficient_privilege(release_error)
        }
        OnceRunError::Task { .. } => false,
    }
}

fn once_transactional_run_error_is_insufficient_privilege(
    error: &OnceTransactionalRunError<TestTaskError>,
) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        OnceTransactionalRunError::Fleet(source)
        | OnceTransactionalRunError::Release { source } => {
            fleet_error_is_insufficient_privilege(source)
        }
        OnceTransactionalRunError::TaskAndTransactionRollback { rollback_error, .. }
        | OnceTransactionalRunError::TaskAndRelease {
            release_error: rollback_error,
            ..
        } => fleet_error_is_insufficient_privilege(rollback_error),
        OnceTransactionalRunError::TaskTransactionRollbackAndRelease {
            rollback_error,
            release_error,
            ..
        }
        | OnceTransactionalRunError::TransactionAndRelease {
            source: rollback_error,
            release_error,
        } => {
            fleet_error_is_insufficient_privilege(rollback_error)
                || fleet_error_is_insufficient_privilege(release_error)
        }
        OnceTransactionalRunError::Task { .. } => false,
    }
}

fn subscription_run_error_is_insufficient_privilege(
    error: &SubscriptionRunError<TestTaskError>,
) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        SubscriptionRunError::Fleet(source)
        | SubscriptionRunError::PollingGuardRelease { source }
        | SubscriptionRunError::FleetAndPollingGuardLost { source } => {
            fleet_error_is_insufficient_privilege(source)
        }
        SubscriptionRunError::FleetAndPollingGuardRelease {
            source,
            release_error,
        } => {
            fleet_error_is_insufficient_privilege(source)
                || fleet_error_is_insufficient_privilege(release_error)
        }
        SubscriptionRunError::HandlerAndPollingGuardRelease { release_error, .. }
        | SubscriptionRunError::PollingGuardLostAndRelease { release_error } => {
            fleet_error_is_insufficient_privilege(release_error)
        }
        SubscriptionRunError::PollingGuardLost
        | SubscriptionRunError::Handler { .. }
        | SubscriptionRunError::HandlerAndPollingGuardLost { .. } => false,
    }
}

fn subscription_handle_error_is_insufficient_privilege(
    error: &SubscriptionRunHandleError<TestTaskError>,
) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        SubscriptionRunHandleError::Run { source } => {
            subscription_run_error_is_insufficient_privilege(source)
        }
        SubscriptionRunHandleError::Join { .. } => false,
    }
}

fn coalescing_cache_error_is_insufficient_privilege(
    error: &crate::fleet::CoalescingCacheFetchError<TestTaskError>,
) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        crate::fleet::CoalescingCacheFetchError::Fleet(source) => {
            fleet_error_is_insufficient_privilege(source)
        }
        crate::fleet::CoalescingCacheFetchError::ComputeAndRelease { release_error, .. } => {
            fleet_error_is_insufficient_privilege(release_error)
        }
        crate::fleet::CoalescingCacheFetchError::Compute { .. } => false,
    }
}

fn unique_kv_config() -> KvStoreConfig {
    KvStoreConfig::new(unique_test_table_name("__marker_kv")).expect("KV config")
}

fn unique_fleet_config() -> FleetStoreConfig {
    FleetStoreConfig::new_with_explicit_fencing_counter_table(
        RootKey::new(unique_test_identifier_text("marker_fleet_root")).expect("Fleet root key"),
        unique_test_table_name("__marker_fleet_state"),
        unique_test_table_name("__marker_fleet_coordination"),
        unique_test_table_name("__marker_fleet_fencing"),
    )
    .expect("Fleet config")
}

fn unique_queue_config() -> QueueStoreConfig {
    QueueStoreConfig::new(
        unique_test_table_name("__marker_queue_jobs"),
        unique_test_table_name("__marker_queue_dead"),
        unique_test_table_name("__marker_queue_pause"),
    )
    .expect("queue config")
}

async fn drop_marker_tables(
    pool: &PgPool,
    kv_config: &KvStoreConfig,
    fleet_config: &FleetStoreConfig,
    queue_config: &QueueStoreConfig,
) {
    common_drop_test_table(pool, &kv_config.table_name).await;
    common_drop_test_table(pool, &fleet_config.state_table_name).await;
    common_drop_test_table(pool, &fleet_config.coordination_table_name).await;
    common_drop_test_table(pool, &fleet_config.fencing_counter_table_name).await;
    common_drop_test_table(pool, &queue_config.table_name).await;
    common_drop_test_table(pool, &queue_config.dead_letter_table_name).await;
    common_drop_test_table(pool, &queue_config.pause_table_name).await;
}

fn unique_test_table_name(prefix: &str) -> PgQualifiedTableName {
    PgQualifiedTableName::unqualified(unique_test_identifier_text(prefix)).expect("table name")
}

fn unique_test_identifier_text(prefix: &str) -> String {
    let id = UniqueTestId::new()
        .expect("new unique test id")
        .to_text()
        .replace('-', "_");
    format!("{prefix}_{id}")
}

fn read_only_test_role_name() -> PgIdentifier {
    PgIdentifier::new(common_read_only_test_role_name()).expect("read-only test role name")
}

async fn connect_write_pool(database_url: &str, application_name: &str) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = 5;
    config.application_name = Some(application_name.to_owned());
    WritePool::connect(config).await.expect("connect WritePool")
}

async fn grant_schema_read_access_to_login_role(pool: &PgPool, role_name: &PgIdentifier) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA public TO {}",
        role_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("grant public schema usage");

    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}",
        role_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("grant schema read access");
}

async fn revoke_schema_read_access_from_login_role(pool: &PgPool, role_name: &PgIdentifier) {
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {}",
        role_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("revoke schema table privileges");
    unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        "REVOKE ALL PRIVILEGES ON SCHEMA public FROM {}",
        role_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("revoke public schema privileges");
}
