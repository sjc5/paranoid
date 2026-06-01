mod common;

use common::{
    connect_sqlx_pool_for_harness, direct_test_database_url as common_direct_test_database_url,
    drop_test_table as common_drop_test_table, fetch_table_exists, standard_test_database_url,
};
use paranoid::db::{
    Error as DbError, PgIdentifier, PgQualifiedTableName, PgSqlState, Pool, PoolConfig, WritePool,
};
use paranoid::fleet::manual::{
    CircuitBreakerManualPermitAcquireResult, RateLimiterManualPermitAcquireResult,
    ThrottlerManualPermitAcquireResult,
};
use paranoid::fleet::{
    CircuitBreakerConfig, CircuitBreakerGuardAcquireResult, CircuitBreakerGuardedTaskResult,
    CircuitBreakerKey, CircuitBreakerTryRunTaskResult, ClaimDuration, CoalescingCacheConfig,
    CoalescingCacheFetchError, CoalescingCacheKey, CoordinationError, CounterKey, CronConfig,
    CronKey, CronRunError, CronRunHandleError, CronTaskErrorAction, CronTryRunOnceResult,
    DEFAULT_SUBSCRIPTION_POLL_LIMIT, DEFAULT_THROTTLER_PROBE_WINDOW, Error, HolderId,
    MAX_CONCURRENT_LIMIT, MAX_SUBSCRIPTION_POLL_LIMIT, MIN_CRON_INTERVAL,
    MIN_MUTEX_HEARTBEAT_INTERVAL, MutexGuardConfig, MutexGuardSnapshot, MutexKey, MutexRunError,
    MutexTryRunTaskResult, OnceKey, OnceRunClaimSnapshot, OnceRunError, OnceRunTaskResult,
    OnceTransactionalRunError, OnceTryRunTaskResult, RateLimitConfig, RateLimiterGuardedTaskResult,
    RateLimiterKey, RateLimiterTryRunTaskResult, RootKey, SemaphoreClaim,
    SemaphoreGuardedTaskResult, SemaphoreKey, SemaphoreTryRunTaskResult, Store, StoreConfig,
    SubscriptionConfig, SubscriptionKey, SubscriptionPollErrorAction, SubscriptionRunError,
    SubscriptionRunHandleError, ThrottlerCircuitBreaker, ThrottlerCircuitState,
    ThrottlerConcurrencyLimit, ThrottlerConfig, ThrottlerGuardAcquireResult,
    ThrottlerGuardedTaskResult, ThrottlerKey, ThrottlerRateLimit, ThrottlerTryRunTaskResult,
    TopicConfig, TopicEvent, TopicKey,
};
use paranoid::id::SortableId as UniqueTestId;
use paranoid::kv::{
    Error as KvError, Item as RawKvItem, Key as RawKvKey, KeyPrefix as RawKvKeyPrefix,
    Store as RawKvStore, StoreConfig as KvStoreConfig, Ttl as KvTtl,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::ConnectOptions;
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;
use std::future::Future;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Barrier;

const CRON_STORAGE_COMPONENT_KEY: &str = "cron";
const CACHE_STORAGE_COMPONENT_KEY: &str = "cache";
const CACHE_VALUE_STORAGE_KEY_PART: &str = "value";
const CACHE_EPOCH_STORAGE_KEY_PART: &str = "epoch";
const MUTEX_STORAGE_COMPONENT_KEY: &str = "mutex";
const TOPIC_STORAGE_COMPONENT_KEY: &str = "topic";
const TOPIC_SEQUENCE_STORAGE_KEY_PART: &str = "sequence";
const TOPIC_EVENTS_STORAGE_KEY_PART: &str = "events";
const TOPIC_SUBSCRIPTIONS_STORAGE_KEY_PART: &str = "subscriptions";
const TOPIC_CURSOR_STORAGE_KEY_PART: &str = "cursor";
const TOPIC_POLLING_MUTEX_STORAGE_KEY_PART: &str = "polling_mutex";
const SEMAPHORE_STORAGE_COMPONENT_KEY: &str = "semaphore";
const SEMAPHORE_SLOTS_STORAGE_KEY_PART: &str = "slots";
const THROTTLER_STORAGE_COMPONENT_KEY: &str = "throttler";
const THROTTLER_STATE_STORAGE_KEY_PART: &str = "state";

#[path = "db_fleet_postgres/api_surface.rs"]
mod api_surface;
#[path = "db_fleet_postgres/cache.rs"]
mod cache;
#[path = "db_fleet_postgres/counter.rs"]
mod counter;
#[path = "db_fleet_postgres/cron.rs"]
mod cron;
#[path = "db_fleet_postgres/cron_run_once_errors.rs"]
mod cron_run_once_errors;
#[path = "db_fleet_postgres/cron_support.rs"]
mod cron_support;
#[path = "db_fleet_postgres/mutex.rs"]
mod mutex;
#[path = "db_fleet_postgres/once.rs"]
mod once;
#[path = "db_fleet_postgres/rate_limiter_and_circuit_breaker.rs"]
mod rate_limiter_and_circuit_breaker;
#[path = "db_fleet_postgres/schema_and_keys.rs"]
mod schema_and_keys;
#[path = "db_fleet_postgres/schema_migration.rs"]
mod schema_migration;
#[path = "db_fleet_postgres/semaphore.rs"]
mod semaphore;
#[path = "db_fleet_postgres/subscription_loop.rs"]
mod subscription_loop;
#[path = "db_fleet_postgres/throttler_core.rs"]
mod throttler_core;
#[path = "db_fleet_postgres/topic.rs"]
mod topic;
#[path = "db_fleet_postgres/topic_transactions_and_concurrency.rs"]
mod topic_transactions_and_concurrency;

fn fast_mutex_guard_config() -> MutexGuardConfig {
    MutexGuardConfig {
        heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
        acquire_retry_interval: Some(Duration::from_millis(25)),
        max_acquire_retry_interval: Some(Duration::from_millis(50)),
        max_consecutive_renewal_failures: Some(1),
    }
}

fn fast_cron_config(key: &str) -> CronConfig {
    CronConfig {
        key: CronKey::new(key).expect("cron key"),
        interval: MIN_CRON_INTERVAL,
        claim_duration: Some(ClaimDuration::expires_after(Duration::from_secs(1)).expect("lease")),
        heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
        acquire_retry_interval: Some(Duration::from_millis(25)),
        max_consecutive_renewal_failures: Some(1),
    }
}

async fn first_cron_leader_absent(pool: &Pool, store: &Store, key: &str) -> bool {
    store
        .new_cron(fast_cron_config(key))
        .expect("new cron")
        .fetch_live_leader(pool)
        .await
        .expect("fetch live cron leader")
        .is_none()
}

async fn migrate_schema(pool: &WritePool, config: &StoreConfig) -> Result<(), DbError> {
    Store::new(config.clone())
        .expect("fleet store")
        .migrate_schema(pool)
        .await
}

async fn validate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), DbError> {
    Store::new(config.clone())
        .expect("fleet store")
        .validate_schema(pool)
        .await
}

async fn wait_until<F, Fut>(description: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let started_at = Instant::now();
    loop {
        if check().await {
            return;
        }
        assert!(
            started_at.elapsed() < timeout,
            "timed out waiting until {description}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn is_subscription_statement_timeout_error(error: &Error) -> bool {
    let database_error = match error {
        Error::Database(source)
        | Error::Kv(KvError::Database(source))
        | Error::Coordination(CoordinationError::Database(source)) => source,
        _ => return false,
    };
    matches!(
        database_error,
        DbError::Query {
            sql_state: Some(PgSqlState::Other(code)),
            ..
        } if code == "57014"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestComputeError(&'static str);

impl std::fmt::Display for TestComputeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TestComputeError {}

struct RunningCounterGuard {
    currently_running: Arc<AtomicUsize>,
}

impl RunningCounterGuard {
    fn increment(
        currently_running: Arc<AtomicUsize>,
        max_concurrent_seen: Arc<AtomicUsize>,
    ) -> Self {
        let running = currently_running.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = max_concurrent_seen.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            Some(current.max(running))
        });
        Self { currently_running }
    }
}

impl Drop for RunningCounterGuard {
    fn drop(&mut self) {
        self.currently_running.fetch_sub(1, Ordering::SeqCst);
    }
}

struct TestDatabase {
    paranoid_pool: WritePool,
    sqlx_pool: PgPool,
    config: StoreConfig,
}

impl TestDatabase {
    async fn connect() -> Self {
        let database_url = test_database_url();
        let paranoid_pool = connect_paranoid_pool(&database_url).await;
        let sqlx_pool = connect_sqlx_pool(&database_url).await;
        let config = StoreConfig::new(
            RootKey::default(),
            unique_test_table_name(),
            unique_test_table_name(),
        )
        .expect("fleet config");

        Self {
            paranoid_pool,
            sqlx_pool,
            config,
        }
    }
}

fn test_database_url() -> String {
    standard_test_database_url()
}

fn direct_test_database_url() -> String {
    common_direct_test_database_url()
}

async fn connect_paranoid_pool(database_url: &str) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = 2;
    config.application_name = Some("paranoid_db_fleet_postgres_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

async fn connect_paranoid_pool_with_statement_timeout(
    database_url: &str,
    statement_timeout: &str,
) -> WritePool {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let connect_url =
        format!("{database_url}{separator}options[statement_timeout]={statement_timeout}");
    connect_paranoid_pool(&connect_url).await
}

async fn connect_paranoid_pool_as_login_role(
    database_url: &str,
    role_name: &PgIdentifier,
    role_password: &str,
) -> WritePool {
    let connect_url = PgConnectOptions::from_str(database_url)
        .expect("parse test database URL")
        .username(role_name.as_str())
        .password(role_password)
        .statement_cache_capacity(0)
        .to_url_lossy()
        .to_string();
    connect_paranoid_pool(&connect_url).await
}

async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 2, "paranoid_db_fleet_postgres_test").await
}

fn unique_test_table_name() -> PgQualifiedTableName {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgQualifiedTableName::unqualified(format!("__fleet_rs_{id}")).expect("test table name")
}

fn unique_test_identifier(prefix: &str) -> PgIdentifier {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgIdentifier::new(format!("{prefix}_{id}")).expect("test identifier")
}

fn unix_microseconds_now() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after Unix epoch");
    i64::try_from(elapsed.as_micros()).expect("current timestamp fits i64")
}

async fn drop_fleet_test_tables(pool: &PgPool, config: &StoreConfig) {
    drop_test_table(pool, &config.state_table_name).await;
    drop_test_table(pool, &config.coordination_table_name).await;
    drop_test_table(pool, &config.fencing_counter_table_name).await;
}

async fn delete_live_cron_lease_row(pool: &PgPool, config: &StoreConfig, cron_key: &str) {
    let persisted_lease_key = format!(
        "{}::{}::{}::",
        config.root_key.as_str(),
        CRON_STORAGE_COMPONENT_KEY,
        cron_key
    );
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM {} WHERE key = $1",
        config.coordination_table_name.quoted()
    )))
    .bind(persisted_lease_key)
    .execute(pool)
    .await
    .expect("delete live cron lease row");
}

fn persisted_mutex_lease_key(config: &StoreConfig, mutex_key: &MutexKey) -> String {
    format!(
        "{}::{}::{}::",
        config.root_key.as_str(),
        MUTEX_STORAGE_COMPONENT_KEY,
        mutex_key.as_str()
    )
}

fn persisted_coalescing_cache_value_key(
    config: &StoreConfig,
    cache_key: &CoalescingCacheKey,
    key_parts: impl IntoIterator<Item = impl AsRef<str>>,
) -> RawKvKey {
    let mut parts = vec![
        config.root_key.as_str().to_owned(),
        CACHE_STORAGE_COMPONENT_KEY.to_owned(),
        cache_key.as_str().to_owned(),
        CACHE_VALUE_STORAGE_KEY_PART.to_owned(),
    ];
    parts.extend(key_parts.into_iter().map(|part| part.as_ref().to_owned()));
    RawKvKey::from_parts(parts).expect("coalescing cache value key")
}

fn persisted_coalescing_cache_epoch_key(
    config: &StoreConfig,
    cache_key: &CoalescingCacheKey,
) -> RawKvKey {
    RawKvKey::from_parts([
        config.root_key.as_str(),
        CACHE_STORAGE_COMPONENT_KEY,
        cache_key.as_str(),
        CACHE_EPOCH_STORAGE_KEY_PART,
    ])
    .expect("coalescing cache epoch key")
}

fn persisted_topic_sequence_key(config: &StoreConfig, topic_key: &TopicKey) -> RawKvKey {
    RawKvKey::from_parts([
        config.root_key.as_str(),
        TOPIC_STORAGE_COMPONENT_KEY,
        topic_key.as_str(),
        TOPIC_SEQUENCE_STORAGE_KEY_PART,
    ])
    .expect("topic sequence key")
}

fn persisted_throttler_state_key(config: &StoreConfig, throttler_key: &ThrottlerKey) -> RawKvKey {
    RawKvKey::from_parts([
        config.root_key.as_str(),
        THROTTLER_STORAGE_COMPONENT_KEY,
        throttler_key.as_str(),
        THROTTLER_STATE_STORAGE_KEY_PART,
    ])
    .expect("throttler state key")
}

fn persisted_semaphore_slot_key(
    config: &StoreConfig,
    semaphore_key: &SemaphoreKey,
    slot_suffix: &str,
) -> RawKvKey {
    RawKvKey::from_parts([
        config.root_key.as_str(),
        SEMAPHORE_STORAGE_COMPONENT_KEY,
        SEMAPHORE_SLOTS_STORAGE_KEY_PART,
        semaphore_key.as_str(),
        slot_suffix,
    ])
    .expect("semaphore slot key")
}

fn persisted_topic_event_key(
    config: &StoreConfig,
    topic_key: &TopicKey,
    sequence: i64,
) -> RawKvKey {
    RawKvKey::from_parts([
        config.root_key.as_str(),
        TOPIC_STORAGE_COMPONENT_KEY,
        topic_key.as_str(),
        TOPIC_EVENTS_STORAGE_KEY_PART,
        format!("{sequence:020}").as_str(),
    ])
    .expect("topic event key")
}

fn subscription_cursor_key_prefix(
    config: &StoreConfig,
    topic_key: &TopicKey,
    subscription_key: &SubscriptionKey,
) -> RawKvKeyPrefix {
    RawKvKeyPrefix::from_parts([
        config.root_key.as_str(),
        TOPIC_STORAGE_COMPONENT_KEY,
        topic_key.as_str(),
        TOPIC_SUBSCRIPTIONS_STORAGE_KEY_PART,
        subscription_key.as_str(),
        TOPIC_CURSOR_STORAGE_KEY_PART,
    ])
    .expect("subscription cursor key prefix")
}

fn persisted_subscription_cursor_key(
    config: &StoreConfig,
    topic_key: &TopicKey,
    subscription_key: &SubscriptionKey,
) -> RawKvKey {
    RawKvKey::from_prefix_and_parts(
        &subscription_cursor_key_prefix(config, topic_key, subscription_key),
        std::iter::empty::<&str>(),
    )
    .expect("subscription cursor key")
}

fn persisted_subscription_polling_mutex_lease_key(
    config: &StoreConfig,
    topic_key: &TopicKey,
    subscription_key: &SubscriptionKey,
) -> String {
    format!(
        "{}::{}::{}::{}::{}::{}::",
        config.root_key.as_str(),
        TOPIC_STORAGE_COMPONENT_KEY,
        topic_key.as_str(),
        TOPIC_SUBSCRIPTIONS_STORAGE_KEY_PART,
        subscription_key.as_str(),
        TOPIC_POLLING_MUTEX_STORAGE_KEY_PART
    )
}

async fn insert_live_subscription_polling_mutex_lease_row(
    pool: &PgPool,
    config: &StoreConfig,
    topic_key: &TopicKey,
    subscription_key: &SubscriptionKey,
) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {} \
         (key, holder_id, fencing_token, lease_token, expires_at, updated_at) \
         VALUES ($1, 'test-holder', 1, $2, \
                 statement_timestamp() + INTERVAL '60 seconds', statement_timestamp()) \
         ON CONFLICT (key) DO UPDATE SET \
             holder_id = EXCLUDED.holder_id, \
             fencing_token = EXCLUDED.fencing_token, \
             lease_token = EXCLUDED.lease_token, \
             expires_at = EXCLUDED.expires_at, \
             updated_at = EXCLUDED.updated_at",
        config.coordination_table_name.quoted()
    )))
    .bind(persisted_subscription_polling_mutex_lease_key(
        config,
        topic_key,
        subscription_key,
    ))
    .bind(vec![1_u8; 32])
    .execute(pool)
    .await
    .expect("insert live subscription polling mutex lease row");
}

async fn set_subscription_cursor_directly(
    pool: &WritePool,
    config: &StoreConfig,
    topic_key: &TopicKey,
    subscription_key: &SubscriptionKey,
    cursor: i64,
) {
    RawKvItem::<i64>::new_plain(
        RawKvStore::new(KvStoreConfig::new(config.state_table_name.clone()).expect("kv config"))
            .expect("kv store"),
        subscription_cursor_key_prefix(config, topic_key, subscription_key),
    )
    .set(
        pool,
        std::iter::empty::<&str>(),
        &cursor,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set subscription cursor directly");
}

async fn delete_live_mutex_lease_row(pool: &PgPool, config: &StoreConfig, mutex_key: &MutexKey) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM {} WHERE key = $1",
        config.coordination_table_name.quoted()
    )))
    .bind(persisted_mutex_lease_key(config, mutex_key))
    .execute(pool)
    .await
    .expect("delete live mutex claim row");
}

async fn begin_transaction_locking_live_mutex_lease_row<'a>(
    pool: &'a PgPool,
    config: &StoreConfig,
    mutex_key: &MutexKey,
) -> sqlx::Transaction<'a, sqlx::Postgres> {
    begin_transaction_locking_coordination_row(
        pool,
        config,
        &persisted_mutex_lease_key(config, mutex_key),
    )
    .await
}

async fn begin_transaction_locking_coordination_row<'a>(
    pool: &'a PgPool,
    config: &StoreConfig,
    coordination_key: &str,
) -> sqlx::Transaction<'a, sqlx::Postgres> {
    let mut tx = sqlx::Acquire::begin(pool)
        .await
        .expect("begin coordination row lock transaction");
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT key FROM {} WHERE key = $1 FOR UPDATE",
        config.coordination_table_name.quoted()
    )))
    .bind(coordination_key)
    .fetch_all(&mut *tx)
    .await
    .expect("lock live coordination row");
    assert_eq!(rows.len(), 1, "expected one live coordination row to lock");
    tx
}

async fn begin_transaction_locking_raw_kv_row<'a>(
    pool: &'a PgPool,
    table_name: &PgQualifiedTableName,
    key: &RawKvKey,
) -> sqlx::Transaction<'a, sqlx::Postgres> {
    let mut tx = sqlx::Acquire::begin(pool)
        .await
        .expect("begin raw kv row lock transaction");
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT key FROM {} WHERE key = $1 FOR UPDATE",
        table_name.quoted()
    )))
    .bind(key.as_str())
    .fetch_all(&mut *tx)
    .await
    .expect("lock raw kv row");
    assert_eq!(rows.len(), 1, "expected one raw kv row to lock");
    tx
}

async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    common_drop_test_table(pool, table_name).await;
}

async fn install_delete_failure_trigger_on_table(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> PgIdentifier {
    let function_name = unique_test_identifier("__fleet_rs_fail_delete");
    let trigger_name = unique_test_identifier("__fleet_rs_fail_delete_trg");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE FUNCTION {}() RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'forced delete failure for test';
            RETURN OLD;
        END;
        $$;
        "#,
        function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create delete failure trigger function");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER {} BEFORE DELETE ON {} FOR EACH ROW EXECUTE FUNCTION {}()",
        trigger_name.quoted(),
        table_name.quoted(),
        function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create delete failure trigger");

    function_name
}

async fn drop_test_function_cascade(pool: &PgPool, function_name: &PgIdentifier) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP FUNCTION IF EXISTS {}() CASCADE",
        function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test function");
}

fn postgres_single_quoted_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

async fn create_non_bypass_login_role_for_test(pool: &PgPool) -> (PgIdentifier, String) {
    let role_name = unique_test_identifier("__fleet_rs_rls_user");
    let role_password: String = UniqueTestId::new().expect("new role password id").to_text();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {} LOGIN PASSWORD {}",
        role_name.quoted(),
        postgres_single_quoted_literal(&role_password)
    )))
    .execute(pool)
    .await
    .expect("create non-bypass login role");
    (role_name, role_password)
}

async fn grant_fleet_test_tables_to_login_role(
    pool: &PgPool,
    config: &StoreConfig,
    role_name: &PgIdentifier,
) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA public TO {}",
        role_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("grant public schema usage to test role");

    for table_name in [
        &config.state_table_name,
        &config.coordination_table_name,
        &config.fencing_counter_table_name,
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {} TO {}",
            table_name.quoted(),
            role_name.quoted()
        )))
        .execute(pool)
        .await
        .expect("grant Fleet test table access to test role");
    }
}

async fn install_write_failure_trigger_on_kv_key(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &RawKvKey,
) -> PgIdentifier {
    let function_name = unique_test_identifier("__fleet_rs_fail_write");
    let trigger_name = unique_test_identifier("__fleet_rs_fail_write_trg");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE FUNCTION {}() RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.key = TG_ARGV[0] THEN
                RAISE EXCEPTION 'forced write failure for test';
            END IF;
            RETURN NEW;
        END;
        $$;
        "#,
        function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create write failure trigger function");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER {} BEFORE INSERT OR UPDATE ON {} FOR EACH ROW EXECUTE FUNCTION {}({})",
        trigger_name.quoted(),
        table_name.quoted(),
        function_name.quoted(),
        postgres_single_quoted_literal(key.as_str())
    )))
    .execute(pool)
    .await
    .expect("create write failure trigger");

    function_name
}

struct OneShotFailureTrigger {
    function_name: PgIdentifier,
    sequence_name: PgIdentifier,
}

async fn install_one_shot_update_failure_trigger_on_table(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
) -> OneShotFailureTrigger {
    let function_name = unique_test_identifier("__fleet_rs_fail_once_update");
    let sequence_name = unique_test_identifier("__fleet_rs_fail_once_update_seq");
    let trigger_name = unique_test_identifier("__fleet_rs_fail_once_update_trg");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE SEQUENCE {}",
        sequence_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create one-shot update failure sequence");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE FUNCTION {}() RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF nextval({}::regclass) = 1 THEN
                RAISE EXCEPTION 'forced one-shot update failure for test';
            END IF;
            RETURN NEW;
        END;
        $$;
        "#,
        function_name.quoted(),
        postgres_single_quoted_literal(&sequence_name.quoted().to_string())
    )))
    .execute(pool)
    .await
    .expect("create one-shot update failure trigger function");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER {} BEFORE UPDATE ON {} FOR EACH ROW EXECUTE FUNCTION {}()",
        trigger_name.quoted(),
        table_name.quoted(),
        function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create one-shot update failure trigger");

    OneShotFailureTrigger {
        function_name,
        sequence_name,
    }
}

async fn drop_one_shot_failure_trigger(pool: &PgPool, trigger: &OneShotFailureTrigger) {
    drop_test_function_cascade(pool, &trigger.function_name).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SEQUENCE IF EXISTS {}",
        trigger.sequence_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop one-shot failure trigger sequence");
}

struct KeyReadCounterPolicy {
    function_name: PgIdentifier,
    sequence_name: PgIdentifier,
}

async fn install_key_read_counter_policy_on_kv_table(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    key: &RawKvKey,
) -> KeyReadCounterPolicy {
    let function_name = unique_test_identifier("__fleet_rs_count_key_read");
    let sequence_name = unique_test_identifier("__fleet_rs_count_key_read_seq");
    let policy_name = unique_test_identifier("__fleet_rs_count_key_read_pol");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE SEQUENCE {}",
        sequence_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create key read counter sequence");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        r#"
        CREATE FUNCTION {}(observed_key text) RETURNS boolean
        LANGUAGE plpgsql
        SECURITY DEFINER
        AS $$
        BEGIN
            IF observed_key = {} THEN
                PERFORM nextval({}::regclass);
            END IF;
            RETURN true;
        END;
        $$;
        "#,
        function_name.quoted(),
        postgres_single_quoted_literal(key.as_str()),
        postgres_single_quoted_literal(&sequence_name.quoted().to_string())
    )))
    .execute(pool)
    .await
    .expect("create key read counter policy function");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE {} ENABLE ROW LEVEL SECURITY",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("enable row level security for key read counter");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE {} FORCE ROW LEVEL SECURITY",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("force row level security for key read counter");

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE POLICY {} ON {} FOR ALL USING ({}(key)) WITH CHECK ({}(key))",
        policy_name.quoted(),
        table_name.quoted(),
        function_name.quoted(),
        function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create key read counter policy");

    KeyReadCounterPolicy {
        function_name,
        sequence_name,
    }
}

async fn fetch_key_read_counter_policy_count(pool: &PgPool, policy: &KeyReadCounterPolicy) -> i64 {
    let (last_value, is_called): (i64, bool) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT last_value, is_called FROM {}",
        policy.sequence_name.quoted()
    )))
    .fetch_one(pool)
    .await
    .expect("fetch key read counter policy sequence");
    if !is_called {
        return 0;
    }
    last_value
}

async fn drop_key_read_counter_policy(pool: &PgPool, policy: &KeyReadCounterPolicy) {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP FUNCTION IF EXISTS {}(text) CASCADE",
        policy.function_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop key read counter policy function");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SEQUENCE IF EXISTS {}",
        policy.sequence_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop key read counter policy sequence");
}
