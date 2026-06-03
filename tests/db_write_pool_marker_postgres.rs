mod common;

use common::{
    connect_sqlx_pool_for_harness, drop_test_table as common_drop_test_table,
    read_only_test_database_url as common_read_only_test_database_url,
    read_only_test_role_name as common_read_only_test_role_name, standard_test_database_url,
};
use paranoid::db::{
    Error as DbError, PgIdentifier, PgQualifiedTableName, PoolConfig, WritePool,
    unparameterized_simple_query,
};
use paranoid::fleet::{
    CircuitBreakerConfig, CircuitBreakerKey, ClaimDuration, CoalescingCacheConfig,
    CoalescingCacheKey, CoordinationError, CounterKey, CronConfig, CronKey, CronRunError,
    CronRunHandleError, CronTaskErrorAction, Error as FleetError, HolderId, MIN_CRON_INTERVAL,
    MIN_MUTEX_HEARTBEAT_INTERVAL, MutexGuardConfig, MutexKey, MutexRunError, OnceKey, OnceRunError,
    OnceTransactionalRunError, RateLimitConfig, RateLimiterKey, RootKey, SemaphoreKey,
    Store as FleetStore, StoreConfig as FleetStoreConfig, SubscriptionConfig, SubscriptionKey,
    SubscriptionRunError, SubscriptionRunHandleError, ThrottlerCircuitBreaker,
    ThrottlerConcurrencyLimit, ThrottlerConfig, ThrottlerKey, ThrottlerRateLimit, TopicConfig,
    TopicKey,
};
use paranoid::id::SortableId as UniqueTestId;
use paranoid::kv::{
    AtomicMutation as KvAtomicMutation, BytesSetEntry as KvBytesSetEntry, Error as KvError,
    Item as KvItem, ItemAtomicMutation as KvItemAtomicMutation, Key as KvKey,
    KeyPrefix as KvKeyPrefix, Store as KvStore, StoreConfig as KvStoreConfig, Ttl as KvTtl,
};
use paranoid::queue::{
    DeadLetterReason, EnqueueBatchOptions, EnqueueOptions, Error as QueueError, JobId,
    ListDeadLetterJobsOptions, ListJobsOptions, Store as QueueStore,
    StoreConfig as QueueStoreConfig, TaskRegistry, WorkerConfig, WorkerMaintenanceConfig,
    WorkerOwnerId,
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

    exercise_kv_public_db_handle_surface(&read_only_backed_write_pool, &kv_store).await;
    exercise_fleet_public_db_handle_surface(&read_only_backed_write_pool, &fleet_store).await;
    exercise_queue_public_db_handle_surface(
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

async fn exercise_kv_public_db_handle_surface(pool: &WritePool, store: &KvStore) {
    let read_pool: &paranoid::db::Pool = pool;
    let key = KvKey::from_parts(["marker", "seed"]).expect("KV key");
    let missing_key = KvKey::from_parts(["marker", "missing"]).expect("missing KV key");
    let multi_key = KvKey::from_parts(["marker", "multi"]).expect("multi KV key");
    let prefix = KvKeyPrefix::from_parts(["marker"]).expect("KV prefix");
    let ttl = KvTtl::no_expiration();
    let expiring_ttl = KvTtl::expires_after(Duration::from_secs(30)).expect("expiring TTL");
    let item_prefix = KvKeyPrefix::from_parts(["typed"]).expect("typed item prefix");
    let item = KvItem::<TestPayload>::new_plain(store.clone(), item_prefix);

    store
        .validate_schema(read_pool)
        .await
        .expect("KV validate_schema should only require SELECT");
    store
        .get_bytes(read_pool, &key)
        .await
        .expect("KV get_bytes should only require SELECT");
    store
        .get_bytes_and_return_database_timestamp(read_pool, &key)
        .await
        .expect("KV timestamped get should only require SELECT");
    store
        .get_bytes_multi(read_pool, &[key.clone(), missing_key.clone()])
        .await
        .expect("KV multi-get should only require SELECT");
    store
        .check_key_exists(read_pool, &key)
        .await
        .expect("KV exists should only require SELECT");
    store
        .count_live_keys_with_prefix(read_pool, &prefix)
        .await
        .expect("KV count should only require SELECT");
    store
        .scan_bytes_with_prefix(read_pool, &prefix, None, 10)
        .await
        .expect("KV byte scan should only require SELECT");
    store
        .scan_keys_with_prefix(read_pool, &prefix, None, 10)
        .await
        .expect("KV key scan should only require SELECT");

    let mut read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin KV read tx");
    store
        .validate_schema_in_current_transaction(&mut read_tx)
        .await
        .expect("KV tx schema validation should only require SELECT");
    store
        .get_bytes_in_current_transaction(&mut read_tx, &key)
        .await
        .expect("KV tx get should only require SELECT");
    store
        .get_bytes_and_return_database_timestamp_in_current_transaction(&mut read_tx, &key)
        .await
        .expect("KV tx timestamped get should only require SELECT");
    store
        .get_bytes_multi_in_current_transaction(&mut read_tx, &[key.clone(), missing_key.clone()])
        .await
        .expect("KV tx multi-get should only require SELECT");
    store
        .check_key_exists_in_current_transaction(&mut read_tx, &key)
        .await
        .expect("KV tx exists should only require SELECT");
    store
        .count_live_keys_with_prefix_in_current_transaction(&mut read_tx, &prefix)
        .await
        .expect("KV tx count should only require SELECT");
    store
        .scan_bytes_with_prefix_in_current_transaction(&mut read_tx, &prefix, None, 10)
        .await
        .expect("KV tx byte scan should only require SELECT");
    store
        .scan_keys_with_prefix_in_current_transaction(&mut read_tx, &prefix, None, 10)
        .await
        .expect("KV tx key scan should only require SELECT");
    read_tx.rollback().await.expect("rollback KV read tx");

    item.get(read_pool, ["seed"])
        .await
        .expect("KV item get should only require SELECT");
    item.get_and_return_database_timestamp(read_pool, ["seed"])
        .await
        .expect("KV item timestamped get should only require SELECT");
    item.get_or_fallback(read_pool, ["missing"], TestPayload { value: -1 })
        .await
        .expect("KV item fallback get should only require SELECT");
    item.get_multi(read_pool, &[["seed"], ["missing"]])
        .await
        .expect("KV item multi-get should only require SELECT");
    item.check_exists(read_pool, ["seed"])
        .await
        .expect("KV item exists should only require SELECT");
    item.count(read_pool)
        .await
        .expect("KV item count should only require SELECT");
    item.scan(read_pool, None, 10)
        .await
        .expect("KV item scan should only require SELECT");
    item.scan_key_suffixes(read_pool, None, 10)
        .await
        .expect("KV item key scan should only require SELECT");

    let mut item_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin KV item read tx");
    item.get_in_current_transaction(&mut item_read_tx, ["seed"])
        .await
        .expect("KV item tx get should only require SELECT");
    item.get_and_return_database_timestamp_in_current_transaction(&mut item_read_tx, ["seed"])
        .await
        .expect("KV item tx timestamped get should only require SELECT");
    item.get_multi_in_current_transaction(&mut item_read_tx, &[["seed"], ["missing"]])
        .await
        .expect("KV item tx multi-get should only require SELECT");
    item.check_exists_in_current_transaction(&mut item_read_tx, ["seed"])
        .await
        .expect("KV item tx exists should only require SELECT");
    item.count_in_current_transaction(&mut item_read_tx)
        .await
        .expect("KV item tx count should only require SELECT");
    item.scan_in_current_transaction(&mut item_read_tx, None, 10)
        .await
        .expect("KV item tx scan should only require SELECT");
    item.scan_key_suffixes_in_current_transaction(&mut item_read_tx, None, 10)
        .await
        .expect("KV item tx key scan should only require SELECT");
    item_read_tx
        .rollback()
        .await
        .expect("rollback KV item read tx");

    assert_fails_with_insufficient_privilege!(
        "KV migrate_schema",
        store.migrate_schema(pool),
        db_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV migrate_schema_in_current_transaction",
        tx,
        store.migrate_schema_in_current_transaction(tx),
        db_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV set_bytes",
        store.set_bytes(pool, &missing_key, b"value", ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV set_bytes_in_current_transaction",
        tx,
        store.set_bytes_in_current_transaction(tx, &missing_key, b"value", ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV set_bytes_and_return_database_timestamp",
        store.set_bytes_and_return_database_timestamp(pool, &missing_key, b"value", ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV set_bytes_and_return_database_timestamp_in_current_transaction",
        tx,
        store.set_bytes_and_return_database_timestamp_in_current_transaction(
            tx,
            &missing_key,
            b"value",
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV set_bytes_if_not_exists",
        store.set_bytes_if_not_exists(pool, &missing_key, b"value", ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV set_bytes_if_not_exists_in_current_transaction",
        tx,
        store.set_bytes_if_not_exists_in_current_transaction(tx, &missing_key, b"value", ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV set_bytes_if_not_exists_and_return_database_timestamp",
        store.set_bytes_if_not_exists_and_return_database_timestamp(
            pool,
            &missing_key,
            b"value",
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV set_bytes_if_not_exists_and_return_database_timestamp_in_current_transaction",
        tx,
        store.set_bytes_if_not_exists_and_return_database_timestamp_in_current_transaction(
            tx,
            &missing_key,
            b"value",
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV set_bytes_multi",
        store.set_bytes_multi(
            pool,
            &[KvBytesSetEntry::new(multi_key.clone(), b"value".as_slice())],
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV set_bytes_multi_in_current_transaction",
        tx,
        store.set_bytes_multi_in_current_transaction(
            tx,
            &[KvBytesSetEntry::new(multi_key.clone(), b"value".as_slice())],
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV touch_key",
        store.touch_key(pool, &key),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV touch_key_in_current_transaction",
        tx,
        store.touch_key_in_current_transaction(tx, &key),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV set_key_ttl",
        store.set_key_ttl(pool, &key, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV set_key_ttl_in_current_transaction",
        tx,
        store.set_key_ttl_in_current_transaction(tx, &key, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV expire_key",
        store.expire_key(pool, &key),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV expire_key_in_current_transaction",
        tx,
        store.expire_key_in_current_transaction(tx, &key),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV delete_key",
        store.delete_key(pool, &key),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV delete_key_in_current_transaction",
        tx,
        store.delete_key_in_current_transaction(tx, &key),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV delete_expired_keys_once",
        store.delete_expired_keys_once(pool, 1),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV delete_expired_keys_once_in_current_transaction",
        tx,
        store.delete_expired_keys_once_in_current_transaction(tx, 1),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV delete_expired_keys_until_empty",
        store.delete_expired_keys_until_empty(pool, 1),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV delete_expired_keys_until_empty_with_delay_between_batches",
        store.delete_expired_keys_until_empty_with_delay_between_batches(pool, 1, Duration::ZERO),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV delete_keys_with_prefix_once",
        store.delete_keys_with_prefix_once(pool, &prefix, 1),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV delete_keys_with_prefix_once_in_current_transaction",
        tx,
        store.delete_keys_with_prefix_once_in_current_transaction(tx, &prefix, 1),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV acquire_slot_bytes",
        store.acquire_slot_bytes(
            pool,
            std::slice::from_ref(&missing_key),
            b"value",
            expiring_ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV acquire_slot_bytes_in_current_transaction",
        tx,
        store.acquire_slot_bytes_in_current_transaction(
            tx,
            std::slice::from_ref(&missing_key),
            b"value",
            expiring_ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV mutate_key_atomically",
        store.mutate_key_atomically::<_, KvError>(pool, &missing_key, |_current| {
            Ok(KvAtomicMutation::SetBytes {
                value: b"value".to_vec(),
                ttl,
            })
        }),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV mutate_key_atomically_in_current_transaction",
        tx,
        store.mutate_key_atomically_in_current_transaction::<_, KvError>(
            tx,
            &missing_key,
            |_current| {
                Ok(KvAtomicMutation::SetBytes {
                    value: b"value".to_vec(),
                    ttl,
                })
            }
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV mutate_live_key_atomically",
        store.mutate_live_key_atomically::<_, KvError>(pool, &key, |_current| {
            Ok(KvAtomicMutation::KeepExisting)
        }),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV mutate_live_key_atomically_in_current_transaction",
        tx,
        store.mutate_live_key_atomically_in_current_transaction::<_, KvError>(
            tx,
            &key,
            |_current| { Ok(KvAtomicMutation::KeepExisting) }
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV mutate_live_key_or_insert_initial_value_atomically",
        store.mutate_live_key_or_insert_initial_value_atomically::<_, _, KvError>(
            pool,
            &missing_key,
            |_timestamp| Ok((b"initial".to_vec(), ttl)),
            |_current| Ok(KvAtomicMutation::KeepExisting)
        ),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV mutate_live_key_or_insert_initial_value_atomically_in_current_transaction",
        tx,
        store.mutate_live_key_or_insert_initial_value_atomically_in_current_transaction::<_, _, KvError>(
            tx,
            &missing_key,
            |_timestamp| Ok((b"initial".to_vec(), ttl)),
            |_current| Ok(KvAtomicMutation::KeepExisting)
        ),
        kv_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "KV item set",
        item.set(pool, ["missing"], &TestPayload { value: 1 }, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item set_in_current_transaction",
        tx,
        item.set_in_current_transaction(tx, ["missing"], &TestPayload { value: 1 }, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item set_and_return_database_timestamp",
        item.set_and_return_database_timestamp(pool, ["missing"], &TestPayload { value: 1 }, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item set_and_return_database_timestamp_in_current_transaction",
        tx,
        item.set_and_return_database_timestamp_in_current_transaction(
            tx,
            ["missing"],
            &TestPayload { value: 1 },
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item set_if_not_exists",
        item.set_if_not_exists(pool, ["missing"], &TestPayload { value: 1 }, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item set_if_not_exists_in_current_transaction",
        tx,
        item.set_if_not_exists_in_current_transaction(
            tx,
            ["missing"],
            &TestPayload { value: 1 },
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item set_if_not_exists_and_return_database_timestamp",
        item.set_if_not_exists_and_return_database_timestamp(
            pool,
            ["missing"],
            &TestPayload { value: 1 },
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item set_if_not_exists_and_return_database_timestamp_in_current_transaction",
        tx,
        item.set_if_not_exists_and_return_database_timestamp_in_current_transaction(
            tx,
            ["missing"],
            &TestPayload { value: 1 },
            ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item set_multi",
        item.set_multi(pool, &[["multi"]], &[TestPayload { value: 2 }], ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item set_multi_in_current_transaction",
        tx,
        item.set_multi_in_current_transaction(tx, &[["multi"]], &[TestPayload { value: 2 }], ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item delete",
        item.delete(pool, ["seed"]),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item delete_in_current_transaction",
        tx,
        item.delete_in_current_transaction(tx, ["seed"]),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item touch",
        item.touch(pool, ["seed"]),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item touch_in_current_transaction",
        tx,
        item.touch_in_current_transaction(tx, ["seed"]),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item set_ttl",
        item.set_ttl(pool, ["seed"], ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item set_ttl_in_current_transaction",
        tx,
        item.set_ttl_in_current_transaction(tx, ["seed"], ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item expire",
        item.expire(pool, ["seed"]),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item expire_in_current_transaction",
        tx,
        item.expire_in_current_transaction(tx, ["seed"]),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item delete_entire_namespace_atomically",
        item.delete_entire_namespace_atomically(pool),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item delete_entire_namespace_in_current_transaction",
        tx,
        item.delete_entire_namespace_in_current_transaction(tx),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item acquire_slot",
        item.acquire_slot(pool, &["slot"], &TestPayload { value: 3 }, expiring_ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item acquire_slot_in_current_transaction",
        tx,
        item.acquire_slot_in_current_transaction(
            tx,
            &["slot"],
            &TestPayload { value: 3 },
            expiring_ttl
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item get_or_init",
        item.get_or_init(pool, ["missing"], TestPayload { value: 4 }, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item get_or_init_in_current_transaction",
        tx,
        item.get_or_init_in_current_transaction(tx, ["missing"], TestPayload { value: 4 }, ttl),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item mutate_atomically",
        item.mutate_atomically::<_, _, _, KvError>(pool, ["missing"], |_current| {
            Ok(KvItemAtomicMutation::SetValue {
                value: TestPayload { value: 5 },
                ttl,
            })
        }),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item mutate_atomically_in_current_transaction",
        tx,
        item.mutate_atomically_in_current_transaction::<_, _, _, KvError>(
            tx,
            ["missing"],
            |_current| {
                Ok(KvItemAtomicMutation::SetValue {
                    value: TestPayload { value: 5 },
                    ttl,
                })
            }
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item mutate_live_atomically",
        item.mutate_live_atomically::<_, _, _, KvError>(pool, ["seed"], |_current| {
            Ok(KvItemAtomicMutation::KeepExisting)
        }),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item mutate_live_atomically_in_current_transaction",
        tx,
        item.mutate_live_atomically_in_current_transaction::<_, _, _, KvError>(
            tx,
            ["seed"],
            |_current| Ok(KvItemAtomicMutation::KeepExisting)
        ),
        kv_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "KV item mutate_live_or_insert_initial_value_atomically",
        item.mutate_live_or_insert_initial_value_atomically::<_, _, _, _, KvError>(
            pool,
            ["missing"],
            |_timestamp| Ok((TestPayload { value: 6 }, ttl)),
            |_current| Ok(KvItemAtomicMutation::KeepExisting)
        ),
        kv_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "KV item mutate_live_or_insert_initial_value_atomically_in_current_transaction",
        tx,
        item.mutate_live_or_insert_initial_value_atomically_in_current_transaction::<
            _,
            _,
            _,
            _,
            KvError,
        >(
            tx,
            ["missing"],
            |_timestamp| Ok((TestPayload { value: 6 }, ttl)),
            |_current| Ok(KvItemAtomicMutation::KeepExisting)
        ),
        kv_error_is_insufficient_privilege
    );
}

async fn exercise_fleet_public_db_handle_surface(pool: &WritePool, store: &FleetStore) {
    let read_pool: &paranoid::db::Pool = pool;
    let ttl = KvTtl::no_expiration();
    let claim_duration = ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim");
    let holder_id = HolderId::new("marker_holder").expect("holder");
    let guard_config = MutexGuardConfig {
        heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
        acquire_retry_interval: Some(Duration::from_millis(10)),
        max_acquire_retry_interval: Some(Duration::from_millis(20)),
        max_consecutive_renewal_failures: Some(1),
    };

    store
        .validate_schema(read_pool)
        .await
        .expect("Fleet validate_schema should only require SELECT");
    let mut read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin Fleet read tx");
    store
        .validate_schema_in_current_transaction(&mut read_tx)
        .await
        .expect("Fleet tx validate_schema should only require SELECT");
    read_tx.rollback().await.expect("rollback Fleet read tx");

    let counter = store
        .new_counter(CounterKey::new("marker_counter").expect("counter key"))
        .expect("counter");
    counter
        .fetch_value(read_pool)
        .await
        .expect("Fleet counter fetch should only require SELECT");
    let mut counter_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin counter read tx");
    counter
        .fetch_value_in_current_transaction(&mut counter_read_tx)
        .await
        .expect("Fleet counter tx fetch should only require SELECT");
    counter_read_tx
        .rollback()
        .await
        .expect("rollback counter read tx");

    let mutex = store
        .new_mutex(
            MutexKey::new("marker_mutex").expect("mutex key"),
            claim_duration,
        )
        .expect("mutex");
    mutex
        .fetch_live_holder(read_pool)
        .await
        .expect("Fleet mutex holder fetch should only require SELECT");
    let mut mutex_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin mutex read tx");
    mutex
        .fetch_live_holder_in_current_transaction(&mut mutex_read_tx)
        .await
        .expect("Fleet mutex tx holder fetch should only require SELECT");
    mutex_read_tx
        .rollback()
        .await
        .expect("rollback mutex read tx");

    let cron = store
        .new_cron(CronConfig {
            key: CronKey::new("marker_cron").expect("cron key"),
            interval: MIN_CRON_INTERVAL,
            claim_duration: Some(claim_duration),
            heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
            acquire_retry_interval: Some(Duration::from_millis(10)),
            max_consecutive_renewal_failures: Some(1),
        })
        .expect("cron");
    cron.fetch_live_leader(read_pool)
        .await
        .expect("Fleet cron leader fetch should only require SELECT");

    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("marker_semaphore").expect("semaphore key"),
            2,
            Duration::from_secs(30),
        )
        .expect("semaphore");
    semaphore
        .fetch_status(read_pool)
        .await
        .expect("Fleet semaphore status fetch should only require SELECT");
    let mut semaphore_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin semaphore read tx");
    semaphore
        .fetch_status_in_current_transaction(&mut semaphore_read_tx)
        .await
        .expect("Fleet semaphore tx status fetch should only require SELECT");
    semaphore_read_tx
        .rollback()
        .await
        .expect("rollback semaphore read tx");

    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("marker_throttler").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 10,
                interval: Duration::from_secs(60),
            }),
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 2,
                max_hold_duration: Some(Duration::from_secs(30)),
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 2,
                recovery_timeout: Duration::from_secs(30),
            }),
        })
        .expect("throttler");
    throttler
        .fetch_status(read_pool)
        .await
        .expect("Fleet throttler status fetch should only require SELECT");
    let mut throttler_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin throttler read tx");
    throttler
        .fetch_status_in_current_transaction(&mut throttler_read_tx)
        .await
        .expect("Fleet throttler tx status fetch should only require SELECT");
    throttler_read_tx
        .rollback()
        .await
        .expect("rollback throttler read tx");

    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("marker_rate_limiter").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 10,
                interval: Duration::from_secs(60),
            },
        )
        .expect("rate limiter");
    rate_limiter
        .fetch_status(read_pool)
        .await
        .expect("Fleet rate limiter status fetch should only require SELECT");

    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("marker_circuit_breaker").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 2,
                recovery_timeout: Duration::from_secs(30),
            },
        )
        .expect("circuit breaker");
    circuit_breaker
        .fetch_status(read_pool)
        .await
        .expect("Fleet circuit breaker status fetch should only require SELECT");

    let once = store
        .new_once(
            OnceKey::new("marker_once").expect("once key"),
            claim_duration,
        )
        .expect("once");
    once.check_done(read_pool)
        .await
        .expect("Fleet once check_done should only require SELECT");
    let mut once_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin once read tx");
    once.check_done_in_current_transaction(&mut once_read_tx)
        .await
        .expect("Fleet once tx check_done should only require SELECT");
    once_read_tx
        .rollback()
        .await
        .expect("rollback once read tx");

    let cache = store
        .new_coalescing_cache::<TestPayload>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("marker_cache").expect("cache key"),
            value_ttl: ttl,
            lock_wait_timeout: Some(Duration::from_millis(100)),
            compute_timeout: Some(Duration::from_millis(100)),
        })
        .expect("cache");

    let topic = store
        .new_topic::<TestPayload>(TopicConfig {
            key: TopicKey::new("marker_topic").expect("topic key"),
            event_ttl: ttl,
        })
        .expect("topic");
    topic
        .fetch_latest_sequence(read_pool)
        .await
        .expect("Fleet topic latest sequence should only require SELECT");
    let mut topic_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin topic read tx");
    topic
        .fetch_latest_sequence_in_current_transaction(&mut topic_read_tx)
        .await
        .expect("Fleet topic tx latest sequence should only require SELECT");
    topic_read_tx
        .rollback()
        .await
        .expect("rollback topic read tx");

    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("marker_subscription").expect("subscription key"),
            poll_limit: Some(10),
        })
        .expect("subscription");
    subscription
        .fetch_events_after(read_pool, 0)
        .await
        .expect("Fleet subscription event fetch should only require SELECT");
    subscription
        .fetch_cursor(read_pool)
        .await
        .expect("Fleet subscription cursor fetch should only require SELECT");
    let mut subscription_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin subscription read tx");
    subscription
        .fetch_events_after_in_current_transaction(&mut subscription_read_tx, 0)
        .await
        .expect("Fleet subscription tx event fetch should only require SELECT");
    subscription
        .fetch_cursor_in_current_transaction(&mut subscription_read_tx)
        .await
        .expect("Fleet subscription tx cursor fetch should only require SELECT");
    subscription_read_tx
        .rollback()
        .await
        .expect("rollback subscription read tx");

    assert_fails_with_insufficient_privilege!(
        "Fleet migrate_schema",
        store.migrate_schema(pool),
        db_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet migrate_schema_in_current_transaction",
        tx,
        store.migrate_schema_in_current_transaction(tx),
        db_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet counter add",
        counter.add(pool, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet counter add_in_current_transaction",
        tx,
        counter.add_in_current_transaction(tx, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet counter set_value",
        counter.set_value(pool, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet counter set_value_in_current_transaction",
        tx,
        counter.set_value_in_current_transaction(tx, 1),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_claim_guard",
        mutex.try_claim_guard(pool, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_claim_guard_for_holder",
        mutex.try_claim_guard_for_holder(pool, &holder_id, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex claim_guard_when_available",
        mutex.claim_guard_when_available(pool, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex claim_guard_for_holder_when_available",
        mutex.claim_guard_for_holder_when_available(pool, &holder_id, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_run_task",
        mutex.try_run_task::<_, TestTaskError, _, _>(pool, guard_config, |_snapshot| async {
            Ok::<_, TestTaskError>(())
        }),
        mutex_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_run_task_for_holder",
        mutex.try_run_task_for_holder::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            guard_config,
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        mutex_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex run_task_when_available",
        mutex.run_task_when_available::<_, TestTaskError, _, _>(
            pool,
            guard_config,
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        mutex_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex run_task_for_holder_when_available",
        mutex.run_task_for_holder_when_available::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            guard_config,
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        mutex_run_error_is_insufficient_privilege
    );

    let mutex_protocol = mutex.begin_manual_renewal_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual mutex try_claim",
        mutex_protocol.try_claim(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual mutex try_claim_in_current_transaction",
        tx,
        mutex_protocol.try_claim_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual mutex try_claim_for_holder",
        mutex_protocol.try_claim_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual mutex try_claim_for_holder_in_current_transaction",
        tx,
        mutex_protocol.try_claim_for_holder_in_current_transaction(tx, &holder_id),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet cron try_run_once",
        cron.try_run_once::<_, TestTaskError, _, _>(pool, |_snapshot| async {
            Ok::<_, TestTaskError>(())
        }),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_once",
        cron.run_once::<_, TestTaskError, _, _>(pool, |_snapshot| async {
            Ok::<_, TestTaskError>(())
        }),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_until_stopped_or_task_error",
        cron.run_until_stopped_or_task_error::<_, TestTaskError, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_until_stopped_with_task_error_policy",
        cron.run_until_stopped_with_task_error_policy::<_, TestTaskError, _, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_continuously_until_stopped_or_task_error",
        cron.run_continuously_until_stopped_or_task_error::<_, TestTaskError, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_continuously_until_stopped_with_task_error_policy",
        cron.run_continuously_until_stopped_with_task_error_policy::<_, TestTaskError, _, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_until_stopped_or_task_error",
        cron.start_until_stopped_or_task_error::<TestTaskError, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
        ),
    )
    .await;
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_until_stopped_with_task_error_policy",
        cron.start_until_stopped_with_task_error_policy::<TestTaskError, _, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop,
        ),
    )
    .await;
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_continuously_until_stopped_or_task_error",
        cron.start_continuously_until_stopped_or_task_error::<TestTaskError, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
        ),
    )
    .await;
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_continuously_until_stopped_with_task_error_policy",
        cron.start_continuously_until_stopped_with_task_error_policy::<TestTaskError, _, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop,
        ),
    )
    .await;

    assert_fails_with_insufficient_privilege!(
        "Fleet cache fetch_or_compute",
        cache.fetch_or_compute::<_, _, TestTaskError, _, _>(pool, ["missing"], || async {
            Ok::<_, TestTaskError>(TestPayload { value: 1 })
        }),
        coalescing_cache_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cache set",
        cache.set(pool, ["missing"], TestPayload { value: 1 }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cache invalidate",
        cache.invalidate(pool, ["missing"]),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cache invalidate_all",
        cache.invalidate_all(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet cache invalidate_all_in_current_transaction",
        tx,
        cache.invalidate_all_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet topic publish",
        topic.publish(pool, TestPayload { value: 1 }),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet topic publish_in_current_transaction",
        tx,
        topic.publish_in_current_transaction(tx, TestPayload { value: 1 }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet topic purge_retained_events_atomically",
        topic.purge_retained_events_atomically(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet topic purge_retained_events_in_current_transaction",
        tx,
        topic.purge_retained_events_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription read_new_events_and_advance_cursor",
        subscription.read_new_events_and_advance_cursor(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet subscription read_new_events_and_advance_cursor_in_current_transaction",
        tx,
        subscription.read_new_events_and_advance_cursor_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription run_polling_until_stopped_or_handler_error",
        subscription.run_polling_until_stopped_or_handler_error::<_, TestTaskError, _, _>(
            pool,
            Duration::from_millis(10),
            std::future::pending::<()>(),
            |_event| async { Ok::<_, TestTaskError>(()) }
        ),
        subscription_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription run_polling_until_stopped_or_handler_error_with_poll_error_policy",
        subscription.run_polling_until_stopped_or_handler_error_with_poll_error_policy::<
            _,
            TestTaskError,
            _,
            _,
            _,
        >(
            pool,
            Duration::from_millis(10),
            std::future::pending::<()>(),
            |_event| async { Ok::<_, TestTaskError>(()) },
            |_error| paranoid::fleet::SubscriptionPollErrorAction::Stop
        ),
        subscription_run_error_is_insufficient_privilege
    );
    assert_subscription_handle_fails_with_insufficient_privilege(
        "Fleet subscription start_polling_until_stopped_or_handler_error",
        subscription.start_polling_until_stopped_or_handler_error::<TestTaskError, _, _>(
            pool.clone(),
            Duration::from_millis(10),
            |_event| async { Ok::<_, TestTaskError>(()) },
        ),
    )
    .await;
    assert_subscription_handle_fails_with_insufficient_privilege(
        "Fleet subscription start_polling_until_stopped_or_handler_error_with_poll_error_policy",
        subscription.start_polling_until_stopped_or_handler_error_with_poll_error_policy::<
            TestTaskError,
            _,
            _,
            _,
        >(
            pool.clone(),
            Duration::from_millis(10),
            |_event| async { Ok::<_, TestTaskError>(()) },
            |_error| paranoid::fleet::SubscriptionPollErrorAction::Stop,
        ),
    )
    .await;
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription set_cursor",
        subscription.set_cursor(pool, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet subscription set_cursor_in_current_transaction",
        tx,
        subscription.set_cursor_in_current_transaction(tx, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription delete_cursor",
        subscription.delete_cursor(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet subscription delete_cursor_in_current_transaction",
        tx,
        subscription.delete_cursor_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore try_acquire_guard",
        semaphore.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore try_acquire_guard_for_holder",
        semaphore.try_acquire_guard_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore acquire_guard_when_available",
        semaphore.acquire_guard_when_available(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore reset",
        semaphore.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet semaphore reset_in_current_transaction",
        tx,
        semaphore.reset_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore try_run_task",
        semaphore.try_run_task::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore run_task_when_available",
        semaphore.run_task_when_available::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    let semaphore_protocol = semaphore.begin_manual_claim_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual semaphore try_acquire_claim",
        semaphore_protocol.try_acquire_claim(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual semaphore try_acquire_claim_for_holder",
        semaphore_protocol.try_acquire_claim_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual semaphore try_acquire_claim_in_current_transaction",
        tx,
        semaphore_protocol.try_acquire_claim_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual semaphore try_acquire_claim_for_holder_in_current_transaction",
        tx,
        semaphore_protocol.try_acquire_claim_for_holder_in_current_transaction(tx, &holder_id),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_acquire_guard",
        throttler.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler acquire_guard_when_ready",
        throttler.acquire_guard_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_run_task",
        throttler.try_run_task::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler run_task_when_ready",
        throttler.run_task_when_ready::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_acquire_guard_for_holder",
        throttler.try_acquire_guard_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler acquire_guard_for_holder_when_ready",
        throttler.acquire_guard_for_holder_when_ready(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_run_task_for_holder",
        throttler.try_run_task_for_holder::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            |_permit| async { Ok::<_, TestTaskError>(()) }
        ),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler run_task_for_holder_when_ready",
        throttler.run_task_for_holder_when_ready::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            |_permit| async { Ok::<_, TestTaskError>(()) }
        ),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler reset",
        throttler.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet throttler reset_in_current_transaction",
        tx,
        throttler.reset_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler open_circuit",
        throttler.open_circuit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet throttler open_circuit_in_current_transaction",
        tx,
        throttler.open_circuit_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler close_circuit",
        throttler.close_circuit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet throttler close_circuit_in_current_transaction",
        tx,
        throttler.close_circuit_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    let throttler_protocol = throttler.begin_manual_permit_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler try_acquire_permit",
        throttler_protocol.try_acquire_permit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler acquire_permit_when_ready",
        throttler_protocol.acquire_permit_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler try_acquire_permit_for_holder",
        throttler_protocol.try_acquire_permit_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler acquire_permit_for_holder_when_ready",
        throttler_protocol.acquire_permit_for_holder_when_ready(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual throttler try_acquire_permit_in_current_transaction",
        tx,
        throttler_protocol.try_acquire_permit_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual throttler try_acquire_permit_for_holder_in_current_transaction",
        tx,
        throttler_protocol.try_acquire_permit_for_holder_in_current_transaction(tx, &holder_id),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter try_acquire_guard",
        rate_limiter.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter acquire_guard_when_ready",
        rate_limiter.acquire_guard_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter try_run_task",
        rate_limiter.try_run_task::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter run_task_when_ready",
        rate_limiter.run_task_when_ready::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter reset",
        rate_limiter.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    let rate_limiter_protocol = rate_limiter.begin_manual_permit_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual rate limiter try_acquire_permit",
        rate_limiter_protocol.try_acquire_permit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual rate limiter acquire_permit_when_ready",
        rate_limiter_protocol.acquire_permit_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker try_acquire_guard",
        circuit_breaker.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker acquire_guard_when_ready",
        circuit_breaker.acquire_guard_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker try_run_task",
        circuit_breaker.try_run_task::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker run_task_when_ready",
        circuit_breaker.run_task_when_ready::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker reset",
        circuit_breaker.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker open",
        circuit_breaker.open(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker close",
        circuit_breaker.close(pool),
        fleet_error_is_insufficient_privilege
    );
    let circuit_breaker_protocol = circuit_breaker.begin_manual_permit_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual circuit breaker try_acquire_permit",
        circuit_breaker_protocol.try_acquire_permit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual circuit breaker acquire_permit_when_ready",
        circuit_breaker_protocol.acquire_permit_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet once try_run_task",
        once.try_run_task::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        once_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet once run_task_when_available",
        once.run_task_when_available::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        once_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet once try_run_task_atomically",
        once.try_run_task_atomically::<_, TestTaskError, _>(pool, |_claim, _tx| {
            Box::pin(async { Ok::<_, TestTaskError>(()) })
        }),
        once_transactional_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet once run_task_atomically_when_available",
        once.run_task_atomically_when_available::<_, TestTaskError, _>(pool, |_claim, _tx| {
            Box::pin(async { Ok::<_, TestTaskError>(()) })
        }),
        once_transactional_run_error_is_insufficient_privilege
    );
    let once_protocol = once.begin_manual_run_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual once try_start_run",
        once_protocol.try_start_run(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual once try_start_run_for_holder",
        once_protocol.try_start_run_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
}

async fn exercise_queue_public_db_handle_surface(
    pool: &WritePool,
    store: &QueueStore,
    fleet_store: &FleetStore,
    job_id: JobId,
) {
    let read_pool: &paranoid::db::Pool = pool;
    let mut registry = TaskRegistry::new();
    let registered_task = store
        .register_json_task_handler::<TestPayload, _, _>(
            &mut registry,
            TEST_TASK_NAME,
            |_context, _payload| async { Ok(()) },
        )
        .expect("registered JSON task");
    let worker_owner_id =
        WorkerOwnerId::new_unique_for_worker_name(TEST_WORKER_NAME).expect("worker owner ID");

    store
        .fetch_job_by_id(read_pool, job_id)
        .await
        .expect("queue fetch_job_by_id should only require SELECT");
    store
        .fetch_job_status(read_pool, job_id)
        .await
        .expect("queue fetch_job_status should only require SELECT");
    store
        .fetch_status_counts(read_pool, None)
        .await
        .expect("queue status counts should only require SELECT");
    store
        .fetch_pending_job_count(read_pool, None)
        .await
        .expect("queue pending count should only require SELECT");
    store
        .fetch_failed_job_count(read_pool, None)
        .await
        .expect("queue failed count should only require SELECT");
    store
        .fetch_queue_is_paused(read_pool)
        .await
        .expect("queue pause status should only require SELECT");
    store
        .fetch_task_is_paused(read_pool, TEST_TASK_NAME)
        .await
        .expect("queue task pause status should only require SELECT");
    store
        .fetch_paused_task_names(read_pool)
        .await
        .expect("queue paused task names should only require SELECT");
    store
        .fetch_orphaned_task_names(read_pool, &registry)
        .await
        .expect("queue orphaned task names should only require SELECT");
    store
        .fetch_worker_pressure(read_pool, &registry)
        .await
        .expect("queue worker pressure should only require SELECT");
    store
        .list_jobs(read_pool, ListJobsOptions::default())
        .await
        .expect("queue list_jobs should only require SELECT");
    store
        .list_dead_letter_jobs(read_pool, ListDeadLetterJobsOptions::default())
        .await
        .expect("queue list_dead_letter_jobs should only require SELECT");

    let mut read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin queue read tx");
    store
        .fetch_job_by_id_in_current_transaction(&mut read_tx, job_id)
        .await
        .expect("queue tx fetch_job_by_id should only require SELECT");
    store
        .fetch_job_status_in_current_transaction(&mut read_tx, job_id)
        .await
        .expect("queue tx fetch_job_status should only require SELECT");
    store
        .fetch_status_counts_in_current_transaction(&mut read_tx, None)
        .await
        .expect("queue tx status counts should only require SELECT");
    store
        .fetch_pending_job_count_in_current_transaction(&mut read_tx, None)
        .await
        .expect("queue tx pending count should only require SELECT");
    store
        .fetch_failed_job_count_in_current_transaction(&mut read_tx, None)
        .await
        .expect("queue tx failed count should only require SELECT");
    store
        .fetch_queue_is_paused_in_current_transaction(&mut read_tx)
        .await
        .expect("queue tx pause status should only require SELECT");
    store
        .fetch_task_is_paused_in_current_transaction(&mut read_tx, TEST_TASK_NAME)
        .await
        .expect("queue tx task pause status should only require SELECT");
    store
        .fetch_paused_task_names_in_current_transaction(&mut read_tx)
        .await
        .expect("queue tx paused task names should only require SELECT");
    store
        .fetch_orphaned_task_names_in_current_transaction(&mut read_tx, &registry)
        .await
        .expect("queue tx orphaned task names should only require SELECT");
    store
        .fetch_worker_pressure_in_current_transaction(&mut read_tx, &registry)
        .await
        .expect("queue tx worker pressure should only require SELECT");
    store
        .list_jobs_in_current_transaction(&mut read_tx, ListJobsOptions::default())
        .await
        .expect("queue tx list_jobs should only require SELECT");
    store
        .list_dead_letter_jobs_in_current_transaction(
            &mut read_tx,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("queue tx list_dead_letter_jobs should only require SELECT");
    read_tx.rollback().await.expect("rollback queue read tx");

    assert_fails_with_insufficient_privilege!(
        "queue migrate_schema",
        store.migrate_schema(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue migrate_schema_in_current_transaction",
        tx,
        store.migrate_schema_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue validate_schema",
        store.validate_schema(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue validate_schema_in_current_transaction",
        tx,
        store.validate_schema_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue enqueue_json",
        store.enqueue_json(
            pool,
            TEST_TASK_NAME,
            &TestPayload { value: 1 },
            EnqueueOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue enqueue_json_in_current_transaction",
        tx,
        store.enqueue_json_in_current_transaction(
            tx,
            TEST_TASK_NAME,
            &TestPayload { value: 1 },
            EnqueueOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue enqueue_json_batch",
        store.enqueue_json_batch(
            pool,
            TEST_TASK_NAME,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue enqueue_json_batch_in_current_transaction",
        tx,
        store.enqueue_json_batch_in_current_transaction(
            tx,
            TEST_TASK_NAME,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue registered task enqueue",
        registered_task.enqueue(pool, &TestPayload { value: 1 }, EnqueueOptions::default()),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue registered task enqueue_in_current_transaction",
        tx,
        registered_task.enqueue_in_current_transaction(
            tx,
            &TestPayload { value: 1 },
            EnqueueOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue registered task enqueue_batch",
        registered_task.enqueue_batch(
            pool,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue registered task enqueue_batch_in_current_transaction",
        tx,
        registered_task.enqueue_batch_in_current_transaction(
            tx,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue pause_queue",
        store.pause_queue(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue pause_queue_in_current_transaction",
        tx,
        store.pause_queue_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue resume_queue",
        store.resume_queue(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue resume_queue_in_current_transaction",
        tx,
        store.resume_queue_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue pause_task",
        store.pause_task(pool, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue pause_task_in_current_transaction",
        tx,
        store.pause_task_in_current_transaction(tx, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue resume_task",
        store.resume_task(pool, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue resume_task_in_current_transaction",
        tx,
        store.resume_task_in_current_transaction(tx, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cancel_pending_job",
        store.cancel_pending_job(pool, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cancel_pending_job_in_current_transaction",
        tx,
        store.cancel_pending_job_in_current_transaction(tx, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue retry_failed_job",
        store.retry_failed_job(pool, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue retry_failed_job_in_current_transaction",
        tx,
        store.retry_failed_job_in_current_transaction(tx, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue retry_available_failed_jobs",
        store.retry_available_failed_jobs(pool, None, 1, None),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue retry_available_failed_jobs_in_current_transaction",
        tx,
        store.retry_available_failed_jobs_in_current_transaction(tx, None, 1, None),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue force_requeue_running_job_by_id",
        store.force_requeue_running_job_by_id(pool, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue force_requeue_running_job_by_id_in_current_transaction",
        tx,
        store.force_requeue_running_job_by_id_in_current_transaction(tx, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue move_failed_job_to_dead_letter",
        store.move_failed_job_to_dead_letter(pool, job_id, DeadLetterReason::OperatorAction),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue move_failed_job_to_dead_letter_in_current_transaction",
        tx,
        store.move_failed_job_to_dead_letter_in_current_transaction(
            tx,
            job_id,
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue move_failed_jobs_to_dead_letter_batch",
        store.move_failed_jobs_to_dead_letter_batch(
            pool,
            &[job_id],
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue move_failed_jobs_to_dead_letter_batch_in_current_transaction",
        tx,
        store.move_failed_jobs_to_dead_letter_batch_in_current_transaction(
            tx,
            &[job_id],
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue requeue_dead_letter_job",
        store.requeue_dead_letter_job(pool, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue requeue_dead_letter_job_in_current_transaction",
        tx,
        store.requeue_dead_letter_job_in_current_transaction(tx, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue delete_dead_letter_job",
        store.delete_dead_letter_job(pool, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue delete_dead_letter_job_in_current_transaction",
        tx,
        store.delete_dead_letter_job_in_current_transaction(tx, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_completed_jobs_older_than_once",
        store.cleanup_available_completed_jobs_older_than_once(pool, Duration::from_secs(1), 1),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_completed_jobs_older_than_until_empty",
        store.cleanup_available_completed_jobs_older_than_until_empty(
            pool,
            Duration::from_secs(1),
            1,
            Duration::ZERO
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cleanup_available_completed_jobs_older_than_once_in_current_transaction",
        tx,
        store.cleanup_available_completed_jobs_older_than_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_failed_jobs_older_than_once",
        store.cleanup_available_failed_jobs_older_than_once(pool, Duration::from_secs(1), 1),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_failed_jobs_older_than_until_empty",
        store.cleanup_available_failed_jobs_older_than_until_empty(
            pool,
            Duration::from_secs(1),
            1,
            Duration::ZERO
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cleanup_available_failed_jobs_older_than_once_in_current_transaction",
        tx,
        store.cleanup_available_failed_jobs_older_than_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_dead_letter_jobs_older_than_once",
        store.cleanup_available_dead_letter_jobs_older_than_once(pool, Duration::from_secs(1), 1),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_dead_letter_jobs_older_than_until_empty",
        store.cleanup_available_dead_letter_jobs_older_than_until_empty(
            pool,
            Duration::from_secs(1),
            1,
            Duration::ZERO
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction",
        tx,
        store.cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue reclaim_available_stale_running_jobs_once",
        store.reclaim_available_stale_running_jobs_once(pool, Duration::from_secs(1), 1, true),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue reclaim_available_stale_running_jobs_once_in_current_transaction",
        tx,
        store.reclaim_available_stale_running_jobs_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1,
            true
        ),
        queue_error_is_insufficient_privilege
    );

    let manual_worker = store.begin_manual_worker_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "queue manual worker claim_available_jobs_for_worker_owner",
        manual_worker.claim_available_jobs_for_worker_owner(
            pool,
            &[TEST_TASK_NAME.to_owned()],
            1,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker claim_available_jobs_for_worker_owner_in_current_transaction",
        tx,
        manual_worker.claim_available_jobs_for_worker_owner_in_current_transaction(
            tx,
            &[TEST_TASK_NAME.to_owned()],
            1,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker mark_owned_running_job_started",
        manual_worker.mark_owned_running_job_started(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker mark_owned_running_job_started_in_current_transaction",
        tx,
        manual_worker.mark_owned_running_job_started_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker mark_owned_running_job_completed",
        manual_worker.mark_owned_running_job_completed(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker mark_owned_running_job_completed_in_current_transaction",
        tx,
        manual_worker.mark_owned_running_job_completed_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker touch_owned_running_job_execution_heartbeat",
        manual_worker.touch_owned_running_job_execution_heartbeat(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker touch_owned_running_job_execution_heartbeat_in_current_transaction",
        tx,
        manual_worker.touch_owned_running_job_execution_heartbeat_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker schedule_owned_running_job_retry",
        manual_worker.schedule_owned_running_job_retry(
            pool,
            job_id,
            &worker_owner_id,
            1,
            Duration::from_secs(1),
            "retry"
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker schedule_owned_running_job_retry_in_current_transaction",
        tx,
        manual_worker.schedule_owned_running_job_retry_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id,
            1,
            Duration::from_secs(1),
            "retry"
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker mark_owned_running_job_failed",
        manual_worker.mark_owned_running_job_failed(pool, job_id, &worker_owner_id, "failed", true),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker mark_owned_running_job_failed_in_current_transaction",
        tx,
        manual_worker.mark_owned_running_job_failed_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id,
            "failed",
            true
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker move_owned_running_job_to_dead_letter",
        manual_worker.move_owned_running_job_to_dead_letter(
            pool,
            job_id,
            &worker_owner_id,
            "dead",
            true,
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker move_owned_running_job_to_dead_letter_in_current_transaction",
        tx,
        manual_worker.move_owned_running_job_to_dead_letter_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id,
            "dead",
            true,
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_owned_unstarted_running_job_to_pending",
        manual_worker.return_owned_unstarted_running_job_to_pending(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_owned_unstarted_running_job_to_pending_in_current_transaction",
        tx,
        manual_worker.return_owned_unstarted_running_job_to_pending_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_owned_started_running_job_to_pending",
        manual_worker.return_owned_started_running_job_to_pending(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_owned_started_running_job_to_pending_in_current_transaction",
        tx,
        manual_worker.return_owned_started_running_job_to_pending_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_available_owned_unstarted_running_jobs_to_pending",
        manual_worker
            .return_available_owned_unstarted_running_jobs_to_pending(pool, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction",
        tx,
        manual_worker
            .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
                tx,
                &worker_owner_id
            ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_available_owned_started_running_jobs_to_pending",
        manual_worker
            .return_available_owned_started_running_jobs_to_pending(pool, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_available_owned_started_running_jobs_to_pending_in_current_transaction",
        tx,
        manual_worker
            .return_available_owned_started_running_jobs_to_pending_in_current_transaction(
                tx,
                &worker_owner_id
            ),
        queue_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "queue process_available_jobs_once_for_worker",
        store.process_available_jobs_once_for_worker(
            pool,
            &registry,
            TEST_WORKER_NAME,
            fast_worker_config()
        ),
        queue_error_is_insufficient_privilege
    );

    let worker = store
        .start_worker(
            pool.clone(),
            registry.clone(),
            TEST_WORKER_NAME,
            fast_worker_config(),
        )
        .expect("start worker with read-only-backed WritePool");
    worker.request_stop();
    let _ = tokio::time::timeout(Duration::from_secs(2), worker.wait())
        .await
        .expect("worker stopped after request");

    let maintenance_worker = store
        .start_worker_with_fleet_maintenance(
            pool.clone(),
            fleet_store.clone(),
            registry,
            "marker_worker_with_maintenance",
            fast_worker_config(),
            fast_worker_maintenance_config(),
        )
        .expect("start worker with Fleet maintenance and read-only-backed WritePool");
    maintenance_worker.request_stop();
    let _ = tokio::time::timeout(Duration::from_secs(2), maintenance_worker.wait())
        .await
        .expect("worker with maintenance stopped after request");
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
        default_job_timeout: paranoid::queue::WorkerDefaultJobTimeout::ExpiresAfter(
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
    handle: paranoid::fleet::CronRunHandle<TestTaskError>,
) {
    let result = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .unwrap_or_else(|_| panic!("{label} did not finish after privilege failure"));
    let error = result.expect_err("cron handle unexpectedly succeeded");
    assert!(
        cron_handle_error_is_insufficient_privilege(&error),
        "{label} did not fail with SQLSTATE 42501: {error:?}",
    );
}

async fn assert_subscription_handle_fails_with_insufficient_privilege(
    label: &str,
    handle: paranoid::fleet::SubscriptionRunHandle<TestTaskError>,
) {
    let result = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .unwrap_or_else(|_| panic!("{label} did not finish after privilege failure"));
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
        if let Some(db_error) = error.downcast_ref::<DbError>() {
            if db_error_is_insufficient_privilege(db_error) {
                return true;
            }
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
    error: &paranoid::fleet::CoalescingCacheFetchError<TestTaskError>,
) -> bool {
    if error_chain_has_insufficient_privilege(error) {
        return true;
    }
    match error {
        paranoid::fleet::CoalescingCacheFetchError::Fleet(source) => {
            fleet_error_is_insufficient_privilege(source)
        }
        paranoid::fleet::CoalescingCacheFetchError::ComputeAndRelease { release_error, .. } => {
            fleet_error_is_insufficient_privilege(release_error)
        }
        paranoid::fleet::CoalescingCacheFetchError::Compute { .. } => false,
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
