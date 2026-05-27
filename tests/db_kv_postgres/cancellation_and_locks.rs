use super::*;

#[tokio::test]
async fn kv_atomic_mutation_rejection_cleans_up_absent_key_placeholder() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["atomic", "reject"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin tx");
    let err = store
        .mutate_key_atomically_in_current_transaction(&mut tx, &key, |current| {
            assert_eq!(current.live_value(), None);
            Err::<KvAtomicMutation, _>(KvError::KeyNotFound)
        })
        .await
        .expect_err("decision rejected");
    assert!(matches!(err, KvError::KeyNotFound));
    tx.commit().await.expect("commit after rejection");

    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_atomic_mutation_serializes_absent_key_races_with_placeholder_lock() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["atomic", "absent-race"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut first_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin first tx");
    store
        .mutate_key_atomically_in_current_transaction(&mut first_tx, &key, |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"first".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("first mutation");

    let (second_started_tx, second_started_rx) = oneshot::channel();
    let (second_observed_tx, mut second_observed_rx) = oneshot::channel();
    let second_pool = test_database.paranoid_pool.clone();
    let second_store = store.clone();
    let second_key = key.clone();
    let second_handle = tokio::spawn(async move {
        let mut second_tx = second_pool
            .begin_transaction()
            .await
            .expect("begin second tx");
        second_started_tx.send(()).expect("send started");
        let result = second_store
            .mutate_key_atomically_in_current_transaction(&mut second_tx, &second_key, |current| {
                second_observed_tx
                    .send(current.live_value().map(|value| value.to_vec()))
                    .expect("send observed");
                Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
            })
            .await
            .expect("second mutation");
        second_tx.commit().await.expect("commit second tx");
        result
    });

    second_started_rx.await.expect("second started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(matches!(
        second_observed_rx.try_recv(),
        Err(TryRecvError::Empty)
    ));

    first_tx.commit().await.expect("commit first tx");
    assert_eq!(
        second_observed_rx.await.expect("second observed"),
        Some(b"first".to_vec())
    );
    assert_eq!(
        second_handle.await.expect("second task"),
        KvAtomicMutationResult {
            previous_live_value: Some(b"first".to_vec()),
            outcome: KvAtomicMutationOutcome::KeptLiveValue,
        }
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_atomic_mutation_future_abort_while_waiting_for_lock_does_not_write_later() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["atomic", "cancel-while-waiting"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"committed",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set committed value");

    let mut first_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin first tx");
    store
        .mutate_key_atomically_in_current_transaction(&mut first_tx, &key, |current| {
            assert_eq!(current.live_value(), Some(b"committed".as_slice()));
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"locked".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("first mutation holds row lock");

    let (second_started_tx, second_started_rx) = oneshot::channel();
    let (second_callback_tx, mut second_callback_rx) = oneshot::channel();
    let second_pool = test_database.paranoid_pool.clone();
    let second_store = store.clone();
    let second_key = key.clone();
    let second_handle = tokio::spawn(async move {
        let mut second_tx = second_pool
            .begin_transaction()
            .await
            .expect("begin second tx");
        second_started_tx.send(()).expect("send second started");
        second_store
            .mutate_key_atomically_in_current_transaction(&mut second_tx, &second_key, |current| {
                second_callback_tx
                    .send(current.live_value().map(|value| value.to_vec()))
                    .expect("send second callback");
                Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                    value: b"cancelled-write".to_vec(),
                    ttl: KvTtl::no_expiration(),
                })
            })
            .await
            .expect("second mutation");
        second_tx.commit().await.expect("commit second tx");
    });

    second_started_rx.await.expect("second task started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!second_handle.is_finished());
    assert!(matches!(
        second_callback_rx.try_recv(),
        Err(TryRecvError::Empty)
    ));

    second_handle.abort();
    assert!(
        second_handle
            .await
            .expect_err("aborted task should not complete")
            .is_cancelled()
    );
    assert!(matches!(
        second_callback_rx.try_recv(),
        Err(TryRecvError::Empty | TryRecvError::Closed)
    ));

    first_tx.commit().await.expect("commit first tx");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get final value"),
        b"locked"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_future_abort_while_waiting_for_pool_connection_does_not_write_later() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping Postgres KV test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run");
        return;
    };

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let key = KvKey::from_parts(["cancel", "pool-wait"]).expect("key");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (set_started_tx, set_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_key = key.clone();
    let set_handle = tokio::spawn(async move {
        set_started_tx.send(()).expect("send set started");
        task_store
            .set_bytes(&task_pool, &task_key, b"late-write", KvTtl::no_expiration())
            .await
            .expect("set after waiting for pool connection");
    });

    set_started_rx.await.expect("set task started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!set_handle.is_finished());

    set_handle.abort();
    assert!(
        set_handle
            .await
            .expect_err("aborted task should not complete")
            .is_cancelled()
    );

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(matches!(
        store.get_bytes(&paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_set_multi_touch_and_set_if_not_exists_future_abort_while_waiting_for_pool_connection_does_not_write_later()
 {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping Postgres KV test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run");
        return;
    };

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let multi_key_a = KvKey::from_parts(["cancel", "set-multi-a"]).expect("key");
    let multi_key_b = KvKey::from_parts(["cancel", "set-multi-b"]).expect("key");
    let touch_key = KvKey::from_parts(["cancel", "touch"]).expect("key");
    let claim_key = KvKey::from_parts(["cancel", "set-if-not-exists"]).expect("key");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");
    store
        .set_bytes(&paranoid_pool, &touch_key, b"touch", KvTtl::no_expiration())
        .await
        .expect("set touch key");
    let touch_updated_at_before =
        fetch_key_updated_at_text(&sqlx_pool, &config.table_name, &touch_key).await;

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");
    let (set_multi_started_tx, set_multi_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_multi_key_a = multi_key_a.clone();
    let task_multi_key_b = multi_key_b.clone();
    let set_multi_handle = tokio::spawn(async move {
        set_multi_started_tx
            .send(())
            .expect("send set_multi started");
        let entries = vec![
            KvBytesSetEntry::new(task_multi_key_a, b"a".to_vec()),
            KvBytesSetEntry::new(task_multi_key_b, b"b".to_vec()),
        ];
        task_store
            .set_bytes_multi(&task_pool, &entries, KvTtl::no_expiration())
            .await
            .expect("set_multi after waiting for pool connection");
    });
    set_multi_started_rx.await.expect("set_multi task started");
    abort_blocked_task(set_multi_handle, "set_multi").await;
    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(matches!(
        store.get_bytes(&paranoid_pool, &multi_key_a).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(matches!(
        store.get_bytes(&paranoid_pool, &multi_key_b).await,
        Err(KvError::KeyNotFound)
    ));

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");
    let (touch_started_tx, touch_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_touch_key = touch_key.clone();
    let touch_handle = tokio::spawn(async move {
        touch_started_tx.send(()).expect("send touch started");
        task_store
            .touch_key(&task_pool, &task_touch_key)
            .await
            .expect("touch after waiting for pool connection");
    });
    touch_started_rx.await.expect("touch task started");
    abort_blocked_task(touch_handle, "touch").await;
    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fetch_key_updated_at_text(&sqlx_pool, &config.table_name, &touch_key).await,
        touch_updated_at_before
    );

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");
    let (claim_started_tx, claim_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_claim_key = claim_key.clone();
    let claim_handle = tokio::spawn(async move {
        claim_started_tx
            .send(())
            .expect("send set_if_not_exists started");
        task_store
            .set_bytes_if_not_exists(
                &task_pool,
                &task_claim_key,
                b"claimed",
                KvTtl::no_expiration(),
            )
            .await
            .expect("set_if_not_exists after waiting for pool connection");
    });
    claim_started_rx
        .await
        .expect("set_if_not_exists task started");
    abort_blocked_task(claim_handle, "set_if_not_exists").await;
    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(matches!(
        store.get_bytes(&paranoid_pool, &claim_key).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_public_write_future_abort_while_waiting_for_row_lock_does_not_write_later() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["cancel", "row-lock"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"committed",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set committed value");

    let mut first_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin first tx");
    store
        .mutate_key_atomically_in_current_transaction(&mut first_tx, &key, |current| {
            assert_eq!(current.live_value(), Some(b"committed".as_slice()));
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"locked".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("first mutation holds row lock");

    let task_pool = test_database.paranoid_pool.clone();
    let task_store = store.clone();
    let task_key = key.clone();
    let set_handle = tokio::spawn(async move {
        task_store
            .set_bytes(&task_pool, &task_key, b"late-write", KvTtl::no_expiration())
            .await
            .expect("set after row lock release");
    });

    abort_blocked_task(set_handle, "set").await;
    first_tx.commit().await.expect("commit first tx");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get final value"),
        b"locked"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_destructive_maintenance_future_abort_while_waiting_for_pool_connection_does_not_delete_later()
 {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping Postgres KV test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run");
        return;
    };

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let expired_key = KvKey::from_parts(["cancel", "expired-cleanup"]).expect("key");
    let prefix = KvKeyPrefix::from_parts(["cancel", "prefix-delete"]).expect("prefix");
    let prefixed_key = KvKey::from_prefix_and_parts(&prefix, ["key"]).expect("key");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");

    store
        .set_bytes(
            &paranoid_pool,
            &expired_key,
            b"expired",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set expiring key");
    store
        .set_bytes(
            &paranoid_pool,
            &prefixed_key,
            b"prefixed",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set prefixed key");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (cleanup_started_tx, cleanup_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let cleanup_handle = tokio::spawn(async move {
        cleanup_started_tx.send(()).expect("send cleanup started");
        task_store
            .delete_expired_keys_until_empty(&task_pool, 10)
            .await
            .expect("delete expired after waiting for pool connection");
    });

    cleanup_started_rx.await.expect("cleanup task started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!cleanup_handle.is_finished());

    cleanup_handle.abort();
    assert!(
        cleanup_handle
            .await
            .expect_err("aborted cleanup task should not complete")
            .is_cancelled()
    );

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fetch_table_row_count(&sqlx_pool, &config.table_name).await,
        2
    );

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (prefix_delete_started_tx, prefix_delete_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_prefix = prefix.clone();
    let prefix_delete_handle = tokio::spawn(async move {
        prefix_delete_started_tx
            .send(())
            .expect("send prefix delete started");
        task_store
            .delete_keys_with_prefix_once(&task_pool, &task_prefix, 10)
            .await
            .expect("delete prefix after waiting for pool connection");
    });

    prefix_delete_started_rx
        .await
        .expect("prefix delete task started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!prefix_delete_handle.is_finished());

    prefix_delete_handle.abort();
    assert!(
        prefix_delete_handle
            .await
            .expect_err("aborted prefix delete task should not complete")
            .is_cancelled()
    );

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        store
            .get_bytes(&paranoid_pool, &prefixed_key)
            .await
            .expect("get prefixed key"),
        b"prefixed"
    );
    assert_eq!(
        fetch_table_row_count(&sqlx_pool, &config.table_name).await,
        2
    );

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_delete_expired_until_empty_future_abort_during_batch_delay_does_not_delete_later() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let expired_a = KvKey::from_parts(["cancel-delay", "expired-a"]).expect("key");
    let expired_b = KvKey::from_parts(["cancel-delay", "expired-b"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for key in [&expired_a, &expired_b] {
        store
            .set_bytes(
                &test_database.paranoid_pool,
                key,
                b"expired",
                KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
            )
            .await
            .expect("set expiring key");
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let task_pool = test_database.paranoid_pool.clone();
    let task_store = store.clone();
    let cleanup_handle = tokio::spawn(async move {
        task_store
            .delete_expired_keys_until_empty_with_delay_between_batches(
                &task_pool,
                1,
                Duration::from_secs(60),
            )
            .await
            .expect("delete expired keys");
    });

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let remaining_rows =
                fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name)
                    .await;
            assert!(
                remaining_rows != 0,
                "cleanup completed all batches before the cancellation point"
            );
            if remaining_rows == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first cleanup batch should complete");

    cleanup_handle.abort();
    assert!(
        cleanup_handle
            .await
            .expect_err("aborted cleanup task should not complete")
            .is_cancelled()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        1
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_delete_entire_namespace_atomically_future_abort_while_waiting_for_pool_connection_does_not_delete_later()
 {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping Postgres KV test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run");
        return;
    };

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["cancel", "namespace"]).expect("prefix"),
    );
    let other_key = KvKey::from_parts(["cancel", "other"]).expect("key");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");

    item.set(
        &paranoid_pool,
        ["a"],
        &TestKvPayload {
            label: "a".to_owned(),
            count: 1,
        },
        KvTtl::no_expiration(),
    )
    .await
    .expect("set a");
    item.set(
        &paranoid_pool,
        ["b"],
        &TestKvPayload {
            label: "b".to_owned(),
            count: 2,
        },
        KvTtl::no_expiration(),
    )
    .await
    .expect("set b");
    store
        .set_bytes(&paranoid_pool, &other_key, b"other", KvTtl::no_expiration())
        .await
        .expect("set other key");

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (delete_started_tx, delete_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_item = item.clone();
    let delete_handle = tokio::spawn(async move {
        delete_started_tx.send(()).expect("send delete started");
        task_item
            .delete_entire_namespace_atomically(&task_pool)
            .await
            .expect("delete namespace after waiting for pool connection");
    });

    delete_started_rx.await.expect("delete task started");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!delete_handle.is_finished());

    delete_handle.abort();
    assert!(
        delete_handle
            .await
            .expect_err("aborted delete task should not complete")
            .is_cancelled()
    );

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        item.count(&paranoid_pool).await.expect("count namespace"),
        2
    );
    assert_eq!(
        store
            .get_bytes(&paranoid_pool, &other_key)
            .await
            .expect("get other key"),
        b"other"
    );
    assert_eq!(
        fetch_table_row_count(&sqlx_pool, &config.table_name).await,
        3
    );

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_item_delete_entire_namespace_atomically_future_abort_while_waiting_for_row_lock_rolls_back()
 {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["cancel", "namespace-row-lock"]).expect("prefix"),
    );
    let other_key = KvKey::from_parts(["cancel", "namespace-row-lock-other"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    item.set(
        &test_database.paranoid_pool,
        ["a"],
        &TestKvPayload {
            label: "a".to_owned(),
            count: 1,
        },
        KvTtl::no_expiration(),
    )
    .await
    .expect("set a");
    item.set(
        &test_database.paranoid_pool,
        ["b"],
        &TestKvPayload {
            label: "b".to_owned(),
            count: 2,
        },
        KvTtl::no_expiration(),
    )
    .await
    .expect("set b");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &other_key,
            b"other",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set other key");

    let mut lock_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin lock transaction");
    item.mutate_atomically_in_current_transaction(&mut lock_tx, ["a"], |current| {
        assert!(current.live_value().is_some());
        Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
            value: TestKvPayload {
                label: "locked".to_owned(),
                count: 10,
            },
            ttl: KvTtl::no_expiration(),
        })
    })
    .await
    .expect("lock namespace row");

    let task_pool = test_database.paranoid_pool.clone();
    let task_item = item.clone();
    let delete_handle = tokio::spawn(async move {
        task_item
            .delete_entire_namespace_atomically(&task_pool)
            .await
            .expect("delete namespace after row lock release");
    });

    abort_blocked_task(delete_handle, "namespace delete").await;
    lock_tx.commit().await.expect("commit lock transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        item.count(&test_database.paranoid_pool)
            .await
            .expect("count namespace"),
        2
    );
    assert_eq!(
        item.get::<_, _>(&test_database.paranoid_pool, ["a"])
            .await
            .expect("get locked item"),
        TestKvPayload {
            label: "locked".to_owned(),
            count: 10,
        }
    );
    assert_eq!(
        item.get::<_, _>(&test_database.paranoid_pool, ["b"])
            .await
            .expect("get b"),
        TestKvPayload {
            label: "b".to_owned(),
            count: 2,
        }
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &other_key)
            .await
            .expect("get other key"),
        b"other"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

async fn abort_blocked_task<T>(handle: tokio::task::JoinHandle<T>, task_name: &str) {
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !handle.is_finished(),
        "{task_name} task should still be blocked"
    );
    handle.abort();
    match handle.await {
        Err(join_error) => assert!(
            join_error.is_cancelled(),
            "{task_name} task join error = {join_error}"
        ),
        Ok(_) => panic!("{task_name} task completed after abort"),
    }
}
