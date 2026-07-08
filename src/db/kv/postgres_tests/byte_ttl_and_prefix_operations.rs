use super::*;

#[tokio::test]
async fn kv_ttl_touch_and_expire_operations_apply_only_to_live_keys() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["ttl", "lifecycle"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"value",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set");
    assert!(
        fetch_key_has_null_expiration(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &key,
        )
        .await
    );

    store
        .set_key_ttl(
            &test_database.paranoid_pool,
            &key,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await
        .expect("set ttl");
    assert!(
        !fetch_key_has_null_expiration(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &key,
        )
        .await
    );

    let updated_at_before = fetch_key_updated_at_text(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        &key,
    )
    .await;
    let expires_at_before_touch = fetch_key_expires_at_text(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        &key,
    )
    .await;
    std::thread::sleep(Duration::from_millis(10));
    store
        .touch_key(&test_database.paranoid_pool, &key)
        .await
        .expect("touch");
    let updated_at_after = fetch_key_updated_at_text(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        &key,
    )
    .await;
    assert_ne!(updated_at_after, updated_at_before);
    assert_eq!(
        fetch_key_expires_at_text(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &key,
        )
        .await,
        expires_at_before_touch
    );

    store
        .set_key_ttl(&test_database.paranoid_pool, &key, KvTtl::no_expiration())
        .await
        .expect("set no expiration");
    assert!(
        fetch_key_has_null_expiration(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &key,
        )
        .await
    );

    let rounded_key = KvKey::from_parts(["ttl", "rounding"]).expect("key");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &rounded_key,
            b"value",
            KvTtl::expires_after(MIN_KV_TTL + Duration::from_nanos(1)).expect("ttl"),
        )
        .await
        .expect("set rounded ttl");
    assert_eq!(
        fetch_key_expiration_delta_microseconds(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &rounded_key,
        )
        .await,
        i64::try_from(MIN_KV_TTL.as_micros()).expect("min ttl micros") + 1
    );

    store
        .expire_key(&test_database.paranoid_pool, &key)
        .await
        .expect("expire");
    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(matches!(
        store.touch_key(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(matches!(
        store
            .set_key_ttl(&test_database.paranoid_pool, &key, KvTtl::no_expiration())
            .await,
        Err(KvError::KeyNotFound)
    ));
    assert!(matches!(
        store.expire_key(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    let statement_time_key = KvKey::from_parts(["ttl", "statement-time"]).expect("key");
    let mut statement_time_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin statement-time tx");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    store
        .set_bytes_in_current_transaction(
            &mut statement_time_tx,
            &statement_time_key,
            b"created-after-transaction-start",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set inside old transaction");
    statement_time_tx
        .commit()
        .await
        .expect("commit statement-time tx");
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &statement_time_key)
            .await
            .expect("ttl must be relative to statement time"),
        b"created-after-transaction-start"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_delete_expired_keys_once_deletes_only_expired_rows_with_bounded_batch_size() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let expired_a = KvKey::from_parts(["cleanup", "expired-a"]).expect("key");
    let expired_b = KvKey::from_parts(["cleanup", "expired-b"]).expect("key");
    let live = KvKey::from_parts(["cleanup", "live"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for key in [&expired_a, &expired_b, &live] {
        store
            .set_bytes(
                &test_database.paranoid_pool,
                key,
                b"value",
                KvTtl::no_expiration(),
            )
            .await
            .expect("set");
    }
    store
        .expire_key(&test_database.paranoid_pool, &expired_a)
        .await
        .expect("expire a");
    store
        .expire_key(&test_database.paranoid_pool, &expired_b)
        .await
        .expect("expire b");

    assert!(matches!(
        store
            .delete_expired_keys_once(&test_database.paranoid_pool, 0)
            .await,
        Err(KvError::DeleteBatchSizeIsZero)
    ));
    assert!(matches!(
        store
            .delete_expired_keys_once(&test_database.paranoid_pool, MAX_KV_DELETE_BATCH_SIZE + 1)
            .await,
        Err(KvError::DeleteBatchSizeTooLarge { .. })
    ));

    assert_eq!(
        store
            .delete_expired_keys_once(&test_database.paranoid_pool, 1)
            .await
            .expect("first cleanup"),
        1
    );
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        2
    );
    assert_eq!(
        store
            .delete_expired_keys_once(&test_database.paranoid_pool, 10)
            .await
            .expect("second cleanup"),
        1
    );
    assert_eq!(
        store
            .delete_expired_keys_once(&test_database.paranoid_pool, 10)
            .await
            .expect("third cleanup"),
        0
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &live)
            .await
            .expect("live key remains"),
        b"value"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_delete_expired_keys_once_concurrent_cleaners_delete_each_expired_row_once() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let total_deleted = Arc::new(AtomicUsize::new(0));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for index in 0..100 {
        let key = KvKey::from_parts([format!("cleanup-{index:03}")]).expect("key");
        store
            .set_bytes(
                &test_database.paranoid_pool,
                &key,
                b"value",
                KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
            )
            .await
            .expect("set expiring key");
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let handles = (0..5)
        .map(|_| {
            let task_store = store.clone();
            let task_pool = test_database.paranoid_pool.clone();
            let task_total_deleted = Arc::clone(&total_deleted);
            tokio::spawn(async move {
                loop {
                    let deleted = task_store
                        .delete_expired_keys_once(&task_pool, 10)
                        .await
                        .expect("delete expired batch");
                    if deleted == 0 {
                        return;
                    }
                    task_total_deleted.fetch_add(deleted as usize, Ordering::SeqCst);
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.await.expect("join cleanup task");
    }
    assert_eq!(total_deleted.load(Ordering::SeqCst), 100);
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_delete_expired_keys_until_empty_deletes_all_currently_expired_batches() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let live_key = KvKey::from_parts(["cleanup-until-empty", "live"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for index in 0..25 {
        let key = KvKey::from_parts(["cleanup-until-empty", &format!("expired-{index:03}")])
            .expect("key");
        store
            .set_bytes(
                &test_database.paranoid_pool,
                &key,
                b"expired",
                KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
            )
            .await
            .expect("set expiring key");
    }
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &live_key,
            b"live",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set live key");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert!(matches!(
        store
            .delete_expired_keys_until_empty(&test_database.paranoid_pool, 0)
            .await,
        Err(KvError::DeleteBatchSizeIsZero)
    ));
    assert!(matches!(
        store
            .delete_expired_keys_until_empty(
                &test_database.paranoid_pool,
                MAX_KV_DELETE_BATCH_SIZE + 1,
            )
            .await,
        Err(KvError::DeleteBatchSizeTooLarge { .. })
    ));
    assert!(matches!(
        store
            .delete_expired_keys_until_empty_with_delay_between_batches(
                &test_database.paranoid_pool,
                0,
                Duration::ZERO,
            )
            .await,
        Err(KvError::DeleteBatchSizeIsZero)
    ));

    assert_eq!(
        store
            .delete_expired_keys_until_empty_with_delay_between_batches(
                &test_database.paranoid_pool,
                10,
                Duration::ZERO,
            )
            .await
            .expect("delete all expired keys"),
        25
    );
    assert_eq!(
        store
            .delete_expired_keys_until_empty(&test_database.paranoid_pool, 10)
            .await
            .expect("delete no expired keys"),
        0
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &live_key)
            .await
            .expect("live key remains"),
        b"live"
    );
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        1
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_prefix_count_scan_and_delete_are_isolated_and_ordered() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["tenant"]).expect("prefix");
    let adjacent_prefix = KvKeyPrefix::from_parts(["tenantx"]).expect("prefix");
    let prefix_exact = KvKey::from_prefix_and_parts::<&str, _>(&prefix, []).expect("key");
    let prefix_a = KvKey::from_prefix_and_parts(&prefix, ["a"]).expect("key");
    let prefix_b = KvKey::from_prefix_and_parts(&prefix, ["b"]).expect("key");
    let prefix_expired = KvKey::from_prefix_and_parts(&prefix, ["expired"]).expect("key");
    let adjacent = KvKey::from_prefix_and_parts(&adjacent_prefix, ["a"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for (key, value) in [
        (&prefix_exact, b"prefix-exact".as_slice()),
        (&prefix_b, b"b".as_slice()),
        (&prefix_a, b"a".as_slice()),
        (&prefix_expired, b"expired".as_slice()),
        (&adjacent, b"adjacent".as_slice()),
    ] {
        store
            .set_bytes(
                &test_database.paranoid_pool,
                key,
                value,
                KvTtl::no_expiration(),
            )
            .await
            .expect("set");
    }
    store
        .expire_key(&test_database.paranoid_pool, &prefix_expired)
        .await
        .expect("expire");

    assert_eq!(
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &prefix)
            .await
            .expect("count prefix"),
        3
    );
    assert_eq!(
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &adjacent_prefix)
            .await
            .expect("count adjacent"),
        1
    );

    let first_page = store
        .scan_bytes_with_prefix(&test_database.paranoid_pool, &prefix, None, 2)
        .await
        .expect("scan first page");
    assert_eq!(
        first_page
            .iter()
            .map(|row| (row.key.as_str(), row.value.as_slice()))
            .collect::<Vec<_>>(),
        vec![
            (prefix_exact.as_str(), b"prefix-exact".as_slice()),
            (prefix_a.as_str(), b"a".as_slice()),
        ]
    );

    let second_page = store
        .scan_bytes_with_prefix(
            &test_database.paranoid_pool,
            &prefix,
            first_page.last().map(|row| &row.key),
            10,
        )
        .await
        .expect("scan second page");
    assert_eq!(
        second_page
            .iter()
            .map(|row| (row.key.as_str(), row.value.as_slice()))
            .collect::<Vec<_>>(),
        vec![(prefix_b.as_str(), b"b".as_slice())]
    );

    assert!(matches!(
        store
            .scan_bytes_with_prefix(&test_database.paranoid_pool, &prefix, Some(&adjacent), 10)
            .await,
        Err(KvError::ScanCursorOutsidePrefix)
    ));
    assert!(matches!(
        store
            .scan_bytes_with_prefix(&test_database.paranoid_pool, &prefix, None, 0)
            .await,
        Err(KvError::ScanLimitIsZero)
    ));
    assert!(matches!(
        store
            .scan_bytes_with_prefix(
                &test_database.paranoid_pool,
                &prefix,
                None,
                MAX_KV_SCAN_LIMIT + 1,
            )
            .await,
        Err(KvError::ScanLimitTooLarge { .. })
    ));
    assert!(matches!(
        store
            .delete_keys_with_prefix_once(&test_database.paranoid_pool, &prefix, 0)
            .await,
        Err(KvError::DeleteBatchSizeIsZero)
    ));
    assert!(matches!(
        store
            .delete_keys_with_prefix_once(
                &test_database.paranoid_pool,
                &prefix,
                MAX_KV_DELETE_BATCH_SIZE + 1
            )
            .await,
        Err(KvError::DeleteBatchSizeTooLarge { .. })
    ));

    assert_eq!(
        store
            .delete_keys_with_prefix_once(&test_database.paranoid_pool, &prefix, 2)
            .await
            .expect("delete first batch"),
        2
    );
    assert_eq!(
        store
            .delete_keys_with_prefix_once(&test_database.paranoid_pool, &prefix, 10)
            .await
            .expect("delete remaining prefix rows"),
        2
    );
    assert_eq!(
        store
            .delete_keys_with_prefix_once(&test_database.paranoid_pool, &prefix, 10)
            .await
            .expect("delete empty prefix"),
        0
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &adjacent)
            .await
            .expect("adjacent key remains"),
        b"adjacent"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_delete_keys_with_prefix_once_concurrent_deleters_delete_each_row_once() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["delete-prefix-concurrent"]).expect("prefix");
    let adjacent_prefix = KvKeyPrefix::from_parts(["delete-prefix-concurrentx"]).expect("prefix");
    let adjacent_key = KvKey::from_prefix_and_parts(&adjacent_prefix, ["survivor"]).expect("key");
    let total_deleted = Arc::new(AtomicUsize::new(0));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for index in 0..100 {
        let key = KvKey::from_prefix_and_parts(&prefix, [format!("key-{index:03}")]).expect("key");
        store
            .set_bytes(
                &test_database.paranoid_pool,
                &key,
                b"value",
                KvTtl::no_expiration(),
            )
            .await
            .expect("set prefixed key");
    }
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &adjacent_key,
            b"adjacent",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set adjacent key");

    let handles = (0..8)
        .map(|_| {
            let task_store = store.clone();
            let task_pool = test_database.paranoid_pool.clone();
            let task_prefix = prefix.clone();
            let task_total_deleted = Arc::clone(&total_deleted);
            tokio::spawn(async move {
                loop {
                    let deleted = task_store
                        .delete_keys_with_prefix_once(&task_pool, &task_prefix, 7)
                        .await
                        .expect("delete prefixed batch");
                    if deleted == 0 {
                        return;
                    }
                    task_total_deleted.fetch_add(deleted as usize, Ordering::SeqCst);
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.await.expect("join prefix deletion task");
    }

    assert_eq!(total_deleted.load(Ordering::SeqCst), 100);
    assert_eq!(
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &prefix)
            .await
            .expect("count deleted prefix"),
        0
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &adjacent_key)
            .await
            .expect("adjacent key remains"),
        b"adjacent"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_prefix_operations_escape_like_metacharacters() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let wildcard_looking_prefix = KvKeyPrefix::from_parts(["tenant%_\\"]).expect("prefix");
    let ordinary_prefix = KvKeyPrefix::from_parts(["tenantabc"]).expect("prefix");
    let wildcard_looking_key =
        KvKey::from_prefix_and_parts(&wildcard_looking_prefix, ["owned"]).expect("key");
    let ordinary_key = KvKey::from_prefix_and_parts(&ordinary_prefix, ["owned"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &wildcard_looking_key,
            b"wildcard-looking",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set wildcard-looking");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &ordinary_key,
            b"ordinary",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set ordinary");

    assert_eq!(
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &wildcard_looking_prefix)
            .await
            .expect("count"),
        1
    );
    assert_eq!(
        store
            .scan_bytes_with_prefix(
                &test_database.paranoid_pool,
                &wildcard_looking_prefix,
                None,
                10,
            )
            .await
            .expect("scan"),
        vec![KvScannedBytes {
            key: wildcard_looking_key.clone(),
            value: b"wildcard-looking".to_vec(),
        }]
    );

    assert_eq!(
        store
            .delete_keys_with_prefix_once(
                &test_database.paranoid_pool,
                &wildcard_looking_prefix,
                10
            )
            .await
            .expect("delete wildcard-looking"),
        1
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &ordinary_key)
            .await
            .expect("ordinary remains"),
        b"ordinary"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
