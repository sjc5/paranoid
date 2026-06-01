use super::*;

#[tokio::test]
async fn fleet_coalescing_cache_set_fetch_and_compute_on_miss() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("profiles").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(
            &test_database.paranoid_pool,
            ["user-1"],
            "manual".to_owned(),
        )
        .await
        .expect("set cache value");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let cached_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["user-1"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("computed".to_owned())
            }
        })
        .await
        .expect("fetch cached value");
    assert_eq!(cached_value, "manual");
    assert_eq!(compute_count.load(Ordering::SeqCst), 0);

    let computed_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["user-2"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("computed".to_owned())
            }
        })
        .await
        .expect("compute missing value");
    assert_eq!(computed_value, "computed");

    let second_fetch = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["user-2"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("wrong".to_owned())
            }
        })
        .await
        .expect("fetch computed cached value");
    assert_eq!(second_fetch, "computed");
    assert_eq!(compute_count.load(Ordering::SeqCst), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_stale_entry_reads_epoch_once_before_and_once_after_lock() {
    let test_database = TestDatabase::connect().await;
    let direct_database_url = direct_test_database_url();

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache_key = CoalescingCacheKey::new("stale-epoch-shape").expect("cache key");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: cache_key.clone(),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(&test_database.paranoid_pool, ["user-1"], "stale".to_owned())
        .await
        .expect("set stale cache value");
    cache
        .invalidate_all(&test_database.paranoid_pool)
        .await
        .expect("invalidate cache epoch");

    let epoch_key = persisted_coalescing_cache_epoch_key(&test_database.config, &cache_key);
    let (role_name, role_password) =
        create_non_bypass_login_role_for_test(&test_database.sqlx_pool).await;
    grant_fleet_test_tables_to_login_role(
        &test_database.sqlx_pool,
        &test_database.config,
        &role_name,
    )
    .await;
    let counter_policy = install_key_read_counter_policy_on_kv_table(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
        &epoch_key,
    )
    .await;
    let non_bypass_pool =
        connect_paranoid_pool_as_login_role(&direct_database_url, &role_name, &role_password).await;
    let compute_count = Arc::new(AtomicUsize::new(0));
    let value = cache
        .fetch_or_compute(&non_bypass_pool, ["user-1"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("recomputed".to_owned())
            }
        })
        .await
        .expect("fetch stale value");
    assert_eq!(value, "recomputed");
    assert_eq!(compute_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        fetch_key_read_counter_policy_count(&test_database.sqlx_pool, &counter_policy).await,
        2
    );

    drop_key_read_counter_policy(&test_database.sqlx_pool, &counter_policy).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_root_keys_isolate_values_in_shared_tables() {
    let test_database = TestDatabase::connect().await;

    let first_store = Store::new(
        StoreConfig::new(
            RootKey::new("prefix1").expect("root key"),
            test_database.config.state_table_name.clone(),
            test_database.config.coordination_table_name.clone(),
        )
        .expect("fleet config"),
    )
    .expect("fleet store");
    let second_store = Store::new(
        StoreConfig::new(
            RootKey::new("prefix2").expect("root key"),
            test_database.config.state_table_name.clone(),
            test_database.config.coordination_table_name.clone(),
        )
        .expect("fleet config"),
    )
    .expect("fleet store");
    let first_cache = first_store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("shared-cache-key").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new first cache");
    let second_cache = second_store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("shared-cache-key").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new second cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    first_store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    first_cache
        .set(
            &test_database.paranoid_pool,
            ["same-key"],
            "value1".to_owned(),
        )
        .await
        .expect("set first cache");
    second_cache
        .set(
            &test_database.paranoid_pool,
            ["same-key"],
            "value2".to_owned(),
        )
        .await
        .expect("set second cache");

    assert_eq!(
        first_cache
            .fetch_or_compute(&test_database.paranoid_pool, ["same-key"], || async {
                Ok::<_, TestComputeError>("wrong1".to_owned())
            })
            .await
            .expect("fetch first cache"),
        "value1"
    );
    assert_eq!(
        second_cache
            .fetch_or_compute(&test_database.paranoid_pool, ["same-key"], || async {
                Ok::<_, TestComputeError>("wrong2".to_owned())
            })
            .await
            .expect("fetch second cache"),
        "value2"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_ttl_expiration_recomputes_value() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("short-lived").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let first_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<_, TestComputeError>(format!("computed-{count}"))
            }
        })
        .await
        .expect("first compute");
    assert_eq!(first_value, "computed-1");

    tokio::time::sleep(Duration::from_millis(1_150)).await;

    let second_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<_, TestComputeError>(format!("computed-{count}"))
            }
        })
        .await
        .expect("recompute after ttl");
    assert_eq!(second_value, "computed-2");
    assert_eq!(compute_count.load(Ordering::SeqCst), 2);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_concurrent_misses_share_one_computation() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = Arc::new(
        store
            .new_coalescing_cache::<String>(CoalescingCacheConfig {
                key: CoalescingCacheKey::new("single-compute").expect("cache key"),
                value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
                lock_wait_timeout: Some(Duration::from_secs(5)),
                compute_timeout: Some(Duration::from_secs(5)),
            })
            .expect("new cache"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_count = 8;
    let barrier = Arc::new(Barrier::new(worker_count));
    let compute_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let cache = Arc::clone(&cache);
        let pool = test_database.paranoid_pool.clone();
        let barrier = Arc::clone(&barrier);
        let compute_count = Arc::clone(&compute_count);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            cache
                .fetch_or_compute(&pool, ["shared"], move || async move {
                    compute_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok::<_, TestComputeError>("shared-value".to_owned())
                })
                .await
                .expect("fetch shared value")
        }));
    }

    for handle in handles {
        assert_eq!(handle.await.expect("join worker"), "shared-value");
    }
    assert_eq!(compute_count.load(Ordering::SeqCst), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_compute_errors_and_timeouts_are_not_cached() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("fallible").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: Some(Duration::from_millis(50)),
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let first_error = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Err::<String, _>(TestComputeError("forced failure"))
            }
        })
        .await
        .expect_err("first compute should fail");
    assert!(matches!(
        first_error,
        CoalescingCacheFetchError::Compute {
            source: TestComputeError("forced failure")
        }
    ));

    let second_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("recovered".to_owned())
            }
        })
        .await
        .expect("second compute should run");
    assert_eq!(second_value, "recovered");
    assert_eq!(compute_count.load(Ordering::SeqCst), 2);

    let timeout_cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("timeout").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: Some(Duration::from_millis(20)),
        })
        .expect("new timeout cache");
    let timeout_error = timeout_cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, TestComputeError>("too-late".to_owned())
        })
        .await
        .expect_err("compute should time out");
    assert!(matches!(
        timeout_error,
        CoalescingCacheFetchError::Fleet(Error::CoalescingCacheComputeTimedOut { .. })
    ));

    let after_timeout_value = timeout_cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            Ok::<_, TestComputeError>("after-timeout".to_owned())
        })
        .await
        .expect("timeout should not cache value");
    assert_eq!(after_timeout_value, "after-timeout");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_waiting_fetch_can_be_cancelled_without_poisoning_cache() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("cancel-waiting-fetch").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let compute_started = Arc::new(Barrier::new(2));
    let first_cache = cache.clone();
    let first_pool = test_database.paranoid_pool.clone();
    let first_compute_started = Arc::clone(&compute_started);
    let first_handle = tokio::spawn(async move {
        first_cache
            .fetch_or_compute(&first_pool, ["key"], move || async move {
                first_compute_started.wait().await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok::<_, TestComputeError>("winner".to_owned())
            })
            .await
    });
    compute_started.wait().await;

    let cancelled = tokio::time::timeout(
        Duration::from_millis(50),
        cache.fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            Ok::<_, TestComputeError>("cancelled".to_owned())
        }),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "waiting fetch should be cancelled by the caller timeout"
    );

    let first_value = first_handle
        .await
        .expect("join first compute")
        .expect("first compute should complete");
    assert_eq!(first_value, "winner");

    let cached_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            Err::<String, _>(TestComputeError("cached value should be reused"))
        })
        .await
        .expect("fetch cached value after cancellation");
    assert_eq!(cached_value, "winner");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_set_and_invalidate_report_lock_wait_timeout() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("set-invalidate-lock-timeout").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_millis(25)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let compute_started = Arc::new(Barrier::new(2));
    let first_cache = cache.clone();
    let first_pool = test_database.paranoid_pool.clone();
    let first_compute_started = Arc::clone(&compute_started);
    let first_handle = tokio::spawn(async move {
        first_cache
            .fetch_or_compute(&first_pool, ["key"], move || async move {
                first_compute_started.wait().await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok::<_, TestComputeError>("held".to_owned())
            })
            .await
    });
    compute_started.wait().await;

    let set_error = cache
        .set(&test_database.paranoid_pool, ["key"], "manual".to_owned())
        .await
        .expect_err("set should time out while compute mutex is held");
    assert!(
        matches!(set_error, Error::CoalescingCacheLockWaitTimedOut { .. }),
        "error = {set_error:?}"
    );

    let invalidate_error = cache
        .invalidate(&test_database.paranoid_pool, ["key"])
        .await
        .expect_err("invalidate should time out while compute mutex is held");
    assert!(
        matches!(
            invalidate_error,
            Error::CoalescingCacheLockWaitTimedOut { .. }
        ),
        "error = {invalidate_error:?}"
    );

    let first_value = first_handle
        .await
        .expect("join first compute")
        .expect("first compute should complete");
    assert_eq!(first_value, "held");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_returns_computed_value_when_cache_write_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("best-effort-store").expect("cache key"),
            value_ttl: KvTtl::no_expiration(),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let first_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            let sqlx_pool = test_database.sqlx_pool.clone();
            let kv_table_name = test_database.config.state_table_name.clone();
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                drop_test_table(&sqlx_pool, &kv_table_name).await;
                Ok::<_, TestComputeError>(format!("computed-{count}"))
            }
        })
        .await
        .expect("computed value should be returned even when cache write fails");
    assert_eq!(first_value, "computed-1");
    assert_eq!(compute_count.load(Ordering::SeqCst), 1);

    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("remigrate missing KV table");

    let second_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<_, TestComputeError>(format!("computed-{count}"))
            }
        })
        .await
        .expect("second compute should run because first value was not cached");
    assert_eq!(second_value, "computed-2");
    assert_eq!(compute_count.load(Ordering::SeqCst), 2);

    let cached_second_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<_, TestComputeError>(format!("unexpected-{count}"))
            }
        })
        .await
        .expect("second value should be cached after schema is available");
    assert_eq!(cached_second_value, "computed-2");
    assert_eq!(compute_count.load(Ordering::SeqCst), 2);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_set_reports_epoch_lookup_failure() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("set-epoch-failure").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
    )
    .await;

    let error = cache
        .set(&test_database.paranoid_pool, ["key"], "manual".to_owned())
        .await
        .expect_err("missing KV table should make epoch lookup fail");
    assert!(
        matches!(error, Error::Kv(KvError::Database(DbError::Query { .. }))),
        "error = {error:?}"
    );

    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("remigrate Fleet schema");
    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_fetch_reports_fresh_cached_value_decode_error() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache_key = CoalescingCacheKey::new("fresh-read-error").expect("cache key");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: cache_key.clone(),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(&test_database.paranoid_pool, ["key"], "cached".to_owned())
        .await
        .expect("set cache value");
    RawKvStore::new(
        KvStoreConfig::new(test_database.config.state_table_name.clone()).expect("kv config"),
    )
    .expect("kv store")
    .set_bytes(
        &test_database.paranoid_pool,
        &persisted_coalescing_cache_value_key(&test_database.config, &cache_key, ["key"]),
        &[0xff],
        KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
    )
    .await
    .expect("corrupt cache value");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let error = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                compute_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should-not-run".to_owned())
            }
        })
        .await
        .expect_err("corrupt fresh cached value should be returned");
    assert!(
        matches!(
            error,
            CoalescingCacheFetchError::Fleet(Error::Kv(KvError::Codec(_)))
        ),
        "error = {error:?}"
    );
    assert_eq!(compute_count.load(Ordering::SeqCst), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_fetch_reports_locked_double_check_decode_error() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache_key = CoalescingCacheKey::new("double-check-error").expect("cache key");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: cache_key.clone(),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let (compute_started_tx, compute_started_rx) = tokio::sync::oneshot::channel();
    let (release_compute_tx, release_compute_rx) = tokio::sync::oneshot::channel();
    let blocker_cache = cache.clone();
    let blocker_pool = test_database.paranoid_pool.clone();
    let blocker_handle = tokio::spawn(async move {
        let mut compute_started_tx = Some(compute_started_tx);
        blocker_cache
            .fetch_or_compute(&blocker_pool, ["key"], move || {
                let compute_started_tx = compute_started_tx.take();
                async move {
                    if let Some(compute_started_tx) = compute_started_tx {
                        compute_started_tx
                            .send(())
                            .expect("send compute started signal");
                    }
                    release_compute_rx.await.expect("release compute");
                    Err::<String, TestComputeError>(TestComputeError("release cache mutex"))
                }
            })
            .await
    });
    compute_started_rx.await.expect("compute started");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let run_cache = cache.clone();
    let run_pool = test_database.paranoid_pool.clone();
    let compute_count_for_task = Arc::clone(&compute_count);
    let fetch_handle = tokio::spawn(async move {
        run_cache
            .fetch_or_compute(&run_pool, ["key"], move || async move {
                compute_count_for_task.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should-not-run".to_owned())
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    RawKvStore::new(
        KvStoreConfig::new(test_database.config.state_table_name.clone()).expect("kv config"),
    )
    .expect("kv store")
    .set_bytes(
        &test_database.paranoid_pool,
        &persisted_coalescing_cache_value_key(&test_database.config, &cache_key, ["key"]),
        &[0xff],
        KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
    )
    .await
    .expect("corrupt cache value before locked double-check");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !fetch_handle.is_finished(),
        "fetch should still be waiting on the compute mutex"
    );

    release_compute_tx
        .send(())
        .expect("send release compute signal");
    blocker_handle
        .await
        .expect("blocker task should not panic")
        .expect_err("blocker compute should fail after releasing cache mutex");

    let error = tokio::time::timeout(Duration::from_secs(2), fetch_handle)
        .await
        .expect("fetch should finish after releasing cache mutex")
        .expect("fetch task should not panic")
        .expect_err("corrupt locked double-check value should be returned");
    assert!(
        matches!(
            error,
            CoalescingCacheFetchError::Fleet(Error::Kv(KvError::Codec(_)))
        ),
        "error = {error:?}"
    );
    assert_eq!(compute_count.load(Ordering::SeqCst), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_fetch_returns_release_error_when_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("fetch-release-error").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failure_function = install_delete_failure_trigger_on_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;
    let error = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            Ok::<_, TestComputeError>("computed".to_owned())
        })
        .await
        .expect_err("release failure should be returned");
    assert!(
        matches!(
            error,
            CoalescingCacheFetchError::Fleet(Error::Coordination(CoordinationError::Database(_)))
        ),
        "error = {error:?}"
    );
    drop_test_function_cascade(&test_database.sqlx_pool, &failure_function).await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_set_returns_release_error_when_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("set-release-error").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failure_function = install_delete_failure_trigger_on_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;
    let error = cache
        .set(&test_database.paranoid_pool, ["key"], "manual".to_owned())
        .await
        .expect_err("release failure should be returned");
    assert!(
        matches!(error, Error::Coordination(CoordinationError::Database(_))),
        "error = {error:?}"
    );
    drop_test_function_cascade(&test_database.sqlx_pool, &failure_function).await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_invalidate_returns_release_error_when_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("invalidate-release-error").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(&test_database.paranoid_pool, ["key"], "manual".to_owned())
        .await
        .expect("set cache value before release failure");
    let failure_function = install_delete_failure_trigger_on_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;
    let error = cache
        .invalidate(&test_database.paranoid_pool, ["key"])
        .await
        .expect_err("release failure should be returned");
    assert!(
        matches!(error, Error::Coordination(CoordinationError::Database(_))),
        "error = {error:?}"
    );
    drop_test_function_cascade(&test_database.sqlx_pool, &failure_function).await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_compute_panic_releases_compute_mutex() {
    async fn panic_cache_compute() -> Result<String, TestComputeError> {
        panic!("cache compute panic")
    }

    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("panic-releases").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_millis(200)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let panic_cache = cache.clone();
    let panic_pool = test_database.paranoid_pool.clone();
    let panic_handle = tokio::spawn(async move {
        panic_cache
            .fetch_or_compute(&panic_pool, ["key"], panic_cache_compute)
            .await
    });
    let join_error = panic_handle
        .await
        .expect_err("cache compute task should panic");
    assert!(join_error.is_panic());

    let recovered = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            Ok::<_, TestComputeError>("recovered".to_owned())
        })
        .await
        .expect("cache compute mutex should be released after panic");
    assert_eq!(recovered, "recovered");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_invalidate_and_invalidate_all_use_epoch_semantics() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("invalidations").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(&test_database.paranoid_pool, ["one"], "manual".to_owned())
        .await
        .expect("set value");
    cache
        .invalidate(&test_database.paranoid_pool, ["one"])
        .await
        .expect("invalidate value");
    cache
        .invalidate(&test_database.paranoid_pool, ["missing"])
        .await
        .expect("invalidating a missing value should be a no-op");
    let after_invalidate = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["one"], || async {
            Ok::<_, TestComputeError>("recomputed".to_owned())
        })
        .await
        .expect("recompute after invalidate");
    assert_eq!(after_invalidate, "recomputed");

    cache
        .set(
            &test_database.paranoid_pool,
            ["two"],
            "before-rollback".to_owned(),
        )
        .await
        .expect("set rollback value");
    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    cache
        .invalidate_all_in_current_transaction(&mut tx)
        .await
        .expect("invalidate all in tx");
    tx.rollback().await.expect("rollback transaction");
    let after_rollback = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["two"], || async {
            Err::<String, _>(TestComputeError("should not run"))
        })
        .await
        .expect("rollback should preserve cached value");
    assert_eq!(after_rollback, "before-rollback");

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit transaction");
    cache
        .invalidate_all_in_current_transaction(&mut tx)
        .await
        .expect("invalidate all in commit tx");
    tx.commit().await.expect("commit transaction");
    let after_commit = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["two"], || async {
            Ok::<_, TestComputeError>("after-commit".to_owned())
        })
        .await
        .expect("committed epoch invalidation should make cached value stale");
    assert_eq!(after_commit, "after-commit");

    cache
        .invalidate_all(&test_database.paranoid_pool)
        .await
        .expect("invalidate all");
    let after_invalidate_all = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["two"], || async {
            Ok::<_, TestComputeError>("after-epoch".to_owned())
        })
        .await
        .expect("recompute after epoch invalidation");
    assert_eq!(after_invalidate_all, "after-epoch");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_concurrent_invalidate_all_is_epoch_safe() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = Arc::new(
        store
            .new_coalescing_cache::<String>(CoalescingCacheConfig {
                key: CoalescingCacheKey::new("concurrent-invalidate-all").expect("cache key"),
                value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
                lock_wait_timeout: Some(Duration::from_secs(5)),
                compute_timeout: None,
            })
            .expect("new cache"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(&test_database.paranoid_pool, ["key"], "before".to_owned())
        .await
        .expect("set cached value");

    let worker_count = 8;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut handles = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let cache = Arc::clone(&cache);
        let pool = test_database.paranoid_pool.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            cache
                .invalidate_all(&pool)
                .await
                .expect("concurrent invalidate all");
        }));
    }
    for handle in handles {
        handle.await.expect("join invalidate_all worker");
    }

    let recomputed = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], || async {
            Ok::<_, TestComputeError>("after".to_owned())
        })
        .await
        .expect("fetch after concurrent invalidations");
    assert_eq!(recomputed, "after");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_no_expiration_values_remain_cached() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("no-expiration").expect("cache key"),
            value_ttl: KvTtl::no_expiration(),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let compute_count = Arc::new(AtomicUsize::new(0));
    let first_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<_, TestComputeError>(format!("computed-{count}"))
            }
        })
        .await
        .expect("first compute");
    assert_eq!(first_value, "computed-1");

    tokio::time::sleep(Duration::from_millis(1_150)).await;

    let second_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["key"], {
            let compute_count = Arc::clone(&compute_count);
            move || async move {
                let count = compute_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok::<_, TestComputeError>(format!("unexpected-{count}"))
            }
        })
        .await
        .expect("fetch no-expiration value");
    assert_eq!(second_value, "computed-1");
    assert_eq!(compute_count.load(Ordering::SeqCst), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_supports_empty_and_multiple_key_part_shapes() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<String>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("key-shapes").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    cache
        .set(
            &test_database.paranoid_pool,
            std::iter::empty::<&str>(),
            "root-value".to_owned(),
        )
        .await
        .expect("set root cache value");
    let root_value = cache
        .fetch_or_compute(
            &test_database.paranoid_pool,
            std::iter::empty::<&str>(),
            || async { Err::<String, _>(TestComputeError("root value should be cached")) },
        )
        .await
        .expect("fetch root cache value");
    assert_eq!(root_value, "root-value");

    cache
        .set(
            &test_database.paranoid_pool,
            ["tenant", "alpha"],
            "alpha-value".to_owned(),
        )
        .await
        .expect("set alpha cache value");
    cache
        .set(
            &test_database.paranoid_pool,
            ["tenant", "beta"],
            "beta-value".to_owned(),
        )
        .await
        .expect("set beta cache value");

    let alpha_value = cache
        .fetch_or_compute(
            &test_database.paranoid_pool,
            ["tenant", "alpha"],
            || async { Err::<String, _>(TestComputeError("alpha value should be cached")) },
        )
        .await
        .expect("fetch alpha cache value");
    let beta_value = cache
        .fetch_or_compute(&test_database.paranoid_pool, ["tenant", "beta"], || async {
            Err::<String, _>(TestComputeError("beta value should be cached"))
        })
        .await
        .expect("fetch beta cache value");
    assert_eq!(alpha_value, "alpha-value");
    assert_eq!(beta_value, "beta-value");

    cache
        .invalidate(&test_database.paranoid_pool, std::iter::empty::<&str>())
        .await
        .expect("invalidate root cache value");
    let recomputed_root_value = cache
        .fetch_or_compute(
            &test_database.paranoid_pool,
            std::iter::empty::<&str>(),
            || async { Ok::<_, TestComputeError>("root-recomputed".to_owned()) },
        )
        .await
        .expect("recompute root cache value");
    assert_eq!(recomputed_root_value, "root-recomputed");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_coalescing_cache_handles_complex_values_and_key_part_validation() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct CachedProfile {
        name: String,
        login_count: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cache = store
        .new_coalescing_cache::<CachedProfile>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("complex").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            lock_wait_timeout: None,
            compute_timeout: None,
        })
        .expect("new cache");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let original = CachedProfile {
        name: "River".to_owned(),
        login_count: 7,
    };
    cache
        .set(
            &test_database.paranoid_pool,
            ["tenant", "user"],
            original.clone(),
        )
        .await
        .expect("set complex value");
    assert_eq!(
        cache
            .fetch_or_compute(&test_database.paranoid_pool, ["tenant", "user"], || async {
                Err::<CachedProfile, _>(TestComputeError("should not run"))
            })
            .await
            .expect("fetch complex value"),
        original
    );

    assert!(matches!(
        cache
            .fetch_or_compute(&test_database.paranoid_pool, ["tenant", ""], || async {
                Ok::<_, TestComputeError>(CachedProfile {
                    name: "bad".to_owned(),
                    login_count: 0,
                })
            })
            .await,
        Err(CoalescingCacheFetchError::Fleet(
            Error::InvalidCoalescingCacheKeyForValue { .. }
        ))
    ));
    assert!(matches!(
        cache
            .set(
                &test_database.paranoid_pool,
                ["invalid:part"],
                CachedProfile {
                    name: "bad".to_owned(),
                    login_count: 0,
                },
            )
            .await,
        Err(Error::InvalidCoalescingCacheKeyForValue { .. })
    ));
    assert!(matches!(
        cache
            .invalidate(&test_database.paranoid_pool, ["invalid:part"])
            .await,
        Err(Error::InvalidCoalescingCacheKeyForValue { .. })
    ));

    let oversized_key_part = "a".repeat(paranoid::kv::MAX_KEY_BYTES);
    assert!(matches!(
        cache
            .fetch_or_compute(
                &test_database.paranoid_pool,
                [oversized_key_part.as_str()],
                || async {
                    Ok::<_, TestComputeError>(CachedProfile {
                        name: "bad".to_owned(),
                        login_count: 0,
                    })
                },
            )
            .await,
        Err(CoalescingCacheFetchError::Fleet(
            Error::InvalidCoalescingCacheKeyForValue { .. }
        ))
    ));
    assert!(matches!(
        cache
            .set(
                &test_database.paranoid_pool,
                [oversized_key_part.as_str()],
                CachedProfile {
                    name: "bad".to_owned(),
                    login_count: 0,
                },
            )
            .await,
        Err(Error::InvalidCoalescingCacheKeyForValue { .. })
    ));
    assert!(matches!(
        cache
            .invalidate(&test_database.paranoid_pool, [oversized_key_part.as_str()])
            .await,
        Err(Error::InvalidCoalescingCacheKeyForValue { .. })
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
