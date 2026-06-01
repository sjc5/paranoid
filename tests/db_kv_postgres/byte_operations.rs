use super::*;

#[tokio::test]
async fn kv_basic_byte_operations_round_trip_and_delete() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["account", "session"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"session-bytes",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set");

    let stored_without_expiration = fetch_key_has_null_expiration(
        &test_database.sqlx_pool,
        &test_database.config.table_name,
        &key,
    )
    .await;
    assert!(stored_without_expiration);

    let got = store
        .get_bytes(&test_database.paranoid_pool, &key)
        .await
        .expect("get");
    assert_eq!(got, b"session-bytes");

    assert!(
        store
            .check_key_exists(&test_database.paranoid_pool, &key)
            .await
            .expect("exists")
    );

    store
        .delete_key(&test_database.paranoid_pool, &key)
        .await
        .expect("delete");

    assert!(
        !store
            .check_key_exists(&test_database.paranoid_pool, &key)
            .await
            .expect("exists after delete")
    );
    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_multi_byte_operations_round_trip_in_input_order() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key_a = KvKey::from_parts(["multi", "a"]).expect("key");
    let key_b = KvKey::from_parts(["multi", "b"]).expect("key");
    let key_c = KvKey::from_parts(["multi", "c"]).expect("key");
    let missing = KvKey::from_parts(["multi", "missing"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    assert_eq!(
        store
            .get_bytes_multi(&test_database.paranoid_pool, &[])
            .await
            .expect("empty get multi"),
        Vec::<Option<Vec<u8>>>::new()
    );
    store
        .set_bytes_multi(
            &test_database.paranoid_pool,
            &[],
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("empty set multi");

    store
        .set_bytes_multi(
            &test_database.paranoid_pool,
            &[
                KvBytesSetEntry::new(key_b.clone(), b"b".to_vec()),
                KvBytesSetEntry::new(key_a.clone(), b"a".to_vec()),
                KvBytesSetEntry::new(key_c.clone(), b"c".to_vec()),
            ],
            KvTtl::no_expiration(),
        )
        .await
        .expect("set multi");
    store
        .expire_key(&test_database.paranoid_pool, &key_c)
        .await
        .expect("expire c");

    assert_eq!(
        store
            .get_bytes_multi(
                &test_database.paranoid_pool,
                &[key_a.clone(), missing.clone(), key_b.clone(), key_c.clone()],
            )
            .await
            .expect("get multi"),
        vec![Some(b"a".to_vec()), None, Some(b"b".to_vec()), None]
    );

    store
        .set_bytes_multi(
            &test_database.paranoid_pool,
            &[
                KvBytesSetEntry::new(key_a.clone(), b"new-a".to_vec()),
                KvBytesSetEntry::new(missing.clone(), b"new-missing".to_vec()),
            ],
            KvTtl::no_expiration(),
        )
        .await
        .expect("overwrite multi");

    assert_eq!(
        store
            .get_bytes_multi(
                &test_database.paranoid_pool,
                &[missing.clone(), key_a.clone()]
            )
            .await
            .expect("get overwritten"),
        vec![Some(b"new-missing".to_vec()), Some(b"new-a".to_vec())]
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_multi_byte_operations_reject_duplicate_and_oversized_inputs() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["multi", "duplicate"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    assert!(matches!(
        store
            .get_bytes_multi(&test_database.paranoid_pool, &[key.clone(), key.clone()])
            .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));
    assert!(matches!(
        store
            .set_bytes_multi(
                &test_database.paranoid_pool,
                &[
                    KvBytesSetEntry::new(key.clone(), b"first".to_vec()),
                    KvBytesSetEntry::new(key.clone(), b"second".to_vec()),
                ],
                KvTtl::no_expiration(),
            )
            .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));

    let too_many_keys = (0..=MAX_KV_GET_MULTI_KEYS)
        .map(|index| KvKey::from_parts([format!("too-many-get-{index}")]).expect("key"))
        .collect::<Vec<_>>();
    assert!(matches!(
        store
            .get_bytes_multi(&test_database.paranoid_pool, &too_many_keys)
            .await,
        Err(KvError::GetMultiKeyCountTooLarge { .. })
    ));

    let too_many_entries = (0..=MAX_KV_SET_MULTI_ENTRIES)
        .map(|index| {
            KvBytesSetEntry::new(
                KvKey::from_parts([format!("too-many-set-{index}")]).expect("key"),
                Vec::new(),
            )
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        store
            .set_bytes_multi(
                &test_database.paranoid_pool,
                &too_many_entries,
                KvTtl::no_expiration(),
            )
            .await,
        Err(KvError::SetMultiEntryCountTooLarge { .. })
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_acquire_slot_claims_candidates_once_and_reuses_expired_slots() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["slots"]).expect("prefix");
    let slot_a = KvKey::from_prefix_and_parts(&prefix, ["a"]).expect("slot");
    let slot_b = KvKey::from_prefix_and_parts(&prefix, ["b"]).expect("slot");
    let slot_c = KvKey::from_prefix_and_parts(&prefix, ["c"]).expect("slot");
    let candidates = vec![slot_a.clone(), slot_b.clone(), slot_c.clone()];

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut acquired = HashSet::new();
    for index in 0..candidates.len() {
        let acquired_slot = store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                &candidates,
                format!("holder-{index}").as_bytes(),
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await
            .expect("acquire slot")
            .expect("slot should be available");
        assert!(
            candidates.contains(&acquired_slot),
            "unexpected slot {acquired_slot:?}"
        );
        assert!(
            acquired.insert(acquired_slot),
            "slot was acquired more than once"
        );
    }

    assert_eq!(
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                &candidates,
                b"holder-after-full",
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await
            .expect("acquire full slot set"),
        None
    );

    let reacquirable_slot = acquired.iter().next().expect("one acquired slot").clone();
    store
        .expire_key(&test_database.paranoid_pool, &reacquirable_slot)
        .await
        .expect("expire slot");
    let reacquired_slot = store
        .acquire_slot_bytes(
            &test_database.paranoid_pool,
            &candidates,
            b"replacement-holder",
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await
        .expect("reacquire slot")
        .expect("expired slot should be available");
    assert_eq!(reacquired_slot, reacquirable_slot);
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &reacquired_slot)
            .await
            .expect("get reacquired slot"),
        b"replacement-holder"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_acquire_slot_rejects_invalid_inputs_without_creating_rows() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["slot-validation"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    assert_eq!(
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                &[],
                b"holder",
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await
            .expect("empty acquire"),
        None
    );
    assert!(matches!(
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                &[],
                b"holder",
                KvTtl::no_expiration(),
            )
            .await,
        Err(KvError::TtlNoExpirationNotAllowed)
    ));
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );

    assert!(matches!(
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                std::slice::from_ref(&key),
                b"holder",
                KvTtl::no_expiration(),
            )
            .await,
        Err(KvError::TtlNoExpirationNotAllowed)
    ));
    assert!(matches!(
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                &[key.clone(), key.clone()],
                b"holder",
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));

    let too_many_candidates = (0..=MAX_KV_ACQUIRE_SLOT_CANDIDATES)
        .map(|index| KvKey::from_parts([format!("too-many-slot-{index}")]).expect("key"))
        .collect::<Vec<_>>();
    assert!(matches!(
        store
            .acquire_slot_bytes(
                &test_database.paranoid_pool,
                &too_many_candidates,
                b"holder",
                KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
            )
            .await,
        Err(KvError::AcquireSlotCandidateCountTooLarge { .. })
    ));

    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_acquire_slot_composes_inside_transaction_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["slot-transaction"]).expect("key");

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
    let acquired_slot = store
        .acquire_slot_bytes_in_current_transaction(
            &mut tx,
            std::slice::from_ref(&key),
            b"inside",
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await
        .expect("acquire in tx")
        .expect("slot should be available");
    assert_eq!(acquired_slot, key);
    assert_eq!(
        store
            .get_bytes_in_current_transaction(&mut tx, &key)
            .await
            .expect("get in tx"),
        b"inside"
    );
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_acquire_slot_allows_only_one_concurrent_holder_per_slot() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["slot-concurrent"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut handles = Vec::new();
    for index in 0..20 {
        let task_store = store.clone();
        let task_pool = test_database.paranoid_pool.clone();
        let task_key = key.clone();
        handles.push(tokio::spawn(async move {
            task_store
                .acquire_slot_bytes(
                    &task_pool,
                    &[task_key],
                    format!("holder-{index}").as_bytes(),
                    KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
                )
                .await
                .expect("concurrent acquire")
        }));
    }

    let mut success_count = 0;
    for handle in handles {
        if handle.await.expect("join").is_some() {
            success_count += 1;
        }
    }
    assert_eq!(success_count, 1);

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_expired_keys_are_treated_as_nonexistent() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["otp", "attempt"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"short-lived",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set with ttl");

    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("immediate get"),
        b"short-lived"
    );

    std::thread::sleep(Duration::from_millis(1200));

    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(
        !store
            .check_key_exists(&test_database.paranoid_pool, &key)
            .await
            .expect("exists after ttl")
    );
    assert!(matches!(
        store.delete_key(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"replacement",
            KvTtl::no_expiration(),
        )
        .await
        .expect("replace expired");
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get replacement"),
        b"replacement"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_operations_can_compose_inside_current_transaction() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["transaction", "key"]).expect("key");

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
    store
        .set_bytes_in_current_transaction(&mut tx, &key, b"inside", KvTtl::no_expiration())
        .await
        .expect("set in tx");
    assert_eq!(
        store
            .get_bytes_in_current_transaction(&mut tx, &key)
            .await
            .expect("get in tx"),
        b"inside"
    );
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_uncommitted_transaction_drop_rolls_back_and_returns_connection() {
    let database_url = test_database_url();

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let key = KvKey::from_parts(["tx", "drop-rollback"]).expect("key");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");

    let mut tx = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin transaction");
    store
        .set_bytes_in_current_transaction(&mut tx, &key, b"uncommitted", KvTtl::no_expiration())
        .await
        .expect("set in tx");
    assert_eq!(
        store
            .get_bytes_in_current_transaction(&mut tx, &key)
            .await
            .expect("read in tx"),
        b"uncommitted"
    );

    drop(tx);

    assert!(matches!(
        store.get_bytes(&paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));
    assert_eq!(
        fetch_table_row_count(&sqlx_pool, &config.table_name).await,
        0
    );

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_transaction_drop_after_task_panic_rolls_back_uncommitted_write() {
    let database_url = test_database_url();

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = KvStoreConfig::new(unique_test_table_name()).expect("kv config");
    let store = KvStore::new(config.clone()).expect("kv store");
    let key = KvKey::from_parts(["tx", "panic-rollback"]).expect("key");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");

    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_key = key.clone();
    let join_error = tokio::spawn(async move {
        let mut tx = task_pool
            .begin_transaction()
            .await
            .expect("begin transaction");
        task_store
            .set_bytes_in_current_transaction(
                &mut tx,
                &task_key,
                b"should-roll-back",
                KvTtl::no_expiration(),
            )
            .await
            .expect("set in transaction");
        panic!("intentional panic after uncommitted KV write");
    })
    .await
    .expect_err("task should panic");
    assert!(join_error.is_panic());

    assert!(matches!(
        store.get_bytes(&paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));
    assert_eq!(
        fetch_table_row_count(&sqlx_pool, &config.table_name).await,
        0
    );

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn kv_set_bytes_if_not_exists_claims_absent_or_expired_keys_only() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["claim", "slot"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    assert!(
        store
            .set_bytes_if_not_exists(
                &test_database.paranoid_pool,
                &key,
                b"first",
                KvTtl::no_expiration(),
            )
            .await
            .expect("first claim")
    );
    assert!(
        !store
            .set_bytes_if_not_exists(
                &test_database.paranoid_pool,
                &key,
                b"second",
                KvTtl::no_expiration(),
            )
            .await
            .expect("second claim")
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get first"),
        b"first"
    );

    store
        .expire_key(&test_database.paranoid_pool, &key)
        .await
        .expect("expire");
    assert!(
        store
            .set_bytes_if_not_exists(
                &test_database.paranoid_pool,
                &key,
                b"replacement",
                KvTtl::no_expiration(),
            )
            .await
            .expect("claim expired")
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get replacement"),
        b"replacement"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_set_bytes_and_conditional_writes_return_database_timestamps() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let set_key = KvKey::from_parts(["timestamp", "set"]).expect("key");
    let claim_key = KvKey::from_parts(["timestamp", "claim"]).expect("key");
    let tx_key = KvKey::from_parts(["timestamp", "rolled-back"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let set_timestamp = store
        .set_bytes_and_return_database_timestamp(
            &test_database.paranoid_pool,
            &set_key,
            b"set",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set returning timestamp");
    let now_after_set = fetch_statement_timestamp_microseconds(&test_database.sqlx_pool).await;
    assert!(set_timestamp.as_i64() > 0);
    assert!(set_timestamp.as_i64() <= now_after_set);
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &set_key)
            .await
            .expect("get set value"),
        b"set"
    );
    let loaded_set = store
        .get_bytes_and_return_database_timestamp(&test_database.paranoid_pool, &set_key)
        .await
        .expect("get returning timestamp");
    assert_eq!(loaded_set.value, b"set");
    assert!(loaded_set.database_timestamp.as_i64() > 0);
    assert!(
        loaded_set.database_timestamp.as_i64()
            <= fetch_statement_timestamp_microseconds(&test_database.sqlx_pool).await
    );

    let first_claim = store
        .set_bytes_if_not_exists_and_return_database_timestamp(
            &test_database.paranoid_pool,
            &claim_key,
            b"first",
            KvTtl::no_expiration(),
        )
        .await
        .expect("first claim returning timestamp");
    let first_claim_timestamp = first_claim
        .database_timestamp
        .expect("successful claim timestamp");
    assert!(first_claim.was_set);
    assert!(first_claim_timestamp.as_i64() > 0);
    assert!(
        first_claim_timestamp.as_i64()
            <= fetch_statement_timestamp_microseconds(&test_database.sqlx_pool).await
    );

    let second_claim = store
        .set_bytes_if_not_exists_and_return_database_timestamp(
            &test_database.paranoid_pool,
            &claim_key,
            b"second",
            KvTtl::no_expiration(),
        )
        .await
        .expect("second claim returning timestamp");
    assert!(!second_claim.was_set);
    assert_eq!(second_claim.database_timestamp, None);
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &claim_key)
            .await
            .expect("claim still first"),
        b"first"
    );

    store
        .expire_key(&test_database.paranoid_pool, &claim_key)
        .await
        .expect("expire claim");
    let replacement_claim = store
        .set_bytes_if_not_exists_and_return_database_timestamp(
            &test_database.paranoid_pool,
            &claim_key,
            b"replacement",
            KvTtl::no_expiration(),
        )
        .await
        .expect("replacement claim returning timestamp");
    assert!(replacement_claim.was_set);
    assert!(
        replacement_claim
            .database_timestamp
            .expect("replacement timestamp")
            .as_i64()
            >= first_claim_timestamp.as_i64()
    );

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin timestamp tx");
    let tx_timestamp = store
        .set_bytes_and_return_database_timestamp_in_current_transaction(
            &mut tx,
            &tx_key,
            b"inside",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set timestamp in tx");
    assert!(tx_timestamp.as_i64() > 0);
    assert_eq!(
        store
            .get_bytes_in_current_transaction(&mut tx, &tx_key)
            .await
            .expect("read in tx"),
        b"inside"
    );
    tx.rollback().await.expect("rollback timestamp tx");
    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &tx_key).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_set_bytes_if_not_exists_allows_exactly_one_concurrent_claim() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["claim", "race"]).expect("key");
    let success_count = Arc::new(AtomicUsize::new(0));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let handles = (0..20)
        .map(|index| {
            let task_store = store.clone();
            let task_pool = test_database.paranoid_pool.clone();
            let task_key = key.clone();
            let task_success_count = Arc::clone(&success_count);
            tokio::spawn(async move {
                let was_set = task_store
                    .set_bytes_if_not_exists(
                        &task_pool,
                        &task_key,
                        format!("candidate-{index}").as_bytes(),
                        KvTtl::no_expiration(),
                    )
                    .await
                    .expect("set if not exists");
                if was_set {
                    task_success_count.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.await.expect("join set_if_not_exists task");
    }
    assert_eq!(success_count.load(Ordering::SeqCst), 1);
    let stored = store
        .get_bytes(&test_database.paranoid_pool, &key)
        .await
        .expect("stored value");
    assert!(
        String::from_utf8(stored)
            .expect("stored value utf8")
            .starts_with("candidate-")
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
