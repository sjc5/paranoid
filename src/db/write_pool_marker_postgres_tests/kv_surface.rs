use super::*;

pub(super) async fn exercise_kv_public_db_handle_surface(pool: &WritePool, store: &KvStore) {
    let read_pool: &crate::db::Pool = pool;
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
