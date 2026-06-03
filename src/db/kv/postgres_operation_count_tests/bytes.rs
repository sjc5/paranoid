use super::*;

#[tokio::test]
async fn kv_set_and_get_bytes_emit_exact_database_operation_records() {
    let database_url = standard_test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let store =
        Store::new(StoreConfig::new(table_name.clone()).expect("kv config")).expect("kv store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_test_table(&sqlx_pool, &table_name).await;
    store
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate KV schema");
    observer.clear();

    let key = Key::from_parts(["operation-count", "basic"]).expect("key");
    store
        .set_bytes(&observed_pool, &key, b"value", Ttl::no_expiration())
        .await
        .expect("set bytes");

    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::BeginTransaction,
                label: "db.begin_transaction",
                statement: None,
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: KV_OPERATION_SET_BYTES,
                statement: Some(store.queries.set_bytes_no_expiration.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::CommitTransaction,
                label: "db.tx.commit",
                statement: None,
            },
        ]
    );
    observer.clear();

    let value = store
        .get_bytes(&observed_pool, &key)
        .await
        .expect("get bytes");
    assert_eq!(value, b"value");
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        })
    );

    observer.clear();
    let missing_key = Key::from_parts(["operation-count", "missing"]).expect("missing key");
    let err = store
        .get_bytes(&observed_pool, &missing_key)
        .await
        .expect_err("missing key");
    assert!(matches!(err, Error::KeyNotFound));
    assert_eq!(
        observer.records(),
        failed_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        })
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}
#[tokio::test]
async fn kv_common_store_operations_emit_exact_database_operation_records() {
    let database_url = standard_test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let store =
        Store::new(StoreConfig::new(table_name.clone()).expect("kv config")).expect("kv store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_test_table(&sqlx_pool, &table_name).await;
    store
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate KV schema");
    observer.clear();

    let prefix = KeyPrefix::from_parts(["operation-count", "common"]).expect("prefix");
    let key_a = Key::from_prefix_and_parts(&prefix, ["a"]).expect("key a");
    let key_b = Key::from_prefix_and_parts(&prefix, ["b"]).expect("key b");
    let key_c = Key::from_prefix_and_parts(&prefix, ["c"]).expect("key c");

    let entries = vec![
        BytesSetEntry::new(key_a.clone(), b"a".to_vec()),
        BytesSetEntry::new(key_b.clone(), b"b".to_vec()),
    ];
    store
        .set_bytes_multi(&observed_pool, &entries, Ttl::no_expiration())
        .await
        .expect("set bytes multi");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_BYTES_MULTI,
            statement: Some(store.queries.set_bytes_multi_no_expiration.clone()),
        })
    );
    observer.clear();

    let multi_values = store
        .get_bytes_multi(
            &observed_pool,
            &[key_a.clone(), key_b.clone(), key_c.clone()],
        )
        .await
        .expect("get bytes multi");
    assert_eq!(
        multi_values,
        vec![Some(b"a".to_vec()), Some(b"b".to_vec()), None]
    );
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchAll,
            label: KV_OPERATION_GET_BYTES_MULTI,
            statement: Some(store.queries.get_bytes_multi.clone()),
        })
    );
    observer.clear();

    store
        .set_bytes_and_return_database_timestamp(&observed_pool, &key_c, b"c", Ttl::no_expiration())
        .await
        .expect("set bytes and timestamp");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: KV_OPERATION_SET_BYTES_RETURNING_DATABASE_TIMESTAMP,
            statement: Some(
                store
                    .queries
                    .set_bytes_no_expiration_returning_database_timestamp
                    .clone()
            ),
        })
    );
    observer.clear();

    let timestamped_value = store
        .get_bytes_and_return_database_timestamp(&observed_pool, &key_c)
        .await
        .expect("get bytes and timestamp");
    assert_eq!(timestamped_value.value, b"c");
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
            statement: Some(store.queries.get_bytes_returning_database_timestamp.clone()),
        })
    );
    observer.clear();

    let missing_key = Key::from_prefix_and_parts(&prefix, ["missing"]).expect("missing key");
    assert!(
        store
            .set_bytes_if_not_exists(
                &observed_pool,
                &missing_key,
                b"missing",
                Ttl::no_expiration()
            )
            .await
            .expect("set if not exists")
    );
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_SET_BYTES_IF_NOT_EXISTS,
            statement: Some(store.queries.set_bytes_if_not_exists_no_expiration.clone()),
        })
    );
    observer.clear();

    let existing_result = store
        .set_bytes_if_not_exists_and_return_database_timestamp(
            &observed_pool,
            &missing_key,
            b"ignored",
            Ttl::no_expiration(),
        )
        .await
        .expect("set if not exists returning timestamp");
    assert!(!existing_result.was_set);
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_SET_BYTES_IF_NOT_EXISTS_RETURNING_DATABASE_TIMESTAMP,
            statement: Some(
                store
                    .queries
                    .set_bytes_if_not_exists_no_expiration_returning_database_timestamp
                    .clone()
            ),
        })
    );
    observer.clear();

    assert!(
        store
            .check_key_exists(&observed_pool, &missing_key)
            .await
            .expect("check key exists")
    );
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: KV_OPERATION_CHECK_KEY_EXISTS,
            statement: Some(store.queries.check_key_exists.clone()),
        })
    );
    observer.clear();

    store
        .touch_key(&observed_pool, &missing_key)
        .await
        .expect("touch key");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_TOUCH_KEY,
            statement: Some(store.queries.touch_key.clone()),
        })
    );
    observer.clear();

    store
        .set_key_ttl(&observed_pool, &missing_key, Ttl::no_expiration())
        .await
        .expect("set key ttl");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_KEY_TTL,
            statement: Some(store.queries.set_key_ttl_no_expiration.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        store
            .count_live_keys_with_prefix(&observed_pool, &prefix)
            .await
            .expect("count live keys"),
        4
    );
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOne,
            label: KV_OPERATION_COUNT_LIVE_KEYS_WITH_PREFIX,
            statement: Some(store.queries.count_live_keys_with_prefix.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        store
            .scan_bytes_with_prefix(&observed_pool, &prefix, None, 10)
            .await
            .expect("scan bytes")
            .len(),
        4
    );
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchAll,
            label: KV_OPERATION_SCAN_BYTES_WITH_PREFIX,
            statement: Some(store.queries.scan_bytes_with_prefix.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        store
            .scan_keys_with_prefix(&observed_pool, &prefix, None, 10)
            .await
            .expect("scan keys")
            .len(),
        4
    );
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchAll,
            label: KV_OPERATION_SCAN_KEYS_WITH_PREFIX,
            statement: Some(store.queries.scan_keys_with_prefix.clone()),
        })
    );
    observer.clear();

    store
        .expire_key(&observed_pool, &missing_key)
        .await
        .expect("expire key");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_EXPIRE_KEY,
            statement: Some(store.queries.expire_key.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        store
            .delete_expired_keys_once(&observed_pool, 10)
            .await
            .expect("delete expired keys once"),
        1
    );
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_DELETE_EXPIRED_KEYS_ONCE,
            statement: Some(store.queries.delete_expired_keys_once.clone()),
        })
    );
    observer.clear();

    store
        .delete_key(&observed_pool, &key_c)
        .await
        .expect("delete key");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_DELETE_KEY,
            statement: Some(store.queries.delete_key.clone()),
        })
    );
    observer.clear();

    let slot_key = Key::from_prefix_and_parts(&prefix, ["slot"]).expect("slot key");
    assert_eq!(
        store
            .acquire_slot_bytes(
                &observed_pool,
                std::slice::from_ref(&slot_key),
                b"slot",
                Ttl::expires_after(Duration::from_secs(5)).expect("ttl"),
            )
            .await
            .expect("acquire slot"),
        Some(slot_key)
    );
    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::BeginTransaction,
                label: "db.begin_transaction",
                statement: None,
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
                statement: Some(store.queries.ensure_slot_keys_exist.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOptional,
                label: KV_OPERATION_ACQUIRE_SLOT,
                statement: Some(store.queries.acquire_slot.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::CommitTransaction,
                label: "db.tx.commit",
                statement: None,
            },
        ]
    );
    observer.clear();

    assert_eq!(
        store
            .delete_keys_with_prefix_once(&observed_pool, &prefix, 10)
            .await
            .expect("delete keys with prefix"),
        3
    );
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_DELETE_KEYS_WITH_PREFIX_ONCE,
            statement: Some(store.queries.delete_keys_with_prefix_once.clone()),
        })
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}
