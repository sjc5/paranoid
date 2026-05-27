use super::*;

#[tokio::test]
async fn kv_delete_expired_until_empty_emits_one_delete_operation_per_batch() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres KV operation-count test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

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

    for suffix in ["a", "b", "c"] {
        let key = Key::from_parts(["operation-count", "delete-expired", suffix]).expect("key");
        store
            .set_bytes(&pool, &key, b"expired", Ttl::no_expiration())
            .await
            .expect("set setup key");
        store
            .expire_key(&pool, &key)
            .await
            .expect("expire setup key");
    }

    assert_eq!(
        store
            .delete_expired_keys_until_empty_with_delay_between_batches(
                &observed_pool,
                2,
                Duration::ZERO,
            )
            .await
            .expect("delete expired keys until empty"),
        3
    );
    let delete_batch_record = DatabaseOperationRecord {
        kind: DatabaseOperationKind::Execute,
        label: KV_OPERATION_DELETE_EXPIRED_KEYS_ONCE,
        statement: Some(store.queries.delete_expired_keys_once.clone()),
    };
    let mut expected_records = transaction_records(delete_batch_record.clone());
    expected_records.extend(transaction_records(delete_batch_record));
    assert_eq!(observer.records(), expected_records);

    drop_test_table(&sqlx_pool, &table_name).await;
}

#[tokio::test]
async fn kv_in_current_transaction_operations_emit_only_inner_database_operation_records() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres KV operation-count test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let store =
        Store::new(StoreConfig::new(table_name.clone()).expect("kv config")).expect("kv store");
    let item = Item::<String>::new_plain(
        store.clone(),
        KeyPrefix::from_parts(["operation-count", "tx-item"]).expect("tx item prefix"),
    );
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_test_table(&sqlx_pool, &table_name).await;
    store
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate KV schema");
    observer.clear();

    let mut tx = observed_pool
        .begin_transaction()
        .await
        .expect("begin caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::BeginTransaction,
            label: "db.begin_transaction",
            statement: None,
        }]
    );
    observer.clear();

    let raw_key = Key::from_parts(["operation-count", "tx", "raw"]).expect("raw key");
    store
        .set_bytes_in_current_transaction(&mut tx, &raw_key, b"raw", Ttl::no_expiration())
        .await
        .expect("set raw bytes in caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_BYTES,
            statement: Some(store.queries.set_bytes_no_expiration.clone()),
        }]
    );
    observer.clear();

    assert_eq!(
        store
            .get_bytes_in_current_transaction(&mut tx, &raw_key)
            .await
            .expect("get raw bytes in caller transaction"),
        b"raw"
    );
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        }]
    );
    observer.clear();

    item.set_in_current_transaction::<&str, _>(
        &mut tx,
        ["typed"],
        &"value".to_owned(),
        Ttl::no_expiration(),
    )
    .await
    .expect("set typed item in caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_BYTES,
            statement: Some(store.queries.set_bytes_no_expiration.clone()),
        }]
    );
    observer.clear();

    assert_eq!(
        item.get_in_current_transaction::<&str, _>(&mut tx, ["typed"])
            .await
            .expect("get typed item in caller transaction"),
        "value"
    );
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        }]
    );
    observer.clear();

    let atomic_key = Key::from_parts(["operation-count", "tx", "atomic"]).expect("atomic key");
    store
        .mutate_key_atomically_in_current_transaction(&mut tx, &atomic_key, |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, Error>(AtomicMutation::SetBytes {
                value: b"atomic".to_vec(),
                ttl: Ttl::no_expiration(),
            })
        })
        .await
        .expect("mutate atomically in caller transaction");
    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOptional,
                label: KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                statement: Some(store.queries.lock_key_for_atomic_mutation.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                statement: Some(
                    store
                        .queries
                        .update_key_value_no_expiration_for_atomic_mutation
                        .clone(),
                ),
            },
        ]
    );
    observer.clear();

    tx.commit().await.expect("commit caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::CommitTransaction,
            label: "db.tx.commit",
            statement: None,
        }]
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}
