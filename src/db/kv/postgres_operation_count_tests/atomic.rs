use super::*;

#[tokio::test]
async fn kv_atomic_mutations_emit_exact_database_operation_records() {
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

    let key = Key::from_parts(["operation-count", "atomic"]).expect("key");
    store
        .mutate_key_atomically(&observed_pool, &key, |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, Error>(AtomicMutation::SetBytes {
                value: b"first".to_vec(),
                ttl: Ttl::no_expiration(),
            })
        })
        .await
        .expect("insert with atomic mutation");
    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::BeginTransaction,
                label: "db.begin_transaction",
                statement: None,
            },
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
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::CommitTransaction,
                label: "db.tx.commit",
                statement: None,
            },
        ]
    );

    observer.clear();
    store
        .mutate_key_atomically(&observed_pool, &key, |current| {
            assert_eq!(current.live_value(), Some(b"first".as_slice()));
            Ok::<_, Error>(AtomicMutation::SetBytesPreservingExpiration {
                value: b"second".to_vec(),
            })
        })
        .await
        .expect("update preserving expiration with atomic mutation");
    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::BeginTransaction,
                label: "db.begin_transaction",
                statement: None,
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOptional,
                label: KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                statement: Some(store.queries.lock_key_for_atomic_mutation.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: KV_OPERATION_SET_BYTES_PRESERVING_EXPIRATION_FOR_ATOMIC_MUTATION,
                statement: Some(
                    store
                        .queries
                        .update_key_value_preserving_expiration_for_atomic_mutation
                        .clone(),
                ),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::CommitTransaction,
                label: "db.tx.commit",
                statement: None,
            },
        ]
    );

    observer.clear();
    store
        .mutate_key_atomically(&observed_pool, &key, |current| {
            assert_eq!(current.live_value(), Some(b"second".as_slice()));
            Ok::<_, Error>(AtomicMutation::Delete)
        })
        .await
        .expect("delete with atomic mutation");
    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::BeginTransaction,
                label: "db.begin_transaction",
                statement: None,
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOptional,
                label: KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                statement: Some(store.queries.lock_key_for_atomic_mutation.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION,
                statement: Some(store.queries.delete_key_for_atomic_mutation.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::CommitTransaction,
                label: "db.tx.commit",
                statement: None,
            },
        ]
    );

    observer.clear();
    let error_key = Key::from_parts(["operation-count", "atomic-error"]).expect("error key");
    let callback_error = store
        .mutate_key_atomically(&observed_pool, &error_key, |current| {
            assert_eq!(current.live_value(), None);
            Err::<AtomicMutation, _>(Error::KeyNotFound)
        })
        .await
        .expect_err("callback error should be returned");
    assert!(matches!(callback_error, Error::KeyNotFound));
    assert_eq!(
        observer.records(),
        vec![
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::BeginTransaction,
                label: "db.begin_transaction",
                statement: None,
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOptional,
                label: KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                statement: Some(store.queries.lock_key_for_atomic_mutation.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::RollbackTransaction,
                label: "db.tx.rollback",
                statement: None,
            },
        ]
    );
    assert!(matches!(
        store.get_bytes(&pool, &error_key).await,
        Err(Error::KeyNotFound)
    ));

    drop_test_table(&sqlx_pool, &table_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kv_typed_item_atomic_operations_emit_exact_database_operation_records() {
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
        KeyPrefix::from_parts(["operation-count", "item-atomic"]).expect("item atomic prefix"),
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

    let initialized = item
        .get_or_init::<&str, _>(
            &observed_pool,
            ["initialized"],
            "first".to_owned(),
            Ttl::no_expiration(),
        )
        .await
        .expect("get or init absent item");
    assert_eq!(initialized.value, "first");
    assert!(initialized.initialized);
    assert_eq!(
        observer.records(),
        transaction_records_many([
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
        ])
    );
    observer.clear();

    let existing = item
        .get_or_init::<&str, _>(
            &observed_pool,
            ["initialized"],
            "ignored".to_owned(),
            Ttl::no_expiration(),
        )
        .await
        .expect("get or init existing item");
    assert_eq!(existing.value, "first");
    assert!(!existing.initialized);
    assert_eq!(
        observer.records(),
        transaction_records_many([DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            statement: Some(store.queries.lock_key_for_atomic_mutation.clone()),
        }])
    );
    observer.clear();

    let replaced = item
        .mutate_live_atomically::<&str, _, _, Error>(&observed_pool, ["initialized"], |current| {
            assert_eq!(current.live_value(), "first");
            Ok(ItemAtomicMutation::SetValuePreservingExpiration {
                value: "second".to_owned(),
            })
        })
        .await
        .expect("mutate live item preserving expiration");
    assert_eq!(replaced.previous_live_value, "first");
    assert_eq!(
        replaced.outcome,
        AtomicMutationOutcome::SetBytesPreservingExpiration
    );
    assert_eq!(
        observer.records(),
        transaction_records_many([
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::FetchOptional,
                label: KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                statement: Some(store.queries.lock_key_for_atomic_mutation.clone()),
            },
            DatabaseOperationRecord {
                kind: DatabaseOperationKind::Execute,
                label: KV_OPERATION_SET_BYTES_PRESERVING_EXPIRATION_FOR_ATOMIC_MUTATION,
                statement: Some(
                    store
                        .queries
                        .update_key_value_preserving_expiration_for_atomic_mutation
                        .clone(),
                ),
            },
        ])
    );
    observer.clear();

    let live_or_init = item
        .mutate_live_or_insert_initial_value_atomically::<&str, _, _, _, Error>(
            &observed_pool,
            ["live-or-init"],
            |_database_timestamp| Ok(("initial".to_owned(), Ttl::no_expiration())),
            |current| {
                assert_eq!(current.live_value(), "initial");
                Ok(ItemAtomicMutation::KeepExisting)
            },
        )
        .await
        .expect("mutate live or insert item");
    assert!(live_or_init.initialized);
    assert_eq!(live_or_init.live_value_seen_by_callback, "initial");
    assert_eq!(live_or_init.outcome, AtomicMutationOutcome::SetBytes);
    assert_eq!(
        observer.records(),
        transaction_records_many([
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
        ])
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}
