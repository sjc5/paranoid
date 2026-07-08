use super::*;

#[tokio::test]
async fn kv_typed_item_operations_emit_exact_database_operation_records() {
    let database_url = standard_test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let store =
        Store::new(StoreConfig::new(table_name.clone()).expect("kv config")).expect("kv store");
    let item = Item::<String>::new_plain(
        store.clone(),
        KeyPrefix::from_parts(["operation-count", "item"]).expect("item prefix"),
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

    item.set::<&str, _>(
        &observed_pool,
        ["alpha"],
        &"one".to_owned(),
        Ttl::no_expiration(),
    )
    .await
    .expect("set typed item");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_BYTES,
            statement: Some(store.queries.set_bytes_no_expiration.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        item.get::<&str, _>(&observed_pool, ["alpha"])
            .await
            .expect("get typed item"),
        "one"
    );
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        item.get_or_fallback::<&str, _>(&observed_pool, ["missing"], "fallback".to_owned())
            .await
            .expect("get typed fallback"),
        "fallback"
    );
    assert_eq!(
        observer.records(),
        failed_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        })
    );
    observer.clear();

    item.set_multi::<&str, _>(
        &observed_pool,
        &[["beta"], ["gamma"]],
        &["two".to_owned(), "three".to_owned()],
        Ttl::no_expiration(),
    )
    .await
    .expect("set typed item multi");
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_BYTES_MULTI,
            statement: Some(store.queries.set_bytes_multi_no_expiration.clone()),
        })
    );
    observer.clear();

    assert_eq!(
        item.get_multi::<&str, _>(&observed_pool, &[["alpha"], ["beta"], ["absent"]])
            .await
            .expect("get typed item multi"),
        vec![Some("one".to_owned()), Some("two".to_owned()), None]
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

    assert_eq!(item.count(&observed_pool).await.expect("count items"), 3);
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
        item.scan(&observed_pool, None, 10)
            .await
            .expect("scan typed items")
            .len(),
        3
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
        item.scan_key_suffixes(&observed_pool, None, 10)
            .await
            .expect("get typed key suffixes"),
        vec!["alpha", "beta", "gamma"]
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

    assert_eq!(
        item.delete_entire_namespace_atomically(&observed_pool)
            .await
            .expect("delete typed namespace"),
        3
    );
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_DELETE_NAMESPACE_KEYS_WITH_PREFIX_ONCE,
            statement: Some(store.queries.delete_namespace_keys_with_prefix_once.clone()),
        })
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}
