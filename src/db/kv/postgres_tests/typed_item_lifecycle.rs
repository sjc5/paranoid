use super::*;

#[tokio::test]
async fn kv_item_ttl_uses_statement_time_and_touch_does_not_extend_expiration() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "ttl"]).expect("prefix"),
    );
    let payload = TestKvPayload {
        label: "ttl".to_owned(),
        count: 1,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut delayed_transaction = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin delayed transaction");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    item.set_in_current_transaction(
        &mut delayed_transaction,
        ["statement-time"],
        &payload,
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set after transaction has been open");
    delayed_transaction
        .commit()
        .await
        .expect("commit delayed transaction");
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["statement-time"])
            .await
            .expect("statement-time value should still be live"),
        payload
    );

    item.set(
        &test_database.paranoid_pool,
        ["no-expiration"],
        &payload,
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set expiring value");
    item.set_ttl(
        &test_database.paranoid_pool,
        ["no-expiration"],
        KvTtl::no_expiration(),
    )
    .await
    .expect("remove expiration");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["no-expiration"])
            .await
            .expect("no-expiration value should still be live"),
        payload
    );

    item.set(
        &test_database.paranoid_pool,
        ["touch"],
        &payload,
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set touch value");
    tokio::time::sleep(Duration::from_millis(200)).await;
    item.touch(&test_database.paranoid_pool, ["touch"])
        .await
        .expect("touch");
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["touch"]).await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_delete_entire_namespace_atomically_includes_expired_rows_and_preserves_other_prefixes()
 {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item_a = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "delete-namespace-a"]).expect("prefix"),
    );
    let item_b = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "delete-namespace-b"]).expect("prefix"),
    );
    let payload = TestKvPayload {
        label: "value".to_owned(),
        count: 1,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    item_a
        .set(
            &test_database.paranoid_pool,
            ["live"],
            &payload,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set live a");
    item_a
        .set(
            &test_database.paranoid_pool,
            ["expired"],
            &payload,
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set expiring a");
    item_b
        .set(
            &test_database.paranoid_pool,
            ["live"],
            &payload,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set live b");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert_eq!(
        item_a
            .count(&test_database.paranoid_pool)
            .await
            .expect("count live a"),
        1
    );
    assert_eq!(
        item_a
            .delete_entire_namespace_atomically(&test_database.paranoid_pool)
            .await
            .expect("delete a namespace"),
        2
    );
    assert_eq!(
        item_b
            .get(&test_database.paranoid_pool, ["live"])
            .await
            .expect("other prefix should survive"),
        payload
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_prefix_and_namespace_deletes_are_transactional() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let raw_prefix = KvKeyPrefix::from_parts(["tx-delete", "raw"]).expect("prefix");
    let raw_a = KvKey::from_prefix_and_parts(&raw_prefix, ["a"]).expect("key");
    let raw_b = KvKey::from_prefix_and_parts(&raw_prefix, ["b"]).expect("key");
    let other_key = KvKey::from_parts(["tx-delete", "other"]).expect("key");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["tx-delete", "item"]).expect("prefix"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for key in [&raw_a, &raw_b] {
        store
            .set_bytes(
                &test_database.paranoid_pool,
                key,
                b"raw",
                KvTtl::no_expiration(),
            )
            .await
            .expect("set raw key");
    }
    for (suffix, count) in [("a", 1), ("b", 2)] {
        item.set(
            &test_database.paranoid_pool,
            [suffix],
            &TestKvPayload {
                label: suffix.to_owned(),
                count,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("set item key");
    }
    item.set(
        &test_database.paranoid_pool,
        ["expired"],
        &TestKvPayload {
            label: "expired".to_owned(),
            count: 3,
        },
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set expiring item key");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &other_key,
            b"other",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set other key");
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback tx");
    assert_eq!(
        store
            .delete_keys_with_prefix_once_in_current_transaction(&mut rollback_tx, &raw_prefix, 10)
            .await
            .expect("delete raw prefix in tx"),
        2
    );
    assert_eq!(
        store
            .count_live_keys_with_prefix_in_current_transaction(&mut rollback_tx, &raw_prefix)
            .await
            .expect("count raw prefix in tx"),
        0
    );
    rollback_tx.rollback().await.expect("rollback raw delete");
    assert_eq!(
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &raw_prefix)
            .await
            .expect("count raw after rollback"),
        2
    );

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit tx");
    assert_eq!(
        item.delete_entire_namespace_in_current_transaction(&mut commit_tx)
            .await
            .expect("delete namespace in tx"),
        3
    );
    assert_eq!(
        item.count_in_current_transaction(&mut commit_tx)
            .await
            .expect("count item namespace in tx"),
        0
    );
    assert_eq!(
        store
            .count_live_keys_with_prefix_in_current_transaction(&mut commit_tx, &raw_prefix)
            .await
            .expect("count raw prefix in commit tx"),
        2
    );
    commit_tx.commit().await.expect("commit namespace delete");

    assert_eq!(
        item.count(&test_database.paranoid_pool)
            .await
            .expect("count item after commit"),
        0
    );
    assert_eq!(
        item.delete_entire_namespace_atomically(&test_database.paranoid_pool)
            .await
            .expect("delete empty namespace"),
        0
    );
    assert_eq!(
        store
            .count_live_keys_with_prefix(&test_database.paranoid_pool, &raw_prefix)
            .await
            .expect("count raw after commit"),
        2
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
