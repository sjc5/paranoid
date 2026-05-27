use super::*;

#[tokio::test]
async fn kv_item_suffixless_scan_pagination_and_cursor_validation_are_precise() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "suffixless"]).expect("prefix"),
    );
    let payload_suffixless = TestKvPayload {
        label: "suffixless".to_owned(),
        count: 0,
    };
    let payload_a = TestKvPayload {
        label: "a".to_owned(),
        count: 1,
    };
    let payload_b = TestKvPayload {
        label: "b".to_owned(),
        count: 2,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    item.set(
        &test_database.paranoid_pool,
        std::iter::empty::<&str>(),
        &payload_suffixless,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set suffixless key");
    item.set(
        &test_database.paranoid_pool,
        ["a"],
        &payload_a,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set a");
    item.set(
        &test_database.paranoid_pool,
        ["b"],
        &payload_b,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set b");

    assert_eq!(
        item.scan(&test_database.paranoid_pool, None, 1)
            .await
            .expect("scan from start"),
        vec![KvItemScannedValue {
            key_suffix: String::new(),
            value: payload_suffixless.clone(),
        }]
    );
    assert_eq!(
        item.scan(&test_database.paranoid_pool, Some(""), 1)
            .await
            .expect("scan after suffixless"),
        vec![KvItemScannedValue {
            key_suffix: "a".to_owned(),
            value: payload_a,
        }]
    );
    assert_eq!(
        item.scan_key_suffixes(&test_database.paranoid_pool, None, 2)
            .await
            .expect("suffixes from start"),
        vec![String::new(), "a".to_owned()]
    );
    assert_eq!(
        item.scan_key_suffixes(&test_database.paranoid_pool, Some(""), 2)
            .await
            .expect("suffixes after suffixless"),
        vec!["a".to_owned(), "b".to_owned()]
    );

    assert!(matches!(
        item.scan(&test_database.paranoid_pool, Some("bad\0cursor"), 10)
            .await,
        Err(KvError::KeyPartContainsNullByte)
    ));
    assert!(matches!(
        item.scan_key_suffixes(&test_database.paranoid_pool, Some("bad\0cursor"), 10)
            .await,
        Err(KvError::KeyPartContainsNullByte)
    ));
    let too_long_cursor = "x".repeat(MAX_KV_KEY_BYTES);
    assert!(matches!(
        item.scan(&test_database.paranoid_pool, Some(&too_long_cursor), 10)
            .await,
        Err(KvError::KeyTooLong { .. })
    ));
    assert!(matches!(
        item.scan_key_suffixes(&test_database.paranoid_pool, Some(&too_long_cursor), 10)
            .await,
        Err(KvError::KeyTooLong { .. })
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_multi_part_scan_cursors_page_by_full_persisted_suffix() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "scan-multipart"]).expect("prefix"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for (suffix_parts, count) in [
        (["user", "alice"], 1),
        (["user", "bob"], 2),
        (["user", "carol"], 3),
    ] {
        item.set(
            &test_database.paranoid_pool,
            suffix_parts,
            &TestKvPayload {
                label: suffix_parts.join("/"),
                count,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("set multi-part key");
    }

    let first_scan_page = item
        .scan(&test_database.paranoid_pool, None, 2)
        .await
        .expect("first scan page");
    assert_eq!(
        first_scan_page,
        vec![
            KvItemScannedValue {
                key_suffix: "user::alice".to_owned(),
                value: TestKvPayload {
                    label: "user/alice".to_owned(),
                    count: 1,
                },
            },
            KvItemScannedValue {
                key_suffix: "user::bob".to_owned(),
                value: TestKvPayload {
                    label: "user/bob".to_owned(),
                    count: 2,
                },
            },
        ]
    );

    assert_eq!(
        item.scan(
            &test_database.paranoid_pool,
            Some(&first_scan_page[1].key_suffix),
            2,
        )
        .await
        .expect("second scan page"),
        vec![KvItemScannedValue {
            key_suffix: "user::carol".to_owned(),
            value: TestKvPayload {
                label: "user/carol".to_owned(),
                count: 3,
            },
        }]
    );

    let first_suffix_page = item
        .scan_key_suffixes(&test_database.paranoid_pool, None, 2)
        .await
        .expect("first suffix page");
    assert_eq!(
        first_suffix_page,
        vec!["user::alice".to_owned(), "user::bob".to_owned()]
    );
    assert_eq!(
        item.scan_key_suffixes(&test_database.paranoid_pool, Some(&first_suffix_page[1]), 2,)
            .await
            .expect("second suffix page"),
        vec!["user::carol".to_owned()]
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
