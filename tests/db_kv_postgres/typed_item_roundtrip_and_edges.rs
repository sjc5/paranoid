use super::*;

#[tokio::test]
async fn kv_item_basic_lifecycle_type_round_trips_and_raw_bytes_match_go_invariants() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "basic"]).expect("prefix"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["missing"]).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(
        !item
            .check_exists(&test_database.paranoid_pool, ["key"])
            .await
            .expect("missing exists")
    );

    let first = TestKvPayload {
        label: "first".to_owned(),
        count: 1,
    };
    let second = TestKvPayload {
        label: "second".to_owned(),
        count: 2,
    };
    item.set(
        &test_database.paranoid_pool,
        ["key"],
        &first,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set first");
    item.set(
        &test_database.paranoid_pool,
        ["key"],
        &second,
        KvTtl::no_expiration(),
    )
    .await
    .expect("overwrite");
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["key"])
            .await
            .expect("get overwritten"),
        second
    );
    assert!(
        item.check_exists(&test_database.paranoid_pool, ["key"])
            .await
            .expect("existing exists")
    );

    item.delete(&test_database.paranoid_pool, ["key"])
        .await
        .expect("delete");
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["key"]).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(matches!(
        item.delete(&test_database.paranoid_pool, ["missing"]).await,
        Err(KvError::KeyNotFound)
    ));

    item.set(
        &test_database.paranoid_pool,
        ["expires"],
        &first,
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set expiring");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(
        item.delete(&test_database.paranoid_pool, ["expires"]).await,
        Err(KvError::KeyNotFound)
    ));
    assert!(
        !item
            .check_exists(&test_database.paranoid_pool, ["expires"])
            .await
            .expect("expired exists")
    );

    let vector_item = KvItem::<Vec<u32>>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "vector"]).expect("prefix"),
    );
    let vector_value = vec![1, 2, 3, 4, 5];
    vector_item
        .set(
            &test_database.paranoid_pool,
            ["key"],
            &vector_value,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set vector");
    assert_eq!(
        vector_item
            .get(&test_database.paranoid_pool, ["key"])
            .await
            .expect("get vector"),
        vector_value
    );

    let map_item = KvItem::<BTreeMap<String, u32>>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "map"]).expect("prefix"),
    );
    let map_value = BTreeMap::from([("alpha".to_owned(), 1), ("beta".to_owned(), 2)]);
    map_item
        .set(
            &test_database.paranoid_pool,
            ["key"],
            &map_value,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set map");
    assert_eq!(
        map_item
            .get(&test_database.paranoid_pool, ["key"])
            .await
            .expect("get map"),
        map_value
    );

    let raw_prefix = KvKeyPrefix::from_parts(["item", "raw"]).expect("prefix");
    let raw_item = KvItem::<PublicBytes>::new_plain(store.clone(), raw_prefix.clone());
    let raw_key = KvKey::from_prefix_and_parts(&raw_prefix, ["key"]).expect("raw key");
    let raw_value = PublicBytes::try_from(&[0x00, 0x01, 0x02, 0xff, 0xfe][..]).expect("raw bytes");
    raw_item
        .set(
            &test_database.paranoid_pool,
            ["key"],
            &raw_value,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set raw");
    assert_eq!(
        raw_item
            .get(&test_database.paranoid_pool, ["key"])
            .await
            .expect("get raw")
            .as_bytes(),
        raw_value.as_bytes()
    );
    assert_eq!(
        fetch_key_raw_value(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &raw_key
        )
        .await,
        raw_value.as_bytes()
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_bulk_and_scan_edges_follow_expected_semantics() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "bulk-scan"]).expect("prefix"),
    );
    let encrypted_keyset = test_kv_item_keyset();
    let encrypted_item = KvItem::<TestKvPayload>::new_encrypted(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "bulk-scan-encrypted"]).expect("prefix"),
        move || Ok(encrypted_keyset.clone()),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let empty_key_parts: Vec<Vec<&str>> = Vec::new();
    let empty_values: Vec<TestKvPayload> = Vec::new();
    assert_eq!(
        item.get_multi(&test_database.paranoid_pool, &empty_key_parts)
            .await
            .expect("empty get multi"),
        Vec::<Option<TestKvPayload>>::new()
    );
    item.set_multi(
        &test_database.paranoid_pool,
        &empty_key_parts,
        &empty_values,
        KvTtl::no_expiration(),
    )
    .await
    .expect("empty set multi");

    let keys = vec![vec!["a"], vec!["b"], vec!["missing"]];
    let initial_values = vec![
        TestKvPayload {
            label: "a".to_owned(),
            count: 1,
        },
        TestKvPayload {
            label: "b".to_owned(),
            count: 2,
        },
    ];
    item.set_multi(
        &test_database.paranoid_pool,
        &keys[..2],
        &initial_values,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set multi");
    assert_eq!(
        item.get_multi(&test_database.paranoid_pool, &keys)
            .await
            .expect("get multi"),
        vec![
            Some(TestKvPayload {
                label: "a".to_owned(),
                count: 1,
            }),
            Some(TestKvPayload {
                label: "b".to_owned(),
                count: 2,
            }),
            None,
        ]
    );

    let replacements = vec![
        TestKvPayload {
            label: "a2".to_owned(),
            count: 11,
        },
        TestKvPayload {
            label: "b2".to_owned(),
            count: 12,
        },
    ];
    item.set_multi(
        &test_database.paranoid_pool,
        &keys[..2],
        &replacements,
        KvTtl::no_expiration(),
    )
    .await
    .expect("overwrite multi");
    assert_eq!(
        item.get_multi(&test_database.paranoid_pool, &keys[..2])
            .await
            .expect("get overwritten multi"),
        vec![
            Some(TestKvPayload {
                label: "a2".to_owned(),
                count: 11,
            }),
            Some(TestKvPayload {
                label: "b2".to_owned(),
                count: 12,
            }),
        ]
    );

    item.set_multi(
        &test_database.paranoid_pool,
        &[vec!["expires-a"], vec!["expires-b"]],
        &replacements,
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set multi with ttl");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        item.get_multi(
            &test_database.paranoid_pool,
            &[vec!["expires-a"], vec!["expires-b"]]
        )
        .await
        .expect("get expired multi"),
        vec![None, None]
    );

    assert!(matches!(
        item.get_multi(&test_database.paranoid_pool, &[vec!["dupe"], vec!["dupe"]])
            .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));
    assert!(matches!(
        item.set_multi(
            &test_database.paranoid_pool,
            &[vec!["dupe", "inner"], vec!["dupe", "inner"]],
            &replacements,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));
    let too_many_get_key_parts = (0..=MAX_KV_GET_MULTI_KEYS)
        .map(|index| vec![format!("too-many-get-{index}")])
        .collect::<Vec<_>>();
    assert!(matches!(
        item.get_multi(&test_database.paranoid_pool, &too_many_get_key_parts)
            .await,
        Err(KvError::GetMultiKeyCountTooLarge { .. })
    ));
    let too_many_set_key_parts = (0..=MAX_KV_SET_MULTI_ENTRIES)
        .map(|index| vec![format!("too-many-set-{index}")])
        .collect::<Vec<_>>();
    let too_many_set_values = (0..=MAX_KV_SET_MULTI_ENTRIES)
        .map(|index| TestKvPayload {
            label: format!("too-many-set-{index}"),
            count: index as u32,
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        item.set_multi(
            &test_database.paranoid_pool,
            &too_many_set_key_parts,
            &too_many_set_values,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::SetMultiEntryCountTooLarge { .. })
    ));

    let page_one = item
        .scan(&test_database.paranoid_pool, None, 1)
        .await
        .expect("page one");
    assert_eq!(page_one.len(), 1);
    let page_two = item
        .scan(
            &test_database.paranoid_pool,
            Some(&page_one[0].key_suffix),
            10,
        )
        .await
        .expect("page two");
    assert!(!page_two.is_empty());
    assert!(
        page_two
            .iter()
            .all(|value| value.key_suffix > page_one[0].key_suffix)
    );
    assert!(matches!(
        item.scan(&test_database.paranoid_pool, None, 0).await,
        Err(KvError::ScanLimitIsZero)
    ));
    assert!(matches!(
        item.scan_key_suffixes(&test_database.paranoid_pool, None, 0)
            .await,
        Err(KvError::ScanLimitIsZero)
    ));

    encrypted_item
        .set_multi(
            &test_database.paranoid_pool,
            &[vec!["a"], vec!["b"]],
            &replacements,
            KvTtl::no_expiration(),
        )
        .await
        .expect("encrypted set multi");
    assert_eq!(
        encrypted_item
            .scan(&test_database.paranoid_pool, None, 10)
            .await
            .expect("encrypted scan"),
        vec![
            KvItemScannedValue {
                key_suffix: "a".to_owned(),
                value: TestKvPayload {
                    label: "a2".to_owned(),
                    count: 11,
                },
            },
            KvItemScannedValue {
                key_suffix: "b".to_owned(),
                value: TestKvPayload {
                    label: "b2".to_owned(),
                    count: 12,
                },
            },
        ]
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_public_methods_reject_invalid_key_parts_before_database_work() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "invalid-keys"]).expect("prefix"),
    );
    let value = TestKvPayload {
        label: "value".to_owned(),
        count: 1,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;

    assert!(matches!(
        item.set(
            &test_database.paranoid_pool,
            [""],
            &value,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.set_and_return_database_timestamp(
            &test_database.paranoid_pool,
            [""],
            &value,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.get(&test_database.paranoid_pool, [""]).await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.get_and_return_database_timestamp(&test_database.paranoid_pool, [""])
            .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.touch(&test_database.paranoid_pool, [""]).await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.set_ttl(&test_database.paranoid_pool, [""], KvTtl::no_expiration())
            .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.delete(&test_database.paranoid_pool, [""]).await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.check_exists(&test_database.paranoid_pool, [""]).await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.set_if_not_exists(
            &test_database.paranoid_pool,
            [""],
            &value,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.set_if_not_exists_and_return_database_timestamp(
            &test_database.paranoid_pool,
            [""],
            &value,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.expire(&test_database.paranoid_pool, [""]).await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.get_multi(&test_database.paranoid_pool, &[vec![""]])
            .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.set_multi(
            &test_database.paranoid_pool,
            &[vec![""]],
            std::slice::from_ref(&value),
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &[""],
            &value,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
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
    assert!(matches!(
        item.mutate_atomically(&test_database.paranoid_pool, [""], |_| {
            Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
        })
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.mutate_live_atomically(&test_database.paranoid_pool, [""], |_| {
            Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
        })
        .await,
        Err(KvError::EmptyKeyPart)
    ));

    let mut initializer_called = false;
    let mut mutation_called = false;
    assert!(matches!(
        item.mutate_live_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            [""],
            |_| {
                initializer_called = true;
                Ok::<_, KvError>((value.clone(), KvTtl::no_expiration()))
            },
            |_| {
                mutation_called = true;
                Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
            },
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(!initializer_called);
    assert!(!mutation_called);
}

#[tokio::test]
async fn kv_item_literal_prefix_matching_and_max_key_length_match_go_invariants() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let literal_prefix_item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "wild%_\\"]).expect("literal prefix"),
    );
    let adjacent_item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "wildx_y\\"]).expect("adjacent prefix"),
    );
    let literal_payload = TestKvPayload {
        label: "literal".to_owned(),
        count: 1,
    };
    let adjacent_payload = TestKvPayload {
        label: "adjacent".to_owned(),
        count: 2,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    literal_prefix_item
        .set(
            &test_database.paranoid_pool,
            ["key"],
            &literal_payload,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set literal");
    adjacent_item
        .set(
            &test_database.paranoid_pool,
            ["key"],
            &adjacent_payload,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set adjacent");

    assert_eq!(
        literal_prefix_item
            .count(&test_database.paranoid_pool)
            .await
            .expect("count literal prefix"),
        1
    );
    assert_eq!(
        literal_prefix_item
            .scan(&test_database.paranoid_pool, None, 10)
            .await
            .expect("scan literal prefix"),
        vec![KvItemScannedValue {
            key_suffix: "key".to_owned(),
            value: literal_payload,
        }]
    );
    assert_eq!(
        literal_prefix_item
            .scan_key_suffixes(&test_database.paranoid_pool, None, 10)
            .await
            .expect("suffixes literal prefix"),
        vec!["key".to_owned()]
    );
    assert_eq!(
        literal_prefix_item
            .delete_entire_namespace_atomically(&test_database.paranoid_pool)
            .await
            .expect("delete literal prefix"),
        1
    );
    assert_eq!(
        adjacent_item
            .get(&test_database.paranoid_pool, ["key"])
            .await
            .expect("adjacent survives"),
        adjacent_payload
    );

    let max_prefix = KvKeyPrefix::from_parts(["item", "max"]).expect("max prefix");
    let max_item = KvItem::<TestKvPayload>::new_plain(store.clone(), max_prefix.clone());
    let suffix_len = MAX_KV_KEY_BYTES - max_prefix.as_str().len();
    let max_suffix = "x".repeat(suffix_len - "::".len());
    let too_long_suffix = format!("{max_suffix}x");
    max_item
        .set(
            &test_database.paranoid_pool,
            [max_suffix.as_str()],
            &adjacent_payload,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set max-length key");
    assert_eq!(
        max_item
            .get(&test_database.paranoid_pool, [max_suffix.as_str()])
            .await
            .expect("get max-length key"),
        adjacent_payload
    );
    assert!(matches!(
        max_item
            .set(
                &test_database.paranoid_pool,
                [too_long_suffix.as_str()],
                &adjacent_payload,
                KvTtl::no_expiration(),
            )
            .await,
        Err(KvError::KeyTooLong { .. })
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
