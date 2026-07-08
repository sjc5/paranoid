use super::*;

#[tokio::test]
async fn kv_plain_item_round_trips_scans_lifecycle_and_deletes_namespace() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "plain"]).expect("prefix"),
    );
    let payload_a = TestKvPayload {
        label: "a".to_owned(),
        count: 1,
    };
    let payload_b = TestKvPayload {
        label: "b".to_owned(),
        count: 2,
    };
    let payload_nested_one = TestKvPayload {
        label: "nested-one".to_owned(),
        count: 11,
    };
    let payload_nested_two = TestKvPayload {
        label: "nested-two".to_owned(),
        count: 12,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

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
    item.set(
        &test_database.paranoid_pool,
        ["nested", "one"],
        &payload_nested_one,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set nested one");
    item.set(
        &test_database.paranoid_pool,
        ["nested", "two"],
        &payload_nested_two,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set nested two");

    let bulk_keys = vec![
        vec!["bulk-a"],
        vec!["bulk-b", "inner"],
        vec!["bulk-missing"],
    ];
    let bulk_values = vec![
        TestKvPayload {
            label: "bulk-a".to_owned(),
            count: 21,
        },
        TestKvPayload {
            label: "bulk-b-inner".to_owned(),
            count: 22,
        },
    ];
    item.set_multi(
        &test_database.paranoid_pool,
        &bulk_keys[..2],
        &bulk_values,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set multi");
    assert_eq!(
        item.get_multi(&test_database.paranoid_pool, &bulk_keys)
            .await
            .expect("get multi"),
        vec![
            Some(TestKvPayload {
                label: "bulk-a".to_owned(),
                count: 21,
            }),
            Some(TestKvPayload {
                label: "bulk-b-inner".to_owned(),
                count: 22,
            }),
            None,
        ]
    );
    assert!(matches!(
        item.set_multi(
            &test_database.paranoid_pool,
            &bulk_keys[..1],
            &bulk_values,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::SetMultiLengthMismatch { .. })
    ));
    assert!(matches!(
        item.get_multi(&test_database.paranoid_pool, &[vec!["dupe"], vec!["dupe"]])
            .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));

    assert_eq!(
        item.get(&test_database.paranoid_pool, ["a"])
            .await
            .expect("get a"),
        payload_a
    );
    assert_eq!(
        item.get_or_fallback(
            &test_database.paranoid_pool,
            ["missing"],
            TestKvPayload {
                label: "fallback".to_owned(),
                count: 9,
            },
        )
        .await
        .expect("fallback"),
        TestKvPayload {
            label: "fallback".to_owned(),
            count: 9,
        }
    );
    assert!(
        item.check_exists(&test_database.paranoid_pool, ["a"])
            .await
            .expect("exists")
    );
    assert!(
        !item
            .set_if_not_exists(
                &test_database.paranoid_pool,
                ["a"],
                &TestKvPayload {
                    label: "not-written".to_owned(),
                    count: 99,
                },
                KvTtl::no_expiration(),
            )
            .await
            .expect("set existing")
    );
    item.touch(&test_database.paranoid_pool, ["a"])
        .await
        .expect("touch");
    item.set_ttl(
        &test_database.paranoid_pool,
        ["a"],
        KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
    )
    .await
    .expect("set ttl");
    item.expire(&test_database.paranoid_pool, ["a"])
        .await
        .expect("expire");
    assert!(
        item.set_if_not_exists(
            &test_database.paranoid_pool,
            ["a"],
            &payload_a,
            KvTtl::no_expiration(),
        )
        .await
        .expect("replace expired")
    );

    assert_eq!(
        item.count(&test_database.paranoid_pool)
            .await
            .expect("count"),
        6
    );
    assert_eq!(
        item.scan(&test_database.paranoid_pool, None, 10)
            .await
            .expect("scan"),
        vec![
            KvItemScannedValue {
                key_suffix: "a".to_owned(),
                value: payload_a.clone(),
            },
            KvItemScannedValue {
                key_suffix: "b".to_owned(),
                value: payload_b,
            },
            KvItemScannedValue {
                key_suffix: "bulk-a".to_owned(),
                value: TestKvPayload {
                    label: "bulk-a".to_owned(),
                    count: 21,
                },
            },
            KvItemScannedValue {
                key_suffix: "bulk-b::inner".to_owned(),
                value: TestKvPayload {
                    label: "bulk-b-inner".to_owned(),
                    count: 22,
                },
            },
            KvItemScannedValue {
                key_suffix: "nested::one".to_owned(),
                value: payload_nested_one,
            },
            KvItemScannedValue {
                key_suffix: "nested::two".to_owned(),
                value: payload_nested_two,
            },
        ]
    );
    assert_eq!(
        item.scan_key_suffixes(&test_database.paranoid_pool, Some("nested::one"), 10)
            .await
            .expect("suffixes after nested one"),
        vec!["nested::two".to_owned()]
    );

    item.delete(&test_database.paranoid_pool, ["a"])
        .await
        .expect("delete a");
    assert!(
        !item
            .check_exists(&test_database.paranoid_pool, ["a"])
            .await
            .expect("exists after delete")
    );

    assert_eq!(
        item.delete_entire_namespace_atomically(&test_database.paranoid_pool)
            .await
            .expect("delete namespace"),
        5
    );
    assert_eq!(
        item.count(&test_database.paranoid_pool)
            .await
            .expect("count after delete"),
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_database_timestamp_returning_methods_follow_conditional_semantics() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "timestamps"]).expect("prefix"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let set_timestamp = item
        .set_and_return_database_timestamp(
            &test_database.paranoid_pool,
            ["set"],
            &TestKvPayload {
                label: "set".to_owned(),
                count: 1,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("typed set timestamp");
    assert!(set_timestamp.as_i64() > 0);
    assert!(
        set_timestamp.as_i64()
            <= fetch_statement_timestamp_microseconds(&test_database.sqlx_pool).await
    );
    let loaded_set = item
        .get_and_return_database_timestamp(&test_database.paranoid_pool, ["set"])
        .await
        .expect("typed get timestamp");
    assert_eq!(
        loaded_set.value,
        TestKvPayload {
            label: "set".to_owned(),
            count: 1,
        }
    );
    assert!(loaded_set.database_timestamp.as_i64() > 0);

    let first_claim = item
        .set_if_not_exists_and_return_database_timestamp(
            &test_database.paranoid_pool,
            ["claim"],
            &TestKvPayload {
                label: "claim".to_owned(),
                count: 2,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("typed conditional timestamp");
    assert!(first_claim.was_set);
    assert!(
        first_claim
            .database_timestamp
            .expect("claim timestamp")
            .as_i64()
            > 0
    );

    let blocked_claim = item
        .set_if_not_exists_and_return_database_timestamp(
            &test_database.paranoid_pool,
            ["claim"],
            &TestKvPayload {
                label: "blocked".to_owned(),
                count: 3,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("typed blocked conditional timestamp");
    assert!(!blocked_claim.was_set);
    assert_eq!(blocked_claim.database_timestamp, None);

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin typed timestamp tx");
    let tx_claim = item
        .set_if_not_exists_and_return_database_timestamp_in_current_transaction(
            &mut tx,
            ["rolled-back"],
            &TestKvPayload {
                label: "rolled-back".to_owned(),
                count: 4,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("typed conditional timestamp in tx");
    assert!(tx_claim.was_set);
    assert!(
        tx_claim
            .database_timestamp
            .expect("tx claim timestamp")
            .as_i64()
            > 0
    );
    let loaded_in_tx = item
        .get_and_return_database_timestamp_in_current_transaction(&mut tx, ["rolled-back"])
        .await
        .expect("typed get timestamp in tx");
    assert_eq!(
        loaded_in_tx.value,
        TestKvPayload {
            label: "rolled-back".to_owned(),
            count: 4,
        }
    );
    assert!(loaded_in_tx.database_timestamp.as_i64() > 0);
    tx.rollback().await.expect("rollback typed timestamp tx");
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["rolled-back"])
            .await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_decode_failures_are_reported_for_get_multi_scan_and_atomic_mutation() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["item", "decode-failure"]).expect("prefix");
    let item = KvItem::<TestKvPayload>::new_plain(store.clone(), prefix.clone());
    let broken_get_key = KvKey::from_prefix_and_parts(&prefix, ["broken-get"]).expect("key");
    let broken_multi_key = KvKey::from_prefix_and_parts(&prefix, ["broken-multi"]).expect("key");
    let broken_scan_key = KvKey::from_prefix_and_parts(&prefix, ["broken-scan"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    for key in [&broken_get_key, &broken_multi_key, &broken_scan_key] {
        store
            .set_bytes(
                &test_database.paranoid_pool,
                key,
                &[0xff, 0x00, 0xff],
                KvTtl::no_expiration(),
            )
            .await
            .expect("insert invalid typed payload");
    }

    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["broken-get"]).await,
        Err(KvError::Codec(Error::PayloadDeserialize(_)))
    ));
    assert!(matches!(
        item.get_and_return_database_timestamp(&test_database.paranoid_pool, ["broken-get"])
            .await,
        Err(KvError::Codec(Error::PayloadDeserialize(_)))
    ));
    assert!(matches!(
        item.get_multi(&test_database.paranoid_pool, &[vec!["broken-multi"]])
            .await,
        Err(KvError::Codec(Error::PayloadDeserialize(_)))
    ));
    assert!(matches!(
        item.scan(&test_database.paranoid_pool, None, 10).await,
        Err(KvError::Codec(Error::PayloadDeserialize(_)))
    ));
    assert_eq!(
        item.scan_key_suffixes(&test_database.paranoid_pool, None, 10)
            .await
            .expect("key suffix scan should not decode values"),
        vec![
            "broken-get".to_owned(),
            "broken-multi".to_owned(),
            "broken-scan".to_owned(),
        ]
    );

    let atomic_callback_calls = AtomicUsize::new(0);
    assert!(matches!(
        item.mutate_atomically(&test_database.paranoid_pool, ["broken-get"], |_| {
            atomic_callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
        })
        .await,
        Err(KvError::Codec(Error::PayloadDeserialize(_)))
    ));
    assert_eq!(atomic_callback_calls.load(Ordering::SeqCst), 0);

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_encrypted_item_round_trips_binds_ciphertext_to_key_and_acquires_slots() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["item", "encrypted"]).expect("prefix");
    let keyset = test_kv_item_keyset();
    let item = KvItem::<TestKvPayload>::new_encrypted(store.clone(), prefix.clone(), move || {
        Ok(keyset.clone())
    });
    let source_key = KvKey::from_prefix_and_parts(&prefix, ["source"]).expect("source key");
    let target_key = KvKey::from_prefix_and_parts(&prefix, ["target"]).expect("target key");
    let payload = TestKvPayload {
        label: "secret".to_owned(),
        count: 7,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    item.set(
        &test_database.paranoid_pool,
        ["source"],
        &payload,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set encrypted");
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["source"])
            .await
            .expect("get encrypted"),
        payload
    );

    let encrypted_bulk_keys = vec![vec!["bulk-source"], vec!["bulk-nested", "source"]];
    let encrypted_bulk_values = vec![
        TestKvPayload {
            label: "encrypted-bulk-a".to_owned(),
            count: 31,
        },
        TestKvPayload {
            label: "encrypted-bulk-b".to_owned(),
            count: 32,
        },
    ];
    item.set_multi(
        &test_database.paranoid_pool,
        &encrypted_bulk_keys,
        &encrypted_bulk_values,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set encrypted multi");
    assert_eq!(
        item.get_multi(&test_database.paranoid_pool, &encrypted_bulk_keys)
            .await
            .expect("get encrypted multi"),
        vec![
            Some(TestKvPayload {
                label: "encrypted-bulk-a".to_owned(),
                count: 31,
            }),
            Some(TestKvPayload {
                label: "encrypted-bulk-b".to_owned(),
                count: 32,
            }),
        ]
    );

    let copied_ciphertext = store
        .get_bytes(&test_database.paranoid_pool, &source_key)
        .await
        .expect("raw source");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &target_key,
            &copied_ciphertext,
            KvTtl::no_expiration(),
        )
        .await
        .expect("copy raw ciphertext");
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["target"]).await,
        Err(KvError::Codec(Error::DecryptionFailed))
    ));
    let malformed_key = KvKey::from_prefix_and_parts(&prefix, ["malformed"]).expect("key");
    store
        .set_bytes(
            &test_database.paranoid_pool,
            &malformed_key,
            b"not-an-encrypted-envelope",
            KvTtl::no_expiration(),
        )
        .await
        .expect("write malformed encrypted payload");
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["malformed"]).await,
        Err(KvError::Codec(_))
    ));

    let acquired_suffix = item
        .acquire_slot(
            &test_database.paranoid_pool,
            &["slot-a", "slot-b"],
            &TestKvPayload {
                label: "slot-holder".to_owned(),
                count: 8,
            },
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await
        .expect("acquire encrypted slot")
        .expect("slot");
    assert!(matches!(acquired_suffix.as_str(), "slot-a" | "slot-b"));
    assert_eq!(
        item.get(&test_database.paranoid_pool, [acquired_suffix.as_str()])
            .await
            .expect("get acquired encrypted slot"),
        TestKvPayload {
            label: "slot-holder".to_owned(),
            count: 8,
        }
    );

    let mutated = item
        .mutate_atomically(&test_database.paranoid_pool, ["source"], |current| {
            assert_eq!(
                current.live_value(),
                Some(&TestKvPayload {
                    label: "secret".to_owned(),
                    count: 7,
                })
            );
            assert!(current.database_timestamp().as_i64() > 0);
            Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                value: TestKvPayload {
                    label: "encrypted-mutation".to_owned(),
                    count: 9,
                },
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("encrypted mutation");
    assert_eq!(
        mutated,
        KvItemAtomicMutationResult {
            previous_live_value: Some(TestKvPayload {
                label: "secret".to_owned(),
                count: 7,
            }),
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["source"])
            .await
            .expect("get mutated encrypted item"),
        TestKvPayload {
            label: "encrypted-mutation".to_owned(),
            count: 9,
        }
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_encrypted_item_bulk_paths_resolve_keyset_once_per_operation() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["item", "encrypted-keyset-calls"]).expect("prefix");
    let keyset = test_kv_item_keyset();
    let keyset_call_count = Arc::new(AtomicUsize::new(0));
    let item = KvItem::<TestKvPayload>::new_encrypted(store.clone(), prefix, {
        let keyset_call_count = keyset_call_count.clone();
        move || {
            keyset_call_count.fetch_add(1, Ordering::SeqCst);
            Ok(keyset.clone())
        }
    });

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let empty_key_parts: Vec<Vec<&str>> = Vec::new();
    let empty_values: Vec<TestKvPayload> = Vec::new();
    item.set_multi(
        &test_database.paranoid_pool,
        &empty_key_parts,
        &empty_values,
        KvTtl::no_expiration(),
    )
    .await
    .expect("empty encrypted set multi");
    assert_eq!(keyset_call_count.load(Ordering::SeqCst), 0);

    let keys = vec![vec!["a"], vec!["b"]];
    let values = vec![
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
        &keys,
        &values,
        KvTtl::no_expiration(),
    )
    .await
    .expect("encrypted set multi");
    assert_eq!(keyset_call_count.swap(0, Ordering::SeqCst), 1);

    assert_eq!(
        item.get_multi(
            &test_database.paranoid_pool,
            &[vec!["missing-a"], vec!["missing-b"]],
        )
        .await
        .expect("encrypted get multi all missing"),
        vec![None, None]
    );
    assert_eq!(keyset_call_count.load(Ordering::SeqCst), 0);

    assert_eq!(
        item.get_multi(
            &test_database.paranoid_pool,
            &[vec!["a"], vec!["b"], vec!["missing"],]
        )
        .await
        .expect("encrypted get multi"),
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
    assert_eq!(keyset_call_count.swap(0, Ordering::SeqCst), 1);

    assert_eq!(
        item.scan(&test_database.paranoid_pool, None, 10)
            .await
            .expect("encrypted scan"),
        vec![
            KvItemScannedValue {
                key_suffix: "a".to_owned(),
                value: TestKvPayload {
                    label: "a".to_owned(),
                    count: 1,
                },
            },
            KvItemScannedValue {
                key_suffix: "b".to_owned(),
                value: TestKvPayload {
                    label: "b".to_owned(),
                    count: 2,
                },
            },
        ]
    );
    assert_eq!(keyset_call_count.swap(0, Ordering::SeqCst), 1);

    assert_eq!(
        item.scan_key_suffixes(&test_database.paranoid_pool, None, 10)
            .await
            .expect("encrypted suffix scan"),
        vec!["a".to_owned(), "b".to_owned()]
    );
    assert_eq!(keyset_call_count.load(Ordering::SeqCst), 0);

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_encrypted_item_reports_keyset_errors_before_database_writes() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["item", "encrypted-keyset-error"]).expect("prefix");
    let attempted_key = KvKey::from_prefix_and_parts(&prefix, ["key"]).expect("key");
    let item =
        KvItem::<TestKvPayload>::new_encrypted(store.clone(), prefix, || Err(Error::EmptyKeyset));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let err = item
        .set(
            &test_database.paranoid_pool,
            ["key"],
            &TestKvPayload {
                label: "should-not-write".to_owned(),
                count: 0,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect_err("keyset error");
    assert!(matches!(err, KvError::Codec(Error::EmptyKeyset)));
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &attempted_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_encrypted_acquire_slot_encode_failure_does_not_leave_claimed_slot() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let prefix = KvKeyPrefix::from_parts(["item", "encrypted-slot-error"]).expect("prefix");
    let slot_key = KvKey::from_prefix_and_parts(&prefix, ["slot"]).expect("slot key");
    let keyset = test_kv_item_keyset();
    let item = KvItem::<MaybeFailingKvPayload>::new_encrypted(store.clone(), prefix, move || {
        Ok(keyset.clone())
    });

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin transaction");
    let err = item
        .acquire_slot_in_current_transaction(
            &mut tx,
            &["slot"],
            &MaybeFailingKvPayload {
                label: "should-not-claim".to_owned(),
                fail_serialize: true,
            },
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await
        .expect_err("serialization failure");
    assert!(matches!(err, KvError::Codec(Error::PayloadSerialize(_))));

    tx.commit().await.expect("commit after failed slot claim");

    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &slot_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
