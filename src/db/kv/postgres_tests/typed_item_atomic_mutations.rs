use super::*;

#[tokio::test]
async fn kv_item_get_or_init_is_atomic_and_transactional() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "init"]).expect("prefix"),
    );
    let lazy_existing_item = KvItem::<MaybeFailingKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "init", "lazy-existing"]).expect("prefix"),
    );
    let initial = TestKvPayload {
        label: "initial".to_owned(),
        count: 1,
    };
    let replacement = TestKvPayload {
        label: "replacement".to_owned(),
        count: 2,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let existing_lazy_value = MaybeFailingKvPayload {
        label: "stored".to_owned(),
        fail_serialize: false,
    };
    lazy_existing_item
        .set(
            &test_database.paranoid_pool,
            ["present"],
            &existing_lazy_value,
            KvTtl::no_expiration(),
        )
        .await
        .expect("set lazy existing value");
    assert_eq!(
        lazy_existing_item
            .get_or_init(
                &test_database.paranoid_pool,
                ["present"],
                MaybeFailingKvPayload {
                    label: "should-not-serialize".to_owned(),
                    fail_serialize: true,
                },
                KvTtl::no_expiration(),
            )
            .await
            .expect("get existing without serializing initial value"),
        KvItemGetOrInitResult {
            value: existing_lazy_value,
            initialized: false,
        }
    );

    assert_eq!(
        item.get_or_init(
            &test_database.paranoid_pool,
            ["config"],
            initial.clone(),
            KvTtl::no_expiration(),
        )
        .await
        .expect("first init"),
        KvItemGetOrInitResult {
            value: initial.clone(),
            initialized: true,
        }
    );
    assert_eq!(
        item.get_or_init(
            &test_database.paranoid_pool,
            ["config"],
            replacement,
            KvTtl::no_expiration(),
        )
        .await
        .expect("second init"),
        KvItemGetOrInitResult {
            value: initial,
            initialized: false,
        }
    );

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin tx");
    assert_eq!(
        item.get_or_init_in_current_transaction(
            &mut tx,
            ["rolled-back"],
            TestKvPayload {
                label: "rolled-back".to_owned(),
                count: 3,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("init in tx"),
        KvItemGetOrInitResult {
            value: TestKvPayload {
                label: "rolled-back".to_owned(),
                count: 3,
            },
            initialized: true,
        }
    );
    tx.rollback().await.expect("rollback");
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["rolled-back"])
            .await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_atomic_error_cleanup_survives_caller_transaction_commit() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let failing_prefix = KvKeyPrefix::from_parts(["item", "atomic-error-cleanup"]).expect("prefix");
    let failing_item =
        KvItem::<MaybeFailingKvPayload>::new_plain(store.clone(), failing_prefix.clone());
    let callback_prefix =
        KvKeyPrefix::from_parts(["item", "atomic-callback-error-cleanup"]).expect("prefix");
    let callback_item = KvItem::<TestKvPayload>::new_plain(store.clone(), callback_prefix.clone());
    let get_or_init_key =
        KvKey::from_prefix_and_parts(&failing_prefix, ["get-or-init"]).expect("key");
    let mutate_key = KvKey::from_prefix_and_parts(&failing_prefix, ["mutate"]).expect("key");
    let init_key = KvKey::from_prefix_and_parts(&failing_prefix, ["init"]).expect("key");
    let callback_error_key =
        KvKey::from_prefix_and_parts(&callback_prefix, ["callback"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut get_or_init_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin get_or_init transaction");
    let get_or_init_err = failing_item
        .get_or_init_in_current_transaction::<&str, _>(
            &mut get_or_init_tx,
            ["get-or-init"],
            MaybeFailingKvPayload {
                label: "should-not-persist".to_owned(),
                fail_serialize: true,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect_err("get_or_init serialization failure");
    assert!(matches!(
        get_or_init_err,
        KvError::Codec(Error::PayloadSerialize(_))
    ));
    get_or_init_tx
        .commit()
        .await
        .expect("commit after get_or_init error");
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &get_or_init_key,
        )
        .await,
        0
    );

    let mut mutate_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin mutate transaction");
    let mutate_err = failing_item
        .mutate_atomically_in_current_transaction(&mut mutate_tx, ["mutate"], |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                value: MaybeFailingKvPayload {
                    label: "should-not-persist".to_owned(),
                    fail_serialize: true,
                },
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect_err("mutate serialization failure");
    assert!(matches!(
        mutate_err,
        KvError::Codec(Error::PayloadSerialize(_))
    ));
    mutate_tx.commit().await.expect("commit after mutate error");
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &mutate_key,
        )
        .await,
        0
    );

    let mut init_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin init transaction");
    let init_err = failing_item
        .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
            &mut init_tx,
            ["init"],
            |_| {
                Ok::<_, KvError>((
                    MaybeFailingKvPayload {
                        label: "should-not-persist".to_owned(),
                        fail_serialize: true,
                    },
                    KvTtl::no_expiration(),
                ))
            },
            |_| Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting),
        )
        .await
        .expect_err("init serialization failure");
    assert!(matches!(
        init_err,
        KvError::Codec(Error::PayloadSerialize(_))
    ));
    init_tx.commit().await.expect("commit after init error");
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &init_key,
        )
        .await,
        0
    );

    let mut callback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin callback transaction");
    let callback_err = callback_item
        .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
            &mut callback_tx,
            ["callback"],
            |_| {
                Ok::<_, KvError>((
                    TestKvPayload {
                        label: "transient".to_owned(),
                        count: 1,
                    },
                    KvTtl::no_expiration(),
                ))
            },
            |current| {
                assert_eq!(
                    current.live_value(),
                    &TestKvPayload {
                        label: "transient".to_owned(),
                        count: 1,
                    }
                );
                Err::<KvItemAtomicMutation<TestKvPayload>, _>(KvError::KeyNotFound)
            },
        )
        .await
        .expect_err("callback error");
    assert!(matches!(callback_err, KvError::KeyNotFound));
    callback_tx
        .commit()
        .await
        .expect("commit after callback error");
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &callback_error_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_atomic_mutation_updates_deletes_preserves_ttl_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "atomic"]).expect("prefix"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let initial = TestKvPayload {
        label: "initial".to_owned(),
        count: 1,
    };
    item.set(
        &test_database.paranoid_pool,
        ["counter"],
        &initial,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set counter");

    let updated = item
        .mutate_atomically(&test_database.paranoid_pool, ["counter"], |current| {
            let current_value = current.live_value().expect("live value");
            assert!(current.database_timestamp().as_i64() > 0);
            Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                value: TestKvPayload {
                    label: "updated".to_owned(),
                    count: current_value.count + 1,
                },
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("typed mutation");
    assert_eq!(
        updated,
        KvItemAtomicMutationResult {
            previous_live_value: Some(initial),
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["counter"])
            .await
            .expect("get updated"),
        TestKvPayload {
            label: "updated".to_owned(),
            count: 2,
        }
    );

    item.set(
        &test_database.paranoid_pool,
        ["expiring"],
        &TestKvPayload {
            label: "expiring".to_owned(),
            count: 3,
        },
        KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
    )
    .await
    .expect("set expiring");
    let preserved = item
        .mutate_atomically(&test_database.paranoid_pool, ["expiring"], |current| {
            assert_eq!(
                current.live_value(),
                Some(&TestKvPayload {
                    label: "expiring".to_owned(),
                    count: 3,
                })
            );
            Ok::<_, KvError>(KvItemAtomicMutation::SetValuePreservingExpiration {
                value: TestKvPayload {
                    label: "preserved".to_owned(),
                    count: 4,
                },
            })
        })
        .await
        .expect("preserve ttl");
    assert_eq!(
        preserved.outcome,
        KvAtomicMutationOutcome::SetBytesPreservingExpiration
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["expiring"]).await,
        Err(KvError::KeyNotFound)
    ));

    let deleted = item
        .mutate_atomically(&test_database.paranoid_pool, ["counter"], |current| {
            assert!(current.has_live_value());
            Ok::<_, KvError>(KvItemAtomicMutation::Delete)
        })
        .await
        .expect("delete via mutation");
    assert_eq!(deleted.outcome, KvAtomicMutationOutcome::DeletedLiveValue);
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["counter"]).await,
        Err(KvError::KeyNotFound)
    ));

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback tx");
    item.mutate_atomically_in_current_transaction(&mut tx, ["rolled-back"], |current| {
        assert_eq!(current.live_value(), None);
        Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
            value: TestKvPayload {
                label: "rolled-back".to_owned(),
                count: 5,
            },
            ttl: KvTtl::no_expiration(),
        })
    })
    .await
    .expect("mutate in tx");
    tx.rollback().await.expect("rollback");
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["rolled-back"])
            .await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_live_atomic_mutation_requires_non_expired_existing_item() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "live-atomic"]).expect("prefix"),
    );
    let keyset = test_kv_item_keyset();
    let encrypted_item = KvItem::<TestKvPayload>::new_encrypted(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "live-atomic-encrypted"]).expect("prefix"),
        move || Ok(keyset.clone()),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let absent_callback_calls = AtomicUsize::new(0);
    let absent_err = item
        .mutate_live_atomically(&test_database.paranoid_pool, ["absent"], |_| {
            absent_callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
        })
        .await
        .expect_err("absent live item mutation should fail");
    assert!(matches!(absent_err, KvError::KeyNotFound));
    assert_eq!(absent_callback_calls.load(Ordering::SeqCst), 0);

    item.set(
        &test_database.paranoid_pool,
        ["expired"],
        &TestKvPayload {
            label: "expired".to_owned(),
            count: 1,
        },
        KvTtl::no_expiration(),
    )
    .await
    .expect("set expired candidate");
    item.expire(&test_database.paranoid_pool, ["expired"])
        .await
        .expect("expire candidate");

    let expired_callback_calls = AtomicUsize::new(0);
    let expired_err = item
        .mutate_live_atomically(&test_database.paranoid_pool, ["expired"], |_| {
            expired_callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
        })
        .await
        .expect_err("expired live item mutation should fail");
    assert!(matches!(expired_err, KvError::KeyNotFound));
    assert_eq!(expired_callback_calls.load(Ordering::SeqCst), 0);

    let initial = TestKvPayload {
        label: "initial".to_owned(),
        count: 10,
    };
    item.set(
        &test_database.paranoid_pool,
        ["present"],
        &initial,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set present");

    let updated = item
        .mutate_live_atomically(&test_database.paranoid_pool, ["present"], |current| {
            assert_eq!(current.live_value(), &initial);
            assert!(current.database_timestamp().as_i64() > 0);
            Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                value: TestKvPayload {
                    label: "updated".to_owned(),
                    count: current.live_value().count + 1,
                },
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("update live item");
    assert_eq!(
        updated,
        KvItemAtomicLiveMutationResult {
            previous_live_value: initial,
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["present"])
            .await
            .expect("get updated"),
        TestKvPayload {
            label: "updated".to_owned(),
            count: 11,
        }
    );

    encrypted_item
        .set(
            &test_database.paranoid_pool,
            ["present"],
            &TestKvPayload {
                label: "encrypted".to_owned(),
                count: 20,
            },
            KvTtl::no_expiration(),
        )
        .await
        .expect("set encrypted present");
    let encrypted_deleted = encrypted_item
        .mutate_live_atomically(&test_database.paranoid_pool, ["present"], |current| {
            assert_eq!(
                current.live_value(),
                &TestKvPayload {
                    label: "encrypted".to_owned(),
                    count: 20,
                }
            );
            Ok::<_, KvError>(KvItemAtomicMutation::Delete)
        })
        .await
        .expect("delete encrypted live item");
    assert_eq!(
        encrypted_deleted,
        KvItemAtomicLiveMutationResult {
            previous_live_value: TestKvPayload {
                label: "encrypted".to_owned(),
                count: 20,
            },
            outcome: KvAtomicMutationOutcome::DeletedLiveValue,
        }
    );
    assert!(matches!(
        encrypted_item
            .get(&test_database.paranoid_pool, ["present"])
            .await,
        Err(KvError::KeyNotFound)
    ));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_live_or_init_atomic_mutation_initializes_once_and_supports_encryption() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item_prefix = KvKeyPrefix::from_parts(["item", "or-init-atomic"]).expect("prefix");
    let typed_delete_initial_key =
        KvKey::from_prefix_and_parts(&item_prefix, ["delete-initial"]).expect("key");
    let item = KvItem::<TestKvPayload>::new_plain(store.clone(), item_prefix);
    let keyset = test_kv_item_keyset();
    let encrypted_item = KvItem::<TestKvPayload>::new_encrypted(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "or-init-atomic-encrypted"]).expect("prefix"),
        move || Ok(keyset.clone()),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let initial = TestKvPayload {
        label: "initial".to_owned(),
        count: 1,
    };
    let kept_initial = item
        .mutate_live_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            ["keep"],
            |database_timestamp| {
                assert!(database_timestamp.as_i64() > 0);
                Ok::<_, KvError>((initial.clone(), KvTtl::no_expiration()))
            },
            |current| {
                assert_eq!(current.live_value(), &initial);
                assert!(current.database_timestamp().as_i64() > 0);
                Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
            },
        )
        .await
        .expect("initialize typed value");
    assert_eq!(
        kept_initial,
        KvItemAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: initial.clone(),
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["keep"])
            .await
            .expect("get initialized typed value"),
        initial
    );

    let typed_preserve_initial_ttl = item
        .mutate_live_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            ["preserve-initial-ttl"],
            |_| {
                Ok::<_, KvError>((
                    TestKvPayload {
                        label: "initial-expiring".to_owned(),
                        count: 30,
                    },
                    KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
                ))
            },
            |current| {
                assert_eq!(
                    current.live_value(),
                    &TestKvPayload {
                        label: "initial-expiring".to_owned(),
                        count: 30,
                    }
                );
                Ok::<_, KvError>(KvItemAtomicMutation::SetValuePreservingExpiration {
                    value: TestKvPayload {
                        label: "replacement-expiring".to_owned(),
                        count: 31,
                    },
                })
            },
        )
        .await
        .expect("initialize typed value and preserve initial ttl");
    assert_eq!(
        typed_preserve_initial_ttl,
        KvItemAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: TestKvPayload {
                label: "initial-expiring".to_owned(),
                count: 30,
            },
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["preserve-initial-ttl"])
            .await
            .expect("get typed replacement before ttl"),
        TestKvPayload {
            label: "replacement-expiring".to_owned(),
            count: 31,
        }
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(
        item.get(&test_database.paranoid_pool, ["preserve-initial-ttl"])
            .await,
        Err(KvError::KeyNotFound)
    ));

    let typed_deleted_initial = item
        .mutate_live_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            ["delete-initial"],
            |_| {
                Ok::<_, KvError>((
                    TestKvPayload {
                        label: "delete-initial".to_owned(),
                        count: 40,
                    },
                    KvTtl::no_expiration(),
                ))
            },
            |current| {
                assert_eq!(
                    current.live_value(),
                    &TestKvPayload {
                        label: "delete-initial".to_owned(),
                        count: 40,
                    }
                );
                Ok::<_, KvError>(KvItemAtomicMutation::Delete)
            },
        )
        .await
        .expect("initialize typed value and delete");
    assert_eq!(
        typed_deleted_initial,
        KvItemAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: TestKvPayload {
                label: "delete-initial".to_owned(),
                count: 40,
            },
            outcome: KvAtomicMutationOutcome::DeletedAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &typed_delete_initial_key,
        )
        .await,
        0
    );

    let existing_typed_initializer_calls = AtomicUsize::new(0);
    let existing_typed_updated = item
        .mutate_live_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            ["keep"],
            |_| {
                existing_typed_initializer_calls.fetch_add(1, Ordering::SeqCst);
                Err::<(TestKvPayload, KvTtl), _>(KvError::KeyNotFound)
            },
            |current| {
                Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                    value: TestKvPayload {
                        label: "existing-updated".to_owned(),
                        count: current.live_value().count + 1,
                    },
                    ttl: KvTtl::no_expiration(),
                })
            },
        )
        .await
        .expect("mutate existing typed value without initializer");
    assert_eq!(
        existing_typed_updated,
        KvItemAtomicLiveOrInitMutationResult {
            initialized: false,
            live_value_seen_by_callback: TestKvPayload {
                label: "initial".to_owned(),
                count: 1,
            },
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(existing_typed_initializer_calls.load(Ordering::SeqCst), 0);

    let counter_initializer_calls = Arc::new(AtomicUsize::new(0));
    let handles = (0..25)
        .map(|_| {
            let task_pool = test_database.paranoid_pool.clone();
            let task_item = item.clone();
            let task_initializer_calls = counter_initializer_calls.clone();
            tokio::spawn(async move {
                task_item
                    .mutate_live_or_insert_initial_value_atomically(
                        &task_pool,
                        ["counter"],
                        |_| {
                            task_initializer_calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, KvError>((
                                TestKvPayload {
                                    label: "counter".to_owned(),
                                    count: 0,
                                },
                                KvTtl::no_expiration(),
                            ))
                        },
                        |current| {
                            Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                                value: TestKvPayload {
                                    label: "counter".to_owned(),
                                    count: current.live_value().count + 1,
                                },
                                ttl: KvTtl::no_expiration(),
                            })
                        },
                    )
                    .await
                    .expect("increment typed counter")
                    .initialized
            })
        })
        .collect::<Vec<_>>();
    let mut initialized_count = 0;
    for handle in handles {
        if handle.await.expect("join typed counter task") {
            initialized_count += 1;
        }
    }
    assert_eq!(initialized_count, 1);
    assert_eq!(counter_initializer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["counter"])
            .await
            .expect("get final typed counter"),
        TestKvPayload {
            label: "counter".to_owned(),
            count: 25,
        }
    );

    let encrypted_initial = TestKvPayload {
        label: "encrypted-initial".to_owned(),
        count: 7,
    };
    let encrypted_result = encrypted_item
        .mutate_live_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            ["secret"],
            |_| Ok::<_, KvError>((encrypted_initial.clone(), KvTtl::no_expiration())),
            |current| {
                assert_eq!(current.live_value(), &encrypted_initial);
                Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                    value: TestKvPayload {
                        label: "encrypted-final".to_owned(),
                        count: 8,
                    },
                    ttl: KvTtl::no_expiration(),
                })
            },
        )
        .await
        .expect("initialize encrypted typed value");
    assert_eq!(
        encrypted_result,
        KvItemAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: encrypted_initial,
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        encrypted_item
            .get(&test_database.paranoid_pool, ["secret"])
            .await
            .expect("get encrypted final value"),
        TestKvPayload {
            label: "encrypted-final".to_owned(),
            count: 8,
        }
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_atomic_mutation_serializes_concurrent_counter_updates() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<i64>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "counter"]).expect("prefix"),
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");
    item.set(
        &test_database.paranoid_pool,
        ["counter"],
        &0,
        KvTtl::no_expiration(),
    )
    .await
    .expect("set counter");

    let handles = (0..50)
        .map(|_| {
            let task_pool = test_database.paranoid_pool.clone();
            let task_item = item.clone();
            tokio::spawn(async move {
                task_item
                    .mutate_atomically(&task_pool, ["counter"], |current| {
                        let current_value = *current.live_value().expect("counter exists");
                        Ok::<_, KvError>(KvItemAtomicMutation::SetValue {
                            value: current_value + 1,
                            ttl: KvTtl::no_expiration(),
                        })
                    })
                    .await
                    .expect("increment counter");
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.await.expect("join increment task");
    }
    assert_eq!(
        item.get(&test_database.paranoid_pool, ["counter"])
            .await
            .expect("get final counter"),
        50
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
