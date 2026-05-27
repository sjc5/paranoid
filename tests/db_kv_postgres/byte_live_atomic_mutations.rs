use super::*;

#[tokio::test]
async fn kv_live_atomic_mutation_requires_non_expired_existing_key() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let absent_key = KvKey::from_parts(["atomic", "live", "absent"]).expect("key");
    let expired_key = KvKey::from_parts(["atomic", "live", "expired"]).expect("key");
    let live_key = KvKey::from_parts(["atomic", "live", "present"]).expect("key");
    let expires_during_callback_key =
        KvKey::from_parts(["atomic", "live", "expires-during-callback"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let absent_callback_calls = AtomicUsize::new(0);
    let absent_err = store
        .mutate_live_key_atomically(&test_database.paranoid_pool, &absent_key, |_| {
            absent_callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
        })
        .await
        .expect_err("absent live mutation should fail");
    assert!(matches!(absent_err, KvError::KeyNotFound));
    assert_eq!(absent_callback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &expired_key,
            b"expired",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set expiring row");
    store
        .expire_key(&test_database.paranoid_pool, &expired_key)
        .await
        .expect("expire row");

    let expired_callback_calls = AtomicUsize::new(0);
    let expired_err = store
        .mutate_live_key_atomically(&test_database.paranoid_pool, &expired_key, |_| {
            expired_callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
        })
        .await
        .expect_err("expired live mutation should fail");
    assert!(matches!(expired_err, KvError::KeyNotFound));
    assert_eq!(expired_callback_calls.load(Ordering::SeqCst), 0);

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &live_key,
            b"live",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set live row");
    let kept = store
        .mutate_live_key_atomically(&test_database.paranoid_pool, &live_key, |current| {
            assert_eq!(current.live_value(), b"live");
            assert!(current.database_timestamp().as_i64() > 0);
            Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
        })
        .await
        .expect("keep live row");
    assert_eq!(
        kept,
        KvAtomicLiveMutationResult {
            previous_live_value: b"live".to_vec(),
            outcome: KvAtomicMutationOutcome::KeptLiveValue,
        }
    );

    let deleted = store
        .mutate_live_key_atomically(&test_database.paranoid_pool, &live_key, |current| {
            assert_eq!(current.live_value(), b"live");
            Ok::<_, KvError>(KvAtomicMutation::Delete)
        })
        .await
        .expect("delete live row");
    assert_eq!(
        deleted,
        KvAtomicLiveMutationResult {
            previous_live_value: b"live".to_vec(),
            outcome: KvAtomicMutationOutcome::DeletedLiveValue,
        }
    );
    assert!(matches!(
        store
            .get_bytes(&test_database.paranoid_pool, &live_key)
            .await,
        Err(KvError::KeyNotFound)
    ));

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &expires_during_callback_key,
            b"briefly-live",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set briefly live row");
    let deleted_after_expiry = store
        .mutate_live_key_atomically(
            &test_database.paranoid_pool,
            &expires_during_callback_key,
            |current| {
                assert_eq!(current.live_value(), b"briefly-live");
                std::thread::sleep(Duration::from_millis(1200));
                Ok::<_, KvError>(KvAtomicMutation::Delete)
            },
        )
        .await
        .expect("delete row that expired while locked");
    assert_eq!(
        deleted_after_expiry,
        KvAtomicLiveMutationResult {
            previous_live_value: b"briefly-live".to_vec(),
            outcome: KvAtomicMutationOutcome::DeletedLiveValue,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &expires_during_callback_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_pool_owned_atomic_callbacks_run_once_and_are_not_retried_after_callback_error() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let plain_key = KvKey::from_parts(["atomic", "callback-once", "plain"]).expect("key");
    let init_key = KvKey::from_parts(["atomic", "callback-once", "init"]).expect("key");
    let error_key = KvKey::from_parts(["atomic", "callback-once", "error"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let plain_callback_calls = AtomicUsize::new(0);
    store
        .mutate_key_atomically(&test_database.paranoid_pool, &plain_key, |current| {
            assert_eq!(current.live_value(), None);
            plain_callback_calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"plain".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("plain atomic mutation");
    assert_eq!(
        plain_callback_calls.load(Ordering::SeqCst),
        1,
        "pool-owned KV atomic mutation must not retry the caller callback"
    );

    let initializer_calls = AtomicUsize::new(0);
    let mutation_callback_calls = AtomicUsize::new(0);
    store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &init_key,
            |database_timestamp| {
                assert!(database_timestamp.as_i64() > 0);
                initializer_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, KvError>((b"initial".to_vec(), KvTtl::no_expiration()))
            },
            |current| {
                assert_eq!(current.live_value(), b"initial");
                mutation_callback_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                    value: b"mutated".to_vec(),
                    ttl: KvTtl::no_expiration(),
                })
            },
        )
        .await
        .expect("init atomic mutation");
    assert_eq!(
        initializer_calls.load(Ordering::SeqCst),
        1,
        "pool-owned KV initializer must not be retried"
    );
    assert_eq!(
        mutation_callback_calls.load(Ordering::SeqCst),
        1,
        "pool-owned KV live-or-init mutation callback must not be retried"
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &init_key)
            .await
            .expect("get initialized and mutated value"),
        b"mutated"
    );

    let error_callback_calls = AtomicUsize::new(0);
    let err = store
        .mutate_key_atomically(&test_database.paranoid_pool, &error_key, |current| {
            assert_eq!(current.live_value(), None);
            error_callback_calls.fetch_add(1, Ordering::SeqCst);
            Err::<KvAtomicMutation, _>(KvError::KeyNotFound)
        })
        .await
        .expect_err("callback error should be returned");
    assert!(matches!(err, KvError::KeyNotFound));
    assert_eq!(
        error_callback_calls.load(Ordering::SeqCst),
        1,
        "pool-owned KV atomic mutation must return caller errors without retrying the callback"
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &error_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_live_or_init_atomic_mutation_initializes_once_and_then_mutates_live_value() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let keep_initial_key = KvKey::from_parts(["atomic", "or-init", "keep"]).expect("key");
    let existing_key = KvKey::from_parts(["atomic", "or-init", "existing"]).expect("key");
    let rollback_key = KvKey::from_parts(["atomic", "or-init", "rollback"]).expect("key");
    let initializer_error_key =
        KvKey::from_parts(["atomic", "or-init", "initializer-error"]).expect("key");
    let callback_error_key =
        KvKey::from_parts(["atomic", "or-init", "callback-error"]).expect("key");
    let preserve_initial_ttl_key =
        KvKey::from_parts(["atomic", "or-init", "preserve-initial-ttl"]).expect("key");
    let delete_initial_key =
        KvKey::from_parts(["atomic", "or-init", "delete-initial"]).expect("key");
    let counter_key = KvKey::from_parts(["atomic", "or-init", "counter"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let kept_initial = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &keep_initial_key,
            |database_timestamp| {
                assert!(database_timestamp.as_i64() > 0);
                Ok::<_, KvError>((b"initial".to_vec(), KvTtl::no_expiration()))
            },
            |current| {
                assert_eq!(current.live_value(), b"initial");
                assert!(current.database_timestamp().as_i64() > 0);
                Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
            },
        )
        .await
        .expect("initialize and keep");
    assert_eq!(
        kept_initial,
        KvAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: b"initial".to_vec(),
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &keep_initial_key)
            .await
            .expect("get initialized key"),
        b"initial"
    );

    let preserved_initial_ttl = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &preserve_initial_ttl_key,
            |_| {
                Ok::<_, KvError>((
                    b"initial-expiring".to_vec(),
                    KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
                ))
            },
            |current| {
                assert_eq!(current.live_value(), b"initial-expiring");
                Ok::<_, KvError>(KvAtomicMutation::SetBytesPreservingExpiration {
                    value: b"replacement-expiring".to_vec(),
                })
            },
        )
        .await
        .expect("initialize and preserve initial ttl");
    assert_eq!(
        preserved_initial_ttl,
        KvAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: b"initial-expiring".to_vec(),
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &preserve_initial_ttl_key)
            .await
            .expect("get replacement before ttl"),
        b"replacement-expiring"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(
        store
            .get_bytes(&test_database.paranoid_pool, &preserve_initial_ttl_key)
            .await,
        Err(KvError::KeyNotFound)
    ));

    let deleted_initial = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &delete_initial_key,
            |_| Ok::<_, KvError>((b"delete-initial".to_vec(), KvTtl::no_expiration())),
            |current| {
                assert_eq!(current.live_value(), b"delete-initial");
                Ok::<_, KvError>(KvAtomicMutation::Delete)
            },
        )
        .await
        .expect("initialize and delete");
    assert_eq!(
        deleted_initial,
        KvAtomicLiveOrInitMutationResult {
            initialized: true,
            live_value_seen_by_callback: b"delete-initial".to_vec(),
            outcome: KvAtomicMutationOutcome::DeletedAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &delete_initial_key,
        )
        .await,
        0
    );

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &existing_key,
            b"existing",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set existing");
    let existing_initializer_calls = AtomicUsize::new(0);
    let existing_updated = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &existing_key,
            |_| {
                existing_initializer_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, KvError>((b"unused".to_vec(), KvTtl::no_expiration()))
            },
            |current| {
                assert_eq!(current.live_value(), b"existing");
                Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                    value: b"updated".to_vec(),
                    ttl: KvTtl::no_expiration(),
                })
            },
        )
        .await
        .expect("mutate existing");
    assert_eq!(
        existing_updated,
        KvAtomicLiveOrInitMutationResult {
            initialized: false,
            live_value_seen_by_callback: b"existing".to_vec(),
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    assert_eq!(existing_initializer_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &existing_key)
            .await
            .expect("get updated existing key"),
        b"updated"
    );

    let existing_callback_error_initializer_calls = AtomicUsize::new(0);
    let existing_callback_error = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &existing_key,
            |_| {
                existing_callback_error_initializer_calls.fetch_add(1, Ordering::SeqCst);
                Err::<(Vec<u8>, KvTtl), _>(KvError::KeyNotFound)
            },
            |current| {
                assert_eq!(current.live_value(), b"updated");
                Err::<KvAtomicMutation, _>(KvError::KeyNotFound)
            },
        )
        .await
        .expect_err("existing callback error should be returned");
    assert!(matches!(existing_callback_error, KvError::KeyNotFound));
    assert_eq!(
        existing_callback_error_initializer_calls.load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &existing_key)
            .await
            .expect("existing key remains unchanged after callback error"),
        b"updated"
    );

    let initializer_error_callback_calls = AtomicUsize::new(0);
    let initializer_error = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &initializer_error_key,
            |_| Err::<(Vec<u8>, KvTtl), _>(KvError::KeyNotFound),
            |_| {
                initializer_error_callback_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
            },
        )
        .await
        .expect_err("initializer error should be returned");
    assert!(matches!(initializer_error, KvError::KeyNotFound));
    assert_eq!(initializer_error_callback_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &initializer_error_key,
        )
        .await,
        0
    );

    let callback_error_initializer_calls = AtomicUsize::new(0);
    let callback_error = store
        .mutate_live_key_or_insert_initial_value_atomically(
            &test_database.paranoid_pool,
            &callback_error_key,
            |_| {
                callback_error_initializer_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, KvError>((b"transient".to_vec(), KvTtl::no_expiration()))
            },
            |current| {
                assert_eq!(current.live_value(), b"transient");
                Err::<KvAtomicMutation, _>(KvError::KeyNotFound)
            },
        )
        .await
        .expect_err("callback error should be returned");
    assert!(matches!(callback_error, KvError::KeyNotFound));
    assert_eq!(callback_error_initializer_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &callback_error_key,
        )
        .await,
        0
    );

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback tx");
    store
        .mutate_live_key_or_insert_initial_value_atomically_in_current_transaction(
            &mut rollback_tx,
            &rollback_key,
            |_| Ok::<_, KvError>((b"rollback-initial".to_vec(), KvTtl::no_expiration())),
            |current| {
                assert_eq!(current.live_value(), b"rollback-initial");
                Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                    value: b"rollback-final".to_vec(),
                    ttl: KvTtl::no_expiration(),
                })
            },
        )
        .await
        .expect("mutate inside rollback tx");
    rollback_tx.rollback().await.expect("rollback");
    assert!(matches!(
        store
            .get_bytes(&test_database.paranoid_pool, &rollback_key)
            .await,
        Err(KvError::KeyNotFound)
    ));

    let counter_initializer_calls = Arc::new(AtomicUsize::new(0));
    let handles = (0..25)
        .map(|_| {
            let task_pool = test_database.paranoid_pool.clone();
            let task_store = store.clone();
            let task_key = counter_key.clone();
            let task_initializer_calls = counter_initializer_calls.clone();
            tokio::spawn(async move {
                task_store
                    .mutate_live_key_or_insert_initial_value_atomically(
                        &task_pool,
                        &task_key,
                        |_| {
                            task_initializer_calls.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, KvError>((0_i64.to_be_bytes().to_vec(), KvTtl::no_expiration()))
                        },
                        |current| {
                            let current_value = i64::from_be_bytes(
                                current.live_value().try_into().expect("i64 bytes"),
                            );
                            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                                value: (current_value + 1).to_be_bytes().to_vec(),
                                ttl: KvTtl::no_expiration(),
                            })
                        },
                    )
                    .await
                    .expect("increment raw counter")
                    .initialized
            })
        })
        .collect::<Vec<_>>();

    let mut initialized_count = 0;
    for handle in handles {
        if handle.await.expect("join raw counter task") {
            initialized_count += 1;
        }
    }
    assert_eq!(initialized_count, 1);
    assert_eq!(counter_initializer_calls.load(Ordering::SeqCst), 1);
    let final_counter_bytes = store
        .get_bytes(&test_database.paranoid_pool, &counter_key)
        .await
        .expect("get final counter");
    assert_eq!(
        i64::from_be_bytes(final_counter_bytes.try_into().expect("i64 bytes")),
        25
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
