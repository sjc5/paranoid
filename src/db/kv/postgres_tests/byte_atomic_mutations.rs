use super::*;

#[tokio::test]
async fn kv_atomic_mutation_handles_absent_live_expired_delete_and_rollback() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let key = KvKey::from_parts(["atomic", "lifecycle"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut create_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin create tx");
    let created = store
        .mutate_key_atomically_in_current_transaction(&mut create_tx, &key, |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"created".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("create mutation");
    assert_eq!(
        created,
        KvAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    create_tx.commit().await.expect("commit create");

    let mut keep_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin keep tx");
    let kept = store
        .mutate_key_atomically_in_current_transaction(&mut keep_tx, &key, |current| {
            assert_eq!(current.live_value(), Some(b"created".as_slice()));
            Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
        })
        .await
        .expect("keep mutation");
    assert_eq!(
        kept,
        KvAtomicMutationResult {
            previous_live_value: Some(b"created".to_vec()),
            outcome: KvAtomicMutationOutcome::KeptLiveValue,
        }
    );
    keep_tx.commit().await.expect("commit keep");

    let mut delete_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin delete tx");
    let deleted = store
        .mutate_key_atomically_in_current_transaction(&mut delete_tx, &key, |current| {
            assert!(current.has_live_value());
            Ok::<_, KvError>(KvAtomicMutation::Delete)
        })
        .await
        .expect("delete mutation");
    assert_eq!(
        deleted,
        KvAtomicMutationResult {
            previous_live_value: Some(b"created".to_vec()),
            outcome: KvAtomicMutationOutcome::DeletedLiveValue,
        }
    );
    delete_tx.commit().await.expect("commit delete");
    assert!(matches!(
        store.get_bytes(&test_database.paranoid_pool, &key).await,
        Err(KvError::KeyNotFound)
    ));

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &key,
            b"expired",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set expired candidate");
    store
        .expire_key(&test_database.paranoid_pool, &key)
        .await
        .expect("expire");

    let mut replace_expired_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin replace expired tx");
    let replaced_expired = store
        .mutate_key_atomically_in_current_transaction(&mut replace_expired_tx, &key, |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"revived".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("replace expired mutation");
    assert_eq!(
        replaced_expired,
        KvAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::SetBytes,
        }
    );
    replace_expired_tx
        .commit()
        .await
        .expect("commit replace expired");
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("get revived"),
        b"revived"
    );

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback tx");
    store
        .mutate_key_atomically_in_current_transaction(&mut rollback_tx, &key, |_| {
            Ok::<_, KvError>(KvAtomicMutation::SetBytes {
                value: b"rolled-back".to_vec(),
                ttl: KvTtl::no_expiration(),
            })
        })
        .await
        .expect("rollback mutation");
    rollback_tx.rollback().await.expect("rollback");
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &key)
            .await
            .expect("rollback preserved old value"),
        b"revived"
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_atomic_mutation_absent_and_expired_outcomes_clean_up_placeholders() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let raw_absent_keep_key = KvKey::from_parts(["atomic", "absent-keep"]).expect("key");
    let raw_absent_delete_key = KvKey::from_parts(["atomic", "absent-delete"]).expect("key");
    let raw_absent_error_key = KvKey::from_parts(["atomic", "absent-error"]).expect("key");
    let raw_expired_keep_key = KvKey::from_parts(["atomic", "expired-keep"]).expect("key");
    let raw_expired_delete_key = KvKey::from_parts(["atomic", "expired-delete"]).expect("key");
    let item_prefix = KvKeyPrefix::from_parts(["item", "atomic-absent-outcomes"]).expect("prefix");
    let item = KvItem::<TestKvPayload>::new_plain(store.clone(), item_prefix.clone());
    let typed_absent_keep_key =
        KvKey::from_prefix_and_parts(&item_prefix, ["absent-keep"]).expect("key");
    let typed_absent_delete_key =
        KvKey::from_prefix_and_parts(&item_prefix, ["absent-delete"]).expect("key");
    let typed_absent_error_key =
        KvKey::from_prefix_and_parts(&item_prefix, ["absent-error"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let raw_kept_absent = store
        .mutate_key_atomically(
            &test_database.paranoid_pool,
            &raw_absent_keep_key,
            |current| {
                assert_eq!(current.live_value(), None);
                assert!(current.database_timestamp().as_i64() > 0);
                Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
            },
        )
        .await
        .expect("keep absent raw key");
    assert_eq!(
        raw_kept_absent,
        KvAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::KeptAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &raw_absent_keep_key,
        )
        .await,
        0
    );

    let raw_deleted_absent = store
        .mutate_key_atomically(
            &test_database.paranoid_pool,
            &raw_absent_delete_key,
            |current| {
                assert_eq!(current.live_value(), None);
                Ok::<_, KvError>(KvAtomicMutation::Delete)
            },
        )
        .await
        .expect("delete absent raw key");
    assert_eq!(
        raw_deleted_absent,
        KvAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::DeletedAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &raw_absent_delete_key,
        )
        .await,
        0
    );

    let raw_absent_error = store
        .mutate_key_atomically(
            &test_database.paranoid_pool,
            &raw_absent_error_key,
            |current| {
                assert_eq!(current.live_value(), None);
                Err::<KvAtomicMutation, _>(KvError::KeyNotFound)
            },
        )
        .await
        .expect_err("raw callback error should be returned");
    assert!(matches!(raw_absent_error, KvError::KeyNotFound));
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &raw_absent_error_key,
        )
        .await,
        0
    );

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &raw_expired_keep_key,
            b"expired-keep",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set raw expired keep key");
    store
        .expire_key(&test_database.paranoid_pool, &raw_expired_keep_key)
        .await
        .expect("expire raw keep key");
    let raw_kept_expired = store
        .mutate_key_atomically(
            &test_database.paranoid_pool,
            &raw_expired_keep_key,
            |current| {
                assert_eq!(current.live_value(), None);
                Ok::<_, KvError>(KvAtomicMutation::KeepExisting)
            },
        )
        .await
        .expect("keep expired raw key");
    assert_eq!(
        raw_kept_expired,
        KvAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::KeptAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &raw_expired_keep_key,
        )
        .await,
        1
    );
    assert!(matches!(
        store
            .get_bytes(&test_database.paranoid_pool, &raw_expired_keep_key)
            .await,
        Err(KvError::KeyNotFound)
    ));

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &raw_expired_delete_key,
            b"expired-delete",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set raw expired delete key");
    store
        .expire_key(&test_database.paranoid_pool, &raw_expired_delete_key)
        .await
        .expect("expire raw delete key");
    let raw_deleted_expired = store
        .mutate_key_atomically(
            &test_database.paranoid_pool,
            &raw_expired_delete_key,
            |current| {
                assert_eq!(current.live_value(), None);
                Ok::<_, KvError>(KvAtomicMutation::Delete)
            },
        )
        .await
        .expect("delete expired raw key");
    assert_eq!(
        raw_deleted_expired,
        KvAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::DeletedAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &raw_expired_delete_key,
        )
        .await,
        0
    );

    let typed_kept_absent = item
        .mutate_atomically(&test_database.paranoid_pool, ["absent-keep"], |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvItemAtomicMutation::KeepExisting)
        })
        .await
        .expect("keep absent typed key");
    assert_eq!(
        typed_kept_absent,
        KvItemAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::KeptAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &typed_absent_keep_key,
        )
        .await,
        0
    );

    let typed_deleted_absent = item
        .mutate_atomically(&test_database.paranoid_pool, ["absent-delete"], |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvItemAtomicMutation::Delete)
        })
        .await
        .expect("delete absent typed key");
    assert_eq!(
        typed_deleted_absent,
        KvItemAtomicMutationResult {
            previous_live_value: None,
            outcome: KvAtomicMutationOutcome::DeletedAbsent,
        }
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &typed_absent_delete_key,
        )
        .await,
        0
    );

    let typed_absent_error = item
        .mutate_atomically(&test_database.paranoid_pool, ["absent-error"], |current| {
            assert_eq!(current.live_value(), None);
            Err::<KvItemAtomicMutation<TestKvPayload>, _>(KvError::KeyNotFound)
        })
        .await
        .expect_err("typed callback error should be returned");
    assert!(matches!(typed_absent_error, KvError::KeyNotFound));
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &typed_absent_error_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
