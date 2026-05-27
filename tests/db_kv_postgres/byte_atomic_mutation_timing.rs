use super::*;

#[tokio::test]
async fn kv_atomic_mutation_preserves_expiration_and_exposes_database_timestamp() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let expiring_key = KvKey::from_parts(["atomic", "preserve-expiring"]).expect("key");
    let no_expiration_key = KvKey::from_parts(["atomic", "preserve-no-expiration"]).expect("key");
    let absent_key = KvKey::from_parts(["atomic", "preserve-absent"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &expiring_key,
            b"original",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set expiring");

    let mut expiring_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin expiring tx");
    let mut observed_database_timestamp = None;
    let preserved = store
        .mutate_key_atomically_in_current_transaction(&mut expiring_tx, &expiring_key, |current| {
            assert_eq!(current.live_value(), Some(b"original".as_slice()));
            observed_database_timestamp = Some(current.database_timestamp());
            Ok::<_, KvError>(KvAtomicMutation::SetBytesPreservingExpiration {
                value: b"updated".to_vec(),
            })
        })
        .await
        .expect("preserve expiration mutation");
    assert_eq!(
        preserved,
        KvAtomicMutationResult {
            previous_live_value: Some(b"original".to_vec()),
            outcome: KvAtomicMutationOutcome::SetBytesPreservingExpiration,
        }
    );
    expiring_tx.commit().await.expect("commit expiring tx");
    let observed_database_timestamp =
        observed_database_timestamp.expect("callback observed database timestamp");
    assert!(observed_database_timestamp.as_i64() > 0);
    assert!(
        observed_database_timestamp.as_i64()
            <= fetch_statement_timestamp_microseconds(&test_database.sqlx_pool).await
    );
    assert_eq!(
        store
            .get_bytes(&test_database.paranoid_pool, &expiring_key)
            .await
            .expect("get updated"),
        b"updated"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(
        store
            .get_bytes(&test_database.paranoid_pool, &expiring_key)
            .await,
        Err(KvError::KeyNotFound)
    ));

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &no_expiration_key,
            b"forever",
            KvTtl::no_expiration(),
        )
        .await
        .expect("set no expiration");
    let mut no_expiration_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin no expiration tx");
    store
        .mutate_key_atomically_in_current_transaction(
            &mut no_expiration_tx,
            &no_expiration_key,
            |current| {
                assert_eq!(current.live_value(), Some(b"forever".as_slice()));
                Ok::<_, KvError>(KvAtomicMutation::SetBytesPreservingExpiration {
                    value: b"still-forever".to_vec(),
                })
            },
        )
        .await
        .expect("preserve no expiration mutation");
    no_expiration_tx
        .commit()
        .await
        .expect("commit no expiration tx");
    assert!(
        fetch_key_has_null_expiration(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &no_expiration_key,
        )
        .await
    );

    let mut absent_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin absent tx");
    let absent_err = store
        .mutate_key_atomically_in_current_transaction(&mut absent_tx, &absent_key, |current| {
            assert_eq!(current.live_value(), None);
            Ok::<_, KvError>(KvAtomicMutation::SetBytesPreservingExpiration {
                value: b"impossible".to_vec(),
            })
        })
        .await
        .expect_err("cannot preserve expiration for absent key");
    assert!(matches!(absent_err, KvError::KeyNotFound));
    absent_tx.commit().await.expect("commit absent tx");
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        2
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_atomic_mutation_applies_to_locked_live_row_even_if_ttl_expires_during_callback() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let preserve_key = KvKey::from_parts(["atomic", "ttl-expires-preserve"]).expect("key");
    let delete_key = KvKey::from_parts(["atomic", "ttl-expires-delete"]).expect("key");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &preserve_key,
            b"original",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set preserve key");
    let preserve_result = store
        .mutate_key_atomically(&test_database.paranoid_pool, &preserve_key, |current| {
            assert_eq!(current.live_value(), Some(b"original".as_slice()));
            std::thread::sleep(Duration::from_millis(1200));
            Ok::<_, KvError>(KvAtomicMutation::SetBytesPreservingExpiration {
                value: b"updated-after-expiry".to_vec(),
            })
        })
        .await
        .expect("preserve mutation after ttl crosses expiry");
    assert_eq!(
        preserve_result.outcome,
        KvAtomicMutationOutcome::SetBytesPreservingExpiration
    );
    assert!(matches!(
        store
            .get_bytes(&test_database.paranoid_pool, &preserve_key)
            .await,
        Err(KvError::KeyNotFound)
    ));
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &preserve_key,
        )
        .await,
        1
    );
    assert_eq!(
        fetch_key_raw_value(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &preserve_key,
        )
        .await,
        b"updated-after-expiry"
    );

    store
        .set_bytes(
            &test_database.paranoid_pool,
            &delete_key,
            b"delete-me",
            KvTtl::expires_after(Duration::from_secs(1)).expect("ttl"),
        )
        .await
        .expect("set delete key");
    let delete_result = store
        .mutate_key_atomically(&test_database.paranoid_pool, &delete_key, |current| {
            assert_eq!(current.live_value(), Some(b"delete-me".as_slice()));
            std::thread::sleep(Duration::from_millis(1200));
            Ok::<_, KvError>(KvAtomicMutation::Delete)
        })
        .await
        .expect("delete mutation after ttl crosses expiry");
    assert_eq!(
        delete_result.outcome,
        KvAtomicMutationOutcome::DeletedLiveValue
    );
    assert_eq!(
        fetch_physical_key_row_count(
            &test_database.sqlx_pool,
            &test_database.config.table_name,
            &delete_key,
        )
        .await,
        0
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
