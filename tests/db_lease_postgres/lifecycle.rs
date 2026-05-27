use super::*;

#[tokio::test]
async fn lease_claim_blocks_contention_and_release_preserves_fencing_progression() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["fleet", "leader"]).expect("key");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let empty_snapshot: Option<LeaseHolderSnapshot> = store
        .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
        .await
        .expect("fetch empty holder");
    assert!(empty_snapshot.is_none());

    let first_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &first_holder, duration)
        .await
        .expect("first claim")
        .expect("first holder should claim absent lease");
    assert_eq!(first_claim.holder_id(), &first_holder);
    assert_eq!(first_claim.fencing_token().as_i64(), 1);

    let first_snapshot = store
        .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
        .await
        .expect("fetch first holder")
        .expect("first holder should be visible without claim authority");
    assert_eq!(first_snapshot.key(), &key);
    assert_eq!(first_snapshot.holder_id(), &first_holder);
    assert_eq!(first_snapshot.fencing_token(), first_claim.fencing_token());
    assert_eq!(
        first_snapshot.expires_at_unix_microseconds(),
        first_claim.expires_at_unix_microseconds()
    );

    assert!(
        store
            .try_claim_lease(&test_database.paranoid_pool, &key, &second_holder, duration)
            .await
            .expect("contended claim")
            .is_none()
    );

    assert!(
        store
            .release_lease(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("release")
    );
    assert!(
        store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch after release")
            .is_none()
    );
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );
    assert_eq!(
        fetch_table_row_count(
            &test_database.sqlx_pool,
            &test_database.config.fencing_counter_table_name
        )
        .await,
        1
    );

    let second_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &second_holder, duration)
        .await
        .expect("second claim")
        .expect("released lease should be claimable");
    assert_eq!(second_claim.holder_id(), &second_holder);
    assert_eq!(second_claim.fencing_token().as_i64(), 2);
    let second_snapshot = store
        .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
        .await
        .expect("fetch second holder")
        .expect("second holder should be visible");
    assert_eq!(second_snapshot.holder_id(), &second_holder);
    assert_eq!(
        second_snapshot.fencing_token(),
        second_claim.fencing_token()
    );

    assert!(
        !store
            .release_lease(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("stale release")
    );

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn lease_fencing_counter_survives_live_state_deletion() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["fleet", "durable-fencing"]).expect("key");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let first_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &first_holder, duration)
        .await
        .expect("first claim")
        .expect("first holder should claim absent lease");
    assert_eq!(first_claim.fencing_token().as_i64(), 1);

    delete_test_lease_state_row(&test_database.sqlx_pool, &test_database.config, &key).await;
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );
    assert_eq!(
        fetch_table_row_count(
            &test_database.sqlx_pool,
            &test_database.config.fencing_counter_table_name
        )
        .await,
        1
    );

    let second_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &second_holder, duration)
        .await
        .expect("second claim")
        .expect("deleted live state should be claimable");
    assert_eq!(second_claim.fencing_token().as_i64(), 2);
    assert_eq!(second_claim.holder_id(), &second_holder);

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn lease_claim_repairs_missing_fencing_counter_from_expired_state() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["fleet", "counter-repair"]).expect("key");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let short_duration = LeaseDuration::expires_after(Duration::from_secs(1)).expect("duration");
    let long_duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let first_claim = store
        .try_claim_lease(
            &test_database.paranoid_pool,
            &key,
            &first_holder,
            short_duration,
        )
        .await
        .expect("first claim")
        .expect("first holder should claim absent lease");
    assert_eq!(first_claim.fencing_token().as_i64(), 1);

    delete_test_lease_fencing_counter_row(&test_database.sqlx_pool, &test_database.config, &key)
        .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let second_claim = store
        .try_claim_lease(
            &test_database.paranoid_pool,
            &key,
            &second_holder,
            long_duration,
        )
        .await
        .expect("second claim")
        .expect("expired state should be claimable even after counter loss");
    assert_eq!(second_claim.fencing_token().as_i64(), 2);
    assert_eq!(second_claim.holder_id(), &second_holder);

    drop_test_lease_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn lease_expiry_takeover_rejects_stale_renew_and_release() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["queue", "sweeper"]).expect("key");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let short_duration = LeaseDuration::expires_after(Duration::from_secs(1)).expect("duration");
    let long_duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let first_claim = store
        .try_claim_lease(
            &test_database.paranoid_pool,
            &key,
            &first_holder,
            short_duration,
        )
        .await
        .expect("first claim")
        .expect("first holder should claim absent lease");

    tokio::time::sleep(Duration::from_millis(1200)).await;

    assert!(
        store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch expired holder")
            .is_none()
    );

    let second_claim = store
        .try_claim_lease(
            &test_database.paranoid_pool,
            &key,
            &second_holder,
            long_duration,
        )
        .await
        .expect("takeover claim")
        .expect("expired lease should be claimable");
    assert_eq!(second_claim.holder_id(), &second_holder);
    assert_eq!(second_claim.fencing_token().as_i64(), 2);

    assert!(
        store
            .try_renew_lease(&test_database.paranoid_pool, &first_claim, long_duration)
            .await
            .expect("stale renew")
            .is_none()
    );
    assert!(
        !store
            .release_lease(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("stale release")
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_renew_rotates_claim_token_and_keeps_fencing_token() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["fleet", "membership"]).expect("key");
    let holder = LeaseHolderId::new("worker-a").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let first_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &holder, duration)
        .await
        .expect("claim")
        .expect("holder should claim absent lease");
    tokio::time::sleep(Duration::from_millis(10)).await;
    let renewed_claim = store
        .try_renew_lease(&test_database.paranoid_pool, &first_claim, duration)
        .await
        .expect("renew")
        .expect("live lease should renew");

    assert_eq!(renewed_claim.key(), &key);
    assert_eq!(renewed_claim.holder_id(), &holder);
    assert_eq!(renewed_claim.fencing_token(), first_claim.fencing_token());
    assert!(
        renewed_claim.expires_at_unix_microseconds() > first_claim.expires_at_unix_microseconds()
    );

    assert!(
        store
            .try_renew_lease(&test_database.paranoid_pool, &first_claim, duration)
            .await
            .expect("old claim renew")
            .is_none()
    );
    assert!(
        !store
            .release_lease(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("old claim release")
    );
    assert!(
        store
            .release_lease(&test_database.paranoid_pool, &renewed_claim)
            .await
            .expect("new claim release")
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
