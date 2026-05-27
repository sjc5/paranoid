use super::*;

#[tokio::test]
async fn lease_claims_compose_inside_current_transaction_and_roll_back() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["transaction", "lease"]).expect("key");
    let holder = LeaseHolderId::new("worker-a").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin tx");
    let in_transaction_claim = store
        .try_claim_lease_in_current_transaction(&mut tx, &key, &holder, duration)
        .await
        .expect("claim in tx")
        .expect("transaction should claim absent lease");
    assert_eq!(in_transaction_claim.fencing_token().as_i64(), 1);
    let in_transaction_snapshot = store
        .fetch_live_lease_holder_in_current_transaction(&mut tx, &key)
        .await
        .expect("fetch holder in tx")
        .expect("transaction should see its own lease");
    assert_eq!(in_transaction_snapshot.holder_id(), &holder);
    assert_eq!(
        in_transaction_snapshot.fencing_token(),
        in_transaction_claim.fencing_token()
    );
    tx.rollback().await.expect("rollback");

    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );
    let committed_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &holder, duration)
        .await
        .expect("claim after rollback")
        .expect("rolled-back lease should be absent");
    assert_eq!(committed_claim.fencing_token().as_i64(), 1);

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_future_abort_while_waiting_for_pool_connection_does_not_mutate_later() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres lease test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let paranoid_pool = connect_paranoid_pool_with_max_connections(&database_url, 1).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = LeaseStoreConfig::new(unique_test_table_name());
    let store = LeaseStore::new(config.clone());
    let key = LeaseKey::from_parts(["cancel", "lease"]).expect("key");
    let holder = LeaseHolderId::new("worker-a").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&sqlx_pool, &config.table_name).await;
    store.migrate_schema(&paranoid_pool).await.expect("migrate");

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (claim_started_tx, claim_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_key = key.clone();
    let task_holder = holder.clone();
    let claim_handle = tokio::spawn(async move {
        claim_started_tx.send(()).expect("send claim started");
        task_store
            .try_claim_lease(&task_pool, &task_key, &task_holder, duration)
            .await
            .expect("claim after waiting for pool connection");
    });

    claim_started_rx.await.expect("claim task started");
    abort_blocked_task(claim_handle, "claim").await;

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fetch_table_row_count(&sqlx_pool, &config.table_name).await,
        0
    );

    let claim = Arc::new(
        store
            .try_claim_lease(&paranoid_pool, &key, &holder, duration)
            .await
            .expect("claim")
            .expect("claim should succeed after aborted claim"),
    );

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (renew_started_tx, renew_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_claim = Arc::clone(&claim);
    let renew_handle = tokio::spawn(async move {
        renew_started_tx.send(()).expect("send renew started");
        task_store
            .try_renew_lease(&task_pool, &task_claim, duration)
            .await
            .expect("renew after waiting for pool connection");
    });

    renew_started_rx.await.expect("renew task started");
    abort_blocked_task(renew_handle, "renew").await;

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let held_transaction = paranoid_pool
        .begin_transaction()
        .await
        .expect("begin held transaction");

    let (release_started_tx, release_started_rx) = oneshot::channel();
    let task_pool = paranoid_pool.clone();
    let task_store = store.clone();
    let task_claim = Arc::clone(&claim);
    let release_handle = tokio::spawn(async move {
        release_started_tx.send(()).expect("send release started");
        task_store
            .release_lease(&task_pool, &task_claim)
            .await
            .expect("release after waiting for pool connection");
    });

    release_started_rx.await.expect("release task started");
    abort_blocked_task(release_handle, "release").await;

    held_transaction
        .rollback()
        .await
        .expect("rollback held transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        store
            .release_lease(&paranoid_pool, &claim)
            .await
            .expect("original claim should still release after aborted renew and release")
    );

    drop_test_table(&sqlx_pool, &config.table_name).await;
}

#[tokio::test]
async fn lease_future_abort_while_waiting_for_row_lock_does_not_mutate_later() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["cancel", "row-lock", "lease"]).expect("key");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let third_holder = LeaseHolderId::new("worker-c").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let old_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &first_holder, duration)
        .await
        .expect("old claim")
        .expect("old holder should claim absent lease");
    assert!(
        store
            .release_lease(&test_database.paranoid_pool, &old_claim)
            .await
            .expect("release old claim")
    );

    let mut claim_lock_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin claim lock transaction");
    let first_blocking_claim = store
        .try_claim_lease_in_current_transaction(&mut claim_lock_tx, &key, &first_holder, duration)
        .await
        .expect("first blocking claim")
        .expect("expired lease should be claimable inside blocking transaction");
    assert_eq!(first_blocking_claim.fencing_token().as_i64(), 2);

    let task_pool = test_database.paranoid_pool.clone();
    let task_store = store.clone();
    let task_key = key.clone();
    let task_holder = second_holder.clone();
    let competing_claim_handle = tokio::spawn(async move {
        task_store
            .try_claim_lease(&task_pool, &task_key, &task_holder, duration)
            .await
            .expect("competing claim after row lock release");
    });
    abort_blocked_task(competing_claim_handle, "competing claim").await;
    claim_lock_tx
        .rollback()
        .await
        .expect("rollback claim lock transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch after aborted competing claim")
            .is_none()
    );

    let current_claim = Arc::new(
        store
            .try_claim_lease(&test_database.paranoid_pool, &key, &third_holder, duration)
            .await
            .expect("current claim")
            .expect("third holder should claim expired lease"),
    );
    assert_eq!(current_claim.fencing_token().as_i64(), 2);

    let mut renew_lock_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin renew lock transaction");
    let renewed_inside_transaction = store
        .try_renew_lease_in_current_transaction(
            &mut renew_lock_tx,
            current_claim.as_ref(),
            duration,
        )
        .await
        .expect("renew inside blocking transaction")
        .expect("current lease should renew inside blocking transaction");
    assert_eq!(
        renewed_inside_transaction.fencing_token(),
        current_claim.fencing_token()
    );

    let task_pool = test_database.paranoid_pool.clone();
    let task_store = store.clone();
    let task_claim = Arc::clone(&current_claim);
    let competing_renew_handle = tokio::spawn(async move {
        task_store
            .try_renew_lease(&task_pool, task_claim.as_ref(), duration)
            .await
            .expect("competing renew after row lock release");
    });
    abort_blocked_task(competing_renew_handle, "competing renew").await;
    renew_lock_tx
        .rollback()
        .await
        .expect("rollback renew lock transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut release_lock_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin release lock transaction");
    let renewed_inside_transaction = store
        .try_renew_lease_in_current_transaction(
            &mut release_lock_tx,
            current_claim.as_ref(),
            duration,
        )
        .await
        .expect("renew inside release blocking transaction")
        .expect("current lease should renew inside release blocking transaction");
    assert_eq!(
        renewed_inside_transaction.fencing_token(),
        current_claim.fencing_token()
    );

    let task_pool = test_database.paranoid_pool.clone();
    let task_store = store.clone();
    let task_claim = Arc::clone(&current_claim);
    let competing_release_handle = tokio::spawn(async move {
        task_store
            .release_lease(&task_pool, task_claim.as_ref())
            .await
            .expect("competing release after row lock release");
    });
    abort_blocked_task(competing_release_handle, "competing release").await;
    release_lock_tx
        .rollback()
        .await
        .expect("rollback release lock transaction");
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        store
            .release_lease(&test_database.paranoid_pool, current_claim.as_ref())
            .await
            .expect("original claim should still release after aborted row-lock operations")
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_claims_serialize_absent_key_races() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["race", "lease"]).expect("key");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let mut first_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin first tx");
    let first_claim = store
        .try_claim_lease_in_current_transaction(&mut first_tx, &key, &first_holder, duration)
        .await
        .expect("first claim")
        .expect("first transaction should claim absent lease");

    let second_pool = test_database.paranoid_pool.clone();
    let second_store = store.clone();
    let second_key = key.clone();
    let second_handle = tokio::spawn(async move {
        second_store
            .try_claim_lease(&second_pool, &second_key, &second_holder, duration)
            .await
            .expect("second claim")
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!second_handle.is_finished());

    first_tx.commit().await.expect("commit first tx");
    assert!(second_handle.await.expect("second task").is_none());
    assert!(
        store
            .release_lease(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("release")
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn lease_claims_serialize_expired_key_races() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = LeaseStore::new(test_database.config.clone());
    let key = LeaseKey::from_parts(["race", "expired", "lease"]).expect("key");
    let old_holder = LeaseHolderId::new("worker-old").expect("holder");
    let first_holder = LeaseHolderId::new("worker-a").expect("holder");
    let second_holder = LeaseHolderId::new("worker-b").expect("holder");
    let duration = LeaseDuration::expires_after(Duration::from_secs(60)).expect("duration");

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let old_claim = store
        .try_claim_lease(&test_database.paranoid_pool, &key, &old_holder, duration)
        .await
        .expect("old claim")
        .expect("old holder should claim absent lease");
    assert!(
        store
            .release_lease(&test_database.paranoid_pool, &old_claim)
            .await
            .expect("release old claim")
    );

    let mut first_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin first tx");
    let first_claim = store
        .try_claim_lease_in_current_transaction(&mut first_tx, &key, &first_holder, duration)
        .await
        .expect("first claim")
        .expect("first transaction should claim expired lease");
    assert_eq!(first_claim.fencing_token().as_i64(), 2);

    let second_pool = test_database.paranoid_pool.clone();
    let second_store = store.clone();
    let second_key = key.clone();
    let second_handle = tokio::spawn(async move {
        second_store
            .try_claim_lease(&second_pool, &second_key, &second_holder, duration)
            .await
            .expect("second claim")
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!second_handle.is_finished());

    first_tx.commit().await.expect("commit first tx");
    assert!(second_handle.await.expect("second task").is_none());
    assert_eq!(
        store
            .fetch_live_lease_holder(&test_database.paranoid_pool, &key)
            .await
            .expect("fetch holder after race")
            .expect("first claim should remain live")
            .holder_id(),
        &first_holder
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
