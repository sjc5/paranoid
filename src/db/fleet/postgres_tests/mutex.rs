use super::*;

#[tokio::test]
async fn fleet_mutex_claim_contention_renew_release_and_fencing_progression() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex_key = MutexKey::new("leader").expect("mutex key");
    let mutex = store
        .new_mutex(
            mutex_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new mutex");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(
        mutex
            .fetch_live_holder(&test_database.paranoid_pool)
            .await
            .expect("fetch absent holder")
            .is_none()
    );

    let first_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first claim")
        .expect("first holder should claim absent mutex");
    assert_eq!(first_claim.mutex_key(), &mutex_key);
    assert_eq!(first_claim.holder_id(), &first_holder);
    assert_eq!(first_claim.fencing_token().as_i64(), 1);

    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .try_claim_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("contended claim")
            .is_none()
    );
    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .try_claim_for_holder(&test_database.paranoid_pool, &first_holder)
            .await
            .expect("same holder reentrant claim")
            .is_none(),
        "a holder must not be able to re-enter an already live mutex claim"
    );

    let renewed_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_renew_claim(&test_database.paranoid_pool, &first_claim)
        .await
        .expect("renew")
        .expect("live claim should renew");
    assert_eq!(renewed_claim.holder_id(), &first_holder);
    assert_eq!(renewed_claim.fencing_token(), first_claim.fencing_token());
    assert!(
        renewed_claim.expires_at_unix_microseconds() >= first_claim.expires_at_unix_microseconds()
    );

    let live_holder = mutex
        .fetch_live_holder(&test_database.paranoid_pool)
        .await
        .expect("fetch holder")
        .expect("holder should be live");
    assert_eq!(live_holder.mutex_key(), &mutex_key);
    assert_eq!(live_holder.holder_id(), &first_holder);
    assert_eq!(live_holder.fencing_token(), first_claim.fencing_token());

    assert!(
        !mutex
            .begin_manual_renewal_lifecycle()
            .release_claim(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("old claim should not release after renewal")
    );
    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .release_claim(&test_database.paranoid_pool, &renewed_claim)
            .await
            .expect("renewed claim should release")
    );

    let second_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("second claim")
        .expect("released mutex should be claimable");
    assert_eq!(second_claim.holder_id(), &second_holder);
    assert_eq!(second_claim.fencing_token().as_i64(), 2);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_claim_cannot_be_used_with_different_mutex() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let duration = ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration");
    let first_mutex = store
        .new_mutex(MutexKey::new("first").expect("key"), duration)
        .expect("first mutex");
    let second_mutex = store
        .new_mutex(MutexKey::new("second").expect("key"), duration)
        .expect("second mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_claim = first_mutex
        .begin_manual_renewal_lifecycle()
        .try_claim(&test_database.paranoid_pool)
        .await
        .expect("first claim")
        .expect("first mutex should be claimable");
    let err = second_mutex
        .begin_manual_renewal_lifecycle()
        .release_claim(&test_database.paranoid_pool, &first_claim)
        .await
        .expect_err("claim should not release through another mutex");
    assert!(
        matches!(err, Error::MutexManualRenewalClaimBelongsToDifferentMutex),
        "error = {err:?}"
    );
    assert!(
        first_mutex
            .fetch_live_holder(&test_database.paranoid_pool)
            .await
            .expect("fetch first holder")
            .is_some(),
        "wrong-mutex release attempt must not release original mutex"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_release_manual_renewal_claim_noops_when_lease_row_is_missing() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex_key = MutexKey::new("missing-release-row").expect("key");
    let mutex = store
        .new_mutex(
            mutex_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim(&test_database.paranoid_pool)
        .await
        .expect("claim mutex")
        .expect("mutex should be claimable");
    delete_live_mutex_lease_row(&test_database.sqlx_pool, &test_database.config, &mutex_key).await;

    assert!(
        !mutex
            .begin_manual_renewal_lifecycle()
            .release_claim(&test_database.paranoid_pool, &claim)
            .await
            .expect("release missing row"),
        "releasing an otherwise valid claim whose row disappeared should be a false no-op"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_fetch_live_holder_propagates_database_errors() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("fetch-holder-db-error").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;

    let err = mutex
        .fetch_live_holder(&test_database.paranoid_pool)
        .await
        .expect_err("fetching holder from a missing lease table should fail");
    assert!(
        matches!(err, Error::Coordination(CoordinationError::Database(_))),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_claims_compose_inside_current_transaction_and_roll_back() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("transactional").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new mutex");
    let holder = HolderId::new("worker-a").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let mut migration_rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin migration rollback transaction");
    store
        .migrate_schema_in_current_transaction(&mut migration_rollback_tx)
        .await
        .expect("migrate Fleet schema inside rollback transaction");
    store
        .validate_schema_in_current_transaction(&mut migration_rollback_tx)
        .await
        .expect("validate Fleet schema inside rollback transaction");
    migration_rollback_tx
        .rollback()
        .await
        .expect("rollback migration transaction");
    assert!(
        !fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.state_table_name
        )
        .await
    );
    assert!(
        !fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.coordination_table_name
        )
        .await
    );
    assert!(
        !fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.fencing_counter_table_name
        )
        .await
    );

    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    let rollback_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder_in_current_transaction(&mut rollback_tx, &holder)
        .await
        .expect("claim inside rollback transaction")
        .expect("mutex should be claimable inside rollback transaction");
    assert_eq!(rollback_claim.fencing_token().as_i64(), 1);
    assert!(
        mutex
            .fetch_live_holder_in_current_transaction(&mut rollback_tx)
            .await
            .expect("fetch holder inside rollback transaction")
            .is_some()
    );
    rollback_tx.rollback().await.expect("rollback transaction");

    assert!(
        mutex
            .fetch_live_holder(&test_database.paranoid_pool)
            .await
            .expect("fetch holder after rollback")
            .is_none()
    );
    let committed_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder(&test_database.paranoid_pool, &holder)
        .await
        .expect("claim after rollback")
        .expect("rolled-back claim should leave mutex absent");
    assert_eq!(committed_claim.fencing_token().as_i64(), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_renews_until_explicit_release() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-renew").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");
    let config = fast_mutex_guard_config();

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = mutex
        .try_claim_guard_for_holder(&test_database.paranoid_pool, &first_holder, config)
        .await
        .expect("claim guarded mutex")
        .expect("mutex should be guard-claimable");
    let initial_snapshot = guard
        .live_claim_snapshot()
        .await
        .expect("initial guard snapshot");
    assert_eq!(initial_snapshot.holder_id(), &first_holder);
    assert_eq!(initial_snapshot.fencing_token().as_i64(), 1);

    tokio::time::sleep(MIN_MUTEX_HEARTBEAT_INTERVAL * 3).await;

    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .try_claim_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("contended claim")
            .is_none(),
        "a renewing guard must keep the mutex unavailable to another holder"
    );
    let renewed_snapshot = guard
        .live_claim_snapshot()
        .await
        .expect("renewed guard snapshot");
    assert_eq!(renewed_snapshot.holder_id(), &first_holder);
    assert_eq!(
        renewed_snapshot.fencing_token(),
        initial_snapshot.fencing_token()
    );
    assert!(
        renewed_snapshot.expires_at_unix_microseconds()
            > initial_snapshot.expires_at_unix_microseconds(),
        "heartbeat should replace the claim with a later expiration"
    );
    assert!(
        guard.release().await.expect("release guard"),
        "explicit release should release the live guarded claim"
    );

    let second_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("claim after guard release")
        .expect("released guarded mutex should be claimable");
    assert_eq!(second_claim.holder_id(), &second_holder);
    assert_eq!(second_claim.fencing_token().as_i64(), 2);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_drop_on_plain_thread_releases_after_heartbeat_stops() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-drop").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = mutex
        .try_claim_guard_for_holder(
            &test_database.paranoid_pool,
            &first_holder,
            fast_mutex_guard_config(),
        )
        .await
        .expect("claim guarded mutex")
        .expect("mutex should be guard-claimable");
    assert!(guard.live_claim_snapshot().await.is_some());

    std::thread::spawn(move || drop(guard))
        .join()
        .expect("plain drop thread should not panic");

    wait_until(
        "plain-thread guard drop releases mutex",
        Duration::from_secs(2),
        || {
            let mutex = mutex.clone();
            let pool = test_database.paranoid_pool.clone();
            let second_holder = second_holder.clone();
            async move {
                mutex
                    .begin_manual_renewal_lifecycle()
                    .try_claim_for_holder(&pool, &second_holder)
                    .await
                    .expect("claim after dropped guard")
                    .is_some()
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_blocking_acquire_waits_for_release() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-blocking").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");
    let config = fast_mutex_guard_config();

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_guard = mutex
        .try_claim_guard_for_holder(&test_database.paranoid_pool, &first_holder, config)
        .await
        .expect("claim first guarded mutex")
        .expect("first holder should claim mutex");

    let waiting_mutex = mutex.clone();
    let waiting_pool = test_database.paranoid_pool.clone();
    let waiting_handle = tokio::spawn(async move {
        waiting_mutex
            .claim_guard_for_holder_when_available(&waiting_pool, &second_holder, config)
            .await
            .expect("blocking guarded claim")
    });

    tokio::time::sleep(config.acquire_retry_interval.expect("retry interval") * 2).await;
    assert!(
        !waiting_handle.is_finished(),
        "blocking acquire must not complete while the first guard owns the mutex"
    );

    assert!(first_guard.release().await.expect("release first guard"));
    let second_guard = tokio::time::timeout(Duration::from_secs(2), waiting_handle)
        .await
        .expect("waiter should acquire after release")
        .expect("join waiter");
    let second_snapshot = second_guard
        .live_claim_snapshot()
        .await
        .expect("second guard snapshot");
    assert_eq!(second_snapshot.holder_id().as_str(), "worker-b");
    assert_eq!(second_snapshot.fencing_token().as_i64(), 2);
    assert!(second_guard.release().await.expect("release second guard"));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_waiting_guard_can_be_cancelled_before_claim() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-wait-cancel").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let config = fast_mutex_guard_config();

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_guard = mutex
        .try_claim_guard(&test_database.paranoid_pool, config)
        .await
        .expect("claim first guard")
        .expect("first holder should claim mutex");
    let waiting_mutex = mutex.clone();
    let waiting_pool = test_database.paranoid_pool.clone();
    let waiting_handle = tokio::spawn(async move {
        waiting_mutex
            .claim_guard_when_available(&waiting_pool, config)
            .await
    });

    tokio::time::sleep(config.acquire_retry_interval.expect("retry interval") * 2).await;
    assert!(
        !waiting_handle.is_finished(),
        "waiting mutex guard must not claim while the mutex is held"
    );
    waiting_handle.abort();
    let join_error = waiting_handle
        .await
        .expect_err("waiting guard task should be cancelled");
    assert!(join_error.is_cancelled());

    assert!(first_guard.release().await.expect("release first guard"));
    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .try_claim(&test_database.paranoid_pool)
            .await
            .expect("claim after cancelling waiter")
            .is_some(),
        "cancelling a waiting guard must not poison the mutex"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_reports_leadership_lost_after_renewal_failures() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-lost").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = mutex
        .try_claim_guard(&test_database.paranoid_pool, fast_mutex_guard_config())
        .await
        .expect("claim guarded mutex")
        .expect("mutex should be guard-claimable");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    tokio::time::timeout(Duration::from_secs(2), guard.wait_until_leadership_lost())
        .await
        .expect("guard should report leadership lost after renewal failures");
    assert!(guard.leadership_lost());
    assert!(guard.live_claim_snapshot().await.is_none());

    drop(guard);
}

#[tokio::test]
async fn fleet_mutex_guard_heartbeat_recovers_after_transient_renewal_error() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-transient-renewal-error").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let guard_config = MutexGuardConfig {
        heartbeat_interval: Some(Duration::from_millis(250)),
        max_consecutive_renewal_failures: Some(2),
        ..MutexGuardConfig::default()
    };

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = mutex
        .try_claim_guard(&test_database.paranoid_pool, guard_config)
        .await
        .expect("claim guarded mutex")
        .expect("mutex should be guard-claimable");
    let initial_snapshot = guard
        .live_claim_snapshot()
        .await
        .expect("initial guard snapshot");
    let initial_expires_at = initial_snapshot.expires_at_unix_microseconds();
    let failure_trigger = install_one_shot_update_failure_trigger_on_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;

    wait_until(
        "mutex guard heartbeat renews after transient renewal error",
        Duration::from_secs(3),
        || {
            let guard = &guard;
            async move {
                guard.live_claim_snapshot().await.is_some_and(|snapshot| {
                    snapshot.expires_at_unix_microseconds() > initial_expires_at
                })
            }
        },
    )
    .await;
    let (trigger_call_count,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT last_value FROM {}",
        failure_trigger.sequence_name.quoted()
    )))
    .fetch_one(&test_database.sqlx_pool)
    .await
    .expect("fetch one-shot trigger call count");
    assert!(
        trigger_call_count >= 2,
        "heartbeat should fail once and then renew successfully"
    );
    assert!(!guard.leadership_lost());
    assert!(guard.live_claim_snapshot().await.is_some());
    assert!(guard.release().await.expect("release guard"));

    drop_one_shot_failure_trigger(&test_database.sqlx_pool, &failure_trigger).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_release_can_be_retried_after_blocked_release_is_cancelled() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex_key = MutexKey::new("guard-release-retry").expect("key");
    let mutex = store
        .new_mutex(
            mutex_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("duration"),
        )
        .expect("new mutex");
    let config = MutexGuardConfig {
        heartbeat_interval: Some(Duration::from_secs(2)),
        acquire_retry_interval: Some(Duration::from_millis(25)),
        max_acquire_retry_interval: Some(Duration::from_millis(50)),
        max_consecutive_renewal_failures: Some(1),
    };

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut guard = mutex
        .try_claim_guard(&test_database.paranoid_pool, config)
        .await
        .expect("claim guarded mutex")
        .expect("mutex should be guard-claimable");
    let snapshot_before_blocked_release = guard
        .live_claim_snapshot()
        .await
        .expect("guard snapshot before blocked release");

    let row_lock_tx = begin_transaction_locking_live_mutex_lease_row(
        &test_database.sqlx_pool,
        &test_database.config,
        &mutex_key,
    )
    .await;

    tokio::time::timeout(Duration::from_millis(200), guard.try_release())
        .await
        .expect_err("release should block behind row lock until cancelled");
    assert_eq!(
        guard
            .live_claim_snapshot()
            .await
            .expect("guard should retain release authority after cancelled release")
            .fencing_token(),
        snapshot_before_blocked_release.fencing_token()
    );

    row_lock_tx
        .rollback()
        .await
        .expect("rollback mutex lease row lock transaction");
    assert!(
        guard.try_release().await.expect("retry guard release"),
        "guard release should succeed after the blocked release future is cancelled"
    );
    assert!(guard.live_claim_snapshot().await.is_none());

    let next_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim(&test_database.paranoid_pool)
        .await
        .expect("claim after retried guard release")
        .expect("mutex should be claimable after retried release");
    assert_eq!(
        next_claim.fencing_token().as_i64(),
        snapshot_before_blocked_release.fencing_token().as_i64() + 1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_release_cancellation_keeps_heartbeat_active_until_retry() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex_key = MutexKey::new("release-cancel-heartbeat").expect("key");
    let mutex = store
        .new_mutex(
            mutex_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut guard = mutex
        .try_claim_guard(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
                acquire_retry_interval: Some(Duration::from_millis(25)),
                max_acquire_retry_interval: Some(Duration::from_millis(50)),
                max_consecutive_renewal_failures: Some(3),
            },
        )
        .await
        .expect("claim guarded mutex")
        .expect("mutex should be guard-claimable");
    let snapshot_before_blocked_release = guard
        .live_claim_snapshot()
        .await
        .expect("guard snapshot before blocked release");
    let expires_at_before_blocked_release =
        snapshot_before_blocked_release.expires_at_unix_microseconds();

    let row_lock_tx = begin_transaction_locking_live_mutex_lease_row(
        &test_database.sqlx_pool,
        &test_database.config,
        &mutex_key,
    )
    .await;

    tokio::time::timeout(Duration::from_millis(200), guard.try_release())
        .await
        .expect_err("release should block behind row lock until cancelled");
    row_lock_tx
        .rollback()
        .await
        .expect("rollback mutex lease row lock transaction");

    wait_until(
        "mutex guard heartbeat renews after cancelled release",
        Duration::from_secs(2),
        || {
            let guard = &guard;
            async move {
                guard.live_claim_snapshot().await.is_some_and(|snapshot| {
                    snapshot.expires_at_unix_microseconds() > expires_at_before_blocked_release
                })
            }
        },
    )
    .await;
    assert!(
        guard.try_release().await.expect("retry guard release"),
        "guard release should succeed after heartbeat survives cancelled release"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_guard_config_rejects_invalid_runtime_options() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(StoreConfig::default()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("guard-config").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");

    let heartbeat_err = mutex
        .try_claim_guard(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_millis(1)),
                ..MutexGuardConfig::default()
            },
        )
        .await
        .expect_err("too-short heartbeat should fail before database work");
    assert!(
        matches!(heartbeat_err, Error::InvalidMutexHeartbeatInterval { .. }),
        "error = {heartbeat_err:?}"
    );

    let retry_err = mutex
        .try_claim_guard(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                acquire_retry_interval: Some(Duration::ZERO),
                ..MutexGuardConfig::default()
            },
        )
        .await
        .expect_err("zero retry interval should fail before database work");
    assert!(
        matches!(retry_err, Error::InvalidMutexAcquireRetryInterval),
        "error = {retry_err:?}"
    );

    let max_retry_err = mutex
        .try_claim_guard(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                acquire_retry_interval: Some(Duration::from_millis(200)),
                max_acquire_retry_interval: Some(Duration::from_millis(100)),
                ..MutexGuardConfig::default()
            },
        )
        .await
        .expect_err("max retry interval below initial interval should fail before database work");
    assert!(
        matches!(max_retry_err, Error::InvalidMutexMaxAcquireRetryInterval),
        "error = {max_retry_err:?}"
    );

    let max_failures_err = mutex
        .try_claim_guard(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                max_consecutive_renewal_failures: Some(0),
                ..MutexGuardConfig::default()
            },
        )
        .await
        .expect_err("zero max failures should fail before database work");
    assert!(
        matches!(
            max_failures_err,
            Error::InvalidMutexMaxConsecutiveRenewalFailures
        ),
        "error = {max_failures_err:?}"
    );

    let lease_too_short_err = mutex
        .try_claim_guard(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_millis(600)),
                ..MutexGuardConfig::default()
            },
        )
        .await
        .expect_err("lease shorter than heartbeat envelope should fail before database work");
    assert!(
        matches!(
            lease_too_short_err,
            Error::MutexClaimDurationTooShortForHeartbeat { .. }
        ),
        "error = {lease_too_short_err:?}"
    );
}

#[tokio::test]
async fn fleet_mutex_try_run_task_runs_and_releases() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex_key = MutexKey::new("task-run").expect("key");
    let mutex = store
        .new_mutex(
            mutex_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let holder = HolderId::new("task-holder").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let expected_mutex_key = mutex_key.clone();
    let expected_holder = holder.clone();
    let result = mutex
        .try_run_task_for_holder(
            &test_database.paranoid_pool,
            &holder,
            fast_mutex_guard_config(),
            |snapshot| async move {
                assert_eq!(snapshot.mutex_key(), &expected_mutex_key);
                assert_eq!(snapshot.holder_id(), &expected_holder);
                Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
            },
        )
        .await
        .expect("run task");
    assert_eq!(result, MutexTryRunTaskResult::Ran(1));
    assert!(
        mutex
            .fetch_live_holder(&test_database.paranoid_pool)
            .await
            .expect("fetch holder after task")
            .is_none(),
        "task helper must release after success"
    );
    let next_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim(&test_database.paranoid_pool)
        .await
        .expect("claim after task")
        .expect("mutex should be claimable after task");
    assert_eq!(next_claim.fencing_token().as_i64(), 2);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_try_run_task_reports_mutex_held() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("task-held").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let config = fast_mutex_guard_config();

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = mutex
        .try_claim_guard(&test_database.paranoid_pool, config)
        .await
        .expect("claim guard")
        .expect("mutex should be claimable");
    let task_ran = Arc::new(AtomicUsize::new(0));
    let task_ran_inside = Arc::clone(&task_ran);
    let result = mutex
        .try_run_task(&test_database.paranoid_pool, config, move |_| {
            let task_ran_inside = Arc::clone(&task_ran_inside);
            async move {
                task_ran_inside.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        })
        .await
        .expect("try run while held");
    assert_eq!(result, MutexTryRunTaskResult::MutexHeld);
    assert_eq!(task_ran.load(Ordering::SeqCst), 0);

    assert!(guard.release().await.expect("release guard"));
    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_try_run_task_returns_release_error_when_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("try-run-release-error").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let err = mutex
        .try_run_task(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_secs(2)),
                ..fast_mutex_guard_config()
            },
            move |_| {
                let sqlx_pool = sqlx_pool.clone();
                let config = config.clone();
                async move {
                    drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
        .expect_err("release failure should be returned");
    assert!(
        matches!(
            err,
            MutexRunError::Release {
                source: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_run_task_when_available_returns_release_error_when_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("run-task-release-error").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let err = mutex
        .run_task_when_available(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_secs(2)),
                ..fast_mutex_guard_config()
            },
            move |_| {
                let sqlx_pool = sqlx_pool.clone();
                let config = config.clone();
                async move {
                    drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
        .expect_err("release failure should be returned");
    assert!(
        matches!(
            err,
            MutexRunError::Release {
                source: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_run_task_when_available_waits_for_release() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("task-wait").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");
    let first_holder = HolderId::new("first-task-holder").expect("holder");
    let second_holder = HolderId::new("second-task-holder").expect("holder");
    let config = fast_mutex_guard_config();

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_guard = mutex
        .try_claim_guard_for_holder(&test_database.paranoid_pool, &first_holder, config)
        .await
        .expect("claim first guard")
        .expect("first holder should claim mutex");
    let waiting_mutex = mutex.clone();
    let waiting_pool = test_database.paranoid_pool.clone();
    let waiting_handle = tokio::spawn(async move {
        waiting_mutex
            .run_task_for_holder_when_available(&waiting_pool, &second_holder, config, |snapshot| async move {
                Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
            })
            .await
    });

    tokio::time::sleep(config.acquire_retry_interval.expect("retry interval") * 2).await;
    assert!(
        !waiting_handle.is_finished(),
        "blocking task runner must not run while another guard owns the mutex"
    );

    assert!(first_guard.release().await.expect("release first guard"));
    let result = tokio::time::timeout(Duration::from_secs(2), waiting_handle)
        .await
        .expect("waiter should run after release")
        .expect("join waiter")
        .expect("waiting task result");
    assert_eq!(result, 2);
    assert!(
        mutex
            .fetch_live_holder(&test_database.paranoid_pool)
            .await
            .expect("fetch holder after waiting task")
            .is_none()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_run_task_error_releases_mutex() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("task-error").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let err = mutex
        .run_task_when_available(
            &test_database.paranoid_pool,
            fast_mutex_guard_config(),
            |_| async { Err::<(), _>(TestComputeError("mutex task failed")) },
        )
        .await
        .expect_err("task error should be returned");
    assert!(
        matches!(
            err,
            MutexRunError::Task {
                source: TestComputeError("mutex task failed")
            }
        ),
        "error = {err:?}"
    );
    assert!(
        mutex
            .fetch_live_holder(&test_database.paranoid_pool)
            .await
            .expect("fetch holder after task error")
            .is_none(),
        "task helper must release after task error"
    );
    let next_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim(&test_database.paranoid_pool)
        .await
        .expect("claim after task error")
        .expect("mutex should be claimable after task error");
    assert_eq!(next_claim.fencing_token().as_i64(), 2);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_run_task_when_available_returns_task_and_release_errors_when_both_fail() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("run-task-and-release-error").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let err = mutex
        .run_task_when_available(
            &test_database.paranoid_pool,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_secs(2)),
                ..fast_mutex_guard_config()
            },
            move |_| {
                let sqlx_pool = sqlx_pool.clone();
                let config = config.clone();
                async move {
                    drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
                    Err::<(), _>(TestComputeError("mutex task failed before release"))
                }
            },
        )
        .await
        .expect_err("task and release failure should both be returned");
    assert!(
        matches!(
            err,
            MutexRunError::TaskAndRelease {
                source: TestComputeError("mutex task failed before release"),
                release_error: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_cancelled_task_drop_releases_mutex() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("task-cancel").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let (task_started_sender, task_started_receiver) = tokio::sync::oneshot::channel();
    let task_mutex = mutex.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let task_handle = tokio::spawn(async move {
        task_mutex
            .run_task_when_available(&task_pool, fast_mutex_guard_config(), move |_| async move {
                task_started_sender.send(()).expect("send task started");
                std::future::pending::<Result<(), TestComputeError>>().await
            })
            .await
    });

    task_started_receiver.await.expect("task should start");
    task_handle.abort();
    let join_error = task_handle
        .await
        .expect_err("mutex task should be cancelled");
    assert!(join_error.is_cancelled());

    wait_until(
        "cancelled mutex task releases",
        Duration::from_secs(2),
        || {
            let mutex = mutex.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                mutex
                    .begin_manual_renewal_lifecycle()
                    .try_claim(&pool)
                    .await
                    .expect("claim after task cancellation")
                    .is_some()
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_task_panic_drop_releases_mutex() {
    async fn panic_task(_: MutexGuardSnapshot) -> Result<(), TestComputeError> {
        panic!("mutex task panic")
    }

    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = store
        .new_mutex(
            MutexKey::new("task-panic").expect("key"),
            ClaimDuration::expires_after(Duration::from_secs(1)).expect("duration"),
        )
        .expect("new mutex");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_mutex = mutex.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let task_handle = tokio::spawn(async move {
        task_mutex
            .try_run_task(&task_pool, fast_mutex_guard_config(), panic_task)
            .await
    });
    let join_error = task_handle.await.expect_err("task should panic");
    assert!(join_error.is_panic());

    wait_until(
        "panic-dropped mutex task releases",
        Duration::from_secs(2),
        || {
            let mutex = mutex.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                mutex
                    .begin_manual_renewal_lifecycle()
                    .try_claim(&pool)
                    .await
                    .expect("claim after task panic")
                    .is_some()
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_mutex_concurrent_try_claim_allows_one_winner_per_round() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let mutex = Arc::new(
        store
            .new_mutex(
                MutexKey::new("concurrent-try-claim").expect("key"),
                ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
            )
            .expect("new mutex"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for round in 0..2 {
        let worker_count = 10;
        let barrier = Arc::new(Barrier::new(worker_count));
        let mut handles = Vec::with_capacity(worker_count);

        for index in 0..worker_count {
            let mutex = Arc::clone(&mutex);
            let pool = test_database.paranoid_pool.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                let holder =
                    HolderId::new(format!("round-{round}-worker-{index}")).expect("holder");
                barrier.wait().await;
                mutex
                    .begin_manual_renewal_lifecycle()
                    .try_claim_for_holder(&pool, &holder)
                    .await
                    .expect("concurrent claim")
            }));
        }

        let mut claims = Vec::new();
        for handle in handles {
            if let Some(claim) = handle.await.expect("join worker") {
                claims.push(claim);
            }
        }
        assert_eq!(
            claims.len(),
            1,
            "round {round} should have exactly one winner"
        );
        assert!(
            mutex
                .begin_manual_renewal_lifecycle()
                .release_claim(&test_database.paranoid_pool, &claims[0])
                .await
                .expect("release round winner")
        );
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
