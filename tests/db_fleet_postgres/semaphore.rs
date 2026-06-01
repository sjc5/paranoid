use super::*;

#[tokio::test]
async fn fleet_semaphore_acquire_release_status_and_reset() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore_key = SemaphoreKey::new("workers").expect("semaphore key");
    let semaphore = store
        .new_semaphore(semaphore_key.clone(), 2, Duration::from_secs(60))
        .expect("new semaphore");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");
    let third_holder = HolderId::new("worker-c").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(semaphore.key(), &semaphore_key);
    assert_eq!(semaphore.max_concurrent(), 2);
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("initial status")
            .current_count(),
        0
    );

    let first_claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first acquire")
        .expect("first slot should be available");
    let second_claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("second acquire")
        .expect("second slot should be available");
    assert_eq!(first_claim.semaphore_key(), &semaphore_key);
    assert_eq!(first_claim.holder_id(), &first_holder);
    assert_eq!(second_claim.holder_id(), &second_holder);
    assert_ne!(first_claim.slot_suffix(), second_claim.slot_suffix());
    let full_status = semaphore
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("full status");
    assert_eq!(full_status.current_count(), 2);
    assert_eq!(full_status.max_count(), 2);

    assert!(
        semaphore
            .begin_manual_claim_lifecycle()
            .try_acquire_claim_for_holder(&test_database.paranoid_pool, &third_holder)
            .await
            .expect("third acquire while full")
            .is_none()
    );

    assert!(
        semaphore
            .begin_manual_claim_lifecycle()
            .release_claim(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("release first claim")
    );
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after release")
            .current_count(),
        1
    );
    let third_claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder(&test_database.paranoid_pool, &third_holder)
        .await
        .expect("third acquire after release")
        .expect("released slot should be reusable");
    assert_eq!(third_claim.holder_id(), &third_holder);

    assert_eq!(
        semaphore
            .reset(&test_database.paranoid_pool)
            .await
            .expect("reset"),
        2
    );
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after reset")
            .current_count(),
        0
    );
    assert!(
        !semaphore
            .begin_manual_claim_lifecycle()
            .release_claim(&test_database.paranoid_pool, &second_claim)
            .await
            .expect("release reset claim")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_guard_drop_on_plain_thread_releases_slot() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("guard-drop-plain-thread").expect("semaphore key"),
            1,
            Duration::from_secs(60),
        )
        .expect("new semaphore");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = semaphore
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("guard acquire")
        .expect("slot should be available");
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after guard acquire")
            .current_count(),
        1
    );

    std::thread::spawn(move || drop(guard))
        .join()
        .expect("plain drop thread should not panic");

    wait_until(
        "plain-thread semaphore guard drop releases slot",
        Duration::from_secs(2),
        || {
            let semaphore = semaphore.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                semaphore
                    .begin_manual_claim_lifecycle()
                    .try_acquire_claim(&pool)
                    .await
                    .expect("acquire after plain-thread guard drop")
                    .is_some()
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_concurrent_acquire_respects_limit() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = Arc::new(
        store
            .new_semaphore(
                SemaphoreKey::new("concurrent-semaphore").expect("semaphore key"),
                3,
                Duration::from_secs(60),
            )
            .expect("new semaphore"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_count = 10;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut handles = Vec::with_capacity(worker_count);

    for index in 0..worker_count {
        let semaphore = Arc::clone(&semaphore);
        let barrier = Arc::clone(&barrier);
        let pool = test_database.paranoid_pool.clone();
        handles.push(tokio::spawn(async move {
            let holder = HolderId::new(format!("worker-{index}")).expect("holder");
            barrier.wait().await;
            semaphore
                .begin_manual_claim_lifecycle()
                .try_acquire_claim_for_holder(&pool, &holder)
                .await
                .expect("try acquire")
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
        3,
        "semaphore should grant exactly its configured live slot count"
    );
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after concurrent acquire")
            .current_count(),
        3
    );

    for claim in &claims {
        assert!(
            semaphore
                .begin_manual_claim_lifecycle()
                .release_claim(&test_database.paranoid_pool, claim)
                .await
                .expect("release claim")
        );
    }
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after releases")
            .current_count(),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_composes_inside_current_transaction_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("transactional-semaphore").expect("semaphore key"),
            1,
            Duration::from_secs(60),
        )
        .expect("new semaphore");
    let holder = HolderId::new("worker-a").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    let claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder_in_current_transaction(&mut rollback_tx, &holder)
        .await
        .expect("acquire inside rollback transaction")
        .expect("slot should be available");
    assert_eq!(
        semaphore
            .fetch_status_in_current_transaction(&mut rollback_tx)
            .await
            .expect("status inside rollback transaction")
            .current_count(),
        1
    );
    rollback_tx.rollback().await.expect("rollback transaction");
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after rollback")
            .current_count(),
        0
    );
    assert!(
        !semaphore
            .begin_manual_claim_lifecycle()
            .release_claim(&test_database.paranoid_pool, &claim)
            .await
            .expect("release rolled-back claim")
    );

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit transaction");
    let committed_claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder_in_current_transaction(&mut commit_tx, &holder)
        .await
        .expect("acquire inside commit transaction")
        .expect("slot should be available");
    commit_tx.commit().await.expect("commit transaction");
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after commit")
            .current_count(),
        1
    );
    assert!(
        semaphore
            .begin_manual_claim_lifecycle()
            .release_claim(&test_database.paranoid_pool, &committed_claim)
            .await
            .expect("release committed claim")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_claims_are_scoped_and_stale_claims_do_not_release_reused_slots() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let duration = Duration::from_millis(1200);
    let first_semaphore = store
        .new_semaphore(
            SemaphoreKey::new("first-semaphore").expect("semaphore key"),
            1,
            duration,
        )
        .expect("first semaphore");
    let second_semaphore = store
        .new_semaphore(
            SemaphoreKey::new("second-semaphore").expect("semaphore key"),
            1,
            duration,
        )
        .expect("second semaphore");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_claim = first_semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first acquire")
        .expect("slot should be available");
    let err = second_semaphore
        .begin_manual_claim_lifecycle()
        .release_claim(&test_database.paranoid_pool, &first_claim)
        .await
        .expect_err("claim should not release a different semaphore");
    assert!(
        matches!(err, Error::SemaphoreClaimBelongsToDifferentSemaphore),
        "error = {err:?}"
    );

    tokio::time::sleep(Duration::from_millis(1300)).await;
    let second_claim = first_semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("second acquire after expiry")
        .expect("expired slot should be reusable");
    assert_eq!(first_claim.slot_suffix(), second_claim.slot_suffix());
    assert!(
        !first_semaphore
            .begin_manual_claim_lifecycle()
            .release_claim(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("stale claim release")
    );
    assert_eq!(
        first_semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after stale release")
            .current_count(),
        1
    );
    assert!(
        first_semaphore
            .begin_manual_claim_lifecycle()
            .release_claim(&test_database.paranoid_pool, &second_claim)
            .await
            .expect("release current claim")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_try_run_task_runs_releases_and_reports_no_slot_available() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("try-run-task").expect("semaphore key"),
            1,
            Duration::from_secs(60),
        )
        .expect("new semaphore");
    let holder = HolderId::new("blocking-holder").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = semaphore
        .try_acquire_guard_for_holder(&test_database.paranoid_pool, &holder)
        .await
        .expect("acquire guard")
        .expect("slot should be available");
    let denied = semaphore
        .try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("should not run")
        })
        .await
        .expect("try run while full");
    assert!(matches!(denied, SemaphoreTryRunTaskResult::NoSlotAvailable));
    assert!(guard.release().await.expect("release blocking guard"));

    let task_run_count = Arc::new(AtomicUsize::new(0));
    let task_run_count_for_task = Arc::clone(&task_run_count);
    let ran = semaphore
        .try_run_task(&test_database.paranoid_pool, move |claim| async move {
            task_run_count_for_task.fetch_add(1, Ordering::SeqCst);
            Ok::<_, TestComputeError>(claim.holder_id().as_str().to_owned())
        })
        .await
        .expect("try run available task");
    match ran {
        SemaphoreTryRunTaskResult::Ran(SemaphoreGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert!(!value.is_empty());
            assert!(release_result.expect("release after task"));
        }
        other => panic!("try run task result = {other:?}, want successful task"),
    }
    assert_eq!(task_run_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after task")
            .current_count(),
        0
    );

    let failed = semaphore
        .try_run_task(&test_database.paranoid_pool, |_| async {
            Err::<(), _>(TestComputeError("semaphore task failed"))
        })
        .await
        .expect("try run failing task");
    match failed {
        SemaphoreTryRunTaskResult::Ran(SemaphoreGuardedTaskResult::Failed {
            error,
            release_result,
        }) => {
            assert_eq!(error, TestComputeError("semaphore task failed"));
            assert!(release_result.expect("release after failed task"));
        }
        other => panic!("failed task result = {other:?}, want failed task"),
    }
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after failed task")
            .current_count(),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_try_release_retains_retry_authority_after_release_failure() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore_key = SemaphoreKey::new("try-release-retry").expect("semaphore key");
    let semaphore = store
        .new_semaphore(semaphore_key.clone(), 1, Duration::from_secs(60))
        .expect("new semaphore");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut guard = semaphore
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("acquire guard")
        .expect("slot should be available");
    let slot_key = {
        let claim = guard.live_claim().expect("guard should own claim");
        persisted_semaphore_slot_key(&test_database.config, &semaphore_key, claim.slot_suffix())
    };
    let trigger_function = install_delete_failure_trigger_on_table(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
    )
    .await;

    guard
        .try_release()
        .await
        .expect_err("forced delete failure should make release observable");
    assert!(
        guard.live_claim().is_some(),
        "guard must retain retry authority after release failure"
    );
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after failed release")
            .current_count(),
        1
    );

    drop_test_function_cascade(&test_database.sqlx_pool, &trigger_function).await;
    assert!(
        guard
            .try_release()
            .await
            .expect("retry release after trigger removal"),
        "retry should release the original slot"
    );
    assert!(guard.live_claim().is_none());
    assert!(matches!(
        RawKvStore::new(
            KvStoreConfig::new(test_database.config.state_table_name.clone()).expect("kv config")
        )
        .expect("raw kv store")
        .get_bytes(&test_database.paranoid_pool, &slot_key)
        .await,
        Err(KvError::KeyNotFound)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_try_release_retains_retry_authority_after_blocked_release_is_cancelled() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore_key = SemaphoreKey::new("try-release-cancelled").expect("semaphore key");
    let semaphore = store
        .new_semaphore(semaphore_key.clone(), 1, Duration::from_secs(60))
        .expect("new semaphore");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut guard = semaphore
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("acquire guard")
        .expect("slot should be available");
    let slot_key = {
        let claim = guard.live_claim().expect("guard should own claim");
        persisted_semaphore_slot_key(&test_database.config, &semaphore_key, claim.slot_suffix())
    };
    let row_lock_transaction = begin_transaction_locking_raw_kv_row(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
        &slot_key,
    )
    .await;

    tokio::time::timeout(Duration::from_millis(200), guard.try_release())
        .await
        .expect_err("blocked release future should be cancellable");
    assert!(
        guard.live_claim().is_some(),
        "cancelling try_release must leave the guard able to retry"
    );

    row_lock_transaction
        .rollback()
        .await
        .expect("rollback semaphore slot row lock transaction");
    assert!(
        guard
            .try_release()
            .await
            .expect("retry release after cancellation"),
        "retry should release the original slot"
    );
    assert!(guard.live_claim().is_none());
    assert_eq!(
        semaphore
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after retry release")
            .current_count(),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_run_task_when_available_waits_for_slot() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("blocking-run-task").expect("semaphore key"),
            1,
            Duration::from_secs(60),
        )
        .expect("new semaphore");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = semaphore
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("acquire initial guard")
        .expect("slot should be available");
    let task_run_count = Arc::new(AtomicUsize::new(0));
    let task_run_count_for_task = Arc::clone(&task_run_count);
    let task_semaphore = semaphore.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let started_at = Instant::now();
    let task_handle = tokio::spawn(async move {
        task_semaphore
            .run_task_when_available(&task_pool, move |_| async move {
                task_run_count_for_task.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("ran")
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !task_handle.is_finished(),
        "blocking semaphore task must wait while all slots are held"
    );
    assert_eq!(task_run_count.load(Ordering::SeqCst), 0);
    assert!(guard.release().await.expect("release initial guard"));

    let result = task_handle
        .await
        .expect("join blocking task")
        .expect("task run");
    assert!(
        started_at.elapsed() >= Duration::from_millis(100),
        "blocking semaphore task returned before waiting for an occupied slot"
    );
    match result {
        SemaphoreGuardedTaskResult::Succeeded {
            value,
            release_result,
        } => {
            assert_eq!(value, "ran");
            assert!(release_result.expect("release after waiting task"));
        }
        other => panic!("blocking task result = {other:?}, want success"),
    }
    assert_eq!(task_run_count.load(Ordering::SeqCst), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_waiting_task_can_be_cancelled_before_execution() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("cancel-blocking-run-task").expect("semaphore key"),
            1,
            Duration::from_secs(60),
        )
        .expect("new semaphore");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = semaphore
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("acquire initial guard")
        .expect("slot should be available");
    let task_run_count = Arc::new(AtomicUsize::new(0));
    let task_run_count_for_task = Arc::clone(&task_run_count);
    let task_semaphore = semaphore.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let task_handle = tokio::spawn(async move {
        task_semaphore
            .run_task_when_available(&task_pool, move |_| async move {
                task_run_count_for_task.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should not run")
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    task_handle.abort();
    let join_error = task_handle
        .await
        .expect_err("waiting semaphore task should be cancelled");
    assert!(join_error.is_cancelled());
    assert_eq!(task_run_count.load(Ordering::SeqCst), 0);
    assert!(guard.release().await.expect("release initial guard"));
    assert!(
        semaphore
            .begin_manual_claim_lifecycle()
            .try_acquire_claim(&test_database.paranoid_pool)
            .await
            .expect("acquire after cancellation")
            .is_some()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_semaphore_task_panic_drop_releases_slot() {
    async fn panic_task(_: SemaphoreClaim) -> Result<(), TestComputeError> {
        panic!("semaphore task panic")
    }

    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("task-panic").expect("semaphore key"),
            1,
            Duration::from_secs(60),
        )
        .expect("new semaphore");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_semaphore = semaphore.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let task_handle =
        tokio::spawn(async move { task_semaphore.try_run_task(&task_pool, panic_task).await });
    let join_error = task_handle.await.expect_err("semaphore task should panic");
    assert!(join_error.is_panic());

    wait_until(
        "panic-dropped semaphore claim releases",
        Duration::from_secs(2),
        || {
            let semaphore = semaphore.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                semaphore
                    .begin_manual_claim_lifecycle()
                    .try_acquire_claim(&pool)
                    .await
                    .expect("acquire after task panic")
                    .is_some()
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
