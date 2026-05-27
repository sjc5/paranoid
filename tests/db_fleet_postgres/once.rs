use super::*;

#[tokio::test]
async fn fleet_once_start_mark_done_and_reset_use_mutex_and_completion_marker() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once_key = OnceKey::new("schema-bootstrap").expect("once key");
    let once = store
        .new_once(
            once_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check initial done")
            .is_none()
    );

    let first_claim = once
        .begin_manual_run_lifecycle()
        .try_start_run_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first start")
        .expect("unfinished once should start");
    assert_eq!(first_claim.once_key(), &once_key);
    assert_eq!(first_claim.holder_id(), &first_holder);
    assert_eq!(first_claim.fencing_token().as_i64(), 1);

    assert!(
        once.begin_manual_run_lifecycle()
            .try_start_run_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("contended start")
            .is_none(),
        "a second worker must not start while the once mutex is held"
    );

    assert!(
        once.begin_manual_run_lifecycle()
            .mark_done_and_release_run(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("mark done")
    );
    let completion = once
        .check_done(&test_database.paranoid_pool)
        .await
        .expect("check done")
        .expect("completion marker should exist");
    assert!(completion.finished_at_unix_microseconds() > 0);
    assert_eq!(completion.holder_id(), first_holder.as_str());
    assert_eq!(
        completion.fencing_token(),
        first_claim.fencing_token().as_i64()
    );

    assert!(
        once.begin_manual_run_lifecycle()
            .try_start_run_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("start after done")
            .is_none(),
        "completed once task should not start again"
    );

    assert!(
        once.try_reset(&test_database.paranoid_pool)
            .await
            .expect("reset")
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after reset")
            .is_none()
    );

    let after_reset_claim = once
        .begin_manual_run_lifecycle()
        .try_start_run_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("start after reset")
        .expect("reset once should start again");
    assert_eq!(after_reset_claim.holder_id(), &second_holder);
    assert!(
        after_reset_claim.fencing_token().as_i64() > first_claim.fencing_token().as_i64(),
        "reset must not rewind the mutex fencing sequence"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_reset_is_idempotent_and_respects_live_claims() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("idempotent-reset").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check initial done")
            .is_none()
    );
    assert!(
        once.try_reset(&test_database.paranoid_pool)
            .await
            .expect("reset absent completion marker")
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after absent reset")
            .is_none()
    );

    let claim = once
        .begin_manual_run_lifecycle()
        .try_start_run(&test_database.paranoid_pool)
        .await
        .expect("start once after absent reset")
        .expect("unfinished once should start");
    assert!(
        !once
            .try_reset(&test_database.paranoid_pool)
            .await
            .expect("reset while live claim is held"),
        "reset must not bypass a live run-once claim"
    );
    assert!(
        once.begin_manual_run_lifecycle()
            .release_run_without_marking_done(&test_database.paranoid_pool, &claim)
            .await
            .expect("release live claim without marking done")
    );
    assert!(
        once.try_reset(&test_database.paranoid_pool)
            .await
            .expect("reset absent completion marker after release")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_reset_returns_release_error_when_release_fails_and_keeps_completion() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("reset-release-error").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(
        once.try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("first run")
        })
        .await
        .expect("first run"),
        OnceTryRunTaskResult::Ran("first run")
    );

    let failure_function = install_delete_failure_trigger_on_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;
    let err = once
        .try_reset(&test_database.paranoid_pool)
        .await
        .expect_err("reset release failure should be returned");
    assert!(
        matches!(err, Error::Coordination(CoordinationError::Database(_))),
        "error = {err:?}"
    );
    drop_test_function_cascade(&test_database.sqlx_pool, &failure_function).await;

    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check done after failed reset")
            .is_some(),
        "failed reset must roll back the completion-marker delete"
    );
    assert!(matches!(
        once.try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("should-not-run")
        })
        .await
        .expect("run after failed reset"),
        OnceTryRunTaskResult::AlreadyDone(_)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_try_run_task_runs_once_reports_done_and_running() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once_key = OnceKey::new("try-run-task").expect("once key");
    let once = store
        .new_once(
            once_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let running_claim = once
        .begin_manual_run_lifecycle()
        .try_start_run(&test_database.paranoid_pool)
        .await
        .expect("start manual run")
        .expect("manual run claim should start");
    assert_eq!(
        once.try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("should-not-run")
        })
        .await
        .expect("try run while manual run claim is live"),
        OnceTryRunTaskResult::AlreadyRunning
    );
    assert!(
        once.begin_manual_run_lifecycle()
            .release_run_without_marking_done(&test_database.paranoid_pool, &running_claim)
            .await
            .expect("release manual run claim")
    );

    let execution_count = Arc::new(AtomicUsize::new(0));
    let execution_count_for_task = Arc::clone(&execution_count);
    let first_result = once
        .try_run_task(&test_database.paranoid_pool, move |snapshot| {
            let execution_count_for_task = Arc::clone(&execution_count_for_task);
            let once_key = once_key.clone();
            async move {
                assert_eq!(snapshot.once_key(), &once_key);
                assert!(snapshot.fencing_token().as_i64() > 0);
                assert!(snapshot.expires_at_unix_microseconds() > 0);
                execution_count_for_task.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("ran")
            }
        })
        .await
        .expect("first try run task");
    assert_eq!(first_result, OnceTryRunTaskResult::Ran("ran"));
    assert_eq!(execution_count.load(Ordering::SeqCst), 1);

    let second_result = once
        .try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("should-not-run")
        })
        .await
        .expect("second try run task");
    match second_result {
        OnceTryRunTaskResult::AlreadyDone(completion) => {
            assert!(completion.finished_at_unix_microseconds() > 0);
            assert!(completion.fencing_token() > 0);
        }
        other => panic!("second try run result = {other:?}, want already done"),
    }
    assert_eq!(execution_count.load(Ordering::SeqCst), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_already_done_task_helpers_skip_mutex_acquisition() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("already-done-skips-mutex").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(
        once.try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("first run")
        })
        .await
        .expect("first run"),
        OnceTryRunTaskResult::Ran("first run")
    );

    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.coordination_table_name,
    )
    .await;

    let task_calls = Arc::new(AtomicUsize::new(0));

    let try_run_task_calls = Arc::clone(&task_calls);
    assert!(matches!(
        once.try_run_task(&test_database.paranoid_pool, move |_| {
            let try_run_task_calls = Arc::clone(&try_run_task_calls);
            async move {
                try_run_task_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should-not-run")
            }
        })
        .await
        .expect("already done try_run_task"),
        OnceTryRunTaskResult::AlreadyDone(_)
    ));

    let run_task_when_available_calls = Arc::clone(&task_calls);
    assert!(matches!(
        once.run_task_when_available(&test_database.paranoid_pool, move |_| {
            let run_task_when_available_calls = Arc::clone(&run_task_when_available_calls);
            async move {
                run_task_when_available_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should-not-run")
            }
        })
        .await
        .expect("already done run_task_when_available"),
        OnceRunTaskResult::AlreadyDone(_)
    ));

    let try_run_atomically_calls = Arc::clone(&task_calls);
    assert!(matches!(
        once.try_run_task_atomically(&test_database.paranoid_pool, move |_, _| {
            Box::pin(async move {
                try_run_atomically_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should-not-run")
            })
        })
        .await
        .expect("already done try_run_task_atomically"),
        OnceTryRunTaskResult::AlreadyDone(_)
    ));

    let run_atomically_calls = Arc::clone(&task_calls);
    assert!(matches!(
        once.run_task_atomically_when_available(&test_database.paranoid_pool, move |_, _| {
            Box::pin(async move {
                run_atomically_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>("should-not-run")
            })
        })
        .await
        .expect("already done run_task_atomically_when_available"),
        OnceRunTaskResult::AlreadyDone(_)
    ));

    assert_eq!(
        task_calls.load(Ordering::SeqCst),
        0,
        "already-done helpers must not run caller tasks"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_run_task_when_available_allows_one_concurrent_runner() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = Arc::new(
        store
            .new_once(
                OnceKey::new("blocking-run-task").expect("once key"),
                ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
            )
            .expect("new once"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_count = 8;
    let barrier = Arc::new(Barrier::new(worker_count));
    let execution_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let once = Arc::clone(&once);
        let pool = test_database.paranoid_pool.clone();
        let barrier = Arc::clone(&barrier);
        let execution_count = Arc::clone(&execution_count);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            once.run_task_when_available(&pool, move |_| {
                let execution_count = Arc::clone(&execution_count);
                async move {
                    execution_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok::<_, TestComputeError>("ran")
                }
            })
            .await
            .expect("run task when available")
        }));
    }

    let mut ran_count = 0;
    let mut already_done_count = 0;
    for handle in handles {
        match handle.await.expect("join worker") {
            OnceRunTaskResult::Ran(value) => {
                assert_eq!(value, "ran");
                ran_count += 1;
            }
            OnceRunTaskResult::AlreadyDone(completion) => {
                assert!(completion.finished_at_unix_microseconds() > 0);
                already_done_count += 1;
            }
        }
    }

    assert_eq!(ran_count, 1);
    assert_eq!(already_done_count, worker_count - 1);
    assert_eq!(execution_count.load(Ordering::SeqCst), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_run_task_when_available_returns_task_and_release_errors_when_both_fail() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("run-task-release-error").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let err = once
        .run_task_when_available(&test_database.paranoid_pool, move |_| {
            let sqlx_pool = sqlx_pool.clone();
            let config = config.clone();
            async move {
                drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
                Err::<(), _>(TestComputeError("once task failed before release"))
            }
        })
        .await
        .expect_err("task and release failure should both be returned");
    assert!(
        matches!(
            err,
            OnceRunError::TaskAndRelease {
                source: TestComputeError("once task failed before release"),
                release_error: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after task and release failure")
            .is_none()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_try_run_task_error_releases_without_marking_done() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("try-run-task-error").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let err = once
        .try_run_task(&test_database.paranoid_pool, |_| async {
            Err::<(), _>(TestComputeError("once task failed"))
        })
        .await
        .expect_err("task error should be returned");
    assert!(
        matches!(
            err,
            OnceRunError::Task {
                source: TestComputeError("once task failed")
            }
        ),
        "error = {err:?}"
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after task error")
            .is_none()
    );
    assert_eq!(
        once.try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("recovered")
        })
        .await
        .expect("retry after task error"),
        OnceTryRunTaskResult::Ran("recovered")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_try_run_task_panic_releases_without_marking_done() {
    async fn panic_once_task(_: OnceRunClaimSnapshot) -> Result<(), TestComputeError> {
        panic!("once task panic")
    }

    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("try-run-task-panic").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let panic_once = once.clone();
    let panic_pool = test_database.paranoid_pool.clone();
    let panic_handle =
        tokio::spawn(async move { panic_once.try_run_task(&panic_pool, panic_once_task).await });
    let join_error = panic_handle.await.expect_err("once task should panic");
    assert!(join_error.is_panic());
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after task panic")
            .is_none()
    );

    let recovered = once
        .try_run_task(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>("recovered")
        })
        .await
        .expect("retry after panic");
    assert_eq!(recovered, OnceTryRunTaskResult::Ran("recovered"));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_cancelled_task_releases_without_marking_done() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("try-run-task-cancelled").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_once = once.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let (task_started_sender, task_started_receiver) = tokio::sync::oneshot::channel();
    let task_handle = tokio::spawn(async move {
        task_once
            .run_task_when_available(&task_pool, move |snapshot| async move {
                assert_eq!(snapshot.once_key().as_str(), "try-run-task-cancelled");
                let _ = task_started_sender.send(());
                std::future::pending::<Result<(), TestComputeError>>().await
            })
            .await
    });

    task_started_receiver
        .await
        .expect("cancelled once task should start");
    task_handle.abort();
    let join_error = task_handle.await.expect_err("task should be cancelled");
    assert!(join_error.is_cancelled());
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after cancellation")
            .is_none()
    );

    wait_until(
        "cancelled once task releases its mutex claim",
        Duration::from_secs(2),
        || {
            let once = once.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                matches!(
                    once.try_run_task(&pool, |_| async { Ok::<_, TestComputeError>("recovered") })
                        .await,
                    Ok(OnceTryRunTaskResult::Ran("recovered"))
                )
            }
        },
    )
    .await;
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after retry")
            .is_some()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_try_run_task_atomically_commits_task_and_completion_once() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once_key = OnceKey::new("atomic-run-task").expect("once key");
    let once = store
        .new_once(
            once_key.clone(),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");
    let counter = store
        .new_counter(CounterKey::new("atomic-run-task-counter").expect("counter key"))
        .expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_result = once
        .try_run_task_atomically(&test_database.paranoid_pool, {
            let counter = counter.clone();
            let once_key = once_key.clone();
            move |snapshot, tx| {
                Box::pin(async move {
                    assert_eq!(snapshot.once_key(), &once_key);
                    assert!(snapshot.fencing_token().as_i64() > 0);
                    counter.add_in_current_transaction(tx, 1).await?;
                    Ok::<_, Error>("committed")
                })
            }
        })
        .await
        .expect("first atomic run");
    assert_eq!(first_result, OnceTryRunTaskResult::Ran("committed"));
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after first atomic run"),
        1
    );

    let second_result = once
        .try_run_task_atomically(&test_database.paranoid_pool, {
            let counter = counter.clone();
            move |_, tx| {
                Box::pin(async move {
                    counter.add_in_current_transaction(tx, 100).await?;
                    Ok::<_, Error>("should-not-run")
                })
            }
        })
        .await
        .expect("second atomic run");
    assert!(matches!(
        second_result,
        OnceTryRunTaskResult::AlreadyDone(_)
    ));
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after already done"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_try_run_task_atomically_rolls_back_task_error_and_allows_retry() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("atomic-run-task-error").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");
    let counter = store
        .new_counter(CounterKey::new("atomic-run-task-error-counter").expect("counter key"))
        .expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let err = once
        .try_run_task_atomically(&test_database.paranoid_pool, {
            let counter = counter.clone();
            move |_, tx| {
                Box::pin(async move {
                    counter
                        .add_in_current_transaction(tx, 1)
                        .await
                        .expect("counter mutation inside failing task");
                    Err::<(), _>(TestComputeError("atomic task failed"))
                })
            }
        })
        .await
        .expect_err("task error should be returned");
    assert!(
        matches!(
            err,
            OnceTransactionalRunError::Task {
                source: TestComputeError("atomic task failed")
            }
        ),
        "error = {err:?}"
    );
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after rollback"),
        0
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after task error")
            .is_none()
    );

    assert_eq!(
        once.try_run_task_atomically(&test_database.paranoid_pool, {
            let counter = counter.clone();
            move |_, tx| {
                Box::pin(async move {
                    counter.add_in_current_transaction(tx, 1).await?;
                    Ok::<_, Error>("recovered")
                })
            }
        })
        .await
        .expect("retry after rollback"),
        OnceTryRunTaskResult::Ran("recovered")
    );
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after retry"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_run_task_atomically_when_available_allows_one_concurrent_runner() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = Arc::new(
        store
            .new_once(
                OnceKey::new("atomic-blocking-run-task").expect("once key"),
                ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
            )
            .expect("new once"),
    );
    let counter = Arc::new(
        store
            .new_counter(CounterKey::new("atomic-blocking-run-task-counter").expect("counter key"))
            .expect("new counter"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_count = 8;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let once = Arc::clone(&once);
        let counter = Arc::clone(&counter);
        let pool = test_database.paranoid_pool.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            once.run_task_atomically_when_available(&pool, move |_, tx| {
                Box::pin(async move {
                    counter.add_in_current_transaction(tx, 1).await?;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok::<_, Error>("ran")
                })
            })
            .await
            .expect("atomic run task when available")
        }));
    }

    let mut ran_count = 0;
    let mut already_done_count = 0;
    for handle in handles {
        match handle.await.expect("join worker") {
            OnceRunTaskResult::Ran(value) => {
                assert_eq!(value, "ran");
                ran_count += 1;
            }
            OnceRunTaskResult::AlreadyDone(completion) => {
                assert!(completion.finished_at_unix_microseconds() > 0);
                already_done_count += 1;
            }
        }
    }

    assert_eq!(ran_count, 1);
    assert_eq!(already_done_count, worker_count - 1);
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after concurrent atomic runs"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_try_run_task_atomically_panic_rolls_back_and_allows_retry() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("atomic-run-task-panic").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");
    let counter = store
        .new_counter(CounterKey::new("atomic-run-task-panic-counter").expect("counter key"))
        .expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let panic_once = once.clone();
    let panic_pool = test_database.paranoid_pool.clone();
    let panic_counter = counter.clone();
    let panic_handle = tokio::spawn(async move {
        panic_once
            .try_run_task_atomically(&panic_pool, move |_, tx| {
                Box::pin(async move {
                    panic_counter
                        .add_in_current_transaction(tx, 1)
                        .await
                        .expect("counter mutation before panic");
                    panic!("atomic once task panic");
                    #[allow(unreachable_code)]
                    Ok::<(), TestComputeError>(())
                })
            })
            .await
    });
    let join_error = panic_handle.await.expect_err("atomic task should panic");
    assert!(join_error.is_panic());
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after panic rollback"),
        0
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after panic")
            .is_none()
    );

    assert_eq!(
        once.run_task_atomically_when_available(&test_database.paranoid_pool, {
            let counter = counter.clone();
            move |_, tx| {
                Box::pin(async move {
                    counter.add_in_current_transaction(tx, 1).await?;
                    Ok::<_, Error>("recovered")
                })
            }
        })
        .await
        .expect("retry after panic"),
        OnceRunTaskResult::Ran("recovered")
    );
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after panic retry"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_cancelled_atomic_task_rolls_back_and_releases_without_marking_done() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("atomic-run-task-cancelled").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");
    let counter = store
        .new_counter(CounterKey::new("atomic-run-task-cancelled-counter").expect("counter key"))
        .expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_once = once.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let task_counter = counter.clone();
    let (task_started_sender, task_started_receiver) = tokio::sync::oneshot::channel();
    let task_handle = tokio::spawn(async move {
        task_once
            .try_run_task_atomically(&task_pool, move |snapshot, tx| {
                Box::pin(async move {
                    assert_eq!(snapshot.once_key().as_str(), "atomic-run-task-cancelled");
                    task_counter
                        .add_in_current_transaction(tx, 1)
                        .await
                        .expect("counter mutation before cancellation");
                    let _ = task_started_sender.send(());
                    std::future::pending::<Result<(), TestComputeError>>().await
                })
            })
            .await
    });

    task_started_receiver
        .await
        .expect("cancelled atomic once task should start");
    task_handle.abort();
    let join_error = task_handle
        .await
        .expect_err("atomic task should be cancelled");
    assert!(join_error.is_cancelled());
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after cancellation rollback"),
        0
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after cancellation")
            .is_none()
    );

    wait_until(
        "cancelled atomic once task releases its mutex claim",
        Duration::from_secs(2),
        || {
            let once = once.clone();
            let counter = counter.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                matches!(
                    once.try_run_task_atomically(&pool, move |_, tx| {
                        Box::pin(async move {
                            counter.add_in_current_transaction(tx, 1).await?;
                            Ok::<_, Error>("recovered")
                        })
                    })
                    .await,
                    Ok(OnceTryRunTaskResult::Ran("recovered"))
                )
            }
        },
    )
    .await;
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("counter after retry"),
        1
    );
    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after retry")
            .is_some()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_allows_one_concurrent_starter_and_records_one_completion() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = Arc::new(
        store
            .new_once(
                OnceKey::new("concurrent-once").expect("once key"),
                ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
            )
            .expect("new once"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_count = 8;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut handles = Vec::with_capacity(worker_count);

    for index in 0..worker_count {
        let once = Arc::clone(&once);
        let barrier = Arc::clone(&barrier);
        let pool = test_database.paranoid_pool.clone();
        handles.push(tokio::spawn(async move {
            let holder_text = format!("worker-{index}");
            let holder = HolderId::new(&holder_text).expect("holder");
            barrier.wait().await;
            let claim = once
                .begin_manual_run_lifecycle()
                .try_start_run_for_holder(&pool, &holder)
                .await
                .expect("try start")?;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                once.begin_manual_run_lifecycle()
                    .mark_done_and_release_run(&pool, &claim)
                    .await
                    .expect("mark done")
            );
            Some(holder_text)
        }));
    }

    let mut completing_holders = Vec::new();
    for handle in handles {
        if let Some(holder) = handle.await.expect("join worker") {
            completing_holders.push(holder);
        }
    }

    assert_eq!(
        completing_holders.len(),
        1,
        "exactly one concurrent worker should acquire the run-once claim"
    );
    let completion = once
        .check_done(&test_database.paranoid_pool)
        .await
        .expect("check done")
        .expect("completion should exist");
    assert_eq!(completion.holder_id(), completing_holders[0].as_str());
    assert!(
        once.begin_manual_run_lifecycle()
            .try_start_run(&test_database.paranoid_pool)
            .await
            .expect("start after completion")
            .is_none()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_completion_marker_rolls_back_with_current_transaction() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let once = store
        .new_once(
            OnceKey::new("transactional-once").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration"),
        )
        .expect("new once");
    let holder = HolderId::new("worker-a").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let claim = once
        .begin_manual_run_lifecycle()
        .try_start_run_for_holder(&test_database.paranoid_pool, &holder)
        .await
        .expect("start")
        .expect("unfinished once should start");

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    assert!(
        once.begin_manual_run_lifecycle()
            .mark_done_and_release_run_in_current_transaction(&mut rollback_tx, &claim)
            .await
            .expect("mark done in rollback transaction")
    );
    assert!(
        once.check_done_in_current_transaction(&mut rollback_tx)
            .await
            .expect("check done inside rollback transaction")
            .is_some()
    );
    rollback_tx.rollback().await.expect("rollback transaction");

    assert!(
        once.check_done(&test_database.paranoid_pool)
            .await
            .expect("check after rollback")
            .is_none(),
        "rolling back the caller transaction must roll back the completion marker"
    );
    assert!(
        once.begin_manual_run_lifecycle()
            .release_run_without_marking_done(&test_database.paranoid_pool, &claim)
            .await
            .expect("release original claim after rollback")
    );

    let second_claim = once
        .begin_manual_run_lifecycle()
        .try_start_run(&test_database.paranoid_pool)
        .await
        .expect("start after rollback release")
        .expect("rolled-back completion should allow retry");
    assert_ne!(second_claim.holder_id(), &holder);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_once_claim_cannot_complete_a_different_once_task() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let duration = ClaimDuration::expires_after(Duration::from_secs(60)).expect("duration");
    let first_once = store
        .new_once(OnceKey::new("first").expect("once key"), duration)
        .expect("first once");
    let second_once = store
        .new_once(OnceKey::new("second").expect("once key"), duration)
        .expect("second once");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_claim = first_once
        .begin_manual_run_lifecycle()
        .try_start_run(&test_database.paranoid_pool)
        .await
        .expect("start first")
        .expect("first once should start");
    let err = second_once
        .begin_manual_run_lifecycle()
        .mark_done_and_release_run(&test_database.paranoid_pool, &first_claim)
        .await
        .expect_err("claim should not complete another once task");
    assert!(
        matches!(err, Error::RunOnceManualRunClaimBelongsToDifferentTask),
        "error = {err:?}"
    );
    assert!(
        second_once
            .check_done(&test_database.paranoid_pool)
            .await
            .expect("check second done")
            .is_none()
    );
    assert!(
        first_once
            .begin_manual_run_lifecycle()
            .release_run_without_marking_done(&test_database.paranoid_pool, &first_claim)
            .await
            .expect("release first claim")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
