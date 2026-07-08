use super::cron_support::*;
use super::*;

#[tokio::test]
async fn fleet_cron_try_run_once_and_run_once_expose_fencing_tokens() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("once-fencing"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let try_result = cron
        .try_run_once(&test_database.paranoid_pool, |snapshot| async move {
            Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
        })
        .await
        .expect("try run once");
    assert_eq!(try_result, CronTryRunOnceResult::Ran(1));
    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch leader after try run once")
            .is_none(),
        "try_run_once should release leadership after the task"
    );

    let second_token = cron
        .run_once(&test_database.paranoid_pool, |snapshot| async move {
            Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
        })
        .await
        .expect("run once");
    assert_eq!(second_token, 2);
    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch leader after run once")
            .is_none(),
        "run_once should release leadership after the task"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_try_run_once_reports_leadership_held() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("leadership-held"))
        .expect("new cron");
    let competing_cron = store
        .new_cron(fast_cron_config("leadership-held"))
        .expect("new competing cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let pool = test_database.paranoid_pool.clone();
    let hold_handle = tokio::spawn(async move {
        cron.try_run_once(&pool, |_| async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok::<_, TestComputeError>(())
        })
        .await
    });

    wait_until("cron leadership is held", Duration::from_secs(2), || {
        let pool = test_database.paranoid_pool.clone();
        let store = store.clone();
        async move { !first_cron_leader_absent(&pool, &store, "leadership-held").await }
    })
    .await;
    assert_eq!(
        competing_cron
            .try_run_once(&test_database.paranoid_pool, |_| async {
                Ok::<_, TestComputeError>(())
            })
            .await
            .expect("try run while held"),
        CronTryRunOnceResult::LeadershipHeld
    );
    assert_eq!(
        hold_handle
            .await
            .expect("join holding cron")
            .expect("holding run"),
        CronTryRunOnceResult::Ran(())
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_fetch_live_leader_reports_holder_and_fencing_token() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("live-leader"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch leader before run")
            .is_none()
    );

    let task_cron = cron.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let (task_started_sender, task_started_receiver) = tokio::sync::oneshot::channel();
    let task_handle = tokio::spawn(async move {
        task_cron
            .run_once(&task_pool, move |snapshot| async move {
                let _ = task_started_sender.send((
                    snapshot.holder_id().as_str().to_owned(),
                    snapshot.fencing_token().as_i64(),
                ));
                std::future::pending::<Result<(), TestComputeError>>().await
            })
            .await
    });

    let (task_holder_id, task_fencing_token) =
        task_started_receiver.await.expect("cron task should start");
    let live_leader = cron
        .fetch_live_leader(&test_database.paranoid_pool)
        .await
        .expect("fetch live leader")
        .expect("leader should be live while cron task runs");
    assert_eq!(live_leader.mutex_key().as_str(), "live-leader");
    assert_eq!(live_leader.holder_id().as_str(), task_holder_id);
    assert_eq!(live_leader.fencing_token().as_i64(), task_fencing_token);
    assert!(live_leader.expires_at_unix_microseconds() > 0);

    task_handle.abort();
    let join_error = task_handle.await.expect_err("task should be cancelled");
    assert!(join_error.is_cancelled());
    wait_until(
        "cancelled live-leader cron releases",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let cron = cron.clone();
            async move {
                cron.fetch_live_leader(&pool)
                    .await
                    .expect("fetch leader after cancellation")
                    .is_none()
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_until_uses_one_leader_and_stops_cleanly() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let first_cron = store
        .new_cron(fast_cron_config("single-leader"))
        .expect("new first cron");
    let second_cron = store
        .new_cron(fast_cron_config("single-leader"))
        .expect("new second cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_count = Arc::new(AtomicUsize::new(0));
    let second_count = Arc::new(AtomicUsize::new(0));
    let first_task_count = Arc::clone(&first_count);
    let second_task_count = Arc::clone(&second_count);
    let pool = test_database.paranoid_pool.clone();
    let first_handle = tokio::spawn(async move {
        first_cron
            .run_until_stopped_or_task_error(
                &pool,
                tokio::time::sleep(Duration::from_millis(1250)),
                move |_| {
                    let first_task_count = Arc::clone(&first_task_count);
                    async move {
                        first_task_count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
    });
    let pool = test_database.paranoid_pool.clone();
    let second_handle = tokio::spawn(async move {
        second_cron
            .run_until_stopped_or_task_error(
                &pool,
                tokio::time::sleep(Duration::from_millis(1250)),
                move |_| {
                    let second_task_count = Arc::clone(&second_task_count);
                    async move {
                        second_task_count.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
    });

    first_handle
        .await
        .expect("join first cron")
        .expect("first cron");
    second_handle
        .await
        .expect("join second cron")
        .expect("second cron");

    let first_runs = first_count.load(Ordering::SeqCst);
    let second_runs = second_count.load(Ordering::SeqCst);
    assert!(
        (first_runs > 0) ^ (second_runs > 0),
        "exactly one cron should run tasks while leadership is continuously held, got first={first_runs}, second={second_runs}"
    );
    assert!(
        first_runs.max(second_runs) >= 2,
        "leader should run immediately and once after the interval"
    );
    assert!(
        first_cron_leader_absent(&test_database.paranoid_pool, &store, "single-leader").await,
        "cron should release leadership after stop"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_task_error_policy_can_continue_after_reported_task_error() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("task-error-policy-continue"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_count = Arc::new(AtomicUsize::new(0));
    let task_error_count = Arc::new(AtomicUsize::new(0));
    let task_count_for_handler = Arc::clone(&task_count);
    let task_error_count_for_policy = Arc::clone(&task_error_count);

    cron.run_until_stopped_with_task_error_policy(
        &test_database.paranoid_pool,
        tokio::time::sleep(Duration::from_millis(1250)),
        move |_| {
            let task_count_for_handler = Arc::clone(&task_count_for_handler);
            async move {
                let previous_count = task_count_for_handler.fetch_add(1, Ordering::SeqCst);
                if previous_count == 0 {
                    return Err(TestComputeError("first cron task failed"));
                }
                Ok(())
            }
        },
        move |error| {
            assert_eq!(*error, TestComputeError("first cron task failed"));
            task_error_count_for_policy.fetch_add(1, Ordering::SeqCst);
            CronTaskErrorAction::Continue
        },
    )
    .await
    .expect("cron should continue after reported task error");

    assert!(
        task_count.load(Ordering::SeqCst) >= 2,
        "cron should keep running after a continued task error"
    );
    assert_eq!(task_error_count.load(Ordering::SeqCst), 1);
    assert!(
        first_cron_leader_absent(
            &test_database.paranoid_pool,
            &store,
            "task-error-policy-continue"
        )
        .await,
        "cron should release leadership after stop"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_task_error_policy_can_stop_after_reported_task_error() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("task-error-policy-stop"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_error_count = Arc::new(AtomicUsize::new(0));
    let task_error_count_for_policy = Arc::clone(&task_error_count);

    let err = cron
        .run_until_stopped_with_task_error_policy(
            &test_database.paranoid_pool,
            tokio::time::sleep(Duration::from_secs(60)),
            |_| async { Err::<(), _>(TestComputeError("cron task should stop")) },
            move |error| {
                assert_eq!(*error, TestComputeError("cron task should stop"));
                task_error_count_for_policy.fetch_add(1, Ordering::SeqCst);
                CronTaskErrorAction::Stop
            },
        )
        .await
        .expect_err("stop policy should return the task error");
    assert!(
        matches!(
            err,
            CronRunError::Task {
                source: TestComputeError("cron task should stop")
            }
        ),
        "error = {err:?}"
    );
    assert_eq!(task_error_count.load(Ordering::SeqCst), 1);
    assert!(
        first_cron_leader_absent(
            &test_database.paranoid_pool,
            &store,
            "task-error-policy-stop"
        )
        .await,
        "cron should release leadership after stop policy returns the task error"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_start_handle_with_task_error_policy_continues_and_stops_cleanly() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("task-error-policy-handle"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_count = Arc::new(AtomicUsize::new(0));
    let task_error_count = Arc::new(AtomicUsize::new(0));
    let task_count_for_handler = Arc::clone(&task_count);
    let task_error_count_for_policy = Arc::clone(&task_error_count);

    let handle = cron.start_until_stopped_with_task_error_policy(
        test_database.paranoid_pool.clone(),
        move |_| {
            let task_count_for_handler = Arc::clone(&task_count_for_handler);
            async move {
                let previous_count = task_count_for_handler.fetch_add(1, Ordering::SeqCst);
                if previous_count == 0 {
                    return Err(TestComputeError("first handle task failed"));
                }
                Ok(())
            }
        },
        move |error| {
            assert_eq!(*error, TestComputeError("first handle task failed"));
            task_error_count_for_policy.fetch_add(1, Ordering::SeqCst);
            CronTaskErrorAction::Continue
        },
    );

    wait_until(
        "cron handle continues after task error",
        Duration::from_secs(3),
        || {
            let task_count = Arc::clone(&task_count);
            async move { task_count.load(Ordering::SeqCst) >= 2 }
        },
    )
    .await;
    handle
        .stop_and_wait()
        .await
        .expect("cron handle should stop cleanly");
    assert_eq!(task_error_count.load(Ordering::SeqCst), 1);
    assert!(
        first_cron_leader_absent(
            &test_database.paranoid_pool,
            &store,
            "task-error-policy-handle"
        )
        .await,
        "cron should release leadership after handle stop"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_task_error_policy_panic_is_reported_as_handle_join_failure() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("task-error-policy-panic"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let handle = cron.start_until_stopped_with_task_error_policy(
        test_database.paranoid_pool.clone(),
        |_| async { Err::<(), _>(TestComputeError("policy input error")) },
        |_| -> CronTaskErrorAction {
            panic!("cron task error policy panic");
        },
    );

    let err = handle
        .wait()
        .await
        .expect_err("policy panic should be reported as join failure");
    assert!(
        matches!(err, CronRunHandleError::Join { ref source } if source.is_panic()),
        "error = {err:?}"
    );
    wait_until(
        "cron releases leadership while unwinding after policy panic",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let store = store.clone();
            async move { first_cron_leader_absent(&pool, &store, "task-error-policy-panic").await }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_start_handle_stops_and_releases_leadership() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("start-handle-stop"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_count = Arc::new(AtomicUsize::new(0));
    let task_count_for_handler = Arc::clone(&task_count);
    let mut handle =
        cron.start_until_stopped_or_task_error(test_database.paranoid_pool.clone(), move |_| {
            let task_count_for_handler = Arc::clone(&task_count_for_handler);
            async move {
                task_count_for_handler.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        });

    wait_until("cron handle task ran", Duration::from_secs(2), || {
        let task_count = Arc::clone(&task_count);
        async move { task_count.load(Ordering::SeqCst) > 0 }
    })
    .await;
    assert!(
        !first_cron_leader_absent(&test_database.paranoid_pool, &store, "start-handle-stop").await,
        "cron should hold leadership while the background handle is running"
    );
    assert!(handle.request_stop());
    assert!(!handle.request_stop());
    handle
        .wait()
        .await
        .expect("cron handle should stop cleanly");
    assert!(
        first_cron_leader_absent(&test_database.paranoid_pool, &store, "start-handle-stop").await,
        "cron should release leadership after handle stop"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_stop_during_task_waits_for_success_and_releases_leadership() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("stop-during-task"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_started = Arc::new(tokio::sync::Notify::new());
    let task_may_finish = Arc::new(tokio::sync::Notify::new());
    let task_count = Arc::new(AtomicUsize::new(0));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let run_pool = test_database.paranoid_pool.clone();
    let run_cron = cron.clone();
    let task_started_for_run = Arc::clone(&task_started);
    let task_may_finish_for_run = Arc::clone(&task_may_finish);
    let task_count_for_run = Arc::clone(&task_count);
    let run_handle = tokio::spawn(async move {
        run_cron
            .run_until_stopped_or_task_error(
                &run_pool,
                async move {
                    let _ = stop_receiver.await;
                },
                move |_| {
                    let task_started_for_run = Arc::clone(&task_started_for_run);
                    let task_may_finish_for_run = Arc::clone(&task_may_finish_for_run);
                    let task_count_for_run = Arc::clone(&task_count_for_run);
                    async move {
                        task_started_for_run.notify_one();
                        task_may_finish_for_run.notified().await;
                        task_count_for_run.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), task_started.notified())
        .await
        .expect("cron task should start");
    let _ = stop_sender.send(());
    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch live leader while task is blocked")
            .is_some(),
        "cron should keep leadership while an already-running task finishes"
    );

    task_may_finish.notify_one();
    tokio::time::timeout(Duration::from_secs(2), run_handle)
        .await
        .expect("cron should stop after task success")
        .expect("cron task should not panic")
        .expect("cron should stop cleanly");

    assert_eq!(task_count.load(Ordering::SeqCst), 1);
    assert!(
        first_cron_leader_absent(&test_database.paranoid_pool, &store, "stop-during-task").await,
        "cron should release leadership after stopping"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_until_returns_immediately_when_stop_future_is_ready_before_acquire() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("already-stopped-before-acquire"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_count = Arc::new(AtomicUsize::new(0));
    let task_count_for_handler = Arc::clone(&task_count);
    cron.run_until_stopped_or_task_error(
        &test_database.paranoid_pool,
        std::future::ready(()),
        move |_| {
            let task_count_for_handler = Arc::clone(&task_count_for_handler);
            async move {
                task_count_for_handler.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        },
    )
    .await
    .expect("ready stop future should return cleanly");

    assert_eq!(task_count.load(Ordering::SeqCst), 0);
    assert!(
        first_cron_leader_absent(
            &test_database.paranoid_pool,
            &store,
            "already-stopped-before-acquire"
        )
        .await,
        "ready stop future should not acquire leadership"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_until_returns_acquire_error_when_schema_is_missing() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("run-until-acquire-missing-schema"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let err = cron
        .run_until_stopped_or_task_error(
            &test_database.paranoid_pool,
            std::future::pending::<()>(),
            |_| async { Ok::<_, TestComputeError>(()) },
        )
        .await
        .expect_err("missing schema should fail acquisition");
    assert!(
        matches!(
            err,
            CronRunError::Fleet(Error::Coordination(CoordinationError::Database(_)))
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_until_stops_while_blocked_on_leadership_acquire() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let holding_cron = store
        .new_cron(fast_cron_config("blocked-acquire-stop"))
        .expect("new holding cron");
    let waiting_cron = store
        .new_cron(fast_cron_config("blocked-acquire-stop"))
        .expect("new waiting cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let holding_pool = test_database.paranoid_pool.clone();
    let holding_handle = tokio::spawn(async move {
        holding_cron
            .try_run_once(&holding_pool, |_| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                Ok::<_, TestComputeError>(())
            })
            .await
    });

    wait_until("cron leadership is held", Duration::from_secs(2), || {
        let pool = test_database.paranoid_pool.clone();
        let store = store.clone();
        async move { !first_cron_leader_absent(&pool, &store, "blocked-acquire-stop").await }
    })
    .await;

    let task_count = Arc::new(AtomicUsize::new(0));
    let task_count_for_waiter = Arc::clone(&task_count);
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let waiting_pool = test_database.paranoid_pool.clone();
    let waiting_handle = tokio::spawn(async move {
        waiting_cron
            .run_until_stopped_or_task_error(
                &waiting_pool,
                async move {
                    let _ = stop_receiver.await;
                },
                move |_| {
                    let task_count_for_waiter = Arc::clone(&task_count_for_waiter);
                    async move {
                        task_count_for_waiter.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
    });

    tokio::time::sleep(Duration::from_millis(75)).await;
    let _ = stop_sender.send(());
    tokio::time::timeout(Duration::from_secs(2), waiting_handle)
        .await
        .expect("waiting cron should stop promptly")
        .expect("join waiting cron")
        .expect("waiting cron should stop cleanly");
    assert_eq!(task_count.load(Ordering::SeqCst), 0);

    let holding_result = holding_handle
        .await
        .expect("join holding cron")
        .expect("holding cron");
    assert_eq!(holding_result, CronTryRunOnceResult::Ran(()));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_until_returns_release_error_when_stop_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(default_heartbeat_cron_config("run-until-release-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_finished = Arc::new(tokio::sync::Notify::new());
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let task_finished_for_task = Arc::clone(&task_finished);
    let run_handle = tokio::spawn({
        let pool = test_database.paranoid_pool.clone();
        async move {
            cron.run_until_stopped_or_task_error(
                &pool,
                async move {
                    let _ = stop_receiver.await;
                },
                move |_| {
                    let sqlx_pool = sqlx_pool.clone();
                    let config = config.clone();
                    let task_finished_for_task = Arc::clone(&task_finished_for_task);
                    async move {
                        drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
                        task_finished_for_task.notify_one();
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
        }
    });

    task_finished.notified().await;
    let _ = stop_sender.send(());
    let err = tokio::time::timeout(Duration::from_secs(2), run_handle)
        .await
        .expect("cron should return after stop")
        .expect("join cron")
        .expect_err("release failure should be returned");
    assert!(
        matches!(
            err,
            CronRunError::Release {
                source: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_start_handle_reports_release_error_when_stop_release_fails() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(default_heartbeat_cron_config("start-handle-release-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_finished = Arc::new(tokio::sync::Notify::new());
    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let task_finished_for_task = Arc::clone(&task_finished);
    let handle =
        cron.start_until_stopped_or_task_error(test_database.paranoid_pool.clone(), move |_| {
            let sqlx_pool = sqlx_pool.clone();
            let config = config.clone();
            let task_finished_for_task = Arc::clone(&task_finished_for_task);
            async move {
                drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
                task_finished_for_task.notify_one();
                Ok::<_, TestComputeError>(())
            }
        });

    task_finished.notified().await;
    let err = tokio::time::timeout(Duration::from_secs(2), handle.stop_and_wait())
        .await
        .expect("cron handle should return after stop")
        .expect_err("release failure should be returned through handle");
    assert!(
        matches!(
            err,
            CronRunHandleError::Run {
                source: CronRunError::Release {
                    source: Error::Coordination(CoordinationError::Database(_))
                }
            }
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_until_reports_leadership_lost() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("leadership-lost"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_count = Arc::new(AtomicUsize::new(0));
    let run_pool = test_database.paranoid_pool.clone();
    let run_task_count = Arc::clone(&task_count);
    let run_handle = tokio::spawn(async move {
        cron.run_until_stopped_or_task_error(
            &run_pool,
            tokio::time::sleep(Duration::from_secs(5)),
            move |_| {
                let run_task_count = Arc::clone(&run_task_count);
                async move {
                    run_task_count.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
    });

    wait_until("cron leader exists", Duration::from_secs(2), || {
        let pool = test_database.paranoid_pool.clone();
        let store = store.clone();
        async move { !first_cron_leader_absent(&pool, &store, "leadership-lost").await }
    })
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let err = tokio::time::timeout(Duration::from_secs(2), run_handle)
        .await
        .expect("cron should stop after leadership loss")
        .expect("join cron")
        .expect_err("leadership loss should be reported");
    assert!(
        matches!(
            err,
            CronRunError::LeadershipLostAndRelease {
                release_error: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );
    assert!(task_count.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn fleet_cron_start_handle_reports_leadership_lost() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("start-handle-leadership-lost"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_count = Arc::new(AtomicUsize::new(0));
    let task_count_for_handler = Arc::clone(&task_count);
    let handle =
        cron.start_until_stopped_or_task_error(test_database.paranoid_pool.clone(), move |_| {
            let task_count_for_handler = Arc::clone(&task_count_for_handler);
            async move {
                task_count_for_handler.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        });

    wait_until("cron handle leader exists", Duration::from_secs(2), || {
        let pool = test_database.paranoid_pool.clone();
        let store = store.clone();
        async move {
            !first_cron_leader_absent(&pool, &store, "start-handle-leadership-lost").await
        }
    })
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let err = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .expect("cron handle should stop after leadership loss")
        .expect_err("leadership loss should be reported");
    assert!(
        matches!(
            err,
            CronRunHandleError::Run {
                source: CronRunError::LeadershipLostAndRelease {
                    release_error: Error::Coordination(CoordinationError::Database(_))
                }
            }
        ),
        "error = {err:?}"
    );
    assert!(task_count.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn fleet_cron_continuous_run_reacquires_after_leadership_loss() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron_key = "continuous-reacquire";
    let cron = store
        .new_cron(fast_cron_config(cron_key))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let observed_fencing_tokens = Arc::new(Mutex::new(Vec::<i64>::new()));
    let task_tokens = Arc::clone(&observed_fencing_tokens);
    let run_pool = test_database.paranoid_pool.clone();
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let run_handle = tokio::spawn(async move {
        cron.run_continuously_until_stopped_or_task_error(
            &run_pool,
            async move {
                let _ = stop_receiver.await;
            },
            move |snapshot| {
                let task_tokens = Arc::clone(&task_tokens);
                async move {
                    task_tokens
                        .lock()
                        .expect("observed fencing token mutex should not be poisoned")
                        .push(snapshot.fencing_token().as_i64());
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
    });

    wait_until(
        "cron continuous first tenure",
        Duration::from_secs(2),
        || {
            let observed_fencing_tokens = Arc::clone(&observed_fencing_tokens);
            async move {
                !observed_fencing_tokens
                    .lock()
                    .expect("observed fencing token mutex should not be poisoned")
                    .is_empty()
            }
        },
    )
    .await;
    let first_fencing_token = observed_fencing_tokens
        .lock()
        .expect("observed fencing token mutex should not be poisoned")[0];

    delete_live_cron_lease_row(&test_database.sqlx_pool, &test_database.config, cron_key).await;

    wait_until(
        "cron continuous reacquired leadership",
        Duration::from_secs(5),
        || {
            let observed_fencing_tokens = Arc::clone(&observed_fencing_tokens);
            async move {
                observed_fencing_tokens
                    .lock()
                    .expect("observed fencing token mutex should not be poisoned")
                    .iter()
                    .any(|fencing_token| *fencing_token > first_fencing_token)
            }
        },
    )
    .await;

    let _ = stop_sender.send(());
    tokio::time::timeout(Duration::from_secs(2), run_handle)
        .await
        .expect("continuous cron should stop after stop signal")
        .expect("join continuous cron")
        .expect("continuous cron should stop cleanly");
}
