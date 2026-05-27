use super::cron_support::*;
use super::*;

#[tokio::test]
async fn fleet_cron_run_once_returns_task_error_and_releases_leadership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("task-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let err = cron
        .run_once(&test_database.paranoid_pool, |_| async {
            Err::<(), _>(TestComputeError("cron task failed"))
        })
        .await
        .expect_err("task error should be returned");
    assert!(
        matches!(
            err,
            CronRunError::Task {
                source: TestComputeError("cron task failed")
            }
        ),
        "error = {err:?}"
    );
    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch leader after task error")
            .is_none(),
        "task errors must not leak leadership"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_try_run_once_returns_acquire_error_when_schema_is_missing() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("try-acquire-missing-schema"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let err = cron
        .try_run_once(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>(())
        })
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
async fn fleet_cron_run_once_returns_acquire_error_when_schema_is_missing() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("run-once-acquire-missing-schema"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let err = cron
        .run_once(&test_database.paranoid_pool, |_| async {
            Ok::<_, TestComputeError>(())
        })
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
async fn fleet_cron_try_run_once_returns_release_error_when_release_fails() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(default_heartbeat_cron_config("try-release-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let err = cron
        .try_run_once(&test_database.paranoid_pool, move |_| async move {
            drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
            Ok::<_, TestComputeError>(())
        })
        .await
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
async fn fleet_cron_run_once_returns_task_and_release_errors_when_both_fail() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(default_heartbeat_cron_config("task-and-release-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let sqlx_pool = test_database.sqlx_pool.clone();
    let config = test_database.config.clone();
    let err = cron
        .run_once(&test_database.paranoid_pool, move |_| async move {
            drop_test_table(&sqlx_pool, &config.coordination_table_name).await;
            Err::<(), _>(TestComputeError("cron task and release failed"))
        })
        .await
        .expect_err("task and release failures should both be returned");
    assert!(
        matches!(
            err,
            CronRunError::TaskAndRelease {
                source: TestComputeError("cron task and release failed"),
                release_error: Error::Coordination(CoordinationError::Database(_))
            }
        ),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_try_run_once_returns_task_error_and_releases_leadership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("try-task-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let err = cron
        .try_run_once(&test_database.paranoid_pool, |_| async {
            Err::<(), _>(TestComputeError("cron try task failed"))
        })
        .await
        .expect_err("task error should be returned");
    assert!(
        matches!(
            err,
            CronRunError::Task {
                source: TestComputeError("cron try task failed")
            }
        ),
        "error = {err:?}"
    );
    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch leader after task error")
            .is_none(),
        "try_run_once task errors must not leak leadership"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_try_run_once_task_panic_releases_leadership() {
    async fn panic_cron_task(_: MutexGuardSnapshot) -> Result<(), TestComputeError> {
        panic!("cron try_run_once panic")
    }

    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("try-task-panic"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let panic_cron = cron.clone();
    let panic_pool = test_database.paranoid_pool.clone();
    let panic_handle =
        tokio::spawn(async move { panic_cron.try_run_once(&panic_pool, panic_cron_task).await });
    let join_error = panic_handle.await.expect_err("cron task should panic");
    assert!(join_error.is_panic());

    wait_until(
        "panic-dropped try_run_once leadership releases",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let store = store.clone();
            async move { first_cron_leader_absent(&pool, &store, "try-task-panic").await }
        },
    )
    .await;
    assert_eq!(
        cron.try_run_once(&test_database.paranoid_pool, |snapshot| async move {
            Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
        })
        .await
        .expect("try run once after task panic"),
        CronTryRunOnceResult::Ran(2)
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_run_once_task_panic_releases_leadership() {
    async fn panic_cron_task(_: MutexGuardSnapshot) -> Result<(), TestComputeError> {
        panic!("cron run_once panic")
    }

    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("run-once-task-panic"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let panic_cron = cron.clone();
    let panic_pool = test_database.paranoid_pool.clone();
    let panic_handle =
        tokio::spawn(async move { panic_cron.run_once(&panic_pool, panic_cron_task).await });
    let join_error = panic_handle.await.expect_err("cron task should panic");
    assert!(join_error.is_panic());

    wait_until(
        "panic-dropped run_once leadership releases",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let store = store.clone();
            async move { first_cron_leader_absent(&pool, &store, "run-once-task-panic").await }
        },
    )
    .await;
    assert_eq!(
        cron.try_run_once(&test_database.paranoid_pool, |snapshot| async move {
            Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
        })
        .await
        .expect("try run once after task panic"),
        CronTryRunOnceResult::Ran(2)
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_cancelled_run_once_releases_leadership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("run-once-cancelled"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_cron = cron.clone();
    let task_pool = test_database.paranoid_pool.clone();
    let (task_started_sender, task_started_receiver) = tokio::sync::oneshot::channel();
    let task_handle = tokio::spawn(async move {
        task_cron
            .run_once(&task_pool, move |snapshot| async move {
                assert_eq!(snapshot.mutex_key().as_str(), "run-once-cancelled");
                let _ = task_started_sender.send(());
                std::future::pending::<Result<(), TestComputeError>>().await
            })
            .await
    });

    task_started_receiver
        .await
        .expect("cancelled cron task should start");
    task_handle.abort();
    let join_error = task_handle.await.expect_err("task should be cancelled");
    assert!(join_error.is_cancelled());

    wait_until(
        "cancelled run_once leadership releases",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let store = store.clone();
            async move { first_cron_leader_absent(&pool, &store, "run-once-cancelled").await }
        },
    )
    .await;
    assert_eq!(
        cron.try_run_once(&test_database.paranoid_pool, |snapshot| async move {
            Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
        })
        .await
        .expect("try run once after cancellation"),
        CronTryRunOnceResult::Ran(2)
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_start_handle_reports_task_error_and_releases_leadership() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("start-handle-task-error"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let handle = cron
        .start_until_stopped_or_task_error(test_database.paranoid_pool.clone(), |_| async {
            Err::<(), _>(TestComputeError("cron handle task failed"))
        });
    let err = handle
        .wait()
        .await
        .expect_err("task error should be returned");
    assert!(
        matches!(
            err,
            CronRunHandleError::Run {
                source: CronRunError::Task {
                    source: TestComputeError("cron handle task failed")
                }
            }
        ),
        "error = {err:?}"
    );
    assert!(
        cron.fetch_live_leader(&test_database.paranoid_pool)
            .await
            .expect("fetch leader after task error")
            .is_none(),
        "task errors must not leak leadership"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_start_handle_task_panic_releases_leadership() {
    async fn panic_cron_task(_: MutexGuardSnapshot) -> Result<(), TestComputeError> {
        panic!("cron task panic")
    }

    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let cron = store
        .new_cron(fast_cron_config("start-handle-task-panic"))
        .expect("new cron");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let handle = cron
        .start_until_stopped_or_task_error(test_database.paranoid_pool.clone(), panic_cron_task);
    let err = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .expect("cron handle should stop after task panic")
        .expect_err("task panic should be returned as a join error");
    match err {
        CronRunHandleError::Join { source } => assert!(source.is_panic()),
        other => panic!("error = {other:?}, want panic join error"),
    }

    wait_until(
        "panic-dropped cron leadership releases",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let store = store.clone();
            async move { first_cron_leader_absent(&pool, &store, "start-handle-task-panic").await }
        },
    )
    .await;
    assert_eq!(
        cron.try_run_once(&test_database.paranoid_pool, |snapshot| async move {
            Ok::<_, TestComputeError>(snapshot.fencing_token().as_i64())
        })
        .await
        .expect("try run once after task panic"),
        CronTryRunOnceResult::Ran(2)
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_cron_config_rejects_invalid_options() {
    assert!(matches!(
        CronKey::new(""),
        Err(Error::InvalidCronKey { .. })
    ));
    assert!(matches!(
        CronKey::new("has:colon"),
        Err(Error::InvalidCronKey { .. })
    ));

    let store = Store::new(StoreConfig::default()).expect("fleet store");
    assert!(matches!(
        store.new_cron(CronConfig {
            key: CronKey::new("too-fast").expect("cron key"),
            interval: MIN_CRON_INTERVAL - Duration::from_millis(1),
            claim_duration: None,
            heartbeat_interval: None,
            acquire_retry_interval: None,
            max_consecutive_renewal_failures: None,
        }),
        Err(Error::InvalidCronInterval { .. })
    ));
    assert!(matches!(
        store.new_cron(CronConfig {
            key: CronKey::new("bad-heartbeat").expect("cron key"),
            interval: MIN_CRON_INTERVAL,
            claim_duration: Some(
                ClaimDuration::expires_after(Duration::from_secs(1)).expect("claim duration")
            ),
            heartbeat_interval: Some(Duration::from_millis(600)),
            acquire_retry_interval: None,
            max_consecutive_renewal_failures: None,
        }),
        Err(Error::MutexClaimDurationTooShortForHeartbeat { .. })
    ));
}
