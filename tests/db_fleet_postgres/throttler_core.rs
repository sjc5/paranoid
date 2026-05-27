use super::*;

#[tokio::test]
async fn fleet_throttler_rate_limit_refills_reports_status_and_resets() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler_key = ThrottlerKey::new("api-rate").expect("throttler key");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: throttler_key.clone(),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 2,
                interval: Duration::from_secs(60),
            }),
            concurrency_limit: None,
            circuit_breaker: None,
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let initial_status = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("initial status");
    assert_eq!(throttler.key(), &throttler_key);
    assert_eq!(initial_status.max_tokens(), 2.0);
    assert_eq!(initial_status.available_tokens(), 2.0);
    assert_eq!(
        initial_status.circuit_state(),
        ThrottlerCircuitState::Closed
    );

    for attempt in 0..2 {
        match throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("try acquire")
        {
            ThrottlerManualPermitAcquireResult::Acquired(permit) => {
                assert_eq!(permit.throttler_key(), &throttler_key);
                assert!(permit.holder_id().is_none());
                assert!(permit.slot_suffix().is_none());
            }
            other => panic!("attempt {attempt} acquire result = {other:?}, want acquired"),
        }
    }

    match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit(&test_database.paranoid_pool)
        .await
        .expect("try acquire while token bucket empty")
    {
        ThrottlerManualPermitAcquireResult::Throttled { retry_after } => {
            assert!(retry_after.is_some_and(|duration| !duration.is_zero()));
        }
        other => panic!("empty token bucket acquire result = {other:?}, want throttled"),
    }
    assert!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after throttling")
            .available_tokens()
            < 1.0
    );

    throttler
        .reset(&test_database.paranoid_pool)
        .await
        .expect("reset");
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after reset")
            .available_tokens(),
        2.0
    );

    let refill_throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("api-rate-refill").expect("refill throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 2,
                interval: Duration::from_millis(200),
            }),
            concurrency_limit: None,
            circuit_breaker: None,
        })
        .expect("new refill throttler");
    for attempt in 0..2 {
        assert!(
            matches!(
                refill_throttler
                    .begin_manual_permit_lifecycle()
                    .try_acquire_permit(&test_database.paranoid_pool)
                    .await
                    .expect("try acquire before refill"),
                ThrottlerManualPermitAcquireResult::Acquired(_)
            ),
            "refill throttler attempt {attempt} should acquire"
        );
    }
    assert!(matches!(
        refill_throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("try acquire empty refill throttler"),
        ThrottlerManualPermitAcquireResult::Throttled { .. }
    ));
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(matches!(
        refill_throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("try acquire after refill"),
        ThrottlerManualPermitAcquireResult::Acquired(_)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_try_run_task_returns_release_error_when_release_fails() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler_key = ThrottlerKey::new("release-error").expect("throttler key");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: throttler_key.clone(),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: None,
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let state_key = persisted_throttler_state_key(&test_database.config, &throttler_key);
    let kv_table_name = test_database.config.state_table_name.clone();
    let sqlx_pool = test_database.sqlx_pool.clone();
    let result = throttler
        .try_run_task(&test_database.paranoid_pool, move |_permit| {
            let sqlx_pool = sqlx_pool.clone();
            let kv_table_name = kv_table_name.clone();
            let state_key = state_key.clone();
            async move {
                let failure_function =
                    install_write_failure_trigger_on_kv_key(&sqlx_pool, &kv_table_name, &state_key)
                        .await;
                Ok::<_, TestComputeError>(failure_function)
            }
        })
        .await
        .expect("try run task");

    let failure_function = match result {
        ThrottlerTryRunTaskResult::Ran(ThrottlerGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert!(
                matches!(
                    release_result,
                    Err(Error::Kv(KvError::Database(DbError::Query { .. })))
                ),
                "release_result = {release_result:?}"
            );
            value
        }
        other => panic!("try_run_task result = {other:?}, want release failure after task success"),
    };
    drop_test_function_cascade(&test_database.sqlx_pool, &failure_function).await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_concurrency_slots_release_and_reacquire() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("workers").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: None,
        })
        .expect("new throttler");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_permit = match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first acquire")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("first acquire result = {other:?}, want acquired"),
    };
    assert_eq!(first_permit.holder_id(), Some(&first_holder));
    assert!(first_permit.slot_suffix().is_some());
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after first acquire")
            .current_concurrency(),
        1
    );

    assert!(matches!(
        throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("second acquire while full"),
        ThrottlerManualPermitAcquireResult::Throttled { retry_after: None }
    ));

    let release_result = throttler
        .begin_manual_permit_lifecycle()
        .release_permit_after_success(&test_database.paranoid_pool, &first_permit)
        .await
        .expect("release first permit");
    assert!(release_result.concurrency_slot_released());
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after release")
            .current_concurrency(),
        0
    );

    assert!(matches!(
        throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("second acquire after release"),
        ThrottlerManualPermitAcquireResult::Acquired(_)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_circuit_transitions_are_noops_when_circuit_breaking_is_disabled() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("no-circuit-transition").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_millis(90)),
            }),
            circuit_breaker: None,
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    throttler
        .open_circuit(&test_database.paranoid_pool)
        .await
        .expect("open circuit should be a no-op");
    throttler
        .close_circuit(&test_database.paranoid_pool)
        .await
        .expect("close circuit should be a no-op");
    assert!(matches!(
        throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("acquire after no-op circuit transitions"),
        ThrottlerManualPermitAcquireResult::Acquired(_)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_releases_acquired_slot_when_rate_limit_blocks() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("combined-limits").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 1,
                interval: Duration::from_secs(60 * 60),
            }),
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: None,
        })
        .expect("new throttler");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first_permit = match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first acquire")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("first acquire result = {other:?}, want acquired"),
    };
    throttler
        .begin_manual_permit_lifecycle()
        .release_permit_after_success(&test_database.paranoid_pool, &first_permit)
        .await
        .expect("release first permit");

    match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("second acquire")
    {
        ThrottlerManualPermitAcquireResult::Throttled { retry_after } => {
            assert!(retry_after.is_some_and(|duration| !duration.is_zero()));
        }
        other => panic!("second acquire result = {other:?}, want throttled"),
    }
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after rate-limit block")
            .current_concurrency(),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_circuit_opens_allows_one_probe_and_closes_on_success() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("remote-api").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 2,
                recovery_timeout: Duration::from_millis(100),
            }),
        })
        .expect("new throttler");
    let first_holder = HolderId::new("worker-a").expect("holder");
    let second_holder = HolderId::new("worker-b").expect("holder");
    let probe_holder = HolderId::new("worker-c").expect("holder");
    let blocked_probe_holder = HolderId::new("worker-d").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for holder in [&first_holder, &second_holder] {
        let permit = match throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit_for_holder(&test_database.paranoid_pool, holder)
            .await
            .expect("acquire before failure")
        {
            ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
            other => panic!("acquire before failure result = {other:?}, want acquired"),
        };
        throttler
            .begin_manual_permit_lifecycle()
            .release_permit_after_failure(&test_database.paranoid_pool, &permit)
            .await
            .expect("release after failure");
    }

    let open_status = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("open status");
    assert_eq!(open_status.circuit_state(), ThrottlerCircuitState::Open);
    assert_eq!(open_status.consecutive_failures(), 2);
    assert!(matches!(
        throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit_for_holder(&test_database.paranoid_pool, &probe_holder)
            .await
            .expect("probe before recovery"),
        ThrottlerManualPermitAcquireResult::CircuitOpen
    ));

    tokio::time::sleep(Duration::from_millis(150)).await;
    let probe_permit = match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &probe_holder)
        .await
        .expect("probe after recovery")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("probe acquire result = {other:?}, want acquired"),
    };
    assert!(probe_permit.probe_acquired());
    assert!(matches!(
        throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit_for_holder(&test_database.paranoid_pool, &blocked_probe_holder)
            .await
            .expect("second probe while first live"),
        ThrottlerManualPermitAcquireResult::CircuitOpen
    ));

    let release_result = throttler
        .begin_manual_permit_lifecycle()
        .release_permit_after_success(&test_database.paranoid_pool, &probe_permit)
        .await
        .expect("release successful probe");
    assert!(release_result.circuit_state_updated());
    assert!(release_result.probe_released());
    let closed_status = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("closed status");
    assert_eq!(closed_status.circuit_state(), ThrottlerCircuitState::Closed);
    assert_eq!(closed_status.consecutive_failures(), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_guarded_probe_stays_reserved_while_task_runs_past_probe_window() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("long-running-probe").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(50),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failed_permit = match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit(&test_database.paranoid_pool)
        .await
        .expect("initial acquire")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("initial acquire result = {other:?}, want acquired"),
    };
    throttler
        .begin_manual_permit_lifecycle()
        .release_permit_after_failure(&test_database.paranoid_pool, &failed_permit)
        .await
        .expect("open circuit");

    tokio::time::sleep(Duration::from_millis(75)).await;

    let (probe_started_sender, probe_started_receiver) = tokio::sync::oneshot::channel();
    let (probe_can_finish_sender, probe_can_finish_receiver) = tokio::sync::oneshot::channel();
    let first_probe_pool = test_database.paranoid_pool.clone();
    let first_probe_throttler = throttler.clone();
    let first_probe_handle = tokio::spawn(async move {
        first_probe_throttler
            .run_task_when_ready(&first_probe_pool, move |permit| async move {
                assert!(permit.probe_acquired());
                probe_started_sender.send(()).expect("notify probe started");
                probe_can_finish_receiver
                    .await
                    .expect("wait for probe release");
                Ok::<_, TestComputeError>("first-probe")
            })
            .await
    });

    probe_started_receiver.await.expect("first probe started");
    let status_after_first_probe_started = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after first probe started");
    assert_eq!(
        status_after_first_probe_started.circuit_state(),
        ThrottlerCircuitState::Open
    );
    assert_eq!(status_after_first_probe_started.consecutive_failures(), 1);
    tokio::time::sleep(DEFAULT_THROTTLER_PROBE_WINDOW + Duration::from_millis(500)).await;
    assert!(!first_probe_handle.is_finished());
    let status_while_first_probe_runs = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status while first probe runs");
    assert_eq!(
        status_while_first_probe_runs.circuit_state(),
        ThrottlerCircuitState::Open
    );
    assert_eq!(status_while_first_probe_runs.consecutive_failures(), 1);

    let second_probe_attempt = throttler
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Ok::<_, TestComputeError>("second-probe")
        })
        .await
        .expect("second probe attempt");
    match second_probe_attempt {
        ThrottlerTryRunTaskResult::CircuitOpen => {}
        other => panic!("second probe attempt = {other:?}, want circuit open while probe runs"),
    }

    probe_can_finish_sender
        .send(())
        .expect("allow first probe to finish");
    let first_probe_result = first_probe_handle
        .await
        .expect("first probe task should not panic")
        .expect("first probe task should not fail");
    match first_probe_result {
        ThrottlerGuardedTaskResult::Succeeded {
            value,
            release_result,
        } => {
            assert_eq!(value, "first-probe");
            assert!(
                release_result
                    .expect("first probe release")
                    .circuit_state_updated()
            );
        }
        other => panic!("first probe result = {other:?}, want success"),
    }

    let status = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after first probe");
    assert_eq!(status.circuit_state(), ThrottlerCircuitState::Closed);
    assert_eq!(status.consecutive_failures(), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_manual_circuit_transitions_clear_stale_probe_reservation() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("manual-circuit").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(10),
            }),
        })
        .expect("new throttler");
    let stale_probe_holder = HolderId::new("worker-a").expect("holder");
    let next_probe_holder = HolderId::new("worker-b").expect("holder");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    throttler
        .open_circuit(&test_database.paranoid_pool)
        .await
        .expect("open circuit");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &stale_probe_holder)
        .await
        .expect("first probe")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit.probe_acquired(),
        other => panic!("first probe result = {other:?}, want acquired probe"),
    });

    throttler
        .close_circuit(&test_database.paranoid_pool)
        .await
        .expect("close circuit");
    throttler
        .open_circuit(&test_database.paranoid_pool)
        .await
        .expect("reopen circuit");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &next_probe_holder)
        .await
        .expect("next probe after manual transition")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit.probe_acquired(),
        other => panic!("next probe result = {other:?}, want acquired probe"),
    });

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_composes_inside_current_transaction_and_rolls_back() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("transactional-throttler").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: None,
        })
        .expect("new throttler");
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
    let rolled_back_permit = match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder_in_current_transaction(&mut rollback_tx, &holder)
        .await
        .expect("acquire in rollback transaction")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("rollback transaction acquire result = {other:?}, want acquired"),
    };
    assert_eq!(
        throttler
            .fetch_status_in_current_transaction(&mut rollback_tx)
            .await
            .expect("status inside rollback transaction")
            .current_concurrency(),
        1
    );
    rollback_tx.rollback().await.expect("rollback transaction");
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after rollback")
            .current_concurrency(),
        0
    );
    assert_eq!(
        throttler
            .begin_manual_permit_lifecycle()
            .release_permit_after_success(&test_database.paranoid_pool, &rolled_back_permit)
            .await
            .expect("release rolled-back permit"),
        Default::default()
    );

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit transaction");
    let committed_permit = match throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder_in_current_transaction(&mut commit_tx, &holder)
        .await
        .expect("acquire in commit transaction")
    {
        ThrottlerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("commit transaction acquire result = {other:?}, want acquired"),
    };
    commit_tx.commit().await.expect("commit transaction");
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after commit")
            .current_concurrency(),
        1
    );
    assert!(
        throttler
            .begin_manual_permit_lifecycle()
            .release_permit_after_success(&test_database.paranoid_pool, &committed_permit)
            .await
            .expect("release committed permit")
            .concurrency_slot_released()
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_acquire_manual_permit_when_ready_waits_for_rate_limit_refill() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("blocking-rate").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 1,
                interval: Duration::from_millis(150),
            }),
            concurrency_limit: None,
            circuit_breaker: None,
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(matches!(
        throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("initial acquire"),
        ThrottlerManualPermitAcquireResult::Acquired(_)
    ));

    let started_at = Instant::now();
    let permit = throttler
        .begin_manual_permit_lifecycle()
        .acquire_permit_when_ready(&test_database.paranoid_pool)
        .await
        .expect("blocking acquire after refill");
    assert!(started_at.elapsed() >= Duration::from_millis(75));
    assert!(permit.holder_id().is_none());

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_run_task_when_ready_can_be_cancelled_while_waiting_for_open_circuit() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("cancel-while-open").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(5),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failed = throttler
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Err::<(), _>(TestComputeError("open circuit"))
        })
        .await
        .expect("open circuit with failed task");
    match failed {
        ThrottlerTryRunTaskResult::Ran(ThrottlerGuardedTaskResult::Failed {
            release_result,
            ..
        }) => {
            assert!(
                release_result
                    .expect("release failed task")
                    .circuit_state_updated()
            );
        }
        other => panic!("failed task result = {other:?}, want task failure"),
    }

    let task_run_count = Arc::new(AtomicUsize::new(0));
    let task_pool = test_database.paranoid_pool.clone();
    let task_throttler = throttler.clone();
    let task_run_count_for_task = Arc::clone(&task_run_count);
    let task_handle = tokio::spawn(async move {
        task_throttler
            .run_task_when_ready(&task_pool, move |_permit| async move {
                task_run_count_for_task.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            })
            .await
    });

    tokio::time::sleep(Duration::from_millis(75)).await;
    assert!(!task_handle.is_finished());
    task_handle.abort();
    let join_error = task_handle.await.expect_err("task should be cancelled");
    assert!(join_error.is_cancelled());

    tokio::time::sleep(Duration::from_millis(75)).await;
    assert_eq!(task_run_count.load(Ordering::SeqCst), 0);
    let status = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after cancelling waiting task");
    assert_eq!(status.circuit_state(), ThrottlerCircuitState::Open);
    assert_eq!(status.consecutive_failures(), 1);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_probe_is_not_reserved_when_rate_limit_denies_admission() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("rate-denied-probe").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 1,
                interval: Duration::from_secs(60 * 60),
            }),
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(50),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failed = throttler
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Err::<(), _>(TestComputeError("consume only token and open circuit"))
        })
        .await
        .expect("run initial failure");
    match failed {
        ThrottlerTryRunTaskResult::Ran(ThrottlerGuardedTaskResult::Failed {
            release_result,
            ..
        }) => {
            assert!(
                release_result
                    .expect("release after initial failure")
                    .circuit_state_updated()
            );
        }
        other => panic!("initial failure result = {other:?}, want task failure"),
    }

    tokio::time::sleep(Duration::from_millis(75)).await;

    let first_holder = HolderId::new("probe-a").expect("holder");
    let first = throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("first probe attempt");
    match first {
        ThrottlerManualPermitAcquireResult::Throttled {
            retry_after: Some(retry_after),
        } => assert!(retry_after > Duration::ZERO),
        other => panic!("first probe attempt = {other:?}, want rate throttled"),
    }

    let status_after_first_denial = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after first rate denial");
    assert_eq!(
        status_after_first_denial.circuit_state(),
        ThrottlerCircuitState::Open
    );
    assert_eq!(status_after_first_denial.consecutive_failures(), 1);

    let second_holder = HolderId::new("probe-b").expect("holder");
    let second = throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit_for_holder(&test_database.paranoid_pool, &second_holder)
        .await
        .expect("second probe attempt");
    match second {
        ThrottlerManualPermitAcquireResult::Throttled {
            retry_after: Some(retry_after),
        } => assert!(retry_after > Duration::ZERO),
        other => panic!("second probe attempt = {other:?}, want rate throttled"),
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
