use super::*;

#[tokio::test]
async fn fleet_rate_limiter_wraps_throttler_admission_status_and_reset() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let key = RateLimiterKey::new("rate-wrapper").expect("rate limiter key");
    let rate_limiter = store
        .new_rate_limiter(
            key.clone(),
            RateLimitConfig {
                requests_per_interval: 2,
                interval: Duration::from_secs(60),
            },
        )
        .expect("new rate limiter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(rate_limiter.key(), &key);
    let initial_status = rate_limiter
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("initial status");
    assert_eq!(initial_status.available_tokens(), 2.0);
    assert_eq!(initial_status.max_tokens(), 2.0);

    for _ in 0..2 {
        assert!(matches!(
            rate_limiter
                .begin_manual_permit_lifecycle()
                .try_acquire_permit(&test_database.paranoid_pool)
                .await
                .expect("rate-limiter acquire"),
            RateLimiterManualPermitAcquireResult::Acquired(_)
        ));
    }
    assert!(matches!(
        rate_limiter
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("rate-limiter acquire while empty"),
        RateLimiterManualPermitAcquireResult::Throttled {
            retry_after: Some(_)
        }
    ));

    rate_limiter
        .reset(&test_database.paranoid_pool)
        .await
        .expect("reset rate limiter");
    assert!(matches!(
        rate_limiter
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("rate-limiter acquire after reset"),
        RateLimiterManualPermitAcquireResult::Acquired(_)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_rate_limiter_fetch_status_propagates_database_errors() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("rate-status-error").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 2,
                interval: Duration::from_secs(60),
            },
        )
        .expect("new rate limiter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let error = rate_limiter
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect_err("missing schema should be returned");
    assert!(
        matches!(error, Error::Kv(KvError::Database(DbError::Query { .. }))),
        "error = {error:?}"
    );
}

#[tokio::test]
async fn fleet_circuit_breaker_wraps_throttler_probe_and_manual_transitions() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let key = CircuitBreakerKey::new("circuit-wrapper").expect("circuit breaker key");
    let circuit_breaker = store
        .new_circuit_breaker(
            key.clone(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(80),
            },
        )
        .expect("new circuit breaker");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(circuit_breaker.key(), &key);
    let first_permit = match circuit_breaker
        .begin_manual_permit_lifecycle()
        .try_acquire_permit(&test_database.paranoid_pool)
        .await
        .expect("initial circuit acquire")
    {
        CircuitBreakerManualPermitAcquireResult::Acquired(permit) => permit,
        other => panic!("initial circuit acquire result = {other:?}, want acquired"),
    };
    circuit_breaker
        .begin_manual_permit_lifecycle()
        .release_permit_after_failure(&test_database.paranoid_pool, &first_permit)
        .await
        .expect("record failure");

    let open_status = circuit_breaker
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("open status");
    assert_eq!(open_status.circuit_state(), ThrottlerCircuitState::Open);
    assert_eq!(open_status.consecutive_failures(), 1);
    assert!(matches!(
        circuit_breaker
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("acquire while open"),
        CircuitBreakerManualPermitAcquireResult::CircuitOpen
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;
    let probe_permit = circuit_breaker
        .begin_manual_permit_lifecycle()
        .acquire_permit_when_ready(&test_database.paranoid_pool)
        .await
        .expect("probe acquire when ready");
    assert!(probe_permit.probe_acquired());
    circuit_breaker
        .begin_manual_permit_lifecycle()
        .release_permit_after_success(&test_database.paranoid_pool, &probe_permit)
        .await
        .expect("record probe success");
    assert_eq!(
        circuit_breaker
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("closed status")
            .circuit_state(),
        ThrottlerCircuitState::Closed
    );

    circuit_breaker
        .open(&test_database.paranoid_pool)
        .await
        .expect("manual open");
    assert!(matches!(
        circuit_breaker
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("acquire after manual open"),
        CircuitBreakerManualPermitAcquireResult::CircuitOpen
    ));
    circuit_breaker
        .close(&test_database.paranoid_pool)
        .await
        .expect("manual close");
    assert!(matches!(
        circuit_breaker
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("acquire after manual close"),
        CircuitBreakerManualPermitAcquireResult::Acquired(_)
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_circuit_breaker_fetch_status_propagates_database_errors() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("circuit-status-error").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(1),
            },
        )
        .expect("new circuit breaker");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let error = circuit_breaker
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect_err("missing schema should be returned");
    assert!(
        matches!(error, Error::Kv(KvError::Database(DbError::Query { .. }))),
        "error = {error:?}"
    );
}

#[tokio::test]
async fn fleet_throttler_guard_drop_on_plain_thread_releases_concurrency_slot() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("guarded-concurrency").expect("throttler key"),
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

    let guard = match throttler
        .try_acquire_guard_for_holder(&test_database.paranoid_pool, &first_holder)
        .await
        .expect("guarded acquire")
    {
        ThrottlerGuardAcquireResult::Acquired(guard) => guard,
        other => panic!("guarded acquire result = {other:?}, want acquired"),
    };
    assert_eq!(
        guard.live_permit().expect("live guard permit").holder_id(),
        Some(&first_holder)
    );
    assert_eq!(
        throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after guarded acquire")
            .current_concurrency(),
        1
    );
    std::thread::spawn(move || drop(guard))
        .join()
        .expect("plain drop thread should not panic");

    let mut reacquired = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        match throttler
            .begin_manual_permit_lifecycle()
            .try_acquire_permit_for_holder(&test_database.paranoid_pool, &second_holder)
            .await
            .expect("reacquire after guard drop")
        {
            ThrottlerManualPermitAcquireResult::Acquired(permit) => {
                reacquired = true;
                throttler
                    .begin_manual_permit_lifecycle()
                    .release_permit_without_task_outcome(&test_database.paranoid_pool, &permit)
                    .await
                    .expect("release reacquired permit");
                break;
            }
            ThrottlerManualPermitAcquireResult::Throttled { retry_after: None } => {}
            other => panic!("reacquire result = {other:?}, want acquired or concurrency throttle"),
        }
    }
    assert!(reacquired);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_circuit_breaker_guard_records_failure_and_drop_clears_probe() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("guarded-circuit").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(50),
            },
        )
        .expect("new circuit breaker");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failure_guard = match circuit_breaker
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("initial guarded circuit acquire")
    {
        CircuitBreakerGuardAcquireResult::Acquired(guard) => guard,
        other => panic!("initial guarded circuit acquire result = {other:?}, want acquired"),
    };
    failure_guard
        .release_after_failure()
        .await
        .expect("release failure guard");
    assert_eq!(
        circuit_breaker
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after failure")
            .circuit_state(),
        ThrottlerCircuitState::Open
    );

    tokio::time::sleep(Duration::from_millis(70)).await;
    let probe_guard = circuit_breaker
        .acquire_guard_when_ready(&test_database.paranoid_pool)
        .await
        .expect("probe guard");
    assert!(
        probe_guard
            .live_permit()
            .expect("live probe guard permit")
            .probe_acquired()
    );
    drop(probe_guard);

    let mut second_probe_acquired = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        match circuit_breaker
            .try_acquire_guard(&test_database.paranoid_pool)
            .await
            .expect("second probe acquire")
        {
            CircuitBreakerGuardAcquireResult::Acquired(guard) => {
                second_probe_acquired = true;
                guard
                    .release_without_task_outcome()
                    .await
                    .expect("release second probe guard");
                break;
            }
            CircuitBreakerGuardAcquireResult::CircuitOpen => {}
        }
    }
    assert!(second_probe_acquired);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_cancelled_guard_release_preserves_task_outcome_on_drop() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler_key =
        ThrottlerKey::new("cancelled-release-records-failure").expect("throttler key");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: throttler_key.clone(),
            rate_limit: None,
            concurrency_limit: None,
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(60),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let guard = match throttler
        .try_acquire_guard(&test_database.paranoid_pool)
        .await
        .expect("guarded circuit acquire")
    {
        ThrottlerGuardAcquireResult::Acquired(guard) => guard,
        other => panic!("guarded acquire result = {other:?}, want acquired"),
    };
    let state_key = persisted_throttler_state_key(&test_database.config, &throttler_key);
    let row_lock_transaction = begin_transaction_locking_raw_kv_row(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
        &state_key,
    )
    .await;

    tokio::time::timeout(Duration::from_millis(200), guard.release_after_failure())
        .await
        .expect_err("blocked release future should be cancellable");

    row_lock_transaction
        .rollback()
        .await
        .expect("rollback throttler state row lock transaction");
    wait_until(
        "cancelled throttler guard release records failure on drop",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let throttler = throttler.clone();
            async move {
                let status = throttler
                    .fetch_status(&pool)
                    .await
                    .expect("fetch throttler status after cancelled release");
                status.circuit_state() == ThrottlerCircuitState::Open
                    && status.consecutive_failures() == 1
            }
        },
    )
    .await;

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_rate_limiter_try_run_task_runs_and_reports_throttled() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("rate-limiter-task-runner").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 1,
                interval: Duration::from_secs(1),
            },
        )
        .expect("new rate limiter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let first = rate_limiter
        .try_run_task(&test_database.paranoid_pool, |permit| async move {
            assert_eq!(
                permit.rate_limiter_key(),
                &RateLimiterKey::new("rate-limiter-task-runner").expect("rate limiter key")
            );
            Ok::<_, &'static str>("ran")
        })
        .await
        .expect("run first rate-limited task");
    match first {
        RateLimiterTryRunTaskResult::Ran(RateLimiterGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert_eq!(value, "ran");
            assert_eq!(release_result.expect("release after rate-limited task"), ());
        }
        other => panic!("first rate-limited task result = {other:?}, want success"),
    }

    let second = rate_limiter
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Ok::<_, &'static str>("should not run")
        })
        .await
        .expect("try second rate-limited task");
    match second {
        RateLimiterTryRunTaskResult::Throttled {
            retry_after: Some(retry_after),
        } => assert!(retry_after <= Duration::from_secs(1)),
        other => panic!("second rate-limited task result = {other:?}, want throttled"),
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_rate_limiter_run_task_when_ready_waits_and_preserves_task_failure() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("rate-limiter-waiting-task").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 1,
                interval: Duration::from_millis(120),
            },
        )
        .expect("new rate limiter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(matches!(
        rate_limiter
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("consume initial token"),
        RateLimiterManualPermitAcquireResult::Acquired(_)
    ));

    let started_at = Instant::now();
    let result = rate_limiter
        .run_task_when_ready(&test_database.paranoid_pool, |_permit| async {
            Err::<(), _>(TestComputeError("limited task failed"))
        })
        .await
        .expect("run waiting rate-limited task");
    assert!(started_at.elapsed() >= Duration::from_millis(60));
    match result {
        RateLimiterGuardedTaskResult::Failed {
            error,
            release_result,
        } => {
            assert_eq!(error, TestComputeError("limited task failed"));
            assert_eq!(
                release_result.expect("release failed rate-limited task"),
                ()
            );
        }
        other => panic!("waiting rate-limited task result = {other:?}, want failure"),
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_rate_limiter_waiting_task_can_be_cancelled_before_execution() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("rate-limiter-cancel-before-task").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 1,
                interval: Duration::from_secs(60 * 60),
            },
        )
        .expect("new rate limiter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert!(matches!(
        rate_limiter
            .begin_manual_permit_lifecycle()
            .try_acquire_permit(&test_database.paranoid_pool)
            .await
            .expect("consume initial token"),
        RateLimiterManualPermitAcquireResult::Acquired(_)
    ));

    let task_run_count = Arc::new(AtomicUsize::new(0));
    let task_run_count_for_task = Arc::clone(&task_run_count);
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        rate_limiter.run_task_when_ready(&test_database.paranoid_pool, move |_permit| async move {
            task_run_count_for_task.fetch_add(1, Ordering::SeqCst);
            Ok::<(), TestComputeError>(())
        }),
    )
    .await;

    assert!(result.is_err());
    assert_eq!(task_run_count.load(Ordering::SeqCst), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_rate_limiter_high_rate_admits_many_immediate_tasks() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("rate-limiter-high-rate").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 100,
                interval: Duration::from_secs(1),
            },
        )
        .expect("new rate limiter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_run_count = AtomicUsize::new(0);
    for task_index in 0..50 {
        let result = rate_limiter
            .try_run_task(&test_database.paranoid_pool, |_permit| async {
                task_run_count.fetch_add(1, Ordering::SeqCst);
                Ok::<(), TestComputeError>(())
            })
            .await
            .expect("run high-rate task");
        match result {
            RateLimiterTryRunTaskResult::Ran(RateLimiterGuardedTaskResult::Succeeded {
                ..
            }) => {}
            other => panic!("high-rate task {task_index} result = {other:?}, want success"),
        }
    }
    assert_eq!(task_run_count.load(Ordering::SeqCst), 50);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_circuit_breaker_run_task_records_failure_denies_and_recovers() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("circuit-task-runner").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(50),
            },
        )
        .expect("new circuit breaker");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let failed = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Err::<(), _>("downstream failed")
        })
        .await
        .expect("run failing circuit task");
    match failed {
        CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Failed {
            error,
            release_result,
        }) => {
            assert_eq!(error, "downstream failed");
            assert!(
                release_result
                    .expect("release after failed circuit task")
                    .circuit_state_updated()
            );
        }
        other => panic!("failed circuit task result = {other:?}, want task failure"),
    }
    assert_eq!(
        circuit_breaker
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after failed task")
            .circuit_state(),
        ThrottlerCircuitState::Open
    );

    let denied = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Ok::<_, &'static str>("should not run")
        })
        .await
        .expect("try task while circuit open");
    match denied {
        CircuitBreakerTryRunTaskResult::CircuitOpen => {}
        other => panic!("open circuit task result = {other:?}, want circuit open"),
    }

    tokio::time::sleep(Duration::from_millis(70)).await;
    let recovered = circuit_breaker
        .run_task_when_ready(&test_database.paranoid_pool, |_permit| async {
            Ok::<_, &'static str>("recovered")
        })
        .await
        .expect("run recovery task");
    match recovered {
        CircuitBreakerGuardedTaskResult::Succeeded {
            value,
            release_result,
        } => {
            assert_eq!(value, "recovered");
            assert!(
                release_result
                    .expect("release after recovery task")
                    .circuit_state_updated()
            );
        }
        other => panic!("recovery task result = {other:?}, want success"),
    }
    let status = circuit_breaker
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after recovery task");
    assert_eq!(status.circuit_state(), ThrottlerCircuitState::Closed);
    assert_eq!(status.consecutive_failures(), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_circuit_breaker_failed_probe_resets_recovery_timeout() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("failed-probe-resets-timeout").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_millis(100),
            },
        )
        .expect("new circuit breaker");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let initial_failure = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Err::<(), _>(TestComputeError("initial failure"))
        })
        .await
        .expect("run initial failing task");
    match initial_failure {
        CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Failed {
            release_result,
            ..
        }) => {
            assert!(
                release_result
                    .expect("release initial failure")
                    .circuit_state_updated()
            );
        }
        other => panic!("initial failure result = {other:?}, want task failure"),
    }

    tokio::time::sleep(Duration::from_millis(125)).await;
    let failed_probe = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |permit| async move {
            assert!(permit.probe_acquired());
            Err::<(), _>(TestComputeError("probe failure"))
        })
        .await
        .expect("run failing probe");
    match failed_probe {
        CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Failed {
            error,
            release_result,
        }) => {
            assert_eq!(error, TestComputeError("probe failure"));
            assert!(
                release_result
                    .expect("release failed probe")
                    .circuit_state_updated()
            );
        }
        other => panic!("failed probe result = {other:?}, want task failure"),
    }

    let immediate_retry = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Ok::<_, TestComputeError>("should-not-run")
        })
        .await
        .expect("immediate retry after failed probe");
    match immediate_retry {
        CircuitBreakerTryRunTaskResult::CircuitOpen => {}
        other => panic!("immediate retry = {other:?}, want circuit open"),
    }

    tokio::time::sleep(Duration::from_millis(125)).await;
    let recovered = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |permit| async move {
            assert!(permit.probe_acquired());
            Ok::<_, TestComputeError>("recovered")
        })
        .await
        .expect("recovery retry after failed probe timeout");
    match recovered {
        CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert_eq!(value, "recovered");
            assert!(
                release_result
                    .expect("release recovery probe")
                    .circuit_state_updated()
            );
        }
        other => panic!("recovery retry = {other:?}, want success"),
    }

    let status = circuit_breaker
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after successful recovery");
    assert_eq!(status.circuit_state(), ThrottlerCircuitState::Closed);
    assert_eq!(status.consecutive_failures(), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_circuit_breaker_success_resets_consecutive_failures_before_threshold() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("circuit-success-resets-failures").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 5,
                recovery_timeout: Duration::from_secs(1),
            },
        )
        .expect("new circuit breaker");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for _ in 0..3 {
        let result = circuit_breaker
            .try_run_task(&test_database.paranoid_pool, |_permit| async {
                Err::<(), _>(TestComputeError("counted failure"))
            })
            .await
            .expect("run counted failure");
        match result {
            CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Failed {
                release_result,
                ..
            }) => {
                assert!(
                    release_result
                        .expect("release counted failure")
                        .circuit_state_updated()
                );
            }
            other => panic!("counted failure result = {other:?}, want failed task"),
        }
    }

    let failed_status = circuit_breaker
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after failures below threshold");
    assert_eq!(failed_status.circuit_state(), ThrottlerCircuitState::Closed);
    assert_eq!(failed_status.consecutive_failures(), 3);

    let success = circuit_breaker
        .try_run_task(&test_database.paranoid_pool, |_permit| async {
            Ok::<_, TestComputeError>("success")
        })
        .await
        .expect("run success");
    match success {
        CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert_eq!(value, "success");
            assert!(
                release_result
                    .expect("release success after failures")
                    .circuit_state_updated()
            );
        }
        other => panic!("success result = {other:?}, want succeeded task"),
    }

    let recovered_status = circuit_breaker
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("status after success");
    assert_eq!(
        recovered_status.circuit_state(),
        ThrottlerCircuitState::Closed
    );
    assert_eq!(recovered_status.consecutive_failures(), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_run_task_abort_releases_slot_and_records_failure() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("abort-task-runner").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(60),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let task_pool = test_database.paranoid_pool.clone();
    let task_throttler = throttler.clone();
    let task_handle = tokio::spawn(async move {
        task_throttler
            .run_task_when_ready(&task_pool, move |_permit| async move {
                let _ = started_sender.send(());
                std::future::pending::<Result<(), &'static str>>().await
            })
            .await
    });

    started_receiver.await.expect("task started");
    task_handle.abort();
    let join_error = task_handle.await.expect_err("task should be aborted");
    assert!(join_error.is_cancelled());

    let mut observed_cleanup = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let status = throttler
            .fetch_status(&test_database.paranoid_pool)
            .await
            .expect("status after task abort");
        if status.current_concurrency() == 0
            && status.circuit_state() == ThrottlerCircuitState::Open
        {
            observed_cleanup = true;
            break;
        }
    }
    assert!(observed_cleanup);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_run_task_panic_releases_slot_and_records_failure() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("panic-task-runner").expect("throttler key"),
            rate_limit: None,
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(60),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let task_pool = test_database.paranoid_pool.clone();
    let task_throttler = throttler.clone();
    let task_handle = tokio::spawn(async move {
        task_throttler
            .run_task_when_ready(&task_pool, |_permit| async {
                panic!("intentional throttler task panic");
                #[allow(unreachable_code)]
                Ok::<(), TestComputeError>(())
            })
            .await
    });

    let join_error = task_handle.await.expect_err("task should panic");
    assert!(join_error.is_panic());

    wait_until(
        "panic-dropped throttler permit releases slot and records failure",
        Duration::from_secs(2),
        || {
            let pool = test_database.paranoid_pool.clone();
            let throttler = throttler.clone();
            async move {
                let status = throttler
                    .fetch_status(&pool)
                    .await
                    .expect("fetch throttler status after task panic");
                status.current_concurrency() == 0
                    && status.circuit_state() == ThrottlerCircuitState::Open
                    && status.consecutive_failures() == 1
            }
        },
    )
    .await;

    let denied_by_open_circuit = throttler
        .begin_manual_permit_lifecycle()
        .try_acquire_permit(&test_database.paranoid_pool)
        .await
        .expect("acquire after task panic cleanup");
    match denied_by_open_circuit {
        ThrottlerManualPermitAcquireResult::CircuitOpen => {}
        other => panic!("acquire after panic = {other:?}, want circuit open"),
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_throttler_mixed_limits_cancellation_stress_releases_all_slots() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("mixed-cancellation-stress").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 8,
                interval: Duration::from_millis(80),
            }),
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 3,
                max_hold_duration: Some(Duration::from_millis(500)),
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 2,
                recovery_timeout: Duration::from_millis(120),
            }),
        })
        .expect("new throttler");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    const WORKER_COUNT: usize = 40;

    let cancelled_count = Arc::new(AtomicUsize::new(0));
    let currently_running = Arc::new(AtomicUsize::new(0));
    let max_concurrent_seen = Arc::new(AtomicUsize::new(0));
    let start_barrier = Arc::new(Barrier::new(WORKER_COUNT));
    let mut worker_handles = Vec::with_capacity(WORKER_COUNT);

    for worker_index in 0..WORKER_COUNT {
        let pool = test_database.paranoid_pool.clone();
        let throttler = throttler.clone();
        let start_barrier = Arc::clone(&start_barrier);
        let cancelled_count = Arc::clone(&cancelled_count);
        let currently_running = Arc::clone(&currently_running);
        let max_concurrent_seen = Arc::clone(&max_concurrent_seen);
        worker_handles.push(tokio::spawn(async move {
            start_barrier.wait().await;
            let timeout = Duration::from_millis(20 + u64::try_from(worker_index % 5).unwrap() * 15);
            let result = tokio::time::timeout(
                timeout,
                throttler.run_task_when_ready(&pool, move |_permit| async move {
                    let _running_guard =
                        RunningCounterGuard::increment(currently_running, max_concurrent_seen);
                    let work_time =
                        Duration::from_millis(10 + u64::try_from(worker_index % 4).unwrap() * 10);
                    tokio::time::sleep(work_time).await;
                    if worker_index % 9 == 0 {
                        return Err(TestComputeError("synthetic throttler failure"));
                    }
                    Ok::<_, TestComputeError>(())
                }),
            )
            .await;
            if result.is_err() {
                cancelled_count.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for worker_handle in worker_handles {
        worker_handle.await.expect("join throttler stress worker");
    }

    assert!(
        max_concurrent_seen.load(Ordering::SeqCst) <= 3,
        "max concurrent task count should respect configured concurrency limit"
    );
    assert!(
        cancelled_count.load(Ordering::SeqCst) > 0,
        "stress run should exercise cancellation"
    );
    wait_until(
        "mixed throttler stress releases all concurrency slots",
        Duration::from_secs(3),
        || {
            let pool = test_database.paranoid_pool.clone();
            let throttler = throttler.clone();
            async move {
                throttler
                    .fetch_status(&pool)
                    .await
                    .expect("status after mixed throttler stress")
                    .current_concurrency()
                    == 0
            }
        },
    )
    .await;
    let final_status = throttler
        .fetch_status(&test_database.paranoid_pool)
        .await
        .expect("final mixed throttler status");
    assert_eq!(final_status.max_tokens(), 8.0);
    assert_eq!(final_status.max_concurrency(), 3);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
