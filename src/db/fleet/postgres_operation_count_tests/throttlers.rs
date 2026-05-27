use super::*;

#[tokio::test]
async fn fleet_throttlers_emit_exact_database_operation_records() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres Fleet operation-count test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let observed = prepare_observed_fleet_store(&database_url).await;
    let store = &observed.store;
    let observer = observed.observer.clone();
    let observed_pool = observed.observed_pool.clone();

    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("operation-count-throttler").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 10,
                interval: Duration::from_secs(60),
            }),
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 1,
                max_hold_duration: Some(Duration::from_secs(60)),
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 2,
                recovery_timeout: Duration::from_secs(60),
            }),
        })
        .expect("throttler");
    let throttler_holder_id = HolderId::new("operation-count-throttler-holder").expect("holder id");
    let throttler_guard = match throttler
        .try_acquire_guard_for_holder(&observed_pool, &throttler_holder_id)
        .await
        .expect("try acquire throttler guard")
    {
        ThrottlerGuardAcquireResult::Acquired(guard) => guard,
        other => panic!("expected throttler guard, got {other:?}"),
    };
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
        ]),
    );

    let release_result = throttler_guard
        .release_without_task_outcome()
        .await
        .expect("release throttler guard");
    assert!(release_result.concurrency_slot_released());
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
        ]),
    );

    assert_eq!(
        throttler
            .fetch_status(&observed_pool)
            .await
            .expect("fetch throttler status")
            .current_concurrency(),
        0
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
        )]),
    );

    throttler
        .reset(&observed_pool)
        .await
        .expect("reset throttler");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_DELETE_KEY)]),
    );

    let waiting_throttler_holder_id =
        HolderId::new("operation-count-waiting-throttler-holder").expect("waiting holder id");
    let expected_waiting_throttler_holder_id = waiting_throttler_holder_id.clone();
    let waiting_throttler_result = throttler
        .run_task_for_holder_when_ready(
            &observed_pool,
            &waiting_throttler_holder_id,
            |permit| async move {
                assert_eq!(
                    permit.holder_id(),
                    Some(&expected_waiting_throttler_holder_id)
                );
                Ok::<_, std::io::Error>("waited-throttler")
            },
        )
        .await
        .expect("run throttler task after waiting for readiness");
    match waiting_throttler_result {
        ThrottlerGuardedTaskResult::Succeeded {
            value,
            release_result,
        } => {
            assert_eq!(value, "waited-throttler");
            assert!(
                release_result
                    .expect("release waiting throttler guard")
                    .concurrency_slot_released()
            );
        }
        other => panic!("expected waiting throttler task to run, got {other:?}"),
    }
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
            ]),
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
            ]),
        ]
        .concat(),
    );

    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("operation-count-rate-limiter").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 10,
                interval: Duration::from_secs(60),
            },
        )
        .expect("rate limiter");
    match rate_limiter
        .try_run_task(&observed_pool, |permit| async move {
            assert_eq!(
                permit.rate_limiter_key(),
                &RateLimiterKey::new("operation-count-rate-limiter").expect("rate limiter key")
            );
            Ok::<_, std::io::Error>(17)
        })
        .await
        .expect("try run rate-limited task")
    {
        RateLimiterTryRunTaskResult::Ran(RateLimiterGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert_eq!(value, 17);
            assert_eq!(release_result.expect("rate-limiter no-op release"), ());
        }
        other => panic!("expected rate-limited task to run, got {other:?}"),
    }
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
        ]),
    );

    assert!(
        rate_limiter
            .fetch_status(&observed_pool)
            .await
            .expect("fetch rate limiter status")
            .available_tokens()
            <= 10.0
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
        )]),
    );

    rate_limiter
        .reset(&observed_pool)
        .await
        .expect("reset rate limiter");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_DELETE_KEY)]),
    );

    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("operation-count-circuit-breaker").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 1,
                recovery_timeout: Duration::from_secs(60),
            },
        )
        .expect("circuit breaker");
    circuit_breaker
        .open(&observed_pool)
        .await
        .expect("open circuit");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
        ]),
    );

    assert!(matches!(
        circuit_breaker
            .try_acquire_guard(&observed_pool)
            .await
            .expect("try acquire open circuit"),
        CircuitBreakerGuardAcquireResult::CircuitOpen
    ));
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
        )]),
    );

    circuit_breaker
        .close(&observed_pool)
        .await
        .expect("close circuit");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
        ]),
    );

    match circuit_breaker
        .try_run_task(&observed_pool, |_permit| async move {
            Err::<(), _>(std::io::Error::other("task failed"))
        })
        .await
        .expect("try run circuit-breaker task")
    {
        CircuitBreakerTryRunTaskResult::Ran(CircuitBreakerGuardedTaskResult::Failed {
            release_result,
            ..
        }) => {
            assert!(
                release_result
                    .expect("release after failed task")
                    .circuit_state_updated()
            );
        }
        other => panic!("expected circuit-breaker task to fail under guard, got {other:?}"),
    }
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
            ]),
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
            ]),
        ]
        .concat(),
    );

    assert_eq!(
        circuit_breaker
            .fetch_status(&observed_pool)
            .await
            .expect("fetch circuit breaker status")
            .circuit_state(),
        ThrottlerCircuitState::Open
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
        )]),
    );

    observed.drop_tables().await;
}
