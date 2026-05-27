use super::*;

#[tokio::test]
async fn fleet_common_composed_operations_emit_exact_database_operation_records() {
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

    let counter = store
        .new_counter(CounterKey::new("operation-count-counter").expect("counter key"))
        .expect("counter");
    counter
        .set_value(&observed_pool, 42)
        .await
        .expect("set counter value");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_SET_BYTES)]),
    );

    assert_eq!(
        counter
            .fetch_value(&observed_pool)
            .await
            .expect("fetch counter value"),
        42
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES,
        )]),
    );

    assert_eq!(
        counter
            .add(&observed_pool, 8)
            .await
            .expect("add to counter value"),
        50
    );
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

    let mutex = store
        .new_mutex(
            MutexKey::new("operation-count-mutex").expect("mutex key"),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("claim duration"),
        )
        .expect("mutex");
    let holder_id = HolderId::new("operation-count-holder").expect("holder id");
    let claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder(&observed_pool, &holder_id)
        .await
        .expect("claim mutex")
        .expect("mutex should be claimable");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
    );

    let live_holder = mutex
        .fetch_live_holder(&observed_pool)
        .await
        .expect("fetch live mutex holder")
        .expect("mutex holder");
    assert_eq!(live_holder.holder_id(), &holder_id);
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            LEASE_OPERATION_FETCH_LIVE_HOLDER,
        )]),
    );

    let renewed_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_renew_claim(&observed_pool, &claim)
        .await
        .expect("renew mutex claim")
        .expect("claim should renew");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_RENEW)]),
    );

    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .release_claim(&observed_pool, &renewed_claim)
            .await
            .expect("release mutex claim")
    );
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
    );

    let guarded_mutex = store
        .new_mutex(
            MutexKey::new("operation-count-guarded-mutex").expect("guarded mutex key"),
            ClaimDuration::expires_after(Duration::from_secs(20)).expect("claim duration"),
        )
        .expect("guarded mutex");
    let guarded_holder_id =
        HolderId::new("operation-count-guarded-holder").expect("guarded holder id");
    let expected_guarded_holder_id = guarded_holder_id.clone();
    let guarded_result = guarded_mutex
        .try_run_task_for_holder(
            &observed_pool,
            &guarded_holder_id,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_secs(5)),
                ..MutexGuardConfig::default()
            },
            |snapshot| async move {
                assert_eq!(snapshot.holder_id(), &expected_guarded_holder_id);
                Ok::<_, std::io::Error>("guarded")
            },
        )
        .await
        .expect("try run guarded mutex task");
    assert_eq!(guarded_result, MutexTryRunTaskResult::Ran("guarded"));
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let waiting_mutex = store
        .new_mutex(
            MutexKey::new("operation-count-waiting-mutex").expect("waiting mutex key"),
            ClaimDuration::expires_after(Duration::from_secs(20)).expect("claim duration"),
        )
        .expect("waiting mutex");
    let waiting_holder_id =
        HolderId::new("operation-count-waiting-holder").expect("waiting holder id");
    let expected_waiting_holder_id = waiting_holder_id.clone();
    let waiting_result = waiting_mutex
        .run_task_for_holder_when_available(
            &observed_pool,
            &waiting_holder_id,
            MutexGuardConfig {
                heartbeat_interval: Some(Duration::from_secs(5)),
                ..MutexGuardConfig::default()
            },
            |snapshot| async move {
                assert_eq!(snapshot.holder_id(), &expected_waiting_holder_id);
                Ok::<_, std::io::Error>("waited-mutex")
            },
        )
        .await
        .expect("run mutex task after waiting for availability");
    assert_eq!(waiting_result, "waited-mutex");
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("operation-count-semaphore").expect("semaphore key"),
            2,
            Duration::from_secs(5),
        )
        .expect("semaphore");
    let semaphore_holder_id =
        HolderId::new("operation-count-semaphore-holder").expect("semaphore holder id");
    let _claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder(&observed_pool, &semaphore_holder_id)
        .await
        .expect("acquire semaphore")
        .expect("semaphore should have a slot");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
            ),
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_ACQUIRE_SLOT,
            ),
        ]),
    );

    assert_eq!(
        semaphore
            .fetch_status(&observed_pool)
            .await
            .expect("fetch semaphore status")
            .current_count(),
        1
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_COUNT_LIVE_KEYS_WITH_PREFIX,
        )]),
    );

    let expected_semaphore_key = semaphore.key().clone();
    let semaphore_task_result = semaphore
        .try_run_task(&observed_pool, |claim| async move {
            assert_eq!(claim.semaphore_key(), &expected_semaphore_key);
            Ok::<_, std::io::Error>(claim.slot_suffix().to_owned())
        })
        .await
        .expect("try run semaphore task");
    match semaphore_task_result {
        SemaphoreTryRunTaskResult::Ran(SemaphoreGuardedTaskResult::Succeeded {
            value,
            release_result,
        }) => {
            assert!(!value.is_empty());
            assert!(release_result.expect("release semaphore task claim"));
        }
        other => panic!("expected semaphore task to run, got {other:?}"),
    }
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
                ),
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_ACQUIRE_SLOT,
                ),
            ]),
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION,
                ),
            ]),
        ]
        .concat(),
    );

    let waiting_semaphore = store
        .new_semaphore(
            SemaphoreKey::new("operation-count-waiting-semaphore").expect("waiting semaphore key"),
            1,
            Duration::from_secs(5),
        )
        .expect("waiting semaphore");
    let expected_waiting_semaphore_key = waiting_semaphore.key().clone();
    let waiting_semaphore_result = waiting_semaphore
        .run_task_when_available(&observed_pool, |claim| async move {
            assert_eq!(claim.semaphore_key(), &expected_waiting_semaphore_key);
            Ok::<_, std::io::Error>("waited-semaphore")
        })
        .await
        .expect("run semaphore task after waiting for availability");
    match waiting_semaphore_result {
        SemaphoreGuardedTaskResult::Succeeded {
            value,
            release_result,
        } => {
            assert_eq!(value, "waited-semaphore");
            assert!(release_result.expect("release waiting semaphore task claim"));
        }
        other => panic!("expected waiting semaphore task to run, got {other:?}"),
    }
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
                ),
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_ACQUIRE_SLOT,
                ),
            ]),
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION,
                ),
            ]),
        ]
        .concat(),
    );

    let cache = store
        .new_coalescing_cache::<CachePayload>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("operation-count-cache").expect("cache key"),
            value_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("cache ttl"),
            lock_wait_timeout: Some(Duration::from_secs(5)),
            compute_timeout: Some(Duration::from_secs(5)),
        })
        .expect("cache");
    cache
        .set(
            &observed_pool,
            ["tenant", "resource"],
            CachePayload { value: 7 },
        )
        .await
        .expect("set cache value");
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_SET_BYTES)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let cached = cache
        .fetch_or_compute(&observed_pool, ["tenant", "resource"], || async {
            Ok::<_, std::io::Error>(CachePayload { value: 99 })
        })
        .await
        .expect("fetch cached value");
    assert_eq!(cached, CachePayload { value: 7 });
    expect_operation_shapes(
        &observer,
        &[
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
        ]
        .concat(),
    );

    let computed = cache
        .fetch_or_compute(&observed_pool, ["tenant", "computed"], || async {
            Ok::<_, std::io::Error>(CachePayload { value: 123 })
        })
        .await
        .expect("compute missing cache value");
    assert_eq!(computed, CachePayload { value: 123 });
    expect_operation_shapes(
        &observer,
        &[
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_SET_BYTES)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    cache
        .invalidate(&observed_pool, ["tenant", "computed"])
        .await
        .expect("invalidate cache value");
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_DELETE_KEY)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    cache
        .invalidate_all(&observed_pool)
        .await
        .expect("invalidate all cache values");
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

    let topic = store
        .new_topic::<CachePayload>(TopicConfig {
            key: TopicKey::new("operation-count-topic").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("topic event ttl"),
        })
        .expect("topic");
    assert_eq!(
        topic
            .publish(&observed_pool, CachePayload { value: 11 })
            .await
            .expect("publish topic event"),
        1
    );
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
            (DatabaseOperationKind::Execute, KV_OPERATION_SET_BYTES),
        ]),
    );

    assert_eq!(
        topic
            .fetch_latest_sequence(&observed_pool)
            .await
            .expect("fetch latest topic sequence"),
        1
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES,
        )]),
    );

    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("operation-count-subscription").expect("subscription key"),
            poll_limit: Some(10),
        })
        .expect("subscription");
    let events = subscription
        .read_new_events_and_advance_cursor(&observed_pool)
        .await
        .expect("poll subscription events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence(), 1);
    assert_eq!(events[0].data(), &CachePayload { value: 11 });
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (DatabaseOperationKind::FetchOptional, KV_OPERATION_GET_BYTES),
            (
                DatabaseOperationKind::FetchAll,
                KV_OPERATION_SCAN_BYTES_WITH_PREFIX,
            ),
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
        subscription
            .read_new_events_and_advance_cursor(&observed_pool)
            .await
            .expect("poll with no new events")
            .is_empty()
    );
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (DatabaseOperationKind::FetchOptional, KV_OPERATION_GET_BYTES),
            (
                DatabaseOperationKind::FetchAll,
                KV_OPERATION_SCAN_BYTES_WITH_PREFIX,
            ),
        ]),
    );

    subscription
        .delete_cursor(&observed_pool)
        .await
        .expect("delete subscription cursor");
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(DatabaseOperationKind::Execute, KV_OPERATION_DELETE_KEY)]),
    );

    assert_eq!(
        topic
            .purge_retained_events_atomically(&observed_pool)
            .await
            .expect("purge topic events"),
        1
    );
    expect_operation_shapes(
        &observer,
        &transaction_shapes([(
            DatabaseOperationKind::Execute,
            KV_OPERATION_DELETE_NAMESPACE_KEYS_WITH_PREFIX_ONCE,
        )]),
    );

    observed.drop_tables().await;
}
