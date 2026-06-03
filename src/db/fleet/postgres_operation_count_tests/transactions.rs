use super::*;

#[tokio::test]
async fn fleet_in_current_transaction_operations_emit_only_inner_database_operation_records() {
    let database_url = standard_test_database_url();

    let observed = prepare_observed_fleet_store(&database_url).await;
    let store = &observed.store;
    let observer = observed.observer.clone();
    let observed_pool = observed.observed_pool.clone();

    let mut tx = observed_pool
        .begin_transaction()
        .await
        .expect("begin caller transaction");
    expect_operation_shapes(
        &observer,
        &[(
            DatabaseOperationKind::BeginTransaction,
            "db.begin_transaction",
        )],
    );

    let counter = store
        .new_counter(CounterKey::new("operation-count-tx-counter").expect("counter key"))
        .expect("counter");
    counter
        .set_value_in_current_transaction(&mut tx, 10)
        .await
        .expect("set counter in caller transaction");
    expect_operation_shapes(
        &observer,
        &[(DatabaseOperationKind::Execute, KV_OPERATION_SET_BYTES)],
    );

    assert_eq!(
        counter
            .add_in_current_transaction(&mut tx, 5)
            .await
            .expect("add counter in caller transaction"),
        15
    );
    expect_operation_shapes(
        &observer,
        &[
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
        ],
    );

    assert_eq!(
        counter
            .fetch_value_in_current_transaction(&mut tx)
            .await
            .expect("fetch counter in caller transaction"),
        15
    );
    expect_operation_shapes(
        &observer,
        &[(DatabaseOperationKind::FetchOptional, KV_OPERATION_GET_BYTES)],
    );

    let mutex = store
        .new_mutex(
            MutexKey::new("operation-count-tx-mutex").expect("mutex key"),
            ClaimDuration::expires_after(Duration::from_secs(5)).expect("claim duration"),
        )
        .expect("mutex");
    let holder_id = HolderId::new("operation-count-tx-holder").expect("holder id");
    let mutex_claim = mutex
        .begin_manual_renewal_lifecycle()
        .try_claim_for_holder_in_current_transaction(&mut tx, &holder_id)
        .await
        .expect("claim mutex in caller transaction")
        .expect("mutex should be claimable");
    expect_operation_shapes(
        &observer,
        &[(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)],
    );

    assert!(
        mutex
            .begin_manual_renewal_lifecycle()
            .release_claim_in_current_transaction(&mut tx, &mutex_claim)
            .await
            .expect("release mutex in caller transaction")
    );
    expect_operation_shapes(
        &observer,
        &[(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)],
    );

    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("operation-count-tx-semaphore").expect("semaphore key"),
            1,
            Duration::from_secs(5),
        )
        .expect("semaphore");
    let semaphore_claim = semaphore
        .begin_manual_claim_lifecycle()
        .try_acquire_claim_for_holder_in_current_transaction(&mut tx, &holder_id)
        .await
        .expect("acquire semaphore in caller transaction")
        .expect("semaphore should have a slot");
    expect_operation_shapes(
        &observer,
        &[
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
            ),
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_ACQUIRE_SLOT,
            ),
        ],
    );

    assert!(
        semaphore
            .begin_manual_claim_lifecycle()
            .release_claim_in_current_transaction(&mut tx, &semaphore_claim)
            .await
            .expect("release semaphore in caller transaction")
    );
    expect_operation_shapes(
        &observer,
        &[
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION,
            ),
        ],
    );

    let topic = store
        .new_topic::<CachePayload>(TopicConfig {
            key: TopicKey::new("operation-count-tx-topic").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("topic event ttl"),
        })
        .expect("topic");
    assert_eq!(
        topic
            .publish_in_current_transaction(&mut tx, CachePayload { value: 22 })
            .await
            .expect("publish topic in caller transaction"),
        1
    );
    expect_operation_shapes(
        &observer,
        &[
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
            (DatabaseOperationKind::Execute, KV_OPERATION_SET_BYTES),
        ],
    );

    tx.commit().await.expect("commit caller transaction");
    expect_operation_shapes(
        &observer,
        &[(DatabaseOperationKind::CommitTransaction, "db.tx.commit")],
    );

    observed.drop_tables().await;
}
