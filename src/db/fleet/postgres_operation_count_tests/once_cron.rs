use super::*;

#[tokio::test]
async fn fleet_once_and_cron_emit_exact_database_operation_records() {
    let database_url = standard_test_database_url();

    let observed = prepare_observed_fleet_store(&database_url).await;
    let store = &observed.store;
    let observer = observed.observer.clone();
    let observed_pool = observed.observed_pool.clone();

    let once = store
        .new_once(
            OnceKey::new("operation-count-once").expect("once key"),
            ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
        )
        .expect("once");
    assert!(
        once.check_done(&observed_pool)
            .await
            .expect("check once completion")
            .is_none()
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES,
        )]),
    );

    let once_holder_id = HolderId::new("operation-count-once-holder").expect("holder id");
    let manual_once = once.begin_manual_run_lifecycle();
    let once_claim = manual_once
        .try_start_run_for_holder(&observed_pool, &once_holder_id)
        .await
        .expect("start once run")
        .expect("once claim");
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
        ]
        .concat(),
    );

    assert!(
        manual_once
            .mark_done_and_release_run(&observed_pool, &once_claim)
            .await
            .expect("mark once done and release")
    );
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (DatabaseOperationKind::FetchOptional, LEASE_OPERATION_RENEW),
            (
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
            ),
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
            ),
            (DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE),
        ]),
    );

    assert!(
        once.check_done(&observed_pool)
            .await
            .expect("check once completion")
            .is_some()
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            KV_OPERATION_GET_BYTES,
        )]),
    );

    assert!(once.try_reset(&observed_pool).await.expect("reset once"));
    expect_operation_shapes(
        &observer,
        &transaction_shapes([
            (DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM),
            (DatabaseOperationKind::Execute, KV_OPERATION_DELETE_KEY),
            (DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE),
        ]),
    );

    let expected_once_key = once.key().clone();
    let high_level_once_result = once
        .try_run_task(&observed_pool, |snapshot| async move {
            assert_eq!(snapshot.once_key(), &expected_once_key);
            Ok::<_, std::io::Error>("once-task")
        })
        .await
        .expect("run high-level once task");
    assert_eq!(
        high_level_once_result,
        OnceTryRunTaskResult::Ran("once-task")
    );
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
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let waiting_once = store
        .new_once(
            OnceKey::new("operation-count-waiting-once").expect("waiting once key"),
            ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
        )
        .expect("waiting once");
    let expected_waiting_once_key = waiting_once.key().clone();
    let waiting_once_result = waiting_once
        .run_task_when_available(&observed_pool, |snapshot| async move {
            assert_eq!(snapshot.once_key(), &expected_waiting_once_key);
            Ok::<_, std::io::Error>("waiting-once-task")
        })
        .await
        .expect("run once task after waiting for availability");
    assert_eq!(
        waiting_once_result,
        OnceRunTaskResult::Ran("waiting-once-task")
    );
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
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let atomic_once = store
        .new_once(
            OnceKey::new("operation-count-atomic-once").expect("atomic once key"),
            ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
        )
        .expect("atomic once");
    let expected_atomic_once_key = atomic_once.key().clone();
    let atomic_once_result = atomic_once
        .try_run_task_atomically(&observed_pool, |snapshot, _tx| {
            Box::pin(async move {
                assert_eq!(snapshot.once_key(), &expected_atomic_once_key);
                Ok::<_, std::io::Error>("atomic-once-task")
            })
        })
        .await
        .expect("run atomic once task");
    assert_eq!(
        atomic_once_result,
        OnceTryRunTaskResult::Ran("atomic-once-task")
    );
    expect_operation_shapes(
        &observer,
        &[
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            vec![
                (
                    DatabaseOperationKind::BeginTransaction,
                    "db.begin_transaction",
                ),
                (DatabaseOperationKind::FetchOptional, KV_OPERATION_GET_BYTES),
                (DatabaseOperationKind::FetchOptional, LEASE_OPERATION_RENEW),
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
                (DatabaseOperationKind::CommitTransaction, "db.tx.commit"),
            ],
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let waiting_atomic_once = store
        .new_once(
            OnceKey::new("operation-count-waiting-atomic-once").expect("waiting atomic once key"),
            ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
        )
        .expect("waiting atomic once");
    let expected_waiting_atomic_once_key = waiting_atomic_once.key().clone();
    let waiting_atomic_once_result = waiting_atomic_once
        .run_task_atomically_when_available(&observed_pool, |snapshot, _tx| {
            Box::pin(async move {
                assert_eq!(snapshot.once_key(), &expected_waiting_atomic_once_key);
                Ok::<_, std::io::Error>("waiting-atomic-once-task")
            })
        })
        .await
        .expect("run atomic once task after waiting for availability");
    assert_eq!(
        waiting_atomic_once_result,
        OnceRunTaskResult::Ran("waiting-atomic-once-task")
    );
    expect_operation_shapes(
        &observer,
        &[
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            vec![
                (
                    DatabaseOperationKind::BeginTransaction,
                    "db.begin_transaction",
                ),
                (DatabaseOperationKind::FetchOptional, KV_OPERATION_GET_BYTES),
                (DatabaseOperationKind::FetchOptional, LEASE_OPERATION_RENEW),
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
                (DatabaseOperationKind::CommitTransaction, "db.tx.commit"),
            ],
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let cron = store
        .new_cron(CronConfig {
            key: CronKey::new("operation-count-cron").expect("cron key"),
            interval: Duration::from_secs(60),
            claim_duration: Some(
                ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
            ),
            heartbeat_interval: Some(Duration::from_secs(10)),
            acquire_retry_interval: Some(Duration::from_secs(1)),
            max_consecutive_renewal_failures: None,
        })
        .expect("cron");
    assert!(
        cron.fetch_live_leader(&observed_pool)
            .await
            .expect("fetch cron leader")
            .is_none()
    );
    expect_operation_shapes(
        &observer,
        &rollback_transaction_shapes([(
            DatabaseOperationKind::FetchOptional,
            LEASE_OPERATION_FETCH_LIVE_HOLDER,
        )]),
    );

    match cron
        .try_run_once(&observed_pool, |_snapshot| async move {
            Ok::<_, std::io::Error>("ran")
        })
        .await
        .expect("run cron once")
    {
        CronTryRunOnceResult::Ran(value) => assert_eq!(value, "ran"),
        CronTryRunOnceResult::LeadershipHeld => panic!("expected cron leadership"),
    }
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    let waiting_cron = store
        .new_cron(CronConfig {
            key: CronKey::new("operation-count-waiting-cron").expect("waiting cron key"),
            interval: Duration::from_secs(60),
            claim_duration: Some(
                ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
            ),
            heartbeat_interval: Some(Duration::from_secs(10)),
            acquire_retry_interval: Some(Duration::from_secs(1)),
            max_consecutive_renewal_failures: None,
        })
        .expect("waiting cron");
    let waiting_cron_result = waiting_cron
        .run_once(&observed_pool, |_snapshot| async move {
            Ok::<_, std::io::Error>("waited-cron")
        })
        .await
        .expect("run cron once after waiting for leadership");
    assert_eq!(waiting_cron_result, "waited-cron");
    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    observed.drop_tables().await;
}

#[tokio::test]
async fn fleet_cron_run_loop_emits_expected_database_operation_records() {
    let database_url = standard_test_database_url();

    let observed = prepare_observed_fleet_store(&database_url).await;
    let store = observed.store.clone();
    let observer = observed.observer.clone();
    let observed_pool = observed.observed_pool.clone();

    let cron = store
        .new_cron(CronConfig {
            key: CronKey::new("operation-count-cron-loop").expect("cron key"),
            interval: Duration::from_secs(60),
            claim_duration: Some(
                ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim duration"),
            ),
            heartbeat_interval: Some(Duration::from_secs(10)),
            acquire_retry_interval: Some(Duration::from_secs(1)),
            max_consecutive_renewal_failures: None,
        })
        .expect("cron");

    let task_ran = Arc::new(Notify::new());
    let stop = Arc::new(Notify::new());
    let cron_for_run = cron.clone();
    let pool_for_run = observed_pool.clone();
    let task_ran_for_run = Arc::clone(&task_ran);
    let stop_for_run = Arc::clone(&stop);
    let run_task = tokio::spawn(async move {
        cron_for_run
            .run_until_stopped_or_task_error(
                &pool_for_run,
                async move {
                    stop_for_run.notified().await;
                },
                move |_snapshot| {
                    let task_ran_for_run = Arc::clone(&task_ran_for_run);
                    async move {
                        task_ran_for_run.notify_one();
                        Ok::<_, std::io::Error>(())
                    }
                },
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), task_ran.notified())
        .await
        .expect("cron task should run once");
    stop.notify_one();
    run_task
        .await
        .expect("cron run task should join")
        .expect("cron run loop should stop cleanly");

    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    observed.drop_tables().await;
}
