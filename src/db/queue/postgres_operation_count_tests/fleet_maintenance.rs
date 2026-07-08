use super::*;

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_emits_expected_database_operation_shape_multiset() {
    let database_url = standard_test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let queue_config = unique_test_config();
    let fleet_config = unique_fleet_test_config();
    let queue = Store::new(queue_config.clone()).expect("queue");
    let fleet_store = FleetStore::new(fleet_config.clone()).expect("fleet store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_queue_test_tables(&sqlx_pool, &queue_config).await;
    drop_fleet_test_tables(&sqlx_pool, &fleet_config).await;
    queue
        .migrate_schema(&pool)
        .await
        .expect("migrate Queue schema");
    fleet_store
        .migrate_schema(&pool)
        .await
        .expect("migrate Fleet schema");

    let reclaimed_job_id = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.maintenance_reclaim",
        62,
        "worker.operation_count.stale_unstarted",
    )
    .await;
    let completed_job_id = claim_test_job(
        &queue,
        &pool,
        "task.operation_count.maintenance_completed",
        63,
        "worker.operation_count.completed",
    )
    .await;
    let completed_worker_owner_id =
        worker_owner_id_for_operation_count_test("worker.operation_count.completed");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started(&pool, completed_job_id, &completed_worker_owner_id)
        .await
        .expect("mark setup completed job started");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(&pool, completed_job_id, &completed_worker_owner_id)
        .await
        .expect("mark setup completed job completed");
    let failed_job_id = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.maintenance_failed",
        64,
        "worker.operation_count.failed",
    )
    .await;
    let failed_for_dead_letter = fail_test_job(
        &queue,
        &pool,
        "task.operation_count.maintenance_dead_letter",
        65,
        "worker.operation_count.dead_letter",
    )
    .await;
    let dead_letter_job_id = queue
        .move_failed_job_to_dead_letter(
            &pool,
            failed_for_dead_letter,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move setup job to dead letter");
    tokio::time::sleep(Duration::from_millis(10)).await;
    observer.clear();

    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            observed_pool.clone(),
            fleet_store.clone(),
            TaskRegistry::new(),
            "worker.operation_count.maintenance_loop",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                startup_jitter_max_delay: Some(Duration::ZERO),
                concurrency: 1,
                stale_threshold: Duration::from_millis(2),
                execution_heartbeat_interval: Duration::from_millis(1),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                dead_letter_enabled: false,
                shutdown_grace_period: Duration::from_secs(5),
                database_operation_timeout: Duration::from_secs(5),
                ..WorkerConfig::default()
            },
            WorkerMaintenanceConfig {
                reclaim_interval: Duration::from_secs(60),
                cleanup_interval: Duration::from_secs(60),
                completed_job_retention: Duration::from_micros(1),
                failed_job_retention: Duration::from_micros(1),
                dead_letter_job_retention: Duration::from_micros(1),
                reclaim_batch_size: 10,
                cleanup_batch_size: 10,
                delay_between_cleanup_batches: Duration::ZERO,
                ..WorkerMaintenanceConfig::default()
            },
        )
        .expect("start worker with Fleet maintenance");

    tokio::time::timeout(
        Duration::from_secs(5),
        wait_until_worker_maintenance_effects_are_visible(
            &sqlx_pool,
            &queue,
            &pool,
            reclaimed_job_id,
            completed_job_id,
            failed_job_id,
            dead_letter_job_id,
        ),
    )
    .await
    .expect("Fleet-backed queue maintenance should run once");
    assert!(worker_handle.request_stop());
    let summary = worker_handle
        .wait()
        .await
        .expect("worker with Fleet maintenance should stop cleanly");
    assert_eq!(summary, WorkerRunLoopSummary::default());

    expect_operation_shape_multiset(
        &observer,
        &[
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::FetchOptional,
                LEASE_OPERATION_CLAIM,
            )]),
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::FetchOptional,
                LEASE_OPERATION_CLAIM,
            )]),
            transaction_operation_shapes(vec![
                (
                    DatabaseOperationKind::FetchAll,
                    QUEUE_OPERATION_RECLAIM_NEVER_STARTED_RUNNING_JOBS,
                ),
                (
                    DatabaseOperationKind::FetchAll,
                    QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_FAILED,
                ),
                (
                    DatabaseOperationKind::FetchAll,
                    QUEUE_OPERATION_RECLAIM_EXPIRED_RUNNING_JOBS_TO_PENDING,
                ),
            ]),
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
            )]),
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_CLEANUP_JOBS_ONCE,
            )]),
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_CLEANUP_DEAD_LETTER_ONCE,
            )]),
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                LEASE_OPERATION_RELEASE,
            )]),
            transaction_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                LEASE_OPERATION_RELEASE,
            )]),
            worker_database_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_UNSTARTED_JOBS,
            )]),
            worker_database_operation_shapes(vec![(
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_RETURN_AVAILABLE_OWNED_STARTED_JOBS,
            )]),
            worker_database_operation_shapes(vec![(
                DatabaseOperationKind::FetchOne,
                QUEUE_OPERATION_COUNT_WORKER_OWNED_RUNNING_JOBS,
            )]),
        ]
        .concat(),
    );

    drop_queue_test_tables(&sqlx_pool, &queue_config).await;
    drop_fleet_test_tables(&sqlx_pool, &fleet_config).await;
}
