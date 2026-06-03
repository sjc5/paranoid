use super::*;

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_reclaims_stale_jobs_and_cleans_old_terminal_rows() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let fleet_config = unique_fleet_test_config();
    let fleet_store = fleet::Store::new(fleet_config.clone()).expect("fleet store");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
    fleet::Store::new(fleet_config.clone())
        .expect("fleet store")
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let stale_running = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.maintenance.stale",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue stale running job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.maintenance.stale"],
        1,
        "worker-maintenance-stale",
    )
    .await
    .expect("claim stale running job");
    set_running_job_staleness(
        &test_database,
        stale_running.job_id,
        Duration::from_secs(120),
        None,
        Duration::from_secs(120),
        0,
        5,
    )
    .await;

    let mut completed_old_job_ids = Vec::new();
    for payload_value in 2..4 {
        let completed_old = queue
            .enqueue_json(
                &test_database.paranoid_pool,
                "task.maintenance.cleanup",
                &TestPayload {
                    value: payload_value,
                },
                EnqueueOptions::default(),
            )
            .await
            .expect("enqueue completed old job");
        completed_old_job_ids.push(completed_old.job_id);
    }
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.maintenance.cleanup"],
        completed_old_job_ids.len(),
        "worker-maintenance-cleanup",
    )
    .await
    .expect("claim cleanup job");
    let worker_maintenance_cleanup_owner_id =
        new_manual_worker_owner_id("worker-maintenance-cleanup");
    for completed_old_job_id in &completed_old_job_ids {
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed(
                &test_database.paranoid_pool,
                *completed_old_job_id,
                &worker_maintenance_cleanup_owner_id,
            )
            .await
            .expect("complete cleanup job");
        set_job_finished_age(
            &test_database,
            *completed_old_job_id,
            Duration::from_secs(7200),
        )
        .await;
    }

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            test_database.paranoid_pool.clone(),
            fleet_store,
            TaskRegistry::new(),
            "worker-maintenance-supervisor",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                stale_threshold: Duration::from_secs(1),
                execution_heartbeat_interval: Duration::from_millis(100),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
            WorkerMaintenanceConfig {
                cron_key_namespace: Some(
                    CronKey::new(format!("queue_maintenance_{suffix}"))
                        .expect("maintenance cron key namespace"),
                ),
                reclaim_interval: Duration::from_secs(1),
                cleanup_interval: Duration::from_secs(1),
                completed_job_retention: Duration::from_secs(1),
                failed_job_retention: Duration::from_secs(3600),
                dead_letter_job_retention: Duration::from_secs(3600),
                reclaim_batch_size: 10,
                cleanup_batch_size: 1,
                delay_between_cleanup_batches: Duration::ZERO,
            },
        )
        .expect("start worker with Fleet maintenance");

    wait_until(
        "Fleet maintenance reclaimed stale job and drained old completed rows",
        Duration::from_secs(4),
        || {
            let queue = queue.clone();
            let pool = test_database.paranoid_pool.clone();
            let completed_old_job_ids = completed_old_job_ids.clone();
            async move {
                let stale_reclaimed = matches!(
                    queue.fetch_job_by_id(&pool, stale_running.job_id).await,
                    Ok(job) if job.status == JobStatus::Pending && job.worker_owner_id.is_none()
                );
                let mut completed_deleted = true;
                for job_id in completed_old_job_ids {
                    if !matches!(
                        queue.fetch_job_by_id(&pool, job_id).await,
                        Err(Error::JobNotFound)
                    ) {
                        completed_deleted = false;
                        break;
                    }
                }
                stale_reclaimed && completed_deleted
            }
        },
    )
    .await;

    worker_handle.request_stop();
    let summary = tokio::time::timeout(Duration::from_secs(3), worker_handle.wait())
        .await
        .expect("maintenance worker should stop promptly")
        .expect("maintenance worker wait");
    assert_eq!(summary.claimed_count, 0);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
}

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_can_skip_dead_letter_cleanup_by_retention() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let fleet_config = unique_fleet_test_config();
    let fleet_store = fleet::Store::new(fleet_config.clone()).expect("fleet store");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
    fleet::Store::new(fleet_config.clone())
        .expect("fleet store")
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let completed_old = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.maintenance.skip_dead.cleanup",
            &TestPayload { value: 10 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue old completed job");
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.maintenance.skip_dead.cleanup"],
        1,
        "worker-maintenance-skip-dead-cleanup",
    )
    .await
    .expect("claim old completed job");
    let worker_maintenance_skip_dead_cleanup_owner_id =
        new_manual_worker_owner_id("worker-maintenance-skip-dead-cleanup");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed(
            &test_database.paranoid_pool,
            completed_old.job_id,
            &worker_maintenance_skip_dead_cleanup_owner_id,
        )
        .await
        .expect("complete old job");
    set_job_finished_age(&test_database, completed_old.job_id, Duration::from_secs(2)).await;

    let failed_old = fail_new_job(
        &queue,
        &test_database,
        "task.maintenance.skip_dead.cleanup",
        11,
        "worker-maintenance-skip-dead-failed",
    )
    .await;
    set_job_finished_age(&test_database, failed_old, Duration::from_secs(2)).await;

    let dead_letter_source = fail_new_job(
        &queue,
        &test_database,
        "task.maintenance.skip_dead.dead",
        12,
        "worker-maintenance-skip-dead-source",
    )
    .await;
    let dead_letter_id = queue
        .move_failed_job_to_dead_letter(
            &test_database.paranoid_pool,
            dead_letter_source,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move failed job to dead letter");
    set_dead_letter_age(&test_database, dead_letter_id, Duration::from_secs(2)).await;

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            test_database.paranoid_pool.clone(),
            fleet_store,
            TaskRegistry::new(),
            "worker-maintenance-skip-dead",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
            WorkerMaintenanceConfig {
                cron_key_namespace: Some(
                    CronKey::new(format!("queue_maintenance_skip_dead_{suffix}"))
                        .expect("maintenance cron key namespace"),
                ),
                reclaim_interval: Duration::from_secs(1),
                cleanup_interval: Duration::from_secs(1),
                completed_job_retention: Duration::from_millis(100),
                failed_job_retention: Duration::from_millis(100),
                dead_letter_job_retention: Duration::from_secs(3600),
                reclaim_batch_size: 10,
                cleanup_batch_size: 10,
                delay_between_cleanup_batches: Duration::ZERO,
            },
        )
        .expect("start worker with Fleet maintenance");

    wait_until(
        "Fleet maintenance cleaned completed/failed rows while retaining dead-letter rows",
        Duration::from_secs(4),
        || {
            let queue = queue.clone();
            let pool = test_database.paranoid_pool.clone();
            async move {
                let completed_deleted = matches!(
                    queue.fetch_job_by_id(&pool, completed_old.job_id).await,
                    Err(Error::JobNotFound)
                );
                let failed_deleted = matches!(
                    queue.fetch_job_by_id(&pool, failed_old).await,
                    Err(Error::JobNotFound)
                );
                let dead_letters = queue
                    .list_dead_letter_jobs(&pool, ListDeadLetterJobsOptions::default())
                    .await
                    .expect("list dead letters during maintenance skip check");
                completed_deleted
                    && failed_deleted
                    && dead_letters.jobs.iter().any(|job| job.id == dead_letter_id)
            }
        },
    )
    .await;

    worker_handle.request_stop();
    tokio::time::timeout(Duration::from_secs(3), worker_handle.wait())
        .await
        .expect("maintenance worker should stop promptly")
        .expect("maintenance worker wait");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
}

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_stop_interrupts_cleanup_between_batches() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let fleet_config = unique_fleet_test_config();
    let fleet_store = fleet::Store::new(fleet_config.clone()).expect("fleet store");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
    fleet::Store::new(fleet_config.clone())
        .expect("fleet store")
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut completed_old_job_ids = Vec::new();
    for value in 30..32 {
        let enqueued = queue
            .enqueue_json(
                &test_database.paranoid_pool,
                "task.maintenance.stop.cleanup",
                &TestPayload { value },
                EnqueueOptions::default(),
            )
            .await
            .expect("enqueue completed cleanup cancellation job");
        completed_old_job_ids.push(enqueued.job_id);
    }
    claim_exact_jobs(
        &queue,
        &test_database,
        &["task.maintenance.stop.cleanup"],
        completed_old_job_ids.len(),
        "worker-maintenance-stop-cleanup",
    )
    .await
    .expect("claim cleanup cancellation jobs");
    let worker_owner_id = new_manual_worker_owner_id("worker-maintenance-stop-cleanup");
    for job_id in &completed_old_job_ids {
        queue
            .begin_manual_worker_lifecycle()
            .mark_owned_running_job_completed(
                &test_database.paranoid_pool,
                *job_id,
                &worker_owner_id,
            )
            .await
            .expect("complete cleanup cancellation job");
        set_job_finished_age(&test_database, *job_id, Duration::from_secs(7200)).await;
    }

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            test_database.paranoid_pool.clone(),
            fleet_store,
            TaskRegistry::new(),
            "worker-maintenance-stop-cleanup",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
            WorkerMaintenanceConfig {
                cron_key_namespace: Some(
                    CronKey::new(format!("queue_maintenance_stop_cleanup_{suffix}"))
                        .expect("maintenance cron key namespace"),
                ),
                reclaim_interval: Duration::from_secs(1),
                cleanup_interval: Duration::from_secs(1),
                completed_job_retention: Duration::from_secs(1),
                failed_job_retention: Duration::from_secs(3600),
                dead_letter_job_retention: Duration::from_secs(3600),
                reclaim_batch_size: 10,
                cleanup_batch_size: 1,
                delay_between_cleanup_batches: Duration::from_secs(60),
            },
        )
        .expect("start worker with cancellable Fleet maintenance");

    wait_until(
        "Fleet cleanup deleted exactly one old completed job before batch delay",
        Duration::from_secs(4),
        || {
            let queue = queue.clone();
            let pool = test_database.paranoid_pool.clone();
            let completed_old_job_ids = completed_old_job_ids.clone();
            async move {
                let mut deleted_count = 0;
                for job_id in completed_old_job_ids {
                    if matches!(
                        queue.fetch_job_by_id(&pool, job_id).await,
                        Err(Error::JobNotFound)
                    ) {
                        deleted_count += 1;
                    }
                }
                deleted_count == 1
            }
        },
    )
    .await;

    worker_handle.request_stop();
    tokio::time::timeout(Duration::from_secs(2), worker_handle.wait())
        .await
        .expect("maintenance worker should stop during cleanup batch delay")
        .expect("maintenance worker wait");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
}

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_derives_default_cron_namespace_from_queue_tables() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let fleet_config = unique_fleet_test_config();
    let fleet_store = fleet::Store::new(fleet_config.clone()).expect("fleet store");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
    fleet::Store::new(fleet_config.clone())
        .expect("fleet store")
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            test_database.paranoid_pool.clone(),
            fleet_store,
            TaskRegistry::new(),
            "worker-maintenance-default-namespace",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
            WorkerMaintenanceConfig {
                reclaim_interval: Duration::from_secs(1),
                cleanup_interval: Duration::from_secs(1),
                ..WorkerMaintenanceConfig::default()
            },
        )
        .expect("start worker with default maintenance cron namespace");

    worker_handle.request_stop();
    tokio::time::timeout(Duration::from_secs(3), worker_handle.wait())
        .await
        .expect("default maintenance worker should stop promptly")
        .expect("default maintenance worker wait");

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
}

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_rejects_subsecond_cron_intervals_before_start() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let reclaim_interval_error = queue.start_worker_with_fleet_maintenance(
        test_database.paranoid_pool.clone(),
        fleet::Store::new(unique_fleet_test_config()).expect("fleet store"),
        TaskRegistry::new(),
        "worker-maintenance-invalid-reclaim-interval",
        WorkerConfig::default(),
        WorkerMaintenanceConfig {
            reclaim_interval: Duration::from_millis(999),
            cleanup_interval: Duration::from_secs(1),
            ..WorkerMaintenanceConfig::default()
        },
    );
    let Err(reclaim_interval_error) = reclaim_interval_error else {
        panic!("subsecond reclaim interval should be rejected before spawning");
    };
    assert!(matches!(reclaim_interval_error, Error::Fleet(_)));

    let cleanup_interval_error = queue.start_worker_with_fleet_maintenance(
        test_database.paranoid_pool.clone(),
        fleet::Store::new(unique_fleet_test_config()).expect("fleet store"),
        TaskRegistry::new(),
        "worker-maintenance-invalid-cleanup-interval",
        WorkerConfig::default(),
        WorkerMaintenanceConfig {
            reclaim_interval: Duration::from_secs(1),
            cleanup_interval: Duration::from_millis(999),
            ..WorkerMaintenanceConfig::default()
        },
    );
    let Err(cleanup_interval_error) = cleanup_interval_error else {
        panic!("subsecond cleanup interval should be rejected before spawning");
    };
    assert!(matches!(cleanup_interval_error, Error::Fleet(_)));
}

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_reports_cron_failure_and_stops_worker() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let fleet_config = unique_fleet_test_config();
    let fleet_store = fleet::Store::new(fleet_config.clone()).expect("fleet store");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            test_database.paranoid_pool.clone(),
            fleet_store,
            TaskRegistry::new(),
            "worker-maintenance-failure",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
            WorkerMaintenanceConfig {
                cron_key_namespace: Some(
                    CronKey::new(format!("queue_maintenance_failure_{suffix}"))
                        .expect("maintenance cron key namespace"),
                ),
                reclaim_interval: Duration::from_secs(1),
                cleanup_interval: Duration::from_secs(1),
                completed_job_retention: Duration::from_secs(1),
                failed_job_retention: Duration::from_secs(1),
                dead_letter_job_retention: Duration::from_secs(1),
                ..WorkerMaintenanceConfig::default()
            },
        )
        .expect("start worker with missing Fleet maintenance schema");

    let error = tokio::time::timeout(Duration::from_secs(3), worker_handle.wait())
        .await
        .expect("maintenance failure should stop worker promptly")
        .expect_err("missing Fleet schema should fail maintenance");
    assert_missing_fleet_schema_maintenance_error(&error);

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
}

fn assert_missing_fleet_schema_maintenance_error(error: &Error) {
    match error {
        Error::MaintenanceCronRunFailed {
            cron_name: "reclaim" | "cleanup",
            ..
        } => {}
        Error::WorkerRuntimeMultipleFailures { failures } => {
            assert!(!failures.is_empty());
            assert!(
                failures
                    .iter()
                    .all(is_missing_fleet_schema_maintenance_failure),
                "unexpected maintenance failure list: {failures:?}"
            );
        }
        _ => panic!("unexpected maintenance failure error: {error:?}"),
    }
}

fn is_missing_fleet_schema_maintenance_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::MaintenanceCronRunFailed {
            cron_name: "reclaim" | "cleanup",
            ..
        }
    )
}

#[tokio::test]
async fn queue_worker_with_fleet_maintenance_failure_returns_in_flight_job_to_pending() {
    let test_database = TestDatabase::connect().await;

    let queue = Store::new(test_database.config.clone()).expect("queue");
    let fleet_config = unique_fleet_test_config();
    let fleet_store = fleet::Store::new(fleet_config.clone()).expect("fleet store");
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
    fleet::Store::new(fleet_config.clone())
        .expect("fleet store")
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.maintenance.failure_running_job",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue job that should be cleaned up after maintenance failure");

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.maintenance.failure_running_job",
            move |_context, payload: TestPayload| {
                let started_tx = started_tx.clone();
                async move {
                    assert_eq!(payload.value, 1);
                    started_tx
                        .send(())
                        .expect("record maintenance-failure handler start");
                    std::future::pending::<Result<(), TaskError>>().await
                }
            },
        )
        .expect("register maintenance-failure running handler");

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let worker_handle = queue
        .start_worker_with_fleet_maintenance(
            test_database.paranoid_pool.clone(),
            fleet_store,
            registry,
            "worker-maintenance-failure-running-job",
            WorkerConfig {
                poll_interval: Duration::from_secs(60),
                concurrency: 1,
                shutdown_grace_period: Duration::from_millis(25),
                default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
                ..fixed_retry_worker_config(Duration::from_millis(1), true)
            },
            WorkerMaintenanceConfig {
                cron_key_namespace: Some(
                    CronKey::new(format!("queue_maintenance_failure_running_{suffix}"))
                        .expect("maintenance cron key namespace"),
                ),
                reclaim_interval: Duration::from_secs(1),
                cleanup_interval: Duration::from_secs(1),
                completed_job_retention: Duration::from_secs(1),
                failed_job_retention: Duration::from_secs(1),
                dead_letter_job_retention: Duration::from_secs(1),
                ..WorkerMaintenanceConfig::default()
            },
        )
        .expect("start worker with Fleet maintenance");

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("running job should start before maintenance failure")
        .expect("started channel should stay open");
    drop_test_table(
        &test_database.sqlx_pool,
        &test_database.config.dead_letter_table_name,
    )
    .await;

    let error = tokio::time::timeout(Duration::from_secs(5), worker_handle.wait())
        .await
        .expect("maintenance failure should stop worker promptly")
        .expect_err("dropped dead-letter table should fail cleanup maintenance");
    assert!(
        matches!(
            error,
            Error::MaintenanceCronRunFailed {
                cron_name: "cleanup",
                ..
            }
        ),
        "unexpected maintenance failure error: {error:?}"
    );

    let job_after_error = queue
        .fetch_job_by_id(&test_database.paranoid_pool, enqueued.job_id)
        .await
        .expect("worker-level cleanup should return running job to pending");
    assert_eq!(job_after_error.status, JobStatus::Pending);
    assert_eq!(job_after_error.retry_count, 0);
    assert!(job_after_error.last_error.is_none());
    assert!(job_after_error.worker_owner_id.is_none());
    assert!(
        job_after_error
            .claimed_by_worker_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_error
            .execution_started_at_unix_microseconds
            .is_none()
    );
    assert!(
        job_after_error
            .execution_heartbeat_at_unix_microseconds
            .is_none()
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    drop_fleet_test_tables(&test_database.sqlx_pool, &fleet_config).await;
}
