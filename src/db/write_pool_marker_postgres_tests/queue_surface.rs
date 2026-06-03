use super::*;

pub(super) async fn exercise_queue_public_db_handle_surface(
    pool: &WritePool,
    store: &QueueStore,
    fleet_store: &FleetStore,
    job_id: JobId,
) {
    let read_pool: &crate::db::Pool = pool;
    let mut registry = TaskRegistry::new();
    let registered_task = store
        .register_json_task_handler::<TestPayload, _, _>(
            &mut registry,
            TEST_TASK_NAME,
            |_context, _payload| async { Ok(()) },
        )
        .expect("registered JSON task");
    let worker_owner_id =
        WorkerOwnerId::new_unique_for_worker_name(TEST_WORKER_NAME).expect("worker owner ID");

    store
        .fetch_job_by_id(read_pool, job_id)
        .await
        .expect("queue fetch_job_by_id should only require SELECT");
    store
        .fetch_job_status(read_pool, job_id)
        .await
        .expect("queue fetch_job_status should only require SELECT");
    store
        .fetch_status_counts(read_pool, None)
        .await
        .expect("queue status counts should only require SELECT");
    store
        .fetch_pending_job_count(read_pool, None)
        .await
        .expect("queue pending count should only require SELECT");
    store
        .fetch_failed_job_count(read_pool, None)
        .await
        .expect("queue failed count should only require SELECT");
    store
        .fetch_queue_is_paused(read_pool)
        .await
        .expect("queue pause status should only require SELECT");
    store
        .fetch_task_is_paused(read_pool, TEST_TASK_NAME)
        .await
        .expect("queue task pause status should only require SELECT");
    store
        .fetch_paused_task_names(read_pool)
        .await
        .expect("queue paused task names should only require SELECT");
    store
        .fetch_orphaned_task_names(read_pool, &registry)
        .await
        .expect("queue orphaned task names should only require SELECT");
    store
        .fetch_worker_pressure(read_pool, &registry)
        .await
        .expect("queue worker pressure should only require SELECT");
    store
        .list_jobs(read_pool, ListJobsOptions::default())
        .await
        .expect("queue list_jobs should only require SELECT");
    store
        .list_dead_letter_jobs(read_pool, ListDeadLetterJobsOptions::default())
        .await
        .expect("queue list_dead_letter_jobs should only require SELECT");

    let mut read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin queue read tx");
    store
        .fetch_job_by_id_in_current_transaction(&mut read_tx, job_id)
        .await
        .expect("queue tx fetch_job_by_id should only require SELECT");
    store
        .fetch_job_status_in_current_transaction(&mut read_tx, job_id)
        .await
        .expect("queue tx fetch_job_status should only require SELECT");
    store
        .fetch_status_counts_in_current_transaction(&mut read_tx, None)
        .await
        .expect("queue tx status counts should only require SELECT");
    store
        .fetch_pending_job_count_in_current_transaction(&mut read_tx, None)
        .await
        .expect("queue tx pending count should only require SELECT");
    store
        .fetch_failed_job_count_in_current_transaction(&mut read_tx, None)
        .await
        .expect("queue tx failed count should only require SELECT");
    store
        .fetch_queue_is_paused_in_current_transaction(&mut read_tx)
        .await
        .expect("queue tx pause status should only require SELECT");
    store
        .fetch_task_is_paused_in_current_transaction(&mut read_tx, TEST_TASK_NAME)
        .await
        .expect("queue tx task pause status should only require SELECT");
    store
        .fetch_paused_task_names_in_current_transaction(&mut read_tx)
        .await
        .expect("queue tx paused task names should only require SELECT");
    store
        .fetch_orphaned_task_names_in_current_transaction(&mut read_tx, &registry)
        .await
        .expect("queue tx orphaned task names should only require SELECT");
    store
        .fetch_worker_pressure_in_current_transaction(&mut read_tx, &registry)
        .await
        .expect("queue tx worker pressure should only require SELECT");
    store
        .list_jobs_in_current_transaction(&mut read_tx, ListJobsOptions::default())
        .await
        .expect("queue tx list_jobs should only require SELECT");
    store
        .list_dead_letter_jobs_in_current_transaction(
            &mut read_tx,
            ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("queue tx list_dead_letter_jobs should only require SELECT");
    read_tx.rollback().await.expect("rollback queue read tx");

    assert_fails_with_insufficient_privilege!(
        "queue migrate_schema",
        store.migrate_schema(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue migrate_schema_in_current_transaction",
        tx,
        store.migrate_schema_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue validate_schema",
        store.validate_schema(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue validate_schema_in_current_transaction",
        tx,
        store.validate_schema_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue enqueue_json",
        store.enqueue_json(
            pool,
            TEST_TASK_NAME,
            &TestPayload { value: 1 },
            EnqueueOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue enqueue_json_in_current_transaction",
        tx,
        store.enqueue_json_in_current_transaction(
            tx,
            TEST_TASK_NAME,
            &TestPayload { value: 1 },
            EnqueueOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue enqueue_json_batch",
        store.enqueue_json_batch(
            pool,
            TEST_TASK_NAME,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue enqueue_json_batch_in_current_transaction",
        tx,
        store.enqueue_json_batch_in_current_transaction(
            tx,
            TEST_TASK_NAME,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue registered task enqueue",
        registered_task.enqueue(pool, &TestPayload { value: 1 }, EnqueueOptions::default()),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue registered task enqueue_in_current_transaction",
        tx,
        registered_task.enqueue_in_current_transaction(
            tx,
            &TestPayload { value: 1 },
            EnqueueOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue registered task enqueue_batch",
        registered_task.enqueue_batch(
            pool,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue registered task enqueue_batch_in_current_transaction",
        tx,
        registered_task.enqueue_batch_in_current_transaction(
            tx,
            &[TestPayload { value: 1 }],
            EnqueueBatchOptions::default()
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue pause_queue",
        store.pause_queue(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue pause_queue_in_current_transaction",
        tx,
        store.pause_queue_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue resume_queue",
        store.resume_queue(pool),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue resume_queue_in_current_transaction",
        tx,
        store.resume_queue_in_current_transaction(tx),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue pause_task",
        store.pause_task(pool, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue pause_task_in_current_transaction",
        tx,
        store.pause_task_in_current_transaction(tx, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue resume_task",
        store.resume_task(pool, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue resume_task_in_current_transaction",
        tx,
        store.resume_task_in_current_transaction(tx, TEST_TASK_NAME),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cancel_pending_job",
        store.cancel_pending_job(pool, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cancel_pending_job_in_current_transaction",
        tx,
        store.cancel_pending_job_in_current_transaction(tx, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue retry_failed_job",
        store.retry_failed_job(pool, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue retry_failed_job_in_current_transaction",
        tx,
        store.retry_failed_job_in_current_transaction(tx, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue retry_available_failed_jobs",
        store.retry_available_failed_jobs(pool, None, 1, None),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue retry_available_failed_jobs_in_current_transaction",
        tx,
        store.retry_available_failed_jobs_in_current_transaction(tx, None, 1, None),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue force_requeue_running_job_by_id",
        store.force_requeue_running_job_by_id(pool, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue force_requeue_running_job_by_id_in_current_transaction",
        tx,
        store.force_requeue_running_job_by_id_in_current_transaction(tx, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue move_failed_job_to_dead_letter",
        store.move_failed_job_to_dead_letter(pool, job_id, DeadLetterReason::OperatorAction),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue move_failed_job_to_dead_letter_in_current_transaction",
        tx,
        store.move_failed_job_to_dead_letter_in_current_transaction(
            tx,
            job_id,
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue move_failed_jobs_to_dead_letter_batch",
        store.move_failed_jobs_to_dead_letter_batch(
            pool,
            &[job_id],
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue move_failed_jobs_to_dead_letter_batch_in_current_transaction",
        tx,
        store.move_failed_jobs_to_dead_letter_batch_in_current_transaction(
            tx,
            &[job_id],
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue requeue_dead_letter_job",
        store.requeue_dead_letter_job(pool, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue requeue_dead_letter_job_in_current_transaction",
        tx,
        store.requeue_dead_letter_job_in_current_transaction(tx, job_id, None),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue delete_dead_letter_job",
        store.delete_dead_letter_job(pool, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue delete_dead_letter_job_in_current_transaction",
        tx,
        store.delete_dead_letter_job_in_current_transaction(tx, job_id),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_completed_jobs_older_than_once",
        store.cleanup_available_completed_jobs_older_than_once(pool, Duration::from_secs(1), 1),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_completed_jobs_older_than_until_empty",
        store.cleanup_available_completed_jobs_older_than_until_empty(
            pool,
            Duration::from_secs(1),
            1,
            Duration::ZERO
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cleanup_available_completed_jobs_older_than_once_in_current_transaction",
        tx,
        store.cleanup_available_completed_jobs_older_than_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_failed_jobs_older_than_once",
        store.cleanup_available_failed_jobs_older_than_once(pool, Duration::from_secs(1), 1),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_failed_jobs_older_than_until_empty",
        store.cleanup_available_failed_jobs_older_than_until_empty(
            pool,
            Duration::from_secs(1),
            1,
            Duration::ZERO
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cleanup_available_failed_jobs_older_than_once_in_current_transaction",
        tx,
        store.cleanup_available_failed_jobs_older_than_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_dead_letter_jobs_older_than_once",
        store.cleanup_available_dead_letter_jobs_older_than_once(pool, Duration::from_secs(1), 1),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue cleanup_available_dead_letter_jobs_older_than_until_empty",
        store.cleanup_available_dead_letter_jobs_older_than_until_empty(
            pool,
            Duration::from_secs(1),
            1,
            Duration::ZERO
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction",
        tx,
        store.cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue reclaim_available_stale_running_jobs_once",
        store.reclaim_available_stale_running_jobs_once(pool, Duration::from_secs(1), 1, true),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue reclaim_available_stale_running_jobs_once_in_current_transaction",
        tx,
        store.reclaim_available_stale_running_jobs_once_in_current_transaction(
            tx,
            Duration::from_secs(1),
            1,
            true
        ),
        queue_error_is_insufficient_privilege
    );

    let manual_worker = store.begin_manual_worker_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "queue manual worker claim_available_jobs_for_worker_owner",
        manual_worker.claim_available_jobs_for_worker_owner(
            pool,
            &[TEST_TASK_NAME.to_owned()],
            1,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker claim_available_jobs_for_worker_owner_in_current_transaction",
        tx,
        manual_worker.claim_available_jobs_for_worker_owner_in_current_transaction(
            tx,
            &[TEST_TASK_NAME.to_owned()],
            1,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker mark_owned_running_job_started",
        manual_worker.mark_owned_running_job_started(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker mark_owned_running_job_started_in_current_transaction",
        tx,
        manual_worker.mark_owned_running_job_started_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker mark_owned_running_job_completed",
        manual_worker.mark_owned_running_job_completed(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker mark_owned_running_job_completed_in_current_transaction",
        tx,
        manual_worker.mark_owned_running_job_completed_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker touch_owned_running_job_execution_heartbeat",
        manual_worker.touch_owned_running_job_execution_heartbeat(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker touch_owned_running_job_execution_heartbeat_in_current_transaction",
        tx,
        manual_worker.touch_owned_running_job_execution_heartbeat_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker schedule_owned_running_job_retry",
        manual_worker.schedule_owned_running_job_retry(
            pool,
            job_id,
            &worker_owner_id,
            1,
            Duration::from_secs(1),
            "retry"
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker schedule_owned_running_job_retry_in_current_transaction",
        tx,
        manual_worker.schedule_owned_running_job_retry_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id,
            1,
            Duration::from_secs(1),
            "retry"
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker mark_owned_running_job_failed",
        manual_worker.mark_owned_running_job_failed(pool, job_id, &worker_owner_id, "failed", true),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker mark_owned_running_job_failed_in_current_transaction",
        tx,
        manual_worker.mark_owned_running_job_failed_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id,
            "failed",
            true
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker move_owned_running_job_to_dead_letter",
        manual_worker.move_owned_running_job_to_dead_letter(
            pool,
            job_id,
            &worker_owner_id,
            "dead",
            true,
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker move_owned_running_job_to_dead_letter_in_current_transaction",
        tx,
        manual_worker.move_owned_running_job_to_dead_letter_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id,
            "dead",
            true,
            DeadLetterReason::OperatorAction
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_owned_unstarted_running_job_to_pending",
        manual_worker.return_owned_unstarted_running_job_to_pending(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_owned_unstarted_running_job_to_pending_in_current_transaction",
        tx,
        manual_worker.return_owned_unstarted_running_job_to_pending_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_owned_started_running_job_to_pending",
        manual_worker.return_owned_started_running_job_to_pending(pool, job_id, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_owned_started_running_job_to_pending_in_current_transaction",
        tx,
        manual_worker.return_owned_started_running_job_to_pending_in_current_transaction(
            tx,
            job_id,
            &worker_owner_id
        ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_available_owned_unstarted_running_jobs_to_pending",
        manual_worker
            .return_available_owned_unstarted_running_jobs_to_pending(pool, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction",
        tx,
        manual_worker
            .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
                tx,
                &worker_owner_id
            ),
        queue_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "queue manual worker return_available_owned_started_running_jobs_to_pending",
        manual_worker
            .return_available_owned_started_running_jobs_to_pending(pool, &worker_owner_id),
        queue_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "queue manual worker return_available_owned_started_running_jobs_to_pending_in_current_transaction",
        tx,
        manual_worker
            .return_available_owned_started_running_jobs_to_pending_in_current_transaction(
                tx,
                &worker_owner_id
            ),
        queue_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "queue process_available_jobs_once_for_worker",
        store.process_available_jobs_once_for_worker(
            pool,
            &registry,
            TEST_WORKER_NAME,
            fast_worker_config()
        ),
        queue_error_is_insufficient_privilege
    );

    let worker = store
        .start_worker(
            pool.clone(),
            registry.clone(),
            TEST_WORKER_NAME,
            fast_worker_config(),
        )
        .expect("start worker with read-only-backed WritePool");
    worker.request_stop();
    let _ = tokio::time::timeout(Duration::from_secs(2), worker.wait())
        .await
        .expect("worker stopped after request");

    let maintenance_worker = store
        .start_worker_with_fleet_maintenance(
            pool.clone(),
            fleet_store.clone(),
            registry,
            "marker_worker_with_maintenance",
            fast_worker_config(),
            fast_worker_maintenance_config(),
        )
        .expect("start worker with Fleet maintenance and read-only-backed WritePool");
    maintenance_worker.request_stop();
    let _ = tokio::time::timeout(Duration::from_secs(2), maintenance_worker.wait())
        .await
        .expect("worker with maintenance stopped after request");
}
