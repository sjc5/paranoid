use super::*;

#[tokio::test]
async fn queue_operations_compose_inside_current_transaction_and_roll_back() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let queue = Store::new(test_database.config.clone()).expect("queue");
    reset_queue_schema(&test_database).await;

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin queue transaction");
    queue
        .validate_schema_in_current_transaction(&mut tx)
        .await
        .expect("validate queue schema in transaction");

    queue
        .pause_queue_in_current_transaction(&mut tx)
        .await
        .expect("pause queue in transaction");
    assert!(
        queue
            .fetch_queue_is_paused_in_current_transaction(&mut tx)
            .await
            .expect("fetch queue pause in transaction")
    );
    queue
        .resume_queue_in_current_transaction(&mut tx)
        .await
        .expect("resume queue in transaction");

    queue
        .pause_task_in_current_transaction(&mut tx, "task.tx.paused")
        .await
        .expect("pause task in transaction");
    assert!(
        queue
            .fetch_task_is_paused_in_current_transaction(&mut tx, "task.tx.paused")
            .await
            .expect("fetch task pause in transaction")
    );
    assert_eq!(
        queue
            .fetch_paused_task_names_in_current_transaction(&mut tx)
            .await
            .expect("fetch paused task names in transaction"),
        vec!["task.tx.paused".to_owned()]
    );
    queue
        .resume_task_in_current_transaction(&mut tx, "task.tx.paused")
        .await
        .expect("resume task in transaction");

    let pending_to_cancel = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.cancel",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue cancel job in transaction");
    queue
        .cancel_pending_job_in_current_transaction(&mut tx, pending_to_cancel.job_id)
        .await
        .expect("cancel pending job in transaction");

    let to_complete = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.complete",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue completion job in transaction");
    let task_complete = vec!["task.tx.complete".to_owned()];
    let tx_worker_complete_owner_id = new_manual_worker_owner_id("tx-worker-complete");
    let claimed_complete = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_complete,
            1,
            &tx_worker_complete_owner_id,
        )
        .await
        .expect("claim completion job in transaction");
    assert_eq!(claimed_complete.len(), 1);
    assert_eq!(claimed_complete[0].id, to_complete.job_id);
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started_in_current_transaction(
            &mut tx,
            to_complete.job_id,
            &tx_worker_complete_owner_id,
        )
        .await
        .expect("mark completion job started in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .touch_owned_running_job_execution_heartbeat_in_current_transaction(
            &mut tx,
            to_complete.job_id,
            &tx_worker_complete_owner_id,
        )
        .await
        .expect("touch completion job heartbeat in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_completed_in_current_transaction(
            &mut tx,
            to_complete.job_id,
            &tx_worker_complete_owner_id,
        )
        .await
        .expect("complete job in transaction");
    assert_eq!(
        queue
            .fetch_job_status_in_current_transaction(&mut tx, to_complete.job_id)
            .await
            .expect("fetch completed status in transaction"),
        JobStatus::Completed
    );

    let to_retry = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.retry",
            &TestPayload { value: 3 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue retry job in transaction");
    let task_retry = vec!["task.tx.retry".to_owned()];
    let tx_worker_retry_owner_id = new_manual_worker_owner_id("tx-worker-retry");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_retry,
            1,
            &tx_worker_retry_owner_id,
        )
        .await
        .expect("claim retry job in transaction");
    let retry_run_at = queue
        .begin_manual_worker_lifecycle()
        .schedule_owned_running_job_retry_in_current_transaction(
            &mut tx,
            to_retry.job_id,
            &tx_worker_retry_owner_id,
            1,
            Duration::from_millis(1),
            "retry in transaction",
        )
        .await
        .expect("schedule retry in transaction");
    assert!(retry_run_at > 0);

    let to_fail = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.failed",
            &TestPayload { value: 4 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue failed job in transaction");
    let task_failed = vec!["task.tx.failed".to_owned()];
    let tx_worker_failed_owner_id = new_manual_worker_owner_id("tx-worker-failed");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_failed,
            1,
            &tx_worker_failed_owner_id,
        )
        .await
        .expect("claim failed job in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed_in_current_transaction(
            &mut tx,
            to_fail.job_id,
            &tx_worker_failed_owner_id,
            "failed in transaction",
            true,
        )
        .await
        .expect("mark failed job in transaction");
    queue
        .retry_failed_job_in_current_transaction(&mut tx, to_fail.job_id, None)
        .await
        .expect("retry failed job in transaction");

    let to_force_requeue = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.force",
            &TestPayload { value: 5 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue force-requeue job in transaction");
    let task_force = vec!["task.tx.force".to_owned()];
    let tx_worker_force_owner_id = new_manual_worker_owner_id("tx-worker-force");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_force,
            1,
            &tx_worker_force_owner_id,
        )
        .await
        .expect("claim force-requeue job in transaction");
    queue
        .force_requeue_running_job_by_id_in_current_transaction(&mut tx, to_force_requeue.job_id)
        .await
        .expect("force requeue running job in transaction");

    let to_return_unstarted = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.return_unstarted",
            &TestPayload { value: 6 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue unstarted return job in transaction");
    let task_return_unstarted = vec!["task.tx.return_unstarted".to_owned()];
    let tx_worker_return_unstarted_owner_id =
        new_manual_worker_owner_id("tx-worker-return-unstarted");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_return_unstarted,
            1,
            &tx_worker_return_unstarted_owner_id,
        )
        .await
        .expect("claim unstarted return job in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_unstarted_running_job_to_pending_in_current_transaction(
            &mut tx,
            to_return_unstarted.job_id,
            &tx_worker_return_unstarted_owner_id,
        )
        .await
        .expect("return unstarted job in transaction");

    let to_return_started = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.return_started",
            &TestPayload { value: 7 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue started return job in transaction");
    let task_return_started = vec!["task.tx.return_started".to_owned()];
    let tx_worker_return_started_owner_id = new_manual_worker_owner_id("tx-worker-return-started");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_return_started,
            1,
            &tx_worker_return_started_owner_id,
        )
        .await
        .expect("claim started return job in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_started_in_current_transaction(
            &mut tx,
            to_return_started.job_id,
            &tx_worker_return_started_owner_id,
        )
        .await
        .expect("mark started return job in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .return_owned_started_running_job_to_pending_in_current_transaction(
            &mut tx,
            to_return_started.job_id,
            &tx_worker_return_started_owner_id,
        )
        .await
        .expect("return started job in transaction");

    let bulk_payloads = [TestPayload { value: 8 }, TestPayload { value: 9 }];
    queue
        .enqueue_json_batch_in_current_transaction(
            &mut tx,
            "task.tx.bulk_return",
            &bulk_payloads,
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("enqueue bulk-return jobs in transaction");
    let task_bulk_return = vec!["task.tx.bulk_return".to_owned()];
    let tx_worker_bulk_return_owner_id = new_manual_worker_owner_id("tx-worker-bulk-return");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_bulk_return,
            2,
            &tx_worker_bulk_return_owner_id,
        )
        .await
        .expect("claim bulk-return jobs in transaction");
    assert_eq!(
        queue
            .begin_manual_worker_lifecycle()
            .return_available_owned_unstarted_running_jobs_to_pending_in_current_transaction(
                &mut tx,
                &tx_worker_bulk_return_owner_id,
            )
            .await
            .expect("bulk return unstarted jobs in transaction"),
        2
    );

    let to_dead_letter = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.dead",
            &TestPayload { value: 10 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue dead-letter source in transaction");
    let task_dead = vec!["task.tx.dead".to_owned()];
    let tx_worker_dead_owner_id = new_manual_worker_owner_id("tx-worker-dead");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_dead,
            1,
            &tx_worker_dead_owner_id,
        )
        .await
        .expect("claim dead-letter source in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed_in_current_transaction(
            &mut tx,
            to_dead_letter.job_id,
            &tx_worker_dead_owner_id,
            "dead-letter in transaction",
            false,
        )
        .await
        .expect("fail dead-letter source in transaction");
    let dead_letter_id = queue
        .move_failed_job_to_dead_letter_in_current_transaction(
            &mut tx,
            to_dead_letter.job_id,
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move failed job to dead letter in transaction");
    let dead_letter_page = queue
        .list_dead_letter_jobs_in_current_transaction(&mut tx, ListDeadLetterJobsOptions::default())
        .await
        .expect("list dead letters in transaction");
    assert_eq!(dead_letter_page.jobs.len(), 1);
    let requeued_dead_letter_id = queue
        .requeue_dead_letter_job_in_current_transaction(&mut tx, dead_letter_id, None)
        .await
        .expect("requeue dead letter in transaction");
    assert_eq!(
        queue
            .fetch_job_status_in_current_transaction(&mut tx, requeued_dead_letter_id)
            .await
            .expect("fetch requeued dead-letter job status in transaction"),
        JobStatus::Pending
    );

    let to_batch_dead_letter = queue
        .enqueue_json_in_current_transaction(
            &mut tx,
            "task.tx.batch_dead",
            &TestPayload { value: 11 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue batch dead-letter source in transaction");
    let task_batch_dead = vec!["task.tx.batch_dead".to_owned()];
    let tx_worker_batch_dead_owner_id = new_manual_worker_owner_id("tx-worker-batch-dead");
    queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner_in_current_transaction(
            &mut tx,
            &task_batch_dead,
            1,
            &tx_worker_batch_dead_owner_id,
        )
        .await
        .expect("claim batch dead-letter source in transaction");
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed_in_current_transaction(
            &mut tx,
            to_batch_dead_letter.job_id,
            &tx_worker_batch_dead_owner_id,
            "batch dead-letter in transaction",
            false,
        )
        .await
        .expect("fail batch dead-letter source in transaction");
    let batch_dead_letter = queue
        .move_failed_jobs_to_dead_letter_batch_in_current_transaction(
            &mut tx,
            &[to_batch_dead_letter.job_id],
            DeadLetterReason::OperatorAction,
        )
        .await
        .expect("move failed jobs to dead letter in transaction");
    assert_eq!(batch_dead_letter.moved_jobs.len(), 1);
    queue
        .delete_dead_letter_job_in_current_transaction(
            &mut tx,
            batch_dead_letter.moved_jobs[0].dead_letter_id,
        )
        .await
        .expect("delete dead-letter row in transaction");

    let counts = queue
        .fetch_status_counts_in_current_transaction(&mut tx, None)
        .await
        .expect("fetch status counts in transaction");
    assert!(counts.total_count() > 0);
    assert_eq!(
        queue
            .fetch_pending_job_count_in_current_transaction(&mut tx, None)
            .await
            .expect("fetch pending count in transaction"),
        counts.pending_count
    );
    assert_eq!(
        queue
            .fetch_failed_job_count_in_current_transaction(&mut tx, None)
            .await
            .expect("fetch failed count in transaction"),
        counts.failed_count
    );
    let jobs_page = queue
        .list_jobs_in_current_transaction(&mut tx, ListJobsOptions::default())
        .await
        .expect("list jobs in transaction");
    assert!(!jobs_page.jobs.is_empty());

    let mut registry = TaskRegistry::new();
    registry
        .register_json_task_handler(
            "task.tx.complete",
            |_context, _payload: TestPayload| async { Ok(()) },
        )
        .expect("register one transaction test task");
    let worker_pressure = queue
        .fetch_worker_pressure_in_current_transaction(&mut tx, &registry)
        .await
        .expect("fetch worker pressure in transaction");
    assert!(worker_pressure.pending_job_count >= 1);
    let orphaned = queue
        .fetch_orphaned_task_names_in_current_transaction(&mut tx, &registry)
        .await
        .expect("fetch orphaned task names in transaction");
    assert!(orphaned.iter().any(|name| name == "task.tx.retry"));

    assert_eq!(
        queue
            .cleanup_available_completed_jobs_older_than_once_in_current_transaction(
                &mut tx,
                Duration::from_secs(3600),
                10,
            )
            .await
            .expect("completed cleanup in transaction"),
        0
    );
    assert_eq!(
        queue
            .cleanup_available_failed_jobs_older_than_once_in_current_transaction(
                &mut tx,
                Duration::from_secs(3600),
                10,
            )
            .await
            .expect("failed cleanup in transaction"),
        0
    );
    assert_eq!(
        queue
            .cleanup_available_dead_letter_jobs_older_than_once_in_current_transaction(
                &mut tx,
                Duration::from_secs(3600),
                10,
            )
            .await
            .expect("dead-letter cleanup in transaction"),
        0
    );
    let reclaim_result = queue
        .reclaim_available_stale_running_jobs_once_in_current_transaction(
            &mut tx,
            Duration::from_secs(1),
            10,
            true,
        )
        .await
        .expect("reclaim stale jobs in transaction");
    assert!(
        reclaim_result
            .never_started_jobs_returned_to_pending
            .is_empty()
    );
    assert!(
        reclaim_result
            .expired_jobs_returned_to_pending_for_retry
            .is_empty()
    );
    assert!(reclaim_result.expired_jobs_moved_to_failed.is_empty());
    assert!(reclaim_result.expired_jobs_moved_to_dead_letter.is_empty());

    tx.rollback().await.expect("rollback queue transaction");
    assert_eq!(
        fetch_queue_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name)
            .await,
        0
    );
    assert_eq!(
        fetch_queue_table_row_count(
            &test_database.sqlx_pool,
            &test_database.config.dead_letter_table_name,
        )
        .await,
        0
    );
    assert_eq!(
        fetch_queue_table_row_count(
            &test_database.sqlx_pool,
            &test_database.config.pause_table_name,
        )
        .await,
        0
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
