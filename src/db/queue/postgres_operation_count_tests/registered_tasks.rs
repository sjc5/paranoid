use super::*;

#[tokio::test]
async fn queue_registered_json_task_helpers_emit_exact_database_operation_records() {
    let database_url = test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let queue = Store::new(config.clone()).expect("queue");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_queue_test_tables(&sqlx_pool, &config).await;
    queue
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate Queue schema");
    observer.clear();

    let mut registry = TaskRegistry::new();
    let registered_task = queue
        .register_json_task_handler::<TestPayload, _, _>(
            &mut registry,
            "task.operation_count.registered",
            |_context, _payload| async { Ok::<(), TaskError>(()) },
        )
        .expect("register typed task helper");

    let enqueued = registered_task
        .enqueue(
            &observed_pool,
            &TestPayload { value: 70 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue through registered task helper");
    assert!(!enqueued.deduplicated);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_ENQUEUE,
        queue.sql_catalog().single_enqueue_query(),
    );

    let dedupe_enqueued = registered_task
        .enqueue(
            &observed_pool,
            &TestPayload { value: 71 },
            EnqueueOptions {
                dedupe_key: Some("registered-task-same-work".to_owned()),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("dedupe enqueue through registered task helper");
    assert!(!dedupe_enqueued.deduplicated);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_DEDUPE_ENQUEUE,
        queue.sql_catalog().dedupe_enqueue_query(),
    );

    registered_task
        .enqueue_batch(
            &observed_pool,
            &[TestPayload { value: 72 }, TestPayload { value: 73 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("batch enqueue through registered task helper");
    let batch_statement = queue.sql_catalog().batch_enqueue_query(2);
    expect_single_pool_transaction_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_BATCH_ENQUEUE,
        batch_statement.as_ref(),
    );

    let mut tx = observed_pool
        .begin_transaction()
        .await
        .expect("begin caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::BeginTransaction,
            label: "db.begin_transaction",
            statement: None,
        }]
    );
    observer.clear();

    registered_task
        .enqueue_in_current_transaction(
            &mut tx,
            &TestPayload { value: 74 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue through registered task helper in caller transaction");
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_ENQUEUE,
        queue.sql_catalog().single_enqueue_query(),
    );

    registered_task
        .enqueue_batch_in_current_transaction(
            &mut tx,
            &[TestPayload { value: 75 }, TestPayload { value: 76 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("batch enqueue through registered task helper in caller transaction");
    let transaction_batch_statement = queue.sql_catalog().batch_enqueue_query(2);
    expect_single_record(
        &observer,
        DatabaseOperationKind::FetchOne,
        QUEUE_OPERATION_BATCH_ENQUEUE,
        transaction_batch_statement.as_ref(),
    );

    tx.commit().await.expect("commit caller transaction");
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind: DatabaseOperationKind::CommitTransaction,
            label: "db.tx.commit",
            statement: None,
        }]
    );
    observer.clear();

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
