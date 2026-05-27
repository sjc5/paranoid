use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn database_operation_hook_can_pause_before_read_transaction_to_force_committed_read_race() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres KV query-hook test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let store =
        Store::new(StoreConfig::new(table_name.clone()).expect("kv config")).expect("kv store");
    let pool = connect_paranoid_pool(&database_url).await;

    drop_test_table(&sqlx_pool, &table_name).await;
    store
        .migrate_schema(&pool)
        .await
        .expect("migrate KV schema");

    let gate = BlockingOperationGate::default();
    let hook_gate = gate.clone();
    let observer = DatabaseOperationObserver::with_before_operation_hook(move |record| {
        hook_gate.pause_first_matching_operation(record, "db.begin_transaction");
    });
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    let key = Key::from_parts(["query-hook", "race"]).expect("key");
    let store_for_blocked_reader = store.clone();
    let observed_pool_for_blocked_reader = observed_pool.clone();
    let key_for_blocked_reader = key.clone();
    let blocked_reader = tokio::spawn(async move {
        store_for_blocked_reader
            .get_bytes(&observed_pool_for_blocked_reader, &key_for_blocked_reader)
            .await
    });

    let wait_gate = gate.clone();
    tokio::task::spawn_blocking(move || wait_gate.wait_until_entered())
        .await
        .expect("join hook waiter");

    tokio::time::timeout(
        Duration::from_secs(5),
        store.set_bytes(&pool, &key, b"committed-before-read", Ttl::no_expiration()),
    )
    .await
    .expect("competing write should not block behind the hooked read")
    .expect("competing write commits before hooked read SQL runs");
    gate.release();

    let blocked_reader_result = tokio::time::timeout(Duration::from_secs(5), blocked_reader)
        .await
        .expect("blocked reader should finish after hook release")
        .expect("join blocked reader")
        .expect("blocked reader result");
    assert_eq!(blocked_reader_result, b"committed-before-read");
    assert_eq!(gate.matched_operation_count(), 1);
    assert_eq!(
        observer.records(),
        read_transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::FetchOptional,
            label: KV_OPERATION_GET_BYTES,
            statement: Some(store.queries.get_bytes.clone()),
        })
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_owned_write_abort_at_commit_boundary_commits_once() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres KV commit-cancellation test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let store =
        Store::new(StoreConfig::new(table_name.clone()).expect("kv config")).expect("kv store");
    let pool = connect_paranoid_pool(&database_url).await;

    drop_test_table(&sqlx_pool, &table_name).await;
    store
        .migrate_schema(&pool)
        .await
        .expect("migrate KV schema");

    let gate = BlockingOperationGate::default();
    let hook_gate = gate.clone();
    let observer = DatabaseOperationObserver::with_before_operation_hook(move |record| {
        hook_gate.pause_first_matching_operation(record, "db.tx.commit");
    });
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    let key = Key::from_parts(["commit-cancel", "set"]).expect("key");
    let store_for_blocked_writer = store.clone();
    let observed_pool_for_blocked_writer = observed_pool.clone();
    let key_for_blocked_writer = key.clone();
    let blocked_writer = tokio::spawn(async move {
        store_for_blocked_writer
            .set_bytes(
                &observed_pool_for_blocked_writer,
                &key_for_blocked_writer,
                b"commit-boundary-value",
                Ttl::no_expiration(),
            )
            .await
    });

    let wait_gate = gate.clone();
    tokio::task::spawn_blocking(move || wait_gate.wait_until_entered())
        .await
        .expect("join hook waiter");

    blocked_writer.abort();
    gate.release();
    let join_error = tokio::time::timeout(Duration::from_secs(5), blocked_writer)
        .await
        .expect("blocked writer should observe cancellation")
        .expect_err("blocked writer should not complete after abort");
    assert!(join_error.is_cancelled());

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        store
            .get_bytes(&pool, &key)
            .await
            .expect("commit-boundary cancellation may still commit"),
        b"commit-boundary-value"
    );
    assert_eq!(fetch_test_table_row_count(&sqlx_pool, &table_name).await, 1);
    assert_eq!(gate.matched_operation_count(), 1);
    assert_eq!(
        observer.records(),
        transaction_records(DatabaseOperationRecord {
            kind: DatabaseOperationKind::Execute,
            label: KV_OPERATION_SET_BYTES,
            statement: Some(store.queries.set_bytes_no_expiration.clone()),
        })
    );

    drop_test_table(&sqlx_pool, &table_name).await;
}
