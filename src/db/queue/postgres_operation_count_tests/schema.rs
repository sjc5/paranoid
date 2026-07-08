use super::*;

#[tokio::test]
async fn queue_schema_setup_and_validation_emit_expected_database_operation_shapes() {
    let database_url = standard_test_database_url();

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
    assert_eq!(
        operation_shapes_from_observer(&observer),
        transaction_operation_shapes(queue_migrate_schema_in_current_transaction_shapes())
    );
    observer.clear();

    queue
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate already-current Queue schema");
    assert_eq!(
        operation_shapes_from_observer(&observer),
        transaction_operation_shapes(
            queue_migrate_already_current_schema_in_current_transaction_shapes()
        )
    );
    observer.clear();

    queue
        .validate_schema(&observed_pool)
        .await
        .expect("validate Queue schema");
    assert_eq!(
        operation_shapes_from_observer(&observer),
        [
            vec![(
                DatabaseOperationKind::BeginTransaction,
                "db.begin_transaction"
            )],
            queue_validate_schema_in_current_transaction_shapes(),
            vec![(DatabaseOperationKind::RollbackTransaction, "db.tx.rollback")],
        ]
        .concat()
    );

    drop_queue_test_tables(&sqlx_pool, &config).await;
}

#[tokio::test]
async fn queue_schema_migration_rolls_back_when_existing_schema_is_incompatible() {
    let database_url = standard_test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let queue = Store::new(config.clone()).expect("queue");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_queue_test_tables(&sqlx_pool, &config).await;
    create_incompatible_placeholder_table(&sqlx_pool, &config.table_name).await;

    queue
        .migrate_schema(&observed_pool)
        .await
        .expect_err("incompatible Queue schema should fail migration");

    assert_transaction_rolled_back_after_error(observer.records());
    assert!(
        !fetch_table_exists(&sqlx_pool, &config.dead_letter_table_name).await,
        "failed migration must not leave dead-letter table behind"
    );
    assert!(
        !fetch_table_exists(&sqlx_pool, &config.pause_table_name).await,
        "failed migration must not leave pause table behind"
    );
    assert!(
        !fetch_table_exists(&sqlx_pool, &config.schema_ledger_table_name).await,
        "failed migration must not leave schema ledger table behind"
    );

    drop_queue_test_tables(&sqlx_pool, &config).await;
}
