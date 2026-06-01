use super::*;

#[tokio::test]
async fn fleet_schema_setup_and_validation_emit_expected_database_operation_shapes() {
    let database_url = test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let store = Store::new(config.clone()).expect("fleet store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_fleet_test_tables(&sqlx_pool, &config).await;
    store
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate Fleet schema");
    assert_eq!(
        operation_shapes(observer.records()),
        transaction_shapes_vec(fleet_migrate_schema_in_current_transaction_shapes())
    );
    observer.clear();

    store
        .validate_schema(&observed_pool)
        .await
        .expect("validate Fleet schema");
    assert_eq!(
        operation_shapes(observer.records()),
        [
            vec![(
                DatabaseOperationKind::BeginTransaction,
                "db.begin_transaction"
            )],
            fleet_validate_schema_in_current_transaction_shapes(),
            vec![(DatabaseOperationKind::RollbackTransaction, "db.tx.rollback")],
        ]
        .concat()
    );

    drop_fleet_test_tables(&sqlx_pool, &config).await;
}

#[tokio::test]
async fn fleet_schema_migration_rolls_back_when_existing_schema_is_incompatible() {
    let database_url = test_database_url();

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = unique_test_config();
    let store = Store::new(config.clone()).expect("fleet store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_fleet_test_tables(&sqlx_pool, &config).await;
    create_incompatible_placeholder_table(&sqlx_pool, &config.state_table_name).await;

    store
        .migrate_schema(&observed_pool)
        .await
        .expect_err("incompatible Fleet schema should fail migration");

    assert_transaction_rolled_back_after_error(observer.records());
    assert!(
        !fetch_table_exists(&sqlx_pool, &config.coordination_table_name).await,
        "failed migration must not leave coordination table behind"
    );
    assert!(
        !fetch_table_exists(&sqlx_pool, &config.fencing_counter_table_name).await,
        "failed migration must not leave fencing table behind"
    );
    assert!(
        !fetch_table_exists(&sqlx_pool, &config.schema_ledger_table_name).await,
        "failed migration must not leave schema ledger table behind"
    );

    drop_fleet_test_tables(&sqlx_pool, &config).await;
}
