use super::*;

#[tokio::test]
async fn kv_schema_setup_and_validation_emit_expected_database_operation_shapes() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres KV schema operation-count test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let schema_ledger_table_name = unique_schema_ledger_table_name();
    let mut config = StoreConfig::new(table_name.clone()).expect("kv config");
    config.schema_ledger_table_name = schema_ledger_table_name.clone();
    let store = Store::new(config).expect("kv store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_test_table(&sqlx_pool, &table_name).await;
    drop_test_table(&sqlx_pool, &schema_ledger_table_name).await;
    store
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate KV schema");
    assert_eq!(
        operation_shapes(&observer),
        transaction_operation_shapes(kv_migrate_schema_in_current_transaction_shapes())
    );
    observer.clear();

    store
        .validate_schema(&observed_pool)
        .await
        .expect("validate KV schema");
    assert_eq!(
        operation_shapes(&observer),
        [
            vec![(
                DatabaseOperationKind::BeginTransaction,
                "db.begin_transaction"
            )],
            kv_validate_schema_in_current_transaction_shapes(),
            vec![(DatabaseOperationKind::RollbackTransaction, "db.tx.rollback")],
        ]
        .concat()
    );

    drop_test_table(&sqlx_pool, &table_name).await;
    drop_test_table(&sqlx_pool, &schema_ledger_table_name).await;
}

#[tokio::test]
async fn kv_schema_migration_rolls_back_when_existing_schema_is_incompatible() {
    let Some(database_url) = test_database_url() else {
        eprintln!(
            "skipping Postgres KV schema rollback test; set TEST_DSN or PARANOID_TEST_DATABASE_URL to run"
        );
        return;
    };

    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let table_name = unique_test_table_name();
    let schema_ledger_table_name = unique_schema_ledger_table_name();
    let mut config = StoreConfig::new(table_name.clone()).expect("kv config");
    config.schema_ledger_table_name = schema_ledger_table_name.clone();
    let store = Store::new(config).expect("kv store");
    let pool = connect_paranoid_pool(&database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_test_table(&sqlx_pool, &table_name).await;
    drop_test_table(&sqlx_pool, &schema_ledger_table_name).await;
    create_incompatible_placeholder_table(&sqlx_pool, &table_name).await;

    store
        .migrate_schema(&observed_pool)
        .await
        .expect_err("incompatible KV schema should fail migration");

    assert_transaction_rolled_back_after_error(observer.records());
    assert!(
        !fetch_table_exists(&sqlx_pool, &schema_ledger_table_name).await,
        "failed migration must not leave schema ledger table behind"
    );

    drop_test_table(&sqlx_pool, &table_name).await;
    drop_test_table(&sqlx_pool, &schema_ledger_table_name).await;
}
