mod common;

use common::{
    connect_sqlx_pool_for_harness, drop_test_schema, fetch_table_exists, standard_test_database_url,
};
use paranoid::db::{
    AuditedSql, BootstrapConfig, PgQualifiedTableName, PgSchemaName, PoolConfig, WritePool,
    component_schema_instance_key_for_tables, portable_query_as,
};
use paranoid::id::SortableId as UniqueTestId;
use secrecy::SecretString;
use sqlx::PgPool;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_bootstrap_migrates_subsystem_tables_in_one_schema() {
    let database_url = standard_test_database_url();
    let paranoid_pool = connect_paranoid_pool(&database_url).await;
    let sqlx_pool = connect_sqlx_pool(&database_url).await;
    let config = BootstrapConfig::new(unique_test_schema_name());

    drop_test_schema(&sqlx_pool, config.schema_name().identifier()).await;

    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let pool = paranoid_pool.clone();
        let task_config = config.clone();
        tasks.spawn(async move { task_config.migrate_schema(&pool).await });
    }

    while let Some(result) = tasks.join_next().await {
        result
            .expect("bootstrap task must not panic")
            .expect("concurrent bootstrap must succeed");
    }

    let table_names = config.table_names();

    for table_name in [
        &table_names.kv,
        &table_names.schema_ledger,
        &table_names.fleet_state,
        &table_names.fleet_coordination,
        &table_names.fleet_fencing_counters,
        &table_names.queue_jobs,
        &table_names.queue_dead_letters,
        &table_names.queue_pauses,
    ] {
        assert!(
            fetch_table_exists(&sqlx_pool, table_name).await,
            "expected bootstrapped table to exist: {}",
            table_name.quoted()
        );
    }

    assert_schema_ledger_self_registration_matches_table_name(
        &sqlx_pool,
        &table_names.schema_ledger,
    )
    .await;

    drop_test_schema(&sqlx_pool, config.schema_name().identifier()).await;
}

#[test]
fn bootstrap_default_layout_uses_schema_as_the_paranoid_namespace() {
    let config = BootstrapConfig::default();
    let table_names = config.table_names();

    for table_name in [
        &table_names.schema_ledger,
        &table_names.kv,
        &table_names.fleet_state,
        &table_names.fleet_coordination,
        &table_names.fleet_fencing_counters,
        &table_names.queue_jobs,
        &table_names.queue_dead_letters,
        &table_names.queue_pauses,
    ] {
        assert_eq!(
            table_name.schema().map(|schema| schema.as_str()),
            Some("__paranoid")
        );
        assert!(
            !table_name.table().as_str().starts_with("__paranoid"),
            "bootstrap table name should not repeat the schema namespace: {}",
            table_name.quoted()
        );
    }
}

async fn connect_paranoid_pool(database_url: &str) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = 8;
    config.application_name = Some("paranoid_db_bootstrap_postgres_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 2, "paranoid_db_bootstrap_postgres_test").await
}

async fn assert_schema_ledger_self_registration_matches_table_name(
    pool: &PgPool,
    ledger_table: &PgQualifiedTableName,
) {
    let table_label = paranoid::db::PgIdentifier::new("table").expect("table label");
    let expected_instance_key =
        component_schema_instance_key_for_tables([(&table_label, ledger_table)]);
    let statement = format!(
        r#"
        SELECT instance_key, schema_version, schema_fingerprint
        FROM {}
        WHERE component = $1
        "#,
        ledger_table.quoted()
    );
    let actual = portable_query_as::<(String, i32, String)>(AuditedSql::new(statement))
        .bind("schema_ledger")
        .fetch_optional(pool)
        .await
        .expect("fetch schema ledger self-registration");
    assert_eq!(
        actual,
        Some((
            expected_instance_key,
            1,
            "paranoid.schema_ledger.v1".to_owned(),
        )),
        "schema ledger should register its own exact table instance"
    );
}

fn unique_test_schema_name() -> PgSchemaName {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgSchemaName::from_identifier_text(format!("__paranoid_bootstrap_{id}"))
        .expect("test schema name")
}
