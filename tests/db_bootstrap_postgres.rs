mod common;

use common::{
    connect_sqlx_pool_for_harness, drop_test_schema, fetch_table_exists, standard_test_database_url,
};
use paranoid::db::{BootstrapConfig, PgSchemaName, PoolConfig, WritePool};
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

    let stores = config.stores().expect("bootstrap stores");
    for table_name in [
        &stores.kv.config().table_name,
        &stores.kv.config().schema_ledger_table_name,
        &stores.fleet.config().state_table_name,
        &stores.fleet.config().coordination_table_name,
        &stores.fleet.config().fencing_counter_table_name,
        &stores.queue.config().table_name,
        &stores.queue.config().dead_letter_table_name,
        &stores.queue.config().pause_table_name,
    ] {
        assert!(
            fetch_table_exists(&sqlx_pool, table_name).await,
            "expected bootstrapped table to exist: {}",
            table_name.quoted()
        );
    }

    drop_test_schema(&sqlx_pool, config.schema_name().identifier()).await;
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

fn unique_test_schema_name() -> PgSchemaName {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgSchemaName::from_identifier_text(format!("__paranoid_bootstrap_{id}"))
        .expect("test schema name")
}
