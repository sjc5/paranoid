use super::*;
use crate::db::kv::{
    KV_OPERATION_ACQUIRE_SLOT, KV_OPERATION_COUNT_LIVE_KEYS_WITH_PREFIX, KV_OPERATION_DELETE_KEY,
    KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION,
    KV_OPERATION_DELETE_NAMESPACE_KEYS_WITH_PREFIX_ONCE, KV_OPERATION_ENSURE_SLOT_KEYS_EXIST,
    KV_OPERATION_GET_BYTES, KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP,
    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION, KV_OPERATION_SCAN_BYTES_WITH_PREFIX,
    KV_OPERATION_SCHEMA_CREATE_INDEX, KV_OPERATION_SCHEMA_CREATE_TABLE,
    KV_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS, KV_OPERATION_SCHEMA_VALIDATE_COLUMNS,
    KV_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
    KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
    KV_OPERATION_SCHEMA_VALIDATE_KEY_PATTERN_INDEX, KV_OPERATION_SCHEMA_VALIDATE_UPDATED_AT_INDEX,
    KV_OPERATION_SET_BYTES, KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
};
use crate::db::lease::{
    LEASE_OPERATION_CLAIM, LEASE_OPERATION_FETCH_LIVE_HOLDER, LEASE_OPERATION_RELEASE,
    LEASE_OPERATION_RENEW, LEASE_OPERATION_SCHEMA_MIGRATE_STATEMENT,
    LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS, LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
    LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
    LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
};
use crate::db::postgres_test_support::{connect_sqlx_pool_for_harness, standard_test_database_url};
use crate::db::{
    DatabaseOperationKind, DatabaseOperationObserver, DatabaseOperationRecord,
    PgQualifiedTableName, PoolConfig, SCHEMA_LEDGER_OPERATION_CLAIM_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT, SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
    SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_LOCK_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS, SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
    SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
};
use crate::id::SortableId as UniqueTestId;
use secrecy::SecretString;
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio::sync::Notify;

type OperationShape = (DatabaseOperationKind, &'static str);

mod common;
mod once_cron;
mod schema;
mod subscription;
mod throttlers;
mod transactions;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct CachePayload {
    value: i64,
}

struct ObservedFleetStore {
    sqlx_pool: PgPool,
    config: StoreConfig,
    store: Store,
    observer: DatabaseOperationObserver,
    observed_pool: WritePool,
}

impl ObservedFleetStore {
    async fn drop_tables(&self) {
        drop_fleet_test_tables(&self.sqlx_pool, &self.config).await;
    }
}

async fn prepare_observed_fleet_store(database_url: &str) -> ObservedFleetStore {
    let sqlx_pool = connect_sqlx_pool(database_url).await;
    let config = unique_test_config();
    let store = Store::new(config.clone()).expect("fleet store");
    let pool = connect_paranoid_pool(database_url).await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());

    drop_fleet_test_tables(&sqlx_pool, &config).await;
    store
        .migrate_schema(&observed_pool)
        .await
        .expect("migrate Fleet schema");
    observer.clear();

    ObservedFleetStore {
        sqlx_pool,
        config,
        store,
        observer,
        observed_pool,
    }
}

fn expect_operation_shapes(
    observer: &DatabaseOperationObserver,
    expected_shapes: &[OperationShape],
) {
    let actual_shapes = operation_shapes(observer.records());
    assert_eq!(actual_shapes, expected_shapes);
    observer.clear();
}

fn operation_shapes(records: Vec<DatabaseOperationRecord>) -> Vec<OperationShape> {
    records
        .into_iter()
        .map(|record| (record.kind, record.label))
        .collect()
}

fn transaction_shapes_vec(inner: Vec<OperationShape>) -> Vec<OperationShape> {
    [
        vec![(
            DatabaseOperationKind::BeginTransaction,
            "db.begin_transaction",
        )],
        inner,
        vec![(DatabaseOperationKind::CommitTransaction, "db.tx.commit")],
    ]
    .concat()
}

fn transaction_shapes<const N: usize>(inner: [OperationShape; N]) -> Vec<OperationShape> {
    let mut records = Vec::with_capacity(N + 2);
    records.push((
        DatabaseOperationKind::BeginTransaction,
        "db.begin_transaction",
    ));
    records.extend(inner);
    records.push((DatabaseOperationKind::CommitTransaction, "db.tx.commit"));
    records
}

fn rollback_transaction_shapes<const N: usize>(inner: [OperationShape; N]) -> Vec<OperationShape> {
    let mut records = Vec::with_capacity(N + 2);
    records.push((
        DatabaseOperationKind::BeginTransaction,
        "db.begin_transaction",
    ));
    records.extend(inner);
    records.push((DatabaseOperationKind::RollbackTransaction, "db.tx.rollback"));
    records
}

fn fleet_migrate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_claim_component_migration_shapes(),
        kv_migrate_schema_in_current_transaction_shapes(),
        lease_migrate_schema_in_current_transaction_shapes(),
        schema_ledger_record_component_migration_completion_shapes(),
        fleet_validate_schema_in_current_transaction_shapes(),
    ]
    .concat()
}

fn fleet_migrate_already_current_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_lock_component_migration_shapes(),
        kv_migrate_already_current_schema_in_current_transaction_shapes(),
        lease_migrate_schema_in_current_transaction_shapes(),
        fleet_validate_schema_in_current_transaction_shapes(),
    ]
    .concat()
}

fn fleet_validate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        kv_validate_schema_in_current_transaction_shapes(),
        lease_validate_schema_in_current_transaction_shapes(),
        schema_ledger_validate_component_version_shapes(),
    ]
    .concat()
}

fn kv_migrate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_claim_component_migration_shapes(),
        vec![
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SCHEMA_CREATE_TABLE,
            ),
            (
                DatabaseOperationKind::FetchAll,
                KV_OPERATION_SCHEMA_VALIDATE_COLUMNS,
            ),
            (
                DatabaseOperationKind::FetchOne,
                KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
            ),
        ],
        vec![
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SCHEMA_CREATE_INDEX,
            );
            3
        ],
        kv_physical_schema_validation_shapes(),
        schema_ledger_record_component_migration_completion_shapes(),
    ]
    .concat()
}

fn kv_migrate_already_current_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_lock_component_migration_shapes(),
        vec![
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SCHEMA_CREATE_TABLE,
            ),
            (
                DatabaseOperationKind::FetchAll,
                KV_OPERATION_SCHEMA_VALIDATE_COLUMNS,
            ),
            (
                DatabaseOperationKind::FetchOne,
                KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
            ),
        ],
        vec![
            (
                DatabaseOperationKind::Execute,
                KV_OPERATION_SCHEMA_CREATE_INDEX,
            );
            3
        ],
        kv_physical_schema_validation_shapes(),
    ]
    .concat()
}

fn kv_validate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        kv_physical_schema_validation_shapes(),
        schema_ledger_validate_component_version_shapes(),
    ]
    .concat()
}

fn kv_physical_schema_validation_shapes() -> Vec<OperationShape> {
    vec![
        (
            DatabaseOperationKind::FetchAll,
            KV_OPERATION_SCHEMA_VALIDATE_COLUMNS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
        ),
        (
            DatabaseOperationKind::FetchAll,
            KV_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
        ),
        (
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_SCHEMA_VALIDATE_KEY_PATTERN_INDEX,
        ),
        (
            DatabaseOperationKind::FetchOne,
            KV_OPERATION_SCHEMA_VALIDATE_UPDATED_AT_INDEX,
        ),
    ]
}

fn lease_migrate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        vec![
            (
                DatabaseOperationKind::Execute,
                LEASE_OPERATION_SCHEMA_MIGRATE_STATEMENT,
            );
            3
        ],
        lease_validate_schema_in_current_transaction_shapes(),
    ]
    .concat()
}

fn lease_validate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    vec![
        (
            DatabaseOperationKind::FetchAll,
            LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
        ),
        (
            DatabaseOperationKind::FetchAll,
            LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
        ),
        (
            DatabaseOperationKind::FetchAll,
            LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
        ),
        (
            DatabaseOperationKind::FetchAll,
            LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
        ),
    ]
}

fn schema_ledger_claim_component_migration_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_ensure_and_validate_shapes(),
        vec![(
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_CLAIM_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

fn schema_ledger_lock_component_migration_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_claim_component_migration_shapes(),
        vec![(
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_LOCK_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

fn schema_ledger_record_component_migration_completion_shapes() -> Vec<OperationShape> {
    vec![
        (
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION,
        ),
        (
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
        ),
    ]
}

fn schema_ledger_validate_component_version_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_validate_physical_shapes(),
        vec![(
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

fn schema_ledger_ensure_and_validate_shapes() -> Vec<OperationShape> {
    [
        vec![
            (
                DatabaseOperationKind::Execute,
                SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT,
            ),
            (
                DatabaseOperationKind::Execute,
                SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
            ),
            (
                DatabaseOperationKind::Execute,
                SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
            ),
        ],
        schema_ledger_validate_physical_shapes(),
    ]
    .concat()
}

fn schema_ledger_validate_physical_shapes() -> Vec<OperationShape> {
    vec![
        (
            DatabaseOperationKind::FetchAll,
            SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
        ),
        (
            DatabaseOperationKind::FetchAll,
            SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS,
        ),
    ]
}

async fn connect_paranoid_pool(database_url: &str) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = 2;
    config.application_name = Some("paranoid_fleet_operation_count_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 2, "paranoid_fleet_operation_count_test").await
}

fn unique_test_config() -> StoreConfig {
    let suffix = UniqueTestId::new().expect("new unique test id").to_text();
    let mut config = StoreConfig::new_with_explicit_fencing_counter_table(
        RootKey::new(format!("__paranoid_fleet_op_count_{suffix}")).expect("root key"),
        PgQualifiedTableName::unqualified(format!("__fleet_op_count_state_{suffix}"))
            .expect("state table"),
        PgQualifiedTableName::unqualified(format!("__fleet_op_count_coord_{suffix}"))
            .expect("coordination table"),
        PgQualifiedTableName::unqualified(format!("__fleet_op_count_fence_{suffix}"))
            .expect("fencing table"),
    )
    .expect("fleet config");
    config.schema_ledger_table_name =
        PgQualifiedTableName::unqualified(format!("__fleet_op_count_schema_ledger_{suffix}"))
            .expect("schema ledger table");
    config
}

async fn drop_fleet_test_tables(pool: &PgPool, config: &StoreConfig) {
    drop_test_table(pool, &config.state_table_name).await;
    drop_test_table(pool, &config.coordination_table_name).await;
    drop_test_table(pool, &config.fencing_counter_table_name).await;
    drop_test_table(pool, &config.schema_ledger_table_name).await;
}

async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TABLE IF EXISTS {} CASCADE",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test table");
}

async fn create_incompatible_placeholder_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE TABLE {} (id BIGINT PRIMARY KEY)",
        table_name.quoted()
    )))
    .execute(pool)
    .await
    .expect("create incompatible placeholder table");
}

async fn fetch_table_exists(pool: &PgPool, table_name: &PgQualifiedTableName) -> bool {
    let schema_expression = table_name
        .schema()
        .map(|schema| postgres_string_literal(schema.as_str()))
        .unwrap_or_else(|| "current_schema()".to_owned());
    let table_expression = postgres_string_literal(table_name.table().as_str());
    let row = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE n.nspname = {schema_expression}
              AND c.relname = {table_expression}
              AND c.relkind IN ('r', 'p')
        )
        "#,
    )))
    .fetch_one(pool)
    .await
    .expect("fetch table existence");
    row.try_get(0).expect("decode table existence")
}

fn postgres_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn assert_transaction_rolled_back_after_error(records: Vec<DatabaseOperationRecord>) {
    assert_eq!(
        records.first().map(|record| record.kind),
        Some(DatabaseOperationKind::BeginTransaction),
        "operation should begin an explicit transaction"
    );
    assert_eq!(
        records.last().map(|record| record.kind),
        Some(DatabaseOperationKind::RollbackTransaction),
        "failed operation should explicitly roll back"
    );
    assert!(
        records
            .iter()
            .all(|record| record.kind != DatabaseOperationKind::CommitTransaction),
        "failed operation must not commit"
    );
}
