use super::*;
use crate::db::fleet::{
    RootKey as FleetRootKey, Store as FleetStore, StoreConfig as FleetStoreConfig,
};
use crate::db::lease::{LEASE_OPERATION_CLAIM, LEASE_OPERATION_RELEASE};
use crate::db::postgres_test_support::{connect_sqlx_pool_for_harness, standard_test_database_url};
use crate::db::{
    DatabaseOperationKind, DatabaseOperationObserver, DatabaseOperationRecord, PoolConfig,
    SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT, SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
    SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS, SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
    SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
};
use crate::id::SortableId as UniqueTestId;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Deserialize, Serialize)]
struct TestPayload {
    value: i32,
}

type OperationShape = (DatabaseOperationKind, &'static str);

mod auxiliary;
mod cleanup;
mod fleet_maintenance;
mod hot_path;
mod operator_failure_lifecycle;
mod registered_tasks;
mod schema;
mod transactions;
mod worker_runtime;

fn expect_single_record(
    observer: &DatabaseOperationObserver,
    kind: DatabaseOperationKind,
    label: &'static str,
    statement: &str,
) {
    assert_eq!(
        observer.records(),
        vec![DatabaseOperationRecord {
            kind,
            label,
            statement: Some(statement.to_owned()),
        }]
    );
    observer.clear();
}

fn expect_single_pool_transaction_record(
    observer: &DatabaseOperationObserver,
    kind: DatabaseOperationKind,
    label: &'static str,
    statement: &str,
) {
    expect_operation_records(
        observer,
        &transaction_records([DatabaseOperationRecord {
            kind,
            label,
            statement: Some(statement.to_owned()),
        }]),
    );
}

fn expect_single_pool_read_transaction_record(
    observer: &DatabaseOperationObserver,
    kind: DatabaseOperationKind,
    label: &'static str,
    statement: &str,
) {
    expect_operation_records(
        observer,
        &read_transaction_records([DatabaseOperationRecord {
            kind,
            label,
            statement: Some(statement.to_owned()),
        }]),
    );
}

fn operation_shapes_from_observer(observer: &DatabaseOperationObserver) -> Vec<OperationShape> {
    observer
        .records()
        .into_iter()
        .map(|record| (record.kind, record.label))
        .collect()
}

fn expect_operation_shape_multiset(
    observer: &DatabaseOperationObserver,
    expected_shapes: &[OperationShape],
) {
    assert_eq!(
        sorted_operation_shapes(operation_shapes_from_observer(observer)),
        sorted_operation_shapes(expected_shapes.to_vec())
    );
    observer.clear();
}

fn sorted_operation_shapes(mut shapes: Vec<OperationShape>) -> Vec<OperationShape> {
    shapes.sort_by(|left, right| {
        database_operation_kind_sort_key(left.0)
            .cmp(&database_operation_kind_sort_key(right.0))
            .then_with(|| left.1.cmp(right.1))
    });
    shapes
}

fn database_operation_kind_sort_key(kind: DatabaseOperationKind) -> u8 {
    match kind {
        DatabaseOperationKind::BeginTransaction => 0,
        DatabaseOperationKind::CommitTransaction => 1,
        DatabaseOperationKind::RollbackTransaction => 2,
        DatabaseOperationKind::Execute => 3,
        DatabaseOperationKind::FetchAll => 4,
        DatabaseOperationKind::FetchOne => 5,
        DatabaseOperationKind::FetchOptional => 6,
    }
}

fn transaction_operation_shapes(inner: Vec<OperationShape>) -> Vec<OperationShape> {
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

fn worker_database_operation_shapes(inner: Vec<OperationShape>) -> Vec<OperationShape> {
    [
        vec![
            (
                DatabaseOperationKind::BeginTransaction,
                "db.begin_transaction",
            ),
            (
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_SET_LOCAL_STATEMENT_TIMEOUT,
            ),
        ],
        inner,
        vec![(DatabaseOperationKind::CommitTransaction, "db.tx.commit")],
    ]
    .concat()
}

fn queue_migrate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        vec![
            (
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_SCHEMA_MIGRATE_STATEMENT,
            );
            14
        ],
        queue_physical_schema_validation_shapes(),
        schema_ledger_record_component_version_shapes(),
        schema_ledger_validate_component_version_shapes(),
    ]
    .concat()
}

fn queue_validate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        queue_physical_schema_validation_shapes(),
        schema_ledger_validate_component_version_shapes(),
    ]
    .concat()
}

fn queue_physical_schema_validation_shapes() -> Vec<OperationShape> {
    [
        vec![
            (
                DatabaseOperationKind::FetchAll,
                QUEUE_OPERATION_SCHEMA_VALIDATE_TABLE_COLUMNS,
            );
            3
        ],
        vec![
            (
                DatabaseOperationKind::FetchOptional,
                QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_CHECK_CONSTRAINT,
            );
            9
        ],
        queue_constraint_probe_shapes(21),
        vec![
            (
                DatabaseOperationKind::FetchOptional,
                QUEUE_OPERATION_SCHEMA_VALIDATE_NAMED_INDEX,
            );
            10
        ],
        vec![(
            DatabaseOperationKind::Execute,
            QUEUE_OPERATION_SCHEMA_VALIDATE_ACTIVE_DEDUPE_ARBITER,
        )],
    ]
    .concat()
}

fn queue_constraint_probe_shapes(count: usize) -> Vec<OperationShape> {
    let mut shapes = Vec::with_capacity(count * 4);
    for _ in 0..count {
        shapes.extend([
            (
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_SCHEMA_PROBE_SAVEPOINT,
            ),
            (
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_SCHEMA_PROBE_INSERT,
            ),
            (
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_SCHEMA_PROBE_ROLLBACK,
            ),
            (
                DatabaseOperationKind::Execute,
                QUEUE_OPERATION_SCHEMA_PROBE_RELEASE,
            ),
        ]);
    }
    shapes
}

fn schema_ledger_record_component_version_shapes() -> Vec<OperationShape> {
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
        (
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION,
        ),
    ]
}

fn schema_ledger_validate_component_version_shapes() -> Vec<OperationShape> {
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
        (
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
        ),
    ]
}

fn expect_operation_records(
    observer: &DatabaseOperationObserver,
    expected_records: &[DatabaseOperationRecord],
) {
    assert_eq!(observer.records(), expected_records);
    observer.clear();
}

fn repeated_pool_transaction_records(
    count: usize,
    record: DatabaseOperationRecord,
) -> Vec<DatabaseOperationRecord> {
    let mut records = Vec::with_capacity(count * 3);
    for _ in 0..count {
        records.extend(transaction_records([record.clone()]));
    }
    records
}

fn transaction_records<const N: usize>(
    inner: [DatabaseOperationRecord; N],
) -> Vec<DatabaseOperationRecord> {
    let mut records = Vec::with_capacity(N + 2);
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::BeginTransaction,
        label: "db.begin_transaction",
        statement: None,
    });
    records.extend(inner);
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::CommitTransaction,
        label: "db.tx.commit",
        statement: None,
    });
    records
}

fn read_transaction_records<const N: usize>(
    inner: [DatabaseOperationRecord; N],
) -> Vec<DatabaseOperationRecord> {
    let mut records = Vec::with_capacity(N + 2);
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::BeginTransaction,
        label: "db.begin_transaction",
        statement: None,
    });
    records.extend(inner);
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::RollbackTransaction,
        label: "db.tx.rollback",
        statement: None,
    });
    records
}

fn worker_database_operation_records<const N: usize>(
    inner: [DatabaseOperationRecord; N],
) -> Vec<DatabaseOperationRecord> {
    let mut records = Vec::with_capacity(N + 3);
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::BeginTransaction,
        label: "db.begin_transaction",
        statement: None,
    });
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::Execute,
        label: QUEUE_OPERATION_SET_LOCAL_STATEMENT_TIMEOUT,
        statement: Some(QUEUE_SET_LOCAL_STATEMENT_TIMEOUT_QUERY.to_owned()),
    });
    records.extend(inner);
    records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::CommitTransaction,
        label: "db.tx.commit",
        statement: None,
    });
    records
}

fn worker_owned_running_jobs_count_query(queue: &Store) -> String {
    format!(
        "SELECT COUNT(*) FROM {} WHERE worker_id = $1 AND status = $2",
        queue.config().table_name.quoted()
    )
}

async fn enqueue_test_job(
    queue: &Store,
    pool: &WritePool,
    task_name: &'static str,
    value: i32,
) -> JobId {
    queue
        .enqueue_json(
            pool,
            task_name,
            &TestPayload { value },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue test job")
        .job_id
}

fn worker_owner_id_for_operation_count_test(worker_owner_id: &str) -> WorkerOwnerId {
    WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text(worker_owner_id)
        .expect("worker owner id")
}

async fn claim_test_job(
    queue: &Store,
    pool: &WritePool,
    task_name: &'static str,
    value: i32,
    worker_id: &'static str,
) -> JobId {
    let worker_owner_id = WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text(worker_id)
        .expect("worker owner id");
    let job_id = enqueue_test_job(queue, pool, task_name, value).await;
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(pool, &[task_name.to_owned()], 1, &worker_owner_id)
        .await
        .expect("claim test job");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, job_id);
    job_id
}

async fn fail_test_job(
    queue: &Store,
    pool: &WritePool,
    task_name: &'static str,
    value: i32,
    worker_id: &'static str,
) -> JobId {
    let worker_owner_id = WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text(worker_id)
        .expect("worker owner id");
    let job_id = claim_test_job(queue, pool, task_name, value, worker_id).await;
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(pool, job_id, &worker_owner_id, "test failure", true)
        .await
        .expect("fail test job");
    job_id
}

async fn wait_until_worker_maintenance_effects_are_visible(
    sqlx_pool: &PgPool,
    queue: &Store,
    pool: &Pool,
    reclaimed_job_id: JobId,
    completed_job_id: JobId,
    failed_job_id: JobId,
    dead_letter_job_id: JobId,
) {
    loop {
        let reclaimed_status = queue
            .fetch_job_status(pool, reclaimed_job_id)
            .await
            .expect("fetch reclaimed job status");
        let completed_job_exists = queue_job_exists(sqlx_pool, queue, completed_job_id).await;
        let failed_job_exists = queue_job_exists(sqlx_pool, queue, failed_job_id).await;
        let dead_letter_job_exists =
            queue_dead_letter_job_exists(sqlx_pool, queue, dead_letter_job_id).await;
        if reclaimed_status == JobStatus::Pending
            && !completed_job_exists
            && !failed_job_exists
            && !dead_letter_job_exists
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn queue_job_exists(sqlx_pool: &PgPool, queue: &Store, job_id: JobId) -> bool {
    let statement = format!(
        "SELECT 1 FROM {} WHERE id = $1",
        queue.config().table_name.quoted()
    );
    sqlx::query_scalar::<_, i32>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(job_id.as_bytes())
        .fetch_optional(sqlx_pool)
        .await
        .expect("query Queue job existence")
        .is_some()
}

async fn queue_dead_letter_job_exists(
    sqlx_pool: &PgPool,
    queue: &Store,
    dead_letter_job_id: JobId,
) -> bool {
    let statement = format!(
        "SELECT 1 FROM {} WHERE id = $1",
        queue.config().dead_letter_table_name.quoted()
    );
    sqlx::query_scalar::<_, i32>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(dead_letter_job_id.as_bytes())
        .fetch_optional(sqlx_pool)
        .await
        .expect("query Queue dead-letter job existence")
        .is_some()
}

async fn connect_paranoid_pool(database_url: &str) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = 2;
    config.application_name = Some("paranoid_queue_operation_count_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 2, "paranoid_queue_operation_count_test").await
}

fn unique_test_config() -> StoreConfig {
    let suffix = UniqueTestId::new().expect("new unique test id").to_text();
    let mut config = StoreConfig::new(
        PgQualifiedTableName::unqualified(format!("__queue_op_count_jobs_{suffix}"))
            .expect("jobs table"),
        PgQualifiedTableName::unqualified(format!("__queue_op_count_dead_{suffix}"))
            .expect("dead-letter table"),
        PgQualifiedTableName::unqualified(format!("__queue_op_count_pause_{suffix}"))
            .expect("pause table"),
    )
    .expect("queue config");
    config.schema_ledger_table_name =
        PgQualifiedTableName::unqualified(format!("__queue_op_count_schema_ledger_{suffix}"))
            .expect("schema ledger table");
    config
}

fn unique_fleet_test_config() -> FleetStoreConfig {
    let suffix = UniqueTestId::new().expect("new unique test id").to_text();
    let mut config = FleetStoreConfig::new_with_explicit_fencing_counter_table(
        FleetRootKey::new(format!("queue_op_count_fleet_{suffix}")).expect("Fleet root key"),
        PgQualifiedTableName::unqualified(format!("__queue_op_count_fleet_state_{suffix}"))
            .expect("Fleet state table"),
        PgQualifiedTableName::unqualified(format!("__queue_op_count_fleet_coordination_{suffix}"))
            .expect("Fleet coordination table"),
        PgQualifiedTableName::unqualified(format!("__queue_op_count_fleet_fencing_{suffix}"))
            .expect("Fleet fencing table"),
    )
    .expect("Fleet config");
    config.schema_ledger_table_name =
        PgQualifiedTableName::unqualified(format!("__queue_op_count_fleet_schema_ledger_{suffix}"))
            .expect("Fleet schema ledger table");
    config
}

async fn drop_queue_test_tables(pool: &PgPool, config: &StoreConfig) {
    drop_test_table(pool, &config.table_name).await;
    drop_test_table(pool, &config.dead_letter_table_name).await;
    drop_test_table(pool, &config.pause_table_name).await;
    drop_test_table(pool, &config.schema_ledger_table_name).await;
}

async fn drop_fleet_test_tables(pool: &PgPool, config: &FleetStoreConfig) {
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
