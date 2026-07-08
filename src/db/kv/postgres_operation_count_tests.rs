use super::*;
use crate::db::postgres_test_support::{connect_sqlx_pool_for_harness, standard_test_database_url};
use crate::db::{
    DatabaseOperationKind, DatabaseOperationObserver, DatabaseOperationRecord, PoolConfig,
    SCHEMA_LEDGER_OPERATION_CLAIM_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_CREATE_TABLE, SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_LOCK_COMPONENT_VERSION,
    SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION, SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
    SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS, SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
    SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
};
use crate::id::SortableId as UniqueTestId;
use secrecy::SecretString;
use sqlx::{PgPool, Row};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::time::Instant;

type OperationShape = (DatabaseOperationKind, &'static str);

mod atomic;
mod bytes;
mod cleanup_and_transactions;
mod hook_and_cancellation;
mod schema;
mod typed_items;

fn operation_shapes(observer: &DatabaseOperationObserver) -> Vec<OperationShape> {
    observer
        .records()
        .into_iter()
        .map(|record| (record.kind, record.label))
        .collect()
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

pub(crate) fn kv_physical_schema_validation_shapes() -> Vec<OperationShape> {
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

pub(crate) fn kv_migrate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
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

pub(crate) fn kv_migrate_already_current_schema_in_current_transaction_shapes()
-> Vec<OperationShape> {
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

pub(crate) fn kv_validate_schema_in_current_transaction_shapes() -> Vec<OperationShape> {
    [
        kv_physical_schema_validation_shapes(),
        schema_ledger_validate_component_version_shapes(),
    ]
    .concat()
}

pub(crate) fn schema_ledger_claim_component_migration_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_ensure_and_validate_shapes(),
        vec![(
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_CLAIM_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

pub(crate) fn schema_ledger_lock_component_migration_shapes() -> Vec<OperationShape> {
    [
        schema_ledger_claim_component_migration_shapes(),
        vec![(
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_LOCK_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

pub(crate) fn schema_ledger_record_component_migration_completion_shapes() -> Vec<OperationShape> {
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

pub(crate) fn schema_ledger_validate_component_version_shapes() -> Vec<OperationShape> {
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

#[derive(Clone, Default)]
struct BlockingOperationGate {
    state: Arc<(Mutex<BlockingOperationGateState>, Condvar)>,
}

#[derive(Default)]
struct BlockingOperationGateState {
    entered: bool,
    released: bool,
    matched_operation_count: usize,
}

impl BlockingOperationGate {
    fn pause_first_matching_operation(
        &self,
        record: DatabaseOperationRecord,
        target_label: &'static str,
    ) {
        if record.label != target_label {
            return;
        }

        let (lock, condvar) = &*self.state;
        let mut state = lock.lock().expect("blocking operation gate lock poisoned");
        state.matched_operation_count += 1;
        if state.matched_operation_count != 1 {
            return;
        }
        state.entered = true;
        condvar.notify_all();
        while !state.released {
            state = condvar
                .wait(state)
                .expect("blocking operation gate wait poisoned");
        }
    }

    fn wait_until_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (lock, condvar) = &*self.state;
        let mut state = lock.lock().expect("blocking operation gate lock poisoned");
        while !state.entered {
            let now = Instant::now();
            assert!(
                now < deadline,
                "database operation hook did not run before the timeout"
            );
            let wait_duration = deadline.saturating_duration_since(now);
            let (next_state, wait_result) = condvar
                .wait_timeout(state, wait_duration)
                .expect("blocking operation gate timed wait poisoned");
            state = next_state;
            assert!(
                !wait_result.timed_out() || state.entered,
                "database operation hook did not run before the timeout"
            );
        }
    }

    fn release(&self) {
        let (lock, condvar) = &*self.state;
        let mut state = lock.lock().expect("blocking operation gate lock poisoned");
        state.released = true;
        condvar.notify_all();
    }

    fn matched_operation_count(&self) -> usize {
        let (lock, _) = &*self.state;
        lock.lock()
            .expect("blocking operation gate lock poisoned")
            .matched_operation_count
    }
}

fn transaction_records(record: DatabaseOperationRecord) -> Vec<DatabaseOperationRecord> {
    transaction_records_many([record])
}

fn read_transaction_records(record: DatabaseOperationRecord) -> Vec<DatabaseOperationRecord> {
    vec![
        DatabaseOperationRecord {
            kind: DatabaseOperationKind::BeginTransaction,
            label: "db.begin_transaction",
            statement: None,
        },
        record,
        DatabaseOperationRecord {
            kind: DatabaseOperationKind::RollbackTransaction,
            label: "db.tx.rollback",
            statement: None,
        },
    ]
}

fn failed_transaction_records(record: DatabaseOperationRecord) -> Vec<DatabaseOperationRecord> {
    vec![
        DatabaseOperationRecord {
            kind: DatabaseOperationKind::BeginTransaction,
            label: "db.begin_transaction",
            statement: None,
        },
        record,
        DatabaseOperationRecord {
            kind: DatabaseOperationKind::RollbackTransaction,
            label: "db.tx.rollback",
            statement: None,
        },
    ]
}

fn transaction_records_many<const N: usize>(
    records: [DatabaseOperationRecord; N],
) -> Vec<DatabaseOperationRecord> {
    let mut operation_records = Vec::with_capacity(N + 2);
    operation_records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::BeginTransaction,
        label: "db.begin_transaction",
        statement: None,
    });
    operation_records.extend(records);
    operation_records.push(DatabaseOperationRecord {
        kind: DatabaseOperationKind::CommitTransaction,
        label: "db.tx.commit",
        statement: None,
    });
    operation_records
}

async fn connect_paranoid_pool(database_url: &str) -> WritePool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = 2;
    config.application_name = Some("paranoid_kv_operation_count_test".to_owned());
    WritePool::connect(config)
        .await
        .expect("connect paranoid pool")
}

async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 2, "paranoid_kv_operation_count_test").await
}

fn unique_test_table_name() -> PgQualifiedTableName {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgQualifiedTableName::unqualified(format!("__kv_op_count_rs_{id}")).expect("test table name")
}

fn unique_schema_ledger_table_name() -> PgQualifiedTableName {
    let id = UniqueTestId::new().expect("new unique test id").to_text();
    PgQualifiedTableName::unqualified(format!("__kv_op_count_schema_ledger_{id}"))
        .expect("schema ledger table name")
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

async fn fetch_test_table_row_count(pool: &PgPool, table_name: &PgQualifiedTableName) -> i64 {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM {}",
        table_name.quoted()
    )))
    .fetch_one(pool)
    .await
    .expect("fetch row count")
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
