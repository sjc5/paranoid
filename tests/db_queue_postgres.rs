mod common;

use common::{
    connect_sqlx_pool_for_harness, drop_test_table as common_drop_test_table, fetch_table_exists,
    queue_test_database_url,
};
use paranoid::db::{PgIdentifier, PgQualifiedTableName, Pool, PoolConfig};
use paranoid::fleet;
use paranoid::fleet::CronKey;
use paranoid::queue::{
    DeadLetterReason, EnqueueBatchOptions, EnqueueOptions, Error, JobRunAtOrAfter, JobStatus,
    JobTimeout, ListDeadLetterJobsOptions, ListJobsOptions, RetryBackoffStrategy, RetryPolicy,
    Store, StoreConfig, TaskError, TaskRegistry, WorkerConfig, WorkerDefaultJobTimeout,
    WorkerMaintenanceConfig, WorkerOwnerId,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

#[path = "db_queue_postgres/dead_letter_cancellation.rs"]
mod dead_letter_cancellation;
#[path = "db_queue_postgres/enqueue_and_observability.rs"]
mod enqueue_and_observability;
#[path = "db_queue_postgres/locking.rs"]
mod locking;
#[path = "db_queue_postgres/maintenance_and_listing.rs"]
mod maintenance_and_listing;
#[path = "db_queue_postgres/maintenance_locking.rs"]
mod maintenance_locking;
#[path = "db_queue_postgres/maintenance_stage_errors.rs"]
mod maintenance_stage_errors;
#[path = "db_queue_postgres/retry_and_dead_letter.rs"]
mod retry_and_dead_letter;
#[path = "db_queue_postgres/schema.rs"]
mod schema;
#[path = "db_queue_postgres/schema_operation_contracts.rs"]
mod schema_operation_contracts;
#[path = "db_queue_postgres/schema_validation.rs"]
mod schema_validation;
#[path = "db_queue_postgres/transactions.rs"]
mod transactions;
#[path = "db_queue_postgres/worker_cleanup_failures.rs"]
mod worker_cleanup_failures;
#[path = "db_queue_postgres/worker_fleet_maintenance.rs"]
mod worker_fleet_maintenance;
#[path = "db_queue_postgres/worker_locking.rs"]
mod worker_locking;
#[path = "db_queue_postgres/worker_loop.rs"]
mod worker_loop;
#[path = "db_queue_postgres/worker_loop_shutdown.rs"]
mod worker_loop_shutdown;
#[path = "db_queue_postgres/worker_once.rs"]
mod worker_once;
#[path = "db_queue_postgres/worker_once_claims.rs"]
mod worker_once_claims;
#[path = "db_queue_postgres/worker_once_support.rs"]
mod worker_once_support;

#[derive(Deserialize, Serialize)]
struct TestPayload {
    value: i32,
}

struct TestDatabase {
    paranoid_pool: Pool,
    sqlx_pool: PgPool,
    config: StoreConfig,
}

impl TestDatabase {
    async fn connect() -> Option<Self> {
        let database_url = test_database_url()?;
        let paranoid_pool = connect_paranoid_pool(&database_url).await;
        let sqlx_pool = connect_sqlx_pool(&database_url).await;
        Some(Self {
            paranoid_pool,
            sqlx_pool,
            config: unique_test_config(),
        })
    }
}

fn test_database_url() -> Option<String> {
    queue_test_database_url()
}

async fn connect_paranoid_pool(database_url: &str) -> Pool {
    connect_paranoid_pool_with_max_connections(database_url, 5).await
}

async fn connect_paranoid_pool_with_max_connections(
    database_url: &str,
    max_connections: u32,
) -> Pool {
    let mut config = PoolConfig::new(SecretString::from(database_url.to_owned()));
    config.max_connections = max_connections;
    config.application_name = Some("paranoid_db_queue_postgres_test".to_owned());
    Pool::connect(config).await.expect("connect paranoid pool")
}

async fn connect_sqlx_pool(database_url: &str) -> PgPool {
    connect_sqlx_pool_for_harness(database_url, 5, "paranoid_db_queue_postgres_test").await
}

async fn reset_queue_schema(test_database: &TestDatabase) {
    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
}

async fn migrate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), Error> {
    Store::new(config.clone())
        .expect("queue")
        .migrate_schema(pool)
        .await
}

async fn migrate_schema_in_current_transaction(
    tx: &mut paranoid::db::Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    Store::new(config.clone())
        .expect("queue")
        .migrate_schema_in_current_transaction(tx)
        .await
}

async fn validate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), Error> {
    Store::new(config.clone())
        .expect("queue")
        .validate_schema(pool)
        .await
}

fn unique_test_config() -> StoreConfig {
    let suffix = paranoid::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    StoreConfig::new(
        PgQualifiedTableName::new(
            None,
            PgIdentifier::new(format!("__queue_test_jobs_{suffix}")).expect("jobs table"),
        ),
        PgQualifiedTableName::new(
            None,
            PgIdentifier::new(format!("__queue_test_dead_{suffix}")).expect("dead-letter table"),
        ),
        PgQualifiedTableName::new(
            None,
            PgIdentifier::new(format!("__queue_test_pause_{suffix}")).expect("pause table"),
        ),
    )
    .expect("queue config")
}

fn unique_fleet_test_config() -> fleet::StoreConfig {
    let suffix = paranoid::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    fleet::StoreConfig::new(
        fleet::RootKey::new(format!("__queue_test_fleet_{suffix}")).expect("Fleet root key"),
        PgQualifiedTableName::new(
            None,
            PgIdentifier::new(format!("__queue_test_fleet_kv_{suffix}")).expect("Fleet KV table"),
        ),
        PgQualifiedTableName::new(
            None,
            PgIdentifier::new(format!("__queue_test_fleet_lease_{suffix}"))
                .expect("Fleet lease table"),
        ),
    )
    .expect("fleet config")
}

async fn drop_queue_test_tables(pool: &PgPool, config: &StoreConfig) {
    drop_test_table(pool, &config.table_name).await;
    drop_test_table(pool, &config.dead_letter_table_name).await;
    drop_test_table(pool, &config.pause_table_name).await;
}

async fn drop_fleet_test_tables(pool: &PgPool, config: &fleet::StoreConfig) {
    drop_test_table(pool, &config.state_table_name).await;
    drop_test_table(pool, &config.coordination_table_name).await;
    drop_test_table(pool, &config.fencing_counter_table_name).await;
}

async fn drop_test_table(pool: &PgPool, table_name: &PgQualifiedTableName) {
    common_drop_test_table(pool, table_name).await;
}

async fn fetch_queue_table_row_count(pool: &PgPool, table_name: &PgQualifiedTableName) -> i64 {
    let statement = format!("SELECT COUNT(*) FROM {}", table_name.quoted());
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(statement.as_str()))
        .fetch_one(pool)
        .await
        .expect("fetch queue table row count")
}

async fn fetch_check_constraint_name_containing(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    definition_fragment: &str,
) -> String {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT con.conname
        FROM pg_constraint AS con
        JOIN pg_class AS cls ON cls.oid = con.conrelid
        JOIN pg_namespace AS ns ON ns.oid = cls.relnamespace
        WHERE ns.nspname = COALESCE($1, current_schema())
          AND cls.relname = $2
          AND con.contype = 'c'
          AND (
            con.conname LIKE '%' || $3 || '%'
            OR pg_get_constraintdef(con.oid) LIKE '%' || $3 || '%'
          )
        ORDER BY con.conname
        LIMIT 1
        "#,
    )
    .bind(table_name.schema().map(|schema| schema.as_str()))
    .bind(table_name.table().as_str())
    .bind(definition_fragment)
    .fetch_one(pool)
    .await
    .expect("fetch check constraint name")
}

fn assert_queue_database_error_contains(error: &Error, expected: &str) {
    assert!(
        matches!(error, Error::Database(_)),
        "queue error = {error:?}, want database error"
    );
    let error_text = error.to_string();
    assert!(
        error_text.contains(expected),
        "queue database error = {error_text:?}, want substring {expected:?}"
    );
}

async fn lock_queue_job_row<'a>(
    test_database: &'a TestDatabase,
    job_id: paranoid::queue::JobId,
) -> sqlx::Transaction<'a, sqlx::Postgres> {
    let mut tx = test_database
        .sqlx_pool
        .begin()
        .await
        .expect("begin queue job row lock transaction");
    let statement = format!(
        "SELECT id FROM {} WHERE id = $1 FOR UPDATE",
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(job_id.as_bytes())
        .fetch_one(&mut *tx)
        .await
        .expect("lock queue job row");
    tx
}

async fn lock_dead_letter_job_row<'a>(
    test_database: &'a TestDatabase,
    dead_letter_job_id: paranoid::queue::JobId,
) -> sqlx::Transaction<'a, sqlx::Postgres> {
    let mut tx = test_database
        .sqlx_pool
        .begin()
        .await
        .expect("begin dead-letter row lock transaction");
    let statement = format!(
        "SELECT id FROM {} WHERE id = $1 FOR UPDATE",
        test_database.config.dead_letter_table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(dead_letter_job_id.as_bytes())
        .fetch_one(&mut *tx)
        .await
        .expect("lock dead-letter job row");
    tx
}

async fn abort_blocked_task<T>(handle: tokio::task::JoinHandle<T>, task_name: &str) {
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !handle.is_finished(),
        "{task_name} task should still be blocked"
    );
    handle.abort();
    match handle.await {
        Err(join_error) => assert!(
            join_error.is_cancelled(),
            "{task_name} task join error = {join_error}"
        ),
        Ok(_) => panic!("{task_name} task completed after abort"),
    }
}

async fn wait_until<F, Fut>(description: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let started_at = Instant::now();
    loop {
        if check().await {
            return;
        }
        assert!(
            started_at.elapsed() < timeout,
            "timed out waiting until {description}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn assert_worker_owner_id_was_derived_from_worker_name(
    worker_owner_id: Option<&str>,
    worker_name: &str,
) -> String {
    let worker_owner_id = worker_owner_id.expect("job should have a worker owner ID");
    let expected_prefix = format!("{worker_name}.");
    assert!(
        worker_owner_id.starts_with(&expected_prefix),
        "worker owner ID {worker_owner_id:?} should start with {expected_prefix:?}"
    );
    assert_eq!(
        worker_owner_id.len(),
        worker_name.len() + 1 + paranoid::id::SORTABLE_ID_TEXT_LEN
    );
    worker_owner_id.to_owned()
}

fn worker_owner_id_text(worker_owner_id: Option<&WorkerOwnerId>) -> Option<&str> {
    worker_owner_id.map(WorkerOwnerId::as_str)
}

fn new_manual_worker_owner_id(worker_owner_id_text: &str) -> WorkerOwnerId {
    WorkerOwnerId::from_manual_worker_lifecycle_owner_id_text(worker_owner_id_text)
        .expect("manual worker owner id")
}

trait TestWorkerOwnerArg {
    fn to_worker_owner_id(&self) -> WorkerOwnerId;
}

impl TestWorkerOwnerArg for &str {
    fn to_worker_owner_id(&self) -> WorkerOwnerId {
        new_manual_worker_owner_id(self)
    }
}

impl TestWorkerOwnerArg for &WorkerOwnerId {
    fn to_worker_owner_id(&self) -> WorkerOwnerId {
        (*self).clone()
    }
}

async fn claim_exact_jobs(
    queue: &Store,
    test_database: &TestDatabase,
    task_names: &[&str],
    expected_count: usize,
    worker_owner: impl TestWorkerOwnerArg,
) -> Result<Vec<paranoid::queue::Job>, Error> {
    let worker_owner_id = worker_owner.to_worker_owner_id();
    claim_exact_jobs_with_worker_owner_id(
        queue,
        test_database,
        task_names,
        expected_count,
        &worker_owner_id,
    )
    .await
}

async fn claim_exact_jobs_with_worker_owner_id(
    queue: &Store,
    test_database: &TestDatabase,
    task_names: &[&str],
    expected_count: usize,
    worker_owner_id: &WorkerOwnerId,
) -> Result<Vec<paranoid::queue::Job>, Error> {
    let registered_task_names = task_names
        .iter()
        .map(|task_name| (*task_name).to_owned())
        .collect::<Vec<_>>();
    let claimed = queue
        .begin_manual_worker_lifecycle()
        .claim_available_jobs_for_worker_owner(
            &test_database.paranoid_pool,
            &registered_task_names,
            expected_count.try_into().expect("expected count fits u32"),
            &worker_owner_id,
        )
        .await?;
    assert_eq!(claimed.len(), expected_count);
    Ok(claimed)
}

async fn enqueue_and_claim_one(
    queue: &Store,
    test_database: &TestDatabase,
    task_name: &str,
    payload_value: i32,
    worker_owner: impl TestWorkerOwnerArg,
) -> paranoid::queue::JobId {
    let worker_owner_id = worker_owner.to_worker_owner_id();
    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            task_name,
            &TestPayload {
                value: payload_value,
            },
            EnqueueOptions {
                run_at_or_after: Some(
                    JobRunAtOrAfter::from_unix_microseconds(0).expect("scheduled run time"),
                ),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue job to claim");
    claim_exact_jobs_with_worker_owner_id(queue, test_database, &[task_name], 1, &worker_owner_id)
        .await
        .expect("claim one job");
    enqueued.job_id
}

async fn fail_new_job(
    queue: &Store,
    test_database: &TestDatabase,
    task_name: &str,
    payload_value: i32,
    worker_owner: impl TestWorkerOwnerArg,
) -> paranoid::queue::JobId {
    let worker_owner_id = worker_owner.to_worker_owner_id();
    let enqueued = queue
        .enqueue_json(
            &test_database.paranoid_pool,
            task_name,
            &TestPayload {
                value: payload_value,
            },
            EnqueueOptions {
                run_at_or_after: Some(
                    JobRunAtOrAfter::from_unix_microseconds(0).expect("scheduled run time"),
                ),
                ..EnqueueOptions::default()
            },
        )
        .await
        .expect("enqueue job to fail");
    claim_exact_jobs_with_worker_owner_id(queue, test_database, &[task_name], 1, &worker_owner_id)
        .await
        .expect("claim job to fail");
    let job_id = enqueued.job_id;
    queue
        .begin_manual_worker_lifecycle()
        .mark_owned_running_job_failed(
            &test_database.paranoid_pool,
            job_id,
            &worker_owner_id,
            "failure for test",
            true,
        )
        .await
        .expect("fail job");
    job_id
}

fn fixed_retry_worker_config(fixed_backoff: Duration, dead_letter_enabled: bool) -> WorkerConfig {
    WorkerConfig {
        concurrency: 10,
        startup_jitter_max_delay: Some(Duration::ZERO),
        default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
        retry_policy: RetryPolicy {
            strategy: RetryBackoffStrategy::Fixed {
                backoff: fixed_backoff,
            },
            jitter_fraction: 0.0,
            ..RetryPolicy::default()
        },
        dead_letter_enabled,
        ..WorkerConfig::default()
    }
}

async fn set_job_finished_age(
    test_database: &TestDatabase,
    job_id: paranoid::queue::JobId,
    age: Duration,
) {
    let statement = format!(
        r#"
        UPDATE {}
        SET finished_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            updated_at = statement_timestamp()
        WHERE id = $1
        "#,
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(job_id.as_bytes())
        .bind(i64::try_from(age.as_micros()).expect("test age should fit into signed microseconds"))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("set job finished age");
}

async fn set_running_job_staleness(
    test_database: &TestDatabase,
    job_id: paranoid::queue::JobId,
    claimed_age: Duration,
    execution_started_age: Option<Duration>,
    execution_heartbeat_age: Duration,
    retry_count: i32,
    max_retries: i32,
) {
    let statement = format!(
        r#"
        UPDATE {}
        SET claimed_by_worker_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            execution_started_at = CASE
                WHEN $3::bigint IS NULL THEN NULL
                ELSE statement_timestamp() - ($3::bigint * INTERVAL '1 microsecond')
            END,
            execution_heartbeat_at = statement_timestamp() - ($4::bigint * INTERVAL '1 microsecond'),
            retry_count = $5,
            max_retries = $6,
            updated_at = statement_timestamp()
        WHERE id = $1
        "#,
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(job_id.as_bytes())
        .bind(duration_microseconds_for_test(claimed_age))
        .bind(execution_started_age.map(duration_microseconds_for_test))
        .bind(duration_microseconds_for_test(execution_heartbeat_age))
        .bind(retry_count)
        .bind(max_retries)
        .execute(&test_database.sqlx_pool)
        .await
        .expect("set running job staleness");
}

async fn set_job_retry_counts(
    test_database: &TestDatabase,
    job_id: paranoid::queue::JobId,
    retry_count: i32,
    max_retries: i32,
) {
    let statement = format!(
        r#"
        UPDATE {}
        SET retry_count = $2, max_retries = $3, updated_at = statement_timestamp()
        WHERE id = $1
        "#,
        test_database.config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(job_id.as_bytes())
        .bind(retry_count)
        .bind(max_retries)
        .execute(&test_database.sqlx_pool)
        .await
        .expect("set job retry counts");
}

fn assert_payload_json_value(payload_json: &str, expected_value: i32) {
    let payload: TestPayload =
        serde_json::from_str(payload_json).expect("payload JSON should decode");
    assert_eq!(payload.value, expected_value);
}

async fn set_dead_letter_age(
    test_database: &TestDatabase,
    dead_letter_job_id: paranoid::queue::JobId,
    age: Duration,
) {
    let statement = format!(
        r#"
        UPDATE {}
        SET dead_lettered_at = statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond'),
            updated_at = statement_timestamp()
        WHERE id = $1
        "#,
        test_database.config.dead_letter_table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(dead_letter_job_id.as_bytes())
        .bind(i64::try_from(age.as_micros()).expect("test age should fit into signed microseconds"))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("set dead-letter age");
}

fn duration_microseconds_for_test(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).expect("test duration should fit into signed microseconds")
}

async fn fetch_has_active_dedupe_unique_index(pool: &PgPool, config: &StoreConfig) -> bool {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index AS idx
            JOIN pg_class AS cls ON cls.oid = idx.indrelid
            JOIN pg_namespace AS ns ON ns.oid = cls.relnamespace
            WHERE ns.nspname = COALESCE($1, current_schema())
              AND cls.relname = $2
              AND idx.indisunique
              AND pg_get_indexdef(idx.indexrelid) LIKE '%WHERE ((dedupe_key IS NOT NULL) AND (status = ANY%'
        )
        "#,
    )
    .bind(config.table_name.schema().map(|schema| schema.as_str()))
    .bind(config.table_name.table().as_str())
    .fetch_one(pool)
    .await
    .expect("fetch active dedupe index")
}

async fn fetch_active_dedupe_index_name(pool: &PgPool, config: &StoreConfig) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT index_cls.relname
        FROM pg_index AS idx
        JOIN pg_class AS table_cls ON table_cls.oid = idx.indrelid
        JOIN pg_class AS index_cls ON index_cls.oid = idx.indexrelid
        JOIN pg_namespace AS ns ON ns.oid = table_cls.relnamespace
        WHERE ns.nspname = COALESCE($1, current_schema())
          AND table_cls.relname = $2
          AND idx.indisunique
          AND pg_get_indexdef(idx.indexrelid) LIKE '%WHERE ((dedupe_key IS NOT NULL) AND (status = ANY%'
        LIMIT 1
        "#,
    )
    .bind(config.table_name.schema().map(|schema| schema.as_str()))
    .bind(config.table_name.table().as_str())
    .fetch_one(pool)
    .await
    .expect("fetch active dedupe index name")
}

async fn fetch_queue_index_name_containing(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    index_definition_fragment: &str,
) -> String {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT index_cls.relname
        FROM pg_index AS idx
        JOIN pg_class AS table_cls ON table_cls.oid = idx.indrelid
        JOIN pg_class AS index_cls ON index_cls.oid = idx.indexrelid
        JOIN pg_namespace AS ns ON ns.oid = table_cls.relnamespace
        WHERE ns.nspname = COALESCE($1, current_schema())
          AND table_cls.relname = $2
          AND pg_get_indexdef(idx.indexrelid) LIKE '%' || $3 || '%'
        ORDER BY index_cls.relname
        LIMIT 1
        "#,
    )
    .bind(table_name.schema().map(|schema| schema.as_str()))
    .bind(table_name.table().as_str())
    .bind(index_definition_fragment)
    .fetch_one(pool)
    .await
    .expect("fetch queue index name")
}
