use super::*;

#[tokio::test]
async fn queue_migration_creates_schema_that_validation_accepts() {
    let test_database = TestDatabase::connect().await;

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("migrate queue schema");
    migrate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("second migrate queue schema");
    validate_schema(&test_database.paranoid_pool, &test_database.config)
        .await
        .expect("validate queue schema");
    assert_eq!(
        fetch_schema_ledger_fingerprint(
            &test_database.sqlx_pool,
            &test_database.config.schema_ledger_table_name,
            "queue",
            &format!(
                "jobs_table={};dead_letter_table={};pause_table={}",
                test_database.config.table_name.quoted(),
                test_database.config.dead_letter_table_name.quoted(),
                test_database.config.pause_table_name.quoted()
            ),
        )
        .await,
        Some("paranoid.queue.v1".to_owned())
    );

    assert!(fetch_table_exists(&test_database.sqlx_pool, &test_database.config.table_name).await);
    assert!(
        fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.dead_letter_table_name,
        )
        .await
    );
    assert!(
        fetch_table_exists(
            &test_database.sqlx_pool,
            &test_database.config.pause_table_name
        )
        .await
    );
    assert!(
        fetch_has_active_dedupe_unique_index(&test_database.sqlx_pool, &test_database.config).await
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn queue_migration_rejects_future_schema_ledger_row_before_current_schema_ddl() {
    let test_database = TestDatabase::connect().await;

    let mut config = unique_test_config();
    config.schema_ledger_table_name = PgQualifiedTableName::unqualified(format!(
        "__queue_test_schema_ledger_{}",
        crate::queue::JobId::new()
            .expect("new job id")
            .to_string()
            .replace('-', "_")
    ))
    .expect("schema ledger table");
    drop_queue_test_tables(&test_database.sqlx_pool, &config).await;
    drop_test_table(&test_database.sqlx_pool, &config.schema_ledger_table_name).await;
    migrate_schema(&test_database.paranoid_pool, &config)
        .await
        .expect("migrate queue schema");

    let instance_key = format!(
        "jobs_table={};dead_letter_table={};pause_table={}",
        config.table_name.quoted(),
        config.dead_letter_table_name.quoted(),
        config.pause_table_name.quoted()
    );
    overwrite_schema_ledger_version_and_fingerprint(
        &test_database.sqlx_pool,
        &config.schema_ledger_table_name,
        "queue",
        &instance_key,
        2,
        "paranoid.queue.v2",
    )
    .await;
    drop_queue_test_tables(&test_database.sqlx_pool, &config).await;

    let err = migrate_schema(&test_database.paranoid_pool, &config)
        .await
        .expect_err("migration should reject a future Queue schema ledger row");
    let message = err.to_string();
    assert!(
        matches!(
            err,
            Error::Database(crate::db::Error::SchemaMismatch { .. })
        ),
        "error = {err:?}"
    );
    assert!(
        message.contains("newer than supported"),
        "error message should describe the future schema version: {message}"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "migration must reject the future ledger row before recreating the current Queue jobs table"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.dead_letter_table_name).await,
        "migration must reject the future ledger row before recreating the current Queue dead-letter table"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.pause_table_name).await,
        "migration must reject the future ledger row before recreating the current Queue pause table"
    );

    drop_test_table(&test_database.sqlx_pool, &config.schema_ledger_table_name).await;
}

async fn fetch_schema_ledger_fingerprint(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
) -> Option<String> {
    let statement = format!(
        "SELECT schema_fingerprint FROM {} WHERE component = $1 AND instance_key = $2",
        table_name.quoted()
    );
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(component)
        .bind(instance_key)
        .fetch_optional(pool)
        .await
        .expect("fetch schema ledger fingerprint")
}

async fn overwrite_schema_ledger_version_and_fingerprint(
    pool: &PgPool,
    table_name: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
    version: i32,
    fingerprint: &str,
) {
    let statement = format!(
        "UPDATE {} SET schema_version = $1, schema_fingerprint = $2 WHERE component = $3 AND instance_key = $4",
        table_name.quoted()
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(version)
        .bind(fingerprint)
        .bind(component)
        .bind(instance_key)
        .execute(pool)
        .await
        .expect("overwrite schema ledger version and fingerprint")
        .rows_affected();
    assert_eq!(rows, 1, "schema ledger row should exist before overwrite");
}

#[tokio::test]
async fn queue_migration_in_current_transaction_is_usable_before_commit_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let config = unique_test_config();
    let queue = Store::new(config.clone()).expect("queue");
    drop_queue_test_tables(&test_database.sqlx_pool, &config).await;

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    migrate_schema_in_current_transaction(&mut rollback_tx, &config)
        .await
        .expect("migrate queue schema in transaction");
    queue
        .enqueue_json_in_current_transaction(
            &mut rollback_tx,
            "task.alpha",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue in rollback transaction");
    rollback_tx.rollback().await.expect("rollback transaction");
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "rolled-back queue migration should leave no table behind"
    );

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit transaction");
    migrate_schema_in_current_transaction(&mut commit_tx, &config)
        .await
        .expect("migrate queue schema in commit transaction");
    let result = queue
        .enqueue_json_in_current_transaction(
            &mut commit_tx,
            "task.alpha",
            &TestPayload { value: 2 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue in commit transaction");
    let batch_results = queue
        .enqueue_json_batch_in_current_transaction(
            &mut commit_tx,
            "task.alpha",
            &[TestPayload { value: 3 }, TestPayload { value: 4 }],
            EnqueueBatchOptions::default(),
        )
        .await
        .expect("batch enqueue in commit transaction");
    commit_tx.commit().await.expect("commit transaction");

    let job = queue
        .fetch_job_by_id(&test_database.paranoid_pool, result.job_id)
        .await
        .expect("fetch committed job");
    assert_eq!(job.status, JobStatus::Pending);
    assert_eq!(job.task_name, "task.alpha");
    assert_eq!(batch_results.len(), 2);
    let pending_count = queue
        .fetch_pending_job_count(&test_database.paranoid_pool, Some("task.alpha"))
        .await
        .expect("pending count after committed transaction");
    assert_eq!(pending_count, 3);

    drop_queue_test_tables(&test_database.sqlx_pool, &config).await;
}

#[tokio::test]
async fn queue_public_migration_rolls_back_created_tables_when_late_validation_fails() {
    let test_database = TestDatabase::connect().await;

    let config = unique_test_config();
    drop_queue_test_tables(&test_database.sqlx_pool, &config).await;
    let create_bad_jobs_table = format!(
        "CREATE TABLE {} (id BYTEA PRIMARY KEY)",
        config.table_name.quoted()
    );
    sqlx::query(sqlx::AssertSqlSafe(create_bad_jobs_table.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("create incompatible jobs table");

    migrate_schema(&test_database.paranoid_pool, &config)
        .await
        .expect_err("incompatible pre-existing jobs table should make migration fail");

    assert!(
        fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await,
        "the pre-existing incompatible jobs table is outside the migration transaction"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.dead_letter_table_name).await,
        "dead-letter table created during the failed migration must roll back"
    );
    assert!(
        !fetch_table_exists(&test_database.sqlx_pool, &config.pause_table_name).await,
        "pause table created during the failed migration must roll back"
    );

    drop_queue_test_tables(&test_database.sqlx_pool, &config).await;
}

#[tokio::test]
async fn queue_schema_qualified_table_names_are_migrated_and_used_without_public_schema_bleed() {
    let test_database = TestDatabase::connect().await;

    let suffix = crate::queue::JobId::new()
        .expect("new job id")
        .to_string()
        .replace('-', "_");
    let schema_name =
        PgIdentifier::new(format!("__queue_test_schema_{suffix}")).expect("schema name");
    let jobs_table = format!("__queue_test_jobs_{suffix}");
    let dead_letter_table = format!("__queue_test_dead_{suffix}");
    let pause_table = format!("__queue_test_pause_{suffix}");
    let config = StoreConfig::new(
        PgQualifiedTableName::with_schema(schema_name.as_str(), &jobs_table)
            .expect("schema-qualified jobs table"),
        PgQualifiedTableName::with_schema(schema_name.as_str(), &dead_letter_table)
            .expect("schema-qualified dead-letter table"),
        PgQualifiedTableName::with_schema(schema_name.as_str(), &pause_table)
            .expect("schema-qualified pause table"),
    )
    .expect("schema-qualified queue config");
    let drop_schema = format!("DROP SCHEMA IF EXISTS {} CASCADE", schema_name.quoted());
    sqlx::query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop stale schema");
    let create_schema = format!("CREATE SCHEMA {}", schema_name.quoted());
    sqlx::query(sqlx::AssertSqlSafe(create_schema.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("create schema");

    let queue = Store::new(config.clone()).expect("queue");
    migrate_schema(&test_database.paranoid_pool, &config)
        .await
        .expect("migrate schema-qualified queue");
    queue
        .enqueue_json(
            &test_database.paranoid_pool,
            "task.schema",
            &TestPayload { value: 1 },
            EnqueueOptions::default(),
        )
        .await
        .expect("enqueue into schema-qualified queue");

    assert!(fetch_table_exists(&test_database.sqlx_pool, &config.table_name).await);
    assert!(fetch_table_exists(&test_database.sqlx_pool, &config.dead_letter_table_name,).await);
    assert!(fetch_table_exists(&test_database.sqlx_pool, &config.pause_table_name).await);
    assert!(
        !fetch_table_exists(
            &test_database.sqlx_pool,
            &PgQualifiedTableName::unqualified(&jobs_table).expect("unqualified jobs table"),
        )
        .await
    );
    assert_eq!(
        fetch_queue_table_row_count(&test_database.sqlx_pool, &config.table_name).await,
        1
    );

    sqlx::query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(&test_database.sqlx_pool)
        .await
        .expect("drop schema");
}
