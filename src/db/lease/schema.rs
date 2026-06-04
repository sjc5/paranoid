use super::*;
use crate::db::normalize_check_constraint_expression;
use sqlx::{Executor, Postgres};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequiredColumn {
    column: LeaseColumn,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActualColumn {
    name: String,
    data_type: String,
    not_null: bool,
    collation: Option<String>,
}

/// Creates and validates the configured lease schema inside one transaction.
#[cfg(test)]
pub(crate) async fn migrate_schema(pool: &WritePool, config: &StoreConfig) -> Result<(), DbError> {
    validate_distinct_table_names(config)?;
    let mut tx = pool.begin_transaction().await?;
    let result = migrate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_transaction(LEASE_OPERATION_SCHEMA_MIGRATE, tx, result).await
}

/// Creates and validates the configured lease schema inside the caller's transaction.
pub(crate) async fn migrate_schema_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    validate_distinct_table_names(config)?;
    for statement in build_migrate_statements(config) {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            LEASE_OPERATION_SCHEMA_MIGRATE_STATEMENT,
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?;
    }

    validate_schema_in_current_transaction(tx, config).await
}

/// Validates that the configured lease schema already exists and is compatible.
#[cfg(test)]
pub(crate) async fn validate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), DbError> {
    validate_distinct_table_names(config)?;
    let mut tx = pool.begin_transaction().await?;
    let validation_result = validate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_validation_transaction(LEASE_OPERATION_SCHEMA_VALIDATE, tx, validation_result)
        .await
}

pub(super) async fn validate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    validate_distinct_table_names(config)?;
    let quoted_table_name = config.table_name.quoted().to_string();
    let required_state_columns = required_state_columns();
    let observer = tx.database_operation_observer().cloned();
    validate_required_columns(
        tx.inner.as_mut(),
        observer.as_ref(),
        &quoted_table_name,
        &required_state_columns,
    )
    .await?;
    validate_key_conflict_arbiter(tx.inner.as_mut(), observer.as_ref(), &quoted_table_name).await?;
    validate_required_state_check_constraints(
        tx.inner.as_mut(),
        observer.as_ref(),
        &quoted_table_name,
    )
    .await?;
    validate_expires_at_index(
        tx.inner.as_mut(),
        observer.as_ref(),
        config,
        &quoted_table_name,
    )
    .await?;

    let quoted_fencing_counter_table_name = config.fencing_counter_table_name.quoted().to_string();
    let required_fencing_counter_columns = required_fencing_counter_columns();
    validate_required_columns(
        tx.inner.as_mut(),
        observer.as_ref(),
        &quoted_fencing_counter_table_name,
        &required_fencing_counter_columns,
    )
    .await?;
    validate_key_conflict_arbiter(
        tx.inner.as_mut(),
        observer.as_ref(),
        &quoted_fencing_counter_table_name,
    )
    .await?;
    validate_required_fencing_counter_check_constraints(
        tx.inner.as_mut(),
        observer.as_ref(),
        &quoted_fencing_counter_table_name,
    )
    .await
}

pub(super) fn validate_distinct_table_names(config: &StoreConfig) -> Result<(), DbError> {
    if pg_table_name_set_could_contain_same_relation(&[
        &config.table_name,
        &config.fencing_counter_table_name,
    ]) {
        return Err(DbError::schema_mismatch(
            "lease state and fencing counter table names must be distinct",
        ));
    }
    Ok(())
}

async fn validate_required_columns<'e, E>(
    executor: E,
    observer: Option<&DatabaseOperationObserver>,
    quoted_table_name: &str,
    required_columns: &[RequiredColumn],
) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let statement = r#"
        SELECT
            attr.attname,
            pg_catalog.format_type(attr.atttypid, attr.atttypmod),
            attr.attnotnull,
            coll.collname
        FROM pg_attribute attr
        LEFT JOIN pg_collation coll ON coll.oid = attr.attcollation
        WHERE attr.attrelid = to_regclass($1)
          AND attr.attnum > 0
          AND NOT attr.attisdropped
        "#;
    record_database_operation(
        observer,
        DatabaseOperationKind::FetchAll,
        LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS,
        Some(statement),
    );
    let actual_columns = pooler_safe_query_as::<(String, String, bool, Option<String>)>(statement)
        .bind(quoted_table_name)
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|(name, data_type, not_null, collation)| ActualColumn {
            name,
            data_type,
            not_null,
            collation,
        })
        .collect::<Vec<_>>();

    for required_column in required_columns {
        let required_column_name = required_column.column.name();
        let Some(actual_column) = actual_columns
            .iter()
            .find(|column| column.name == required_column_name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "required column {:?} not found on table {}",
                required_column_name, quoted_table_name
            )));
        };

        validate_required_column(quoted_table_name, *required_column, actual_column)?;
    }

    Ok(())
}

async fn validate_key_conflict_arbiter<'e, E>(
    executor: E,
    observer: Option<&DatabaseOperationObserver>,
    quoted_table_name: &str,
) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_attribute attr
              ON attr.attrelid = idx.indrelid
             AND attr.attname = $2
             AND NOT attr.attisdropped
            WHERE idx.indrelid = to_regclass($1)
              AND idx.indisunique
              AND idx.indisvalid
              AND idx.indimmediate
              AND idx.indnkeyatts = 1
              AND idx.indpred IS NULL
              AND idx.indexprs IS NULL
              AND idx.indkey[0] = attr.attnum
        )
        "#;
    record_database_operation(
        observer,
        DatabaseOperationKind::FetchOne,
        LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
        Some(statement),
    );
    let has_usable_unique_key = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .bind(LeaseColumn::Key.name())
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

    if !has_usable_unique_key {
        let key = LeaseColumn::Key.name();
        return Err(DbError::schema_mismatch(format!(
            r#"column "{key}" must have a unique or primary key constraint usable by ON CONFLICT ({key})"#
        )));
    }

    Ok(())
}

async fn fetch_normalized_check_constraint_expressions<'e, E>(
    executor: E,
    observer: Option<&DatabaseOperationObserver>,
    quoted_table_name: &str,
) -> Result<Vec<String>, DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let statement = r#"
        SELECT pg_get_expr(con.conbin, con.conrelid)
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND con.convalidated
        "#;
    record_database_operation(
        observer,
        DatabaseOperationKind::FetchAll,
        LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
        Some(statement),
    );
    let normalized_check_expressions = pooler_safe_query_scalar::<String>(statement)
        .bind(quoted_table_name)
        .fetch_all(executor)
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|expression| normalize_check_constraint_expression(&expression))
        .collect::<Vec<String>>();

    Ok(normalized_check_expressions)
}

async fn validate_required_state_check_constraints<'e, E>(
    executor: E,
    observer: Option<&DatabaseOperationObserver>,
    quoted_table_name: &str,
) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let normalized_check_expressions =
        fetch_normalized_check_constraint_expressions(executor, observer, quoted_table_name)
            .await?;

    for column in LEASE_STATE_CHECKED_COLUMNS {
        validate_required_check_constraint(
            quoted_table_name,
            &normalized_check_expressions,
            column,
        )?;
    }

    Ok(())
}

async fn validate_required_fencing_counter_check_constraints<'e, E>(
    executor: E,
    observer: Option<&DatabaseOperationObserver>,
    quoted_table_name: &str,
) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let normalized_check_expressions =
        fetch_normalized_check_constraint_expressions(executor, observer, quoted_table_name)
            .await?;

    for column in LEASE_FENCING_COUNTER_CHECKED_COLUMNS {
        validate_required_check_constraint(
            quoted_table_name,
            &normalized_check_expressions,
            column,
        )?;
    }

    Ok(())
}

fn validate_required_check_constraint(
    quoted_table_name: &str,
    normalized_check_expressions: &[String],
    column: LeaseColumn,
) -> Result<(), DbError> {
    let required_expression = column
        .normalized_check_constraint()
        .expect("checked lease column must define a constraint");
    if normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_expression)
    {
        return Ok(());
    }

    let expected_check = column
        .human_check_constraint()
        .expect("checked lease column must define a constraint");
    Err(DbError::schema_mismatch(format!(
        "table {} must enforce CHECK ({})",
        quoted_table_name, expected_check
    )))
}

async fn validate_expires_at_index<'e, E>(
    executor: E,
    observer: Option<&DatabaseOperationObserver>,
    config: &StoreConfig,
    quoted_table_name: &str,
) -> Result<(), DbError>
where
    E: Executor<'e, Database = Postgres>,
{
    let expires_at = LeaseColumn::ExpiresAt.name();
    let index_name = migration_index_identifier(config, expires_at);
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_class index_class ON index_class.oid = idx.indexrelid
            JOIN pg_attribute attr
              ON attr.attrelid = idx.indrelid
             AND attr.attnum = idx.indkey[0]
             AND NOT attr.attisdropped
            WHERE idx.indrelid = to_regclass($1)
              AND index_class.relname = $2
              AND idx.indisvalid
              AND idx.indnkeyatts = 1
              AND idx.indpred IS NULL
              AND idx.indexprs IS NULL
              AND attr.attname = $3
        )
        "#;
    record_database_operation(
        observer,
        DatabaseOperationKind::FetchOne,
        LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .bind(index_name.as_str())
        .bind(expires_at)
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

    if !has_index {
        return Err(DbError::schema_mismatch(format!(
            "table {} must have {} index {:?}",
            quoted_table_name,
            expires_at,
            index_name.as_str()
        )));
    }

    Ok(())
}

fn validate_required_column(
    quoted_table_name: &str,
    required_column: RequiredColumn,
    actual_column: &ActualColumn,
) -> Result<(), DbError> {
    let column_name = required_column.column.name();
    let required_data_type = required_column.column.validation_type();
    let allowed_collations = required_column.column.allowed_collations();

    if actual_column.data_type != required_data_type {
        return Err(DbError::schema_mismatch(format!(
            "column {:?} on table {} must be type {:?}, got {:?}",
            column_name, quoted_table_name, required_data_type, actual_column.data_type
        )));
    }

    if !actual_column.not_null {
        let expected_nullability = "NOT NULL";
        let actual_nullability = if actual_column.not_null {
            "NOT NULL"
        } else {
            "NULL"
        };
        return Err(DbError::schema_mismatch(format!(
            "column {:?} on table {} must be {}, got {}",
            column_name, quoted_table_name, expected_nullability, actual_nullability
        )));
    }

    if !allowed_collations.is_empty() {
        let actual_collation = actual_column.collation.as_deref().unwrap_or("<none>");
        if !allowed_collations.contains(&actual_collation) {
            return Err(DbError::schema_mismatch(format!(
                "column {:?} on table {} must use one of collations {:?}, got {:?}",
                column_name, quoted_table_name, allowed_collations, actual_collation
            )));
        }
    }

    Ok(())
}

fn required_state_columns() -> [RequiredColumn; 6] {
    LEASE_STATE_COLUMNS.map(|column| RequiredColumn { column })
}

fn required_fencing_counter_columns() -> [RequiredColumn; 3] {
    LEASE_FENCING_COUNTER_COLUMNS.map(|column| RequiredColumn { column })
}

pub(super) fn build_migrate_statements(config: &StoreConfig) -> [String; 3] {
    [
        create_lease_table_statement(config),
        create_fencing_counter_table_statement(config),
        create_expires_at_index_statement(config),
    ]
}
