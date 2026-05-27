use super::*;
use crate::db::normalize_check_constraint_expression;
use sqlx::{Executor, Postgres};

const EXPIRES_AT_INDEX_SUFFIX: &str = "expires_at";
const CREATE_LEASE_TABLE_TEMPLATE_PREFIX: &str = "CREATE TABLE IF NOT EXISTS ";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequiredColumn {
    name: &'static str,
    data_type: &'static str,
    not_null: bool,
    allowed_collations: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActualColumn {
    name: String,
    data_type: String,
    not_null: bool,
    collation: Option<String>,
}

/// Creates and validates the configured lease schema inside one transaction.
pub async fn migrate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), DbError> {
    validate_distinct_table_names(config)?;
    let mut tx = pool.begin_transaction().await?;
    let result = migrate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_transaction(LEASE_OPERATION_SCHEMA_MIGRATE, tx, result).await
}

/// Creates and validates the configured lease schema inside the caller's transaction.
pub async fn migrate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
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
pub async fn validate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), DbError> {
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
        let Some(actual_column) = actual_columns
            .iter()
            .find(|column| column.name == required_column.name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "required column {:?} not found on table {}",
                required_column.name, quoted_table_name
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
             AND attr.attname = 'key'
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
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

    if !has_usable_unique_key {
        return Err(DbError::schema_mismatch(
            r#"column "key" must have a unique or primary key constraint usable by ON CONFLICT (key)"#,
        ));
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

    let required_key_length_expression =
        format!("(octet_length(key)>0)AND(octet_length(key)<={MAX_LEASE_KEY_BYTES})");
    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_key_length_expression)
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (octet_length(key) > 0 AND octet_length(key) <= {})"#,
            quoted_table_name, MAX_LEASE_KEY_BYTES
        )));
    }

    let required_holder_id_length_expression = format!(
        "(octet_length(holder_id)>0)AND(octet_length(holder_id)<={MAX_LEASE_HOLDER_ID_BYTES})"
    );
    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_holder_id_length_expression)
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= {})"#,
            quoted_table_name, MAX_LEASE_HOLDER_ID_BYTES
        )));
    }

    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == "fencing_token>0")
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (fencing_token > 0)"#,
            quoted_table_name
        )));
    }

    let required_token_length_expression = format!("octet_length(lease_token)={LEASE_TOKEN_BYTES}");
    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_token_length_expression)
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (octet_length(lease_token) = {})"#,
            quoted_table_name, LEASE_TOKEN_BYTES
        )));
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

    let required_key_length_expression =
        format!("(octet_length(key)>0)AND(octet_length(key)<={MAX_LEASE_KEY_BYTES})");
    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_key_length_expression)
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (octet_length(key) > 0 AND octet_length(key) <= {})"#,
            quoted_table_name, MAX_LEASE_KEY_BYTES
        )));
    }

    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == "last_fencing_token>0")
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (last_fencing_token > 0)"#,
            quoted_table_name
        )));
    }

    Ok(())
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
    let index_name = migration_index_identifier(config, EXPIRES_AT_INDEX_SUFFIX);
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
              AND attr.attname = 'expires_at'
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
        .fetch_one(executor)
        .await
        .map_err(DbError::query)?;

    if !has_index {
        return Err(DbError::schema_mismatch(format!(
            "table {} must have expires_at index {:?}",
            quoted_table_name,
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
    if actual_column.data_type != required_column.data_type {
        return Err(DbError::schema_mismatch(format!(
            "column {:?} on table {} must be type {:?}, got {:?}",
            required_column.name,
            quoted_table_name,
            required_column.data_type,
            actual_column.data_type
        )));
    }

    if actual_column.not_null != required_column.not_null {
        let expected_nullability = if required_column.not_null {
            "NOT NULL"
        } else {
            "NULL"
        };
        let actual_nullability = if actual_column.not_null {
            "NOT NULL"
        } else {
            "NULL"
        };
        return Err(DbError::schema_mismatch(format!(
            "column {:?} on table {} must be {}, got {}",
            required_column.name, quoted_table_name, expected_nullability, actual_nullability
        )));
    }

    if !required_column.allowed_collations.is_empty() {
        let actual_collation = actual_column.collation.as_deref().unwrap_or("<none>");
        if !required_column
            .allowed_collations
            .contains(&actual_collation)
        {
            return Err(DbError::schema_mismatch(format!(
                "column {:?} on table {} must use one of collations {:?}, got {:?}",
                required_column.name,
                quoted_table_name,
                required_column.allowed_collations,
                actual_collation
            )));
        }
    }

    Ok(())
}

fn required_state_columns() -> [RequiredColumn; 6] {
    [
        RequiredColumn {
            name: "key",
            data_type: "text",
            not_null: true,
            allowed_collations: &["C", "POSIX"],
        },
        RequiredColumn {
            name: "holder_id",
            data_type: "text",
            not_null: true,
            allowed_collations: &["C", "POSIX"],
        },
        RequiredColumn {
            name: "fencing_token",
            data_type: "bigint",
            not_null: true,
            allowed_collations: &[],
        },
        RequiredColumn {
            name: "lease_token",
            data_type: "bytea",
            not_null: true,
            allowed_collations: &[],
        },
        RequiredColumn {
            name: "expires_at",
            data_type: "timestamp with time zone",
            not_null: true,
            allowed_collations: &[],
        },
        RequiredColumn {
            name: "updated_at",
            data_type: "timestamp with time zone",
            not_null: true,
            allowed_collations: &[],
        },
    ]
}

fn required_fencing_counter_columns() -> [RequiredColumn; 3] {
    [
        RequiredColumn {
            name: "key",
            data_type: "text",
            not_null: true,
            allowed_collations: &["C", "POSIX"],
        },
        RequiredColumn {
            name: "last_fencing_token",
            data_type: "bigint",
            not_null: true,
            allowed_collations: &[],
        },
        RequiredColumn {
            name: "updated_at",
            data_type: "timestamp with time zone",
            not_null: true,
            allowed_collations: &[],
        },
    ]
}

pub(super) fn build_migrate_statements(config: &StoreConfig) -> [String; 3] {
    [
        build_create_table_statement(config),
        build_create_fencing_counter_table_statement(config),
        build_create_expires_at_index_statement(config),
    ]
}

fn build_create_table_statement(config: &StoreConfig) -> String {
    format!(
        r#"{CREATE_LEASE_TABLE_TEMPLATE_PREFIX}{} (
    key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= {MAX_LEASE_KEY_BYTES}),
    holder_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= {MAX_LEASE_HOLDER_ID_BYTES}),
    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
    lease_token BYTEA NOT NULL CHECK (octet_length(lease_token) = {LEASE_TOKEN_BYTES}),
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
        config.table_name.quoted()
    )
}

fn build_create_fencing_counter_table_statement(config: &StoreConfig) -> String {
    format!(
        r#"{CREATE_LEASE_TABLE_TEMPLATE_PREFIX}{} (
    key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= {MAX_LEASE_KEY_BYTES}),
    last_fencing_token BIGINT NOT NULL CHECK (last_fencing_token > 0),
    updated_at TIMESTAMPTZ NOT NULL
)"#,
        config.fencing_counter_table_name.quoted()
    )
}

fn build_create_expires_at_index_statement(config: &StoreConfig) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (expires_at)",
        migration_index_identifier(config, EXPIRES_AT_INDEX_SUFFIX).quoted(),
        config.table_name.quoted()
    )
}
