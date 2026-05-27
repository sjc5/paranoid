use super::{
    DatabaseOperationKind, DbError, PgQualifiedTableName, PgSqlState, Tx,
    normalize_check_constraint_expression, pooler_safe_query, pooler_safe_query_as,
    pooler_safe_query_scalar, sql_state_from_sqlx_error,
};

const SCHEMA_LEDGER_CREATE_SAVEPOINT: &str = "__paranoid_schema_ledger_create";
pub(crate) const SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT: &str = "schema_ledger.create_savepoint";
pub(crate) const SCHEMA_LEDGER_OPERATION_CREATE_TABLE: &str = "schema_ledger.create_table";
pub(crate) const SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT: &str =
    "schema_ledger.release_savepoint";
pub(crate) const SCHEMA_LEDGER_OPERATION_ROLLBACK_SAVEPOINT: &str =
    "schema_ledger.rollback_savepoint";
pub(crate) const SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS: &str = "schema_ledger.validate_columns";
pub(crate) const SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY: &str =
    "schema_ledger.validate_primary_key";
pub(crate) const SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS: &str =
    "schema_ledger.validate_check_constraints";
pub(crate) const SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION: &str =
    "schema_ledger.record_component_version";
pub(crate) const SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION: &str =
    "schema_ledger.fetch_component_version";

/// Default prefix reserved for Paranoid-owned Postgres objects.
pub const DEFAULT_RESERVED_DB_OBJECT_PREFIX: &str = "__paranoid_";

/// Default prefix reserved for Paranoid-owned KV keys.
pub const DEFAULT_RESERVED_KV_KEY_PREFIX: &str = "__paranoid";

/// Default table where Paranoid records current component schema versions.
pub const DEFAULT_SCHEMA_LEDGER_TABLE_NAME: &str = "__paranoid_schema_ledger";

pub(crate) const MAX_SCHEMA_LEDGER_COMPONENT_BYTES: usize = 128;
pub(crate) const MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES: usize = 1024;
pub(crate) const MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SchemaLedgerConfig {
    pub(crate) table_name: PgQualifiedTableName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ComponentSchemaVersion<'a> {
    pub(crate) component: &'a str,
    pub(crate) instance_key: &'a str,
    pub(crate) version: i32,
    pub(crate) fingerprint: &'a str,
}

impl Default for SchemaLedgerConfig {
    fn default() -> Self {
        Self {
            table_name: PgQualifiedTableName::unqualified(DEFAULT_SCHEMA_LEDGER_TABLE_NAME)
                .expect("default schema ledger table name must be valid"),
        }
    }
}

pub(crate) async fn record_component_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<(), DbError> {
    validate_component_schema_version(component_schema_version)?;
    execute_schema_ledger_migration_in_current_transaction(tx, table_name).await?;

    let statement = format!(
        r#"
        INSERT INTO {} (
            component,
            instance_key,
            schema_version,
            schema_fingerprint,
            applied_at
        )
        VALUES ($1, $2, $3, $4, statement_timestamp())
        ON CONFLICT (component, instance_key)
        DO NOTHING
        "#,
        table_name.quoted()
    );

    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION,
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(component_schema_version.component)
        .bind(component_schema_version.instance_key)
        .bind(component_schema_version.version)
        .bind(component_schema_version.fingerprint)
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    Ok(())
}

pub(crate) async fn validate_component_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<(), DbError> {
    validate_component_schema_version(component_schema_version)?;
    validate_schema_ledger_with_transaction(tx, table_name).await?;

    let statement = format!(
        r#"
        SELECT schema_version, schema_fingerprint
        FROM {}
        WHERE component = $1
          AND instance_key = $2
        "#,
        table_name.quoted()
    );

    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
        Some(statement.as_str()),
    );
    let actual = pooler_safe_query_as::<(i32, String)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(component_schema_version.component)
        .bind(component_schema_version.instance_key)
        .fetch_optional(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    let Some((actual_version, actual_fingerprint)) = actual else {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} was not found",
            component_schema_version.component, component_schema_version.instance_key
        )));
    };

    if actual_version != component_schema_version.version {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} recorded version {}, expected {}",
            component_schema_version.component,
            component_schema_version.instance_key,
            actual_version,
            component_schema_version.version
        )));
    }

    if actual_fingerprint != component_schema_version.fingerprint {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} recorded fingerprint {:?}, expected {:?}",
            component_schema_version.component,
            component_schema_version.instance_key,
            actual_fingerprint,
            component_schema_version.fingerprint
        )));
    }

    Ok(())
}

pub(crate) fn schema_instance_key_for_parts<'a, I>(parts: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a PgQualifiedTableName)>,
{
    parts
        .into_iter()
        .map(|(label, table_name)| format!("{label}={}", table_name.quoted()))
        .collect::<Vec<_>>()
        .join(";")
}

async fn execute_schema_ledger_migration_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
) -> Result<(), DbError> {
    let statement = build_create_schema_ledger_table_statement(table_name);
    execute_create_schema_ledger_table_statement_in_current_transaction(tx, &statement).await?;
    validate_schema_ledger_with_transaction_table(tx, table_name).await
}

async fn execute_create_schema_ledger_table_statement_in_current_transaction(
    tx: &mut Tx<'_>,
    statement: &str,
) -> Result<(), DbError> {
    execute_schema_ledger_static_statement(
        tx,
        SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT,
        &format!("SAVEPOINT {SCHEMA_LEDGER_CREATE_SAVEPOINT}"),
    )
    .await?;

    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
        Some(statement),
    );
    let create_result = pooler_safe_query(sqlx::AssertSqlSafe(statement))
        .execute(tx.inner.as_mut())
        .await;

    match create_result {
        Ok(_) => {
            execute_schema_ledger_static_statement(
                tx,
                SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
                &format!("RELEASE SAVEPOINT {SCHEMA_LEDGER_CREATE_SAVEPOINT}"),
            )
            .await
        }
        Err(error) if is_concurrent_schema_ledger_create_race(&error) => {
            execute_schema_ledger_static_statement(
                tx,
                SCHEMA_LEDGER_OPERATION_ROLLBACK_SAVEPOINT,
                &format!("ROLLBACK TO SAVEPOINT {SCHEMA_LEDGER_CREATE_SAVEPOINT}"),
            )
            .await?;
            execute_schema_ledger_static_statement(
                tx,
                SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
                &format!("RELEASE SAVEPOINT {SCHEMA_LEDGER_CREATE_SAVEPOINT}"),
            )
            .await
        }
        Err(error) => {
            let _ = execute_schema_ledger_static_statement(
                tx,
                SCHEMA_LEDGER_OPERATION_ROLLBACK_SAVEPOINT,
                &format!("ROLLBACK TO SAVEPOINT {SCHEMA_LEDGER_CREATE_SAVEPOINT}"),
            )
            .await;
            let _ = execute_schema_ledger_static_statement(
                tx,
                SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
                &format!("RELEASE SAVEPOINT {SCHEMA_LEDGER_CREATE_SAVEPOINT}"),
            )
            .await;
            Err(DbError::query(error))
        }
    }
}

async fn execute_schema_ledger_static_statement(
    tx: &mut Tx<'_>,
    label: &'static str,
    statement: &str,
) -> Result<(), DbError> {
    tx.record_database_operation(DatabaseOperationKind::Execute, label, Some(statement));
    pooler_safe_query(sqlx::AssertSqlSafe(statement))
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

fn is_concurrent_schema_ledger_create_race(error: &sqlx::Error) -> bool {
    match sql_state_from_sqlx_error(error) {
        Some(PgSqlState::UniqueViolation) => {
            error
                .as_database_error()
                .and_then(|database_error| database_error.constraint())
                == Some("pg_type_typname_nsp_index")
        }
        Some(PgSqlState::Other(code)) => code == "42P07" || code == "42710",
        _ => false,
    }
}

async fn validate_schema_ledger_with_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
) -> Result<(), DbError> {
    validate_schema_ledger_with_transaction_table(tx, table_name).await
}

async fn validate_schema_ledger_with_transaction_table(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
) -> Result<(), DbError> {
    let quoted_table_name = table_name.quoted().to_string();
    validate_schema_ledger_required_columns(tx, &quoted_table_name).await?;
    validate_schema_ledger_primary_key(tx, &quoted_table_name).await?;
    validate_schema_ledger_required_check_constraints(tx, &quoted_table_name).await
}

async fn validate_schema_ledger_required_columns(
    tx: &mut Tx<'_>,
    quoted_table_name: &str,
) -> Result<(), DbError> {
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
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
        Some(statement),
    );
    let actual_columns = pooler_safe_query_as::<(String, String, bool, Option<String>)>(statement)
        .bind(quoted_table_name)
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    for (name, expected_type, expected_not_null, expected_collation) in [
        ("component", "text", true, Some("C")),
        ("instance_key", "text", true, Some("C")),
        ("schema_version", "integer", true, None),
        ("schema_fingerprint", "text", true, Some("C")),
        ("applied_at", "timestamp with time zone", true, None),
    ] {
        let Some((_, actual_type, actual_not_null, actual_collation)) = actual_columns
            .iter()
            .find(|(column_name, ..)| column_name == name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "required column {:?} not found on schema ledger table {}",
                name, quoted_table_name
            )));
        };

        if actual_type != expected_type {
            return Err(DbError::schema_mismatch(format!(
                "schema ledger table {} column {:?} has type {:?}, expected {:?}",
                quoted_table_name, name, actual_type, expected_type
            )));
        }
        if *actual_not_null != expected_not_null {
            return Err(DbError::schema_mismatch(format!(
                "schema ledger table {} column {:?} has not-null {}, expected {}",
                quoted_table_name, name, actual_not_null, expected_not_null
            )));
        }
        if actual_collation.as_deref() != expected_collation {
            return Err(DbError::schema_mismatch(format!(
                "schema ledger table {} column {:?} has collation {:?}, expected {:?}",
                quoted_table_name,
                name,
                actual_collation.as_deref(),
                expected_collation
            )));
        }
    }

    Ok(())
}

async fn validate_schema_ledger_primary_key(
    tx: &mut Tx<'_>,
    quoted_table_name: &str,
) -> Result<(), DbError> {
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_attribute component_attr
              ON component_attr.attrelid = idx.indrelid
             AND component_attr.attname = 'component'
             AND NOT component_attr.attisdropped
            JOIN pg_attribute instance_attr
              ON instance_attr.attrelid = idx.indrelid
             AND instance_attr.attname = 'instance_key'
             AND NOT instance_attr.attisdropped
            WHERE idx.indrelid = to_regclass($1)
              AND idx.indisprimary
              AND idx.indisvalid
              AND idx.indimmediate
              AND idx.indnkeyatts = 2
              AND idx.indpred IS NULL
              AND idx.indexprs IS NULL
              AND idx.indkey[0] = component_attr.attnum
              AND idx.indkey[1] = instance_attr.attnum
        )
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
        Some(statement),
    );
    let has_primary_key = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_primary_key {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger table {} must have primary key (component, instance_key)",
            quoted_table_name
        )));
    }

    Ok(())
}

async fn validate_schema_ledger_required_check_constraints(
    tx: &mut Tx<'_>,
    quoted_table_name: &str,
) -> Result<(), DbError> {
    let statement = r#"
        SELECT pg_get_expr(con.conbin, con.conrelid)
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND con.convalidated
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS,
        Some(statement),
    );
    let normalized_check_expressions = pooler_safe_query_scalar::<String>(statement)
        .bind(quoted_table_name)
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|expression| normalize_check_constraint_expression(&expression))
        .collect::<Vec<String>>();

    for required_expression in [
        format!(
            "(octet_length(component)>0)AND(octet_length(component)<={MAX_SCHEMA_LEDGER_COMPONENT_BYTES})"
        ),
        format!(
            "(octet_length(instance_key)>0)AND(octet_length(instance_key)<={MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES})"
        ),
        "schema_version>0".to_owned(),
        format!(
            "(octet_length(schema_fingerprint)>0)AND(octet_length(schema_fingerprint)<={MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES})"
        ),
    ] {
        if !normalized_check_expressions
            .iter()
            .any(|expression| expression == &required_expression)
        {
            return Err(DbError::schema_mismatch(format!(
                "schema ledger table {} must enforce CHECK ({})",
                quoted_table_name, required_expression
            )));
        }
    }

    Ok(())
}

fn build_create_schema_ledger_table_statement(table_name: &PgQualifiedTableName) -> String {
    format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            component TEXT COLLATE "C" NOT NULL CHECK (
                octet_length(component) > 0
                AND octet_length(component) <= {MAX_SCHEMA_LEDGER_COMPONENT_BYTES}
            ),
            instance_key TEXT COLLATE "C" NOT NULL CHECK (
                octet_length(instance_key) > 0
                AND octet_length(instance_key) <= {MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES}
            ),
            schema_version INTEGER NOT NULL CHECK (schema_version > 0),
            schema_fingerprint TEXT COLLATE "C" NOT NULL CHECK (
                octet_length(schema_fingerprint) > 0
                AND octet_length(schema_fingerprint) <= {MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES}
            ),
            applied_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (component, instance_key)
        )
        "#,
        table_name.quoted()
    )
}

fn validate_component_schema_version(
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<(), DbError> {
    validate_bounded_nonempty_schema_ledger_text(
        "component",
        component_schema_version.component,
        MAX_SCHEMA_LEDGER_COMPONENT_BYTES,
    )?;
    validate_bounded_nonempty_schema_ledger_text(
        "instance_key",
        component_schema_version.instance_key,
        MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES,
    )?;
    validate_bounded_nonempty_schema_ledger_text(
        "schema_fingerprint",
        component_schema_version.fingerprint,
        MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES,
    )?;
    if component_schema_version.version <= 0 {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger version must be positive, got {}",
            component_schema_version.version
        )));
    }
    Ok(())
}

fn validate_bounded_nonempty_schema_ledger_text(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), DbError> {
    if value.is_empty() {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger {label} must not be empty"
        )));
    }
    if value.len() > max_bytes {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger {label} is {} bytes, maximum is {}",
            value.len(),
            max_bytes
        )));
    }
    if value.as_bytes().contains(&0) {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger {label} must not contain null bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn build_migrate_schema_ledger_statement_for_test(
    config: &SchemaLedgerConfig,
) -> String {
    build_create_schema_ledger_table_statement(&config.table_name)
}
