use crate::db::{
    DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName, Tx,
    normalize_check_constraint_expression, pooler_safe_query_as, pooler_safe_query_scalar,
    unparameterized_simple_query,
};

use super::postgres_store::PostgresAuthMethodCommitError;

pub(crate) const METHOD_SCHEMA_BYTEWISE_TEXT_COLLATIONS: &[&str] = &["C", "POSIX"];
pub(crate) const METHOD_SCHEMA_NO_COLLATIONS: &[&str] = &[];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MethodTableColumnContract {
    name: &'static str,
    data_type: &'static str,
    not_null: bool,
    allowed_collations: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MethodTableCheckConstraint {
    name_suffix: &'static str,
    expression: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MethodTableIndexContract {
    description: &'static str,
    unique: bool,
    columns: Vec<&'static str>,
    predicate: Option<String>,
}

impl MethodTableColumnContract {
    pub(crate) const fn bytea(name: &'static str, not_null: bool) -> Self {
        Self {
            name,
            data_type: "bytea",
            not_null,
            allowed_collations: METHOD_SCHEMA_NO_COLLATIONS,
        }
    }

    pub(crate) const fn bigint(name: &'static str, not_null: bool) -> Self {
        Self {
            name,
            data_type: "bigint",
            not_null,
            allowed_collations: METHOD_SCHEMA_NO_COLLATIONS,
        }
    }

    pub(crate) const fn text_collate_c(name: &'static str, not_null: bool) -> Self {
        Self {
            name,
            data_type: "text",
            not_null,
            allowed_collations: METHOD_SCHEMA_BYTEWISE_TEXT_COLLATIONS,
        }
    }
}

impl MethodTableCheckConstraint {
    pub(crate) fn new(name_suffix: &'static str, expression: impl Into<String>) -> Self {
        Self {
            name_suffix,
            expression: expression.into(),
        }
    }

    pub(crate) fn expression(&self) -> &str {
        &self.expression
    }
}

impl MethodTableIndexContract {
    pub(crate) fn unique(
        description: &'static str,
        columns: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Self {
            description,
            unique: true,
            columns: columns.into_iter().collect(),
            predicate: None,
        }
    }

    pub(crate) fn nonunique_partial(
        description: &'static str,
        columns: impl IntoIterator<Item = &'static str>,
        predicate: impl Into<String>,
    ) -> Self {
        Self {
            description,
            unique: false,
            columns: columns.into_iter().collect(),
            predicate: Some(predicate.into()),
        }
    }
}

pub(crate) async fn ensure_method_table_check_constraints_in_current_transaction(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
    checks: &[MethodTableCheckConstraint],
) -> Result<(), PostgresAuthMethodCommitError> {
    let existing_checks = fetch_normalized_check_constraint_expressions(tx, table).await?;
    for check in checks {
        let required = normalize_method_check_constraint_expression(check.expression());
        if existing_checks
            .iter()
            .any(|existing_check| existing_check == &required)
        {
            continue;
        }

        let constraint_name = method_check_constraint_name(table, check.name_suffix)?;
        let statement = format!(
            "ALTER TABLE {} ADD CONSTRAINT {} CHECK ({})",
            table.quoted(),
            constraint_name.quoted(),
            check.expression()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.method_schema.add_check_constraint",
            Some(statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}

pub(crate) async fn validate_method_table_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
    columns: &[MethodTableColumnContract],
    checks: &[MethodTableCheckConstraint],
    indexes: &[MethodTableIndexContract],
) -> Result<(), PostgresAuthMethodCommitError> {
    validate_method_table_columns(tx, table, columns).await?;
    validate_method_table_check_constraints(tx, table, checks).await?;
    validate_method_table_indexes(tx, table, indexes).await
}

async fn validate_method_table_columns(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
    required_columns: &[MethodTableColumnContract],
) -> Result<(), PostgresAuthMethodCommitError> {
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
        "auth_core.method_schema.validate_columns",
        Some(statement),
    );
    let actual_columns = pooler_safe_query_as::<(String, String, bool, Option<String>)>(statement)
        .bind(table.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    if actual_columns.is_empty() {
        return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
            "missing auth method table {}",
            table.quoted()
        )));
    }

    for (actual_column, ..) in &actual_columns {
        if !required_columns
            .iter()
            .any(|required| required.name == actual_column)
        {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} has unexpected column {:?}",
                table.quoted(),
                actual_column
            )));
        }
    }

    for required in required_columns {
        let Some((_, actual_type, actual_not_null, actual_collation)) = actual_columns
            .iter()
            .find(|(column_name, ..)| column_name == required.name)
        else {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} is missing column {:?}",
                table.quoted(),
                required.name
            )));
        };
        if actual_type != required.data_type {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} column {:?} has type {:?}, expected {:?}",
                table.quoted(),
                required.name,
                actual_type,
                required.data_type
            )));
        }
        if *actual_not_null != required.not_null {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} column {:?} nullability does not match contract",
                table.quoted(),
                required.name
            )));
        }
        if !required.allowed_collations.is_empty()
            && !required
                .allowed_collations
                .contains(&actual_collation.as_deref().unwrap_or(""))
        {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} column {:?} uses collation {:?}, expected one of {:?}",
                table.quoted(),
                required.name,
                actual_collation,
                required.allowed_collations
            )));
        }
    }
    Ok(())
}

async fn validate_method_table_check_constraints(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
    required_checks: &[MethodTableCheckConstraint],
) -> Result<(), PostgresAuthMethodCommitError> {
    let actual_checks = fetch_normalized_check_constraint_expressions(tx, table).await?;
    for required in required_checks {
        let required_expression =
            normalize_method_check_constraint_expression(required.expression());
        if !actual_checks
            .iter()
            .any(|actual_check| actual_check == &required_expression)
        {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} must enforce CHECK ({})",
                table.quoted(),
                required.expression()
            )));
        }
    }
    Ok(())
}

async fn validate_method_table_indexes(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
    required_indexes: &[MethodTableIndexContract],
) -> Result<(), PostgresAuthMethodCommitError> {
    let statement = r#"
        SELECT
            ARRAY(
                SELECT attr.attname
                FROM unnest(idx.indkey) WITH ORDINALITY AS key(attnum, ordinality)
                JOIN pg_attribute attr
                  ON attr.attrelid = idx.indrelid
                 AND attr.attnum = key.attnum
                 AND NOT attr.attisdropped
                WHERE key.ordinality <= idx.indnkeyatts
                ORDER BY key.ordinality
            ) AS columns,
            idx.indisunique,
            pg_get_expr(idx.indpred, idx.indrelid) AS predicate
        FROM pg_index idx
        WHERE idx.indrelid = to_regclass($1)
          AND idx.indisvalid
          AND idx.indexprs IS NULL
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.method_schema.validate_indexes",
        Some(statement),
    );
    let actual_indexes = pooler_safe_query_as::<(Vec<String>, bool, Option<String>)>(statement)
        .bind(table.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;

    for required in required_indexes {
        let required_columns = required
            .columns
            .iter()
            .map(|column| column.to_string())
            .collect::<Vec<_>>();
        let required_predicate = required
            .predicate
            .as_deref()
            .map(normalize_method_check_constraint_expression);
        if !actual_indexes.iter().any(|actual| {
            actual.0 == required_columns
                && actual.1 == required.unique
                && actual
                    .2
                    .as_deref()
                    .map(normalize_method_check_constraint_expression)
                    == required_predicate
        }) {
            return Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
                "auth method table {} is missing {} index over ({})",
                table.quoted(),
                required.description,
                required.columns.join(", ")
            )));
        }
    }
    Ok(())
}

async fn fetch_normalized_check_constraint_expressions(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
) -> Result<Vec<String>, PostgresAuthMethodCommitError> {
    let statement = r#"
        SELECT pg_get_expr(con.conbin, con.conrelid)
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND con.convalidated
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.method_schema.validate_check_constraints",
        Some(statement),
    );
    let checks = pooler_safe_query_scalar::<String>(statement)
        .bind(table.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|check| normalize_method_check_constraint_expression(&check))
        .collect();
    Ok(checks)
}

fn method_check_constraint_name(
    table: &PgQualifiedTableName,
    suffix: &str,
) -> Result<PgIdentifier, PostgresAuthMethodCommitError> {
    PgIdentifier::new(format!("{}_{}", table.table().as_str(), suffix))
        .map_err(DbError::from)
        .map_err(PostgresAuthMethodCommitError::Database)
}

fn normalize_method_check_constraint_expression(expression: &str) -> String {
    normalize_check_constraint_expression(expression)
        .chars()
        .filter(|character| *character != '"' && *character != '(' && *character != ')')
        .collect::<String>()
        .to_ascii_lowercase()
}

pub(crate) fn quoted_len_at_least_one_and_at_most(column: &str, max_bytes: usize) -> String {
    format!(r#"octet_length("{column}") >= 1 AND octet_length("{column}") <= {max_bytes}"#)
}

pub(crate) fn quoted_len_equals(column: &str, exact_bytes: usize) -> String {
    format!(r#"octet_length("{column}") = {exact_bytes}"#)
}

pub(crate) fn quoted_bigint_positive(column: &str) -> String {
    format!(r#""{column}" > 0"#)
}

pub(crate) fn quoted_bigint_nonnegative(column: &str) -> String {
    format!(r#""{column}" >= 0"#)
}

pub(crate) fn quoted_nullable_bigint_nonnegative(column: &str) -> String {
    format!(r#""{column}" IS NULL OR "{column}" >= 0"#)
}

pub(crate) fn quoted_nullable_len_equals(column: &str, exact_bytes: usize) -> String {
    format!(r#""{column}" IS NULL OR octet_length("{column}") = {exact_bytes}"#)
}

pub(crate) fn quoted_null_pair_matches(left: &str, right: &str) -> String {
    format!(r#"("{left}" IS NULL) = ("{right}" IS NULL)"#)
}
