use super::{
    ComponentSchemaMigrationPlan, ComponentSchemaMigrationStep, DatabaseOperationKind, DbError,
    PgIdentifier, PgQualifiedTableName, PgSqlState, RecordedComponentSchemaVersion, Tx,
    normalize_check_constraint_expression, plan_component_schema_migration, pooler_safe_query,
    pooler_safe_query_as, pooler_safe_query_scalar, sql_state_from_sqlx_error,
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
pub(crate) const SCHEMA_LEDGER_OPERATION_UPDATE_COMPONENT_VERSION: &str =
    "schema_ledger.update_component_version";
pub(crate) const SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION: &str =
    "schema_ledger.fetch_component_version";

pub(crate) const MAX_SCHEMA_LEDGER_COMPONENT_BYTES: usize = 128;
pub(crate) const MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES: usize = 1024;
pub(crate) const MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES: usize = 256;
const SCHEMA_LEDGER_C_COLLATION: &str = "C";

const SCHEMA_LEDGER_REQUIRED_COLUMNS: [SchemaLedgerColumn; 5] = [
    SchemaLedgerColumn::Component,
    SchemaLedgerColumn::InstanceKey,
    SchemaLedgerColumn::SchemaVersion,
    SchemaLedgerColumn::SchemaFingerprint,
    SchemaLedgerColumn::AppliedAt,
];
const SCHEMA_LEDGER_PRIMARY_KEY_COLUMNS: [SchemaLedgerColumn; 2] = [
    SchemaLedgerColumn::Component,
    SchemaLedgerColumn::InstanceKey,
];
const SCHEMA_LEDGER_CHECKED_COLUMNS: [SchemaLedgerColumn; 4] = [
    SchemaLedgerColumn::Component,
    SchemaLedgerColumn::InstanceKey,
    SchemaLedgerColumn::SchemaVersion,
    SchemaLedgerColumn::SchemaFingerprint,
];

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SchemaLedgerConfig {
    pub(crate) table_name: PgQualifiedTableName,
}

/// Current schema version identity for one component schema instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentSchemaVersion<'a> {
    /// Stable component name, such as `paranoid.kv` or an app-owned component id.
    pub component: &'a str,
    /// Stable instance key for the concrete physical schema instance.
    ///
    /// Use [`component_schema_instance_key_for_tables`](crate::db::component_schema_instance_key_for_tables)
    /// when the instance is defined by one or more table names.
    pub instance_key: &'a str,
    /// Current supported schema version.
    pub version: i32,
    /// Fingerprint of the canonical schema shape for this version.
    pub fingerprint: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaLedgerColumn {
    Component,
    InstanceKey,
    SchemaVersion,
    SchemaFingerprint,
    AppliedAt,
}

impl SchemaLedgerColumn {
    const fn name(self) -> &'static str {
        match self {
            Self::Component => "component",
            Self::InstanceKey => "instance_key",
            Self::SchemaVersion => "schema_version",
            Self::SchemaFingerprint => "schema_fingerprint",
            Self::AppliedAt => "applied_at",
        }
    }

    const fn create_table_type(self) -> &'static str {
        match self {
            Self::Component | Self::InstanceKey | Self::SchemaFingerprint => "TEXT",
            Self::SchemaVersion => "INTEGER",
            Self::AppliedAt => "TIMESTAMPTZ",
        }
    }

    const fn validation_type(self) -> &'static str {
        match self {
            Self::Component | Self::InstanceKey | Self::SchemaFingerprint => "text",
            Self::SchemaVersion => "integer",
            Self::AppliedAt => "timestamp with time zone",
        }
    }

    const fn required_collation(self) -> Option<&'static str> {
        match self {
            Self::Component | Self::InstanceKey | Self::SchemaFingerprint => {
                Some(SCHEMA_LEDGER_C_COLLATION)
            }
            Self::SchemaVersion | Self::AppliedAt => None,
        }
    }

    const fn max_octet_length(self) -> Option<usize> {
        match self {
            Self::Component => Some(MAX_SCHEMA_LEDGER_COMPONENT_BYTES),
            Self::InstanceKey => Some(MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES),
            Self::SchemaFingerprint => Some(MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES),
            Self::SchemaVersion | Self::AppliedAt => None,
        }
    }

    fn normalized_check_constraint(self) -> Option<String> {
        let column = self.name();
        match self {
            Self::Component | Self::InstanceKey | Self::SchemaFingerprint => {
                let max_octet_length = self
                    .max_octet_length()
                    .expect("checked text column must have a max length");
                Some(format!(
                    "(octet_length({column})>0)AND(octet_length({column})<={max_octet_length})"
                ))
            }
            Self::SchemaVersion => Some(format!("{column}>0")),
            Self::AppliedAt => None,
        }
    }
}

struct SchemaLedgerCatalog<'a> {
    table_name: &'a PgQualifiedTableName,
}

impl<'a> SchemaLedgerCatalog<'a> {
    fn new(table_name: &'a PgQualifiedTableName) -> Self {
        Self { table_name }
    }

    fn quoted_table_name(&self) -> String {
        self.table_name.quoted().to_string()
    }

    fn create_table_statement(&self) -> String {
        let component = SchemaLedgerColumn::Component.name();
        let component_type = SchemaLedgerColumn::Component.create_table_type();
        let instance_key = SchemaLedgerColumn::InstanceKey.name();
        let instance_key_type = SchemaLedgerColumn::InstanceKey.create_table_type();
        let schema_version = SchemaLedgerColumn::SchemaVersion.name();
        let schema_version_type = SchemaLedgerColumn::SchemaVersion.create_table_type();
        let schema_fingerprint = SchemaLedgerColumn::SchemaFingerprint.name();
        let schema_fingerprint_type = SchemaLedgerColumn::SchemaFingerprint.create_table_type();
        let applied_at = SchemaLedgerColumn::AppliedAt.name();
        let applied_at_type = SchemaLedgerColumn::AppliedAt.create_table_type();
        let primary_key_columns = schema_ledger_column_list(&SCHEMA_LEDGER_PRIMARY_KEY_COLUMNS);

        format!(
            r#"
        CREATE TABLE IF NOT EXISTS {} (
            {component} {component_type} COLLATE "C" NOT NULL CHECK (
                octet_length({component}) > 0
                AND octet_length({component}) <= {MAX_SCHEMA_LEDGER_COMPONENT_BYTES}
            ),
            {instance_key} {instance_key_type} COLLATE "C" NOT NULL CHECK (
                octet_length({instance_key}) > 0
                AND octet_length({instance_key}) <= {MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES}
            ),
            {schema_version} {schema_version_type} NOT NULL CHECK ({schema_version} > 0),
            {schema_fingerprint} {schema_fingerprint_type} COLLATE "C" NOT NULL CHECK (
                octet_length({schema_fingerprint}) > 0
                AND octet_length({schema_fingerprint}) <= {MAX_SCHEMA_LEDGER_FINGERPRINT_BYTES}
            ),
            {applied_at} {applied_at_type} NOT NULL,
            PRIMARY KEY ({primary_key_columns})
        )
        "#,
            self.table_name.quoted()
        )
    }

    fn record_component_version_statement(&self) -> String {
        let component = SchemaLedgerColumn::Component.name();
        let instance_key = SchemaLedgerColumn::InstanceKey.name();
        let schema_version = SchemaLedgerColumn::SchemaVersion.name();
        let schema_fingerprint = SchemaLedgerColumn::SchemaFingerprint.name();
        let applied_at = SchemaLedgerColumn::AppliedAt.name();
        let primary_key_columns = schema_ledger_column_list(&SCHEMA_LEDGER_PRIMARY_KEY_COLUMNS);

        format!(
            r#"
        INSERT INTO {} (
            {component},
            {instance_key},
            {schema_version},
            {schema_fingerprint},
            {applied_at}
        )
        VALUES ($1, $2, $3, $4, statement_timestamp())
        ON CONFLICT ({primary_key_columns})
        DO NOTHING
        "#,
            self.table_name.quoted()
        )
    }

    fn fetch_component_version_statement(&self) -> String {
        let component = SchemaLedgerColumn::Component.name();
        let instance_key = SchemaLedgerColumn::InstanceKey.name();
        let schema_version = SchemaLedgerColumn::SchemaVersion.name();
        let schema_fingerprint = SchemaLedgerColumn::SchemaFingerprint.name();

        format!(
            r#"
        SELECT {schema_version}, {schema_fingerprint}
        FROM {}
        WHERE {component} = $1
          AND {instance_key} = $2
        "#,
            self.table_name.quoted()
        )
    }

    fn update_component_version_statement(&self) -> String {
        let component = SchemaLedgerColumn::Component.name();
        let instance_key = SchemaLedgerColumn::InstanceKey.name();
        let schema_version = SchemaLedgerColumn::SchemaVersion.name();
        let schema_fingerprint = SchemaLedgerColumn::SchemaFingerprint.name();
        let applied_at = SchemaLedgerColumn::AppliedAt.name();

        format!(
            r#"
        UPDATE {}
        SET
            {schema_version} = $5,
            {schema_fingerprint} = $6,
            {applied_at} = statement_timestamp()
        WHERE {component} = $1
          AND {instance_key} = $2
          AND {schema_version} = $3
          AND {schema_fingerprint} = $4
        "#,
            self.table_name.quoted()
        )
    }
}

fn schema_ledger_column_list(columns: &[SchemaLedgerColumn]) -> String {
    columns
        .iter()
        .map(|column| column.name())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
impl SchemaLedgerConfig {
    pub(crate) fn new(table_name: PgQualifiedTableName) -> Self {
        Self { table_name }
    }
}

#[cfg(test)]
pub(crate) fn test_schema_ledger_table_name() -> PgQualifiedTableName {
    PgQualifiedTableName::unqualified("__paranoid_test_schema_ledger")
        .expect("test schema ledger table name must be valid")
}

#[cfg(test)]
pub(crate) fn test_schema_ledger_config() -> SchemaLedgerConfig {
    SchemaLedgerConfig::new(test_schema_ledger_table_name())
}

pub(crate) async fn plan_component_schema_migration_in_current_transaction<'a>(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
    upgrade_steps: &'a [ComponentSchemaMigrationStep<'a>],
) -> Result<ComponentSchemaMigrationPlan<'a>, DbError> {
    validate_component_schema_version(component_schema_version)?;
    execute_schema_ledger_migration_in_current_transaction(tx, table_name).await?;
    let recorded = fetch_component_schema_version_row_in_current_transaction(
        tx,
        table_name,
        component_schema_version,
    )
    .await?;
    plan_component_schema_migration(component_schema_version, recorded, upgrade_steps)
}

pub(crate) async fn record_component_schema_migration_completion_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
    prior_recorded_version: Option<&RecordedComponentSchemaVersion>,
) -> Result<(), DbError> {
    validate_component_schema_version(component_schema_version)?;
    let catalog = SchemaLedgerCatalog::new(table_name);

    if let Some(prior_recorded_version) = prior_recorded_version {
        let statement = catalog.update_component_version_statement();
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_UPDATE_COMPONENT_VERSION,
            Some(statement.as_str()),
        );
        let rows_affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(component_schema_version.component)
            .bind(component_schema_version.instance_key)
            .bind(prior_recorded_version.version)
            .bind(prior_recorded_version.fingerprint.as_str())
            .bind(component_schema_version.version)
            .bind(component_schema_version.fingerprint)
            .execute(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if rows_affected != 1 {
            return Err(DbError::schema_mismatch(format!(
                "schema ledger row for component {:?} instance {:?} changed before migration completion",
                component_schema_version.component, component_schema_version.instance_key
            )));
        }
    } else {
        let statement = catalog.record_component_version_statement();
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
    }

    validate_component_schema_version_row_in_current_transaction(
        tx,
        table_name,
        component_schema_version,
    )
    .await
}

pub(crate) async fn validate_component_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<(), DbError> {
    validate_component_schema_version(component_schema_version)?;
    validate_schema_ledger_with_transaction(tx, table_name).await?;
    validate_component_schema_version_row_in_current_transaction(
        tx,
        table_name,
        component_schema_version,
    )
    .await
}

async fn validate_component_schema_version_row_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<(), DbError> {
    let actual = fetch_component_schema_version_row_in_current_transaction(
        tx,
        table_name,
        component_schema_version,
    )
    .await?;

    let Some(actual) = actual else {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} was not found",
            component_schema_version.component, component_schema_version.instance_key
        )));
    };

    if actual.version != component_schema_version.version {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} recorded version {}, expected {}",
            component_schema_version.component,
            component_schema_version.instance_key,
            actual.version,
            component_schema_version.version
        )));
    }

    if actual.fingerprint != component_schema_version.fingerprint {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} recorded fingerprint {:?}, expected {:?}",
            component_schema_version.component,
            component_schema_version.instance_key,
            actual.fingerprint,
            component_schema_version.fingerprint
        )));
    }

    Ok(())
}

async fn fetch_component_schema_version_row_in_current_transaction(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<Option<RecordedComponentSchemaVersion>, DbError> {
    let catalog = SchemaLedgerCatalog::new(table_name);

    let statement = catalog.fetch_component_version_statement();

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

    Ok(
        actual.map(|(version, fingerprint)| RecordedComponentSchemaVersion {
            version,
            fingerprint,
        }),
    )
}

/// Builds a stable schema instance key from labeled qualified table names.
///
/// Labels are validated Postgres identifiers. The returned key includes quoted
/// schema and table names, so schemas with the same table names remain
/// distinct.
pub fn component_schema_instance_key_for_tables<'a, I>(parts: I) -> String
where
    I: IntoIterator<Item = (&'a PgIdentifier, &'a PgQualifiedTableName)>,
{
    parts
        .into_iter()
        .map(|(label, table_name)| format!("{}={}", label.as_str(), table_name.quoted()))
        .collect::<Vec<_>>()
        .join(";")
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
    let catalog = SchemaLedgerCatalog::new(table_name);
    validate_schema_ledger_required_columns(tx, &catalog).await?;
    validate_schema_ledger_primary_key(tx, &catalog).await?;
    validate_schema_ledger_required_check_constraints(tx, &catalog).await
}

async fn validate_schema_ledger_required_columns(
    tx: &mut Tx<'_>,
    catalog: &SchemaLedgerCatalog<'_>,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
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
        .bind(quoted_table_name.as_str())
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    for column in SCHEMA_LEDGER_REQUIRED_COLUMNS {
        let name = column.name();
        let expected_type = column.validation_type();
        let expected_not_null = true;
        let expected_collation = column.required_collation();
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
    catalog: &SchemaLedgerCatalog<'_>,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_attribute component_attr
              ON component_attr.attrelid = idx.indrelid
             AND component_attr.attname = $2
             AND NOT component_attr.attisdropped
            JOIN pg_attribute instance_attr
              ON instance_attr.attrelid = idx.indrelid
             AND instance_attr.attname = $3
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
        .bind(quoted_table_name.as_str())
        .bind(SchemaLedgerColumn::Component.name())
        .bind(SchemaLedgerColumn::InstanceKey.name())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_primary_key {
        let primary_key_columns = schema_ledger_column_list(&SCHEMA_LEDGER_PRIMARY_KEY_COLUMNS);
        return Err(DbError::schema_mismatch(format!(
            "schema ledger table {} must have primary key ({})",
            quoted_table_name, primary_key_columns
        )));
    }

    Ok(())
}

async fn validate_schema_ledger_required_check_constraints(
    tx: &mut Tx<'_>,
    catalog: &SchemaLedgerCatalog<'_>,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
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
        .bind(quoted_table_name.as_str())
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|expression| normalize_check_constraint_expression(&expression))
        .collect::<Vec<String>>();

    for column in SCHEMA_LEDGER_CHECKED_COLUMNS {
        let required_expression = column
            .normalized_check_constraint()
            .expect("checked schema ledger column must define a constraint");
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
    SchemaLedgerCatalog::new(table_name).create_table_statement()
}

pub(crate) fn validate_component_schema_version(
    component_schema_version: ComponentSchemaVersion<'_>,
) -> Result<(), DbError> {
    validate_bounded_nonempty_schema_ledger_text(
        SchemaLedgerColumn::Component.name(),
        component_schema_version.component,
        MAX_SCHEMA_LEDGER_COMPONENT_BYTES,
    )?;
    validate_bounded_nonempty_schema_ledger_text(
        SchemaLedgerColumn::InstanceKey.name(),
        component_schema_version.instance_key,
        MAX_SCHEMA_LEDGER_INSTANCE_KEY_BYTES,
    )?;
    validate_bounded_nonempty_schema_ledger_text(
        SchemaLedgerColumn::SchemaFingerprint.name(),
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
