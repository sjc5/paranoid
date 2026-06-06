#[cfg(feature = "__auth_wip")]
use super::validate_component_schema_version_in_current_transaction;
use super::{
    AuditedSql, BootstrapStores, ComponentSchemaMigrationPlan, ComponentSchemaMigrationStep,
    ComponentSchemaVersion, DatabaseOperationKind, Error, PgQualifiedTableName, Tx, WritePool,
    WriteTx, finish_pool_owned_write_transaction_and_preserve_rollback_error,
    plan_component_schema_migration_in_current_transaction,
    record_component_schema_migration_completion_in_current_transaction,
    unparameterized_simple_query, validate_component_schema_version,
};
use std::borrow::Cow;

use sqlx::Row;

pub(crate) const COMPONENT_SCHEMA_OPERATION_EXECUTE_FRESH_INSTALL_STATEMENT: &str =
    "component_schema.execute_fresh_install_statement";
pub(crate) const COMPONENT_SCHEMA_OPERATION_EXECUTE_UPGRADE_STATEMENT: &str =
    "component_schema.execute_upgrade_statement";
pub(crate) const COMPONENT_SCHEMA_OPERATION_EXECUTE_VALIDATION_CHECK: &str =
    "component_schema.execute_validation_check";
const COMPONENT_SCHEMA_OPERATION_MIGRATE: &str = "component_schema.migrate";

/// One unparameterized SQL statement owned by a component schema migration.
///
/// Statements run through Postgres simple-query protocol and must be a single
/// statement. Use this type for DDL or migration SQL whose dynamic identifiers
/// have already been validated and quoted through Paranoid's Postgres
/// identifier types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentSchemaStatement<'a> {
    sql: Cow<'a, str>,
}

/// One physical schema validation check.
///
/// A validation check is a single SQL boolean expression. Paranoid wraps it as
/// `SELECT (<expression>)` and requires the result to decode as exactly one
/// boolean `true`. A false, null, non-boolean, non-scalar, or failing expression
/// makes schema validation fail. Dynamic identifiers inside the expression must
/// already be validated and quoted through Paranoid's Postgres identifier types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentSchemaValidationCheck<'a> {
    boolean_expression: Cow<'a, str>,
}

/// One ordered physical migration step for a component schema instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentSchemaMigration<'a> {
    step: ComponentSchemaMigrationStep<'a>,
    statements: &'a [ComponentSchemaStatement<'a>],
}

/// Complete schema description for one schema-family instance registered with Paranoid bootstrap.
///
/// `ComponentSchema` describes the latest supported version of a schema family
/// plus the physical work needed to fresh-install or upgrade to that version.
/// It does not choose the schema ledger table or transaction boundary; callers
/// run it through [`BootstrapStores::migrate_component_schema`](crate::db::BootstrapStores::migrate_component_schema).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentSchema<'a> {
    current_version: ComponentSchemaVersion<'a>,
    fresh_install_statements: &'a [ComponentSchemaStatement<'a>],
    migrations: &'a [ComponentSchemaMigration<'a>],
    validation_checks: &'a [ComponentSchemaValidationCheck<'a>],
}

/// Result of applying or validating a component schema migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentSchemaMigrationOutcome {
    /// The ledger had no row for this component instance, so fresh-install
    /// statements and validation ran before recording the current version.
    FreshInstall {
        /// Recorded schema version.
        version: i32,
    },
    /// The ledger row already matched the requested version and fingerprint,
    /// and physical validation succeeded.
    AlreadyCurrent {
        /// Validated schema version.
        version: i32,
    },
    /// One or more ordered upgrade steps ran, physical validation succeeded,
    /// and the ledger row was advanced.
    Upgraded {
        /// Previously recorded schema version.
        from_version: i32,
        /// Newly recorded schema version.
        to_version: i32,
        /// Number of migration steps applied.
        steps_applied: usize,
    },
}

impl ComponentSchemaStatement<'static> {
    /// Creates a component schema statement from static SQL.
    pub fn from_static_sql(sql: &'static str) -> Result<ComponentSchemaStatement<'static>, Error> {
        Self::from_cow(Cow::Borrowed(sql))
    }

    /// Creates a component schema statement from audited owned dynamic SQL.
    pub fn from_audited_dynamic_sql(
        sql: AuditedSql<String>,
    ) -> Result<ComponentSchemaStatement<'static>, Error> {
        Self::from_cow(Cow::Owned(sql.into_inner()))
    }
}

impl<'a> ComponentSchemaStatement<'a> {
    /// Creates a component schema statement from audited borrowed dynamic SQL.
    pub fn from_audited_borrowed_sql(sql: AuditedSql<&'a str>) -> Result<Self, Error> {
        Self::from_cow(Cow::Borrowed(sql.into_inner()))
    }

    /// Returns the SQL statement text.
    pub fn as_str(&self) -> &str {
        self.sql.as_ref()
    }

    fn from_cow(sql: Cow<'a, str>) -> Result<Self, Error> {
        validate_component_schema_sql(sql.as_ref(), "component schema SQL statement")?;
        if sql.as_bytes().contains(&b';') {
            return Err(Error::schema_mismatch(
                "component schema SQL statement must not contain semicolons",
            ));
        }
        Ok(Self { sql })
    }
}

impl ComponentSchemaValidationCheck<'static> {
    /// Creates a component schema validation check from a static SQL boolean expression.
    pub fn from_static_boolean_expression(
        boolean_expression: &'static str,
    ) -> Result<ComponentSchemaValidationCheck<'static>, Error> {
        Self::from_cow(Cow::Borrowed(boolean_expression))
    }

    /// Creates a component schema validation check from an audited owned SQL boolean expression.
    pub fn from_audited_dynamic_boolean_expression(
        boolean_expression: AuditedSql<String>,
    ) -> Result<ComponentSchemaValidationCheck<'static>, Error> {
        Self::from_cow(Cow::Owned(boolean_expression.into_inner()))
    }
}

impl<'a> ComponentSchemaValidationCheck<'a> {
    /// Creates a component schema validation check from an audited borrowed SQL boolean expression.
    pub fn from_audited_borrowed_boolean_expression(
        boolean_expression: AuditedSql<&'a str>,
    ) -> Result<Self, Error> {
        Self::from_cow(Cow::Borrowed(boolean_expression.into_inner()))
    }

    /// Returns the SQL boolean expression text.
    pub fn boolean_expression(&self) -> &str {
        self.boolean_expression.as_ref()
    }

    fn from_cow(boolean_expression: Cow<'a, str>) -> Result<Self, Error> {
        validate_component_schema_sql(
            boolean_expression.as_ref(),
            "component schema validation boolean expression",
        )?;
        if boolean_expression.as_bytes().contains(&b';') {
            return Err(Error::schema_mismatch(
                "component schema validation boolean expression must not contain semicolons",
            ));
        }
        Ok(Self { boolean_expression })
    }
}

impl<'a> ComponentSchemaMigration<'a> {
    /// Creates a physical migration for one supported version/fingerprint step.
    pub const fn new(
        step: ComponentSchemaMigrationStep<'a>,
        statements: &'a [ComponentSchemaStatement<'a>],
    ) -> Self {
        Self { step, statements }
    }

    /// Returns the version/fingerprint step this migration implements.
    pub const fn step(&self) -> ComponentSchemaMigrationStep<'a> {
        self.step
    }

    /// Returns the SQL statements for this physical migration.
    pub const fn statements(&self) -> &'a [ComponentSchemaStatement<'a>] {
        self.statements
    }
}

impl<'a> ComponentSchema<'a> {
    /// Creates a component schema description.
    ///
    /// Validation checks are required because the schema ledger must never
    /// become the only proof that physical tables match the claimed version.
    /// Fresh-install statements may be empty for schemas that are only valid as
    /// upgrades from earlier versions, but validation checks must always prove
    /// the final physical shape.
    pub fn new(
        current_version: ComponentSchemaVersion<'a>,
        fresh_install_statements: &'a [ComponentSchemaStatement<'a>],
        migrations: &'a [ComponentSchemaMigration<'a>],
        validation_checks: &'a [ComponentSchemaValidationCheck<'a>],
    ) -> Result<Self, Error> {
        validate_component_schema_version(current_version)?;
        if validation_checks.is_empty() {
            return Err(Error::schema_mismatch(
                "component schema validation checks must not be empty",
            ));
        }
        Ok(Self {
            current_version,
            fresh_install_statements,
            migrations,
            validation_checks,
        })
    }

    /// Returns the current schema version identity.
    pub const fn current_version(&self) -> ComponentSchemaVersion<'a> {
        self.current_version
    }

    /// Returns the fresh-install SQL statements.
    pub const fn fresh_install_statements(&self) -> &'a [ComponentSchemaStatement<'a>] {
        self.fresh_install_statements
    }

    /// Returns the ordered migration definitions.
    pub const fn migrations(&self) -> &'a [ComponentSchemaMigration<'a>] {
        self.migrations
    }

    /// Returns the physical validation checks.
    pub const fn validation_checks(&self) -> &'a [ComponentSchemaValidationCheck<'a>] {
        self.validation_checks
    }
}

/// Migrates or validates one component schema instance through Paranoid bootstrap state.
///
/// The DB foundation must be migrated first with [`BootstrapConfig`](crate::db::BootstrapConfig).
/// This function owns the transaction boundary. Physical migration
/// statements and validation checks may target tables in any Postgres schema.
/// The shared Paranoid schema ledger serializes migration planning for the
/// schema instance and is recorded only after selected physical work succeeds
/// and every validation check returns true.
pub(crate) async fn migrate_component_schema(
    pool: &WritePool,
    stores: &BootstrapStores,
    schema: &ComponentSchema<'_>,
) -> Result<ComponentSchemaMigrationOutcome, Error> {
    let mut tx = pool.begin_transaction().await?;
    let result = async {
        migrate_component_schema_in_current_transaction(
            &mut tx,
            stores.schema_ledger_table_name(),
            schema,
        )
        .await
    }
    .await;

    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        COMPONENT_SCHEMA_OPERATION_MIGRATE,
        tx,
        result,
        std::convert::identity,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error: Box::new(rollback_error),
        },
    )
    .await
}

pub(crate) async fn migrate_component_schema_in_current_transaction(
    tx: &mut WriteTx<'_>,
    ledger_table: &PgQualifiedTableName,
    schema: &ComponentSchema<'_>,
) -> Result<ComponentSchemaMigrationOutcome, Error> {
    let migration_steps = schema
        .migrations
        .iter()
        .map(ComponentSchemaMigration::step)
        .collect::<Vec<_>>();

    match plan_component_schema_migration_in_current_transaction(
        tx,
        ledger_table,
        schema.current_version,
        &migration_steps,
    )
    .await?
    {
        ComponentSchemaMigrationPlan::FreshInstall => {
            execute_component_schema_statements(
                tx,
                COMPONENT_SCHEMA_OPERATION_EXECUTE_FRESH_INSTALL_STATEMENT,
                schema.fresh_install_statements,
            )
            .await?;
            execute_component_schema_validation_checks(tx, schema.validation_checks).await?;
            record_component_schema_migration_completion_in_current_transaction(
                tx,
                ledger_table,
                schema.current_version,
                None,
            )
            .await?;
            Ok(ComponentSchemaMigrationOutcome::FreshInstall {
                version: schema.current_version.version,
            })
        }
        ComponentSchemaMigrationPlan::AlreadyCurrent => {
            execute_component_schema_validation_checks(tx, schema.validation_checks).await?;
            Ok(ComponentSchemaMigrationOutcome::AlreadyCurrent {
                version: schema.current_version.version,
            })
        }
        ComponentSchemaMigrationPlan::Upgrade { from, steps } => {
            for step in &steps {
                let migration = component_schema_migration_for_step(schema, *step)?;
                execute_component_schema_statements(
                    tx,
                    COMPONENT_SCHEMA_OPERATION_EXECUTE_UPGRADE_STATEMENT,
                    migration.statements,
                )
                .await?;
            }
            execute_component_schema_validation_checks(tx, schema.validation_checks).await?;
            record_component_schema_migration_completion_in_current_transaction(
                tx,
                ledger_table,
                schema.current_version,
                Some(&from),
            )
            .await?;
            Ok(ComponentSchemaMigrationOutcome::Upgraded {
                from_version: from.version,
                to_version: schema.current_version.version,
                steps_applied: steps.len(),
            })
        }
    }
}

/// Validates one component schema instance inside the current transaction.
///
/// This checks both the schema ledger row and the caller-provided physical
/// validation checks.
#[cfg(feature = "__auth_wip")]
pub(crate) async fn validate_component_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    ledger_table: &PgQualifiedTableName,
    schema: &ComponentSchema<'_>,
) -> Result<(), Error> {
    validate_component_schema_version_in_current_transaction(
        tx,
        ledger_table,
        schema.current_version,
    )
    .await?;
    execute_component_schema_validation_checks(tx, schema.validation_checks).await
}

async fn execute_component_schema_statements(
    tx: &mut Tx<'_>,
    operation_label: &'static str,
    statements: &[ComponentSchemaStatement<'_>],
) -> Result<(), Error> {
    for statement in statements {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            operation_label,
            Some(statement.as_str()),
        );
        unparameterized_simple_query(AuditedSql::new(statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(Error::query)?;
    }
    Ok(())
}

async fn execute_component_schema_validation_checks(
    tx: &mut Tx<'_>,
    validation_checks: &[ComponentSchemaValidationCheck<'_>],
) -> Result<(), Error> {
    for validation_check in validation_checks {
        let statement = format!(
            "SELECT ({}) AS component_schema_validation_check",
            validation_check.boolean_expression()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOne,
            COMPONENT_SCHEMA_OPERATION_EXECUTE_VALIDATION_CHECK,
            Some(&statement),
        );
        let row = unparameterized_simple_query(AuditedSql::new(statement))
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(Error::query)?;
        let passed = row.try_get::<Option<bool>, _>(0).map_err(Error::query)?;
        match passed {
            Some(true) => {}
            Some(false) => {
                return Err(Error::schema_mismatch(format!(
                    "component schema validation check returned false: {}",
                    validation_check.boolean_expression()
                )));
            }
            None => {
                return Err(Error::schema_mismatch(format!(
                    "component schema validation check returned null: {}",
                    validation_check.boolean_expression()
                )));
            }
        }
    }
    Ok(())
}

fn component_schema_migration_for_step<'schema, 'a>(
    schema: &'schema ComponentSchema<'a>,
    step: ComponentSchemaMigrationStep<'a>,
) -> Result<&'schema ComponentSchemaMigration<'a>, Error> {
    schema
        .migrations
        .iter()
        .find(|migration| migration.step == step)
        .ok_or_else(|| {
            Error::schema_mismatch(format!(
                "component schema migration for step {} fingerprint {:?} to {} fingerprint {:?} was not found",
                step.from().version(),
                step.from().fingerprint(),
                step.to().version(),
                step.to().fingerprint()
            ))
        })
}

fn validate_component_schema_sql(sql: &str, label: &'static str) -> Result<(), Error> {
    if sql.trim().is_empty() {
        return Err(Error::schema_mismatch(format!("{label} must not be empty")));
    }
    if sql.as_bytes().contains(&0) {
        return Err(Error::schema_mismatch(format!(
            "{label} must not contain null bytes"
        )));
    }
    Ok(())
}
