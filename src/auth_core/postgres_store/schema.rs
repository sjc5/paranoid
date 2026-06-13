use super::*;

const AUTH_SCHEMA_COMPONENT: &str = "auth_core";
const AUTH_SCHEMA_VERSION: i32 = 4;
const AUTH_SCHEMA_FINGERPRINT: &str = "auth-core-postgres-v4";
const AUTH_SCHEMA_V3_FINGERPRINT: &str = "auth-core-postgres-v3";
const AUTH_SCHEMA_V3_TO_V4_STEP: ComponentSchemaMigrationStep<'static> =
    ComponentSchemaMigrationStep::new(
        ComponentSchemaMigrationTarget::new(3, AUTH_SCHEMA_V3_FINGERPRINT),
        ComponentSchemaMigrationTarget::new(AUTH_SCHEMA_VERSION, AUTH_SCHEMA_FINGERPRINT),
    );
const AUTH_SCHEMA_V3_TO_V4_MIGRATION: ComponentSchemaMigration<'static> =
    ComponentSchemaMigration::new(AUTH_SCHEMA_V3_TO_V4_STEP, &[]);
const AUTH_SCHEMA_MIGRATIONS: &[ComponentSchemaMigration<'static>] =
    &[AUTH_SCHEMA_V3_TO_V4_MIGRATION];
impl PostgresAuthStore {
    pub(crate) async fn migrate_schema(
        &self,
        pool: &WritePool,
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.migrate_schema_in_current_transaction(&mut tx).await;
        finish_auth_store_write_transaction("auth_core.migrate_schema", tx, result).await
    }

    pub(crate) async fn validate_schema(&self, pool: &Pool) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.validate_schema_in_current_transaction(&mut tx).await;
        finish_auth_store_validation_transaction("auth_core.validate_schema", tx, result).await
    }

    pub(crate) async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
    ) -> Result<(), PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        for contract in PostgresAuthCoreSchemaContract::table_contracts() {
            execute_create_table(tx, &table_names, &contract).await?;
        }
        for contract in PostgresAuthCoreSchemaContract::table_contracts() {
            execute_create_unique_indexes(tx, &table_names, &contract).await?;
        }
        validate_physical_schema_in_current_transaction(tx, &table_names).await?;
        if let Some(registry) = self.method_registry.as_ref() {
            registry
                .migrate_schema_in_current_transaction(tx)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodRegistryFailed {
                    operation: "migrate_schema",
                    source,
                })?;
            registry
                .validate_schema_in_current_transaction(tx)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodRegistryFailed {
                    operation: "validate_schema",
                    source,
                })?;
        }
        migrate_auth_component_schema_in_current_transaction(tx, &self.config, &table_names)
            .await?;
        Ok(())
    }

    pub(crate) async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        validate_physical_schema_in_current_transaction(tx, &table_names).await?;
        if let Some(registry) = self.method_registry.as_ref() {
            registry
                .validate_schema_in_current_transaction(tx)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodRegistryFailed {
                    operation: "validate_schema",
                    source,
                })?;
        }
        validate_auth_component_schema_in_current_transaction(tx, &self.config).await?;
        Ok(())
    }
}

pub(in crate::auth_core) async fn execute_create_table(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
) -> Result<(), PostgresAuthStoreError> {
    let statement = build_create_table_statement(table_names, contract)?;
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.schema.create_table",
        Some(statement.as_str()),
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(statement.as_str()))
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn execute_create_unique_indexes(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
) -> Result<(), PostgresAuthStoreError> {
    for uniqueness in contract
        .uniqueness()
        .iter()
        .filter(|uniqueness| uniqueness.name() != "primary_key")
    {
        let statement = build_create_unique_index_statement(table_names, contract, uniqueness)?;
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.schema.create_unique_index",
            Some(statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}

pub(in crate::auth_core) async fn validate_physical_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
) -> Result<(), PostgresAuthStoreError> {
    for contract in PostgresAuthCoreSchemaContract::table_contracts() {
        validate_table(tx, table_names, &contract).await?;
    }
    Ok(())
}

pub(in crate::auth_core) async fn migrate_auth_component_schema_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &PostgresAuthStoreConfig,
    table_names: &AuthCoreTableNames,
) -> Result<(), PostgresAuthStoreError> {
    let instance_key = schema_instance_key(config);
    let validation_checks = auth_component_schema_validation_checks(table_names)?;
    let component_schema = ComponentSchema::new(
        ComponentSchemaVersion {
            component: AUTH_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: AUTH_SCHEMA_VERSION,
            fingerprint: AUTH_SCHEMA_FINGERPRINT,
        },
        &[],
        AUTH_SCHEMA_MIGRATIONS,
        validation_checks.as_slice(),
    )?;
    migrate_component_schema_in_current_transaction(
        tx,
        &config.schema_ledger_table_name()?,
        &component_schema,
    )
    .await?;
    validate_auth_component_schema_in_current_transaction_with_table_names(tx, config, table_names)
        .await
}

pub(in crate::auth_core) async fn validate_auth_component_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &PostgresAuthStoreConfig,
) -> Result<(), PostgresAuthStoreError> {
    let table_names = config.table_names()?;
    validate_auth_component_schema_in_current_transaction_with_table_names(tx, config, &table_names)
        .await
}

pub(in crate::auth_core) async fn validate_auth_component_schema_in_current_transaction_with_table_names(
    tx: &mut Tx<'_>,
    config: &PostgresAuthStoreConfig,
    table_names: &AuthCoreTableNames,
) -> Result<(), PostgresAuthStoreError> {
    let instance_key = schema_instance_key(config);
    let validation_checks = auth_component_schema_validation_checks(table_names)?;
    let component_schema = ComponentSchema::new(
        ComponentSchemaVersion {
            component: AUTH_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: AUTH_SCHEMA_VERSION,
            fingerprint: AUTH_SCHEMA_FINGERPRINT,
        },
        &[],
        AUTH_SCHEMA_MIGRATIONS,
        validation_checks.as_slice(),
    )?;
    validate_component_schema_in_current_transaction(
        tx,
        &config.schema_ledger_table_name()?,
        &component_schema,
    )
    .await?;
    Ok(())
}

pub(in crate::auth_core) fn auth_component_schema_validation_checks(
    table_names: &AuthCoreTableNames,
) -> Result<Vec<ComponentSchemaValidationCheck<'static>>, PostgresAuthStoreError> {
    PostgresAuthCoreSchemaContract::table_contracts()
        .iter()
        .map(|contract| {
            let expression =
                build_component_schema_projection_validation_expression(table_names, contract)?;
            ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(
                AuditedSql::new(expression),
            )
            .map_err(PostgresAuthStoreError::from)
        })
        .collect()
}

pub(in crate::auth_core) fn build_component_schema_projection_validation_expression(
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
) -> Result<String, PostgresAuthStoreError> {
    let quoted_columns = contract
        .columns()
        .iter()
        .map(|column| {
            PgIdentifier::new(column.name())
                .map(|identifier| identifier.quoted().to_string())
                .map_err(DbError::from)
                .map_err(PostgresAuthStoreError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "NOT EXISTS (SELECT {} FROM {} WHERE false)",
        quoted_columns.join(", "),
        table_names.get(contract.table()).quoted()
    ))
}

pub(in crate::auth_core) fn build_create_table_statement(
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
) -> Result<String, PostgresAuthStoreError> {
    let table_name = table_names.get(contract.table());
    let mut parts = contract
        .columns()
        .iter()
        .map(column_definition)
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(primary_key) = contract
        .uniqueness()
        .iter()
        .find(|uniqueness| uniqueness.name() == "primary_key")
    {
        parts.push(format!(
            "PRIMARY KEY ({})",
            primary_key
                .columns()
                .iter()
                .map(|column| format!(r#""{column}""#))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {} (\n    {}\n)",
        table_name.quoted(),
        parts.join(",\n    ")
    ))
}

pub(in crate::auth_core) fn build_create_unique_index_statement(
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
    uniqueness: &PostgresUniquenessContract,
) -> Result<String, PostgresAuthStoreError> {
    let index_name = PgIdentifier::new(format!(
        "{}{}_{}",
        table_names.index_name_prefix,
        auth_table_number(contract.table()),
        uniqueness.name()
    ))
    .map_err(DbError::from)?;
    let columns = uniqueness
        .columns()
        .iter()
        .map(|column| format!(r#""{column}""#))
        .collect::<Vec<_>>()
        .join(", ");
    let predicate = match uniqueness.predicate() {
        Some(PostgresUniquePredicate::OpenRow) => r#" WHERE "closed_at" IS NULL"#,
        None => "",
    };
    Ok(format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} ({}){}",
        index_name.quoted(),
        table_names.get(contract.table()).quoted(),
        columns,
        predicate
    ))
}

pub(in crate::auth_core) fn column_definition(
    column: &PostgresColumnContract,
) -> Result<String, PostgresAuthStoreError> {
    let mut definition = format!(
        r#""{}" {}"#,
        column.name(),
        storage_sql(column.storage(), column.value())
    );
    if !column.nullable() {
        definition.push_str(" NOT NULL");
    }
    for check in column_checks(column) {
        definition.push_str(" CHECK (");
        definition.push_str(&check);
        definition.push(')');
    }
    Ok(definition)
}

pub(in crate::auth_core) fn storage_sql(
    storage: PostgresColumnStorage,
    value: PostgresColumnValueContract,
) -> &'static str {
    match (storage, value) {
        (PostgresColumnStorage::Bytea, _) => "BYTEA",
        (PostgresColumnStorage::Bigint, PostgresColumnValueContract::GeneratedIdentity) => {
            "BIGINT GENERATED ALWAYS AS IDENTITY"
        }
        (PostgresColumnStorage::Bigint, _) => "BIGINT",
        (PostgresColumnStorage::Integer, _) => "INTEGER",
        (PostgresColumnStorage::Boolean, _) => "BOOLEAN",
        (PostgresColumnStorage::TextCollateC, _) => r#"TEXT COLLATE "C""#,
    }
}

pub(in crate::auth_core) fn column_checks(column: &PostgresColumnContract) -> Vec<String> {
    let name = format!(r#""{}""#, column.name());
    let raw_check = match column.value() {
        PostgresColumnValueContract::OpaqueIdBytes { max_bytes } => Some(format!(
            "octet_length({name}) > 0 AND octet_length({name}) <= {max_bytes}"
        )),
        PostgresColumnValueContract::FixedOpaqueBytes { exact_bytes } => {
            Some(format!("octet_length({name}) = {exact_bytes}"))
        }
        PostgresColumnValueContract::BoundedOpaqueBytes { max_bytes } => Some(format!(
            "octet_length({name}) > 0 AND octet_length({name}) <= {max_bytes}"
        )),
        PostgresColumnValueContract::MacOverSecretBytes { exact_bytes } => {
            Some(format!("octet_length({name}) = {exact_bytes}"))
        }
        PostgresColumnValueContract::SecretVersion => Some(format!("{name} > 0")),
        PostgresColumnValueContract::UnixSeconds
        | PostgresColumnValueContract::Counter
        | PostgresColumnValueContract::NonNegativeBigint => Some(format!("{name} >= 0")),
        PostgresColumnValueContract::CoreEnumDiscriminant => Some(format!("{name} > 0")),
        PostgresColumnValueContract::ValidatedText { max_bytes } => Some(format!(
            "octet_length({name}) > 0 AND octet_length({name}) <= {max_bytes}"
        )),
        PostgresColumnValueContract::Boolean | PostgresColumnValueContract::GeneratedIdentity => {
            None
        }
    };
    raw_check
        .map(|check| {
            if column.nullable() {
                format!("{name} IS NULL OR ({check})")
            } else {
                check
            }
        })
        .into_iter()
        .collect()
}

pub(in crate::auth_core) async fn validate_table(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
) -> Result<(), PostgresAuthStoreError> {
    let table_name = table_names.get(contract.table());
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
        "auth_core.schema.validate_columns",
        Some(statement),
    );
    let rows = pooler_safe_query_as::<(String, String, bool, Option<String>)>(statement)
        .bind(table_name.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    if rows.is_empty() {
        return Err(DbError::schema_mismatch(format!(
            "auth table {} was not found",
            table_name.quoted()
        ))
        .into());
    }
    for (actual_column, ..) in &rows {
        if !contract
            .columns()
            .iter()
            .any(|column| column.name() == actual_column)
        {
            return Err(DbError::schema_mismatch(format!(
                "auth table {} has unexpected column {:?}",
                table_name.quoted(),
                actual_column
            ))
            .into());
        }
    }
    for column in contract.columns() {
        let Some((_, actual_type, actual_not_null, actual_collation)) =
            rows.iter().find(|(name, ..)| name == column.name())
        else {
            return Err(DbError::schema_mismatch(format!(
                "auth table {} is missing column {:?}",
                table_name.quoted(),
                column.name()
            ))
            .into());
        };
        let expected_type = validation_type_sql(column.storage());
        if actual_type != expected_type {
            return Err(DbError::schema_mismatch(format!(
                "auth table {} column {:?} has type {:?}, expected {:?}",
                table_name.quoted(),
                column.name(),
                actual_type,
                expected_type
            ))
            .into());
        }
        if *actual_not_null == column.nullable() {
            return Err(DbError::schema_mismatch(format!(
                "auth table {} column {:?} nullability does not match contract",
                table_name.quoted(),
                column.name()
            ))
            .into());
        }
        if column.storage() == PostgresColumnStorage::TextCollateC
            && !matches!(actual_collation.as_deref(), Some("C") | Some("POSIX"))
        {
            return Err(DbError::schema_mismatch(format!(
                "auth table {} column {:?} uses collation {:?}, expected C or POSIX",
                table_name.quoted(),
                column.name(),
                actual_collation
            ))
            .into());
        }
    }
    validate_table_check_constraints(tx, table_name, contract).await?;
    validate_table_uniqueness(tx, table_name, contract).await?;
    Ok(())
}

pub(in crate::auth_core) async fn validate_table_check_constraints(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    contract: &PostgresAuthCoreTableContract,
) -> Result<(), PostgresAuthStoreError> {
    let statement = r#"
        SELECT pg_get_expr(con.conbin, con.conrelid)
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND con.convalidated
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.schema.validate_check_constraints",
        Some(statement),
    );
    let actual_checks = pooler_safe_query_scalar::<String>(statement)
        .bind(table_name.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|check| normalize_auth_check_constraint_expression(&check))
        .collect::<Vec<_>>();

    for column in contract.columns() {
        for required_check in column_checks(column) {
            let normalized_required = normalize_auth_check_constraint_expression(&required_check);
            if !actual_checks
                .iter()
                .any(|actual_check| actual_check == &normalized_required)
            {
                return Err(DbError::schema_mismatch(format!(
                    "auth table {} column {:?} must enforce CHECK ({})",
                    table_name.quoted(),
                    column.name(),
                    required_check
                ))
                .into());
            }
        }
    }
    Ok(())
}

pub(in crate::auth_core) fn normalize_auth_check_constraint_expression(expression: &str) -> String {
    normalize_check_constraint_expression(expression)
        .chars()
        .filter(|character| *character != '"' && *character != '(' && *character != ')')
        .collect::<String>()
        .to_ascii_lowercase()
}

pub(in crate::auth_core) async fn validate_table_uniqueness(
    tx: &mut Tx<'_>,
    table_name: &PgQualifiedTableName,
    contract: &PostgresAuthCoreTableContract,
) -> Result<(), PostgresAuthStoreError> {
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
        "auth_core.schema.validate_uniqueness",
        Some(statement),
    );
    let actual_indexes = pooler_safe_query_as::<(Vec<String>, bool, Option<String>)>(statement)
        .bind(table_name.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;

    for uniqueness in contract.uniqueness() {
        let required_columns = uniqueness
            .columns()
            .iter()
            .map(|column| column.to_string())
            .collect::<Vec<_>>();
        let required_predicate = uniqueness
            .predicate()
            .map(required_unique_predicate_expression)
            .map(normalize_auth_check_constraint_expression);

        if !actual_indexes.iter().any(|actual| {
            actual.0 == required_columns
                && actual.1
                && actual
                    .2
                    .as_deref()
                    .map(normalize_auth_check_constraint_expression)
                    == required_predicate
        }) {
            return Err(DbError::schema_mismatch(format!(
                "auth table {} is missing unique contract {:?} over ({})",
                table_name.quoted(),
                uniqueness.name(),
                uniqueness.columns().join(", ")
            ))
            .into());
        }
    }
    Ok(())
}

pub(in crate::auth_core) fn required_unique_predicate_expression(
    predicate: PostgresUniquePredicate,
) -> &'static str {
    match predicate {
        PostgresUniquePredicate::OpenRow => r#""closed_at" IS NULL"#,
    }
}

pub(in crate::auth_core) fn validation_type_sql(storage: PostgresColumnStorage) -> &'static str {
    match storage {
        PostgresColumnStorage::Bytea => "bytea",
        PostgresColumnStorage::Bigint => "bigint",
        PostgresColumnStorage::Integer => "integer",
        PostgresColumnStorage::Boolean => "boolean",
        PostgresColumnStorage::TextCollateC => "text",
    }
}
