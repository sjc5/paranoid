use super::*;

/// Creates and validates the configured KV schema inside one transaction.
#[cfg(test)]
pub(crate) async fn migrate_schema(
    pool: &WritePool,
    config: &StoreConfig,
) -> Result<(), crate::db::Error> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    let mut tx = pool.begin_transaction().await?;
    let result = migrate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_transaction(KV_OPERATION_SCHEMA_MIGRATE, tx, result).await
}

/// Creates and validates the configured KV schema inside the caller's transaction.
pub(crate) async fn migrate_schema_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &StoreConfig,
) -> Result<(), crate::db::Error> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;

    let instance_key = kv_schema_instance_key(config);
    let component_schema_version = kv_component_schema_version(&instance_key);
    let migration_plan = plan_component_schema_migration_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        component_schema_version,
        KV_SCHEMA_MIGRATION_STEPS,
    )
    .await?;

    match migration_plan {
        ComponentSchemaMigrationPlan::FreshInstall => {
            execute_kv_current_schema_install_in_current_transaction(tx, config).await?;
            validate_physical_schema_in_current_transaction(tx, config).await?;
            record_kv_schema_migration_completion_in_current_transaction(
                tx,
                config,
                component_schema_version,
                None,
            )
            .await
        }
        ComponentSchemaMigrationPlan::AlreadyCurrent => {
            execute_kv_current_schema_install_in_current_transaction(tx, config).await?;
            validate_physical_schema_in_current_transaction(tx, config).await
        }
        ComponentSchemaMigrationPlan::Upgrade { from, steps } => {
            execute_kv_schema_upgrade_steps_in_current_transaction(tx, config, &steps).await?;
            validate_physical_schema_in_current_transaction(tx, config).await?;
            record_kv_schema_migration_completion_in_current_transaction(
                tx,
                config,
                component_schema_version,
                Some(&from),
            )
            .await
        }
    }
}

/// Validates that the configured KV schema already exists and is compatible.
#[cfg(test)]
pub(crate) async fn validate_schema(
    pool: &Pool,
    config: &StoreConfig,
) -> Result<(), crate::db::Error> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    let mut tx = pool.begin_transaction().await?;
    let validation_result = validate_schema_in_current_transaction(&mut tx, config).await;
    finish_db_pool_validation_transaction(KV_OPERATION_SCHEMA_VALIDATE, tx, validation_result).await
}

pub(crate) async fn validate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    validate_distinct_table_names(config)
        .map_err(|error| DbError::schema_mismatch(error.to_string()))?;
    validate_physical_schema_in_current_transaction(tx, config).await?;
    validate_kv_schema_version_in_current_transaction(tx, config).await
}

async fn validate_physical_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    let catalog = KvCatalog::new(config);
    validate_required_columns(tx, &catalog).await?;
    validate_key_conflict_arbiter(tx, &catalog).await?;
    validate_required_check_constraints(tx, &catalog).await?;
    validate_expires_at_index(tx, &catalog).await?;
    validate_key_pattern_index(tx, &catalog).await?;
    if config.create_updated_at_index {
        validate_updated_at_index(tx, &catalog).await?;
    }
    Ok(())
}

async fn execute_kv_current_schema_install_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    let catalog = KvCatalog::new(config);
    let create_table_statement = catalog.create_table_statement();
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        KV_OPERATION_SCHEMA_CREATE_TABLE,
        Some(create_table_statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(create_table_statement.as_str()))
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    validate_required_columns(tx, &catalog).await?;
    validate_key_conflict_arbiter(tx, &catalog).await?;

    for statement in catalog.create_index_statements() {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            KV_OPERATION_SCHEMA_CREATE_INDEX,
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?;
    }

    Ok(())
}

async fn execute_kv_schema_upgrade_steps_in_current_transaction(
    _tx: &mut Tx<'_>,
    _config: &StoreConfig,
    steps: &[ComponentSchemaMigrationStep<'_>],
) -> Result<(), DbError> {
    debug_assert!(
        steps.is_empty(),
        "KV has no executable schema upgrade steps yet"
    );
    if steps.is_empty() {
        return Ok(());
    }
    Err(DbError::schema_mismatch(
        "KV schema upgrade steps were planned but no KV upgrade executor exists",
    ))
}

pub(super) async fn validate_required_columns(
    tx: &mut Tx<'_>,
    catalog: &KvCatalog,
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
        KV_OPERATION_SCHEMA_VALIDATE_COLUMNS,
        Some(statement),
    );
    let actual_columns = pooler_safe_query_as::<(String, String, bool, Option<String>)>(statement)
        .bind(&quoted_table_name)
        .fetch_all(tx.inner.as_mut())
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

    for required_column in catalog.required_columns() {
        let Some(actual_column) = actual_columns
            .iter()
            .find(|column| column.name == required_column.name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "required column {:?} not found on table {}",
                required_column.name, quoted_table_name
            )));
        };

        validate_required_column(&quoted_table_name, required_column, actual_column)?;
    }

    Ok(())
}

async fn record_kv_schema_migration_completion_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    component_schema_version: ComponentSchemaVersion<'_>,
    prior_recorded_version: Option<&RecordedComponentSchemaVersion>,
) -> Result<(), DbError> {
    record_component_schema_migration_completion_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        component_schema_version,
        prior_recorded_version,
    )
    .await
}

async fn validate_kv_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    let instance_key = kv_schema_instance_key(config);
    validate_component_schema_version_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        kv_component_schema_version(&instance_key),
    )
    .await
}

fn kv_schema_instance_key(config: &StoreConfig) -> String {
    schema_instance_key_for_parts([("table", &config.table_name)])
}

fn kv_component_schema_version(instance_key: &str) -> ComponentSchemaVersion<'_> {
    ComponentSchemaVersion {
        component: KV_SCHEMA_COMPONENT,
        instance_key,
        version: KV_SCHEMA_VERSION,
        fingerprint: KV_SCHEMA_FINGERPRINT,
    }
}

pub(super) async fn validate_key_conflict_arbiter(
    tx: &mut Tx<'_>,
    catalog: &KvCatalog,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
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
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
        Some(statement),
    );
    let has_usable_unique_key = pooler_safe_query_scalar::<bool>(statement)
        .bind(&quoted_table_name)
        .bind(KvColumn::Key.name())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_usable_unique_key {
        let key = KvColumn::Key.name();
        return Err(DbError::schema_mismatch(format!(
            r#"column "{key}" must have a unique or primary key constraint usable by ON CONFLICT ({key})"#
        )));
    }

    Ok(())
}

pub(super) async fn validate_required_check_constraints(
    tx: &mut Tx<'_>,
    catalog: &KvCatalog,
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
        KV_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
        Some(statement),
    );
    let normalized_check_expressions = pooler_safe_query_scalar::<String>(statement)
        .bind(&quoted_table_name)
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?
        .into_iter()
        .map(|expression| normalize_check_constraint_expression(&expression))
        .collect::<Vec<String>>();

    let required_key_length_expression = catalog.normalized_key_length_check_expression();
    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_key_length_expression)
    {
        let key_length_check = catalog.key_length_check_sql();
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK ({})"#,
            quoted_table_name, key_length_check
        )));
    }

    Ok(())
}

pub(super) async fn validate_expires_at_index(
    tx: &mut Tx<'_>,
    catalog: &KvCatalog,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
    let index_name = catalog.migration_index_identifier(KvIndex::ExpiresAt);
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
              AND idx.indexprs IS NULL
              AND attr.attname = $3
              AND pg_get_expr(idx.indpred, idx.indrelid) IN ($4, $5)
        )
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(&quoted_table_name)
        .bind(index_name.as_str())
        .bind(KvColumn::ExpiresAt.name())
        .bind(catalog.expires_at_index_predicate_sql())
        .bind(catalog.parenthesized_expires_at_index_predicate_sql())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_index {
        let expires_at = KvColumn::ExpiresAt.name();
        return Err(DbError::schema_mismatch(format!(
            "table {} must have partial {} index {:?}",
            quoted_table_name,
            expires_at,
            index_name.as_str()
        )));
    }

    Ok(())
}

pub(super) async fn validate_key_pattern_index(
    tx: &mut Tx<'_>,
    catalog: &KvCatalog,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
    let index_name = catalog.migration_index_identifier(KvIndex::KeyPattern);
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM pg_index idx
            JOIN pg_class index_class ON index_class.oid = idx.indexrelid
            JOIN pg_attribute attr
              ON attr.attrelid = idx.indrelid
             AND attr.attnum = idx.indkey[0]
             AND NOT attr.attisdropped
            JOIN pg_opclass opclass ON opclass.oid = idx.indclass[0]
            WHERE idx.indrelid = to_regclass($1)
              AND index_class.relname = $2
              AND idx.indisvalid
              AND idx.indnkeyatts = 1
              AND idx.indpred IS NULL
              AND idx.indexprs IS NULL
              AND attr.attname = $3
              AND opclass.opcname = 'text_pattern_ops'
        )
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_KEY_PATTERN_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(&quoted_table_name)
        .bind(index_name.as_str())
        .bind(KvColumn::Key.name())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_index {
        let key = KvColumn::Key.name();
        return Err(DbError::schema_mismatch(format!(
            "table {} must have {} text_pattern_ops index {:?}",
            quoted_table_name,
            key,
            index_name.as_str()
        )));
    }

    Ok(())
}

pub(super) async fn validate_updated_at_index(
    tx: &mut Tx<'_>,
    catalog: &KvCatalog,
) -> Result<(), DbError> {
    let quoted_table_name = catalog.quoted_table_name();
    let index_name = catalog.migration_index_identifier(KvIndex::UpdatedAt);
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
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_UPDATED_AT_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(&quoted_table_name)
        .bind(index_name.as_str())
        .bind(KvColumn::UpdatedAt.name())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_index {
        let updated_at = KvColumn::UpdatedAt.name();
        return Err(DbError::schema_mismatch(format!(
            "table {} must have {} index {:?}",
            quoted_table_name,
            updated_at,
            index_name.as_str()
        )));
    }

    Ok(())
}

pub(super) fn validate_required_column(
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

#[cfg(test)]
pub(super) fn build_migrate_statements(config: &StoreConfig) -> Vec<String> {
    KvCatalog::new(config).all_migrate_statements()
}
