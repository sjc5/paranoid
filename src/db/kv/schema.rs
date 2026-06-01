use super::*;

/// Creates and validates the configured KV schema inside one transaction.
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
    let create_table_statement = build_create_table_statement(config);
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        KV_OPERATION_SCHEMA_CREATE_TABLE,
        Some(create_table_statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(create_table_statement.as_str()))
        .execute(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    let quoted_table_name = config.table_name.quoted().to_string();
    validate_required_columns(tx, &quoted_table_name).await?;
    validate_key_conflict_arbiter(tx, &quoted_table_name).await?;

    for statement in build_create_index_statements(config) {
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

    validate_physical_schema_in_current_transaction(tx, config).await?;
    record_kv_schema_version_in_current_transaction(tx, config).await?;
    validate_schema_in_current_transaction(tx, config).await
}

/// Validates that the configured KV schema already exists and is compatible.
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
    let quoted_table_name = config.table_name.quoted().to_string();
    validate_required_columns(tx, &quoted_table_name).await?;
    validate_key_conflict_arbiter(tx, &quoted_table_name).await?;
    validate_required_check_constraints(tx, &quoted_table_name).await?;
    validate_expires_at_index(tx, config, &quoted_table_name).await?;
    validate_key_pattern_index(tx, config, &quoted_table_name).await?;
    if config.create_updated_at_index {
        validate_updated_at_index(tx, config, &quoted_table_name).await?;
    }
    Ok(())
}

pub(super) async fn validate_required_columns(
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
        KV_OPERATION_SCHEMA_VALIDATE_COLUMNS,
        Some(statement),
    );
    let actual_columns = pooler_safe_query_as::<(String, String, bool, Option<String>)>(statement)
        .bind(quoted_table_name)
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

    for required_column in required_columns() {
        let Some(actual_column) = actual_columns
            .iter()
            .find(|column| column.name == required_column.name)
        else {
            return Err(DbError::schema_mismatch(format!(
                "required column {:?} not found on table {}",
                required_column.name, quoted_table_name
            )));
        };

        validate_required_column(quoted_table_name, required_column, actual_column)?;
    }

    Ok(())
}

async fn record_kv_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), DbError> {
    let instance_key = kv_schema_instance_key(config);
    record_component_schema_version_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        ComponentSchemaVersion {
            component: KV_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: KV_SCHEMA_VERSION,
            fingerprint: KV_SCHEMA_FINGERPRINT,
        },
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
        ComponentSchemaVersion {
            component: KV_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: KV_SCHEMA_VERSION,
            fingerprint: KV_SCHEMA_FINGERPRINT,
        },
    )
    .await
}

fn kv_schema_instance_key(config: &StoreConfig) -> String {
    schema_instance_key_for_parts([("table", &config.table_name)])
}

pub(super) async fn validate_key_conflict_arbiter(
    tx: &mut Tx<'_>,
    quoted_table_name: &str,
) -> Result<(), DbError> {
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
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER,
        Some(statement),
    );
    let has_usable_unique_key = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_usable_unique_key {
        return Err(DbError::schema_mismatch(
            r#"column "key" must have a unique or primary key constraint usable by ON CONFLICT (key)"#,
        ));
    }

    Ok(())
}

pub(super) async fn validate_required_check_constraints(
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
        KV_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS,
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

    let required_key_length_expression =
        format!("(octet_length(key)>0)AND(octet_length(key)<={MAX_KV_KEY_BYTES})");
    if !normalized_check_expressions
        .iter()
        .any(|expression| expression == &required_key_length_expression)
    {
        return Err(DbError::schema_mismatch(format!(
            r#"table {} must enforce CHECK (octet_length(key) > 0 AND octet_length(key) <= {})"#,
            quoted_table_name, MAX_KV_KEY_BYTES
        )));
    }

    Ok(())
}

pub(super) async fn validate_expires_at_index(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    quoted_table_name: &str,
) -> Result<(), DbError> {
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
              AND idx.indexprs IS NULL
              AND attr.attname = 'expires_at'
              AND pg_get_expr(idx.indpred, idx.indrelid) IN (
                  'expires_at IS NOT NULL',
                  '(expires_at IS NOT NULL)'
              )
        )
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .bind(index_name.as_str())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_index {
        return Err(DbError::schema_mismatch(format!(
            "table {} must have partial expires_at index {:?}",
            quoted_table_name,
            index_name.as_str()
        )));
    }

    Ok(())
}

pub(super) async fn validate_key_pattern_index(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    quoted_table_name: &str,
) -> Result<(), DbError> {
    let index_name = migration_index_identifier(config, KEY_PATTERN_INDEX_SUFFIX);
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
              AND attr.attname = 'key'
              AND opclass.opcname = 'text_pattern_ops'
        )
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_KEY_PATTERN_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .bind(index_name.as_str())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_index {
        return Err(DbError::schema_mismatch(format!(
            "table {} must have key text_pattern_ops index {:?}",
            quoted_table_name,
            index_name.as_str()
        )));
    }

    Ok(())
}

pub(super) async fn validate_updated_at_index(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
    quoted_table_name: &str,
) -> Result<(), DbError> {
    let index_name = migration_index_identifier(config, UPDATED_AT_INDEX_SUFFIX);
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
              AND attr.attname = 'updated_at'
        )
        "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        KV_OPERATION_SCHEMA_VALIDATE_UPDATED_AT_INDEX,
        Some(statement),
    );
    let has_index = pooler_safe_query_scalar::<bool>(statement)
        .bind(quoted_table_name)
        .bind(index_name.as_str())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(DbError::query)?;

    if !has_index {
        return Err(DbError::schema_mismatch(format!(
            "table {} must have updated_at index {:?}",
            quoted_table_name,
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

pub(super) fn required_columns() -> [RequiredColumn; 4] {
    [
        RequiredColumn {
            name: "key",
            data_type: "text",
            not_null: true,
            allowed_collations: &["C", "POSIX"],
        },
        RequiredColumn {
            name: "value",
            data_type: "bytea",
            not_null: true,
            allowed_collations: &[],
        },
        RequiredColumn {
            name: "expires_at",
            data_type: "timestamp with time zone",
            not_null: false,
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

#[cfg(test)]
pub(super) fn build_migrate_statements(config: &StoreConfig) -> Vec<String> {
    let mut statements = Vec::with_capacity(if config.create_updated_at_index { 4 } else { 3 });
    statements.push(build_create_table_statement(config));
    statements.extend(build_create_index_statements(config));
    statements
}

pub(super) fn build_create_index_statements(config: &StoreConfig) -> Vec<String> {
    let mut statements = Vec::with_capacity(if config.create_updated_at_index { 3 } else { 2 });
    statements.push(build_create_expires_at_index_statement(config));
    statements.push(build_create_key_pattern_index_statement(config));
    if config.create_updated_at_index {
        statements.push(build_create_updated_at_index_statement(config));
    }
    statements
}

pub(super) fn build_create_table_statement(config: &StoreConfig) -> String {
    format!(
        r#"{CREATE_KV_TABLE_TEMPLATE_PREFIX}{} (
    key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= {MAX_KV_KEY_BYTES}),
    value BYTEA NOT NULL,
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL
)"#,
        config.table_name.quoted()
    )
}

pub(super) fn build_create_expires_at_index_statement(config: &StoreConfig) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (expires_at)\nWHERE expires_at IS NOT NULL",
        migration_index_identifier(config, EXPIRES_AT_INDEX_SUFFIX).quoted(),
        config.table_name.quoted()
    )
}

pub(super) fn build_create_key_pattern_index_statement(config: &StoreConfig) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (key text_pattern_ops)",
        migration_index_identifier(config, KEY_PATTERN_INDEX_SUFFIX).quoted(),
        config.table_name.quoted()
    )
}

pub(super) fn build_create_updated_at_index_statement(config: &StoreConfig) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} (updated_at)",
        migration_index_identifier(config, UPDATED_AT_INDEX_SUFFIX).quoted(),
        config.table_name.quoted()
    )
}
