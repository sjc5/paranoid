use super::protocol::{SUPPORTED_EPOCH, SUPPORTED_FINGERPRINT};
use super::{
    ComponentSchemaMigrationPlan, ComponentSchemaVersion, DatabaseOperationKind, Error,
    PgQualifiedTableName, Protocol, ProtocolError, Tx, WriteTx,
    plan_component_schema_migration_in_current_transaction, pooler_safe_query,
    pooler_safe_query_as, pooler_safe_query_scalar,
    record_component_schema_migration_completion_in_current_transaction,
    schema_instance_key_for_parts,
};

pub(crate) async fn protocol_exists(tx: &mut Tx<'_>, protocol: &Protocol) -> Result<bool, Error> {
    let statement = "SELECT pg_catalog.to_regclass($1) IS NOT NULL";
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "paranoid.protocol.inspect_placement",
        Some(statement),
    );
    pooler_safe_query_scalar::<bool>(statement)
        .bind(protocol.table_name().quoted().to_string())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(Error::query)
}

/// The bootstrap caller holds serialization and has checked the unversioned source before creation.
pub(crate) async fn prepare_protocol(
    tx: &mut WriteTx<'_>,
    protocol: &Protocol,
    ledger: &PgQualifiedTableName,
    create: bool,
) -> Result<(), Error> {
    if create {
        let statement = format!(
            "CREATE TABLE {} (singleton pg_catalog.int4 PRIMARY KEY CHECK (singleton = 1), \
             epoch pg_catalog.int4 NOT NULL CHECK (epoch > 0), \
             fingerprint pg_catalog.text COLLATE \"C\" NOT NULL \
             CHECK (pg_catalog.octet_length(fingerprint) > 0 AND pg_catalog.octet_length(fingerprint) <= 256))",
            protocol.table_name().quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "paranoid.protocol.create",
            Some(&statement),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.inner.as_mut())
            .await
            .map_err(Error::query)?;
        let statement = format!(
            "INSERT INTO {} (singleton, epoch, fingerprint) VALUES (1, $1, $2) RETURNING singleton, epoch, fingerprint",
            protocol.table_name().quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "paranoid.protocol.initialize",
            Some(&statement),
        );
        let rows =
            pooler_safe_query_as::<(i32, i32, String)>(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(SUPPORTED_EPOCH)
                .bind(SUPPORTED_FINGERPRINT)
                .fetch_all(tx.inner.as_mut())
                .await
                .map_err(Error::query)?;
        if rows.as_slice() != [(1, SUPPORTED_EPOCH, SUPPORTED_FINGERPRINT.to_owned())] {
            return Err(ProtocolError::State {
                reason: "protocol initialization did not return the selected control record",
            }
            .into());
        }
    }
    protocol.admit(tx).await?;
    validate_protocol_catalog(tx, protocol).await?;
    let instance_key = schema_instance_key_for_parts([("protocol_table", protocol.table_name())]);
    let version = ComponentSchemaVersion {
        component: "paranoid_protocol",
        instance_key: &instance_key,
        version: 1,
        fingerprint: "paranoid.protocol-table.v1",
    };
    let plan =
        plan_component_schema_migration_in_current_transaction(tx, ledger, version, &[]).await?;
    match plan {
        ComponentSchemaMigrationPlan::FreshInstall if create => {
            record_component_schema_migration_completion_in_current_transaction(
                tx, ledger, version, None,
            )
            .await
        }
        ComponentSchemaMigrationPlan::AlreadyCurrent if !create => Ok(()),
        _ => Err(ProtocolError::State {
            reason: "protocol relation and physical schema ledger do not agree",
        }
        .into()),
    }
}

async fn validate_protocol_catalog(tx: &mut Tx<'_>, protocol: &Protocol) -> Result<(), Error> {
    let statement = r#"
SELECT (
    SELECT count(*) = 3 FROM pg_catalog.pg_attribute a
    LEFT JOIN pg_catalog.pg_collation c ON c.oid = a.attcollation
    WHERE a.attrelid = pg_catalog.to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped AND a.attnotnull
      AND ((a.attname IN ('singleton', 'epoch') AND a.atttypid = 'pg_catalog.int4'::pg_catalog.regtype)
        OR (a.attname = 'fingerprint' AND a.atttypid = 'pg_catalog.text'::pg_catalog.regtype AND c.collname = 'C'))
) AND EXISTS (
    SELECT 1 FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attname = 'singleton'
    JOIN pg_catalog.pg_opclass o ON o.oid = i.indclass[0]
    WHERE i.indrelid = pg_catalog.to_regclass($1) AND i.indisprimary AND i.indisunique
      AND i.indisvalid AND i.indisready AND i.indimmediate AND i.indnkeyatts = 1
      AND i.indkey[0] = a.attnum AND i.indexprs IS NULL AND i.indpred IS NULL
      AND o.opcname = 'int4_ops'
)"#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "paranoid.protocol.validate_columns_and_primary_key",
        Some(statement),
    );
    let valid = pooler_safe_query_scalar::<bool>(statement)
        .bind(protocol.table_name().quoted().to_string())
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(Error::query)?;
    if !valid {
        return Err(ProtocolError::State {
            reason: "protocol columns or primary key are incompatible",
        }
        .into());
    }
    let statement = crate::db::schema::BUILTIN_CHECK_EXPRESSIONS_SQL;
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "paranoid.protocol.validate_checks",
        Some(statement),
    );
    let checks = pooler_safe_query_scalar::<String>(statement)
        .bind(protocol.table_name().quoted().to_string())
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(Error::query)?;
    let normalized = checks
        .iter()
        .map(|value| crate::db::schema::normalize_builtin_check_expression(value))
        .collect::<Vec<_>>();
    for required in [
        "singleton=1",
        "epoch>0",
        "(octet_length(fingerprint)>0)AND(octet_length(fingerprint)<=256)",
    ] {
        if !normalized.iter().any(|value| value == required) {
            return Err(ProtocolError::State {
                reason: "protocol domain constraints are incompatible",
            }
            .into());
        }
    }
    Ok(())
}

/// Existing state without protocol metadata must have its exact recognized source ledger entry.
pub(crate) async fn validate_protocol_adoption_source(
    tx: &mut Tx<'_>,
    ledger: &PgQualifiedTableName,
    version: ComponentSchemaVersion<'_>,
    state_tables: &[&PgQualifiedTableName],
) -> Result<(), Error> {
    let statement = format!(
        "SELECT schema_version, schema_fingerprint FROM ONLY {} WHERE component = $1 AND instance_key = $2 FOR UPDATE",
        ledger.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "paranoid.protocol.inspect_source_version",
        Some(&statement),
    );
    let recorded = pooler_safe_query_as::<(i32, String)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(version.component)
        .bind(version.instance_key)
        .fetch_optional(tx.inner.as_mut())
        .await
        .map_err(Error::query)?;
    if let Some((recorded_version, fingerprint)) = recorded {
        return if recorded_version == version.version && fingerprint == version.fingerprint {
            Ok(())
        } else {
            Err(ProtocolError::State {
                reason: "unversioned installation contains an unsupported component version",
            }
            .into())
        };
    }
    let names = state_tables
        .iter()
        .map(|name| name.quoted().to_string())
        .collect::<Vec<_>>();
    let statement = "SELECT EXISTS (SELECT 1 FROM pg_catalog.unnest($1::pg_catalog.text[]) AS relations(name) WHERE pg_catalog.to_regclass(name) IS NOT NULL)";
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "paranoid.protocol.inspect_unrecorded_state",
        Some(statement),
    );
    let exists = pooler_safe_query_scalar::<bool>(statement)
        .bind(names)
        .fetch_one(tx.inner.as_mut())
        .await
        .map_err(Error::query)?;
    if exists {
        Err(ProtocolError::State {
            reason: "unversioned existing state has no recorded source version",
        }
        .into())
    } else {
        Ok(())
    }
}
