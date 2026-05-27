use super::*;
use super::{
    schema_migration::*,
    schema_validation::validate_schema_in_current_transaction as validate_physical_schema_in_current_transaction,
};

/// Runs idempotent queue schema migration and validates the result.
pub(crate) async fn migrate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), Error> {
    let mut tx = pool.begin_transaction().await?;
    let result = migrate_schema_in_current_transaction(&mut tx, config).await;
    finish_queue_pool_transaction(QUEUE_OPERATION_SCHEMA_MIGRATE, tx, result).await
}

/// Runs queue schema migration inside the caller's active transaction.
pub(crate) async fn migrate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let queue = Store::new(config.clone())?;
    execute_queue_migration_statements_in_current_transaction(tx, queue.config()).await?;
    validate_physical_schema_in_current_transaction(tx, queue.config()).await?;
    record_queue_schema_version_in_current_transaction(tx, queue.config()).await?;
    validate_queue_schema_version_in_current_transaction(tx, queue.config()).await?;
    Ok(())
}

/// Validates an existing queue schema.
pub(crate) async fn validate_schema(pool: &Pool, config: &StoreConfig) -> Result<(), Error> {
    let mut tx = pool.begin_transaction().await?;
    let validation_result = validate_schema_in_current_transaction(&mut tx, config).await;
    finish_queue_validation_transaction(QUEUE_OPERATION_SCHEMA_VALIDATE, tx, validation_result)
        .await
}

/// Validates an existing queue schema inside the caller's active transaction.
pub(crate) async fn validate_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let queue = Store::new(config.clone())?;
    validate_physical_schema_in_current_transaction(tx, queue.config()).await?;
    validate_queue_schema_version_in_current_transaction(tx, queue.config()).await?;
    Ok(())
}

async fn record_queue_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let instance_key = queue_schema_instance_key(config);
    record_component_schema_version_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        ComponentSchemaVersion {
            component: QUEUE_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: QUEUE_SCHEMA_VERSION,
            fingerprint: QUEUE_SCHEMA_FINGERPRINT,
        },
    )
    .await?;
    Ok(())
}

async fn validate_queue_schema_version_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let instance_key = queue_schema_instance_key(config);
    validate_component_schema_version_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        ComponentSchemaVersion {
            component: QUEUE_SCHEMA_COMPONENT,
            instance_key: &instance_key,
            version: QUEUE_SCHEMA_VERSION,
            fingerprint: QUEUE_SCHEMA_FINGERPRINT,
        },
    )
    .await?;
    Ok(())
}

fn queue_schema_instance_key(config: &StoreConfig) -> String {
    schema_instance_key_for_parts([
        ("jobs_table", &config.table_name),
        ("dead_letter_table", &config.dead_letter_table_name),
        ("pause_table", &config.pause_table_name),
    ])
}
