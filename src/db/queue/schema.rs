#[cfg(test)]
use crate::db::schema_ledger::validate_component_schema_with_compatible_prepared_versions;
use crate::db::schema_ledger::{
    CompatibleComponentSchemaPlan, plan_component_schema_with_compatible_prepared_versions,
};
const COMPATIBLE_PREPARED_QUEUE_VERSIONS: &[crate::db::ComponentSchemaMigrationTarget<'static>] =
    &[crate::db::ComponentSchemaMigrationTarget::new(
        2,
        "paranoid.queue.v2",
    )];
#[cfg(test)]
use super::schema_validation::deep_validate_schema_in_current_transaction;
use super::*;
use super::{
    schema_migration::*,
    schema_validation::validate_schema_in_current_transaction as validate_physical_schema_in_current_transaction,
};

/// Runs idempotent queue schema migration and validates the result.
#[cfg(any(test, feature = "component-authoring"))]
pub(crate) async fn migrate_schema(pool: &WritePool, config: &StoreConfig) -> Result<(), Error> {
    let mut tx = pool.begin_transaction().await?;
    let result = migrate_schema_in_current_transaction(&mut tx, config).await;
    finish_queue_pool_transaction(QUEUE_OPERATION_SCHEMA_MIGRATE, tx, result).await
}

/// Runs queue schema migration inside the caller's active transaction.
pub(crate) async fn migrate_schema_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    config.protocol.admit(tx).await?;
    let queue = Store::new_inner(config.clone())?;
    let instance_key = queue_schema_instance_key(queue.config_inner());
    let component_schema_version = queue_component_schema_version(&instance_key);
    let migration_plan = plan_component_schema_with_compatible_prepared_versions(
        tx,
        &queue.config_inner().schema_ledger_table_name,
        component_schema_version,
        QUEUE_SCHEMA_MIGRATION_STEPS,
        COMPATIBLE_PREPARED_QUEUE_VERSIONS,
    )
    .await?;

    let migration_plan = match migration_plan {
        CompatibleComponentSchemaPlan::Prepared => {
            validate_physical_schema_in_current_transaction(tx, config).await?;
            return super::schema_validation::validate_prepared_claim_token_in_current_transaction(
                tx, config,
            )
            .await;
        }
        CompatibleComponentSchemaPlan::Migrate(plan) => plan,
    };

    match migration_plan {
        ComponentSchemaMigrationPlan::FreshInstall => {
            execute_queue_migration_statements_in_current_transaction(tx, queue.config_inner())
                .await?;
            validate_physical_schema_in_current_transaction(tx, queue.config_inner()).await?;
            record_queue_schema_migration_completion_in_current_transaction(
                tx,
                queue.config_inner(),
                component_schema_version,
                None,
            )
            .await?;
            Ok(())
        }
        ComponentSchemaMigrationPlan::AlreadyCurrent => {
            execute_queue_migration_statements_in_current_transaction(tx, queue.config_inner())
                .await?;
            validate_physical_schema_in_current_transaction(tx, queue.config_inner()).await?;
            Ok(())
        }
        ComponentSchemaMigrationPlan::Upgrade { from, steps } => {
            execute_queue_schema_upgrade_steps_in_current_transaction(
                tx,
                queue.config_inner(),
                &steps,
            )
            .await?;
            validate_physical_schema_in_current_transaction(tx, queue.config_inner()).await?;
            record_queue_schema_migration_completion_in_current_transaction(
                tx,
                queue.config_inner(),
                component_schema_version,
                Some(&from),
            )
            .await?;
            Ok(())
        }
    }
}

/// Validates an existing queue schema.
#[cfg(test)]
pub(crate) async fn validate_schema(pool: &WritePool, config: &StoreConfig) -> Result<(), Error> {
    let mut tx = pool.begin_transaction().await?;
    let validation_result = validate_schema_in_current_transaction(&mut tx, config).await;
    finish_queue_validation_transaction(QUEUE_OPERATION_SCHEMA_VALIDATE, tx, validation_result)
        .await
}

/// Deep semantic schema validation (catalog checks plus active constraint-rejection probes).
///
/// Test/opt-in only — not part of the production boot path. This is the tool that proves a
/// broadened (over-permissive) CHECK constraint is rejected, which catalog fragment matching
/// cannot detect on its own.
#[cfg(test)]
pub(crate) async fn deep_validate_schema(
    pool: &WritePool,
    config: &StoreConfig,
) -> Result<(), Error> {
    let mut tx = pool.begin_transaction().await?;
    let validation_result = deep_validate_schema_in_current_transaction(&mut tx, config).await;
    finish_queue_validation_transaction(QUEUE_OPERATION_SCHEMA_VALIDATE, tx, validation_result)
        .await
}

/// Validates an existing queue schema inside the caller's active transaction.
#[cfg(test)]
pub(crate) async fn validate_schema_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    config.protocol.admit(tx).await?;
    let queue = Store::new_inner(config.clone())?;
    validate_physical_schema_in_current_transaction(tx, queue.config_inner()).await?;
    validate_queue_schema_version_in_current_transaction(tx, queue.config_inner()).await?;
    Ok(())
}

async fn record_queue_schema_migration_completion_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &StoreConfig,
    component_schema_version: ComponentSchemaVersion<'_>,
    prior_recorded_version: Option<&RecordedComponentSchemaVersion>,
) -> Result<(), Error> {
    record_component_schema_migration_completion_in_current_transaction(
        tx,
        &config.schema_ledger_table_name,
        component_schema_version,
        prior_recorded_version,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
async fn validate_queue_schema_version_in_current_transaction(
    tx: &mut WriteTx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    let instance_key = queue_schema_instance_key(config);
    validate_component_schema_with_compatible_prepared_versions(
        tx,
        &config.schema_ledger_table_name,
        queue_component_schema_version(&instance_key),
        COMPATIBLE_PREPARED_QUEUE_VERSIONS,
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

fn queue_component_schema_version(instance_key: &str) -> ComponentSchemaVersion<'_> {
    ComponentSchemaVersion {
        component: QUEUE_SCHEMA_COMPONENT,
        instance_key,
        version: QUEUE_SCHEMA_VERSION,
        fingerprint: QUEUE_SCHEMA_FINGERPRINT,
    }
}

async fn execute_queue_schema_upgrade_steps_in_current_transaction(
    _tx: &mut WriteTx<'_>,
    _config: &StoreConfig,
    steps: &[ComponentSchemaMigrationStep<'_>],
) -> Result<(), Error> {
    debug_assert!(
        steps.is_empty(),
        "Queue has no executable schema upgrade steps yet"
    );
    if steps.is_empty() {
        return Ok(());
    }
    Err(DbError::schema_mismatch(
        "Queue schema upgrade steps were planned but no Queue upgrade executor exists",
    )
    .into())
}

impl Store {
    pub(crate) async fn validate_protocol_adoption_source(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), DbError> {
        let key = queue_schema_instance_key(&self.config);
        crate::db::protocol_schema::validate_protocol_adoption_source(
            tx,
            &self.config.schema_ledger_table_name,
            queue_component_schema_version(&key),
            &[
                &self.config.table_name,
                &self.config.dead_letter_table_name,
                &self.config.pause_table_name,
            ],
        )
        .await
    }
}
