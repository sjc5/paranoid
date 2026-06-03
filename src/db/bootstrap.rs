use super::{
    DatabaseOperationKind, Error, InvalidPgIdentifier, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, PgSqlState, WritePool, WriteTx,
    finish_pool_owned_write_transaction_and_preserve_rollback_error, pooler_safe_query,
    sql_state_from_sqlx_error, unparameterized_simple_query,
};
use crate::{fleet, kv, queue};
use std::time::Duration;

const BOOTSTRAP_SCHEMA_CREATION_RACE_MAX_ATTEMPTS: u32 = 64;
const BOOTSTRAP_SCHEMA_CREATION_RACE_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Default schema name for Paranoid-owned DB primitive bootstrap.
pub const DEFAULT_BOOTSTRAP_SCHEMA_NAME: &str = "__paranoid";

const BOOTSTRAP_ADVISORY_LOCK_CLASS_ID: i32 = i32::from_be_bytes(*b"para");
const BOOTSTRAP_ADVISORY_LOCK_OBJECT_ID: i32 = i32::from_be_bytes(*b"boot");
const DB_BOOTSTRAP_OPERATION_MIGRATE_SCHEMA: &str = "db.bootstrap.migrate_schema";
const DB_BOOTSTRAP_OPERATION_ACQUIRE_LOCK: &str = "db.bootstrap.acquire_transaction_lock";
const DB_BOOTSTRAP_OPERATION_CREATE_SCHEMA: &str = "db.bootstrap.create_schema";

/// Configuration for bootstrapping Paranoid's Postgres-backed primitives into one schema.
///
/// This config derives KV, Fleet, and Queue table names from one schema name so
/// applications do not have to manually keep Paranoid subsystem table layouts in sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapConfig {
    schema_name: PgSchemaName,
}

/// Store handles configured by [`BootstrapConfig`].
#[derive(Clone, Debug)]
pub struct BootstrapStores {
    /// KV store configured in the bootstrap schema.
    pub kv: kv::Store,
    /// Fleet store configured in the bootstrap schema.
    pub fleet: fleet::Store,
    /// Queue store configured in the bootstrap schema.
    pub queue: queue::Store,
}

/// Error returned by Paranoid DB bootstrap.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// Database foundation operation failed.
    #[error(transparent)]
    Database(#[from] Error),
    /// KV store configuration failed.
    #[error(transparent)]
    Kv(#[from] kv::Error),
    /// Fleet store configuration failed.
    #[error(transparent)]
    Fleet(#[from] fleet::Error),
    /// Queue store configuration or migration failed.
    #[error(transparent)]
    Queue(#[from] queue::Error),
    /// Postgres kept reporting a concurrent schema-creation catalog race.
    #[error(
        "concurrent Postgres schema creation race during Paranoid DB bootstrap after {attempts} attempts"
    )]
    ConcurrentSchemaCreationRace {
        /// Number of bootstrap attempts.
        attempts: u32,
    },
    /// Bootstrap failed and transaction rollback also failed.
    #[error("Paranoid DB bootstrap operation {operation} failed, then transaction rollback failed")]
    DatabaseOperationRollbackFailed {
        /// Operation being cleaned up.
        operation: &'static str,
        /// Original bootstrap error.
        operation_error: Box<BootstrapError>,
        /// Rollback failure.
        rollback_error: Box<Error>,
    },
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            schema_name: PgSchemaName::from_identifier_text(DEFAULT_BOOTSTRAP_SCHEMA_NAME)
                .expect("default bootstrap schema name must be a valid Postgres identifier"),
        }
    }
}

impl BootstrapConfig {
    /// Creates a bootstrap config for a validated schema name.
    pub fn new(schema_name: PgSchemaName) -> Self {
        Self { schema_name }
    }

    /// Validates a schema name and creates a bootstrap config.
    pub fn from_schema_name_text(
        schema_name: impl AsRef<str>,
    ) -> Result<Self, InvalidPgIdentifier> {
        Ok(Self::new(PgSchemaName::from_identifier_text(schema_name)?))
    }

    /// Returns the configured schema name.
    pub fn schema_name(&self) -> &PgSchemaName {
        &self.schema_name
    }

    /// Builds KV, Fleet, and Queue store handles for this bootstrap config.
    pub fn stores(&self) -> Result<BootstrapStores, BootstrapError> {
        let schema_ledger_table_name =
            self.qualified_table_name(super::DEFAULT_SCHEMA_LEDGER_TABLE_NAME);

        let kv_config = kv::StoreConfig {
            table_name: self.qualified_table_name(kv::DEFAULT_TABLE_NAME),
            schema_ledger_table_name: schema_ledger_table_name.clone(),
            create_updated_at_index: true,
        };

        let fleet_config = fleet::StoreConfig {
            root_key: fleet::RootKey::default(),
            state_table_name: self.qualified_table_name(fleet::DEFAULT_STATE_TABLE_NAME),
            coordination_table_name: self
                .qualified_table_name(fleet::DEFAULT_COORDINATION_TABLE_NAME),
            fencing_counter_table_name: self
                .qualified_table_name(fleet::DEFAULT_FENCING_COUNTER_TABLE_NAME),
            schema_ledger_table_name: schema_ledger_table_name.clone(),
            create_state_updated_at_index: true,
        };

        let queue_config = queue::StoreConfig {
            table_name: self.qualified_table_name(queue::DEFAULT_TABLE_NAME),
            dead_letter_table_name: self
                .qualified_table_name(queue::DEFAULT_DEAD_LETTER_TABLE_NAME),
            pause_table_name: self.qualified_table_name(queue::DEFAULT_PAUSE_TABLE_NAME),
            schema_ledger_table_name,
            payload_json_limit_bytes: queue::DEFAULT_PAYLOAD_JSON_LIMIT_BYTES,
        };

        Ok(BootstrapStores {
            kv: kv::Store::new(kv_config)?,
            fleet: fleet::Store::new(fleet_config)?,
            queue: queue::Store::new(queue_config)?,
        })
    }

    /// Creates and validates KV, Fleet, and Queue schemas in one serialized transaction.
    ///
    /// This is the only Paranoid DB path that uses a Postgres advisory lock.
    /// The lock is transaction-scoped and exists only to serialize creation of
    /// Paranoid's own coordination tables before those tables are available.
    pub async fn migrate_schema(
        &self,
        pool: &WritePool,
    ) -> Result<BootstrapStores, BootstrapError> {
        for attempt in 1..=BOOTSTRAP_SCHEMA_CREATION_RACE_MAX_ATTEMPTS {
            match self.migrate_schema_once(pool).await {
                Ok(stores) => return Ok(stores),
                Err(BootstrapError::ConcurrentSchemaCreationRace { .. })
                    if attempt < BOOTSTRAP_SCHEMA_CREATION_RACE_MAX_ATTEMPTS =>
                {
                    tokio::time::sleep(BOOTSTRAP_SCHEMA_CREATION_RACE_RETRY_DELAY).await;
                }
                Err(BootstrapError::ConcurrentSchemaCreationRace { .. }) => {
                    return Err(BootstrapError::ConcurrentSchemaCreationRace { attempts: attempt });
                }
                Err(error) => return Err(error),
            }
        }

        Err(BootstrapError::ConcurrentSchemaCreationRace {
            attempts: BOOTSTRAP_SCHEMA_CREATION_RACE_MAX_ATTEMPTS,
        })
    }

    async fn migrate_schema_once(
        &self,
        pool: &WritePool,
    ) -> Result<BootstrapStores, BootstrapError> {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(BootstrapError::from)?;
        let result = async {
            let stores = self.stores()?;
            acquire_bootstrap_transaction_lock(&mut tx).await?;
            create_bootstrap_schema_if_needed(&mut tx, self.schema_name()).await?;
            stores
                .kv
                .migrate_schema_in_current_transaction(&mut tx)
                .await?;
            stores
                .fleet
                .migrate_schema_in_current_transaction(&mut tx)
                .await?;
            stores
                .queue
                .migrate_schema_in_current_transaction(&mut tx)
                .await?;
            Ok(stores)
        }
        .await;

        finish_pool_owned_write_transaction_and_preserve_rollback_error(
            DB_BOOTSTRAP_OPERATION_MIGRATE_SCHEMA,
            tx,
            result,
            BootstrapError::from,
            |operation, error, rollback_error| BootstrapError::DatabaseOperationRollbackFailed {
                operation,
                operation_error: Box::new(error),
                rollback_error: Box::new(rollback_error),
            },
        )
        .await
    }

    fn qualified_table_name(&self, table_name: &str) -> PgQualifiedTableName {
        PgQualifiedTableName::new(
            Some(self.schema_name.clone()),
            PgIdentifier::new(table_name)
                .expect("Paranoid default table name must be a valid Postgres identifier"),
        )
    }
}

async fn acquire_bootstrap_transaction_lock(tx: &mut WriteTx<'_>) -> Result<(), BootstrapError> {
    let statement = "SELECT pg_advisory_xact_lock($1, $2)";
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        DB_BOOTSTRAP_OPERATION_ACQUIRE_LOCK,
        Some(statement),
    );
    pooler_safe_query(statement)
        .bind(BOOTSTRAP_ADVISORY_LOCK_CLASS_ID)
        .bind(BOOTSTRAP_ADVISORY_LOCK_OBJECT_ID)
        .execute(tx.inner.as_mut())
        .await
        .map_err(Error::query)?;
    Ok(())
}

async fn create_bootstrap_schema_if_needed(
    tx: &mut WriteTx<'_>,
    schema_name: &PgSchemaName,
) -> Result<(), BootstrapError> {
    let statement = format!(
        "CREATE SCHEMA IF NOT EXISTS {}",
        schema_name.identifier().quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        DB_BOOTSTRAP_OPERATION_CREATE_SCHEMA,
        Some(statement.as_str()),
    );
    let create_schema_result =
        unparameterized_simple_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.inner.as_mut())
            .await;
    match create_schema_result {
        Ok(_) => Ok(()),
        Err(error) if sql_state_from_sqlx_error(&error) == Some(PgSqlState::UniqueViolation) => {
            Err(BootstrapError::ConcurrentSchemaCreationRace { attempts: 1 })
        }
        Err(error) => Err(BootstrapError::from(Error::query(error))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bootstrap_config_derives_every_store_table_from_one_schema() {
        let config = BootstrapConfig::default();
        let stores = config.stores().expect("bootstrap stores");
        let expected_schema = config.schema_name();

        for table_name in [
            &stores.kv.config().table_name,
            &stores.kv.config().schema_ledger_table_name,
            &stores.fleet.config().state_table_name,
            &stores.fleet.config().coordination_table_name,
            &stores.fleet.config().fencing_counter_table_name,
            &stores.fleet.config().schema_ledger_table_name,
            &stores.queue.config().table_name,
            &stores.queue.config().dead_letter_table_name,
            &stores.queue.config().pause_table_name,
            &stores.queue.config().schema_ledger_table_name,
        ] {
            assert_eq!(table_name.schema(), Some(expected_schema));
        }
    }

    #[test]
    fn default_bootstrap_config_uses_distinct_subsystem_tables_and_one_schema_ledger() {
        let stores = BootstrapConfig::default()
            .stores()
            .expect("bootstrap stores");

        assert_ne!(
            stores.kv.config().table_name,
            stores.fleet.config().state_table_name
        );
        assert_ne!(
            stores.queue.config().table_name,
            stores.queue.config().dead_letter_table_name
        );
        assert_eq!(
            stores.kv.config().schema_ledger_table_name,
            stores.fleet.config().schema_ledger_table_name
        );
        assert_eq!(
            stores.kv.config().schema_ledger_table_name,
            stores.queue.config().schema_ledger_table_name
        );
    }
}
