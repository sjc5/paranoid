use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::crypto::{Keyset, MacOverSecret, SecretBytes};
use crate::db::{
    AuditedSql, BootstrapConfig, ComponentSchema, ComponentSchemaMigration,
    ComponentSchemaMigrationStep, ComponentSchemaMigrationTarget, ComponentSchemaValidationCheck,
    ComponentSchemaVersion, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, PgSqlState, Pool, Tx, WritePool, WriteTx,
    migrate_component_schema_in_current_transaction, normalize_check_constraint_expression,
    pooler_safe_query, pooler_safe_query_as, pooler_safe_query_scalar,
    schema_instance_key_for_parts, sql_state_from_sqlx_error, unparameterized_simple_query,
    validate_component_schema_in_current_transaction,
};

use super::postgres_method_runtime::PostgresAuthMethodRegistry;
use super::prelude::*;

mod codecs;
mod commit;
mod config;
mod errors;
mod load_paths;
mod method_commit;
mod mutations;
mod preconditions;
mod query_helpers;
mod row_reads;
mod row_writes;
mod schema;
mod secrets;
#[cfg(test)]
mod test_support;
mod transactions;

pub(super) use codecs::*;
pub(super) use config::*;
pub(super) use errors::*;
pub(super) use method_commit::*;
pub(super) use mutations::*;
pub(super) use preconditions::*;
pub(super) use query_helpers::*;
pub(super) use row_reads::*;
pub(super) use row_writes::*;
pub(super) use secrets::*;
pub(super) use transactions::*;

pub(super) const DURABLE_EFFECT_KIND_SEND_OUT_OF_BAND_MESSAGE: i32 = 1;
pub(super) const DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT: i32 = 2;
pub(super) const DURABLE_EFFECT_KIND_DELETE_APPLICATION_SUBJECT_DATA: i32 = 3;
pub(super) const DURABLE_EFFECT_KIND_DISABLE_APPLICATION_SUBJECT_DATA: i32 = 4;

pub(crate) struct PostgresAuthStore {
    config: PostgresAuthStoreConfig,
    credential_secret_keyset: Keyset,
    method_registry: Option<Arc<PostgresAuthMethodRegistry>>,
}

impl PostgresAuthStore {
    pub(crate) fn new(config: PostgresAuthStoreConfig, credential_secret_keyset: Keyset) -> Self {
        Self {
            config,
            credential_secret_keyset,
            method_registry: None,
        }
    }

    pub(crate) fn with_method_registry(
        mut self,
        registry: Arc<PostgresAuthMethodRegistry>,
    ) -> Self {
        self.method_registry = Some(registry);
        self
    }

    pub(crate) fn method_registry(&self) -> Option<&PostgresAuthMethodRegistry> {
        self.method_registry.as_deref()
    }

    pub(crate) fn config(&self) -> &PostgresAuthStoreConfig {
        &self.config
    }

    pub(crate) fn method_registry_arc(&self) -> Option<Arc<PostgresAuthMethodRegistry>> {
        self.method_registry.clone()
    }
}
