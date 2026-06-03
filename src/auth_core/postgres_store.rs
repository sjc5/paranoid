use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::crypto::{Keyset, MacOverSecret, SecretBytes};
use crate::db::{
    ComponentSchemaVersion, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Pool, Tx, pooler_safe_query, pooler_safe_query_as, pooler_safe_query_scalar,
    record_component_schema_version_in_current_transaction, unparameterized_simple_query,
    validate_component_schema_version_in_current_transaction,
};

use super::postgres_method_runtime::PostgresAuthMethodRegistry;
use super::*;

const AUTH_SCHEMA_COMPONENT: &str = "auth_core";
const AUTH_SCHEMA_VERSION: i32 = 1;
const AUTH_SCHEMA_FINGERPRINT: &str = "auth-core-postgres-v1";
const DEFAULT_AUTH_TABLE_PREFIX: &str = crate::db::DEFAULT_RESERVED_DB_OBJECT_PREFIX;
const AUTH_CREDENTIAL_SECRET_BYTES: usize = 32;
const SESSION_SECRET_MAC_CONTEXT_PREFIX: &[u8] = b"paranoid/auth/v1/session-secret";
const TRUSTED_DEVICE_SECRET_MAC_CONTEXT_PREFIX: &[u8] = b"paranoid/auth/v1/trusted-device-secret";
const ACTIVE_PROOF_CONTINUATION_SECRET_MAC_CONTEXT_PREFIX: &[u8] =
    b"paranoid/auth/v1/active-proof-continuation-secret";
const DURABLE_EFFECT_KIND_SEND_OUT_OF_BAND_MESSAGE: i32 = 1;
const DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT: i32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresAuthStoreConfig {
    schema: Option<PgSchemaName>,
    table_prefix: PgIdentifier,
}

impl PostgresAuthStoreConfig {
    pub(crate) fn new(
        schema: Option<PgSchemaName>,
        table_prefix: PgIdentifier,
    ) -> Result<Self, PostgresAuthStoreError> {
        let config = Self {
            schema,
            table_prefix,
        };
        config.table_names()?;
        Ok(config)
    }

    pub(crate) fn table_name(
        &self,
        table: PostgresAuthCoreTable,
    ) -> Result<PgQualifiedTableName, PostgresAuthStoreError> {
        let table_name = PgIdentifier::new(format!(
            "{}{}",
            self.table_prefix.as_str(),
            table.default_suffix()
        ))
        .map_err(DbError::from)?;
        Ok(PgQualifiedTableName::new(self.schema.clone(), table_name))
    }

    fn table_names(&self) -> Result<AuthCoreTableNames, PostgresAuthStoreError> {
        AuthCoreTableNames::new(self)
    }
}

impl Default for PostgresAuthStoreConfig {
    fn default() -> Self {
        Self {
            schema: None,
            table_prefix: PgIdentifier::new(DEFAULT_AUTH_TABLE_PREFIX)
                .expect("default auth table prefix must be a valid Postgres identifier"),
        }
    }
}

pub(crate) trait PostgresAuthMethodCommitExecutor: Send + Sync {
    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostgresAuthMethodCommitStage {
    EnforcePrecondition,
    ApplyMutation,
    AppendDurableEffectCommand,
}

#[derive(Debug)]
pub(crate) enum PostgresAuthMethodCommitError {
    Database(DbError),
    InvalidOperation(String),
    PreconditionFailed(&'static str),
    UnregisteredMethod {
        family: ProofFamily,
        method_label: String,
    },
}

impl fmt::Display for PostgresAuthMethodCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "{error}"),
            Self::InvalidOperation(operation) => {
                write!(f, "unsupported method commit operation: {operation}")
            }
            Self::PreconditionFailed(reason) => {
                write!(f, "method commit precondition failed: {reason}")
            }
            Self::UnregisteredMethod {
                family,
                method_label,
            } => write!(
                f,
                "no registered method plugin for {family:?}/{method_label}"
            ),
        }
    }
}

impl std::error::Error for PostgresAuthMethodCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidOperation(_)
            | Self::PreconditionFailed(_)
            | Self::UnregisteredMethod { .. } => None,
        }
    }
}

impl From<DbError> for PostgresAuthMethodCommitError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

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

    pub(crate) async fn migrate_schema(&self, pool: &Pool) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.migrate_schema_in_current_transaction(&mut tx).await;
        finish_auth_store_transaction("auth_core.migrate_schema", tx, result).await
    }

    pub(crate) async fn validate_schema(&self, pool: &Pool) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.validate_schema_in_current_transaction(&mut tx).await;
        finish_auth_store_validation_transaction("auth_core.validate_schema", tx, result).await
    }

    pub(crate) async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
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
        let ledger_row = ComponentSchemaVersion {
            component: AUTH_SCHEMA_COMPONENT,
            instance_key: &schema_instance_key(&self.config),
            version: AUTH_SCHEMA_VERSION,
            fingerprint: AUTH_SCHEMA_FINGERPRINT,
        };
        record_component_schema_version_in_current_transaction(
            tx,
            &crate::db::SchemaLedgerConfig::default().table_name,
            ledger_row,
        )
        .await?;
        validate_auth_schema_ledger_in_current_transaction(tx, &self.config).await?;
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
        validate_auth_schema_ledger_in_current_transaction(tx, &self.config).await?;
        Ok(())
    }

    pub(crate) async fn load_state_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        request: AuthLoadStateRequest<'_>,
    ) -> Result<LoadedState, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let mut loaded = LoadedState {
            session_cookie: request.presented_cookies().session_cookie.clone(),
            trusted_device_cookie: request.presented_cookies().trusted_device_cookie.clone(),
            ..LoadedState::default()
        };

        for requirement in request.loaded_state_contract().required() {
            match requirement {
                LoadedStateRequirement::PresentedSessionCookie { .. }
                | LoadedStateRequirement::PresentedTrustedDeviceCookie { .. } => {}
                LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
                    session_id,
                } => {
                    self.load_session_record_and_secret_match(
                        tx,
                        &table_names,
                        &mut loaded,
                        session_id,
                        request.presented_cookie_secrets(),
                        request.now(),
                    )
                    .await?;
                }
                LoadedStateRequirement::TrustedDeviceRecordAndSecretMatchForPresentedCookie {
                    device_credential_id,
                } => {
                    self.load_trusted_device_record_and_secret_match(
                        tx,
                        &table_names,
                        &mut loaded,
                        device_credential_id,
                        request.presented_cookie_secrets(),
                        request.now(),
                    )
                    .await?;
                }
                LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject { .. } => {
                    if let Some(subject_id) = loaded
                        .session_record
                        .as_ref()
                        .map(|record| record.subject_id.clone())
                    {
                        load_subject_revocation(tx, &table_names, &mut loaded, &subject_id).await?;
                    }
                }
                LoadedStateRequirement::SubjectRevocationForLoadedTrustedDeviceSubject {
                    ..
                } => {
                    if let Some(subject_id) = loaded
                        .trusted_device_record
                        .as_ref()
                        .map(|record| record.subject_id.clone())
                    {
                        load_subject_revocation(tx, &table_names, &mut loaded, &subject_id).await?;
                    }
                }
                LoadedStateRequirement::ActiveProofAttempt { attempt_id } => {
                    load_active_proof_attempt(
                        tx,
                        &table_names,
                        &mut loaded,
                        attempt_id,
                        request.presented_cookie_secrets(),
                        &self.credential_secret_keyset,
                    )
                    .await?;
                }
                LoadedStateRequirement::ActiveProofContinuationSecretMatchForPresentedCookie {
                    attempt_id,
                } => {
                    load_active_proof_continuation_secret_match(
                        tx,
                        &table_names,
                        &mut loaded,
                        attempt_id,
                        request.presented_cookie_secrets(),
                        &self.credential_secret_keyset,
                    )
                    .await?;
                }
                LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
                    ..
                } => {
                    if let Some(subject_id) = loaded
                        .active_proof_attempt_record
                        .as_ref()
                        .and_then(|record| record.subject_id.clone())
                    {
                        load_subject_revocation(tx, &table_names, &mut loaded, &subject_id).await?;
                    }
                }
                LoadedStateRequirement::SubjectRevocationForVerifiedActiveProofSubject {
                    subject_id,
                } => {
                    load_subject_revocation(tx, &table_names, &mut loaded, subject_id).await?;
                }
                LoadedStateRequirement::ActiveProofChallenge { challenge_id } => {
                    load_active_proof_challenge(tx, &table_names, &mut loaded, challenge_id)
                        .await?;
                }
            }
        }
        Ok(loaded)
    }

    pub(crate) async fn commit_atomic_work_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        request: AtomicCommitRequest<'_>,
    ) -> Result<Vec<MaterializedFreshCredentialSecret>, PostgresAuthStoreError> {
        request.atomic_work().validate_for_commit()?;
        let method_commit_executor = self.method_commit_executor_for(request.atomic_work())?;
        let table_names = self.config.table_names()?;
        for precondition in &request.atomic_work().preconditions {
            enforce_precondition(tx, &table_names, precondition).await?;
        }
        if let Some(executor) = method_commit_executor {
            enforce_method_commit_preconditions(
                tx,
                executor,
                &request.atomic_work().method_commit_work,
            )
            .await?;
        }
        let mut materialized =
            Vec::with_capacity(request.atomic_work().fresh_credential_secrets.len());
        for fresh_secret in &request.atomic_work().fresh_credential_secrets {
            materialized.push(
                self.materialize_fresh_credential_secret(tx, &table_names, fresh_secret)
                    .await?,
            );
        }
        for mutation in &request.atomic_work().mutations {
            apply_mutation(tx, &table_names, mutation).await?;
        }
        if let Some(executor) = method_commit_executor {
            apply_method_commit_mutations(tx, executor, &request.atomic_work().method_commit_work)
                .await?;
        }
        append_audit_events(tx, &table_names, &request.atomic_work().audit_events).await?;
        append_core_durable_effects(tx, &table_names, &request.atomic_work().durable_effects)
            .await?;
        if let Some(executor) = method_commit_executor {
            append_method_commit_durable_effect_commands(
                tx,
                executor,
                &request.atomic_work().method_commit_work,
            )
            .await?;
        }
        Ok(materialized)
    }

    pub(crate) async fn load_credential_lifecycle_action_context_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        target_credential_instance_id: &VerifiedProofSourceId,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Option<CredentialLifecycleActionContext>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let Some(target_credential) =
            load_credential_instance_metadata(tx, &table_names, target_credential_instance_id)
                .await?
        else {
            return Ok(None);
        };
        let authorities =
            load_credential_recovery_authorities(tx, &table_names, target_credential_instance_id)
                .await?;
        let recovery_authority_graph = CredentialRecoveryAuthorityGraph::new(authorities)?;
        let mut evidence = Vec::new();
        for source in evidence_sources {
            if let Some(loaded_evidence) =
                load_lifecycle_authority_evidence(tx, &table_names, source).await?
            {
                evidence.push(loaded_evidence);
            }
        }
        Ok(Some(CredentialLifecycleActionContext::new(
            target_credential,
            recovery_authority_graph,
            evidence,
        )))
    }

    pub(crate) async fn load_and_evaluate_credential_lifecycle_action_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        target_credential_instance_id: &VerifiedProofSourceId,
        evidence_sources: &[LifecycleAuthoritySource],
        action: CredentialLifecycleAction,
        independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    ) -> Result<Option<CredentialLifecycleActionDecision>, PostgresAuthStoreError> {
        Ok(self
            .load_credential_lifecycle_action_context_in_current_transaction(
                tx,
                target_credential_instance_id,
                evidence_sources,
            )
            .await?
            .map(|context| context.evaluate_action(action, independent_evidence_required)))
    }

    pub(crate) async fn load_pending_credential_lifecycle_action_with_target_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingCredentialLifecycleActionId,
    ) -> Result<
        Option<(
            CredentialInstanceMetadata,
            PendingCredentialLifecycleActionRecord,
        )>,
        PostgresAuthStoreError,
    > {
        let table_names = self.config.table_names()?;
        let Some(pending_action) =
            load_pending_credential_lifecycle_action(tx, &table_names, pending_action_id).await?
        else {
            return Ok(None);
        };
        let Some(target_credential) = load_credential_instance_metadata(
            tx,
            &table_names,
            &pending_action.target_credential_instance_id,
        )
        .await?
        else {
            return Ok(None);
        };
        Ok(Some((target_credential, pending_action)))
    }

    pub(crate) async fn load_pending_credential_reset_execution_authority_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingCredentialLifecycleActionId,
    ) -> Result<
        Option<(
            CredentialInstanceMetadata,
            PendingCredentialLifecycleActionRecord,
        )>,
        PostgresAuthStoreError,
    > {
        self.load_pending_credential_lifecycle_action_with_target_in_current_transaction(
            tx,
            pending_action_id,
        )
        .await
    }

    pub(crate) async fn load_pending_credential_reset_for_cancellation_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingCredentialLifecycleActionId,
    ) -> Result<
        Option<(
            CredentialInstanceMetadata,
            PendingCredentialLifecycleActionRecord,
        )>,
        PostgresAuthStoreError,
    > {
        self.load_pending_credential_reset_execution_authority_in_current_transaction(
            tx,
            pending_action_id,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_credential_lifecycle_metadata_for_test(
        &self,
        pool: &Pool,
        metadata: &[CredentialInstanceMetadata],
        authorities: &[CredentialRecoveryAuthority],
        authority_sources: &[LifecycleAuthorityEvidence],
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for metadata in metadata {
                insert_credential_instance_metadata(&mut tx, &table_names, metadata, now).await?;
            }
            for authority in authorities {
                insert_credential_recovery_authority(&mut tx, &table_names, authority, now).await?;
            }
            for evidence in authority_sources {
                for authority_id in evidence.authority_ids() {
                    insert_lifecycle_authority_source(
                        &mut tx,
                        &table_names,
                        evidence.source(),
                        authority_id,
                        now,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_credential_lifecycle_metadata_for_test",
            tx,
            result,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_pending_credential_lifecycle_actions_for_test(
        &self,
        pool: &Pool,
        records: &[PendingCredentialLifecycleActionRecord],
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for record in records {
                insert_pending_credential_lifecycle_action(&mut tx, &table_names, record).await?;
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_pending_credential_lifecycle_actions_for_test",
            tx,
            result,
        )
        .await
    }

    fn method_commit_executor_for(
        &self,
        work: &AtomicCommitWork,
    ) -> Result<Option<&dyn PostgresAuthMethodCommitExecutor>, PostgresAuthStoreError> {
        if work.method_commit_work.is_empty() {
            Ok(None)
        } else {
            match self.method_registry.as_deref() {
                Some(registry) => Ok(Some(registry as &dyn PostgresAuthMethodCommitExecutor)),
                None => Err(PostgresAuthStoreError::MethodRegistryNotConfigured),
            }
        }
    }

    async fn materialize_fresh_credential_secret(
        &self,
        tx: &mut Tx<'_>,
        table_names: &AuthCoreTableNames,
        fresh_secret: &FreshCredentialSecret,
    ) -> Result<MaterializedFreshCredentialSecret, PostgresAuthStoreError> {
        let secret = AuthCredentialSecret::from_secret_bytes(
            SecretBytes::<AuthCredentialSecretKind>::random(AUTH_CREDENTIAL_SECRET_BYTES)
                .map_err(PostgresAuthStoreError::Crypto)?,
        )?;
        let target = match fresh_secret {
            FreshCredentialSecret::Session {
                session_id,
                secret_version,
            } => {
                let target = CoreStorageTarget::SessionCredentialSecret {
                    session_id: session_id.clone(),
                    secret_version: *secret_version,
                };
                let mac = secret
                    .to_mac(
                        &self.credential_secret_keyset,
                        &credential_secret_mac_context(&target),
                    )
                    .map_err(PostgresAuthStoreError::Crypto)?;
                insert_session_secret_mac(
                    tx,
                    table_names,
                    session_id,
                    *secret_version,
                    mac.as_bytes(),
                )
                .await?;
                target
            }
            FreshCredentialSecret::TrustedDevice {
                device_credential_id,
                secret_version,
            } => {
                let target = CoreStorageTarget::TrustedDeviceCredentialSecret {
                    device_credential_id: device_credential_id.clone(),
                    secret_version: *secret_version,
                };
                let mac = secret
                    .to_mac(
                        &self.credential_secret_keyset,
                        &credential_secret_mac_context(&target),
                    )
                    .map_err(PostgresAuthStoreError::Crypto)?;
                insert_trusted_device_secret_mac(
                    tx,
                    table_names,
                    device_credential_id,
                    *secret_version,
                    mac.as_bytes(),
                )
                .await?;
                target
            }
            FreshCredentialSecret::ActiveProofContinuation { attempt_id } => {
                let target = CoreStorageTarget::ActiveProofContinuationSecret {
                    attempt_id: attempt_id.clone(),
                };
                let mac = secret
                    .to_mac(
                        &self.credential_secret_keyset,
                        &credential_secret_mac_context(&target),
                    )
                    .map_err(PostgresAuthStoreError::Crypto)?;
                insert_active_proof_continuation_secret_mac(
                    tx,
                    table_names,
                    attempt_id,
                    mac.as_bytes(),
                )
                .await?;
                target
            }
        };
        Ok(MaterializedFreshCredentialSecret::new(target, secret))
    }
}

#[derive(Debug)]
pub(crate) enum PostgresAuthStoreError {
    Core(Error),
    Crypto(crate::crypto::Error),
    Database(DbError),
    InvalidStoredData(&'static str),
    MethodRegistryNotConfigured,
    MethodCommitWorkFailed {
        stage: PostgresAuthMethodCommitStage,
        operation: String,
        source: PostgresAuthMethodCommitError,
    },
    MethodRegistryFailed {
        operation: &'static str,
        source: PostgresAuthMethodCommitError,
    },
    PreconditionFailed(&'static str),
}

impl fmt::Display for PostgresAuthStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "auth Postgres store crypto error: {error}"),
            Self::Database(error) => write!(f, "auth Postgres store database error: {error}"),
            Self::InvalidStoredData(reason) => {
                write!(f, "auth Postgres store loaded invalid data: {reason}")
            }
            Self::MethodRegistryNotConfigured => {
                write!(
                    f,
                    "auth Postgres store cannot commit method/plugin work without a configured method registry"
                )
            }
            Self::MethodCommitWorkFailed {
                stage,
                operation,
                source,
            } => {
                write!(
                    f,
                    "auth Postgres store method/plugin work failed during {stage:?} for {operation}: {source}"
                )
            }
            Self::MethodRegistryFailed { operation, source } => {
                write!(
                    f,
                    "auth Postgres store method/plugin registry failed during {operation}: {source}"
                )
            }
            Self::PreconditionFailed(reason) => {
                write!(f, "auth Postgres store precondition failed: {reason}")
            }
        }
    }
}

impl std::error::Error for PostgresAuthStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::MethodCommitWorkFailed { source, .. } => Some(source),
            Self::MethodRegistryFailed { source, .. } => Some(source),
            Self::InvalidStoredData(_)
            | Self::MethodRegistryNotConfigured
            | Self::PreconditionFailed(_) => None,
        }
    }
}

impl From<Error> for PostgresAuthStoreError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

impl From<DbError> for PostgresAuthStoreError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Debug)]
struct AuthCoreTableNames {
    by_table: BTreeMap<PostgresAuthCoreTable, PgQualifiedTableName>,
}

impl AuthCoreTableNames {
    fn new(config: &PostgresAuthStoreConfig) -> Result<Self, PostgresAuthStoreError> {
        let mut by_table = BTreeMap::new();
        for table in PostgresAuthCoreSchemaContract::table_kinds() {
            by_table.insert(*table, config.table_name(*table)?);
        }
        Ok(Self { by_table })
    }

    fn get(&self, table: PostgresAuthCoreTable) -> &PgQualifiedTableName {
        self.by_table
            .get(&table)
            .expect("auth table names must include every table kind")
    }

    fn iter(&self) -> impl Iterator<Item = (PostgresAuthCoreTable, &PgQualifiedTableName)> {
        self.by_table.iter().map(|(kind, name)| (*kind, name))
    }
}

impl Ord for PostgresAuthCoreTable {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl PartialOrd for PostgresAuthCoreTable {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub(super) async fn finish_auth_store_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, PostgresAuthStoreError>,
) -> Result<T, PostgresAuthStoreError> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let rollback_result = tx.rollback().await;
            if let Err(rollback_error) = rollback_result {
                return Err(PostgresAuthStoreError::Database(
                    DbError::DatabaseOperationRollbackFailed {
                        operation,
                        operation_error: Box::new(db_error_from_auth_error(error)),
                        rollback_error: Box::new(rollback_error),
                    },
                ));
            }
            Err(error)
        }
    }
}

async fn finish_auth_store_validation_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, PostgresAuthStoreError>,
) -> Result<T, PostgresAuthStoreError> {
    match result {
        Ok(value) => {
            tx.rollback().await?;
            Ok(value)
        }
        Err(error) => {
            let rollback_result = tx.rollback().await;
            if let Err(rollback_error) = rollback_result {
                return Err(PostgresAuthStoreError::Database(
                    DbError::DatabaseOperationRollbackFailed {
                        operation,
                        operation_error: Box::new(db_error_from_auth_error(error)),
                        rollback_error: Box::new(rollback_error),
                    },
                ));
            }
            Err(error)
        }
    }
}

fn db_error_from_auth_error(error: PostgresAuthStoreError) -> DbError {
    match error {
        PostgresAuthStoreError::Database(error) => error,
        other => DbError::schema_mismatch(other.to_string()),
    }
}

async fn execute_create_table(
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

async fn execute_create_unique_indexes(
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

async fn validate_physical_schema_in_current_transaction(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
) -> Result<(), PostgresAuthStoreError> {
    for contract in PostgresAuthCoreSchemaContract::table_contracts() {
        validate_table(tx, table_names, &contract).await?;
    }
    Ok(())
}

async fn validate_auth_schema_ledger_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &PostgresAuthStoreConfig,
) -> Result<(), PostgresAuthStoreError> {
    let ledger_row = ComponentSchemaVersion {
        component: AUTH_SCHEMA_COMPONENT,
        instance_key: &schema_instance_key(config),
        version: AUTH_SCHEMA_VERSION,
        fingerprint: AUTH_SCHEMA_FINGERPRINT,
    };
    validate_component_schema_version_in_current_transaction(
        tx,
        &crate::db::SchemaLedgerConfig::default().table_name,
        ledger_row,
    )
    .await?;
    Ok(())
}

fn build_create_table_statement(
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

fn build_create_unique_index_statement(
    table_names: &AuthCoreTableNames,
    contract: &PostgresAuthCoreTableContract,
    uniqueness: &PostgresUniquenessContract,
) -> Result<String, PostgresAuthStoreError> {
    let index_name = PgIdentifier::new(format!(
        "{}{}_{}",
        DEFAULT_AUTH_TABLE_PREFIX,
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

fn column_definition(column: &PostgresColumnContract) -> Result<String, PostgresAuthStoreError> {
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

fn storage_sql(storage: PostgresColumnStorage, value: PostgresColumnValueContract) -> &'static str {
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

fn column_checks(column: &PostgresColumnContract) -> Vec<String> {
    let name = format!(r#""{}""#, column.name());
    let raw_check = match column.value() {
        PostgresColumnValueContract::OpaqueIdBytes { max_bytes } => Some(format!(
            "octet_length({name}) > 0 AND octet_length({name}) <= {max_bytes}"
        )),
        PostgresColumnValueContract::MacOverSecretBytes { exact_bytes } => {
            Some(format!("octet_length({name}) = {exact_bytes}"))
        }
        PostgresColumnValueContract::SecretVersion => Some(format!("{name} > 0")),
        PostgresColumnValueContract::UnixSeconds | PostgresColumnValueContract::Counter => {
            Some(format!("{name} >= 0"))
        }
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

async fn validate_table(
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
    Ok(())
}

fn validation_type_sql(storage: PostgresColumnStorage) -> &'static str {
    match storage {
        PostgresColumnStorage::Bytea => "bytea",
        PostgresColumnStorage::Bigint => "bigint",
        PostgresColumnStorage::Integer => "integer",
        PostgresColumnStorage::Boolean => "boolean",
        PostgresColumnStorage::TextCollateC => "text",
    }
}

impl PostgresAuthStore {
    async fn load_session_record_and_secret_match(
        &self,
        tx: &mut Tx<'_>,
        table_names: &AuthCoreTableNames,
        loaded: &mut LoadedState,
        session_id: &SessionId,
        presented_secrets: &PresentedAuthCookieSecrets,
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let statement = format!(
            r#"
        SELECT
            s.subject_id,
            s.device_credential_id,
            s.current_secret_version,
            s.previous_secret_version,
            s.previous_secret_accept_until,
            s.created_at,
            s.refreshed_at,
            s.expires_at,
            s.step_up_expires_at,
            s.revoked_at,
            current_mac.secret_mac,
            previous_mac.secret_mac
        FROM {} s
        LEFT JOIN {} current_mac
          ON current_mac.session_id = s.session_id
         AND current_mac.secret_version = s.current_secret_version
        LEFT JOIN {} previous_mac
          ON previous_mac.session_id = s.session_id
         AND previous_mac.secret_version = s.previous_secret_version
        WHERE s.session_id = $1
        "#,
            table_names.get(PostgresAuthCoreTable::Session).quoted(),
            table_names
                .get(PostgresAuthCoreTable::SessionCredentialSecretMac)
                .quoted(),
            table_names
                .get(PostgresAuthCoreTable::SessionCredentialSecretMac)
                .quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.load.session_with_secret_macs",
            Some(statement.as_str()),
        );
        let row = pooler_safe_query_as::<(
            Vec<u8>,
            Option<Vec<u8>>,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(session_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
        let Some(row) = row else {
            return Ok(());
        };
        let record = SessionRecord {
            session_id: session_id.clone(),
            subject_id: SubjectId::from_bytes(row.0)?,
            device_credential_id: row
                .1
                .map(TrustedDeviceCredentialId::from_bytes)
                .transpose()?,
            current_secret_version: secret_version_from_i64(row.2)?,
            previous_secret_version: row.3.map(secret_version_from_i64).transpose()?,
            previous_secret_accept_until: row.4.map(unix_seconds_from_i64).transpose()?,
            created_at: unix_seconds_from_i64(row.5)?,
            refreshed_at: unix_seconds_from_i64(row.6)?,
            expires_at: unix_seconds_from_i64(row.7)?,
            step_up_expires_at: row.8.map(unix_seconds_from_i64).transpose()?,
            revoked_at: row.9.map(unix_seconds_from_i64).transpose()?,
        };
        let match_kind = match presented_secrets.session() {
            Some(secret) => classify_presented_secret(
                &self.credential_secret_keyset,
                &CoreStorageTarget::SessionCredentialSecret {
                    session_id: record.session_id.clone(),
                    secret_version: record.current_secret_version,
                },
                row.10.as_deref(),
                secret.secret(),
                record.current_secret_version,
                &CoreStorageTarget::SessionCredentialSecret {
                    session_id: record.session_id.clone(),
                    secret_version: record
                        .previous_secret_version
                        .unwrap_or(record.current_secret_version),
                },
                row.11.as_deref(),
                record.previous_secret_version,
                record.previous_secret_accept_until,
                now,
            )?,
            None => StoredSecretMatch::Unknown,
        };
        loaded.session_record = Some(record);
        loaded.session_secret_match = Some(LoadedSessionSecretMatch::new(
            session_id.clone(),
            match_kind,
        ));
        Ok(())
    }

    async fn load_trusted_device_record_and_secret_match(
        &self,
        tx: &mut Tx<'_>,
        table_names: &AuthCoreTableNames,
        loaded: &mut LoadedState,
        device_credential_id: &TrustedDeviceCredentialId,
        presented_secrets: &PresentedAuthCookieSecrets,
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let statement = format!(
            r#"
        SELECT
            d.subject_id,
            d.current_secret_version,
            d.previous_secret_version,
            d.previous_secret_accept_until,
            d.created_at,
            d.last_used_at,
            d.expires_at,
            d.silent_revival_until,
            d.revoked_at,
            d.display_label,
            current_mac.secret_mac,
            previous_mac.secret_mac
        FROM {} d
        LEFT JOIN {} current_mac
          ON current_mac.device_credential_id = d.device_credential_id
         AND current_mac.secret_version = d.current_secret_version
        LEFT JOIN {} previous_mac
          ON previous_mac.device_credential_id = d.device_credential_id
         AND previous_mac.secret_version = d.previous_secret_version
        WHERE d.device_credential_id = $1
        "#,
            table_names
                .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                .quoted(),
            table_names
                .get(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
                .quoted(),
            table_names
                .get(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
                .quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.load.trusted_device_with_secret_macs",
            Some(statement.as_str()),
        );
        let row = pooler_safe_query_as::<(
            Vec<u8>,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(device_credential_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
        let Some(row) = row else {
            return Ok(());
        };
        let record = TrustedDeviceCredentialRecord {
            device_credential_id: device_credential_id.clone(),
            subject_id: SubjectId::from_bytes(row.0)?,
            current_secret_version: secret_version_from_i64(row.1)?,
            previous_secret_version: row.2.map(secret_version_from_i64).transpose()?,
            previous_secret_accept_until: row.3.map(unix_seconds_from_i64).transpose()?,
            created_at: unix_seconds_from_i64(row.4)?,
            last_used_at: unix_seconds_from_i64(row.5)?,
            expires_at: unix_seconds_from_i64(row.6)?,
            silent_revival_until: unix_seconds_from_i64(row.7)?,
            revoked_at: row.8.map(unix_seconds_from_i64).transpose()?,
            display_label: row.9,
        };
        let match_kind = match presented_secrets.trusted_device() {
            Some(secret) => classify_presented_secret(
                &self.credential_secret_keyset,
                &CoreStorageTarget::TrustedDeviceCredentialSecret {
                    device_credential_id: record.device_credential_id.clone(),
                    secret_version: record.current_secret_version,
                },
                row.10.as_deref(),
                secret.secret(),
                record.current_secret_version,
                &CoreStorageTarget::TrustedDeviceCredentialSecret {
                    device_credential_id: record.device_credential_id.clone(),
                    secret_version: record
                        .previous_secret_version
                        .unwrap_or(record.current_secret_version),
                },
                row.11.as_deref(),
                record.previous_secret_version,
                record.previous_secret_accept_until,
                now,
            )?,
            None => StoredSecretMatch::Unknown,
        };
        loaded.trusted_device_record = Some(record);
        loaded.trusted_device_secret_match = Some(LoadedTrustedDeviceSecretMatch::new(
            device_credential_id.clone(),
            match_kind,
        ));
        Ok(())
    }
}

async fn load_subject_revocation(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    subject_id: &SubjectId,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT revoke_records_created_at_or_before
        FROM {}
        WHERE subject_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.subject_revocation",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(subject_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    loaded.subject_revocations.push_loaded(
        subject_id.clone(),
        row.map(|value| {
            Ok::<_, PostgresAuthStoreError>(SubjectRevocationState {
                revoke_records_created_at_or_before: unix_seconds_from_i64(value)?,
            })
        })
        .transpose()?,
    )?;
    Ok(())
}

async fn load_credential_instance_metadata(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    credential_instance_id: &VerifiedProofSourceId,
) -> Result<Option<CredentialInstanceMetadata>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, credential_kind, method_label, lifecycle_state
        FROM {}
        WHERE credential_instance_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.credential_instance_metadata",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>, i32, String, i32)>(sqlx::AssertSqlSafe(
        statement.as_str(),
    ))
    .bind(credential_instance_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    row.map(
        |(subject_id, credential_kind, method_label, lifecycle_state)| {
            CredentialInstanceMetadata::new(
                credential_instance_id.clone(),
                SubjectId::from_bytes(subject_id)?,
                credential_instance_kind_from_i32(credential_kind)?,
                method_label,
                credential_lifecycle_state_from_i32(lifecycle_state)?,
            )
            .map_err(PostgresAuthStoreError::Core)
        },
    )
    .transpose()
}

async fn load_credential_recovery_authorities(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    target_credential_instance_id: &VerifiedProofSourceId,
) -> Result<Vec<CredentialRecoveryAuthority>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT lifecycle_action, authority_id, authority_timing
        FROM {}
        WHERE target_credential_instance_id = $1
        ORDER BY lifecycle_action ASC, authority_id ASC, authority_timing ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialRecoveryAuthority)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.credential_recovery_authorities",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(i32, Vec<u8>, i32)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(target_credential_instance_id.as_bytes())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    rows.into_iter()
        .map(|(action, authority_id, timing)| {
            Ok(CredentialRecoveryAuthority::new(
                target_credential_instance_id.clone(),
                credential_lifecycle_action_from_i32(action)?,
                RecoveryAuthorityId::from_bytes(authority_id)?,
                recovery_authority_timing_from_i32(timing)?,
            ))
        })
        .collect()
}

async fn load_lifecycle_authority_evidence(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source: &LifecycleAuthoritySource,
) -> Result<Option<LifecycleAuthorityEvidence>, PostgresAuthStoreError> {
    let (source_kind, source_id) = lifecycle_authority_source_key(source)?;
    let statement = format!(
        r#"
        SELECT authority_id
        FROM {}
        WHERE source_kind = $1 AND source_id = $2
        ORDER BY authority_id ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::LifecycleAuthoritySource)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.lifecycle_authority_evidence",
        Some(statement.as_str()),
    );
    let authority_ids =
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(i32_from_lifecycle_authority_source_kind(source_kind))
            .bind(source_id.as_bytes())
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .into_iter()
            .map(RecoveryAuthorityId::from_bytes)
            .collect::<Result<Vec<_>, _>>()?;
    if authority_ids.is_empty() {
        return Ok(None);
    }
    LifecycleAuthorityEvidence::new(source.clone(), authority_ids)
        .map(Some)
        .map_err(PostgresAuthStoreError::Core)
}

#[cfg(test)]
async fn insert_credential_instance_metadata(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    metadata: &CredentialInstanceMetadata,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            credential_instance_id,
            subject_id,
            credential_kind,
            method_label,
            lifecycle_state,
            created_at,
            updated_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$6)
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.test.insert_credential_instance_metadata",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(metadata.credential_instance_id().as_bytes())
        .bind(metadata.subject_id().as_bytes())
        .bind(i32_from_credential_instance_kind(metadata.kind()))
        .bind(metadata.method_label())
        .bind(i32_from_credential_lifecycle_state(
            metadata.lifecycle_state(),
        ))
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

#[cfg(test)]
async fn insert_credential_recovery_authority(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    authority: &CredentialRecoveryAuthority,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            target_credential_instance_id,
            lifecycle_action,
            authority_id,
            authority_timing,
            created_at
        )
        VALUES ($1,$2,$3,$4,$5)
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialRecoveryAuthority)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.test.insert_credential_recovery_authority",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(authority.target_credential_instance_id().as_bytes())
        .bind(i32_from_credential_lifecycle_action(authority.action()))
        .bind(authority.authority_id().as_bytes())
        .bind(i32_from_recovery_authority_timing(authority.timing()))
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

#[cfg(test)]
async fn insert_lifecycle_authority_source(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source: &LifecycleAuthoritySource,
    authority_id: &RecoveryAuthorityId,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let (source_kind, source_id) = lifecycle_authority_source_key(source)?;
    let statement = format!(
        r#"
        INSERT INTO {} (
            source_kind,
            source_id,
            authority_id,
            created_at
        )
        VALUES ($1,$2,$3,$4)
        "#,
        table_names
            .get(PostgresAuthCoreTable::LifecycleAuthoritySource)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.test.insert_lifecycle_authority_source",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(i32_from_lifecycle_authority_source_kind(source_kind))
        .bind(source_id.as_bytes())
        .bind(authority_id.as_bytes())
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_pending_credential_lifecycle_action(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &PendingCredentialLifecycleActionRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            lifecycle_action,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
        table_names
            .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_pending_credential_lifecycle_action",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.pending_action_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(record.target_credential_instance_id.as_bytes())
        .bind(i32_from_credential_lifecycle_action(record.action))
        .bind(i64_from_unix_seconds(record.requested_at)?)
        .bind(i64_from_unix_seconds(record.earliest_execute_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn load_pending_credential_lifecycle_action(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> Result<Option<PendingCredentialLifecycleActionRecord>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, target_credential_instance_id, lifecycle_action,
               requested_at, earliest_execute_at, expires_at, closed_at
        FROM {}
        WHERE pending_action_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.pending_credential_lifecycle_action",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>, Vec<u8>, i32, i64, i64, i64, Option<i64>)>(
        sqlx::AssertSqlSafe(statement.as_str()),
    )
    .bind(pending_action_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    row.map(
        |(
            subject_id,
            target_credential_instance_id,
            action,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at,
        )| {
            Ok(PendingCredentialLifecycleActionRecord {
                pending_action_id: pending_action_id.clone(),
                subject_id: SubjectId::from_bytes(subject_id)?,
                target_credential_instance_id: VerifiedProofSourceId::from_bytes(
                    target_credential_instance_id,
                )?,
                action: credential_lifecycle_action_from_i32(action)?,
                requested_at: unix_seconds_from_i64(requested_at)?,
                earliest_execute_at: unix_seconds_from_i64(earliest_execute_at)?,
                expires_at: unix_seconds_from_i64(expires_at)?,
                closed_at: closed_at.map(unix_seconds_from_i64).transpose()?,
            })
        },
    )
    .transpose()
}

fn lifecycle_authority_source_key(
    source: &LifecycleAuthoritySource,
) -> Result<(LifecycleAuthoritySourceKind, VerifiedProofSourceId), PostgresAuthStoreError> {
    match source {
        LifecycleAuthoritySource::VerifiedProofSource(source) => {
            let kind = match source.kind() {
                VerifiedProofSourceKind::CredentialInstance => {
                    LifecycleAuthoritySourceKind::CredentialInstance
                }
                VerifiedProofSourceKind::OutOfBandIdentifier => {
                    LifecycleAuthoritySourceKind::OutOfBandIdentifier
                }
                VerifiedProofSourceKind::ExternalAuthority => {
                    LifecycleAuthoritySourceKind::ExternalAuthority
                }
            };
            Ok((kind, source.source_id().clone()))
        }
        LifecycleAuthoritySource::AuthenticatedSession(session_id) => Ok((
            LifecycleAuthoritySourceKind::AuthenticatedSession,
            VerifiedProofSourceId::from_bytes(session_id.as_bytes().to_vec())?,
        )),
        LifecycleAuthoritySource::AdminSupportIntervention(intervention_id) => Ok((
            LifecycleAuthoritySourceKind::AdminSupportIntervention,
            intervention_id.clone(),
        )),
    }
}

async fn load_active_proof_attempt(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    attempt_id: &ActiveProofAttemptId,
    presented_cookie_secrets: &PresentedAuthCookieSecrets,
    credential_secret_keyset: &Keyset,
) -> Result<(), PostgresAuthStoreError> {
    let attempt_statement = format!(
        r#"
        SELECT proof_use, subject_id, weak_proof_failures, max_weak_proof_failures,
               created_at, expires_at, closed_at
        FROM {}
        WHERE attempt_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofAttempt)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.active_proof_attempt",
        Some(attempt_statement.as_str()),
    );
    let row = pooler_safe_query_as::<(i32, Option<Vec<u8>>, i32, i32, i64, i64, Option<i64>)>(
        sqlx::AssertSqlSafe(attempt_statement.as_str()),
    )
    .bind(attempt_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    let Some(row) = row else {
        return Ok(());
    };

    let satisfied_statement = format!(
        r#"
        SELECT proof_family, method_label, online_guessing_risk,
               proof_source_kind, proof_source_id, satisfied_at
        FROM {}
        WHERE attempt_id = $1
        ORDER BY satisfied_at ASC, proof_family ASC, method_label ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.active_proof_satisfied_proofs",
        Some(satisfied_statement.as_str()),
    );
    let proof_rows =
        pooler_safe_query_as::<(i32, String, bool, Option<i32>, Option<Vec<u8>>, i64)>(
            sqlx::AssertSqlSafe(satisfied_statement.as_str()),
        )
        .bind(attempt_id.as_bytes())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    let mut satisfied_proofs = Vec::with_capacity(proof_rows.len());
    for (family_id, method_label, online_guessing_risk, source_kind, source_id, _) in proof_rows {
        let proof = ProofSummary::new_with_online_guessing_risk(
            proof_family_from_i32(family_id)?,
            method_label,
            online_guessing_risk_from_bool(online_guessing_risk),
        )?;
        let source = match (source_kind, source_id) {
            (Some(kind), Some(source_id)) => Some(VerifiedProofSource::new(
                verified_proof_source_kind_from_i32(kind)?,
                VerifiedProofSourceId::from_bytes(source_id)
                    .map_err(PostgresAuthStoreError::Core)?,
            )),
            (None, None) => None,
            _ => {
                return Err(PostgresAuthStoreError::InvalidStoredData(
                    "satisfied proof source kind/id must both be null or both be present",
                ));
            }
        };
        satisfied_proofs.push(SatisfiedProof::new(proof, source));
    }

    loaded.active_proof_attempt_record = Some(ActiveProofAttemptRecord {
        attempt_id: attempt_id.clone(),
        proof_use: proof_use_from_i32(row.0)?,
        subject_id: row.1.map(SubjectId::from_bytes).transpose()?,
        satisfied_proofs,
        weak_proof_failures: u32_from_i32(row.2)?,
        max_weak_proof_failures: u32_from_i32(row.3)?,
        created_at: unix_seconds_from_i64(row.4)?,
        expires_at: unix_seconds_from_i64(row.5)?,
        closed_at: row.6.map(unix_seconds_from_i64).transpose()?,
    });
    load_active_proof_continuation_secret_match(
        tx,
        table_names,
        loaded,
        attempt_id,
        presented_cookie_secrets,
        credential_secret_keyset,
    )
    .await?;
    Ok(())
}

async fn load_active_proof_continuation_secret_match(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    attempt_id: &ActiveProofAttemptId,
    presented_cookie_secrets: &PresentedAuthCookieSecrets,
    credential_secret_keyset: &Keyset,
) -> Result<(), PostgresAuthStoreError> {
    if loaded
        .active_proof_continuation_secret_match
        .as_ref()
        .is_some_and(|existing| existing.attempt_id() == attempt_id)
    {
        return Ok(());
    }
    let Some(presented_secret) = presented_cookie_secrets.active_proof_continuation() else {
        return Ok(());
    };
    if presented_secret.attempt_id() != attempt_id {
        loaded.active_proof_continuation_secret_match =
            Some(LoadedActiveProofContinuationSecretMatch::new(
                attempt_id.clone(),
                StoredSecretMatch::Unknown,
            ));
        return Ok(());
    }
    let statement = format!(
        r#"
        SELECT secret_mac
        FROM {}
        WHERE attempt_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofContinuationSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.active_proof_continuation_secret_mac",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>,)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(attempt_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    let kind = match row {
        Some((current_mac,)) => {
            let current_target = CoreStorageTarget::ActiveProofContinuationSecret {
                attempt_id: attempt_id.clone(),
            };
            let current_mac = MacOverSecret::try_from(current_mac)
                .map_err(|_| PostgresAuthStoreError::InvalidStoredData("stored MAC malformed"))?;
            if current_mac.verify(
                credential_secret_keyset,
                presented_secret.secret().expose_secret(),
                &credential_secret_mac_context(&current_target),
            ) {
                StoredSecretMatch::Current
            } else {
                StoredSecretMatch::Unknown
            }
        }
        None => StoredSecretMatch::Unknown,
    };
    loaded.active_proof_continuation_secret_match = Some(
        LoadedActiveProofContinuationSecretMatch::new(attempt_id.clone(), kind),
    );
    Ok(())
}

async fn load_active_proof_challenge(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    challenge_id: &ActiveProofChallengeId,
) -> Result<(), PostgresAuthStoreError> {
    let challenge_statement = format!(
        r#"
        SELECT attempt_id, proof_family, method_label, online_guessing_risk,
               challenge_dedupe_key, recipient_handle, resend_count, max_resends,
               requires_stateless_fast_fail, created_at, expires_at, closed_at
        FROM {}
        WHERE challenge_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallenge)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.active_proof_challenge",
        Some(challenge_statement.as_str()),
    );
    let row = pooler_safe_query_as::<(
        Vec<u8>,
        i32,
        String,
        bool,
        Option<String>,
        Option<String>,
        i32,
        i32,
        bool,
        i64,
        i64,
        Option<i64>,
    )>(sqlx::AssertSqlSafe(challenge_statement.as_str()))
    .bind(challenge_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    let Some(row) = row else {
        return Ok(());
    };

    let delivery_statement = format!(
        r#"
        SELECT delivery_idempotency_key
        FROM {}
        WHERE challenge_id = $1
        ORDER BY created_at ASC, delivery_idempotency_key ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.active_proof_challenge_delivery_keys",
        Some(delivery_statement.as_str()),
    );
    let used_delivery_idempotency_keys =
        pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(delivery_statement.as_str()))
            .bind(challenge_id.as_bytes())
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;

    loaded.active_proof_challenge_record = Some(ActiveProofChallengeRecord {
        challenge_id: challenge_id.clone(),
        attempt_id: ActiveProofAttemptId::from_bytes(row.0)?,
        proof: ProofSummary::new_with_online_guessing_risk(
            proof_family_from_i32(row.1)?,
            row.2,
            online_guessing_risk_from_bool(row.3),
        )?,
        challenge_dedupe_key: row.4.map(OutOfBandChallengeDedupeKey::new).transpose()?,
        recipient_handle: row.5,
        used_delivery_idempotency_keys,
        resend_count: u32_from_i32(row.6)?,
        max_resends: u32_from_i32(row.7)?,
        requires_stateless_fast_fail: row.8,
        created_at: unix_seconds_from_i64(row.9)?,
        expires_at: unix_seconds_from_i64(row.10)?,
        closed_at: row.11.map(unix_seconds_from_i64).transpose()?,
    });
    Ok(())
}

async fn enforce_precondition(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    precondition: &Precondition,
) -> Result<(), PostgresAuthStoreError> {
    match precondition {
        Precondition::SessionStillMatches {
            session_id,
            subject_id,
            now,
            current_secret_version,
        } => {
            materialize_and_lock_subject_auth_state(
                tx,
                table_names,
                subject_id,
                UnixSeconds::new(0),
            )
            .await?;
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE session_id = $1
                  AND subject_id = $2
                  AND current_secret_version = $3
                  AND revoked_at IS NULL
                  AND expires_at > $4
                FOR UPDATE
                "#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.session_still_matches",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i64_from_secret_version(*current_secret_version)?)
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "session no longer matches loaded state",
                ));
            }
            validate_subject_cutoff_does_not_invalidate(
                tx,
                table_names,
                subject_id,
                CoreStorageTarget::Session(session_id.clone()),
            )
            .await?;
        }
        Precondition::TrustedDeviceStillMatches {
            device_credential_id,
            subject_id,
            now,
            current_secret_version,
        } => {
            materialize_and_lock_subject_auth_state(
                tx,
                table_names,
                subject_id,
                UnixSeconds::new(0),
            )
            .await?;
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE device_credential_id = $1
                  AND subject_id = $2
                  AND current_secret_version = $3
                  AND revoked_at IS NULL
                  AND expires_at > $4
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.trusted_device_still_matches",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i64_from_secret_version(*current_secret_version)?)
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "trusted device no longer matches loaded state",
                ));
            }
            validate_subject_cutoff_does_not_invalidate(
                tx,
                table_names,
                subject_id,
                CoreStorageTarget::TrustedDeviceCredential(device_credential_id.clone()),
            )
            .await?;
        }
        Precondition::SessionBelongsToSubject {
            session_id,
            subject_id,
        } => {
            let statement = format!(
                r#"SELECT 1 FROM {} WHERE session_id = $1 AND subject_id = $2 AND revoked_at IS NULL FOR UPDATE"#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.session_belongs_to_subject",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(subject_id.as_bytes()))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "session does not belong to subject",
                ));
            }
        }
        Precondition::TrustedDeviceBelongsToSubject {
            device_credential_id,
            subject_id,
        } => {
            let statement = format!(
                r#"SELECT 1 FROM {} WHERE device_credential_id = $1 AND subject_id = $2 AND revoked_at IS NULL FOR UPDATE"#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.trusted_device_belongs_to_subject",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(subject_id.as_bytes()))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "trusted device does not belong to subject",
                ));
            }
        }
        Precondition::ActiveProofAttemptStillOpen {
            attempt_id,
            now,
            observed_subject_id,
            observed_weak_proof_failures,
            subject_id_for_revocation,
            created_at,
            ..
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE attempt_id = $1
                  AND weak_proof_failures = $2
                  AND created_at = $3
                  AND closed_at IS NULL
                  AND expires_at > $4
                  AND subject_id IS NOT DISTINCT FROM $5
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.active_proof_attempt_still_open",
                &statement,
                |query| {
                    Ok(query
                        .bind(attempt_id.as_bytes())
                        .bind(i32_from_u32(*observed_weak_proof_failures)?)
                        .bind(i64_from_unix_seconds(*created_at)?)
                        .bind(i64_from_unix_seconds(*now)?)
                        .bind(observed_subject_id.as_ref().map(Id::as_bytes)))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "active proof attempt no longer matches loaded state",
                ));
            }
            if let Some(subject_id) = subject_id_for_revocation {
                materialize_and_lock_subject_auth_state(
                    tx,
                    table_names,
                    subject_id,
                    UnixSeconds::new(0),
                )
                .await?;
                validate_subject_cutoff_does_not_invalidate(
                    tx,
                    table_names,
                    subject_id,
                    CoreStorageTarget::ActiveProofAttempt(attempt_id.clone()),
                )
                .await?;
            }
        }
        Precondition::ActiveProofChallengeStillOpen { challenge_id, now } => {
            let statement = format!(
                r#"SELECT 1 FROM {} WHERE challenge_id = $1 AND closed_at IS NULL AND expires_at > $2 FOR UPDATE"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.active_proof_challenge_still_open",
                &statement,
                |query| {
                    Ok(query
                        .bind(challenge_id.as_bytes())
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "active proof challenge is no longer open",
                ));
            }
        }
        Precondition::OutOfBandChallengeResendStillAllowed {
            challenge_id,
            now,
            observed_resend_count,
            observed_used_delivery_idempotency_keys,
        } => {
            let open_statement = format!(
                r#"SELECT 1 FROM {} WHERE challenge_id = $1 AND closed_at IS NULL AND expires_at > $2 FOR UPDATE"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            let is_open = fetch_exists_for_update(
                tx,
                "auth_core.precondition.out_of_band_resend_challenge_still_open",
                &open_statement,
                |query| {
                    Ok(query
                        .bind(challenge_id.as_bytes())
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !is_open {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "active proof challenge is no longer open",
                ));
            }
            let count_statement = format!(
                r#"SELECT resend_count FROM {} WHERE challenge_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::FetchOne,
                "auth_core.precondition.out_of_band_resend_count",
                Some(count_statement.as_str()),
            );
            let resend_count =
                pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(count_statement.as_str()))
                    .bind(challenge_id.as_bytes())
                    .fetch_one(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            if u32_from_i32(resend_count)? != *observed_resend_count {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "out-of-band resend count changed",
                ));
            }
            let delivery_statement = format!(
                r#"SELECT delivery_idempotency_key FROM {} WHERE challenge_id = $1 ORDER BY delivery_idempotency_key ASC"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::FetchAll,
                "auth_core.precondition.out_of_band_delivery_keys",
                Some(delivery_statement.as_str()),
            );
            let mut stored_keys = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
                delivery_statement.as_str(),
            ))
            .bind(challenge_id.as_bytes())
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
            let mut observed = observed_used_delivery_idempotency_keys.clone();
            stored_keys.sort();
            observed.sort();
            if stored_keys != observed {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "out-of-band delivery idempotency keys changed",
                ));
            }
        }
        Precondition::NoOpenOutOfBandChallengeForDedupeKey {
            challenge_dedupe_key,
            now,
        } => {
            let close_statement = format!(
                r#"UPDATE {} SET closed_at = $2 WHERE challenge_dedupe_key = $1 AND closed_at IS NULL AND expires_at <= $2"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.precondition.close_expired_open_challenges_for_dedupe_key",
                Some(close_statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(close_statement.as_str()))
                .bind(challenge_dedupe_key.as_str())
                .bind(i64_from_unix_seconds(*now)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;
        }
        Precondition::CredentialInstanceStillActive {
            credential_instance_id,
            subject_id,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE credential_instance_id = $1
                  AND subject_id = $2
                  AND lifecycle_state = $3
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.credential_instance_still_active",
                &statement,
                |query| {
                    Ok(query
                        .bind(credential_instance_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_state(
                            CredentialLifecycleState::Active,
                        )))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "credential instance is not active for subject",
                ));
            }
        }
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id,
            action,
            now,
        } => {
            let close_statement = format!(
                r#"
                UPDATE {}
                SET closed_at = $3
                WHERE target_credential_instance_id = $1
                  AND lifecycle_action = $2
                  AND closed_at IS NULL
                  AND expires_at <= $3
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.precondition.close_expired_pending_credential_lifecycle_actions",
                Some(close_statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(close_statement.as_str()))
                .bind(target_credential_instance_id.as_bytes())
                .bind(i32_from_credential_lifecycle_action(*action))
                .bind(i64_from_unix_seconds(*now)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;

            let open_statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE target_credential_instance_id = $1
                  AND lifecycle_action = $2
                  AND closed_at IS NULL
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.no_open_pending_credential_lifecycle_action",
                &open_statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action)))
                },
            )
            .await?;
            if found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending credential lifecycle action already exists",
                ));
            }
        }
        Precondition::PendingCredentialLifecycleActionStillExecutable {
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE pending_action_id = $1
                  AND subject_id = $2
                  AND target_credential_instance_id = $3
                  AND lifecycle_action = $4
                  AND closed_at IS NULL
                  AND earliest_execute_at <= $5
                  AND $5 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending credential lifecycle action is not executable",
                ));
            }
        }
        Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE pending_action_id = $1
                  AND subject_id = $2
                  AND target_credential_instance_id = $3
                  AND lifecycle_action = $4
                  AND closed_at IS NULL
                  AND $5 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.pending_credential_lifecycle_action_still_cancellable_for_target",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending credential lifecycle action is not cancellable for target",
                ));
            }
        }
    }
    Ok(())
}

async fn enforce_method_commit_preconditions(
    tx: &mut Tx<'_>,
    executor: &dyn PostgresAuthMethodCommitExecutor,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), PostgresAuthStoreError> {
    for work in method_commit_work {
        for precondition in work.preconditions() {
            let operation = precondition.operation().as_str().to_owned();
            executor
                .enforce_precondition(tx, work, precondition)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage: PostgresAuthMethodCommitStage::EnforcePrecondition,
                    operation,
                    source,
                })?;
        }
    }
    Ok(())
}

async fn apply_method_commit_mutations(
    tx: &mut Tx<'_>,
    executor: &dyn PostgresAuthMethodCommitExecutor,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), PostgresAuthStoreError> {
    for work in method_commit_work {
        for mutation in work.mutations() {
            let operation = mutation.operation().as_str().to_owned();
            executor
                .apply_mutation(tx, work, mutation)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage: PostgresAuthMethodCommitStage::ApplyMutation,
                    operation,
                    source,
                })?;
        }
    }
    Ok(())
}

async fn append_method_commit_durable_effect_commands(
    tx: &mut Tx<'_>,
    executor: &dyn PostgresAuthMethodCommitExecutor,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), PostgresAuthStoreError> {
    for work in method_commit_work {
        for command in work.durable_effect_commands() {
            let operation = command.operation().as_str().to_owned();
            executor
                .append_durable_effect_command(tx, work, command)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage: PostgresAuthMethodCommitStage::AppendDurableEffectCommand,
                    operation,
                    source,
                })?;
        }
    }
    Ok(())
}

async fn apply_mutation(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    mutation: &Mutation,
) -> Result<(), PostgresAuthStoreError> {
    match mutation {
        Mutation::CreateSession(record) => insert_session(tx, table_names, record).await,
        Mutation::RefreshSession {
            session_id,
            new_secret_version,
            previous_secret_version,
            previous_secret_accept_until,
            refreshed_at,
            expires_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET current_secret_version = $2,
                    previous_secret_version = $3,
                    previous_secret_accept_until = $4,
                    refreshed_at = $5,
                    expires_at = $6
                WHERE session_id = $1
                "#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.refresh_session",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(i64_from_secret_version(*new_secret_version)?)
                        .bind(i64_from_secret_version(*previous_secret_version)?)
                        .bind(i64_from_unix_seconds(*previous_secret_accept_until)?)
                        .bind(i64_from_unix_seconds(*refreshed_at)?)
                        .bind(i64_from_unix_seconds(*expires_at)?))
                },
            )
            .await
        }
        Mutation::RecordStepUp {
            session_id,
            new_secret_version,
            previous_secret_version,
            previous_secret_accept_until,
            step_up_expires_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET current_secret_version = $2,
                    previous_secret_version = $3,
                    previous_secret_accept_until = $4,
                    step_up_expires_at = $5
                WHERE session_id = $1
                "#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_step_up",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(i64_from_secret_version(*new_secret_version)?)
                        .bind(i64_from_secret_version(*previous_secret_version)?)
                        .bind(i64_from_unix_seconds(*previous_secret_accept_until)?)
                        .bind(i64_from_unix_seconds(*step_up_expires_at)?))
                },
            )
            .await
        }
        Mutation::CreateTrustedDeviceCredential(record) => {
            insert_trusted_device(tx, table_names, record).await
        }
        Mutation::CreateActiveProofAttempt(record) => {
            insert_active_proof_attempt(tx, table_names, record).await
        }
        Mutation::CreateActiveProofChallenge(record) => {
            insert_active_proof_challenge(tx, table_names, record).await
        }
        Mutation::RecordWeakProofFailure {
            attempt_id,
            weak_proof_failures,
        } => {
            let statement = format!(
                r#"UPDATE {} SET weak_proof_failures = $2 WHERE attempt_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_weak_proof_failure",
                &statement,
                |query| {
                    Ok(query
                        .bind(attempt_id.as_bytes())
                        .bind(i32_from_u32(*weak_proof_failures)?))
                },
            )
            .await
        }
        Mutation::RecordActiveProofSucceeded {
            attempt_id,
            subject_id,
            proof,
            satisfied_at,
        } => {
            let update_statement = format!(
                r#"UPDATE {} SET subject_id = COALESCE(subject_id, $2) WHERE attempt_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.bind_active_proof_attempt_subject",
                &update_statement,
                |query| {
                    Ok(query
                        .bind(attempt_id.as_bytes())
                        .bind(subject_id.as_ref().map(|id| id.as_bytes().to_vec())))
                },
            )
            .await?;
            insert_satisfied_proof(tx, table_names, attempt_id, proof, *satisfied_at).await
        }
        Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
            attempt_id,
            proof_family,
            closed_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET closed_at = $3
                WHERE attempt_id = $1
                  AND proof_family = $2
                  AND closed_at IS NULL
                "#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.mutation.close_open_challenges_for_proof_family",
                Some(statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(attempt_id.as_bytes())
                .bind(i32_from_proof_family(*proof_family))
                .bind(i64_from_unix_seconds(*closed_at)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;
            Ok(())
        }
        Mutation::RecordOutOfBandChallengeResent {
            challenge_id,
            resend_count,
            used_delivery_idempotency_keys,
            resent_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET resend_count = $2 WHERE challenge_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_out_of_band_challenge_resent",
                &statement,
                |query| {
                    Ok(query
                        .bind(challenge_id.as_bytes())
                        .bind(i32_from_u32(*resend_count)?))
                },
            )
            .await?;
            for key in used_delivery_idempotency_keys {
                insert_challenge_delivery_key(tx, table_names, challenge_id, key, *resent_at)
                    .await?;
            }
            Ok(())
        }
        Mutation::DeleteActiveProofAttempt { attempt_id } => {
            hard_delete_active_proof_attempt(tx, table_names, attempt_id).await
        }
        Mutation::RotateTrustedDeviceCredential {
            device_credential_id,
            new_secret_version,
            previous_secret_version,
            previous_secret_accept_until,
            last_used_at,
            silent_revival_until,
            expires_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET current_secret_version = $2,
                    previous_secret_version = $3,
                    previous_secret_accept_until = $4,
                    last_used_at = $5,
                    silent_revival_until = $6,
                    expires_at = $7
                WHERE device_credential_id = $1
                "#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.rotate_trusted_device",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(i64_from_secret_version(*new_secret_version)?)
                        .bind(i64_from_secret_version(*previous_secret_version)?)
                        .bind(i64_from_unix_seconds(*previous_secret_accept_until)?)
                        .bind(i64_from_unix_seconds(*last_used_at)?)
                        .bind(i64_from_unix_seconds(*silent_revival_until)?)
                        .bind(i64_from_unix_seconds(*expires_at)?))
                },
            )
            .await
        }
        Mutation::RevokeSession {
            session_id,
            revoked_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET revoked_at = $2 WHERE session_id = $1"#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.revoke_session",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(i64_from_unix_seconds(*revoked_at)?))
                },
            )
            .await
        }
        Mutation::RevokeTrustedDeviceCredential {
            device_credential_id,
            revoked_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET revoked_at = $2 WHERE device_credential_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.revoke_trusted_device",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(i64_from_unix_seconds(*revoked_at)?))
                },
            )
            .await
        }
        Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id,
            revoke_records_created_at_or_before,
            ..
        } => {
            materialize_and_lock_subject_auth_state(
                tx,
                table_names,
                subject_id,
                *revoke_records_created_at_or_before,
            )
            .await
        }
        Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id,
            authorized_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET updated_at = $2 WHERE credential_instance_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_credential_lifecycle_action_authorized",
                &statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i64_from_unix_seconds(*authorized_at)?))
                },
            )
            .await
        }
        Mutation::CreatePendingCredentialLifecycleAction(record) => {
            insert_pending_credential_lifecycle_action(tx, table_names, record).await
        }
        Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id,
            executed_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET updated_at = $2 WHERE credential_instance_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_credential_lifecycle_action_executed",
                &statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i64_from_unix_seconds(*executed_at)?))
                },
            )
            .await
        }
        Mutation::SetCredentialLifecycleState {
            credential_instance_id,
            lifecycle_state,
            updated_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET lifecycle_state = $2, updated_at = $3 WHERE credential_instance_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.set_credential_lifecycle_state",
                &statement,
                |query| {
                    Ok(query
                        .bind(credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_state(*lifecycle_state))
                        .bind(i64_from_unix_seconds(*updated_at)?))
                },
            )
            .await
        }
        Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id,
            closed_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET closed_at = $2 WHERE pending_action_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.close_pending_credential_lifecycle_action",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(i64_from_unix_seconds(*closed_at)?))
                },
            )
            .await
        }
    }
}

async fn insert_session(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &SessionRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            session_id, subject_id, device_credential_id, current_secret_version,
            previous_secret_version, previous_secret_accept_until, created_at, refreshed_at,
            expires_at, step_up_expires_at, revoked_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
        table_names.get(PostgresAuthCoreTable::Session).quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_session",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.session_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(
            record
                .device_credential_id
                .as_ref()
                .map(|id| id.as_bytes().to_vec()),
        )
        .bind(i64_from_secret_version(record.current_secret_version)?)
        .bind(optional_i64_from_secret_version(
            record.previous_secret_version,
        )?)
        .bind(optional_i64_from_unix_seconds(
            record.previous_secret_accept_until,
        )?)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.refreshed_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.step_up_expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.revoked_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_trusted_device(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &TrustedDeviceCredentialRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            device_credential_id, subject_id, current_secret_version, previous_secret_version,
            previous_secret_accept_until, created_at, last_used_at, expires_at,
            silent_revival_until, revoked_at, display_label
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
        table_names
            .get(PostgresAuthCoreTable::TrustedDeviceCredential)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_trusted_device",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.device_credential_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(i64_from_secret_version(record.current_secret_version)?)
        .bind(optional_i64_from_secret_version(
            record.previous_secret_version,
        )?)
        .bind(optional_i64_from_unix_seconds(
            record.previous_secret_accept_until,
        )?)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.last_used_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(i64_from_unix_seconds(record.silent_revival_until)?)
        .bind(optional_i64_from_unix_seconds(record.revoked_at)?)
        .bind(record.display_label.as_deref())
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_active_proof_attempt(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &ActiveProofAttemptRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            attempt_id, proof_use, subject_id, weak_proof_failures,
            max_weak_proof_failures, created_at, expires_at, closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofAttempt)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_active_proof_attempt",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.attempt_id.as_bytes())
        .bind(i32_from_proof_use(record.proof_use))
        .bind(record.subject_id.as_ref().map(|id| id.as_bytes().to_vec()))
        .bind(i32_from_u32(record.weak_proof_failures)?)
        .bind(i32_from_u32(record.max_weak_proof_failures)?)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_active_proof_challenge(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &ActiveProofChallengeRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            challenge_id, attempt_id, proof_family, method_label, online_guessing_risk,
            challenge_dedupe_key, recipient_handle, resend_count, max_resends,
            requires_stateless_fast_fail, created_at, expires_at, closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallenge)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_active_proof_challenge",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.challenge_id.as_bytes())
        .bind(record.attempt_id.as_bytes())
        .bind(i32_from_proof_family(record.proof.family()))
        .bind(record.proof.method_label())
        .bind(bool_from_online_guessing_risk(
            record.proof.online_guessing_risk(),
        ))
        .bind(record.challenge_dedupe_key.as_ref().map(|key| key.as_str()))
        .bind(record.recipient_handle.as_deref())
        .bind(i32_from_u32(record.resend_count)?)
        .bind(i32_from_u32(record.max_resends)?)
        .bind(record.requires_stateless_fast_fail)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    for key in &record.used_delivery_idempotency_keys {
        insert_challenge_delivery_key(
            tx,
            table_names,
            &record.challenge_id,
            key,
            record.created_at,
        )
        .await?;
    }
    Ok(())
}

async fn insert_satisfied_proof(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    attempt_id: &ActiveProofAttemptId,
    proof: &SatisfiedProof,
    satisfied_at: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            attempt_id, proof_family, method_label, online_guessing_risk,
            proof_source_kind, proof_source_id, satisfied_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_satisfied_proof",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(attempt_id.as_bytes())
        .bind(i32_from_proof_family(proof.family()))
        .bind(proof.method_label())
        .bind(bool_from_online_guessing_risk(proof.online_guessing_risk()))
        .bind(
            proof
                .source()
                .map(|source| i32_from_verified_proof_source_kind(source.kind())),
        )
        .bind(proof.source().map(|source| source.source_id().as_bytes()))
        .bind(i64_from_unix_seconds(satisfied_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_challenge_delivery_key(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    challenge_id: &ActiveProofChallengeId,
    idempotency_key: &str,
    created_at: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (challenge_id, delivery_idempotency_key, created_at)
        VALUES ($1,$2,$3)
        ON CONFLICT (challenge_id, delivery_idempotency_key) DO NOTHING
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_challenge_delivery_key",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(challenge_id.as_bytes())
        .bind(idempotency_key)
        .bind(i64_from_unix_seconds(created_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_session_secret_mac(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    session_id: &SessionId,
    secret_version: SecretVersion,
    mac_bytes: &[u8],
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (session_id, secret_version, secret_mac, created_at)
        VALUES ($1,$2,$3,0)
        "#,
        table_names
            .get(PostgresAuthCoreTable::SessionCredentialSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.secret.insert_session_mac",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(session_id.as_bytes())
        .bind(i64_from_secret_version(secret_version)?)
        .bind(mac_bytes)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_trusted_device_secret_mac(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    device_credential_id: &TrustedDeviceCredentialId,
    secret_version: SecretVersion,
    mac_bytes: &[u8],
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (device_credential_id, secret_version, secret_mac, created_at)
        VALUES ($1,$2,$3,0)
        "#,
        table_names
            .get(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.secret.insert_trusted_device_mac",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(device_credential_id.as_bytes())
        .bind(i64_from_secret_version(secret_version)?)
        .bind(mac_bytes)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn insert_active_proof_continuation_secret_mac(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    attempt_id: &ActiveProofAttemptId,
    mac_bytes: &[u8],
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (attempt_id, secret_mac, created_at)
        VALUES ($1,$2,0)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofContinuationSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.secret.insert_active_proof_continuation_mac",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(attempt_id.as_bytes())
        .bind(mac_bytes)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

async fn hard_delete_active_proof_attempt(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    attempt_id: &ActiveProofAttemptId,
) -> Result<(), PostgresAuthStoreError> {
    let delivery_statement = format!(
        r#"
        DELETE FROM {}
        WHERE challenge_id IN (
            SELECT challenge_id FROM {} WHERE attempt_id = $1
        )
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
            .quoted(),
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallenge)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.delete_active_proof_delivery_keys",
        Some(delivery_statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(delivery_statement.as_str()))
        .bind(attempt_id.as_bytes())
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;

    for (label, table) in [
        (
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            PostgresAuthCoreTable::ActiveProofSatisfiedProof,
        ),
        (
            "auth_core.mutation.delete_active_proof_challenges",
            PostgresAuthCoreTable::ActiveProofChallenge,
        ),
        (
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            PostgresAuthCoreTable::ActiveProofContinuationSecretMac,
        ),
        (
            "auth_core.mutation.delete_active_proof_attempt",
            PostgresAuthCoreTable::ActiveProofAttempt,
        ),
    ] {
        let statement = format!(
            r#"DELETE FROM {} WHERE attempt_id = $1"#,
            table_names.get(table).quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            label,
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes())
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}

async fn append_audit_events(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    events: &[AuditEvent],
) -> Result<(), PostgresAuthStoreError> {
    for event in events {
        let statement = format!(
            r#"
            INSERT INTO {} (
                kind, subject_id, session_id, device_credential_id, attempt_id,
                challenge_id, weak_proof_gate_kind, weak_proof_gate_method_label, occurred_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            "#,
            table_names.get(PostgresAuthCoreTable::AuditEvent).quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.audit.append_event",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(i32_from_audit_event_kind(event.kind))
            .bind(event.subject_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(event.session_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(
                event
                    .device_credential_id
                    .as_ref()
                    .map(|id| id.as_bytes().to_vec()),
            )
            .bind(event.attempt_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(event.challenge_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(
                event
                    .weak_proof_gate
                    .as_ref()
                    .map(|gate| i32_from_weak_gate_kind(gate.kind())),
            )
            .bind(
                event
                    .weak_proof_gate
                    .as_ref()
                    .map(WeakProofGateSummary::method_label),
            )
            .bind(i64_from_unix_seconds(event.occurred_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}

async fn append_core_durable_effects(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    commands: &[DurableEffectCommand],
) -> Result<(), PostgresAuthStoreError> {
    for command in commands {
        match command {
            DurableEffectCommand::SendOutOfBandMessage(command) => {
                let statement = format!(
                    r#"
                    INSERT INTO {} (
                        kind, security_notification_kind, challenge_id, proof_method_label, recipient_handle,
                        delivery_idempotency_key, expires_at, created_at
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
                    "#,
                    table_names
                        .get(PostgresAuthCoreTable::CoreDurableEffectCommand)
                        .quoted()
                );
                tx.record_database_operation(
                    DatabaseOperationKind::Execute,
                    "auth_core.effect.append_out_of_band_message",
                    Some(statement.as_str()),
                );
                pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                    .bind(DURABLE_EFFECT_KIND_SEND_OUT_OF_BAND_MESSAGE)
                    .bind(Option::<i32>::None)
                    .bind(command.challenge_id.as_bytes())
                    .bind(command.proof_method_label.as_str())
                    .bind(command.recipient_handle.as_str())
                    .bind(command.idempotency_key.as_str())
                    .bind(i64_from_unix_seconds(command.expires_at)?)
                    .execute(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            }
            DurableEffectCommand::NotifySecurityEvent(command) => {
                let statement = format!(
                    r#"
                    INSERT INTO {} (kind, security_notification_kind, subject_id, created_at)
                    VALUES ($1,$2,$3,0)
                    "#,
                    table_names
                        .get(PostgresAuthCoreTable::CoreDurableEffectCommand)
                        .quoted()
                );
                tx.record_database_operation(
                    DatabaseOperationKind::Execute,
                    "auth_core.effect.append_security_notification",
                    Some(statement.as_str()),
                );
                pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                    .bind(DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT)
                    .bind(i32_from_security_notification_kind(command.kind))
                    .bind(command.subject_id.as_bytes())
                    .execute(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            }
        }
    }
    Ok(())
}

async fn materialize_and_lock_subject_auth_state(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    cutoff: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let upsert_statement = format!(
        r#"
        INSERT INTO {} (subject_id, revoke_records_created_at_or_before)
        VALUES ($1,$2)
        ON CONFLICT (subject_id)
        DO UPDATE SET revoke_records_created_at_or_before = GREATEST(
            {}.revoke_records_created_at_or_before,
            EXCLUDED.revoke_records_created_at_or_before
        )
        "#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted(),
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.precondition.materialize_subject_auth_state",
        Some(upsert_statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(upsert_statement.as_str()))
        .bind(subject_id.as_bytes())
        .bind(i64_from_unix_seconds(cutoff)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;

    let lock_statement = format!(
        r#"SELECT 1 FROM {} WHERE subject_id = $1 FOR UPDATE"#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    let found = fetch_exists_for_update(
        tx,
        "auth_core.precondition.lock_subject_auth_state",
        &lock_statement,
        |query| Ok(query.bind(subject_id.as_bytes())),
    )
    .await?;
    if !found {
        return Err(PostgresAuthStoreError::PreconditionFailed(
            "subject auth state could not be locked",
        ));
    }
    Ok(())
}

async fn validate_subject_cutoff_does_not_invalidate(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    target: CoreStorageTarget,
) -> Result<(), PostgresAuthStoreError> {
    let cutoff_statement = format!(
        r#"SELECT revoke_records_created_at_or_before FROM {} WHERE subject_id = $1"#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "auth_core.precondition.fetch_subject_cutoff",
        Some(cutoff_statement.as_str()),
    );
    let cutoff = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(cutoff_statement.as_str()))
        .bind(subject_id.as_bytes())
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    let cutoff = unix_seconds_from_i64(cutoff)?;
    if cutoff.get() == 0 {
        return Ok(());
    }
    let created_at = fetch_target_created_at(tx, table_names, &target).await?;
    if created_at <= cutoff {
        return Err(PostgresAuthStoreError::PreconditionFailed(
            "subject auth state invalidates target",
        ));
    }
    Ok(())
}

async fn fetch_target_created_at(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    target: &CoreStorageTarget,
) -> Result<UnixSeconds, PostgresAuthStoreError> {
    let (statement, id_bytes): (String, &[u8]) = match target {
        CoreStorageTarget::Session(session_id) => (
            format!(
                r#"SELECT created_at FROM {} WHERE session_id = $1"#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            ),
            session_id.as_bytes(),
        ),
        CoreStorageTarget::TrustedDeviceCredential(device_credential_id) => (
            format!(
                r#"SELECT created_at FROM {} WHERE device_credential_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            ),
            device_credential_id.as_bytes(),
        ),
        CoreStorageTarget::ActiveProofAttempt(attempt_id) => (
            format!(
                r#"SELECT created_at FROM {} WHERE attempt_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            ),
            attempt_id.as_bytes(),
        ),
        _ => {
            return Err(PostgresAuthStoreError::InvalidStoredData(
                "subject revocation validation target does not have created_at",
            ));
        }
    };
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "auth_core.precondition.fetch_target_created_at",
        Some(statement.as_str()),
    );
    let created_at = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(id_bytes)
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    unix_seconds_from_i64(created_at)
}

async fn fetch_exists_for_update<'q, F>(
    tx: &mut Tx<'_>,
    label: &'static str,
    statement: &'q str,
    bind: F,
) -> Result<bool, PostgresAuthStoreError>
where
    F: FnOnce(
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> Result<
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
        PostgresAuthStoreError,
    >,
{
    tx.record_database_operation(DatabaseOperationKind::FetchOptional, label, Some(statement));
    let row = bind(pooler_safe_query(sqlx::AssertSqlSafe(statement)))?
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(row.is_some())
}

async fn execute_one_row_update<'q, F>(
    tx: &mut Tx<'_>,
    label: &'static str,
    statement: &'q str,
    bind: F,
) -> Result<(), PostgresAuthStoreError>
where
    F: FnOnce(
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> Result<
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
        PostgresAuthStoreError,
    >,
{
    tx.record_database_operation(DatabaseOperationKind::Execute, label, Some(statement));
    let affected = bind(pooler_safe_query(sqlx::AssertSqlSafe(statement)))?
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?
        .rows_affected();
    if affected != 1 {
        return Err(PostgresAuthStoreError::PreconditionFailed(
            "expected exactly one row to be updated",
        ));
    }
    Ok(())
}

fn classify_presented_secret(
    keyset: &Keyset,
    current_target: &CoreStorageTarget,
    current_mac_bytes: Option<&[u8]>,
    secret: &AuthCredentialSecret,
    current_version: SecretVersion,
    previous_target: &CoreStorageTarget,
    previous_mac_bytes: Option<&[u8]>,
    previous_version: Option<SecretVersion>,
    previous_secret_accept_until: Option<UnixSeconds>,
    now: UnixSeconds,
) -> Result<StoredSecretMatch, PostgresAuthStoreError> {
    if let Some(current_mac) = current_mac_bytes {
        let current_mac = MacOverSecret::try_from(current_mac)
            .map_err(|_| PostgresAuthStoreError::InvalidStoredData("malformed current MAC"))?;
        if current_mac.verify(
            keyset,
            secret.expose_secret(),
            &credential_secret_mac_context(current_target),
        ) {
            return Ok(StoredSecretMatch::Current);
        }
    }
    if previous_version.is_some()
        && let Some(previous_mac) = previous_mac_bytes
    {
        let previous_mac = MacOverSecret::try_from(previous_mac)
            .map_err(|_| PostgresAuthStoreError::InvalidStoredData("malformed previous MAC"))?;
        if previous_mac.verify(
            keyset,
            secret.expose_secret(),
            &credential_secret_mac_context(previous_target),
        ) {
            if previous_version.is_some_and(|version| version != current_version)
                && previous_secret_accept_until.is_some_and(|accept_until| now < accept_until)
            {
                return Ok(StoredSecretMatch::PreviousWithinGrace);
            }
            return Ok(StoredSecretMatch::PreviousAfterGrace);
        }
    }
    Ok(StoredSecretMatch::Unknown)
}

pub(super) fn credential_secret_mac_context(target: &CoreStorageTarget) -> Vec<u8> {
    let mut context = Vec::new();
    match target {
        CoreStorageTarget::SessionCredentialSecret {
            session_id,
            secret_version,
        } => {
            context.extend_from_slice(SESSION_SECRET_MAC_CONTEXT_PREFIX);
            append_context_bytes(&mut context, session_id.as_bytes());
            context.extend_from_slice(&secret_version.get().to_be_bytes());
        }
        CoreStorageTarget::TrustedDeviceCredentialSecret {
            device_credential_id,
            secret_version,
        } => {
            context.extend_from_slice(TRUSTED_DEVICE_SECRET_MAC_CONTEXT_PREFIX);
            append_context_bytes(&mut context, device_credential_id.as_bytes());
            context.extend_from_slice(&secret_version.get().to_be_bytes());
        }
        CoreStorageTarget::ActiveProofContinuationSecret { attempt_id } => {
            context.extend_from_slice(ACTIVE_PROOF_CONTINUATION_SECRET_MAC_CONTEXT_PREFIX);
            append_context_bytes(&mut context, attempt_id.as_bytes());
        }
        _ => {}
    }
    context
}

fn append_context_bytes(context: &mut Vec<u8>, bytes: &[u8]) {
    context.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    context.extend_from_slice(bytes);
}

pub(super) fn schema_instance_key(config: &PostgresAuthStoreConfig) -> String {
    let schema = config.schema.as_ref().map_or("", PgSchemaName::as_str);
    format!(
        "schema={schema};table_prefix={}",
        config.table_prefix.as_str()
    )
}

fn auth_table_number(table: PostgresAuthCoreTable) -> u8 {
    match table {
        PostgresAuthCoreTable::Session => 1,
        PostgresAuthCoreTable::SessionCredentialSecretMac => 2,
        PostgresAuthCoreTable::TrustedDeviceCredential => 3,
        PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac => 4,
        PostgresAuthCoreTable::ActiveProofAttempt => 5,
        PostgresAuthCoreTable::ActiveProofContinuationSecretMac => 6,
        PostgresAuthCoreTable::ActiveProofSatisfiedProof => 7,
        PostgresAuthCoreTable::ActiveProofChallenge => 8,
        PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey => 9,
        PostgresAuthCoreTable::SubjectAuthState => 10,
        PostgresAuthCoreTable::CredentialInstance => 11,
        PostgresAuthCoreTable::CredentialRecoveryAuthority => 12,
        PostgresAuthCoreTable::LifecycleAuthoritySource => 13,
        PostgresAuthCoreTable::PendingCredentialLifecycleAction => 14,
        PostgresAuthCoreTable::AuditEvent => 15,
        PostgresAuthCoreTable::CoreDurableEffectCommand => 16,
    }
}

fn unix_seconds_from_i64(value: i64) -> Result<UnixSeconds, PostgresAuthStoreError> {
    let value = u64::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("negative Unix timestamp"))?;
    Ok(UnixSeconds::new(value))
}

fn i64_from_unix_seconds(value: UnixSeconds) -> Result<i64, PostgresAuthStoreError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("Unix timestamp too large"))
}

fn optional_i64_from_unix_seconds(
    value: Option<UnixSeconds>,
) -> Result<Option<i64>, PostgresAuthStoreError> {
    value.map(i64_from_unix_seconds).transpose()
}

fn secret_version_from_i64(value: i64) -> Result<SecretVersion, PostgresAuthStoreError> {
    let value = u64::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("negative secret version"))?;
    SecretVersion::new(value).map_err(PostgresAuthStoreError::Core)
}

fn i64_from_secret_version(value: SecretVersion) -> Result<i64, PostgresAuthStoreError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("secret version too large"))
}

fn optional_i64_from_secret_version(
    value: Option<SecretVersion>,
) -> Result<Option<i64>, PostgresAuthStoreError> {
    value.map(i64_from_secret_version).transpose()
}

fn u32_from_i32(value: i32) -> Result<u32, PostgresAuthStoreError> {
    u32::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("negative u32-backed value"))
}

fn i32_from_u32(value: u32) -> Result<i32, PostgresAuthStoreError> {
    i32::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("u32-backed value too large"))
}

pub(super) fn proof_family_from_i32(value: i32) -> Result<ProofFamily, PostgresAuthStoreError> {
    let value = u8::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("invalid proof family id"))?;
    proof_family_from_wire_id(value).map_err(PostgresAuthStoreError::Core)
}

pub(super) fn i32_from_proof_family(value: ProofFamily) -> i32 {
    i32::from(proof_family_wire_id(value))
}

pub(super) fn verified_proof_source_kind_from_i32(
    value: i32,
) -> Result<VerifiedProofSourceKind, PostgresAuthStoreError> {
    match value {
        1 => Ok(VerifiedProofSourceKind::CredentialInstance),
        2 => Ok(VerifiedProofSourceKind::OutOfBandIdentifier),
        3 => Ok(VerifiedProofSourceKind::ExternalAuthority),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid verified proof source kind",
        )),
    }
}

pub(super) fn i32_from_verified_proof_source_kind(value: VerifiedProofSourceKind) -> i32 {
    match value {
        VerifiedProofSourceKind::CredentialInstance => 1,
        VerifiedProofSourceKind::OutOfBandIdentifier => 2,
        VerifiedProofSourceKind::ExternalAuthority => 3,
    }
}

pub(super) fn credential_instance_kind_from_i32(
    value: i32,
) -> Result<CredentialInstanceKind, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialInstanceKind::MessageSignatureVerifier),
        2 => Ok(CredentialInstanceKind::SharedSecretOtpVerifier),
        3 => Ok(CredentialInstanceKind::OriginBoundPublicKeyCredential),
        4 => Ok(CredentialInstanceKind::RecoveryCodeCredential),
        5 => Ok(CredentialInstanceKind::TrustedDeviceCredential),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential instance kind",
        )),
    }
}

pub(super) fn i32_from_credential_instance_kind(value: CredentialInstanceKind) -> i32 {
    match value {
        CredentialInstanceKind::MessageSignatureVerifier => 1,
        CredentialInstanceKind::SharedSecretOtpVerifier => 2,
        CredentialInstanceKind::OriginBoundPublicKeyCredential => 3,
        CredentialInstanceKind::RecoveryCodeCredential => 4,
        CredentialInstanceKind::TrustedDeviceCredential => 5,
    }
}

pub(super) fn credential_lifecycle_state_from_i32(
    value: i32,
) -> Result<CredentialLifecycleState, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialLifecycleState::Active),
        2 => Ok(CredentialLifecycleState::PendingActivation),
        3 => Ok(CredentialLifecycleState::PendingReplacement),
        4 => Ok(CredentialLifecycleState::PendingRemoval),
        5 => Ok(CredentialLifecycleState::ScheduledDeletion),
        6 => Ok(CredentialLifecycleState::Consumed),
        7 => Ok(CredentialLifecycleState::Revoked),
        8 => Ok(CredentialLifecycleState::Expired),
        9 => Ok(CredentialLifecycleState::Superseded),
        10 => Ok(CredentialLifecycleState::AdminSuspended),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential lifecycle state",
        )),
    }
}

pub(super) fn i32_from_credential_lifecycle_state(value: CredentialLifecycleState) -> i32 {
    match value {
        CredentialLifecycleState::Active => 1,
        CredentialLifecycleState::PendingActivation => 2,
        CredentialLifecycleState::PendingReplacement => 3,
        CredentialLifecycleState::PendingRemoval => 4,
        CredentialLifecycleState::ScheduledDeletion => 5,
        CredentialLifecycleState::Consumed => 6,
        CredentialLifecycleState::Revoked => 7,
        CredentialLifecycleState::Expired => 8,
        CredentialLifecycleState::Superseded => 9,
        CredentialLifecycleState::AdminSuspended => 10,
    }
}

pub(super) fn credential_lifecycle_action_from_i32(
    value: i32,
) -> Result<CredentialLifecycleAction, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialLifecycleAction::Create),
        2 => Ok(CredentialLifecycleAction::Reset),
        3 => Ok(CredentialLifecycleAction::Replace),
        4 => Ok(CredentialLifecycleAction::Remove),
        5 => Ok(CredentialLifecycleAction::Disable),
        6 => Ok(CredentialLifecycleAction::Regenerate),
        7 => Ok(CredentialLifecycleAction::RecoverSubjectAccess),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential lifecycle action",
        )),
    }
}

pub(super) fn i32_from_credential_lifecycle_action(value: CredentialLifecycleAction) -> i32 {
    match value {
        CredentialLifecycleAction::Create => 1,
        CredentialLifecycleAction::Reset => 2,
        CredentialLifecycleAction::Replace => 3,
        CredentialLifecycleAction::Remove => 4,
        CredentialLifecycleAction::Disable => 5,
        CredentialLifecycleAction::Regenerate => 6,
        CredentialLifecycleAction::RecoverSubjectAccess => 7,
    }
}

pub(super) fn recovery_authority_timing_from_i32(
    value: i32,
) -> Result<RecoveryAuthorityTiming, PostgresAuthStoreError> {
    match value {
        1 => Ok(RecoveryAuthorityTiming::Immediate),
        2 => Ok(RecoveryAuthorityTiming::Delayed),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid recovery authority timing",
        )),
    }
}

pub(super) fn i32_from_recovery_authority_timing(value: RecoveryAuthorityTiming) -> i32 {
    match value {
        RecoveryAuthorityTiming::Immediate => 1,
        RecoveryAuthorityTiming::Delayed => 2,
    }
}

pub(super) fn lifecycle_authority_source_kind_from_i32(
    value: i32,
) -> Result<LifecycleAuthoritySourceKind, PostgresAuthStoreError> {
    match value {
        1 => Ok(LifecycleAuthoritySourceKind::CredentialInstance),
        2 => Ok(LifecycleAuthoritySourceKind::OutOfBandIdentifier),
        3 => Ok(LifecycleAuthoritySourceKind::ExternalAuthority),
        4 => Ok(LifecycleAuthoritySourceKind::AuthenticatedSession),
        5 => Ok(LifecycleAuthoritySourceKind::AdminSupportIntervention),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid lifecycle authority source kind",
        )),
    }
}

pub(super) fn i32_from_lifecycle_authority_source_kind(value: LifecycleAuthoritySourceKind) -> i32 {
    match value {
        LifecycleAuthoritySourceKind::CredentialInstance => 1,
        LifecycleAuthoritySourceKind::OutOfBandIdentifier => 2,
        LifecycleAuthoritySourceKind::ExternalAuthority => 3,
        LifecycleAuthoritySourceKind::AuthenticatedSession => 4,
        LifecycleAuthoritySourceKind::AdminSupportIntervention => 5,
    }
}

fn online_guessing_risk_from_bool(value: bool) -> OnlineGuessingRisk {
    if value {
        OnlineGuessingRisk::OnlineGuessable
    } else {
        OnlineGuessingRisk::NotOnlineGuessable
    }
}

fn bool_from_online_guessing_risk(value: OnlineGuessingRisk) -> bool {
    matches!(value, OnlineGuessingRisk::OnlineGuessable)
}

pub(super) fn proof_use_from_i32(value: i32) -> Result<ProofUse, PostgresAuthStoreError> {
    match value {
        1 => Ok(ProofUse::BindSubjectToActiveProofAttempt),
        2 => Ok(ProofUse::ContributeToFullAuthentication),
        3 => Ok(ProofUse::ReviveTrustedDeviceWithActiveProof),
        4 => Ok(ProofUse::SatisfyStepUp),
        5 => Ok(ProofUse::SilentlyReviveTrustedDeviceSession),
        6 => Ok(ProofUse::ReduceAuthenticationRequirement),
        7 => Ok(ProofUse::RecoverOrReplaceCredential),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid proof use id",
        )),
    }
}

pub(super) fn i32_from_proof_use(value: ProofUse) -> i32 {
    match value {
        ProofUse::BindSubjectToActiveProofAttempt => 1,
        ProofUse::ContributeToFullAuthentication => 2,
        ProofUse::ReviveTrustedDeviceWithActiveProof => 3,
        ProofUse::SatisfyStepUp => 4,
        ProofUse::SilentlyReviveTrustedDeviceSession => 5,
        ProofUse::ReduceAuthenticationRequirement => 6,
        ProofUse::RecoverOrReplaceCredential => 7,
    }
}

fn i32_from_audit_event_kind(value: AuditEventKind) -> i32 {
    match value {
        AuditEventKind::SessionCreated => 1,
        AuditEventKind::SessionRefreshed => 2,
        AuditEventKind::TrustedDeviceSilentRevival => 3,
        AuditEventKind::TrustedDeviceActiveProofRevival => 4,
        AuditEventKind::TrustedDeviceCreated => 5,
        AuditEventKind::TrustedDeviceRotated => 6,
        AuditEventKind::StepUpCompleted => 7,
        AuditEventKind::CredentialMismatch => 8,
        AuditEventKind::SessionRevoked => 9,
        AuditEventKind::TrustedDeviceRevoked => 10,
        AuditEventKind::SubjectAuthStateRevoked => 11,
        AuditEventKind::ActiveProofAttemptStarted => 12,
        AuditEventKind::OutOfBandChallengeIssued => 13,
        AuditEventKind::OutOfBandChallengeResent => 14,
        AuditEventKind::ActiveProofFailed => 15,
        AuditEventKind::ActiveProofSucceeded => 16,
        AuditEventKind::ActiveProofAttemptClosed => 17,
        AuditEventKind::ActiveProofAttemptDeletedAfterWeakProofFailures => 18,
        AuditEventKind::ActiveProofMethodChallengeIssued => 19,
        AuditEventKind::CredentialResetAuthorized => 20,
        AuditEventKind::CredentialResetPendingActionScheduled => 21,
        AuditEventKind::CredentialResetExecuted => 22,
        AuditEventKind::CredentialResetPendingActionCancelled => 23,
        AuditEventKind::CredentialReplacementExecuted => 24,
        AuditEventKind::CredentialReplacementPendingActionCancelled => 25,
        AuditEventKind::CredentialRemovalExecuted => 26,
        AuditEventKind::CredentialRemovalPendingActionCancelled => 27,
        AuditEventKind::CredentialRegenerationExecuted => 28,
        AuditEventKind::CredentialRegenerationPendingActionCancelled => 29,
    }
}

pub(super) fn i32_from_security_notification_kind(value: SecurityNotificationKind) -> i32 {
    match value {
        SecurityNotificationKind::TrustedDeviceCreated => 1,
        SecurityNotificationKind::CredentialResetAuthorized => 2,
        SecurityNotificationKind::CredentialResetPendingActionScheduled => 3,
        SecurityNotificationKind::CredentialResetExecuted => 4,
        SecurityNotificationKind::CredentialResetPendingActionCancelled => 5,
        SecurityNotificationKind::CredentialReplacementExecuted => 6,
        SecurityNotificationKind::CredentialReplacementPendingActionCancelled => 7,
        SecurityNotificationKind::CredentialRemovalExecuted => 8,
        SecurityNotificationKind::CredentialRemovalPendingActionCancelled => 9,
        SecurityNotificationKind::CredentialRegenerationExecuted => 10,
        SecurityNotificationKind::CredentialRegenerationPendingActionCancelled => 11,
    }
}

fn i32_from_weak_gate_kind(value: WeakProofGateKind) -> i32 {
    match value {
        WeakProofGateKind::ProofOfWork => 1,
        WeakProofGateKind::HumanChallenge => 2,
        WeakProofGateKind::RiskDecision => 3,
        WeakProofGateKind::Other => 4,
    }
}
