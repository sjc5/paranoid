use super::*;

const DEFAULT_SCHEMA_LOCAL_AUTH_INDEX_PREFIX: &str = "auth_";
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresAuthStoreConfig {
    schema: PgSchemaName,
    schema_ledger_table_name: PgQualifiedTableName,
}

impl PostgresAuthStoreConfig {
    pub(crate) fn for_db_bootstrap_config(
        bootstrap_config: &BootstrapConfig,
    ) -> Result<Self, PostgresAuthStoreError> {
        let config = Self {
            schema: bootstrap_config.schema_name().clone(),
            schema_ledger_table_name: bootstrap_config.table_names().schema_ledger,
        };
        config.table_names()?;
        Ok(config)
    }

    pub(crate) fn table_name(
        &self,
        table: PostgresAuthCoreTable,
    ) -> Result<PgQualifiedTableName, PostgresAuthStoreError> {
        let table_name = PgIdentifier::new(table.default_suffix()).map_err(DbError::from)?;
        Ok(PgQualifiedTableName::new(
            Some(self.schema.clone()),
            table_name,
        ))
    }

    pub(in crate::auth_core) fn table_names(
        &self,
    ) -> Result<AuthCoreTableNames, PostgresAuthStoreError> {
        AuthCoreTableNames::new(self)
    }

    pub(in crate::auth_core) fn schema_ledger_table_name(
        &self,
    ) -> Result<PgQualifiedTableName, PostgresAuthStoreError> {
        Ok(self.schema_ledger_table_name.clone())
    }

    pub(in crate::auth_core) fn index_name_prefix(&self) -> &str {
        DEFAULT_SCHEMA_LOCAL_AUTH_INDEX_PREFIX
    }
}
#[derive(Clone, Debug)]
pub(in crate::auth_core) struct AuthCoreTableNames {
    pub(in crate::auth_core) by_table: BTreeMap<PostgresAuthCoreTable, PgQualifiedTableName>,
    pub(in crate::auth_core) index_name_prefix: String,
}

impl AuthCoreTableNames {
    pub(in crate::auth_core) fn new(
        config: &PostgresAuthStoreConfig,
    ) -> Result<Self, PostgresAuthStoreError> {
        let mut by_table = BTreeMap::new();
        for table in PostgresAuthCoreSchemaContract::table_kinds() {
            by_table.insert(*table, config.table_name(*table)?);
        }
        Ok(Self {
            by_table,
            index_name_prefix: config.index_name_prefix().to_owned(),
        })
    }

    pub(in crate::auth_core) fn get(&self, table: PostgresAuthCoreTable) -> &PgQualifiedTableName {
        self.by_table
            .get(&table)
            .expect("auth table names must include every table kind")
    }

    pub(in crate::auth_core) fn iter(
        &self,
    ) -> impl Iterator<Item = (PostgresAuthCoreTable, &PgQualifiedTableName)> {
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
pub(in crate::auth_core) fn schema_instance_key(config: &PostgresAuthStoreConfig) -> String {
    let schema_ledger_table_name = config
        .schema_ledger_table_name()
        .expect("validated auth store config must produce schema ledger table name");
    let session_table_name = config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("validated auth store config must produce session table name");
    schema_instance_key_for_parts([
        ("schema_ledger", &schema_ledger_table_name),
        ("session_table", &session_table_name),
    ])
}

pub(in crate::auth_core) fn auth_table_number(table: PostgresAuthCoreTable) -> u8 {
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
        PostgresAuthCoreTable::PendingSubjectLifecycleAction => 15,
        PostgresAuthCoreTable::AuditEvent => 16,
        PostgresAuthCoreTable::CoreDurableEffectCommand => 17,
        PostgresAuthCoreTable::AdminSupportIntervention => 18,
        PostgresAuthCoreTable::CoreDurableEffectQueueDispatch => 19,
        PostgresAuthCoreTable::SubjectLifecycleAuthority => 20,
        PostgresAuthCoreTable::OutOfBandIdentifierBinding => 21,
    }
}
