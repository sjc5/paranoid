use super::*;

const POSTGRES_AUTH_CORE_TABLES: &[PostgresAuthCoreTable] = &[
    PostgresAuthCoreTable::Session,
    PostgresAuthCoreTable::SessionCredentialSecretMac,
    PostgresAuthCoreTable::TrustedDeviceCredential,
    PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac,
    PostgresAuthCoreTable::ActiveProofAttempt,
    PostgresAuthCoreTable::ActiveProofContinuationSecretMac,
    PostgresAuthCoreTable::ActiveProofSatisfiedProof,
    PostgresAuthCoreTable::ActiveProofChallenge,
    PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey,
    PostgresAuthCoreTable::SubjectAuthState,
    PostgresAuthCoreTable::CredentialInstance,
    PostgresAuthCoreTable::CredentialRecoveryAuthority,
    PostgresAuthCoreTable::LifecycleAuthoritySource,
    PostgresAuthCoreTable::PendingCredentialLifecycleAction,
    PostgresAuthCoreTable::AuditEvent,
    PostgresAuthCoreTable::CoreDurableEffectCommand,
];

/// Postgres schema contract for reducer-owned auth state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresAuthCoreSchemaContract;

impl PostgresAuthCoreSchemaContract {
    /// Returns every reducer-owned Postgres table family.
    pub const fn table_kinds() -> &'static [PostgresAuthCoreTable] {
        POSTGRES_AUTH_CORE_TABLES
    }

    /// Returns table contracts for every reducer-owned Postgres table family.
    pub fn table_contracts() -> Vec<PostgresAuthCoreTableContract> {
        POSTGRES_AUTH_CORE_TABLES
            .iter()
            .copied()
            .map(PostgresAuthCoreTableContract::for_table)
            .collect()
    }

    /// Returns the Postgres table that stores a concrete core storage target.
    pub const fn table_for_storage_target(target: &CoreStorageTarget) -> PostgresAuthCoreTable {
        match target {
            CoreStorageTarget::Session(_) => PostgresAuthCoreTable::Session,
            CoreStorageTarget::SessionCredentialSecret { .. } => {
                PostgresAuthCoreTable::SessionCredentialSecretMac
            }
            CoreStorageTarget::TrustedDeviceCredential(_) => {
                PostgresAuthCoreTable::TrustedDeviceCredential
            }
            CoreStorageTarget::TrustedDeviceCredentialSecret { .. } => {
                PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac
            }
            CoreStorageTarget::ActiveProofAttempt(_) => PostgresAuthCoreTable::ActiveProofAttempt,
            CoreStorageTarget::ActiveProofContinuationSecret { .. } => {
                PostgresAuthCoreTable::ActiveProofContinuationSecretMac
            }
            CoreStorageTarget::ActiveProofChallenge(_)
            | CoreStorageTarget::ActiveProofChallengesForAttemptProofFamily { .. }
            | CoreStorageTarget::OpenOutOfBandChallengeDedupeKey(_) => {
                PostgresAuthCoreTable::ActiveProofChallenge
            }
            CoreStorageTarget::SubjectAuthState(_) => PostgresAuthCoreTable::SubjectAuthState,
            CoreStorageTarget::CredentialInstance(_) => PostgresAuthCoreTable::CredentialInstance,
            CoreStorageTarget::CredentialRecoveryAuthoritiesForCredential(_) => {
                PostgresAuthCoreTable::CredentialRecoveryAuthority
            }
            CoreStorageTarget::LifecycleAuthoritySource { .. } => {
                PostgresAuthCoreTable::LifecycleAuthoritySource
            }
            CoreStorageTarget::PendingCredentialLifecycleAction(_)
            | CoreStorageTarget::OpenPendingCredentialLifecycleActionForTarget { .. } => {
                PostgresAuthCoreTable::PendingCredentialLifecycleAction
            }
            CoreStorageTarget::AuditEvents => PostgresAuthCoreTable::AuditEvent,
            CoreStorageTarget::CoreDurableEffectCommands => {
                PostgresAuthCoreTable::CoreDurableEffectCommand
            }
        }
    }

    /// Returns credential-secret MAC row mappings.
    pub fn credential_secret_mac_mappings() -> [PostgresCredentialSecretMacMappingContract; 2] {
        [
            PostgresCredentialSecretMacMappingContract::session(),
            PostgresCredentialSecretMacMappingContract::trusted_device(),
        ]
    }
}

/// Reducer-owned Postgres table family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresAuthCoreTable {
    /// Authoritative sessions.
    Session,
    /// Session credential MAC rows keyed by session id and secret version.
    SessionCredentialSecretMac,
    /// Authoritative trusted-device credentials.
    TrustedDeviceCredential,
    /// Trusted-device credential MAC rows keyed by credential id and secret version.
    TrustedDeviceCredentialSecretMac,
    /// Active-proof attempts.
    ActiveProofAttempt,
    /// Active-proof continuation credential MAC rows keyed by attempt id.
    ActiveProofContinuationSecretMac,
    /// Satisfied proof stack entries for active-proof attempts.
    ActiveProofSatisfiedProof,
    /// Active-proof challenges.
    ActiveProofChallenge,
    /// Delivery idempotency keys already used by active-proof challenges.
    ActiveProofChallengeDeliveryKey,
    /// Per-subject auth-state rows.
    SubjectAuthState,
    /// Core-visible credential-instance metadata.
    CredentialInstance,
    /// Recovery-authority edges for credential lifecycle actions.
    CredentialRecoveryAuthority,
    /// Mapping from lifecycle evidence sources to effective recovery authorities.
    LifecycleAuthoritySource,
    /// Delayed credential lifecycle actions.
    PendingCredentialLifecycleAction,
    /// Append-only audit event stream.
    AuditEvent,
    /// Durable core effect command outbox.
    CoreDurableEffectCommand,
}

impl PostgresAuthCoreTable {
    /// Returns the default table suffix under the configured auth table prefix.
    pub const fn default_suffix(self) -> &'static str {
        match self {
            Self::Session => "auth_sessions",
            Self::SessionCredentialSecretMac => "auth_session_secret_macs",
            Self::TrustedDeviceCredential => "auth_trusted_device_credentials",
            Self::TrustedDeviceCredentialSecretMac => "auth_trusted_device_secret_macs",
            Self::ActiveProofAttempt => "auth_active_proof_attempts",
            Self::ActiveProofContinuationSecretMac => "auth_active_proof_continuation_secret_macs",
            Self::ActiveProofSatisfiedProof => "auth_active_proof_satisfied_proofs",
            Self::ActiveProofChallenge => "auth_active_proof_challenges",
            Self::ActiveProofChallengeDeliveryKey => "auth_active_proof_challenge_delivery_keys",
            Self::SubjectAuthState => "auth_subject_state",
            Self::CredentialInstance => "auth_credential_instances",
            Self::CredentialRecoveryAuthority => "auth_credential_recovery_authorities",
            Self::LifecycleAuthoritySource => "auth_lifecycle_authority_sources",
            Self::PendingCredentialLifecycleAction => "auth_credential_lifecycle_pending_actions",
            Self::AuditEvent => "auth_audit_events",
            Self::CoreDurableEffectCommand => "auth_core_durable_effect_commands",
        }
    }

    /// Returns the reducer record kind this table supports.
    pub const fn record_kind(self) -> CoreStorageRecordKind {
        match self {
            Self::Session => CoreStorageRecordKind::Session,
            Self::SessionCredentialSecretMac => CoreStorageRecordKind::SessionCredentialSecret,
            Self::TrustedDeviceCredential => CoreStorageRecordKind::TrustedDeviceCredential,
            Self::TrustedDeviceCredentialSecretMac => {
                CoreStorageRecordKind::TrustedDeviceCredentialSecret
            }
            Self::ActiveProofAttempt | Self::ActiveProofSatisfiedProof => {
                CoreStorageRecordKind::ActiveProofAttempt
            }
            Self::ActiveProofContinuationSecretMac => {
                CoreStorageRecordKind::ActiveProofContinuationSecret
            }
            Self::ActiveProofChallenge | Self::ActiveProofChallengeDeliveryKey => {
                CoreStorageRecordKind::ActiveProofChallenge
            }
            Self::SubjectAuthState => CoreStorageRecordKind::SubjectAuthState,
            Self::CredentialInstance => CoreStorageRecordKind::CredentialInstance,
            Self::CredentialRecoveryAuthority => CoreStorageRecordKind::CredentialRecoveryAuthority,
            Self::LifecycleAuthoritySource => CoreStorageRecordKind::LifecycleAuthoritySource,
            Self::PendingCredentialLifecycleAction => {
                CoreStorageRecordKind::PendingCredentialLifecycleAction
            }
            Self::AuditEvent => CoreStorageRecordKind::AuditEvent,
            Self::CoreDurableEffectCommand => CoreStorageRecordKind::CoreDurableEffectCommand,
        }
    }
}

/// Postgres contract for one auth-core table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresAuthCoreTableContract {
    table: PostgresAuthCoreTable,
    columns: Vec<PostgresColumnContract>,
    uniqueness: Vec<PostgresUniquenessContract>,
    write_policy: PostgresTableWritePolicy,
}

impl PostgresAuthCoreTableContract {
    /// Builds the contract for one Postgres auth-core table.
    pub fn for_table(table: PostgresAuthCoreTable) -> Self {
        match table {
            PostgresAuthCoreTable::Session => table_contract(
                table,
                vec![
                    id_column("session_id", false),
                    id_column("subject_id", false),
                    id_column("device_credential_id", true),
                    secret_version_column("current_secret_version", false),
                    secret_version_column("previous_secret_version", true),
                    unix_seconds_column("previous_secret_accept_until", true),
                    unix_seconds_column("created_at", false),
                    unix_seconds_column("refreshed_at", false),
                    unix_seconds_column("expires_at", false),
                    unix_seconds_column("step_up_expires_at", true),
                    unix_seconds_column("revoked_at", true),
                ],
                vec![primary_key(["session_id"])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::SessionCredentialSecretMac => table_contract(
                table,
                vec![
                    id_column("session_id", false),
                    secret_version_column("secret_version", false),
                    mac_over_secret_column("secret_mac"),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key(["session_id", "secret_version"])],
                PostgresTableWritePolicy::InsertOnlyRows,
            ),
            PostgresAuthCoreTable::TrustedDeviceCredential => table_contract(
                table,
                vec![
                    id_column("device_credential_id", false),
                    id_column("subject_id", false),
                    secret_version_column("current_secret_version", false),
                    secret_version_column("previous_secret_version", true),
                    unix_seconds_column("previous_secret_accept_until", true),
                    unix_seconds_column("created_at", false),
                    unix_seconds_column("last_used_at", false),
                    unix_seconds_column("expires_at", false),
                    unix_seconds_column("silent_revival_until", false),
                    unix_seconds_column("revoked_at", true),
                    validated_text_column(
                        "display_label",
                        true,
                        TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES,
                    ),
                ],
                vec![primary_key(["device_credential_id"])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac => table_contract(
                table,
                vec![
                    id_column("device_credential_id", false),
                    secret_version_column("secret_version", false),
                    mac_over_secret_column("secret_mac"),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key(["device_credential_id", "secret_version"])],
                PostgresTableWritePolicy::InsertOnlyRows,
            ),
            PostgresAuthCoreTable::ActiveProofAttempt => table_contract(
                table,
                vec![
                    id_column("attempt_id", false),
                    core_enum_column("proof_use", false),
                    id_column("subject_id", true),
                    counter_column("weak_proof_failures", false),
                    counter_column("max_weak_proof_failures", false),
                    unix_seconds_column("created_at", false),
                    unix_seconds_column("expires_at", false),
                    unix_seconds_column("closed_at", true),
                ],
                vec![primary_key(["attempt_id"])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::ActiveProofContinuationSecretMac => table_contract(
                table,
                vec![
                    id_column("attempt_id", false),
                    mac_over_secret_column("secret_mac"),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key(["attempt_id"])],
                PostgresTableWritePolicy::InsertOnlyRows,
            ),
            PostgresAuthCoreTable::ActiveProofSatisfiedProof => table_contract(
                table,
                vec![
                    id_column("attempt_id", false),
                    core_enum_column("proof_family", false),
                    validated_text_column("method_label", false, METHOD_LABEL_MAX_BYTES),
                    boolean_column("online_guessing_risk", false),
                    core_enum_column("proof_source_kind", true),
                    id_column("proof_source_id", true),
                    unix_seconds_column("satisfied_at", false),
                ],
                vec![
                    primary_key(["attempt_id", "proof_family"]),
                    unique(
                        "active_proof_satisfied_proof_method",
                        ["attempt_id", "method_label"],
                        None,
                    ),
                ],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::ActiveProofChallenge => table_contract(
                table,
                vec![
                    id_column("challenge_id", false),
                    id_column("attempt_id", false),
                    core_enum_column("proof_family", false),
                    validated_text_column("method_label", false, METHOD_LABEL_MAX_BYTES),
                    boolean_column("online_guessing_risk", false),
                    validated_text_column(
                        "challenge_dedupe_key",
                        true,
                        OUT_OF_BAND_CHALLENGE_DEDUPE_KEY_MAX_BYTES,
                    ),
                    validated_text_column(
                        "recipient_handle",
                        true,
                        OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
                    ),
                    counter_column("resend_count", false),
                    counter_column("max_resends", false),
                    boolean_column("requires_stateless_fast_fail", false),
                    unix_seconds_column("created_at", false),
                    unix_seconds_column("expires_at", false),
                    unix_seconds_column("closed_at", true),
                ],
                vec![
                    primary_key(["challenge_id"]),
                    unique(
                        "active_proof_open_challenge_dedupe_key",
                        ["challenge_dedupe_key"],
                        Some(PostgresUniquePredicate::OpenRow),
                    ),
                ],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey => table_contract(
                table,
                vec![
                    id_column("challenge_id", false),
                    validated_text_column(
                        "delivery_idempotency_key",
                        false,
                        DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
                    ),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key(["challenge_id", "delivery_idempotency_key"])],
                PostgresTableWritePolicy::InsertOnlyRows,
            ),
            PostgresAuthCoreTable::SubjectAuthState => table_contract(
                table,
                vec![
                    id_column("subject_id", false),
                    unix_seconds_column("revoke_records_created_at_or_before", false),
                ],
                vec![primary_key(["subject_id"])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::CredentialInstance => table_contract(
                table,
                vec![
                    id_column("credential_instance_id", false),
                    id_column("subject_id", false),
                    core_enum_column("credential_kind", false),
                    validated_text_column("method_label", false, METHOD_LABEL_MAX_BYTES),
                    core_enum_column("lifecycle_state", false),
                    unix_seconds_column("created_at", false),
                    unix_seconds_column("updated_at", false),
                ],
                vec![primary_key(["credential_instance_id"])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::CredentialRecoveryAuthority => table_contract(
                table,
                vec![
                    id_column("target_credential_instance_id", false),
                    core_enum_column("lifecycle_action", false),
                    id_column("authority_id", false),
                    core_enum_column("authority_timing", false),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key([
                    "target_credential_instance_id",
                    "lifecycle_action",
                    "authority_id",
                    "authority_timing",
                ])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::LifecycleAuthoritySource => table_contract(
                table,
                vec![
                    core_enum_column("source_kind", false),
                    id_column("source_id", false),
                    id_column("authority_id", false),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key(["source_kind", "source_id", "authority_id"])],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::PendingCredentialLifecycleAction => table_contract(
                table,
                vec![
                    id_column("pending_action_id", false),
                    id_column("subject_id", false),
                    id_column("target_credential_instance_id", false),
                    core_enum_column("lifecycle_action", false),
                    unix_seconds_column("requested_at", false),
                    unix_seconds_column("earliest_execute_at", false),
                    unix_seconds_column("expires_at", false),
                    unix_seconds_column("closed_at", true),
                ],
                vec![
                    primary_key(["pending_action_id"]),
                    unique(
                        "credential_lifecycle_open_pending_action",
                        ["target_credential_instance_id", "lifecycle_action"],
                        Some(PostgresUniquePredicate::OpenRow),
                    ),
                ],
                PostgresTableWritePolicy::MutableRows,
            ),
            PostgresAuthCoreTable::AuditEvent => table_contract(
                table,
                vec![
                    identity_column("audit_event_id"),
                    core_enum_column("kind", false),
                    id_column("subject_id", true),
                    id_column("session_id", true),
                    id_column("device_credential_id", true),
                    id_column("attempt_id", true),
                    id_column("challenge_id", true),
                    core_enum_column("weak_proof_gate_kind", true),
                    validated_text_column(
                        "weak_proof_gate_method_label",
                        true,
                        WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES,
                    ),
                    unix_seconds_column("occurred_at", false),
                ],
                vec![primary_key(["audit_event_id"])],
                PostgresTableWritePolicy::AppendOnlyRows,
            ),
            PostgresAuthCoreTable::CoreDurableEffectCommand => table_contract(
                table,
                vec![
                    identity_column("effect_command_id"),
                    core_enum_column("kind", false),
                    id_column("subject_id", true),
                    core_enum_column("security_notification_kind", true),
                    id_column("challenge_id", true),
                    validated_text_column("proof_method_label", true, METHOD_LABEL_MAX_BYTES),
                    validated_text_column(
                        "recipient_handle",
                        true,
                        OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
                    ),
                    validated_text_column(
                        "delivery_idempotency_key",
                        true,
                        DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
                    ),
                    unix_seconds_column("expires_at", true),
                    unix_seconds_column("created_at", false),
                ],
                vec![primary_key(["effect_command_id"])],
                PostgresTableWritePolicy::AppendOnlyRows,
            ),
        }
    }

    /// Returns the table kind.
    pub const fn table(&self) -> PostgresAuthCoreTable {
        self.table
    }

    /// Returns the table's column contracts.
    pub fn columns(&self) -> &[PostgresColumnContract] {
        &self.columns
    }

    /// Returns table uniqueness contracts.
    pub fn uniqueness(&self) -> &[PostgresUniquenessContract] {
        &self.uniqueness
    }

    /// Returns the table write policy.
    pub const fn write_policy(&self) -> PostgresTableWritePolicy {
        self.write_policy
    }
}

/// Postgres column contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresColumnContract {
    name: &'static str,
    storage: PostgresColumnStorage,
    value: PostgresColumnValueContract,
    nullable: bool,
}

impl PostgresColumnContract {
    /// Returns the column name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the Postgres storage type/collation requirement.
    pub const fn storage(&self) -> PostgresColumnStorage {
        self.storage
    }

    /// Returns the semantic value contract.
    pub const fn value(&self) -> PostgresColumnValueContract {
        self.value
    }

    /// Returns whether the column may be null.
    pub const fn nullable(&self) -> bool {
        self.nullable
    }
}

/// Postgres storage type and collation requirement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresColumnStorage {
    /// `BYTEA`.
    Bytea,
    /// `BIGINT`.
    Bigint,
    /// `INTEGER`.
    Integer,
    /// `BOOLEAN`.
    Boolean,
    /// `TEXT COLLATE "C"`.
    TextCollateC,
}

/// Semantic value stored in a Postgres column.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresColumnValueContract {
    /// Non-empty opaque bytes bounded by the auth id limit.
    OpaqueIdBytes {
        /// Maximum byte length.
        max_bytes: usize,
    },
    /// `crate::crypto::MacOverSecret` bytes.
    MacOverSecretBytes {
        /// Exact byte length.
        exact_bytes: usize,
    },
    /// Non-zero credential secret version.
    SecretVersion,
    /// Unix timestamp in whole seconds.
    UnixSeconds,
    /// Non-negative counter.
    Counter,
    /// Core enum discriminant represented as a small numeric domain.
    CoreEnumDiscriminant,
    /// Validated auth-core identifier or display text under bytewise collation.
    ValidatedText {
        /// Maximum UTF-8 byte length.
        max_bytes: usize,
    },
    /// Boolean.
    Boolean,
    /// Generated identity value.
    GeneratedIdentity,
}

/// Uniqueness or primary-key contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresUniquenessContract {
    name: &'static str,
    columns: Vec<&'static str>,
    predicate: Option<PostgresUniquePredicate>,
}

impl PostgresUniquenessContract {
    /// Returns the constraint or index name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns constrained columns.
    pub fn columns(&self) -> &[&'static str] {
        &self.columns
    }

    /// Returns the partial-unique predicate, if any.
    pub const fn predicate(&self) -> Option<PostgresUniquePredicate> {
        self.predicate
    }
}

/// Partial uniqueness predicate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresUniquePredicate {
    /// Applies only while `closed_at IS NULL`.
    OpenRow,
}

/// Table write policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresTableWritePolicy {
    /// Rows may be inserted and updated through core mutations.
    MutableRows,
    /// Rows are inserted and never updated by the core.
    InsertOnlyRows,
    /// Rows are append-only and must not be updated or deleted.
    AppendOnlyRows,
}

/// Mapping from credential rows to MAC-over-secret rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresCredentialSecretMacMappingContract {
    credential_table: PostgresAuthCoreTable,
    mac_table: PostgresAuthCoreTable,
    credential_id_column: &'static str,
    mac_owner_id_column: &'static str,
    current_secret_version_column: &'static str,
    previous_secret_version_column: &'static str,
    previous_secret_accept_until_column: &'static str,
    mac_secret_version_column: &'static str,
    mac_column: &'static str,
}

impl PostgresCredentialSecretMacMappingContract {
    fn session() -> Self {
        Self {
            credential_table: PostgresAuthCoreTable::Session,
            mac_table: PostgresAuthCoreTable::SessionCredentialSecretMac,
            credential_id_column: "session_id",
            mac_owner_id_column: "session_id",
            current_secret_version_column: "current_secret_version",
            previous_secret_version_column: "previous_secret_version",
            previous_secret_accept_until_column: "previous_secret_accept_until",
            mac_secret_version_column: "secret_version",
            mac_column: "secret_mac",
        }
    }

    fn trusted_device() -> Self {
        Self {
            credential_table: PostgresAuthCoreTable::TrustedDeviceCredential,
            mac_table: PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac,
            credential_id_column: "device_credential_id",
            mac_owner_id_column: "device_credential_id",
            current_secret_version_column: "current_secret_version",
            previous_secret_version_column: "previous_secret_version",
            previous_secret_accept_until_column: "previous_secret_accept_until",
            mac_secret_version_column: "secret_version",
            mac_column: "secret_mac",
        }
    }

    /// Returns the authoritative credential table.
    pub const fn credential_table(&self) -> PostgresAuthCoreTable {
        self.credential_table
    }

    /// Returns the MAC-over-secret table.
    pub const fn mac_table(&self) -> PostgresAuthCoreTable {
        self.mac_table
    }

    /// Returns the credential table's id column.
    pub const fn credential_id_column(&self) -> &'static str {
        self.credential_id_column
    }

    /// Returns the MAC table's owner id column.
    pub const fn mac_owner_id_column(&self) -> &'static str {
        self.mac_owner_id_column
    }

    /// Returns the credential table's current version column.
    pub const fn current_secret_version_column(&self) -> &'static str {
        self.current_secret_version_column
    }

    /// Returns the credential table's previous version column.
    pub const fn previous_secret_version_column(&self) -> &'static str {
        self.previous_secret_version_column
    }

    /// Returns the credential table's previous-secret grace deadline column.
    pub const fn previous_secret_accept_until_column(&self) -> &'static str {
        self.previous_secret_accept_until_column
    }

    /// Returns the MAC table's secret version column.
    pub const fn mac_secret_version_column(&self) -> &'static str {
        self.mac_secret_version_column
    }

    /// Returns the MAC table's MAC bytes column.
    pub const fn mac_column(&self) -> &'static str {
        self.mac_column
    }
}

fn table_contract(
    table: PostgresAuthCoreTable,
    columns: Vec<PostgresColumnContract>,
    uniqueness: Vec<PostgresUniquenessContract>,
    write_policy: PostgresTableWritePolicy,
) -> PostgresAuthCoreTableContract {
    PostgresAuthCoreTableContract {
        table,
        columns,
        uniqueness,
        write_policy,
    }
}

fn column(
    name: &'static str,
    storage: PostgresColumnStorage,
    value: PostgresColumnValueContract,
    nullable: bool,
) -> PostgresColumnContract {
    PostgresColumnContract {
        name,
        storage,
        value,
        nullable,
    }
}

fn id_column(name: &'static str, nullable: bool) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Bytea,
        PostgresColumnValueContract::OpaqueIdBytes {
            max_bytes: ID_MAX_BYTES,
        },
        nullable,
    )
}

fn mac_over_secret_column(name: &'static str) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Bytea,
        PostgresColumnValueContract::MacOverSecretBytes {
            exact_bytes: crate::crypto::MAC_OVER_SECRET_SIZE,
        },
        false,
    )
}

fn secret_version_column(name: &'static str, nullable: bool) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Bigint,
        PostgresColumnValueContract::SecretVersion,
        nullable,
    )
}

fn unix_seconds_column(name: &'static str, nullable: bool) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Bigint,
        PostgresColumnValueContract::UnixSeconds,
        nullable,
    )
}

fn counter_column(name: &'static str, nullable: bool) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Integer,
        PostgresColumnValueContract::Counter,
        nullable,
    )
}

fn core_enum_column(name: &'static str, nullable: bool) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Integer,
        PostgresColumnValueContract::CoreEnumDiscriminant,
        nullable,
    )
}

fn boolean_column(name: &'static str, nullable: bool) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Boolean,
        PostgresColumnValueContract::Boolean,
        nullable,
    )
}

fn validated_text_column(
    name: &'static str,
    nullable: bool,
    max_bytes: usize,
) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::TextCollateC,
        PostgresColumnValueContract::ValidatedText { max_bytes },
        nullable,
    )
}

fn identity_column(name: &'static str) -> PostgresColumnContract {
    column(
        name,
        PostgresColumnStorage::Bigint,
        PostgresColumnValueContract::GeneratedIdentity,
        false,
    )
}

fn primary_key<const N: usize>(columns: [&'static str; N]) -> PostgresUniquenessContract {
    unique("primary_key", columns, None)
}

fn unique<const N: usize>(
    name: &'static str,
    columns: [&'static str; N],
    predicate: Option<PostgresUniquePredicate>,
) -> PostgresUniquenessContract {
    PostgresUniquenessContract {
        name,
        columns: columns.to_vec(),
        predicate,
    }
}
