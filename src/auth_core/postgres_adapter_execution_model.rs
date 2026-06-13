use super::prelude::*;

/// Postgres migration and validation contract for auth-core storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresSchemaMigrationContract {
    stages: Vec<PostgresSchemaMigrationStage>,
    schema_validation: PostgresSchemaValidationContract,
}

impl PostgresSchemaMigrationContract {
    /// Builds the migration contract for the auth-core Postgres schema.
    pub fn for_auth_core_schema() -> Self {
        Self {
            stages: vec![
                PostgresSchemaMigrationStage::BeginMigrationTransaction,
                PostgresSchemaMigrationStage::CreateMissingTables,
                PostgresSchemaMigrationStage::CreateMissingColumns,
                PostgresSchemaMigrationStage::CreateMissingUniquenessConstraints,
                PostgresSchemaMigrationStage::ValidateExistingSchema,
                PostgresSchemaMigrationStage::RecordSchemaVersionAfterValidation,
                PostgresSchemaMigrationStage::CommitMigrationTransaction,
            ],
            schema_validation: PostgresSchemaValidationContract::for_auth_core_schema(),
        }
    }

    /// Returns ordered migration stages.
    pub fn stages(&self) -> &[PostgresSchemaMigrationStage] {
        &self.stages
    }

    /// Returns the validation contract that must pass before migration commit.
    pub const fn schema_validation(&self) -> &PostgresSchemaValidationContract {
        &self.schema_validation
    }
}

/// Ordered Postgres migration stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresSchemaMigrationStage {
    /// Begin one migration transaction.
    BeginMigrationTransaction,
    /// Create missing reducer-owned tables under the configured table prefix.
    CreateMissingTables,
    /// Create missing reducer-owned columns with required storage types.
    CreateMissingColumns,
    /// Create missing primary-key and uniqueness constraints.
    CreateMissingUniquenessConstraints,
    /// Validate the complete existing schema against the typed contract.
    ValidateExistingSchema,
    /// Record the schema version only after validation succeeds.
    RecordSchemaVersionAfterValidation,
    /// Commit the migration transaction.
    CommitMigrationTransaction,
}

/// Postgres schema validation contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresSchemaValidationContract {
    tables: Vec<PostgresTableValidationContract>,
}

impl PostgresSchemaValidationContract {
    /// Builds validation requirements for every auth-core Postgres table.
    pub fn for_auth_core_schema() -> Self {
        Self {
            tables: PostgresAuthCoreSchemaContract::table_contracts()
                .into_iter()
                .map(PostgresTableValidationContract::for_table_contract)
                .collect(),
        }
    }

    /// Returns table validation contracts.
    pub fn tables(&self) -> &[PostgresTableValidationContract] {
        &self.tables
    }
}

/// Validation contract for one Postgres table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresTableValidationContract {
    table: PostgresAuthCoreTable,
    columns: Vec<PostgresColumnValidationContract>,
    uniqueness: Vec<PostgresUniquenessValidationContract>,
    write_policy: PostgresTableWritePolicy,
}

impl PostgresTableValidationContract {
    /// Builds table validation from the schema table contract.
    pub fn for_table_contract(contract: PostgresAuthCoreTableContract) -> Self {
        Self {
            table: contract.table(),
            columns: contract
                .columns()
                .iter()
                .map(PostgresColumnValidationContract::for_column_contract)
                .collect(),
            uniqueness: contract
                .uniqueness()
                .iter()
                .map(PostgresUniquenessValidationContract::for_uniqueness_contract)
                .collect(),
            write_policy: contract.write_policy(),
        }
    }

    /// Returns the table kind.
    pub const fn table(&self) -> PostgresAuthCoreTable {
        self.table
    }

    /// Returns column validations.
    pub fn columns(&self) -> &[PostgresColumnValidationContract] {
        &self.columns
    }

    /// Returns uniqueness validations.
    pub fn uniqueness(&self) -> &[PostgresUniquenessValidationContract] {
        &self.uniqueness
    }

    /// Returns the table write policy.
    pub const fn write_policy(&self) -> PostgresTableWritePolicy {
        self.write_policy
    }
}

/// Validation contract for one Postgres column.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresColumnValidationContract {
    name: &'static str,
    storage: PostgresColumnStorage,
    nullable: bool,
    checks: Vec<PostgresColumnValidationCheck>,
}

impl PostgresColumnValidationContract {
    /// Builds column validation from a schema column contract.
    pub fn for_column_contract(contract: &PostgresColumnContract) -> Self {
        let mut checks = vec![
            PostgresColumnValidationCheck::ColumnExists,
            PostgresColumnValidationCheck::StorageTypeMatches,
            PostgresColumnValidationCheck::NullabilityMatches,
        ];
        match contract.storage() {
            PostgresColumnStorage::TextCollateC => {
                checks.push(PostgresColumnValidationCheck::TextUsesBytewiseCollation);
            }
            PostgresColumnStorage::Bytea => {
                if matches!(
                    contract.value(),
                    PostgresColumnValueContract::MacOverSecretBytes { .. }
                        | PostgresColumnValueContract::FixedOpaqueBytes { .. }
                ) {
                    checks.push(PostgresColumnValidationCheck::ByteaLengthConstraintMatches);
                }
            }
            PostgresColumnStorage::Bigint
            | PostgresColumnStorage::Integer
            | PostgresColumnStorage::Boolean => {}
        }
        Self {
            name: contract.name(),
            storage: contract.storage(),
            nullable: contract.nullable(),
            checks,
        }
    }

    /// Returns the column name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the required Postgres storage type/collation.
    pub const fn storage(&self) -> PostgresColumnStorage {
        self.storage
    }

    /// Returns whether the column may be null.
    pub const fn nullable(&self) -> bool {
        self.nullable
    }

    /// Returns validation checks.
    pub fn checks(&self) -> &[PostgresColumnValidationCheck] {
        &self.checks
    }
}

/// Column validation check.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresColumnValidationCheck {
    /// Column exists.
    ColumnExists,
    /// Existing column storage type matches the schema contract.
    StorageTypeMatches,
    /// Existing column nullability matches the schema contract.
    NullabilityMatches,
    /// Text column uses bytewise `C` or equivalent `POSIX` collation.
    TextUsesBytewiseCollation,
    /// Fixed-size `BYTEA` value has the required length check.
    ByteaLengthConstraintMatches,
}

/// Validation contract for one uniqueness requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresUniquenessValidationContract {
    name: &'static str,
    columns: Vec<&'static str>,
    predicate: Option<PostgresUniquePredicate>,
}

impl PostgresUniquenessValidationContract {
    /// Builds uniqueness validation from a schema uniqueness contract.
    pub fn for_uniqueness_contract(contract: &PostgresUniquenessContract) -> Self {
        Self {
            name: contract.name(),
            columns: contract.columns().to_vec(),
            predicate: contract.predicate(),
        }
    }

    /// Returns the uniqueness name.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns constrained columns.
    pub fn columns(&self) -> &[&'static str] {
        &self.columns
    }

    /// Returns the required partial predicate, if any.
    pub const fn predicate(&self) -> Option<PostgresUniquePredicate> {
        self.predicate
    }
}

/// Postgres query contract for loading reducer state before reduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresLoadedStateQueryContract {
    queries: Vec<PostgresLoadedStateQuery>,
}

impl PostgresLoadedStateQueryContract {
    /// Builds Postgres load query contracts from a reducer loaded-state contract.
    pub fn for_loaded_state_contract(contract: &CommandLoadedStateContract) -> Self {
        Self {
            queries: contract
                .required()
                .iter()
                .map(PostgresLoadedStateQuery::for_loaded_state_requirement)
                .collect(),
        }
    }

    /// Returns required load queries in command-contract order.
    pub fn queries(&self) -> &[PostgresLoadedStateQuery] {
        &self.queries
    }
}

/// One Postgres query shape for a loaded-state requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresLoadedStateQuery {
    requirement: LoadedStateRequirement,
    shape: PostgresLoadedStateQueryShape,
    locking: PostgresLoadQueryLocking,
}

impl PostgresLoadedStateQuery {
    /// Builds a query contract for one loaded-state requirement.
    pub fn for_loaded_state_requirement(requirement: &LoadedStateRequirement) -> Self {
        let shape = match requirement {
            LoadedStateRequirement::PresentedSessionCookie { .. }
            | LoadedStateRequirement::PresentedTrustedDeviceCookie { .. } => {
                PostgresLoadedStateQueryShape::NoPostgresQuery
            }
            LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie { .. } => {
                PostgresLoadedStateQueryShape::SelectSessionRowAndCurrentPreviousMacRowsBySessionId
            }
            LoadedStateRequirement::TrustedDeviceRecordAndSecretMatchForPresentedCookie {
                ..
            } => {
                PostgresLoadedStateQueryShape::SelectTrustedDeviceRowAndCurrentPreviousMacRowsByCredentialId
            }
            LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject { .. } => {
                PostgresLoadedStateQueryShape::SelectSubjectAuthStateForLoadedSessionSubject
            }
            LoadedStateRequirement::SubjectRevocationForLoadedTrustedDeviceSubject { .. } => {
                PostgresLoadedStateQueryShape::SelectSubjectAuthStateForLoadedTrustedDeviceSubject
            }
            LoadedStateRequirement::ActiveProofAttempt { .. } => {
                PostgresLoadedStateQueryShape::SelectActiveProofAttemptAndSatisfiedProofRowsByAttemptId
            }
            LoadedStateRequirement::ActiveProofContinuationSecretMatchForPresentedCookie {
                ..
            } => PostgresLoadedStateQueryShape::SelectActiveProofContinuationMacRowByAttemptId,
            LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
                ..
            } => {
                PostgresLoadedStateQueryShape::SelectSubjectAuthStateForLoadedAttemptSubjectIfBound
            }
            LoadedStateRequirement::SubjectRevocationForVerifiedActiveProofSubject { .. } => {
                PostgresLoadedStateQueryShape::SelectSubjectAuthStateByVerifiedSubjectId
            }
            LoadedStateRequirement::ActiveProofChallenge { .. } => {
                PostgresLoadedStateQueryShape::SelectActiveProofChallengeAndDeliveryKeyRowsByChallengeId
            }
        };
        let locking = if shape == PostgresLoadedStateQueryShape::NoPostgresQuery {
            PostgresLoadQueryLocking::NoStorageQuery
        } else {
            PostgresLoadQueryLocking::ReadOnlySnapshot
        };
        Self {
            requirement: requirement.clone(),
            shape,
            locking,
        }
    }

    /// Returns the loaded-state requirement.
    pub const fn requirement(&self) -> &LoadedStateRequirement {
        &self.requirement
    }

    /// Returns the Postgres query shape.
    pub const fn shape(&self) -> PostgresLoadedStateQueryShape {
        self.shape
    }

    /// Returns the load query locking behavior.
    pub const fn locking(&self) -> PostgresLoadQueryLocking {
        self.locking
    }
}

/// Postgres query shape used for loaded-state construction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresLoadedStateQueryShape {
    /// No storage query; the requirement is satisfied by already-decoded transport state.
    NoPostgresQuery,
    /// Select the session row plus current and previous session MAC rows by session id.
    SelectSessionRowAndCurrentPreviousMacRowsBySessionId,
    /// Select the trusted-device row plus current and previous MAC rows by credential id.
    SelectTrustedDeviceRowAndCurrentPreviousMacRowsByCredentialId,
    /// Select subject auth state after loading a session subject.
    SelectSubjectAuthStateForLoadedSessionSubject,
    /// Select subject auth state after loading a trusted-device subject.
    SelectSubjectAuthStateForLoadedTrustedDeviceSubject,
    /// Select active-proof attempt plus satisfied proof rows by attempt id.
    SelectActiveProofAttemptAndSatisfiedProofRowsByAttemptId,
    /// Select active-proof continuation MAC row by attempt id.
    SelectActiveProofContinuationMacRowByAttemptId,
    /// Select subject auth state after loading an attempt subject, if the attempt is bound.
    SelectSubjectAuthStateForLoadedAttemptSubjectIfBound,
    /// Select subject auth state for the subject resolved by a verified proof.
    SelectSubjectAuthStateByVerifiedSubjectId,
    /// Select active-proof challenge plus delivery idempotency key rows by challenge id.
    SelectActiveProofChallengeAndDeliveryKeyRowsByChallengeId,
}

/// Locking behavior for loaded-state queries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresLoadQueryLocking {
    /// Requirement does not issue a storage query.
    NoStorageQuery,
    /// Load a snapshot only; any later commit must revalidate under row locks.
    ReadOnlySnapshot,
}

/// Postgres execution contract for one reducer precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresPreconditionExecutionContract {
    kind: CorePreconditionKind,
    lock_steps: Vec<PostgresPreconditionLockStep>,
    validation_steps: Vec<PostgresPreconditionValidationStep>,
}

impl PostgresPreconditionExecutionContract {
    /// Builds the Postgres precondition execution contract.
    pub fn for_precondition(precondition: &Precondition) -> Self {
        let storage_contract = CorePreconditionStorageContract::for_precondition(precondition);
        let lock_steps = storage_contract
            .lock_requirements()
            .iter()
            .map(PostgresPreconditionLockStep::for_lock_requirement)
            .collect();
        let validation_steps = match precondition {
            Precondition::SessionStillMatches {
                subject_id,
                now,
                current_secret_version,
                ..
            } => vec![
                PostgresPreconditionValidationStep::SessionRowStillLiveWithSubjectAndCurrentVersion {
                    subject_id: subject_id.clone(),
                    now: *now,
                    current_secret_version: *current_secret_version,
                },
                PostgresPreconditionValidationStep::SubjectAuthStateDoesNotInvalidateRecord,
            ],
            Precondition::TrustedDeviceStillMatches {
                subject_id,
                now,
                current_secret_version,
                ..
            } => vec![
                PostgresPreconditionValidationStep::TrustedDeviceRowStillLiveWithSubjectAndCurrentVersion {
                    subject_id: subject_id.clone(),
                    now: *now,
                    current_secret_version: *current_secret_version,
                },
                PostgresPreconditionValidationStep::SubjectAuthStateDoesNotInvalidateRecord,
            ],
            Precondition::SessionBelongsToSubject { subject_id, .. } => {
                vec![PostgresPreconditionValidationStep::SessionRowBelongsToSubject {
                    subject_id: subject_id.clone(),
                }]
            }
            Precondition::TrustedDeviceBelongsToSubject { subject_id, .. } => {
                vec![
                    PostgresPreconditionValidationStep::TrustedDeviceRowBelongsToSubject {
                        subject_id: subject_id.clone(),
                    },
                ]
            }
            Precondition::ActiveProofAttemptStillOpen {
                now,
                observed_subject_id,
                observed_satisfied_proofs,
                observed_weak_proof_failures,
                subject_id_for_revocation,
                created_at,
                ..
            } => {
                let mut steps = vec![
                    PostgresPreconditionValidationStep::ActiveProofAttemptOpenSnapshotMatches {
                        now: *now,
                        observed_subject_id: observed_subject_id.clone(),
                        observed_satisfied_proofs: observed_satisfied_proofs.clone(),
                        observed_weak_proof_failures: *observed_weak_proof_failures,
                        created_at: *created_at,
                    },
                ];
                if subject_id_for_revocation.is_some() {
                    steps.push(
                        PostgresPreconditionValidationStep::SubjectAuthStateDoesNotInvalidateRecord,
                    );
                }
                steps
            }
            Precondition::ActiveProofChallengeStillOpen { now, .. } => {
                vec![PostgresPreconditionValidationStep::ActiveProofChallengeOpen {
                    now: *now,
                }]
            }
            Precondition::OutOfBandChallengeResendStillAllowed {
                now,
                observed_resend_count,
                observed_used_delivery_idempotency_keys,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::OutOfBandChallengeResendStateMatches {
                        now: *now,
                        observed_resend_count: *observed_resend_count,
                        observed_used_delivery_idempotency_keys:
                            observed_used_delivery_idempotency_keys.clone(),
                    },
                ]
            }
            Precondition::NoOpenOutOfBandChallengeForDedupeKey {
                now,
                replaceable_created_at_or_before,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::CloseReplaceableOpenOutOfBandChallengesBeforeDedupeCheck {
                        now: *now,
                        replaceable_created_at_or_before: *replaceable_created_at_or_before,
                    },
                    PostgresPreconditionValidationStep::TreatOpenChallengeDedupeUniqueViolationAsPreconditionFailure,
                ]
            }
            Precondition::CredentialInstanceStillActive { subject_id, .. } => {
                vec![
                    PostgresPreconditionValidationStep::CredentialInstanceStillActiveWithSubject {
                        subject_id: subject_id.clone(),
                    },
                ]
            }
            Precondition::SubjectRetainsRequiredCredentialPostureAfterRemoval {
                subject_id,
                removed_credential_instance_id,
                removed_credential_reset_policy_role,
            } => {
                vec![
                    PostgresPreconditionValidationStep::SubjectRetainsRequiredCredentialPostureAfterRemoval {
                        subject_id: subject_id.clone(),
                        removed_credential_instance_id: removed_credential_instance_id.clone(),
                        removed_credential_reset_policy_role: *removed_credential_reset_policy_role,
                    },
                ]
            }
            Precondition::SubjectRetainsRequiredCredentialPostureAfterReplacement {
                subject_id,
                replaced_credential_instance_id,
                replaced_credential_reset_policy_role,
                successor,
            } => {
                vec![
                    PostgresPreconditionValidationStep::SubjectRetainsRequiredCredentialPostureAfterReplacement {
                        subject_id: subject_id.clone(),
                        replaced_credential_instance_id: replaced_credential_instance_id.clone(),
                        replaced_credential_reset_policy_role: *replaced_credential_reset_policy_role,
                        successor: successor.clone(),
                    },
                ]
            }
            Precondition::SubjectRetainsRequiredCredentialPostureAfterAddition {
                subject_id,
                added_credential,
                added_recovery_authorities,
            } => {
                vec![
                    PostgresPreconditionValidationStep::SubjectRetainsRequiredCredentialPostureAfterAddition {
                        subject_id: subject_id.clone(),
                        added_credential: added_credential.clone(),
                        added_recovery_authorities: added_recovery_authorities.clone(),
                    },
                ]
            }
            Precondition::NoOpenPendingCredentialLifecycleActionForTarget { now, .. } => {
                vec![
                    PostgresPreconditionValidationStep::CloseExpiredOpenPendingCredentialLifecycleActionsBeforeUniquenessCheck {
                        now: *now,
                    },
                    PostgresPreconditionValidationStep::TreatOpenPendingCredentialLifecycleActionUniqueViolationAsPreconditionFailure,
                ]
            }
            Precondition::PendingCredentialLifecycleActionStillExecutable {
                subject_id,
                target_credential_instance_id,
                action,
                now,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::PendingCredentialLifecycleActionOpenMatureUnexpiredAndTargetMatched {
                        subject_id: subject_id.clone(),
                        target_credential_instance_id: target_credential_instance_id.clone(),
                        action: *action,
                        now: *now,
                    },
                ]
            }
            Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
                subject_id,
                target_credential_instance_id,
                action,
                now,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::PendingCredentialLifecycleActionOpenUnexpiredAndTargetMatched {
                        subject_id: subject_id.clone(),
                        target_credential_instance_id: target_credential_instance_id.clone(),
                        action: *action,
                        now: *now,
                    },
                ]
            }
            Precondition::NoOpenPendingSubjectLifecycleActionForSubject { now, .. } => {
                vec![
                    PostgresPreconditionValidationStep::CloseExpiredOpenPendingSubjectLifecycleActionsBeforeUniquenessCheck {
                        now: *now,
                    },
                    PostgresPreconditionValidationStep::TreatOpenPendingSubjectLifecycleActionUniqueViolationAsPreconditionFailure,
                ]
            }
            Precondition::PendingSubjectLifecycleActionStillExecutable {
                subject_id,
                action,
                now,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::PendingSubjectLifecycleActionOpenMatureUnexpiredAndSubjectMatched {
                        subject_id: subject_id.clone(),
                        action: *action,
                        now: *now,
                    },
                ]
            }
            Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
                subject_id,
                action,
                now,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::PendingSubjectLifecycleActionOpenUnexpiredAndSubjectMatched {
                        subject_id: subject_id.clone(),
                        action: *action,
                        now: *now,
                    },
                ]
            }
            Precondition::OutOfBandIdentifierBindingStillActive { subject_id, .. } => {
                vec![
                    PostgresPreconditionValidationStep::OutOfBandIdentifierBindingActiveWithSubject {
                        subject_id: subject_id.clone(),
                    },
                ]
            }
            Precondition::OutOfBandIdentifierBindingStillPendingActivation {
                subject_id,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::OutOfBandIdentifierBindingPendingActivationWithSubject {
                        subject_id: subject_id.clone(),
                    },
                ]
            }
            Precondition::NoOpenAdminSupportInterventionForTarget { now, .. } => {
                vec![
                    PostgresPreconditionValidationStep::CloseExpiredOpenAdminSupportInterventionsBeforeUniquenessCheck {
                        now: *now,
                    },
                    PostgresPreconditionValidationStep::TreatOpenAdminSupportInterventionUniqueViolationAsPreconditionFailure,
                ]
            }
            Precondition::AdminSupportInterventionStillOpen {
                subject_id,
                target_credential_instance_id,
                action,
                now,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::AdminSupportInterventionOpenUnexpiredAndTargetMatched {
                        subject_id: subject_id.clone(),
                        target_credential_instance_id: target_credential_instance_id.clone(),
                        action: *action,
                        now: *now,
                    },
                ]
            }
            Precondition::AdminSupportInterventionStillExpiredOpen {
                subject_id,
                target_credential_instance_id,
                action,
                now,
                ..
            } => {
                vec![
                    PostgresPreconditionValidationStep::AdminSupportInterventionExpiredOpenAndTargetMatched {
                        subject_id: subject_id.clone(),
                        target_credential_instance_id: target_credential_instance_id.clone(),
                        action: *action,
                        now: *now,
                    },
                ]
            }
        };
        Self {
            kind: storage_contract.kind(),
            lock_steps,
            validation_steps,
        }
    }

    /// Returns the precondition kind.
    pub const fn kind(&self) -> CorePreconditionKind {
        self.kind
    }

    /// Returns required lock or uniqueness steps.
    pub fn lock_steps(&self) -> &[PostgresPreconditionLockStep] {
        &self.lock_steps
    }

    /// Returns required validation steps.
    pub fn validation_steps(&self) -> &[PostgresPreconditionValidationStep] {
        &self.validation_steps
    }
}

/// Postgres lock, materialization, or uniqueness step for a precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostgresPreconditionLockStep {
    /// `SELECT ... FOR UPDATE` over an existing row.
    SelectExistingRowForUpdate {
        /// Locked target.
        target: CoreStorageTarget,
        /// Table that stores the target.
        table: PostgresAuthCoreTable,
    },
    /// `INSERT ... ON CONFLICT DO NOTHING`, then `SELECT ... FOR UPDATE`.
    MaterializeSubjectAuthStateThenSelectForUpdate {
        /// Subject id.
        subject_id: SubjectId,
    },
    /// `SELECT ... FOR UPDATE` over active credential-instance rows ordered by id.
    SelectActiveCredentialInstancesForSubjectForUpdate {
        /// Subject id.
        subject_id: SubjectId,
    },
    /// `SELECT ... FOR UPDATE` over recovery-authority rows for active credentials.
    SelectActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
        /// Subject id.
        subject_id: SubjectId,
    },
    /// Enforce the partial unique index for open challenge dedupe.
    UseOpenOutOfBandChallengeDedupeUniqueIndex {
        /// Dedupe key.
        challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    },
    /// Enforce the partial unique index for open pending lifecycle actions.
    UseOpenPendingCredentialLifecycleActionUniqueIndex {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
    },
    /// Enforce the partial unique index for open pending subject lifecycle actions.
    UseOpenPendingSubjectLifecycleActionUniqueIndex {
        /// Subject targeted by the pending action.
        subject_id: SubjectId,
        /// Subject lifecycle action.
        action: SubjectLifecycleAction,
    },
    /// Enforce the partial unique index for open support/admin interventions.
    UseOpenAdminSupportInterventionUniqueIndex {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
    },
}

impl PostgresPreconditionLockStep {
    fn for_lock_requirement(requirement: &StorageLockRequirement) -> Self {
        match requirement {
            StorageLockRequirement::LockExistingRowForUpdate(target) => {
                Self::SelectExistingRowForUpdate {
                    table: PostgresAuthCoreSchemaContract::table_for_storage_target(target),
                    target: target.clone(),
                }
            }
            StorageLockRequirement::MaterializeSubjectAuthStateThenLockForUpdate { subject_id } => {
                Self::MaterializeSubjectAuthStateThenSelectForUpdate {
                    subject_id: subject_id.clone(),
                }
            }
            StorageLockRequirement::LockActiveCredentialInstancesForSubjectForUpdate {
                subject_id,
            } => Self::SelectActiveCredentialInstancesForSubjectForUpdate {
                subject_id: subject_id.clone(),
            },
            StorageLockRequirement::LockActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id,
            } => Self::SelectActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: subject_id.clone(),
            },
            StorageLockRequirement::EnforceOpenOutOfBandChallengeDedupeUniqueness {
                challenge_dedupe_key,
            } => Self::UseOpenOutOfBandChallengeDedupeUniqueIndex {
                challenge_dedupe_key: challenge_dedupe_key.clone(),
            },
            StorageLockRequirement::EnforceOpenPendingCredentialLifecycleActionUniqueness {
                target_credential_instance_id,
                action,
            } => Self::UseOpenPendingCredentialLifecycleActionUniqueIndex {
                target_credential_instance_id: target_credential_instance_id.clone(),
                action: *action,
            },
            StorageLockRequirement::EnforceOpenPendingSubjectLifecycleActionUniqueness {
                subject_id,
                action,
            } => Self::UseOpenPendingSubjectLifecycleActionUniqueIndex {
                subject_id: subject_id.clone(),
                action: *action,
            },
            StorageLockRequirement::EnforceOpenAdminSupportInterventionUniqueness {
                target_credential_instance_id,
                action,
            } => Self::UseOpenAdminSupportInterventionUniqueIndex {
                target_credential_instance_id: target_credential_instance_id.clone(),
                action: *action,
            },
        }
    }
}

/// Postgres validation semantics for one precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostgresPreconditionValidationStep {
    /// Session row must be live, subject-bound, and still on the observed current version.
    SessionRowStillLiveWithSubjectAndCurrentVersion {
        /// Required subject.
        subject_id: SubjectId,
        /// Transition time.
        now: UnixSeconds,
        /// Required current credential version.
        current_secret_version: SecretVersion,
    },
    /// Trusted-device row must be live, subject-bound, and still on the observed version.
    TrustedDeviceRowStillLiveWithSubjectAndCurrentVersion {
        /// Required subject.
        subject_id: SubjectId,
        /// Transition time.
        now: UnixSeconds,
        /// Required current credential version.
        current_secret_version: SecretVersion,
    },
    /// Session row must be live and owned by the required subject.
    SessionRowBelongsToSubject {
        /// Required subject.
        subject_id: SubjectId,
    },
    /// Trusted-device row must be live and owned by the required subject.
    TrustedDeviceRowBelongsToSubject {
        /// Required subject.
        subject_id: SubjectId,
    },
    /// Active-proof attempt must still match the reducer-loaded snapshot.
    ActiveProofAttemptOpenSnapshotMatches {
        /// Transition time.
        now: UnixSeconds,
        /// Observed subject binding.
        observed_subject_id: Option<SubjectId>,
        /// Observed satisfied proof stack.
        observed_satisfied_proofs: Vec<SatisfiedProof>,
        /// Observed weak proof failure count.
        observed_weak_proof_failures: u32,
        /// Observed creation time.
        created_at: UnixSeconds,
    },
    /// Active-proof challenge must still be open.
    ActiveProofChallengeOpen {
        /// Transition time.
        now: UnixSeconds,
    },
    /// Resend state must still match the loaded challenge snapshot.
    OutOfBandChallengeResendStateMatches {
        /// Transition time.
        now: UnixSeconds,
        /// Observed resend count.
        observed_resend_count: u32,
        /// Observed used delivery idempotency keys.
        observed_used_delivery_idempotency_keys: Vec<String>,
    },
    /// Expired or replacement-eligible open rows must be closed before unique enforcement.
    CloseReplaceableOpenOutOfBandChallengesBeforeDedupeCheck {
        /// Transition time.
        now: UnixSeconds,
        /// Live challenges created at or before this timestamp may be replaced.
        replaceable_created_at_or_before: Option<UnixSeconds>,
    },
    /// The partial unique index is the race-proof dedupe check.
    TreatOpenChallengeDedupeUniqueViolationAsPreconditionFailure,
    /// Credential instance must still be active and owned by the required subject.
    CredentialInstanceStillActiveWithSubject {
        /// Required subject.
        subject_id: SubjectId,
    },
    /// Subject must still have an acceptable credential posture after removing the target.
    SubjectRetainsRequiredCredentialPostureAfterRemoval {
        /// Required subject.
        subject_id: SubjectId,
        /// Credential being removed or disabled.
        removed_credential_instance_id: VerifiedProofSourceId,
        /// Reset policy role of the credential being removed.
        removed_credential_reset_policy_role: CredentialResetPolicyRole,
    },
    /// Subject must still have an acceptable credential posture after replacing the target.
    SubjectRetainsRequiredCredentialPostureAfterReplacement {
        /// Required subject.
        subject_id: SubjectId,
        /// Credential being replaced.
        replaced_credential_instance_id: VerifiedProofSourceId,
        /// Reset policy role of the credential being replaced.
        replaced_credential_reset_policy_role: CredentialResetPolicyRole,
        /// Successor credential being created by the replacement.
        successor: CredentialReplacementSuccessor,
    },
    /// Adding a credential must not create a collapsed ordinary/second-factor posture.
    SubjectRetainsRequiredCredentialPostureAfterAddition {
        /// Required subject.
        subject_id: SubjectId,
        /// Credential being added.
        added_credential: CredentialInstanceMetadata,
        /// Recovery authorities being added with the credential.
        added_recovery_authorities: Vec<CredentialRecoveryAuthority>,
    },
    /// Expired open pending lifecycle actions must be closed before uniqueness check.
    CloseExpiredOpenPendingCredentialLifecycleActionsBeforeUniquenessCheck {
        /// Transition time.
        now: UnixSeconds,
    },
    /// The partial unique index is the race-proof open pending-action check.
    TreatOpenPendingCredentialLifecycleActionUniqueViolationAsPreconditionFailure,
    /// Pending credential lifecycle action must be open, mature, unexpired, and target-matched.
    PendingCredentialLifecycleActionOpenMatureUnexpiredAndTargetMatched {
        /// Required subject.
        subject_id: SubjectId,
        /// Required target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Required lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time.
        now: UnixSeconds,
    },
    /// Pending credential lifecycle action must be open, unexpired, and target-matched.
    PendingCredentialLifecycleActionOpenUnexpiredAndTargetMatched {
        /// Required subject.
        subject_id: SubjectId,
        /// Required target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Required lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time.
        now: UnixSeconds,
    },
    /// Expired open subject pending actions must be closed before uniqueness check.
    CloseExpiredOpenPendingSubjectLifecycleActionsBeforeUniquenessCheck {
        /// Transition time.
        now: UnixSeconds,
    },
    /// The partial unique index is the race-proof open subject pending-action check.
    TreatOpenPendingSubjectLifecycleActionUniqueViolationAsPreconditionFailure,
    /// Pending subject lifecycle action must be open, mature, unexpired, and subject-matched.
    PendingSubjectLifecycleActionOpenMatureUnexpiredAndSubjectMatched {
        /// Required subject.
        subject_id: SubjectId,
        /// Required subject lifecycle action.
        action: SubjectLifecycleAction,
        /// Transition time.
        now: UnixSeconds,
    },
    /// Pending subject lifecycle action must be open, unexpired, and subject-matched.
    PendingSubjectLifecycleActionOpenUnexpiredAndSubjectMatched {
        /// Required subject.
        subject_id: SubjectId,
        /// Required subject lifecycle action.
        action: SubjectLifecycleAction,
        /// Transition time.
        now: UnixSeconds,
    },
    /// Out-of-band identifier binding must be active and owned by the required subject.
    OutOfBandIdentifierBindingActiveWithSubject {
        /// Required subject.
        subject_id: SubjectId,
    },
    /// Out-of-band identifier binding must be pending activation and owned by the required subject.
    OutOfBandIdentifierBindingPendingActivationWithSubject {
        /// Required subject.
        subject_id: SubjectId,
    },
    /// Expired open support/admin interventions must be closed before uniqueness check.
    CloseExpiredOpenAdminSupportInterventionsBeforeUniquenessCheck {
        /// Transition time.
        now: UnixSeconds,
    },
    /// The partial unique index is the race-proof open intervention check.
    TreatOpenAdminSupportInterventionUniqueViolationAsPreconditionFailure,
    /// Support/admin intervention must be open, unexpired, and target-matched.
    AdminSupportInterventionOpenUnexpiredAndTargetMatched {
        /// Required subject.
        subject_id: SubjectId,
        /// Required target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Required lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time.
        now: UnixSeconds,
    },
    /// Support/admin intervention must be open, expired, and target-matched.
    AdminSupportInterventionExpiredOpenAndTargetMatched {
        /// Required subject.
        subject_id: SubjectId,
        /// Required target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Required lifecycle action.
        action: CredentialLifecycleAction,
        /// Transition time.
        now: UnixSeconds,
    },
    /// Subject revocation cutoff must not invalidate the guarded record.
    SubjectAuthStateDoesNotInvalidateRecord,
}

/// Postgres execution contract for one core mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresMutationExecutionContract {
    kind: CoreMutationKind,
    write_step: PostgresMutationWriteStep,
}

impl PostgresMutationExecutionContract {
    /// Builds the Postgres mutation execution contract.
    pub fn for_mutation(mutation: &Mutation) -> Self {
        let storage_contract = CoreMutationStorageContract::for_mutation(mutation);
        let write_step =
            PostgresMutationWriteStep::for_storage_write(storage_contract.write_requirement());
        Self {
            kind: storage_contract.kind(),
            write_step,
        }
    }

    /// Returns the mutation kind.
    pub const fn kind(&self) -> CoreMutationKind {
        self.kind
    }

    /// Returns required write behavior.
    pub const fn write_step(&self) -> &PostgresMutationWriteStep {
        &self.write_step
    }
}

/// Postgres write step for a reducer mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostgresMutationWriteStep {
    /// `INSERT` one unique row.
    InsertUniqueRow {
        /// Insert target.
        target: CoreStorageTarget,
        /// Table that stores the target.
        table: PostgresAuthCoreTable,
    },
    /// `UPDATE` one row that was locked by preconditions.
    UpdatePreviouslyLockedRow {
        /// Updated target.
        target: CoreStorageTarget,
        /// Table that stores the target.
        table: PostgresAuthCoreTable,
    },
    /// `UPDATE` matching rows in one statement.
    UpdateMatchingRowsWithSingleStatement {
        /// Updated target set.
        target: CoreStorageTarget,
        /// Table that stores the target set.
        table: PostgresAuthCoreTable,
    },
    /// `DELETE` one locked row and delete/cascade required children in the same transaction.
    HardDeletePreviouslyLockedRow {
        /// Deleted target.
        target: CoreStorageTarget,
        /// Tables whose child rows must be removed.
        cascades_to_tables: Vec<PostgresAuthCoreTable>,
    },
    /// `DELETE` matching rows in one statement.
    HardDeleteMatchingRowsWithSingleStatement {
        /// Deleted target set.
        target: CoreStorageTarget,
        /// Table that stores the target set.
        table: PostgresAuthCoreTable,
    },
    /// `INSERT ... ON CONFLICT DO UPDATE SET cutoff = GREATEST(existing, excluded)`.
    MonotonicUpsertSubjectAuthRevocationCutoff {
        /// Subject id.
        subject_id: SubjectId,
    },
}

impl PostgresMutationWriteStep {
    fn for_storage_write(write: &StorageWriteRequirement) -> Self {
        match write {
            StorageWriteRequirement::InsertUnique(target) => Self::InsertUniqueRow {
                table: PostgresAuthCoreSchemaContract::table_for_storage_target(target),
                target: target.clone(),
            },
            StorageWriteRequirement::UpdateLockedRow(target) => Self::UpdatePreviouslyLockedRow {
                table: PostgresAuthCoreSchemaContract::table_for_storage_target(target),
                target: target.clone(),
            },
            StorageWriteRequirement::UpdateLockedRowsMatching(target) => {
                Self::UpdateMatchingRowsWithSingleStatement {
                    table: PostgresAuthCoreSchemaContract::table_for_storage_target(target),
                    target: target.clone(),
                }
            }
            StorageWriteRequirement::HardDeleteLockedRow {
                target,
                cascades_to_record_kinds,
            } => Self::HardDeletePreviouslyLockedRow {
                target: target.clone(),
                cascades_to_tables: cascades_to_record_kinds
                    .iter()
                    .map(postgres_table_for_record_kind)
                    .collect(),
            },
            StorageWriteRequirement::HardDeleteRowsMatching(target) => {
                Self::HardDeleteMatchingRowsWithSingleStatement {
                    table: PostgresAuthCoreSchemaContract::table_for_storage_target(target),
                    target: target.clone(),
                }
            }
            StorageWriteRequirement::MonotonicUpsertSubjectAuthRevocationCutoff { subject_id } => {
                Self::MonotonicUpsertSubjectAuthRevocationCutoff {
                    subject_id: subject_id.clone(),
                }
            }
        }
    }
}

/// Postgres execution contract for fresh credential-secret materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresFreshCredentialSecretExecutionContract {
    target: CoreStorageTarget,
    table: PostgresAuthCoreTable,
    stages: Vec<PostgresFreshCredentialSecretExecutionStage>,
}

impl PostgresFreshCredentialSecretExecutionContract {
    /// Builds the Postgres execution contract for one fresh credential secret.
    pub fn for_fresh_credential_secret(fresh_secret: &FreshCredentialSecret) -> Self {
        let storage_contract =
            FreshCredentialSecretStorageContract::for_fresh_credential_secret(fresh_secret);
        let target = storage_contract.target().clone();
        Self {
            table: PostgresAuthCoreSchemaContract::table_for_storage_target(&target),
            target,
            stages: vec![
                PostgresFreshCredentialSecretExecutionStage::GenerateFreshSecretBytes,
                PostgresFreshCredentialSecretExecutionStage::ComputeMacOverSecret,
                PostgresFreshCredentialSecretExecutionStage::InsertUniqueMacRow,
                PostgresFreshCredentialSecretExecutionStage::ReturnPlaintextOnlyAsCommitEvidence,
            ],
        }
    }

    /// Returns the fresh-secret target.
    pub const fn target(&self) -> &CoreStorageTarget {
        &self.target
    }

    /// Returns the MAC table.
    pub const fn table(&self) -> PostgresAuthCoreTable {
        self.table
    }

    /// Returns ordered fresh-secret execution stages.
    pub fn stages(&self) -> &[PostgresFreshCredentialSecretExecutionStage] {
        &self.stages
    }
}

/// Fresh credential-secret execution stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresFreshCredentialSecretExecutionStage {
    /// Generate fresh random credential secret bytes.
    GenerateFreshSecretBytes,
    /// Compute `MacOverSecret`.
    ComputeMacOverSecret,
    /// Insert one unique MAC row for the credential version.
    InsertUniqueMacRow,
    /// Return plaintext only as commit evidence for response materialization.
    ReturnPlaintextOnlyAsCommitEvidence,
}

/// Postgres execution contract for one atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresAtomicCommitExecutionContract {
    stages: Vec<PostgresAtomicCommitExecutionStage>,
}

impl PostgresAtomicCommitExecutionContract {
    /// Builds ordered Postgres execution stages for reducer-planned atomic work.
    pub fn for_atomic_work(work: &AtomicCommitWork) -> Result<Self, Error> {
        let storage_contract = AtomicCommitStorageContract::for_atomic_work(work)?;
        let mut stages = vec![PostgresAtomicCommitExecutionStage::ValidateAtomicWork];
        if !work.is_empty() {
            stages.push(PostgresAtomicCommitExecutionStage::BeginTransaction);
            stages.extend(
                work.preconditions
                    .iter()
                    .map(PostgresPreconditionExecutionContract::for_precondition)
                    .map(PostgresAtomicCommitExecutionStage::EnforceCorePrecondition),
            );
            if storage_contract.method_commit_work().iter().any(|method| {
                method
                    .stages()
                    .contains(&MethodCommitTransactionStage::EnforcePreconditions)
            }) {
                stages.push(PostgresAtomicCommitExecutionStage::EnforceMethodPreconditions);
            }
            stages.extend(
                work.fresh_credential_secrets
                    .iter()
                    .map(
                        PostgresFreshCredentialSecretExecutionContract::for_fresh_credential_secret,
                    )
                    .map(PostgresAtomicCommitExecutionStage::MaterializeFreshCredentialSecret),
            );
            stages.extend(
                work.mutations
                    .iter()
                    .map(PostgresMutationExecutionContract::for_mutation)
                    .map(PostgresAtomicCommitExecutionStage::ApplyCoreMutation),
            );
            if storage_contract.method_commit_work().iter().any(|method| {
                method
                    .stages()
                    .contains(&MethodCommitTransactionStage::ApplyMutations)
            }) {
                stages.push(PostgresAtomicCommitExecutionStage::ApplyMethodMutations);
            }
            if storage_contract.audit_event_count() > 0 {
                stages.push(PostgresAtomicCommitExecutionStage::AppendAuditEvents {
                    count: storage_contract.audit_event_count(),
                });
            }
            if storage_contract.core_durable_effect_command_count() > 0 {
                stages.push(
                    PostgresAtomicCommitExecutionStage::AppendCoreDurableEffectCommands {
                        count: storage_contract.core_durable_effect_command_count(),
                    },
                );
            }
            if storage_contract.method_commit_work().iter().any(|method| {
                method
                    .stages()
                    .contains(&MethodCommitTransactionStage::CommitDurableEffectCommands)
            }) {
                stages.push(PostgresAtomicCommitExecutionStage::AppendMethodDurableEffectCommands);
            }
            stages.push(PostgresAtomicCommitExecutionStage::CommitTransaction);
        }
        Ok(Self { stages })
    }

    /// Returns ordered Postgres atomic commit stages.
    pub fn stages(&self) -> &[PostgresAtomicCommitExecutionStage] {
        &self.stages
    }
}

/// Ordered Postgres stage for one atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostgresAtomicCommitExecutionStage {
    /// Validate reducer-planned atomic work before opening a transaction.
    ValidateAtomicWork,
    /// Begin one Postgres transaction.
    BeginTransaction,
    /// Enforce one core precondition inside the transaction.
    EnforceCorePrecondition(PostgresPreconditionExecutionContract),
    /// Enforce method/plugin preconditions inside the transaction before mutations.
    EnforceMethodPreconditions,
    /// Materialize one fresh credential secret and insert its MAC row.
    MaterializeFreshCredentialSecret(PostgresFreshCredentialSecretExecutionContract),
    /// Apply one core mutation.
    ApplyCoreMutation(PostgresMutationExecutionContract),
    /// Apply method/plugin mutations inside the same transaction.
    ApplyMethodMutations,
    /// Append audit events.
    AppendAuditEvents {
        /// Number of events.
        count: usize,
    },
    /// Append core durable effect commands.
    AppendCoreDurableEffectCommands {
        /// Number of commands.
        count: usize,
    },
    /// Append method/plugin durable effect commands.
    AppendMethodDurableEffectCommands,
    /// Commit the transaction.
    CommitTransaction,
}

fn postgres_table_for_record_kind(kind: &CoreStorageRecordKind) -> PostgresAuthCoreTable {
    match kind {
        CoreStorageRecordKind::Session => PostgresAuthCoreTable::Session,
        CoreStorageRecordKind::SessionCredentialSecret => {
            PostgresAuthCoreTable::SessionCredentialSecretMac
        }
        CoreStorageRecordKind::TrustedDeviceCredential => {
            PostgresAuthCoreTable::TrustedDeviceCredential
        }
        CoreStorageRecordKind::TrustedDeviceCredentialSecret => {
            PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac
        }
        CoreStorageRecordKind::ActiveProofAttempt => PostgresAuthCoreTable::ActiveProofAttempt,
        CoreStorageRecordKind::ActiveProofContinuationSecret => {
            PostgresAuthCoreTable::ActiveProofContinuationSecretMac
        }
        CoreStorageRecordKind::ActiveProofChallenge => PostgresAuthCoreTable::ActiveProofChallenge,
        CoreStorageRecordKind::SubjectAuthState => PostgresAuthCoreTable::SubjectAuthState,
        CoreStorageRecordKind::CredentialInstance => PostgresAuthCoreTable::CredentialInstance,
        CoreStorageRecordKind::CredentialRecoveryAuthority => {
            PostgresAuthCoreTable::CredentialRecoveryAuthority
        }
        CoreStorageRecordKind::SubjectLifecycleAuthority => {
            PostgresAuthCoreTable::SubjectLifecycleAuthority
        }
        CoreStorageRecordKind::LifecycleAuthoritySource => {
            PostgresAuthCoreTable::LifecycleAuthoritySource
        }
        CoreStorageRecordKind::OutOfBandIdentifierBinding => {
            PostgresAuthCoreTable::OutOfBandIdentifierBinding
        }
        CoreStorageRecordKind::PendingCredentialLifecycleAction => {
            PostgresAuthCoreTable::PendingCredentialLifecycleAction
        }
        CoreStorageRecordKind::PendingSubjectLifecycleAction => {
            PostgresAuthCoreTable::PendingSubjectLifecycleAction
        }
        CoreStorageRecordKind::AdminSupportIntervention => {
            PostgresAuthCoreTable::AdminSupportIntervention
        }
        CoreStorageRecordKind::AuditEvent => PostgresAuthCoreTable::AuditEvent,
        CoreStorageRecordKind::CoreDurableEffectCommand => {
            PostgresAuthCoreTable::CoreDurableEffectCommand
        }
    }
}
