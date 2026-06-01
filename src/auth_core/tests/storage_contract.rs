use super::*;

fn prepare(command: Command, presented_cookies: PresentedAuthCookies) -> PreparedCommandExecution {
    PreparedCommandExecution::prepare(&config(), command, presented_cookies)
        .expect("prepared command")
}

fn postgres_table(table: PostgresAuthCoreTable) -> PostgresAuthCoreTableContract {
    PostgresAuthCoreTableContract::for_table(table)
}

fn postgres_table_validation(table: PostgresAuthCoreTable) -> PostgresTableValidationContract {
    PostgresSchemaValidationContract::for_auth_core_schema()
        .tables()
        .iter()
        .find(|contract| contract.table() == table)
        .expect("table validation")
        .clone()
}

#[test]
fn core_storage_schema_contract_names_reducer_owned_record_families() {
    assert_eq!(
        CoreStorageSchemaContract::record_kinds(),
        &[
            CoreStorageRecordKind::Session,
            CoreStorageRecordKind::SessionCredentialSecret,
            CoreStorageRecordKind::TrustedDeviceCredential,
            CoreStorageRecordKind::TrustedDeviceCredentialSecret,
            CoreStorageRecordKind::ActiveProofAttempt,
            CoreStorageRecordKind::ActiveProofContinuationSecret,
            CoreStorageRecordKind::ActiveProofChallenge,
            CoreStorageRecordKind::SubjectAuthState,
            CoreStorageRecordKind::AuditEvent,
            CoreStorageRecordKind::CoreDurableEffectCommand,
        ]
    );
}

#[test]
fn postgres_schema_contract_names_table_families() {
    assert_eq!(
        PostgresAuthCoreSchemaContract::table_kinds(),
        &[
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
            PostgresAuthCoreTable::AuditEvent,
            PostgresAuthCoreTable::CoreDurableEffectCommand,
        ]
    );
    assert_eq!(
        PostgresAuthCoreTable::Session.default_suffix(),
        "auth_sessions"
    );
    assert_eq!(
        PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey.default_suffix(),
        "auth_active_proof_challenge_delivery_keys"
    );
}

#[test]
fn postgres_migration_contract_validates_schema_before_recording_schema_version() {
    let contract = PostgresSchemaMigrationContract::for_auth_core_schema();

    assert_eq!(
        contract.stages(),
        &[
            PostgresSchemaMigrationStage::BeginMigrationTransaction,
            PostgresSchemaMigrationStage::CreateMissingTables,
            PostgresSchemaMigrationStage::CreateMissingColumns,
            PostgresSchemaMigrationStage::CreateMissingUniquenessConstraints,
            PostgresSchemaMigrationStage::ValidateExistingSchema,
            PostgresSchemaMigrationStage::RecordSchemaVersionAfterValidation,
            PostgresSchemaMigrationStage::CommitMigrationTransaction,
        ]
    );
    assert_eq!(
        contract.schema_validation().tables().len(),
        PostgresAuthCoreSchemaContract::table_kinds().len()
    );
}

#[test]
fn postgres_schema_validation_pins_collation_and_fixed_byte_checks() {
    let session_mac_table =
        postgres_table_validation(PostgresAuthCoreTable::SessionCredentialSecretMac);
    let secret_mac_column = session_mac_table
        .columns()
        .iter()
        .find(|column| column.name() == "secret_mac")
        .expect("secret mac column");
    assert_eq!(secret_mac_column.storage(), PostgresColumnStorage::Bytea);
    assert!(
        secret_mac_column
            .checks()
            .contains(&PostgresColumnValidationCheck::ByteaLengthConstraintMatches)
    );

    let challenge_table = postgres_table_validation(PostgresAuthCoreTable::ActiveProofChallenge);
    let method_label_column = challenge_table
        .columns()
        .iter()
        .find(|column| column.name() == "method_label")
        .expect("method label column");
    assert_eq!(
        method_label_column.storage(),
        PostgresColumnStorage::TextCollateC
    );
    assert!(
        method_label_column
            .checks()
            .contains(&PostgresColumnValidationCheck::TextUsesBytewiseCollation)
    );
    assert!(
        challenge_table
            .uniqueness()
            .iter()
            .any(
                |constraint| constraint.name() == "active_proof_open_challenge_dedupe_key"
                    && constraint.predicate() == Some(PostgresUniquePredicate::OpenRow)
            )
    );

    let satisfied_proof_table =
        postgres_table_validation(PostgresAuthCoreTable::ActiveProofSatisfiedProof);
    let source_kind_column = satisfied_proof_table
        .columns()
        .iter()
        .find(|column| column.name() == "proof_source_kind")
        .expect("proof source kind column");
    assert_eq!(source_kind_column.storage(), PostgresColumnStorage::Integer);
    assert!(source_kind_column.nullable());
    let source_id_column = satisfied_proof_table
        .columns()
        .iter()
        .find(|column| column.name() == "proof_source_id")
        .expect("proof source id column");
    assert_eq!(source_id_column.storage(), PostgresColumnStorage::Bytea);
    assert!(source_id_column.nullable());
}

#[test]
fn postgres_loaded_state_query_contract_reads_snapshots_without_locking_them() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(10),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );

    let query_contract = PostgresLoadedStateQueryContract::for_loaded_state_contract(
        prepared.loaded_state_contract(),
    );

    assert_eq!(
        query_contract
            .queries()
            .iter()
            .map(PostgresLoadedStateQuery::shape)
            .collect::<Vec<_>>(),
        vec![
            PostgresLoadedStateQueryShape::NoPostgresQuery,
            PostgresLoadedStateQueryShape::SelectSessionRowAndCurrentPreviousMacRowsBySessionId,
            PostgresLoadedStateQueryShape::SelectSubjectAuthStateForLoadedSessionSubject,
        ]
    );
    assert_eq!(
        query_contract
            .queries()
            .iter()
            .map(PostgresLoadedStateQuery::locking)
            .collect::<Vec<_>>(),
        vec![
            PostgresLoadQueryLocking::NoStorageQuery,
            PostgresLoadQueryLocking::ReadOnlySnapshot,
            PostgresLoadQueryLocking::ReadOnlySnapshot,
        ]
    );
}

#[test]
fn postgres_schema_contract_uses_byte_stable_storage_for_correctness_columns() {
    for table in PostgresAuthCoreSchemaContract::table_contracts() {
        for column in table.columns() {
            match column.value() {
                PostgresColumnValueContract::OpaqueIdBytes { .. }
                | PostgresColumnValueContract::MacOverSecretBytes { .. } => {
                    assert_eq!(column.storage(), PostgresColumnStorage::Bytea);
                }
                PostgresColumnValueContract::ValidatedText { .. } => {
                    assert_eq!(column.storage(), PostgresColumnStorage::TextCollateC);
                }
                PostgresColumnValueContract::SecretVersion
                | PostgresColumnValueContract::UnixSeconds
                | PostgresColumnValueContract::GeneratedIdentity => {
                    assert_eq!(column.storage(), PostgresColumnStorage::Bigint);
                }
                PostgresColumnValueContract::Counter
                | PostgresColumnValueContract::CoreEnumDiscriminant => {
                    assert_eq!(column.storage(), PostgresColumnStorage::Integer);
                }
                PostgresColumnValueContract::Boolean => {
                    assert_eq!(column.storage(), PostgresColumnStorage::Boolean);
                }
            }
        }
    }
}

#[test]
fn postgres_schema_contract_maps_storage_targets_to_table_families() {
    assert_eq!(
        PostgresAuthCoreSchemaContract::table_for_storage_target(&CoreStorageTarget::Session(id(
            "session"
        ))),
        PostgresAuthCoreTable::Session,
    );
    assert_eq!(
        PostgresAuthCoreSchemaContract::table_for_storage_target(
            &CoreStorageTarget::SessionCredentialSecret {
                session_id: id("session"),
                secret_version: version(4),
            }
        ),
        PostgresAuthCoreTable::SessionCredentialSecretMac,
    );
    assert_eq!(
        PostgresAuthCoreSchemaContract::table_for_storage_target(
            &CoreStorageTarget::OpenOutOfBandChallengeDedupeKey(dedupe_key(
                "login:email-hash:window"
            ))
        ),
        PostgresAuthCoreTable::ActiveProofChallenge,
    );
}

#[test]
fn postgres_schema_contract_pins_uniqueness_for_open_challenges_and_child_rows() {
    let challenge_table = postgres_table(PostgresAuthCoreTable::ActiveProofChallenge);
    assert!(
        challenge_table
            .uniqueness()
            .iter()
            .any(
                |constraint| constraint.name() == "active_proof_open_challenge_dedupe_key"
                    && constraint.columns() == ["challenge_dedupe_key"]
                    && constraint.predicate() == Some(PostgresUniquePredicate::OpenRow)
            )
    );

    let delivery_key_table = postgres_table(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey);
    assert_eq!(
        delivery_key_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("delivery key primary key")
            .columns(),
        &["challenge_id", "delivery_idempotency_key"]
    );

    let satisfied_proof_table = postgres_table(PostgresAuthCoreTable::ActiveProofSatisfiedProof);
    assert_eq!(
        satisfied_proof_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("satisfied proof primary key")
            .columns(),
        &["attempt_id", "proof_family"]
    );
}

#[test]
fn postgres_schema_contract_maps_current_and_previous_secret_versions_to_mac_rows() {
    let mappings = PostgresAuthCoreSchemaContract::credential_secret_mac_mappings();

    assert_eq!(mappings.len(), 2);
    for mapping in mappings {
        let mac_table = postgres_table(mapping.mac_table());
        let mac_column = mac_table
            .columns()
            .iter()
            .find(|column| column.name() == mapping.mac_column())
            .expect("mac column");
        assert_eq!(mac_column.storage(), PostgresColumnStorage::Bytea);
        assert_eq!(
            mac_column.value(),
            PostgresColumnValueContract::MacOverSecretBytes {
                exact_bytes: crate::crypto::MAC_OVER_SECRET_SIZE,
            }
        );
        assert!(
            mac_table
                .uniqueness()
                .iter()
                .any(|constraint| constraint.name() == "primary_key"
                    && constraint.columns()
                        == [
                            mapping.mac_owner_id_column(),
                            mapping.mac_secret_version_column()
                        ])
        );

        let credential_table = postgres_table(mapping.credential_table());
        assert!(credential_table.columns().iter().any(|column| column.name()
            == mapping.current_secret_version_column()
            && column.value() == PostgresColumnValueContract::SecretVersion
            && !column.nullable()));
        assert!(credential_table.columns().iter().any(|column| column.name()
            == mapping.previous_secret_version_column()
            && column.value() == PostgresColumnValueContract::SecretVersion
            && column.nullable()));
        assert!(credential_table.columns().iter().any(|column| column.name()
            == mapping.previous_secret_accept_until_column()
            && column.value() == PostgresColumnValueContract::UnixSeconds
            && column.nullable()));
    }
}

#[test]
fn postgres_precondition_execution_locks_then_validates_session_and_subject_state() {
    let contract = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::SessionStillMatches {
            session_id: id("session"),
            subject_id: id("subject"),
            now: at(40),
            current_secret_version: version(3),
        },
    );

    assert_eq!(contract.kind(), CorePreconditionKind::SessionStillMatches);
    assert_eq!(
        contract.lock_steps(),
        &[
            PostgresPreconditionLockStep::SelectExistingRowForUpdate {
                target: CoreStorageTarget::Session(id("session")),
                table: PostgresAuthCoreTable::Session,
            },
            PostgresPreconditionLockStep::MaterializeSubjectAuthStateThenSelectForUpdate {
                subject_id: id("subject"),
            },
        ]
    );
    assert_eq!(
        contract.validation_steps(),
        &[
            PostgresPreconditionValidationStep::SessionRowStillLiveWithSubjectAndCurrentVersion {
                subject_id: id("subject"),
                now: at(40),
                current_secret_version: version(3),
            },
            PostgresPreconditionValidationStep::SubjectAuthStateDoesNotInvalidateRecord,
        ]
    );
}

#[test]
fn postgres_precondition_execution_uses_unique_index_for_open_challenge_dedupe() {
    let contract = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::NoOpenOutOfBandChallengeForDedupeKey {
            challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            now: at(40),
        },
    );

    assert_eq!(
        contract.kind(),
        CorePreconditionKind::NoOpenOutOfBandChallengeForDedupeKey
    );
    assert_eq!(
        contract.lock_steps(),
        &[
            PostgresPreconditionLockStep::UseOpenOutOfBandChallengeDedupeUniqueIndex {
                challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            }
        ]
    );
    assert_eq!(
        contract.validation_steps(),
        &[
            PostgresPreconditionValidationStep::CloseExpiredOpenOutOfBandChallengesBeforeDedupeCheck {
                now: at(40),
            },
            PostgresPreconditionValidationStep::TreatOpenChallengeDedupeUniqueViolationAsPreconditionFailure,
        ]
    );
}

#[test]
fn postgres_mutation_execution_distinguishes_locked_delete_and_monotonic_upsert() {
    let delete_attempt =
        PostgresMutationExecutionContract::for_mutation(&Mutation::DeleteActiveProofAttempt {
            attempt_id: id("attempt"),
        });
    assert_eq!(
        delete_attempt.kind(),
        CoreMutationKind::DeleteActiveProofAttempt
    );
    assert_eq!(
        delete_attempt.write_step(),
        &PostgresMutationWriteStep::HardDeletePreviouslyLockedRow {
            target: CoreStorageTarget::ActiveProofAttempt(id("attempt")),
            cascades_to_tables: vec![
                PostgresAuthCoreTable::ActiveProofContinuationSecretMac,
                PostgresAuthCoreTable::ActiveProofChallenge,
            ],
        }
    );

    let revoke_subject = PostgresMutationExecutionContract::for_mutation(
        &Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: id("subject"),
            revoke_records_created_at_or_before: at(40),
            reason: RevocationReason::SubjectAuthStateChanged,
        },
    );
    assert_eq!(
        revoke_subject.kind(),
        CoreMutationKind::RaiseSubjectAuthRevocationCutoff
    );
    assert_eq!(
        revoke_subject.write_step(),
        &PostgresMutationWriteStep::MonotonicUpsertSubjectAuthRevocationCutoff {
            subject_id: id("subject"),
        }
    );
}

#[test]
fn postgres_atomic_commit_execution_orders_locks_secrets_mutations_and_effects() {
    let work = AtomicCommitWork {
        preconditions: vec![Precondition::SessionStillMatches {
            session_id: id("session"),
            subject_id: id("subject"),
            now: at(40),
            current_secret_version: version(3),
        }],
        mutations: vec![Mutation::RefreshSession {
            session_id: id("session"),
            new_secret_version: version(4),
            previous_secret_version: version(3),
            previous_secret_accept_until: at(45),
            refreshed_at: at(40),
            expires_at: at(140),
        }],
        audit_events: vec![AuditEvent {
            kind: AuditEventKind::SessionRefreshed,
            subject_id: Some(id("subject")),
            session_id: Some(id("session")),
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(40),
        }],
        method_commit_work: vec![out_of_band_method_commit_work()],
        fresh_credential_secrets: vec![fresh_session_secret("session", 4)],
        durable_effects: vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::TrustedDeviceCreated,
                subject_id: id("subject"),
            },
        )],
    };

    let contract =
        PostgresAtomicCommitExecutionContract::for_atomic_work(&work).expect("execution contract");

    assert_eq!(
        contract.stages(),
        &[
            PostgresAtomicCommitExecutionStage::ValidateAtomicWork,
            PostgresAtomicCommitExecutionStage::BeginTransaction,
            PostgresAtomicCommitExecutionStage::EnforceCorePrecondition(
                PostgresPreconditionExecutionContract::for_precondition(
                    &Precondition::SessionStillMatches {
                        session_id: id("session"),
                        subject_id: id("subject"),
                        now: at(40),
                        current_secret_version: version(3),
                    },
                ),
            ),
            PostgresAtomicCommitExecutionStage::EnforceMethodPreconditions,
            PostgresAtomicCommitExecutionStage::MaterializeFreshCredentialSecret(
                PostgresFreshCredentialSecretExecutionContract::for_fresh_credential_secret(
                    &fresh_session_secret("session", 4),
                ),
            ),
            PostgresAtomicCommitExecutionStage::ApplyCoreMutation(
                PostgresMutationExecutionContract::for_mutation(&Mutation::RefreshSession {
                    session_id: id("session"),
                    new_secret_version: version(4),
                    previous_secret_version: version(3),
                    previous_secret_accept_until: at(45),
                    refreshed_at: at(40),
                    expires_at: at(140),
                }),
            ),
            PostgresAtomicCommitExecutionStage::ApplyMethodMutations,
            PostgresAtomicCommitExecutionStage::AppendAuditEvents { count: 1 },
            PostgresAtomicCommitExecutionStage::AppendCoreDurableEffectCommands { count: 1 },
            PostgresAtomicCommitExecutionStage::AppendMethodDurableEffectCommands,
            PostgresAtomicCommitExecutionStage::CommitTransaction,
        ]
    );
}

#[test]
fn storage_boundary_contract_keeps_authoritative_load_and_commit_in_one_boundary() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let prepared_boundary = PreparedStorageBoundaryContract::for_prepared_command(&prepared);

    assert_eq!(
        prepared_boundary.stages(),
        &[
            PreparedStorageBoundaryStage::DeriveLoadedStateContract,
            PreparedStorageBoundaryStage::OpenBeforeStateLoad,
            PreparedStorageBoundaryStage::LoadAuthoritativeStateInsideOpenBoundary,
            PreparedStorageBoundaryStage::ValidateLoadedState,
            PreparedStorageBoundaryStage::ReduceCommand,
        ]
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let planned_boundary =
        PlannedStorageBoundaryContract::for_planned_execution(&prepared_boundary, &planned)
            .expect("planned storage boundary");

    assert_eq!(
        planned_boundary.atomic_commit_boundary(),
        AtomicCommitBoundary::LoadedStateBoundary
    );
    assert_eq!(
        planned_boundary.stages(),
        &[
            PlannedStorageBoundaryStage::BuildStorageContract,
            PlannedStorageBoundaryStage::CommitInsideLoadedStateBoundary,
            PlannedStorageBoundaryStage::MaterializeResponseEffects,
            PlannedStorageBoundaryStage::ReleaseResponseEffects,
        ]
    );
}

#[test]
fn storage_boundary_contract_allows_safe_read_without_storage_boundary() {
    let mut cookie = session_cookie(200);
    cookie.safe_read_valid_until = Some(at(80));
    let loaded = LoadedState {
        session_cookie: Some(cookie.clone()),
        ..LoadedState::default()
    };
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        PresentedAuthCookies {
            session_cookie: Some(cookie),
            trusted_device_cookie: None,
            active_proof_challenge_cookie: None,
            active_proof_continuation_cookie: None,
        },
    );
    let prepared_boundary = PreparedStorageBoundaryContract::for_prepared_command(&prepared);

    assert_eq!(
        prepared_boundary.boundary_before_reduce(),
        StorageBoundaryBeforeReduce::None
    );
    assert_eq!(
        prepared_boundary.stages(),
        &[
            PreparedStorageBoundaryStage::DeriveLoadedStateContract,
            PreparedStorageBoundaryStage::LoadNoAuthoritativeState,
            PreparedStorageBoundaryStage::ValidateLoadedState,
            PreparedStorageBoundaryStage::ReduceCommand,
        ]
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let planned_boundary =
        PlannedStorageBoundaryContract::for_planned_execution(&prepared_boundary, &planned)
            .expect("planned storage boundary");

    assert_eq!(
        planned_boundary.atomic_commit_boundary(),
        AtomicCommitBoundary::None
    );
    assert_eq!(
        planned_boundary.stages(),
        &[
            PlannedStorageBoundaryStage::MaterializeResponseEffects,
            PlannedStorageBoundaryStage::ReleaseResponseEffects,
        ]
    );
}

#[test]
fn storage_boundary_contract_opens_commit_only_boundary_for_write_without_load() {
    let prepared = prepare(
        Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: at(20),
            attempt_id: id("attempt"),
            proof_use: ProofUse::ContributeToFullAuthentication,
            subject_id: Some(id("subject")),
        }),
        PresentedAuthCookies::default(),
    );
    let prepared_boundary = PreparedStorageBoundaryContract::for_prepared_command(&prepared);

    assert_eq!(
        prepared_boundary.boundary_before_reduce(),
        StorageBoundaryBeforeReduce::None
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &LoadedState::default())
        .expect("planned execution");
    let planned_boundary =
        PlannedStorageBoundaryContract::for_planned_execution(&prepared_boundary, &planned)
            .expect("planned storage boundary");

    assert_eq!(
        planned_boundary.atomic_commit_boundary(),
        AtomicCommitBoundary::CommitOnlyBoundary
    );
    assert_eq!(
        planned_boundary.stages(),
        &[
            PlannedStorageBoundaryStage::BuildStorageContract,
            PlannedStorageBoundaryStage::OpenCommitOnlyBoundary,
            PlannedStorageBoundaryStage::CommitInsideCommitOnlyBoundary,
            PlannedStorageBoundaryStage::MaterializeResponseEffects,
            PlannedStorageBoundaryStage::ReleaseResponseEffects,
        ]
    );
}

#[test]
fn method_commit_boundary_places_plugin_work_inside_core_atomic_boundary() {
    let work = AtomicCommitWork {
        method_commit_work: vec![out_of_band_method_commit_work()],
        ..AtomicCommitWork::default()
    };
    let storage_contract = work.storage_contract().expect("storage contract");

    let method_boundary =
        MethodCommitBoundaryContract::for_atomic_commit_storage_contract(&storage_contract);

    assert_eq!(
        method_boundary.stages(),
        &[
            MethodCommitBoundaryStage::EnforceAfterCorePreconditions,
            MethodCommitBoundaryStage::ApplyAfterCoreMutations,
            MethodCommitBoundaryStage::PersistDurableCommandsBeforeCommit,
        ]
    );
    assert_eq!(
        storage_contract.transaction_contract().stages(),
        &[
            AtomicCommitTransactionStage::ValidateAtomicWork,
            AtomicCommitTransactionStage::BeginTransaction,
            AtomicCommitTransactionStage::EnforceMethodPreconditions,
            AtomicCommitTransactionStage::ApplyMethodMutations,
            AtomicCommitTransactionStage::CommitMethodDurableEffectCommands,
            AtomicCommitTransactionStage::CommitTransaction,
        ]
    );
}

#[test]
fn session_still_matches_locks_session_and_subject_auth_state() {
    let contract =
        CorePreconditionStorageContract::for_precondition(&Precondition::SessionStillMatches {
            session_id: id("session"),
            subject_id: id("subject"),
            now: at(40),
            current_secret_version: version(3),
        });

    assert_eq!(contract.kind(), CorePreconditionKind::SessionStillMatches);
    assert_eq!(
        contract.lock_requirements(),
        &[
            StorageLockRequirement::LockExistingRowForUpdate(CoreStorageTarget::Session(id(
                "session"
            ))),
            StorageLockRequirement::MaterializeSubjectAuthStateThenLockForUpdate {
                subject_id: id("subject"),
            },
        ]
    );
    assert_eq!(
        contract.validation_requirements(),
        &[
            StorageValidationRequirement::SessionStillLiveAndMatchesObservedVersion,
            StorageValidationRequirement::SubjectAuthStateDoesNotInvalidateRecord,
        ]
    );
}

#[test]
fn out_of_band_dedupe_precondition_requires_uniqueness_not_absent_row_locking() {
    let contract = CorePreconditionStorageContract::for_precondition(
        &Precondition::NoOpenOutOfBandChallengeForDedupeKey {
            challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            now: at(40),
        },
    );

    assert_eq!(
        contract.kind(),
        CorePreconditionKind::NoOpenOutOfBandChallengeForDedupeKey
    );
    assert_eq!(
        contract.lock_requirements(),
        &[
            StorageLockRequirement::EnforceOpenOutOfBandChallengeDedupeUniqueness {
                challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            }
        ]
    );
    assert_eq!(
        contract.validation_requirements(),
        &[StorageValidationRequirement::NoOpenOutOfBandChallengeForDedupeKey]
    );
}

#[test]
fn active_proof_attempt_precondition_locks_subject_auth_state_only_when_subject_known() {
    let without_subject = CorePreconditionStorageContract::for_precondition(
        &Precondition::ActiveProofAttemptStillOpen {
            attempt_id: id("attempt"),
            now: at(40),
            observed_subject_id: None,
            observed_satisfied_proofs: Vec::new(),
            observed_weak_proof_failures: 0,
            subject_id_for_revocation: None,
            created_at: at(10),
        },
    );
    assert_eq!(
        without_subject.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::ActiveProofAttempt(id("attempt")),
        )]
    );

    let with_subject = CorePreconditionStorageContract::for_precondition(
        &Precondition::ActiveProofAttemptStillOpen {
            attempt_id: id("attempt"),
            now: at(40),
            observed_subject_id: Some(id("subject")),
            observed_satisfied_proofs: Vec::new(),
            observed_weak_proof_failures: 0,
            subject_id_for_revocation: Some(id("subject")),
            created_at: at(10),
        },
    );
    assert_eq!(
        with_subject.lock_requirements(),
        &[
            StorageLockRequirement::LockExistingRowForUpdate(
                CoreStorageTarget::ActiveProofAttempt(id("attempt"))
            ),
            StorageLockRequirement::MaterializeSubjectAuthStateThenLockForUpdate {
                subject_id: id("subject"),
            },
        ]
    );
    assert_eq!(
        with_subject.validation_requirements(),
        &[
            StorageValidationRequirement::ActiveProofAttemptOpenSnapshotMatches,
            StorageValidationRequirement::SubjectAuthStateDoesNotInvalidateRecord,
        ]
    );
}

#[test]
fn mutation_storage_contract_distinguishes_updates_hard_deletes_and_monotonic_upserts() {
    let refresh = CoreMutationStorageContract::for_mutation(&Mutation::RefreshSession {
        session_id: id("session"),
        new_secret_version: version(4),
        previous_secret_version: version(3),
        previous_secret_accept_until: at(45),
        refreshed_at: at(40),
        expires_at: at(140),
    });
    assert_eq!(refresh.kind(), CoreMutationKind::RefreshSession);
    assert_eq!(
        refresh.write_requirement(),
        &StorageWriteRequirement::UpdateLockedRow(CoreStorageTarget::Session(id("session")))
    );

    let delete_attempt =
        CoreMutationStorageContract::for_mutation(&Mutation::DeleteActiveProofAttempt {
            attempt_id: id("attempt"),
        });
    assert_eq!(
        delete_attempt.kind(),
        CoreMutationKind::DeleteActiveProofAttempt
    );
    assert_eq!(
        delete_attempt.write_requirement(),
        &StorageWriteRequirement::HardDeleteLockedRow {
            target: CoreStorageTarget::ActiveProofAttempt(id("attempt")),
            cascades_to_record_kinds: vec![
                CoreStorageRecordKind::ActiveProofContinuationSecret,
                CoreStorageRecordKind::ActiveProofChallenge,
            ],
        }
    );

    let revoke_subject =
        CoreMutationStorageContract::for_mutation(&Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: id("subject"),
            revoke_records_created_at_or_before: at(40),
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    assert_eq!(
        revoke_subject.kind(),
        CoreMutationKind::RaiseSubjectAuthRevocationCutoff
    );
    assert_eq!(
        revoke_subject.write_requirement(),
        &StorageWriteRequirement::MonotonicUpsertSubjectAuthRevocationCutoff {
            subject_id: id("subject"),
        }
    );
}

#[test]
fn fresh_credential_secret_storage_contract_stores_mac_target_only() {
    let contract = FreshCredentialSecretStorageContract::for_fresh_credential_secret(
        &fresh_session_secret("session", 4),
    );

    assert_eq!(
        contract.target(),
        &CoreStorageTarget::SessionCredentialSecret {
            session_id: id("session"),
            secret_version: version(4),
        }
    );
    assert_eq!(
        contract.write_requirement(),
        FreshCredentialSecretWriteRequirement::GenerateFreshSecretAndStoreMacOnly
    );
}

#[test]
fn atomic_commit_storage_contract_collects_commit_execution_requirements() {
    let work = AtomicCommitWork {
        preconditions: vec![Precondition::SessionStillMatches {
            session_id: id("session"),
            subject_id: id("subject"),
            now: at(40),
            current_secret_version: version(3),
        }],
        mutations: vec![Mutation::RefreshSession {
            session_id: id("session"),
            new_secret_version: version(4),
            previous_secret_version: version(3),
            previous_secret_accept_until: at(45),
            refreshed_at: at(40),
            expires_at: at(140),
        }],
        audit_events: vec![AuditEvent {
            kind: AuditEventKind::SessionRefreshed,
            subject_id: Some(id("subject")),
            session_id: Some(id("session")),
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(40),
        }],
        method_commit_work: vec![out_of_band_method_commit_work()],
        fresh_credential_secrets: vec![fresh_session_secret("session", 4)],
        durable_effects: vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::TrustedDeviceCreated,
                subject_id: id("subject"),
            },
        )],
    };

    let contract = work.storage_contract().expect("storage contract");

    assert_eq!(
        contract.transaction_contract().stages(),
        &[
            AtomicCommitTransactionStage::ValidateAtomicWork,
            AtomicCommitTransactionStage::BeginTransaction,
            AtomicCommitTransactionStage::EnforceCorePreconditions,
            AtomicCommitTransactionStage::EnforceMethodPreconditions,
            AtomicCommitTransactionStage::MaterializeFreshCredentialSecrets,
            AtomicCommitTransactionStage::ApplyCoreMutations,
            AtomicCommitTransactionStage::ApplyMethodMutations,
            AtomicCommitTransactionStage::CommitAuditEvents,
            AtomicCommitTransactionStage::CommitCoreDurableEffectCommands,
            AtomicCommitTransactionStage::CommitMethodDurableEffectCommands,
            AtomicCommitTransactionStage::CommitTransaction,
        ]
    );
    assert_eq!(contract.preconditions().len(), 1);
    assert_eq!(contract.fresh_credential_secrets().len(), 1);
    assert_eq!(contract.mutations().len(), 1);
    assert_eq!(contract.method_commit_work().len(), 1);
    assert_eq!(contract.audit_event_count(), 1);
    assert_eq!(contract.core_durable_effect_command_count(), 1);
}
