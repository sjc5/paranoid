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
            CoreStorageRecordKind::CredentialInstance,
            CoreStorageRecordKind::CredentialRecoveryAuthority,
            CoreStorageRecordKind::SubjectLifecycleAuthority,
            CoreStorageRecordKind::LifecycleAuthoritySource,
            CoreStorageRecordKind::OutOfBandIdentifierBinding,
            CoreStorageRecordKind::PendingCredentialLifecycleAction,
            CoreStorageRecordKind::PendingSubjectLifecycleAction,
            CoreStorageRecordKind::AdminSupportIntervention,
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
            PostgresAuthCoreTable::CredentialInstance,
            PostgresAuthCoreTable::CredentialRecoveryAuthority,
            PostgresAuthCoreTable::SubjectLifecycleAuthority,
            PostgresAuthCoreTable::LifecycleAuthoritySource,
            PostgresAuthCoreTable::OutOfBandIdentifierBinding,
            PostgresAuthCoreTable::PendingCredentialLifecycleAction,
            PostgresAuthCoreTable::PendingSubjectLifecycleAction,
            PostgresAuthCoreTable::AdminSupportIntervention,
            PostgresAuthCoreTable::AuditEvent,
            PostgresAuthCoreTable::CoreDurableEffectCommand,
            PostgresAuthCoreTable::CoreDurableEffectQueueDispatch,
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
    assert_eq!(
        PostgresAuthCoreTable::CredentialInstance.default_suffix(),
        "auth_credential_instances"
    );
    assert_eq!(
        PostgresAuthCoreTable::SubjectLifecycleAuthority.default_suffix(),
        "auth_subject_lifecycle_authorities"
    );
    assert_eq!(
        PostgresAuthCoreTable::OutOfBandIdentifierBinding.default_suffix(),
        "auth_out_of_band_identifier_bindings"
    );
    assert_eq!(
        PostgresAuthCoreTable::PendingCredentialLifecycleAction.default_suffix(),
        "auth_credential_lifecycle_pending_actions"
    );
    assert_eq!(
        PostgresAuthCoreTable::PendingSubjectLifecycleAction.default_suffix(),
        "auth_subject_lifecycle_pending_actions"
    );
    assert_eq!(
        PostgresAuthCoreTable::AdminSupportIntervention.default_suffix(),
        "auth_admin_support_interventions"
    );
    assert_eq!(
        PostgresAuthCoreTable::CoreDurableEffectQueueDispatch.default_suffix(),
        "auth_core_durable_effect_queue_dispatches"
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

    let support_intervention_table =
        postgres_table_validation(PostgresAuthCoreTable::AdminSupportIntervention);
    assert!(
        support_intervention_table
            .uniqueness()
            .iter()
            .any(
                |constraint| constraint.name() == "admin_support_open_intervention"
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

    let credential_instance_table =
        postgres_table_validation(PostgresAuthCoreTable::CredentialInstance);
    let credential_instance_columns = credential_instance_table
        .columns()
        .iter()
        .map(|column| (column.name(), column.storage(), column.nullable()))
        .collect::<Vec<_>>();
    assert_eq!(
        credential_instance_columns,
        vec![
            (
                "credential_instance_id",
                PostgresColumnStorage::Bytea,
                false
            ),
            ("subject_id", PostgresColumnStorage::Bytea, false),
            ("credential_kind", PostgresColumnStorage::Integer, false),
            ("method_label", PostgresColumnStorage::TextCollateC, false),
            ("reset_policy_role", PostgresColumnStorage::Integer, false),
            ("lifecycle_state", PostgresColumnStorage::Integer, false),
            ("created_at", PostgresColumnStorage::Bigint, false),
            ("updated_at", PostgresColumnStorage::Bigint, false),
        ]
    );
    let credential_method_label_column = credential_instance_table
        .columns()
        .iter()
        .find(|column| column.name() == "method_label")
        .expect("credential method label column");
    assert!(
        credential_method_label_column
            .checks()
            .contains(&PostgresColumnValidationCheck::TextUsesBytewiseCollation)
    );
    assert!(
        credential_instance_table
            .uniqueness()
            .iter()
            .any(|constraint| constraint.name() == "primary_key"
                && constraint.columns() == ["credential_instance_id"])
    );
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
                | PostgresColumnValueContract::FixedOpaqueBytes { .. }
                | PostgresColumnValueContract::BoundedOpaqueBytes { .. }
                | PostgresColumnValueContract::MacOverSecretBytes { .. } => {
                    assert_eq!(column.storage(), PostgresColumnStorage::Bytea);
                }
                PostgresColumnValueContract::ValidatedText { .. } => {
                    assert_eq!(column.storage(), PostgresColumnStorage::TextCollateC);
                }
                PostgresColumnValueContract::SecretVersion
                | PostgresColumnValueContract::UnixSeconds
                | PostgresColumnValueContract::NonNegativeBigint
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
    let mappings = [
        (
            CoreStorageTarget::Session(id("session")),
            PostgresAuthCoreTable::Session,
        ),
        (
            CoreStorageTarget::SessionCredentialSecret {
                session_id: id("session"),
                secret_version: version(4),
            },
            PostgresAuthCoreTable::SessionCredentialSecretMac,
        ),
        (
            CoreStorageTarget::TrustedDeviceCredential(id("device")),
            PostgresAuthCoreTable::TrustedDeviceCredential,
        ),
        (
            CoreStorageTarget::TrustedDeviceCredentialSecret {
                device_credential_id: id("device"),
                secret_version: version(4),
            },
            PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac,
        ),
        (
            CoreStorageTarget::ActiveProofAttempt(id("attempt")),
            PostgresAuthCoreTable::ActiveProofAttempt,
        ),
        (
            CoreStorageTarget::ActiveProofContinuationSecret {
                attempt_id: id("attempt"),
            },
            PostgresAuthCoreTable::ActiveProofContinuationSecretMac,
        ),
        (
            CoreStorageTarget::ActiveProofChallenge(id("challenge")),
            PostgresAuthCoreTable::ActiveProofChallenge,
        ),
        (
            CoreStorageTarget::ActiveProofChallengesForAttemptProofFamily {
                attempt_id: id("attempt"),
                proof_family: ProofFamily::OutOfBandCode,
            },
            PostgresAuthCoreTable::ActiveProofChallenge,
        ),
        (
            CoreStorageTarget::OpenOutOfBandChallengeDedupeKey(dedupe_key(
                "login:email-hash:window",
            )),
            PostgresAuthCoreTable::ActiveProofChallenge,
        ),
        (
            CoreStorageTarget::SubjectAuthState(id("subject")),
            PostgresAuthCoreTable::SubjectAuthState,
        ),
        (
            CoreStorageTarget::CredentialInstance(id("credential")),
            PostgresAuthCoreTable::CredentialInstance,
        ),
        (
            CoreStorageTarget::CredentialRecoveryAuthority {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Create,
                authority_id: id("authority"),
                timing: RecoveryAuthorityTiming::Immediate,
            },
            PostgresAuthCoreTable::CredentialRecoveryAuthority,
        ),
        (
            CoreStorageTarget::CredentialRecoveryAuthoritiesForCredential(id("credential")),
            PostgresAuthCoreTable::CredentialRecoveryAuthority,
        ),
        (
            CoreStorageTarget::SubjectLifecycleAuthority {
                subject_id: id("subject"),
                action: SubjectLifecycleAction::DeleteSubjectAuthState,
                authority_id: id("authority"),
                timing: RecoveryAuthorityTiming::Immediate,
            },
            PostgresAuthCoreTable::SubjectLifecycleAuthority,
        ),
        (
            CoreStorageTarget::SubjectLifecycleAuthoritiesForSubject(id("subject")),
            PostgresAuthCoreTable::SubjectLifecycleAuthority,
        ),
        (
            CoreStorageTarget::LifecycleAuthoritySource {
                source_kind: LifecycleAuthoritySourceKind::CredentialInstance,
                source_id: id("credential"),
                authority_id: id("authority"),
            },
            PostgresAuthCoreTable::LifecycleAuthoritySource,
        ),
        (
            CoreStorageTarget::LifecycleAuthoritySourcesForSource {
                source_kind: LifecycleAuthoritySourceKind::CredentialInstance,
                source_id: id("credential"),
            },
            PostgresAuthCoreTable::LifecycleAuthoritySource,
        ),
        (
            CoreStorageTarget::OutOfBandIdentifierBinding(id("source")),
            PostgresAuthCoreTable::OutOfBandIdentifierBinding,
        ),
        (
            CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-credential")),
            PostgresAuthCoreTable::PendingCredentialLifecycleAction,
        ),
        (
            CoreStorageTarget::OpenPendingCredentialLifecycleActionForTarget {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Reset,
            },
            PostgresAuthCoreTable::PendingCredentialLifecycleAction,
        ),
        (
            CoreStorageTarget::PendingSubjectLifecycleAction(id("pending-subject")),
            PostgresAuthCoreTable::PendingSubjectLifecycleAction,
        ),
        (
            CoreStorageTarget::OpenPendingSubjectLifecycleActionForSubject {
                subject_id: id("subject"),
                action: SubjectLifecycleAction::DeleteSubjectAuthState,
            },
            PostgresAuthCoreTable::PendingSubjectLifecycleAction,
        ),
        (
            CoreStorageTarget::AdminSupportIntervention(id("intervention")),
            PostgresAuthCoreTable::AdminSupportIntervention,
        ),
        (
            CoreStorageTarget::OpenAdminSupportInterventionForTarget {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Reset,
            },
            PostgresAuthCoreTable::AdminSupportIntervention,
        ),
        (
            CoreStorageTarget::AuditEvents,
            PostgresAuthCoreTable::AuditEvent,
        ),
        (
            CoreStorageTarget::CoreDurableEffectCommands,
            PostgresAuthCoreTable::CoreDurableEffectCommand,
        ),
    ];

    for (target, table) in mappings {
        assert_eq!(
            PostgresAuthCoreSchemaContract::table_for_storage_target(&target),
            table,
            "wrong Postgres table for {target:?}"
        );
    }
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

    let recovery_authority_table =
        postgres_table(PostgresAuthCoreTable::CredentialRecoveryAuthority);
    assert_eq!(
        recovery_authority_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("recovery authority primary key")
            .columns(),
        &[
            "target_credential_instance_id",
            "lifecycle_action",
            "authority_id",
            "authority_timing"
        ]
    );

    let lifecycle_authority_source_table =
        postgres_table(PostgresAuthCoreTable::LifecycleAuthoritySource);
    assert_eq!(
        lifecycle_authority_source_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("lifecycle authority source primary key")
            .columns(),
        &["source_kind", "source_id", "authority_id"]
    );

    let pending_lifecycle_action_table =
        postgres_table(PostgresAuthCoreTable::PendingCredentialLifecycleAction);
    assert_eq!(
        pending_lifecycle_action_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("pending action primary key")
            .columns(),
        &["pending_action_id"]
    );
    assert!(
        pending_lifecycle_action_table
            .uniqueness()
            .iter()
            .any(
                |constraint| constraint.name() == "credential_lifecycle_open_pending_action"
                    && constraint.columns()
                        == ["target_credential_instance_id", "lifecycle_action"]
                    && constraint.predicate() == Some(PostgresUniquePredicate::OpenRow)
            )
    );

    let pending_subject_lifecycle_action_table =
        postgres_table(PostgresAuthCoreTable::PendingSubjectLifecycleAction);
    assert_eq!(
        pending_subject_lifecycle_action_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("pending subject action primary key")
            .columns(),
        &["pending_action_id"]
    );
    assert!(
        pending_subject_lifecycle_action_table
            .uniqueness()
            .iter()
            .any(
                |constraint| constraint.name() == "subject_lifecycle_open_pending_action"
                    && constraint.columns() == ["subject_id", "subject_lifecycle_action"]
                    && constraint.predicate() == Some(PostgresUniquePredicate::OpenRow)
            )
    );

    let durable_effect_dispatch_table =
        postgres_table(PostgresAuthCoreTable::CoreDurableEffectQueueDispatch);
    assert_eq!(
        durable_effect_dispatch_table
            .uniqueness()
            .iter()
            .find(|constraint| constraint.name() == "primary_key")
            .expect("durable effect dispatch primary key")
            .columns(),
        &["effect_command_id"]
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
            replaceable_created_at_or_before: Some(at(20)),
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
            PostgresPreconditionValidationStep::CloseReplaceableOpenOutOfBandChallengesBeforeDedupeCheck {
                now: at(40),
                replaceable_created_at_or_before: Some(at(20)),
            },
            PostgresPreconditionValidationStep::TreatOpenChallengeDedupeUniqueViolationAsPreconditionFailure,
        ]
    );
}

#[test]
fn postgres_precondition_execution_guards_credential_reset_target_and_pending_uniqueness() {
    let target_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::CredentialInstanceStillActive {
            credential_instance_id: id("credential"),
            subject_id: id("subject"),
        },
    );
    assert_eq!(
        target_guard.kind(),
        CorePreconditionKind::CredentialInstanceStillActive
    );
    assert_eq!(
        target_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::CredentialInstance(id("credential")),
            table: PostgresAuthCoreTable::CredentialInstance,
        }]
    );
    assert_eq!(
        target_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::CredentialInstanceStillActiveWithSubject {
                subject_id: id("subject"),
            }
        ]
    );

    let posture_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::SubjectRetainsRequiredCredentialPostureAfterRemoval {
            subject_id: id("subject"),
            removed_credential_instance_id: id("credential"),
            removed_credential_reset_policy_role: CredentialResetPolicyRole::SecondFactorCredential,
        },
    );
    assert_eq!(
        posture_guard.kind(),
        CorePreconditionKind::SubjectRetainsRequiredCredentialPostureAfterRemoval
    );
    assert_eq!(
        posture_guard.lock_steps(),
        &[
            PostgresPreconditionLockStep::SelectActiveCredentialInstancesForSubjectForUpdate {
                subject_id: id("subject"),
            },
            PostgresPreconditionLockStep::SelectActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: id("subject"),
            }
        ]
    );
    assert_eq!(
        posture_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::SubjectRetainsRequiredCredentialPostureAfterRemoval {
                subject_id: id("subject"),
                removed_credential_instance_id: id("credential"),
                removed_credential_reset_policy_role: CredentialResetPolicyRole::SecondFactorCredential,
            }
        ]
    );

    let target_credential = message_signature_credential_metadata("credential");
    let replacement_successor = replacement_successor_inheriting_target_policy(
        "replacement-credential",
        &target_credential,
        [CredentialRecoveryAuthority::new(
            id("credential"),
            CredentialLifecycleAction::Replace,
            id("replacement-authority"),
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("replacement-successor-authority")],
    );
    let replacement_posture_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::SubjectRetainsRequiredCredentialPostureAfterReplacement {
            subject_id: id("subject"),
            replaced_credential_instance_id: id("credential"),
            replaced_credential_reset_policy_role:
                CredentialResetPolicyRole::SecondFactorCredential,
            successor: replacement_successor.clone(),
        },
    );
    assert_eq!(
        replacement_posture_guard.kind(),
        CorePreconditionKind::SubjectRetainsRequiredCredentialPostureAfterReplacement
    );
    assert_eq!(
        replacement_posture_guard.lock_steps(),
        &[
            PostgresPreconditionLockStep::SelectActiveCredentialInstancesForSubjectForUpdate {
                subject_id: id("subject"),
            },
            PostgresPreconditionLockStep::SelectActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: id("subject"),
            }
        ]
    );
    assert_eq!(
        replacement_posture_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::SubjectRetainsRequiredCredentialPostureAfterReplacement {
                subject_id: id("subject"),
                replaced_credential_instance_id: id("credential"),
                replaced_credential_reset_policy_role: CredentialResetPolicyRole::SecondFactorCredential,
                successor: replacement_successor,
            }
        ]
    );

    let added_credential = message_signature_credential_metadata("added-credential");
    let added_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        id("added-credential"),
        CredentialLifecycleAction::Reset,
        id("added-credential-authority"),
        RecoveryAuthorityTiming::Immediate,
    )];
    let addition_posture_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::SubjectRetainsRequiredCredentialPostureAfterAddition {
            subject_id: id("subject"),
            added_credential: added_credential.clone(),
            added_recovery_authorities: added_recovery_authorities.clone(),
        },
    );
    assert_eq!(
        addition_posture_guard.kind(),
        CorePreconditionKind::SubjectRetainsRequiredCredentialPostureAfterAddition
    );
    assert_eq!(
        addition_posture_guard.lock_steps(),
        &[
            PostgresPreconditionLockStep::SelectActiveCredentialInstancesForSubjectForUpdate {
                subject_id: id("subject"),
            },
            PostgresPreconditionLockStep::SelectActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: id("subject"),
            }
        ]
    );
    assert_eq!(
        addition_posture_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::SubjectRetainsRequiredCredentialPostureAfterAddition {
                subject_id: id("subject"),
                added_credential,
                added_recovery_authorities,
            }
        ]
    );

    let pending_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            now: at(100),
        },
    );
    assert_eq!(
        pending_guard.kind(),
        CorePreconditionKind::NoOpenPendingCredentialLifecycleActionForTarget
    );
    assert_eq!(
        pending_guard.lock_steps(),
        &[
            PostgresPreconditionLockStep::UseOpenPendingCredentialLifecycleActionUniqueIndex {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Reset,
            }
        ]
    );
    assert_eq!(
        pending_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::CloseExpiredOpenPendingCredentialLifecycleActionsBeforeUniquenessCheck {
                now: at(100),
            },
            PostgresPreconditionValidationStep::TreatOpenPendingCredentialLifecycleActionUniqueViolationAsPreconditionFailure,
        ]
    );

    let pending_execution_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::PendingCredentialLifecycleActionStillExecutable {
            pending_action_id: id("pending-reset"),
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            now: at(250),
        },
    );
    assert_eq!(
        pending_execution_guard.kind(),
        CorePreconditionKind::PendingCredentialLifecycleActionStillExecutable
    );
    assert_eq!(
        pending_execution_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset")),
            table: PostgresAuthCoreTable::PendingCredentialLifecycleAction,
        }]
    );
    assert_eq!(
        pending_execution_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::PendingCredentialLifecycleActionOpenMatureUnexpiredAndTargetMatched {
                subject_id: id("subject"),
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Reset,
                now: at(250),
            }
        ]
    );

    let pending_cancellation_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
            pending_action_id: id("pending-reset"),
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            now: at(250),
        },
    );
    assert_eq!(
        pending_cancellation_guard.kind(),
        CorePreconditionKind::PendingCredentialLifecycleActionStillCancellableForTarget
    );
    assert_eq!(
        pending_cancellation_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset")),
            table: PostgresAuthCoreTable::PendingCredentialLifecycleAction,
        }]
    );
    assert_eq!(
        pending_cancellation_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::PendingCredentialLifecycleActionOpenUnexpiredAndTargetMatched {
                subject_id: id("subject"),
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Reset,
                now: at(250),
            }
        ]
    );

    let subject_pending_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
            subject_id: id("subject"),
            action: SubjectLifecycleAction::DeleteSubjectAuthState,
            now: at(100),
        },
    );
    assert_eq!(
        subject_pending_guard.kind(),
        CorePreconditionKind::NoOpenPendingSubjectLifecycleActionForSubject
    );
    assert_eq!(
        subject_pending_guard.lock_steps(),
        &[
            PostgresPreconditionLockStep::UseOpenPendingSubjectLifecycleActionUniqueIndex {
                subject_id: id("subject"),
                action: SubjectLifecycleAction::DeleteSubjectAuthState,
            }
        ]
    );
    assert_eq!(
        subject_pending_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::CloseExpiredOpenPendingSubjectLifecycleActionsBeforeUniquenessCheck {
                now: at(100),
            },
            PostgresPreconditionValidationStep::TreatOpenPendingSubjectLifecycleActionUniqueViolationAsPreconditionFailure,
        ]
    );

    let subject_execution_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::PendingSubjectLifecycleActionStillExecutable {
            pending_action_id: id("pending-subject-deletion"),
            subject_id: id("subject"),
            action: SubjectLifecycleAction::DeleteSubjectAuthState,
            now: at(250),
        },
    );
    assert_eq!(
        subject_execution_guard.kind(),
        CorePreconditionKind::PendingSubjectLifecycleActionStillExecutable
    );
    assert_eq!(
        subject_execution_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::PendingSubjectLifecycleAction(id(
                "pending-subject-deletion"
            )),
            table: PostgresAuthCoreTable::PendingSubjectLifecycleAction,
        }]
    );
    assert_eq!(
        subject_execution_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::PendingSubjectLifecycleActionOpenMatureUnexpiredAndSubjectMatched {
                subject_id: id("subject"),
                action: SubjectLifecycleAction::DeleteSubjectAuthState,
                now: at(250),
            }
        ]
    );

    let subject_cancellation_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
            pending_action_id: id("pending-subject-deletion"),
            subject_id: id("subject"),
            action: SubjectLifecycleAction::DeleteSubjectAuthState,
            now: at(250),
        },
    );
    assert_eq!(
        subject_cancellation_guard.kind(),
        CorePreconditionKind::PendingSubjectLifecycleActionStillCancellableForSubject
    );
    assert_eq!(
        subject_cancellation_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::PendingSubjectLifecycleAction(id(
                "pending-subject-deletion"
            )),
            table: PostgresAuthCoreTable::PendingSubjectLifecycleAction,
        }]
    );
    assert_eq!(
        subject_cancellation_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::PendingSubjectLifecycleActionOpenUnexpiredAndSubjectMatched {
                subject_id: id("subject"),
                action: SubjectLifecycleAction::DeleteSubjectAuthState,
                now: at(250),
            }
        ]
    );

    let active_identifier_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::OutOfBandIdentifierBindingStillActive {
            source_id: id("current-email-source"),
            subject_id: id("subject"),
        },
    );
    assert_eq!(
        active_identifier_guard.kind(),
        CorePreconditionKind::OutOfBandIdentifierBindingStillActive
    );
    assert_eq!(
        active_identifier_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::OutOfBandIdentifierBinding(id("current-email-source")),
            table: PostgresAuthCoreTable::OutOfBandIdentifierBinding,
        }]
    );
    assert_eq!(
        active_identifier_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::OutOfBandIdentifierBindingActiveWithSubject {
                subject_id: id("subject"),
            }
        ]
    );

    let pending_identifier_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::OutOfBandIdentifierBindingStillPendingActivation {
            source_id: id("candidate-email-source"),
            subject_id: id("subject"),
        },
    );
    assert_eq!(
        pending_identifier_guard.kind(),
        CorePreconditionKind::OutOfBandIdentifierBindingStillPendingActivation
    );
    assert_eq!(
        pending_identifier_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::OutOfBandIdentifierBinding(id("candidate-email-source")),
            table: PostgresAuthCoreTable::OutOfBandIdentifierBinding,
        }]
    );
    assert_eq!(
        pending_identifier_guard.validation_steps(),
        &[PostgresPreconditionValidationStep::OutOfBandIdentifierBindingPendingActivationWithSubject {
            subject_id: id("subject"),
        }]
    );

    let support_uniqueness_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::NoOpenAdminSupportInterventionForTarget {
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Replace,
            now: at(100),
        },
    );
    assert_eq!(
        support_uniqueness_guard.kind(),
        CorePreconditionKind::NoOpenAdminSupportInterventionForTarget
    );
    assert_eq!(
        support_uniqueness_guard.lock_steps(),
        &[
            PostgresPreconditionLockStep::UseOpenAdminSupportInterventionUniqueIndex {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Replace,
            }
        ]
    );
    assert_eq!(
        support_uniqueness_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::CloseExpiredOpenAdminSupportInterventionsBeforeUniquenessCheck {
                now: at(100),
            },
            PostgresPreconditionValidationStep::TreatOpenAdminSupportInterventionUniqueViolationAsPreconditionFailure,
        ]
    );

    let support_open_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::AdminSupportInterventionStillOpen {
            intervention_id: id("support-intervention"),
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Replace,
            now: at(100),
        },
    );
    assert_eq!(
        support_open_guard.kind(),
        CorePreconditionKind::AdminSupportInterventionStillOpen
    );
    assert_eq!(
        support_open_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::AdminSupportIntervention(id("support-intervention")),
            table: PostgresAuthCoreTable::AdminSupportIntervention,
        }]
    );
    assert_eq!(
        support_open_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::AdminSupportInterventionOpenUnexpiredAndTargetMatched {
                subject_id: id("subject"),
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Replace,
                now: at(100),
            }
        ]
    );

    let support_expired_guard = PostgresPreconditionExecutionContract::for_precondition(
        &Precondition::AdminSupportInterventionStillExpiredOpen {
            intervention_id: id("support-intervention"),
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Replace,
            now: at(200),
        },
    );
    assert_eq!(
        support_expired_guard.kind(),
        CorePreconditionKind::AdminSupportInterventionStillExpiredOpen
    );
    assert_eq!(
        support_expired_guard.lock_steps(),
        &[PostgresPreconditionLockStep::SelectExistingRowForUpdate {
            target: CoreStorageTarget::AdminSupportIntervention(id("support-intervention")),
            table: PostgresAuthCoreTable::AdminSupportIntervention,
        }]
    );
    assert_eq!(
        support_expired_guard.validation_steps(),
        &[
            PostgresPreconditionValidationStep::AdminSupportInterventionExpiredOpenAndTargetMatched {
                subject_id: id("subject"),
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Replace,
                now: at(200),
            }
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

    let authorize_reset = PostgresMutationExecutionContract::for_mutation(
        &Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            authorized_at: at(100),
        },
    );
    assert_eq!(
        authorize_reset.kind(),
        CoreMutationKind::RecordCredentialLifecycleActionAuthorized
    );
    assert_eq!(
        authorize_reset.write_step(),
        &PostgresMutationWriteStep::UpdatePreviouslyLockedRow {
            target: CoreStorageTarget::CredentialInstance(id("credential")),
            table: PostgresAuthCoreTable::CredentialInstance,
        }
    );

    let create_credential = PostgresMutationExecutionContract::for_mutation(
        &Mutation::CreateCredentialInstanceMetadata {
            metadata: message_signature_credential_metadata("credential"),
            created_at: at(100),
        },
    );
    assert_eq!(
        create_credential.kind(),
        CoreMutationKind::CreateCredentialInstanceMetadata
    );
    assert_eq!(
        create_credential.write_step(),
        &PostgresMutationWriteStep::InsertUniqueRow {
            target: CoreStorageTarget::CredentialInstance(id("credential")),
            table: PostgresAuthCoreTable::CredentialInstance,
        }
    );

    let create_authority = PostgresMutationExecutionContract::for_mutation(
        &Mutation::CreateCredentialRecoveryAuthority {
            authority: CredentialRecoveryAuthority::new(
                id("credential"),
                CredentialLifecycleAction::Create,
                id("authority"),
                RecoveryAuthorityTiming::Immediate,
            ),
            created_at: at(100),
        },
    );
    assert_eq!(
        create_authority.kind(),
        CoreMutationKind::CreateCredentialRecoveryAuthority
    );
    assert_eq!(
        create_authority.write_step(),
        &PostgresMutationWriteStep::InsertUniqueRow {
            target: CoreStorageTarget::CredentialRecoveryAuthority {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Create,
                authority_id: id("authority"),
                timing: RecoveryAuthorityTiming::Immediate,
            },
            table: PostgresAuthCoreTable::CredentialRecoveryAuthority,
        }
    );

    let create_authority_source = PostgresMutationExecutionContract::for_mutation(
        &Mutation::CreateLifecycleAuthoritySource {
            source: LifecycleAuthoritySource::VerifiedProofSource(VerifiedProofSource::new(
                VerifiedProofSourceKind::CredentialInstance,
                id("credential"),
            )),
            authority_id: id("authority"),
            created_at: at(100),
        },
    );
    assert_eq!(
        create_authority_source.kind(),
        CoreMutationKind::CreateLifecycleAuthoritySource
    );
    assert_eq!(
        create_authority_source.write_step(),
        &PostgresMutationWriteStep::InsertUniqueRow {
            target: CoreStorageTarget::LifecycleAuthoritySource {
                source_kind: LifecycleAuthoritySourceKind::CredentialInstance,
                source_id: id("credential"),
                authority_id: id("authority"),
            },
            table: PostgresAuthCoreTable::LifecycleAuthoritySource,
        }
    );

    let delete_authority_sources_for_source = PostgresMutationExecutionContract::for_mutation(
        &Mutation::DeleteLifecycleAuthoritySourcesForSource {
            source: LifecycleAuthoritySource::VerifiedProofSource(VerifiedProofSource::new(
                VerifiedProofSourceKind::OutOfBandIdentifier,
                id("identifier-source"),
            )),
        },
    );
    assert_eq!(
        delete_authority_sources_for_source.kind(),
        CoreMutationKind::DeleteLifecycleAuthoritySourcesForSource
    );
    assert_eq!(
        delete_authority_sources_for_source.write_step(),
        &PostgresMutationWriteStep::HardDeleteMatchingRowsWithSingleStatement {
            target: CoreStorageTarget::LifecycleAuthoritySourcesForSource {
                source_kind: LifecycleAuthoritySourceKind::OutOfBandIdentifier,
                source_id: id("identifier-source"),
            },
            table: PostgresAuthCoreTable::LifecycleAuthoritySource,
        }
    );

    let create_pending = PostgresMutationExecutionContract::for_mutation(
        &Mutation::CreatePendingCredentialLifecycleAction(
            PendingCredentialLifecycleActionRecord::new_open(
                id("pending-reset"),
                id("subject"),
                id("credential"),
                CredentialLifecycleAction::Reset,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        ),
    );
    assert_eq!(
        create_pending.kind(),
        CoreMutationKind::CreatePendingCredentialLifecycleAction
    );
    assert_eq!(
        create_pending.write_step(),
        &PostgresMutationWriteStep::InsertUniqueRow {
            target: CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset")),
            table: PostgresAuthCoreTable::PendingCredentialLifecycleAction,
        }
    );

    let execute_reset = PostgresMutationExecutionContract::for_mutation(
        &Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            executed_at: at(250),
        },
    );
    assert_eq!(
        execute_reset.kind(),
        CoreMutationKind::RecordCredentialLifecycleActionExecuted
    );
    assert_eq!(
        execute_reset.write_step(),
        &PostgresMutationWriteStep::UpdatePreviouslyLockedRow {
            target: CoreStorageTarget::CredentialInstance(id("credential")),
            table: PostgresAuthCoreTable::CredentialInstance,
        }
    );

    let set_lifecycle_state =
        PostgresMutationExecutionContract::for_mutation(&Mutation::SetCredentialLifecycleState {
            credential_instance_id: id("credential"),
            lifecycle_state: CredentialLifecycleState::Superseded,
            updated_at: at(250),
        });
    assert_eq!(
        set_lifecycle_state.kind(),
        CoreMutationKind::SetCredentialLifecycleState
    );
    assert_eq!(
        set_lifecycle_state.write_step(),
        &PostgresMutationWriteStep::UpdatePreviouslyLockedRow {
            target: CoreStorageTarget::CredentialInstance(id("credential")),
            table: PostgresAuthCoreTable::CredentialInstance,
        }
    );

    let close_pending = PostgresMutationExecutionContract::for_mutation(
        &Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id: id("pending-reset"),
            closed_at: at(250),
        },
    );
    assert_eq!(
        close_pending.kind(),
        CoreMutationKind::ClosePendingCredentialLifecycleAction
    );
    assert_eq!(
        close_pending.write_step(),
        &PostgresMutationWriteStep::UpdatePreviouslyLockedRow {
            target: CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset")),
            table: PostgresAuthCoreTable::PendingCredentialLifecycleAction,
        }
    );

    let create_subject_pending = PostgresMutationExecutionContract::for_mutation(
        &Mutation::CreatePendingSubjectLifecycleAction(
            PendingSubjectLifecycleActionRecord::new_open(
                id("pending-subject-deletion"),
                id("subject"),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject action"),
        ),
    );
    assert_eq!(
        create_subject_pending.kind(),
        CoreMutationKind::CreatePendingSubjectLifecycleAction
    );
    assert_eq!(
        create_subject_pending.write_step(),
        &PostgresMutationWriteStep::InsertUniqueRow {
            target: CoreStorageTarget::PendingSubjectLifecycleAction(id(
                "pending-subject-deletion"
            )),
            table: PostgresAuthCoreTable::PendingSubjectLifecycleAction,
        }
    );

    let close_subject_pending = PostgresMutationExecutionContract::for_mutation(
        &Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id: id("pending-subject-deletion"),
            closed_at: at(250),
        },
    );
    assert_eq!(
        close_subject_pending.kind(),
        CoreMutationKind::ClosePendingSubjectLifecycleAction
    );
    assert_eq!(
        close_subject_pending.write_step(),
        &PostgresMutationWriteStep::UpdatePreviouslyLockedRow {
            target: CoreStorageTarget::PendingSubjectLifecycleAction(id(
                "pending-subject-deletion"
            )),
            table: PostgresAuthCoreTable::PendingSubjectLifecycleAction,
        }
    );

    let create_support_intervention =
        PostgresMutationExecutionContract::for_mutation(&Mutation::CreateAdminSupportIntervention(
            AdminSupportInterventionRecord::new_requested(
                id("support-intervention"),
                id("subject"),
                id("credential"),
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
            )
            .expect("support intervention"),
        ));
    assert_eq!(
        create_support_intervention.kind(),
        CoreMutationKind::CreateAdminSupportIntervention
    );
    assert_eq!(
        create_support_intervention.write_step(),
        &PostgresMutationWriteStep::InsertUniqueRow {
            target: CoreStorageTarget::AdminSupportIntervention(id("support-intervention")),
            table: PostgresAuthCoreTable::AdminSupportIntervention,
        }
    );

    let close_support_intervention =
        PostgresMutationExecutionContract::for_mutation(&Mutation::CloseAdminSupportIntervention {
            intervention_id: id("support-intervention"),
            status: AdminSupportInterventionStatus::Approved,
            closed_at: at(150),
        });
    assert_eq!(
        close_support_intervention.kind(),
        CoreMutationKind::CloseAdminSupportIntervention
    );
    assert_eq!(
        close_support_intervention.write_step(),
        &PostgresMutationWriteStep::UpdatePreviouslyLockedRow {
            target: CoreStorageTarget::AdminSupportIntervention(id("support-intervention")),
            table: PostgresAuthCoreTable::AdminSupportIntervention,
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
            replaceable_created_at_or_before: Some(at(20)),
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
fn credential_lifecycle_preconditions_lock_target_and_enforce_pending_uniqueness() {
    let target_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::CredentialInstanceStillActive {
            credential_instance_id: id("credential"),
            subject_id: id("subject"),
        },
    );
    assert_eq!(
        target_guard.kind(),
        CorePreconditionKind::CredentialInstanceStillActive
    );
    assert_eq!(
        target_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::CredentialInstance(id("credential")),
        )]
    );
    assert_eq!(
        target_guard.validation_requirements(),
        &[StorageValidationRequirement::CredentialInstanceStillActive]
    );

    let posture_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::SubjectRetainsRequiredCredentialPostureAfterRemoval {
            subject_id: id("subject"),
            removed_credential_instance_id: id("credential"),
            removed_credential_reset_policy_role: CredentialResetPolicyRole::SecondFactorCredential,
        },
    );
    assert_eq!(
        posture_guard.kind(),
        CorePreconditionKind::SubjectRetainsRequiredCredentialPostureAfterRemoval
    );
    assert_eq!(
        posture_guard.lock_requirements(),
        &[
            StorageLockRequirement::LockActiveCredentialInstancesForSubjectForUpdate {
                subject_id: id("subject"),
            },
            StorageLockRequirement::LockActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: id("subject"),
            }
        ]
    );
    assert_eq!(
        posture_guard.validation_requirements(),
        &[StorageValidationRequirement::SubjectRetainsRequiredCredentialPostureAfterRemoval]
    );

    let target_credential = message_signature_credential_metadata("credential");
    let replacement_successor = replacement_successor_inheriting_target_policy(
        "replacement-credential",
        &target_credential,
        [CredentialRecoveryAuthority::new(
            id("credential"),
            CredentialLifecycleAction::Replace,
            id("replacement-authority"),
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("replacement-successor-authority")],
    );
    let replacement_posture_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::SubjectRetainsRequiredCredentialPostureAfterReplacement {
            subject_id: id("subject"),
            replaced_credential_instance_id: id("credential"),
            replaced_credential_reset_policy_role:
                CredentialResetPolicyRole::SecondFactorCredential,
            successor: replacement_successor,
        },
    );
    assert_eq!(
        replacement_posture_guard.kind(),
        CorePreconditionKind::SubjectRetainsRequiredCredentialPostureAfterReplacement
    );
    assert_eq!(
        replacement_posture_guard.lock_requirements(),
        &[
            StorageLockRequirement::LockActiveCredentialInstancesForSubjectForUpdate {
                subject_id: id("subject"),
            },
            StorageLockRequirement::LockActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: id("subject"),
            }
        ]
    );
    assert_eq!(
        replacement_posture_guard.validation_requirements(),
        &[StorageValidationRequirement::SubjectRetainsRequiredCredentialPostureAfterReplacement]
    );

    let added_credential = message_signature_credential_metadata("added-credential");
    let addition_posture_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::SubjectRetainsRequiredCredentialPostureAfterAddition {
            subject_id: id("subject"),
            added_credential,
            added_recovery_authorities: vec![CredentialRecoveryAuthority::new(
                id("added-credential"),
                CredentialLifecycleAction::Reset,
                id("added-credential-authority"),
                RecoveryAuthorityTiming::Immediate,
            )],
        },
    );
    assert_eq!(
        addition_posture_guard.kind(),
        CorePreconditionKind::SubjectRetainsRequiredCredentialPostureAfterAddition
    );
    assert_eq!(
        addition_posture_guard.lock_requirements(),
        &[
            StorageLockRequirement::LockActiveCredentialInstancesForSubjectForUpdate {
                subject_id: id("subject"),
            },
            StorageLockRequirement::LockActiveCredentialRecoveryAuthoritiesForSubjectForUpdate {
                subject_id: id("subject"),
            }
        ]
    );
    assert_eq!(
        addition_posture_guard.validation_requirements(),
        &[StorageValidationRequirement::SubjectRetainsRequiredCredentialPostureAfterAddition]
    );

    let pending_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            now: at(100),
        },
    );
    assert_eq!(
        pending_guard.kind(),
        CorePreconditionKind::NoOpenPendingCredentialLifecycleActionForTarget
    );
    assert_eq!(
        pending_guard.lock_requirements(),
        &[
            StorageLockRequirement::EnforceOpenPendingCredentialLifecycleActionUniqueness {
                target_credential_instance_id: id("credential"),
                action: CredentialLifecycleAction::Reset,
            }
        ]
    );
    assert_eq!(
        pending_guard.validation_requirements(),
        &[StorageValidationRequirement::NoOpenPendingCredentialLifecycleActionForTarget]
    );

    let pending_execution_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::PendingCredentialLifecycleActionStillExecutable {
            pending_action_id: id("pending-reset"),
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            now: at(250),
        },
    );
    assert_eq!(
        pending_execution_guard.kind(),
        CorePreconditionKind::PendingCredentialLifecycleActionStillExecutable
    );
    assert_eq!(
        pending_execution_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset"))
        )]
    );
    assert_eq!(
        pending_execution_guard.validation_requirements(),
        &[StorageValidationRequirement::PendingCredentialLifecycleActionStillExecutable]
    );

    let pending_cancellation_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
            pending_action_id: id("pending-reset"),
            subject_id: id("subject"),
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            now: at(250),
        },
    );
    assert_eq!(
        pending_cancellation_guard.kind(),
        CorePreconditionKind::PendingCredentialLifecycleActionStillCancellableForTarget
    );
    assert_eq!(
        pending_cancellation_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset"))
        )]
    );
    assert_eq!(
        pending_cancellation_guard.validation_requirements(),
        &[StorageValidationRequirement::PendingCredentialLifecycleActionStillCancellableForTarget]
    );

    let subject_pending_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
            subject_id: id("subject"),
            action: SubjectLifecycleAction::DeleteSubjectAuthState,
            now: at(100),
        },
    );
    assert_eq!(
        subject_pending_guard.kind(),
        CorePreconditionKind::NoOpenPendingSubjectLifecycleActionForSubject
    );
    assert_eq!(
        subject_pending_guard.lock_requirements(),
        &[
            StorageLockRequirement::EnforceOpenPendingSubjectLifecycleActionUniqueness {
                subject_id: id("subject"),
                action: SubjectLifecycleAction::DeleteSubjectAuthState,
            }
        ]
    );
    assert_eq!(
        subject_pending_guard.validation_requirements(),
        &[StorageValidationRequirement::NoOpenPendingSubjectLifecycleActionForSubject]
    );

    let subject_execution_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::PendingSubjectLifecycleActionStillExecutable {
            pending_action_id: id("pending-subject-deletion"),
            subject_id: id("subject"),
            action: SubjectLifecycleAction::DeleteSubjectAuthState,
            now: at(250),
        },
    );
    assert_eq!(
        subject_execution_guard.kind(),
        CorePreconditionKind::PendingSubjectLifecycleActionStillExecutable
    );
    assert_eq!(
        subject_execution_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::PendingSubjectLifecycleAction(id("pending-subject-deletion"))
        )]
    );
    assert_eq!(
        subject_execution_guard.validation_requirements(),
        &[StorageValidationRequirement::PendingSubjectLifecycleActionStillExecutable]
    );

    let subject_cancellation_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
            pending_action_id: id("pending-subject-deletion"),
            subject_id: id("subject"),
            action: SubjectLifecycleAction::DeleteSubjectAuthState,
            now: at(250),
        },
    );
    assert_eq!(
        subject_cancellation_guard.kind(),
        CorePreconditionKind::PendingSubjectLifecycleActionStillCancellableForSubject
    );
    assert_eq!(
        subject_cancellation_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::PendingSubjectLifecycleAction(id("pending-subject-deletion"))
        )]
    );
    assert_eq!(
        subject_cancellation_guard.validation_requirements(),
        &[StorageValidationRequirement::PendingSubjectLifecycleActionStillCancellableForSubject]
    );

    let active_identifier_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::OutOfBandIdentifierBindingStillActive {
            source_id: id("current-email-source"),
            subject_id: id("subject"),
        },
    );
    assert_eq!(
        active_identifier_guard.kind(),
        CorePreconditionKind::OutOfBandIdentifierBindingStillActive
    );
    assert_eq!(
        active_identifier_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::OutOfBandIdentifierBinding(id("current-email-source"))
        )]
    );
    assert_eq!(
        active_identifier_guard.validation_requirements(),
        &[StorageValidationRequirement::OutOfBandIdentifierBindingStillActive]
    );

    let pending_identifier_guard = CorePreconditionStorageContract::for_precondition(
        &Precondition::OutOfBandIdentifierBindingStillPendingActivation {
            source_id: id("candidate-email-source"),
            subject_id: id("subject"),
        },
    );
    assert_eq!(
        pending_identifier_guard.kind(),
        CorePreconditionKind::OutOfBandIdentifierBindingStillPendingActivation
    );
    assert_eq!(
        pending_identifier_guard.lock_requirements(),
        &[StorageLockRequirement::LockExistingRowForUpdate(
            CoreStorageTarget::OutOfBandIdentifierBinding(id("candidate-email-source"))
        )]
    );
    assert_eq!(
        pending_identifier_guard.validation_requirements(),
        &[StorageValidationRequirement::OutOfBandIdentifierBindingStillPendingActivation]
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

    let authorize_reset = CoreMutationStorageContract::for_mutation(
        &Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            authorized_at: at(100),
        },
    );
    assert_eq!(
        authorize_reset.kind(),
        CoreMutationKind::RecordCredentialLifecycleActionAuthorized
    );
    assert_eq!(
        authorize_reset.write_requirement(),
        &StorageWriteRequirement::UpdateLockedRow(CoreStorageTarget::CredentialInstance(id(
            "credential"
        )))
    );

    let create_credential =
        CoreMutationStorageContract::for_mutation(&Mutation::CreateCredentialInstanceMetadata {
            metadata: message_signature_credential_metadata("credential"),
            created_at: at(100),
        });
    assert_eq!(
        create_credential.kind(),
        CoreMutationKind::CreateCredentialInstanceMetadata
    );
    assert_eq!(
        create_credential.write_requirement(),
        &StorageWriteRequirement::InsertUnique(CoreStorageTarget::CredentialInstance(id(
            "credential"
        )))
    );

    let create_authority =
        CoreMutationStorageContract::for_mutation(&Mutation::CreateCredentialRecoveryAuthority {
            authority: CredentialRecoveryAuthority::new(
                id("credential"),
                CredentialLifecycleAction::Create,
                id("authority"),
                RecoveryAuthorityTiming::Immediate,
            ),
            created_at: at(100),
        });
    assert_eq!(
        create_authority.kind(),
        CoreMutationKind::CreateCredentialRecoveryAuthority
    );
    assert_eq!(
        create_authority.write_requirement(),
        &StorageWriteRequirement::InsertUnique(CoreStorageTarget::CredentialRecoveryAuthority {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Create,
            authority_id: id("authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        })
    );

    let create_authority_source =
        CoreMutationStorageContract::for_mutation(&Mutation::CreateLifecycleAuthoritySource {
            source: LifecycleAuthoritySource::VerifiedProofSource(VerifiedProofSource::new(
                VerifiedProofSourceKind::CredentialInstance,
                id("credential"),
            )),
            authority_id: id("authority"),
            created_at: at(100),
        });
    assert_eq!(
        create_authority_source.kind(),
        CoreMutationKind::CreateLifecycleAuthoritySource
    );
    assert_eq!(
        create_authority_source.write_requirement(),
        &StorageWriteRequirement::InsertUnique(CoreStorageTarget::LifecycleAuthoritySource {
            source_kind: LifecycleAuthoritySourceKind::CredentialInstance,
            source_id: id("credential"),
            authority_id: id("authority"),
        })
    );

    let delete_authority_sources_for_source = CoreMutationStorageContract::for_mutation(
        &Mutation::DeleteLifecycleAuthoritySourcesForSource {
            source: LifecycleAuthoritySource::VerifiedProofSource(VerifiedProofSource::new(
                VerifiedProofSourceKind::OutOfBandIdentifier,
                id("identifier-source"),
            )),
        },
    );
    assert_eq!(
        delete_authority_sources_for_source.kind(),
        CoreMutationKind::DeleteLifecycleAuthoritySourcesForSource
    );
    assert_eq!(
        delete_authority_sources_for_source.write_requirement(),
        &StorageWriteRequirement::HardDeleteRowsMatching(
            CoreStorageTarget::LifecycleAuthoritySourcesForSource {
                source_kind: LifecycleAuthoritySourceKind::OutOfBandIdentifier,
                source_id: id("identifier-source"),
            }
        )
    );

    let create_pending = CoreMutationStorageContract::for_mutation(
        &Mutation::CreatePendingCredentialLifecycleAction(
            PendingCredentialLifecycleActionRecord::new_open(
                id("pending-reset"),
                id("subject"),
                id("credential"),
                CredentialLifecycleAction::Reset,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        ),
    );
    assert_eq!(
        create_pending.kind(),
        CoreMutationKind::CreatePendingCredentialLifecycleAction
    );
    assert_eq!(
        create_pending.write_requirement(),
        &StorageWriteRequirement::InsertUnique(
            CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset"))
        )
    );

    let execute_reset = CoreMutationStorageContract::for_mutation(
        &Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: id("credential"),
            action: CredentialLifecycleAction::Reset,
            executed_at: at(250),
        },
    );
    assert_eq!(
        execute_reset.kind(),
        CoreMutationKind::RecordCredentialLifecycleActionExecuted
    );
    assert_eq!(
        execute_reset.write_requirement(),
        &StorageWriteRequirement::UpdateLockedRow(CoreStorageTarget::CredentialInstance(id(
            "credential"
        )))
    );

    let close_pending = CoreMutationStorageContract::for_mutation(
        &Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id: id("pending-reset"),
            closed_at: at(250),
        },
    );
    assert_eq!(
        close_pending.kind(),
        CoreMutationKind::ClosePendingCredentialLifecycleAction
    );
    assert_eq!(
        close_pending.write_requirement(),
        &StorageWriteRequirement::UpdateLockedRow(
            CoreStorageTarget::PendingCredentialLifecycleAction(id("pending-reset"))
        )
    );

    let create_subject_pending =
        CoreMutationStorageContract::for_mutation(&Mutation::CreatePendingSubjectLifecycleAction(
            PendingSubjectLifecycleActionRecord::new_open(
                id("pending-subject-deletion"),
                id("subject"),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject action"),
        ));
    assert_eq!(
        create_subject_pending.kind(),
        CoreMutationKind::CreatePendingSubjectLifecycleAction
    );
    assert_eq!(
        create_subject_pending.write_requirement(),
        &StorageWriteRequirement::InsertUnique(CoreStorageTarget::PendingSubjectLifecycleAction(
            id("pending-subject-deletion")
        ))
    );

    let close_subject_pending =
        CoreMutationStorageContract::for_mutation(&Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id: id("pending-subject-deletion"),
            closed_at: at(250),
        });
    assert_eq!(
        close_subject_pending.kind(),
        CoreMutationKind::ClosePendingSubjectLifecycleAction
    );
    assert_eq!(
        close_subject_pending.write_requirement(),
        &StorageWriteRequirement::UpdateLockedRow(
            CoreStorageTarget::PendingSubjectLifecycleAction(id("pending-subject-deletion"))
        )
    );

    let create_identifier_binding =
        CoreMutationStorageContract::for_mutation(&Mutation::CreateOutOfBandIdentifierBinding {
            record: OutOfBandIdentifierBindingRecord::new(
                VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    id("candidate-email-source"),
                ),
                id("subject"),
                "email_otp",
                OutOfBandIdentifierBindingLifecycleState::PendingActivation,
            )
            .expect("candidate identifier binding"),
            created_at: at(250),
        });
    assert_eq!(
        create_identifier_binding.kind(),
        CoreMutationKind::CreateOutOfBandIdentifierBinding
    );
    assert_eq!(
        create_identifier_binding.write_requirement(),
        &StorageWriteRequirement::InsertUnique(CoreStorageTarget::OutOfBandIdentifierBinding(id(
            "candidate-email-source"
        )))
    );

    let activate_identifier_binding = CoreMutationStorageContract::for_mutation(
        &Mutation::SetOutOfBandIdentifierBindingLifecycleState {
            source_id: id("candidate-email-source"),
            lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Active,
            updated_at: at(250),
        },
    );
    assert_eq!(
        activate_identifier_binding.kind(),
        CoreMutationKind::SetOutOfBandIdentifierBindingLifecycleState
    );
    assert_eq!(
        activate_identifier_binding.write_requirement(),
        &StorageWriteRequirement::UpdateLockedRow(CoreStorageTarget::OutOfBandIdentifierBinding(
            id("candidate-email-source")
        ))
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
