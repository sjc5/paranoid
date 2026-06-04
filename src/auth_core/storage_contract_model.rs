use super::*;

const CORE_STORAGE_RECORD_KINDS: &[CoreStorageRecordKind] = &[
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
    CoreStorageRecordKind::LifecycleAuthoritySource,
    CoreStorageRecordKind::PendingCredentialLifecycleAction,
    CoreStorageRecordKind::PendingSubjectLifecycleAction,
    CoreStorageRecordKind::AuditEvent,
    CoreStorageRecordKind::CoreDurableEffectCommand,
];

/// Storage contract for the reducer-owned record families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreStorageSchemaContract;

impl CoreStorageSchemaContract {
    /// Returns every core-owned record family an adapter must persist.
    pub const fn record_kinds() -> &'static [CoreStorageRecordKind] {
        CORE_STORAGE_RECORD_KINDS
    }
}

/// Core-owned record family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoreStorageRecordKind {
    /// Authoritative session record.
    Session,
    /// MAC of a session credential secret.
    SessionCredentialSecret,
    /// Authoritative trusted-device credential record.
    TrustedDeviceCredential,
    /// MAC of a trusted-device credential secret.
    TrustedDeviceCredentialSecret,
    /// Active proof attempt record.
    ActiveProofAttempt,
    /// MAC of an active-proof attempt continuation secret.
    ActiveProofContinuationSecret,
    /// Active proof challenge record.
    ActiveProofChallenge,
    /// Per-subject auth state, including the subject-wide revocation cutoff.
    SubjectAuthState,
    /// Core-visible credential-instance lifecycle metadata.
    CredentialInstance,
    /// Credential lifecycle recovery-authority edge.
    CredentialRecoveryAuthority,
    /// Mapping from a lifecycle evidence source to an effective recovery authority.
    LifecycleAuthoritySource,
    /// Delayed credential lifecycle action.
    PendingCredentialLifecycleAction,
    /// Delayed subject lifecycle action.
    PendingSubjectLifecycleAction,
    /// Immutable audit event.
    AuditEvent,
    /// Durable command to deliver a core-owned external effect after commit.
    CoreDurableEffectCommand,
}

/// Concrete storage contract for one reducer-planned atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicCommitStorageContract {
    transaction_contract: AtomicCommitTransactionContract,
    preconditions: Vec<CorePreconditionStorageContract>,
    fresh_credential_secrets: Vec<FreshCredentialSecretStorageContract>,
    mutations: Vec<CoreMutationStorageContract>,
    method_commit_work: Vec<MethodCommitTransactionContract>,
    audit_event_count: usize,
    core_durable_effect_command_count: usize,
}

impl AtomicCommitStorageContract {
    /// Builds the concrete storage contract for reducer-planned atomic work.
    pub fn for_atomic_work(work: &AtomicCommitWork) -> Result<Self, Error> {
        work.validate_for_commit()?;
        Ok(Self {
            transaction_contract: work.transaction_contract()?,
            preconditions: work
                .preconditions
                .iter()
                .map(CorePreconditionStorageContract::for_precondition)
                .collect(),
            fresh_credential_secrets: work
                .fresh_credential_secrets
                .iter()
                .map(FreshCredentialSecretStorageContract::for_fresh_credential_secret)
                .collect(),
            mutations: work
                .mutations
                .iter()
                .map(CoreMutationStorageContract::for_mutation)
                .collect(),
            method_commit_work: work
                .method_commit_work
                .iter()
                .map(MethodCommitTransactionContract::for_method_work)
                .collect::<Result<Vec<_>, _>>()?,
            audit_event_count: work.audit_events.len(),
            core_durable_effect_command_count: work.durable_effects.len(),
        })
    }

    /// Returns the ordered transaction contract.
    pub fn transaction_contract(&self) -> &AtomicCommitTransactionContract {
        &self.transaction_contract
    }

    /// Returns core precondition storage contracts.
    pub fn preconditions(&self) -> &[CorePreconditionStorageContract] {
        &self.preconditions
    }

    /// Returns fresh credential-secret storage contracts.
    pub fn fresh_credential_secrets(&self) -> &[FreshCredentialSecretStorageContract] {
        &self.fresh_credential_secrets
    }

    /// Returns core mutation storage contracts.
    pub fn mutations(&self) -> &[CoreMutationStorageContract] {
        &self.mutations
    }

    /// Returns method-owned commit-work transaction contracts.
    pub fn method_commit_work(&self) -> &[MethodCommitTransactionContract] {
        &self.method_commit_work
    }

    /// Returns how many audit events must be appended inside the transaction.
    pub const fn audit_event_count(&self) -> usize {
        self.audit_event_count
    }

    /// Returns how many core durable effect commands must be appended inside the transaction.
    pub const fn core_durable_effect_command_count(&self) -> usize {
        self.core_durable_effect_command_count
    }
}

/// Storage contract for one core precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorePreconditionStorageContract {
    kind: CorePreconditionKind,
    lock_requirements: Vec<StorageLockRequirement>,
    validation_requirements: Vec<StorageValidationRequirement>,
}

impl CorePreconditionStorageContract {
    /// Builds the storage contract for one reducer precondition.
    pub fn for_precondition(precondition: &Precondition) -> Self {
        match precondition {
            Precondition::SessionStillMatches {
                session_id,
                subject_id,
                ..
            } => Self {
                kind: CorePreconditionKind::SessionStillMatches,
                lock_requirements: vec![
                    StorageLockRequirement::LockExistingRowForUpdate(CoreStorageTarget::Session(
                        session_id.clone(),
                    )),
                    StorageLockRequirement::MaterializeSubjectAuthStateThenLockForUpdate {
                        subject_id: subject_id.clone(),
                    },
                ],
                validation_requirements: vec![
                    StorageValidationRequirement::SessionStillLiveAndMatchesObservedVersion,
                    StorageValidationRequirement::SubjectAuthStateDoesNotInvalidateRecord,
                ],
            },
            Precondition::TrustedDeviceStillMatches {
                device_credential_id,
                subject_id,
                ..
            } => Self {
                kind: CorePreconditionKind::TrustedDeviceStillMatches,
                lock_requirements: vec![
                    StorageLockRequirement::LockExistingRowForUpdate(
                        CoreStorageTarget::TrustedDeviceCredential(device_credential_id.clone()),
                    ),
                    StorageLockRequirement::MaterializeSubjectAuthStateThenLockForUpdate {
                        subject_id: subject_id.clone(),
                    },
                ],
                validation_requirements: vec![
                    StorageValidationRequirement::TrustedDeviceStillLiveAndMatchesObservedVersion,
                    StorageValidationRequirement::SubjectAuthStateDoesNotInvalidateRecord,
                ],
            },
            Precondition::SessionBelongsToSubject { session_id, .. } => Self {
                kind: CorePreconditionKind::SessionBelongsToSubject,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::Session(session_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::SessionBelongsToSubject,
                ],
            },
            Precondition::TrustedDeviceBelongsToSubject {
                device_credential_id,
                ..
            } => Self {
                kind: CorePreconditionKind::TrustedDeviceBelongsToSubject,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::TrustedDeviceCredential(device_credential_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::TrustedDeviceBelongsToSubject,
                ],
            },
            Precondition::ActiveProofAttemptStillOpen {
                attempt_id,
                subject_id_for_revocation,
                ..
            } => {
                let mut lock_requirements = vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::ActiveProofAttempt(attempt_id.clone()),
                )];
                let mut validation_requirements =
                    vec![StorageValidationRequirement::ActiveProofAttemptOpenSnapshotMatches];
                if let Some(subject_id) = subject_id_for_revocation {
                    lock_requirements.push(
                        StorageLockRequirement::MaterializeSubjectAuthStateThenLockForUpdate {
                            subject_id: subject_id.clone(),
                        },
                    );
                    validation_requirements.push(
                        StorageValidationRequirement::SubjectAuthStateDoesNotInvalidateRecord,
                    );
                }
                Self {
                    kind: CorePreconditionKind::ActiveProofAttemptStillOpen,
                    lock_requirements,
                    validation_requirements,
                }
            }
            Precondition::ActiveProofChallengeStillOpen { challenge_id, .. } => Self {
                kind: CorePreconditionKind::ActiveProofChallengeStillOpen,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::ActiveProofChallenge(challenge_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::ActiveProofChallengeOpen,
                ],
            },
            Precondition::OutOfBandChallengeResendStillAllowed { challenge_id, .. } => Self {
                kind: CorePreconditionKind::OutOfBandChallengeResendStillAllowed,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::ActiveProofChallenge(challenge_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::OutOfBandChallengeResendStateMatches,
                ],
            },
            Precondition::NoOpenOutOfBandChallengeForDedupeKey {
                challenge_dedupe_key,
                ..
            } => Self {
                kind: CorePreconditionKind::NoOpenOutOfBandChallengeForDedupeKey,
                lock_requirements: vec![
                    StorageLockRequirement::EnforceOpenOutOfBandChallengeDedupeUniqueness {
                        challenge_dedupe_key: challenge_dedupe_key.clone(),
                    },
                ],
                validation_requirements: vec![
                    StorageValidationRequirement::NoOpenOutOfBandChallengeForDedupeKey,
                ],
            },
            Precondition::CredentialInstanceStillActive {
                credential_instance_id,
                ..
            } => Self {
                kind: CorePreconditionKind::CredentialInstanceStillActive,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::CredentialInstance(credential_instance_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::CredentialInstanceStillActive,
                ],
            },
            Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
                target_credential_instance_id,
                action,
                ..
            } => Self {
                kind: CorePreconditionKind::NoOpenPendingCredentialLifecycleActionForTarget,
                lock_requirements: vec![
                    StorageLockRequirement::EnforceOpenPendingCredentialLifecycleActionUniqueness {
                        target_credential_instance_id: target_credential_instance_id.clone(),
                        action: *action,
                    },
                ],
                validation_requirements: vec![
                    StorageValidationRequirement::NoOpenPendingCredentialLifecycleActionForTarget,
                ],
            },
            Precondition::PendingCredentialLifecycleActionStillExecutable {
                pending_action_id,
                ..
            } => Self {
                kind: CorePreconditionKind::PendingCredentialLifecycleActionStillExecutable,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::PendingCredentialLifecycleAction(pending_action_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::PendingCredentialLifecycleActionStillExecutable,
                ],
            },
            Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
                pending_action_id,
                ..
            } => Self {
                kind: CorePreconditionKind::PendingCredentialLifecycleActionStillCancellableForTarget,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::PendingCredentialLifecycleAction(pending_action_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::PendingCredentialLifecycleActionStillCancellableForTarget,
                ],
            },
            Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
                subject_id,
                action,
                ..
            } => Self {
                kind: CorePreconditionKind::NoOpenPendingSubjectLifecycleActionForSubject,
                lock_requirements: vec![
                    StorageLockRequirement::EnforceOpenPendingSubjectLifecycleActionUniqueness {
                        subject_id: subject_id.clone(),
                        action: *action,
                    },
                ],
                validation_requirements: vec![
                    StorageValidationRequirement::NoOpenPendingSubjectLifecycleActionForSubject,
                ],
            },
            Precondition::PendingSubjectLifecycleActionStillExecutable {
                pending_action_id,
                ..
            } => Self {
                kind: CorePreconditionKind::PendingSubjectLifecycleActionStillExecutable,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::PendingSubjectLifecycleAction(pending_action_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::PendingSubjectLifecycleActionStillExecutable,
                ],
            },
            Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
                pending_action_id,
                ..
            } => Self {
                kind: CorePreconditionKind::PendingSubjectLifecycleActionStillCancellableForSubject,
                lock_requirements: vec![StorageLockRequirement::LockExistingRowForUpdate(
                    CoreStorageTarget::PendingSubjectLifecycleAction(pending_action_id.clone()),
                )],
                validation_requirements: vec![
                    StorageValidationRequirement::PendingSubjectLifecycleActionStillCancellableForSubject,
                ],
            },
        }
    }

    /// Returns the precondition kind.
    pub const fn kind(&self) -> CorePreconditionKind {
        self.kind
    }

    /// Returns row, materialization, or uniqueness locks required by this precondition.
    pub fn lock_requirements(&self) -> &[StorageLockRequirement] {
        &self.lock_requirements
    }

    /// Returns values the adapter must validate while holding required locks.
    pub fn validation_requirements(&self) -> &[StorageValidationRequirement] {
        &self.validation_requirements
    }
}

/// Storage contract for one core mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreMutationStorageContract {
    kind: CoreMutationKind,
    write_requirement: StorageWriteRequirement,
}

impl CoreMutationStorageContract {
    /// Builds the storage contract for one reducer mutation.
    pub fn for_mutation(mutation: &Mutation) -> Self {
        match mutation {
            Mutation::CreateSession(session) => Self {
                kind: CoreMutationKind::CreateSession,
                write_requirement: StorageWriteRequirement::InsertUnique(
                    CoreStorageTarget::Session(session.session_id.clone()),
                ),
            },
            Mutation::RefreshSession { session_id, .. } => Self {
                kind: CoreMutationKind::RefreshSession,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::Session(session_id.clone()),
                ),
            },
            Mutation::RecordStepUp { session_id, .. } => Self {
                kind: CoreMutationKind::RecordStepUp,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::Session(session_id.clone()),
                ),
            },
            Mutation::CreateTrustedDeviceCredential(trusted_device) => Self {
                kind: CoreMutationKind::CreateTrustedDeviceCredential,
                write_requirement: StorageWriteRequirement::InsertUnique(
                    CoreStorageTarget::TrustedDeviceCredential(
                        trusted_device.device_credential_id.clone(),
                    ),
                ),
            },
            Mutation::CreateActiveProofAttempt(attempt) => Self {
                kind: CoreMutationKind::CreateActiveProofAttempt,
                write_requirement: StorageWriteRequirement::InsertUnique(
                    CoreStorageTarget::ActiveProofAttempt(attempt.attempt_id.clone()),
                ),
            },
            Mutation::CreateActiveProofChallenge(challenge) => Self {
                kind: CoreMutationKind::CreateActiveProofChallenge,
                write_requirement: StorageWriteRequirement::InsertUnique(
                    CoreStorageTarget::ActiveProofChallenge(challenge.challenge_id.clone()),
                ),
            },
            Mutation::RecordWeakProofFailure { attempt_id, .. } => Self {
                kind: CoreMutationKind::RecordWeakProofFailure,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::ActiveProofAttempt(attempt_id.clone()),
                ),
            },
            Mutation::RecordActiveProofSucceeded { attempt_id, .. } => Self {
                kind: CoreMutationKind::RecordActiveProofSucceeded,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::ActiveProofAttempt(attempt_id.clone()),
                ),
            },
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
                attempt_id,
                proof_family,
                ..
            } => Self {
                kind: CoreMutationKind::CloseOpenActiveProofChallengesForAttemptProofFamily,
                write_requirement: StorageWriteRequirement::UpdateLockedRowsMatching(
                    CoreStorageTarget::ActiveProofChallengesForAttemptProofFamily {
                        attempt_id: attempt_id.clone(),
                        proof_family: *proof_family,
                    },
                ),
            },
            Mutation::RecordOutOfBandChallengeResent { challenge_id, .. } => Self {
                kind: CoreMutationKind::RecordOutOfBandChallengeResent,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::ActiveProofChallenge(challenge_id.clone()),
                ),
            },
            Mutation::DeleteActiveProofAttempt { attempt_id } => Self {
                kind: CoreMutationKind::DeleteActiveProofAttempt,
                write_requirement: StorageWriteRequirement::HardDeleteLockedRow {
                    target: CoreStorageTarget::ActiveProofAttempt(attempt_id.clone()),
                    cascades_to_record_kinds: vec![
                        CoreStorageRecordKind::ActiveProofContinuationSecret,
                        CoreStorageRecordKind::ActiveProofChallenge,
                    ],
                },
            },
            Mutation::RotateTrustedDeviceCredential {
                device_credential_id,
                ..
            } => Self {
                kind: CoreMutationKind::RotateTrustedDeviceCredential,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::TrustedDeviceCredential(device_credential_id.clone()),
                ),
            },
            Mutation::RevokeSession { session_id, .. } => Self {
                kind: CoreMutationKind::RevokeSession,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::Session(session_id.clone()),
                ),
            },
            Mutation::RevokeTrustedDeviceCredential {
                device_credential_id,
                ..
            } => Self {
                kind: CoreMutationKind::RevokeTrustedDeviceCredential,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::TrustedDeviceCredential(device_credential_id.clone()),
                ),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff { subject_id, .. } => Self {
                kind: CoreMutationKind::RaiseSubjectAuthRevocationCutoff,
                write_requirement:
                    StorageWriteRequirement::MonotonicUpsertSubjectAuthRevocationCutoff {
                        subject_id: subject_id.clone(),
                    },
            },
            Mutation::RecordCredentialLifecycleActionAuthorized {
                target_credential_instance_id,
                ..
            } => Self {
                kind: CoreMutationKind::RecordCredentialLifecycleActionAuthorized,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::CredentialInstance(target_credential_instance_id.clone()),
                ),
            },
            Mutation::CreatePendingCredentialLifecycleAction(record) => Self {
                kind: CoreMutationKind::CreatePendingCredentialLifecycleAction,
                write_requirement: StorageWriteRequirement::InsertUnique(
                    CoreStorageTarget::PendingCredentialLifecycleAction(
                        record.pending_action_id.clone(),
                    ),
                ),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id,
                ..
            } => Self {
                kind: CoreMutationKind::RecordCredentialLifecycleActionExecuted,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::CredentialInstance(target_credential_instance_id.clone()),
                ),
            },
            Mutation::SetCredentialLifecycleState {
                credential_instance_id,
                ..
            } => Self {
                kind: CoreMutationKind::SetCredentialLifecycleState,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::CredentialInstance(credential_instance_id.clone()),
                ),
            },
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id, ..
            } => Self {
                kind: CoreMutationKind::ClosePendingCredentialLifecycleAction,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::PendingCredentialLifecycleAction(pending_action_id.clone()),
                ),
            },
            Mutation::CreatePendingSubjectLifecycleAction(record) => Self {
                kind: CoreMutationKind::CreatePendingSubjectLifecycleAction,
                write_requirement: StorageWriteRequirement::InsertUnique(
                    CoreStorageTarget::PendingSubjectLifecycleAction(
                        record.pending_action_id.clone(),
                    ),
                ),
            },
            Mutation::ClosePendingSubjectLifecycleAction {
                pending_action_id, ..
            } => Self {
                kind: CoreMutationKind::ClosePendingSubjectLifecycleAction,
                write_requirement: StorageWriteRequirement::UpdateLockedRow(
                    CoreStorageTarget::PendingSubjectLifecycleAction(pending_action_id.clone()),
                ),
            },
        }
    }

    /// Returns the mutation kind.
    pub const fn kind(&self) -> CoreMutationKind {
        self.kind
    }

    /// Returns the required storage write.
    pub fn write_requirement(&self) -> &StorageWriteRequirement {
        &self.write_requirement
    }
}

/// Storage contract for fresh credential-secret materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshCredentialSecretStorageContract {
    target: CoreStorageTarget,
}

impl FreshCredentialSecretStorageContract {
    /// Builds the storage contract for one fresh credential secret.
    pub fn for_fresh_credential_secret(fresh_secret: &FreshCredentialSecret) -> Self {
        let target = match fresh_secret {
            FreshCredentialSecret::Session {
                session_id,
                secret_version,
            } => CoreStorageTarget::SessionCredentialSecret {
                session_id: session_id.clone(),
                secret_version: *secret_version,
            },
            FreshCredentialSecret::TrustedDevice {
                device_credential_id,
                secret_version,
            } => CoreStorageTarget::TrustedDeviceCredentialSecret {
                device_credential_id: device_credential_id.clone(),
                secret_version: *secret_version,
            },
            FreshCredentialSecret::ActiveProofContinuation { attempt_id } => {
                CoreStorageTarget::ActiveProofContinuationSecret {
                    attempt_id: attempt_id.clone(),
                }
            }
        };
        Self { target }
    }

    /// Returns where the adapter must store a MAC of the fresh secret.
    pub fn target(&self) -> &CoreStorageTarget {
        &self.target
    }

    /// Returns the required secret write behavior.
    pub const fn write_requirement(&self) -> FreshCredentialSecretWriteRequirement {
        FreshCredentialSecretWriteRequirement::GenerateFreshSecretAndStoreMacOnly
    }
}

/// Core precondition kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CorePreconditionKind {
    /// Session still matches the loaded live row.
    SessionStillMatches,
    /// Trusted device still matches the loaded live row.
    TrustedDeviceStillMatches,
    /// Session belongs to the subject.
    SessionBelongsToSubject,
    /// Trusted device belongs to the subject.
    TrustedDeviceBelongsToSubject,
    /// Active-proof attempt still matches the loaded open row.
    ActiveProofAttemptStillOpen,
    /// Active-proof challenge still matches the loaded open row.
    ActiveProofChallengeStillOpen,
    /// Out-of-band resend budget and idempotency state still match.
    OutOfBandChallengeResendStillAllowed,
    /// No open out-of-band challenge exists for the dedupe key.
    NoOpenOutOfBandChallengeForDedupeKey,
    /// Credential instance is still active.
    CredentialInstanceStillActive,
    /// No open pending credential lifecycle action exists for the target/action pair.
    NoOpenPendingCredentialLifecycleActionForTarget,
    /// Pending credential lifecycle action is still open, mature, unexpired, and target-matched.
    PendingCredentialLifecycleActionStillExecutable,
    /// Pending credential lifecycle action is still open, unexpired, and target-matched.
    PendingCredentialLifecycleActionStillCancellableForTarget,
    /// No open pending subject lifecycle action exists for the subject/action pair.
    NoOpenPendingSubjectLifecycleActionForSubject,
    /// Pending subject lifecycle action is still open, mature, unexpired, and subject-matched.
    PendingSubjectLifecycleActionStillExecutable,
    /// Pending subject lifecycle action is still open, unexpired, and subject-matched.
    PendingSubjectLifecycleActionStillCancellableForSubject,
}

/// Core mutation kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoreMutationKind {
    /// Create a session row.
    CreateSession,
    /// Refresh a session row.
    RefreshSession,
    /// Record step-up freshness on a session row.
    RecordStepUp,
    /// Create a trusted-device credential row.
    CreateTrustedDeviceCredential,
    /// Create an active-proof attempt row.
    CreateActiveProofAttempt,
    /// Create an active-proof challenge row.
    CreateActiveProofChallenge,
    /// Record one weak-proof failure.
    RecordWeakProofFailure,
    /// Record one satisfied active proof.
    RecordActiveProofSucceeded,
    /// Close open active-proof challenges for one attempt and proof family.
    CloseOpenActiveProofChallengesForAttemptProofFamily,
    /// Record one out-of-band resend.
    RecordOutOfBandChallengeResent,
    /// Hard-delete an active-proof attempt.
    DeleteActiveProofAttempt,
    /// Rotate a trusted-device credential.
    RotateTrustedDeviceCredential,
    /// Mark a session revoked.
    RevokeSession,
    /// Mark a trusted-device credential revoked.
    RevokeTrustedDeviceCredential,
    /// Raise the subject-wide auth revocation cutoff.
    RaiseSubjectAuthRevocationCutoff,
    /// Record an immediately authorized credential lifecycle action.
    RecordCredentialLifecycleActionAuthorized,
    /// Create a delayed credential lifecycle action.
    CreatePendingCredentialLifecycleAction,
    /// Record an executed credential lifecycle action.
    RecordCredentialLifecycleActionExecuted,
    /// Set a credential's core-visible lifecycle state.
    SetCredentialLifecycleState,
    /// Close a delayed credential lifecycle action.
    ClosePendingCredentialLifecycleAction,
    /// Create a delayed subject lifecycle action.
    CreatePendingSubjectLifecycleAction,
    /// Close a delayed subject lifecycle action.
    ClosePendingSubjectLifecycleAction,
}

/// Concrete storage target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreStorageTarget {
    /// One session row.
    Session(SessionId),
    /// One session credential secret MAC row.
    SessionCredentialSecret {
        /// Session id.
        session_id: SessionId,
        /// Secret version.
        secret_version: SecretVersion,
    },
    /// One trusted-device credential row.
    TrustedDeviceCredential(TrustedDeviceCredentialId),
    /// One trusted-device credential secret MAC row.
    TrustedDeviceCredentialSecret {
        /// Trusted-device credential id.
        device_credential_id: TrustedDeviceCredentialId,
        /// Secret version.
        secret_version: SecretVersion,
    },
    /// One active-proof attempt row.
    ActiveProofAttempt(ActiveProofAttemptId),
    /// One active-proof continuation secret MAC row.
    ActiveProofContinuationSecret {
        /// Active-proof attempt id.
        attempt_id: ActiveProofAttemptId,
    },
    /// One active-proof challenge row.
    ActiveProofChallenge(ActiveProofChallengeId),
    /// Open challenges for one attempt and proof family.
    ActiveProofChallengesForAttemptProofFamily {
        /// Attempt id.
        attempt_id: ActiveProofAttemptId,
        /// Proof family.
        proof_family: ProofFamily,
    },
    /// One subject auth-state row.
    SubjectAuthState(SubjectId),
    /// One credential-instance metadata row.
    CredentialInstance(VerifiedProofSourceId),
    /// Recovery-authority rows for one target credential.
    CredentialRecoveryAuthoritiesForCredential(VerifiedProofSourceId),
    /// One source-to-recovery-authority mapping row.
    LifecycleAuthoritySource {
        /// Source kind wire id.
        source_kind: LifecycleAuthoritySourceKind,
        /// Source id.
        source_id: VerifiedProofSourceId,
        /// Effective recovery authority id.
        authority_id: RecoveryAuthorityId,
    },
    /// One delayed credential lifecycle action.
    PendingCredentialLifecycleAction(PendingCredentialLifecycleActionId),
    /// One delayed subject lifecycle action.
    PendingSubjectLifecycleAction(PendingSubjectLifecycleActionId),
    /// Open pending credential lifecycle actions for one target/action pair.
    OpenPendingCredentialLifecycleActionForTarget {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
    },
    /// Open pending subject lifecycle actions for one subject/action pair.
    OpenPendingSubjectLifecycleActionForSubject {
        /// Subject targeted by the pending action.
        subject_id: SubjectId,
        /// Subject lifecycle action.
        action: SubjectLifecycleAction,
    },
    /// Open out-of-band challenge dedupe key.
    OpenOutOfBandChallengeDedupeKey(OutOfBandChallengeDedupeKey),
    /// Audit event append stream.
    AuditEvents,
    /// Core durable effect command append stream.
    CoreDurableEffectCommands,
}

impl CoreStorageTarget {
    /// Returns the storage record kind for this target.
    pub const fn record_kind(&self) -> CoreStorageRecordKind {
        match self {
            Self::Session(_) => CoreStorageRecordKind::Session,
            Self::SessionCredentialSecret { .. } => CoreStorageRecordKind::SessionCredentialSecret,
            Self::TrustedDeviceCredential(_) => CoreStorageRecordKind::TrustedDeviceCredential,
            Self::TrustedDeviceCredentialSecret { .. } => {
                CoreStorageRecordKind::TrustedDeviceCredentialSecret
            }
            Self::ActiveProofAttempt(_) => CoreStorageRecordKind::ActiveProofAttempt,
            Self::ActiveProofContinuationSecret { .. } => {
                CoreStorageRecordKind::ActiveProofContinuationSecret
            }
            Self::ActiveProofChallenge(_)
            | Self::ActiveProofChallengesForAttemptProofFamily { .. }
            | Self::OpenOutOfBandChallengeDedupeKey(_) => {
                CoreStorageRecordKind::ActiveProofChallenge
            }
            Self::SubjectAuthState(_) => CoreStorageRecordKind::SubjectAuthState,
            Self::CredentialInstance(_) => CoreStorageRecordKind::CredentialInstance,
            Self::CredentialRecoveryAuthoritiesForCredential(_) => {
                CoreStorageRecordKind::CredentialRecoveryAuthority
            }
            Self::LifecycleAuthoritySource { .. } => {
                CoreStorageRecordKind::LifecycleAuthoritySource
            }
            Self::PendingCredentialLifecycleAction(_)
            | Self::OpenPendingCredentialLifecycleActionForTarget { .. } => {
                CoreStorageRecordKind::PendingCredentialLifecycleAction
            }
            Self::PendingSubjectLifecycleAction(_)
            | Self::OpenPendingSubjectLifecycleActionForSubject { .. } => {
                CoreStorageRecordKind::PendingSubjectLifecycleAction
            }
            Self::AuditEvents => CoreStorageRecordKind::AuditEvent,
            Self::CoreDurableEffectCommands => CoreStorageRecordKind::CoreDurableEffectCommand,
        }
    }
}

/// Stored lifecycle evidence source kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleAuthoritySourceKind {
    /// A credential-instance proof source.
    CredentialInstance,
    /// An out-of-band identifier proof source.
    OutOfBandIdentifier,
    /// A federated or otherwise external authority proof source.
    ExternalAuthority,
    /// A live authenticated session.
    AuthenticatedSession,
    /// A Paranoid-shaped admin/support intervention.
    AdminSupportIntervention,
}

/// Lock or uniqueness requirement inside the atomic transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageLockRequirement {
    /// Lock an existing row for update.
    LockExistingRowForUpdate(CoreStorageTarget),
    /// Create the subject auth-state row if absent, then lock it for update.
    MaterializeSubjectAuthStateThenLockForUpdate {
        /// Subject id.
        subject_id: SubjectId,
    },
    /// Enforce open challenge uniqueness for a dedupe key.
    EnforceOpenOutOfBandChallengeDedupeUniqueness {
        /// Dedupe key.
        challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    },
    /// Enforce one open pending action for one target/action pair.
    EnforceOpenPendingCredentialLifecycleActionUniqueness {
        /// Target credential instance.
        target_credential_instance_id: VerifiedProofSourceId,
        /// Lifecycle action.
        action: CredentialLifecycleAction,
    },
    /// Enforce one open pending action for one subject/action pair.
    EnforceOpenPendingSubjectLifecycleActionUniqueness {
        /// Subject targeted by the pending action.
        subject_id: SubjectId,
        /// Subject lifecycle action.
        action: SubjectLifecycleAction,
    },
}

/// Value-level validation the adapter must perform while holding required locks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StorageValidationRequirement {
    /// Session row is live and still has the observed version and subject.
    SessionStillLiveAndMatchesObservedVersion,
    /// Trusted-device row is live and still has the observed version and subject.
    TrustedDeviceStillLiveAndMatchesObservedVersion,
    /// Session row is live and belongs to the subject.
    SessionBelongsToSubject,
    /// Trusted-device row is live and belongs to the subject.
    TrustedDeviceBelongsToSubject,
    /// Active-proof attempt is open and its loaded snapshot still matches.
    ActiveProofAttemptOpenSnapshotMatches,
    /// Active-proof challenge is open.
    ActiveProofChallengeOpen,
    /// Out-of-band resend count, idempotency keys, liveness, and budget still match.
    OutOfBandChallengeResendStateMatches,
    /// No open out-of-band challenge exists for the dedupe key.
    NoOpenOutOfBandChallengeForDedupeKey,
    /// Subject auth-state cutoff does not invalidate the record being committed.
    SubjectAuthStateDoesNotInvalidateRecord,
    /// Credential instance is active and owned by the expected subject.
    CredentialInstanceStillActive,
    /// No open pending credential lifecycle action exists for the target/action pair.
    NoOpenPendingCredentialLifecycleActionForTarget,
    /// Pending credential lifecycle action is still open, mature, unexpired, and target-matched.
    PendingCredentialLifecycleActionStillExecutable,
    /// Pending credential lifecycle action is still open, unexpired, and target-matched.
    PendingCredentialLifecycleActionStillCancellableForTarget,
    /// No open pending subject lifecycle action exists for the subject/action pair.
    NoOpenPendingSubjectLifecycleActionForSubject,
    /// Pending subject lifecycle action is still open, mature, unexpired, and subject-matched.
    PendingSubjectLifecycleActionStillExecutable,
    /// Pending subject lifecycle action is still open, unexpired, and subject-matched.
    PendingSubjectLifecycleActionStillCancellableForSubject,
}

/// Required storage write behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageWriteRequirement {
    /// Insert one row and reject duplicates.
    InsertUnique(CoreStorageTarget),
    /// Update one row that was locked earlier in the same transaction.
    UpdateLockedRow(CoreStorageTarget),
    /// Update every matching row using a statement that locks the affected rows.
    UpdateLockedRowsMatching(CoreStorageTarget),
    /// Hard-delete one row that was locked earlier in the same transaction.
    HardDeleteLockedRow {
        /// Row to delete.
        target: CoreStorageTarget,
        /// Child record families that must be deleted by cascade or equivalent same-transaction work.
        cascades_to_record_kinds: Vec<CoreStorageRecordKind>,
    },
    /// Materialize and update the subject auth-state row without moving the cutoff backward.
    MonotonicUpsertSubjectAuthRevocationCutoff {
        /// Subject id.
        subject_id: SubjectId,
    },
}

/// Required fresh credential-secret write behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FreshCredentialSecretWriteRequirement {
    /// Generate fresh secret bytes and store only a MAC for the target credential version.
    GenerateFreshSecretAndStoreMacOnly,
}

impl AtomicCommitWork {
    /// Returns the concrete storage contract for this atomic work.
    pub fn storage_contract(&self) -> Result<AtomicCommitStorageContract, Error> {
        AtomicCommitStorageContract::for_atomic_work(self)
    }
}
