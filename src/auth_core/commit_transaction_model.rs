use super::prelude::*;

/// Ordered transaction contract for committing reducer-planned atomic work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicCommitTransactionContract {
    stages: Vec<AtomicCommitTransactionStage>,
}

impl AtomicCommitTransactionContract {
    /// Builds the storage transaction contract for validated atomic work.
    pub fn for_atomic_work(work: &AtomicCommitWork) -> Result<Self, Error> {
        work.validate_for_commit()?;
        let mut stages = vec![AtomicCommitTransactionStage::ValidateAtomicWork];
        if !work.is_empty() {
            stages.push(AtomicCommitTransactionStage::BeginTransaction);
            if !work.preconditions.is_empty() {
                stages.push(AtomicCommitTransactionStage::EnforceCorePreconditions);
            }
            if work
                .method_commit_work
                .iter()
                .any(|method_work| !method_work.preconditions().is_empty())
            {
                stages.push(AtomicCommitTransactionStage::EnforceMethodPreconditions);
            }
            if !work.fresh_credential_secrets.is_empty() {
                stages.push(AtomicCommitTransactionStage::MaterializeFreshCredentialSecrets);
            }
            if !work.mutations.is_empty() {
                stages.push(AtomicCommitTransactionStage::ApplyCoreMutations);
            }
            if work
                .method_commit_work
                .iter()
                .any(|method_work| !method_work.mutations().is_empty())
            {
                stages.push(AtomicCommitTransactionStage::ApplyMethodMutations);
            }
            if !work.audit_events.is_empty() {
                stages.push(AtomicCommitTransactionStage::CommitAuditEvents);
            }
            if !work.durable_effects.is_empty() {
                stages.push(AtomicCommitTransactionStage::CommitCoreDurableEffectCommands);
            }
            if work
                .method_commit_work
                .iter()
                .any(|method_work| !method_work.durable_effect_commands().is_empty())
            {
                stages.push(AtomicCommitTransactionStage::CommitMethodDurableEffectCommands);
            }
            stages.push(AtomicCommitTransactionStage::CommitTransaction);
        }
        Ok(Self { stages })
    }

    /// Returns ordered transaction stages.
    pub fn stages(&self) -> &[AtomicCommitTransactionStage] {
        &self.stages
    }
}

/// Ordered storage transaction stage for `AtomicCommitWork`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AtomicCommitTransactionStage {
    /// Validate internal atomic-work consistency before opening a transaction.
    ValidateAtomicWork,
    /// Begin one storage transaction.
    BeginTransaction,
    /// Enforce all reducer preconditions in the same transaction as mutations.
    EnforceCorePreconditions,
    /// Enforce method/plugin preconditions before any mutation is applied.
    EnforceMethodPreconditions,
    /// Generate credential secrets and store only their MACs.
    MaterializeFreshCredentialSecrets,
    /// Apply core state mutations.
    ApplyCoreMutations,
    /// Apply method/plugin-owned mutations inside the same transaction.
    ApplyMethodMutations,
    /// Commit audit events inside the same transaction.
    CommitAuditEvents,
    /// Persist durable effect commands inside the same transaction before delivery.
    CommitCoreDurableEffectCommands,
    /// Persist method/plugin durable effect commands inside the same transaction.
    CommitMethodDurableEffectCommands,
    /// Commit the storage transaction.
    CommitTransaction,
}
