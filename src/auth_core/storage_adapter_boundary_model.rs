use super::*;

/// Storage-boundary contract before a command is reduced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedStorageBoundaryContract {
    stages: Vec<PreparedStorageBoundaryStage>,
    boundary_before_reduce: StorageBoundaryBeforeReduce,
}

impl PreparedStorageBoundaryContract {
    /// Builds the storage-boundary contract for an already-derived loaded-state contract.
    pub fn for_loaded_state_contract(loaded_state_contract: &CommandLoadedStateContract) -> Self {
        let mut stages = vec![PreparedStorageBoundaryStage::DeriveLoadedStateContract];
        let boundary_before_reduce = if loaded_state_contract
            .required()
            .iter()
            .any(loaded_state_requirement_requires_authoritative_storage)
        {
            stages.push(PreparedStorageBoundaryStage::OpenBeforeStateLoad);
            stages.push(PreparedStorageBoundaryStage::LoadAuthoritativeStateInsideOpenBoundary);
            StorageBoundaryBeforeReduce::OpenBeforeStateLoad
        } else {
            stages.push(PreparedStorageBoundaryStage::LoadNoAuthoritativeState);
            StorageBoundaryBeforeReduce::None
        };
        stages.push(PreparedStorageBoundaryStage::ValidateLoadedState);
        stages.push(PreparedStorageBoundaryStage::ReduceCommand);
        Self {
            stages,
            boundary_before_reduce,
        }
    }

    /// Builds the storage-boundary contract for a prepared command.
    pub fn for_prepared_command(prepared: &PreparedCommandExecution) -> Self {
        Self::for_loaded_state_contract(prepared.loaded_state_contract())
    }

    /// Returns ordered prepared-command storage-boundary stages.
    pub fn stages(&self) -> &[PreparedStorageBoundaryStage] {
        &self.stages
    }

    /// Returns whether a storage boundary must already be open before reduce.
    pub const fn boundary_before_reduce(&self) -> StorageBoundaryBeforeReduce {
        self.boundary_before_reduce
    }
}

/// Storage boundary state before reducing a command.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StorageBoundaryBeforeReduce {
    /// No authoritative state load is required before reduce.
    None,
    /// A storage boundary must be opened before state is loaded and kept alive.
    OpenBeforeStateLoad,
}

/// Ordered storage-boundary stage before reduce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PreparedStorageBoundaryStage {
    /// Derive the loaded-state contract from decoded cookies and command input.
    DeriveLoadedStateContract,
    /// No authoritative storage load is required before reduce.
    LoadNoAuthoritativeState,
    /// Open one storage boundary before any authoritative state load.
    OpenBeforeStateLoad,
    /// Load and classify state inside the open storage boundary.
    LoadAuthoritativeStateInsideOpenBoundary,
    /// Validate loaded state against the command's load contract.
    ValidateLoadedState,
    /// Reduce the command while the storage boundary remains available.
    ReduceCommand,
}

/// Storage-boundary contract after a command has been reduced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedStorageBoundaryContract {
    stages: Vec<PlannedStorageBoundaryStage>,
    atomic_commit_boundary: AtomicCommitBoundary,
}

impl PlannedStorageBoundaryContract {
    /// Builds the storage-boundary contract for planned command execution.
    pub fn for_planned_execution(
        prepared: &PreparedStorageBoundaryContract,
        planned: &PlannedCommandExecution,
    ) -> Result<Self, Error> {
        let atomic_work = planned.atomic_commit_work();
        let mut stages = Vec::new();
        let atomic_commit_boundary = if atomic_work.is_empty() {
            if prepared.boundary_before_reduce() == StorageBoundaryBeforeReduce::OpenBeforeStateLoad
            {
                stages.push(PlannedStorageBoundaryStage::CloseReadOnlyStorageBoundary);
            }
            AtomicCommitBoundary::None
        } else {
            atomic_work.storage_contract()?;
            stages.push(PlannedStorageBoundaryStage::BuildStorageContract);
            match prepared.boundary_before_reduce() {
                StorageBoundaryBeforeReduce::OpenBeforeStateLoad => {
                    stages.push(PlannedStorageBoundaryStage::CommitInsideLoadedStateBoundary);
                    AtomicCommitBoundary::LoadedStateBoundary
                }
                StorageBoundaryBeforeReduce::None => {
                    stages.push(PlannedStorageBoundaryStage::OpenCommitOnlyBoundary);
                    stages.push(PlannedStorageBoundaryStage::CommitInsideCommitOnlyBoundary);
                    AtomicCommitBoundary::CommitOnlyBoundary
                }
            }
        };
        stages.push(PlannedStorageBoundaryStage::MaterializeResponseEffects);
        stages.push(PlannedStorageBoundaryStage::ReleaseResponseEffects);
        Ok(Self {
            stages,
            atomic_commit_boundary,
        })
    }

    /// Returns ordered planned-command storage-boundary stages.
    pub fn stages(&self) -> &[PlannedStorageBoundaryStage] {
        &self.stages
    }

    /// Returns where atomic work must commit.
    pub const fn atomic_commit_boundary(&self) -> AtomicCommitBoundary {
        self.atomic_commit_boundary
    }
}

/// Storage boundary used for atomic commit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AtomicCommitBoundary {
    /// No atomic commit is required.
    None,
    /// Commit must happen in the same boundary opened before state load.
    LoadedStateBoundary,
    /// Commit may open a fresh boundary because no authoritative state was loaded.
    CommitOnlyBoundary,
}

/// Ordered storage-boundary stage after reduce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlannedStorageBoundaryStage {
    /// Close a read-only boundary opened for state loading when no commit is required.
    CloseReadOnlyStorageBoundary,
    /// Build and validate the concrete storage contract for atomic work.
    BuildStorageContract,
    /// Open a storage boundary only for commit work.
    OpenCommitOnlyBoundary,
    /// Commit atomic work in the boundary that loaded authoritative state.
    CommitInsideLoadedStateBoundary,
    /// Commit atomic work in a boundary opened only for commit work.
    CommitInsideCommitOnlyBoundary,
    /// Combine response drafts with committed or presented credential secrets.
    MaterializeResponseEffects,
    /// Release materialized response effects after storage is settled.
    ReleaseResponseEffects,
}

/// Method/plugin work placement inside a core-owned atomic commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitBoundaryContract {
    stages: Vec<MethodCommitBoundaryStage>,
}

impl MethodCommitBoundaryContract {
    /// Builds the method/plugin boundary contract from concrete atomic storage work.
    pub fn for_atomic_commit_storage_contract(contract: &AtomicCommitStorageContract) -> Self {
        let has_method_preconditions = contract.method_commit_work().iter().any(|method| {
            method
                .stages()
                .contains(&MethodCommitTransactionStage::EnforcePreconditions)
        });
        let has_method_mutations = contract.method_commit_work().iter().any(|method| {
            method
                .stages()
                .contains(&MethodCommitTransactionStage::ApplyMutations)
        });
        let has_method_durable_effects = contract.method_commit_work().iter().any(|method| {
            method
                .stages()
                .contains(&MethodCommitTransactionStage::CommitDurableEffectCommands)
        });
        let mut stages = Vec::new();
        if has_method_preconditions {
            stages.push(MethodCommitBoundaryStage::EnforceAfterCorePreconditions);
        }
        if has_method_mutations {
            stages.push(MethodCommitBoundaryStage::ApplyAfterCoreMutations);
        }
        if has_method_durable_effects {
            stages.push(MethodCommitBoundaryStage::PersistDurableCommandsBeforeCommit);
        }
        Self { stages }
    }

    /// Returns ordered method/plugin boundary stages.
    pub fn stages(&self) -> &[MethodCommitBoundaryStage] {
        &self.stages
    }
}

/// Where method/plugin work may run inside the core atomic boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodCommitBoundaryStage {
    /// Method preconditions run after core preconditions and before any mutations.
    EnforceAfterCorePreconditions,
    /// Method mutations run inside the same transaction after core mutations.
    ApplyAfterCoreMutations,
    /// Method durable effect commands are persisted before transaction commit.
    PersistDurableCommandsBeforeCommit,
}

fn loaded_state_requirement_requires_authoritative_storage(
    requirement: &LoadedStateRequirement,
) -> bool {
    !matches!(
        requirement,
        LoadedStateRequirement::PresentedSessionCookie { .. }
            | LoadedStateRequirement::PresentedTrustedDeviceCookie { .. }
    )
}
