use super::*;

/// Storage adapter used by the runtime execution boundary.
///
/// Implementations must enforce the supplied storage contract and return only after the
/// atomic commit has durably succeeded. The returned targets are the fresh credential
/// secrets the adapter generated and stored as MACs during that same commit.
pub trait AtomicCommitAdapter {
    /// Adapter-specific commit error.
    type Error;

    /// Commits one reducer-planned atomic work item.
    fn commit_atomic_work(
        &mut self,
        request: AtomicCommitRequest<'_>,
    ) -> Result<Vec<MaterializedFreshCredentialSecret>, Self::Error>;
}

/// Atomic commit request passed to a storage adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicCommitRequest<'a> {
    atomic_work: &'a AtomicCommitWork,
    storage_contract: AtomicCommitStorageContract,
    planned_storage_boundary_contract: Option<PlannedStorageBoundaryContract>,
    method_commit_boundary_contract: MethodCommitBoundaryContract,
}

impl<'a> AtomicCommitRequest<'a> {
    pub(crate) fn for_atomic_work(atomic_work: &'a AtomicCommitWork) -> Result<Self, Error> {
        Self::new(atomic_work, None)
    }

    pub(crate) fn for_atomic_work_with_storage_boundary(
        atomic_work: &'a AtomicCommitWork,
        planned_storage_boundary_contract: PlannedStorageBoundaryContract,
    ) -> Result<Self, Error> {
        Self::new(atomic_work, Some(planned_storage_boundary_contract))
    }

    fn new(
        atomic_work: &'a AtomicCommitWork,
        planned_storage_boundary_contract: Option<PlannedStorageBoundaryContract>,
    ) -> Result<Self, Error> {
        let storage_contract = atomic_work.storage_contract()?;
        let method_commit_boundary_contract =
            MethodCommitBoundaryContract::for_atomic_commit_storage_contract(&storage_contract);
        Ok(Self {
            atomic_work,
            storage_contract,
            planned_storage_boundary_contract,
            method_commit_boundary_contract,
        })
    }

    /// Returns the reducer-planned atomic work to commit.
    pub fn atomic_work(&self) -> &AtomicCommitWork {
        self.atomic_work
    }

    /// Returns the concrete storage contract the adapter must enforce.
    pub fn storage_contract(&self) -> &AtomicCommitStorageContract {
        &self.storage_contract
    }

    /// Returns the runtime storage-boundary contract supplied by the facade.
    pub fn planned_storage_boundary_contract(&self) -> Option<&PlannedStorageBoundaryContract> {
        self.planned_storage_boundary_contract.as_ref()
    }

    /// Returns where method/plugin work is allowed inside the core atomic boundary.
    pub fn method_commit_boundary_contract(&self) -> &MethodCommitBoundaryContract {
        &self.method_commit_boundary_contract
    }
}

/// Error returned by runtime execution after a command has been planned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeAdapterExecutionError<E> {
    /// Core validation rejected the execution.
    Core(Error),
    /// The storage adapter failed to commit atomic work.
    AtomicCommit(E),
}

impl<E> RuntimeAdapterExecutionError<E> {
    pub(crate) fn core(error: Error) -> Self {
        Self::Core(error)
    }

    pub(crate) fn atomic_commit(error: E) -> Self {
        Self::AtomicCommit(error)
    }
}

/// End-to-end stage contract for a runtime adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAdapterPipelineContract {
    stages: Vec<RuntimeAdapterPipelineStage>,
}

impl RuntimeAdapterPipelineContract {
    /// Returns the pre-reduction stages for a prepared command.
    pub fn for_prepared_command(_prepared: &PreparedCommandExecution) -> Self {
        Self {
            stages: vec![
                RuntimeAdapterPipelineStage::DecodePresentedCookies,
                RuntimeAdapterPipelineStage::DeriveLoadedStateContract,
                RuntimeAdapterPipelineStage::LoadState,
                RuntimeAdapterPipelineStage::ValidateLoadedState,
                RuntimeAdapterPipelineStage::ReduceCommand,
            ],
        }
    }

    /// Returns the post-reduction stages for a planned command.
    pub fn for_planned_execution(planned: &PlannedCommandExecution) -> Result<Self, Error> {
        let atomic_work = planned.atomic_commit_work();
        let mut stages = Vec::new();
        if !atomic_work.is_empty() {
            atomic_work.storage_contract()?;
            stages.push(RuntimeAdapterPipelineStage::BuildStorageContract);
            if !atomic_work.fresh_credential_secrets.is_empty() {
                stages.push(RuntimeAdapterPipelineStage::MaterializeFreshCredentialSecrets);
            }
            stages.push(RuntimeAdapterPipelineStage::CommitAtomicStorageWork);
        }
        stages.push(RuntimeAdapterPipelineStage::MaterializeResponseEffects);
        stages.push(RuntimeAdapterPipelineStage::ReleaseResponseEffects);
        Ok(Self { stages })
    }

    /// Returns the ordered runtime adapter stages.
    pub fn stages(&self) -> &[RuntimeAdapterPipelineStage] {
        &self.stages
    }
}

/// One runtime adapter stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeAdapterPipelineStage {
    /// Decode request cookies into `PresentedAuthCookies`.
    DecodePresentedCookies,
    /// Build the command's loaded-state contract from command and decoded cookies.
    DeriveLoadedStateContract,
    /// Load and classify exactly the state required by the loaded-state contract.
    LoadState,
    /// Validate the loaded state against the contract before reducing.
    ValidateLoadedState,
    /// Run the reducer and split atomic work from response effects.
    ReduceCommand,
    /// Build the concrete storage contract for atomic work.
    BuildStorageContract,
    /// Generate fresh credential secrets and store only MACs inside the transaction.
    MaterializeFreshCredentialSecrets,
    /// Commit storage work atomically.
    CommitAtomicStorageWork,
    /// Combine response drafts with committed or presented credential secrets.
    MaterializeResponseEffects,
    /// Release materialized response effects after required atomic work has succeeded.
    ReleaseResponseEffects,
}

/// Fresh credential secrets materialized during one atomic commit.
#[derive(Debug, Default)]
pub struct MaterializedFreshCredentialSecrets {
    materialized: Vec<MaterializedFreshCredentialSecret>,
    targets: Vec<CoreStorageTarget>,
}

impl MaterializedFreshCredentialSecrets {
    /// Creates materialized secret evidence for an atomic work item.
    pub(crate) fn for_atomic_work(
        work: &AtomicCommitWork,
        materialized: Vec<MaterializedFreshCredentialSecret>,
    ) -> Result<Self, Error> {
        work.validate_for_commit()?;
        let targets = materialized
            .iter()
            .map(|secret| secret.target().clone())
            .collect::<Vec<_>>();
        validate_materialized_fresh_credential_targets(work, &targets)?;
        Ok(Self {
            materialized,
            targets,
        })
    }

    /// Returns materialized fresh credential-secret targets.
    pub fn targets(&self) -> &[CoreStorageTarget] {
        &self.targets
    }

    /// Returns materialized fresh credential secrets.
    pub fn materialized(&self) -> &[MaterializedFreshCredentialSecret] {
        &self.materialized
    }

    pub(crate) fn take_secret_for_target(
        &mut self,
        target: &CoreStorageTarget,
    ) -> Option<AuthCredentialSecret> {
        let index = self
            .materialized
            .iter()
            .position(|materialized| materialized.target() == target)?;
        Some(self.materialized.remove(index).into_secret())
    }
}

/// Successful commit evidence for one reducer-planned atomic work item.
#[derive(Debug)]
pub struct AtomicCommitSuccess {
    storage_contract: AtomicCommitStorageContract,
    materialized_fresh_credential_secrets: MaterializedFreshCredentialSecrets,
}

impl AtomicCommitSuccess {
    /// Creates successful commit evidence for the exact atomic work committed.
    pub(crate) fn for_atomic_work(
        work: &AtomicCommitWork,
        materialized_fresh_credential_secrets: MaterializedFreshCredentialSecrets,
    ) -> Result<Self, Error> {
        validate_materialized_fresh_credential_targets(
            work,
            materialized_fresh_credential_secrets.targets(),
        )?;
        Ok(Self {
            storage_contract: work.storage_contract()?,
            materialized_fresh_credential_secrets,
        })
    }

    /// Returns the committed storage contract.
    pub fn storage_contract(&self) -> &AtomicCommitStorageContract {
        &self.storage_contract
    }

    /// Returns fresh credential-secret targets materialized during the commit.
    pub fn materialized_fresh_credential_secrets(&self) -> &MaterializedFreshCredentialSecrets {
        &self.materialized_fresh_credential_secrets
    }

    pub(crate) fn into_materialized_fresh_credential_secrets(
        self,
    ) -> MaterializedFreshCredentialSecrets {
        self.materialized_fresh_credential_secrets
    }
}

/// Fresh credential secret generated and MAC-stored by an atomic commit adapter.
#[derive(Debug)]
pub struct MaterializedFreshCredentialSecret {
    target: CoreStorageTarget,
    secret: AuthCredentialSecret,
}

impl MaterializedFreshCredentialSecret {
    /// Creates a materialized fresh credential secret.
    pub fn new(target: CoreStorageTarget, secret: AuthCredentialSecret) -> Self {
        Self { target, secret }
    }

    /// Returns the storage target whose MAC was committed for this secret.
    pub fn target(&self) -> &CoreStorageTarget {
        &self.target
    }

    /// Returns the generated credential secret.
    pub fn secret(&self) -> &AuthCredentialSecret {
        &self.secret
    }

    fn into_secret(self) -> AuthCredentialSecret {
        self.secret
    }
}

fn validate_materialized_fresh_credential_targets(
    work: &AtomicCommitWork,
    materialized_targets: &[CoreStorageTarget],
) -> Result<(), Error> {
    let expected_targets = expected_fresh_credential_secret_targets(work)?;
    let mut seen = Vec::with_capacity(materialized_targets.len());
    for target in materialized_targets {
        if seen.contains(target) {
            return Err(Error::DuplicateMaterializedFreshCredentialSecret);
        }
        seen.push(target.clone());
        if !expected_targets.contains(target) {
            return Err(Error::UnexpectedMaterializedFreshCredentialSecret);
        }
    }
    for expected_target in expected_targets {
        if !materialized_targets.contains(&expected_target) {
            return Err(Error::MissingMaterializedFreshCredentialSecret);
        }
    }
    Ok(())
}

fn expected_fresh_credential_secret_targets(
    work: &AtomicCommitWork,
) -> Result<Vec<CoreStorageTarget>, Error> {
    Ok(work
        .storage_contract()?
        .fresh_credential_secrets()
        .iter()
        .map(|secret| secret.target().clone())
        .collect())
}
