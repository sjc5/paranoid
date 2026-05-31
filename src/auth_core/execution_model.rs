use super::*;

/// Command prepared for adapter execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCommandExecution {
    command: Command,
    presented_cookies: PresentedAuthCookies,
    loaded_state_contract: CommandLoadedStateContract,
}

impl PreparedCommandExecution {
    /// Builds the load contract for a command after cookies have been decoded.
    pub fn prepare(
        config: &Config,
        command: Command,
        presented_cookies: PresentedAuthCookies,
    ) -> Result<Self, Error> {
        let loaded_state_contract =
            CommandLoadedStateContract::for_command(config, &command, &presented_cookies)?;
        Ok(Self {
            command,
            presented_cookies,
            loaded_state_contract,
        })
    }

    /// Returns the command being executed.
    pub fn command(&self) -> &Command {
        &self.command
    }

    /// Returns the decoded cookies used to derive the load contract.
    pub fn presented_cookies(&self) -> &PresentedAuthCookies {
        &self.presented_cookies
    }

    /// Returns the loaded-state contract adapters must satisfy.
    pub fn loaded_state_contract(&self) -> &CommandLoadedStateContract {
        &self.loaded_state_contract
    }

    /// Returns the pre-reduction runtime adapter pipeline contract.
    pub fn runtime_pipeline_contract(&self) -> RuntimeAdapterPipelineContract {
        RuntimeAdapterPipelineContract::for_prepared_command(self)
    }

    /// Validates loaded state, reduces the command, and separates commit work from effects.
    pub fn reduce_loaded_state(
        self,
        config: &Config,
        loaded: &LoadedState,
    ) -> Result<PlannedCommandExecution, Error> {
        self.validate_loaded_cookies_match_presented(loaded)?;
        self.loaded_state_contract.validate_loaded_state(loaded)?;
        let transition = reduce_command(config, self.command, loaded)?;
        PlannedCommandExecution::from_transition(transition, self.presented_cookies)
    }

    fn validate_loaded_cookies_match_presented(&self, loaded: &LoadedState) -> Result<(), Error> {
        if loaded.session_cookie != self.presented_cookies.session_cookie {
            return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                "loaded session cookie differs from presented session cookie",
            ));
        }
        if loaded.trusted_device_cookie != self.presented_cookies.trusted_device_cookie {
            return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                "loaded trusted-device cookie differs from presented trusted-device cookie",
            ));
        }
        Ok(())
    }
}

/// Reduced command ready for adapter commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedCommandExecution {
    outcome: Outcome,
    presented_cookies: PresentedAuthCookies,
    atomic_commit_work: AtomicCommitWork,
    validated_response_effects: ValidatedResponseEffects,
}

impl PlannedCommandExecution {
    /// Validates a reducer transition and separates atomic work from response effects.
    pub(crate) fn from_transition(
        transition: Transition,
        presented_cookies: PresentedAuthCookies,
    ) -> Result<Self, Error> {
        let (atomic_commit_work, response_effects) = transition
            .commit_plan
            .try_into_validated_atomic_work_and_response_effects()?;
        Ok(Self {
            outcome: transition.outcome,
            presented_cookies,
            atomic_commit_work,
            validated_response_effects: ValidatedResponseEffects(response_effects),
        })
    }

    /// Returns the semantic reducer outcome.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Returns the decoded cookies used to derive this execution.
    pub fn presented_cookies(&self) -> &PresentedAuthCookies {
        &self.presented_cookies
    }

    /// Returns atomic work the adapter must commit before applying response effects.
    pub fn atomic_commit_work(&self) -> &AtomicCommitWork {
        &self.atomic_commit_work
    }

    /// Returns the ordered storage transaction contract for this planned execution.
    pub fn atomic_commit_transaction_contract(
        &self,
    ) -> Result<AtomicCommitTransactionContract, Error> {
        self.atomic_commit_work.transaction_contract()
    }

    /// Returns the concrete storage contract for the planned atomic work.
    pub fn atomic_commit_storage_contract(&self) -> Result<AtomicCommitStorageContract, Error> {
        self.atomic_commit_work.storage_contract()
    }

    /// Returns the post-reduction runtime adapter pipeline contract.
    pub fn runtime_pipeline_contract(&self) -> Result<RuntimeAdapterPipelineContract, Error> {
        RuntimeAdapterPipelineContract::for_planned_execution(self)
    }

    /// Commits required atomic work through an adapter, then releases response effects.
    pub fn complete_with_commit_adapter<A>(
        self,
        adapter: &mut A,
    ) -> Result<CompletedCommandExecution, RuntimeAdapterExecutionError<A::Error>>
    where
        A: AtomicCommitAdapter,
    {
        self.complete_with_commit_adapter_inner(adapter, None)
    }

    /// Commits required atomic work through an adapter with a storage-boundary contract.
    pub fn complete_with_commit_adapter_and_storage_boundary<A>(
        self,
        adapter: &mut A,
        planned_storage_boundary_contract: PlannedStorageBoundaryContract,
    ) -> Result<CompletedCommandExecution, RuntimeAdapterExecutionError<A::Error>>
    where
        A: AtomicCommitAdapter,
    {
        self.complete_with_commit_adapter_inner(adapter, Some(planned_storage_boundary_contract))
    }

    fn complete_with_commit_adapter_inner<A>(
        self,
        adapter: &mut A,
        planned_storage_boundary_contract: Option<PlannedStorageBoundaryContract>,
    ) -> Result<CompletedCommandExecution, RuntimeAdapterExecutionError<A::Error>>
    where
        A: AtomicCommitAdapter,
    {
        if self.atomic_commit_work.is_empty() {
            return self
                .finish_without_atomic_commit()
                .map_err(RuntimeAdapterExecutionError::core);
        }

        let request = if let Some(boundary_contract) = planned_storage_boundary_contract {
            AtomicCommitRequest::for_atomic_work_with_storage_boundary(
                &self.atomic_commit_work,
                boundary_contract,
            )
        } else {
            AtomicCommitRequest::for_atomic_work(&self.atomic_commit_work)
        }
        .map_err(RuntimeAdapterExecutionError::core)?;
        let materialized_targets = adapter
            .commit_atomic_work(request)
            .map_err(RuntimeAdapterExecutionError::atomic_commit)?;
        let materialized_fresh_credential_secrets =
            MaterializedFreshCredentialSecrets::for_atomic_work(
                &self.atomic_commit_work,
                materialized_targets,
            )
            .map_err(RuntimeAdapterExecutionError::core)?;
        let commit_success = AtomicCommitSuccess::for_atomic_work(
            &self.atomic_commit_work,
            materialized_fresh_credential_secrets,
        )
        .map_err(RuntimeAdapterExecutionError::core)?;
        self.finish_after_successful_atomic_commit(commit_success)
            .map_err(RuntimeAdapterExecutionError::core)
    }

    /// Commits required atomic work, then materializes response effects.
    pub fn complete_with_commit_adapter_and_materialize_response<A>(
        self,
        adapter: &mut A,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<MaterializedCompletedCommandExecution, RuntimeAdapterExecutionError<A::Error>>
    where
        A: AtomicCommitAdapter,
    {
        self.complete_with_commit_adapter(adapter)?
            .materialize_response_effects(presented_cookie_secrets)
            .map_err(RuntimeAdapterExecutionError::core)
    }

    /// Commits atomic work with a storage-boundary contract, then materializes response effects.
    pub fn complete_with_commit_adapter_and_storage_boundary_and_materialize_response<A>(
        self,
        adapter: &mut A,
        planned_storage_boundary_contract: PlannedStorageBoundaryContract,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<MaterializedCompletedCommandExecution, RuntimeAdapterExecutionError<A::Error>>
    where
        A: AtomicCommitAdapter,
    {
        self.complete_with_commit_adapter_and_storage_boundary(
            adapter,
            planned_storage_boundary_contract,
        )?
        .materialize_response_effects(presented_cookie_secrets)
        .map_err(RuntimeAdapterExecutionError::core)
    }

    /// Releases response effects only when no atomic commit is required.
    pub fn finish_without_atomic_commit(self) -> Result<CompletedCommandExecution, Error> {
        if !self.atomic_commit_work.is_empty() {
            return Err(Error::AtomicCommitRequiredBeforeResponseEffects);
        }
        Ok(CompletedCommandExecution {
            outcome: self.outcome,
            presented_cookies: self.presented_cookies,
            commit_success: None,
            validated_response_effects: self.validated_response_effects,
        })
    }

    /// Releases response effects only after the exact planned atomic work has committed.
    pub fn finish_after_successful_atomic_commit(
        self,
        commit_success: AtomicCommitSuccess,
    ) -> Result<CompletedCommandExecution, Error> {
        if commit_success.storage_contract() != &self.atomic_commit_work.storage_contract()? {
            return Err(Error::AtomicCommitSuccessDoesNotMatchPlannedWork);
        }
        Ok(CompletedCommandExecution {
            outcome: self.outcome,
            presented_cookies: self.presented_cookies,
            commit_success: Some(commit_success),
            validated_response_effects: self.validated_response_effects,
        })
    }

    /// Consumes planned execution after a failed commit without releasing response effects.
    pub fn discard_after_failed_atomic_commit<E>(self, error: E) -> E {
        error
    }
}

/// Command execution completed after required atomic work succeeded.
#[derive(Debug)]
pub struct CompletedCommandExecution {
    outcome: Outcome,
    presented_cookies: PresentedAuthCookies,
    commit_success: Option<AtomicCommitSuccess>,
    validated_response_effects: ValidatedResponseEffects,
}

impl CompletedCommandExecution {
    /// Returns the semantic reducer outcome.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Returns response effects validated against successfully committed work.
    pub fn validated_response_effects(&self) -> &ValidatedResponseEffects {
        &self.validated_response_effects
    }

    /// Materializes response effects into transport-ready cookie operations.
    pub fn materialize_response_effects(
        self,
        presented_cookie_secrets: PresentedAuthCookieSecrets,
    ) -> Result<MaterializedCompletedCommandExecution, Error> {
        presented_cookie_secrets.validate_matches_presented_cookies(&self.presented_cookies)?;
        let materialized_response_effects =
            MaterializedResponseEffects::from_validated_response_effects(
                self.validated_response_effects,
                self.commit_success,
                presented_cookie_secrets,
            )?;
        Ok(MaterializedCompletedCommandExecution::new(
            self.outcome,
            materialized_response_effects,
        ))
    }

    /// Splits completed execution into outcome and response effects.
    pub fn into_parts(self) -> (Outcome, ValidatedResponseEffects) {
        (self.outcome, self.validated_response_effects)
    }
}

/// Response effects released only after commit-work validation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatedResponseEffects(Vec<ResponseEffect>);

impl ValidatedResponseEffects {
    /// Returns whether there are no response effects.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns validated response effects.
    pub fn as_slice(&self) -> &[ResponseEffect] {
        &self.0
    }

    /// Consumes the wrapper and returns validated response effects.
    pub fn into_vec(self) -> Vec<ResponseEffect> {
        self.0
    }
}
