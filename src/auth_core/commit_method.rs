use super::*;

/// Method/plugin work that must commit atomically with the core transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitWork {
    /// Exact proof this work belongs to.
    pub(super) proof: ProofSummary,
    /// Method-specific preconditions the adapter must enforce before applying mutations.
    pub(super) preconditions: Vec<MethodCommitPrecondition>,
    /// Method-specific mutations the adapter must commit with core mutations.
    pub(super) mutations: Vec<MethodCommitMutation>,
    /// Method-specific durable effects the adapter must persist before external delivery.
    pub(super) durable_effect_commands: Vec<MethodCommitDurableEffectCommand>,
}

impl MethodCommitWork {
    /// Creates one method/plugin atomic-work batch for an already verified proof.
    pub(crate) fn new(
        proof: ProofSummary,
        preconditions: Vec<MethodCommitPrecondition>,
        mutations: Vec<MethodCommitMutation>,
        durable_effect_commands: Vec<MethodCommitDurableEffectCommand>,
    ) -> Result<Self, Error> {
        let work = Self {
            proof,
            preconditions,
            mutations,
            durable_effect_commands,
        };
        work.validate()?;
        Ok(work)
    }

    /// Returns the exact proof this method work belongs to.
    pub fn proof(&self) -> &ProofSummary {
        &self.proof
    }

    /// Returns method-specific preconditions.
    pub fn preconditions(&self) -> &[MethodCommitPrecondition] {
        &self.preconditions
    }

    /// Returns method-specific mutations.
    pub fn mutations(&self) -> &[MethodCommitMutation] {
        &self.mutations
    }

    /// Returns method-specific durable effect commands.
    pub fn durable_effect_commands(&self) -> &[MethodCommitDurableEffectCommand] {
        &self.durable_effect_commands
    }

    /// Returns the ordered transaction contract for this method-owned work.
    pub fn transaction_contract(&self) -> Result<MethodCommitTransactionContract, Error> {
        MethodCommitTransactionContract::for_method_work(self)
    }

    /// Validates that method work is non-empty and self-identifying.
    pub fn validate(&self) -> Result<(), Error> {
        self.proof.validate()?;
        if self.preconditions.is_empty()
            && self.mutations.is_empty()
            && self.durable_effect_commands.is_empty()
        {
            return Err(Error::EmptyMethodCommitWork);
        }
        for item in &self.preconditions {
            item.validate()?;
        }
        for item in &self.mutations {
            item.validate()?;
        }
        for item in &self.durable_effect_commands {
            item.validate()?;
        }
        Ok(())
    }
}

/// Method/plugin precondition that must be enforced before any mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitPrecondition(MethodCommitOperationRequest);

impl MethodCommitPrecondition {
    /// Creates one method/plugin precondition request.
    pub(crate) fn new(
        operation: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self(MethodCommitOperationRequest::new(operation, payload)?))
    }

    /// Returns the adapter-specific operation identity.
    pub fn operation(&self) -> &MethodCommitOperation {
        self.0.operation()
    }

    /// Returns the canonical method-defined payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.0.payload()
    }

    fn validate(&self) -> Result<(), Error> {
        self.0.validate()
    }
}

/// Method/plugin mutation that must commit in the same transaction as core mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitMutation(MethodCommitOperationRequest);

impl MethodCommitMutation {
    /// Creates one method/plugin mutation request.
    pub(crate) fn new(
        operation: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self(MethodCommitOperationRequest::new(operation, payload)?))
    }

    /// Returns the adapter-specific operation identity.
    pub fn operation(&self) -> &MethodCommitOperation {
        self.0.operation()
    }

    /// Returns the canonical method-defined payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.0.payload()
    }

    fn validate(&self) -> Result<(), Error> {
        self.0.validate()
    }
}

/// Method/plugin durable effect command to persist before external delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitDurableEffectCommand(MethodCommitOperationRequest);

impl MethodCommitDurableEffectCommand {
    /// Creates one method/plugin durable effect command request.
    pub(crate) fn new(
        operation: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self(MethodCommitOperationRequest::new(operation, payload)?))
    }

    /// Returns the adapter-specific operation identity.
    pub fn operation(&self) -> &MethodCommitOperation {
        self.0.operation()
    }

    /// Returns the canonical method-defined payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.0.payload()
    }

    fn validate(&self) -> Result<(), Error> {
        self.0.validate()
    }
}

/// Adapter-specific method/plugin operation identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MethodCommitOperation(String);

impl MethodCommitOperation {
    /// Creates a non-empty method/plugin operation identity.
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyMethodCommitWorkItemLabel);
        }
        validate_auth_identifier_string(
            "method commit operation",
            &value,
            METHOD_COMMIT_OPERATION_MAX_BYTES,
        )?;
        Ok(Self(value))
    }

    /// Returns the operation identity string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            return Err(Error::EmptyMethodCommitWorkItemLabel);
        }
        validate_auth_identifier_string(
            "method commit operation",
            &self.0,
            METHOD_COMMIT_OPERATION_MAX_BYTES,
        )?;
        Ok(())
    }
}

/// Ordered transaction contract for one method-owned commit-work batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MethodCommitTransactionContract {
    proof: ProofSummary,
    stages: Vec<MethodCommitTransactionStage>,
}

impl MethodCommitTransactionContract {
    /// Builds the transaction contract for one method-owned work batch.
    pub fn for_method_work(work: &MethodCommitWork) -> Result<Self, Error> {
        work.validate()?;
        let mut stages = Vec::new();
        if !work.preconditions.is_empty() {
            stages.push(MethodCommitTransactionStage::EnforcePreconditions);
        }
        if !work.mutations.is_empty() {
            stages.push(MethodCommitTransactionStage::ApplyMutations);
        }
        if !work.durable_effect_commands.is_empty() {
            stages.push(MethodCommitTransactionStage::CommitDurableEffectCommands);
        }
        Ok(Self {
            proof: work.proof.clone(),
            stages,
        })
    }

    /// Returns the exact proof identity this method work belongs to.
    pub fn proof(&self) -> &ProofSummary {
        &self.proof
    }

    /// Returns ordered method-owned transaction stages.
    pub fn stages(&self) -> &[MethodCommitTransactionStage] {
        &self.stages
    }
}

/// Ordered transaction stage for method/plugin-owned commit work.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MethodCommitTransactionStage {
    /// Enforce method-owned preconditions before core or method mutations.
    EnforcePreconditions,
    /// Apply method-owned mutations inside the active transaction.
    ApplyMutations,
    /// Persist method-owned durable effect commands inside the active transaction.
    CommitDurableEffectCommands,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MethodCommitOperationRequest {
    operation: MethodCommitOperation,
    payload: Vec<u8>,
}

impl MethodCommitOperationRequest {
    fn new(operation: impl Into<String>, payload: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let payload = payload.into();
        validate_auth_bytes_not_too_long(
            "method commit payload",
            &payload,
            METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        )?;
        Ok(Self {
            operation: MethodCommitOperation::new(operation)?,
            payload,
        })
    }

    fn operation(&self) -> &MethodCommitOperation {
        &self.operation
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn validate(&self) -> Result<(), Error> {
        self.operation.validate()?;
        validate_auth_bytes_not_too_long(
            "method commit payload",
            &self.payload,
            METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        )
    }
}
