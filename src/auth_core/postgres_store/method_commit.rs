use super::*;

pub(crate) trait PostgresAuthMethodCommitExecutor: Send + Sync {
    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostgresAuthMethodCommitStage {
    EnforcePrecondition,
    ApplyMutation,
    AppendDurableEffectCommand,
}

#[derive(Debug)]
pub(crate) enum PostgresAuthMethodCommitError {
    Database(DbError),
    InvalidOperation(String),
    PreconditionFailed(&'static str),
    UnregisteredMethod {
        family: ProofFamily,
        method_label: String,
    },
}

impl fmt::Display for PostgresAuthMethodCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "{error}"),
            Self::InvalidOperation(operation) => {
                write!(f, "unsupported method commit operation: {operation}")
            }
            Self::PreconditionFailed(reason) => {
                write!(f, "method commit precondition failed: {reason}")
            }
            Self::UnregisteredMethod {
                family,
                method_label,
            } => write!(
                f,
                "no registered method plugin for {family:?}/{method_label}"
            ),
        }
    }
}

impl std::error::Error for PostgresAuthMethodCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidOperation(_)
            | Self::PreconditionFailed(_)
            | Self::UnregisteredMethod { .. } => None,
        }
    }
}

impl From<DbError> for PostgresAuthMethodCommitError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}
pub(in crate::auth_core) async fn enforce_method_commit_preconditions(
    tx: &mut Tx<'_>,
    executor: &dyn PostgresAuthMethodCommitExecutor,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), PostgresAuthStoreError> {
    for work in method_commit_work {
        for precondition in work.preconditions() {
            let operation = precondition.operation().as_str().to_owned();
            executor
                .enforce_precondition(tx, work, precondition)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage: PostgresAuthMethodCommitStage::EnforcePrecondition,
                    operation,
                    source,
                })?;
        }
    }
    Ok(())
}

pub(in crate::auth_core) async fn enforce_out_of_band_identifier_binding_lifecycle_state(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source_id: &VerifiedProofSourceId,
    subject_id: &SubjectId,
    expected_state: OutOfBandIdentifierBindingLifecycleState,
    operation_name: &'static str,
    failure_message: &'static str,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT 1
        FROM {}
        WHERE source_id = $1
          AND subject_id = $2
          AND lifecycle_state = $3
        FOR UPDATE
        "#,
        table_names
            .get(PostgresAuthCoreTable::OutOfBandIdentifierBinding)
            .quoted()
    );
    let found = fetch_exists_for_update(tx, operation_name, &statement, |query| {
        Ok(query
            .bind(source_id.as_bytes())
            .bind(subject_id.as_bytes())
            .bind(i32_from_out_of_band_identifier_binding_lifecycle_state(
                expected_state,
            )))
    })
    .await?;
    if !found {
        return Err(PostgresAuthStoreError::PreconditionFailed(failure_message));
    }
    Ok(())
}

pub(in crate::auth_core) async fn apply_method_commit_mutations(
    tx: &mut Tx<'_>,
    executor: &dyn PostgresAuthMethodCommitExecutor,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), PostgresAuthStoreError> {
    for work in method_commit_work {
        for mutation in work.mutations() {
            let operation = mutation.operation().as_str().to_owned();
            executor
                .apply_mutation(tx, work, mutation)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage: PostgresAuthMethodCommitStage::ApplyMutation,
                    operation,
                    source,
                })?;
        }
    }
    Ok(())
}

pub(in crate::auth_core) async fn append_method_commit_durable_effect_commands(
    tx: &mut Tx<'_>,
    executor: &dyn PostgresAuthMethodCommitExecutor,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), PostgresAuthStoreError> {
    for work in method_commit_work {
        for command in work.durable_effect_commands() {
            let operation = command.operation().as_str().to_owned();
            executor
                .append_durable_effect_command(tx, work, command)
                .await
                .map_err(|source| PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage: PostgresAuthMethodCommitStage::AppendDurableEffectCommand,
                    operation,
                    source,
                })?;
        }
    }
    Ok(())
}
