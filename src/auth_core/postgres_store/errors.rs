use super::*;

#[derive(Debug)]
pub(crate) enum PostgresAuthStoreError {
    Core(Error),
    Crypto(crate::crypto::Error),
    Database(DbError),
    InvalidStoredData(&'static str),
    MethodRegistryNotConfigured,
    MethodCommitWorkFailed {
        stage: PostgresAuthMethodCommitStage,
        operation: String,
        source: PostgresAuthMethodCommitError,
    },
    MethodRegistryFailed {
        operation: &'static str,
        source: PostgresAuthMethodCommitError,
    },
    PreconditionFailed(&'static str),
}

impl fmt::Display for PostgresAuthStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "auth Postgres store crypto error: {error}"),
            Self::Database(error) => write!(f, "auth Postgres store database error: {error}"),
            Self::InvalidStoredData(reason) => {
                write!(f, "auth Postgres store loaded invalid data: {reason}")
            }
            Self::MethodRegistryNotConfigured => {
                write!(
                    f,
                    "auth Postgres store cannot commit method/plugin work without a configured method registry"
                )
            }
            Self::MethodCommitWorkFailed {
                stage,
                operation,
                source,
            } => {
                write!(
                    f,
                    "auth Postgres store method/plugin work failed during {stage:?} for {operation}: {source}"
                )
            }
            Self::MethodRegistryFailed { operation, source } => {
                write!(
                    f,
                    "auth Postgres store method/plugin registry failed during {operation}: {source}"
                )
            }
            Self::PreconditionFailed(reason) => {
                write!(f, "auth Postgres store precondition failed: {reason}")
            }
        }
    }
}

impl std::error::Error for PostgresAuthStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::MethodCommitWorkFailed { source, .. } => Some(source),
            Self::MethodRegistryFailed { source, .. } => Some(source),
            Self::InvalidStoredData(_)
            | Self::MethodRegistryNotConfigured
            | Self::PreconditionFailed(_) => None,
        }
    }
}

impl From<Error> for PostgresAuthStoreError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

impl From<DbError> for PostgresAuthStoreError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}
