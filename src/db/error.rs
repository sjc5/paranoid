use super::{InvalidPgIdentifier, PgSqlState};
use std::error::Error as StdError;

/// Database foundation error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Pool configuration was internally inconsistent.
    #[error("invalid Postgres pool configuration: {reason}")]
    InvalidPoolConfig {
        /// Human-readable reason.
        reason: &'static str,
    },
    /// The configured database URL could not be parsed.
    #[error("invalid Postgres database URL")]
    InvalidDatabaseUrl {
        /// Underlying parse error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// A Postgres connection pool could not be opened.
    #[error("failed to connect to Postgres")]
    Connect {
        /// Underlying connection error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// A transaction operation failed.
    #[error("Postgres transaction operation failed")]
    Transaction {
        /// Underlying transaction error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// A Postgres query failed.
    #[error("Postgres query failed")]
    Query {
        /// SQLSTATE category when Postgres supplied one.
        sql_state: Option<PgSqlState>,
        /// Underlying query error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// A database operation failed and its cleanup rollback also failed.
    #[error("Postgres database operation {operation} failed, then transaction rollback failed")]
    DatabaseOperationRollbackFailed {
        /// Operation being cleaned up.
        operation: &'static str,
        /// Original operation error.
        operation_error: Box<Error>,
        /// Rollback failure.
        rollback_error: Box<Error>,
    },
    /// Existing Postgres schema is incompatible with the requested primitive.
    #[error("Postgres schema mismatch: {reason}")]
    SchemaMismatch {
        /// Human-readable reason.
        reason: String,
    },
    /// A configured SQL identifier was invalid.
    #[error(transparent)]
    InvalidIdentifier(#[from] InvalidPgIdentifier),
}

impl Error {
    pub(crate) fn invalid_database_url(error: sqlx::Error) -> Self {
        Self::InvalidDatabaseUrl {
            source: Box::new(error),
        }
    }

    pub(crate) fn connect(error: sqlx::Error) -> Self {
        Self::Connect {
            source: Box::new(error),
        }
    }

    pub(crate) fn transaction(error: sqlx::Error) -> Self {
        Self::Transaction {
            source: Box::new(error),
        }
    }

    pub(crate) fn query(error: sqlx::Error) -> Self {
        Self::Query {
            sql_state: sql_state_from_sqlx_error(&error),
            source: Box::new(error),
        }
    }

    pub(crate) fn schema_mismatch(reason: impl Into<String>) -> Self {
        Self::SchemaMismatch {
            reason: reason.into(),
        }
    }
}

pub(crate) fn sql_state_from_sqlx_error(error: &sqlx::Error) -> Option<PgSqlState> {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(PgSqlState::from_code)
}
