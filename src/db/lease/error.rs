use super::{MAX_LEASE_HOLDER_ID_BYTES, MAX_LEASE_KEY_BYTES, MIN_LEASE_DURATION};
use std::time::Duration as StdDuration;

/// Errors returned by Postgres-backed coordination primitives.
#[derive(Debug, thiserror::Error)]
pub enum CoordinationError {
    /// A key needed at least one part.
    #[error("coordination key must contain at least one part")]
    EmptyKey,
    /// A key part was empty.
    #[error("coordination key part must not be empty")]
    EmptyKeyPart,
    /// A key part contained the key separator byte.
    #[error("coordination key part must not contain ':'")]
    KeyPartContainsSeparatorByte,
    /// A key part contained a null byte.
    #[error("coordination key part must not contain null bytes")]
    KeyPartContainsNullByte,
    /// A composed key exceeded the maximum accepted byte length.
    #[error("coordination key is {actual} bytes, maximum is {max}")]
    KeyTooLong {
        /// Actual key byte length.
        actual: usize,
        /// Maximum accepted key byte length.
        max: usize,
    },
    /// Holder identifiers must be non-empty.
    #[error("coordination holder identifier must not be empty")]
    EmptyHolderId,
    /// A holder identifier contained a null byte.
    #[error("coordination holder identifier must not contain null bytes")]
    HolderIdContainsNullByte,
    /// A holder identifier exceeded the maximum accepted byte length.
    #[error("coordination holder identifier is {actual} bytes, maximum is {max}")]
    HolderIdTooLong {
        /// Actual holder identifier byte length.
        actual: usize,
        /// Maximum accepted holder identifier byte length.
        max: usize,
    },
    /// A positive claim duration must be supplied through `ClaimDuration::expires_after`.
    #[error("coordination claim duration cannot be zero")]
    DurationIsZero,
    /// A positive duration was below the configured minimum.
    #[error("coordination claim duration is below the minimum of {minimum:?}")]
    DurationBelowMinimum {
        /// Minimum accepted positive duration.
        minimum: StdDuration,
    },
    /// A duration was too large to bind safely as microseconds.
    #[error("coordination claim duration is too large")]
    DurationTooLarge,
    /// Persisted claim token bytes had an impossible length.
    #[error("persisted coordination claim token is {actual} bytes, expected {expected}")]
    InvalidPersistedTokenLength {
        /// Actual token byte length.
        actual: usize,
        /// Expected token byte length.
        expected: usize,
    },
    /// Persisted fencing token was not positive.
    #[error("persisted coordination fencing token must be positive, got {value}")]
    InvalidPersistedFencingToken {
        /// Invalid persisted fencing token.
        value: i64,
    },
    /// Random claim token generation failed.
    #[error("failed to generate coordination claim token")]
    TokenGeneration {
        /// Underlying random generation error.
        #[source]
        source: crate::crypto::Error,
    },
    /// A database operation failed.
    #[error(transparent)]
    Database(#[from] crate::db::Error),
    /// A coordination database operation failed and its cleanup rollback also failed.
    #[error("coordination database operation {operation} failed, then transaction rollback failed")]
    DatabaseOperationRollbackFailed {
        /// Operation being cleaned up.
        operation: &'static str,
        /// Original operation error.
        operation_error: Box<CoordinationError>,
        /// Rollback failure.
        rollback_error: crate::db::Error,
    },
}

impl CoordinationError {
    pub(super) fn key_too_long(actual: usize) -> Self {
        Self::KeyTooLong {
            actual,
            max: MAX_LEASE_KEY_BYTES,
        }
    }

    pub(super) fn holder_id_too_long(actual: usize) -> Self {
        Self::HolderIdTooLong {
            actual,
            max: MAX_LEASE_HOLDER_ID_BYTES,
        }
    }

    pub(super) fn duration_below_minimum() -> Self {
        Self::DurationBelowMinimum {
            minimum: MIN_LEASE_DURATION,
        }
    }
}
