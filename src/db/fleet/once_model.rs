use super::*;
use std::future::Future;
use std::pin::Pin;

/// Fleet run-once task handle.
#[derive(Clone, Debug)]
pub struct Once {
    pub(super) completion_item: KvItem<OnceCompletion>,
    pub(super) key: OnceKey,
    pub(super) mutex: Mutex,
}

/// Explicit opt-in handle for run-once claims that are managed through the manual run protocol.
#[must_use = "use this handle to start, complete, or release manual run-once work"]
pub struct OnceManualRunProtocol<'a> {
    pub(super) once: &'a Once,
}

/// Live claim authorizing one worker to perform a Fleet run-once task.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a manual run-once claim must be completed or released explicitly"]
pub struct OnceManualRunClaim {
    pub(super) once_key: OnceKey,
    pub(super) mutex_claim: MutexManualRenewalClaim,
}

/// Non-secret view of the live claim authorizing one worker to perform a Fleet run-once task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnceRunClaimSnapshot {
    pub(super) once_key: OnceKey,
    pub(super) holder_id: HolderId,
    pub(super) fencing_token: FencingToken,
    pub(super) expires_at_unix_microseconds: i64,
}

/// Durable completion marker for a Fleet run-once task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OnceCompletion {
    pub(super) finished_at_unix_microseconds: i64,
    pub(super) holder_id: String,
    pub(super) fencing_token: i64,
}

/// Result of trying to acquire exclusive run-once execution and run a task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnceTryRunTaskResult<T> {
    /// This caller ran the task and recorded completion.
    Ran(T),
    /// The task was already completed before this caller ran it.
    AlreadyDone(OnceCompletion),
    /// Another caller currently owns exclusive execution.
    AlreadyRunning,
}

/// Result of waiting for run-once availability and running a task if needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnceRunTaskResult<T> {
    /// This caller ran the task and recorded completion.
    Ran(T),
    /// The task was already completed before this caller ran it.
    AlreadyDone(OnceCompletion),
}

/// Error returned while running a Fleet run-once task through the high-level task helpers.
#[derive(Debug, thiserror::Error)]
pub enum OnceRunError<E> {
    /// A Fleet operation failed before the caller task ran.
    #[error(transparent)]
    Fleet(#[from] Error),
    /// The caller-supplied task failed.
    #[error("Fleet run-once task failed")]
    Task {
        /// Underlying task error.
        #[source]
        source: E,
    },
    /// The caller-supplied task failed and releasing exclusive execution also failed.
    #[error("Fleet run-once task failed and release also failed")]
    TaskAndRelease {
        /// Underlying task error.
        #[source]
        source: E,
        /// Release error.
        release_error: Error,
    },
    /// The caller-supplied task succeeded but recording completion failed.
    #[error("Fleet run-once task succeeded but completion failed")]
    TaskSucceededButCompletionFailed {
        /// Completion error.
        #[source]
        source: Error,
    },
    /// The caller-supplied task succeeded, recording completion failed, and release also failed.
    #[error("Fleet run-once task succeeded but completion and release both failed")]
    TaskSucceededButCompletionAndReleaseFailed {
        /// Completion error.
        #[source]
        source: Error,
        /// Release error.
        release_error: Error,
    },
    /// The caller-supplied task succeeded but releasing exclusive execution failed.
    #[error("Fleet run-once task succeeded but release failed")]
    Release {
        /// Release error.
        #[source]
        source: Error,
    },
}

/// Boxed future returned by a transactional Fleet run-once task.
pub type OnceTransactionalTaskFuture<'a, T, E> =
    Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Error returned while running a Fleet run-once task inside the same transaction as completion.
#[derive(Debug, thiserror::Error)]
pub enum OnceTransactionalRunError<E> {
    /// A Fleet operation failed before the caller task ran.
    #[error(transparent)]
    Fleet(#[from] Error),
    /// The caller-supplied task failed.
    #[error("Fleet transactional run-once task failed")]
    Task {
        /// Underlying task error.
        #[source]
        source: E,
    },
    /// The caller-supplied task failed and rolling back its transaction also failed.
    #[error("Fleet transactional run-once task failed and transaction rollback also failed")]
    TaskAndTransactionRollback {
        /// Underlying task error.
        #[source]
        source: E,
        /// Rollback error.
        rollback_error: Error,
    },
    /// The caller-supplied task failed and releasing exclusive execution also failed.
    #[error("Fleet transactional run-once task failed and release also failed")]
    TaskAndRelease {
        /// Underlying task error.
        #[source]
        source: E,
        /// Release error.
        release_error: Error,
    },
    /// The caller-supplied task failed, rolling back failed, and releasing exclusive execution failed.
    #[error(
        "Fleet transactional run-once task failed, transaction rollback failed, and release failed"
    )]
    TaskTransactionRollbackAndRelease {
        /// Underlying task error.
        #[source]
        source: E,
        /// Rollback error.
        rollback_error: Error,
        /// Release error.
        release_error: Error,
    },
    /// The transaction failed and releasing exclusive execution also failed.
    #[error("Fleet transactional run-once transaction failed and release also failed")]
    TransactionAndRelease {
        /// Transaction error.
        #[source]
        source: Error,
        /// Release error.
        release_error: Error,
    },
    /// The transaction succeeded but releasing exclusive execution failed.
    #[error("Fleet transactional run-once task succeeded but release failed")]
    Release {
        /// Release error.
        #[source]
        source: Error,
    },
}
