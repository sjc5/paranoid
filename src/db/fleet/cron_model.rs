use super::*;

/// Configures a Fleet cron.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CronConfig {
    /// Cron namespace key.
    pub key: CronKey,
    /// Time between task starts while this process holds leadership.
    pub interval: Duration,
    /// Leadership claim duration. Defaults to [`crate::fleet::DEFAULT_CRON_CLAIM_DURATION`].
    pub claim_duration: Option<ClaimDuration>,
    /// Leadership claim heartbeat interval. Defaults to [`crate::fleet::DEFAULT_CRON_HEARTBEAT_INTERVAL`].
    pub heartbeat_interval: Option<Duration>,
    /// Wait between leadership acquisition attempts. Defaults to [`crate::fleet::DEFAULT_CRON_ACQUIRE_RETRY_INTERVAL`].
    pub acquire_retry_interval: Option<Duration>,
    /// Consecutive renewal failures tolerated before leadership is considered lost.
    pub max_consecutive_renewal_failures: Option<u32>,
}

/// Coordination-backed single-leader periodic runner.
#[derive(Clone, Debug)]
pub struct Cron {
    pub(super) key: CronKey,
    pub(super) interval: Duration,
    pub(super) mutex: Mutex,
    pub(super) guard_config: MutexGuardConfig,
}

/// Result of attempting to run a Fleet cron task once without waiting for leadership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CronTryRunOnceResult<T> {
    /// This process acquired leadership and ran the task.
    Ran(T),
    /// Another process currently holds leadership.
    LeadershipHeld,
}

/// Policy decision after a Fleet cron task returns an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CronTaskErrorAction {
    /// Keep leadership and continue running future ticks.
    Continue,
    /// Release leadership and return the task error.
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CronLeadershipTenureOutcome {
    StopRequested,
    LeadershipLost,
}

/// Error returned while running a Fleet cron task.
#[derive(Debug, thiserror::Error)]
pub enum CronRunError<E> {
    /// A Fleet operation failed.
    #[error(transparent)]
    Fleet(#[from] Error),
    /// A Fleet operation failed and leadership was no longer live at release.
    #[error("Fleet cron operation failed and leadership was no longer live at release")]
    FleetAndLeadershipLost {
        /// Underlying Fleet error.
        #[source]
        source: Error,
    },
    /// A Fleet operation failed and releasing leadership also failed.
    #[error("Fleet cron operation failed and leadership release also failed")]
    FleetAndRelease {
        /// Underlying Fleet error.
        #[source]
        source: Error,
        /// Release error.
        release_error: Error,
    },
    /// Leadership was lost before the task could complete under a live guard.
    #[error("Fleet cron leadership was lost")]
    LeadershipLost,
    /// Leadership was lost and releasing leadership also failed.
    #[error("Fleet cron leadership was lost and leadership release also failed")]
    LeadershipLostAndRelease {
        /// Release error.
        #[source]
        release_error: Error,
    },
    /// The caller-supplied task failed.
    #[error("Fleet cron task failed")]
    Task {
        /// Underlying task error.
        #[source]
        source: E,
    },
    /// The caller-supplied task failed and leadership was no longer live at release.
    #[error("Fleet cron task failed and leadership was no longer live at release")]
    TaskAndLeadershipLost {
        /// Underlying task error.
        #[source]
        source: E,
    },
    /// The caller-supplied task succeeded but leadership release failed.
    #[error("Fleet cron leadership release failed")]
    Release {
        /// Release error.
        #[source]
        source: Error,
    },
    /// The caller-supplied task failed and leadership release also failed.
    #[error("Fleet cron task failed and leadership release also failed")]
    TaskAndRelease {
        /// Underlying task error.
        #[source]
        source: E,
        /// Release error.
        release_error: Error,
    },
}

/// Error returned while waiting for a Fleet cron background task.
#[derive(Debug, thiserror::Error)]
pub enum CronRunHandleError<E> {
    /// The cron loop returned an error.
    #[error(transparent)]
    Run {
        /// Cron loop error.
        #[from]
        source: CronRunError<E>,
    },
    /// The background task failed to join.
    #[error("Fleet cron background task failed to join")]
    Join {
        /// Join error.
        #[source]
        source: tokio::task::JoinError,
    },
}

/// Handle for a Fleet cron background task.
#[must_use = "call request_stop, wait, or stop_and_wait so the cron loop lifecycle is observed"]
#[derive(Debug)]
pub struct CronRunHandle<E> {
    pub(super) stop_sender: Option<oneshot::Sender<()>>,
    pub(super) join_handle: Option<JoinHandle<Result<(), CronRunError<E>>>>,
}
