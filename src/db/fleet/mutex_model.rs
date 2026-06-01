use super::*;

/// Coordination-backed Fleet mutex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mutex {
    pub(super) lease_store: LeaseStore,
    pub(super) key: MutexKey,
    pub(super) lease_key: LeaseKey,
    pub(super) claim_duration: ClaimDuration,
}

/// Explicit opt-in handle for mutex claims that are manually renewed.
#[must_use = "use this handle to claim, renew, or release a manually renewed mutex claim"]
pub struct MutexManualRenewalProtocol<'a> {
    pub(super) mutex: &'a Mutex,
}

/// Live Fleet mutex claim that is manually renewed.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "a manual-renewal mutex claim must be renewed or released explicitly"]
pub struct MutexManualRenewalClaim {
    pub(super) mutex_key: MutexKey,
    pub(super) lease_claim: LeaseClaim,
}

/// Non-secret view of the current live Fleet mutex holder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutexHolderSnapshot {
    pub(super) mutex_key: MutexKey,
    pub(super) lease_holder_snapshot: LeaseHolderSnapshot,
}

/// Runtime behavior for a guarded Fleet mutex claim with automatic heartbeats.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MutexGuardConfig {
    /// How often the guard renews its claim. Defaults to one third of the claim duration, with a floor.
    pub heartbeat_interval: Option<Duration>,
    /// How long a blocking guard acquisition waits between attempts.
    pub acquire_retry_interval: Option<Duration>,
    /// Maximum wait between blocking guard acquisition attempts.
    pub max_acquire_retry_interval: Option<Duration>,
    /// Consecutive renewal failures tolerated before the guard marks leadership lost.
    pub max_consecutive_renewal_failures: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResolvedMutexGuardConfig {
    pub(super) heartbeat_interval: Duration,
    pub(super) acquire_retry_interval: Duration,
    pub(super) max_acquire_retry_interval: Duration,
    pub(super) max_consecutive_renewal_failures: u32,
}

/// Guard that owns and periodically renews a Fleet mutex claim.
#[must_use = "a mutex guard holds live Fleet coordination state; call release or run_task to observe cleanup"]
pub struct MutexGuard {
    pub(super) mutex: Mutex,
    pub(super) pool: WritePool,
    pub(super) runtime_handle: RuntimeHandle,
    pub(super) current_claim: Arc<tokio::sync::Mutex<Option<MutexManualRenewalClaim>>>,
    pub(super) stop_heartbeat: Arc<AtomicBool>,
    pub(super) stop_heartbeat_notify: Arc<Notify>,
    pub(super) leadership_lost: Arc<AtomicBool>,
    pub(super) leadership_lost_notify: Arc<Notify>,
    pub(super) heartbeat_task: Option<JoinHandle<()>>,
}

/// Non-secret view of the claim currently owned by a Fleet mutex guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutexGuardSnapshot {
    pub(super) mutex_key: MutexKey,
    pub(super) holder_id: HolderId,
    pub(super) fencing_token: FencingToken,
    pub(super) expires_at_unix_microseconds: i64,
}

/// Result of trying to acquire and run a Fleet mutex-guarded task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutexTryRunTaskResult<T> {
    /// The mutex was acquired and the task ran.
    Ran(T),
    /// Another holder currently owns the mutex.
    MutexHeld,
}

/// Error returned while running a Fleet mutex-guarded task.
#[derive(Debug, thiserror::Error)]
pub enum MutexRunError<E> {
    /// A Fleet operation failed.
    #[error(transparent)]
    Fleet(#[from] Error),
    /// A Fleet operation failed and leadership was no longer live at release.
    #[error("Fleet mutex operation failed and leadership was no longer live at release")]
    FleetAndLeadershipLost {
        /// Underlying Fleet error.
        #[source]
        source: Error,
    },
    /// A Fleet operation failed and releasing leadership also failed.
    #[error("Fleet mutex operation failed and release also failed")]
    FleetAndRelease {
        /// Underlying Fleet error.
        #[source]
        source: Error,
        /// Release error.
        release_error: Error,
    },
    /// Leadership was lost before the task could complete under a live guard.
    #[error("Fleet mutex leadership was lost")]
    LeadershipLost,
    /// Leadership was lost and releasing leadership also failed.
    #[error("Fleet mutex leadership was lost and release also failed")]
    LeadershipLostAndRelease {
        /// Release error.
        #[source]
        release_error: Error,
    },
    /// The caller-supplied task failed.
    #[error("Fleet mutex task failed")]
    Task {
        /// Underlying task error.
        #[source]
        source: E,
    },
    /// The caller-supplied task failed and leadership was no longer live at release.
    #[error("Fleet mutex task failed and leadership was no longer live at release")]
    TaskAndLeadershipLost {
        /// Underlying task error.
        #[source]
        source: E,
    },
    /// The caller-supplied task succeeded but leadership release failed.
    #[error("Fleet mutex release failed")]
    Release {
        /// Release error.
        #[source]
        source: Error,
    },
    /// The caller-supplied task failed and leadership release also failed.
    #[error("Fleet mutex task failed and release also failed")]
    TaskAndRelease {
        /// Underlying task error.
        #[source]
        source: E,
        /// Release error.
        release_error: Error,
    },
}

pub(super) struct MutexHeartbeatRuntime {
    pub(super) mutex: Mutex,
    pub(super) pool: WritePool,
    pub(super) current_claim: Arc<tokio::sync::Mutex<Option<MutexManualRenewalClaim>>>,
    pub(super) stop_heartbeat: Arc<AtomicBool>,
    pub(super) stop_heartbeat_notify: Arc<Notify>,
    pub(super) leadership_lost: Arc<AtomicBool>,
    pub(super) leadership_lost_notify: Arc<Notify>,
}
