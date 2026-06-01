use super::*;

/// KV-slot-backed Fleet semaphore.
#[derive(Clone)]
pub struct Semaphore {
    pub(super) key: SemaphoreKey,
    pub(super) max_concurrent: u16,
    pub(super) max_hold_ttl: KvTtl,
    pub(super) slot_suffixes: Vec<String>,
    pub(super) slots_item: KvItem<SemaphoreSlot>,
}

/// Explicit opt-in handle for semaphore claims managed manually by the caller.
#[must_use = "use this handle to acquire or release semaphore claims manually"]
pub struct SemaphoreManualClaimProtocol<'a> {
    pub(super) semaphore: &'a Semaphore,
}

/// Live Fleet semaphore claim.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "a semaphore claim acquired manually must be released explicitly"]
pub struct SemaphoreClaim {
    pub(super) semaphore_key: SemaphoreKey,
    pub(super) slot_suffix: String,
    pub(super) holder_id: HolderId,
}

/// Owned Fleet semaphore claim with explicit release/task helpers and best-effort drop cleanup.
#[must_use = "a semaphore claim guard holds live Fleet coordination state; call release, try_release, or run_task to observe cleanup"]
pub struct SemaphoreClaimGuard {
    pub(super) semaphore: Semaphore,
    pub(super) pool: WritePool,
    pub(super) runtime_handle: RuntimeHandle,
    pub(super) claim: Option<SemaphoreClaim>,
}

/// Result of running a task behind a Fleet semaphore guard.
#[derive(Debug)]
pub enum SemaphoreGuardedTaskResult<T, E> {
    /// The task returned `Ok`.
    Succeeded {
        /// Task output.
        value: T,
        /// Result of releasing the semaphore claim after success.
        release_result: Result<bool, Error>,
    },
    /// The task returned `Err`.
    Failed {
        /// Task error.
        error: E,
        /// Result of releasing the semaphore claim after failure.
        release_result: Result<bool, Error>,
    },
}

/// Result of trying to acquire and run a Fleet semaphore guarded task.
#[derive(Debug)]
pub enum SemaphoreTryRunTaskResult<T, E> {
    /// The task ran.
    Ran(SemaphoreGuardedTaskResult<T, E>),
    /// All semaphore slots are currently occupied.
    NoSlotAvailable,
}

/// Current Fleet semaphore status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemaphoreStatus {
    pub(super) current_count: u64,
    pub(super) max_count: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct SemaphoreSlot {
    pub(super) holder_id: String,
}
