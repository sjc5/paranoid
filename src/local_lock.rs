//! Local process file locks with heartbeat-based stale recovery.
//!
//! `local_lock` is for human-operated local tooling that needs exclusive access
//! to a file or directory. A [`ProcessLock`] creates a lock file, writes a
//! small JSON lease record containing the current process id and a random owner
//! id, and refreshes that record on a heartbeat thread. If a process exits
//! without releasing the lock, the next owner can reclaim it after the heartbeat
//! becomes stale.

use std::error::Error as StdError;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const LEASE_SCHEMA_VERSION: u32 = 1;
const ACQUIRE_RETRY_LIMIT: usize = 3;
const ACQUIRE_RETRY_DELAY: Duration = Duration::from_millis(20);
const INVALID_LOCK_STALE_AFTER: Duration = Duration::from_millis(1200);

/// Default cadence for refreshing a held lock.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);

/// Default stale-heartbeat threshold before a lock can be reclaimed.
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(3);

static OWNER_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Result type returned by local process locks.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by local process locks.
#[derive(Debug)]
pub enum Error {
    /// The lock path was empty or whitespace-only.
    EmptyPath,
    /// The lock path had no parent directory.
    NoParentDirectory {
        /// Lock path without a parent directory.
        path: PathBuf,
    },
    /// Another process currently owns the lock.
    LockHeld {
        /// Lock file path.
        path: PathBuf,
        /// Owning process id when the lock file contains a valid lease record.
        pid: Option<u32>,
    },
    /// Lock contention did not settle within the retry budget.
    ContentionExceeded {
        /// Lock file path.
        path: PathBuf,
    },
    /// Filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Path involved in the operation.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Lease JSON encoding or decoding failed.
    Json {
        /// Operation being performed.
        operation: &'static str,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPath => write!(f, "paranoid local-lock: lock path is empty"),
            Self::NoParentDirectory { path } => {
                write!(
                    f,
                    "paranoid local-lock: lock path has no parent directory: {path:?}"
                )
            }
            Self::LockHeld {
                path,
                pid: Some(pid),
            } => write!(
                f,
                "paranoid local-lock: lock is already held at {path:?} by pid {pid}"
            ),
            Self::LockHeld { path, pid: None } => {
                write!(f, "paranoid local-lock: lock is already held at {path:?}")
            }
            Self::ContentionExceeded { path } => write!(
                f,
                "paranoid local-lock: lock contention did not settle for {path:?}"
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "paranoid local-lock: {operation} {path:?}: {source}"),
            Self::Json { operation, source } => {
                write!(f, "paranoid local-lock: {operation}: {source}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Lock-file behavior.
#[derive(Clone, Default)]
pub struct ProcessLockOptions {
    /// Heartbeat write cadence while the lock is held.
    ///
    /// Defaults to [`DEFAULT_HEARTBEAT_INTERVAL`].
    pub heartbeat_interval: Option<Duration>,
    /// Stale heartbeat threshold before another process may take over.
    ///
    /// Defaults to [`DEFAULT_STALE_AFTER`].
    pub stale_after: Option<Duration>,
    /// Called after a held lock loses ownership.
    pub on_lock_lost: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

impl std::fmt::Debug for ProcessLockOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessLockOptions")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("stale_after", &self.stale_after)
            .field("on_lock_lost", &self.on_lock_lost.is_some())
            .finish()
    }
}

/// Exclusive ownership for one local lock-file path.
#[derive(Debug)]
pub struct ProcessLock {
    path: PathBuf,
    options: ResolvedOptions,
    state: Arc<Mutex<LeaseState>>,
    heartbeat_stop: Option<Sender<()>>,
    heartbeat_done: Option<Receiver<()>>,
}

#[derive(Clone)]
struct ResolvedOptions {
    heartbeat_interval: Duration,
    stale_after: Duration,
    on_lock_lost: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
}

impl std::fmt::Debug for ResolvedOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedOptions")
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("stale_after", &self.stale_after)
            .field("on_lock_lost", &self.on_lock_lost.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct LeaseState {
    held: bool,
    owner_id: String,
}

#[derive(Clone, Debug)]
struct LeaseSnapshot {
    raw_data: Vec<u8>,
    modified: SystemTime,
    record: LeaseRecord,
    parsed: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct LeaseRecord {
    #[serde(rename = "version")]
    version: u32,
    #[serde(rename = "ownerID")]
    owner_id: String,
    #[serde(rename = "pid")]
    pid: u32,
    #[serde(rename = "lastHeartbeatUnixNano")]
    last_heartbeat_unix_nano: u128,
}

impl ProcessLock {
    /// Creates a process lock using default options.
    pub fn new(lock_file_path: impl Into<PathBuf>) -> Self {
        Self::with_options(lock_file_path, ProcessLockOptions::default())
    }

    /// Creates a process lock with explicit options.
    pub fn with_options(lock_file_path: impl Into<PathBuf>, options: ProcessLockOptions) -> Self {
        Self {
            path: lock_file_path.into(),
            options: resolve_options(options),
            state: Arc::new(Mutex::new(LeaseState::default())),
            heartbeat_stop: None,
            heartbeat_done: None,
        }
    }

    /// Returns the full lock-file path.
    pub fn lock_file_path(&self) -> &Path {
        &self.path
    }

    /// Reports whether this process still owns the lock.
    pub fn is_held_by_current_process(&self) -> bool {
        self.state.lock().expect("lock state poisoned").held
    }

    /// Obtains lock ownership or returns [`Error::LockHeld`].
    pub fn acquire(&mut self) -> Result<()> {
        if self.path.to_string_lossy().trim().is_empty() {
            return Err(Error::EmptyPath);
        }
        if self.is_held_by_current_process() {
            return Ok(());
        }

        let parent = self.path.parent().ok_or_else(|| Error::NoParentDirectory {
            path: self.path.clone(),
        })?;
        fs::create_dir_all(parent).map_err(|source| Error::Io {
            operation: "create lock directory",
            path: parent.to_owned(),
            source,
        })?;

        let owner_id = build_owner_id();
        for _ in 0..ACQUIRE_RETRY_LIMIT {
            match self.try_acquire(owner_id.as_str())? {
                TryAcquire::Acquired => {
                    {
                        let mut state = self.state.lock().expect("lock state poisoned");
                        state.held = true;
                        state.owner_id = owner_id.clone();
                    }
                    self.start_heartbeat(owner_id);
                    return Ok(());
                }
                TryAcquire::Held(error) => return Err(error),
                TryAcquire::Retry => thread::sleep(ACQUIRE_RETRY_DELAY),
            }
        }

        Err(Error::ContentionExceeded {
            path: self.path.clone(),
        })
    }

    /// Releases lock ownership by removing the lock file if this process still owns it.
    pub fn release(&mut self) -> Result<()> {
        let owner_id = {
            let mut state = self.state.lock().expect("lock state poisoned");
            let owner_id = if state.held {
                Some(std::mem::take(&mut state.owner_id))
            } else {
                None
            };
            state.held = false;
            owner_id
        };

        self.stop_heartbeat();

        if let Some(owner_id) = owner_id {
            self.try_remove_if_owned(owner_id.as_str())?;
        }
        Ok(())
    }

    fn try_acquire(&self, owner_id: &str) -> Result<TryAcquire> {
        if self.try_create(owner_id)? {
            return Ok(TryAcquire::Acquired);
        }

        let Some(snapshot) = self.read_snapshot()? else {
            return Ok(TryAcquire::Retry);
        };

        if snapshot.parsed {
            if !is_lease_stale(&snapshot.record, self.options.stale_after) {
                return Ok(TryAcquire::Held(Error::LockHeld {
                    path: self.path.clone(),
                    pid: Some(snapshot.record.pid),
                }));
            }
        } else if !is_invalid_lock_stale(snapshot.modified) {
            return Ok(TryAcquire::Held(Error::LockHeld {
                path: self.path.clone(),
                pid: None,
            }));
        }

        if self.try_remove_if_unchanged(&snapshot)? {
            return Ok(TryAcquire::Retry);
        }
        Ok(TryAcquire::Retry)
    }

    fn try_create(&self, owner_id: &str) -> Result<bool> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path);
        let mut file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
            Err(source) => {
                return Err(Error::Io {
                    operation: "create lock file",
                    path: self.path.clone(),
                    source,
                });
            }
        };

        let record = build_lease_record(owner_id);
        let encoded = encode_lease_record(&record)?;
        if let Err(source) = file.write_all(&encoded) {
            let _ = fs::remove_file(&self.path);
            return Err(Error::Io {
                operation: "write lock file lease",
                path: self.path.clone(),
                source,
            });
        }
        Ok(true)
    }

    fn read_snapshot(&self) -> Result<Option<LeaseSnapshot>> {
        let raw_data = match fs::read(&self.path) {
            Ok(raw_data) => raw_data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(Error::Io {
                    operation: "read lock file",
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(Error::Io {
                    operation: "stat lock file",
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let (record, parsed) = parse_lease_record(&raw_data);
        Ok(Some(LeaseSnapshot {
            raw_data,
            modified: metadata.modified().unwrap_or(UNIX_EPOCH),
            record,
            parsed,
        }))
    }

    fn try_remove_if_unchanged(&self, snapshot: &LeaseSnapshot) -> Result<bool> {
        let current_data = match fs::read(&self.path) {
            Ok(current_data) => current_data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(Error::Io {
                    operation: "re-read lock file",
                    path: self.path.clone(),
                    source,
                });
            }
        };
        if current_data != snapshot.raw_data {
            return Ok(false);
        }
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(Error::Io {
                operation: "remove stale lock file",
                path: self.path.clone(),
                source,
            }),
        }
    }

    fn try_remove_if_owned(&self, owner_id: &str) -> Result<bool> {
        let Some(snapshot) = self.read_snapshot()? else {
            return Ok(false);
        };
        if !snapshot.parsed || snapshot.record.owner_id != owner_id {
            return Ok(false);
        }
        self.try_remove_if_unchanged(&snapshot)
    }

    fn start_heartbeat(&mut self, owner_id: String) {
        if self.options.heartbeat_interval.is_zero() {
            return;
        }
        self.stop_heartbeat();

        let (stop_tx, stop_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let path = self.path.clone();
        let interval = self.options.heartbeat_interval;
        let state = Arc::clone(&self.state);
        let on_lock_lost = self.options.on_lock_lost.clone();
        thread::spawn(move || {
            loop {
                match stop_rx.recv_timeout(interval) {
                    Ok(()) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let lost = refresh_heartbeat(&path, owner_id.as_str()).unwrap_or(true);
                        if lost {
                            handle_lock_loss(&state, owner_id.as_str(), on_lock_lost.as_deref());
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            let _ = done_tx.send(());
        });
        self.heartbeat_stop = Some(stop_tx);
        self.heartbeat_done = Some(done_rx);
    }

    fn stop_heartbeat(&mut self) {
        if let Some(stop) = self.heartbeat_stop.take() {
            let _ = stop.send(());
        }
        if let Some(done) = self.heartbeat_done.take() {
            let _ = done.recv();
        }
    }
}

impl Drop for ProcessLock {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

enum TryAcquire {
    Acquired,
    Held(Error),
    Retry,
}

fn resolve_options(options: ProcessLockOptions) -> ResolvedOptions {
    ResolvedOptions {
        heartbeat_interval: options
            .heartbeat_interval
            .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL),
        stale_after: options.stale_after.unwrap_or(DEFAULT_STALE_AFTER),
        on_lock_lost: options.on_lock_lost,
    }
}

fn parse_lease_record(raw_data: &[u8]) -> (LeaseRecord, bool) {
    let Ok(record) = serde_json::from_slice::<LeaseRecord>(raw_data) else {
        return (LeaseRecord::default(), false);
    };
    let parsed = record.version == LEASE_SCHEMA_VERSION
        && !record.owner_id.trim().is_empty()
        && record.pid > 0
        && record.last_heartbeat_unix_nano > 0;
    (record, parsed)
}

fn is_lease_stale(record: &LeaseRecord, threshold: Duration) -> bool {
    let heartbeat = UNIX_EPOCH + Duration::from_nanos(record.last_heartbeat_unix_nano as u64);
    heartbeat.elapsed().unwrap_or_default() >= threshold
}

fn is_invalid_lock_stale(modified_at: SystemTime) -> bool {
    modified_at.elapsed().unwrap_or_default() >= INVALID_LOCK_STALE_AFTER
}

fn build_lease_record(owner_id: &str) -> LeaseRecord {
    LeaseRecord {
        version: LEASE_SCHEMA_VERSION,
        owner_id: owner_id.to_owned(),
        pid: std::process::id(),
        last_heartbeat_unix_nano: unix_nanos_now(),
    }
}

fn encode_lease_record(record: &LeaseRecord) -> Result<Vec<u8>> {
    let mut data = serde_json::to_vec(record).map_err(|source| Error::Json {
        operation: "encode lock file lease",
        source,
    })?;
    data.push(b'\n');
    Ok(data)
}

fn build_owner_id() -> String {
    let sequence = OWNER_ID_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1;
    format!("{}-{}-{sequence}", std::process::id(), unix_nanos_now())
}

fn unix_nanos_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn handle_lock_loss(
    state: &Arc<Mutex<LeaseState>>,
    owner_id: &str,
    on_lock_lost: Option<&(dyn Fn() + Send + Sync + 'static)>,
) {
    let mut state = state.lock().expect("lock state poisoned");
    if !state.held || state.owner_id != owner_id {
        return;
    }
    state.held = false;
    state.owner_id.clear();
    drop(state);

    if let Some(on_lock_lost) = on_lock_lost {
        on_lock_lost();
    }
}

fn refresh_heartbeat(path: &Path, owner_id: &str) -> Result<bool> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(source) => {
            return Err(Error::Io {
                operation: "open lock file for heartbeat",
                path: path.to_owned(),
                source,
            });
        }
    };
    let metadata_at_open = file.metadata().map_err(|source| Error::Io {
        operation: "stat lock file descriptor for heartbeat",
        path: path.to_owned(),
        source,
    })?;

    let mut raw_data = Vec::new();
    file.read_to_end(&mut raw_data)
        .map_err(|source| Error::Io {
            operation: "read lock file for heartbeat",
            path: path.to_owned(),
            source,
        })?;
    let (mut record, parsed) = parse_lease_record(&raw_data);
    if !parsed || record.owner_id != owner_id {
        return Ok(true);
    }

    let metadata_at_path = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(source) => {
            return Err(Error::Io {
                operation: "stat lock file path for heartbeat",
                path: path.to_owned(),
                source,
            });
        }
    };
    if !same_file(&metadata_at_open, &metadata_at_path) {
        return Ok(true);
    }

    record.last_heartbeat_unix_nano = unix_nanos_now();
    let encoded = encode_lease_record(&record)?;
    file.set_len(0).map_err(|source| Error::Io {
        operation: "truncate lock file for heartbeat",
        path: path.to_owned(),
        source,
    })?;
    file.rewind().map_err(|source| Error::Io {
        operation: "seek lock file for heartbeat",
        path: path.to_owned(),
        source,
    })?;
    file.write_all(&encoded).map_err(|source| Error::Io {
        operation: "write lock file heartbeat",
        path: path.to_owned(),
        source,
    })?;

    let metadata_after_write = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(source) => {
            return Err(Error::Io {
                operation: "stat lock file path after heartbeat write",
                path: path.to_owned(),
                source,
            });
        }
    };
    Ok(!same_file(&metadata_at_open, &metadata_after_write))
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn acquire_creates_lock_and_release_removes_it() {
        let path = temp_lock_path("basic");
        let mut lock = ProcessLock::new(&path);

        lock.acquire().unwrap();

        assert!(lock.is_held_by_current_process());
        assert_eq!(lock.lock_file_path(), path.as_path());
        assert!(path.exists());

        lock.release().unwrap();

        assert!(!lock.is_held_by_current_process());
        assert!(!path.exists());
    }

    #[test]
    fn acquire_reports_fresh_owner_as_typed_lock_held_error() {
        let path = temp_lock_path("held");
        let mut first = ProcessLock::new(&path);
        first.acquire().unwrap();
        let mut second = ProcessLock::new(&path);

        let error = second.acquire().unwrap_err();

        assert!(matches!(
            error,
            Error::LockHeld {
                pid: Some(pid),
                ..
            } if pid == std::process::id()
        ));
        first.release().unwrap();
    }

    #[test]
    fn fresh_invalid_lock_file_is_held_with_unknown_owner() {
        let path = temp_lock_path("fresh-invalid");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not json").unwrap();
        let mut lock = ProcessLock::new(&path);

        let error = lock.acquire().unwrap_err();

        assert!(matches!(error, Error::LockHeld { pid: None, .. }));
    }

    #[test]
    fn invalid_old_lock_file_is_reclaimed() {
        let path = temp_lock_path("invalid");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not json").unwrap();
        thread::sleep(INVALID_LOCK_STALE_AFTER + Duration::from_millis(25));
        let mut lock = ProcessLock::new(&path);

        lock.acquire().unwrap();

        assert!(lock.is_held_by_current_process());
        lock.release().unwrap();
    }

    #[test]
    fn stale_valid_lease_is_reclaimed() {
        let path = temp_lock_path("stale-valid");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let record = LeaseRecord {
            version: LEASE_SCHEMA_VERSION,
            owner_id: "stale-owner".to_owned(),
            pid: std::process::id(),
            last_heartbeat_unix_nano: 1,
        };
        fs::write(&path, encode_lease_record(&record).unwrap()).unwrap();
        let mut lock = ProcessLock::with_options(
            &path,
            ProcessLockOptions {
                stale_after: Some(Duration::from_millis(1)),
                ..ProcessLockOptions::default()
            },
        );

        lock.acquire().unwrap();

        assert!(lock.is_held_by_current_process());
        lock.release().unwrap();
    }

    #[test]
    fn release_does_not_remove_lock_owned_by_replacement() {
        let path = temp_lock_path("replacement");
        let mut lock = ProcessLock::with_options(
            &path,
            ProcessLockOptions {
                heartbeat_interval: Some(Duration::from_secs(60)),
                ..ProcessLockOptions::default()
            },
        );
        lock.acquire().unwrap();
        let replacement = LeaseRecord {
            version: LEASE_SCHEMA_VERSION,
            owner_id: "replacement-owner".to_owned(),
            pid: std::process::id(),
            last_heartbeat_unix_nano: unix_nanos_now(),
        };
        fs::write(&path, encode_lease_record(&replacement).unwrap()).unwrap();

        lock.release().unwrap();

        assert!(path.exists());
    }

    #[test]
    fn heartbeat_loss_marks_lock_unheld_invokes_callback_and_release_cleans_thread() {
        let path = temp_lock_path("heartbeat-loss");
        let (lost_tx, lost_rx) = mpsc::channel();
        let mut lock = ProcessLock::with_options(
            &path,
            ProcessLockOptions {
                heartbeat_interval: Some(Duration::from_millis(10)),
                on_lock_lost: Some(Arc::new(move || {
                    let _ = lost_tx.send(());
                })),
                ..ProcessLockOptions::default()
            },
        );
        lock.acquire().unwrap();

        fs::remove_file(&path).unwrap();

        lost_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!lock.is_held_by_current_process());
        lock.release().unwrap();
        assert!(lock.heartbeat_stop.is_none());
        assert!(lock.heartbeat_done.is_none());
    }

    fn temp_lock_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("paranoid-local-lock-{name}-{nonce}/dev.lock"))
    }
}
