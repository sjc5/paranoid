//! Postgres-backed key-value storage primitives.
//!
//! `kv::Store` owns a validated table configuration and exposes explicit
//! pool-vs-transaction methods. Use the pool methods for standalone
//! operations, and the `*_in_current_transaction` methods when the KV write
//! must commit atomically with app-owned SQL.
//!
//! ```rust,no_run
//! # #[cfg(feature = "db")]
//! # async fn example(pool: paranoid::db::WritePool) -> Result<(), Box<dyn std::error::Error>> {
//! use paranoid::db::BootstrapConfig;
//! use paranoid::kv::{Key, Ttl};
//!
//! let stores = BootstrapConfig::default().migrate_schema(&pool).await?;
//! let store = stores.kv;
//!
//! let key = Key::from_parts(["account", "acct_123", "status"])?;
//! store
//!     .set_bytes(&pool, &key, b"active", Ttl::no_expiration())
//!     .await?;
//! let status = store.get_bytes(&pool, &key).await?;
//! assert_eq!(status.as_slice(), b"active");
//! # Ok(())
//! # }
//! ```

pub use crate::db::kv::{
    AtomicLiveMutationCurrent, AtomicLiveMutationResult, AtomicLiveOrInitMutationResult,
    AtomicMutation, AtomicMutationCurrent, AtomicMutationOutcome, AtomicMutationResult,
    BytesSetEntry, BytesWithDatabaseTimestamp,
    DEFAULT_KV_DELETE_BATCH_DELAY as DEFAULT_DELETE_BATCH_DELAY,
    DEFAULT_KV_DELETE_BATCH_SIZE as DEFAULT_DELETE_BATCH_SIZE, DatabaseTimestampMicros, Error,
    Item, ItemAtomicLiveMutationCurrent, ItemAtomicLiveMutationResult,
    ItemAtomicLiveOrInitMutationResult, ItemAtomicMutation, ItemAtomicMutationCurrent,
    ItemAtomicMutationResult, ItemGetOrInitResult, ItemScannedValue, ItemWithDatabaseTimestamp,
    KV_KEY_SEPARATOR as KEY_SEPARATOR, Key, KeyPrefix,
    MAX_KV_ACQUIRE_SLOT_CANDIDATES as MAX_ACQUIRE_SLOT_CANDIDATES,
    MAX_KV_DELETE_BATCH_SIZE as MAX_DELETE_BATCH_SIZE, MAX_KV_GET_MULTI_KEYS as MAX_GET_MULTI_KEYS,
    MAX_KV_KEY_BYTES as MAX_KEY_BYTES, MAX_KV_SCAN_LIMIT as MAX_SCAN_LIMIT,
    MAX_KV_SET_MULTI_ENTRIES as MAX_SET_MULTI_ENTRIES, MIN_KV_TTL as MIN_TTL, ScannedBytes,
    SetIfNotExistsResult, Store, Ttl,
};
