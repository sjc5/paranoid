use super::{
    ComponentSchemaVersion, DatabaseOperationKind, DatabaseOperationObserver, DbError,
    PgQualifiedTableName, Pool, Tx, WritePool, WriteTx,
    finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error,
    finish_pool_owned_write_transaction_and_preserve_rollback_error,
    normalize_check_constraint_expression, pg_table_name_set_could_contain_same_relation,
    pooler_safe_query, pooler_safe_query_as, pooler_safe_query_scalar,
    record_component_schema_version_in_current_transaction, record_database_operation,
    schema_instance_key_for_parts, validate_component_schema_version_in_current_transaction,
};
#[cfg(test)]
use super::{
    finish_db_pool_transaction, finish_db_pool_validation_transaction,
    test_schema_ledger_table_name,
};
use crate::crypto::Error as CodecError;
use crate::crypto::envelope::encrypt_plaintext_bytes_as;
use crate::crypto::envelope::{Encrypted, Plaintext, decrypt, encrypt};
use crate::crypto::keyset::Keyset;
use sqlx::{Executor, Postgres};
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

/// Test-only unqualified KV backing table name.
#[cfg(test)]
pub const TEST_KV_TABLE_NAME: &str = "__paranoid_kv_store";

/// Separator used when composing persisted KV keys from key parts.
pub const KV_KEY_SEPARATOR: &str = "::";

/// Maximum accepted persisted KV key length, in bytes.
pub const MAX_KV_KEY_BYTES: usize = 2048;

/// Minimum accepted positive KV TTL.
pub const MIN_KV_TTL: Duration = Duration::from_secs(1);

/// Default maximum number of rows deleted by one batch-delete statement.
pub const DEFAULT_KV_DELETE_BATCH_SIZE: u32 = 1000;

/// Default delay between full expired-key cleanup batches.
pub const DEFAULT_KV_DELETE_BATCH_DELAY: Duration = Duration::from_millis(10);

/// Maximum accepted number of rows deleted by one batch-delete statement.
pub const MAX_KV_DELETE_BATCH_SIZE: u32 = 10_000;

/// Maximum accepted scan result limit.
pub const MAX_KV_SCAN_LIMIT: u32 = 10_000;

/// Maximum number of keys accepted by one multi-get operation.
pub const MAX_KV_GET_MULTI_KEYS: usize = 10_000;

/// Maximum number of entries accepted by one multi-set operation.
pub const MAX_KV_SET_MULTI_ENTRIES: usize = 10_000;

/// Maximum number of candidate keys accepted by one slot acquisition.
pub const MAX_KV_ACQUIRE_SLOT_CANDIDATES: usize = 10_000;

const INDEX_KIND: &str = "idx";
const EXPIRES_AT_INDEX_SUFFIX: &str = "expires_at";
const KEY_PATTERN_INDEX_SUFFIX: &str = "key_pattern";
const UPDATED_AT_INDEX_SUFFIX: &str = "updated_at";
const KV_SCHEMA_COMPONENT: &str = "kv";
const KV_SCHEMA_VERSION: i32 = 1;
const KV_SCHEMA_FINGERPRINT: &str = "paranoid.kv.v1";
pub(crate) const KV_OPERATION_SET_BYTES: &str = "kv.set_bytes";
pub(crate) const KV_OPERATION_SET_BYTES_RETURNING_DATABASE_TIMESTAMP: &str =
    "kv.set_bytes_returning_database_timestamp";
pub(crate) const KV_OPERATION_SET_BYTES_IF_NOT_EXISTS: &str = "kv.set_bytes_if_not_exists";
pub(crate) const KV_OPERATION_SET_BYTES_IF_NOT_EXISTS_RETURNING_DATABASE_TIMESTAMP: &str =
    "kv.set_bytes_if_not_exists_returning_database_timestamp";
pub(crate) const KV_OPERATION_GET_BYTES: &str = "kv.get_bytes";
pub(crate) const KV_OPERATION_GET_BYTES_RETURNING_DATABASE_TIMESTAMP: &str =
    "kv.get_bytes_returning_database_timestamp";
pub(crate) const KV_OPERATION_GET_BYTES_MULTI: &str = "kv.get_bytes_multi";
pub(crate) const KV_OPERATION_SET_BYTES_MULTI: &str = "kv.set_bytes_multi";
pub(crate) const KV_OPERATION_TOUCH_KEY: &str = "kv.touch_key";
pub(crate) const KV_OPERATION_SET_KEY_TTL: &str = "kv.set_key_ttl";
pub(crate) const KV_OPERATION_EXPIRE_KEY: &str = "kv.expire_key";
pub(crate) const KV_OPERATION_DELETE_KEY: &str = "kv.delete_key";
pub(crate) const KV_OPERATION_CHECK_KEY_EXISTS: &str = "kv.check_key_exists";
pub(crate) const KV_OPERATION_COUNT_LIVE_KEYS_WITH_PREFIX: &str = "kv.count_live_keys_with_prefix";
pub(crate) const KV_OPERATION_SCAN_BYTES_WITH_PREFIX: &str = "kv.scan_bytes_with_prefix";
pub(crate) const KV_OPERATION_SCAN_KEYS_WITH_PREFIX: &str = "kv.scan_keys_with_prefix";
pub(crate) const KV_OPERATION_DELETE_EXPIRED_KEYS_ONCE: &str = "kv.delete_expired_keys_once";
pub(crate) const KV_OPERATION_DELETE_KEYS_WITH_PREFIX_ONCE: &str =
    "kv.delete_keys_with_prefix_once";
pub(crate) const KV_OPERATION_DELETE_NAMESPACE_KEYS_WITH_PREFIX_ONCE: &str =
    "kv.delete_namespace_keys_with_prefix_once";
pub(crate) const KV_OPERATION_ENSURE_SLOT_KEYS_EXIST: &str = "kv.ensure_slot_keys_exist";
pub(crate) const KV_OPERATION_ACQUIRE_SLOT: &str = "kv.acquire_slot";
pub(crate) const KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION: &str =
    "kv.lock_key_for_atomic_mutation";
pub(crate) const KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION: &str =
    "kv.set_bytes_for_atomic_mutation";
pub(crate) const KV_OPERATION_SET_BYTES_PRESERVING_EXPIRATION_FOR_ATOMIC_MUTATION: &str =
    "kv.set_bytes_preserving_expiration_for_atomic_mutation";
pub(crate) const KV_OPERATION_DELETE_KEY_FOR_ATOMIC_MUTATION: &str =
    "kv.delete_key_for_atomic_mutation";
pub(crate) const KV_OPERATION_GET_OR_INIT_ITEM: &str = "kv.item.get_or_init";
pub(crate) const KV_OPERATION_MUTATE_ITEM_ATOMICALLY: &str = "kv.item.mutate_atomically";
pub(crate) const KV_OPERATION_MUTATE_LIVE_ITEM_ATOMICALLY: &str = "kv.item.mutate_live_atomically";
pub(crate) const KV_OPERATION_MUTATE_LIVE_OR_INIT_ITEM_ATOMICALLY: &str =
    "kv.item.mutate_live_or_insert_initial_value_atomically";
pub(crate) const KV_OPERATION_DELETE_ENTIRE_ITEM_NAMESPACE: &str =
    "kv.item.delete_entire_namespace_atomically";
pub(crate) const KV_OPERATION_ACQUIRE_ITEM_SLOT: &str = "kv.item.acquire_slot";
pub(crate) const KV_OPERATION_MUTATE_KEY_ATOMICALLY: &str = "kv.mutate_key_atomically";
pub(crate) const KV_OPERATION_MUTATE_LIVE_KEY_ATOMICALLY: &str = "kv.mutate_live_key_atomically";
pub(crate) const KV_OPERATION_MUTATE_LIVE_OR_INIT_KEY_ATOMICALLY: &str =
    "kv.mutate_live_key_or_insert_initial_value_atomically";
pub(crate) const KV_OPERATION_SCHEMA_CREATE_TABLE: &str = "kv.schema.create_table";
pub(crate) const KV_OPERATION_SCHEMA_CREATE_INDEX: &str = "kv.schema.create_index";
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE_COLUMNS: &str = "kv.schema.validate_columns";
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER: &str =
    "kv.schema.validate_key_conflict_arbiter";
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS: &str =
    "kv.schema.validate_check_constraints";
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX: &str =
    "kv.schema.validate_expires_at_index";
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE_KEY_PATTERN_INDEX: &str =
    "kv.schema.validate_key_pattern_index";
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE_UPDATED_AT_INDEX: &str =
    "kv.schema.validate_updated_at_index";
#[cfg(test)]
pub(crate) const KV_OPERATION_SCHEMA_MIGRATE: &str = "kv.schema.migrate";
#[cfg(test)]
pub(crate) const KV_OPERATION_SCHEMA_VALIDATE: &str = "kv.schema.validate";

const CREATE_KV_TABLE_TEMPLATE_PREFIX: &str = "CREATE TABLE IF NOT EXISTS ";
const NOT_EXPIRED_FILTER: &str = "(expires_at IS NULL OR expires_at > statement_timestamp())";
const EXPIRED_FILTER: &str = "(expires_at IS NOT NULL AND expires_at <= statement_timestamp())";

/// Errors returned by the Postgres-backed KV primitive.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// KV table and schema ledger table names must be distinct.
    #[error("KV table and schema ledger table names must be distinct")]
    TableNamesMustBeDistinct,
    /// A key needed at least one part.
    #[error("KV key must contain at least one part")]
    EmptyKey,
    /// A key part was empty.
    #[error("KV key part must not be empty")]
    EmptyKeyPart,
    /// A key part contained the key separator byte.
    #[error("KV key part must not contain ':'")]
    KeyPartContainsSeparatorByte,
    /// A key part contained a null byte.
    #[error("KV key part must not contain null bytes")]
    KeyPartContainsNullByte,
    /// A composed key exceeded the maximum accepted byte length.
    #[error("KV key is {actual} bytes, maximum is {max}")]
    KeyTooLong {
        /// Actual key byte length.
        actual: usize,
        /// Maximum accepted key byte length.
        max: usize,
    },
    /// A positive TTL must be supplied through `Ttl::expires_after`.
    #[error("KV TTL cannot be zero")]
    TtlIsZero,
    /// A positive TTL was below [`crate::kv::MIN_TTL`].
    #[error("KV TTL is below the minimum of {minimum:?}")]
    TtlBelowMinimum {
        /// Minimum accepted positive TTL.
        minimum: Duration,
    },
    /// A TTL was too large to bind safely as microseconds.
    #[error("KV TTL is too large")]
    TtlTooLarge,
    /// A slot acquisition requires a positive expiration.
    #[error("KV slot acquisition requires an expiring TTL")]
    TtlNoExpirationNotAllowed,
    /// A scan limit must be at least one row.
    #[error("KV scan limit cannot be zero")]
    ScanLimitIsZero,
    /// A scan limit exceeded [`crate::kv::MAX_SCAN_LIMIT`].
    #[error("KV scan limit is {actual}, maximum is {max}")]
    ScanLimitTooLarge {
        /// Actual requested scan limit.
        actual: u32,
        /// Maximum accepted scan limit.
        max: u32,
    },
    /// A scan cursor did not belong to the scanned prefix.
    #[error("KV scan cursor is outside the requested key prefix")]
    ScanCursorOutsidePrefix,
    /// A multi-get request exceeded [`crate::kv::MAX_GET_MULTI_KEYS`].
    #[error("KV multi-get key count is {actual}, maximum is {max}")]
    GetMultiKeyCountTooLarge {
        /// Actual requested key count.
        actual: usize,
        /// Maximum accepted key count.
        max: usize,
    },
    /// A multi-set request exceeded [`crate::kv::MAX_SET_MULTI_ENTRIES`].
    #[error("KV multi-set entry count is {actual}, maximum is {max}")]
    SetMultiEntryCountTooLarge {
        /// Actual requested entry count.
        actual: usize,
        /// Maximum accepted entry count.
        max: usize,
    },
    /// A typed multi-set request received different key and value counts.
    #[error("KV typed multi-set key count {key_count} does not match value count {value_count}")]
    SetMultiLengthMismatch {
        /// Number of supplied keys.
        key_count: usize,
        /// Number of supplied values.
        value_count: usize,
    },
    /// A bulk operation received the same persisted key more than once.
    #[error("KV bulk operation received a duplicate key")]
    DuplicateKeyInBulkOperation,
    /// A slot-acquisition request exceeded [`crate::kv::MAX_ACQUIRE_SLOT_CANDIDATES`].
    #[error("KV slot acquisition candidate count is {actual}, maximum is {max}")]
    AcquireSlotCandidateCountTooLarge {
        /// Actual requested candidate count.
        actual: usize,
        /// Maximum accepted candidate count.
        max: usize,
    },
    /// A batch-delete size must be at least one row.
    #[error("KV batch-delete size cannot be zero")]
    DeleteBatchSizeIsZero,
    /// A batch-delete size exceeded [`crate::kv::MAX_DELETE_BATCH_SIZE`].
    #[error("KV batch-delete size is {actual}, maximum is {max}")]
    DeleteBatchSizeTooLarge {
        /// Actual requested batch-delete size.
        actual: u32,
        /// Maximum accepted batch-delete size.
        max: u32,
    },
    /// A key could not be locked for atomic mutation after repeated attempts.
    #[error("KV key could not be locked for atomic mutation")]
    AtomicMutationCouldNotLockKey,
    /// A KV atomic mutation callback was invoked more than once.
    #[error("KV atomic mutation callback was invoked more than once")]
    AtomicMutationCallbackInvokedMoreThanOnce,
    /// A KV atomic mutation lock completed without returning the locked row.
    #[error("KV atomic mutation lock completed without returning the locked row")]
    AtomicMutationLockReturnedNoRow,
    /// A KV atomic mutation did not capture the current value presented to the callback.
    #[error("KV atomic mutation did not capture the current value presented to the callback")]
    AtomicMutationCurrentValueWasNotCaptured,
    /// The requested key is absent or expired.
    #[error("KV key not found")]
    KeyNotFound,
    /// A database operation failed.
    #[error(transparent)]
    Database(#[from] crate::db::Error),
    /// A KV database operation failed and its cleanup rollback also failed.
    #[error("KV database operation {operation} failed, then transaction rollback failed")]
    DatabaseOperationRollbackFailed {
        /// Operation being cleaned up.
        operation: &'static str,
        /// Original operation error.
        operation_error: Box<Error>,
        /// Rollback failure.
        rollback_error: crate::db::Error,
    },
    /// A KV callback-shaped operation failed and its cleanup rollback also failed.
    #[error(
        "KV database operation {operation} failed with a caller-provided error, then transaction rollback failed"
    )]
    DatabaseOperationRollbackFailedAfterCallerError {
        /// Operation being cleaned up.
        operation: &'static str,
        /// Rollback failure.
        rollback_error: crate::db::Error,
    },
    /// A typed or encrypted item value could not be encoded or decoded.
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// Validated persisted KV key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key(String);

/// Validated persisted KV key prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyPrefix(String);

/// Validated KV TTL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ttl {
    positive_duration: Option<Duration>,
}

/// Scanned KV row containing a full persisted key and its bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedBytes {
    /// Full persisted key.
    pub key: Key,
    /// Stored value bytes.
    pub value: Vec<u8>,
}

/// Bytes to store for one key in a multi-set operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytesSetEntry {
    key: Key,
    value: Vec<u8>,
}

/// Bytes loaded from KV together with the database timestamp for the read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytesWithDatabaseTimestamp {
    /// Stored value bytes.
    pub value: Vec<u8>,
    /// Database statement timestamp for the read.
    pub database_timestamp: DatabaseTimestampMicros,
}

/// Database statement timestamp returned by a KV write, expressed as Unix microseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DatabaseTimestampMicros(i64);

/// Result of a conditional KV write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetIfNotExistsResult {
    /// Whether this call stored the value.
    pub was_set: bool,
    /// Database timestamp for the write, present only when `was_set` is true.
    pub database_timestamp: Option<DatabaseTimestampMicros>,
}

async fn finish_kv_pool_transaction<T>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, Error>,
) -> Result<T, Error> {
    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}

async fn finish_kv_read_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, Error>,
) -> Result<T, Error> {
    finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        Error::from,
        |operation, error, rollback_error| Error::DatabaseOperationRollbackFailed {
            operation,
            operation_error: Box::new(error),
            rollback_error,
        },
    )
    .await
}

async fn finish_kv_callback_pool_transaction<T, E>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, E>,
) -> Result<T, E>
where
    E: From<Error>,
{
    finish_pool_owned_write_transaction_and_preserve_rollback_error(
        operation,
        tx,
        result,
        |error| E::from(Error::from(error)),
        |operation, _error, rollback_error| {
            E::from(Error::DatabaseOperationRollbackFailedAfterCallerError {
                operation,
                rollback_error,
            })
        },
    )
    .await
}

/// Scanned typed KV item containing a key suffix and decoded value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemScannedValue<T> {
    /// Key suffix under the item's configured prefix.
    pub key_suffix: String,
    /// Decoded value.
    pub value: T,
}

/// Result returned by `Item::get_or_init`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemGetOrInitResult<T> {
    /// Existing or initialized value.
    pub value: T,
    /// Whether this call initialized the key.
    pub initialized: bool,
}

/// Typed value loaded from KV together with the database timestamp for the read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemWithDatabaseTimestamp<T> {
    /// Decoded value.
    pub value: T,
    /// Database statement timestamp for the read.
    pub database_timestamp: DatabaseTimestampMicros,
}

/// Current typed value presented to an item atomic mutation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemAtomicMutationCurrent<'a, T> {
    live_value: Option<&'a T>,
    database_timestamp: DatabaseTimestampMicros,
}

/// Current typed live value presented to an existing-item atomic mutation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemAtomicLiveMutationCurrent<'a, T> {
    live_value: &'a T,
    database_timestamp: DatabaseTimestampMicros,
}

/// Typed mutation to apply after an item key has been locked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ItemAtomicMutation<T> {
    /// Keep the currently loaded live value, or keep absence if no live value exists.
    KeepExisting,
    /// Store a replacement value with the supplied TTL.
    SetValue {
        /// Replacement value.
        value: T,
        /// Replacement TTL.
        ttl: Ttl,
    },
    /// Store a replacement value while preserving the locked row's current expiration.
    SetValuePreservingExpiration {
        /// Replacement value.
        value: T,
    },
    /// Physically delete the key row, even if the existing row is expired.
    Delete,
}

/// Result returned after a typed item atomic mutation is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemAtomicMutationResult<T> {
    /// Live value observed while the key lock was held.
    pub previous_live_value: Option<T>,
    /// Mutation outcome.
    pub outcome: AtomicMutationOutcome,
}

/// Result returned after an existing typed item atomic mutation is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemAtomicLiveMutationResult<T> {
    /// Live value observed while the key lock was held.
    pub previous_live_value: T,
    /// Mutation outcome.
    pub outcome: AtomicMutationOutcome,
}

/// Result returned after an item atomic mutation that initializes absent keys before callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemAtomicLiveOrInitMutationResult<T> {
    /// Whether this operation initialized the key before invoking the mutation callback.
    pub initialized: bool,
    /// Live value that was presented to the mutation callback.
    pub live_value_seen_by_callback: T,
    /// Mutation outcome.
    pub outcome: AtomicMutationOutcome,
}

/// Typed accessor scoped to one KV key prefix.
pub struct Item<T> {
    store: Store,
    prefix: KeyPrefix,
    codec: ItemCodec,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for Item<T> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            prefix: self.prefix.clone(),
            codec: self.codec.clone(),
            marker: PhantomData,
        }
    }
}

#[derive(Clone)]
enum ItemCodec {
    Plain,
    Encrypted {
        get_keyset: Arc<dyn Fn() -> Result<Arc<Keyset>, CodecError> + Send + Sync + 'static>,
    },
}

/// Current live value presented to an atomic mutation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicMutationCurrent<'a> {
    live_value: Option<&'a [u8]>,
    database_timestamp: DatabaseTimestampMicros,
}

/// Current live value presented to an existing-key atomic mutation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicLiveMutationCurrent<'a> {
    live_value: &'a [u8],
    database_timestamp: DatabaseTimestampMicros,
}

/// Mutation to apply after a key has been locked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicMutation {
    /// Keep the currently loaded live value, or keep absence if no live value exists.
    KeepExisting,
    /// Store replacement bytes with the supplied TTL.
    SetBytes {
        /// Replacement value bytes.
        value: Vec<u8>,
        /// Replacement TTL.
        ttl: Ttl,
    },
    /// Store replacement bytes while preserving the locked row's current expiration.
    SetBytesPreservingExpiration {
        /// Replacement value bytes.
        value: Vec<u8>,
    },
    /// Physically delete the key row, even if the existing row is expired.
    Delete,
}

/// Outcome of an atomic mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicMutationOutcome {
    /// A live value existed and was kept.
    KeptLiveValue,
    /// No live value existed and absence was kept.
    KeptAbsent,
    /// Replacement bytes were stored.
    SetBytes,
    /// Replacement bytes were stored without changing the previous expiration.
    SetBytesPreservingExpiration,
    /// A live value existed and was deleted.
    DeletedLiveValue,
    /// No live value existed and the key was left absent.
    DeletedAbsent,
}

/// Result returned after an atomic mutation is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicMutationResult {
    /// Live value observed while the key lock was held.
    pub previous_live_value: Option<Vec<u8>>,
    /// Mutation outcome.
    pub outcome: AtomicMutationOutcome,
}

/// Result returned after an existing-key atomic mutation is applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicLiveMutationResult {
    /// Live bytes observed while the key lock was held.
    pub previous_live_value: Vec<u8>,
    /// Mutation outcome.
    pub outcome: AtomicMutationOutcome,
}

/// Result returned after an atomic mutation that initializes absent keys before callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicLiveOrInitMutationResult {
    /// Whether this operation initialized the key before invoking the mutation callback.
    pub initialized: bool,
    /// Live bytes that were presented to the mutation callback.
    pub live_value_seen_by_callback: Vec<u8>,
    /// Mutation outcome.
    pub outcome: AtomicMutationOutcome,
}

/// Schema configuration for the Postgres-backed KV primitive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoreConfig {
    /// Backing table for KV rows.
    pub(crate) table_name: PgQualifiedTableName,
    /// Schema ledger table for this KV store.
    pub(crate) schema_ledger_table_name: PgQualifiedTableName,
    /// Whether migration should create and validation should require `updated_at`.
    pub(crate) create_updated_at_index: bool,
}

/// Postgres-backed KV store bound to one configured table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store {
    config: StoreConfig,
    queries: Queries,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Queries {
    get_bytes: String,
    get_bytes_returning_database_timestamp: String,
    get_bytes_multi: String,
    set_bytes_with_ttl: String,
    set_bytes_no_expiration: String,
    set_bytes_with_ttl_returning_database_timestamp: String,
    set_bytes_no_expiration_returning_database_timestamp: String,
    set_bytes_multi_with_ttl: String,
    set_bytes_multi_no_expiration: String,
    set_bytes_if_not_exists_with_ttl: String,
    set_bytes_if_not_exists_no_expiration: String,
    set_bytes_if_not_exists_with_ttl_returning_database_timestamp: String,
    set_bytes_if_not_exists_no_expiration_returning_database_timestamp: String,
    touch_key: String,
    set_key_ttl_with_ttl: String,
    set_key_ttl_no_expiration: String,
    expire_key: String,
    delete_key: String,
    check_key_exists: String,
    delete_expired_keys_once: String,
    count_live_keys_with_prefix: String,
    scan_bytes_with_prefix: String,
    scan_keys_with_prefix: String,
    delete_keys_with_prefix_once: String,
    delete_namespace_keys_with_prefix_once: String,
    ensure_slot_keys_exist: String,
    acquire_slot: String,
    lock_key_for_atomic_mutation: String,
    update_key_value_with_ttl_for_atomic_mutation: String,
    update_key_value_no_expiration_for_atomic_mutation: String,
    update_key_value_preserving_expiration_for_atomic_mutation: String,
    delete_key_for_atomic_mutation: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequiredColumn {
    name: &'static str,
    data_type: &'static str,
    not_null: bool,
    allowed_collations: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActualColumn {
    name: String,
    data_type: String,
    not_null: bool,
    collation: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LockedKvRow {
    value: Vec<u8>,
    is_live: bool,
    database_timestamp: DatabaseTimestampMicros,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedMultiGetKeys {
    keys: Vec<String>,
    key_to_index: HashMap<String, usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedSlotCandidateKeys {
    keys: Vec<Key>,
    key_to_suffix: HashMap<String, String>,
}

mod item;
mod item_atomic;
mod item_lifecycle;
mod item_read;
mod item_support;
mod item_write;
mod keys;
mod mutation;
mod schema;
mod sql;
mod store;
mod store_atomic_api;
mod store_execution;
mod store_execution_atomic;
mod store_execution_maintenance;
mod validation;

#[cfg(test)]
use schema::build_migrate_statements;
#[cfg(test)]
pub(crate) use schema::{migrate_schema, validate_schema};
pub(crate) use schema::{
    migrate_schema_in_current_transaction, validate_schema_in_current_transaction,
};
use validation::*;

#[cfg(test)]
mod postgres_operation_count_tests;
#[cfg(test)]
mod postgres_tests;
#[cfg(test)]
mod tests;
