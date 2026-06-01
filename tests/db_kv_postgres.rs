mod common;

use common::{
    connect_sqlx_pool_for_harness, create_test_schema as common_create_test_schema,
    drop_test_schema as common_drop_test_schema, drop_test_table as common_drop_test_table,
    fetch_table_exists, standard_test_database_url,
};
use paranoid::crypto::{Error, Key32, Keyset, PublicBytes, derive_keyset_from_latest_first_keys};
use paranoid::db::{
    Error as DbError, PgIdentifier, PgQualifiedTableName, Pool, PoolConfig, WritePool,
    portable_query as db_query, portable_query_scalar as db_query_scalar,
    unparameterized_simple_query as db_unparameterized_simple_query,
};
use paranoid::id::SortableId as UniqueTestId;
use paranoid::kv::{
    AtomicLiveMutationResult as KvAtomicLiveMutationResult,
    AtomicLiveOrInitMutationResult as KvAtomicLiveOrInitMutationResult,
    AtomicMutation as KvAtomicMutation, AtomicMutationOutcome as KvAtomicMutationOutcome,
    AtomicMutationResult as KvAtomicMutationResult, BytesSetEntry as KvBytesSetEntry,
    Error as KvError, Item as KvItem,
    ItemAtomicLiveMutationResult as KvItemAtomicLiveMutationResult,
    ItemAtomicLiveOrInitMutationResult as KvItemAtomicLiveOrInitMutationResult,
    ItemAtomicMutation as KvItemAtomicMutation,
    ItemAtomicMutationResult as KvItemAtomicMutationResult,
    ItemGetOrInitResult as KvItemGetOrInitResult, ItemScannedValue as KvItemScannedValue,
    Key as KvKey, KeyPrefix as KvKeyPrefix,
    MAX_ACQUIRE_SLOT_CANDIDATES as MAX_KV_ACQUIRE_SLOT_CANDIDATES,
    MAX_DELETE_BATCH_SIZE as MAX_KV_DELETE_BATCH_SIZE, MAX_GET_MULTI_KEYS as MAX_KV_GET_MULTI_KEYS,
    MAX_KEY_BYTES as MAX_KV_KEY_BYTES, MAX_SCAN_LIMIT as MAX_KV_SCAN_LIMIT,
    MAX_SET_MULTI_ENTRIES as MAX_KV_SET_MULTI_ENTRIES, MIN_TTL as MIN_KV_TTL,
    ScannedBytes as KvScannedBytes, Store as KvStore, StoreConfig as KvStoreConfig, Ttl as KvTtl,
};
use secrecy::SecretString;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;

const COMPATIBLE_KV_KEY_PRIMARY_KEY_COLUMN_DEFINITION: &str = r#"key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#;

#[path = "db_kv_postgres/support.rs"]
mod support;

use support::*;

async fn migrate_kv_schema(pool: &WritePool, config: &KvStoreConfig) -> Result<(), DbError> {
    KvStore::new(config.clone())
        .expect("KV store")
        .migrate_schema(pool)
        .await
}

async fn validate_kv_schema(pool: &Pool, config: &KvStoreConfig) -> Result<(), DbError> {
    KvStore::new(config.clone())
        .expect("KV store")
        .validate_schema(pool)
        .await
}

#[path = "db_kv_postgres/byte_atomic_mutation_timing.rs"]
mod byte_atomic_mutation_timing;
#[path = "db_kv_postgres/byte_atomic_mutations.rs"]
mod byte_atomic_mutations;
#[path = "db_kv_postgres/byte_live_atomic_mutations.rs"]
mod byte_live_atomic_mutations;
#[path = "db_kv_postgres/byte_operations.rs"]
mod byte_operations;
#[path = "db_kv_postgres/byte_ttl_and_prefix_operations.rs"]
mod byte_ttl_and_prefix_operations;
#[path = "db_kv_postgres/cancellation_and_locks.rs"]
mod cancellation_and_locks;
#[path = "db_kv_postgres/db_access.rs"]
mod db_access;
#[path = "db_kv_postgres/schema.rs"]
mod schema;
#[path = "db_kv_postgres/schema_validation_columns.rs"]
mod schema_validation_columns;
#[path = "db_kv_postgres/schema_validation_indexes.rs"]
mod schema_validation_indexes;
#[path = "db_kv_postgres/typed_item_atomic_mutations.rs"]
mod typed_item_atomic_mutations;
#[path = "db_kv_postgres/typed_item_contention.rs"]
mod typed_item_contention;
#[path = "db_kv_postgres/typed_item_lifecycle.rs"]
mod typed_item_lifecycle;
#[path = "db_kv_postgres/typed_item_roundtrip_and_edges.rs"]
mod typed_item_roundtrip_and_edges;
#[path = "db_kv_postgres/typed_item_scan_and_lifecycle.rs"]
mod typed_item_scan_and_lifecycle;
#[path = "db_kv_postgres/typed_plain_items.rs"]
mod typed_plain_items;
