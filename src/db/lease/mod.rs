use super::{
    DatabaseOperationKind, DatabaseOperationObserver, DbError, PgQualifiedTableName, Pool,
    WritePool, finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error,
    finish_pool_owned_write_transaction_and_preserve_rollback_error,
    pg_table_name_set_could_contain_same_relation, pooler_safe_query, pooler_safe_query_as,
    pooler_safe_query_scalar, record_database_operation,
};
use super::{Tx, WriteTx};
#[cfg(test)]
use super::{finish_db_pool_transaction, finish_db_pool_validation_transaction};
use sqlx::{Executor, Postgres};
use std::time::Duration as StdDuration;

/// Test-only unqualified lease backing table name.
#[cfg(test)]
pub const TEST_LEASE_TABLE_NAME: &str = "__paranoid_lease_store";

/// Test-only unqualified lease fencing counter backing table name.
#[cfg(test)]
pub const TEST_LEASE_FENCING_COUNTER_TABLE_NAME: &str = "__paranoid_lease_fencing_counters";

/// Separator used when composing persisted lease keys from key parts.
pub const LEASE_KEY_SEPARATOR: &str = "::";

/// Maximum accepted persisted lease key length, in bytes.
pub const MAX_LEASE_KEY_BYTES: usize = 2048;

/// Maximum accepted lease holder identifier length, in bytes.
pub const MAX_LEASE_HOLDER_ID_BYTES: usize = 512;

/// Minimum accepted positive lease duration.
pub const MIN_LEASE_DURATION: StdDuration = StdDuration::from_secs(1);

const LEASE_TOKEN_BYTES: usize = 32;

mod catalog;
mod error;
mod execution;
mod model;
mod queries;
mod schema;
mod store;

use catalog::*;
pub(crate) use error::CoordinationError as Error;
pub use error::CoordinationError;
use model::Token;
pub use model::{Claim, ClaimDuration, FencingToken, HolderId, HolderSnapshot, Key};
use queries::*;
pub(crate) use schema::migrate_schema_in_current_transaction;
use schema::validate_schema_in_current_transaction;
#[cfg(test)]
use schema::{build_migrate_statements, validate_distinct_table_names};
#[cfg(test)]
pub(crate) use schema::{migrate_schema, validate_schema};
pub(crate) use store::{Store, StoreConfig};

#[cfg(test)]
mod postgres_tests;

pub(crate) const LEASE_OPERATION_CLAIM: &str = "lease.claim";
pub(crate) const LEASE_OPERATION_FETCH_LIVE_HOLDER: &str = "lease.fetch_live_holder";
pub(crate) const LEASE_OPERATION_RELEASE: &str = "lease.release";
pub(crate) const LEASE_OPERATION_RENEW: &str = "lease.renew";
pub(crate) const LEASE_OPERATION_SCHEMA_MIGRATE_STATEMENT: &str = "lease.schema.migrate_statement";
pub(crate) const LEASE_OPERATION_SCHEMA_VALIDATE_COLUMNS: &str = "lease.schema.validate_columns";
pub(crate) const LEASE_OPERATION_SCHEMA_VALIDATE_KEY_CONFLICT_ARBITER: &str =
    "lease.schema.validate_key_conflict_arbiter";
pub(crate) const LEASE_OPERATION_SCHEMA_VALIDATE_CHECK_CONSTRAINTS: &str =
    "lease.schema.validate_check_constraints";
pub(crate) const LEASE_OPERATION_SCHEMA_VALIDATE_EXPIRES_AT_INDEX: &str =
    "lease.schema.validate_expires_at_index";
#[cfg(test)]
pub(crate) const LEASE_OPERATION_SCHEMA_MIGRATE: &str = "lease.schema.migrate";
#[cfg(test)]
pub(crate) const LEASE_OPERATION_SCHEMA_VALIDATE: &str = "lease.schema.validate";

async fn finish_lease_pool_transaction<T>(
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

async fn finish_lease_read_transaction<T>(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_sql_uses_c_collation_and_no_session_level_postgres_features() {
        let config = StoreConfig::default();
        let queries = Queries::new(&config);
        let joined = [
            build_migrate_statements(&config).join("\n"),
            queries.claim_lease,
            queries.renew_lease,
            queries.release_lease,
            queries.fetch_live_lease_holder,
        ]
        .join("\n");
        let joined_lowercase = joined.to_lowercase();

        assert!(
            joined
                .contains(r#"key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#)
        );
        assert!(joined.contains(
            r#"holder_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512)"#
        ));
        assert!(joined.contains("fencing_token BIGINT NOT NULL CHECK (fencing_token > 0)"));
        assert!(
            joined.contains("lease_token BYTEA NOT NULL CHECK (octet_length(lease_token) = 32)")
        );
        assert!(
            joined.contains("last_fencing_token BIGINT NOT NULL CHECK (last_fencing_token > 0)")
        );
        for forbidden in ["advisory", "listen", "notify"] {
            assert!(
                !joined_lowercase.contains(forbidden),
                "lease SQL must not contain {forbidden:?}"
            );
        }
    }

    #[test]
    fn lease_authority_queries_are_fenced_by_current_claim_material() {
        let config = StoreConfig::default();
        let queries = Queries::new(&config);

        let claim = queries
            .claim_lease
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let claim_compact = claim.replace(' ', "");
        assert!(
            claim.contains("SELECT fencing_token, expires_at FROM")
                && claim.contains("WHERE key = $1 FOR UPDATE"),
            "claim must lock the existing lease row for this key before deciding claimability: {claim}"
        );
        assert!(
            claim_compact.contains(
                "WHERENOTEXISTS(SELECT1FROMexisting_leaseWHEREexpires_at>statement_timestamp())"
            ),
            "claim must refuse to replace a live lease: {claim}"
        );
        assert!(
            claim_compact.contains(
                "last_fencing_token=GREATEST(counter_target.last_fencing_token+1,EXCLUDED.last_fencing_token)"
            ),
            "claim must monotonically advance the durable fencing counter: {claim}"
        );
        assert!(
            claim_compact.contains("WHERElease_target.expires_at<=statement_timestamp()"),
            "claim upsert must still reject a concurrently live lease: {claim}"
        );

        let renew = queries
            .renew_lease
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            renew.contains("SET lease_token = $5"),
            "renewal must rotate the lease token: {renew}"
        );
        for predicate in [
            "key = $1",
            "holder_id = $2",
            "fencing_token = $3",
            "lease_token = $4",
            "expires_at > statement_timestamp()",
        ] {
            assert!(
                renew.contains(predicate),
                "renewal must require predicate {predicate:?}: {renew}"
            );
        }

        let release = queries
            .release_lease
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for predicate in [
            "key = $1",
            "holder_id = $2",
            "fencing_token = $3",
            "lease_token = $4",
            "expires_at > statement_timestamp()",
        ] {
            assert!(
                release.contains(predicate),
                "release must require predicate {predicate:?}: {release}"
            );
        }
    }

    #[test]
    fn lease_store_config_rejects_ambiguous_state_and_fencing_counter_tables() {
        let unqualified_table = PgQualifiedTableName::unqualified("__paranoid_same_lease_table")
            .expect("valid unqualified table");
        let public_table =
            PgQualifiedTableName::with_schema("public", "__paranoid_same_lease_table")
                .expect("valid public-qualified table");

        let config =
            StoreConfig::new_with_explicit_fencing_counter_table(unqualified_table, public_table);

        let error = validate_distinct_table_names(&config).expect_err("ambiguous table names");
        assert!(
            error
                .to_string()
                .contains("lease state and fencing counter table names must be distinct")
        );
    }

    #[test]
    fn lease_key_from_parts_validates_and_joins_key_parts() {
        let key = Key::from_parts(["fleet", "leader"]).expect("key");
        assert_eq!(key.as_str(), "fleet::leader::");

        assert!(matches!(
            Key::from_parts::<&str, _>([]),
            Err(Error::EmptyKey)
        ));
        assert!(matches!(Key::from_parts([""]), Err(Error::EmptyKeyPart)));
        assert!(matches!(
            Key::from_parts(["has:colon"]),
            Err(Error::KeyPartContainsSeparatorByte)
        ));
        assert!(matches!(
            Key::from_parts(["has\0null"]),
            Err(Error::KeyPartContainsNullByte)
        ));
    }

    #[test]
    fn lease_holder_id_validates_length_and_null_bytes() {
        assert!(HolderId::new("worker-1").is_ok());
        assert!(matches!(HolderId::new(""), Err(Error::EmptyHolderId)));
        assert!(matches!(
            HolderId::new("bad\0holder"),
            Err(Error::HolderIdContainsNullByte)
        ));
        assert!(matches!(
            HolderId::new("a".repeat(MAX_LEASE_HOLDER_ID_BYTES + 1)),
            Err(Error::HolderIdTooLong { .. })
        ));
    }

    #[test]
    fn lease_duration_rejects_zero_too_small_and_too_large_values() {
        assert!(matches!(
            ClaimDuration::expires_after(StdDuration::ZERO),
            Err(Error::DurationIsZero)
        ));
        assert!(matches!(
            ClaimDuration::expires_after(StdDuration::from_millis(999)),
            Err(Error::DurationBelowMinimum { .. })
        ));
        assert!(matches!(
            ClaimDuration::expires_after(StdDuration::from_micros(i64::MAX as u64 + 1)),
            Err(Error::DurationTooLarge)
        ));
        assert!(ClaimDuration::expires_after(MIN_LEASE_DURATION).is_ok());
        assert_eq!(
            ClaimDuration::expires_after(StdDuration::from_secs(1) + StdDuration::from_nanos(1))
                .expect("duration")
                .positive_microseconds()
                .expect("microseconds"),
            1_000_001
        );
    }
}
