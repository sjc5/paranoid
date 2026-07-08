//! Proves [`portable_query`]/[`portable_query_scalar`] are safe to execute directly on a
//! [`Pool`], with no transaction wrap, under connection-pooler backend contention.
//!
//! Every `.bind()` renders its value as a safely-escaped Postgres literal immediately, and
//! executing the query substitutes those literals into the SQL and sends the result as a
//! single simple-protocol `Query` with no bind parameters at all. There is no `Parse`/`Bind`
//! split for a pooler to land on two different backends, so unlike a query built through the
//! Postgres extended protocol, this has no `SQLSTATE 26000 "unnamed prepared statement does
//! not exist"` hazard to reproduce: this test asserts its absence under the same concurrent,
//! backend-rotating contention pattern that would expose it for an extended-protocol query.
//! (Parameterized helpers execute as single simple-protocol messages precisely
//! so transaction-mode poolers cannot observe a prepared-statement lifecycle.)

use secrecy::SecretString;

use super::postgres_test_support::standard_test_database_url;
use super::{Pool, PoolConfig, portable_query_scalar};

const CONCURRENT_QUERY_COUNT: usize = 300;

async fn connect_pool_under_pooler_backend_contention() -> Pool {
    let mut config = PoolConfig::new(SecretString::from(standard_test_database_url()));
    config.max_connections = CONCURRENT_QUERY_COUNT as u32;
    config.application_name = Some("paranoid_db_portable_query_postgres_test".to_owned());
    Pool::connect(config)
        .await
        .expect("connect pool under pooler backend contention")
}

/// Runs [`CONCURRENT_QUERY_COUNT`] concurrent [`portable_query_scalar`] calls directly
/// against `pool.sqlx_pool()` (no `begin_transaction()` wrap), with `max_connections` set
/// so a transaction-mode pooler rotates backends between queries, and asserts every query
/// succeeds and round-trips the value it bound. An extended-protocol query executed this
/// way can fail with `SQLSTATE 26000` because `Parse` and `Bind`/`Execute` are two separate
/// pooler transactions that can land on different backends; `portable_query_scalar` has no
/// such split to begin with, so this contention pattern has nothing to expose.
#[tokio::test]
async fn direct_on_pool_portable_query_scalar_succeeds_under_pooler_backend_contention() {
    let pool = connect_pool_under_pooler_backend_contention().await;

    let mut join_set = tokio::task::JoinSet::new();
    for value in 0..CONCURRENT_QUERY_COUNT as i64 {
        let sqlx_pool = pool.sqlx_pool().clone();
        join_set.spawn(async move {
            let read_back = portable_query_scalar::<i64>("SELECT $1::bigint")
                .bind(value)
                .fetch_one(&sqlx_pool)
                .await
                .expect("direct-on-pool portable_query_scalar fetch_one");
            (value, read_back)
        });
    }

    let mut round_tripped_pairs = Vec::with_capacity(CONCURRENT_QUERY_COUNT);
    while let Some(joined) = join_set.join_next().await {
        round_tripped_pairs.push(joined.expect("join direct-on-pool query task"));
    }
    assert_eq!(round_tripped_pairs.len(), CONCURRENT_QUERY_COUNT);

    for (bound_value, read_back) in round_tripped_pairs {
        assert_eq!(
            read_back, bound_value,
            "value round-tripped through a direct-on-pool portable_query_scalar call did \
             not match what was bound"
        );
    }
}

/// Proves that [`time::OffsetDateTime`] binds through [`IntoPortableQueryLiteral`] as an
/// RFC 3339 text literal cast to `timestamptz`, and that a real Postgres server parses that
/// literal and hands back the exact same instant. A non-UTC offset is used deliberately so
/// this cannot pass by coincidentally normalizing to UTC on both ends without actually
/// carrying the offset through the literal correctly.
///
/// [`IntoPortableQueryLiteral`]: super::portable_query_literal::IntoPortableQueryLiteral
#[tokio::test]
async fn offset_date_time_binds_and_round_trips_as_timestamptz() {
    let pool = connect_pool_under_pooler_backend_contention().await;
    let sqlx_pool = pool.sqlx_pool().clone();

    let date = time::Date::from_calendar_date(2026, time::Month::July, 8).unwrap();
    let time_of_day = time::Time::from_hms_milli(12, 34, 56, 789).unwrap();
    let offset = time::UtcOffset::from_hms(-5, 0, 0).unwrap();
    let bound_value = date.with_time(time_of_day).assume_offset(offset);

    let read_back = portable_query_scalar::<time::OffsetDateTime>("SELECT $1::timestamptz")
        .bind(bound_value)
        .fetch_one(&sqlx_pool)
        .await
        .expect("offset_date_time portable_query_scalar fetch_one");

    assert_eq!(read_back, bound_value);
}

#[tokio::test]
async fn date_binds_and_round_trips_as_date() {
    let pool = connect_pool_under_pooler_backend_contention().await;
    let sqlx_pool = pool.sqlx_pool().clone();

    let bound_value = time::Date::from_calendar_date(2026, time::Month::July, 8).unwrap();
    let read_back = portable_query_scalar::<time::Date>("SELECT $1::date")
        .bind(bound_value)
        .fetch_one(&sqlx_pool)
        .await
        .expect("date portable_query_scalar fetch_one");

    assert_eq!(read_back, bound_value);
}

#[tokio::test]
async fn json_value_binds_and_round_trips_as_jsonb() {
    let pool = connect_pool_under_pooler_backend_contention().await;
    let sqlx_pool = pool.sqlx_pool().clone();

    let bound_value = serde_json::json!({
        "text": "it's \"quoted\" — and unicode: ✓",
        "nested": {"n": 42, "list": [1, 2, 3], "null": null, "flag": true}
    });
    let read_back = portable_query_scalar::<serde_json::Value>("SELECT $1::jsonb")
        .bind(&bound_value)
        .fetch_one(&sqlx_pool)
        .await
        .expect("json portable_query_scalar fetch_one");

    assert_eq!(read_back, bound_value);
}

#[cfg(feature = "db-uuid")]
#[tokio::test]
async fn uuid_binds_and_round_trips_as_uuid() {
    let pool = connect_pool_under_pooler_backend_contention().await;
    let sqlx_pool = pool.sqlx_pool().clone();

    let bound_value = uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
    let read_back = portable_query_scalar::<uuid::Uuid>("SELECT $1::uuid")
        .bind(bound_value)
        .fetch_one(&sqlx_pool)
        .await
        .expect("uuid portable_query_scalar fetch_one");

    assert_eq!(read_back, bound_value);
}

/// Proves, at the wire-protocol level, that a bound [`portable_query`] finishes as a
/// Postgres simple-protocol `Query` rather than an extended-protocol `Parse`/`Bind`/`Execute`.
///
/// The simple query protocol allows a single `Query` message to carry multiple
/// semicolon-separated statements; the extended protocol's `Parse` step rejects multi-statement
/// SQL outright (`cannot insert multiple commands into a prepared statement`). Binding a value
/// into a template whose SQL contains two statements, and asserting the call still succeeds,
/// is therefore an affirmative proof that no extended-protocol `Parse` step exists anywhere on
/// this path: an implementation that routed through `Parse`/`Bind`/`Execute` could not pass
/// this test no matter how the parameters were supplied.
#[tokio::test]
async fn bound_query_permits_multiple_statements_proving_simple_protocol_use() {
    let pool = connect_pool_under_pooler_backend_contention().await;
    let sqlx_pool = pool.sqlx_pool().clone();

    let row_count = super::portable_query("CREATE TEMPORARY TABLE __portable_query_multi_statement_probe (value BIGINT NOT NULL); INSERT INTO __portable_query_multi_statement_probe (value) VALUES ($1)")
        .bind(42_i64)
        .execute(&sqlx_pool)
        .await
        .expect(
            "multi-statement bound portable_query execute \
             (would be rejected by the extended protocol's Parse step)",
        )
        .rows_affected();

    assert_eq!(row_count, 1, "the INSERT statement affects exactly one row");
}
