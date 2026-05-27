//! Optional SQLx query constructors for app-owned SQL that should remain
//! compatible with transaction-mode connection poolers.

use sqlx::RawSql;
use sqlx::postgres::{PgArguments, PgRow};
use sqlx::query::{Query, QueryAs, QueryScalar};
use sqlx::{Decode, FromRow, Postgres, SqlSafeStr, Type};

/// Constructs an unparameterized SQLx query using Postgres simple-query protocol.
///
/// Use this for DDL and administration statements that cannot bind values.
/// Because simple-query protocol has no bind parameters, only pass dynamic SQL
/// after validating and quoting every dynamic identifier.
pub fn unparameterized_simple_query(sql: impl SqlSafeStr) -> RawSql {
    sqlx::raw_sql(sql)
}

/// Constructs a Postgres SQLx query with persistent server-side statements disabled.
///
/// This helper is optional for application code. Use it when app-owned SQL
/// should follow Paranoid's portable Postgres execution style.
pub fn portable_query<'q>(sql: impl SqlSafeStr + 'q) -> Query<'q, Postgres, PgArguments> {
    sqlx::query::<Postgres>(sql).persistent(false)
}

/// Constructs a typed Postgres SQLx query with persistent server-side statements disabled.
///
/// This is the [`portable_query`] equivalent for SQLx row mapping.
pub fn portable_query_as<'q, O>(sql: impl SqlSafeStr + 'q) -> QueryAs<'q, Postgres, O, PgArguments>
where
    O: for<'r> FromRow<'r, PgRow>,
{
    sqlx::query_as::<Postgres, O>(sql).persistent(false)
}

/// Constructs a scalar Postgres SQLx query with persistent server-side statements disabled.
///
/// This is the [`portable_query`] equivalent for SQLx scalar row mapping.
pub fn portable_query_scalar<'q, O>(
    sql: impl SqlSafeStr + 'q,
) -> QueryScalar<'q, Postgres, O, PgArguments>
where
    O: for<'r> Decode<'r, Postgres> + Type<Postgres>,
{
    sqlx::query_scalar::<Postgres, O>(sql).persistent(false)
}
