//! Optional SQLx query constructors for app-owned SQL that should remain
//! compatible with transaction-mode connection poolers.

use sqlx::postgres::{PgArguments, PgRow};
use sqlx::query::{Query, QueryAs, QueryScalar};
use sqlx::{Decode, FromRow, Postgres, SqlSafeStr, Type};
use sqlx::{RawSql, SqlStr};

/// Dynamic SQL text whose construction has been audited for injection safety.
///
/// This is an explicit assertion, not a sanitizer. Use it only when SQL must be
/// assembled dynamically, such as DDL containing Paranoid-validated and quoted
/// Postgres identifiers. Ordinary dynamic values should use bind parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedSql<T>(T);

impl<T> AuditedSql<T> {
    /// Marks SQL text as audited for injection safety.
    pub const fn new(sql: T) -> Self {
        Self(sql)
    }

    /// Returns the wrapped SQL text.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> SqlSafeStr for AuditedSql<T>
where
    sqlx::AssertSqlSafe<T>: SqlSafeStr,
{
    fn into_sql_str(self) -> SqlStr {
        sqlx::AssertSqlSafe(self.0).into_sql_str()
    }
}

/// Constructs an unparameterized SQLx query using Postgres simple-query protocol.
///
/// Use this for DDL and administration statements that cannot bind values.
/// Because simple-query protocol has no bind parameters, only pass dynamic SQL
/// through [`AuditedSql`] after validating and quoting every dynamic identifier.
pub fn unparameterized_simple_query(sql: impl SqlSafeStr) -> RawSql {
    sqlx::raw_sql(sql)
}

/// Constructs a Postgres SQLx query with persistent server-side statements disabled.
///
/// This helper is optional for application code. Use it when app-owned SQL
/// should follow Paranoid's portable Postgres execution style. If the SQL text
/// is dynamic, pass [`AuditedSql`] after validating and quoting all dynamic SQL
/// identifiers and binding ordinary values as parameters.
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
