//! Postgres query constructors for app-owned SQL that stay safe under **every**
//! connection-pooler mode, including statement-mode pooling.
//!
//! [`portable_query`], [`portable_query_as`], and [`portable_query_scalar`] accept the same
//! `$1`, `$2`, ... placeholder SQL and fluent `.bind(value)` calling convention as SQLx's own
//! query constructors, but never use the Postgres extended protocol. Each `.bind()` renders
//! its value immediately as a safely-escaped Postgres literal (reusing the same encoder as
//! [`SimpleQuery`](super::SimpleQuery)); executing the query then substitutes those literals
//! into the SQL template and sends the result as a single simple-protocol `Query` with no
//! bind parameters at all. There is no `Parse`/`Bind` split for a connection pooler to land
//! on two different backends, so this is safe to execute directly on a [`Pool`](super::Pool)
//! or [`WritePool`](super::WritePool) as well as inside a [`Tx`](super::Tx)/
//! [`WriteTx`](super::WriteTx), under every pooler mode.
//!
//! # Injection safety
//!
//! See [`SimpleQuery`](super::SimpleQuery)'s module documentation for the literal-encoding
//! guarantees this shares. SQL structure comes only from the template text passed to
//! [`portable_query`]/[`portable_query_as`]/[`portable_query_scalar`], which — like any other
//! dynamic SQL text in Paranoid — must be a trusted, non-attacker-controlled string; bound
//! values are always rendered as quoted/typed literals and can never widen structure.

use std::marker::PhantomData;

use sqlx::postgres::{PgQueryResult, PgRow};
use sqlx::{Decode, Executor, FromRow, Postgres, RawSql, Row, SqlSafeStr, SqlStr, Type};

use super::Error as DbError;
use super::portable_query_literal::IntoPortableQueryLiteral;
use super::portable_query_template::render_portable_query_sql;

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

impl<'a> AuditedSql<&'a str> {
    /// Borrows the vouched SQL text as a string slice.
    pub(crate) fn as_str(&self) -> &'a str {
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
///
/// To bind *values* while keeping the single-`Query`, pooler-independent simple protocol,
/// use [`SimpleQuery`](crate::db::SimpleQuery), which renders bound values as safely-escaped
/// literals, or use [`portable_query`], which does the same thing while keeping the `$n` +
/// `.bind()` calling convention.
pub fn unparameterized_simple_query(sql: impl SqlSafeStr) -> RawSql {
    sqlx::raw_sql(sql)
}

fn portable_query_error_to_sqlx_error(error: DbError) -> sqlx::Error {
    sqlx::Error::Encode(Box::new(error))
}

/// Constructs a pooler-safe Postgres query.
///
/// This helper is optional for application code. Use it when app-owned SQL should follow
/// Paranoid's portable Postgres execution style: `$1`, `$2`, ... placeholders and a fluent
/// `.bind(value)` call for each, exactly like a SQLx query. Unlike a raw SQLx query, every
/// bound value is rendered as a safely-escaped Postgres literal at bind time and substituted
/// into the SQL before it is ever sent, so the finished statement carries no bind parameters
/// and is safe to execute directly on a [`Pool`](super::Pool)/[`WritePool`](super::WritePool)
/// or inside a transaction, under every connection-pooler mode. If the SQL text itself is
/// dynamic, pass [`AuditedSql`] after validating and quoting all dynamic SQL identifiers and
/// binding ordinary values as parameters.
///
/// A `.bind()` value's encode failure (currently only a NUL byte in text, which Postgres
/// text cannot store) is not reported at the `.bind()` call site; like SQLx's own bind
/// parameters, it is deferred and surfaces when `.execute()`/`.fetch_one()`/etc. is awaited.
pub fn portable_query(sql: impl SqlSafeStr) -> PortableQuery {
    PortableQuery {
        template: sql.into_sql_str(),
        fragments: Vec::new(),
        pending_error: None,
    }
}

/// Constructs a typed pooler-safe Postgres query.
///
/// This is the [`portable_query`] equivalent for SQLx row mapping. See [`portable_query`].
pub fn portable_query_as<O>(sql: impl SqlSafeStr) -> PortableQueryAs<O>
where
    O: for<'r> FromRow<'r, PgRow>,
{
    PortableQueryAs {
        inner: portable_query(sql),
        row_type: PhantomData,
    }
}

/// Constructs a scalar pooler-safe Postgres query.
///
/// This is the [`portable_query`] equivalent for SQLx scalar row mapping. See
/// [`portable_query`].
pub fn portable_query_scalar<O>(sql: impl SqlSafeStr) -> PortableQueryScalar<O>
where
    O: for<'r> Decode<'r, Postgres> + Type<Postgres>,
{
    PortableQueryScalar {
        inner: portable_query(sql),
        scalar_type: PhantomData,
    }
}

/// A pooler-safe Postgres query built by [`portable_query`].
///
/// Bind values with [`PortableQuery::bind`], then finish with [`PortableQuery::execute`],
/// [`PortableQuery::fetch_one`], [`PortableQuery::fetch_all`], or
/// [`PortableQuery::fetch_optional`].
#[derive(Debug)]
pub struct PortableQuery {
    template: SqlStr,
    fragments: Vec<String>,
    pending_error: Option<DbError>,
}

impl PortableQuery {
    /// Binds a value in place of its `$n` placeholder, rendering it immediately as a
    /// safely-escaped Postgres literal.
    ///
    /// See [`portable_query`] for how an encode failure is reported.
    pub fn bind<T>(mut self, value: T) -> Self
    where
        T: IntoPortableQueryLiteral,
    {
        if self.pending_error.is_none() {
            let mut fragment = String::new();
            match value.encode_portable_query_literal(&mut fragment) {
                Ok(()) => self.fragments.push(fragment),
                Err(error) => self.pending_error = Some(error),
            }
        }
        self
    }

    /// Finishes the query into the unparameterized [`RawSql`] it always executes as.
    ///
    /// Crate-internal only; every public finishing method (`execute`, `fetch_one`,
    /// `fetch_all`, `fetch_optional`) routes through this. Exposed at `pub(crate)`
    /// visibility so tests can prove the resulting query carries no bind parameters and
    /// is not eligible for a persistent server-side prepared statement.
    pub(crate) fn into_raw_sql(self) -> Result<RawSql, sqlx::Error> {
        if let Some(error) = self.pending_error {
            return Err(portable_query_error_to_sqlx_error(error));
        }
        let sql = render_portable_query_sql(self.template.as_str(), &self.fragments)
            .map_err(portable_query_error_to_sqlx_error)?;
        Ok(unparameterized_simple_query(sqlx::AssertSqlSafe(sql)))
    }

    /// Executes the query, returning the number of rows affected.
    pub async fn execute<'e, E>(self, executor: E) -> Result<PgQueryResult, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        self.into_raw_sql()?.execute(executor).await
    }

    /// Fetches the first row, or [`sqlx::Error::RowNotFound`] if the query returned none.
    pub async fn fetch_one<'e, E>(self, executor: E) -> Result<PgRow, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        self.into_raw_sql()?.fetch_one(executor).await
    }

    /// Fetches every row.
    pub async fn fetch_all<'e, E>(self, executor: E) -> Result<Vec<PgRow>, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        self.into_raw_sql()?.fetch_all(executor).await
    }

    /// Fetches at most one row.
    pub async fn fetch_optional<'e, E>(self, executor: E) -> Result<Option<PgRow>, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        self.into_raw_sql()?.fetch_optional(executor).await
    }
}

/// A typed pooler-safe Postgres query built by [`portable_query_as`].
#[derive(Debug)]
pub struct PortableQueryAs<O> {
    inner: PortableQuery,
    row_type: PhantomData<fn() -> O>,
}

impl<O> PortableQueryAs<O>
where
    O: for<'r> FromRow<'r, PgRow>,
{
    /// Binds a value in place of its `$n` placeholder. See [`PortableQuery::bind`].
    pub fn bind<T>(mut self, value: T) -> Self
    where
        T: IntoPortableQueryLiteral,
    {
        self.inner = self.inner.bind(value);
        self
    }

    /// Finishes the query into the unparameterized [`RawSql`] it always executes as. See
    /// [`PortableQuery::into_raw_sql`].
    #[cfg(test)]
    pub(crate) fn into_raw_sql(self) -> Result<RawSql, sqlx::Error> {
        self.inner.into_raw_sql()
    }

    /// Fetches the first row, decoded as `O`, or [`sqlx::Error::RowNotFound`] if the query
    /// returned none.
    pub async fn fetch_one<'e, E>(self, executor: E) -> Result<O, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let row = self.inner.fetch_one(executor).await?;
        O::from_row(&row)
    }

    /// Fetches every row, each decoded as `O`.
    pub async fn fetch_all<'e, E>(self, executor: E) -> Result<Vec<O>, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let rows = self.inner.fetch_all(executor).await?;
        rows.iter().map(O::from_row).collect()
    }

    /// Fetches at most one row, decoded as `O`.
    pub async fn fetch_optional<'e, E>(self, executor: E) -> Result<Option<O>, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        match self.inner.fetch_optional(executor).await? {
            Some(row) => Ok(Some(O::from_row(&row)?)),
            None => Ok(None),
        }
    }
}

/// A scalar pooler-safe Postgres query built by [`portable_query_scalar`].
#[derive(Debug)]
pub struct PortableQueryScalar<O> {
    inner: PortableQuery,
    scalar_type: PhantomData<fn() -> O>,
}

impl<O> PortableQueryScalar<O>
where
    O: for<'r> Decode<'r, Postgres> + Type<Postgres>,
{
    /// Binds a value in place of its `$n` placeholder. See [`PortableQuery::bind`].
    pub fn bind<T>(mut self, value: T) -> Self
    where
        T: IntoPortableQueryLiteral,
    {
        self.inner = self.inner.bind(value);
        self
    }

    /// Finishes the query into the unparameterized [`RawSql`] it always executes as. See
    /// [`PortableQuery::into_raw_sql`].
    #[cfg(test)]
    pub(crate) fn into_raw_sql(self) -> Result<RawSql, sqlx::Error> {
        self.inner.into_raw_sql()
    }

    /// Fetches the first row's first column, decoded as `O`, or
    /// [`sqlx::Error::RowNotFound`] if the query returned none.
    pub async fn fetch_one<'e, E>(self, executor: E) -> Result<O, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let row = self.inner.fetch_one(executor).await?;
        row.try_get(0)
    }

    /// Fetches every row's first column, each decoded as `O`.
    pub async fn fetch_all<'e, E>(self, executor: E) -> Result<Vec<O>, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let rows = self.inner.fetch_all(executor).await?;
        rows.iter().map(|row| row.try_get(0)).collect()
    }

    /// Fetches at most one row's first column, decoded as `O`.
    pub async fn fetch_optional<'e, E>(self, executor: E) -> Result<Option<O>, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        match self.inner.fetch_optional(executor).await? {
            Some(row) => Ok(Some(row.try_get(0)?)),
            None => Ok(None),
        }
    }
}
