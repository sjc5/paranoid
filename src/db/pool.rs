use super::{DatabaseOperationKind, DatabaseOperationObserver, Error};
use secrecy::{ExposeSecret, SecretString};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::time::Duration;

pub(crate) const POOLER_SAFE_STATEMENT_CACHE_CAPACITY: usize = 0;

const DEFAULT_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_MIN_CONNECTIONS: u32 = 0;
const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Pool configuration for Paranoid-owned Postgres connections.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Postgres connection URL.
    pub database_url: SecretString,
    /// Maximum number of open pool connections.
    pub max_connections: u32,
    /// Minimum number of idle pool connections to maintain.
    pub min_connections: u32,
    /// Maximum time to wait when acquiring or opening a connection.
    pub acquire_timeout: Duration,
    /// Maximum time an idle connection may remain in the pool.
    pub idle_timeout: Option<Duration>,
    /// Maximum lifetime for a pooled connection.
    pub max_lifetime: Option<Duration>,
    /// Optional Postgres application name.
    pub application_name: Option<String>,
    /// Optional TLS mode override for Postgres connections.
    pub ssl_mode: Option<SslMode>,
}

/// Paranoid-owned, SQLx-backed Postgres pool.
///
/// Paranoid constructs this pool through [`Pool::connect`] so Paranoid-owned DB
/// primitives share one conservative connection configuration. Applications may
/// use [`Pool::sqlx_pool`] for app-owned SQL that should share the same pool,
/// and may use Paranoid's portable query constructors
/// when app-owned SQL should follow the same portable Postgres execution style.
///
/// `Pool` does not imply any particular database privileges. It is the neutral
/// Paranoid DB handle type.
#[derive(Clone)]
pub struct Pool {
    pub(crate) inner: PgPool,
    pub(crate) operation_observer: Option<DatabaseOperationObserver>,
}

/// Paranoid-owned Postgres pool for APIs that require write authority.
///
/// `WritePool` is a Rust API marker over the credentials used to connect. It
/// does not inspect, reduce, or enforce Postgres privileges. Construct it with a
/// connection URL whose database role has the privileges required by the write
/// APIs you intend to call.
///
/// A `WritePool` can be passed to APIs that take [`Pool`] because a
/// write-marked handle is also a valid neutral DB handle. A plain [`Pool`]
/// cannot be passed to APIs that require `WritePool`.
#[derive(Clone)]
pub struct WritePool {
    pub(crate) pool: Pool,
}

/// Paranoid-owned, SQLx-backed Postgres transaction.
///
/// Applications may use [`Tx::sqlx_transaction`] for app-owned SQLx queries
/// that should commit or roll back with Paranoid-owned operations in the same
/// transaction. Paranoid's portable query constructors are
/// optional helpers for app-owned SQL that should stay portable to
/// transaction-mode connection poolers.
///
/// `Tx` does not imply any particular database privileges. It is the neutral
/// Paranoid transaction handle type.
pub struct Tx<'tx> {
    pub(crate) inner: sqlx::Transaction<'tx, Postgres>,
    pub(crate) operation_observer: Option<DatabaseOperationObserver>,
}

/// Paranoid-owned Postgres transaction for APIs that require write authority.
///
/// Like [`WritePool`], this is a Rust API marker over the connection
/// credentials that created the transaction. It does not inspect or enforce
/// Postgres privileges.
pub struct WriteTx<'tx> {
    pub(crate) tx: Tx<'tx>,
}

/// TLS mode for Paranoid-owned Postgres connections.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SslMode {
    /// Only try a non-TLS connection.
    Disable,
    /// First try a non-TLS connection, then a TLS connection.
    Allow,
    /// First try a TLS connection, then a non-TLS connection.
    #[default]
    Prefer,
    /// Only try a TLS connection.
    Require,
    /// Only try a TLS connection and verify the certificate authority.
    VerifyCa,
    /// Only try a TLS connection and verify both CA and hostname.
    VerifyFull,
}

impl PoolConfig {
    /// Creates a pool config with conservative Postgres defaults.
    pub fn new(database_url: SecretString) -> Self {
        Self {
            database_url,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: DEFAULT_MIN_CONNECTIONS,
            acquire_timeout: DEFAULT_ACQUIRE_TIMEOUT,
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            max_lifetime: Some(DEFAULT_MAX_LIFETIME),
            application_name: None,
            ssl_mode: None,
        }
    }
}

impl Pool {
    /// Opens a Paranoid-owned Postgres pool.
    pub async fn connect(config: PoolConfig) -> Result<Self, Error> {
        let connect_options = build_pooler_safe_pg_connect_options(&config)?;
        let pool_options = build_pg_pool_options(&config)?;
        let inner = pool_options
            .connect_with(connect_options)
            .await
            .map_err(Error::connect)?;
        Ok(Self {
            inner,
            operation_observer: None,
        })
    }

    /// Returns the SQLx Postgres pool managed by Paranoid.
    ///
    /// This is a supported integration point for app-owned SQL. Applications
    /// may use raw SQLx normally, or use Paranoid's
    /// portable query constructors when they want
    /// app-owned SQL to follow the same portable Postgres execution style as
    /// Paranoid internals.
    pub fn sqlx_pool(&self) -> &PgPool {
        &self.inner
    }

    /// Starts an explicit Postgres transaction.
    pub async fn begin_transaction(&self) -> Result<Tx<'_>, Error> {
        self.record_database_operation(
            DatabaseOperationKind::BeginTransaction,
            "db.begin_transaction",
            None,
        );
        let inner = self.inner.begin().await.map_err(Error::transaction)?;
        Ok(Tx {
            inner,
            operation_observer: self.operation_observer.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn clone_with_database_operation_observer(
        &self,
        operation_observer: DatabaseOperationObserver,
    ) -> Self {
        Self {
            inner: self.inner.clone(),
            operation_observer: Some(operation_observer),
        }
    }

    pub(crate) fn record_database_operation(
        &self,
        kind: DatabaseOperationKind,
        label: &'static str,
        statement: Option<&str>,
    ) {
        if let Some(operation_observer) = &self.operation_observer {
            operation_observer.record(kind, label, statement);
        }
    }
}

impl WritePool {
    /// Opens a Paranoid-owned Postgres pool for APIs that require write authority.
    pub async fn connect(config: PoolConfig) -> Result<Self, Error> {
        Ok(Self {
            pool: Pool::connect(config).await?,
        })
    }

    /// Returns the SQLx Postgres pool managed by Paranoid.
    pub fn sqlx_pool(&self) -> &PgPool {
        self.pool.sqlx_pool()
    }

    /// Starts an explicit Postgres transaction for write-requiring APIs.
    pub async fn begin_transaction(&self) -> Result<WriteTx<'_>, Error> {
        Ok(WriteTx {
            tx: self.pool.begin_transaction().await?,
        })
    }

    #[cfg(test)]
    pub(crate) fn clone_with_database_operation_observer(
        &self,
        operation_observer: DatabaseOperationObserver,
    ) -> Self {
        Self {
            pool: self
                .pool
                .clone_with_database_operation_observer(operation_observer),
        }
    }
}

impl Deref for WritePool {
    type Target = Pool;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

impl<'tx> Tx<'tx> {
    /// Returns the SQLx Postgres transaction managed by Paranoid.
    ///
    /// This is a supported integration point for app-owned SQL that should
    /// commit or roll back with Paranoid-owned operations.
    pub fn sqlx_transaction(&mut self) -> &mut sqlx::Transaction<'tx, Postgres> {
        &mut self.inner
    }

    pub(crate) fn database_operation_observer(&self) -> Option<&DatabaseOperationObserver> {
        self.operation_observer.as_ref()
    }

    pub(crate) fn record_database_operation(
        &self,
        kind: DatabaseOperationKind,
        label: &'static str,
        statement: Option<&str>,
    ) {
        if let Some(operation_observer) = &self.operation_observer {
            operation_observer.record(kind, label, statement);
        }
    }

    /// Commits this transaction.
    pub async fn commit(self) -> Result<(), Error> {
        self.record_database_operation(
            DatabaseOperationKind::CommitTransaction,
            "db.tx.commit",
            None,
        );
        self.inner.commit().await.map_err(Error::transaction)
    }

    /// Rolls this transaction back.
    pub async fn rollback(self) -> Result<(), Error> {
        self.record_database_operation(
            DatabaseOperationKind::RollbackTransaction,
            "db.tx.rollback",
            None,
        );
        self.inner.rollback().await.map_err(Error::transaction)
    }
}

impl<'tx> WriteTx<'tx> {
    /// Returns the SQLx Postgres transaction managed by Paranoid.
    ///
    /// This is a supported integration point for app-owned SQL that should
    /// commit or roll back with Paranoid-owned operations.
    pub fn sqlx_transaction(&mut self) -> &mut sqlx::Transaction<'tx, Postgres> {
        self.tx.sqlx_transaction()
    }

    pub(crate) fn database_operation_observer(&self) -> Option<&DatabaseOperationObserver> {
        self.tx.database_operation_observer()
    }

    pub(crate) fn record_database_operation(
        &self,
        kind: DatabaseOperationKind,
        label: &'static str,
        statement: Option<&str>,
    ) {
        self.tx.record_database_operation(kind, label, statement);
    }

    /// Commits this transaction.
    pub async fn commit(self) -> Result<(), Error> {
        self.tx.commit().await
    }

    /// Rolls this transaction back.
    pub async fn rollback(self) -> Result<(), Error> {
        self.tx.rollback().await
    }
}

impl<'tx> Deref for WriteTx<'tx> {
    type Target = Tx<'tx>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl<'tx> DerefMut for WriteTx<'tx> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl SslMode {
    /// Returns the Postgres keyword for this TLS mode.
    pub fn as_postgres_keyword(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Allow => "allow",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }

    fn to_sqlx(self) -> sqlx::postgres::PgSslMode {
        match self {
            Self::Disable => sqlx::postgres::PgSslMode::Disable,
            Self::Allow => sqlx::postgres::PgSslMode::Allow,
            Self::Prefer => sqlx::postgres::PgSslMode::Prefer,
            Self::Require => sqlx::postgres::PgSslMode::Require,
            Self::VerifyCa => sqlx::postgres::PgSslMode::VerifyCa,
            Self::VerifyFull => sqlx::postgres::PgSslMode::VerifyFull,
        }
    }
}

pub(crate) fn build_pooler_safe_pg_connect_options(
    config: &PoolConfig,
) -> Result<PgConnectOptions, Error> {
    validate_pg_pool_config(config)?;

    let mut options = PgConnectOptions::from_str(config.database_url.expose_secret())
        .map_err(Error::invalid_database_url)?;
    options = options.statement_cache_capacity(POOLER_SAFE_STATEMENT_CACHE_CAPACITY);

    if let Some(application_name) = config.application_name.as_deref() {
        options = options.application_name(application_name);
    }
    if let Some(ssl_mode) = config.ssl_mode {
        options = options.ssl_mode(ssl_mode.to_sqlx());
    }

    Ok(options)
}

pub(crate) fn build_pg_pool_options(config: &PoolConfig) -> Result<PgPoolOptions, Error> {
    validate_pg_pool_config(config)?;

    Ok(PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(config.max_lifetime))
}

fn validate_pg_pool_config(config: &PoolConfig) -> Result<(), Error> {
    if config.max_connections == 0 {
        return Err(Error::InvalidPoolConfig {
            reason: "max_connections must be at least 1",
        });
    }
    if config.min_connections > config.max_connections {
        return Err(Error::InvalidPoolConfig {
            reason: "min_connections must not exceed max_connections",
        });
    }
    if config.acquire_timeout.is_zero() {
        return Err(Error::InvalidPoolConfig {
            reason: "acquire_timeout must be non-zero",
        });
    }
    if config
        .idle_timeout
        .is_some_and(|duration| duration.is_zero())
    {
        return Err(Error::InvalidPoolConfig {
            reason: "idle_timeout must be non-zero when configured",
        });
    }
    if config
        .max_lifetime
        .is_some_and(|duration| duration.is_zero())
    {
        return Err(Error::InvalidPoolConfig {
            reason: "max_lifetime must be non-zero when configured",
        });
    }
    if config.database_url.expose_secret().trim().is_empty() {
        return Err(Error::InvalidPoolConfig {
            reason: "database_url must not be empty",
        });
    }
    if let Some(application_name) = config.application_name.as_deref()
        && (application_name.is_empty() || application_name.as_bytes().contains(&0))
    {
        return Err(Error::InvalidPoolConfig {
            reason: "application_name must be non-empty and must not contain null bytes",
        });
    }

    Ok(())
}
