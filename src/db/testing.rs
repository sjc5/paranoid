//! Isolated Postgres/PgBouncer test harness.
//!
//! This module is available behind the `db-test-harness` feature. It starts an
//! embedded Postgres instance, routes every exposed database URL through a
//! Paranoid-pinned PgBouncer binary configured in transaction-pooler mode, and
//! exposes the same environment variables Paranoid's own database tests use.
//!
//! The harness is intended for integration tests in crates and applications
//! that consume Paranoid. It is not a production database launcher.

use super::{Pool, PoolConfig, WritePool};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pg_embed::pg_enums::{PgAuthMethod, PgServerStatus};
use pg_embed::pg_fetch::{PG_V16, PgFetchSettings};
use pg_embed::postgres::{PgEmbed, PgSettings};
use sha2::{Digest, Sha256};
use tokio::process::Command as TokioCommand;
use tokio_postgres::NoTls;

const RUN_ROOT: &str = "target/paranoid-isolated-test-db";
const TOOL_ROOT: &str = "target/paranoid-tools";
const PINNED_PGBOUNCER_VERSION: &str = "1.25.2";
const PINNED_PGBOUNCER_SOURCE_SHA256: &str =
    "924ad35113fd0a71c8e2dbe85b5d03445532e2b7b37a9f8a48983beea238b332";
const PINNED_PGBOUNCER_SOURCE_URL: &str =
    "https://www.pgbouncer.org/downloads/files/1.25.2/pgbouncer-1.25.2.tar.gz";
const PINNED_PGBOUNCER_CONFIGURE_ARGS: &[&str] =
    &["--without-openssl", "--without-cares", "--disable-evdns"];
const TEST_DATABASE_NAME: &str = "test";
const TEST_USER: &str = "test";
const TEST_PASSWORD: &str = "test";
const NON_BYPASS_USER: &str = "paranoid_nobypass";
const NON_BYPASS_PASSWORD: &str = "paranoid_nobypass";
const READ_ONLY_USER: &str = "paranoid_read_only";
const READ_ONLY_PASSWORD: &str = "paranoid_read_only";
const STATEMENT_TIMEOUT_USER: &str = "paranoid_statement_timeout";
const STATEMENT_TIMEOUT_PASSWORD: &str = "paranoid_statement_timeout";
const STATEMENT_TIMEOUT: &str = "50ms";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
const EMBEDDED_POSTGRES_LOCALE: &str = "C";

/// Configuration for [`IsolatedPostgresTestHarness`].
#[derive(Clone, Debug)]
pub struct IsolatedPostgresTestHarnessConfig {
    root_directory: PathBuf,
}

/// Isolated embedded Postgres plus pinned transaction-mode PgBouncer.
pub struct IsolatedPostgresTestHarness {
    postgres: Option<PgEmbed>,
    pgbouncer: Option<Child>,
    run_dir: Option<PathBuf>,
    database_urls: IsolatedPostgresTestHarnessDatabaseUrls,
}

#[derive(Clone)]
struct IsolatedPostgresTestHarnessDatabaseUrls {
    standard: String,
    non_bypass: String,
    read_only: String,
    statement_timeout: String,
}

/// Error returned by the Postgres test harness.
#[derive(Debug)]
pub struct IsolatedPostgresTestHarnessError {
    message: String,
}

impl IsolatedPostgresTestHarnessConfig {
    /// Creates a harness config rooted at `root_directory`.
    ///
    /// The harness writes ephemeral run directories under
    /// `target/paranoid-isolated-test-db` and pinned tool binaries under
    /// `target/paranoid-tools` relative to this directory.
    pub fn new(root_directory: impl Into<PathBuf>) -> Self {
        Self {
            root_directory: root_directory.into(),
        }
    }

    /// Creates a harness config rooted at the current process working directory.
    pub fn from_current_dir() -> Result<Self, IsolatedPostgresTestHarnessError> {
        env::current_dir().map(Self::new).map_err(|error| {
            IsolatedPostgresTestHarnessError::new(format!("read current dir: {error}"))
        })
    }
}

impl IsolatedPostgresTestHarness {
    /// Starts an isolated Postgres/PgBouncer test harness under the current directory.
    pub async fn start() -> Result<Self, IsolatedPostgresTestHarnessError> {
        Self::start_with_config(IsolatedPostgresTestHarnessConfig::from_current_dir()?).await
    }

    /// Starts an isolated Postgres/PgBouncer test harness with explicit configuration.
    pub async fn start_with_config(
        config: IsolatedPostgresTestHarnessConfig,
    ) -> Result<Self, IsolatedPostgresTestHarnessError> {
        let pgbouncer_binary = ensure_pinned_pgbouncer_binary(&config.root_directory).await?;
        let run_dir = create_run_directory(&config.root_directory)?;
        let postgres_port = reserve_loopback_port()?;
        let pgbouncer_port = reserve_loopback_port()?;

        let postgres = start_embedded_postgres(&run_dir, postgres_port).await?;
        configure_test_database_roles(postgres_dsn_for_role(
            postgres_port,
            TEST_USER,
            TEST_PASSWORD,
        ))
        .await?;
        let pgbouncer_config_path =
            write_pgbouncer_config(&run_dir, postgres_port, pgbouncer_port)?;
        let mut pgbouncer = start_pgbouncer(&pgbouncer_binary, &pgbouncer_config_path, &run_dir)?;

        let standard_url = pooler_dsn_for_role(pgbouncer_port, TEST_USER, TEST_PASSWORD);
        if let Err(error) = wait_for_pgbouncer(&standard_url, &mut pgbouncer).await {
            let _ = stop_pgbouncer(&mut pgbouncer);
            return Err(error.into());
        }

        Ok(Self {
            postgres: Some(postgres),
            pgbouncer: Some(pgbouncer),
            run_dir: Some(run_dir),
            database_urls: IsolatedPostgresTestHarnessDatabaseUrls {
                standard: standard_url,
                non_bypass: pooler_dsn_for_role(
                    pgbouncer_port,
                    NON_BYPASS_USER,
                    NON_BYPASS_PASSWORD,
                ),
                read_only: pooler_dsn_for_role(pgbouncer_port, READ_ONLY_USER, READ_ONLY_PASSWORD),
                statement_timeout: pooler_dsn_for_role(
                    pgbouncer_port,
                    STATEMENT_TIMEOUT_USER,
                    STATEMENT_TIMEOUT_PASSWORD,
                ),
            },
        })
    }

    /// Returns the standard transaction-pooled database URL.
    pub fn standard_database_url(&self) -> &str {
        self.database_urls.standard()
    }

    /// Returns the transaction-pooled URL for a non-bypass login role.
    pub fn non_bypass_database_url(&self) -> &str {
        self.database_urls.non_bypass()
    }

    /// Returns the transaction-pooled URL for a read-only login role.
    pub fn read_only_database_url(&self) -> &str {
        self.database_urls.read_only()
    }

    /// Returns the transaction-pooled URL for a role with a short statement timeout.
    pub fn statement_timeout_database_url(&self) -> &str {
        self.database_urls.statement_timeout()
    }

    /// Returns the non-bypass login role name.
    pub fn non_bypass_role_name(&self) -> &'static str {
        NON_BYPASS_USER
    }

    /// Returns the read-only login role name.
    pub fn read_only_role_name(&self) -> &'static str {
        READ_ONLY_USER
    }

    /// Returns the statement-timeout login role name.
    pub fn statement_timeout_role_name(&self) -> &'static str {
        STATEMENT_TIMEOUT_USER
    }

    /// Returns a Paranoid pool config for the standard transaction-pooled URL.
    pub fn standard_pool_config(&self) -> PoolConfig {
        PoolConfig::new(SecretString::from(self.standard_database_url().to_owned()))
    }

    /// Connects a neutral Paranoid [`Pool`] to the standard transaction-pooled URL.
    pub async fn connect_standard_pool(&self) -> Result<Pool, super::Error> {
        Pool::connect(self.standard_pool_config()).await
    }

    /// Connects a write-marked Paranoid [`WritePool`] to the standard transaction-pooled URL.
    pub async fn connect_standard_write_pool(&self) -> Result<WritePool, super::Error> {
        WritePool::connect(self.standard_pool_config()).await
    }

    /// Applies the harness database environment to a child command.
    ///
    /// The standard environment variables are set to transaction-pooled URLs.
    /// Direct embedded-Postgres URL variables are removed so child tests cannot
    /// accidentally bypass PgBouncer.
    pub fn apply_database_environment_to_child_command(&self, command: &mut Command) {
        self.database_urls
            .apply_database_environment_to_child_command(command);
    }

    /// Runs a child command with the harness database environment.
    pub fn run_child_command_with_database_environment<I, S>(
        &self,
        program: S,
        args: I,
    ) -> Result<i32, IsolatedPostgresTestHarnessError>
    where
        I: IntoIterator,
        I::Item: AsRef<OsStr>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(program);
        command.args(args);
        self.apply_database_environment_to_child_command(&mut command);
        let status = command.status().map_err(|error| {
            IsolatedPostgresTestHarnessError::new(format!(
                "run child command with test database: {error}"
            ))
        })?;
        Ok(exit_code_from_status(status))
    }

    /// Stops PgBouncer, stops embedded Postgres, and removes the run directory.
    pub async fn shutdown(mut self) -> Result<(), IsolatedPostgresTestHarnessError> {
        if let Some(mut pgbouncer) = self.pgbouncer.take() {
            stop_pgbouncer(&mut pgbouncer).map_err(IsolatedPostgresTestHarnessError::from)?;
        }
        if let Some(mut postgres) = self.postgres.take() {
            stop_embedded_postgres_with_deterministic_locale(&mut postgres)
                .await
                .map_err(IsolatedPostgresTestHarnessError::from)?;
        }
        if let Some(run_dir) = self.run_dir.take() {
            fs::remove_dir_all(&run_dir).map_err(|error| {
                IsolatedPostgresTestHarnessError::new(format!(
                    "remove isolated DB run directory {}: {error}",
                    run_dir.display()
                ))
            })?;
        }
        Ok(())
    }
}

impl IsolatedPostgresTestHarnessDatabaseUrls {
    fn standard(&self) -> &str {
        &self.standard
    }

    fn non_bypass(&self) -> &str {
        &self.non_bypass
    }

    fn read_only(&self) -> &str {
        &self.read_only
    }

    fn statement_timeout(&self) -> &str {
        &self.statement_timeout
    }

    fn apply_database_environment_to_child_command(&self, command: &mut Command) {
        command
            .env("TEST_DSN", self.standard())
            .env("TEST_DATABASE_URL", self.standard())
            .env("PARANOID_TEST_DATABASE_URL", self.standard())
            .env("PARANOID_TEST_NON_BYPASS_DATABASE_URL", self.non_bypass())
            .env("PARANOID_TEST_NON_BYPASS_ROLE", NON_BYPASS_USER)
            .env("PARANOID_TEST_READ_ONLY_DATABASE_URL", self.read_only())
            .env("PARANOID_TEST_READ_ONLY_ROLE", READ_ONLY_USER)
            .env(
                "PARANOID_TEST_STATEMENT_TIMEOUT_DATABASE_URL",
                self.statement_timeout(),
            )
            .env(
                "PARANOID_TEST_STATEMENT_TIMEOUT_ROLE",
                STATEMENT_TIMEOUT_USER,
            )
            .env_remove("TEST_DSN_DIRECT")
            .env_remove("PARANOID_TEST_DATABASE_DIRECT_URL");
    }
}

impl IsolatedPostgresTestHarnessError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for IsolatedPostgresTestHarnessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for IsolatedPostgresTestHarnessError {}

impl From<String> for IsolatedPostgresTestHarnessError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for IsolatedPostgresTestHarnessError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

impl Drop for IsolatedPostgresTestHarness {
    fn drop(&mut self) {
        if let Some(mut pgbouncer) = self.pgbouncer.take() {
            let _ = stop_pgbouncer(&mut pgbouncer);
        }
        if let Some(mut postgres) = self.postgres.take() {
            let _ = stop_embedded_postgres_sync_with_deterministic_locale(&mut postgres);
        }
        if let Some(run_dir) = self.run_dir.take() {
            let _ = fs::remove_dir_all(run_dir);
        }
    }
}

async fn ensure_pinned_pgbouncer_binary(
    root_directory: &Path,
) -> Result<PathBuf, IsolatedPostgresTestHarnessError> {
    let target = supported_tool_target()?;
    let tool_dir = root_directory
        .join(TOOL_ROOT)
        .join("pgbouncer")
        .join(PINNED_PGBOUNCER_VERSION)
        .join(target);
    let binary_path = tool_dir.join("pgbouncer");
    let manifest_path = tool_dir.join("pgbouncer.install");

    if pinned_pgbouncer_install_matches(&binary_path, &manifest_path, target)? {
        return Ok(binary_path);
    }

    if binary_path.exists() {
        fs::remove_file(&binary_path)
            .map_err(|error| format!("remove stale pinned PgBouncer binary: {error}"))?;
    }
    if manifest_path.exists() {
        fs::remove_file(&manifest_path)
            .map_err(|error| format!("remove stale pinned PgBouncer install manifest: {error}"))?;
    }

    let build_dir = tool_dir.join("build");
    let archive_path = build_dir.join(format!("pgbouncer-{}.tar.gz", PINNED_PGBOUNCER_VERSION));
    fs::create_dir_all(&build_dir)
        .map_err(|error| format!("create PgBouncer tool build dir: {error}"))?;

    ensure_pinned_pgbouncer_source_archive(&archive_path).await?;
    let source_dir = unpack_pinned_pgbouncer_source_archive(&archive_path, &build_dir)?;
    build_and_install_pinned_pgbouncer(&source_dir, &tool_dir)?;
    write_pinned_pgbouncer_install_manifest(
        &manifest_path,
        target,
        &file_sha256_hex(&binary_path)?,
    )?;
    if !pinned_pgbouncer_install_matches(&binary_path, &manifest_path, target)? {
        return Err("pinned PgBouncer install verification failed after build".into());
    }

    Ok(binary_path)
}

fn supported_tool_target() -> Result<&'static str, String> {
    match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        (os, arch) => Err(format!(
            "no pinned PgBouncer tool target is defined for {os}/{arch}"
        )),
    }
}

async fn ensure_pinned_pgbouncer_source_archive(archive_path: &Path) -> Result<(), String> {
    if archive_path.exists() && file_sha256_hex(archive_path)? == PINNED_PGBOUNCER_SOURCE_SHA256 {
        return Ok(());
    }

    if archive_path.exists() {
        fs::remove_file(archive_path)
            .map_err(|error| format!("remove bad PgBouncer source archive: {error}"))?;
    }

    let response = reqwest::get(PINNED_PGBOUNCER_SOURCE_URL)
        .await
        .map_err(|error| format!("download pinned PgBouncer source: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "download pinned PgBouncer source returned HTTP {}",
            response.status()
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("read pinned PgBouncer source response body: {error}"))?;
    let actual = sha256_hex(&bytes);
    if actual != PINNED_PGBOUNCER_SOURCE_SHA256 {
        return Err(format!(
            "pinned PgBouncer source checksum mismatch: expected {PINNED_PGBOUNCER_SOURCE_SHA256}, got {actual}"
        ));
    }
    fs::write(archive_path, &bytes)
        .map_err(|error| format!("write pinned PgBouncer source archive: {error}"))
}

fn unpack_pinned_pgbouncer_source_archive(
    archive_path: &Path,
    build_dir: &Path,
) -> Result<PathBuf, String> {
    let source_dir = build_dir.join(format!("pgbouncer-{}", PINNED_PGBOUNCER_VERSION));
    if source_dir.exists() {
        fs::remove_dir_all(&source_dir)
            .map_err(|error| format!("remove stale PgBouncer source dir: {error}"))?;
    }

    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(archive_path)
        .args(["-C"])
        .arg(build_dir)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .status()
        .map_err(|error| format!("extract pinned PgBouncer source archive: {error}"))?;
    if !status.success() {
        return Err(format!(
            "extract pinned PgBouncer source archive failed: {status}"
        ));
    }
    if !source_dir.exists() {
        return Err(format!(
            "pinned PgBouncer source archive did not create {}",
            source_dir.display()
        ));
    }
    Ok(source_dir)
}

fn build_and_install_pinned_pgbouncer(source_dir: &Path, tool_dir: &Path) -> Result<(), String> {
    let binary_path = tool_dir.join("pgbouncer");
    if binary_path.exists() {
        fs::remove_file(&binary_path)
            .map_err(|error| format!("remove stale PgBouncer binary: {error}"))?;
    }

    let mut configure = Command::new("./configure");
    configure
        .current_dir(source_dir)
        .arg(format!("--prefix={}", tool_dir.display()))
        .arg(format!("--bindir={}", tool_dir.display()));
    configure.args(PINNED_PGBOUNCER_CONFIGURE_ARGS);
    add_libevent_build_environment(&mut configure)?;
    run_logged_command(configure, "configure pinned PgBouncer")?;

    let mut make = Command::new("make");
    make.current_dir(source_dir).arg("pgbouncer").arg(format!(
        "-j{}",
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1)
    ));
    run_logged_command(make, "build pinned PgBouncer")?;

    fs::copy(source_dir.join("pgbouncer"), &binary_path)
        .map_err(|error| format!("install pinned PgBouncer binary: {error}"))?;

    if !binary_path.exists() {
        return Err(format!(
            "pinned PgBouncer install did not create {}",
            binary_path.display()
        ));
    }

    Ok(())
}

fn pinned_pgbouncer_install_matches(
    binary_path: &Path,
    manifest_path: &Path,
    target: &str,
) -> Result<bool, String> {
    if !binary_path.exists() || !manifest_path.exists() {
        return Ok(false);
    }

    verify_pinned_pgbouncer_binary_version(binary_path)?;
    let manifest = read_pinned_pgbouncer_install_manifest(manifest_path)?;
    let expected_binary_sha256 = manifest
        .get("binary_sha256")
        .ok_or_else(|| "pinned PgBouncer install manifest is missing binary_sha256".to_owned())?;

    Ok(
        manifest.get("manifest_version").map(String::as_str) == Some("1")
            && manifest.get("pgbouncer_version").map(String::as_str)
                == Some(PINNED_PGBOUNCER_VERSION)
            && manifest.get("target").map(String::as_str) == Some(target)
            && manifest.get("source_url").map(String::as_str) == Some(PINNED_PGBOUNCER_SOURCE_URL)
            && manifest.get("source_sha256").map(String::as_str)
                == Some(PINNED_PGBOUNCER_SOURCE_SHA256)
            && manifest.get("configure_args").map(String::as_str)
                == Some(&PINNED_PGBOUNCER_CONFIGURE_ARGS.join(" "))
            && file_sha256_hex(binary_path)? == *expected_binary_sha256,
    )
}

fn write_pinned_pgbouncer_install_manifest(
    manifest_path: &Path,
    target: &str,
    binary_sha256: &str,
) -> Result<(), String> {
    let contents = [
        "manifest_version=1".to_owned(),
        format!("pgbouncer_version={PINNED_PGBOUNCER_VERSION}"),
        format!("target={target}"),
        format!("source_url={PINNED_PGBOUNCER_SOURCE_URL}"),
        format!("source_sha256={PINNED_PGBOUNCER_SOURCE_SHA256}"),
        format!(
            "configure_args={}",
            PINNED_PGBOUNCER_CONFIGURE_ARGS.join(" ")
        ),
        format!("binary_sha256={binary_sha256}"),
    ]
    .join("\n");
    fs::write(manifest_path, format!("{contents}\n"))
        .map_err(|error| format!("write pinned PgBouncer install manifest: {error}"))
}

fn read_pinned_pgbouncer_install_manifest(
    manifest_path: &Path,
) -> Result<BTreeMap<String, String>, String> {
    let contents = fs::read_to_string(manifest_path).map_err(|error| {
        format!(
            "read pinned PgBouncer install manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let mut fields = BTreeMap::new();
    for line in contents.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "pinned PgBouncer install manifest has a malformed line".to_owned())?;
        if key.is_empty()
            || value.is_empty()
            || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err("pinned PgBouncer install manifest has invalid fields".to_owned());
        }
    }
    Ok(fields)
}

fn add_libevent_build_environment(command: &mut Command) -> Result<(), String> {
    if command_exists("pkg-config") {
        return Ok(());
    }

    let prefix = find_libevent_prefix().ok_or_else(|| {
        "building pinned PgBouncer requires libevent; install pkg-config plus libevent, or set PARANOID_TEST_LIBEVENT_PREFIX to the libevent prefix".to_owned()
    })?;
    command
        .env(
            "LIBEVENT_CFLAGS",
            format!("-I{}", prefix.join("include").display()),
        )
        .env(
            "LIBEVENT_LIBS",
            format!("-L{} -levent", prefix.join("lib").display()),
        );
    Ok(())
}

fn find_libevent_prefix() -> Option<PathBuf> {
    if let Some(prefix) = env::var_os("PARANOID_TEST_LIBEVENT_PREFIX") {
        let path = PathBuf::from(prefix);
        if libevent_prefix_is_usable(&path) {
            return Some(path);
        }
    }

    [
        "/opt/homebrew/opt/libevent",
        "/usr/local/opt/libevent",
        "/opt/local",
        "/usr",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| libevent_prefix_is_usable(path))
}

fn libevent_prefix_is_usable(prefix: &Path) -> bool {
    let header = prefix.join("include/event2/event.h");
    let lib_dir = prefix.join("lib");
    header.exists()
        && ["libevent.dylib", "libevent.so", "libevent.a"]
            .iter()
            .any(|name| lib_dir.join(name).exists())
}

fn command_exists(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn run_logged_command(mut command: Command, label: &str) -> Result<(), String> {
    command.env("LC_ALL", "C").env("LANG", "C");
    let output = command
        .output()
        .map_err(|error| format!("{label}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn verify_pinned_pgbouncer_binary_version(binary_path: &Path) -> Result<(), String> {
    let output = Command::new(binary_path)
        .arg("--version")
        .output()
        .map_err(|error| {
            format!(
                "run pinned PgBouncer binary {} --version: {error}",
                binary_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "pinned PgBouncer binary {} --version failed: {}",
            binary_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let version_output = String::from_utf8_lossy(&output.stdout);
    if !version_output.contains(&format!("PgBouncer {PINNED_PGBOUNCER_VERSION}")) {
        return Err(format!(
            "pinned PgBouncer binary {} reports unexpected version: {}",
            binary_path.display(),
            version_output.trim()
        ));
    }
    Ok(())
}

fn file_sha256_hex(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("open {} for sha256: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {} for sha256: {error}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn create_run_directory(root_directory: &Path) -> Result<PathBuf, String> {
    let root = root_directory.join(RUN_ROOT);
    fs::create_dir_all(&root)
        .map_err(|error| format!("create isolated DB root {}: {error}", root.display()))?;
    let run_dir = root.join(new_run_id()?);
    fs::create_dir(&run_dir).map_err(|error| {
        format!(
            "create isolated DB run directory {}: {error}",
            run_dir.display()
        )
    })?;
    write_owner_pid(&run_dir)?;
    Ok(run_dir)
}

fn new_run_id() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("run-{nanos}-{}", std::process::id()))
}

fn write_owner_pid(run_dir: &Path) -> Result<(), String> {
    fs::write(run_dir.join("owner.pid"), std::process::id().to_string())
        .map_err(|error| format!("write isolated DB owner pid: {error}"))
}

fn reserve_loopback_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("reserve loopback port: {error}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|error| format!("read reserved loopback port: {error}"))
}

async fn start_embedded_postgres(run_dir: &Path, postgres_port: u16) -> Result<PgEmbed, String> {
    let mut postgres = PgEmbed::new(
        PgSettings {
            database_dir: run_dir.join("postgres"),
            port: postgres_port,
            user: TEST_USER.to_owned(),
            password: TEST_PASSWORD.to_owned(),
            auth_method: PgAuthMethod::Plain,
            persistent: false,
            timeout: Some(STARTUP_TIMEOUT),
            migration_dir: None,
        },
        PgFetchSettings {
            version: PG_V16,
            ..PgFetchSettings::default()
        },
    )
    .await
    .map_err(|error| format!("create embedded Postgres: {error}"))?;

    setup_embedded_postgres_with_deterministic_locale(&mut postgres).await?;
    start_embedded_postgres_with_deterministic_locale(&mut postgres).await?;
    create_embedded_postgres_test_database(postgres_port).await?;

    Ok(postgres)
}

async fn setup_embedded_postgres_with_deterministic_locale(
    postgres: &mut PgEmbed,
) -> Result<(), String> {
    postgres
        .pg_access
        .maybe_acquire_postgres()
        .await
        .map_err(|error| format!("acquire embedded Postgres binaries: {error}"))?;
    postgres
        .pg_access
        .create_password_file(postgres.pg_settings.password.as_bytes())
        .await
        .map_err(|error| format!("create embedded Postgres password file: {error}"))?;
    if postgres
        .pg_access
        .db_files_exist()
        .await
        .map_err(|error| format!("check embedded Postgres data directory: {error}"))?
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Initialized;
    } else {
        init_embedded_postgres_with_deterministic_locale(postgres).await?;
    }
    Ok(())
}

async fn init_embedded_postgres_with_deterministic_locale(
    postgres: &mut PgEmbed,
) -> Result<(), String> {
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Initializing;
    }

    let password_file = postgres
        .pg_access
        .pw_file_path
        .to_str()
        .ok_or_else(|| "embedded Postgres password file path is not valid UTF-8".to_owned())?;
    let database_dir =
        postgres.pg_access.database_dir.to_str().ok_or_else(|| {
            "embedded Postgres database directory path is not valid UTF-8".to_owned()
        })?;
    let args = vec![
        "-A".to_owned(),
        postgres_auth_method_name(&postgres.pg_settings.auth_method).to_owned(),
        "-U".to_owned(),
        postgres.pg_settings.user.clone(),
        "-E=UTF8".to_owned(),
        "-D".to_owned(),
        database_dir.to_owned(),
        format!("--pwfile={password_file}"),
    ];
    if let Err(error) = run_embedded_postgres_lifecycle_command(
        &postgres.pg_access.init_db_exe,
        &args,
        postgres.pg_settings.timeout,
        "initialize embedded Postgres",
    )
    .await
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Failure;
        return Err(error);
    }

    let mut server_status = postgres.server_status.lock().await;
    *server_status = PgServerStatus::Initialized;
    Ok(())
}

async fn start_embedded_postgres_with_deterministic_locale(
    postgres: &mut PgEmbed,
) -> Result<(), String> {
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Starting;
    }
    postgres.shutting_down = false;

    let database_dir =
        postgres.pg_access.database_dir.to_str().ok_or_else(|| {
            "embedded Postgres database directory path is not valid UTF-8".to_owned()
        })?;
    let args = vec![
        "-o".to_owned(),
        format!("-F -p {}", postgres.pg_settings.port),
        "start".to_owned(),
        "-w".to_owned(),
        "-D".to_owned(),
        database_dir.to_owned(),
    ];
    if let Err(error) = run_embedded_postgres_lifecycle_status_command(
        &postgres.pg_access.pg_ctl_exe,
        &args,
        postgres.pg_settings.timeout,
        "start embedded Postgres",
    )
    .await
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Failure;
        return Err(error);
    }

    let mut server_status = postgres.server_status.lock().await;
    *server_status = PgServerStatus::Started;
    Ok(())
}

async fn stop_embedded_postgres_with_deterministic_locale(
    postgres: &mut PgEmbed,
) -> Result<(), String> {
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Stopping;
    }
    postgres.shutting_down = true;

    let database_dir =
        postgres.pg_access.database_dir.to_str().ok_or_else(|| {
            "embedded Postgres database directory path is not valid UTF-8".to_owned()
        })?;
    let args = embedded_postgres_stop_args(database_dir);
    if let Err(error) = run_embedded_postgres_lifecycle_command(
        &postgres.pg_access.pg_ctl_exe,
        &args,
        postgres.pg_settings.timeout,
        "stop embedded Postgres",
    )
    .await
    {
        let mut server_status = postgres.server_status.lock().await;
        *server_status = PgServerStatus::Failure;
        return Err(error);
    }

    let mut server_status = postgres.server_status.lock().await;
    *server_status = PgServerStatus::Stopped;
    Ok(())
}

fn stop_embedded_postgres_sync_with_deterministic_locale(
    postgres: &mut PgEmbed,
) -> Result<(), String> {
    postgres.shutting_down = true;
    let database_dir =
        postgres.pg_access.database_dir.to_str().ok_or_else(|| {
            "embedded Postgres database directory path is not valid UTF-8".to_owned()
        })?;
    run_embedded_postgres_lifecycle_command_sync(
        &postgres.pg_access.pg_ctl_exe,
        &embedded_postgres_stop_args(database_dir),
        "stop embedded Postgres",
    )
}

fn embedded_postgres_stop_args(database_dir: &str) -> Vec<String> {
    vec![
        "stop".to_owned(),
        "-w".to_owned(),
        "-D".to_owned(),
        database_dir.to_owned(),
    ]
}

fn postgres_auth_method_name(auth_method: &PgAuthMethod) -> &'static str {
    match auth_method {
        PgAuthMethod::Plain => "password",
        PgAuthMethod::MD5 => "md5",
        PgAuthMethod::ScramSha256 => "scram-sha-256",
    }
}

async fn run_embedded_postgres_lifecycle_command(
    program: &Path,
    args: &[String],
    timeout_duration: Option<Duration>,
    label: &str,
) -> Result<(), String> {
    let mut command = TokioCommand::new(program);
    command
        .args(args)
        .env("LC_ALL", EMBEDDED_POSTGRES_LOCALE)
        .env("LANG", EMBEDDED_POSTGRES_LOCALE)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output_future = command.output();
    let output = match timeout_duration {
        Some(duration) => tokio::time::timeout(duration, output_future)
            .await
            .map_err(|_| format!("{label} timed out after {duration:?}"))?,
        None => output_future.await,
    }
    .map_err(|error| format!("{label}: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

async fn run_embedded_postgres_lifecycle_status_command(
    program: &Path,
    args: &[String],
    timeout_duration: Option<Duration>,
    label: &str,
) -> Result<(), String> {
    let mut command = TokioCommand::new(program);
    command
        .args(args)
        .env("LC_ALL", EMBEDDED_POSTGRES_LOCALE)
        .env("LANG", EMBEDDED_POSTGRES_LOCALE)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status_future = command.status();
    let status = match timeout_duration {
        Some(duration) => tokio::time::timeout(duration, status_future)
            .await
            .map_err(|_| format!("{label} timed out after {duration:?}"))?,
        None => status_future.await,
    }
    .map_err(|error| format!("{label}: {error}"))?;

    if status.success() {
        return Ok(());
    }

    Err(format!("{label} failed with {status}"))
}

fn run_embedded_postgres_lifecycle_command_sync(
    program: &Path,
    args: &[String],
    label: &str,
) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", EMBEDDED_POSTGRES_LOCALE)
        .env("LANG", EMBEDDED_POSTGRES_LOCALE)
        .output()
        .map_err(|error| format!("{label}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

async fn create_embedded_postgres_test_database(postgres_port: u16) -> Result<(), String> {
    let default_database_dsn = postgres_dsn(postgres_port, TEST_USER, TEST_PASSWORD, "postgres");
    let (client, connection) = tokio_postgres::connect(&default_database_dsn, NoTls)
        .await
        .map_err(|error| format!("connect to embedded Postgres for database setup: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("embedded Postgres database setup connection error: {error}");
        }
    });

    client
        .batch_execute(&format!("CREATE DATABASE {TEST_DATABASE_NAME}"))
        .await
        .map_err(|error| format!("create embedded Postgres test database: {error}"))
}

async fn configure_test_database_roles(superuser_dsn: String) -> Result<(), String> {
    let (client, connection) = tokio_postgres::connect(&superuser_dsn, NoTls)
        .await
        .map_err(|error| format!("connect to embedded Postgres for role setup: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("embedded Postgres role setup connection error: {error}");
        }
    });

    client
        .batch_execute(&format!(
            r#"
            CREATE ROLE {non_bypass_user} LOGIN PASSWORD {non_bypass_password}
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            CREATE ROLE {read_only_user} LOGIN PASSWORD {read_only_password}
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
            CREATE ROLE {timeout_user} LOGIN PASSWORD {timeout_password}
                SUPERUSER NOCREATEDB NOCREATEROLE INHERIT;
            ALTER ROLE {timeout_user} SET statement_timeout = {statement_timeout};
            GRANT CONNECT ON DATABASE {database_name} TO {non_bypass_user};
            GRANT CONNECT ON DATABASE {database_name} TO {read_only_user};
            GRANT CONNECT ON DATABASE {database_name} TO {timeout_user};
            "#,
            non_bypass_user = NON_BYPASS_USER,
            non_bypass_password = postgres_single_quoted_literal(NON_BYPASS_PASSWORD),
            read_only_user = READ_ONLY_USER,
            read_only_password = postgres_single_quoted_literal(READ_ONLY_PASSWORD),
            timeout_user = STATEMENT_TIMEOUT_USER,
            timeout_password = postgres_single_quoted_literal(STATEMENT_TIMEOUT_PASSWORD),
            statement_timeout = postgres_single_quoted_literal(STATEMENT_TIMEOUT),
            database_name = TEST_DATABASE_NAME,
        ))
        .await
        .map_err(|error| format!("configure embedded Postgres test roles: {error}"))
}

fn write_pgbouncer_config(
    run_dir: &Path,
    postgres_port: u16,
    pgbouncer_port: u16,
) -> Result<PathBuf, String> {
    let auth_file = run_dir.join("pgbouncer-users.txt");
    let config_file = run_dir.join("pgbouncer.ini");
    let log_file = run_dir.join("pgbouncer.log");
    let pid_file = run_dir.join("pgbouncer.pid");

    fs::write(
        &auth_file,
        [
            pgbouncer_user_line(TEST_USER, TEST_PASSWORD),
            pgbouncer_user_line(NON_BYPASS_USER, NON_BYPASS_PASSWORD),
            pgbouncer_user_line(READ_ONLY_USER, READ_ONLY_PASSWORD),
            pgbouncer_user_line(STATEMENT_TIMEOUT_USER, STATEMENT_TIMEOUT_PASSWORD),
        ]
        .join("\n"),
    )
    .map_err(|error| format!("write PgBouncer auth file {}: {error}", auth_file.display()))?;

    let config = format!(
        r#"[databases]
{database} = host=127.0.0.1 port={postgres_port} dbname={database}

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {pgbouncer_port}
auth_type = plain
auth_file = {auth_file}
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 20
client_tls_sslmode = disable
server_tls_sslmode = disable
ignore_startup_parameters = extra_float_digits
logfile = {log_file}
pidfile = {pid_file}
"#,
        database = TEST_DATABASE_NAME,
        auth_file = auth_file.display(),
        log_file = log_file.display(),
        pid_file = pid_file.display(),
    );

    fs::write(&config_file, config)
        .map_err(|error| format!("write PgBouncer config {}: {error}", config_file.display()))?;
    Ok(config_file)
}

fn pgbouncer_user_line(user: &str, password: &str) -> String {
    format!(
        "\"{}\" \"{}\"",
        pgbouncer_quoted_value(user),
        pgbouncer_quoted_value(password)
    )
}

fn pgbouncer_quoted_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn start_pgbouncer(
    pgbouncer_binary: &Path,
    config_path: &Path,
    run_dir: &Path,
) -> Result<Child, String> {
    let stdout = File::create(run_dir.join("pgbouncer.stdout.log"))
        .map_err(|error| format!("create PgBouncer stdout log: {error}"))?;
    let stderr = File::create(run_dir.join("pgbouncer.stderr.log"))
        .map_err(|error| format!("create PgBouncer stderr log: {error}"))?;
    Command::new(pgbouncer_binary)
        .arg(config_path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("start PgBouncer {}: {error}", pgbouncer_binary.display()))
}

async fn wait_for_pgbouncer(dsn: &str, child: &mut Child) -> Result<(), String> {
    let started_at = tokio::time::Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("inspect PgBouncer process status: {error}"))?
        {
            return Err(format!("PgBouncer exited before readiness: {status}"));
        }

        if let Ok((client, connection)) = tokio_postgres::connect(dsn, NoTls).await {
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    eprintln!("PgBouncer readiness connection error: {error}");
                }
            });
            if client.simple_query("SELECT 1").await.is_ok() {
                return Ok(());
            }
        }

        if started_at.elapsed() >= STARTUP_TIMEOUT {
            return Err("timed out waiting for PgBouncer readiness".to_owned());
        }
        tokio::time::sleep(READINESS_POLL_INTERVAL).await;
    }
}

fn stop_pgbouncer(child: &mut Child) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|error| format!("inspect PgBouncer process before shutdown: {error}"))?
        .is_some()
    {
        return Ok(());
    }

    terminate_child_process(child)?;
    let status = child
        .wait()
        .map_err(|error| format!("wait for PgBouncer shutdown: {error}"))?;
    if status.success() || status_was_terminated(status) {
        Ok(())
    } else {
        Err(format!("PgBouncer shutdown failed: {status}"))
    }
}

fn terminate_child_process(child: &mut Child) -> Result<(), String> {
    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .map_err(|error| format!("send SIGTERM to PgBouncer: {error}"))?;
        if status.success() {
            return Ok(());
        }
    }

    child
        .kill()
        .map_err(|error| format!("kill PgBouncer process: {error}"))
}

fn status_was_terminated(status: ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().is_some()
    }

    #[cfg(not(unix))]
    {
        let _ = status;
        true
    }
}

fn pooler_dsn_for_role(port: u16, user: &str, password: &str) -> String {
    postgres_dsn(port, user, password, TEST_DATABASE_NAME)
}

fn postgres_dsn_for_role(port: u16, user: &str, password: &str) -> String {
    postgres_dsn(port, user, password, TEST_DATABASE_NAME)
}

fn postgres_dsn(port: u16, user: &str, password: &str, database: &str) -> String {
    format!(
        "postgres://{}:{}@127.0.0.1:{}/{}?sslmode=disable",
        percent_encode_url_component(user),
        percent_encode_url_component(password),
        port,
        percent_encode_url_component(database)
    )
}

fn percent_encode_url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn postgres_single_quoted_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn exit_code_from_status(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn pooler_dsn_uses_loopback_postgres_shape() {
        assert_eq!(
            pooler_dsn_for_role(65432, TEST_USER, TEST_PASSWORD),
            "postgres://test:test@127.0.0.1:65432/test?sslmode=disable"
        );
    }

    #[test]
    fn percent_encoder_preserves_safe_bytes_and_encodes_reserved_bytes() {
        assert_eq!(
            percent_encode_url_component("abc-._~ :/@"),
            "abc-._~%20%3A%2F%40"
        );
    }

    #[test]
    fn run_directory_is_rooted_under_configured_directory() {
        let root = std::env::temp_dir().join(format!(
            "paranoid-harness-run-root-test-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale run-root test dir");
        }
        fs::create_dir(&root).expect("create run-root test dir");
        let run_dir = create_run_directory(&root).expect("create run directory");

        assert!(run_dir.starts_with(root.join(RUN_ROOT)));
        assert!(run_dir.join("owner.pid").exists());

        fs::remove_dir_all(root).expect("remove run-root test dir");
    }

    #[test]
    fn pgbouncer_auth_lines_quote_values() {
        assert_eq!(pgbouncer_user_line("u\"x", "p\\y"), "\"u\\\"x\" \"p\\\\y\"");
    }

    #[test]
    fn pgbouncer_config_is_transaction_pooler_only() {
        let root =
            std::env::temp_dir().join(format!("paranoid-xtask-config-test-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale config test dir");
        }
        fs::create_dir(&root).expect("create config test dir");
        let config_path = write_pgbouncer_config(&root, 15432, 25432).expect("write config");
        let config = fs::read_to_string(config_path).expect("read config");
        assert!(config.contains("pool_mode = transaction"));
        assert!(config.contains("listen_addr = 127.0.0.1"));
        assert!(!config.contains("pool_mode = session"));
        fs::remove_dir_all(root).expect("remove config test dir");
    }

    #[test]
    fn pinned_pgbouncer_source_pin_is_the_official_1_25_2_archive() {
        assert_eq!(PINNED_PGBOUNCER_VERSION, "1.25.2");
        assert_eq!(
            PINNED_PGBOUNCER_SOURCE_URL,
            "https://www.pgbouncer.org/downloads/files/1.25.2/pgbouncer-1.25.2.tar.gz"
        );
        assert_eq!(
            PINNED_PGBOUNCER_SOURCE_SHA256,
            "924ad35113fd0a71c8e2dbe85b5d03445532e2b7b37a9f8a48983beea238b332"
        );
    }

    #[test]
    fn supported_tool_target_uses_rust_target_triple_shape() {
        let target = supported_tool_target().expect("current platform should be supported");

        assert!(target.contains('-'));
        assert_ne!(target, "pgbouncer");
        assert_ne!(target, env::consts::OS);
    }

    #[test]
    fn child_environment_does_not_expose_direct_postgres_variables() {
        let database_urls = IsolatedPostgresTestHarnessDatabaseUrls {
            standard: pooler_dsn_for_role(1, TEST_USER, TEST_PASSWORD),
            non_bypass: pooler_dsn_for_role(1, NON_BYPASS_USER, NON_BYPASS_PASSWORD),
            read_only: pooler_dsn_for_role(1, READ_ONLY_USER, READ_ONLY_PASSWORD),
            statement_timeout: pooler_dsn_for_role(
                1,
                STATEMENT_TIMEOUT_USER,
                STATEMENT_TIMEOUT_PASSWORD,
            ),
        };
        let mut command = Command::new(OsStr::new("true"));
        database_urls.apply_database_environment_to_child_command(&mut command);

        let envs = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect::<Vec<_>>();
        assert!(envs.iter().any(|(key, _)| *key == "TEST_DSN"));
        assert!(envs.iter().any(
            |(key, value)| *key == "PARANOID_TEST_STATEMENT_TIMEOUT_ROLE"
                && *value == OsStr::new(STATEMENT_TIMEOUT_USER)
        ));
        assert!(!envs.iter().any(|(key, _)| *key == "TEST_DSN_DIRECT"));
        assert!(
            !envs
                .iter()
                .any(|(key, _)| *key == "PARANOID_TEST_DATABASE_DIRECT_URL")
        );
    }

    #[tokio::test]
    async fn embedded_postgres_lifecycle_command_forces_c_locale_for_child_process() {
        let assert_locale_args = [
            "-c".to_owned(),
            r#"[ "$LC_ALL" = "C" ] && [ "$LANG" = "C" ]"#.to_owned(),
        ];
        run_embedded_postgres_lifecycle_command(
            Path::new("sh"),
            &assert_locale_args,
            Some(Duration::from_secs(5)),
            "assert deterministic child locale",
        )
        .await
        .expect("child process should receive deterministic locale");

        run_embedded_postgres_lifecycle_status_command(
            Path::new("sh"),
            &assert_locale_args,
            Some(Duration::from_secs(5)),
            "assert deterministic status child locale",
        )
        .await
        .expect("status child process should receive deterministic locale");

        run_embedded_postgres_lifecycle_command_sync(
            Path::new("sh"),
            &assert_locale_args,
            "assert deterministic sync child locale",
        )
        .expect("sync child process should receive deterministic locale");
    }
}
