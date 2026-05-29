//! Local encrypted environment vault and command runner.
//!
//! `local_env_vault` is for application-owned local wrappers such as `./env`. The
//! application defines profiles in code; Paranoid owns vault encryption,
//! password prompting, locking, atomic writes, and command argument handling.
//! The vault lives in the fixed `.paranoid_local_env_vault` directory under the
//! wrapper-owned root and relative parent path.
//!
//! The wrapper intentionally has a small command shape:
//!
//! - `configure` opens the human configuration flow;
//! - `validate PROFILE` checks whether that profile's required values are present;
//! - `run PROFILE -- COMMAND [ARG ...]` unlocks the vault, decrypts only that
//!   profile's values, overlays them into the child process environment, and
//!   runs the command.
//!
//! # Wrapper
//!
//! ```no_run
//! use paranoid::local_env_vault::{Profile, VaultRunner};
//!
//! fn main() -> Result<(), paranoid::local_env_vault::Error> {
//!     let profiles = [
//!         Profile::new(
//!             "app",
//!             [
//!                 "DATABASE_URL",
//!                 "APP_API_KEY",
//!                 "APP_API_SECRET",
//!             ],
//!         )?,
//!         Profile::new(
//!             "worker",
//!             [
//!                 "DATABASE_URL",
//!                 "WORKER_API_URL",
//!                 "WORKER_MODE",
//!             ],
//!         )?,
//!     ];
//!     let mut runner = VaultRunner::new(env!("CARGO_MANIFEST_DIR"), ".", profiles)?;
//!
//!     runner.run_from_args(std::env::args_os())
//! }
//! ```
//!
//! # Custom Process Projection
//!
//! Most wrappers should use [`VaultRunner::run_from_args`]. Applications
//! with their own process launcher can instead decrypt the selected profile as
//! [`SecretBytes`] values and inject those values themselves.
//!
//! ```no_run
//! use std::process::Command;
//!
//! use paranoid::crypto::SecretBytes;
//! use paranoid::local_env_vault::{Profile, VaultRunner};
//!
//! fn build_command(
//!     password: &SecretBytes,
//! ) -> Result<Command, paranoid::local_env_vault::Error> {
//!     let runner = VaultRunner::new(
//!         env!("CARGO_MANIFEST_DIR"),
//!         ".",
//!         [Profile::new("app", ["APP_API_KEY"])?],
//!     )?;
//!     let projected_env = runner.decrypt_profile_env("app", password)?;
//!
//!     let mut command = Command::new("cargo");
//!     command.arg("run");
//!     for (name, value) in projected_env {
//!         let value = std::str::from_utf8(value.expose_secret()).map_err(|_| {
//!             paranoid::local_env_vault::Error::SecretValueNotUtf8 { name: name.clone() }
//!         })?;
//!         command.env(name.as_str(), value);
//!     }
//!     Ok(command)
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{
    Base64Url, Encrypted, PasswordKdfParams, PasswordKdfSalt, PublicBytes, SecretBytes, decrypt,
    derive_argon2id_key32_from_password, derive_keyset_from_latest_first_keys, encrypt,
    random_public_bytes,
};
use crate::local_lock::{ProcessLock, ProcessLockOptions};

#[cfg(unix)]
use atomic_write_file::unix::OpenOptionsExt as AtomicUnixOpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::{
    DirBuilderExt as StdUnixDirBuilderExt, OpenOptionsExt as StdUnixOpenOptionsExt, PermissionsExt,
};

const DEFAULT_VAULT_DIR: &str = ".paranoid_local_env_vault";
const DEFAULT_VAULT_FILE_NAME: &str = "vault.json";
const VAULT_GITIGNORE_CONTENT: &str = "*\n";
const VAULT_VERSION: u32 = 1;
const ENCRYPTED_ENTRY_VERSION: u32 = 1;
const KDF_ALGORITHM_ARGON2ID: &str = "argon2id";
const ARGON2_VERSION_0X13: u32 = 19;
const STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
const STORED_PASSWORD_KDF_MAX_ITERATIONS: u32 = 10;
const MAX_VAULT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const VAULT_ID_RANDOM_BYTES: usize = 16;
const VAULT_LOCK_FILE_NAME: &str = "vault.lock";
const VAULT_LOCK_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);
const VAULT_LOCK_STALE_AFTER: Duration = Duration::from_secs(3);
const LOCAL_ENV_VAULT_KEYSET_PURPOSE: &str = "paranoid.local-env-vault.v1";
const LOCAL_ENV_VAULT_ENTRY_ASSOCIATED_DATA_DOMAIN: &[u8] = b"paranoid.local-env-vault.v1.entry";
const LOCAL_ENV_VAULT_PASSWORD_CHECK_ASSOCIATED_DATA_DOMAIN: &[u8] =
    b"paranoid.local-env-vault.v1.password-check";
const PASSWORD_CHECK_PLAINTEXT: &[u8] = b"paranoid.local-env-vault.v1.password-check";
#[cfg(unix)]
const VAULT_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const VAULT_FILE_MODE: u32 = 0o600;

/// Environment variable name accepted by Paranoid local env vault profiles and vaults.
///
/// Names use the strict ASCII grammar `[A-Z_][A-Z0-9_]*`.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvVarName(String);

impl EnvVarName {
    /// Validates an environment variable name.
    pub fn new(name: impl AsRef<str>) -> Result<Self, Error> {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(Error::InvalidEnvVarName {
                name: name.to_owned(),
            });
        }

        for (index, byte) in name.bytes().enumerate() {
            let valid = if index == 0 {
                byte == b'_' || byte.is_ascii_uppercase()
            } else {
                byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit()
            };
            if !valid {
                return Err(Error::InvalidEnvVarName {
                    name: name.to_owned(),
                });
            }
        }

        Ok(Self(name.to_owned()))
    }

    /// Returns the validated environment variable name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnvVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EnvVarName").field(&self.0).finish()
    }
}

impl fmt::Display for EnvVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Named local command profile with its required vault values.
///
/// A profile is an application-defined local command context, such as
/// `app` or `worker`. The profile name is not secret. Required values are
/// deduplicated and used to decide which vault entries may be decrypted for
/// that profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    name: String,
    required_names: BTreeSet<EnvVarName>,
}

impl Profile {
    /// Validates and constructs a local env vault profile.
    ///
    /// Profile names must start with an ASCII lowercase letter or digit and may
    /// then contain ASCII lowercase letters, digits, `_`, or `-`.
    pub fn new<I, S>(name: impl AsRef<str>, required_names: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let name = validate_profile_name(name.as_ref())?;
        let mut required = BTreeSet::new();
        for required_name in required_names {
            required.insert(EnvVarName::new(required_name)?);
        }
        if required.is_empty() {
            return Err(Error::ProfileRequiresNoValues { name });
        }

        Ok(Self {
            name,
            required_names: required,
        })
    }

    /// Returns the profile name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the required environment variable names.
    pub fn required_names(&self) -> impl ExactSizeIterator<Item = &EnvVarName> {
        self.required_names.iter()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalTextStyle {
    Heading,
    Success,
    Warning,
    Muted,
}

trait VaultTerminal {
    fn prompt_hidden_secret(&mut self, prompt: &str) -> Result<SecretBytes, Error>;

    fn select_menu_index(
        &mut self,
        prompt: &str,
        help_message: &str,
        options: &[String],
    ) -> Result<usize, Error>;

    fn write_line(&mut self, line: &str) -> Result<(), Error>;

    fn write_styled_line(&mut self, line: &str, _style: TerminalTextStyle) -> Result<(), Error> {
        self.write_line(line)
    }
}

#[derive(Debug, Default)]
struct SystemTerminal;

impl VaultTerminal for SystemTerminal {
    fn prompt_hidden_secret(&mut self, prompt: &str) -> Result<SecretBytes, Error> {
        let mut value = rpassword::prompt_password(prompt).map_err(Error::Io)?;
        let secret = SecretBytes::try_from(value.as_bytes())?;
        value.zeroize();
        Ok(secret)
    }

    fn select_menu_index(
        &mut self,
        prompt: &str,
        help_message: &str,
        options: &[String],
    ) -> Result<usize, Error> {
        if options.is_empty() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vault menu cannot be empty",
            )));
        }
        let selected = inquire::Select::new(prompt, options.to_vec())
            .with_help_message(help_message)
            .with_page_size(options.len().clamp(1, 12))
            .with_render_config(vault_menu_render_config())
            .raw_prompt_skippable()
            .map_err(inquire_error)?;
        Ok(selected.map_or(options.len() - 1, |selected| selected.index))
    }

    fn write_line(&mut self, line: &str) -> Result<(), Error> {
        write_system_terminal_line(line, None)
    }

    fn write_styled_line(&mut self, line: &str, style: TerminalTextStyle) -> Result<(), Error> {
        write_system_terminal_line(line, Some(style))
    }
}

fn write_system_terminal_line(line: &str, style: Option<TerminalTextStyle>) -> Result<(), Error> {
    let should_style =
        style.is_some() && io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut stdout = io::stdout().lock();
    if should_style {
        stdout
            .write_all(terminal_style_start_sequence(style.expect("style is present")).as_bytes())
            .map_err(Error::Io)?;
    }
    stdout.write_all(line.as_bytes()).map_err(Error::Io)?;
    if should_style {
        stdout.write_all(b"\x1b[0m").map_err(Error::Io)?;
    }
    stdout.write_all(b"\n").map_err(Error::Io)?;
    stdout.flush().map_err(Error::Io)
}

fn terminal_style_start_sequence(style: TerminalTextStyle) -> &'static str {
    match style {
        TerminalTextStyle::Heading => "\x1b[36m",
        TerminalTextStyle::Success => "\x1b[32m",
        TerminalTextStyle::Warning => "\x1b[33m",
        TerminalTextStyle::Muted => "\x1b[90m",
    }
}

fn vault_menu_render_config() -> inquire::ui::RenderConfig<'static> {
    let mut render_config = inquire::ui::RenderConfig::default();
    if std::env::var_os("NO_COLOR").is_none() {
        render_config = render_config
            .with_prompt_prefix(inquire::ui::Styled::new("?").with_fg(inquire::ui::Color::DarkCyan))
            .with_answered_prompt_prefix(
                inquire::ui::Styled::new(">").with_fg(inquire::ui::Color::DarkCyan),
            )
            .with_highlighted_option_prefix(
                inquire::ui::Styled::new(">").with_fg(inquire::ui::Color::DarkCyan),
            )
            .with_selected_option(Some(
                inquire::ui::StyleSheet::new().with_fg(inquire::ui::Color::DarkCyan),
            ))
            .with_help_message(inquire::ui::StyleSheet::new().with_fg(inquire::ui::Color::DarkGrey))
            .with_answer(inquire::ui::StyleSheet::new().with_fg(inquire::ui::Color::DarkCyan));
    }
    render_config
}

fn inquire_error(error: inquire::InquireError) -> Error {
    Error::Io(io::Error::other(error))
}

trait ChildProcessRunner {
    fn run_child_command(
        &mut self,
        command: Vec<OsString>,
        projected_env: BTreeMap<EnvVarName, SecretBytes>,
    ) -> Result<(), Error>;
}

#[derive(Debug, Default)]
struct SystemChildProcessRunner;

impl ChildProcessRunner for SystemChildProcessRunner {
    fn run_child_command(
        &mut self,
        command: Vec<OsString>,
        projected_env: BTreeMap<EnvVarName, SecretBytes>,
    ) -> Result<(), Error> {
        let status = spawn_with_projected_env(command, projected_env)?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::ChildCommandFailed { status })
        }
    }
}

/// Local encrypted environment vault runner.
///
/// This is the public high-level entry point for app-owned wrappers. It owns
/// terminal prompting, vault locking, vault file IO, and child process
/// execution. Lower-level terminal and process seams are intentionally private
/// so normal consumers get the hard-to-misuse path.
pub struct VaultRunner {
    core: VaultRunnerCore<SystemTerminal, SystemChildProcessRunner>,
}

impl VaultRunner {
    /// Constructs a local encrypted environment vault runner.
    ///
    /// `root` must be an absolute wrapper-owned directory, usually
    /// `env!("CARGO_MANIFEST_DIR")`. `path_relative_to_root` must be a
    /// non-empty relative path under `root`; pass `"."` to place the vault
    /// directly under `root`. Paranoid appends the fixed
    /// `.paranoid_local_env_vault` directory.
    ///
    /// Profile names must be unique. The vault value inventory is derived from
    /// the union of profile-required environment variable names.
    pub fn new<R, V, P>(root: R, path_relative_to_root: V, profiles: P) -> Result<Self, Error>
    where
        R: AsRef<Path>,
        V: AsRef<Path>,
        P: IntoIterator<Item = Profile>,
    {
        let mut core = VaultRunnerCore::with_terminal_and_child_process(
            profiles,
            SystemTerminal,
            SystemChildProcessRunner,
        )?;
        core.vault_dir =
            vault_dir_from_root_and_relative_parent(root.as_ref(), path_relative_to_root.as_ref())?;
        Ok(Self { core })
    }

    /// Runs the wrapper command from process arguments.
    ///
    /// The first argument is treated as the wrapper executable name. `configure`
    /// opens the configuration flow. `validate PROFILE` checks that the
    /// profile's required values are present. `run PROFILE -- COMMAND [ARG ...]`
    /// unlocks the vault, decrypts only the
    /// profile's required values, overlays them into the child process
    /// environment, and runs the child command.
    pub fn run_from_args<I, S>(&mut self, args: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.core.run_from_args(args)
    }

    /// Decrypts profile values for an application-owned child process runner.
    ///
    /// This is for wrappers that need custom process spawning but still want
    /// Paranoid to own vault parsing, password-derived keys, and per-profile
    /// decryption. The returned values are secret memory; callers must inject
    /// them into the child environment without logging or printing them.
    pub fn decrypt_profile_env(
        &self,
        profile_name: &str,
        password: &SecretBytes,
    ) -> Result<BTreeMap<EnvVarName, SecretBytes>, Error> {
        self.core.project_profile_env(profile_name, password)
    }
}

struct VaultRunnerCore<T, C> {
    profiles: BTreeMap<String, Profile>,
    required_vault_value_names: BTreeSet<EnvVarName>,
    vault_dir: PathBuf,
    password_kdf_params: PasswordKdfParams,
    terminal: T,
    child_process: C,
}

struct VaultValueStatusRow {
    name: EnvVarName,
    is_stored: bool,
    required_profile_count: usize,
}

struct ProfileStatusRow {
    name: String,
    stored_value_count: usize,
    required_value_count: usize,
}

struct ProfileValueStatusRow {
    is_stored: bool,
    name: EnvVarName,
}

#[derive(Clone, Copy)]
enum MainMenuAction {
    ConfigureVaultValues,
    ReviewProfiles,
    RemoveValuesNotRequiredByProfiles,
    Done,
}

struct MainMenuOption {
    action: MainMenuAction,
    label: String,
}

#[cfg(test)]
impl<T> VaultRunnerCore<T, SystemChildProcessRunner>
where
    T: VaultTerminal,
{
    fn with_terminal<P>(profiles: P, terminal: T) -> Result<Self, Error>
    where
        P: IntoIterator<Item = Profile>,
    {
        Self::with_terminal_and_child_process(profiles, terminal, SystemChildProcessRunner)
    }
}

impl<T, C> VaultRunnerCore<T, C>
where
    T: VaultTerminal,
    C: ChildProcessRunner,
{
    fn with_terminal_and_child_process<P>(
        profiles: P,
        terminal: T,
        child_process: C,
    ) -> Result<Self, Error>
    where
        P: IntoIterator<Item = Profile>,
    {
        let mut by_name = BTreeMap::new();
        for profile in profiles {
            let previous = by_name.insert(profile.name.clone(), profile);
            if previous.is_some() {
                return Err(Error::DuplicateProfileName);
            }
        }
        if by_name.is_empty() {
            return Err(Error::RunnerRequiresAtLeastOneProfile);
        }
        let required_vault_value_names = required_vault_value_names_for_profiles(&by_name);
        Ok(Self {
            profiles: by_name,
            required_vault_value_names,
            vault_dir: PathBuf::from(DEFAULT_VAULT_DIR),
            password_kdf_params: PasswordKdfParams::interactive_default(),
            terminal,
            child_process,
        })
    }

    #[cfg(test)]
    fn with_vault_dir(mut self, vault_dir: impl Into<PathBuf>) -> Self {
        self.vault_dir = vault_dir.into();
        self
    }

    fn run_from_args<I, S>(&mut self, args: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut args = args.into_iter().map(Into::into);
        let _program = args.next();
        let Some(command_name) = args.next() else {
            return Err(Error::InvalidCommandUsage);
        };
        let command_name = os_string_to_string(command_name)?;

        match command_name.as_str() {
            "configure" if args.next().is_none() => self.configure(),
            "validate" => {
                let Some(profile_name) = args.next() else {
                    return Err(Error::InvalidCommandUsage);
                };
                let profile_name = os_string_to_string(profile_name)?;
                if args.next().is_some() {
                    return Err(Error::InvalidCommandUsage);
                }
                self.check_profile(profile_name.as_str())
            }
            "run" => {
                let Some(profile_name) = args.next() else {
                    return Err(Error::InvalidCommandUsage);
                };
                let profile_name = os_string_to_string(profile_name)?;
                let Some(separator) = args.next() else {
                    return Err(Error::InvalidCommandUsage);
                };
                if separator != OsStr::new("--") {
                    return Err(Error::InvalidCommandUsage);
                }
                let command: Vec<OsString> = args.collect();
                if command.is_empty() {
                    return Err(Error::InvalidCommandUsage);
                }
                self.run_profile(profile_name.as_str(), command)
            }
            _ => Err(Error::InvalidCommandUsage),
        }
    }

    fn configure(&mut self) -> Result<(), Error> {
        ensure_vault_directory_layout(&self.vault_dir)?;

        let vault_path = self.vault_path();
        let lock = acquire_vault_lock(&self.vault_dir)?;
        let vault_exists = vault_file_exists_or_conflicts(&vault_path)?;
        let existing_vault = if vault_exists {
            Some(read_vault(&vault_path)?)
        } else {
            None
        };
        lock.ensure_still_owned()?;
        let password = if existing_vault.is_some() {
            self.terminal.write_line("")?;
            self.write_heading("UNLOCK VAULT")?;
            self.terminal.write_styled_line(
                "Unlocking local environment vault...",
                TerminalTextStyle::Muted,
            )?;
            self.terminal
                .prompt_hidden_secret("Enter vault password: ")?
        } else {
            self.terminal.write_line("")?;
            self.write_heading("CREATE VAULT")?;
            self.terminal.write_line(
                "Choose a password for checking profiles and projecting values into commands",
            )?;
            self.prompt_confirmed_password()?
        };
        lock.ensure_still_owned()?;
        let mut vault = if let Some(vault) = existing_vault {
            vault
        } else {
            let vault = VaultFile::new(&password, self.password_kdf_params)?;
            lock.run_while_owned(|| write_vault_atomically(&vault_path, &vault))?;
            self.write_success("Vault created")?;
            vault
        };
        lock.ensure_still_owned()?;
        let keyset = unlock_vault_keyset(&vault, &password)?;
        self.write_configure_overview()?;

        loop {
            lock.ensure_still_owned()?;
            self.terminal.write_line("")?;
            self.write_heading("MAIN MENU")?;
            let menu_options = self.main_menu_options(&vault);
            let options: Vec<String> = menu_options
                .iter()
                .map(|option| option.label.clone())
                .collect();
            let selected = self.terminal.select_menu_index(
                "Choose an action:",
                "Use arrow keys to move, type to filter, enter to select",
                &options,
            )?;
            if selected >= menu_options.len() {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vault menu selection out of range",
                )));
            }
            lock.ensure_still_owned()?;
            match menu_options[selected].action {
                MainMenuAction::ConfigureVaultValues => {
                    self.configure_vault_values(&vault_path, &mut vault, &keyset, &lock)?
                }
                MainMenuAction::ReviewProfiles => self.review_profiles(&vault, &lock)?,
                MainMenuAction::RemoveValuesNotRequiredByProfiles => self
                    .confirm_and_remove_values_not_required_by_profiles(
                        &vault_path,
                        &mut vault,
                        &lock,
                    )?,
                MainMenuAction::Done => return Ok(()),
            }
        }
    }

    fn write_configure_overview(&mut self) -> Result<(), Error> {
        self.terminal.write_line("")?;
        self.write_heading("LOCAL ENVIRONMENT VAULT")?;
        self.terminal
            .write_line("Values are shared by environment variable name")?;
        self.terminal
            .write_line("Profiles choose which vault values a command may access")?;
        Ok(())
    }

    fn configure_vault_values(
        &mut self,
        vault_path: &Path,
        vault: &mut VaultFile,
        keyset: &crate::crypto::Keyset,
        lock: &VaultLockSession,
    ) -> Result<(), Error> {
        loop {
            lock.ensure_still_owned()?;
            self.terminal.write_line("")?;
            self.write_heading("VALUES")?;
            let value_rows = self.vault_value_status_rows(vault);
            let options = self.vault_value_menu_options(&value_rows);
            let selected = self.terminal.select_menu_index(
                "Select a value to set or update:",
                "Values are shared across every profile that requires the same env var",
                &options,
            )?;
            if selected >= value_rows.len() {
                return Ok(());
            }
            lock.ensure_still_owned()?;
            let name = value_rows[selected].name.clone();
            self.write_one_value(vault_path, vault, keyset, &name, lock)?;
        }
    }

    fn review_profiles(&mut self, vault: &VaultFile, lock: &VaultLockSession) -> Result<(), Error> {
        loop {
            lock.ensure_still_owned()?;
            self.terminal.write_line("")?;
            self.write_heading("PROFILES")?;
            let profile_rows = self.profile_status_rows(vault);
            let options = self.profile_menu_options(&profile_rows);
            let selected = self.terminal.select_menu_index(
                "Select a profile to review:",
                "Profiles show which vault values a command needs",
                &options,
            )?;
            if selected >= profile_rows.len() {
                return Ok(());
            }
            lock.ensure_still_owned()?;
            let profile_name = profile_rows[selected].name.clone();
            self.write_profile_review(profile_name.as_str(), vault)?;
            let options = vec![
                "Back to profiles".to_owned(),
                "Done reviewing profiles".to_owned(),
            ];
            let selected = self.terminal.select_menu_index(
                "Continue:",
                "Use this review to find missing values; set them from the VALUES menu",
                &options,
            )?;
            lock.ensure_still_owned()?;
            if selected != 0 {
                return Ok(());
            }
        }
    }

    fn write_profile_review(&mut self, profile_name: &str, vault: &VaultFile) -> Result<(), Error> {
        self.terminal.write_line("")?;
        self.write_heading(&format!("PROFILE: {profile_name}"))?;
        self.terminal.write_line("REQUIRED VALUES:")?;
        for row in self.profile_value_status_rows(profile_name, vault)? {
            let status = if row.is_stored { "stored" } else { "missing" };
            self.terminal
                .write_line(&format!("  {} - {status}", row.name.as_str()))?;
        }
        Ok(())
    }

    fn write_one_value(
        &mut self,
        vault_path: &Path,
        vault: &mut VaultFile,
        keyset: &crate::crypto::Keyset,
        name: &EnvVarName,
        lock: &VaultLockSession,
    ) -> Result<(), Error> {
        lock.ensure_still_owned()?;
        self.terminal.write_line("")?;
        self.write_heading(&format!("SET VALUE: {}", name.as_str()))?;
        self.terminal
            .write_line("Input is hidden: nothing will appear while you type or paste")?;
        let value = self.terminal.prompt_hidden_secret("Enter value: ")?;
        let size_bucket = secret_size_bucket(&value);
        lock.run_while_owned(|| {
            vault.set_encrypted_value(keyset, name, &value)?;
            write_vault_atomically(vault_path, vault)
        })?;
        self.write_success(&format!("Stored {} ({size_bucket})", name.as_str()))
    }

    fn check_profile(&mut self, profile_name: &str) -> Result<(), Error> {
        self.profile(profile_name)?;
        let vault = read_vault(&self.vault_path())?;
        if self.write_profile_status(profile_name, &vault)? {
            Ok(())
        } else {
            Err(Error::MissingProfileValues)
        }
    }

    fn write_profile_status(
        &mut self,
        profile_name: &str,
        vault: &VaultFile,
    ) -> Result<bool, Error> {
        let profile = self.profile(profile_name)?;
        let missing = self.missing_profile_names(profile, vault);
        if missing.is_empty() {
            self.write_success(&format!("Profile {profile_name} is ready"))?;
            Ok(true)
        } else {
            self.write_heading("MISSING VALUES")?;
            for name in missing {
                self.write_warning(&format!("Missing {}", name.as_str()))?;
            }
            Ok(false)
        }
    }

    fn main_menu_options(&self, vault: &VaultFile) -> Vec<MainMenuOption> {
        let value_rows = self.vault_value_status_rows(vault);
        let stored_value_count = value_rows.iter().filter(|row| row.is_stored).count();
        let profile_rows = self.profile_status_rows(vault);
        let ready_profile_count = profile_rows
            .iter()
            .filter(|row| row.stored_value_count == row.required_value_count)
            .count();
        let removable_count = self.vault_value_names_not_required_by_profiles(vault).len();
        let mut options = vec![
            MainMenuOption {
                action: MainMenuAction::ConfigureVaultValues,
                label: format!(
                    "Set or update values ({stored_value_count}/{} stored)",
                    value_rows.len()
                ),
            },
            MainMenuOption {
                action: MainMenuAction::ReviewProfiles,
                label: format!(
                    "Review profiles ({ready_profile_count}/{} ready)",
                    profile_rows.len()
                ),
            },
        ];
        if removable_count != 0 {
            options.push(MainMenuOption {
                action: MainMenuAction::RemoveValuesNotRequiredByProfiles,
                label: format!(
                    "Remove values not required by profiles ({removable_count} {})",
                    plural_noun(removable_count, "value", "values")
                ),
            });
        }
        options.push(MainMenuOption {
            action: MainMenuAction::Done,
            label: "Done".to_owned(),
        });
        options
    }

    fn vault_value_status_rows(&self, vault: &VaultFile) -> Vec<VaultValueStatusRow> {
        self.required_vault_value_names
            .iter()
            .map(|name| {
                let required_profile_count = self
                    .profiles
                    .values()
                    .filter(|profile| profile.required_names.contains(name))
                    .count();
                VaultValueStatusRow {
                    is_stored: vault.encrypted_env.contains_key(name.as_str()),
                    name: name.clone(),
                    required_profile_count,
                }
            })
            .collect()
    }

    fn vault_value_menu_options(&self, rows: &[VaultValueStatusRow]) -> Vec<String> {
        let name_width = rows
            .iter()
            .map(|row| row.name.as_str().len())
            .max()
            .unwrap_or(0);
        let mut options: Vec<String> = rows
            .iter()
            .map(|row| {
                let status = if row.is_stored { "stored" } else { "missing" };
                format!(
                    "{:<name_width$}  {:<7}  required by {}",
                    row.name.as_str(),
                    status,
                    profile_count_text(row.required_profile_count)
                )
            })
            .collect();
        options.push("Back".to_owned());
        options
    }

    fn profile_menu_options(&self, rows: &[ProfileStatusRow]) -> Vec<String> {
        let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
        let mut options: Vec<String> = rows
            .iter()
            .map(|row| {
                format!(
                    "{:<name_width$}  {}/{} values stored",
                    row.name.as_str(),
                    row.stored_value_count,
                    row.required_value_count
                )
            })
            .collect();
        options.push("Back".to_owned());
        options
    }

    fn profile_status_rows(&self, vault: &VaultFile) -> Vec<ProfileStatusRow> {
        self.profiles
            .values()
            .map(|profile| {
                let required_value_count = profile.required_names().len();
                let stored_value_count = profile
                    .required_names()
                    .filter(|name| vault.encrypted_env.contains_key(name.as_str()))
                    .count();
                ProfileStatusRow {
                    name: profile.name().to_owned(),
                    stored_value_count,
                    required_value_count,
                }
            })
            .collect()
    }

    fn profile_value_status_rows(
        &self,
        profile_name: &str,
        vault: &VaultFile,
    ) -> Result<Vec<ProfileValueStatusRow>, Error> {
        let profile = self.profile(profile_name)?;
        Ok(profile
            .required_names()
            .map(|name| ProfileValueStatusRow {
                name: name.clone(),
                is_stored: vault.encrypted_env.contains_key(name.as_str()),
            })
            .collect())
    }

    fn vault_value_names_not_required_by_profiles(&self, vault: &VaultFile) -> Vec<EnvVarName> {
        vault
            .encrypted_env
            .keys()
            .filter_map(|name| {
                let name = EnvVarName::new(name).expect("vault validation ensures env var names");
                (!self.required_vault_value_names.contains(&name)).then_some(name)
            })
            .collect()
    }

    fn confirm_and_remove_values_not_required_by_profiles(
        &mut self,
        vault_path: &Path,
        vault: &mut VaultFile,
        lock: &VaultLockSession,
    ) -> Result<(), Error> {
        lock.ensure_still_owned()?;
        let names = self.vault_value_names_not_required_by_profiles(vault);
        if names.is_empty() {
            return Ok(());
        }

        self.terminal.write_line("")?;
        self.write_heading("VALUES NOT REQUIRED")?;
        for name in &names {
            self.write_warning(&format!("Not required {}", name.as_str()))?;
        }
        let options = vec![
            format!(
                "Remove {} {} not required by profiles",
                names.len(),
                plural_noun(names.len(), "value", "values")
            ),
            "Back".to_owned(),
        ];
        let selected = self.terminal.select_menu_index(
            "Choose cleanup action:",
            "Only remove values that no current profile requires",
            &options,
        )?;
        if selected != 0 {
            return Ok(());
        }
        let removed_count = lock.run_while_owned(|| {
            let removed_count = self.remove_vault_entries_not_required_by_profiles(vault)?;
            write_vault_atomically(vault_path, vault)?;
            Ok(removed_count)
        })?;
        self.write_success(&format!(
            "Removed {removed_count} stale {}",
            plural_noun(removed_count, "value", "values")
        ))
    }

    fn remove_vault_entries_not_required_by_profiles(
        &self,
        vault: &mut VaultFile,
    ) -> Result<usize, Error> {
        let required_names: BTreeSet<String> = self
            .required_vault_value_names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        let original_count = vault.encrypted_env.len();
        vault
            .encrypted_env
            .retain(|name, _entry| required_names.contains(name));
        let removed_count = original_count - vault.encrypted_env.len();
        if removed_count != 0 {
            vault.updated_at_unix_seconds = unix_now()?;
        }
        Ok(removed_count)
    }

    fn write_heading(&mut self, line: &str) -> Result<(), Error> {
        self.terminal
            .write_styled_line(line, TerminalTextStyle::Heading)
    }

    fn write_success(&mut self, line: &str) -> Result<(), Error> {
        self.terminal
            .write_styled_line(line, TerminalTextStyle::Success)
    }

    fn write_warning(&mut self, line: &str) -> Result<(), Error> {
        self.terminal
            .write_styled_line(line, TerminalTextStyle::Warning)
    }

    fn project_profile_env(
        &self,
        profile_name: &str,
        password: &SecretBytes,
    ) -> Result<BTreeMap<EnvVarName, SecretBytes>, Error> {
        let profile = self.profile(profile_name)?;
        let vault = self.read_vault_and_require_complete_profile(profile)?;
        let keyset = unlock_vault_keyset(&vault, password)?;
        self.decrypt_profile_from_unlocked_vault(profile, &vault, &keyset)
    }

    fn decrypt_profile_from_unlocked_vault(
        &self,
        profile: &Profile,
        vault: &VaultFile,
        keyset: &crate::crypto::Keyset,
    ) -> Result<BTreeMap<EnvVarName, SecretBytes>, Error> {
        let mut projected = BTreeMap::new();
        for name in profile.required_names() {
            let value = vault.decrypt_value(&keyset, name)?;
            projected.insert(name.clone(), value);
        }
        Ok(projected)
    }

    fn read_vault_and_require_complete_profile(
        &self,
        profile: &Profile,
    ) -> Result<VaultFile, Error> {
        let vault = read_vault(&self.vault_path())?;
        let missing = self.missing_profile_names(profile, &vault);
        if !missing.is_empty() {
            return Err(Error::MissingProfileValues);
        }
        Ok(vault)
    }

    fn run_profile(&mut self, profile_name: &str, command: Vec<OsString>) -> Result<(), Error> {
        if command.is_empty() {
            return Err(Error::MissingChildCommand);
        }
        let profile = self.profile(profile_name)?.clone();
        let vault = self.read_vault_and_require_complete_profile(&profile)?;
        let password = self
            .terminal
            .prompt_hidden_secret("Enter vault password: ")?;
        let keyset = unlock_vault_keyset(&vault, &password)?;
        let projected = self.decrypt_profile_from_unlocked_vault(&profile, &vault, &keyset)?;
        self.child_process.run_child_command(command, projected)
    }

    fn missing_profile_names(&self, profile: &Profile, vault: &VaultFile) -> Vec<EnvVarName> {
        profile
            .required_names()
            .filter_map(|name| {
                (!vault.encrypted_env.contains_key(name.as_str())).then_some(name.clone())
            })
            .collect()
    }

    fn profile(&self, profile_name: &str) -> Result<&Profile, Error> {
        self.profiles
            .get(profile_name)
            .ok_or_else(|| Error::UnknownProfile {
                name: profile_name.to_owned(),
            })
    }

    fn vault_path(&self) -> PathBuf {
        self.vault_dir.join(DEFAULT_VAULT_FILE_NAME)
    }

    fn prompt_confirmed_password(&mut self) -> Result<SecretBytes, Error> {
        let first = self
            .terminal
            .prompt_hidden_secret("Enter new vault password: ")?;
        let second = self
            .terminal
            .prompt_hidden_secret("Confirm new vault password: ")?;
        if first.expose_secret() != second.expose_secret() {
            return Err(Error::PasswordConfirmationMismatch);
        }
        Ok(first)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultFile {
    version: u32,
    vault_id: String,
    created_at_unix_seconds: u64,
    updated_at_unix_seconds: u64,
    kdf: StoredPasswordKdf,
    password_check: String,
    encrypted_env: BTreeMap<String, EncryptedEnvEntry>,
}

impl VaultFile {
    fn new(password: &SecretBytes, kdf_params: PasswordKdfParams) -> Result<Self, Error> {
        let now = unix_now()?;
        let mut vault = Self {
            version: VAULT_VERSION,
            vault_id: encode_public_bytes(random_public_bytes(VAULT_ID_RANDOM_BYTES)?),
            created_at_unix_seconds: now,
            updated_at_unix_seconds: now,
            kdf: StoredPasswordKdf::new(kdf_params)?,
            password_check: String::new(),
            encrypted_env: BTreeMap::new(),
        };
        let keyset = derive_vault_keyset(&vault, password)?;
        let check_plaintext: SecretBytes = SecretBytes::try_from(PASSWORD_CHECK_PLAINTEXT)?;
        let encrypted = encrypt(
            &keyset,
            &check_plaintext,
            &password_check_associated_data(&vault),
        )?;
        vault.password_check = encrypted.to_base64_url()?.into_exposed_string();
        Ok(vault)
    }

    fn set_encrypted_value(
        &mut self,
        keyset: &crate::crypto::Keyset,
        name: &EnvVarName,
        value: &SecretBytes,
    ) -> Result<(), Error> {
        let entry = EncryptedEnvEntry {
            version: ENCRYPTED_ENTRY_VERSION,
            updated_at_unix_seconds: unix_now()?,
            ciphertext: String::new(),
        };
        let associated_data = entry_associated_data(self, name, &entry);
        let encrypted = encrypt(keyset, value, &associated_data)?;
        let encoded = encrypted.to_base64_url()?.into_exposed_string();
        self.encrypted_env.insert(
            name.as_str().to_owned(),
            EncryptedEnvEntry {
                ciphertext: encoded,
                ..entry
            },
        );
        self.updated_at_unix_seconds = unix_now()?;
        Ok(())
    }

    fn decrypt_value(
        &self,
        keyset: &crate::crypto::Keyset,
        name: &EnvVarName,
    ) -> Result<SecretBytes, Error> {
        let entry = self
            .encrypted_env
            .get(name.as_str())
            .ok_or(Error::MissingProfileValues)?;
        let encrypted =
            Base64Url::<Encrypted<SecretBytes>>::parse_str(entry.ciphertext.as_str())?.decode()?;
        let associated_data = entry_associated_data(self, name, entry);
        decrypt(keyset, &encrypted, &associated_data).map_err(Error::from)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredPasswordKdf {
    algorithm: String,
    version: u32,
    memory_cost_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

impl StoredPasswordKdf {
    fn new(params: PasswordKdfParams) -> Result<Self, Error> {
        reject_password_kdf_params_above_local_bounds(&params)?;
        let salt = PasswordKdfSalt::generate()?;
        Ok(Self {
            algorithm: KDF_ALGORITHM_ARGON2ID.to_owned(),
            version: ARGON2_VERSION_0X13,
            memory_cost_kib: params.memory_cost_kib(),
            iterations: params.iterations(),
            parallelism: params.parallelism(),
            salt: encode_public_bytes(PublicBytes::try_from(salt.as_bytes().as_slice())?),
        })
    }

    fn params(&self) -> Result<PasswordKdfParams, Error> {
        if self.algorithm != KDF_ALGORITHM_ARGON2ID || self.version != ARGON2_VERSION_0X13 {
            return Err(Error::UnsupportedPasswordKdf);
        }
        let params =
            PasswordKdfParams::new(self.memory_cost_kib, self.iterations, self.parallelism)?;
        reject_password_kdf_params_above_local_bounds(&params)?;
        Ok(params)
    }

    fn salt(&self) -> Result<PasswordKdfSalt, Error> {
        let bytes = Base64Url::<PublicBytes>::parse_str(self.salt.as_str())?
            .decode()?
            .into_bytes();
        Ok(PasswordKdfSalt::from_bytes(bytes.as_slice())?)
    }
}

fn reject_password_kdf_params_above_local_bounds(params: &PasswordKdfParams) -> Result<(), Error> {
    if params.memory_cost_kib() > STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB {
        return Err(Error::PasswordKdfMemoryCostTooLarge {
            actual: params.memory_cost_kib(),
            max: STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB,
        });
    }
    if params.iterations() > STORED_PASSWORD_KDF_MAX_ITERATIONS {
        return Err(Error::PasswordKdfIterationsTooMany {
            actual: params.iterations(),
            max: STORED_PASSWORD_KDF_MAX_ITERATIONS,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EncryptedEnvEntry {
    version: u32,
    updated_at_unix_seconds: u64,
    ciphertext: String,
}

/// Errors returned by the local env vault.
#[derive(Debug)]
pub enum Error {
    /// A profile name was invalid.
    InvalidProfileName {
        /// Invalid profile name.
        name: String,
    },
    /// An environment variable name was invalid.
    InvalidEnvVarName {
        /// Invalid environment variable name.
        name: String,
    },
    /// A profile did not require any vault values.
    ProfileRequiresNoValues {
        /// Profile name.
        name: String,
    },
    /// More than one profile used the same name.
    DuplicateProfileName,
    /// A runner was constructed without any profiles.
    RunnerRequiresAtLeastOneProfile,
    /// The fixed vault path conflicts with an existing filesystem object.
    VaultPathConflict {
        /// Conflicting path.
        path: PathBuf,
    },
    /// A wrapper command did not match the supported command grammar.
    InvalidCommandUsage,
    /// A wrapper invocation expected a child command after `--`.
    MissingChildCommand,
    /// A wrapper argument was not UTF-8.
    ArgumentNotUtf8 {
        /// Non-UTF-8 argument.
        argument: OsString,
    },
    /// The named profile is not registered.
    UnknownProfile {
        /// Unknown profile name.
        name: String,
    },
    /// A profile is missing one or more required values.
    MissingProfileValues,
    /// Password confirmation did not match.
    PasswordConfirmationMismatch,
    /// The supplied password did not unlock the vault.
    PasswordRejected,
    /// The vault file is missing.
    VaultMissing {
        /// Missing vault path.
        path: PathBuf,
    },
    /// The vault file is too large to read.
    VaultFileTooLarge {
        /// Actual vault file size in bytes.
        actual: u64,
        /// Maximum accepted vault file size in bytes.
        max: u64,
    },
    /// The vault is currently locked.
    VaultLocked {
        /// Lock file path.
        path: PathBuf,
        /// Owning process id when available.
        pid: Option<u32>,
    },
    /// The vault lock was lost before a pending write could finish.
    VaultLockLost {
        /// Lock file path.
        path: PathBuf,
    },
    /// The vault root path was not absolute.
    VaultRootMustBeAbsolute {
        /// Supplied root path.
        path: PathBuf,
    },
    /// The vault parent path relative to root was empty.
    VaultParentPathRelativeToRootMustNotBeEmpty,
    /// The vault parent path relative to root was not relative.
    VaultParentPathMustBeRelative {
        /// Supplied parent path.
        path: PathBuf,
    },
    /// The vault parent path relative to root attempted to traverse upward.
    VaultParentPathMustNotTraverseParent {
        /// Supplied parent path.
        path: PathBuf,
    },
    /// Local lock operation failed.
    Lock(crate::local_lock::Error),
    /// The vault file uses an unsupported version.
    UnsupportedVaultVersion {
        /// Unsupported vault version.
        version: u32,
    },
    /// The encrypted entry uses an unsupported version.
    UnsupportedEncryptedEntryVersion {
        /// Unsupported entry version.
        version: u32,
    },
    /// The stored password KDF is unsupported.
    UnsupportedPasswordKdf,
    /// The stored password KDF memory cost is too large.
    PasswordKdfMemoryCostTooLarge {
        /// Actual memory cost in KiB.
        actual: u32,
        /// Maximum accepted memory cost in KiB.
        max: u32,
    },
    /// The stored password KDF iteration count is too large.
    PasswordKdfIterationsTooMany {
        /// Actual iteration count.
        actual: u32,
        /// Maximum accepted iteration count.
        max: u32,
    },
    /// The stored vault id has the wrong byte length.
    InvalidVaultIdLength {
        /// Actual decoded vault id byte length.
        actual: usize,
    },
    /// A decrypted environment value was not UTF-8.
    SecretValueNotUtf8 {
        /// Environment variable name.
        name: EnvVarName,
    },
    /// The child command returned a non-success exit status.
    ChildCommandFailed {
        /// Exit status returned by the child command.
        status: ExitStatus,
    },
    /// Filesystem or process IO failed.
    Io(io::Error),
    /// Vault JSON serialization or deserialization failed.
    Json(serde_json::Error),
    /// A Paranoid crypto primitive failed.
    Crypto(crate::crypto::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfileName { name } => {
                write!(f, "paranoid local-env-vault: invalid profile name {name:?}")
            }
            Self::InvalidEnvVarName { name } => {
                write!(
                    f,
                    "paranoid local-env-vault: invalid environment variable name {name:?}"
                )
            }
            Self::ProfileRequiresNoValues { name } => {
                write!(
                    f,
                    "paranoid local-env-vault: profile {name:?} must require at least one value"
                )
            }
            Self::DuplicateProfileName => {
                write!(f, "paranoid local-env-vault: duplicate profile name")
            }
            Self::RunnerRequiresAtLeastOneProfile => {
                write!(
                    f,
                    "paranoid local-env-vault: runner must register at least one profile"
                )
            }
            Self::VaultPathConflict { path } => {
                write!(
                    f,
                    "paranoid local-env-vault: fixed vault path conflicts with existing filesystem object at {path:?}"
                )
            }
            Self::InvalidCommandUsage => write!(
                f,
                "paranoid local-env-vault: invalid command usage; expected configure, validate PROFILE, or run PROFILE -- COMMAND [ARG ...]"
            ),
            Self::MissingChildCommand => {
                write!(f, "paranoid local-env-vault: missing child command")
            }
            Self::ArgumentNotUtf8 { argument } => {
                write!(
                    f,
                    "paranoid local-env-vault: argument is not UTF-8: {argument:?}"
                )
            }
            Self::UnknownProfile { name } => {
                write!(f, "paranoid local-env-vault: unknown profile {name:?}")
            }
            Self::MissingProfileValues => {
                write!(f, "paranoid local-env-vault: profile has missing values")
            }
            Self::PasswordConfirmationMismatch => {
                write!(
                    f,
                    "paranoid local-env-vault: password confirmation mismatch"
                )
            }
            Self::PasswordRejected => write!(f, "paranoid local-env-vault: password rejected"),
            Self::VaultMissing { path } => {
                write!(f, "paranoid local-env-vault: vault is missing at {path:?}")
            }
            Self::VaultFileTooLarge { actual, max } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault file size {actual} bytes exceeds maximum {max} bytes"
                )
            }
            Self::VaultLocked {
                path,
                pid: Some(pid),
            } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault is locked at {path:?} by pid {pid}"
                )
            }
            Self::VaultLocked { path, pid: None } => {
                write!(f, "paranoid local-env-vault: vault is locked at {path:?}")
            }
            Self::VaultLockLost { path } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault lock was lost at {path:?}"
                )
            }
            Self::VaultRootMustBeAbsolute { path } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault root path must be absolute: {path:?}"
                )
            }
            Self::VaultParentPathRelativeToRootMustNotBeEmpty => {
                write!(
                    f,
                    "paranoid local-env-vault: vault parent path relative to root must not be empty"
                )
            }
            Self::VaultParentPathMustBeRelative { path } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault parent path must be relative to root: {path:?}"
                )
            }
            Self::VaultParentPathMustNotTraverseParent { path } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault parent path must not traverse above root: {path:?}"
                )
            }
            Self::Lock(error) => write!(f, "paranoid local-env-vault: lock: {error}"),
            Self::UnsupportedVaultVersion { version } => {
                write!(
                    f,
                    "paranoid local-env-vault: unsupported vault version {version}"
                )
            }
            Self::UnsupportedEncryptedEntryVersion { version } => {
                write!(
                    f,
                    "paranoid local-env-vault: unsupported encrypted entry version {version}"
                )
            }
            Self::UnsupportedPasswordKdf => {
                write!(f, "paranoid local-env-vault: unsupported password KDF")
            }
            Self::PasswordKdfMemoryCostTooLarge { actual, max } => {
                write!(
                    f,
                    "paranoid local-env-vault: password KDF memory cost {actual} KiB exceeds maximum {max} KiB"
                )
            }
            Self::PasswordKdfIterationsTooMany { actual, max } => {
                write!(
                    f,
                    "paranoid local-env-vault: password KDF iteration count {actual} exceeds maximum {max}"
                )
            }
            Self::InvalidVaultIdLength { actual } => {
                write!(
                    f,
                    "paranoid local-env-vault: vault id length {actual}, want {VAULT_ID_RANDOM_BYTES}"
                )
            }
            Self::SecretValueNotUtf8 { name } => {
                write!(
                    f,
                    "paranoid local-env-vault: decrypted value for {name} is not UTF-8"
                )
            }
            Self::ChildCommandFailed { status } => {
                write!(
                    f,
                    "paranoid local-env-vault: child command failed with {status}"
                )
            }
            Self::Io(error) => write!(f, "paranoid local-env-vault: IO: {error}"),
            Self::Json(error) => write!(f, "paranoid local-env-vault: JSON: {error}"),
            Self::Crypto(error) => write!(f, "paranoid local-env-vault: crypto: {error}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Lock(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Crypto(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::crypto::Error> for Error {
    fn from(value: crate::crypto::Error) -> Self {
        Self::Crypto(value)
    }
}

fn validate_profile_name(name: &str) -> Result<String, Error> {
    if name.is_empty() {
        return Err(Error::InvalidProfileName {
            name: name.to_owned(),
        });
    }
    for (index, byte) in name.bytes().enumerate() {
        let valid = if index == 0 {
            byte.is_ascii_lowercase() || byte.is_ascii_digit()
        } else {
            byte == b'-' || byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit()
        };
        if !valid {
            return Err(Error::InvalidProfileName {
                name: name.to_owned(),
            });
        }
    }
    Ok(name.to_owned())
}

fn required_vault_value_names_for_profiles(
    profiles: &BTreeMap<String, Profile>,
) -> BTreeSet<EnvVarName> {
    profiles
        .values()
        .flat_map(|profile| profile.required_names().cloned())
        .collect()
}

fn os_string_to_string(argument: OsString) -> Result<String, Error> {
    argument
        .into_string()
        .map_err(|argument| Error::ArgumentNotUtf8 { argument })
}

fn vault_dir_from_root_and_relative_parent(
    root: &Path,
    path_relative_to_root: &Path,
) -> Result<PathBuf, Error> {
    if !root.is_absolute() {
        return Err(Error::VaultRootMustBeAbsolute {
            path: root.to_owned(),
        });
    }
    validate_vault_parent_path_relative_to_root(path_relative_to_root)?;
    Ok(root.join(path_relative_to_root).join(DEFAULT_VAULT_DIR))
}

fn validate_vault_parent_path_relative_to_root(path: &Path) -> Result<(), Error> {
    if path.as_os_str().is_empty() {
        return Err(Error::VaultParentPathRelativeToRootMustNotBeEmpty);
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::VaultParentPathMustNotTraverseParent {
                    path: path.to_owned(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::VaultParentPathMustBeRelative {
                    path: path.to_owned(),
                });
            }
        }
    }
    Ok(())
}

struct VaultLockSession {
    lock: ProcessLock,
    lock_lost: Arc<AtomicBool>,
}

impl VaultLockSession {
    fn ensure_still_owned(&self) -> Result<(), Error> {
        ensure_vault_lock_still_owned(&self.lock, &self.lock_lost)
    }

    fn run_while_owned<R>(&self, run: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
        self.ensure_still_owned()?;
        let result = run()?;
        self.ensure_still_owned()?;
        Ok(result)
    }

    #[cfg(test)]
    fn mark_lock_lost_for_test(&self) {
        self.lock_lost.store(true, Ordering::SeqCst);
    }
}

impl Drop for VaultLockSession {
    fn drop(&mut self) {
        let _ = self.lock.release();
    }
}

fn ensure_vault_lock_still_owned(lock: &ProcessLock, lock_lost: &AtomicBool) -> Result<(), Error> {
    if lock_lost.load(Ordering::SeqCst) || !lock.is_held_by_current_process() {
        return Err(Error::VaultLockLost {
            path: lock.lock_file_path().to_owned(),
        });
    }
    Ok(())
}

fn acquire_vault_lock(vault_dir: &Path) -> Result<VaultLockSession, Error> {
    ensure_vault_directory(vault_dir)?;
    let path = vault_dir.join(VAULT_LOCK_FILE_NAME);
    let lock_lost = Arc::new(AtomicBool::new(false));
    let lock_lost_for_callback = Arc::clone(&lock_lost);
    let mut lock = ProcessLock::with_options(
        &path,
        ProcessLockOptions {
            heartbeat_interval: Some(VAULT_LOCK_HEARTBEAT_INTERVAL),
            stale_after: Some(VAULT_LOCK_STALE_AFTER),
            on_lock_lost: Some(Arc::new(move || {
                lock_lost_for_callback.store(true, Ordering::SeqCst);
            })),
        },
    );
    match lock.acquire() {
        Ok(()) => Ok(VaultLockSession { lock, lock_lost }),
        Err(crate::local_lock::Error::LockHeld { path, pid }) => {
            Err(Error::VaultLocked { path, pid })
        }
        Err(error) => Err(Error::Lock(error)),
    }
}

fn read_vault(path: &Path) -> Result<VaultFile, Error> {
    ensure_existing_vault_parent_directory(path)?;
    ensure_existing_regular_vault_file_path(path)?;
    ensure_restrictive_file_permissions(path)?;
    reject_oversized_vault_file(path)?;
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Error::VaultMissing {
                path: path.to_owned(),
            }
        } else {
            Error::Io(error)
        }
    })?;
    let vault: VaultFile = serde_json::from_slice(&bytes).map_err(Error::Json)?;
    validate_vault(&vault)?;
    Ok(vault)
}

fn reject_oversized_vault_file(path: &Path) -> Result<(), Error> {
    let len = fs::metadata(path).map_err(Error::Io)?.len();
    if len > MAX_VAULT_FILE_BYTES {
        return Err(Error::VaultFileTooLarge {
            actual: len,
            max: MAX_VAULT_FILE_BYTES,
        });
    }
    Ok(())
}

fn ensure_existing_vault_parent_directory(path: &Path) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            ensure_restrictive_directory_permissions(parent)
        }
        Ok(_) => Err(Error::VaultPathConflict {
            path: parent.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(Error::VaultMissing {
            path: path.to_owned(),
        }),
        Err(error) => Err(Error::Io(error)),
    }
}

fn ensure_existing_regular_vault_file_path(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Error::VaultMissing {
                path: path.to_owned(),
            }
        } else {
            Error::Io(error)
        }
    })?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(Error::VaultPathConflict {
            path: path.to_owned(),
        })
    }
}

fn vault_file_exists_or_conflicts(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Error::VaultPathConflict {
            path: path.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

fn ensure_replaceable_vault_file_path(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(Error::VaultPathConflict {
            path: path.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

fn validate_vault(vault: &VaultFile) -> Result<(), Error> {
    if vault.version != VAULT_VERSION {
        return Err(Error::UnsupportedVaultVersion {
            version: vault.version,
        });
    }
    validate_vault_id(vault.vault_id.as_str())?;
    vault.kdf.params()?;
    vault.kdf.salt()?;
    validate_encrypted_secret_envelope(vault.password_check.as_str())?;
    for (name, entry) in &vault.encrypted_env {
        EnvVarName::new(name)?;
        if entry.version != ENCRYPTED_ENTRY_VERSION {
            return Err(Error::UnsupportedEncryptedEntryVersion {
                version: entry.version,
            });
        }
        validate_encrypted_secret_envelope(entry.ciphertext.as_str())?;
    }
    Ok(())
}

fn validate_encrypted_secret_envelope(encoded: &str) -> Result<(), Error> {
    let _ = Base64Url::<Encrypted<SecretBytes>>::parse_str(encoded)?.decode()?;
    Ok(())
}

fn validate_vault_id(vault_id: &str) -> Result<(), Error> {
    let bytes = Base64Url::<PublicBytes>::parse_str(vault_id)?
        .decode()?
        .into_bytes();
    if bytes.len() != VAULT_ID_RANDOM_BYTES {
        return Err(Error::InvalidVaultIdLength {
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn write_vault_atomically(path: &Path, vault: &VaultFile) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        ensure_vault_directory(parent)?;
    }
    ensure_replaceable_vault_file_path(path)?;
    let mut options = AtomicWriteFile::options();
    configure_atomic_vault_file_options(&mut options);
    let mut file = options.open(path).map_err(Error::Io)?;
    serde_json::to_writer_pretty(&mut file, vault).map_err(Error::Json)?;
    file.write_all(b"\n").map_err(Error::Io)?;
    file.commit().map_err(Error::Io)?;
    ensure_restrictive_file_permissions(path)
}

fn configure_atomic_vault_file_options(options: &mut atomic_write_file::OpenOptions) {
    #[cfg(unix)]
    {
        options.preserve_mode(false);
        options.mode(VAULT_FILE_MODE);
    }
}

fn derive_vault_keyset(
    vault: &VaultFile,
    password: &SecretBytes,
) -> Result<crate::crypto::Keyset, Error> {
    let key =
        derive_argon2id_key32_from_password(password, &vault.kdf.salt()?, vault.kdf.params()?)?;
    derive_keyset_from_latest_first_keys([key], LOCAL_ENV_VAULT_KEYSET_PURPOSE).map_err(Error::from)
}

fn unlock_vault_keyset(
    vault: &VaultFile,
    password: &SecretBytes,
) -> Result<crate::crypto::Keyset, Error> {
    let keyset = derive_vault_keyset(vault, password)?;
    let encrypted =
        Base64Url::<Encrypted<SecretBytes>>::parse_str(vault.password_check.as_str())?.decode()?;
    let decrypted = decrypt(&keyset, &encrypted, &password_check_associated_data(vault))
        .map_err(|_| Error::PasswordRejected)?;
    if decrypted.expose_secret() != PASSWORD_CHECK_PLAINTEXT {
        return Err(Error::PasswordRejected);
    }
    Ok(keyset)
}

fn entry_associated_data(
    vault: &VaultFile,
    name: &EnvVarName,
    entry: &EncryptedEnvEntry,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        LOCAL_ENV_VAULT_ENTRY_ASSOCIATED_DATA_DOMAIN.len()
            + vault.vault_id.len()
            + name.as_str().len()
            + 32,
    );
    push_ad_part(&mut out, LOCAL_ENV_VAULT_ENTRY_ASSOCIATED_DATA_DOMAIN);
    out.extend_from_slice(&vault.version.to_be_bytes());
    push_ad_part(&mut out, vault.vault_id.as_bytes());
    push_ad_part(&mut out, name.as_str().as_bytes());
    out.extend_from_slice(&entry.version.to_be_bytes());
    out
}

fn password_check_associated_data(vault: &VaultFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        LOCAL_ENV_VAULT_PASSWORD_CHECK_ASSOCIATED_DATA_DOMAIN.len() + vault.vault_id.len() + 16,
    );
    push_ad_part(
        &mut out,
        LOCAL_ENV_VAULT_PASSWORD_CHECK_ASSOCIATED_DATA_DOMAIN,
    );
    out.extend_from_slice(&vault.version.to_be_bytes());
    push_ad_part(&mut out, vault.vault_id.as_bytes());
    out
}

fn push_ad_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
    out.extend_from_slice(part);
}

fn secret_size_bucket(secret: &SecretBytes) -> &'static str {
    if secret.is_empty() {
        "0 bytes"
    } else {
        "1+ bytes"
    }
}

fn profile_count_text(count: usize) -> String {
    format!("{count} {}", plural_noun(count, "profile", "profiles"))
}

fn plural_noun<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn spawn_with_projected_env(
    command: Vec<OsString>,
    projected: BTreeMap<EnvVarName, SecretBytes>,
) -> Result<ExitStatus, Error> {
    let mut child = build_child_command_with_projected_env(command, projected)?;
    child.status().map_err(Error::Io)
}

fn build_child_command_with_projected_env(
    command: Vec<OsString>,
    projected: BTreeMap<EnvVarName, SecretBytes>,
) -> Result<Command, Error> {
    let mut command_iter = command.into_iter();
    let program = command_iter.next().ok_or(Error::MissingChildCommand)?;
    let mut child = Command::new(program);
    child.args(command_iter);

    for (name, value) in projected {
        let mut value_text = String::from_utf8(value.expose_secret().to_vec())
            .map_err(|_| Error::SecretValueNotUtf8 { name: name.clone() })?;
        child.env(name.as_str(), value_text.as_str());
        value_text.zeroize();
    }

    Ok(child)
}

fn encode_public_bytes(bytes: PublicBytes) -> String {
    bytes
        .to_base64_url()
        .expect("public bytes base64url encoding cannot fail")
        .into_exposed_string()
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| Error::Io(io::Error::other(error)))
}

fn ensure_vault_directory_layout(vault_dir: &Path) -> Result<(), Error> {
    ensure_vault_directory(vault_dir)?;
    ensure_vault_gitignore(vault_dir)
}

fn ensure_vault_directory(vault_dir: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(vault_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            ensure_restrictive_directory_permissions(vault_dir)
        }
        Ok(_) => Err(Error::VaultPathConflict {
            path: vault_dir.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_vault_directory(vault_dir),
        Err(error) => Err(Error::Io(error)),
    }
}

fn create_vault_directory(vault_dir: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    configure_new_restricted_directory_options(&mut builder);
    builder.create(vault_dir).map_err(Error::Io)?;
    ensure_restrictive_directory_permissions(vault_dir)
}

fn configure_new_restricted_directory_options(builder: &mut fs::DirBuilder) {
    #[cfg(unix)]
    {
        builder.mode(VAULT_DIR_MODE);
    }
}

fn ensure_vault_gitignore(vault_dir: &Path) -> Result<(), Error> {
    let gitignore_path = vault_dir.join(".gitignore");
    match fs::symlink_metadata(&gitignore_path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(Error::VaultPathConflict {
                path: gitignore_path,
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return write_new_vault_gitignore(&gitignore_path);
        }
        Err(error) => return Err(Error::Io(error)),
    }
    match fs::read_to_string(&gitignore_path) {
        Ok(existing) if existing == VAULT_GITIGNORE_CONTENT => {
            ensure_restrictive_file_permissions(&gitignore_path)
        }
        Ok(_) => Err(Error::VaultPathConflict {
            path: gitignore_path,
        }),
        Err(error) => Err(Error::Io(error)),
    }
}

fn write_new_vault_gitignore(path: &Path) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_new_restricted_file_options(&mut options);
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(VAULT_GITIGNORE_CONTENT.as_bytes())
                .map_err(Error::Io)?;
            file.sync_all().map_err(Error::Io)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure_vault_gitignore(path.parent().unwrap_or_else(|| Path::new(".")))
        }
        Err(error) => Err(Error::Io(error)),
    }
}

fn configure_new_restricted_file_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(VAULT_FILE_MODE);
    }
}

fn ensure_restrictive_directory_permissions(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        set_mode_if_needed(path, VAULT_DIR_MODE)?;
    }
    Ok(())
}

fn ensure_restrictive_file_permissions(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        set_mode_if_needed(path, VAULT_FILE_MODE)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode_if_needed(path: &Path, mode: u32) -> Result<(), Error> {
    let metadata = fs::metadata(path).map_err(Error::Io)?;
    let current = metadata.permissions().mode() & 0o777;
    if current != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(Error::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
