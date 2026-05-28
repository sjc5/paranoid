//! Local encrypted environment vault and command runner.
//!
//! `local_env_vault` is for application-owned local wrappers such as `./env`. The
//! application defines profiles in code; Paranoid owns vault encryption,
//! password prompting, locking, atomic writes, and command argument handling.
//!
//! The wrapper intentionally has a small command shape:
//!
//! - no profile argument opens the human configuration flow;
//! - `PROFILE` checks whether that profile's required secret names are present;
//! - `PROFILE -- COMMAND [ARG ...]` unlocks the vault, decrypts only that
//!   profile's secrets, overlays them into the child process environment, and
//!   runs the command.
//!
//! # Wrapper
//!
//! ```no_run
//! use paranoid::local_env_vault::{Profile, VaultRunner};
//!
//! fn main() -> Result<(), paranoid::local_env_vault::Error> {
//!     let mut runner = VaultRunner::new([
//!         Profile::new(
//!             "app",
//!             [
//!                 "APP_DATABASE_URL",
//!                 "APP_API_KEY",
//!                 "APP_API_SECRET",
//!             ],
//!         )?,
//!         Profile::new(
//!             "worker",
//!             [
//!                 "WORKER_DATABASE_URL",
//!                 "WORKER_API_URL",
//!                 "WORKER_MODE",
//!             ],
//!         )?,
//!     ])?
//!     .with_vault_dir(".paranoid");
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
//!     let runner = VaultRunner::new([Profile::new("app", ["APP_API_KEY"])?])?;
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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{
    Base64Url, Encrypted, PasswordKdfParams, PasswordKdfSalt, PublicBytes, SecretBytes, decrypt,
    derive_argon2id_key32_from_password, derive_keyset_from_latest_first_keys, encrypt,
    random_public_bytes,
};
use crate::local_lock::{ProcessLock, ProcessLockOptions};

const DEFAULT_VAULT_DIR: &str = ".paranoid";
const DEFAULT_VAULT_FILE_NAME: &str = "vault.json";
const VAULT_GITIGNORE_CONTENT: &str = "*\n";
const VAULT_VERSION: u32 = 1;
const ENCRYPTED_ENTRY_VERSION: u32 = 1;
const KDF_ALGORITHM_ARGON2ID: &str = "argon2id";
const ARGON2_VERSION_0X13: u32 = 19;
const VAULT_ID_RANDOM_BYTES: usize = 16;
const LOCK_RANDOM_BYTES: usize = 16;
const VAULT_LOCK_FILE_NAME: &str = "vault.lock";
const VAULT_LOCK_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);
const VAULT_LOCK_STALE_AFTER: Duration = Duration::from_secs(3);
const LOCAL_ENV_VAULT_KEYSET_PURPOSE: &str = "paranoid.local-env-vault.v1";
const LOCAL_ENV_VAULT_ENTRY_ASSOCIATED_DATA_DOMAIN: &[u8] = b"paranoid.local-env-vault.v1.entry";
const LOCAL_ENV_VAULT_PASSWORD_CHECK_ASSOCIATED_DATA_DOMAIN: &[u8] =
    b"paranoid.local-env-vault.v1.password-check";
const PASSWORD_CHECK_PLAINTEXT: &[u8] = b"paranoid.local-env-vault.v1.password-check";

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

/// Named local command profile with its required environment variables.
///
/// A profile is an application-defined local command context, such as
/// `app` or `worker`. The profile name is not secret. The required
/// environment variable names are validated, deduplicated, and used to decide
/// which vault entries may be decrypted for that profile.
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
            return Err(Error::ProfileRequiresNoEnvVars { name });
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

trait VaultTerminal {
    fn prompt_line(&mut self, prompt: &str) -> Result<String, Error>;

    fn prompt_hidden_secret(&mut self, prompt: &str) -> Result<SecretBytes, Error>;

    fn write_line(&mut self, line: &str) -> Result<(), Error>;
}

#[derive(Debug, Default)]
struct SystemTerminal;

impl VaultTerminal for SystemTerminal {
    fn prompt_line(&mut self, prompt: &str) -> Result<String, Error> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(prompt.as_bytes()).map_err(Error::Io)?;
        stdout.flush().map_err(Error::Io)?;

        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(Error::Io)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }

    fn prompt_hidden_secret(&mut self, prompt: &str) -> Result<SecretBytes, Error> {
        let mut value = rpassword::prompt_password(prompt).map_err(Error::Io)?;
        let secret = SecretBytes::try_from(value.as_bytes())?;
        value.zeroize();
        Ok(secret)
    }

    fn write_line(&mut self, line: &str) -> Result<(), Error> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(line.as_bytes()).map_err(Error::Io)?;
        stdout.write_all(b"\n").map_err(Error::Io)?;
        stdout.flush().map_err(Error::Io)
    }
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
    /// Profile names must be unique.
    pub fn new<I>(profiles: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Profile>,
    {
        Ok(Self {
            core: VaultRunnerCore::with_terminal_and_child_process(
                profiles,
                SystemTerminal,
                SystemChildProcessRunner,
            )?,
        })
    }

    /// Sets the vault directory.
    ///
    /// The default is `.paranoid`.
    pub fn with_vault_dir(mut self, vault_dir: impl Into<PathBuf>) -> Self {
        self.core.vault_dir = vault_dir.into();
        self
    }

    /// Sets the vault JSON filename inside the vault directory.
    ///
    /// The default is `vault.json`. The filename must be a single file name,
    /// not a path.
    pub fn with_vault_file_name(
        mut self,
        vault_file_name: impl Into<String>,
    ) -> Result<Self, Error> {
        self.core.set_vault_file_name(vault_file_name)?;
        Ok(self)
    }

    /// Runs the wrapper command from process arguments.
    ///
    /// The first argument is treated as the wrapper executable name. With no
    /// following argument, this opens the configuration flow. With `PROFILE`,
    /// it checks that the profile's required secret names are present. With
    /// `PROFILE -- COMMAND [ARG ...]`, it unlocks the vault, decrypts only the
    /// profile's required values, overlays them into the child process
    /// environment, and runs the child command.
    pub fn run_from_args<I, S>(&mut self, args: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.core.run_from_args(args)
    }

    /// Decrypts profile secrets for an application-owned child process runner.
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
    vault_dir: PathBuf,
    vault_file_name: String,
    password_kdf_params: PasswordKdfParams,
    terminal: T,
    child_process: C,
}

#[cfg(test)]
impl<T> VaultRunnerCore<T, SystemChildProcessRunner>
where
    T: VaultTerminal,
{
    fn with_terminal<I>(profiles: I, terminal: T) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Profile>,
    {
        Self::with_terminal_and_child_process(profiles, terminal, SystemChildProcessRunner)
    }
}

impl<T, C> VaultRunnerCore<T, C>
where
    T: VaultTerminal,
    C: ChildProcessRunner,
{
    fn with_terminal_and_child_process<I>(
        profiles: I,
        terminal: T,
        child_process: C,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Profile>,
    {
        let mut by_name = BTreeMap::new();
        for profile in profiles {
            let previous = by_name.insert(profile.name.clone(), profile);
            if previous.is_some() {
                return Err(Error::DuplicateProfileName);
            }
        }
        Ok(Self {
            profiles: by_name,
            vault_dir: PathBuf::from(DEFAULT_VAULT_DIR),
            vault_file_name: DEFAULT_VAULT_FILE_NAME.to_owned(),
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

    fn set_vault_file_name(&mut self, vault_file_name: impl Into<String>) -> Result<(), Error> {
        let vault_file_name = vault_file_name.into();
        if vault_file_name.is_empty()
            || vault_file_name.contains('/')
            || vault_file_name.contains('\\')
            || vault_file_name == "."
            || vault_file_name == ".."
        {
            return Err(Error::InvalidVaultFileName { vault_file_name });
        }
        self.vault_file_name = vault_file_name;
        Ok(())
    }

    fn run_from_args<I, S>(&mut self, args: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut args = args.into_iter().map(Into::into);
        let _program = args.next();
        let Some(profile_name) = args.next() else {
            return self.configure();
        };
        let profile_name = os_string_to_string(profile_name)?;

        match args.next() {
            None => self.check_profile(profile_name.as_str()),
            Some(separator) if separator == OsStr::new("--") => {
                let command: Vec<OsString> = args.collect();
                self.run_profile(profile_name.as_str(), command)
            }
            Some(_) => Err(Error::UnexpectedExtraArgs),
        }
    }

    fn configure(&mut self) -> Result<(), Error> {
        fs::create_dir_all(&self.vault_dir).map_err(Error::Io)?;
        ensure_vault_gitignore(&self.vault_dir)?;

        let vault_path = self.vault_path();
        let lock_lost = Arc::new(AtomicBool::new(false));
        let lock = acquire_vault_lock(&self.vault_dir, &lock_lost)?;
        let vault_exists = vault_path.try_exists().map_err(Error::Io)?;
        let password = if vault_exists {
            self.terminal.write_line("")?;
            self.terminal
                .write_line("Unlock local environment vault.")?;
            self.terminal.prompt_hidden_secret("Vault password: ")?
        } else {
            self.terminal.write_line("")?;
            self.terminal
                .write_line("Create local environment vault.")?;
            self.terminal.write_line(
                "Choose a password. It will be required to check or project secrets.",
            )?;
            self.prompt_confirmed_password()?
        };
        let mut vault = if vault_exists {
            read_vault(&vault_path)?
        } else {
            let vault = VaultFile::new(&password, self.password_kdf_params)?;
            write_vault_atomically(&vault_path, &vault)?;
            self.terminal.write_line("Vault initialized.")?;
            vault
        };
        let keyset = unlock_vault_keyset(&vault, &password)?;

        loop {
            self.terminal.write_line("")?;
            self.terminal.write_line("Profiles:")?;
            let profile_rows = self.profile_status_rows(&vault);
            for (index, (name, configured, required)) in profile_rows.iter().enumerate() {
                self.terminal.write_line(&format!(
                    "  {}. {} - {}/{} secrets configured",
                    index + 1,
                    name,
                    configured,
                    required
                ))?;
            }
            self.terminal.write_line("  0. Done")?;
            let choice = self.terminal.prompt_line(&format!(
                "Select a profile [0-{}, Enter = done]: ",
                profile_rows.len()
            ))?;
            let choice = choice.trim();
            if choice.is_empty() || choice == "0" {
                return Ok(());
            }
            match parse_menu_choice(choice, profile_rows.len()) {
                Some(index) => {
                    let profile_name = profile_rows[index].0.clone();
                    self.configure_profile_secrets(
                        &vault_path,
                        &mut vault,
                        &keyset,
                        &profile_name,
                        &lock,
                        &lock_lost,
                    )?
                }
                _ => self.write_unknown_menu_choice(profile_rows.len())?,
            }
        }
    }

    fn configure_profile_secrets(
        &mut self,
        vault_path: &Path,
        vault: &mut VaultFile,
        keyset: &crate::crypto::Keyset,
        profile_name: &str,
        lock: &ProcessLock,
        lock_lost: &AtomicBool,
    ) -> Result<(), Error> {
        loop {
            self.terminal.write_line("")?;
            self.terminal
                .write_line(&format!("Profile: {profile_name}"))?;
            self.terminal.write_line("Secrets:")?;
            let secret_rows = self.profile_secret_status_rows(profile_name, vault)?;
            for (index, (name, is_configured)) in secret_rows.iter().enumerate() {
                let status = if *is_configured {
                    "configured"
                } else {
                    "missing"
                };
                self.terminal.write_line(&format!(
                    "  {}. {} - {}",
                    index + 1,
                    name.as_str(),
                    status
                ))?;
            }
            self.terminal.write_line("  0. Back")?;
            let choice = self.terminal.prompt_line(&format!(
                "Select a secret [0-{}, Enter = back]: ",
                secret_rows.len()
            ))?;
            let choice = choice.trim();
            if choice.is_empty() || choice == "0" {
                return Ok(());
            }
            match parse_menu_choice(choice, secret_rows.len()) {
                Some(index) => {
                    let name = secret_rows[index].0.clone();
                    self.write_one_secret(vault_path, vault, keyset, &name, lock, lock_lost)?;
                }
                None => self.write_unknown_menu_choice(secret_rows.len())?,
            }
        }
    }

    fn write_one_secret(
        &mut self,
        vault_path: &Path,
        vault: &mut VaultFile,
        keyset: &crate::crypto::Keyset,
        name: &EnvVarName,
        lock: &ProcessLock,
        lock_lost: &AtomicBool,
    ) -> Result<(), Error> {
        ensure_vault_lock_still_owned(lock, lock_lost)?;
        let value = self
            .terminal
            .prompt_hidden_secret(&format!("Enter value for {}: ", name.as_str()))?;
        ensure_vault_lock_still_owned(lock, lock_lost)?;
        vault.set_encrypted_value(keyset, name, &value)?;
        ensure_vault_lock_still_owned(lock, lock_lost)?;
        write_vault_atomically(vault_path, vault)?;
        self.terminal
            .write_line(&format!("Stored {}.", name.as_str()))
    }

    fn check_profile(&mut self, profile_name: &str) -> Result<(), Error> {
        let vault = read_vault(&self.vault_path())?;
        if self.write_profile_status(profile_name, &vault)? {
            Ok(())
        } else {
            Err(Error::MissingProfileSecrets)
        }
    }

    fn write_profile_status(
        &mut self,
        profile_name: &str,
        vault: &VaultFile,
    ) -> Result<bool, Error> {
        let profile = self.profile(profile_name)?;
        let missing = missing_profile_names(profile, vault);
        if missing.is_empty() {
            self.terminal
                .write_line(&format!("Profile {profile_name} is ready."))?;
            Ok(true)
        } else {
            for name in missing {
                self.terminal
                    .write_line(&format!("Missing {}.", name.as_str()))?;
            }
            Ok(false)
        }
    }

    fn profile_status_rows(&self, vault: &VaultFile) -> Vec<(String, usize, usize)> {
        self.profiles
            .values()
            .map(|profile| {
                let required = profile.required_names().len();
                let configured = profile
                    .required_names()
                    .filter(|name| vault.encrypted_env.contains_key(name.as_str()))
                    .count();
                (profile.name().to_owned(), configured, required)
            })
            .collect()
    }

    fn profile_secret_status_rows(
        &self,
        profile_name: &str,
        vault: &VaultFile,
    ) -> Result<Vec<(EnvVarName, bool)>, Error> {
        let profile = self.profile(profile_name)?;
        Ok(profile
            .required_names()
            .map(|name| {
                (
                    name.clone(),
                    vault.encrypted_env.contains_key(name.as_str()),
                )
            })
            .collect())
    }

    fn project_profile_env(
        &self,
        profile_name: &str,
        password: &SecretBytes,
    ) -> Result<BTreeMap<EnvVarName, SecretBytes>, Error> {
        let profile = self.profile(profile_name)?;
        let vault = read_vault(&self.vault_path())?;
        let missing = missing_profile_names(profile, &vault);
        if !missing.is_empty() {
            return Err(Error::MissingProfileSecrets);
        }
        let keyset = unlock_vault_keyset(&vault, password)?;
        let mut projected = BTreeMap::new();
        for name in profile.required_names() {
            let value = vault.decrypt_value(&keyset, name)?;
            projected.insert(name.clone(), value);
        }
        Ok(projected)
    }

    fn run_profile(&mut self, profile_name: &str, command: Vec<OsString>) -> Result<(), Error> {
        if command.is_empty() {
            return Err(Error::MissingChildCommand);
        }
        let password = self.terminal.prompt_hidden_secret("Vault password: ")?;
        let projected = self.project_profile_env(profile_name, &password)?;
        self.child_process.run_child_command(command, projected)
    }

    fn profile(&self, profile_name: &str) -> Result<&Profile, Error> {
        self.profiles
            .get(profile_name)
            .ok_or_else(|| Error::UnknownProfile {
                name: profile_name.to_owned(),
            })
    }

    fn vault_path(&self) -> PathBuf {
        self.vault_dir.join(&self.vault_file_name)
    }

    fn prompt_confirmed_password(&mut self) -> Result<SecretBytes, Error> {
        let first = self.terminal.prompt_hidden_secret("New vault password: ")?;
        let second = self
            .terminal
            .prompt_hidden_secret("Confirm vault password: ")?;
        if first.expose_secret() != second.expose_secret() {
            return Err(Error::PasswordConfirmationMismatch);
        }
        Ok(first)
    }

    fn write_unknown_menu_choice(&mut self, max_choice: usize) -> Result<(), Error> {
        self.terminal.write_line(&format!(
            "Unknown selection. Choose a number from 0 to {max_choice}."
        ))
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
            .ok_or(Error::MissingProfileSecrets)?;
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
        Ok(PasswordKdfParams::new(
            self.memory_cost_kib,
            self.iterations,
            self.parallelism,
        )?)
    }

    fn salt(&self) -> Result<PasswordKdfSalt, Error> {
        let bytes = Base64Url::<PublicBytes>::parse_str(self.salt.as_str())?
            .decode()?
            .into_bytes();
        Ok(PasswordKdfSalt::from_bytes(bytes.as_slice())?)
    }
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
    /// A profile did not require any environment variables.
    ProfileRequiresNoEnvVars {
        /// Profile name.
        name: String,
    },
    /// More than one profile used the same name.
    DuplicateProfileName,
    /// A vault filename was invalid.
    InvalidVaultFileName {
        /// Invalid vault filename.
        vault_file_name: String,
    },
    /// A wrapper invocation expected a child command after `--`.
    MissingChildCommand,
    /// A wrapper argument was not UTF-8.
    ArgumentNotUtf8 {
        /// Non-UTF-8 argument.
        argument: OsString,
    },
    /// A wrapper command received unexpected extra arguments.
    UnexpectedExtraArgs,
    /// The named profile is not registered.
    UnknownProfile {
        /// Unknown profile name.
        name: String,
    },
    /// A profile is missing one or more required secrets.
    MissingProfileSecrets,
    /// Password confirmation did not match.
    PasswordConfirmationMismatch,
    /// The supplied password did not unlock the vault.
    PasswordRejected,
    /// The vault file is missing.
    VaultMissing {
        /// Missing vault path.
        path: PathBuf,
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
            Self::ProfileRequiresNoEnvVars { name } => {
                write!(
                    f,
                    "paranoid local-env-vault: profile {name:?} must require at least one environment variable"
                )
            }
            Self::DuplicateProfileName => {
                write!(f, "paranoid local-env-vault: duplicate profile name")
            }
            Self::InvalidVaultFileName { vault_file_name } => {
                write!(
                    f,
                    "paranoid local-env-vault: invalid vault filename {vault_file_name:?}"
                )
            }
            Self::MissingChildCommand => {
                write!(f, "paranoid local-env-vault: missing child command")
            }
            Self::ArgumentNotUtf8 { argument } => {
                write!(
                    f,
                    "paranoid local-env-vault: argument is not UTF-8: {argument:?}"
                )
            }
            Self::UnexpectedExtraArgs => {
                write!(f, "paranoid local-env-vault: unexpected extra arguments")
            }
            Self::UnknownProfile { name } => {
                write!(f, "paranoid local-env-vault: unknown profile {name:?}")
            }
            Self::MissingProfileSecrets => {
                write!(f, "paranoid local-env-vault: profile has missing secrets")
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

fn os_string_to_string(argument: OsString) -> Result<String, Error> {
    argument
        .into_string()
        .map_err(|argument| Error::ArgumentNotUtf8 { argument })
}

fn parse_menu_choice(choice: &str, option_count: usize) -> Option<usize> {
    let raw_index = choice.parse::<usize>().ok()?;
    let index = raw_index.checked_sub(1)?;
    (index < option_count).then_some(index)
}

fn acquire_vault_lock(vault_dir: &Path, lock_lost: &Arc<AtomicBool>) -> Result<ProcessLock, Error> {
    fs::create_dir_all(vault_dir).map_err(Error::Io)?;
    let path = vault_dir.join(VAULT_LOCK_FILE_NAME);
    let lock_lost_for_callback = Arc::clone(lock_lost);
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
        Ok(()) => Ok(lock),
        Err(crate::local_lock::Error::LockHeld { path, pid }) => {
            Err(Error::VaultLocked { path, pid })
        }
        Err(error) => Err(Error::Lock(error)),
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

fn read_vault(path: &Path) -> Result<VaultFile, Error> {
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
    fs::create_dir_all(parent).map_err(Error::Io)?;
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(DEFAULT_VAULT_FILE_NAME),
        encode_public_bytes(random_public_bytes(LOCK_RANDOM_BYTES)?)
    );
    let tmp_path = parent.join(tmp_name);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(Error::Io)?;
        serde_json::to_writer_pretty(&mut file, vault).map_err(Error::Json)?;
        file.write_all(b"\n").map_err(Error::Io)?;
        file.sync_all().map_err(Error::Io)?;
        drop(file);
        fs::rename(&tmp_path, path).map_err(Error::Io)?;
        if let Ok(parent_file) = File::open(parent) {
            let _ = parent_file.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
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

fn missing_profile_names(profile: &Profile, vault: &VaultFile) -> Vec<EnvVarName> {
    profile
        .required_names()
        .filter(|name| !vault.encrypted_env.contains_key(name.as_str()))
        .cloned()
        .collect()
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

fn ensure_vault_gitignore(vault_dir: &Path) -> Result<(), Error> {
    let gitignore_path = vault_dir.join(".gitignore");
    match fs::read_to_string(&gitignore_path) {
        Ok(existing) if existing == VAULT_GITIGNORE_CONTENT => Ok(()),
        Ok(_) => fs::write(&gitignore_path, VAULT_GITIGNORE_CONTENT).map_err(Error::Io),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::write(&gitignore_path, VAULT_GITIGNORE_CONTENT).map_err(Error::Io)
        }
        Err(error) => Err(Error::Io(error)),
    }
}

#[cfg(test)]
mod tests;
