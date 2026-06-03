use super::*;

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
