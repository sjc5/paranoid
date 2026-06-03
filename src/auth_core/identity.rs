use std::fmt;
use std::marker::PhantomData;

use super::*;

/// Opaque identifier for auth records of one semantic kind.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Id<K> {
    bytes: Vec<u8>,
    kind: PhantomData<fn() -> K>,
}

impl<K> Id<K> {
    /// Generates a new opaque auth identifier.
    pub(crate) fn generate() -> Result<Self, Error> {
        let id = crate::id::SortableId::new().map_err(|_| Error::FreshRandomMaterialUnavailable)?;
        Self::from_bytes(id.as_bytes().to_vec())
    }

    /// Copies non-empty opaque identifier bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptyId);
        }
        validate_auth_bytes_not_too_long("auth id", &bytes, ID_MAX_BYTES)?;
        Ok(Self {
            bytes,
            kind: PhantomData,
        })
    }

    /// Returns the opaque identifier bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<K> fmt::Debug for Id<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Id")
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

/// Semantic marker for subject identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SubjectIdKind {}

/// Semantic marker for session identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionIdKind {}

/// Semantic marker for trusted-device credential identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TrustedDeviceCredentialIdKind {}

/// Semantic marker for active-proof attempt identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActiveProofAttemptIdKind {}

/// Semantic marker for active-proof challenge identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActiveProofChallengeIdKind {}

/// Semantic marker for verified proof source identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VerifiedProofSourceIdKind {}

/// Semantic marker for effective recovery-authority identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RecoveryAuthorityIdKind {}

/// Semantic marker for pending credential-lifecycle action identifiers.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PendingCredentialLifecycleActionIdKind {}

/// Opaque auth subject id.
pub type SubjectId = Id<SubjectIdKind>;

/// Opaque auth session id.
pub type SessionId = Id<SessionIdKind>;

/// Opaque trusted-device credential id.
pub type TrustedDeviceCredentialId = Id<TrustedDeviceCredentialIdKind>;

/// Opaque active-proof attempt id.
pub type ActiveProofAttemptId = Id<ActiveProofAttemptIdKind>;

/// Opaque active-proof challenge id.
pub type ActiveProofChallengeId = Id<ActiveProofChallengeIdKind>;

/// Opaque identifier for the credential or external authority that produced a proof.
pub type VerifiedProofSourceId = Id<VerifiedProofSourceIdKind>;

/// Opaque identifier for one effective authority that can recover or mutate credentials.
pub type RecoveryAuthorityId = Id<RecoveryAuthorityIdKind>;

/// Opaque identifier for one delayed credential-lifecycle action.
pub type PendingCredentialLifecycleActionId = Id<PendingCredentialLifecycleActionIdKind>;

/// Unix timestamp in whole seconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixSeconds(u64);

impl UnixSeconds {
    /// Creates a timestamp from whole Unix seconds.
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the whole Unix seconds.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds a duration, returning an error on overflow.
    pub fn checked_add_duration(self, duration: DurationSeconds) -> Result<Self, Error> {
        self.0
            .checked_add(duration.get())
            .map(Self)
            .ok_or(Error::TimeOverflow)
    }

    pub(super) fn checked_sub_duration(self, duration: DurationSeconds) -> Option<Self> {
        self.0.checked_sub(duration.get()).map(Self)
    }
}

/// Duration in whole seconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DurationSeconds(u64);

impl DurationSeconds {
    /// Creates a duration from whole seconds.
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the whole seconds.
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(super) fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Reducer-visible credential version.
///
/// This is not secret material. A real store maps each issued version to a
/// client-held random secret and stores only the corresponding `MacOverSecret`
/// server-side. The reducer keeps the version visible so tests can verify
/// rotation and stale-credential handling without embedding random bytes in the
/// state machine.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretVersion(u64);

impl SecretVersion {
    /// Creates a non-zero credential version.
    pub fn new(version: u64) -> Result<Self, Error> {
        if version == 0 {
            return Err(Error::SecretVersionZero);
        }
        Ok(Self(version))
    }

    /// Returns the numeric version.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next credential version.
    pub fn next(self) -> Result<Self, Error> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(Error::SecretVersionOverflow)
    }
}
