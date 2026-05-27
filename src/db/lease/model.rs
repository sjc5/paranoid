use super::*;
use crate::crypto::fill_random;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Validated persisted coordination key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key(pub(super) String);

/// Validated coordination holder identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HolderId(pub(super) String);

/// Positive lease ownership generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FencingToken(pub(super) i64);

pub(super) struct Token(pub(super) [u8; LEASE_TOKEN_BYTES]);

/// Validated coordination claim duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimDuration {
    positive_duration: StdDuration,
}

/// Current coordination claim returned by a successful claim or renewal.
#[derive(Debug, Eq, PartialEq)]
pub struct Claim {
    pub(super) key: Key,
    pub(super) holder_id: HolderId,
    pub(super) fencing_token: FencingToken,
    pub(super) lease_token: Token,
    pub(super) expires_at_unix_microseconds: i64,
}

/// Non-secret view of the current live holder for a coordination key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HolderSnapshot {
    pub(super) key: Key,
    pub(super) holder_id: HolderId,
    pub(super) fencing_token: FencingToken,
    pub(super) expires_at_unix_microseconds: i64,
}

impl Key {
    /// Validates and joins key parts into a persisted coordination key.
    pub fn from_parts<S, I>(parts: I) -> Result<Self, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        Ok(Self(build_key_from_parts(parts)?))
    }

    /// Returns the persisted key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl HolderId {
    /// Validates and copies a coordination holder identifier.
    pub fn new(input: impl AsRef<str>) -> Result<Self, Error> {
        validate_holder_id(input.as_ref())?;
        Ok(Self(input.as_ref().to_owned()))
    }

    /// Returns the holder identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FencingToken {
    /// Returns the positive fencing token as a signed Postgres integer.
    pub fn as_i64(self) -> i64 {
        self.0
    }

    pub(super) fn from_i64(value: i64) -> Result<Self, Error> {
        if value <= 0 {
            return Err(Error::InvalidPersistedFencingToken { value });
        }
        Ok(Self(value))
    }
}

impl Token {
    pub(super) fn random() -> Result<Self, Error> {
        let mut bytes = [0_u8; LEASE_TOKEN_BYTES];
        fill_random(&mut bytes).map_err(|source| Error::TokenGeneration {
            source: crate::crypto::Error::from(source),
        })?;
        Ok(Self(bytes))
    }

    pub(super) fn from_persisted_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let actual = bytes.len();
        let token_bytes: [u8; LEASE_TOKEN_BYTES] =
            bytes
                .try_into()
                .map_err(|_| Error::InvalidPersistedTokenLength {
                    actual,
                    expected: LEASE_TOKEN_BYTES,
                })?;
        Ok(Self(token_bytes))
    }

    pub(super) fn as_bytes(&self) -> &[u8; LEASE_TOKEN_BYTES] {
        &self.0
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl Eq for Token {}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("len", &LEASE_TOKEN_BYTES)
            .finish()
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ClaimDuration {
    /// Validates a positive coordination claim duration.
    pub fn expires_after(duration: StdDuration) -> Result<Self, Error> {
        if duration.is_zero() {
            return Err(Error::DurationIsZero);
        }
        if duration < MIN_LEASE_DURATION {
            return Err(Error::duration_below_minimum());
        }
        duration_to_rounded_microseconds(duration)?;
        Ok(Self {
            positive_duration: duration,
        })
    }

    /// Returns the validated positive coordination claim duration.
    pub fn as_duration(self) -> StdDuration {
        self.positive_duration
    }

    pub(super) fn positive_microseconds(self) -> Result<i64, Error> {
        duration_to_rounded_microseconds(self.positive_duration)
    }
}

impl Claim {
    /// Returns the coordination key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        &self.holder_id
    }

    /// Returns this claim's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the claim expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.expires_at_unix_microseconds
    }
}

impl HolderSnapshot {
    /// Returns the coordination key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        &self.holder_id
    }

    /// Returns the holder's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the holder snapshot expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.expires_at_unix_microseconds
    }
}

fn build_key_from_parts<S, I>(parts: I) -> Result<String, Error>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut key = String::new();
    let mut saw_part = false;

    for part in parts {
        let part = part.as_ref();
        validate_key_part(part)?;
        if saw_part {
            key.push_str(LEASE_KEY_SEPARATOR);
        }
        key.push_str(part);
        saw_part = true;
    }

    if !saw_part {
        return Err(Error::EmptyKey);
    }

    key.push_str(LEASE_KEY_SEPARATOR);
    validate_key_length(&key)?;
    Ok(key)
}

fn validate_key_part(part: &str) -> Result<(), Error> {
    if part.is_empty() {
        return Err(Error::EmptyKeyPart);
    }
    if part.as_bytes().contains(&b':') {
        return Err(Error::KeyPartContainsSeparatorByte);
    }
    if part.as_bytes().contains(&0) {
        return Err(Error::KeyPartContainsNullByte);
    }
    Ok(())
}

fn validate_key_length(key: &str) -> Result<(), Error> {
    let actual = key.len();
    if actual > MAX_LEASE_KEY_BYTES {
        return Err(Error::key_too_long(actual));
    }
    Ok(())
}

fn validate_holder_id(holder_id: &str) -> Result<(), Error> {
    if holder_id.is_empty() {
        return Err(Error::EmptyHolderId);
    }
    if holder_id.as_bytes().contains(&0) {
        return Err(Error::HolderIdContainsNullByte);
    }
    let actual = holder_id.len();
    if actual > MAX_LEASE_HOLDER_ID_BYTES {
        return Err(Error::holder_id_too_long(actual));
    }
    Ok(())
}

pub(super) fn duration_to_rounded_microseconds(duration: StdDuration) -> Result<i64, Error> {
    let nanoseconds = duration.as_nanos();
    let microseconds = (nanoseconds / 1_000) + u128::from(!nanoseconds.is_multiple_of(1_000));
    if microseconds > i64::MAX as u128 {
        return Err(Error::DurationTooLarge);
    }
    Ok(microseconds as i64)
}
