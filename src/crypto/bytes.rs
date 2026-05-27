use std::fmt;
use std::marker::PhantomData;

use crate::crypto::Error;
use crate::crypto::{KEY32_SIZE, Key32, SecretBytes, fill_random};
use zeroize::Zeroize;

/// Maximum random byte buffer size accepted by this crate.
pub const MAX_RANDOM_BYTES_SIZE: usize = MAX_BYTE_CONTAINER_SIZE;

/// Maximum caller-provided public or secret byte container size accepted by this crate.
pub const MAX_BYTE_CONTAINER_SIZE: usize = 1 << 20;

/// Default marker for public bytes without a narrower semantic role.
pub enum PublicBytesKind {}

/// Public bytes with an optional semantic marker.
pub struct PublicBytes<K = PublicBytesKind> {
    bytes: Vec<u8>,
    kind: PhantomData<fn() -> K>,
}

impl<K> PublicBytes<K> {
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        validate_byte_container_len(bytes.len())?;
        let mut copied = public_vec_with_capacity(bytes.len())?;
        copied.extend_from_slice(bytes);
        Ok(Self {
            bytes: copied,
            kind: PhantomData,
        })
    }

    pub(crate) fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        validate_byte_container_len(bytes.len())?;
        Ok(Self {
            bytes,
            kind: PhantomData,
        })
    }

    /// Returns the public bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the public bytes by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[cfg(test)]
    pub(crate) fn with_kind<T>(self) -> PublicBytes<T> {
        PublicBytes {
            bytes: self.bytes,
            kind: PhantomData,
        }
    }
}

impl<K> TryFrom<&[u8]> for PublicBytes<K> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl<K> TryFrom<Vec<u8>> for PublicBytes<K> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}

impl<K> AsRef<[u8]> for PublicBytes<K> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<K> Clone for PublicBytes<K> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            kind: PhantomData,
        }
    }
}

impl<K> PartialEq for PublicBytes<K> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<K> Eq for PublicBytes<K> {}

impl<K> fmt::Debug for PublicBytes<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicBytes")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Generates one random 32-byte key.
pub fn random_key32() -> Result<Key32, Error> {
    let mut bytes = [0_u8; KEY32_SIZE];
    fill_random(&mut bytes)?;
    let key = Key32::try_from(bytes.as_slice());
    bytes.zeroize();
    key
}

/// Generates a random secret byte buffer of exactly `len` bytes.
pub fn random_secret_bytes(len: usize) -> Result<SecretBytes, Error> {
    validate_random_len(len)?;
    SecretBytes::random(len)
}

/// Generates a random public byte buffer of exactly `len` bytes.
pub fn random_public_bytes(len: usize) -> Result<PublicBytes, Error> {
    validate_random_len(len)?;
    let mut bytes = public_vec_with_capacity(len)?;
    bytes.resize(len, 0);
    fill_random(&mut bytes)?;
    PublicBytes::from_vec(bytes)
}

fn validate_random_len(len: usize) -> Result<(), Error> {
    if len == 0 {
        return Err(Error::RandomBytesLengthIsZero);
    }
    if len > MAX_RANDOM_BYTES_SIZE {
        return Err(Error::RandomBytesTooLarge {
            actual: len,
            max: MAX_RANDOM_BYTES_SIZE,
        });
    }
    Ok(())
}

pub(crate) fn validate_byte_container_len(len: usize) -> Result<(), Error> {
    if len > MAX_BYTE_CONTAINER_SIZE {
        return Err(Error::ByteContainerTooLarge {
            actual: len,
            max: MAX_BYTE_CONTAINER_SIZE,
        });
    }
    Ok(())
}

pub(crate) fn public_vec_with_capacity(capacity: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::AllocationFailed)?;
    Ok(bytes)
}
