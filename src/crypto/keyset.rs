use std::fmt;

use crate::crypto::Error;
use crate::crypto::bytes::public_vec_with_capacity;
use crate::crypto::{KEY32_SIZE, Key32, SecretBytes, derive_blake3_key};

const KEYSET_HKDF_DERIVATION_SALT: &[u8] = b"paranoid/v1/purpose-keyset/hkdf-sha256/salt";
const KEYSET_HKDF_DERIVATION_INFO_PREFIX: &[u8] = b"paranoid/v1/purpose-keyset/hkdf-sha256/info/";
const KEYSET_BLAKE3_DERIVATION_CONTEXT: &str = "paranoid/v1/purpose-keyset/blake3";
const CHILD_HKDF_DERIVATION_SALT: &[u8] = b"paranoid/v1/child-keyset/hkdf-sha256/salt";
const CHILD_HKDF_DERIVATION_INFO_PREFIX: &[u8] = b"paranoid/v1/child-keyset/hkdf-sha256/info/";
const CHILD_BLAKE3_DERIVATION_CONTEXT: &str = "paranoid/v1/child-keyset/blake3";
pub(crate) const MAX_PURPOSE_LEN: usize = 255;

/// Maximum number of latest-first rotation keys accepted in one keyset.
pub const MAX_KEYSET_KEYS: usize = 16;

/// A latest-first set of derived working keys for one purpose.
pub struct Keyset {
    purpose: Purpose,
    latest_first_keys: Vec<ParanoidKey>,
}

/// Derives a latest-first keyset from latest-first `Key32` values and a purpose string.
pub fn derive_keyset_from_latest_first_keys<I>(
    latest_first_keys: I,
    purpose: &str,
) -> Result<Keyset, Error>
where
    I: IntoIterator<Item = Key32>,
{
    let mut input_keys = Vec::new();
    input_keys
        .try_reserve_exact(MAX_KEYSET_KEYS)
        .map_err(|_| Error::AllocationFailed)?;
    for key in latest_first_keys {
        if input_keys.len() == MAX_KEYSET_KEYS {
            return Err(Error::TooManyKeys {
                max: MAX_KEYSET_KEYS,
            });
        }
        input_keys.push(key);
    }
    validate_latest_first_keys(&input_keys)?;
    let purpose = Purpose::new(purpose)?;
    let mut derived_keys = Vec::new();
    derived_keys
        .try_reserve_exact(input_keys.len())
        .map_err(|_| Error::AllocationFailed)?;
    for key in &input_keys {
        derived_keys.push(derive_working_key_from_key32(key, purpose.as_str())?);
    }
    Ok(Keyset {
        purpose,
        latest_first_keys: derived_keys,
    })
}

impl Keyset {
    /// Returns the purpose string used to derive this keyset.
    pub fn purpose(&self) -> &str {
        self.purpose.as_str()
    }

    /// Returns the number of latest-first keys in this keyset.
    pub fn key_count(&self) -> usize {
        self.latest_first_keys.len()
    }

    /// Derives a latest-first child keyset for a narrower purpose.
    pub fn derive_child_keyset(&self, purpose: &str) -> Result<Keyset, Error> {
        let child_purpose = self.purpose.for_child(purpose)?;
        let mut child_keys = Vec::new();
        child_keys
            .try_reserve_exact(self.latest_first_keys.len())
            .map_err(|_| Error::AllocationFailed)?;
        for key in &self.latest_first_keys {
            child_keys.push(derive_child_key(key, self.purpose.as_str(), purpose)?);
        }
        Ok(Keyset {
            purpose: child_purpose,
            latest_first_keys: child_keys,
        })
    }

    pub(crate) fn latest_key(&self) -> &ParanoidKey {
        &self.latest_first_keys[0]
    }

    pub(crate) fn latest_first_keys(&self) -> &[ParanoidKey] {
        &self.latest_first_keys
    }
}

impl fmt::Debug for Keyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyset")
            .field("purpose", &self.purpose)
            .field("key_count", &self.latest_first_keys.len())
            .finish()
    }
}

pub(crate) struct ParanoidKey {
    pub(crate) hkdf_sha256: Key32,
    pub(crate) blake3: Key32,
}

impl fmt::Debug for ParanoidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ParanoidKey([redacted; 2])")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Purpose(String);

impl Purpose {
    fn new(purpose: &str) -> Result<Self, Error> {
        validate_purpose(purpose)?;
        Ok(Self(purpose.to_owned()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn for_child(&self, child_purpose: &str) -> Result<Self, Error> {
        validate_purpose(child_purpose)?;
        let combined_len = self.0.len() + 1 + child_purpose.len();
        if combined_len > MAX_PURPOSE_LEN {
            return Err(Error::PurposeTooLong {
                actual: combined_len,
                max: MAX_PURPOSE_LEN,
            });
        }

        let mut combined = String::new();
        combined
            .try_reserve_exact(combined_len)
            .map_err(|_| Error::AllocationFailed)?;
        combined.push_str(&self.0);
        combined.push('/');
        combined.push_str(child_purpose);
        Ok(Self(combined))
    }
}

impl fmt::Debug for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Purpose").field(&self.0).finish()
    }
}

fn validate_latest_first_keys(latest_first_keys: &[Key32]) -> Result<(), Error> {
    if latest_first_keys.is_empty() {
        return Err(Error::EmptyKeyset);
    }
    for index in 0..latest_first_keys.len() {
        if latest_first_keys[..index].contains(&latest_first_keys[index]) {
            return Err(Error::DuplicateKey { index });
        }
    }
    Ok(())
}

pub(crate) fn derive_working_key_from_key32(
    input_key: &Key32,
    purpose: &str,
) -> Result<ParanoidKey, Error> {
    let purpose_bytes = length_prefixed_bytes(purpose.as_bytes())?;
    let hkdf_sha256 = derive_hkdf_key(
        input_key,
        KEYSET_HKDF_DERIVATION_SALT,
        KEYSET_HKDF_DERIVATION_INFO_PREFIX,
        &purpose_bytes,
    )?;
    let blake3 =
        derive_blake3_key_from_parent(input_key, KEYSET_BLAKE3_DERIVATION_CONTEXT, &purpose_bytes)?;
    Ok(ParanoidKey {
        hkdf_sha256,
        blake3,
    })
}

fn derive_child_key(
    parent_key: &ParanoidKey,
    parent_purpose: &str,
    child_purpose: &str,
) -> Result<ParanoidKey, Error> {
    let parent_purpose_bytes = parent_purpose.as_bytes();
    let child_purpose_bytes = child_purpose.as_bytes();
    let mut derivation_context = public_vec_with_capacity(
        std::mem::size_of::<u16>()
            + parent_purpose_bytes.len()
            + std::mem::size_of::<u16>()
            + child_purpose_bytes.len(),
    )?;
    derivation_context.extend_from_slice(&(parent_purpose_bytes.len() as u16).to_be_bytes());
    derivation_context.extend_from_slice(parent_purpose_bytes);
    derivation_context.extend_from_slice(&(child_purpose_bytes.len() as u16).to_be_bytes());
    derivation_context.extend_from_slice(child_purpose_bytes);

    let hkdf_sha256 = derive_hkdf_key(
        &parent_key.hkdf_sha256,
        CHILD_HKDF_DERIVATION_SALT,
        CHILD_HKDF_DERIVATION_INFO_PREFIX,
        &derivation_context,
    )?;
    let blake3 = derive_blake3_key_from_parent(
        &parent_key.blake3,
        CHILD_BLAKE3_DERIVATION_CONTEXT,
        &derivation_context,
    )?;
    Ok(ParanoidKey {
        hkdf_sha256,
        blake3,
    })
}

fn length_prefixed_bytes(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = public_vec_with_capacity(std::mem::size_of::<u16>() + bytes.len())?;
    output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(output)
}

fn derive_hkdf_key(
    parent_key: &Key32,
    salt: &[u8],
    info_prefix: &[u8],
    derivation_context: &[u8],
) -> Result<Key32, Error> {
    let mut info = public_vec_with_capacity(info_prefix.len() + derivation_context.len())?;
    info.extend_from_slice(info_prefix);
    info.extend_from_slice(derivation_context);
    parent_key
        .derive_hkdf_sha256(salt, &info)
        .map_err(Error::from)
}

fn derive_blake3_key_from_parent(
    parent_key: &Key32,
    context: &'static str,
    derivation_context: &[u8],
) -> Result<Key32, Error> {
    let mut key_material: SecretBytes =
        SecretBytes::new_zeroed(KEY32_SIZE + derivation_context.len())?;
    let (key_bytes, context_bytes) = key_material.expose_secret_mut().split_at_mut(KEY32_SIZE);
    key_bytes.copy_from_slice(parent_key.expose_secret());
    context_bytes.copy_from_slice(derivation_context);
    Ok(derive_blake3_key(context, key_material.expose_secret()))
}

fn validate_purpose(purpose: &str) -> Result<(), Error> {
    if purpose.is_empty() {
        return Err(Error::EmptyPurpose);
    }
    if purpose.len() > MAX_PURPOSE_LEN {
        return Err(Error::PurposeTooLong {
            actual: purpose.len(),
            max: MAX_PURPOSE_LEN,
        });
    }
    for (index, byte) in purpose.as_bytes().iter().copied().enumerate() {
        if byte == b'/' || !(0x21..=0x7e).contains(&byte) {
            return Err(Error::InvalidPurposeByte { index, byte });
        }
    }
    Ok(())
}
