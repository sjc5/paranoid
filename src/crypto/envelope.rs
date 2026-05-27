use std::fmt;
use std::marker::PhantomData;

use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

use crate::crypto::Error;
use crate::crypto::bytes::{PublicBytes, public_vec_with_capacity};
use crate::crypto::keyset::{Keyset, ParanoidKey};
use crate::crypto::{
    AES_256_GCM_SIV_NONCE_SIZE, AES_256_GCM_SIV_TAG_SIZE, KEY_SIZE, Key32, SecretBytes,
    XCHACHA20_POLY1305_NONCE_SIZE, XCHACHA20_POLY1305_TAG_SIZE, decrypt_aes_256_gcm_siv,
    decrypt_xchacha20_poly1305, derive_blake3_key, encrypt_aes_256_gcm_siv,
    encrypt_xchacha20_poly1305, random_array,
};

/// Maximum plaintext size accepted by purpose-bound encryption.
pub const MAX_PLAINTEXT_SIZE: usize = 1 << 20;

/// Maximum associated-data size accepted by purpose-bound encryption.
pub const MAX_ASSOCIATED_DATA_SIZE: usize = 1 << 20;

pub(crate) const MAGIC: &[u8; 4] = b"PARA";
pub(crate) const VERSION: u8 = 1;
pub(crate) const SUITE_PARANOID_V1: u8 = 1;
pub(crate) const SALT_SIZE: usize = 32;
pub(crate) const TRUE_LENGTH_SIZE: usize = 8;
pub(crate) const MIN_PADDED_PAYLOAD_SIZE: usize = 256;
pub(crate) const MAX_PADDED_PAYLOAD_SIZE: usize = 1 << 21;
pub(crate) const CASCADE_TAG_OVERHEAD: usize =
    XCHACHA20_POLY1305_TAG_SIZE + AES_256_GCM_SIV_TAG_SIZE;
const MIN_CASCADE_CIPHERTEXT_SIZE: usize = MIN_PADDED_PAYLOAD_SIZE + CASCADE_TAG_OVERHEAD;
const MAX_CASCADE_CIPHERTEXT_SIZE: usize = MAX_PADDED_PAYLOAD_SIZE + CASCADE_TAG_OVERHEAD;
pub(crate) const HKDF_SALT_OFFSET: usize = MAGIC.len() + 2;
pub(crate) const BLAKE3_SALT_OFFSET: usize = HKDF_SALT_OFFSET + SALT_SIZE;
pub(crate) const XCHACHA_NONCE_OFFSET: usize = BLAKE3_SALT_OFFSET + SALT_SIZE;
pub(crate) const AES_GCM_SIV_NONCE_OFFSET: usize =
    XCHACHA_NONCE_OFFSET + XCHACHA20_POLY1305_NONCE_SIZE;
pub(crate) const HEADER_SIZE: usize = AES_GCM_SIV_NONCE_OFFSET + AES_256_GCM_SIV_NONCE_SIZE;
pub(crate) const MIN_ENVELOPE_SIZE: usize = HEADER_SIZE + MIN_CASCADE_CIPHERTEXT_SIZE;

/// Maximum encrypted envelope size accepted by `Encrypted` byte conversion.
pub const MAX_ENVELOPE_SIZE: usize = HEADER_SIZE + MAX_CASCADE_CIPHERTEXT_SIZE;

pub(crate) const HKDF_INNER_KEY_INFO: &[u8] = b"paranoid/v1/hkdf-sha256/xchacha20poly1305/inner";
const BLAKE3_OUTER_KEY_CONTEXT: &str = "paranoid/v1/blake3/aes-256-gcm-siv/outer";

/// Default marker for encrypted bytes without a narrower semantic role.
pub enum OpaqueEncryptedKind {}

/// Encrypted envelope bytes with a semantic payload marker.
pub struct Encrypted<T = OpaqueEncryptedKind> {
    bytes: Vec<u8>,
    kind: PhantomData<fn() -> T>,
}

impl<T> Encrypted<T> {
    pub(crate) fn from_bytes_with_type(envelope: &[u8]) -> Result<Self, Error> {
        validate_envelope_size(envelope)?;
        ParsedEnvelope::parse(envelope)?;
        let mut copied = public_vec_with_capacity(envelope.len())?;
        copied.extend_from_slice(envelope);
        Ok(Self {
            bytes: copied,
            kind: PhantomData,
        })
    }

    fn from_vec_with_type(envelope: Vec<u8>) -> Result<Self, Error> {
        validate_envelope_size(&envelope)?;
        ParsedEnvelope::parse(&envelope)?;
        Ok(Self {
            bytes: envelope,
            kind: PhantomData,
        })
    }

    /// Returns the encrypted envelope bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the encrypted envelope bytes by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<T> TryFrom<&[u8]> for Encrypted<T> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes_with_type(value)
    }
}

impl<T> TryFrom<Vec<u8>> for Encrypted<T> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_vec_with_type(value)
    }
}

impl<T> AsRef<[u8]> for Encrypted<T> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T> Clone for Encrypted<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            kind: PhantomData,
        }
    }
}

impl<T> PartialEq for Encrypted<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T> Eq for Encrypted<T> {}

impl<T> fmt::Debug for Encrypted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypted")
            .field("envelope_len", &self.bytes.len())
            .finish()
    }
}

mod sealed {
    pub trait PlaintextSealed {}
}

/// A value that `paranoid::crypto::encrypt` can turn into protected plaintext bytes.
///
/// This trait is sealed. It is implemented for all serde-serializable values
/// that can also be deserialized, plus `SecretBytes` and `PublicBytes`.
/// Callers normally use it only through the `encrypt` and `decrypt` bounds.
pub trait Plaintext: sealed::PlaintextSealed + Sized {
    #[doc(hidden)]
    fn to_plaintext_bytes(&self) -> Result<SecretBytes, Error>;

    #[doc(hidden)]
    fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

impl<T> sealed::PlaintextSealed for T where T: Serialize + DeserializeOwned {}

impl<T> Plaintext for T
where
    T: Serialize + DeserializeOwned,
{
    fn to_plaintext_bytes(&self) -> Result<SecretBytes, Error> {
        let serialized_len =
            postcard::serialize_with_flavor(self, postcard::ser_flavors::Size::default())
                .map_err(Error::PayloadSerialize)?;
        validate_plaintext_len(serialized_len)?;
        let serialized = postcard::to_allocvec(self).map_err(Error::PayloadSerialize)?;
        debug_assert_eq!(serialized.len(), serialized_len);
        Ok(SecretBytes::from_vec(serialized))
    }

    fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, Error> {
        postcard::from_bytes(bytes).map_err(Error::PayloadDeserialize)
    }
}

impl<K> sealed::PlaintextSealed for SecretBytes<K> {}

impl<K> Plaintext for SecretBytes<K> {
    fn to_plaintext_bytes(&self) -> Result<SecretBytes, Error> {
        SecretBytes::from_slice(self.expose_secret())
    }

    fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, Error> {
        SecretBytes::from_slice(bytes)
    }
}

impl<K> sealed::PlaintextSealed for PublicBytes<K> {}

impl<K> Plaintext for PublicBytes<K> {
    fn to_plaintext_bytes(&self) -> Result<SecretBytes, Error> {
        SecretBytes::from_slice(self.as_bytes())
    }

    fn from_plaintext_bytes(bytes: &[u8]) -> Result<Self, Error> {
        PublicBytes::from_slice(bytes)
    }
}

/// Encrypts a serializable value with the latest key in `keyset`.
pub fn encrypt<T>(keyset: &Keyset, plaintext: &T, context: &[u8]) -> Result<Encrypted<T>, Error>
where
    T: Plaintext,
{
    let plaintext = plaintext.to_plaintext_bytes()?;
    encrypt_plaintext_bytes_as(keyset, plaintext.expose_secret(), context)
}

/// Decrypts encrypted bytes with the first matching key in `keyset`.
pub fn decrypt<T>(keyset: &Keyset, encrypted: &Encrypted<T>, context: &[u8]) -> Result<T, Error>
where
    T: Plaintext,
{
    let plaintext = decrypt_bytes_with_associated_data(keyset, encrypted.as_bytes(), context)?;
    T::from_plaintext_bytes(plaintext.expose_secret())
}

pub(crate) fn encrypt_plaintext_bytes_as<T>(
    keyset: &Keyset,
    plaintext: &[u8],
    context: &[u8],
) -> Result<Encrypted<T>, Error> {
    encrypt_with_key_and_associated_data(plaintext, context, keyset.latest_key())
}

pub(crate) fn decrypt_bytes_with_associated_data(
    keyset: &Keyset,
    envelope: &[u8],
    associated_data: &[u8],
) -> Result<SecretBytes, Error> {
    validate_envelope_size(envelope)?;
    let parsed = ParsedEnvelope::parse(envelope)?;
    let associated_data_for_layers = build_layer_associated_data(parsed.header, associated_data)?;

    let mut decrypted = None;
    for key in keyset.latest_first_keys() {
        match decrypt_parsed_with_key(parsed, &associated_data_for_layers, key) {
            Ok(plaintext) if decrypted.is_none() => decrypted = Some(plaintext),
            Ok(_) | Err(_) => {}
        }
    }

    decrypted.ok_or(Error::DecryptionFailed)
}

#[cfg(test)]
impl Keyset {
    pub(crate) fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Encrypted, Error> {
        self.encrypt_bytes_with_associated_data(plaintext, &[])
    }

    pub(crate) fn encrypt_bytes_as<T>(&self, plaintext: &[u8]) -> Result<Encrypted<T>, Error> {
        self.encrypt_bytes_with_associated_data_as(plaintext, &[])
    }

    pub(crate) fn encrypt_bytes_with_associated_data(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Encrypted, Error> {
        encrypt_with_key_and_associated_data(plaintext, associated_data, self.latest_key())
    }

    pub(crate) fn encrypt_bytes_with_associated_data_as<T>(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Encrypted<T>, Error> {
        encrypt_with_key_and_associated_data(plaintext, associated_data, self.latest_key())
    }

    pub(crate) fn decrypt_bytes(&self, envelope: &[u8]) -> Result<SecretBytes, Error> {
        self.decrypt_bytes_with_associated_data(envelope, &[])
    }

    pub(crate) fn decrypt_encrypted_bytes<T>(
        &self,
        encrypted: &Encrypted<T>,
    ) -> Result<SecretBytes<T>, Error> {
        self.decrypt_encrypted_bytes_with_associated_data(encrypted, &[])
    }

    pub(crate) fn decrypt_bytes_with_associated_data(
        &self,
        envelope: &[u8],
        associated_data: &[u8],
    ) -> Result<SecretBytes, Error> {
        decrypt_bytes_with_associated_data(self, envelope, associated_data)
    }

    pub(crate) fn decrypt_encrypted_bytes_with_associated_data<T>(
        &self,
        encrypted: &Encrypted<T>,
        associated_data: &[u8],
    ) -> Result<SecretBytes<T>, Error> {
        self.decrypt_bytes_with_associated_data(encrypted.as_bytes(), associated_data)
            .map(SecretBytes::with_kind)
    }
}

fn encrypt_with_key_and_associated_data<T>(
    plaintext: &[u8],
    associated_data: &[u8],
    key: &ParanoidKey,
) -> Result<Encrypted<T>, Error> {
    let padded_payload_len = padded_payload_len_for_plaintext_len(plaintext.len())?;

    let mut padded_payload: SecretBytes = SecretBytes::random(padded_payload_len)?;
    padded_payload.expose_secret_mut()[..TRUE_LENGTH_SIZE]
        .copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
    padded_payload.expose_secret_mut()[TRUE_LENGTH_SIZE..TRUE_LENGTH_SIZE + plaintext.len()]
        .copy_from_slice(plaintext);

    let hkdf_salt = random_array::<SALT_SIZE>()?;
    let blake3_salt = random_array::<SALT_SIZE>()?;
    let xchacha_nonce = random_array::<XCHACHA20_POLY1305_NONCE_SIZE>()?;
    let aes_gcm_siv_nonce = random_array::<AES_256_GCM_SIV_NONCE_SIZE>()?;
    let header = build_header(&hkdf_salt, &blake3_salt, &xchacha_nonce, &aes_gcm_siv_nonce);
    let associated_data_for_layers = build_layer_associated_data(&header, associated_data)?;

    let xchacha_key = key
        .hkdf_sha256
        .derive_hkdf_sha256(&hkdf_salt, HKDF_INNER_KEY_INFO)?;
    let aes_gcm_siv_key = derive_blake3_outer_key(&key.blake3, &blake3_salt)?;

    let inner_ciphertext = encrypt_xchacha20_poly1305(
        &xchacha_key,
        &xchacha_nonce,
        &associated_data_for_layers,
        padded_payload.expose_secret(),
    )?;
    let ciphertext = encrypt_aes_256_gcm_siv(
        &aes_gcm_siv_key,
        &aes_gcm_siv_nonce,
        &associated_data_for_layers,
        &inner_ciphertext,
    )?;

    let mut envelope = public_vec_with_capacity(header.len() + ciphertext.len())?;
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&ciphertext);
    debug_assert!(envelope.len() <= MAX_ENVELOPE_SIZE);

    Ok(Encrypted {
        bytes: envelope,
        kind: PhantomData,
    })
}

#[cfg(test)]
pub(crate) fn decrypt_with_key_and_associated_data(
    envelope: &[u8],
    associated_data: &[u8],
    key: &ParanoidKey,
) -> Result<SecretBytes, Error> {
    validate_envelope_size(envelope)?;
    let parsed = ParsedEnvelope::parse(envelope)?;
    let associated_data_for_layers = build_layer_associated_data(parsed.header, associated_data)?;

    decrypt_parsed_with_key(parsed, &associated_data_for_layers, key)
}

fn decrypt_parsed_with_key(
    parsed: ParsedEnvelope<'_>,
    associated_data_for_layers: &[u8],
    key: &ParanoidKey,
) -> Result<SecretBytes, Error> {
    let xchacha_key = key
        .hkdf_sha256
        .derive_hkdf_sha256(parsed.hkdf_salt, HKDF_INNER_KEY_INFO)?;
    let aes_gcm_siv_key = derive_blake3_outer_key(&key.blake3, parsed.blake3_salt)?;

    let inner_ciphertext = decrypt_aes_256_gcm_siv(
        &aes_gcm_siv_key,
        parsed.aes_gcm_siv_nonce,
        associated_data_for_layers,
        parsed.ciphertext,
    )?;
    let padded_payload = decrypt_xchacha20_poly1305(
        &xchacha_key,
        parsed.xchacha_nonce,
        associated_data_for_layers,
        &inner_ciphertext,
    )?;
    let padded_payload = SecretBytes::from_vec(padded_payload);
    plaintext_from_padded_payload(&padded_payload)
}

pub(crate) fn build_header(
    hkdf_salt: &[u8; SALT_SIZE],
    blake3_salt: &[u8; SALT_SIZE],
    xchacha_nonce: &[u8; XCHACHA20_POLY1305_NONCE_SIZE],
    aes_gcm_siv_nonce: &[u8; AES_256_GCM_SIV_NONCE_SIZE],
) -> [u8; HEADER_SIZE] {
    let mut header = [0_u8; HEADER_SIZE];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()] = VERSION;
    header[MAGIC.len() + 1] = SUITE_PARANOID_V1;
    header[HKDF_SALT_OFFSET..BLAKE3_SALT_OFFSET].copy_from_slice(hkdf_salt);
    header[BLAKE3_SALT_OFFSET..XCHACHA_NONCE_OFFSET].copy_from_slice(blake3_salt);
    header[XCHACHA_NONCE_OFFSET..AES_GCM_SIV_NONCE_OFFSET].copy_from_slice(xchacha_nonce);
    header[AES_GCM_SIV_NONCE_OFFSET..HEADER_SIZE].copy_from_slice(aes_gcm_siv_nonce);
    header
}

pub(crate) fn build_layer_associated_data(
    header: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    validate_associated_data_len(associated_data.len())?;
    let combined_len =
        header
            .len()
            .checked_add(associated_data.len())
            .ok_or(Error::AssociatedDataTooLarge {
                actual: associated_data.len(),
                max: MAX_ASSOCIATED_DATA_SIZE,
            })?;
    let mut combined = public_vec_with_capacity(combined_len)?;
    combined.extend_from_slice(header);
    combined.extend_from_slice(associated_data);
    Ok(combined)
}

pub(crate) fn derive_blake3_outer_key(key: &Key32, salt: &[u8; SALT_SIZE]) -> Result<Key32, Error> {
    let mut key_material: SecretBytes = SecretBytes::new_zeroed(KEY_SIZE + SALT_SIZE)?;
    let (key_bytes, salt_bytes) = key_material.expose_secret_mut().split_at_mut(KEY_SIZE);
    key_bytes.copy_from_slice(key.as_bytes());
    salt_bytes.copy_from_slice(salt);
    Ok(derive_blake3_key(
        BLAKE3_OUTER_KEY_CONTEXT,
        key_material.expose_secret(),
    ))
}

pub(crate) fn padded_payload_len_for_plaintext_len(plaintext_len: usize) -> Result<usize, Error> {
    validate_plaintext_len(plaintext_len)?;
    let internal_len =
        TRUE_LENGTH_SIZE
            .checked_add(plaintext_len)
            .ok_or(Error::PlaintextTooLarge {
                actual: plaintext_len,
                max: MAX_PLAINTEXT_SIZE,
            })?;
    Ok(internal_len
        .next_power_of_two()
        .max(MIN_PADDED_PAYLOAD_SIZE))
}

fn validate_plaintext_len(plaintext_len: usize) -> Result<(), Error> {
    if plaintext_len > MAX_PLAINTEXT_SIZE {
        return Err(Error::PlaintextTooLarge {
            actual: plaintext_len,
            max: MAX_PLAINTEXT_SIZE,
        });
    }
    Ok(())
}

fn validate_associated_data_len(associated_data_len: usize) -> Result<(), Error> {
    if associated_data_len > MAX_ASSOCIATED_DATA_SIZE {
        return Err(Error::AssociatedDataTooLarge {
            actual: associated_data_len,
            max: MAX_ASSOCIATED_DATA_SIZE,
        });
    }
    Ok(())
}

pub(crate) fn is_valid_padded_payload_len(len: usize) -> bool {
    (MIN_PADDED_PAYLOAD_SIZE..=MAX_PADDED_PAYLOAD_SIZE).contains(&len) && len.is_power_of_two()
}

fn plaintext_from_padded_payload(padded_payload: &SecretBytes) -> Result<SecretBytes, Error> {
    if !is_valid_padded_payload_len(padded_payload.len()) {
        return Err(Error::DecryptionFailed);
    }
    let mut length_bytes = [0_u8; TRUE_LENGTH_SIZE];
    length_bytes.copy_from_slice(&padded_payload.expose_secret()[..TRUE_LENGTH_SIZE]);
    let plaintext_len_u64 = u64::from_le_bytes(length_bytes);
    length_bytes.zeroize();
    let plaintext_len = usize::try_from(plaintext_len_u64).map_err(|_| Error::DecryptionFailed)?;
    if plaintext_len > MAX_PLAINTEXT_SIZE {
        return Err(Error::DecryptionFailed);
    }
    let canonical_padded_len =
        padded_payload_len_for_plaintext_len(plaintext_len).map_err(|_| Error::DecryptionFailed)?;
    if canonical_padded_len != padded_payload.len() {
        return Err(Error::DecryptionFailed);
    }

    let plaintext_start = TRUE_LENGTH_SIZE;
    let plaintext_end = plaintext_start + plaintext_len;
    SecretBytes::from_slice(&padded_payload.expose_secret()[plaintext_start..plaintext_end])
}

fn validate_envelope_size(envelope: &[u8]) -> Result<(), Error> {
    if envelope.is_empty() {
        return Err(Error::EmptyEnvelope);
    }
    if envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(Error::EnvelopeTooLarge {
            actual: envelope.len(),
            max: MAX_ENVELOPE_SIZE,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ParsedEnvelope<'a> {
    header: &'a [u8],
    hkdf_salt: &'a [u8; SALT_SIZE],
    blake3_salt: &'a [u8; SALT_SIZE],
    xchacha_nonce: &'a [u8; XCHACHA20_POLY1305_NONCE_SIZE],
    aes_gcm_siv_nonce: &'a [u8; AES_256_GCM_SIV_NONCE_SIZE],
    ciphertext: &'a [u8],
}

impl<'a> ParsedEnvelope<'a> {
    fn parse(envelope: &'a [u8]) -> Result<Self, Error> {
        if envelope.len() < MIN_ENVELOPE_SIZE {
            return Err(Error::EnvelopeTooShort {
                actual: envelope.len(),
                min: MIN_ENVELOPE_SIZE,
            });
        }
        if &envelope[..MAGIC.len()] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        let version = envelope[MAGIC.len()];
        if version != VERSION {
            return Err(Error::UnsupportedVersion { version });
        }
        let suite = envelope[MAGIC.len() + 1];
        if suite != SUITE_PARANOID_V1 {
            return Err(Error::UnsupportedSuite { suite });
        }

        let ciphertext_len = envelope.len() - HEADER_SIZE;
        if ciphertext_len < MIN_CASCADE_CIPHERTEXT_SIZE {
            return Err(Error::EnvelopeTooShort {
                actual: envelope.len(),
                min: MIN_ENVELOPE_SIZE,
            });
        }
        let padded_payload_len = ciphertext_len - CASCADE_TAG_OVERHEAD;
        if !is_valid_padded_payload_len(padded_payload_len) {
            return Err(Error::InvalidEnvelopeLength {
                actual: envelope.len(),
            });
        }

        Ok(Self {
            header: &envelope[..HEADER_SIZE],
            hkdf_salt: envelope[HKDF_SALT_OFFSET..BLAKE3_SALT_OFFSET]
                .try_into()
                .map_err(|_| Error::InvalidEnvelopeLength {
                    actual: envelope.len(),
                })?,
            blake3_salt: envelope[BLAKE3_SALT_OFFSET..XCHACHA_NONCE_OFFSET]
                .try_into()
                .map_err(|_| Error::InvalidEnvelopeLength {
                    actual: envelope.len(),
                })?,
            xchacha_nonce: envelope[XCHACHA_NONCE_OFFSET..AES_GCM_SIV_NONCE_OFFSET]
                .try_into()
                .map_err(|_| Error::InvalidEnvelopeLength {
                    actual: envelope.len(),
                })?,
            aes_gcm_siv_nonce: envelope[AES_GCM_SIV_NONCE_OFFSET..HEADER_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidEnvelopeLength {
                    actual: envelope.len(),
                })?,
            ciphertext: &envelope[HEADER_SIZE..],
        })
    }
}
