//! Cryptographic primitives and edge codecs.

pub(crate) mod bip39_english_words;
pub(crate) mod bytes;
pub(crate) mod codecs;
pub(crate) mod envelope;
pub(crate) mod error;
pub(crate) mod keyset;
pub(crate) mod token;

use std::error::Error as StdError;
use std::fmt;
use std::marker::PhantomData;

use aes_gcm_siv::{Aes256GcmSiv, Nonce as AesGcmSivNonce};
use argon2::{Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ring::{hkdf, hmac};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub use bytes::{
    MAX_BYTE_CONTAINER_SIZE, MAX_RANDOM_BYTES_SIZE, PublicBytes, PublicBytesKind, random_key32,
    random_public_bytes, random_secret_bytes,
};
pub use codecs::{Base58, Base64Url, CrockfordBase32, EdgeByteContainer, Mnemonic};
pub use envelope::{
    Encrypted, MAX_ASSOCIATED_DATA_SIZE, MAX_ENVELOPE_SIZE, MAX_PLAINTEXT_SIZE,
    OpaqueEncryptedKind, Plaintext, decrypt, encrypt,
};
pub use error::{Error, RandomError};
pub use keyset::{Keyset, MAX_KEYSET_KEYS, derive_keyset_from_latest_first_keys};
pub use token::{MAC_OVER_SECRET_SIZE, MacOverSecret};

use bytes::validate_byte_container_len;

#[cfg(test)]
use sha2::{Digest, Sha256};

/// Size, in bytes, of a `Key32`.
pub const KEY32_SIZE: usize = 32;

pub(crate) const KEY_SIZE: usize = KEY32_SIZE;

/// Size, in bytes, of a password KDF salt.
pub const PASSWORD_KDF_SALT_SIZE: usize = 32;

/// Default Argon2id memory cost for interactive local password-derived keys.
pub const PASSWORD_KDF_DEFAULT_MEMORY_COST_KIB: u32 = 64 * 1024;

/// Default Argon2id iteration count for interactive local password-derived keys.
pub const PASSWORD_KDF_DEFAULT_ITERATIONS: u32 = 3;

/// Default Argon2id parallelism for interactive local password-derived keys.
pub const PASSWORD_KDF_DEFAULT_PARALLELISM: u32 = 1;

/// Minimum accepted Argon2id memory cost for public password KDF parameters.
pub const PASSWORD_KDF_MIN_MEMORY_COST_KIB: u32 = 19 * 1024;

/// Minimum accepted Argon2id iteration count for public password KDF parameters.
pub const PASSWORD_KDF_MIN_ITERATIONS: u32 = 2;

/// Maximum accepted Argon2id parallelism for public password KDF parameters.
pub const PASSWORD_KDF_MAX_PARALLELISM: u32 = 16;

/// Size, in bytes, of the digest outputs tested by this crate.
#[cfg(test)]
pub(crate) const HASH_SIZE: usize = 32;

/// Size, in bytes, of an XChaCha20-Poly1305 nonce.
pub(crate) const XCHACHA20_POLY1305_NONCE_SIZE: usize = 24;

/// Size, in bytes, of an XChaCha20-Poly1305 authentication tag.
pub(crate) const XCHACHA20_POLY1305_TAG_SIZE: usize = 16;

/// Size, in bytes, of an AES-256-GCM-SIV nonce.
pub(crate) const AES_256_GCM_SIV_NONCE_SIZE: usize = 12;

/// Size, in bytes, of an AES-256-GCM-SIV authentication tag.
pub(crate) const AES_256_GCM_SIV_TAG_SIZE: usize = 16;

/// A 32-byte secret key.
pub struct Key32(SecretBox<[u8; KEY_SIZE]>);

impl Key32 {
    /// Copies exactly 32 input bytes into a key.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0_u8; KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        let key = Self::from_array(key_bytes);
        key_bytes.zeroize();
        Ok(key)
    }

    /// Explicitly exposes this key as secret bytes.
    pub fn expose_secret(&self) -> &[u8; KEY_SIZE] {
        self.0.expose_secret()
    }

    /// Returns this key as raw bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        self.0.expose_secret()
    }

    /// Derives a 32-byte key using HKDF-SHA256.
    pub(crate) fn derive_hkdf_sha256(&self, salt: &[u8], info: &[u8]) -> Result<Self, CryptoError> {
        derive_hkdf_sha256(self, salt, info)
    }

    fn from_array(mut bytes: [u8; KEY_SIZE]) -> Self {
        let key = Self(SecretBox::new(Box::new(bytes)));
        bytes.zeroize();
        key
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl Eq for Key32 {}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32([redacted; 32])")
    }
}

impl TryFrom<&[u8]> for Key32 {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value).map_err(Error::from)
    }
}

impl TryFrom<Vec<u8>> for Key32 {
    type Error = Error;

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        let key = Self::try_from(value.as_slice());
        value.zeroize();
        key
    }
}

/// Public salt used for Argon2id password-derived keys.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PasswordKdfSalt([u8; PASSWORD_KDF_SALT_SIZE]);

impl PasswordKdfSalt {
    /// Generates a fresh random password KDF salt.
    pub fn generate() -> Result<Self, Error> {
        random_array::<PASSWORD_KDF_SALT_SIZE>()
            .map(Self)
            .map_err(Error::from)
    }

    /// Copies exactly 32 input bytes into a password KDF salt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PASSWORD_KDF_SALT_SIZE {
            return Err(Error::InvalidPasswordKdfSaltLength {
                actual: bytes.len(),
            });
        }

        let mut salt = [0_u8; PASSWORD_KDF_SALT_SIZE];
        salt.copy_from_slice(bytes);
        Ok(Self(salt))
    }

    /// Returns the salt bytes.
    pub fn as_bytes(&self) -> &[u8; PASSWORD_KDF_SALT_SIZE] {
        &self.0
    }
}

impl fmt::Debug for PasswordKdfSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordKdfSalt")
            .field("len", &PASSWORD_KDF_SALT_SIZE)
            .finish()
    }
}

impl TryFrom<&[u8]> for PasswordKdfSalt {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

/// Public Argon2id parameters for password-derived keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordKdfParams {
    memory_cost_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl PasswordKdfParams {
    /// Returns Paranoid's default interactive Argon2id parameters.
    pub const fn interactive_default() -> Self {
        Self {
            memory_cost_kib: PASSWORD_KDF_DEFAULT_MEMORY_COST_KIB,
            iterations: PASSWORD_KDF_DEFAULT_ITERATIONS,
            parallelism: PASSWORD_KDF_DEFAULT_PARALLELISM,
        }
    }

    /// Validates and constructs public Argon2id parameters.
    pub fn new(memory_cost_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, Error> {
        if memory_cost_kib < PASSWORD_KDF_MIN_MEMORY_COST_KIB {
            return Err(Error::PasswordKdfMemoryCostTooSmall {
                actual: memory_cost_kib,
                min: PASSWORD_KDF_MIN_MEMORY_COST_KIB,
            });
        }
        if iterations < PASSWORD_KDF_MIN_ITERATIONS {
            return Err(Error::PasswordKdfIterationsTooFew {
                actual: iterations,
                min: PASSWORD_KDF_MIN_ITERATIONS,
            });
        }
        if parallelism == 0 || parallelism > PASSWORD_KDF_MAX_PARALLELISM {
            return Err(Error::PasswordKdfParallelismInvalid {
                actual: parallelism,
                min: 1,
                max: PASSWORD_KDF_MAX_PARALLELISM,
            });
        }

        let params = Self {
            memory_cost_kib,
            iterations,
            parallelism,
        };
        params.to_argon2_params()?;
        Ok(params)
    }

    /// Returns the Argon2id memory cost in KiB.
    pub const fn memory_cost_kib(&self) -> u32 {
        self.memory_cost_kib
    }

    /// Returns the Argon2id iteration count.
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Returns the Argon2id parallelism.
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    fn to_argon2_params(self) -> Result<Argon2Params, Error> {
        Argon2Params::new(
            self.memory_cost_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_SIZE),
        )
        .map_err(|_| Error::InvalidPasswordKdfParams)
    }

    #[cfg(test)]
    pub(crate) fn new_for_tests(memory_cost_kib: u32, iterations: u32, parallelism: u32) -> Self {
        let params = Self {
            memory_cost_kib,
            iterations,
            parallelism,
        };
        params
            .to_argon2_params()
            .expect("test password KDF params must be accepted by argon2");
        params
    }
}

impl Default for PasswordKdfParams {
    fn default() -> Self {
        Self::interactive_default()
    }
}

/// Derives a 32-byte key from a password using Argon2id.
pub fn derive_argon2id_key32_from_password<K>(
    password: &SecretBytes<K>,
    salt: &PasswordKdfSalt,
    params: PasswordKdfParams,
) -> Result<Key32, Error> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Argon2Version::V0x13,
        params.to_argon2_params()?,
    );
    let mut output = [0_u8; KEY_SIZE];
    let result = argon2.hash_password_into(password.expose_secret(), salt.as_bytes(), &mut output);
    if result.is_err() {
        output.zeroize();
        return Err(Error::KeyDerivationFailed);
    }

    let key = Key32::from_array(output);
    output.zeroize();
    Ok(key)
}

/// A 32-byte public hash output.
#[cfg(test)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct Hash32([u8; HASH_SIZE]);

#[cfg(test)]
impl Hash32 {
    /// Returns this hash as raw bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }
}

#[cfg(test)]
impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash32").field(&self.0).finish()
    }
}

/// Default marker for unclassified secret bytes.
pub enum SecretBytesKind {}

/// An owned byte buffer that zeroizes its contents on drop.
pub struct SecretBytes<K = SecretBytesKind> {
    secret: SecretBox<Vec<u8>>,
    kind: PhantomData<fn() -> K>,
}

impl<K> SecretBytes<K> {
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        validate_byte_container_len(bytes.len())?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::AllocationFailed)?;
        buffer.extend_from_slice(bytes);
        Ok(Self::from_vec(buffer))
    }

    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            secret: SecretBox::new(Box::new(bytes)),
            kind: PhantomData,
        }
    }

    pub(crate) fn new_zeroed(len: usize) -> Result<Self, Error> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|_| Error::AllocationFailed)?;
        buffer.resize(len, 0);
        Ok(Self::from_vec(buffer))
    }

    pub(crate) fn random(len: usize) -> Result<Self, Error> {
        let mut bytes = Self::new_zeroed(len)?;
        fill_random(bytes.expose_secret_mut()).map_err(Error::from)?;
        Ok(bytes)
    }

    /// Returns the buffer length.
    pub fn len(&self) -> usize {
        self.secret.expose_secret().len()
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.secret.expose_secret().is_empty()
    }

    /// Explicitly exposes the secret bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.secret.expose_secret().as_slice()
    }

    /// Explicitly exposes the mutable secret bytes.
    pub fn expose_secret_mut(&mut self) -> &mut [u8] {
        self.secret.expose_secret_mut().as_mut_slice()
    }

    #[cfg(test)]
    pub(crate) fn with_kind<T>(self) -> SecretBytes<T> {
        let Self { secret, kind: _ } = self;
        SecretBytes {
            secret,
            kind: PhantomData,
        }
    }
}

impl<K> TryFrom<&[u8]> for SecretBytes<K> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl<K> TryFrom<Vec<u8>> for SecretBytes<K> {
    type Error = Error;

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        if let Err(error) = validate_byte_container_len(value.len()) {
            value.zeroize();
            return Err(error);
        }
        Ok(Self::from_vec(value))
    }
}

impl<K> fmt::Debug for SecretBytes<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.len())
            .finish()
    }
}

/// Fills `bytes` with cryptographically secure random data.
pub(crate) fn fill_random(bytes: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(bytes).map_err(CryptoError::Random)
}

/// Returns a fixed-size array of cryptographically secure random data.
pub(crate) fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Hashes ordered byte slices with SHA-256.
#[cfg(test)]
pub(crate) fn sha256_hash_parts(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut bytes = [0_u8; HASH_SIZE];
    bytes.copy_from_slice(&digest);
    Hash32(bytes)
}

/// Hashes ordered byte slices with BLAKE3.
#[cfg(test)]
pub(crate) fn blake3_hash_parts(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    Hash32(*hasher.finalize().as_bytes())
}

/// Derives a 32-byte key using HKDF-SHA256.
pub(crate) fn derive_hkdf_sha256(
    secret_key: &Key32,
    salt: &[u8],
    info: &[u8],
) -> Result<Key32, CryptoError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let pseudo_random_key = salt.extract(secret_key.as_bytes());
    let info_parts = [info];
    let output_key_material = pseudo_random_key
        .expand(&info_parts, hkdf::HKDF_SHA256)
        .map_err(|_| CryptoError::HkdfExpand)?;

    let mut derived = [0_u8; KEY_SIZE];
    output_key_material
        .fill(&mut derived)
        .map_err(|_| CryptoError::HkdfExpand)?;
    let key = Key32::from_array(derived);
    derived.zeroize();
    Ok(key)
}

/// Derives a 32-byte key using BLAKE3 derive-key mode.
///
/// `context` should be a hard-coded, globally unique domain-separation string.
/// Do not pass user-controlled context strings.
pub(crate) fn derive_blake3_key(context: &'static str, key_material: &[u8]) -> Key32 {
    let mut derived = blake3::derive_key(context, key_material);
    let key = Key32::from_array(derived);
    derived.zeroize();
    key
}

/// Computes HMAC-SHA256 over ordered byte slices.
pub(crate) fn hmac_sha256_parts(key: &Key32, parts: &[&[u8]]) -> [u8; KEY_SIZE] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
    let mut context = hmac::Context::with_key(&key);
    for part in parts {
        context.update(part);
    }
    let tag = context.sign();
    let mut output = [0_u8; KEY_SIZE];
    output.copy_from_slice(tag.as_ref());
    output
}

/// Computes keyed BLAKE3 over ordered byte slices.
pub(crate) fn blake3_keyed_hash_parts(key: &Key32, parts: &[&[u8]]) -> [u8; KEY_SIZE] {
    let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Compares two 32-byte values in constant time.
#[cfg(test)]
pub(crate) fn constant_time_eq_32(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> bool {
    left.ct_eq(right).into()
}

/// Encrypts bytes with XChaCha20-Poly1305.
pub(crate) fn encrypt_xchacha20_poly1305(
    key: &Key32,
    nonce: &[u8; XCHACHA20_POLY1305_NONCE_SIZE],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts bytes with XChaCha20-Poly1305.
pub(crate) fn decrypt_xchacha20_poly1305(
    key: &Key32,
    nonce: &[u8; XCHACHA20_POLY1305_NONCE_SIZE],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypts bytes with AES-256-GCM-SIV.
pub(crate) fn encrypt_aes_256_gcm_siv(
    key: &Key32,
    nonce: &[u8; AES_256_GCM_SIV_NONCE_SIZE],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256GcmSiv::new(key.as_bytes().into());
    let nonce = AesGcmSivNonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts bytes with AES-256-GCM-SIV.
pub(crate) fn decrypt_aes_256_gcm_siv(
    key: &Key32,
    nonce: &[u8; AES_256_GCM_SIV_NONCE_SIZE],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256GcmSiv::new(key.as_bytes().into());
    let nonce = AesGcmSivNonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Errors returned by crypto primitives.
#[derive(Debug)]
pub(crate) enum CryptoError {
    /// A key was not exactly 32 bytes long.
    InvalidKeyLength { actual: usize },
    /// Secure random byte generation failed.
    Random(getrandom::Error),
    /// HKDF expansion failed.
    HkdfExpand,
    /// Encryption failed.
    EncryptionFailed,
    /// Decryption failed.
    DecryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { actual } => {
                write!(f, "crypto: key length {actual}, want {KEY_SIZE}")
            }
            Self::Random(err) => write!(f, "crypto: random bytes: {err}"),
            Self::HkdfExpand => write!(f, "crypto: HKDF-SHA256 expansion failed"),
            Self::EncryptionFailed => write!(f, "crypto: encryption failed"),
            Self::DecryptionFailed => write!(f, "crypto: decryption failed"),
        }
    }
}

impl StdError for CryptoError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}

#[cfg(test)]
mod conformance_tests;
#[cfg(test)]
mod tests;
