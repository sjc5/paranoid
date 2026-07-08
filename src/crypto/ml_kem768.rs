//! ML-KEM-768 key encapsulation (FIPS 203) over a 64-byte seed.
//!
//! This is a raw asymmetric-encapsulation primitive: seed-derived keypair,
//! encapsulate, and decapsulate, and nothing else. It exposes no raw
//! `ml-kem` types. Paranoid has no other public-key encryption/KEM
//! primitive of any kind; this one is post-quantum (Module-Lattice-based,
//! standardized by NIST), so it is safe to adopt today against a
//! harvest-now-decrypt-later adversary who records ciphertext now and
//! decrypts it once a cryptographically relevant quantum computer exists —
//! a risk a classical KEM (X25519, RSA, and so on) cannot address no matter
//! how large its keys are.
//!
//! This primitive establishes a shared [`Key32`] between an encapsulator
//! (who holds only the recipient's public [`MlKem768EncapsulationKey`]) and
//! the recipient (who holds the matching [`MlKem768DecapsulationKey`]).
//! What either side does with that shared key — seal a payload under it,
//! fold it into a larger keyset, combine it with a classical KEM for
//! hybrid defense-in-depth, wrap it to more than one recipient, and so on —
//! is deliberately out of scope here and belongs to a higher-level
//! construction that consumes this primitive.
//!
//! # Decapsulation never fails
//!
//! FIPS 203's decapsulation algorithm uses *implicit rejection*: a
//! ciphertext that was never actually produced by [`MlKem768EncapsulationKey::encapsulate`]
//! for a given decapsulation key still decapsulates to a value, computed
//! deterministically from the decapsulation key and the (invalid)
//! ciphertext. That output is indistinguishable from a genuine shared
//! secret to anyone without the decapsulation key, and it exists
//! specifically so an attacker who submits crafted ciphertexts cannot learn
//! anything from an error response (a chosen-ciphertext oracle). Concretely:
//! [`MlKem768DecapsulationKey::decapsulate`] returning a [`Key32`] is never,
//! on its own, proof the ciphertext was genuine or that the two parties now
//! share a secret. Callers must authenticate over the shared secret (fold
//! it into a MAC or AEAD binding, or bind it to a subsequent authenticated
//! step) rather than treating a successful call to `decapsulate` as an
//! authentication event by itself.

use std::fmt;

use ml_kem::{Decapsulate, KeyExport};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::crypto::Error;
use crate::crypto::{Key32, fill_random};

type RingDecapsulationKey = ml_kem::ml_kem_768::DecapsulationKey;
type RingEncapsulationKey = ml_kem::ml_kem_768::EncapsulationKey;
type RingCiphertext = ml_kem::ml_kem_768::Ciphertext;

/// Size, in bytes, of an ML-KEM-768 seed.
pub const ML_KEM_768_SEED_SIZE: usize = 64;

/// Size, in bytes, of an ML-KEM-768 encapsulation (public) key.
pub const ML_KEM_768_ENCAPSULATION_KEY_SIZE: usize = 1184;

/// Size, in bytes, of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;

/// A 64-byte seed an ML-KEM-768 decapsulation key is deterministically
/// derived from.
///
/// Every 64-byte string is a valid seed: unlike an encapsulation key or a
/// ciphertext, a seed carries no internal structure that can be malformed,
/// only a length that this type enforces at construction.
pub struct MlKem768Seed(SecretBox<[u8; ML_KEM_768_SEED_SIZE]>);

impl MlKem768Seed {
    /// Copies exactly 64 input bytes into a seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ML_KEM_768_SEED_SIZE {
            return Err(Error::InvalidMlKem768SeedLength {
                actual: bytes.len(),
            });
        }
        let mut seed_bytes = [0_u8; ML_KEM_768_SEED_SIZE];
        seed_bytes.copy_from_slice(bytes);
        let seed = Self(SecretBox::new(Box::new(seed_bytes)));
        seed_bytes.zeroize();
        Ok(seed)
    }

    /// Generates a fresh random seed.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0_u8; ML_KEM_768_SEED_SIZE];
        fill_random(&mut bytes).map_err(Error::from)?;
        let seed = Self::from_bytes(&bytes);
        bytes.zeroize();
        seed
    }

    fn expose_secret(&self) -> &[u8; ML_KEM_768_SEED_SIZE] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for MlKem768Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768Seed")
            .field("len", &ML_KEM_768_SEED_SIZE)
            .finish()
    }
}

impl TryFrom<&[u8]> for MlKem768Seed {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

/// An ML-KEM-768 decapsulation (private) key, deterministically derived
/// from a [`MlKem768Seed`].
pub struct MlKem768DecapsulationKey(RingDecapsulationKey);

impl MlKem768DecapsulationKey {
    /// Derives an ML-KEM-768 decapsulation key from a 64-byte seed.
    ///
    /// Infallible: every 64-byte seed is a valid ML-KEM-768 seed, and
    /// `seed`'s exact length is already guaranteed by [`MlKem768Seed`].
    pub fn from_seed(seed: &MlKem768Seed) -> Self {
        let seed_array = ml_kem::Seed::try_from(seed.expose_secret().as_slice())
            .expect("MlKem768Seed is always exactly 64 bytes");
        Self(RingDecapsulationKey::from_seed(seed_array))
    }

    /// Returns this key's encapsulation (public) key.
    pub fn encapsulation_key(&self) -> MlKem768EncapsulationKey {
        MlKem768EncapsulationKey(self.0.encapsulation_key().clone())
    }

    /// Decapsulates `ciphertext`, deriving the shared secret it encodes.
    ///
    /// Never fails: FIPS 203 implicit rejection means an invalid or
    /// tampered ciphertext still decapsulates to a deterministic
    /// pseudorandom [`Key32`] rather than an error. See the module
    /// documentation for why that is a deliberate anti-oracle property, not
    /// a missed validation check, and what it means for callers.
    pub fn decapsulate(&self, ciphertext: &MlKem768Ciphertext) -> Key32 {
        let shared = self.0.decapsulate(&ciphertext.0);
        Key32::from_bytes(shared.as_slice())
            .expect("ML-KEM-768 shared secret is always exactly 32 bytes")
    }
}

impl fmt::Debug for MlKem768DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768DecapsulationKey").finish()
    }
}

/// An ML-KEM-768 encapsulation (public) key.
#[derive(Clone)]
pub struct MlKem768EncapsulationKey(RingEncapsulationKey);

impl MlKem768EncapsulationKey {
    /// Parses an ML-KEM-768 encapsulation key from its FIPS 203 encoding.
    ///
    /// Unlike a seed, an encapsulation key's bytes carry algebraic
    /// structure (a set of ring elements) that FIPS 203 requires be
    /// validated on decode; a well-formed-length byte string can still be
    /// rejected here if it fails that structural check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ML_KEM_768_ENCAPSULATION_KEY_SIZE {
            return Err(Error::InvalidMlKem768EncapsulationKeyLength {
                actual: bytes.len(),
            });
        }
        let key_array = ml_kem::Key::<RingEncapsulationKey>::try_from(bytes)
            .expect("length already validated above");
        RingEncapsulationKey::new(&key_array)
            .map(Self)
            .map_err(|_| Error::InvalidMlKem768EncapsulationKeyEncoding)
    }

    /// Returns the encapsulation key's FIPS 203 encoding.
    pub fn as_bytes(&self) -> [u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE] {
        self.0.to_bytes().into()
    }

    /// Encapsulates a fresh, random shared secret to this key's holder.
    ///
    /// Returns the ciphertext to send to the holder of the matching
    /// decapsulation key, and the [`Key32`] shared secret it encodes.
    pub fn encapsulate(&self) -> Result<(MlKem768Ciphertext, Key32), Error> {
        let mut randomness = [0_u8; 32];
        fill_random(&mut randomness).map_err(Error::from)?;
        let m = ml_kem::B32::try_from(randomness.as_slice())
            .expect("randomness buffer is always exactly 32 bytes");
        let (ciphertext, shared) = self.0.encapsulate_deterministic(&m);
        randomness.zeroize();

        let shared_key = Key32::from_bytes(shared.as_slice())
            .expect("ML-KEM-768 shared secret is always exactly 32 bytes");
        Ok((MlKem768Ciphertext(ciphertext), shared_key))
    }
}

impl fmt::Debug for MlKem768EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768EncapsulationKey")
            .field("len", &ML_KEM_768_ENCAPSULATION_KEY_SIZE)
            .finish()
    }
}

impl PartialEq for MlKem768EncapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for MlKem768EncapsulationKey {}

impl TryFrom<&[u8]> for MlKem768EncapsulationKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

/// An ML-KEM-768 ciphertext (an encapsulated shared secret).
#[derive(Clone)]
pub struct MlKem768Ciphertext(RingCiphertext);

impl MlKem768Ciphertext {
    /// Copies exactly [`ML_KEM_768_CIPHERTEXT_SIZE`] input bytes into a
    /// ciphertext.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ML_KEM_768_CIPHERTEXT_SIZE {
            return Err(Error::InvalidMlKem768CiphertextLength {
                actual: bytes.len(),
            });
        }
        let array = RingCiphertext::try_from(bytes).expect("length already validated above");
        Ok(Self(array))
    }

    /// Returns the ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for MlKem768Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768Ciphertext")
            .field("len", &ML_KEM_768_CIPHERTEXT_SIZE)
            .finish()
    }
}

impl PartialEq for MlKem768Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for MlKem768Ciphertext {}

impl TryFrom<&[u8]> for MlKem768Ciphertext {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::KeySizeUser;

    use super::*;

    fn seed(byte: u8) -> MlKem768Seed {
        MlKem768Seed::from_bytes(&[byte; ML_KEM_768_SEED_SIZE]).expect("seed")
    }

    #[test]
    fn declared_sizes_match_the_underlying_fips_203_parameter_set() {
        assert_eq!(
            ML_KEM_768_ENCAPSULATION_KEY_SIZE,
            RingEncapsulationKey::key_size()
        );
        assert_eq!(ML_KEM_768_CIPHERTEXT_SIZE, RingCiphertext::default().len());
    }

    #[test]
    fn encapsulate_and_decapsulate_round_trip_to_the_same_shared_secret() {
        let decapsulation_key = MlKem768DecapsulationKey::from_seed(&seed(1));
        let encapsulation_key = decapsulation_key.encapsulation_key();

        let (ciphertext, sender_shared_secret) =
            encapsulation_key.encapsulate().expect("encapsulate");
        let receiver_shared_secret = decapsulation_key.decapsulate(&ciphertext);

        assert_eq!(sender_shared_secret, receiver_shared_secret);
    }

    #[test]
    fn same_seed_derives_the_same_encapsulation_key() {
        let first = MlKem768DecapsulationKey::from_seed(&seed(7));
        let second = MlKem768DecapsulationKey::from_seed(&seed(7));
        assert_eq!(first.encapsulation_key(), second.encapsulation_key());
    }

    #[test]
    fn different_seeds_derive_different_encapsulation_keys() {
        let first = MlKem768DecapsulationKey::from_seed(&seed(1));
        let second = MlKem768DecapsulationKey::from_seed(&seed(2));
        assert_ne!(first.encapsulation_key(), second.encapsulation_key());
    }

    #[test]
    fn each_encapsulation_call_produces_a_fresh_ciphertext_and_shared_secret() {
        let decapsulation_key = MlKem768DecapsulationKey::from_seed(&seed(3));
        let encapsulation_key = decapsulation_key.encapsulation_key();

        let (first_ciphertext, first_secret) =
            encapsulation_key.encapsulate().expect("encapsulate");
        let (second_ciphertext, second_secret) =
            encapsulation_key.encapsulate().expect("encapsulate");

        assert_ne!(first_ciphertext.as_bytes(), second_ciphertext.as_bytes());
        assert_ne!(first_secret, second_secret);
    }

    #[test]
    fn decapsulating_under_the_wrong_key_never_fails_and_never_matches() {
        let decapsulation_key = MlKem768DecapsulationKey::from_seed(&seed(4));
        let other_decapsulation_key = MlKem768DecapsulationKey::from_seed(&seed(5));
        let encapsulation_key = decapsulation_key.encapsulation_key();

        let (ciphertext, sender_shared_secret) =
            encapsulation_key.encapsulate().expect("encapsulate");
        let wrong_holder_secret = other_decapsulation_key.decapsulate(&ciphertext);

        assert_ne!(sender_shared_secret, wrong_holder_secret);
    }

    #[test]
    fn decapsulating_a_tampered_ciphertext_never_fails_and_never_matches() {
        let decapsulation_key = MlKem768DecapsulationKey::from_seed(&seed(6));
        let encapsulation_key = decapsulation_key.encapsulation_key();

        let (ciphertext, sender_shared_secret) =
            encapsulation_key.encapsulate().expect("encapsulate");
        let mut tampered_bytes = ciphertext.as_bytes().to_vec();
        tampered_bytes[0] ^= 0x01;
        let tampered_ciphertext =
            MlKem768Ciphertext::from_bytes(&tampered_bytes).expect("well-formed length");

        let recovered_secret = decapsulation_key.decapsulate(&tampered_ciphertext);

        assert_ne!(sender_shared_secret, recovered_secret);
    }

    #[test]
    fn round_trips_an_encapsulation_key_through_its_byte_encoding() {
        let decapsulation_key = MlKem768DecapsulationKey::from_seed(&seed(8));
        let encapsulation_key = decapsulation_key.encapsulation_key();

        let encoded = encapsulation_key.as_bytes();
        let decoded = MlKem768EncapsulationKey::from_bytes(&encoded).expect("decode");

        assert_eq!(encapsulation_key, decoded);
    }

    #[test]
    fn seed_rejects_malformed_length() {
        assert!(matches!(
            MlKem768Seed::from_bytes(&[0_u8; ML_KEM_768_SEED_SIZE - 1]),
            Err(Error::InvalidMlKem768SeedLength { actual }) if actual == ML_KEM_768_SEED_SIZE - 1
        ));
        assert!(matches!(
            MlKem768Seed::from_bytes(&[0_u8; ML_KEM_768_SEED_SIZE + 1]),
            Err(Error::InvalidMlKem768SeedLength { actual }) if actual == ML_KEM_768_SEED_SIZE + 1
        ));
    }

    #[test]
    fn encapsulation_key_rejects_malformed_length() {
        assert!(matches!(
            MlKem768EncapsulationKey::from_bytes(&[0_u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE - 1]),
            Err(Error::InvalidMlKem768EncapsulationKeyLength { actual })
                if actual == ML_KEM_768_ENCAPSULATION_KEY_SIZE - 1
        ));
        assert!(matches!(
            MlKem768EncapsulationKey::from_bytes(&[0_u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE + 1]),
            Err(Error::InvalidMlKem768EncapsulationKeyLength { actual })
                if actual == ML_KEM_768_ENCAPSULATION_KEY_SIZE + 1
        ));
    }

    #[test]
    fn encapsulation_key_rejects_well_formed_length_garbage() {
        let garbage = [0xFF_u8; ML_KEM_768_ENCAPSULATION_KEY_SIZE];
        assert!(matches!(
            MlKem768EncapsulationKey::from_bytes(&garbage),
            Err(Error::InvalidMlKem768EncapsulationKeyEncoding)
        ));
    }

    #[test]
    fn ciphertext_rejects_malformed_length() {
        assert!(matches!(
            MlKem768Ciphertext::from_bytes(&[0_u8; ML_KEM_768_CIPHERTEXT_SIZE - 1]),
            Err(Error::InvalidMlKem768CiphertextLength { actual })
                if actual == ML_KEM_768_CIPHERTEXT_SIZE - 1
        ));
        assert!(matches!(
            MlKem768Ciphertext::from_bytes(&[0_u8; ML_KEM_768_CIPHERTEXT_SIZE + 1]),
            Err(Error::InvalidMlKem768CiphertextLength { actual })
                if actual == ML_KEM_768_CIPHERTEXT_SIZE + 1
        ));
    }
}
