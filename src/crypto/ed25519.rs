//! Ed25519 signatures (RFC 8032) over a 32-byte seed.
//!
//! This is a raw asymmetric-signature primitive: keypair-from-seed, sign, and
//! verify, and nothing else. It exposes no raw backend types. A seed is always
//! exactly 32 bytes because it is carried as a [`Key32`], so key-pair
//! construction cannot fail on seed shape; only externally supplied public
//! keys and signatures (attacker-controlled byte lengths) are fallible to
//! parse. Verification failure and malformed-input rejection are
//! indistinguishable by design, matching this crate's other authenticated
//! primitives.
//!
//! Method-specific concerns (canonical message framing, verifier storage,
//! lookup handles, and so on) are deliberately out of scope here and belong
//! to the auth method that consumes this primitive.

use std::fmt;

use ed25519_dalek::Signer as _;

use crate::crypto::Error;
use crate::crypto::Key32;

/// Size, in bytes, of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size, in bytes, of an Ed25519 signature.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// An Ed25519 key pair derived from a 32-byte seed.
pub struct Ed25519KeyPair(ed25519_dalek::SigningKey);

impl Ed25519KeyPair {
    /// Derives an Ed25519 key pair from a 32-byte seed (RFC 8032 §5.1.5).
    ///
    /// Infallible: every 32-byte seed is a valid Ed25519 seed, and `seed`'s
    /// exact length is already guaranteed by [`Key32`].
    pub fn from_seed(seed: &Key32) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed.expose_secret()))
    }

    /// Returns this key pair's public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs `message`, producing a detached signature.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(message).to_bytes())
    }
}

/// A 32-byte Ed25519 public key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_SIZE]);

impl Ed25519PublicKey {
    /// Copies exactly 32 input bytes into an Ed25519 public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidEd25519PublicKeyLength {
                actual: bytes.len(),
            });
        }
        let mut key = [0_u8; ED25519_PUBLIC_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Returns the public key bytes.
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Verifies `signature` over `message` under this public key.
    ///
    /// A wrong key, a wrong message, and a malformed signature are all
    /// reported as the same verification failure; this primitive never
    /// distinguishes why a signature was rejected. Verification is strict
    /// (`verify_strict`): non-canonical and small-order components are
    /// rejected, closing the signature-malleability class entirely rather
    /// than only the parts plain RFC 8032 verification happens to reject.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(self.as_bytes())
            .map_err(|_| Error::Ed25519SignatureVerificationFailed)?;
        key.verify_strict(
            message,
            &ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
        )
        .map_err(|_| Error::Ed25519SignatureVerificationFailed)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PublicKey")
            .field("len", &ED25519_PUBLIC_KEY_SIZE)
            .finish()
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

/// A detached 64-byte Ed25519 signature.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ed25519Signature([u8; ED25519_SIGNATURE_SIZE]);

impl Ed25519Signature {
    /// Copies exactly 64 input bytes into an Ed25519 signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ED25519_SIGNATURE_SIZE {
            return Err(Error::InvalidEd25519SignatureLength {
                actual: bytes.len(),
            });
        }
        let mut signature = [0_u8; ED25519_SIGNATURE_SIZE];
        signature.copy_from_slice(bytes);
        Ok(Self(signature))
    }

    /// Returns the signature bytes.
    pub fn as_bytes(&self) -> &[u8; ED25519_SIGNATURE_SIZE] {
        &self.0
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signature")
            .field("len", &ED25519_SIGNATURE_SIZE)
            .finish()
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> Key32 {
        Key32::from_bytes(&[byte; 32]).expect("seed")
    }

    /// RFC 8032 §7.1 TEST 2 — pins the exact wire format (seed → public key,
    /// message → signature) to the standard's own vector, so a signing
    /// backend swap that changed bytes on the wire (breaking signatures
    /// already held by consumers) fails here instead of in production.
    /// Ed25519 signing is deterministic, so exact byte equality is the
    /// correct assertion, not just verify-accepts.
    #[test]
    fn rfc_8032_test_vector_pins_the_wire_format() {
        fn from_hex(hex: &str) -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex"))
                .collect()
        }
        let seed_bytes =
            from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_public =
            from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_signature = from_hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let message = [0x72_u8];

        let key_pair =
            Ed25519KeyPair::from_seed(&Key32::from_bytes(&seed_bytes).expect("32-byte seed"));
        assert_eq!(key_pair.public_key().as_bytes().as_slice(), expected_public);
        let signature = key_pair.sign(&message);
        assert_eq!(signature.as_bytes().as_slice(), expected_signature);
        assert!(key_pair.public_key().verify(&message, &signature).is_ok());
    }

    #[test]
    fn sign_and_verify_round_trips() {
        let key_pair = Ed25519KeyPair::from_seed(&seed(7));
        let public_key = key_pair.public_key();
        let signature = key_pair.sign(b"paranoid ed25519 message");

        assert!(
            public_key
                .verify(b"paranoid ed25519 message", &signature)
                .is_ok()
        );
    }

    #[test]
    fn same_seed_derives_the_same_public_key() {
        let first = Ed25519KeyPair::from_seed(&seed(9));
        let second = Ed25519KeyPair::from_seed(&seed(9));
        assert_eq!(first.public_key(), second.public_key());
    }

    #[test]
    fn different_seeds_derive_different_public_keys() {
        let first = Ed25519KeyPair::from_seed(&seed(1));
        let second = Ed25519KeyPair::from_seed(&seed(2));
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key_pair = Ed25519KeyPair::from_seed(&seed(11));
        let other_key_pair = Ed25519KeyPair::from_seed(&seed(12));
        let signature = key_pair.sign(b"message");

        assert!(matches!(
            other_key_pair.public_key().verify(b"message", &signature),
            Err(Error::Ed25519SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let key_pair = Ed25519KeyPair::from_seed(&seed(13));
        let public_key = key_pair.public_key();
        let signature = key_pair.sign(b"original message");

        assert!(matches!(
            public_key.verify(b"tampered message", &signature),
            Err(Error::Ed25519SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let key_pair = Ed25519KeyPair::from_seed(&seed(14));
        let public_key = key_pair.public_key();
        let mut signature = key_pair.sign(b"message");
        signature.0[0] ^= 0x01;

        assert!(matches!(
            public_key.verify(b"message", &signature),
            Err(Error::Ed25519SignatureVerificationFailed)
        ));
    }

    #[test]
    fn public_key_rejects_malformed_length() {
        assert!(matches!(
            Ed25519PublicKey::from_bytes(&[0_u8; ED25519_PUBLIC_KEY_SIZE - 1]),
            Err(Error::InvalidEd25519PublicKeyLength { actual }) if actual == ED25519_PUBLIC_KEY_SIZE - 1
        ));
        assert!(matches!(
            Ed25519PublicKey::from_bytes(&[0_u8; ED25519_PUBLIC_KEY_SIZE + 1]),
            Err(Error::InvalidEd25519PublicKeyLength { actual }) if actual == ED25519_PUBLIC_KEY_SIZE + 1
        ));
    }

    #[test]
    fn signature_rejects_malformed_length() {
        assert!(matches!(
            Ed25519Signature::from_bytes(&[0_u8; ED25519_SIGNATURE_SIZE - 1]),
            Err(Error::InvalidEd25519SignatureLength { actual }) if actual == ED25519_SIGNATURE_SIZE - 1
        ));
        assert!(matches!(
            Ed25519Signature::from_bytes(&[0_u8; ED25519_SIGNATURE_SIZE + 1]),
            Err(Error::InvalidEd25519SignatureLength { actual }) if actual == ED25519_SIGNATURE_SIZE + 1
        ));
    }

    #[test]
    fn public_key_and_signature_debug_do_not_leak_bytes() {
        let key_pair = Ed25519KeyPair::from_seed(&seed(15));
        let public_key = key_pair.public_key();
        let signature = key_pair.sign(b"message");

        let public_key_debug = format!("{public_key:?}");
        let signature_debug = format!("{signature:?}");
        assert!(public_key_debug.contains("len"));
        assert!(signature_debug.contains("len"));
    }
}
