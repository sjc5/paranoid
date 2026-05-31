use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::Error;
use crate::crypto::bytes::PublicBytes;
use crate::crypto::keyset::{Keyset, ParanoidKey};
use crate::crypto::{KEY32_SIZE, SecretBytes, blake3_keyed_hash_parts, hmac_sha256_parts};

pub(crate) const MAC_OVER_SECRET_VERSION: u8 = 1;
const MAC_OVER_SECRET_BODY_SIZE: usize = KEY32_SIZE;
const MAC_OVER_SECRET_HMAC_LABEL: &[u8] = b"paranoid/v1/mac-over-secret/hmac-sha256";
const MAC_OVER_SECRET_BLAKE3_LABEL: &[u8] = b"paranoid/v1/mac-over-secret/blake3";

/// Size, in bytes, of a `MacOverSecret`.
pub const MAC_OVER_SECRET_SIZE: usize = 1 + MAC_OVER_SECRET_BODY_SIZE;

enum MacOverSecretKind {}

/// A public MAC computed over secret bytes.
pub struct MacOverSecret(PublicBytes<MacOverSecretKind>);

impl MacOverSecret {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        validate_mac_over_secret_bytes(bytes)?;
        Ok(Self(PublicBytes::from_slice(bytes)?))
    }

    fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        validate_mac_over_secret_bytes(&bytes)?;
        Ok(Self(PublicBytes::from_vec(bytes)?))
    }

    pub(crate) fn from_mac_array(bytes: [u8; MAC_OVER_SECRET_SIZE]) -> Result<Self, Error> {
        Ok(Self(PublicBytes::from_slice(&bytes)?))
    }

    /// Returns the public MAC bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the public MAC bytes by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    /// Verifies secret bytes against this MAC.
    pub fn verify(&self, keyset: &Keyset, secret: &[u8], context: &[u8]) -> bool {
        let mut matches = 0_u8;
        for key in keyset.latest_first_keys() {
            let mut candidate = mac_over_secret_bytes_for_key(secret, context, key);
            matches |= candidate.as_slice().ct_eq(self.as_bytes()).unwrap_u8();
            candidate.zeroize();
        }
        matches == 1
    }
}

fn validate_mac_over_secret_bytes(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() != MAC_OVER_SECRET_SIZE {
        return Err(Error::InvalidMacOverSecretLength {
            actual: bytes.len(),
        });
    }
    if bytes[0] != MAC_OVER_SECRET_VERSION {
        return Err(Error::UnsupportedMacOverSecretVersion { version: bytes[0] });
    }
    Ok(())
}

impl TryFrom<&[u8]> for MacOverSecret {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for MacOverSecret {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_vec(value)
    }
}

impl Clone for MacOverSecret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl AsRef<[u8]> for MacOverSecret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for MacOverSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacOverSecret")
            .field("len", &self.as_bytes().len())
            .finish()
    }
}

impl<K> SecretBytes<K> {
    /// Computes a public MAC over these secret bytes.
    pub fn to_mac(&self, keyset: &Keyset, context: &[u8]) -> Result<MacOverSecret, Error> {
        MacOverSecret::from_mac_array(mac_over_secret_bytes_for_key(
            self.expose_secret(),
            context,
            keyset.latest_key(),
        ))
    }

    pub(crate) fn to_macs_for_all_keyset_keys(
        &self,
        keyset: &Keyset,
        context: &[u8],
    ) -> Result<Vec<MacOverSecret>, Error> {
        let mut macs = Vec::new();
        macs.try_reserve_exact(keyset.key_count())
            .map_err(|_| Error::AllocationFailed)?;
        for key in keyset.latest_first_keys() {
            macs.push(MacOverSecret::from_mac_array(
                mac_over_secret_bytes_for_key(self.expose_secret(), context, key),
            )?);
        }
        Ok(macs)
    }
}

fn mac_over_secret_bytes_for_key(
    secret: &[u8],
    context: &[u8],
    key: &ParanoidKey,
) -> [u8; MAC_OVER_SECRET_SIZE] {
    let mut context_len = (context.len() as u64).to_be_bytes();
    let mut secret_len = (secret.len() as u64).to_be_bytes();
    let mut hmac_lane = hmac_sha256_parts(
        &key.hkdf_sha256,
        &[
            MAC_OVER_SECRET_HMAC_LABEL,
            &context_len,
            context,
            &secret_len,
            secret,
        ],
    );
    let mut blake3_lane = blake3_keyed_hash_parts(
        &key.blake3,
        &[
            MAC_OVER_SECRET_BLAKE3_LABEL,
            &context_len,
            context,
            &secret_len,
            secret,
        ],
    );
    let mut mac = [0_u8; MAC_OVER_SECRET_SIZE];
    mac[0] = MAC_OVER_SECRET_VERSION;
    for index in 0..MAC_OVER_SECRET_BODY_SIZE {
        mac[1 + index] = hmac_lane[index] ^ blake3_lane[index];
    }
    context_len.zeroize();
    secret_len.zeroize();
    hmac_lane.zeroize();
    blake3_lane.zeroize();
    mac
}
