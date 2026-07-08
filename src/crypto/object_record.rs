//! The lean single-layer AEAD record for content-addressed object stores.
//!
//! A stored-object encryption primitive for content-addressed stores that
//! encrypt every object at rest: a 5-byte cleartext header (record
//! version and key generation), a 24-byte random nonce, and an XChaCha20-Poly1305
//! ciphertext, with the associated data constructed here so callers cannot forget the
//! header binding. The caller supplies the role byte and the role-specific suffix
//! (address and domain for objects; writer, sequence, and domain for log entries);
//! the role registry itself is owned by the consuming format specification, not by
//! this crate.
//!
//! Randomness is caller-injected on the seal path so sans-IO consumers can drive
//! encryption without this crate reaching for an ambient random source.

use zeroize::Zeroizing;

use crate::crypto::bytes::public_vec_with_capacity;
use crate::crypto::error::Error;
use crate::crypto::{
    Key32, XCHACHA20_POLY1305_NONCE_SIZE, XCHACHA20_POLY1305_TAG_SIZE, decrypt_xchacha20_poly1305,
    encrypt_xchacha20_poly1305,
};

/// Object record version written and accepted by this module.
pub const OBJECT_RECORD_VERSION: u8 = 1;

/// Size, in bytes, of the cleartext object record header (version byte plus
/// 4-byte little-endian key generation).
pub const OBJECT_RECORD_HEADER_SIZE: usize = 5;

/// Fixed overhead, in bytes, of an object record over its plaintext
/// (header + nonce + authentication tag).
pub const OBJECT_RECORD_OVERHEAD: usize =
    OBJECT_RECORD_HEADER_SIZE + XCHACHA20_POLY1305_NONCE_SIZE + XCHACHA20_POLY1305_TAG_SIZE;

/// Maximum plaintext size accepted by object record sealing and opening.
pub const MAX_OBJECT_RECORD_PLAINTEXT_SIZE: usize = 16 * 1024 * 1024;

/// Maximum encoded object record size (maximum plaintext plus fixed overhead).
pub const MAX_OBJECT_RECORD_SIZE: usize = MAX_OBJECT_RECORD_PLAINTEXT_SIZE + OBJECT_RECORD_OVERHEAD;

/// Maximum caller-supplied associated-data suffix size accepted by this module.
pub const MAX_OBJECT_RECORD_ASSOCIATED_DATA_SUFFIX_SIZE: usize = 1024;

const NONCE_OFFSET: usize = OBJECT_RECORD_HEADER_SIZE;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + XCHACHA20_POLY1305_NONCE_SIZE;

/// Parsed cleartext header of an object record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectRecordHeader {
    version: u8,
    key_generation: u32,
}

impl ObjectRecordHeader {
    /// Returns the record version byte.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the key generation under which the record was sealed.
    pub const fn key_generation(&self) -> u32 {
        self.key_generation
    }
}

/// Parses and validates the cleartext header of an object record without decrypting.
///
/// This is the key-selection step: the caller reads the generation, resolves the
/// matching key, and then calls [`open_object_record`]. Length bounds are enforced
/// here, before any size-proportional work.
pub fn parse_object_record_header(record: &[u8]) -> Result<ObjectRecordHeader, Error> {
    validate_record_len(record.len())?;
    let version = record[0];
    if version != OBJECT_RECORD_VERSION {
        return Err(Error::UnsupportedObjectRecordVersion { version });
    }
    let mut generation_bytes = [0_u8; 4];
    generation_bytes.copy_from_slice(&record[1..OBJECT_RECORD_HEADER_SIZE]);
    Ok(ObjectRecordHeader {
        version,
        key_generation: u32::from_le_bytes(generation_bytes),
    })
}

/// Seals plaintext into an object record using caller-injected randomness.
///
/// The associated data is constructed internally as
/// `role_byte || header (5 bytes, exactly as stored) || suffix`, so the header
/// binding can never be skipped. `fill_random` must fill its argument with
/// cryptographically secure random bytes; sans-IO callers inject their shell's
/// source and may report failure with [`Error::InjectedRandomFillFailed`].
pub fn seal_object_record(
    key: &Key32,
    key_generation: u32,
    associated_data_role: u8,
    associated_data_suffix: &[u8],
    plaintext: &[u8],
    mut fill_random: impl FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_OBJECT_RECORD_PLAINTEXT_SIZE {
        return Err(Error::PlaintextTooLarge {
            actual: plaintext.len(),
            max: MAX_OBJECT_RECORD_PLAINTEXT_SIZE,
        });
    }
    validate_associated_data_suffix_len(associated_data_suffix.len())?;

    let mut header = [0_u8; OBJECT_RECORD_HEADER_SIZE];
    header[0] = OBJECT_RECORD_VERSION;
    header[1..].copy_from_slice(&key_generation.to_le_bytes());

    let mut nonce = [0_u8; XCHACHA20_POLY1305_NONCE_SIZE];
    fill_random(&mut nonce)?;

    let associated_data =
        build_associated_data(associated_data_role, &header, associated_data_suffix)?;
    let ciphertext = encrypt_xchacha20_poly1305(key, &nonce, &associated_data, plaintext)
        .map_err(Error::from)?;

    let mut record = public_vec_with_capacity(
        OBJECT_RECORD_HEADER_SIZE + XCHACHA20_POLY1305_NONCE_SIZE + ciphertext.len(),
    )?;
    record.extend_from_slice(&header);
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&ciphertext);
    debug_assert_eq!(record.len(), plaintext.len() + OBJECT_RECORD_OVERHEAD);
    Ok(record)
}

/// Opens an object record sealed by [`seal_object_record`].
///
/// The caller supplies the same role byte and suffix used at sealing; the stored
/// header participates in authentication automatically. The record must carry the
/// generation the supplied key belongs to — callers select the key via
/// [`parse_object_record_header`] first, and a wrong key fails authentication.
pub fn open_object_record(
    key: &Key32,
    record: &[u8],
    associated_data_role: u8,
    associated_data_suffix: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let _ = parse_object_record_header(record)?;
    validate_associated_data_suffix_len(associated_data_suffix.len())?;

    let header = &record[..OBJECT_RECORD_HEADER_SIZE];
    let nonce: &[u8; XCHACHA20_POLY1305_NONCE_SIZE] = record[NONCE_OFFSET..CIPHERTEXT_OFFSET]
        .try_into()
        .map_err(|_| Error::DecryptionFailed)?;
    let ciphertext = &record[CIPHERTEXT_OFFSET..];

    let associated_data =
        build_associated_data(associated_data_role, header, associated_data_suffix)?;
    let plaintext = decrypt_xchacha20_poly1305(key, nonce, &associated_data, ciphertext)
        .map_err(Error::from)?;
    Ok(Zeroizing::new(plaintext))
}

/// Returns the padded plaintext length for the size-bucket padding rule
/// `max(512, next_power_of_two(len))`.
///
/// This is the bucket arithmetic only. Applying the padding (appending zero bytes
/// before sealing) and verifying it (parsing the embedded structure to its logical
/// length and checking the tail is zero) belong to the consumer, which owns the
/// payload's self-delimiting encoding; this crate cannot verify padding it cannot
/// parse.
pub fn pad_bucket_len(plaintext_len: usize) -> Result<usize, Error> {
    if plaintext_len > MAX_OBJECT_RECORD_PLAINTEXT_SIZE {
        return Err(Error::PlaintextTooLarge {
            actual: plaintext_len,
            max: MAX_OBJECT_RECORD_PLAINTEXT_SIZE,
        });
    }
    Ok(plaintext_len.next_power_of_two().max(512))
}

fn build_associated_data(role: u8, header: &[u8], suffix: &[u8]) -> Result<Vec<u8>, Error> {
    let mut associated_data = public_vec_with_capacity(1 + header.len() + suffix.len())?;
    associated_data.push(role);
    associated_data.extend_from_slice(header);
    associated_data.extend_from_slice(suffix);
    Ok(associated_data)
}

fn validate_record_len(len: usize) -> Result<(), Error> {
    if len < OBJECT_RECORD_OVERHEAD {
        return Err(Error::ObjectRecordTooShort {
            actual: len,
            min: OBJECT_RECORD_OVERHEAD,
        });
    }
    if len > MAX_OBJECT_RECORD_SIZE {
        return Err(Error::ObjectRecordTooLarge {
            actual: len,
            max: MAX_OBJECT_RECORD_SIZE,
        });
    }
    Ok(())
}

fn validate_associated_data_suffix_len(len: usize) -> Result<(), Error> {
    if len > MAX_OBJECT_RECORD_ASSOCIATED_DATA_SUFFIX_SIZE {
        return Err(Error::AssociatedDataTooLarge {
            actual: len,
            max: MAX_OBJECT_RECORD_ASSOCIATED_DATA_SUFFIX_SIZE,
        });
    }
    Ok(())
}
