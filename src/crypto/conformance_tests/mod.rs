use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::codecs::{
    BASE64URL_CODEC_NAME, CROCKFORD_BASE32_CODEC_NAME, MNEMONIC_CODEC_NAME,
};
use crate::crypto::envelope::{
    AES_GCM_SIV_NONCE_OFFSET, BLAKE3_SALT_OFFSET, CASCADE_TAG_OVERHEAD, HEADER_SIZE,
    HKDF_INNER_KEY_INFO, HKDF_SALT_OFFSET, MAGIC, MAX_PADDED_PAYLOAD_SIZE, MIN_ENVELOPE_SIZE,
    MIN_PADDED_PAYLOAD_SIZE, SALT_SIZE, SUITE_PARANOID_V1, TRUE_LENGTH_SIZE, VERSION,
    XCHACHA_NONCE_OFFSET, build_header, build_layer_associated_data,
    decrypt_with_key_and_associated_data, derive_blake3_outer_key,
    padded_payload_len_for_plaintext_len,
};
use crate::crypto::keyset::{MAX_PURPOSE_LEN, ParanoidKey, derive_working_key_from_key32};
use crate::crypto::token::MAC_OVER_SECRET_VERSION;
use crate::crypto::{
    AES_256_GCM_SIV_NONCE_SIZE, Base58, Base64Url, CrockfordBase32, Encrypted, Error, KEY_SIZE,
    KEY32_SIZE, Key32, Keyset, MAC_OVER_SECRET_SIZE, MAX_ASSOCIATED_DATA_SIZE,
    MAX_BYTE_CONTAINER_SIZE, MAX_ENVELOPE_SIZE, MAX_KEYSET_KEYS, MAX_PLAINTEXT_SIZE,
    MAX_RANDOM_BYTES_SIZE, MacOverSecret, Mnemonic, OpaqueEncryptedKind, Plaintext, PublicBytes,
    PublicBytesKind, SecretBytes, SecretBytesKind, XCHACHA20_POLY1305_NONCE_SIZE,
    XCHACHA20_POLY1305_TAG_SIZE, blake3_hash_parts, decrypt, derive_keyset_from_latest_first_keys,
    encrypt, encrypt_aes_256_gcm_siv, encrypt_xchacha20_poly1305, random_key32,
    random_public_bytes, random_secret_bytes, sha256_hash_parts,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as TEST_BASE64_URL_SAFE_NO_PAD;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

const V1_VECTOR_001: &str = include_str!("../../../tests/testdata/envelope-v1/v1-vector-001.txt");
const V1_VECTOR_002_EMPTY: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-vector-002-empty.txt");
const V1_VECTOR_003_248_BYTE: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-vector-003-248-byte.txt");
const V1_VECTOR_004_249_BYTE: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-vector-004-249-byte.txt");
const V1_VECTOR_005_505_BYTE: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-vector-005-505-byte.txt");
const V1_INVALID_001_EMPTY_ENVELOPE: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-001-empty-envelope.txt");
const V1_INVALID_002_BAD_MAGIC: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-002-bad-magic.txt");
const V1_INVALID_003_UNSUPPORTED_VERSION: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-003-unsupported-version.txt");
const V1_INVALID_004_UNSUPPORTED_SUITE: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-004-unsupported-suite.txt");
const V1_INVALID_005_TRUNCATED: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-005-truncated.txt");
const V1_INVALID_006_ODD_EXTENSION: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-006-odd-extension.txt");
const V1_INVALID_007_CIPHERTEXT_TAMPERED: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-007-ciphertext-tampered.txt");
const V1_INVALID_008_WRONG_ASSOCIATED_DATA: &str =
    include_str!("../../../tests/testdata/envelope-v1/v1-invalid-008-wrong-associated-data.txt");
const V1_FIXTURE_TEXTS: &[&str] = &[
    V1_VECTOR_001,
    V1_VECTOR_002_EMPTY,
    V1_VECTOR_003_248_BYTE,
    V1_VECTOR_004_249_BYTE,
    V1_VECTOR_005_505_BYTE,
];
const V1_INVALID_FIXTURE_TEXTS: &[&str] = &[
    V1_INVALID_001_EMPTY_ENVELOPE,
    V1_INVALID_002_BAD_MAGIC,
    V1_INVALID_003_UNSUPPORTED_VERSION,
    V1_INVALID_004_UNSUPPORTED_SUITE,
    V1_INVALID_005_TRUNCATED,
    V1_INVALID_006_ODD_EXTENSION,
    V1_INVALID_007_CIPHERTEXT_TAMPERED,
    V1_INVALID_008_WRONG_ASSOCIATED_DATA,
];
const TEST_PURPOSE: &str = "paranoid.test.v1";

fn test_key(byte: u8) -> Key32 {
    Key32::from_bytes(&[byte; KEY_SIZE]).expect("key")
}

fn test_keyset(bytes: &[u8]) -> Keyset {
    derive_keyset_from_latest_first_keys(bytes.iter().copied().map(test_key), TEST_PURPOSE)
        .expect("keyset")
}

fn plaintext_with_len(len: usize) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(len);
    for index in 0..len {
        plaintext.push((index % 251) as u8);
    }
    plaintext
}

fn envelope_len_for_padded_payload_len(padded_payload_len: usize) -> usize {
    HEADER_SIZE + padded_payload_len + CASCADE_TAG_OVERHEAD
}

fn assert_encoded_text_hashes(
    encoded: &str,
    expected_len: usize,
    expected_sha256_base64: &str,
    expected_blake3_base64: &str,
) {
    assert_eq!(encoded.len(), expected_len);
    assert_eq!(
        BASE64_STANDARD.encode(sha256_hash_parts(&[encoded.as_bytes()]).as_bytes()),
        expected_sha256_base64
    );
    assert_eq!(
        BASE64_STANDARD.encode(blake3_hash_parts(&[encoded.as_bytes()]).as_bytes()),
        expected_blake3_base64
    );
}

mod edge_codecs;
mod envelope_and_fixtures;
mod public_and_byte_containers;
mod typed_payloads_macs_and_keysets;

fn parser_boundary_lengths() -> Vec<usize> {
    let candidates = [
        0,
        1,
        MAGIC.len() - 1,
        MAGIC.len(),
        HEADER_SIZE - 1,
        HEADER_SIZE,
        MIN_ENVELOPE_SIZE - 1,
        MIN_ENVELOPE_SIZE,
        MIN_ENVELOPE_SIZE + 1,
        envelope_len_for_padded_payload_len(512) - 1,
        envelope_len_for_padded_payload_len(512),
        envelope_len_for_padded_payload_len(512) + 1,
        MAX_ENVELOPE_SIZE - 1,
        MAX_ENVELOPE_SIZE,
        MAX_ENVELOPE_SIZE + 1,
    ];
    candidates.into_iter().collect()
}

fn exercise_untrusted_envelope_bytes(input: &[u8], keyset: &Keyset) {
    let _: Result<Encrypted, Error> = Encrypted::try_from(input);
    let _ = keyset.decrypt_bytes(input);
    let _ = keyset.decrypt_bytes_with_associated_data(input, b"fuzz associated data");
}

struct V1Fixture {
    name: String,
    input_key: Vec<u8>,
    purpose: String,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
    hkdf_salt: [u8; SALT_SIZE],
    blake3_salt: [u8; SALT_SIZE],
    xchacha_nonce: [u8; XCHACHA20_POLY1305_NONCE_SIZE],
    aes_gcm_siv_nonce: [u8; AES_256_GCM_SIV_NONCE_SIZE],
    padded_payload: Vec<u8>,
    inner_ciphertext: Vec<u8>,
    envelope: Vec<u8>,
    sha256_envelope: Vec<u8>,
    blake3_envelope: Vec<u8>,
}

impl V1Fixture {
    fn parse(input: &str) -> Self {
        let fields = fixture_fields(input);

        Self {
            name: fixture_field(&fields, "name").to_owned(),
            input_key: fixture_base64_field(&fields, "input_key_base64"),
            purpose: fixture_field(&fields, "purpose").to_owned(),
            plaintext: fixture_base64_field(&fields, "plaintext_base64"),
            associated_data: fixture_base64_field(&fields, "associated_data_base64"),
            hkdf_salt: fixture_array_field(&fields, "hkdf_salt_base64"),
            blake3_salt: fixture_array_field(&fields, "blake3_salt_base64"),
            xchacha_nonce: fixture_array_field(&fields, "xchacha20_poly1305_nonce_base64"),
            aes_gcm_siv_nonce: fixture_array_field(&fields, "aes_256_gcm_siv_nonce_base64"),
            padded_payload: fixture_base64_field(&fields, "padded_payload_base64"),
            inner_ciphertext: fixture_base64_field(&fields, "inner_ciphertext_base64"),
            envelope: fixture_base64_field(&fields, "envelope_base64"),
            sha256_envelope: fixture_base64_field(&fields, "sha256_envelope_base64"),
            blake3_envelope: fixture_base64_field(&fields, "blake3_envelope_base64"),
        }
    }
}

struct V1InvalidFixture {
    name: String,
    input_key: Vec<u8>,
    purpose: String,
    associated_data: Vec<u8>,
    envelope: Vec<u8>,
    expected_error: ExpectedFixtureError,
}

impl V1InvalidFixture {
    fn parse(input: &str) -> Self {
        let fields = fixture_fields(input);

        Self {
            name: fixture_field(&fields, "name").to_owned(),
            input_key: fixture_base64_field(&fields, "input_key_base64"),
            purpose: fixture_field(&fields, "purpose").to_owned(),
            associated_data: fixture_base64_field(&fields, "associated_data_base64"),
            envelope: fixture_base64_field(&fields, "envelope_base64"),
            expected_error: ExpectedFixtureError::parse(fixture_field(&fields, "expected_error")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedFixtureError {
    EmptyEnvelope,
    EnvelopeTooShort,
    InvalidEnvelopeLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    DecryptionFailed,
}

impl ExpectedFixtureError {
    fn parse(input: &str) -> Self {
        match input {
            "empty_envelope" => Self::EmptyEnvelope,
            "envelope_too_short" => Self::EnvelopeTooShort,
            "invalid_envelope_length" => Self::InvalidEnvelopeLength,
            "invalid_magic" => Self::InvalidMagic,
            "unsupported_version" => Self::UnsupportedVersion,
            "unsupported_suite" => Self::UnsupportedSuite,
            "decryption_failed" => Self::DecryptionFailed,
            _ => panic!("unknown expected fixture error {input}"),
        }
    }

    fn matches_error(self, error: &Error) -> bool {
        matches!(
            (self, error),
            (Self::EmptyEnvelope, Error::EmptyEnvelope)
                | (Self::EnvelopeTooShort, Error::EnvelopeTooShort { .. })
                | (
                    Self::InvalidEnvelopeLength,
                    Error::InvalidEnvelopeLength { .. }
                )
                | (Self::InvalidMagic, Error::InvalidMagic)
                | (Self::UnsupportedVersion, Error::UnsupportedVersion { .. })
                | (Self::UnsupportedSuite, Error::UnsupportedSuite { .. })
                | (Self::DecryptionFailed, Error::DecryptionFailed)
        )
    }

    fn is_structurally_valid_envelope(self) -> bool {
        matches!(self, Self::DecryptionFailed)
    }
}

fn fixture_fields(input: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("fixture key=value line");
        assert!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate fixture field {key}"
        );
    }
    fields
}

fn fixture_field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    fields
        .get(key)
        .unwrap_or_else(|| panic!("missing fixture field {key}"))
}

fn fixture_base64_field(fields: &BTreeMap<String, String>, key: &str) -> Vec<u8> {
    BASE64_STANDARD
        .decode(fixture_field(fields, key))
        .unwrap_or_else(|error| panic!("invalid base64 field {key}: {error}"))
}

fn fixture_array_field<const N: usize>(fields: &BTreeMap<String, String>, key: &str) -> [u8; N] {
    fixture_base64_field(fields, key)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| {
            panic!("fixture field {key} length {}, want {N}", bytes.len())
        })
}

#[derive(Clone, Copy)]
enum ManualEnvelopeMutation {
    None,
    TamperInnerCiphertext,
}

struct ManualEncryptionInputs<'a> {
    key: &'a ParanoidKey,
    padded_payload: &'a SecretBytes,
    associated_data: &'a [u8],
    hkdf_salt: &'a [u8; SALT_SIZE],
    blake3_salt: &'a [u8; SALT_SIZE],
    xchacha_nonce: &'a [u8; XCHACHA20_POLY1305_NONCE_SIZE],
    aes_gcm_siv_nonce: &'a [u8; AES_256_GCM_SIV_NONCE_SIZE],
    mutation: ManualEnvelopeMutation,
}

struct ManualEncryptionOutput {
    inner_ciphertext: Vec<u8>,
    envelope: Vec<u8>,
}

fn valid_test_padded_payload(plaintext: &[u8]) -> SecretBytes {
    let padded_payload_len =
        padded_payload_len_for_plaintext_len(plaintext.len()).expect("padded len");
    let mut padded_payload = SecretBytes::new_zeroed(padded_payload_len).expect("payload");
    padded_payload.expose_secret_mut().fill(0xa5);
    padded_payload.expose_secret_mut()[..TRUE_LENGTH_SIZE]
        .copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
    padded_payload.expose_secret_mut()[TRUE_LENGTH_SIZE..TRUE_LENGTH_SIZE + plaintext.len()]
        .copy_from_slice(plaintext);
    padded_payload
}

fn invalid_length_test_padded_payload() -> SecretBytes {
    let mut padded_payload = SecretBytes::new_zeroed(MIN_PADDED_PAYLOAD_SIZE).expect("payload");
    padded_payload.expose_secret_mut().fill(0xa5);
    padded_payload.expose_secret_mut()[..TRUE_LENGTH_SIZE]
        .copy_from_slice(&(MIN_PADDED_PAYLOAD_SIZE as u64).to_le_bytes());
    padded_payload
}

fn manually_encrypt_padded_payload(
    key: &ParanoidKey,
    padded_payload: &SecretBytes,
    associated_data: &[u8],
    mutation: ManualEnvelopeMutation,
) -> Vec<u8> {
    let hkdf_salt = [0x11_u8; SALT_SIZE];
    let blake3_salt = [0x22_u8; SALT_SIZE];
    let xchacha_nonce = [0x33_u8; XCHACHA20_POLY1305_NONCE_SIZE];
    let aes_gcm_siv_nonce = [0x44_u8; AES_256_GCM_SIV_NONCE_SIZE];

    manually_encrypt_padded_payload_with_components(ManualEncryptionInputs {
        key,
        padded_payload,
        associated_data,
        hkdf_salt: &hkdf_salt,
        blake3_salt: &blake3_salt,
        xchacha_nonce: &xchacha_nonce,
        aes_gcm_siv_nonce: &aes_gcm_siv_nonce,
        mutation,
    })
    .envelope
}

fn manually_encrypt_padded_payload_with_components(
    inputs: ManualEncryptionInputs<'_>,
) -> ManualEncryptionOutput {
    let header = build_header(
        inputs.hkdf_salt,
        inputs.blake3_salt,
        inputs.xchacha_nonce,
        inputs.aes_gcm_siv_nonce,
    );
    let associated_data_for_layers =
        build_layer_associated_data(&header, inputs.associated_data).expect("layer aad");
    let xchacha_key = inputs
        .key
        .hkdf_sha256
        .derive_hkdf_sha256(inputs.hkdf_salt, HKDF_INNER_KEY_INFO)
        .expect("xchacha key");
    let aes_gcm_siv_key =
        derive_blake3_outer_key(&inputs.key.blake3, inputs.blake3_salt).expect("aes key");

    let mut inner_ciphertext = encrypt_xchacha20_poly1305(
        &xchacha_key,
        inputs.xchacha_nonce,
        &associated_data_for_layers,
        inputs.padded_payload.expose_secret(),
    )
    .expect("inner encrypt");
    if matches!(
        inputs.mutation,
        ManualEnvelopeMutation::TamperInnerCiphertext
    ) {
        inner_ciphertext[0] ^= 0x01;
    }

    let ciphertext = encrypt_aes_256_gcm_siv(
        &aes_gcm_siv_key,
        inputs.aes_gcm_siv_nonce,
        &associated_data_for_layers,
        &inner_ciphertext,
    )
    .expect("outer encrypt");

    let mut envelope = Vec::new();
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&ciphertext);
    ManualEncryptionOutput {
        inner_ciphertext,
        envelope,
    }
}
