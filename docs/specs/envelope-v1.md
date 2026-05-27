# Envelope v1 Spec

This document specifies the `paranoid` v1 encrypted envelope format.

## Scope

Paranoid v1 encrypts byte plaintext from high-entropy 32-byte input keys. In the public
Rust API, callers derive a latest-first `Keyset` with
`derive_keyset_from_latest_first_keys(...)` and an explicit purpose string. A `Keyset` may
derive narrower child keysets with `derive_child_keyset(...)`. Input keys cannot encrypt
directly.

Purpose binding derives two internal 32-byte lanes from each 32-byte root key: one
HKDF-SHA256 lane and one BLAKE3 derive-key lane. The byte envelope is then a two-layer
cascade over those two lanes.

Paranoid v1 does not perform password hashing. Password-to-key derivation belongs in a
separate layer.

The public API accepts optional associated data. Associated data is authenticated by both
AEAD layers but is not stored in the envelope.

Purpose strings are also not stored in the envelope. The same purpose must be used for
decryption, and parent/child purpose keysets are intentionally unable to decrypt each
other's envelopes. Otherwise the purpose-bound key material differs and decryption fails.

Purpose strings are non-empty byte strings up to 255 bytes. They must use visible ASCII
bytes except `/`; slash is reserved as the display separator between parent and child
purpose segments.

## Constants

- maximum plaintext size: `1048576` bytes.
- maximum associated data size: `1048576` bytes.
- minimum padded payload size: `256` bytes.
- maximum padded payload size: `2097152` bytes.
- salt size: `32` bytes.
- XChaCha20-Poly1305 nonce size: `24` bytes.
- AES-256-GCM-SIV nonce size: `12` bytes.
- AEAD tag size for each layer: `16` bytes.
- cascade tag overhead: `32` bytes.
- header size: `106` bytes.
- minimum envelope size: `394` bytes.
- maximum envelope size: `2097290` bytes.

## Header

The first 106 bytes are public header bytes:

| Offset | Size | Field                    |
| ------ | ---: | ------------------------ |
| 0      |    4 | magic bytes `PARA`       |
| 4      |    1 | version byte `1`         |
| 5      |    1 | suite id byte `1`        |
| 6      |   32 | HKDF-SHA256 salt         |
| 38     |   32 | BLAKE3 derive-key salt   |
| 70     |   24 | XChaCha20-Poly1305 nonce |
| 94     |   12 | AES-256-GCM-SIV nonce    |

The header is authenticated by both AEAD layers.

## Padding

The internal padded payload is:

```text
little_endian_u64(plaintext_len) || plaintext || random_padding
```

The padded payload length is:

```text
max(256, next_power_of_two(8 + plaintext_len))
```

The true plaintext length and padding length are not public. Decryption must reject if the
decrypted plaintext length does not produce the envelope's padded payload bucket.

## Purpose Keys

The public API first derives a two-lane purpose key from each 32-byte root key.

Purpose context:

```text
big_endian_u16(purpose_len) || purpose
```

Purpose HKDF-SHA256 lane:

```text
HKDF-SHA256(
  secret_key = root_key,
  salt = "paranoid/v1/purpose-keyset/hkdf-sha256/salt",
  info = "paranoid/v1/purpose-keyset/hkdf-sha256/info/" || purpose_context
)
```

Purpose BLAKE3 lane:

```text
BLAKE3 derive-key(
  context = "paranoid/v1/purpose-keyset/blake3",
  key_material = root_key || purpose_context
)
```

Child-purpose context:

```text
big_endian_u16(parent_purpose_len) || parent_purpose ||
big_endian_u16(child_purpose_len) || child_purpose
```

Child-purpose HKDF-SHA256 lane:

```text
HKDF-SHA256(
  secret_key = parent_purpose_key.hkdf_sha256,
  salt = "paranoid/v1/child-keyset/hkdf-sha256/salt",
  info = "paranoid/v1/child-keyset/hkdf-sha256/info/" || child_purpose_context
)
```

Child-purpose BLAKE3 lane:

```text
BLAKE3 derive-key(
  context = "paranoid/v1/child-keyset/blake3",
  key_material = parent_purpose_key.blake3 || child_purpose_context
)
```

## Message Keys

The inner XChaCha20-Poly1305 key is derived from the purpose HKDF-SHA256 lane:

```text
HKDF-SHA256(
  secret_key = purpose_key.hkdf_sha256,
  salt = header.hkdf_salt,
  info = "paranoid/v1/hkdf-sha256/xchacha20poly1305/inner"
)
```

The outer AES-256-GCM-SIV key is derived from the purpose BLAKE3 lane:

```text
BLAKE3 derive-key(
  context = "paranoid/v1/blake3/aes-256-gcm-siv/outer",
  key_material = purpose_key.blake3 || header.blake3_salt
)
```

## AEAD Cascade

The associated data passed to both AEAD layers is:

```text
header || caller_associated_data
```

The inner ciphertext is:

```text
XChaCha20-Poly1305(
  key = inner_key,
  nonce = header.xchacha_nonce,
  associated_data = header || caller_associated_data,
  plaintext = padded_payload
)
```

The outer ciphertext is:

```text
AES-256-GCM-SIV(
  key = outer_key,
  nonce = header.aes_256_gcm_siv_nonce,
  associated_data = header || caller_associated_data,
  plaintext = inner_ciphertext
)
```

## Envelope

The final envelope is:

```text
header || outer_ciphertext
```

The inferred padded payload length is:

```text
len(outer_ciphertext) - 32
```

That inferred padded payload length must be a valid padded payload bucket. The `32` bytes
are the two 16-byte AEAD tags.

## Decryption

Decryption must:

1. Validate the public envelope structure.
2. Derive the inner and outer message keys.
3. Decrypt the outer AES-256-GCM-SIV layer.
4. Decrypt the inner XChaCha20-Poly1305 layer.
5. Validate the plaintext length prefix against the canonical bucket.
6. Return plaintext as a zeroizing owned buffer.

All AEAD authentication failures return generic decryption failure.

## Compatibility Fixtures

Deterministic fixture files live under `tests/testdata/envelope-v1`.

The fixture corpus includes:

- `v1-vector-001.txt`: normal small payload with associated data.
- `v1-vector-002-empty.txt`: empty payload and empty associated data.
- `v1-vector-003-248-byte.txt`: largest payload in the 256-byte padded bucket.
- `v1-vector-004-249-byte.txt`: first payload in the 512-byte padded bucket.
- `v1-vector-005-505-byte.txt`: first payload in the 1024-byte padded bucket.

Each fixture uses fixed root key material, purpose, associated data, salts, nonces, and
padded payload bytes. Each includes the expected inner ciphertext, final envelope, and
envelope digests as standard Base64 fields. Other implementations should use these
fixtures to verify byte-for-byte compatibility with this spec.

Deterministic invalid fixture files also live under `tests/testdata/envelope-v1`. They
include structurally invalid envelopes and structurally valid envelopes that must fail
decryption. Implementations should reject each invalid fixture with the named error class
or a stricter local equivalent.

## Parser Requirements

Envelope parsing must be total over untrusted bytes: malformed inputs may return errors,
but must not panic. Implementations must enforce the exact size bounds, magic bytes,
version, suite identifier, padding bucket shape, and generic decryption-failure behavior
specified above.
