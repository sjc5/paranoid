use super::Error;

/// Maximum byte length for opaque auth-core record identifiers.
pub const ID_MAX_BYTES: usize = 256;
/// Maximum byte length for adapter-specific proof method labels.
pub const METHOD_LABEL_MAX_BYTES: usize = 128;
/// Maximum byte length for weak-proof gate method labels.
pub const WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES: usize = 128;
/// Maximum byte length for one weak-proof gate response payload.
pub const WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
/// Maximum byte length for out-of-band challenge dedupe keys.
pub const OUT_OF_BAND_CHALLENGE_DEDUPE_KEY_MAX_BYTES: usize = 512;
/// Maximum byte length for opaque out-of-band recipient handles.
pub const OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES: usize = 2048;
/// Maximum byte length for durable delivery idempotency keys.
pub const DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES: usize = 512;
/// Maximum byte length for trusted-device display labels.
pub const TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES: usize = 1024;
/// Maximum byte length for method/plugin commit operation labels.
pub const METHOD_COMMIT_OPERATION_MAX_BYTES: usize = 256;
/// Maximum byte length for one method/plugin commit payload.
pub const METHOD_COMMIT_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
/// Maximum byte length for one method/plugin challenge presentation.
pub const ACTIVE_PROOF_METHOD_CHALLENGE_PRESENTATION_MAX_BYTES: usize = 64 * 1024;
/// Maximum byte length for one method/plugin challenge request payload.
pub const ACTIVE_PROOF_METHOD_CHALLENGE_REQUEST_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
/// Maximum byte length for one method/plugin challenge state payload.
pub const ACTIVE_PROOF_METHOD_CHALLENGE_STATE_MAX_BYTES: usize = 64 * 1024;
/// Maximum byte length for one method/plugin challenge response.
pub const ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
/// Maximum byte length for a challenge-bound configured-secret Bloom-filter bitset.
pub const CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_BYTES: usize = 512;
/// Maximum number of hash probes for a challenge-bound configured-secret Bloom filter.
pub const CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_HASH_COUNT: u8 = 32;
/// Maximum number of recovery authorities on one pending identifier-change candidate.
pub const OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT: usize = 16;
/// Maximum byte length for encoded pending identifier-change candidate authority ids.
pub const OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_IDS_MAX_BYTES: usize =
    2 + OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT * (2 + ID_MAX_BYTES);

pub(super) fn validate_auth_string_not_too_long(
    input_name: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), Error> {
    if value.len() > max_bytes {
        return Err(Error::InputTooLong {
            input_name,
            max_bytes,
        });
    }
    Ok(())
}

pub(super) fn validate_auth_bytes_not_too_long(
    input_name: &'static str,
    value: &[u8],
    max_bytes: usize,
) -> Result<(), Error> {
    if value.len() > max_bytes {
        return Err(Error::InputTooLong {
            input_name,
            max_bytes,
        });
    }
    Ok(())
}

pub(super) fn validate_auth_identifier_string(
    input_name: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), Error> {
    validate_auth_string_not_too_long(input_name, value, max_bytes)?;
    if !value.bytes().all(is_visible_ascii_non_whitespace) {
        return Err(Error::InvalidIdentifierString { input_name });
    }
    Ok(())
}

fn is_visible_ascii_non_whitespace(value: u8) -> bool {
    matches!(value, b'!'..=b'~')
}
