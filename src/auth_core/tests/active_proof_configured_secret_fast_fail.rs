use super::*;

const TOTP_BLOOM_FILTER_BYTES: usize = 64;
const TOTP_BLOOM_FILTER_HASH_COUNT: u8 = 10;

#[test]
fn challenge_bound_configured_secret_bloom_filter_rejects_definite_non_matches() {
    let keyset = test_keyset("tests.auth.challenge-bound-configured-secret-bloom.v1");
    let challenge_context = b"attempt/challenge/method/window/nonce";
    let current_code =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"123456").expect("current code");
    let adjacent_code =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"123457").expect("adjacent code");
    let wrong_code =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"000000").expect("wrong code");
    let mut bloom_filter = ChallengeBoundConfiguredSecretFastFailBloomFilter::new(
        TOTP_BLOOM_FILTER_BYTES,
        TOTP_BLOOM_FILTER_HASH_COUNT,
    )
    .expect("Bloom filter");

    bloom_filter
        .insert_response_for_latest_key(&keyset, challenge_context, &current_code)
        .expect("insert current code");
    bloom_filter
        .insert_response_for_latest_key(&keyset, challenge_context, &adjacent_code)
        .expect("insert adjacent code");

    assert!(
        bloom_filter
            .might_contain_response_in_challenge_context(&keyset, challenge_context, &current_code)
            .expect("check current code")
    );
    assert!(
        bloom_filter
            .might_contain_response_in_challenge_context(&keyset, challenge_context, &adjacent_code)
            .expect("check adjacent code")
    );
    assert!(
        bloom_filter
            .definitely_rejects_response_in_challenge_context(
                &keyset,
                challenge_context,
                &wrong_code
            )
            .expect("check wrong code")
    );
}

#[test]
fn challenge_bound_configured_secret_bloom_filter_is_bound_to_context() {
    let keyset = test_keyset("tests.auth.challenge-bound-configured-secret-bloom.context.v1");
    let original_context = b"attempt-a/challenge-a/totp/window-a/nonce-a";
    let other_context = b"attempt-b/challenge-b/totp/window-a/nonce-a";
    let code = KnownSubjectActiveProofSecretResponse::try_from_bytes(b"987654").expect("code");
    let mut bloom_filter = ChallengeBoundConfiguredSecretFastFailBloomFilter::new(
        TOTP_BLOOM_FILTER_BYTES,
        TOTP_BLOOM_FILTER_HASH_COUNT,
    )
    .expect("Bloom filter");

    bloom_filter
        .insert_response_for_latest_key(&keyset, original_context, &code)
        .expect("insert code");

    assert!(
        bloom_filter
            .might_contain_response_in_challenge_context(&keyset, original_context, &code)
            .expect("check original context")
    );
    assert!(
        bloom_filter
            .definitely_rejects_response_in_challenge_context(&keyset, other_context, &code)
            .expect("check other context")
    );
}

#[test]
fn challenge_bound_configured_secret_bloom_filter_roundtrips_as_bitset_and_hash_count() {
    let keyset = test_keyset("tests.auth.challenge-bound-configured-secret-bloom.roundtrip.v1");
    let challenge_context = b"attempt/challenge/totp/window/nonce";
    let valid_code =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"555555").expect("valid code");
    let wrong_code =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"555556").expect("wrong code");
    let mut bloom_filter = ChallengeBoundConfiguredSecretFastFailBloomFilter::new(
        TOTP_BLOOM_FILTER_BYTES,
        TOTP_BLOOM_FILTER_HASH_COUNT,
    )
    .expect("Bloom filter");

    bloom_filter
        .insert_response_for_latest_key(&keyset, challenge_context, &valid_code)
        .expect("insert valid code");
    let reparsed = ChallengeBoundConfiguredSecretFastFailBloomFilter::try_from_parts(
        bloom_filter.bitset_bytes().to_vec(),
        bloom_filter.hash_count(),
    )
    .expect("reparsed Bloom filter");

    assert_eq!(reparsed.bitset_bytes().len(), TOTP_BLOOM_FILTER_BYTES);
    assert_eq!(reparsed.hash_count(), TOTP_BLOOM_FILTER_HASH_COUNT);
    assert!(
        reparsed
            .might_contain_response_in_challenge_context(&keyset, challenge_context, &valid_code)
            .expect("check valid code")
    );
    assert!(
        reparsed
            .definitely_rejects_response_in_challenge_context(
                &keyset,
                challenge_context,
                &wrong_code
            )
            .expect("check wrong code")
    );
}

#[test]
fn challenge_bound_configured_secret_bloom_filter_accepts_previous_key_during_key_rotation() {
    let old_key = crate::crypto::Key32::try_from([11_u8; crate::crypto::KEY32_SIZE].as_slice())
        .expect("old key");
    let old_key_again =
        crate::crypto::Key32::try_from([11_u8; crate::crypto::KEY32_SIZE].as_slice())
            .expect("old key again");
    let new_key = crate::crypto::Key32::try_from([12_u8; crate::crypto::KEY32_SIZE].as_slice())
        .expect("new key");
    let issue_keyset =
        crate::crypto::derive_keyset_from_latest_first_keys([old_key], "tests.rotation")
            .expect("issue keyset");
    let verify_keyset = crate::crypto::derive_keyset_from_latest_first_keys(
        [new_key, old_key_again],
        "tests.rotation",
    )
    .expect("verify keyset");
    let challenge_context = b"attempt/challenge/totp/window/nonce";
    let code = KnownSubjectActiveProofSecretResponse::try_from_bytes(b"444444").expect("code");
    let mut bloom_filter = ChallengeBoundConfiguredSecretFastFailBloomFilter::new(
        TOTP_BLOOM_FILTER_BYTES,
        TOTP_BLOOM_FILTER_HASH_COUNT,
    )
    .expect("Bloom filter");

    bloom_filter
        .insert_response_for_latest_key(&issue_keyset, challenge_context, &code)
        .expect("insert code");

    assert!(
        bloom_filter
            .might_contain_response_in_challenge_context(&verify_keyset, challenge_context, &code)
            .expect("check rotated keyset")
    );
}

#[test]
fn challenge_bound_configured_secret_bloom_filter_rejects_invalid_shapes() {
    let too_large =
        vec![0_u8; CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_BYTES + 1];

    assert!(matches!(
        ChallengeBoundConfiguredSecretFastFailBloomFilter::new(0, TOTP_BLOOM_FILTER_HASH_COUNT),
        Err(Error::EmptyChallengeBoundConfiguredSecretFastFailBloomFilter)
    ));
    assert!(matches!(
        ChallengeBoundConfiguredSecretFastFailBloomFilter::new(TOTP_BLOOM_FILTER_BYTES, 0),
        Err(Error::InvalidChallengeBoundConfiguredSecretFastFailBloomFilterHashCount { actual: 0 })
    ));
    assert!(matches!(
        ChallengeBoundConfiguredSecretFastFailBloomFilter::new(
            TOTP_BLOOM_FILTER_BYTES,
            CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_HASH_COUNT + 1
        ),
        Err(Error::InvalidChallengeBoundConfiguredSecretFastFailBloomFilterHashCount { .. })
    ));
    assert!(matches!(
        ChallengeBoundConfiguredSecretFastFailBloomFilter::try_from_parts(
            too_large,
            TOTP_BLOOM_FILTER_HASH_COUNT
        ),
        Err(Error::InputTooLong {
            input_name: "challenge-bound configured-secret fast-fail Bloom filter",
            ..
        })
    ));
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([91_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}
