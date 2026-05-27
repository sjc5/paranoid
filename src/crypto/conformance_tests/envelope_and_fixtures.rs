use super::*;

#[test]
fn encrypt_decrypt_round_trips_representative_sizes() {
    let keyset = test_keyset(&[1]);

    for plaintext_len in [0, 1, 32, 248, 249, 4096, MAX_PLAINTEXT_SIZE] {
        let plaintext = plaintext_with_len(plaintext_len);
        let encrypted = keyset.encrypt_bytes(&plaintext).expect("encrypt");
        let decrypted = keyset.decrypt_bytes(encrypted.as_bytes()).expect("decrypt");

        assert_eq!(decrypted.expose_secret(), plaintext);
    }
}

#[test]
fn associated_data_must_match() {
    let keyset = test_keyset(&[1]);
    let encrypted = keyset
        .encrypt_bytes_with_associated_data(b"secret", b"header")
        .expect("encrypt");

    let decrypted = keyset
        .decrypt_bytes_with_associated_data(encrypted.as_bytes(), b"header")
        .expect("decrypt");
    assert_eq!(decrypted.expose_secret(), b"secret");
    assert!(matches!(
        keyset.decrypt_bytes_with_associated_data(encrypted.as_bytes(), b"other header"),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn associated_data_size_is_bounded_before_layer_allocation() {
    let keyset = test_keyset(&[1]);
    let oversized_context = vec![0_u8; MAX_ASSOCIATED_DATA_SIZE + 1];
    let encrypted = keyset.encrypt_bytes(b"secret").expect("encrypt");

    assert!(matches!(
        keyset.encrypt_bytes_with_associated_data(b"secret", &oversized_context),
        Err(Error::AssociatedDataTooLarge { actual, max })
            if actual == MAX_ASSOCIATED_DATA_SIZE + 1 && max == MAX_ASSOCIATED_DATA_SIZE
    ));
    assert!(matches!(
        keyset.decrypt_bytes_with_associated_data(encrypted.as_bytes(), &oversized_context),
        Err(Error::AssociatedDataTooLarge { actual, max })
            if actual == MAX_ASSOCIATED_DATA_SIZE + 1 && max == MAX_ASSOCIATED_DATA_SIZE
    ));
}

#[test]
fn envelope_header_debug_and_bucketed_length_are_expected() {
    let keyset = test_keyset(&[1]);
    let first = keyset
        .encrypt_bytes(b"short secret")
        .expect("first encrypt");
    let second_plaintext = vec![b'a'; 200];
    let second = keyset
        .encrypt_bytes(&second_plaintext)
        .expect("second encrypt");

    assert_eq!(&first.as_bytes()[..MAGIC.len()], MAGIC);
    assert_eq!(first.as_bytes()[MAGIC.len()], VERSION);
    assert_eq!(first.as_bytes()[MAGIC.len() + 1], SUITE_PARANOID_V1);
    assert_eq!(first.as_bytes().len(), second.as_bytes().len());
    assert!(
        !first
            .as_bytes()
            .windows(b"short secret".len())
            .any(|window| window == b"short secret")
    );

    let copied: Encrypted = Encrypted::try_from(first.as_bytes()).expect("from envelope");
    assert_eq!(copied.as_bytes(), first.as_bytes());

    let debug = format!("{first:?}");
    assert!(debug.contains("envelope_len"));
    assert!(!debug.contains("short secret"));
}

#[test]
fn padding_bucket_schedule_is_stable() {
    for (plaintext_len, padded_payload_len) in [
        (0, 256),
        (1, 256),
        (248, 256),
        (249, 512),
        (504, 512),
        (505, 1024),
        (1016, 1024),
        (1017, 2048),
        (MAX_PLAINTEXT_SIZE, MAX_PADDED_PAYLOAD_SIZE),
    ] {
        assert_eq!(
            padded_payload_len_for_plaintext_len(plaintext_len).expect("padded payload length"),
            padded_payload_len
        );
        assert_eq!(
            envelope_len_for_padded_payload_len(padded_payload_len),
            HEADER_SIZE + padded_payload_len + CASCADE_TAG_OVERHEAD
        );
    }
}

#[test]
fn same_plaintext_encrypts_differently() {
    let keyset = test_keyset(&[1]);

    let first = keyset
        .encrypt_bytes(b"same plaintext")
        .expect("first encrypt");
    let second = keyset
        .encrypt_bytes(b"same plaintext")
        .expect("second encrypt");

    assert_ne!(first.as_bytes(), second.as_bytes());
}

#[test]
fn wrong_key_and_ciphertext_tampering_fail_decryption() {
    let keyset = test_keyset(&[1]);
    let wrong_keyset = test_keyset(&[2]);
    let encrypted = keyset.encrypt_bytes(b"secret").expect("encrypt");

    assert!(matches!(
        wrong_keyset.decrypt_bytes(encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));

    for tamper_index in [HEADER_SIZE, encrypted.as_bytes().len() - 1] {
        let mut tampered = encrypted.as_bytes().to_vec();
        tampered[tamper_index] ^= 0x01;

        assert!(matches!(
            keyset.decrypt_bytes(&tampered),
            Err(Error::DecryptionFailed)
        ));
    }
}

#[test]
fn every_single_byte_modification_is_rejected() {
    let keyset = test_keyset(&[1]);
    let encrypted = keyset
        .encrypt_bytes(b"secret")
        .expect("encrypt")
        .into_bytes();

    for tamper_index in 0..encrypted.len() {
        let mut tampered = encrypted.clone();
        tampered[tamper_index] ^= 0x01;

        assert!(
            keyset.decrypt_bytes(&tampered).is_err(),
            "tampered byte {tamper_index} decrypted successfully"
        );
    }
}

#[test]
fn header_field_modification_is_rejected_or_fails_decryption() {
    let keyset = test_keyset(&[1]);
    let encrypted = keyset.encrypt_bytes(b"secret").expect("encrypt");

    let mut tampered = encrypted.as_bytes().to_vec();
    tampered[0] ^= 0x01;
    assert!(matches!(
        keyset.decrypt_bytes(&tampered),
        Err(Error::InvalidMagic)
    ));

    let mut tampered = encrypted.as_bytes().to_vec();
    tampered[MAGIC.len()] = VERSION + 1;
    assert!(matches!(
        keyset.decrypt_bytes(&tampered),
        Err(Error::UnsupportedVersion { .. })
    ));

    let mut tampered = encrypted.as_bytes().to_vec();
    tampered[MAGIC.len() + 1] = SUITE_PARANOID_V1 + 1;
    assert!(matches!(
        keyset.decrypt_bytes(&tampered),
        Err(Error::UnsupportedSuite { .. })
    ));

    for tamper_index in [
        HKDF_SALT_OFFSET,
        BLAKE3_SALT_OFFSET,
        XCHACHA_NONCE_OFFSET,
        AES_GCM_SIV_NONCE_OFFSET,
    ] {
        let mut tampered = encrypted.as_bytes().to_vec();
        tampered[tamper_index] ^= 0x01;

        assert!(matches!(
            keyset.decrypt_bytes(&tampered),
            Err(Error::DecryptionFailed)
        ));
    }
}

#[test]
fn invalid_envelope_sizes_are_rejected() {
    let keyset = test_keyset(&[1]);

    assert!(matches!(
        keyset.decrypt_bytes(&[]),
        Err(Error::EmptyEnvelope)
    ));
    assert!(matches!(
        Encrypted::<OpaqueEncryptedKind>::try_from(&[0_u8; MIN_ENVELOPE_SIZE - 1][..]),
        Err(Error::EnvelopeTooShort { .. })
    ));
    assert!(matches!(
        Encrypted::<OpaqueEncryptedKind>::try_from(vec![0_u8; MAX_ENVELOPE_SIZE + 1].as_slice()),
        Err(Error::EnvelopeTooLarge { .. })
    ));

    let mut odd_len = keyset
        .encrypt_bytes(b"secret")
        .expect("encrypt")
        .into_bytes();
    odd_len.push(0);
    assert!(matches!(
        Encrypted::<OpaqueEncryptedKind>::try_from(odd_len.as_slice()),
        Err(Error::InvalidEnvelopeLength { .. })
    ));

    let mut invalid_bucket = keyset
        .encrypt_bytes(&plaintext_with_len(249))
        .expect("encrypt")
        .into_bytes();
    invalid_bucket.truncate(invalid_bucket.len() - 2);
    assert!(matches!(
        Encrypted::<OpaqueEncryptedKind>::try_from(invalid_bucket.as_slice()),
        Err(Error::InvalidEnvelopeLength { .. })
    ));

    assert!(matches!(
        keyset.encrypt_bytes(&vec![0_u8; MAX_PLAINTEXT_SIZE + 1]),
        Err(Error::PlaintextTooLarge { .. })
    ));
}

#[test]
fn truncation_and_extension_are_rejected() {
    let keyset = test_keyset(&[1]);
    let encrypted = keyset
        .encrypt_bytes(&plaintext_with_len(249))
        .expect("encrypt")
        .into_bytes();

    for truncated_len in 0..encrypted.len() {
        assert!(
            keyset.decrypt_bytes(&encrypted[..truncated_len]).is_err(),
            "truncated length {truncated_len} decrypted successfully"
        );
    }

    let mut invalid_extension = encrypted.clone();
    invalid_extension.push(0);
    assert!(matches!(
        keyset.decrypt_bytes(&invalid_extension),
        Err(Error::InvalidEnvelopeLength { .. })
    ));

    let mut structurally_valid_extension = encrypted;
    structurally_valid_extension.resize(envelope_len_for_padded_payload_len(1024), 0);
    assert!(matches!(
        keyset.decrypt_bytes(&structurally_valid_extension),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn deterministic_fuzz_corpus_never_panics() {
    let keyset = test_keyset(&[1]);
    let mut rng = ChaCha20Rng::seed_from_u64(0x766f_726d_615f_7631);

    for len in parser_boundary_lengths() {
        let mut input = vec![0_u8; len];
        rng.fill_bytes(&mut input);
        exercise_untrusted_envelope_bytes(&input, &keyset);
    }

    for _ in 0..512 {
        let len = rng.random_range(0..=4096);
        let mut input = vec![0_u8; len];
        rng.fill_bytes(&mut input);
        exercise_untrusted_envelope_bytes(&input, &keyset);
    }

    for padded_payload_len in [MIN_PADDED_PAYLOAD_SIZE, 512, 1024, MAX_PADDED_PAYLOAD_SIZE] {
        let envelope_len = envelope_len_for_padded_payload_len(padded_payload_len);
        let mut input = vec![0_u8; envelope_len];
        rng.fill_bytes(&mut input);
        input[..MAGIC.len()].copy_from_slice(MAGIC);
        input[MAGIC.len()] = VERSION;
        input[MAGIC.len() + 1] = SUITE_PARANOID_V1;
        exercise_untrusted_envelope_bytes(&input, &keyset);
    }
}

#[test]
fn inner_ciphertext_authentication_failure_is_rejected() {
    let input_key = test_key(1);
    let key = derive_working_key_from_key32(&input_key, TEST_PURPOSE).expect("purpose key");
    let malformed = manually_encrypt_padded_payload(
        &key,
        &valid_test_padded_payload(b"secret"),
        &[],
        ManualEnvelopeMutation::TamperInnerCiphertext,
    );

    assert!(matches!(
        decrypt_with_key_and_associated_data(&malformed, &[], &key),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn padding_validation_rejects_noncanonical_plaintext_length() {
    let input_key = test_key(1);
    let key = derive_working_key_from_key32(&input_key, TEST_PURPOSE).expect("purpose key");
    let malformed = manually_encrypt_padded_payload(
        &key,
        &invalid_length_test_padded_payload(),
        &[],
        ManualEnvelopeMutation::None,
    );

    assert!(matches!(
        decrypt_with_key_and_associated_data(&malformed, &[], &key),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn deterministic_v1_fixtures_are_stable_and_decrypt() {
    let mut fixture_names = BTreeSet::new();

    for fixture_text in V1_FIXTURE_TEXTS {
        let fixture = V1Fixture::parse(fixture_text);
        assert!(
            fixture_names.insert(fixture.name.clone()),
            "duplicate fixture name {}",
            fixture.name
        );
        assert_eq!(fixture.input_key.len(), KEY_SIZE);

        let input_key = Key32::from_bytes(&fixture.input_key).expect("key");
        let key = derive_working_key_from_key32(&input_key, &fixture.purpose).expect("purpose key");
        let padded_payload = SecretBytes::from_slice(&fixture.padded_payload).expect("payload");
        let expected_padded_payload_len =
            padded_payload_len_for_plaintext_len(fixture.plaintext.len())
                .expect("padded payload length");

        assert_eq!(fixture.padded_payload.len(), expected_padded_payload_len);
        assert_eq!(
            fixture.inner_ciphertext.len(),
            expected_padded_payload_len + XCHACHA20_POLY1305_TAG_SIZE
        );
        assert_eq!(
            fixture.envelope.len(),
            envelope_len_for_padded_payload_len(expected_padded_payload_len)
        );

        let manual_output =
            manually_encrypt_padded_payload_with_components(ManualEncryptionInputs {
                key: &key,
                padded_payload: &padded_payload,
                associated_data: &fixture.associated_data,
                hkdf_salt: &fixture.hkdf_salt,
                blake3_salt: &fixture.blake3_salt,
                xchacha_nonce: &fixture.xchacha_nonce,
                aes_gcm_siv_nonce: &fixture.aes_gcm_siv_nonce,
                mutation: ManualEnvelopeMutation::None,
            });
        let parsed_envelope: Encrypted =
            Encrypted::try_from(fixture.envelope.as_slice()).expect("fixture envelope");
        let decrypted =
            decrypt_with_key_and_associated_data(&fixture.envelope, &fixture.associated_data, &key)
                .expect("decrypt");

        assert_eq!(
            manual_output.inner_ciphertext, fixture.inner_ciphertext,
            "{}",
            fixture.name
        );
        assert_eq!(manual_output.envelope, fixture.envelope, "{}", fixture.name);
        assert_eq!(
            parsed_envelope.as_bytes(),
            fixture.envelope,
            "{}",
            fixture.name
        );
        assert_eq!(
            sha256_hash_parts(&[&fixture.envelope]).as_bytes(),
            fixture.sha256_envelope.as_slice(),
            "{}",
            fixture.name
        );
        assert_eq!(
            blake3_hash_parts(&[&fixture.envelope]).as_bytes(),
            fixture.blake3_envelope.as_slice(),
            "{}",
            fixture.name
        );
        assert_eq!(
            decrypted.expose_secret(),
            fixture.plaintext,
            "{}",
            fixture.name
        );
    }

    assert_eq!(
        fixture_names,
        BTreeSet::from([
            "v1-vector-001".to_owned(),
            "v1-vector-002-empty".to_owned(),
            "v1-vector-003-248-byte".to_owned(),
            "v1-vector-004-249-byte".to_owned(),
            "v1-vector-005-505-byte".to_owned(),
        ])
    );
}

#[test]
fn deterministic_v1_invalid_fixtures_fail_as_expected() {
    let mut fixture_names = BTreeSet::new();

    for fixture_text in V1_INVALID_FIXTURE_TEXTS {
        let fixture = V1InvalidFixture::parse(fixture_text);
        assert!(
            fixture_names.insert(fixture.name.clone()),
            "duplicate invalid fixture name {}",
            fixture.name
        );

        let input_key = Key32::from_bytes(&fixture.input_key).expect("key");
        let key = derive_working_key_from_key32(&input_key, &fixture.purpose).expect("purpose key");
        let error =
            decrypt_with_key_and_associated_data(&fixture.envelope, &fixture.associated_data, &key)
                .expect_err("invalid fixture decrypted successfully");
        assert!(
            fixture.expected_error.matches_error(&error),
            "{} returned {error:?}, wanted {:?}",
            fixture.name,
            fixture.expected_error
        );

        let from_envelope_result: Result<Encrypted, Error> =
            Encrypted::try_from(fixture.envelope.as_slice());
        if fixture.expected_error.is_structurally_valid_envelope() {
            assert!(
                from_envelope_result.is_ok(),
                "{} should parse as a structurally valid envelope",
                fixture.name
            );
        } else {
            assert!(
                from_envelope_result.is_err(),
                "{} should fail public envelope parsing",
                fixture.name
            );
        }
    }

    assert_eq!(
        fixture_names,
        BTreeSet::from([
            "v1-invalid-001-empty-envelope".to_owned(),
            "v1-invalid-002-bad-magic".to_owned(),
            "v1-invalid-003-unsupported-version".to_owned(),
            "v1-invalid-004-unsupported-suite".to_owned(),
            "v1-invalid-005-truncated".to_owned(),
            "v1-invalid-006-odd-extension".to_owned(),
            "v1-invalid-007-ciphertext-tampered".to_owned(),
            "v1-invalid-008-wrong-associated-data".to_owned(),
        ])
    );
}
