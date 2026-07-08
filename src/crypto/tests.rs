use super::*;

fn test_key(byte: u8) -> Key32 {
    Key32::from_bytes(&[byte; KEY_SIZE]).expect("key")
}

#[test]
fn key32_validates_length_and_copies_input() {
    let mut bytes = [7_u8; KEY_SIZE];
    let key = Key32::from_bytes(&bytes).expect("key");
    bytes[0] = 9;

    assert_eq!(key.as_bytes()[0], 7);
    assert!(matches!(
        Key32::from_bytes(&bytes[..KEY_SIZE - 1]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        Key32::from_bytes(&[0_u8; KEY_SIZE + 1]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
}

#[test]
fn key32_debug_redacts_secret_bytes() {
    let key = test_key(1);
    let debug = format!("{key:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("01"));
}

#[test]
fn key32_equality_compares_secret_bytes() {
    assert_eq!(test_key(1), test_key(1));
    assert_ne!(test_key(1), test_key(2));
}

#[test]
fn secret_bytes_owns_and_redacts_secret_buffer() {
    let mut secret: SecretBytes = SecretBytes::from_slice(b"secret").expect("secret");
    assert_eq!(secret.expose_secret(), b"secret");
    secret.expose_secret_mut()[0] = b'S';
    assert_eq!(secret.expose_secret(), b"Secret");

    let debug = format!("{secret:?}");
    assert!(debug.contains("len"));
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("Secret\""));

    let random: SecretBytes = SecretBytes::random(32).expect("random");
    assert_eq!(random.len(), 32);
    assert!(!random.is_empty());
}

#[test]
fn sha256_hash_matches_known_answer() {
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    assert_eq!(sha256_hash_parts(&[b"abc"]).as_bytes(), &expected);
    assert_eq!(sha256_hash_parts(&[b"a", b"b", b"c"]).as_bytes(), &expected);
}

#[test]
fn blake3_hash_matches_known_answer() {
    let expected = [
        0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d,
        0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd,
        0x9d, 0x85,
    ];

    assert_eq!(blake3_hash_parts(&[b"abc"]).as_bytes(), &expected);
    assert_eq!(blake3_hash_parts(&[b"a", b"b", b"c"]).as_bytes(), &expected);
}

#[test]
fn hkdf_sha256_matches_independent_test_vector() {
    let mut input_key_material = [0_u8; KEY_SIZE];
    for (index, byte) in input_key_material.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let key = Key32::from_bytes(&input_key_material).expect("key");
    let expected = [
        0xdf, 0x94, 0xa6, 0xd7, 0xe3, 0x4e, 0xff, 0xd1, 0xda, 0xbc, 0x58, 0xbb, 0x54, 0x15, 0xc3,
        0x53, 0x17, 0x3d, 0x42, 0x09, 0x46, 0x73, 0x75, 0x26, 0xad, 0x9a, 0x10, 0xaf, 0x34, 0xe0,
        0xb8, 0x73,
    ];

    let derived = derive_hkdf_sha256(&key, b"application", b"purpose").expect("derived");

    assert_eq!(derived.as_bytes(), &expected);
}

#[test]
fn password_kdf_salt_validates_length_and_copies_input() {
    let mut salt_bytes = [7_u8; PASSWORD_KDF_SALT_SIZE];
    let salt = PasswordKdfSalt::from_bytes(&salt_bytes).expect("salt");
    salt_bytes[0] = 9;

    assert_eq!(salt.as_bytes()[0], 7);
    assert!(matches!(
        PasswordKdfSalt::from_bytes(&salt_bytes[..PASSWORD_KDF_SALT_SIZE - 1]),
        Err(Error::InvalidPasswordKdfSaltLength { .. })
    ));
    assert!(matches!(
        PasswordKdfSalt::from_bytes(&[0_u8; PASSWORD_KDF_SALT_SIZE + 1]),
        Err(Error::InvalidPasswordKdfSaltLength { .. })
    ));

    let generated = PasswordKdfSalt::generate().expect("generated salt");
    assert_eq!(generated.as_bytes().len(), PASSWORD_KDF_SALT_SIZE);
}

#[test]
fn password_kdf_params_validate_public_bounds() {
    assert_eq!(
        PasswordKdfParams::default(),
        PasswordKdfParams::interactive_default()
    );
    assert_eq!(
        PasswordKdfParams::interactive_default().memory_cost_kib(),
        PASSWORD_KDF_DEFAULT_MEMORY_COST_KIB
    );
    assert_eq!(
        PasswordKdfParams::interactive_default().iterations(),
        PASSWORD_KDF_DEFAULT_ITERATIONS
    );
    assert_eq!(
        PasswordKdfParams::interactive_default().parallelism(),
        PASSWORD_KDF_DEFAULT_PARALLELISM
    );

    assert!(matches!(
        PasswordKdfParams::new(
            PASSWORD_KDF_MIN_MEMORY_COST_KIB - 1,
            PASSWORD_KDF_MIN_ITERATIONS,
            1,
        ),
        Err(Error::PasswordKdfMemoryCostTooSmall { .. })
    ));
    assert!(matches!(
        PasswordKdfParams::new(
            PASSWORD_KDF_MIN_MEMORY_COST_KIB,
            PASSWORD_KDF_MIN_ITERATIONS - 1,
            1
        ),
        Err(Error::PasswordKdfIterationsTooFew { .. })
    ));
    assert!(matches!(
        PasswordKdfParams::new(
            PASSWORD_KDF_MIN_MEMORY_COST_KIB,
            PASSWORD_KDF_MIN_ITERATIONS,
            0
        ),
        Err(Error::PasswordKdfParallelismInvalid { .. })
    ));
    assert!(matches!(
        PasswordKdfParams::new(
            PASSWORD_KDF_MIN_MEMORY_COST_KIB,
            PASSWORD_KDF_MIN_ITERATIONS,
            PASSWORD_KDF_MAX_PARALLELISM + 1,
        ),
        Err(Error::PasswordKdfParallelismInvalid { .. })
    ));
    assert_eq!(
        PasswordKdfParams::new(
            PASSWORD_KDF_MIN_MEMORY_COST_KIB,
            PASSWORD_KDF_MIN_ITERATIONS,
            1
        )
        .expect("params"),
        PasswordKdfParams {
            memory_cost_kib: PASSWORD_KDF_MIN_MEMORY_COST_KIB,
            iterations: PASSWORD_KDF_MIN_ITERATIONS,
            parallelism: 1,
        }
    );
}

#[test]
fn argon2id_password_kdf_is_deterministic_and_domain_separated_by_salt_and_params() {
    let password: SecretBytes =
        SecretBytes::try_from(b"correct horse battery staple".as_slice()).expect("password bytes");
    let first_salt = PasswordKdfSalt::from_bytes(&[1_u8; PASSWORD_KDF_SALT_SIZE]).expect("salt");
    let second_salt = PasswordKdfSalt::from_bytes(&[2_u8; PASSWORD_KDF_SALT_SIZE]).expect("salt");
    let first_params = PasswordKdfParams::new_for_tests(8, 1, 1);
    let second_params = PasswordKdfParams::new_for_tests(16, 1, 1);

    let first =
        derive_argon2id_key32_from_password(&password, &first_salt, first_params).expect("key");
    let first_again =
        derive_argon2id_key32_from_password(&password, &first_salt, first_params).expect("key");
    let different_salt =
        derive_argon2id_key32_from_password(&password, &second_salt, first_params).expect("key");
    let different_params =
        derive_argon2id_key32_from_password(&password, &first_salt, second_params).expect("key");

    assert_eq!(first, first_again);
    assert_ne!(first, different_salt);
    assert_ne!(first, different_params);
}

#[test]
fn blake3_derive_key_separates_contexts_and_key_material() {
    let key_material = b"high entropy key material";
    let first_context = "paranoid test 2026-05-19 first";
    let second_context = "paranoid test 2026-05-19 second";

    let first = derive_blake3_key(first_context, key_material);
    let first_again = derive_blake3_key(first_context, key_material);
    let second = derive_blake3_key(second_context, key_material);
    let different_material = derive_blake3_key(first_context, b"different key material");

    assert_eq!(first, first_again);
    assert_ne!(first, second);
    assert_ne!(first, different_material);
}

#[test]
fn constant_time_eq_32_reports_equality() {
    let left = [1_u8; HASH_SIZE];
    let same = [1_u8; HASH_SIZE];
    let different = [2_u8; HASH_SIZE];

    assert!(constant_time_eq_32(&left, &same));
    assert!(!constant_time_eq_32(&left, &different));
}

#[test]
fn xchacha20_poly1305_round_trips_with_associated_data() {
    let key = test_key(1);
    let nonce = [2_u8; XCHACHA20_POLY1305_NONCE_SIZE];
    let associated_data = b"header";
    let plaintext = b"secret";

    let ciphertext =
        encrypt_xchacha20_poly1305(&key, &nonce, associated_data, plaintext).expect("encrypt");
    let decrypted =
        decrypt_xchacha20_poly1305(&key, &nonce, associated_data, &ciphertext).expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_ne!(ciphertext, plaintext);
}

#[test]
fn xchacha20_poly1305_rejects_wrong_key_and_tampering() {
    let key = test_key(1);
    let wrong_key = test_key(2);
    let nonce = [3_u8; XCHACHA20_POLY1305_NONCE_SIZE];
    let ciphertext =
        encrypt_xchacha20_poly1305(&key, &nonce, b"header", b"secret").expect("encrypt");

    assert!(matches!(
        decrypt_xchacha20_poly1305(&wrong_key, &nonce, b"header", &ciphertext),
        Err(CryptoError::DecryptionFailed)
    ));
    assert!(matches!(
        decrypt_xchacha20_poly1305(&key, &nonce, b"other header", &ciphertext),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut tampered = ciphertext;
    let last_index = tampered.len() - 1;
    tampered[last_index] ^= 0x01;
    assert!(matches!(
        decrypt_xchacha20_poly1305(&key, &nonce, b"header", &tampered),
        Err(CryptoError::DecryptionFailed)
    ));
}

#[test]
fn aes_256_gcm_siv_matches_rfc8452_empty_message_vector() {
    let mut key_bytes = [0_u8; KEY_SIZE];
    key_bytes[0] = 0x01;
    let key = Key32::from_bytes(&key_bytes).expect("key");
    let mut nonce = [0_u8; AES_256_GCM_SIV_NONCE_SIZE];
    nonce[0] = 0x03;
    let expected = [
        0x07, 0xf5, 0xf4, 0x16, 0x9b, 0xbf, 0x55, 0xa8, 0x40, 0x0c, 0xd4, 0x7e, 0xa6, 0xfd, 0x40,
        0x0f,
    ];

    let ciphertext = encrypt_aes_256_gcm_siv(&key, &nonce, b"", b"").expect("encrypt");
    let plaintext = decrypt_aes_256_gcm_siv(&key, &nonce, b"", &ciphertext).expect("decrypt");

    assert_eq!(ciphertext, expected);
    assert!(plaintext.is_empty());
}

#[test]
fn aes_256_gcm_siv_round_trips_with_associated_data() {
    let key = test_key(1);
    let nonce = [2_u8; AES_256_GCM_SIV_NONCE_SIZE];
    let associated_data = b"header";
    let plaintext = b"secret";

    let ciphertext =
        encrypt_aes_256_gcm_siv(&key, &nonce, associated_data, plaintext).expect("encrypt");
    let decrypted =
        decrypt_aes_256_gcm_siv(&key, &nonce, associated_data, &ciphertext).expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_ne!(ciphertext, plaintext);
}

#[test]
fn aes_256_gcm_siv_rejects_wrong_key_and_tampering() {
    let key = test_key(1);
    let wrong_key = test_key(2);
    let nonce = [3_u8; AES_256_GCM_SIV_NONCE_SIZE];
    let ciphertext = encrypt_aes_256_gcm_siv(&key, &nonce, b"header", b"secret").expect("encrypt");

    assert!(matches!(
        decrypt_aes_256_gcm_siv(&wrong_key, &nonce, b"header", &ciphertext),
        Err(CryptoError::DecryptionFailed)
    ));
    assert!(matches!(
        decrypt_aes_256_gcm_siv(&key, &nonce, b"other header", &ciphertext),
        Err(CryptoError::DecryptionFailed)
    ));

    let mut tampered = ciphertext;
    let last_index = tampered.len() - 1;
    tampered[last_index] ^= 0x01;
    assert!(matches!(
        decrypt_aes_256_gcm_siv(&key, &nonce, b"header", &tampered),
        Err(CryptoError::DecryptionFailed)
    ));
}

#[test]
fn random_array_returns_requested_size() {
    let bytes = random_array::<XCHACHA20_POLY1305_NONCE_SIZE>().expect("random");
    assert_eq!(bytes.len(), XCHACHA20_POLY1305_NONCE_SIZE);
}

#[test]
fn public_random_error_exposes_getrandom_source() {
    let error = Error::from(CryptoError::Random(getrandom::Error::UNSUPPORTED));
    let source = <Error as std::error::Error>::source(&error).expect("getrandom source");

    assert_eq!(
        source.to_string(),
        getrandom::Error::UNSUPPORTED.to_string()
    );
    assert_eq!(
        match error {
            Error::Random(random_error) => random_error.getrandom_error().to_string(),
            other => panic!("unexpected error: {other}"),
        },
        getrandom::Error::UNSUPPORTED.to_string()
    );
}

fn counting_fill(counter: &mut u8) -> impl FnMut(&mut [u8]) -> Result<(), Error> + '_ {
    move |bytes: &mut [u8]| {
        for byte in bytes.iter_mut() {
            *byte = *counter;
            *counter = counter.wrapping_add(1);
        }
        Ok(())
    }
}

#[test]
fn object_record_seals_opens_and_reports_exact_overhead() {
    let key = test_key(3);
    for plaintext in [&b""[..], &b"x"[..], &[0xab_u8; 100_000][..]] {
        let mut counter = 0_u8;
        let record = seal_object_record(
            &key,
            7,
            0x01,
            b"suffix",
            plaintext,
            counting_fill(&mut counter),
        )
        .expect("seal");
        assert_eq!(record.len(), plaintext.len() + OBJECT_RECORD_OVERHEAD);

        let header = parse_object_record_header(&record).expect("header");
        assert_eq!(header.version(), OBJECT_RECORD_VERSION);
        assert_eq!(header.key_generation(), 7);

        let opened = open_object_record(&key, &record, 0x01, b"suffix").expect("open");
        assert_eq!(opened.as_slice(), plaintext);
    }
}

#[test]
fn object_record_is_deterministic_given_fill_and_varies_with_nonce() {
    let key = test_key(4);
    let mut counter_a = 0_u8;
    let mut counter_b = 0_u8;
    let record_a = seal_object_record(
        &key,
        0,
        0x02,
        b"s",
        b"payload",
        counting_fill(&mut counter_a),
    )
    .expect("seal a");
    let record_b = seal_object_record(
        &key,
        0,
        0x02,
        b"s",
        b"payload",
        counting_fill(&mut counter_b),
    )
    .expect("seal b");
    assert_eq!(record_a, record_b);

    let mut counter_c = 100_u8;
    let record_c = seal_object_record(
        &key,
        0,
        0x02,
        b"s",
        b"payload",
        counting_fill(&mut counter_c),
    )
    .expect("seal c");
    assert_ne!(record_a, record_c);
}

#[test]
fn object_record_rejects_every_tampered_region_and_mismatched_inputs() {
    let key = test_key(5);
    let mut counter = 0_u8;
    let record = seal_object_record(
        &key,
        9,
        0x01,
        b"addr+domain",
        b"object bytes",
        counting_fill(&mut counter),
    )
    .expect("seal");

    for index in [1_usize, 5, 20, 30, record.len() - 1] {
        let mut tampered = record.clone();
        tampered[index] ^= 0x01;
        assert!(
            open_object_record(&key, &tampered, 0x01, b"addr+domain").is_err(),
            "tampered byte {index} must fail"
        );
    }

    let mut wrong_version = record.clone();
    wrong_version[0] = 2;
    assert!(matches!(
        parse_object_record_header(&wrong_version),
        Err(Error::UnsupportedObjectRecordVersion { version: 2 })
    ));
    assert!(open_object_record(&key, &wrong_version, 0x01, b"addr+domain").is_err());

    assert!(open_object_record(&key, &record, 0x02, b"addr+domain").is_err());
    assert!(open_object_record(&key, &record, 0x01, b"addr+domain!").is_err());
    assert!(open_object_record(&test_key(6), &record, 0x01, b"addr+domain").is_err());
}

#[test]
fn object_record_enforces_length_bounds_before_decryption() {
    assert!(matches!(
        parse_object_record_header(&[1_u8; OBJECT_RECORD_OVERHEAD - 1]),
        Err(Error::ObjectRecordTooShort { .. })
    ));
    let oversized = vec![1_u8; MAX_OBJECT_RECORD_SIZE + 1];
    assert!(matches!(
        parse_object_record_header(&oversized),
        Err(Error::ObjectRecordTooLarge { .. })
    ));

    let key = test_key(7);
    let too_large_plaintext = vec![0_u8; MAX_OBJECT_RECORD_PLAINTEXT_SIZE + 1];
    let mut counter = 0_u8;
    assert!(matches!(
        seal_object_record(
            &key,
            0,
            0x01,
            b"",
            &too_large_plaintext,
            counting_fill(&mut counter)
        ),
        Err(Error::PlaintextTooLarge { .. })
    ));
}

#[test]
fn object_record_propagates_injected_random_failure() {
    let key = test_key(8);
    let result = seal_object_record(&key, 0, 0x01, b"", b"payload", |_| {
        Err(Error::InjectedRandomFillFailed)
    });
    assert!(matches!(result, Err(Error::InjectedRandomFillFailed)));
}

#[test]
fn pad_bucket_len_matches_spec_rule() {
    for (input, expected) in [
        (0_usize, 512_usize),
        (1, 512),
        (511, 512),
        (512, 512),
        (513, 1024),
        (65_536, 65_536),
        (65_537, 131_072),
        (
            MAX_OBJECT_RECORD_PLAINTEXT_SIZE,
            MAX_OBJECT_RECORD_PLAINTEXT_SIZE,
        ),
    ] {
        assert_eq!(
            pad_bucket_len(input).expect("bucket"),
            expected,
            "input {input}"
        );
    }
    assert!(matches!(
        pad_bucket_len(MAX_OBJECT_RECORD_PLAINTEXT_SIZE + 1),
        Err(Error::PlaintextTooLarge { .. })
    ));
}

#[test]
fn blake3_keyed_hash_xof_prefix_matches_fixed_output_and_stream_does_not_repeat() {
    let key = test_key(9);
    let fixed = blake3_keyed_hash32(&key, b"gear table input");

    let mut xof = [0_u8; 2048];
    blake3_keyed_hash_xof_into(&key, b"gear table input", &mut xof);
    assert_eq!(&xof[..32], &fixed);
    assert_ne!(&xof[32..64], &xof[..32]);

    let mut xof_again = [0_u8; 2048];
    blake3_keyed_hash_xof_into(&key, b"gear table input", &mut xof_again);
    assert_eq!(xof, xof_again);
}

#[test]
fn derive_blake3_key32_is_deterministic_and_context_separated() {
    let material = test_key(10);
    let key_a = derive_blake3_key32("paranoid.test.context.a", &material);
    let key_b = derive_blake3_key32("paranoid.test.context.a", &material);
    let key_c = derive_blake3_key32("paranoid.test.context.b", &material);
    assert_eq!(key_a, key_b);
    assert_ne!(key_a, key_c);
    assert_ne!(key_a.expose_secret(), material.expose_secret());
}

#[test]
fn envelope_encrypt_with_random_fill_roundtrips_and_propagates_failure() {
    let keyset =
        derive_keyset_from_latest_first_keys([test_key(11)], "test-envelope-fill").expect("keyset");
    let plaintext: SecretBytes = SecretBytes::from_slice(b"sans-io payload").expect("plaintext");

    let mut counter = 0_u8;
    let encrypted =
        encrypt_with_random_fill(&keyset, &plaintext, b"ctx", counting_fill(&mut counter))
            .expect("encrypt");
    let decrypted: SecretBytes = decrypt(&keyset, &encrypted, b"ctx").expect("decrypt");
    assert_eq!(decrypted.expose_secret(), b"sans-io payload");

    let failed = encrypt_with_random_fill(&keyset, &plaintext, b"ctx", |_| {
        Err(Error::InjectedRandomFillFailed)
    });
    assert!(matches!(failed, Err(Error::InjectedRandomFillFailed)));
}

#[test]
fn password_sealed_key32_roundtrips_and_rejects_wrong_password_and_tampering() {
    let key = test_key(12);
    let password: SecretBytes = SecretBytes::from_slice(b"correct horse").expect("password");
    let params = PasswordKdfParams::new_for_tests(19 * 1024, 2, 1);

    let mut counter = 0_u8;
    let record = seal_key32_with_password(&key, &password, params, counting_fill(&mut counter))
        .expect("seal");
    assert_eq!(record.len(), PASSWORD_SEALED_KEY32_RECORD_SIZE);
    assert_eq!(record[0], PASSWORD_SEALED_KEY32_VERSION);

    let opened = open_key32_with_password(&record, &password).expect("open");
    assert_eq!(opened, key);
    assert_eq!(
        read_password_sealed_key32_params(&record).expect("params"),
        params
    );

    let wrong: SecretBytes = SecretBytes::from_slice(b"incorrect horse").expect("password");
    assert!(matches!(
        open_key32_with_password(&record, &wrong),
        Err(Error::DecryptionFailed)
    ));

    for index in [1_usize, 40, 50, record.len() - 1] {
        let mut tampered = record.clone();
        tampered[index] ^= 0x01;
        assert!(
            open_key32_with_password(&tampered, &password).is_err(),
            "tampered byte {index} must fail"
        );
    }

    let mut wrong_version = record.clone();
    wrong_version[0] = 2;
    assert!(matches!(
        open_key32_with_password(&wrong_version, &password),
        Err(Error::UnsupportedPasswordSealedKeyVersion { version: 2 })
    ));

    assert!(matches!(
        open_key32_with_password(&record[..record.len() - 1], &password),
        Err(Error::InvalidPasswordSealedKeyLength { .. })
    ));
}

#[test]
fn password_sealed_key32_rejects_out_of_range_params_before_kdf_work() {
    let key = test_key(13);
    let password: SecretBytes = SecretBytes::from_slice(b"pw").expect("password");
    let params = PasswordKdfParams::new_for_tests(19 * 1024, 2, 1);
    let mut counter = 0_u8;
    let mut record = seal_key32_with_password(&key, &password, params, counting_fill(&mut counter))
        .expect("seal");

    // Forge an absurd memory cost: rejected as out-of-range before any KDF
    // pass (this test would take effectively forever if the KDF ran).
    record[33..37].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        open_key32_with_password(&record, &password),
        Err(Error::PasswordSealedKeyParamsOutOfRange)
    ));
    assert!(matches!(
        read_password_sealed_key32_params(&record),
        Err(Error::PasswordSealedKeyParamsOutOfRange)
    ));
}

#[test]
fn password_sealed_key32_caller_salt_roundtrips_and_rejects_wrong_password_wrong_salt_and_tampering()
 {
    let key = test_key(20);
    let password: SecretBytes = SecretBytes::from_slice(b"correct horse").expect("password");
    let caller_salt = test_key(21);
    let params = PasswordKdfParams::new_for_tests(19 * 1024, 2, 1);

    let mut counter = 0_u8;
    let record = seal_key32_with_password_and_caller_salt(
        &key,
        &password,
        &caller_salt,
        params,
        counting_fill(&mut counter),
    )
    .expect("seal");
    assert_eq!(record.len(), PASSWORD_SEALED_KEY32_CALLER_SALT_RECORD_SIZE);
    assert_eq!(record[0], PASSWORD_SEALED_KEY32_CALLER_SALT_VERSION);

    let opened =
        open_key32_with_password_and_caller_salt(&record, &password, &caller_salt).expect("open");
    assert_eq!(opened, key);
    assert_eq!(
        read_password_sealed_key32_caller_salt_params(&record).expect("params"),
        params
    );

    let wrong_password: SecretBytes = SecretBytes::from_slice(b"incorrect horse").expect("wrong");
    assert!(matches!(
        open_key32_with_password_and_caller_salt(&record, &wrong_password, &caller_salt),
        Err(Error::DecryptionFailed)
    ));

    let wrong_salt = test_key(22);
    assert!(matches!(
        open_key32_with_password_and_caller_salt(&record, &password, &wrong_salt),
        Err(Error::DecryptionFailed)
    ));

    for index in [1_usize, 13, 20, record.len() - 1] {
        let mut tampered = record.clone();
        tampered[index] ^= 0x01;
        assert!(
            open_key32_with_password_and_caller_salt(&tampered, &password, &caller_salt).is_err(),
            "tampered byte {index} must fail"
        );
    }

    let mut wrong_version = record.clone();
    wrong_version[0] = 3;
    assert!(matches!(
        open_key32_with_password_and_caller_salt(&wrong_version, &password, &caller_salt),
        Err(Error::UnsupportedPasswordSealedKeyVersion { version: 3 })
    ));

    assert!(matches!(
        open_key32_with_password_and_caller_salt(
            &record[..record.len() - 1],
            &password,
            &caller_salt
        ),
        Err(Error::InvalidPasswordSealedKeyLength { .. })
    ));
}

#[test]
fn password_sealed_key32_caller_salt_rejects_out_of_range_params_before_kdf_work() {
    let key = test_key(23);
    let password: SecretBytes = SecretBytes::from_slice(b"pw").expect("password");
    let caller_salt = test_key(24);
    let params = PasswordKdfParams::new_for_tests(19 * 1024, 2, 1);
    let mut counter = 0_u8;
    let mut record = seal_key32_with_password_and_caller_salt(
        &key,
        &password,
        &caller_salt,
        params,
        counting_fill(&mut counter),
    )
    .expect("seal");

    // Forge an absurd memory cost: rejected as out-of-range before any KDF
    // pass (this test would take effectively forever if the KDF ran).
    record[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        open_key32_with_password_and_caller_salt(&record, &password, &caller_salt),
        Err(Error::PasswordSealedKeyParamsOutOfRange)
    ));
    assert!(matches!(
        read_password_sealed_key32_caller_salt_params(&record),
        Err(Error::PasswordSealedKeyParamsOutOfRange)
    ));
}

#[test]
fn password_sealed_key32_stored_and_caller_salt_shapes_are_mutually_exclusive() {
    let key = test_key(25);
    let password: SecretBytes = SecretBytes::from_slice(b"shared password").expect("password");
    let caller_salt = test_key(26);
    let params = PasswordKdfParams::new_for_tests(19 * 1024, 2, 1);

    let mut counter_a = 0_u8;
    let stored_salt_record =
        seal_key32_with_password(&key, &password, params, counting_fill(&mut counter_a))
            .expect("seal stored-salt");

    let mut counter_b = 0_u8;
    let caller_salt_record = seal_key32_with_password_and_caller_salt(
        &key,
        &password,
        &caller_salt,
        params,
        counting_fill(&mut counter_b),
    )
    .expect("seal caller-salt");

    assert_ne!(stored_salt_record.len(), caller_salt_record.len());
    assert_ne!(stored_salt_record[0], caller_salt_record[0]);

    assert!(matches!(
        open_key32_with_password_and_caller_salt(&stored_salt_record, &password, &caller_salt),
        Err(Error::InvalidPasswordSealedKeyLength { .. })
    ));
    assert!(matches!(
        open_key32_with_password(&caller_salt_record, &password),
        Err(Error::InvalidPasswordSealedKeyLength { .. })
    ));
}
