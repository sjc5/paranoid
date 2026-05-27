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
