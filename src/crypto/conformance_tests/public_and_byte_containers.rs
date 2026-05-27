use super::*;

#[test]
fn public_v1_layout_constants_match_spec() {
    assert_eq!(HKDF_SALT_OFFSET, 6);
    assert_eq!(BLAKE3_SALT_OFFSET, 38);
    assert_eq!(XCHACHA_NONCE_OFFSET, 70);
    assert_eq!(AES_GCM_SIV_NONCE_OFFSET, 94);
    assert_eq!(HEADER_SIZE, 106);
    assert_eq!(MIN_ENVELOPE_SIZE, 394);
    assert_eq!(MAX_ENVELOPE_SIZE, 2_097_290);
    assert_eq!(MAX_ASSOCIATED_DATA_SIZE, 1_048_576);
    assert_eq!(MAX_BYTE_CONTAINER_SIZE, 1_048_576);
    assert_eq!(MAX_RANDOM_BYTES_SIZE, MAX_BYTE_CONTAINER_SIZE);
}

#[test]
fn random_keys_and_byte_containers_use_canonical_base64url() {
    let first_secret = random_secret_bytes(32).expect("secret");
    let second_secret = random_secret_bytes(32).expect("secret");
    let custom_secret = random_secret_bytes(17).expect("custom secret");
    let key = random_key32().expect("key");
    let first_secret_text = first_secret.to_base64_url().expect("encode secret");
    let second_secret_text = second_secret.to_base64_url().expect("encode secret");
    let decoded_first_secret: SecretBytes = Base64Url::parse_str(first_secret_text.as_str())
        .expect("parse secret")
        .decode()
        .expect("decode secret");
    let encoded_key = key.to_base64_url().expect("encode key");
    let decoded_key: Key32 = Base64Url::parse_str(encoded_key.as_str())
        .expect("parse key")
        .decode()
        .expect("decode key");

    assert_eq!(first_secret.len(), 32);
    assert_eq!(second_secret.len(), 32);
    assert_eq!(custom_secret.len(), 17);
    assert_eq!(key.expose_secret().len(), KEY32_SIZE);
    assert_eq!(decoded_key.expose_secret(), key.expose_secret());
    assert_eq!(
        decoded_first_secret.expose_secret(),
        first_secret.expose_secret()
    );
    assert_ne!(first_secret.expose_secret(), second_secret.expose_secret());
    assert_eq!(first_secret_text.as_str().len(), 43);
    assert_eq!(encoded_key.as_str().len(), 43);
    assert_ne!(first_secret_text.as_str(), second_secret_text.as_str());
    assert!(!first_secret_text.as_str().contains('='));
    assert!(!encoded_key.as_str().contains('='));
    assert!(format!("{encoded_key:?}").contains("encoded_len"));
    assert!(!format!("{encoded_key:?}").contains(encoded_key.as_str()));
    assert_eq!(
        TEST_BASE64_URL_SAFE_NO_PAD
            .decode(encoded_key.as_str())
            .expect("decode")
            .len(),
        KEY32_SIZE
    );
    assert!(matches!(
        random_secret_bytes(MAX_RANDOM_BYTES_SIZE + 1),
        Err(Error::RandomBytesTooLarge { .. })
    ));
    assert!(matches!(
        random_secret_bytes(0),
        Err(Error::RandomBytesLengthIsZero)
    ));
    assert!(matches!(
        random_public_bytes(0),
        Err(Error::RandomBytesLengthIsZero)
    ));
    assert!(matches!(
        Base64Url::<Key32>::parse_str("not base64"),
        Err(Error::EncodingDecode { codec, .. }) if codec == BASE64URL_CODEC_NAME
    ));
    assert!(matches!(
        Base64Url::<Key32>::parse_str(
            TEST_BASE64_URL_SAFE_NO_PAD.encode([1_u8; KEY_SIZE - 1]).as_str()
        )
        .expect("parse")
        .decode(),
        Err(Error::InvalidKey32Length { actual }) if actual == KEY_SIZE - 1
    ));
}

#[test]
fn keysets_accept_typed_key32_values() {
    let first_key = Key32::try_from(&[1_u8; KEY_SIZE][..]).expect("key");
    let second_key = Key32::try_from(&[2_u8; KEY_SIZE][..]).expect("key");
    let keyset =
        derive_keyset_from_latest_first_keys([second_key, first_key], "paranoid.test.typed-key")
            .expect("keyset");
    let encrypted = keyset.encrypt_bytes(b"typed key").expect("encrypt");
    let decrypted = keyset.decrypt_bytes(encrypted.as_bytes()).expect("decrypt");

    assert_eq!(keyset.key_count(), 2);
    assert_eq!(decrypted.expose_secret(), b"typed key");
}

#[test]
fn key32_import_export_vectors_are_stable_across_edge_codecs() {
    let key_bytes = (0_u8..KEY32_SIZE as u8).collect::<Vec<_>>();
    let key = Key32::try_from(key_bytes.as_slice()).expect("key");

    let base64 = key.to_base64_url().expect("base64url");
    let crockford = key.to_crockford_base32().expect("crockford");
    let base58 = key.to_base58().expect("base58");
    let mnemonic = key.to_mnemonic().expect("mnemonic");

    assert_eq!(
        base64.as_str(),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    );
    assert_eq!(
        crockford.as_str(),
        "000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG"
    );
    assert_eq!(
        base58.as_str(),
        "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"
    );
    assert_eq!(
        mnemonic.as_str(),
        "absurd abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey theme slim pull"
    );

    let decoded_base64: Key32 = Base64Url::parse_str(base64.as_str())
        .expect("parse base64")
        .decode()
        .expect("decode base64");
    let decoded_crockford: Key32 = CrockfordBase32::parse_str(crockford.as_str())
        .expect("parse crockford")
        .decode()
        .expect("decode crockford");
    let decoded_base58: Key32 = Base58::parse_str(base58.as_str())
        .expect("parse base58")
        .decode()
        .expect("decode base58");
    let decoded_mnemonic: Key32 = Mnemonic::parse_str(mnemonic.as_str())
        .expect("parse mnemonic")
        .decode()
        .expect("decode mnemonic");

    assert_eq!(decoded_base64.expose_secret(), key.expose_secret());
    assert_eq!(decoded_crockford.expose_secret(), key.expose_secret());
    assert_eq!(decoded_base58.expose_secret(), key.expose_secret());
    assert_eq!(decoded_mnemonic.expose_secret(), key.expose_secret());
}

#[test]
fn edge_codecs_validate_decoded_bytes_against_the_requested_type() {
    let key_bytes = (0_u8..KEY32_SIZE as u8).collect::<Vec<_>>();
    let key = Key32::try_from(key_bytes.as_slice()).expect("key");
    let key_text = key.to_base64_url().expect("key text");
    let keyset = test_keyset(&[1]);
    let secret: SecretBytes =
        SecretBytes::try_from(b"codec misuse secret".as_slice()).expect("secret");
    let mac = secret.to_mac(&keyset, b"codec misuse").expect("mac");
    let mac_text = mac.to_base64_url().expect("mac text");
    let encrypted = keyset.encrypt_bytes(b"codec misuse").expect("encrypt");
    let encrypted_text = encrypted.to_base64_url().expect("encrypted text");

    assert!(matches!(
        Base64Url::<MacOverSecret>::parse_str(key_text.as_str())
            .expect("parse key text")
            .decode(),
        Err(Error::InvalidMacOverSecretLength { actual }) if actual == KEY32_SIZE
    ));
    assert!(matches!(
        Base64Url::<Key32>::parse_str(mac_text.as_str()),
        Err(Error::EncodedTextTooLarge { codec, actual, max })
            if codec == BASE64URL_CODEC_NAME && actual == 44 && max == 43
    ));
    assert!(matches!(
        Base64Url::<MacOverSecret>::parse_str(encrypted_text.as_str()),
        Err(Error::EncodedTextTooLarge { codec, actual, max })
            if codec == BASE64URL_CODEC_NAME && actual > max
    ));
}

#[test]
fn public_bytes_preserve_non_secret_semantic_roles() {
    enum StoredMacKind {}
    enum DigestKind {}

    let stored_mac: PublicBytes<StoredMacKind> =
        PublicBytes::from_slice(b"stored mac").expect("stored mac");
    let digest: PublicBytes<DigestKind> = stored_mac.clone().with_kind();

    assert_eq!(stored_mac.as_bytes(), b"stored mac");
    assert_eq!(digest.as_bytes(), b"stored mac");
    assert!(format!("{stored_mac:?}").contains("len"));
}

#[test]
fn caller_provided_byte_containers_enforce_max_size() {
    let oversized = vec![0_u8; MAX_BYTE_CONTAINER_SIZE + 1];

    assert!(matches!(
        PublicBytes::<PublicBytesKind>::try_from(oversized.clone()),
        Err(Error::ByteContainerTooLarge { actual, max })
            if actual == MAX_BYTE_CONTAINER_SIZE + 1 && max == MAX_BYTE_CONTAINER_SIZE
    ));
    assert!(matches!(
        PublicBytes::<PublicBytesKind>::try_from(oversized.as_slice()),
        Err(Error::ByteContainerTooLarge { actual, max })
            if actual == MAX_BYTE_CONTAINER_SIZE + 1 && max == MAX_BYTE_CONTAINER_SIZE
    ));
    assert!(matches!(
        SecretBytes::<SecretBytesKind>::try_from(oversized.clone()),
        Err(Error::ByteContainerTooLarge { actual, max })
            if actual == MAX_BYTE_CONTAINER_SIZE + 1 && max == MAX_BYTE_CONTAINER_SIZE
    ));
    assert!(matches!(
        SecretBytes::<SecretBytesKind>::try_from(oversized.as_slice()),
        Err(Error::ByteContainerTooLarge { actual, max })
            if actual == MAX_BYTE_CONTAINER_SIZE + 1 && max == MAX_BYTE_CONTAINER_SIZE
    ));
}

#[test]
fn encrypted_bytes_preserve_semantic_payload_markers() {
    enum CookiePayloadKind {}

    let keyset = test_keyset(&[1]);
    let encrypted: Encrypted<CookiePayloadKind> =
        keyset.encrypt_bytes_as(b"cookie").expect("encrypt");
    let copied: Encrypted<CookiePayloadKind> =
        Encrypted::from_bytes_with_type(encrypted.as_bytes()).expect("copy");
    let encoded = copied.to_base64_url().expect("encode");
    let decoded: Encrypted<CookiePayloadKind> = Base64Url::parse_str(encoded.as_str())
        .expect("parse")
        .decode()
        .expect("decode");
    let decrypted: SecretBytes<CookiePayloadKind> = keyset
        .decrypt_encrypted_bytes(&decoded)
        .expect("typed decrypt");

    assert_eq!(decrypted.expose_secret(), b"cookie");
}
