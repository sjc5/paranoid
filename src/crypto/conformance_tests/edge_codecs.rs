use super::*;

#[test]
fn explicit_base64url_codec_handles_keys_and_envelopes() {
    let first_key_text = TEST_BASE64_URL_SAFE_NO_PAD.encode([1_u8; KEY_SIZE]);
    let second_key_text = TEST_BASE64_URL_SAFE_NO_PAD.encode([2_u8; KEY_SIZE]);
    let first_key: Key32 = Base64Url::parse_str(first_key_text.as_str())
        .expect("parse first key")
        .decode()
        .expect("first key");
    let second_key: Key32 = Base64Url::parse_str(second_key_text.as_str())
        .expect("parse second key")
        .decode()
        .expect("second key");
    let keyset =
        derive_keyset_from_latest_first_keys([first_key, second_key], "paranoid.cookies.v1")
            .expect("cookie keyset");

    let encrypted = keyset.encrypt_bytes(b"secret").expect("encrypt");
    let encoded = encrypted.to_base64_url().expect("encode encrypted");
    let decoded: Encrypted = Base64Url::parse_str(encoded.as_str())
        .expect("parse encrypted")
        .decode()
        .expect("decode");
    let decrypted = keyset.decrypt_bytes(decoded.as_bytes()).expect("decrypt");

    assert_eq!(keyset.key_count(), 2);
    assert_eq!(decoded.as_bytes(), encrypted.as_bytes());
    assert_eq!(decrypted.expose_secret(), b"secret");
    assert!(matches!(
        Base64Url::<Key32>::parse_str("not base64"),
        Err(Error::EncodingDecode { codec, .. }) if codec == BASE64URL_CODEC_NAME
    ));
    assert!(matches!(
        Base64Url::<Encrypted>::parse_str("not base64"),
        Err(Error::EncodingDecode { codec, .. }) if codec == BASE64URL_CODEC_NAME
    ));
}

#[test]
fn edge_codecs_round_trip_typed_byte_containers() {
    enum PublicKind {}
    enum SecretKind {}

    let public = PublicBytes::<PublicKind>::from_slice(b"hello world").expect("public bytes");
    let public_base64 = public.to_base64_url().expect("public base64url");
    let public_crockford = public.to_crockford_base32().expect("public crockford");
    let public_base58 = public.to_base58().expect("public base58");
    let public_mnemonic = public.to_mnemonic().expect("public mnemonic");

    assert_eq!(public_base64.as_str(), "aGVsbG8gd29ybGQ");
    assert_eq!(public_crockford.as_str(), "D1JPRV3F41VPYWKCCG");
    assert_eq!(public_base58.as_str(), "StV1DL6CwTryKyV");
    assert_eq!(
        public_mnemonic.as_str(),
        "abandon half clock brand tattoo alter response situate milk treat supreme"
    );
    assert_eq!(
        public
            .to_base64_url()
            .expect("public base64url")
            .into_exposed_string(),
        "aGVsbG8gd29ybGQ"
    );
    assert_eq!(
        Base64Url::<PublicBytes<PublicKind>>::parse_str(public_base64.as_str())
            .expect("parse base64url")
            .decode()
            .expect("decode base64url")
            .as_bytes(),
        b"hello world"
    );
    assert_eq!(
        CrockfordBase32::<PublicBytes<PublicKind>>::parse_str(public_crockford.as_str())
            .expect("parse crockford")
            .decode()
            .expect("decode crockford")
            .as_bytes(),
        b"hello world"
    );
    assert_eq!(
        Base58::<PublicBytes<PublicKind>>::parse_str(public_base58.as_str())
            .expect("parse base58")
            .decode()
            .expect("decode base58")
            .as_bytes(),
        b"hello world"
    );
    assert_eq!(
        Mnemonic::<PublicBytes<PublicKind>>::parse_str(public_mnemonic.as_str())
            .expect("parse mnemonic")
            .decode()
            .expect("decode mnemonic")
            .as_bytes(),
        b"hello world"
    );

    let secret = SecretBytes::<SecretKind>::from_slice(b"hello").expect("secret bytes");
    let secret_base64 = secret.to_base64_url().expect("secret base64url");
    let secret_crockford = secret.to_crockford_base32().expect("secret crockford");
    let secret_base58 = secret.to_base58().expect("secret base58");
    let secret_mnemonic = secret.to_mnemonic().expect("secret mnemonic");
    let other_secret = random_secret_bytes(32).expect("other secret");
    let other_secret_base64 = other_secret
        .to_base64_url()
        .expect("other secret base64url");
    let other_secret_crockford = other_secret
        .to_crockford_base32()
        .expect("other secret crockford");
    let other_secret_base58 = other_secret.to_base58().expect("other secret base58");
    let other_secret_mnemonic = other_secret.to_mnemonic().expect("other secret mnemonic");

    assert_eq!(secret_base64.as_str(), "aGVsbG8");
    assert_eq!(secret_crockford.as_str(), "D1JPRV3F");
    assert_eq!(secret_base58.as_str(), "Cn8eVZg");
    assert_eq!(
        secret_mnemonic.as_str(),
        "above half clock brand task plug finish"
    );
    assert_eq!(
        Base64Url::<SecretBytes<SecretKind>>::parse_str(secret_base64.as_str())
            .expect("parse base64url")
            .decode()
            .expect("decode base64url")
            .expose_secret(),
        b"hello"
    );
    assert_eq!(
        CrockfordBase32::<SecretBytes<SecretKind>>::parse_str(secret_crockford.as_str())
            .expect("parse crockford")
            .decode()
            .expect("decode crockford")
            .expose_secret(),
        b"hello"
    );
    assert_eq!(
        Base58::<SecretBytes<SecretKind>>::parse_str(secret_base58.as_str())
            .expect("parse base58")
            .decode()
            .expect("decode base58")
            .expose_secret(),
        b"hello"
    );
    assert_eq!(
        Mnemonic::<SecretBytes<SecretKind>>::parse_str(secret_mnemonic.as_str())
            .expect("parse mnemonic")
            .decode()
            .expect("decode mnemonic")
            .expose_secret(),
        b"hello"
    );
    assert_eq!(
        Base64Url::<SecretBytes>::parse_str(other_secret_base64.as_str())
            .expect("parse base64url secret")
            .decode()
            .expect("decode base64url secret")
            .expose_secret(),
        other_secret.expose_secret()
    );
    assert_eq!(
        CrockfordBase32::<SecretBytes>::parse_str(other_secret_crockford.as_str())
            .expect("parse crockford secret")
            .decode()
            .expect("decode crockford secret")
            .expose_secret(),
        other_secret.expose_secret()
    );
    assert_eq!(
        Base58::<SecretBytes>::parse_str(other_secret_base58.as_str())
            .expect("parse base58 secret")
            .decode()
            .expect("decode base58 secret")
            .expose_secret(),
        other_secret.expose_secret()
    );
    assert_eq!(
        Mnemonic::<SecretBytes>::parse_str(other_secret_mnemonic.as_str())
            .expect("parse mnemonic secret")
            .decode()
            .expect("decode mnemonic secret")
            .expose_secret(),
        other_secret.expose_secret()
    );
}

#[test]
fn mnemonic_codec_handles_arbitrary_secret_and_encrypted_bytes() {
    enum EntropyKind {}

    let key = Key32::try_from(&[0_u8; KEY32_SIZE][..]).expect("key");
    let encoded_key = key.to_mnemonic().expect("encode key");
    let decoded_key: Key32 = Mnemonic::parse_str(encoded_key.as_str())
        .expect("parse key")
        .decode()
        .expect("decode key");

    assert_eq!(decoded_key.expose_secret(), key.expose_secret());

    for size in [0, 1, 2, 3, 5, 16, 32, 33, 257] {
        let bytes = (0..size).map(|index| index as u8).collect::<Vec<_>>();
        let entropy = SecretBytes::<EntropyKind>::from_slice(&bytes).expect("entropy");
        let encoded_entropy = entropy.to_mnemonic().expect("encode entropy");
        let decoded_entropy: SecretBytes<EntropyKind> =
            Mnemonic::parse_str(encoded_entropy.as_str())
                .expect("parse entropy")
                .decode()
                .expect("decode entropy");

        assert_eq!(decoded_entropy.expose_secret(), bytes);
    }

    let keyset = test_keyset(&[7]);
    let encrypted = keyset.encrypt_bytes(b"ciphertext backup").expect("encrypt");
    let encoded_encrypted = encrypted.to_mnemonic().expect("encode encrypted");
    let decoded_encrypted: Encrypted = Mnemonic::parse_str(encoded_encrypted.as_str())
        .expect("parse encrypted")
        .decode()
        .expect("decode encrypted");
    let decrypted = keyset
        .decrypt_bytes(decoded_encrypted.as_bytes())
        .expect("decrypt");

    assert_eq!(decoded_encrypted.as_bytes(), encrypted.as_bytes());
    assert_eq!(decrypted.expose_secret(), b"ciphertext backup");
}

#[test]
fn edge_codecs_reject_noncanonical_or_invalid_text() {
    enum PublicKind {}

    assert!(matches!(
        Base64Url::<PublicBytes<PublicKind>>::parse_str("aGVsbG8="),
        Err(Error::EncodingDecode { codec, .. }) if codec == BASE64URL_CODEC_NAME
    ));
    assert!(matches!(
        CrockfordBase32::<PublicBytes<PublicKind>>::parse_str("d1jprv3f"),
        Err(Error::EncodingDecode { codec, .. }) if codec == CROCKFORD_BASE32_CODEC_NAME
    ));
    assert!(matches!(
        Base58::<PublicBytes<PublicKind>>::parse_str("0"),
        Err(Error::Base58Decode(_))
    ));

    let secret = SecretBytes::<PublicKind>::from_slice(b"hello").expect("secret");
    let encoded_mnemonic = secret.to_mnemonic().expect("encode mnemonic");
    let mut noncanonical_mnemonic = encoded_mnemonic.as_str().to_owned();
    noncanonical_mnemonic.replace_range(5..6, "  ");
    assert!(matches!(
        Mnemonic::<SecretBytes<PublicKind>>::parse_str(&noncanonical_mnemonic),
        Err(Error::NonCanonicalEncoding { codec }) if codec == MNEMONIC_CODEC_NAME
    ));
    assert!(matches!(
        Mnemonic::<SecretBytes<PublicKind>>::parse_str(""),
        Err(Error::EmptyMnemonic)
    ));
    assert!(matches!(
        Mnemonic::<SecretBytes<PublicKind>>::parse_str("abandon notaword ability"),
        Err(Error::UnknownMnemonicWord { index }) if index == 1
    ));

    let mut checksum_tampered = encoded_mnemonic
        .as_str()
        .split_whitespace()
        .collect::<Vec<_>>();
    checksum_tampered[1] = "abandon";
    let checksum_tampered = checksum_tampered.join(" ");
    assert!(matches!(
        Mnemonic::<SecretBytes<PublicKind>>::parse_str(&checksum_tampered),
        Err(Error::InvalidMnemonicChecksum)
    ));
}

#[test]
fn edge_codecs_reject_text_too_large_for_requested_type_before_decode() {
    assert!(matches!(
        Base64Url::<Key32>::parse_str("A".repeat(44).as_str()),
        Err(Error::EncodedTextTooLarge { codec, actual, max })
            if codec == BASE64URL_CODEC_NAME && actual == 44 && max == 43
    ));
    assert!(matches!(
        CrockfordBase32::<Key32>::parse_str("0".repeat(53).as_str()),
        Err(Error::EncodedTextTooLarge { codec, actual, max })
            if codec == CROCKFORD_BASE32_CODEC_NAME && actual == 53 && max == 52
    ));
    assert!(matches!(
        Base58::<Key32>::parse_str("1".repeat(47).as_str()),
        Err(Error::EncodedTextTooLarge { codec, actual, max })
            if codec == "base58" && actual == 47 && max == 46
    ));
    assert!(matches!(
        Base58::<Key32>::parse_str("1".repeat(KEY32_SIZE + 1).as_str()),
        Err(Error::DecodedBytesTooLarge { codec, actual, max })
            if codec == "base58" && actual == KEY32_SIZE + 1 && max == KEY32_SIZE
    ));

    let oversized_mnemonic = "abandon ".repeat(100);
    assert!(matches!(
        Mnemonic::<Key32>::parse_str(oversized_mnemonic.as_str()),
        Err(Error::EncodedTextTooLarge { codec, .. }) if codec == MNEMONIC_CODEC_NAME
    ));
}
