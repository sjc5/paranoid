use super::*;
use proptest::prelude::*;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct SecureBytesFixturePayload {
    user_id: u64,
    active: bool,
    roles: Vec<String>,
    login_count: Option<u32>,
    recovery_codes: Vec<[u8; 4]>,
}

fn secure_bytes_fixture_payload() -> SecureBytesFixturePayload {
    SecureBytesFixturePayload {
        user_id: 42,
        active: true,
        roles: vec!["admin".to_owned(), "billing".to_owned()],
        login_count: Some(7),
        recovery_codes: vec![[1, 2, 3, 4], [0xaa, 0xbb, 0xcc, 0xdd]],
    }
}

#[test]
fn typed_payloads_use_pinned_postcard_serialization_before_encryption() {
    let payload = secure_bytes_fixture_payload();
    let serialized = payload.to_plaintext_bytes().expect("serialize");
    let keyset = test_keyset(&[1]);
    let encrypted = encrypt(&keyset, &payload, b"typed payload").expect("encrypt typed payload");
    let decrypted: SecureBytesFixturePayload =
        decrypt(&keyset, &encrypted, b"typed payload").expect("decrypt typed payload");

    assert_eq!(
        BASE64_STANDARD.encode(serialized.expose_secret()),
        "KgECBWFkbWluB2JpbGxpbmcBBwIBAgMEqrvM3Q=="
    );
    assert_eq!(decrypted, payload);
    assert!(matches!(
        SecureBytesFixturePayload::from_plaintext_bytes(&[0xff]),
        Err(Error::PayloadDeserialize(_))
    ));
}

#[test]
fn typed_encrypt_rejects_oversized_serialized_payloads() {
    let keyset = test_keyset(&[1]);
    let oversized_payload = vec![0_u8; MAX_PLAINTEXT_SIZE + 1];

    assert!(matches!(
        encrypt(&keyset, &oversized_payload, b"oversized typed payload"),
        Err(Error::PlaintextTooLarge { actual, max })
            if actual > MAX_PLAINTEXT_SIZE && max == MAX_PLAINTEXT_SIZE
    ));
}

#[test]
fn typed_encrypted_payload_deterministic_vector_matches_postcard_then_envelope() {
    let payload = secure_bytes_fixture_payload();
    let serialized = payload.to_plaintext_bytes().expect("serialize");
    let key = derive_working_key_from_key32(&test_key(1), TEST_PURPOSE).expect("purpose key");
    let envelope = manually_encrypt_padded_payload(
        &key,
        &valid_test_padded_payload(serialized.expose_secret()),
        b"typed payload vector",
        ManualEnvelopeMutation::None,
    );
    let encrypted: Encrypted<SecureBytesFixturePayload> =
        Encrypted::try_from(envelope.as_slice()).expect("encrypted");
    let keyset = test_keyset(&[1]);
    let decrypted: SecureBytesFixturePayload =
        decrypt(&keyset, &encrypted, b"typed payload vector").expect("decrypt");

    assert_eq!(
        BASE64_STANDARD.encode(&envelope),
        "UEFSQQEBEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIjMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0RERERERERERERERGyU8asKG7APblvqD5ZjUeoReH914hLsmh9QRQaXMRzWtJSolFc8KMLljyq6+f2TXqtkCzaN9k3MZKaOESIK8scYhno6gOvH17+rBXatpUSPQ7i4ViDmHWprF6dGrqC+TSsx5SewMmkmjc6SiOz5qlchl8LJqcrKfHFrokg8qgNfUx9ZklKeJ+dOkE+WnDUinxeUHVImHwFw66q4Bl7aHyE2ieIbpNZ+zE1i6UNsZOBI5/QPl6WRUu3i4BF/ClunFxrF4gKxu029YmzMUjgMZiEJXorfWzkMNDs9GdNfn6/3GstZZHKQ+PQpXgmxkxBBScf1luybD99nbhv09jAxgWbZRMDFfpOH8zfLvNy20BKp180MFUgWyhO55grkGRm95Q=="
    );

    let base64url = encrypted.to_base64_url().expect("base64url");
    let crockford = encrypted.to_crockford_base32().expect("crockford");
    let base58 = encrypted.to_base58().expect("base58");
    let mnemonic = encrypted.to_mnemonic().expect("mnemonic");

    assert_encoded_text_hashes(
        base64url.as_str(),
        526,
        "EoD0aLcyYa4T56jNG34TBX16AcMYvonGC4feXxAxmSc=",
        "odG8FBZ6wZonVzeujpN4PlU71aT5ibBKGR6ErN3QwY0=",
    );
    assert_encoded_text_hashes(
        crockford.as_str(),
        631,
        "la2+DRSP7EpOE9IQYQMor1jFTjecFa7CHDjQT7nEgS4=",
        "A3uxyBknWF5A6RDqo/wI+VlOSyHUH4liI2/MhlwlgaI=",
    );
    assert_encoded_text_hashes(
        base58.as_str(),
        538,
        "Hg1RzegUyYzeezHnPw+l0N21qq5j1GRIChLq1SQpQYI=",
        "wMnDMtRNEkwyCgWuhAnYhhLXcg3qqfne+9xM+jzWJqQ=",
    );
    assert_encoded_text_hashes(
        mnemonic.as_str(),
        1788,
        "upklmK0R+li2Ljw255sNNmSUok/i3ImFjHQdytnKYe8=",
        "aySTFM23+Zs0vukeSXArB9zj3gFfRZXNrBwzPgZ/pls=",
    );
    assert_eq!(mnemonic.as_str().split_whitespace().count(), 290);
    assert_eq!(
        Base64Url::<Encrypted<SecureBytesFixturePayload>>::parse_str(base64url.as_str())
            .expect("parse base64url")
            .decode()
            .expect("decode base64url")
            .as_bytes(),
        envelope
    );
    assert_eq!(
        CrockfordBase32::<Encrypted<SecureBytesFixturePayload>>::parse_str(crockford.as_str())
            .expect("parse crockford")
            .decode()
            .expect("decode crockford")
            .as_bytes(),
        envelope
    );
    assert_eq!(
        Base58::<Encrypted<SecureBytesFixturePayload>>::parse_str(base58.as_str())
            .expect("parse base58")
            .decode()
            .expect("decode base58")
            .as_bytes(),
        envelope
    );
    assert_eq!(
        Mnemonic::<Encrypted<SecureBytesFixturePayload>>::parse_str(mnemonic.as_str())
            .expect("parse mnemonic")
            .decode()
            .expect("decode mnemonic")
            .as_bytes(),
        envelope
    );
    assert_eq!(decrypted, payload);
}

#[test]
fn typed_encrypted_payload_marker_mismatch_fails_deserialization() {
    let keyset = test_keyset(&[1]);
    let payload = secure_bytes_fixture_payload();
    let encrypted = encrypt(&keyset, &payload, b"typed payload").expect("encrypt");
    let wrong_payload_type: Encrypted<Vec<u64>> =
        Encrypted::try_from(encrypted.as_bytes()).expect("same envelope bytes");

    assert!(matches!(
        decrypt(&keyset, &wrong_payload_type, b"typed payload"),
        Err(Error::PayloadDeserialize(_))
    ));
}

#[test]
fn macs_over_secret_are_versioned_and_purpose_bound() {
    let secret = random_secret_bytes(32).expect("secret");
    let keyset =
        derive_keyset_from_latest_first_keys([test_key(1), test_key(2)], "paranoid.tokens.v1")
            .expect("token keyset");
    let same_keyset =
        derive_keyset_from_latest_first_keys([test_key(1), test_key(2)], "paranoid.tokens.v1")
            .expect("same token keyset");
    let other_purpose_keyset = derive_keyset_from_latest_first_keys(
        [test_key(1), test_key(2)],
        "paranoid.other-tokens.v1",
    )
    .expect("other token keyset");

    let mac = secret.to_mac(&keyset, b"token").expect("mac");
    let same_mac = secret.to_mac(&same_keyset, b"token").expect("same mac");
    let parsed_mac = MacOverSecret::try_from(mac.as_bytes()).expect("parse");
    let wrong_secret = random_secret_bytes(32).expect("wrong secret");

    assert_eq!(mac.as_bytes().len(), MAC_OVER_SECRET_SIZE);
    assert_eq!(mac.as_bytes()[0], MAC_OVER_SECRET_VERSION);
    assert_eq!(mac.as_bytes(), same_mac.as_bytes());
    assert!(mac.verify(&keyset, secret.expose_secret(), b"token"));
    assert!(parsed_mac.verify(&same_keyset, secret.expose_secret(), b"token"));
    assert!(!mac.verify(&keyset, wrong_secret.expose_secret(), b"token"));
    assert!(!mac.verify(&other_purpose_keyset, secret.expose_secret(), b"token"));
    assert!(!mac.verify(&keyset, secret.expose_secret(), b"other"));
    assert!(format!("{mac:?}").contains("len"));
    assert!(!format!("{secret:?}").contains("secret"));
}

#[test]
fn mac_over_secret_deterministic_vector_is_stable() {
    let keyset =
        derive_keyset_from_latest_first_keys([test_key(2), test_key(1)], "paranoid.mac.vector.v1")
            .expect("keyset");
    let secret: SecretBytes =
        SecretBytes::try_from(b"mac vector secret".as_slice()).expect("secret");
    let mac = secret.to_mac(&keyset, b"mac-vector").expect("mac");

    assert_eq!(
        BASE64_STANDARD.encode(mac.as_bytes()),
        "AT+72Yw0O08DavYfXw4fzFni6Ef2tFrClXi4euecxd7M"
    );
    assert_eq!(
        mac.to_base64_url().expect("base64url").as_str(),
        "AT-72Yw0O08DavYfXw4fzFni6Ef2tFrClXi4euecxd7M"
    );
    assert_eq!(
        mac.to_crockford_base32().expect("crockford").as_str(),
        "04ZVQPCC6GXMY0VAYRFNY3GZSHCY5T27YTT5NGMNF2W7NSWWRQFCR"
    );
    assert_eq!(
        mac.to_base58().expect("base58").as_str(),
        "NX7C5BN2EU9kvf1ZRDiEfNjjWcfPyM321bmW8MZcuvRR"
    );
    assert_eq!(
        mac.to_mnemonic().expect("mnemonic").as_str(),
        "abandon abuse worry wait blur dry pole asset gain butter wear margin obvious owner injury cabin story food believe funny ill purpose solar blast sunset deer predict"
    );
    assert_eq!(mac.as_bytes()[0], MAC_OVER_SECRET_VERSION);
    assert!(mac.verify(&keyset, b"mac vector secret", b"mac-vector"));
    assert_eq!(
        Base64Url::<MacOverSecret>::parse_str(mac.to_base64_url().expect("base64url").as_str())
            .expect("parse base64url")
            .decode()
            .expect("decode base64url")
            .as_bytes(),
        mac.as_bytes()
    );
    assert_eq!(
        CrockfordBase32::<MacOverSecret>::parse_str(
            mac.to_crockford_base32().expect("crockford").as_str()
        )
        .expect("parse crockford")
        .decode()
        .expect("decode crockford")
        .as_bytes(),
        mac.as_bytes()
    );
    assert_eq!(
        Base58::<MacOverSecret>::parse_str(mac.to_base58().expect("base58").as_str())
            .expect("parse base58")
            .decode()
            .expect("decode base58")
            .as_bytes(),
        mac.as_bytes()
    );
    assert_eq!(
        Mnemonic::<MacOverSecret>::parse_str(mac.to_mnemonic().expect("mnemonic").as_str())
            .expect("parse mnemonic")
            .decode()
            .expect("decode mnemonic")
            .as_bytes(),
        mac.as_bytes()
    );
}

#[test]
fn macs_over_secret_length_frame_context_and_secret_boundaries() {
    let keyset = derive_keyset_from_latest_first_keys([test_key(1)], "paranoid.mac-framing.v1")
        .expect("keyset");
    let first_secret: SecretBytes = SecretBytes::try_from(b"bc".as_slice()).expect("first secret");
    let second_secret: SecretBytes = SecretBytes::try_from(b"c".as_slice()).expect("second secret");

    let first_mac = first_secret.to_mac(&keyset, b"a").expect("first mac");
    let second_mac = second_secret.to_mac(&keyset, b"ab").expect("second mac");

    assert_ne!(first_mac.as_bytes(), second_mac.as_bytes());
    assert!(first_mac.verify(&keyset, b"bc", b"a"));
    assert!(second_mac.verify(&keyset, b"c", b"ab"));
    assert!(!first_mac.verify(&keyset, b"c", b"ab"));
    assert!(!second_mac.verify(&keyset, b"bc", b"a"));
}

proptest! {
    #[test]
    fn macs_over_secret_generated_context_secret_splits_are_length_framed(
        combined in prop::collection::vec(any::<u8>(), 1..=64),
        first_split_selector in any::<usize>(),
        second_split_selector in any::<usize>(),
    ) {
        let split_count = combined.len() + 1;
        let first_split = first_split_selector % split_count;
        let mut second_split = second_split_selector % split_count;
        if second_split == first_split {
            second_split = (second_split + 1) % split_count;
        }

        let keyset =
            derive_keyset_from_latest_first_keys([test_key(1)], "paranoid.mac-framing.v1")
                .expect("keyset");
        let first_secret: SecretBytes =
            SecretBytes::try_from(&combined[first_split..]).expect("first secret");
        let second_secret: SecretBytes =
            SecretBytes::try_from(&combined[second_split..]).expect("second secret");
        let first_context = &combined[..first_split];
        let second_context = &combined[..second_split];

        let first_mac = first_secret.to_mac(&keyset, first_context).expect("first mac");
        let second_mac = second_secret.to_mac(&keyset, second_context).expect("second mac");

        prop_assert_ne!(first_mac.as_bytes(), second_mac.as_bytes());
        prop_assert!(first_mac.verify(&keyset, first_secret.expose_secret(), first_context));
        prop_assert!(second_mac.verify(&keyset, second_secret.expose_secret(), second_context));
        prop_assert!(!first_mac.verify(&keyset, second_secret.expose_secret(), second_context));
        prop_assert!(!second_mac.verify(&keyset, first_secret.expose_secret(), first_context));
    }
}

#[test]
fn macs_over_secret_support_latest_first_rotation() {
    let secret = random_secret_bytes(32).expect("secret");
    let old_keyset = derive_keyset_from_latest_first_keys([test_key(1)], "paranoid.tokens.v1")
        .expect("old keyset");
    let rotated_keyset =
        derive_keyset_from_latest_first_keys([test_key(2), test_key(1)], "paranoid.tokens.v1")
            .expect("rotated keyset");

    let old_mac = secret.to_mac(&old_keyset, b"token").expect("old mac");
    let rotated_mac = secret
        .to_mac(&rotated_keyset, b"token")
        .expect("rotated mac");

    assert!(old_mac.verify(&old_keyset, secret.expose_secret(), b"token"));
    assert!(old_mac.verify(&rotated_keyset, secret.expose_secret(), b"token"));
    assert!(rotated_mac.verify(&rotated_keyset, secret.expose_secret(), b"token"));
    assert!(!rotated_mac.verify(&old_keyset, secret.expose_secret(), b"token"));
    assert_ne!(old_mac.as_bytes(), rotated_mac.as_bytes());
}

#[test]
fn macs_over_secret_reject_malformed_inputs() {
    let keyset = test_keyset(&[1]);
    let secret = random_secret_bytes(32).expect("secret");
    let mac = secret.to_mac(&keyset, b"token").expect("mac");
    let mut unsupported_version = mac.as_bytes().to_vec();
    unsupported_version[0] = MAC_OVER_SECRET_VERSION + 1;
    let mut tampered = mac.as_bytes().to_vec();
    let tampered_index = tampered.len() - 1;
    tampered[tampered_index] ^= 1;
    let tampered = MacOverSecret::try_from(tampered.as_slice()).expect("tampered mac parses");

    assert!(!tampered.verify(&keyset, secret.expose_secret(), b"token"));
    assert!(matches!(
        MacOverSecret::try_from(&mac.as_bytes()[..MAC_OVER_SECRET_SIZE - 1]),
        Err(Error::InvalidMacOverSecretLength { actual }) if actual == MAC_OVER_SECRET_SIZE - 1
    ));
    assert!(matches!(
        MacOverSecret::try_from(unsupported_version.as_slice()),
        Err(Error::UnsupportedMacOverSecretVersion { version }) if version == MAC_OVER_SECRET_VERSION + 1
    ));
}

#[test]
fn keysets_require_a_purpose_before_encryption() {
    let cookies =
        derive_keyset_from_latest_first_keys([test_key(1), test_key(2)], "paranoid.cookies.v1")
            .expect("cookie keyset");
    let backups =
        derive_keyset_from_latest_first_keys([test_key(1), test_key(2)], "my-app.backups.v1")
            .expect("backup keyset");

    let encrypted = cookies.encrypt_bytes(b"cookie payload").expect("encrypt");
    let decrypted = cookies
        .decrypt_bytes(encrypted.as_bytes())
        .expect("decrypt");

    assert_eq!(decrypted.expose_secret(), b"cookie payload");
    assert!(matches!(
        backups.decrypt_bytes(encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
    assert_eq!(cookies.purpose(), "paranoid.cookies.v1");
    assert_eq!(cookies.key_count(), 2);
}

#[test]
fn latest_first_rotation_encrypts_with_latest_and_decrypts_with_any() {
    let old_cookie_keyset =
        derive_keyset_from_latest_first_keys([test_key(1)], "paranoid.cookies.v1")
            .expect("old cookie keyset");
    let old_encrypted = old_cookie_keyset
        .encrypt_bytes(b"old cookie payload")
        .expect("old encrypt");

    let rotated_cookie_keyset =
        derive_keyset_from_latest_first_keys([test_key(2), test_key(1)], "paranoid.cookies.v1")
            .expect("rotated cookie keyset");
    let decrypted = rotated_cookie_keyset
        .decrypt_bytes(old_encrypted.as_bytes())
        .expect("decrypt old with rotated keys");

    assert_eq!(decrypted.expose_secret(), b"old cookie payload");

    let latest_encrypted = rotated_cookie_keyset
        .encrypt_bytes(b"latest cookie payload")
        .expect("latest encrypt");
    assert!(matches!(
        old_cookie_keyset.decrypt_bytes(latest_encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn child_keysets_are_hierarchically_domain_separated() {
    let cookie_keyset = derive_keyset_from_latest_first_keys([test_key(1)], "my-app.cookies.v1")
        .expect("cookie keyset");
    let session_cookie_keyset = cookie_keyset
        .derive_child_keyset("encrypted-host.session")
        .expect("session cookie keyset");
    let same_session_cookie_keyset = cookie_keyset
        .derive_child_keyset("encrypted-host.session")
        .expect("same session cookie keyset");
    let csrf_cookie_keyset = cookie_keyset
        .derive_child_keyset("client-readable-host.csrf")
        .expect("csrf cookie keyset");
    let admin_cookie_keyset =
        derive_keyset_from_latest_first_keys([test_key(1)], "my-app.admin-cookies.v1")
            .expect("admin cookie keyset")
            .derive_child_keyset("encrypted-host.session")
            .expect("admin session cookie keyset");

    let encrypted = session_cookie_keyset
        .encrypt_bytes(b"session payload")
        .expect("encrypt");
    let decrypted = same_session_cookie_keyset
        .decrypt_bytes(encrypted.as_bytes())
        .expect("decrypt");

    assert_eq!(
        session_cookie_keyset.purpose(),
        "my-app.cookies.v1/encrypted-host.session"
    );
    assert_eq!(decrypted.expose_secret(), b"session payload");
    assert!(matches!(
        csrf_cookie_keyset.decrypt_bytes(encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
    assert!(matches!(
        admin_cookie_keyset.decrypt_bytes(encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn child_keyset_deterministic_vector_matches_child_keyset_domain_labels() {
    let parent_keyset =
        derive_keyset_from_latest_first_keys([test_key(1)], "paranoid.fixture.parent.v1")
            .expect("parent keyset");
    let child_keyset = parent_keyset
        .derive_child_keyset("encrypted-host.session")
        .expect("child keyset");
    let envelope = manually_encrypt_padded_payload(
        child_keyset.latest_key(),
        &valid_test_padded_payload(b"child keyset fixture"),
        b"child keyset associated data",
        ManualEnvelopeMutation::None,
    );

    assert_eq!(
        BASE64_STANDARD.encode(&envelope),
        "UEFSQQEBEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIjMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0RERERERERERERERGLc6hK0oyHbkeMntBpQ0BmzdVXH7AJ0pSyZt6GcUryHB97uRE0eRAT+vwHf8B9bBK1djHmZiSapuhiPEqjFmE5/b/RZKznlbYq82K3FDa9cUny4TVsuu5B80bUVGQmV7CInohzzdvVuS/JzHZjw2xElZPGJYD5urkB066/S7t0emopIH1xjiMx5nf3HoNpJ//HgYs4lsbPrExh+vIdKqUP7iL/NSnnPlcxWH8+ic35NQfCnx1mO1IqI9b39thlVfB7+y2Kp0kU2bkcDRQmSKhTEto9DswtFufrMEm+zPEpUWSPD/AknP8ZdjyJXjW4OyreDnz949KIaOAqawjwJgpxTSDfPt0SG2TdKoUaY7Xr5wipDM3IIClpYNS1LtJw3eA=="
    );
    assert_eq!(
        BASE64_STANDARD.encode(sha256_hash_parts(&[&envelope]).as_bytes()),
        "9NENX58/AQyC3y2y6eiZ4EVM9aIxZJ0a6IRReFF8oUU="
    );
    assert_eq!(
        BASE64_STANDARD.encode(blake3_hash_parts(&[&envelope]).as_bytes()),
        "2lAXFEyb+GwUigx3G18mXoDWUfWE038vgLK8Zw2c2PE="
    );
}

#[test]
fn parent_and_child_purpose_keysets_cannot_decrypt_each_other() {
    let parent_keyset = test_keyset(&[1]);
    let child_keyset = parent_keyset
        .derive_child_keyset("encrypted-host.session")
        .expect("child keyset");

    let parent_encrypted = parent_keyset
        .encrypt_bytes(b"parent")
        .expect("parent encrypt");
    let child_encrypted = child_keyset.encrypt_bytes(b"child").expect("child encrypt");

    assert!(matches!(
        child_keyset.decrypt_bytes(parent_encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
    assert!(matches!(
        parent_keyset.decrypt_bytes(child_encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn child_keysets_preserve_latest_first_rotation() {
    let old_child_keyset = derive_keyset_from_latest_first_keys([test_key(1)], "my-app.cookies.v1")
        .expect("old parent keyset")
        .derive_child_keyset("encrypted-host.session")
        .expect("old child keyset");
    let rotated_child_keyset =
        derive_keyset_from_latest_first_keys([test_key(2), test_key(1)], "my-app.cookies.v1")
            .expect("rotated parent keyset")
            .derive_child_keyset("encrypted-host.session")
            .expect("rotated child keyset");

    let old_encrypted = old_child_keyset
        .encrypt_bytes(b"old child payload")
        .expect("old encrypt");
    let old_decrypted = rotated_child_keyset
        .decrypt_bytes(old_encrypted.as_bytes())
        .expect("decrypt old with rotated keys");
    let latest_encrypted = rotated_child_keyset
        .encrypt_bytes(b"latest child payload")
        .expect("latest encrypt");

    assert_eq!(old_decrypted.expose_secret(), b"old child payload");
    assert!(matches!(
        old_child_keyset.decrypt_bytes(latest_encrypted.as_bytes()),
        Err(Error::DecryptionFailed)
    ));
}

#[test]
fn keysets_reject_empty_and_duplicate_input_keys() {
    assert!(matches!(
        derive_keyset_from_latest_first_keys(Vec::new(), TEST_PURPOSE),
        Err(Error::EmptyKeyset)
    ));
    assert!(matches!(
        Key32::try_from(&[1_u8; KEY_SIZE - 1][..]),
        Err(Error::InvalidKey32Length { actual }) if actual == KEY_SIZE - 1
    ));
    assert!(matches!(
        derive_keyset_from_latest_first_keys(vec![test_key(1), test_key(1)], TEST_PURPOSE),
        Err(Error::DuplicateKey { index: 1 })
    ));
}

#[test]
fn keysets_reject_too_many_rotation_keys_before_unbounded_collection() {
    let keys = (0..=MAX_KEYSET_KEYS).map(|index| test_key(index as u8));

    assert!(matches!(
        derive_keyset_from_latest_first_keys(keys, TEST_PURPOSE),
        Err(Error::TooManyKeys {
            max: MAX_KEYSET_KEYS,
        })
    ));
}

#[test]
fn purpose_strings_are_validated() {
    let purpose_bound_keyset =
        derive_keyset_from_latest_first_keys([test_key(1)], "my-app.cookies.v1")
            .expect("purpose keyset");

    assert!(matches!(
        derive_keyset_from_latest_first_keys([test_key(1)], ""),
        Err(Error::EmptyPurpose)
    ));
    assert!(matches!(
        derive_keyset_from_latest_first_keys([test_key(1)], "has spaces"),
        Err(Error::InvalidPurposeByte { index: 3, .. })
    ));
    assert!(matches!(
        derive_keyset_from_latest_first_keys([test_key(1)], "has/slash"),
        Err(Error::InvalidPurposeByte {
            index: 3,
            byte: b'/'
        })
    ));
    assert!(matches!(
        derive_keyset_from_latest_first_keys([test_key(1)], "contains-é"),
        Err(Error::InvalidPurposeByte { .. })
    ));
    assert!(matches!(
        derive_keyset_from_latest_first_keys([test_key(1)], &"a".repeat(MAX_PURPOSE_LEN + 1)),
        Err(Error::PurposeTooLong { .. })
    ));
    assert!(matches!(
        purpose_bound_keyset.derive_child_keyset(""),
        Err(Error::EmptyPurpose)
    ));
    assert!(matches!(
        purpose_bound_keyset.derive_child_keyset("has spaces"),
        Err(Error::InvalidPurposeByte { index: 3, .. })
    ));
    assert!(matches!(
        purpose_bound_keyset.derive_child_keyset("has/slash"),
        Err(Error::InvalidPurposeByte {
            index: 3,
            byte: b'/'
        })
    ));
    assert!(matches!(
        purpose_bound_keyset.derive_child_keyset("contains-é"),
        Err(Error::InvalidPurposeByte { .. })
    ));
    assert!(matches!(
        purpose_bound_keyset.derive_child_keyset(&"a".repeat(MAX_PURPOSE_LEN + 1)),
        Err(Error::PurposeTooLong { .. })
    ));

    let max_len_parent =
        derive_keyset_from_latest_first_keys([test_key(1)], &"a".repeat(MAX_PURPOSE_LEN))
            .expect("max length parent");
    assert!(matches!(
        max_len_parent.derive_child_keyset("b"),
        Err(Error::PurposeTooLong { .. })
    ));
}
