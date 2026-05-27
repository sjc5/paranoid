#![no_main]

use libfuzzer_sys::fuzz_target;
use paranoid::crypto::{Base58, Base64Url, CrockfordBase32, Mnemonic, PublicBytes};

enum FuzzPublicBytes {}

fuzz_target!(|data: &[u8]| {
    let public = PublicBytes::<FuzzPublicBytes>::try_from(data).expect("public bytes");

    let base64url = public.to_base64_url().expect("base64url");
    let _ = Base64Url::<PublicBytes<FuzzPublicBytes>>::parse_str(base64url.as_str())
        .and_then(Base64Url::decode);

    let crockford = public.to_crockford_base32().expect("crockford");
    let _ = CrockfordBase32::<PublicBytes<FuzzPublicBytes>>::parse_str(crockford.as_str())
        .and_then(CrockfordBase32::decode);

    let base58 = public.to_base58().expect("base58");
    let _ =
        Base58::<PublicBytes<FuzzPublicBytes>>::parse_str(base58.as_str()).and_then(Base58::decode);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ =
            Base64Url::<PublicBytes<FuzzPublicBytes>>::parse_str(text).and_then(Base64Url::decode);
        let _ = Base64Url::<paranoid::crypto::Key32>::parse_str(text).and_then(Base64Url::decode);
        let _ =
            Base64Url::<paranoid::crypto::Encrypted>::parse_str(text).and_then(Base64Url::decode);
        let _ = CrockfordBase32::<PublicBytes<FuzzPublicBytes>>::parse_str(text)
            .and_then(CrockfordBase32::decode);
        let _ = CrockfordBase32::<paranoid::crypto::Key32>::parse_str(text)
            .and_then(CrockfordBase32::decode);
        let _ = Base58::<PublicBytes<FuzzPublicBytes>>::parse_str(text).and_then(Base58::decode);
        let _ = Base58::<paranoid::crypto::Key32>::parse_str(text).and_then(Base58::decode);
        let _ = Mnemonic::<paranoid::crypto::SecretBytes<FuzzPublicBytes>>::parse_str(text)
            .and_then(Mnemonic::decode);
        let _ = Mnemonic::<paranoid::crypto::Key32>::parse_str(text).and_then(Mnemonic::decode);
    }
});
