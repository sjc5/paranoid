#![no_main]

use libfuzzer_sys::fuzz_target;
use paranoid::crypto::{
    Encrypted, KEY32_SIZE, Key32, SecretBytes, decrypt, derive_keyset_from_latest_first_keys,
};

const FALLBACK_ROOT_KEY_BYTES: [u8; KEY32_SIZE] = [0_u8; KEY32_SIZE];
const FUZZ_PURPOSE: &str = "paranoid.fuzz.v1";

fuzz_target!(|data: &[u8]| {
    let _ = Encrypted::<SecretBytes>::try_from(data);

    let (root_key_bytes, remaining) = root_key_and_remaining(data);
    let (associated_data, envelope) = split_associated_data_and_envelope(remaining);
    let root_key = Key32::try_from(root_key_bytes.as_slice()).expect("fixed-size fuzz root key");
    let keyset = derive_keyset_from_latest_first_keys([root_key], FUZZ_PURPOSE)
        .expect("static non-empty fuzz keyset");

    if let Ok(encrypted) = Encrypted::<SecretBytes>::try_from(envelope) {
        let _ = decrypt(&keyset, &encrypted, b"");
        let _ = decrypt(&keyset, &encrypted, associated_data);
    }
});

fn root_key_and_remaining(input: &[u8]) -> ([u8; KEY32_SIZE], &[u8]) {
    if input.len() >= KEY32_SIZE {
        let root_key_bytes = input[..KEY32_SIZE]
            .try_into()
            .expect("slice length is checked");
        return (root_key_bytes, &input[KEY32_SIZE..]);
    }

    (FALLBACK_ROOT_KEY_BYTES, input)
}

fn split_associated_data_and_envelope(input: &[u8]) -> (&[u8], &[u8]) {
    if input.is_empty() {
        return (&[], input);
    }

    let associated_data_len = usize::from(input[0]).min(input.len() - 1);
    let associated_data_end = 1 + associated_data_len;
    (
        &input[1..associated_data_end],
        &input[associated_data_end..],
    )
}
