use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::LazyLock;

use data_encoding::{BASE64URL_NOPAD, Encoding, Specification};
use zeroize::Zeroize;

use crate::crypto::Error;
use crate::crypto::bip39_english_words::BIP39_ENGLISH_WORDS;
use crate::crypto::bytes::{MAX_BYTE_CONTAINER_SIZE, PublicBytes, public_vec_with_capacity};
use crate::crypto::envelope::{Encrypted, MAX_ENVELOPE_SIZE};
use crate::crypto::token::{MAC_OVER_SECRET_SIZE, MacOverSecret};
use crate::crypto::{Key32, SecretBytes};

pub(crate) const BASE64URL_CODEC_NAME: &str = "base64url";
pub(crate) const CROCKFORD_BASE32_CODEC_NAME: &str = "crockford-base32";
const BASE58_CODEC_NAME: &str = "base58";
pub(crate) const MNEMONIC_CODEC_NAME: &str = "mnemonic";
const KEY32_DECODED_LEN: usize = 32;
const CROCKFORD_BASE32_SYMBOLS: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const MNEMONIC_WORD_BITS: usize = 11;
const MNEMONIC_WORD_MASK: u32 = (1 << MNEMONIC_WORD_BITS) - 1;
const MNEMONIC_VERSION: usize = 0;
const MNEMONIC_PADDING_VALUE_COUNT: usize = MNEMONIC_WORD_BITS;
const MNEMONIC_CHECKSUM_WORD_COUNT: usize = 2;
const MIN_MNEMONIC_WORD_COUNT: usize = 1 + MNEMONIC_CHECKSUM_WORD_COUNT;
const MNEMONIC_CHECKSUM_CONTEXT: &[u8] = b"paranoid/mnemonic-codec/v1/checksum";

static CROCKFORD_BASE32_ENCODING: LazyLock<Encoding> = LazyLock::new(|| {
    let mut specification = Specification::new();
    specification.symbols.push_str(CROCKFORD_BASE32_SYMBOLS);
    specification
        .encoding()
        .expect("crockford base32 specification is valid")
});

static MNEMONIC_WORD_INDEX_BY_WORD: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    let mut word_index_by_word = HashMap::with_capacity(BIP39_ENGLISH_WORDS.len());
    for (index, word) in BIP39_ENGLISH_WORDS.iter().copied().enumerate() {
        assert!(word_index_by_word.insert(word, index as u16).is_none());
    }
    word_index_by_word
});

/// Canonical unpadded URL-safe Base64 text for `T`.
pub struct Base64Url<T> {
    encoded: String,
    value_type: PhantomData<fn() -> T>,
}

/// Canonical Crockford Base32 text for `T`.
pub struct CrockfordBase32<T> {
    encoded: String,
    value_type: PhantomData<fn() -> T>,
}

/// Canonical Bitcoin Base58 text for `T`.
pub struct Base58<T> {
    encoded: String,
    value_type: PhantomData<fn() -> T>,
}

/// Canonical English mnemonic text for `T`.
///
/// This codec uses the official BIP39 English word list as its fixed
/// vocabulary, but it is not the BIP39 mnemonic protocol.
pub struct Mnemonic<T> {
    encoded: String,
    value_type: PhantomData<fn() -> T>,
}

mod sealed {
    pub trait EdgeByteContainerSealed {}
}

/// Typed byte container that can be decoded from edge text.
pub trait EdgeByteContainer:
    sealed::EdgeByteContainerSealed + TryFrom<Vec<u8>, Error = Error>
{
    #[doc(hidden)]
    const MAX_DECODED_LEN: usize;
}

impl sealed::EdgeByteContainerSealed for Key32 {}

impl EdgeByteContainer for Key32 {
    const MAX_DECODED_LEN: usize = KEY32_DECODED_LEN;
}

impl<K> sealed::EdgeByteContainerSealed for SecretBytes<K> {}

impl<K> EdgeByteContainer for SecretBytes<K> {
    const MAX_DECODED_LEN: usize = MAX_BYTE_CONTAINER_SIZE;
}

impl<K> sealed::EdgeByteContainerSealed for PublicBytes<K> {}

impl<K> EdgeByteContainer for PublicBytes<K> {
    const MAX_DECODED_LEN: usize = MAX_BYTE_CONTAINER_SIZE;
}

impl<T> sealed::EdgeByteContainerSealed for Encrypted<T> {}

impl<T> EdgeByteContainer for Encrypted<T> {
    const MAX_DECODED_LEN: usize = MAX_ENVELOPE_SIZE;
}

impl sealed::EdgeByteContainerSealed for MacOverSecret {}

impl EdgeByteContainer for MacOverSecret {
    const MAX_DECODED_LEN: usize = MAC_OVER_SECRET_SIZE;
}

macro_rules! impl_encoded_wrapper {
    ($name:ident, $decode:ident, $codec_name:expr) => {
        impl<T> $name<T> {
            fn from_canonical_string(encoded: String) -> Self {
                Self {
                    encoded,
                    value_type: PhantomData,
                }
            }

            /// Returns the encoded string.
            pub fn as_str(&self) -> &str {
                &self.encoded
            }

            /// Returns the encoded string as an ordinary, non-zeroizing `String`.
            pub fn into_exposed_string(mut self) -> String {
                std::mem::take(&mut self.encoded)
            }
        }

        impl<T> $name<T>
        where
            T: EdgeByteContainer,
        {
            /// Parses and validates encoded string syntax.
            pub fn parse_str(encoded: &str) -> Result<Self, Error> {
                let mut decoded_for_validation = $decode(encoded, T::MAX_DECODED_LEN)?;
                decoded_for_validation.zeroize();
                Ok(Self::from_canonical_string(encoded.to_owned()))
            }

            /// Decodes this encoded value into its typed byte container.
            pub fn decode(self) -> Result<T, Error> {
                let decoded = $decode(&self.encoded, T::MAX_DECODED_LEN)?;
                T::try_from(decoded)
            }
        }

        impl<T> Drop for $name<T> {
            fn drop(&mut self) {
                self.encoded.zeroize();
            }
        }

        impl<T> AsRef<str> for $name<T> {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<T> fmt::Debug for $name<T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("encoded_len", &self.encoded.len())
                    .finish()
            }
        }
    };
}

impl_encoded_wrapper!(Base64Url, decode_base64url, BASE64URL_CODEC_NAME);
impl_encoded_wrapper!(
    CrockfordBase32,
    decode_crockford_base32,
    CROCKFORD_BASE32_CODEC_NAME
);
impl_encoded_wrapper!(Base58, decode_base58, BASE58_CODEC_NAME);
impl_encoded_wrapper!(Mnemonic, decode_mnemonic, MNEMONIC_CODEC_NAME);

impl Key32 {
    /// Encodes this key as canonical unpadded URL-safe Base64.
    pub fn to_base64_url(&self) -> Result<Base64Url<Self>, Error> {
        Ok(Base64Url::from_canonical_string(encode_base64url(
            self.expose_secret(),
        )))
    }

    /// Encodes this key as canonical Crockford Base32.
    pub fn to_crockford_base32(&self) -> Result<CrockfordBase32<Self>, Error> {
        Ok(CrockfordBase32::from_canonical_string(
            encode_crockford_base32(self.expose_secret()),
        ))
    }

    /// Encodes this key as canonical Bitcoin Base58.
    pub fn to_base58(&self) -> Result<Base58<Self>, Error> {
        Ok(Base58::from_canonical_string(encode_base58(
            self.expose_secret(),
        )))
    }

    /// Encodes this key as canonical English mnemonic text.
    pub fn to_mnemonic(&self) -> Result<Mnemonic<Self>, Error> {
        Ok(Mnemonic::from_canonical_string(encode_mnemonic(
            self.expose_secret(),
        )))
    }
}

impl<K> SecretBytes<K> {
    /// Encodes these secret bytes as canonical unpadded URL-safe Base64.
    pub fn to_base64_url(&self) -> Result<Base64Url<Self>, Error> {
        Ok(Base64Url::from_canonical_string(encode_base64url(
            self.expose_secret(),
        )))
    }

    /// Encodes these secret bytes as canonical Crockford Base32.
    pub fn to_crockford_base32(&self) -> Result<CrockfordBase32<Self>, Error> {
        Ok(CrockfordBase32::from_canonical_string(
            encode_crockford_base32(self.expose_secret()),
        ))
    }

    /// Encodes these secret bytes as canonical Bitcoin Base58.
    pub fn to_base58(&self) -> Result<Base58<Self>, Error> {
        Ok(Base58::from_canonical_string(encode_base58(
            self.expose_secret(),
        )))
    }

    /// Encodes these secret bytes as canonical English mnemonic text.
    pub fn to_mnemonic(&self) -> Result<Mnemonic<Self>, Error> {
        Ok(Mnemonic::from_canonical_string(encode_mnemonic(
            self.expose_secret(),
        )))
    }
}

impl<K> PublicBytes<K> {
    /// Encodes these public bytes as canonical unpadded URL-safe Base64.
    pub fn to_base64_url(&self) -> Result<Base64Url<Self>, Error> {
        Ok(Base64Url::from_canonical_string(encode_base64url(
            self.as_bytes(),
        )))
    }

    /// Encodes these public bytes as canonical Crockford Base32.
    pub fn to_crockford_base32(&self) -> Result<CrockfordBase32<Self>, Error> {
        Ok(CrockfordBase32::from_canonical_string(
            encode_crockford_base32(self.as_bytes()),
        ))
    }

    /// Encodes these public bytes as canonical Bitcoin Base58.
    pub fn to_base58(&self) -> Result<Base58<Self>, Error> {
        Ok(Base58::from_canonical_string(encode_base58(
            self.as_bytes(),
        )))
    }

    /// Encodes these public bytes as canonical English mnemonic text.
    pub fn to_mnemonic(&self) -> Result<Mnemonic<Self>, Error> {
        Ok(Mnemonic::from_canonical_string(encode_mnemonic(
            self.as_bytes(),
        )))
    }
}

impl<T> Encrypted<T> {
    /// Encodes these encrypted bytes as canonical unpadded URL-safe Base64.
    pub fn to_base64_url(&self) -> Result<Base64Url<Self>, Error> {
        Ok(Base64Url::from_canonical_string(encode_base64url(
            self.as_bytes(),
        )))
    }

    /// Encodes these encrypted bytes as canonical Crockford Base32.
    pub fn to_crockford_base32(&self) -> Result<CrockfordBase32<Self>, Error> {
        Ok(CrockfordBase32::from_canonical_string(
            encode_crockford_base32(self.as_bytes()),
        ))
    }

    /// Encodes these encrypted bytes as canonical Bitcoin Base58.
    pub fn to_base58(&self) -> Result<Base58<Self>, Error> {
        Ok(Base58::from_canonical_string(encode_base58(
            self.as_bytes(),
        )))
    }

    /// Encodes these encrypted bytes as canonical English mnemonic text.
    pub fn to_mnemonic(&self) -> Result<Mnemonic<Self>, Error> {
        Ok(Mnemonic::from_canonical_string(encode_mnemonic(
            self.as_bytes(),
        )))
    }
}

impl MacOverSecret {
    /// Encodes this MAC as canonical unpadded URL-safe Base64.
    pub fn to_base64_url(&self) -> Result<Base64Url<Self>, Error> {
        Ok(Base64Url::from_canonical_string(encode_base64url(
            self.as_bytes(),
        )))
    }

    /// Encodes this MAC as canonical Crockford Base32.
    pub fn to_crockford_base32(&self) -> Result<CrockfordBase32<Self>, Error> {
        Ok(CrockfordBase32::from_canonical_string(
            encode_crockford_base32(self.as_bytes()),
        ))
    }

    /// Encodes this MAC as canonical Bitcoin Base58.
    pub fn to_base58(&self) -> Result<Base58<Self>, Error> {
        Ok(Base58::from_canonical_string(encode_base58(
            self.as_bytes(),
        )))
    }

    /// Encodes this MAC as canonical English mnemonic text.
    pub fn to_mnemonic(&self) -> Result<Mnemonic<Self>, Error> {
        Ok(Mnemonic::from_canonical_string(encode_mnemonic(
            self.as_bytes(),
        )))
    }
}

fn encode_base64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

fn decode_base64url(encoded: &str, max_decoded_len: usize) -> Result<Vec<u8>, Error> {
    validate_encoded_len(
        BASE64URL_CODEC_NAME,
        encoded.len(),
        max_base64url_encoded_len_for_decoded_len(max_decoded_len),
    )?;
    let decoded = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|source| Error::EncodingDecode {
            codec: BASE64URL_CODEC_NAME,
            source,
        })?;
    let mut decoded = decoded;
    if let Err(error) = validate_decoded_len(BASE64URL_CODEC_NAME, decoded.len(), max_decoded_len)
        .and_then(|()| {
            validate_canonical_encoding(BASE64URL_CODEC_NAME, encoded, &encode_base64url(&decoded))
        })
    {
        decoded.zeroize();
        return Err(error);
    }
    Ok(decoded)
}

fn encode_crockford_base32(bytes: &[u8]) -> String {
    CROCKFORD_BASE32_ENCODING.encode(bytes)
}

fn decode_crockford_base32(encoded: &str, max_decoded_len: usize) -> Result<Vec<u8>, Error> {
    validate_encoded_len(
        CROCKFORD_BASE32_CODEC_NAME,
        encoded.len(),
        max_crockford_base32_encoded_len_for_decoded_len(max_decoded_len),
    )?;
    let decoded = CROCKFORD_BASE32_ENCODING
        .decode(encoded.as_bytes())
        .map_err(|source| Error::EncodingDecode {
            codec: CROCKFORD_BASE32_CODEC_NAME,
            source,
        })?;
    let mut decoded = decoded;
    if let Err(error) =
        validate_decoded_len(CROCKFORD_BASE32_CODEC_NAME, decoded.len(), max_decoded_len).and_then(
            |()| {
                validate_canonical_encoding(
                    CROCKFORD_BASE32_CODEC_NAME,
                    encoded,
                    &encode_crockford_base32(&decoded),
                )
            },
        )
    {
        decoded.zeroize();
        return Err(error);
    }
    Ok(decoded)
}

fn encode_base58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn decode_base58(encoded: &str, max_decoded_len: usize) -> Result<Vec<u8>, Error> {
    validate_encoded_len(
        BASE58_CODEC_NAME,
        encoded.len(),
        max_base58_encoded_len_for_decoded_len(max_decoded_len),
    )?;
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(Error::Base58Decode)?;
    let mut decoded = decoded;
    if let Err(error) = validate_decoded_len(BASE58_CODEC_NAME, decoded.len(), max_decoded_len)
        .and_then(|()| {
            validate_canonical_encoding(BASE58_CODEC_NAME, encoded, &encode_base58(&decoded))
        })
    {
        decoded.zeroize();
        return Err(error);
    }
    Ok(decoded)
}

fn encode_mnemonic(bytes: &[u8]) -> String {
    let data_word_count = bytes.len() * 8_usize / MNEMONIC_WORD_BITS
        + usize::from(!((bytes.len() * 8).is_multiple_of(MNEMONIC_WORD_BITS)));
    let padding_bits = data_word_count * MNEMONIC_WORD_BITS - bytes.len() * 8;
    let header_word_index = MNEMONIC_VERSION * MNEMONIC_PADDING_VALUE_COUNT + padding_bits;
    let checksum_words = mnemonic_checksum_words(bytes);
    let mut encoded = String::new();

    push_mnemonic_word(&mut encoded, BIP39_ENGLISH_WORDS[header_word_index]);
    let mut staged_bits = 0_u32;
    let mut staged_bit_count = 0_usize;

    for byte in bytes {
        staged_bits = (staged_bits << 8) | u32::from(*byte);
        staged_bit_count += 8;
        while staged_bit_count >= MNEMONIC_WORD_BITS {
            staged_bit_count -= MNEMONIC_WORD_BITS;
            let word_index = ((staged_bits >> staged_bit_count) & MNEMONIC_WORD_MASK) as usize;
            push_mnemonic_word(&mut encoded, BIP39_ENGLISH_WORDS[word_index]);
            staged_bits &= low_bit_mask(staged_bit_count);
        }
    }

    if staged_bit_count > 0 {
        let word_index = (staged_bits << (MNEMONIC_WORD_BITS - staged_bit_count)) as usize;
        push_mnemonic_word(&mut encoded, BIP39_ENGLISH_WORDS[word_index]);
    }

    for checksum_word in checksum_words {
        push_mnemonic_word(
            &mut encoded,
            BIP39_ENGLISH_WORDS[usize::from(checksum_word)],
        );
    }

    encoded
}

fn decode_mnemonic(encoded: &str, max_decoded_len: usize) -> Result<Vec<u8>, Error> {
    validate_encoded_len(
        MNEMONIC_CODEC_NAME,
        encoded.len(),
        max_mnemonic_encoded_len_for_decoded_len(max_decoded_len),
    )?;
    let max_word_count = max_mnemonic_word_count_for_decoded_len(max_decoded_len);
    let word_indices = mnemonic_word_indices(encoded, max_word_count)?;
    let word_count = word_indices.len();
    if word_count < MIN_MNEMONIC_WORD_COUNT {
        return Err(Error::MnemonicTooShort {
            words: word_count,
            min: MIN_MNEMONIC_WORD_COUNT,
        });
    }

    let header_word = usize::from(word_indices[0]);
    let version = header_word / MNEMONIC_PADDING_VALUE_COUNT;
    if version != MNEMONIC_VERSION {
        return Err(Error::UnsupportedMnemonicVersion { version });
    }
    let padding_bits = header_word % MNEMONIC_PADDING_VALUE_COUNT;
    let data_word_count = word_count - MIN_MNEMONIC_WORD_COUNT;
    let data_bit_count = data_word_count * MNEMONIC_WORD_BITS;
    if padding_bits > data_bit_count {
        return Err(Error::InvalidMnemonicPadding {
            padding_bits,
            data_word_count,
        });
    }

    let byte_bit_count = data_bit_count - padding_bits;
    if !byte_bit_count.is_multiple_of(8) {
        return Err(Error::InvalidMnemonicPadding {
            padding_bits,
            data_word_count,
        });
    }
    let expected_byte_count = byte_bit_count / 8;
    validate_decoded_len(MNEMONIC_CODEC_NAME, expected_byte_count, max_decoded_len)?;
    let mut decoded = public_vec_with_capacity(expected_byte_count)?;

    let mut staged_bits = 0_u32;
    let mut staged_bit_count = 0_usize;
    let data_words = &word_indices[1..1 + data_word_count];
    for word_index in data_words {
        staged_bits = (staged_bits << MNEMONIC_WORD_BITS) | u32::from(*word_index);
        staged_bit_count += MNEMONIC_WORD_BITS;
        while staged_bit_count >= 8 && decoded.len() < expected_byte_count {
            staged_bit_count -= 8;
            decoded.push((staged_bits >> staged_bit_count) as u8);
            staged_bits &= low_bit_mask(staged_bit_count);
        }
    }

    if staged_bit_count != padding_bits || staged_bits != 0 {
        decoded.zeroize();
        return Err(Error::InvalidMnemonicPadding {
            padding_bits,
            data_word_count,
        });
    }

    let expected_checksum_words = mnemonic_checksum_words(&decoded);
    let checksum_words = &word_indices[1 + data_word_count..];
    if checksum_words != expected_checksum_words {
        decoded.zeroize();
        return Err(Error::InvalidMnemonicChecksum);
    }

    if let Err(error) =
        validate_canonical_encoding(MNEMONIC_CODEC_NAME, encoded, &encode_mnemonic(&decoded))
    {
        decoded.zeroize();
        return Err(error);
    }
    Ok(decoded)
}

fn mnemonic_word_indices(encoded: &str, max_word_count: usize) -> Result<Vec<u16>, Error> {
    let mut indices = Vec::new();
    for (index, word) in encoded.split_whitespace().enumerate() {
        if index >= max_word_count {
            return Err(Error::EncodedTextTooLarge {
                codec: MNEMONIC_CODEC_NAME,
                actual: index + 1,
                max: max_word_count,
            });
        }
        let word_index = MNEMONIC_WORD_INDEX_BY_WORD
            .get(word)
            .copied()
            .ok_or(Error::UnknownMnemonicWord { index })?;
        indices.push(word_index);
    }

    if indices.is_empty() {
        return Err(Error::EmptyMnemonic);
    }
    Ok(indices)
}

fn mnemonic_checksum_words(bytes: &[u8]) -> [u16; MNEMONIC_CHECKSUM_WORD_COUNT] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MNEMONIC_CHECKSUM_CONTEXT);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    let checksum_bits = ((u32::from(digest.as_bytes()[0]) << 16)
        | (u32::from(digest.as_bytes()[1]) << 8)
        | u32::from(digest.as_bytes()[2]))
        >> 2;
    [
        ((checksum_bits >> MNEMONIC_WORD_BITS) & MNEMONIC_WORD_MASK) as u16,
        (checksum_bits & MNEMONIC_WORD_MASK) as u16,
    ]
}

fn push_mnemonic_word(encoded: &mut String, word: &str) {
    if !encoded.is_empty() {
        encoded.push(' ');
    }
    encoded.push_str(word);
}

fn low_bit_mask(bit_count: usize) -> u32 {
    if bit_count == 0 {
        return 0;
    }
    (1_u32 << bit_count) - 1
}

fn validate_canonical_encoding(
    codec: &'static str,
    encoded: &str,
    canonical: &str,
) -> Result<(), Error> {
    if encoded != canonical {
        return Err(Error::NonCanonicalEncoding { codec });
    }
    Ok(())
}

fn validate_encoded_len(codec: &'static str, actual: usize, max: usize) -> Result<(), Error> {
    if actual > max {
        return Err(Error::EncodedTextTooLarge { codec, actual, max });
    }
    Ok(())
}

fn validate_decoded_len(codec: &'static str, actual: usize, max: usize) -> Result<(), Error> {
    if actual > max {
        return Err(Error::DecodedBytesTooLarge { codec, actual, max });
    }
    Ok(())
}

fn max_base64url_encoded_len_for_decoded_len(decoded_len: usize) -> usize {
    decoded_len.saturating_mul(4).div_ceil(3)
}

fn max_crockford_base32_encoded_len_for_decoded_len(decoded_len: usize) -> usize {
    decoded_len.saturating_mul(8).div_ceil(5)
}

fn max_base58_encoded_len_for_decoded_len(decoded_len: usize) -> usize {
    decoded_len
        .saturating_mul(138)
        .div_ceil(100)
        .saturating_add(1)
}

fn max_mnemonic_word_count_for_decoded_len(decoded_len: usize) -> usize {
    1 + decoded_len.saturating_mul(8).div_ceil(MNEMONIC_WORD_BITS) + MNEMONIC_CHECKSUM_WORD_COUNT
}

fn max_mnemonic_encoded_len_for_decoded_len(decoded_len: usize) -> usize {
    let max_word_count = max_mnemonic_word_count_for_decoded_len(decoded_len);
    let max_word_len = BIP39_ENGLISH_WORDS
        .iter()
        .map(|word| word.len())
        .max()
        .unwrap_or(0);
    max_word_count.saturating_mul(max_word_len.saturating_add(1))
}
