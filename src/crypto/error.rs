use std::error::Error as StdError;
use std::fmt;

use crate::crypto::{CryptoError, KEY32_SIZE, MAC_OVER_SECRET_SIZE};

/// Error returned by the operating system random source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomError {
    source: getrandom::Error,
}

impl RandomError {
    /// Returns the underlying `getrandom` error.
    pub fn getrandom_error(&self) -> &getrandom::Error {
        &self.source
    }
}

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl StdError for RandomError {}

/// Errors returned by Paranoid crypto primitives.
#[derive(Debug)]
pub enum Error {
    /// A keyset must contain at least one key.
    EmptyKeyset,
    /// A keyset contained the same key more than once.
    DuplicateKey {
        /// Latest-first key index where the duplicate was found.
        index: usize,
    },
    /// A keyset contained more rotation keys than the supported maximum.
    TooManyKeys {
        /// Maximum accepted key count.
        max: usize,
    },
    /// A key was not exactly 32 bytes long.
    InvalidKey32Length {
        /// Actual key byte length.
        actual: usize,
    },
    /// A password KDF salt was not exactly 32 bytes long.
    InvalidPasswordKdfSaltLength {
        /// Actual salt byte length.
        actual: usize,
    },
    /// Password KDF memory cost was lower than Paranoid accepts.
    PasswordKdfMemoryCostTooSmall {
        /// Actual Argon2id memory cost in KiB.
        actual: u32,
        /// Minimum accepted Argon2id memory cost in KiB.
        min: u32,
    },
    /// Password KDF iteration count was lower than Paranoid accepts.
    PasswordKdfIterationsTooFew {
        /// Actual Argon2id iteration count.
        actual: u32,
        /// Minimum accepted Argon2id iteration count.
        min: u32,
    },
    /// Password KDF parallelism was outside Paranoid's accepted range.
    PasswordKdfParallelismInvalid {
        /// Actual Argon2id parallelism.
        actual: u32,
        /// Minimum accepted Argon2id parallelism.
        min: u32,
        /// Maximum accepted Argon2id parallelism.
        max: u32,
    },
    /// Password KDF parameters were rejected by Argon2id.
    InvalidPasswordKdfParams,
    /// A random byte request exceeded the supported limit.
    RandomBytesTooLarge {
        /// Requested random byte length.
        actual: usize,
        /// Maximum supported random byte length.
        max: usize,
    },
    /// A random byte request must request at least one byte.
    RandomBytesLengthIsZero,
    /// A public or secret byte container exceeded the supported size.
    ByteContainerTooLarge {
        /// Requested byte container length.
        actual: usize,
        /// Maximum supported byte container length.
        max: usize,
    },
    /// A MAC over secret bytes was not the expected size.
    InvalidMacOverSecretLength {
        /// Actual MAC byte length.
        actual: usize,
    },
    /// A MAC over secret bytes used an unsupported version.
    UnsupportedMacOverSecretVersion {
        /// Version byte found in the MAC.
        version: u8,
    },
    /// Encoded edge text could not be decoded.
    EncodingDecode {
        /// Codec that rejected the encoded text.
        codec: &'static str,
        /// Underlying decoder error.
        source: data_encoding::DecodeError,
    },
    /// Encoded edge text exceeded the supported size before decode.
    EncodedTextTooLarge {
        /// Codec that rejected the encoded text.
        codec: &'static str,
        /// Actual encoded text byte length.
        actual: usize,
        /// Maximum accepted encoded text byte length.
        max: usize,
    },
    /// Edge text decoded into more bytes than the requested type accepts.
    DecodedBytesTooLarge {
        /// Codec that decoded the bytes.
        codec: &'static str,
        /// Actual decoded byte length.
        actual: usize,
        /// Maximum accepted decoded byte length for the target type.
        max: usize,
    },
    /// Payload bytes could not be serialized.
    PayloadSerialize(postcard::Error),
    /// Payload bytes could not be deserialized.
    PayloadDeserialize(postcard::Error),
    /// Encoded edge text decoded successfully but was not canonical.
    NonCanonicalEncoding {
        /// Codec that detected non-canonical text.
        codec: &'static str,
    },
    /// A Bitcoin Base58 value could not be decoded.
    Base58Decode(bs58::decode::Error),
    /// Mnemonic edge text was empty.
    EmptyMnemonic,
    /// Mnemonic edge text did not contain enough framing words.
    MnemonicTooShort {
        /// Actual word count.
        words: usize,
        /// Minimum accepted word count.
        min: usize,
    },
    /// Mnemonic edge text contained an unknown English word.
    UnknownMnemonicWord {
        /// Zero-based word index where the unknown word was found.
        index: usize,
    },
    /// Mnemonic edge text used an unsupported framing version.
    UnsupportedMnemonicVersion {
        /// Framing version decoded from the first word.
        version: usize,
    },
    /// Mnemonic edge text had an invalid padding shape.
    InvalidMnemonicPadding {
        /// Padding bit count decoded from the framing word.
        padding_bits: usize,
        /// Number of data words in the encoded text.
        data_word_count: usize,
    },
    /// Mnemonic edge text failed its checksum.
    InvalidMnemonicChecksum,
    /// Secure random byte generation failed.
    Random(RandomError),
    /// Purpose strings must not be empty.
    EmptyPurpose,
    /// Purpose strings must fit within the configured maximum size.
    PurposeTooLong {
        /// Actual purpose byte length.
        actual: usize,
        /// Maximum accepted purpose byte length.
        max: usize,
    },
    /// Purpose strings must use visible non-slash ASCII bytes.
    InvalidPurposeByte {
        /// Zero-based byte index where validation failed.
        index: usize,
        /// Invalid byte value.
        byte: u8,
    },
    /// Plaintext exceeded the configured maximum size.
    PlaintextTooLarge {
        /// Actual plaintext byte length.
        actual: usize,
        /// Maximum accepted plaintext byte length.
        max: usize,
    },
    /// Associated data exceeded the configured maximum size.
    AssociatedDataTooLarge {
        /// Actual associated-data byte length.
        actual: usize,
        /// Maximum accepted associated-data byte length.
        max: usize,
    },
    /// Encrypted envelope was empty.
    EmptyEnvelope,
    /// Encrypted envelope exceeded the configured maximum size.
    EnvelopeTooLarge {
        /// Actual encrypted envelope byte length.
        actual: usize,
        /// Maximum accepted encrypted envelope byte length.
        max: usize,
    },
    /// Encrypted envelope was too short to contain a valid paranoid v1 payload.
    EnvelopeTooShort {
        /// Actual encrypted envelope byte length.
        actual: usize,
        /// Minimum accepted encrypted envelope byte length.
        min: usize,
    },
    /// Encrypted envelope length was not a valid paranoid v1 bucket.
    InvalidEnvelopeLength {
        /// Actual encrypted envelope byte length.
        actual: usize,
    },
    /// Encrypted envelope did not start with the paranoid magic marker.
    InvalidMagic,
    /// Encrypted envelope used an unsupported version.
    UnsupportedVersion {
        /// Version byte found in the encrypted envelope.
        version: u8,
    },
    /// Encrypted envelope used an unsupported suite.
    UnsupportedSuite {
        /// Suite byte found in the encrypted envelope.
        suite: u8,
    },
    /// Key derivation failed.
    KeyDerivationFailed,
    /// Encryption failed.
    EncryptionFailed,
    /// Output allocation failed.
    AllocationFailed,
    /// Decryption failed.
    DecryptionFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKeyset => write!(f, "paranoid: at least one key is required"),
            Self::DuplicateKey { index } => {
                write!(f, "paranoid: duplicate key at index {index}")
            }
            Self::TooManyKeys { max } => {
                write!(f, "paranoid: keyset accepts at most {max} keys")
            }
            Self::InvalidKey32Length { actual } => {
                write!(f, "paranoid: key length {actual}, want {KEY32_SIZE}")
            }
            Self::InvalidPasswordKdfSaltLength { actual } => {
                write!(f, "paranoid: password KDF salt length {actual}, want 32")
            }
            Self::PasswordKdfMemoryCostTooSmall { actual, min } => {
                write!(
                    f,
                    "paranoid: password KDF memory cost {actual} KiB, min {min} KiB"
                )
            }
            Self::PasswordKdfIterationsTooFew { actual, min } => {
                write!(f, "paranoid: password KDF iterations {actual}, min {min}")
            }
            Self::PasswordKdfParallelismInvalid { actual, min, max } => {
                write!(
                    f,
                    "paranoid: password KDF parallelism {actual}, accepted range {min}..={max}"
                )
            }
            Self::InvalidPasswordKdfParams => {
                write!(f, "paranoid: invalid password KDF parameters")
            }
            Self::RandomBytesTooLarge { actual, max } => {
                write!(f, "paranoid: random byte length {actual}, max {max}")
            }
            Self::RandomBytesLengthIsZero => {
                write!(f, "paranoid: random byte length cannot be zero")
            }
            Self::ByteContainerTooLarge { actual, max } => {
                write!(f, "paranoid: byte container length {actual}, max {max}")
            }
            Self::InvalidMacOverSecretLength { actual } => {
                write!(
                    f,
                    "paranoid: mac-over-secret length {actual}, want {MAC_OVER_SECRET_SIZE}"
                )
            }
            Self::UnsupportedMacOverSecretVersion { version } => {
                write!(f, "paranoid: unsupported mac-over-secret version {version}")
            }
            Self::EncodingDecode { codec, source } => {
                write!(f, "paranoid: {codec} decode: {source}")
            }
            Self::EncodedTextTooLarge { codec, actual, max } => {
                write!(f, "paranoid: {codec} text length {actual}, max {max}")
            }
            Self::DecodedBytesTooLarge { codec, actual, max } => {
                write!(
                    f,
                    "paranoid: {codec} decoded byte length {actual}, max {max}"
                )
            }
            Self::PayloadSerialize(err) => write!(f, "paranoid: payload serialize: {err}"),
            Self::PayloadDeserialize(err) => write!(f, "paranoid: payload deserialize: {err}"),
            Self::NonCanonicalEncoding { codec } => {
                write!(f, "paranoid: {codec} text is not canonical")
            }
            Self::Base58Decode(err) => write!(f, "paranoid: base58 decode: {err}"),
            Self::EmptyMnemonic => {
                write!(f, "paranoid: mnemonic text is empty")
            }
            Self::MnemonicTooShort { words, min } => {
                write!(f, "paranoid: mnemonic text has {words} words, min {min}")
            }
            Self::UnknownMnemonicWord { index } => {
                write!(
                    f,
                    "paranoid: mnemonic text has an unknown word at index {index}"
                )
            }
            Self::UnsupportedMnemonicVersion { version } => {
                write!(f, "paranoid: unsupported mnemonic version {version}")
            }
            Self::InvalidMnemonicPadding {
                padding_bits,
                data_word_count,
            } => {
                write!(
                    f,
                    "paranoid: invalid mnemonic padding {padding_bits} for {data_word_count} data words"
                )
            }
            Self::InvalidMnemonicChecksum => {
                write!(f, "paranoid: invalid mnemonic checksum")
            }
            Self::Random(err) => write!(f, "paranoid: random bytes: {err}"),
            Self::EmptyPurpose => write!(f, "paranoid: purpose is empty"),
            Self::PurposeTooLong { actual, max } => {
                write!(f, "paranoid: purpose length {actual}, max {max}")
            }
            Self::InvalidPurposeByte { index, byte } => {
                write!(
                    f,
                    "paranoid: purpose byte at index {index} is not visible non-slash ASCII: {byte}"
                )
            }
            Self::PlaintextTooLarge { actual, max } => {
                write!(f, "paranoid: plaintext size {actual}, max {max}")
            }
            Self::AssociatedDataTooLarge { actual, max } => {
                write!(f, "paranoid: associated data size {actual}, max {max}")
            }
            Self::EmptyEnvelope => write!(f, "paranoid: encrypted envelope is empty"),
            Self::EnvelopeTooLarge { actual, max } => {
                write!(f, "paranoid: encrypted envelope size {actual}, max {max}")
            }
            Self::EnvelopeTooShort { actual, min } => {
                write!(f, "paranoid: encrypted envelope size {actual}, min {min}")
            }
            Self::InvalidEnvelopeLength { actual } => {
                write!(f, "paranoid: invalid encrypted envelope size {actual}")
            }
            Self::InvalidMagic => write!(f, "paranoid: invalid envelope magic"),
            Self::UnsupportedVersion { version } => {
                write!(f, "paranoid: unsupported version {version}")
            }
            Self::UnsupportedSuite { suite } => {
                write!(f, "paranoid: unsupported suite {suite}")
            }
            Self::KeyDerivationFailed => write!(f, "paranoid: key derivation failed"),
            Self::EncryptionFailed => write!(f, "paranoid: encryption failed"),
            Self::AllocationFailed => write!(f, "paranoid: output allocation failed"),
            Self::DecryptionFailed => write!(f, "paranoid: decryption failed"),
        }
    }
}

impl From<CryptoError> for Error {
    fn from(value: CryptoError) -> Self {
        match value {
            CryptoError::InvalidKeyLength { actual } => Self::InvalidKey32Length { actual },
            CryptoError::Random(err) => Self::Random(RandomError { source: err }),
            CryptoError::HkdfExpand => Self::KeyDerivationFailed,
            CryptoError::EncryptionFailed => Self::EncryptionFailed,
            CryptoError::DecryptionFailed => Self::DecryptionFailed,
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::EncodingDecode { source, .. } => Some(source),
            Self::PayloadSerialize(err) => Some(err),
            Self::PayloadDeserialize(err) => Some(err),
            Self::Base58Decode(err) => Some(err),
            Self::Random(err) => Some(err),
            _ => None,
        }
    }
}
