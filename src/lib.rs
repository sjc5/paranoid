//! Misuse-resistant application security primitives.
//!
//! Default features are disabled. Consumers opt into the namespaces they use:
//! `crypto`, `id`, `local-lock`, `local-env-vault`, `web`, `db`, or
//! `db-test-harness`.
//!
//! The Postgres-backed APIs are intentionally namespaced under `kv`, `fleet`,
//! and `queue` so callers can use plain names like `Store` and `Key` without
//! losing the package boundary that gives those names meaning.
//!
#![deny(missing_docs)]

//! # Typed encryption
//!
//! ```rust
//! # #[cfg(not(feature = "crypto"))]
//! # fn main() {}
//! # #[cfg(feature = "crypto")]
//! use serde::{Deserialize, Serialize};
//!
//! # #[cfg(feature = "crypto")]
//! #[derive(Debug, Deserialize, PartialEq, Serialize)]
//! struct SessionPayload {
//!     user_id: String,
//! }
//!
//! # #[cfg(feature = "crypto")]
//! # fn main() -> Result<(), paranoid::crypto::Error> {
//! let current_key = paranoid::crypto::random_key32()?;
//! let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys(
//!     [current_key],
//!     "my-app.sessions.v1",
//! )?;
//!
//! let payload = SessionPayload { user_id: "u123".to_owned() };
//! let encrypted = paranoid::crypto::encrypt(&keyset, &payload, b"session-cookie")?;
//! let decrypted = paranoid::crypto::decrypt(&keyset, &encrypted, b"session-cookie")?;
//! assert_eq!(decrypted, payload);
//! # Ok(())
//! # }
//! ```
//!
//! # Exact byte encryption
//!
//! ```rust
//! # #[cfg(not(feature = "crypto"))]
//! # fn main() {}
//! # #[cfg(feature = "crypto")]
//! use paranoid::crypto::SecretBytes;
//!
//! # #[cfg(feature = "crypto")]
//! # fn main() -> Result<(), paranoid::crypto::Error> {
//! let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys(
//!     [paranoid::crypto::random_key32()?],
//!     "my-app.backups.v1",
//! )?;
//!
//! let plaintext = SecretBytes::try_from(b"already canonical bytes".as_slice())?;
//! let encrypted = paranoid::crypto::encrypt(&keyset, &plaintext, b"")?;
//! let decrypted: SecretBytes = paranoid::crypto::decrypt(&keyset, &encrypted, b"")?;
//!
//! assert_eq!(decrypted.expose_secret(), b"already canonical bytes");
//! # Ok(())
//! # }
//! ```
//!
//! # MACs over secret bytes
//!
//! ```rust
//! # #[cfg(not(feature = "crypto"))]
//! # fn main() {}
//! # #[cfg(feature = "crypto")]
//! use paranoid::crypto::SecretBytes;
//!
//! # #[cfg(feature = "crypto")]
//! # fn main() -> Result<(), paranoid::crypto::Error> {
//! let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys(
//!     [paranoid::crypto::random_key32()?],
//!     "my-app.tokens.v1",
//! )?;
//! let secret = paranoid::crypto::random_secret_bytes(32)?;
//! let mac = secret.to_mac(&keyset, b"session-token")?;
//!
//! assert!(mac.verify(&keyset, secret.expose_secret(), b"session-token"));
//! # Ok(())
//! # }
//! ```
//!
//! # Edge codecs
//!
//! ```rust
//! # #[cfg(not(feature = "crypto"))]
//! # fn main() {}
//! # #[cfg(feature = "crypto")]
//! use paranoid::crypto::{Base64Url, Encrypted};
//!
//! # #[cfg(feature = "crypto")]
//! # fn main() -> Result<(), paranoid::crypto::Error> {
//! let key = paranoid::crypto::random_key32()?;
//! let backup_words = key.to_mnemonic()?;
//! let decoded_key = backup_words.decode()?;
//! assert_eq!(decoded_key.expose_secret(), key.expose_secret());
//!
//! let keyset = paranoid::crypto::derive_keyset_from_latest_first_keys([decoded_key], "my-app.v1")?;
//! let recovery_material = "recovery material".to_owned();
//! let encrypted = paranoid::crypto::encrypt(&keyset, &recovery_material, b"")?;
//! let transport_text = encrypted.to_base64_url()?;
//! let decoded_envelope = Base64Url::<Encrypted<String>>::parse_str(transport_text.as_str())?.decode()?;
//! assert_eq!(decoded_envelope.as_bytes(), encrypted.as_bytes());
//! # Ok(())
//! # }
//! ```
//!
//! # Ed25519 signatures
//!
//! ```rust
//! # #[cfg(not(feature = "crypto"))]
//! # fn main() {}
//! # #[cfg(feature = "crypto")]
//! use paranoid::crypto::Ed25519KeyPair;
//!
//! # #[cfg(feature = "crypto")]
//! # fn main() -> Result<(), paranoid::crypto::Error> {
//! let seed = paranoid::crypto::random_key32()?;
//! let key_pair = Ed25519KeyPair::from_seed(&seed);
//! let public_key = key_pair.public_key();
//!
//! let signature = key_pair.sign(b"canonical message bytes");
//! assert!(public_key.verify(b"canonical message bytes", &signature).is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! # Password-sealed keys
//!
//! A 32-byte key can be sealed at rest under a password in one of two mutually exclusive
//! shapes. The stored-salt shape generates and stores its own Argon2id salt; the
//! caller-salt shape never generates or stores a salt, so the caller must supply the
//! exact same secret salt back on open (for example, a second independently held factor).
//!
//! ```rust
//! # #[cfg(not(feature = "crypto"))]
//! # fn main() {}
//! # #[cfg(feature = "crypto")]
//! use paranoid::crypto::{PasswordKdfParams, SecretBytes};
//!
//! # #[cfg(feature = "crypto")]
//! # fn fill_random(buf: &mut [u8]) -> Result<(), paranoid::crypto::Error> {
//! # let random = paranoid::crypto::random_secret_bytes(buf.len())?;
//! # buf.copy_from_slice(random.expose_secret());
//! # Ok(())
//! # }
//! # #[cfg(feature = "crypto")]
//! # fn main() -> Result<(), paranoid::crypto::Error> {
//! let key = paranoid::crypto::random_key32()?;
//! let password: SecretBytes = SecretBytes::try_from(b"correct horse battery staple".as_slice())?;
//! let params = PasswordKdfParams::interactive_default();
//!
//! // Stored-salt shape: the salt is generated here and travels inside the record.
//! let stored_salt_record =
//!     paranoid::crypto::seal_key32_with_password(&key, &password, params, fill_random)?;
//! let opened = paranoid::crypto::open_key32_with_password(&stored_salt_record, &password)?;
//! assert_eq!(opened.expose_secret(), key.expose_secret());
//!
//! // Caller-salt shape: the caller holds the salt out of band and supplies it on open.
//! let caller_salt = paranoid::crypto::random_key32()?;
//! let caller_salt_record = paranoid::crypto::seal_key32_with_password_and_caller_salt(
//!     &key,
//!     &password,
//!     &caller_salt,
//!     params,
//!     fill_random,
//! )?;
//! let opened = paranoid::crypto::open_key32_with_password_and_caller_salt(
//!     &caller_salt_record,
//!     &password,
//!     &caller_salt,
//! )?;
//! assert_eq!(opened.expose_secret(), key.expose_secret());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "db")]
pub mod db;
#[cfg(feature = "db")]
pub mod fleet;
#[cfg(feature = "id")]
pub mod id;
#[cfg(feature = "db")]
pub mod kv;
#[cfg(feature = "local-env-vault")]
pub mod local_env_vault;
#[cfg(feature = "local-lock")]
pub mod local_lock;
#[cfg(feature = "db")]
pub mod queue;
#[cfg(feature = "web")]
pub mod web;

/// Fuzz-only entry points into otherwise-internal `db` parsing boundaries.
///
/// This module exists **only under `--cfg fuzzing`** (set by cargo-fuzz) so the fuzz crate
/// can drive encapsulated boundaries with adversarial bytes. It is never part of a normal
/// build and does not widen the public API.
#[cfg(all(fuzzing, feature = "db"))]
pub mod db_fuzz {
    /// Fuzz the `portable_query` SQL template placeholder scanner: rewrites `$1`, `$2`,
    /// ... placeholders in `template` into the corresponding entry of `fragments`
    /// (1-indexed), skipping over string literals, quoted identifiers, and comments.
    pub fn render_portable_query_sql(
        template: &str,
        fragments: &[String],
    ) -> Result<String, crate::db::Error> {
        crate::db::fuzz_render_portable_query_sql(template, fragments)
    }
}
