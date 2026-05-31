//! Misuse-resistant application security primitives.
//!
//! Default features are disabled. Consumers opt into the namespaces they use:
//! `crypto`, `id`, `local-lock`, `local-env-vault`, `web`, or `db`.
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

#[cfg(feature = "auth")]
mod auth_core;
