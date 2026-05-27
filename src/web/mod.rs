//! Web security helpers.
//!
//! The web module groups encrypted cookies and CSRF protection behind the
//! `web` feature.
//!
//! ```rust
//! # #[cfg(feature = "web")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use paranoid::crypto::{derive_keyset_from_latest_first_keys, random_key32};
//! use paranoid::web::{CookieManager, SecureCookieConfig};
//!
//! let keyset = derive_keyset_from_latest_first_keys([random_key32()?], "my-app.cookies.v1")?;
//! let cookies = CookieManager::from_keyset(keyset);
//! let session_cookie = cookies.secure_cookie::<String>(SecureCookieConfig::new("session"))?;
//! let cookie = session_cookie.new_cookie(&"session-id".to_owned())?;
//!
//! assert!(cookie.name().starts_with("__Host-"));
//! # Ok(())
//! # }
//! ```
//!
//! ```rust
//! # #[cfg(feature = "web")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use paranoid::crypto::{derive_keyset_from_latest_first_keys, random_key32};
//! use paranoid::web::{CookieManager, CsrfProtector, CsrfProtectorConfig};
//!
//! let keyset = derive_keyset_from_latest_first_keys([random_key32()?], "my-app.web.v1")?;
//! let cookies = CookieManager::from_keyset(keyset);
//! let csrf = CsrfProtector::new(CsrfProtectorConfig::new(cookies))?;
//!
//! assert!(csrf.cookie_name().starts_with("__Host-"));
//! # Ok(())
//! # }
//! ```

mod cookies;
mod csrf;
mod error;

pub use cookies::{
    ClientReadableCookie, ClientReadableCookieConfig, ClientReadableCookieNonHostOnly,
    ClientReadableCookieNonHostOnlyConfig, CookieManager, CookieManagerConfig, CookieMaxAgeSeconds,
    CookieSameSite, SecureCookie, SecureCookieConfig, SecureCookieNonHostOnly,
    SecureCookieNonHostOnlyConfig,
};
pub use csrf::{
    CsrfBinding, CsrfBindingExtractor, CsrfLayer, CsrfProtector, CsrfProtectorConfig, CsrfService,
    DEFAULT_CSRF_COOKIE_NAME, DEFAULT_CSRF_HEADER_NAME, DEFAULT_CSRF_TOKEN_MAX_AGE_SECONDS,
    MAX_CSRF_BINDING_SIZE,
};
pub use error::Error;
