use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;

use cookie::{Cookie, SameSite};
use http::header::COOKIE;
use http::{HeaderMap, Request};
use serde::{Serialize, de::DeserializeOwned};

use crate::crypto::bytes::public_vec_with_capacity;
use crate::crypto::{Base64Url, Encrypted, Keyset, decrypt, encrypt};
use crate::web::error::Error;

mod encrypted;
mod manager;
mod plaintext;
mod spec;

use encrypted::EncryptedCookie;
pub use manager::{CookieManager, CookieManagerConfig, CookieMaxAgeSeconds, CookieSameSite};
use plaintext::PlaintextCookie;
use spec::{
    CookieHttpOnlyMode, CookieScope, CookieSpec, missing_cookie_to_none, validate_cookie_name,
    validate_unprefixed_cookie_name,
};

const ENCRYPTED_COOKIE_CHILD_PURPOSE: &str = "paranoid.cookies.encrypted.v1";
const COOKIE_ASSOCIATED_DATA_CONTEXT: &[u8] = b"paranoid/cookie-associated-data/v1";
const HOST_PREFIX: &str = "__Host-";
const DEV_PREFIX: &str = "__Dev-";
const MAX_COOKIE_MAX_AGE_SECONDS: u64 = i64::MAX as u64;

/// Configuration for a host-only encrypted cookie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureCookieConfig {
    /// Caller-supplied cookie suffix. Do not include `__Host-` or `__Dev-`.
    pub name: String,
    /// Optional persistent cookie max-age. `None` emits a session cookie.
    pub max_age: Option<CookieMaxAgeSeconds>,
    /// Optional per-cookie SameSite override.
    pub same_site: Option<CookieSameSite>,
    /// Optional per-cookie Partitioned override.
    pub partitioned: Option<bool>,
}

impl SecureCookieConfig {
    /// Creates host-only encrypted cookie configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_age: None,
            same_site: None,
            partitioned: None,
        }
    }

    fn into_parts(self) -> CookieConfigParts {
        self.into_parts_with_http_only(None)
    }

    fn into_parts_with_http_only(self, http_only: Option<bool>) -> CookieConfigParts {
        CookieConfigParts {
            name: self.name,
            max_age: self.max_age,
            same_site: self.same_site,
            partitioned: self.partitioned,
            http_only,
        }
    }
}

/// Configuration for a non-host-only encrypted cookie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureCookieNonHostOnlyConfig {
    /// Caller-supplied cookie name. Do not include `__Host-` or `__Dev-`.
    pub name: String,
    /// Cookie path. Empty paths are normalized to `/`.
    pub path: String,
    /// Optional cookie domain. Empty domains are normalized to no domain.
    pub domain: Option<String>,
    /// Optional persistent cookie max-age. `None` emits a session cookie.
    pub max_age: Option<CookieMaxAgeSeconds>,
    /// Optional per-cookie SameSite override.
    pub same_site: Option<CookieSameSite>,
    /// Optional per-cookie Partitioned override.
    pub partitioned: Option<bool>,
}

impl SecureCookieNonHostOnlyConfig {
    /// Creates non-host-only encrypted cookie configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: "/".to_owned(),
            domain: None,
            max_age: None,
            same_site: None,
            partitioned: None,
        }
    }
}

/// Configuration for a host-only client-readable cookie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientReadableCookieConfig {
    /// Caller-supplied cookie suffix. Do not include `__Host-` or `__Dev-`.
    pub name: String,
    /// Optional persistent cookie max-age. `None` emits a session cookie.
    pub max_age: Option<CookieMaxAgeSeconds>,
    /// Optional per-cookie SameSite override.
    pub same_site: Option<CookieSameSite>,
    /// Optional per-cookie Partitioned override.
    pub partitioned: Option<bool>,
}

impl ClientReadableCookieConfig {
    /// Creates host-only client-readable cookie configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_age: None,
            same_site: None,
            partitioned: None,
        }
    }

    fn into_parts(self) -> CookieConfigParts {
        CookieConfigParts {
            name: self.name,
            max_age: self.max_age,
            same_site: self.same_site,
            partitioned: self.partitioned,
            http_only: None,
        }
    }
}

/// Configuration for a non-host-only client-readable cookie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientReadableCookieNonHostOnlyConfig {
    /// Caller-supplied cookie name. Do not include `__Host-` or `__Dev-`.
    pub name: String,
    /// Cookie path. Empty paths are normalized to `/`.
    pub path: String,
    /// Optional cookie domain. Empty domains are normalized to no domain.
    pub domain: Option<String>,
    /// Optional persistent cookie max-age. `None` emits a session cookie.
    pub max_age: Option<CookieMaxAgeSeconds>,
    /// Optional per-cookie SameSite override.
    pub same_site: Option<CookieSameSite>,
    /// Optional per-cookie Partitioned override.
    pub partitioned: Option<bool>,
}

impl ClientReadableCookieNonHostOnlyConfig {
    /// Creates non-host-only client-readable cookie configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: "/".to_owned(),
            domain: None,
            max_age: None,
            same_site: None,
            partitioned: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CookieConfigParts {
    name: String,
    max_age: Option<CookieMaxAgeSeconds>,
    same_site: Option<CookieSameSite>,
    partitioned: Option<bool>,
    http_only: Option<bool>,
}

/// Host-only encrypted cookie helper for typed serializable payloads.
pub struct SecureCookie<T> {
    encrypted: EncryptedCookie,
    payload: PhantomData<fn() -> T>,
}

impl<T> SecureCookie<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Returns the final emitted cookie name.
    pub fn name(&self) -> &str {
        self.encrypted.name()
    }

    /// Serializes, encrypts, and returns a configured cookie.
    pub fn new_cookie(&self, payload: &T) -> Result<Cookie<'static>, Error> {
        self.encrypted.new_cookie(payload)
    }

    /// Finds, decrypts, and deserializes this cookie from an HTTP request.
    pub fn get_from_request<B>(&self, request: &Request<B>) -> Result<T, Error> {
        self.encrypted.get_from_request(request)
    }

    /// Finds, decrypts, and deserializes this cookie from HTTP request headers.
    pub fn get_from_headers(&self, headers: &HeaderMap) -> Result<T, Error> {
        self.encrypted.get_from_headers(headers)
    }

    /// Finds this cookie from an HTTP request, returning `None` only when it is absent.
    pub fn get_optional_from_request<B>(&self, request: &Request<B>) -> Result<Option<T>, Error> {
        self.encrypted.get_optional_from_request(request)
    }

    /// Finds this cookie from HTTP request headers, returning `None` only when it is absent.
    pub fn get_optional_from_headers(&self, headers: &HeaderMap) -> Result<Option<T>, Error> {
        self.encrypted.get_optional_from_headers(headers)
    }

    /// Finds, decrypts, and deserializes this cookie from an HTTP `Cookie` header.
    pub fn get_from_cookie_header(&self, cookie_header: &str) -> Result<T, Error> {
        self.encrypted.get_from_cookie_header(cookie_header)
    }

    /// Finds this cookie from an HTTP `Cookie` header, returning `None` only when it is absent.
    pub fn get_optional_from_cookie_header(&self, cookie_header: &str) -> Result<Option<T>, Error> {
        self.encrypted
            .get_optional_from_cookie_header(cookie_header)
    }

    pub(crate) fn parse_from_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Cookie<'static>, Error> {
        self.encrypted.parse_from_request(request)
    }

    /// Decrypts and deserializes a parsed cookie previously emitted by this helper.
    pub fn get_from_cookie(&self, cookie: &Cookie<'_>) -> Result<T, Error> {
        self.encrypted.get_from_cookie(cookie)
    }

    /// Decrypts and deserializes a cookie value previously emitted by this helper.
    pub fn decode_cookie_value(&self, value: &str) -> Result<T, Error> {
        self.encrypted.decode_cookie_value(value)
    }

    /// Returns a configured deletion cookie for this helper.
    pub fn deletion_cookie(&self) -> Cookie<'static> {
        self.encrypted.deletion_cookie()
    }
}

impl<T> Clone for SecureCookie<T> {
    fn clone(&self) -> Self {
        Self {
            encrypted: self.encrypted.clone(),
            payload: PhantomData,
        }
    }
}

impl<T> fmt::Debug for SecureCookie<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureCookie")
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

/// Non-host-only encrypted cookie helper for typed serializable payloads.
pub struct SecureCookieNonHostOnly<T> {
    encrypted: EncryptedCookie,
    payload: PhantomData<fn() -> T>,
}

impl<T> SecureCookieNonHostOnly<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Returns the final emitted cookie name.
    pub fn name(&self) -> &str {
        self.encrypted.name()
    }

    /// Serializes, encrypts, and returns a configured cookie.
    pub fn new_cookie(&self, payload: &T) -> Result<Cookie<'static>, Error> {
        self.encrypted.new_cookie(payload)
    }

    /// Finds, decrypts, and deserializes this cookie from an HTTP request.
    pub fn get_from_request<B>(&self, request: &Request<B>) -> Result<T, Error> {
        self.encrypted.get_from_request(request)
    }

    /// Finds, decrypts, and deserializes this cookie from HTTP request headers.
    pub fn get_from_headers(&self, headers: &HeaderMap) -> Result<T, Error> {
        self.encrypted.get_from_headers(headers)
    }

    /// Finds this cookie from an HTTP request, returning `None` only when it is absent.
    pub fn get_optional_from_request<B>(&self, request: &Request<B>) -> Result<Option<T>, Error> {
        self.encrypted.get_optional_from_request(request)
    }

    /// Finds this cookie from HTTP request headers, returning `None` only when it is absent.
    pub fn get_optional_from_headers(&self, headers: &HeaderMap) -> Result<Option<T>, Error> {
        self.encrypted.get_optional_from_headers(headers)
    }

    /// Finds, decrypts, and deserializes this cookie from an HTTP `Cookie` header.
    pub fn get_from_cookie_header(&self, cookie_header: &str) -> Result<T, Error> {
        self.encrypted.get_from_cookie_header(cookie_header)
    }

    /// Finds this cookie from an HTTP `Cookie` header, returning `None` only when it is absent.
    pub fn get_optional_from_cookie_header(&self, cookie_header: &str) -> Result<Option<T>, Error> {
        self.encrypted
            .get_optional_from_cookie_header(cookie_header)
    }

    /// Decrypts and deserializes a parsed cookie previously emitted by this helper.
    pub fn get_from_cookie(&self, cookie: &Cookie<'_>) -> Result<T, Error> {
        self.encrypted.get_from_cookie(cookie)
    }

    /// Decrypts and deserializes a cookie value previously emitted by this helper.
    pub fn decode_cookie_value(&self, value: &str) -> Result<T, Error> {
        self.encrypted.decode_cookie_value(value)
    }

    /// Returns a configured deletion cookie for this helper.
    pub fn deletion_cookie(&self) -> Cookie<'static> {
        self.encrypted.deletion_cookie()
    }
}

impl<T> Clone for SecureCookieNonHostOnly<T> {
    fn clone(&self) -> Self {
        Self {
            encrypted: self.encrypted.clone(),
            payload: PhantomData,
        }
    }
}

impl<T> fmt::Debug for SecureCookieNonHostOnly<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureCookieNonHostOnly")
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

/// Host-only client-readable cookie helper.
pub struct ClientReadableCookie<T = String> {
    plaintext: PlaintextCookie,
    value: PhantomData<fn() -> T>,
}

impl<T> ClientReadableCookie<T>
where
    T: FromStr + fmt::Display,
    T::Err: fmt::Display,
{
    /// Returns the final emitted cookie name.
    pub fn name(&self) -> &str {
        self.plaintext.name()
    }

    /// Renders `value`, verifies the rendered text can be parsed as `T`, and
    /// returns a configured cookie containing that text.
    pub fn new_cookie(&self, value: impl Into<T>) -> Result<Cookie<'static>, Error> {
        self.plaintext
            .new_cookie(&render_client_readable_cookie_value(value.into())?)
    }

    /// Finds and parses this cookie from an HTTP request.
    pub fn get_from_request<B>(&self, request: &Request<B>) -> Result<T, Error> {
        self.plaintext.get_from_request(request)
    }

    /// Finds and parses this cookie from HTTP request headers.
    pub fn get_from_headers(&self, headers: &HeaderMap) -> Result<T, Error> {
        self.plaintext.get_from_headers(headers)
    }

    /// Finds this cookie from an HTTP request, returning `None` only when it is absent.
    pub fn get_optional_from_request<B>(&self, request: &Request<B>) -> Result<Option<T>, Error> {
        self.plaintext.get_optional_from_request(request)
    }

    /// Finds this cookie from HTTP request headers, returning `None` only when it is absent.
    pub fn get_optional_from_headers(&self, headers: &HeaderMap) -> Result<Option<T>, Error> {
        self.plaintext.get_optional_from_headers(headers)
    }

    /// Finds and parses this cookie from an HTTP `Cookie` header.
    pub fn get_from_cookie_header(&self, cookie_header: &str) -> Result<T, Error> {
        self.plaintext.get_from_cookie_header(cookie_header)
    }

    /// Finds this cookie from an HTTP `Cookie` header, returning `None` only when it is absent.
    pub fn get_optional_from_cookie_header(&self, cookie_header: &str) -> Result<Option<T>, Error> {
        self.plaintext
            .get_optional_from_cookie_header(cookie_header)
    }

    /// Parses a cookie previously emitted by this helper.
    pub fn get_from_cookie(&self, cookie: &Cookie<'_>) -> Result<T, Error> {
        self.plaintext.get_from_cookie(cookie)
    }

    /// Parses a raw cookie value previously emitted by this helper.
    pub fn parse_cookie_value(&self, value: &str) -> Result<T, Error> {
        self.plaintext.parse_cookie_value(value)
    }

    /// Returns a configured deletion cookie for this helper.
    pub fn deletion_cookie(&self) -> Cookie<'static> {
        self.plaintext.deletion_cookie()
    }
}

impl<T> Clone for ClientReadableCookie<T> {
    fn clone(&self) -> Self {
        Self {
            plaintext: self.plaintext.clone(),
            value: PhantomData,
        }
    }
}

impl<T> fmt::Debug for ClientReadableCookie<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientReadableCookie")
            .field("plaintext", &self.plaintext)
            .finish()
    }
}

/// Non-host-only client-readable cookie helper.
pub struct ClientReadableCookieNonHostOnly<T = String> {
    plaintext: PlaintextCookie,
    value: PhantomData<fn() -> T>,
}

impl<T> ClientReadableCookieNonHostOnly<T>
where
    T: FromStr + fmt::Display,
    T::Err: fmt::Display,
{
    /// Returns the final emitted cookie name.
    pub fn name(&self) -> &str {
        self.plaintext.name()
    }

    /// Renders `value`, verifies the rendered text can be parsed as `T`, and
    /// returns a configured cookie containing that text.
    pub fn new_cookie(&self, value: impl Into<T>) -> Result<Cookie<'static>, Error> {
        self.plaintext
            .new_cookie(&render_client_readable_cookie_value(value.into())?)
    }

    /// Finds and parses this cookie from an HTTP request.
    pub fn get_from_request<B>(&self, request: &Request<B>) -> Result<T, Error> {
        self.plaintext.get_from_request(request)
    }

    /// Finds and parses this cookie from HTTP request headers.
    pub fn get_from_headers(&self, headers: &HeaderMap) -> Result<T, Error> {
        self.plaintext.get_from_headers(headers)
    }

    /// Finds this cookie from an HTTP request, returning `None` only when it is absent.
    pub fn get_optional_from_request<B>(&self, request: &Request<B>) -> Result<Option<T>, Error> {
        self.plaintext.get_optional_from_request(request)
    }

    /// Finds this cookie from HTTP request headers, returning `None` only when it is absent.
    pub fn get_optional_from_headers(&self, headers: &HeaderMap) -> Result<Option<T>, Error> {
        self.plaintext.get_optional_from_headers(headers)
    }

    /// Finds and parses this cookie from an HTTP `Cookie` header.
    pub fn get_from_cookie_header(&self, cookie_header: &str) -> Result<T, Error> {
        self.plaintext.get_from_cookie_header(cookie_header)
    }

    /// Finds this cookie from an HTTP `Cookie` header, returning `None` only when it is absent.
    pub fn get_optional_from_cookie_header(&self, cookie_header: &str) -> Result<Option<T>, Error> {
        self.plaintext
            .get_optional_from_cookie_header(cookie_header)
    }

    /// Parses a cookie previously emitted by this helper.
    pub fn get_from_cookie(&self, cookie: &Cookie<'_>) -> Result<T, Error> {
        self.plaintext.get_from_cookie(cookie)
    }

    /// Parses a raw cookie value previously emitted by this helper.
    pub fn parse_cookie_value(&self, value: &str) -> Result<T, Error> {
        self.plaintext.parse_cookie_value(value)
    }

    /// Returns a configured deletion cookie for this helper.
    pub fn deletion_cookie(&self) -> Cookie<'static> {
        self.plaintext.deletion_cookie()
    }
}

impl<T> Clone for ClientReadableCookieNonHostOnly<T> {
    fn clone(&self) -> Self {
        Self {
            plaintext: self.plaintext.clone(),
            value: PhantomData,
        }
    }
}

impl<T> fmt::Debug for ClientReadableCookieNonHostOnly<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientReadableCookieNonHostOnly")
            .field("plaintext", &self.plaintext)
            .finish()
    }
}

#[cfg(test)]
mod tests;

fn render_client_readable_cookie_value<T>(value: T) -> Result<String, Error>
where
    T: FromStr + fmt::Display,
    T::Err: fmt::Display,
{
    let rendered = value.to_string();
    let _: T = rendered
        .parse()
        .map_err(|error: T::Err| Error::ClientReadableCookieParse {
            message: error.to_string(),
        })?;
    Ok(rendered)
}
