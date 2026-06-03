use std::fmt;
use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use cookie::Cookie;
use http::header::{HOST, HeaderName, HeaderValue, ORIGIN, REFERER, SET_COOKIE};
use http::{HeaderMap, Request, Response};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_layer::Layer;
use tower_service::Service;

use crate::crypto::{SecretBytes, random_array};
use crate::web::cookies::{
    CookieManager, CookieMaxAgeSeconds, CookieSameSite, SecureCookie, SecureCookieConfig,
};
use crate::web::error::Error;

const CSRF_NONCE_SIZE: usize = 16;

/// Maximum CSRF binding byte length.
pub const MAX_CSRF_BINDING_SIZE: usize = 1024;

mod header_helpers;
mod host_helpers;
mod origin_helpers;

use header_helpers::{append_set_cookie_header, header_to_nonempty_str, submitted_token};
use host_helpers::{is_localhost_host, request_host};
use origin_helpers::{normalize_allowed_origins, normalize_request_origin_header};

/// Callback type that extracts CSRF token binding bytes from HTTP headers.
pub type CsrfBindingExtractor =
    dyn Fn(&HeaderMap) -> Result<Option<CsrfBinding>, Error> + Send + Sync + 'static;

type CsrfFailureResponse<ResponseBody> =
    dyn Fn(Error) -> Response<ResponseBody> + Send + Sync + 'static;

type CsrfServiceFuture<ResponseBody, ServiceError> =
    Pin<Box<dyn Future<Output = Result<Response<ResponseBody>, ServiceError>>>>;

/// Default CSRF cookie suffix.
pub const DEFAULT_CSRF_COOKIE_NAME: &str = "csrf_token";

/// Default HTTP header name applications can use for submitted CSRF tokens.
pub const DEFAULT_CSRF_HEADER_NAME: &str = "X-CSRF-Token";

/// Default CSRF token lifetime in seconds.
pub const DEFAULT_CSRF_TOKEN_MAX_AGE_SECONDS: u64 = 4 * 60 * 60;

enum CsrfBindingKind {}

/// Bytes that bind a CSRF token to the current stateless request identity.
pub struct CsrfBinding {
    bytes: SecretBytes<CsrfBindingKind>,
}

impl CsrfBinding {
    /// Copies non-empty binding bytes into a zeroizing buffer.
    pub fn from_non_empty_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyCsrfBinding);
        }
        if bytes.len() > MAX_CSRF_BINDING_SIZE {
            return Err(Error::CsrfBindingTooLarge {
                actual: bytes.len(),
                max: MAX_CSRF_BINDING_SIZE,
            });
        }
        Ok(Self {
            bytes: SecretBytes::try_from(bytes)?,
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

impl fmt::Debug for CsrfBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfBinding")
            .field("len", &self.as_bytes().len())
            .finish()
    }
}

/// CSRF helper configuration.
pub struct CsrfProtectorConfig {
    /// Cookie manager used for encrypted token cookies.
    pub cookie_manager: CookieManager,
    /// Extracts the current token binding from HTTP headers.
    pub extract_binding_from_headers: Arc<CsrfBindingExtractor>,
    /// Host-only cookie suffix.
    pub cookie_name: String,
    /// HTTP header name used for submitted CSRF tokens.
    pub header_name: HeaderName,
    /// CSRF token cookie max-age.
    pub token_max_age: CookieMaxAgeSeconds,
    /// Optional origin allowlist for unsafe requests.
    ///
    /// When non-empty, unsafe requests must include an `Origin` or `Referer`
    /// header that matches this allowlist.
    pub allowed_origins: Vec<String>,
}

impl CsrfProtectorConfig {
    /// Creates CSRF configuration using `cookie_manager`.
    pub fn new(cookie_manager: CookieManager) -> Self {
        Self {
            cookie_manager,
            extract_binding_from_headers: Arc::new(|_| Ok(None)),
            cookie_name: DEFAULT_CSRF_COOKIE_NAME.to_owned(),
            header_name: DEFAULT_CSRF_HEADER_NAME
                .parse()
                .expect("default CSRF header name is valid"),
            token_max_age: CookieMaxAgeSeconds::new(DEFAULT_CSRF_TOKEN_MAX_AGE_SECONDS)
                .expect("default CSRF max-age is non-zero and representable"),
            allowed_origins: Vec::new(),
        }
    }
}

impl fmt::Debug for CsrfProtectorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfProtectorConfig")
            .field("cookie_manager", &self.cookie_manager)
            .field("extract_binding_from_headers", &"[callback]")
            .field("cookie_name", &self.cookie_name)
            .field("header_name", &self.header_name)
            .field("token_max_age", &self.token_max_age)
            .field("allowed_origins", &self.allowed_origins)
            .finish()
    }
}

/// Framework-agnostic CSRF token issuer and verifier.
pub struct CsrfProtector {
    cookie_manager: CookieManager,
    extract_binding_from_headers: Arc<CsrfBindingExtractor>,
    cookie: SecureCookie<CsrfCookiePayload>,
    header_name: HeaderName,
    token_max_age: CookieMaxAgeSeconds,
    allowed_origins: Vec<String>,
}

impl CsrfProtector {
    /// Creates a CSRF protector from cookie policy.
    pub fn new(config: CsrfProtectorConfig) -> Result<Self, Error> {
        let allowed_origins = normalize_allowed_origins(config.allowed_origins)?;
        let mut cookie_config = SecureCookieConfig::new(config.cookie_name);
        cookie_config.max_age = Some(config.token_max_age);
        cookie_config.same_site = Some(CookieSameSite::Lax);
        let cookie = config
            .cookie_manager
            .secure_cookie_with_http_only(cookie_config, false)?;
        Ok(Self {
            cookie_manager: config.cookie_manager,
            extract_binding_from_headers: config.extract_binding_from_headers,
            cookie,
            header_name: config.header_name,
            token_max_age: config.token_max_age,
            allowed_origins,
        })
    }

    /// Returns the final emitted CSRF cookie name.
    pub fn cookie_name(&self) -> &str {
        self.cookie.name()
    }

    /// Returns the submitted-token HTTP header name.
    pub fn header_name(&self) -> &HeaderName {
        &self.header_name
    }

    /// Issues a fresh CSRF token cookie for the request's extracted binding.
    pub fn cycle_token_cookie_for_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Cookie<'static>, Error> {
        self.validate_development_request_host_is_localhost(request)?;
        let binding = self.extract_binding(request)?;
        self.new_token_cookie(binding.as_ref())
    }

    /// Issues a fresh CSRF token cookie for an explicit binding.
    pub fn cycle_token_cookie_for_binding(
        &self,
        binding: Option<&CsrfBinding>,
    ) -> Result<Cookie<'static>, Error> {
        self.new_token_cookie(binding)
    }

    /// Issues a fresh token only when the request does not already carry a valid token.
    pub fn issue_token_cookie_if_needed_for_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Option<Cookie<'static>>, Error> {
        self.validate_development_request_host_is_localhost(request)?;
        let binding = self.extract_binding(request)?;
        if let Ok(cookie) = self.cookie.parse_from_request(request)
            && let Ok(payload) = self.payload_from_cookie(&cookie)
            && payload.is_valid(current_unix_seconds()?)
            && binding_matches(payload.binding.as_deref(), binding.as_ref())
        {
            return Ok(None);
        }
        self.new_token_cookie(binding.as_ref()).map(Some)
    }

    /// Verifies CSRF protection for an HTTP request.
    pub fn verify_request<B>(&self, request: &Request<B>) -> Result<(), Error> {
        self.validate_development_request_host_is_localhost(request)?;
        if is_csrf_safe_method(request.method().as_str()) {
            return Ok(());
        }

        self.verify_unsafe_request(request)
            .map_err(|failure| failure.error)
    }

    fn verify_unsafe_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(), CsrfVerificationFailure> {
        self.validate_origin(request.headers())
            .map_err(CsrfVerificationFailure::without_self_heal)?;
        let binding = self
            .extract_binding(request)
            .map_err(CsrfVerificationFailure::without_self_heal)?;
        let parsed_cookie = match self.cookie.parse_from_request(request) {
            Ok(cookie) => cookie,
            Err(error) => return Err(CsrfVerificationFailure::with_self_heal(error, binding)),
        };
        let payload = match self.payload_from_cookie(&parsed_cookie) {
            Ok(payload) => payload,
            Err(error) => return Err(CsrfVerificationFailure::with_self_heal(error, binding)),
        };
        if !payload
            .is_valid(current_unix_seconds().map_err(CsrfVerificationFailure::without_self_heal)?)
        {
            return Err(CsrfVerificationFailure::with_self_heal(
                Error::CsrfTokenInvalidOrExpired,
                binding,
            ));
        }

        let submitted_token = submitted_token(request.headers(), &self.header_name)
            .map_err(CsrfVerificationFailure::without_self_heal)?;
        if submitted_token
            .as_bytes()
            .ct_eq(parsed_cookie.value().as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(CsrfVerificationFailure::without_self_heal(
                Error::CsrfTokenMismatch,
            ));
        }

        if !binding_matches(payload.binding.as_deref(), binding.as_ref()) {
            return Err(CsrfVerificationFailure::with_self_heal(
                Error::CsrfBindingMismatch,
                binding,
            ));
        }
        Ok(())
    }

    fn new_token_cookie(&self, binding: Option<&CsrfBinding>) -> Result<Cookie<'static>, Error> {
        let payload = CsrfCookiePayload {
            nonce: random_array::<CSRF_NONCE_SIZE>()?,
            expires_at_unix: current_unix_seconds()?
                .checked_add(self.token_max_age.get() as i64)
                .ok_or(Error::CsrfExpirationOverflow)?,
            binding: binding.map(|binding| binding.as_bytes().to_owned()),
        };
        self.cookie.new_cookie(&payload)
    }

    fn payload_from_cookie(&self, cookie: &Cookie<'_>) -> Result<CsrfCookiePayload, Error> {
        self.cookie.get_from_cookie(cookie)
    }

    fn extract_binding<B>(&self, request: &Request<B>) -> Result<Option<CsrfBinding>, Error> {
        (self.extract_binding_from_headers)(request.headers())
    }

    fn validate_origin(&self, headers: &HeaderMap) -> Result<(), Error> {
        if self.allowed_origins.is_empty() {
            return Ok(());
        }
        if let Some(origin_header) = header_to_nonempty_str(headers, &ORIGIN, "Origin")? {
            return self.validate_origin_header(origin_header, "Origin");
        }
        if let Some(referer_header) = header_to_nonempty_str(headers, &REFERER, "Referer")? {
            return self.validate_origin_header(referer_header, "Referer");
        }
        Err(Error::CsrfOriginAndRefererMissing)
    }

    fn validate_origin_header(&self, header: &str, label: &'static str) -> Result<(), Error> {
        let normalized = normalize_request_origin_header(header, label)?;
        if self
            .allowed_origins
            .iter()
            .any(|allowed| allowed == &normalized)
        {
            return Ok(());
        }
        Err(Error::CsrfOriginNotAllowed { origin: normalized })
    }

    fn validate_development_request_host_is_localhost<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(), Error> {
        if !self.cookie_manager.is_development() {
            return Ok(());
        }
        let host = request_host(request).unwrap_or("");
        if is_localhost_host(host) {
            return Ok(());
        }
        Err(Error::DevelopmentModeNonLocalhostHost {
            host: host.to_owned(),
        })
    }
}

impl fmt::Debug for CsrfProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfProtector")
            .field("cookie_name", &self.cookie_name())
            .field("header_name", &self.header_name)
            .field("token_max_age", &self.token_max_age)
            .field("allowed_origin_count", &self.allowed_origins.len())
            .finish()
    }
}

struct CsrfVerificationFailure {
    error: Error,
    self_heal_binding: Option<Option<CsrfBinding>>,
}

impl CsrfVerificationFailure {
    fn without_self_heal(error: Error) -> Self {
        Self {
            error,
            self_heal_binding: None,
        }
    }

    fn with_self_heal(error: Error, binding: Option<CsrfBinding>) -> Self {
        Self {
            error,
            self_heal_binding: Some(binding),
        }
    }
}

/// Tower layer that applies CSRF verification and token refresh behavior.
#[derive(Clone)]
pub struct CsrfLayer<ResponseBody> {
    protector: Arc<CsrfProtector>,
    failure_response: Arc<CsrfFailureResponse<ResponseBody>>,
}

impl<ResponseBody> CsrfLayer<ResponseBody> {
    /// Creates a Tower layer from a CSRF protector and rejection response callback.
    pub fn new(
        protector: impl Into<Arc<CsrfProtector>>,
        failure_response: impl Fn(Error) -> Response<ResponseBody> + Send + Sync + 'static,
    ) -> Self {
        Self {
            protector: protector.into(),
            failure_response: Arc::new(failure_response),
        }
    }
}

impl<S, ResponseBody> Layer<S> for CsrfLayer<ResponseBody> {
    type Service = CsrfService<S, ResponseBody>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            protector: self.protector.clone(),
            failure_response: self.failure_response.clone(),
        }
    }
}

impl<ResponseBody> fmt::Debug for CsrfLayer<ResponseBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfLayer")
            .field("protector", &self.protector)
            .field("failure_response", &"[callback]")
            .finish()
    }
}

/// Tower service produced by [`CsrfLayer`].
#[derive(Clone)]
pub struct CsrfService<S, ResponseBody> {
    inner: S,
    protector: Arc<CsrfProtector>,
    failure_response: Arc<CsrfFailureResponse<ResponseBody>>,
}

impl<S, RequestBody, ResponseBody> Service<Request<RequestBody>> for CsrfService<S, ResponseBody>
where
    S: Service<Request<RequestBody>, Response = Response<ResponseBody>>,
    S::Future: 'static,
    S::Error: 'static,
    RequestBody: 'static,
    ResponseBody: 'static,
{
    type Response = Response<ResponseBody>;
    type Error = S::Error;
    type Future = CsrfServiceFuture<ResponseBody, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<RequestBody>) -> Self::Future {
        if is_csrf_safe_method(request.method().as_str()) {
            return self.call_safe_request(request);
        }
        if let Err(error) = self
            .protector
            .validate_development_request_host_is_localhost(&request)
        {
            let response = (self.failure_response)(error);
            return Box::pin(ready(Ok(response)));
        }
        match self.protector.verify_unsafe_request(&request) {
            Ok(()) => Box::pin(self.inner.call(request)),
            Err(failure) => {
                let response = self.response_for_failure(failure);
                Box::pin(ready(Ok(response)))
            }
        }
    }
}

impl<S, ResponseBody> CsrfService<S, ResponseBody> {
    fn call_safe_request<RequestBody>(
        &mut self,
        request: Request<RequestBody>,
    ) -> CsrfServiceFuture<ResponseBody, S::Error>
    where
        S: Service<Request<RequestBody>, Response = Response<ResponseBody>>,
        S::Future: 'static,
        S::Error: 'static,
        RequestBody: 'static,
        ResponseBody: 'static,
    {
        match self
            .protector
            .issue_token_cookie_if_needed_for_request(&request)
        {
            Ok(cookie) => {
                let future = self.inner.call(request);
                let failure_response = self.failure_response.clone();
                Box::pin(async move {
                    let mut response = future.await?;
                    if let Some(cookie) = cookie
                        && let Err(error) =
                            append_set_cookie_header(response.headers_mut(), &cookie)
                    {
                        return Ok((failure_response)(error));
                    }
                    Ok(response)
                })
            }
            Err(error) => {
                let response = (self.failure_response)(error);
                Box::pin(ready(Ok(response)))
            }
        }
    }

    fn response_for_failure(&self, failure: CsrfVerificationFailure) -> Response<ResponseBody> {
        let mut response = (self.failure_response)(failure.error);
        if let Some(binding) = failure.self_heal_binding {
            let cookie = match self.protector.new_token_cookie(binding.as_ref()) {
                Ok(cookie) => cookie,
                Err(error) => return (self.failure_response)(error),
            };
            if let Err(error) = append_set_cookie_header(response.headers_mut(), &cookie) {
                return (self.failure_response)(error);
            }
        }
        response
    }
}

impl<S, ResponseBody> fmt::Debug for CsrfService<S, ResponseBody>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfService")
            .field("inner", &self.inner)
            .field("protector", &self.protector)
            .field("failure_response", &"[callback]")
            .finish()
    }
}

fn is_csrf_safe_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

#[derive(Debug, Deserialize, Serialize)]
struct CsrfCookiePayload {
    nonce: [u8; CSRF_NONCE_SIZE],
    expires_at_unix: i64,
    binding: Option<Vec<u8>>,
}

impl CsrfCookiePayload {
    fn is_valid(&self, now_unix: i64) -> bool {
        self.nonce != [0_u8; CSRF_NONCE_SIZE] && now_unix < self.expires_at_unix
    }
}

fn current_unix_seconds() -> Result<i64, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::ClockBeforeUnixEpoch)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| Error::CsrfExpirationOverflow)
}

fn binding_matches(left: Option<&[u8]>, right: Option<&CsrfBinding>) -> bool {
    match (left, right.map(CsrfBinding::as_bytes)) {
        (None, None) => true,
        (Some(left), Some(right)) => left.ct_eq(right).unwrap_u8() == 1,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
