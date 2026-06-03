use std::error::Error as StdError;
use std::fmt;

/// Errors returned by Paranoid web security helpers.
#[derive(Debug)]
pub enum Error {
    /// A lower-level crypto or edge-codec operation failed.
    Crypto(crate::crypto::Error),
    /// Output allocation failed.
    AllocationFailed,
    /// Cookie header text could not be parsed.
    CookieParse(cookie::ParseError),
    /// Cookie header bytes were not valid visible header text.
    CookieHeaderDecode(http::header::ToStrError),
    /// A Set-Cookie value could not be represented as an HTTP header value.
    CookieSetHeaderInvalid(http::header::InvalidHeaderValue),
    /// Cookie names must not be empty.
    EmptyCookieName,
    /// A caller-supplied cookie name already contained a prefix managed by this crate.
    ManagedCookieNamePrefix {
        /// Prefix that must not be supplied by the caller.
        prefix: &'static str,
    },
    /// A cookie name was rejected by the ecosystem cookie parser.
    InvalidCookieName,
    /// A cookie value was rejected by the ecosystem cookie parser.
    InvalidCookieValue,
    /// A cookie path was empty or did not start with `/`.
    InvalidCookiePath,
    /// A cookie domain was not safe to emit as a `Set-Cookie` domain attribute.
    InvalidCookieDomain,
    /// A configured cookie max-age was zero.
    CookieMaxAgeSecondsZero,
    /// A configured cookie max-age exceeded the supported signed second count.
    CookieMaxAgeSecondsTooLarge {
        /// Requested max-age seconds.
        seconds: u64,
        /// Maximum accepted max-age seconds.
        max: u64,
    },
    /// The requested cookie was not present in a cookie header.
    MissingCookie {
        /// Cookie name searched for.
        name: String,
    },
    /// A cookie with the wrong name was provided to a cookie helper.
    CookieNameMismatch {
        /// Cookie name expected by the helper.
        expected: String,
        /// Cookie name actually provided.
        actual: String,
    },
    /// A cookie header contained the same cookie name more than once.
    DuplicateCookie {
        /// Duplicate cookie name.
        name: String,
    },
    /// Cookie values must not be empty.
    EmptyCookieValue,
    /// A client-readable cookie value could not be parsed into the requested type.
    ClientReadableCookieParse {
        /// Parse error message.
        message: String,
    },
    /// System time was before the Unix epoch.
    ClockBeforeUnixEpoch,
    /// A CSRF token expiration timestamp could not be represented.
    CsrfExpirationOverflow,
    /// A CSRF origin or referer header could not be parsed.
    CsrfOriginParse {
        /// Header label.
        label: &'static str,
        /// Underlying URL parse error.
        source: url::ParseError,
    },
    /// A CSRF origin or referer header did not contain a host.
    CsrfOriginMissingHost {
        /// Header label.
        label: &'static str,
    },
    /// A CSRF origin or referer used a scheme other than `http` or `https`.
    CsrfOriginUnsupportedScheme {
        /// Header label.
        label: &'static str,
        /// Scheme that was rejected.
        scheme: String,
    },
    /// A configured CSRF origin or request `Origin` header contained URL parts
    /// that are not part of an origin.
    CsrfOriginContainsNonOriginParts {
        /// Header label.
        label: &'static str,
    },
    /// Development-mode web helpers only accept localhost request hosts.
    DevelopmentModeNonLocalhostHost {
        /// Host header or URI host that was rejected.
        host: String,
    },
    /// A CSRF header was not valid visible header text.
    CsrfHeaderDecode {
        /// Header label.
        label: &'static str,
        /// Underlying header decode error.
        source: http::header::ToStrError,
    },
    /// A single-valued CSRF decision header was present more than once.
    DuplicateCsrfHeader {
        /// Header label.
        label: &'static str,
    },
    /// A CSRF origin or referer header was not in the allowlist.
    CsrfOriginNotAllowed {
        /// Normalized origin.
        origin: String,
    },
    /// A CSRF origin allowlist was configured, but the request had no Origin or Referer header.
    CsrfOriginAndRefererMissing,
    /// CSRF binding bytes must not be empty.
    EmptyCsrfBinding,
    /// CSRF binding bytes exceeded the supported size.
    CsrfBindingTooLarge {
        /// Requested CSRF binding byte length.
        actual: usize,
        /// Maximum supported CSRF binding byte length.
        max: usize,
    },
    /// A submitted CSRF token header was not valid visible header text.
    CsrfSubmittedTokenHeaderDecode(http::header::ToStrError),
    /// A CSRF request did not include a submitted token.
    CsrfTokenMissing,
    /// A CSRF cookie token and submitted token did not match.
    CsrfTokenMismatch,
    /// A CSRF token payload was invalid or expired.
    CsrfTokenInvalidOrExpired,
    /// A CSRF token was bound to different request identity bytes.
    CsrfBindingMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "{err}"),
            Self::AllocationFailed => write!(f, "paranoid web: output allocation failed"),
            Self::CookieParse(err) => write!(f, "paranoid web: cookie parse: {err}"),
            Self::CookieHeaderDecode(err) => {
                write!(f, "paranoid web: cookie header decode: {err}")
            }
            Self::CookieSetHeaderInvalid(err) => {
                write!(f, "paranoid web: set-cookie header value: {err}")
            }
            Self::EmptyCookieName => write!(f, "paranoid web: cookie name is empty"),
            Self::ManagedCookieNamePrefix { prefix } => {
                write!(
                    f,
                    "paranoid web: cookie name must not include managed prefix {prefix}"
                )
            }
            Self::InvalidCookieName => write!(f, "paranoid web: invalid cookie name"),
            Self::InvalidCookieValue => write!(f, "paranoid web: invalid cookie value"),
            Self::InvalidCookiePath => write!(f, "paranoid web: invalid cookie path"),
            Self::InvalidCookieDomain => write!(f, "paranoid web: invalid cookie domain"),
            Self::CookieMaxAgeSecondsZero => {
                write!(f, "paranoid web: cookie max-age seconds must be non-zero")
            }
            Self::CookieMaxAgeSecondsTooLarge { seconds, max } => {
                write!(
                    f,
                    "paranoid web: cookie max-age seconds {seconds}, max {max}"
                )
            }
            Self::MissingCookie { name } => write!(f, "paranoid web: missing cookie {name}"),
            Self::CookieNameMismatch { expected, actual } => {
                write!(
                    f,
                    "paranoid web: cookie name mismatch, expected {expected}, got {actual}"
                )
            }
            Self::DuplicateCookie { name } => {
                write!(f, "paranoid web: duplicate cookie {name}")
            }
            Self::EmptyCookieValue => write!(f, "paranoid web: cookie value is empty"),
            Self::ClientReadableCookieParse { message } => {
                write!(f, "paranoid web: client-readable cookie parse: {message}")
            }
            Self::ClockBeforeUnixEpoch => write!(f, "paranoid web: clock is before Unix epoch"),
            Self::CsrfExpirationOverflow => write!(f, "paranoid web: csrf expiration overflow"),
            Self::CsrfOriginParse { label, source } => {
                write!(f, "paranoid web: csrf {label} parse: {source}")
            }
            Self::CsrfOriginMissingHost { label } => {
                write!(f, "paranoid web: csrf {label} is missing host")
            }
            Self::CsrfOriginUnsupportedScheme { label, scheme } => {
                write!(
                    f,
                    "paranoid web: csrf {label} scheme must be http or https, got {scheme}"
                )
            }
            Self::CsrfOriginContainsNonOriginParts { label } => {
                write!(
                    f,
                    "paranoid web: csrf {label} must be an origin without path, query, fragment, username, or password"
                )
            }
            Self::DevelopmentModeNonLocalhostHost { host } => {
                write!(
                    f,
                    "paranoid web: development mode only accepts localhost request hosts, got {host}"
                )
            }
            Self::CsrfHeaderDecode { label, source } => {
                write!(f, "paranoid web: csrf {label} header decode: {source}")
            }
            Self::DuplicateCsrfHeader { label } => {
                write!(
                    f,
                    "paranoid web: csrf {label} header appeared more than once"
                )
            }
            Self::CsrfOriginNotAllowed { origin } => {
                write!(f, "paranoid web: csrf origin not allowed: {origin}")
            }
            Self::CsrfOriginAndRefererMissing => {
                write!(f, "paranoid web: csrf origin and referer are missing")
            }
            Self::EmptyCsrfBinding => write!(f, "paranoid web: csrf binding is empty"),
            Self::CsrfBindingTooLarge { actual, max } => {
                write!(f, "paranoid web: csrf binding length {actual}, max {max}")
            }
            Self::CsrfSubmittedTokenHeaderDecode(err) => {
                write!(f, "paranoid web: csrf submitted token header decode: {err}")
            }
            Self::CsrfTokenMissing => write!(f, "paranoid web: csrf token missing"),
            Self::CsrfTokenMismatch => write!(f, "paranoid web: csrf token mismatch"),
            Self::CsrfTokenInvalidOrExpired => {
                write!(f, "paranoid web: csrf token invalid or expired")
            }
            Self::CsrfBindingMismatch => write!(f, "paranoid web: csrf binding mismatch"),
        }
    }
}

impl From<crate::crypto::Error> for Error {
    fn from(value: crate::crypto::Error) -> Self {
        Self::Crypto(value)
    }
}

impl From<crate::crypto::CryptoError> for Error {
    fn from(value: crate::crypto::CryptoError) -> Self {
        Self::Crypto(value.into())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            Self::CookieParse(err) => Some(err),
            Self::CookieHeaderDecode(err) => Some(err),
            Self::CookieSetHeaderInvalid(err) => Some(err),
            Self::CsrfHeaderDecode { source, .. } => Some(source),
            Self::CsrfSubmittedTokenHeaderDecode(err) => Some(err),
            Self::CsrfOriginParse { source, .. } => Some(source),
            _ => None,
        }
    }
}
