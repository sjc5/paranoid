use super::*;
use crate::crypto::{KEY32_SIZE, Key32, derive_keyset_from_latest_first_keys};
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct TestSession {
    user_id: String,
    roles: Vec<String>,
}

fn test_session() -> TestSession {
    TestSession {
        user_id: "user-123".to_owned(),
        roles: vec!["admin".to_owned(), "billing".to_owned()],
    }
}

fn test_key(byte: u8) -> Key32 {
    Key32::try_from(&[byte; KEY32_SIZE][..]).expect("key")
}

fn test_keyset(bytes: &[u8]) -> Keyset {
    derive_keyset_from_latest_first_keys(bytes.iter().copied().map(test_key), "tests.cookies")
        .expect("keyset")
}

fn test_manager() -> CookieManager {
    CookieManager::from_keyset(test_keyset(&[7]))
}

fn test_development_manager(is_development: bool) -> CookieManager {
    let mut config = CookieManagerConfig::from_keyset(test_keyset(&[7]));
    config.is_development = Arc::new(move || is_development);
    CookieManager::new(config)
}

#[test]
fn cookie_manager_defaults_to_secure_production_policy() {
    let manager = test_manager();

    assert!(!manager.is_development());
    assert_eq!(manager.resolve_same_site(None), CookieSameSite::Lax);
    assert!(manager.resolve_partitioned(None));
    assert!(manager.resolve_http_only(None));
}

#[test]
fn host_only_secure_cookie_uses_host_prefix_and_secure_defaults_in_production() {
    let manager = test_manager();
    let mut config = SecureCookieConfig::new("session");
    config.max_age = Some(CookieMaxAgeSeconds::new(3600).expect("max age"));
    let cookie = manager
        .secure_cookie::<TestSession>(config)
        .expect("cookie");

    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");

    assert_eq!(cookie.name(), "__Host-session");
    assert_eq!(emitted.name(), "__Host-session");
    assert_eq!(emitted.path(), Some("/"));
    assert_eq!(emitted.domain(), None);
    assert_eq!(emitted.secure(), Some(true));
    assert_eq!(emitted.http_only(), Some(true));
    assert_eq!(emitted.same_site(), Some(SameSite::Lax));
    assert_eq!(emitted.partitioned(), Some(true));
    assert_eq!(
        emitted.max_age().map(|max_age| max_age.whole_seconds()),
        Some(3600)
    );
}

#[test]
fn host_only_secure_cookie_uses_dev_prefix_and_disables_secure_partitioned_in_development() {
    let manager = test_development_manager(true);
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");

    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");

    assert_eq!(cookie.name(), "__Dev-session");
    assert_eq!(emitted.name(), "__Dev-session");
    assert_eq!(emitted.secure(), Some(false));
    assert_eq!(emitted.partitioned(), Some(false));
}

#[test]
fn non_host_only_secure_cookie_preserves_explicit_scope() {
    let manager = test_manager();
    let mut config = SecureCookieNonHostOnlyConfig::new("session");
    config.path = "/app".to_owned();
    config.domain = Some("example.com".to_owned());
    config.same_site = Some(CookieSameSite::Strict);
    config.partitioned = Some(false);
    let cookie = manager
        .secure_cookie_non_host_only::<TestSession>(config)
        .expect("cookie");

    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");

    assert_eq!(emitted.name(), "session");
    assert_eq!(emitted.path(), Some("/app"));
    assert_eq!(emitted.domain(), Some("example.com"));
    assert_eq!(emitted.secure(), Some(true));
    assert_eq!(emitted.http_only(), Some(true));
    assert_eq!(emitted.same_site(), Some(SameSite::Strict));
    assert_eq!(emitted.partitioned(), Some(false));
}

#[test]
fn secure_cookie_round_trips_typed_payloads_from_request() {
    let manager = test_manager();
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let payload = test_session();
    let emitted = cookie.new_cookie(&payload).expect("emitted cookie");
    let request = Request::builder()
        .header(
            COOKIE,
            format!("other=value; {}={}", cookie.name(), emitted.value()),
        )
        .body(())
        .expect("request");

    let decoded = cookie.get_from_request(&request).expect("decoded");

    assert_eq!(decoded, payload);
    assert_ne!(emitted.value(), "user-123");
}

#[test]
fn secure_cookie_reads_from_cookie_header() {
    let manager = test_manager();
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let payload = test_session();
    let emitted = cookie.new_cookie(&payload).expect("emitted cookie");
    let header = format!("other=value; {}={}", cookie.name(), emitted.value());

    let decoded = cookie.get_from_cookie_header(&header).expect("decoded");

    assert_eq!(decoded, payload);
}

#[test]
fn secure_cookie_optional_getters_distinguish_absent_from_invalid() {
    let manager = test_manager();
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");
    let valid_header = format!("{}={}", cookie.name(), emitted.value());
    let mut tampered = emitted.value().to_owned();
    tampered.push('A');
    let tampered_header = format!("{}={tampered}", cookie.name());
    let missing_request = Request::builder()
        .header(COOKIE, "other=value")
        .body(())
        .expect("request");
    let tampered_request = Request::builder()
        .header(COOKIE, tampered_header.clone())
        .body(())
        .expect("request");

    assert_eq!(
        cookie
            .get_optional_from_cookie_header(&valid_header)
            .expect("valid optional"),
        Some(test_session())
    );
    assert_eq!(
        cookie
            .get_optional_from_cookie_header("other=value")
            .expect("missing optional"),
        None
    );
    assert!(
        cookie
            .get_optional_from_cookie_header(&tampered_header)
            .is_err()
    );
    assert_eq!(
        cookie
            .get_optional_from_request(&missing_request)
            .expect("missing optional"),
        None
    );
    assert!(cookie.get_optional_from_request(&tampered_request).is_err());
}

#[test]
fn secure_cookie_rejects_wrong_cookie_name_empty_values_and_tampering() {
    let manager = test_manager();
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");
    let wrong_name = Cookie::new("__Host-other", emitted.value().to_owned());
    let mut tampered = emitted.value().to_owned();
    tampered.push('A');

    assert!(matches!(
        cookie.get_from_cookie(&wrong_name),
        Err(Error::CookieNameMismatch { .. })
    ));
    assert!(matches!(
        cookie.decode_cookie_value(""),
        Err(Error::EmptyCookieValue)
    ));
    assert!(cookie.decode_cookie_value(&tampered).is_err());
}

#[test]
fn secure_cookie_scope_is_authenticated_associated_data() {
    let manager = test_manager();
    let first = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let second = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("other"))
        .expect("cookie");
    let emitted = first.new_cookie(&test_session()).expect("emitted cookie");

    assert!(matches!(
        second.decode_cookie_value(emitted.value()),
        Err(Error::Crypto(crate::crypto::Error::DecryptionFailed))
    ));
}

#[test]
fn secure_cookie_uses_live_manager_keyset_for_rotation() {
    let phase = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut config = CookieManagerConfig::new({
        let phase = phase.clone();
        let calls = calls.clone();
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            if phase.load(Ordering::SeqCst) {
                Ok(Arc::new(test_keyset(&[8, 7])))
            } else {
                Ok(Arc::new(test_keyset(&[7])))
            }
        }
    });
    config.is_development = Arc::new(|| false);
    let manager = CookieManager::new(config);
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");

    phase.store(true, Ordering::SeqCst);
    let decoded = cookie.get_from_cookie(&emitted).expect("decoded");

    assert_eq!(decoded, test_session());
    assert!(calls.load(Ordering::SeqCst) >= 2);
}

#[test]
fn client_readable_cookie_round_trips_string_values() {
    let manager = test_manager();
    let mut config = ClientReadableCookieConfig::new("theme");
    config.max_age = Some(CookieMaxAgeSeconds::new(3600).expect("max age"));
    let cookie = manager
        .client_readable_cookie::<String>(config)
        .expect("cookie");
    let emitted = cookie.new_cookie("dark-mode").expect("emitted cookie");
    let request = Request::builder()
        .header(COOKIE, format!("{}={}", cookie.name(), emitted.value()))
        .body(())
        .expect("request");

    let decoded = cookie.get_from_request(&request).expect("decoded");

    assert_eq!(cookie.name(), "__Host-theme");
    assert_eq!(emitted.value(), "dark-mode");
    assert_eq!(emitted.http_only(), Some(false));
    assert_eq!(emitted.path(), Some("/"));
    assert_eq!(
        emitted.max_age().map(|max_age| max_age.whole_seconds()),
        Some(3600)
    );
    assert_eq!(decoded, "dark-mode");
}

#[test]
fn client_readable_cookie_rejects_unsafe_output_values() {
    let manager = test_manager();
    let cookie = manager
        .client_readable_cookie::<String>(ClientReadableCookieConfig::new("theme"))
        .expect("cookie");

    for value in [
        "dark; Path=/",
        "dark\r\nSet-Cookie: other=value",
        "dark\nmode",
    ] {
        assert!(
            matches!(cookie.new_cookie(value), Err(Error::InvalidCookieValue)),
            "expected unsafe client-readable cookie value rejection for {value:?}"
        );
    }
}

#[test]
fn client_readable_non_host_only_cookie_preserves_explicit_scope() {
    let manager = test_manager();
    let mut config = ClientReadableCookieNonHostOnlyConfig::new("locale");
    config.path = "/app".to_owned();
    config.domain = Some(".example.com".to_owned());
    config.same_site = Some(CookieSameSite::Strict);
    let cookie = manager
        .client_readable_cookie_non_host_only::<String>(config)
        .expect("cookie");

    let emitted = cookie.new_cookie("en-US").expect("emitted cookie");
    let decoded = cookie
        .get_from_cookie_header(&format!("locale={}", emitted.value()))
        .expect("decoded");
    let decoded_value = cookie
        .parse_cookie_value(emitted.value())
        .expect("decoded value");

    assert_eq!(emitted.name(), "locale");
    assert_eq!(emitted.value(), "en-US");
    assert_eq!(emitted.path(), Some("/app"));
    assert_eq!(emitted.domain(), Some("example.com"));
    assert_eq!(emitted.http_only(), Some(false));
    assert_eq!(emitted.same_site(), Some(SameSite::Strict));
    assert_eq!(decoded, "en-US");
    assert_eq!(decoded_value, "en-US");
}

#[derive(Debug, Eq, PartialEq)]
enum Theme {
    Dark,
}

struct UnparseableDisplay;

impl fmt::Display for Theme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dark => f.write_str("dark"),
        }
    }
}

impl FromStr for Theme {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dark" => Ok(Self::Dark),
            _ => Err("unknown theme"),
        }
    }
}

impl fmt::Display for UnparseableDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not-parseable")
    }
}

impl FromStr for UnparseableDisplay {
    type Err = &'static str;

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        Err("unparseable display")
    }
}

#[test]
fn client_readable_cookie_supports_custom_parseable_string_types() {
    let manager = test_manager();
    let cookie = manager
        .client_readable_cookie::<Theme>(ClientReadableCookieConfig::new("theme"))
        .expect("cookie");

    let emitted = cookie.new_cookie(Theme::Dark).expect("emitted cookie");
    let decoded = cookie.get_from_cookie(&emitted).expect("decoded");
    let decoded_value = cookie
        .parse_cookie_value(emitted.value())
        .expect("decoded value");

    assert_eq!(decoded, Theme::Dark);
    assert_eq!(decoded_value, Theme::Dark);
    assert!(matches!(
        cookie.get_from_cookie(&Cookie::new(cookie.name().to_owned(), "blue")),
        Err(Error::ClientReadableCookieParse { .. })
    ));
    assert!(matches!(
        cookie.parse_cookie_value("blue"),
        Err(Error::ClientReadableCookieParse { .. })
    ));
}

#[test]
fn client_readable_cookie_rejects_display_values_that_it_cannot_parse() {
    let manager = test_manager();
    let host_only = manager
        .client_readable_cookie::<UnparseableDisplay>(ClientReadableCookieConfig::new("mode"))
        .expect("host-only cookie");
    let non_host_only = manager
        .client_readable_cookie_non_host_only::<UnparseableDisplay>(
            ClientReadableCookieNonHostOnlyConfig::new("mode"),
        )
        .expect("non-host-only cookie");

    assert!(matches!(
        host_only.new_cookie(UnparseableDisplay),
        Err(Error::ClientReadableCookieParse { .. })
    ));
    assert!(matches!(
        non_host_only.new_cookie(UnparseableDisplay),
        Err(Error::ClientReadableCookieParse { .. })
    ));
}

#[test]
fn client_readable_cookie_optional_getters_distinguish_absent_from_invalid() {
    let manager = test_manager();
    let cookie = manager
        .client_readable_cookie::<Theme>(ClientReadableCookieConfig::new("theme"))
        .expect("cookie");
    let valid_header = format!("{}=dark", cookie.name());
    let invalid_header = format!("{}=blue", cookie.name());

    assert_eq!(
        cookie
            .get_optional_from_cookie_header(&valid_header)
            .expect("valid optional"),
        Some(Theme::Dark)
    );
    assert_eq!(
        cookie
            .get_optional_from_cookie_header("other=value")
            .expect("missing optional"),
        None
    );
    assert!(matches!(
        cookie.get_optional_from_cookie_header(&invalid_header),
        Err(Error::ClientReadableCookieParse { .. })
    ));
}

#[test]
fn deletion_cookie_preserves_scope_and_expires_immediately() {
    let manager = test_manager();
    let mut config = SecureCookieNonHostOnlyConfig::new("session");
    config.path = "/app".to_owned();
    config.domain = Some("example.com".to_owned());
    config.max_age = Some(CookieMaxAgeSeconds::new(3600).expect("max age"));
    let cookie = manager
        .secure_cookie_non_host_only::<TestSession>(config)
        .expect("cookie");

    let deletion = cookie.deletion_cookie();

    assert_eq!(deletion.name(), "session");
    assert_eq!(deletion.value(), "");
    assert_eq!(deletion.path(), Some("/app"));
    assert_eq!(deletion.domain(), Some("example.com"));
    assert_eq!(
        deletion.max_age().map(|max_age| max_age.whole_seconds()),
        Some(0)
    );
}

#[test]
fn cookie_config_rejects_footguns() {
    let manager = test_manager();

    assert!(matches!(
        manager.secure_cookie::<TestSession>(SecureCookieConfig::new("")),
        Err(Error::EmptyCookieName)
    ));
    assert!(matches!(
        manager.secure_cookie::<TestSession>(SecureCookieConfig::new("__Host-session")),
        Err(Error::ManagedCookieNamePrefix { .. })
    ));

    let mut bad_path = SecureCookieNonHostOnlyConfig::new("session");
    bad_path.path = "app".to_owned();
    assert!(matches!(
        manager.secure_cookie_non_host_only::<TestSession>(bad_path),
        Err(Error::InvalidCookiePath)
    ));
    let mut injected_path = SecureCookieNonHostOnlyConfig::new("session");
    injected_path.path = "/app; Secure".to_owned();
    assert!(matches!(
        manager.secure_cookie_non_host_only::<TestSession>(injected_path),
        Err(Error::InvalidCookiePath)
    ));
    let mut injected_domain = SecureCookieNonHostOnlyConfig::new("session");
    injected_domain.domain = Some("example.com; secure".to_owned());
    assert!(matches!(
        manager.secure_cookie_non_host_only::<TestSession>(injected_domain),
        Err(Error::InvalidCookieDomain)
    ));
    let mut repeated_leading_dot_domain = SecureCookieNonHostOnlyConfig::new("session");
    repeated_leading_dot_domain.domain = Some("..example.com".to_owned());
    assert!(matches!(
        manager.secure_cookie_non_host_only::<TestSession>(repeated_leading_dot_domain),
        Err(Error::InvalidCookieDomain)
    ));
    assert!(matches!(
        CookieMaxAgeSeconds::new(0),
        Err(Error::CookieMaxAgeSecondsZero)
    ));
}

#[test]
fn request_cookie_parsing_handles_multiple_headers_and_invalid_header_text() {
    let manager = test_manager();
    let cookie = manager
        .client_readable_cookie::<String>(ClientReadableCookieConfig::new("theme"))
        .expect("cookie");
    let request = Request::builder()
        .header(COOKIE, "other=value")
        .header(COOKIE, format!("{}=dark", cookie.name()))
        .body(())
        .expect("request");
    let mut invalid_request = Request::builder().body(()).expect("request");
    invalid_request.headers_mut().insert(
        COOKIE,
        HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes"),
    );

    assert_eq!(cookie.get_from_request(&request).expect("theme"), "dark");
    assert_eq!(
        cookie.get_from_headers(request.headers()).expect("theme"),
        "dark"
    );
    assert_eq!(
        cookie
            .get_optional_from_headers(request.headers())
            .expect("theme"),
        Some("dark".to_owned())
    );
    assert!(matches!(
        cookie.get_from_request(&invalid_request),
        Err(Error::CookieHeaderDecode(_))
    ));
    assert!(matches!(
        cookie.get_from_headers(invalid_request.headers()),
        Err(Error::CookieHeaderDecode(_))
    ));
}

#[test]
fn request_cookie_parsing_rejects_malformed_cookie_header_before_later_valid_header() {
    let manager = test_manager();
    let cookie = manager
        .client_readable_cookie::<String>(ClientReadableCookieConfig::new("theme"))
        .expect("cookie");
    let request = Request::builder()
        .header(COOKIE, "=value")
        .header(COOKIE, format!("{}=dark", cookie.name()))
        .body(())
        .expect("request");

    assert!(matches!(
        cookie.get_optional_from_headers(request.headers()),
        Err(Error::CookieParse(_))
    ));
}

#[test]
fn secure_cookie_rejects_poisoned_duplicate_before_later_valid_duplicate() {
    let manager = test_manager();
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");
    let poisoned_header = format!(
        "{}={}A; {}={}",
        cookie.name(),
        emitted.value(),
        cookie.name(),
        emitted.value()
    );
    let poisoned_request = Request::builder()
        .header(COOKIE, poisoned_header)
        .body(())
        .expect("request");
    let poisoned_across_headers_request = Request::builder()
        .header(COOKIE, format!("{}={}A", cookie.name(), emitted.value()))
        .header(COOKIE, format!("{}={}", cookie.name(), emitted.value()))
        .body(())
        .expect("request");

    assert!(
        cookie
            .get_optional_from_headers(poisoned_request.headers())
            .is_err()
    );
    assert!(
        cookie
            .get_optional_from_headers(poisoned_across_headers_request.headers())
            .is_err()
    );
}

#[test]
fn cookie_lookup_rejects_duplicate_matching_names_even_when_first_value_is_valid() {
    let manager = test_manager();
    let cookie = manager
        .secure_cookie::<TestSession>(SecureCookieConfig::new("session"))
        .expect("cookie");
    let emitted = cookie.new_cookie(&test_session()).expect("emitted cookie");
    let duplicate_cookie_header = format!(
        "{}={}; {}={}",
        cookie.name(),
        emitted.value(),
        cookie.name(),
        emitted.value()
    );
    let duplicate_across_headers_request = Request::builder()
        .header(COOKIE, format!("{}={}", cookie.name(), emitted.value()))
        .header(COOKIE, format!("{}={}", cookie.name(), emitted.value()))
        .body(())
        .expect("request");

    assert!(matches!(
        cookie.get_from_cookie_header(&duplicate_cookie_header),
        Err(Error::DuplicateCookie { name }) if name == cookie.name()
    ));
    assert!(matches!(
        cookie.get_optional_from_headers(duplicate_across_headers_request.headers()),
        Err(Error::DuplicateCookie { name }) if name == cookie.name()
    ));
}

#[test]
fn present_empty_cookie_header_is_absent() {
    let manager = test_manager();
    let cookie = manager
        .client_readable_cookie::<String>(ClientReadableCookieConfig::new("theme"))
        .expect("cookie");
    let request = Request::builder()
        .header(COOKIE, "")
        .body(())
        .expect("request");

    assert_eq!(
        cookie
            .get_optional_from_headers(request.headers())
            .expect("optional cookie"),
        None
    );
}
