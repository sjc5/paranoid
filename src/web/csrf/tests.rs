use super::origin_helpers::normalize_origin;
use super::*;
use crate::crypto::{KEY32_SIZE, Key32, Keyset, derive_keyset_from_latest_first_keys};
use http::HeaderValue;
use http::Method;
use http::header::{COOKIE, SET_COOKIE};
use std::convert::Infallible;
use std::future::Ready;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Wake, Waker};

#[derive(Debug)]
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn block_on_ready<F>(future: F) -> F::Output
where
    F: Future,
{
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

#[derive(Clone, Debug)]
struct OkService;

impl Service<Request<()>> for OkService {
    type Response = Response<String>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<()>) -> Self::Future {
        ready(Ok(Response::builder()
            .status(200)
            .body("ok".to_owned())
            .expect("response")))
    }
}

fn forbidden_response(_error: Error) -> Response<String> {
    Response::builder()
        .status(403)
        .body("forbidden".to_owned())
        .expect("response")
}

fn test_key(byte: u8) -> Key32 {
    Key32::try_from(&[byte; KEY32_SIZE][..]).expect("key")
}

fn test_keyset_from_bytes(bytes: &[u8]) -> Keyset {
    derive_keyset_from_latest_first_keys(bytes.iter().copied().map(test_key), "tests.csrf")
        .expect("keyset")
}

fn test_keyset() -> Keyset {
    test_keyset_from_bytes(&[11])
}

fn test_manager() -> CookieManager {
    CookieManager::from_keyset(test_keyset())
}

fn test_development_manager() -> CookieManager {
    let mut config = crate::web::cookies::CookieManagerConfig::from_keyset(test_keyset());
    config.is_development = Arc::new(|| true);
    CookieManager::new(config)
}

fn test_rotating_manager() -> (CookieManager, Arc<AtomicBool>) {
    let use_rotated_keyset = Arc::new(AtomicBool::new(false));
    let config = crate::web::cookies::CookieManagerConfig::new({
        let use_rotated_keyset = use_rotated_keyset.clone();
        move || {
            if use_rotated_keyset.load(Ordering::SeqCst) {
                Ok(Arc::new(test_keyset_from_bytes(&[12, 11])))
            } else {
                Ok(Arc::new(test_keyset_from_bytes(&[11])))
            }
        }
    });
    (CookieManager::new(config), use_rotated_keyset)
}

fn test_protector(allowed_origins: Vec<String>) -> CsrfProtector {
    let mut config = CsrfProtectorConfig::new(test_manager());
    config.allowed_origins = allowed_origins;
    CsrfProtector::new(config).expect("protector")
}

fn test_protector_with_binding_header() -> CsrfProtector {
    let mut config = CsrfProtectorConfig::new(test_manager());
    config.allowed_origins = vec!["https://example.com".to_owned()];
    config.extract_binding_from_headers = Arc::new(|headers| {
        let Some(value) = headers.get("x-session-cookie-value") else {
            return Ok(None);
        };
        let value = value.to_str().map_err(|source| Error::CsrfHeaderDecode {
            label: "x-session-cookie-value",
            source,
        })?;
        CsrfBinding::from_non_empty_bytes(value.as_bytes()).map(Some)
    });
    CsrfProtector::new(config).expect("protector")
}

fn request_with_headers(
    method: Method,
    host: &str,
    csrf_cookie: Option<&Cookie<'_>>,
    csrf_header_value: Option<&str>,
    binding_header_value: Option<&str>,
    origin_header_value: Option<&str>,
    referer_header_value: Option<&str>,
) -> Request<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri("https://example.com/form")
        .header(HOST, host);
    if let Some(cookie) = csrf_cookie {
        builder = builder.header(COOKIE, format!("{}={}", cookie.name(), cookie.value()));
    }
    if let Some(token) = csrf_header_value {
        builder = builder.header(DEFAULT_CSRF_HEADER_NAME, token);
    }
    if let Some(binding) = binding_header_value {
        builder = builder.header("x-session-cookie-value", binding);
    }
    if let Some(origin) = origin_header_value {
        builder = builder.header(ORIGIN, origin);
    }
    if let Some(referer) = referer_header_value {
        builder = builder.header(REFERER, referer);
    }
    builder.body(()).expect("request")
}

#[test]
fn csrf_default_config_issues_readable_host_only_cookie() {
    let protector = test_protector(Vec::new());
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);

    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");

    assert_eq!(protector.cookie_name(), "__Host-csrf_token");
    assert_eq!(protector.header_name().as_str(), "x-csrf-token");
    assert_eq!(cookie.name(), "__Host-csrf_token");
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.domain(), None);
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(false));
    assert_eq!(cookie.same_site(), Some(cookie::SameSite::Lax));
    assert_eq!(cookie.partitioned(), Some(true));
    assert_eq!(
        cookie.max_age().map(|max_age| max_age.whole_seconds()),
        Some(DEFAULT_CSRF_TOKEN_MAX_AGE_SECONDS as i64)
    );
}

#[test]
fn csrf_token_round_trips_with_origin_and_binding() {
    let protector = test_protector_with_binding_header();
    let issue_request = request_with_headers(
        Method::GET,
        "example.com",
        None,
        None,
        Some("session-1"),
        None,
        None,
    );
    let cookie = protector
        .cycle_token_cookie_for_request(&issue_request)
        .expect("cookie");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        Some("session-1"),
        Some("https://example.com"),
        None,
    );

    protector
        .verify_request(&verify_request)
        .expect("valid csrf token");
}

#[test]
fn csrf_allows_referer_with_path_and_normalizes_case() {
    let protector = test_protector(vec!["https://example.com:8443".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        None,
        Some("HTTPS://EXAMPLE.COM:8443/path?x=1"),
    );

    protector
        .verify_request(&verify_request)
        .expect("valid csrf token");
}

#[test]
fn csrf_rejects_allowed_origin_config_that_is_not_an_exact_http_origin() {
    for allowed_origin in [
        "https://example.com/path",
        "https://example.com?x=1",
        "https://example.com#fragment",
        "https://user@example.com",
        "ftp://example.com",
    ] {
        let mut config = CsrfProtectorConfig::new(test_manager());
        config.allowed_origins = vec![allowed_origin.to_owned()];

        assert!(
            CsrfProtector::new(config).is_err(),
            "expected rejection for configured origin {allowed_origin:?}"
        );
    }
}

#[test]
fn csrf_rejects_origin_header_that_is_not_an_exact_origin_but_allows_referer_urls() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let origin_with_path_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some("https://example.com/path"),
        None,
    );
    let referer_with_path_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        None,
        Some("https://example.com/path"),
    );

    assert!(matches!(
        protector.verify_request(&origin_with_path_request),
        Err(Error::CsrfOriginContainsNonOriginParts { label: "Origin" })
    ));
    protector
        .verify_request(&referer_with_path_request)
        .expect("referer URL can carry a path");
}

#[test]
fn csrf_origin_normalization_preserves_ipv6_brackets() {
    assert_eq!(
        normalize_origin("https://[::1]:8443", "Origin").expect("normalized"),
        "https://[::1]:8443"
    );
}

#[test]
fn csrf_uses_origin_before_referer_when_both_are_present() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some("https://example.com"),
        Some("https://evil.example/path"),
    );

    protector
        .verify_request(&verify_request)
        .expect("allowed origin wins over disallowed referer");
}

#[test]
fn csrf_rejects_malformed_origin_even_when_referer_would_be_allowed() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some("https://[::1"),
        Some("https://example.com/path"),
    );

    assert!(matches!(
        protector.verify_request(&verify_request),
        Err(Error::CsrfOriginParse {
            label: "Origin",
            ..
        })
    ));
}

#[test]
fn csrf_empty_origin_falls_back_to_referer() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some(""),
        Some("https://example.com/path"),
    );

    protector
        .verify_request(&verify_request)
        .expect("valid referer is used when origin is empty");
}

#[test]
fn csrf_rejects_missing_origin_and_referer_when_origin_allowlist_is_configured() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        None,
        None,
    );

    assert!(matches!(
        protector.verify_request(&verify_request),
        Err(Error::CsrfOriginAndRefererMissing)
    ));
}

#[test]
fn csrf_origin_normalization_rejects_hostile_corpus() {
    for header in [
        "not a url",
        "https:",
        "https://",
        "https://[::1",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "mailto:user@example.com",
    ] {
        assert!(normalize_origin(header, "Origin").is_err(), "{header}");
    }
}

#[test]
fn csrf_issues_token_only_when_needed() {
    let protector = test_protector_with_binding_header();
    let request = request_with_headers(
        Method::GET,
        "example.com",
        None,
        None,
        Some("session-1"),
        None,
        None,
    );

    let first = protector
        .issue_token_cookie_if_needed_for_request(&request)
        .expect("issue")
        .expect("new token");
    let same_binding_request = request_with_headers(
        Method::GET,
        "example.com",
        Some(&first),
        None,
        Some("session-1"),
        None,
        None,
    );
    let changed_binding_request = request_with_headers(
        Method::GET,
        "example.com",
        Some(&first),
        None,
        Some("session-2"),
        None,
        None,
    );

    assert!(
        protector
            .issue_token_cookie_if_needed_for_request(&same_binding_request)
            .expect("no issue")
            .is_none()
    );
    assert!(
        protector
            .issue_token_cookie_if_needed_for_request(&changed_binding_request)
            .expect("issue replacement")
            .is_some()
    );
}

#[test]
fn csrf_issue_if_needed_replaces_tampered_existing_cookie() {
    let protector = test_protector(Vec::new());
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let tampered = Cookie::new(cookie.name().to_owned(), cookie.value().to_owned() + "A");
    let request_with_tampered_cookie = request_with_headers(
        Method::GET,
        "example.com",
        Some(&tampered),
        None,
        None,
        None,
        None,
    );

    let replacement = protector
        .issue_token_cookie_if_needed_for_request(&request_with_tampered_cookie)
        .expect("replace tampered cookie")
        .expect("replacement cookie");

    assert_eq!(replacement.name(), protector.cookie_name());
    assert_ne!(replacement.value(), tampered.value());
}

#[test]
fn csrf_accepts_existing_token_after_latest_first_cookie_key_rotation() {
    let (manager, use_rotated_keyset) = test_rotating_manager();
    let protector = CsrfProtector::new(CsrfProtectorConfig::new(manager)).expect("protector");
    let issue_request =
        request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&issue_request)
        .expect("cookie");

    use_rotated_keyset.store(true, Ordering::SeqCst);

    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        None,
        None,
    );
    protector
        .verify_request(&verify_request)
        .expect("old csrf cookie remains valid under fallback key");
}

#[test]
fn csrf_layer_adds_token_cookie_to_safe_responses() {
    let protector = test_protector(Vec::new());
    let cookie_name = protector.cookie_name().to_owned();
    let layer = CsrfLayer::new(protector, forbidden_response);
    let mut service = layer.layer(OkService);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);

    let response = block_on_ready(service.call(request)).expect("response");
    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .expect("set-cookie text");

    assert_eq!(response.status(), 200);
    assert!(set_cookie.starts_with(&format!("{cookie_name}=")));
}

#[test]
fn csrf_layer_accepts_valid_unsafe_requests() {
    let protector = test_protector(Vec::new());
    let issue_request =
        request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&issue_request)
        .expect("cookie");
    let layer = CsrfLayer::new(protector, forbidden_response);
    let mut service = layer.layer(OkService);
    let request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        None,
        None,
    );

    let response = block_on_ready(service.call(request)).expect("response");

    assert_eq!(response.status(), 200);
    assert!(response.headers().get(SET_COOKIE).is_none());
}

#[test]
fn csrf_layer_rejects_unsafe_requests_and_self_heals_missing_cookie() {
    let protector = test_protector(Vec::new());
    let cookie_name = protector.cookie_name().to_owned();
    let layer = CsrfLayer::new(protector, forbidden_response);
    let mut service = layer.layer(OkService);
    let request = request_with_headers(Method::POST, "example.com", None, None, None, None, None);

    let response = block_on_ready(service.call(request)).expect("response");
    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .expect("self-heal set-cookie")
        .to_str()
        .expect("set-cookie text");

    assert_eq!(response.status(), 403);
    assert_eq!(response.body(), "forbidden");
    assert!(set_cookie.starts_with(&format!("{cookie_name}=")));
}

#[test]
fn csrf_layer_rejects_token_mismatch_without_self_healing() {
    let protector = test_protector(Vec::new());
    let issue_request =
        request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&issue_request)
        .expect("cookie");
    let layer = CsrfLayer::new(protector, forbidden_response);
    let mut service = layer.layer(OkService);
    let request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some("wrong"),
        None,
        None,
        None,
    );

    let response = block_on_ready(service.call(request)).expect("response");

    assert_eq!(response.status(), 403);
    assert!(response.headers().get(SET_COOKIE).is_none());
}

#[test]
fn csrf_layer_rejects_origin_failure_without_self_healing() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let issue_request =
        request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&issue_request)
        .expect("cookie");
    let layer = CsrfLayer::new(protector, forbidden_response);
    let mut service = layer.layer(OkService);
    let request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some("https://evil.example"),
        None,
    );

    let response = block_on_ready(service.call(request)).expect("response");

    assert_eq!(response.status(), 403);
    assert!(response.headers().get(SET_COOKIE).is_none());
}

#[test]
fn csrf_verify_request_skips_get_like_methods() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(
        Method::GET,
        "example.com",
        None,
        None,
        None,
        Some("https://evil.example"),
        None,
    );

    protector.verify_request(&request).expect("safe method");
}

#[test]
fn csrf_rejects_token_mismatch_origin_mismatch_and_binding_mismatch() {
    let protector = test_protector_with_binding_header();
    let issue_request = request_with_headers(
        Method::GET,
        "example.com",
        None,
        None,
        Some("session-1"),
        None,
        None,
    );
    let cookie = protector
        .cycle_token_cookie_for_request(&issue_request)
        .expect("cookie");

    let wrong_token_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some("wrong"),
        Some("session-1"),
        Some("https://example.com"),
        None,
    );
    assert!(matches!(
        protector.verify_request(&wrong_token_request),
        Err(Error::CsrfTokenMismatch)
    ));

    let wrong_origin_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        Some("session-1"),
        Some("https://evil.example"),
        None,
    );
    assert!(matches!(
        protector.verify_request(&wrong_origin_request),
        Err(Error::CsrfOriginNotAllowed { .. })
    ));

    let wrong_binding_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        Some("session-2"),
        Some("https://example.com"),
        None,
    );
    assert!(matches!(
        protector.verify_request(&wrong_binding_request),
        Err(Error::CsrfBindingMismatch)
    ));
}

#[test]
fn csrf_rejects_tampered_cookie() {
    let protector = test_protector(Vec::new());
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let mut tampered = Cookie::new(cookie.name().to_owned(), cookie.value().to_owned() + "A");
    tampered.set_path("/");
    let verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&tampered),
        Some(tampered.value()),
        None,
        None,
        None,
    );

    assert!(protector.verify_request(&verify_request).is_err());
}

#[test]
fn csrf_explicit_cycle_accepts_known_binding() {
    let protector = test_protector(Vec::new());
    let binding = CsrfBinding::from_non_empty_bytes(b"fresh-session").expect("binding");

    let cookie = protector
        .cycle_token_cookie_for_binding(Some(&binding))
        .expect("cookie");

    assert_eq!(cookie.name(), protector.cookie_name());
}

#[test]
fn csrf_binding_rejects_empty_bytes() {
    assert!(matches!(
        CsrfBinding::from_non_empty_bytes(b""),
        Err(Error::EmptyCsrfBinding)
    ));
}

#[test]
fn csrf_binding_rejects_oversized_bytes() {
    let oversized = vec![0_u8; MAX_CSRF_BINDING_SIZE + 1];

    assert!(matches!(
        CsrfBinding::from_non_empty_bytes(&oversized),
        Err(Error::CsrfBindingTooLarge { actual, max })
            if actual == MAX_CSRF_BINDING_SIZE + 1 && max == MAX_CSRF_BINDING_SIZE
    ));
}

#[test]
fn csrf_safe_method_matches_go_baseline() {
    assert!(is_csrf_safe_method("GET"));
    assert!(is_csrf_safe_method("HEAD"));
    assert!(is_csrf_safe_method("OPTIONS"));
    assert!(is_csrf_safe_method("TRACE"));
    assert!(!is_csrf_safe_method("POST"));
    assert!(!is_csrf_safe_method("PATCH"));
}

#[test]
fn localhost_host_detection_matches_go_baseline_cases() {
    for host in [
        "localhost",
        "LOCALHOST",
        "localhost:3000",
        "127.0.0.1",
        "127.0.0.1:8080",
        "127.42.0.1",
        "::1",
        "[::1]",
        "[::1]:3000",
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.1]:3000",
    ] {
        assert!(is_localhost_host(host), "{host}");
    }

    for host in [
        "",
        "example.com",
        "localhost.example.com",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "8.8.8.8",
        "[::2]",
        "not-an-ip:abc",
    ] {
        assert!(!is_localhost_host(host), "{host}");
    }
}

#[test]
#[should_panic(expected = "DANGER: CSRF middleware is configured for development mode")]
fn csrf_development_mode_panics_on_non_localhost_host() {
    let config = CsrfProtectorConfig::new(test_development_manager());
    let protector = CsrfProtector::new(config).expect("protector");
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);

    let _ = protector.issue_token_cookie_if_needed_for_request(&request);
}

#[test]
#[should_panic(expected = "DANGER: CSRF middleware is configured for development mode")]
fn csrf_layer_development_mode_panics_on_non_localhost_unsafe_host() {
    let config = CsrfProtectorConfig::new(test_development_manager());
    let protector = CsrfProtector::new(config).expect("protector");
    let layer = CsrfLayer::new(protector, forbidden_response);
    let mut service = layer.layer(OkService);
    let request = request_with_headers(Method::POST, "example.com", None, None, None, None, None);

    std::mem::drop(service.call(request));
}

#[test]
fn csrf_development_mode_allows_localhost_host() {
    let config = CsrfProtectorConfig::new(test_development_manager());
    let protector = CsrfProtector::new(config).expect("protector");
    let request = request_with_headers(Method::GET, "localhost:3000", None, None, None, None, None);

    assert!(
        protector
            .issue_token_cookie_if_needed_for_request(&request)
            .expect("dev localhost")
            .is_some()
    );
}

#[test]
fn csrf_rejects_invalid_submitted_token_header_bytes() {
    let protector = test_protector(Vec::new());
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");
    let mut verify_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        None,
        None,
        None,
        None,
    );
    verify_request.headers_mut().insert(
        DEFAULT_CSRF_HEADER_NAME,
        HeaderValue::from_bytes(&[0xff]).expect("opaque header bytes"),
    );

    assert!(matches!(
        protector.verify_request(&verify_request),
        Err(Error::CsrfSubmittedTokenHeaderDecode(_))
    ));
}

#[test]
fn csrf_rejects_duplicate_single_valued_decision_headers() {
    let protector = test_protector(vec!["https://example.com".to_owned()]);
    let request = request_with_headers(Method::GET, "example.com", None, None, None, None, None);
    let cookie = protector
        .cycle_token_cookie_for_request(&request)
        .expect("cookie");

    let mut duplicate_token_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some("https://example.com"),
        None,
    );
    duplicate_token_request.headers_mut().append(
        DEFAULT_CSRF_HEADER_NAME,
        HeaderValue::from_str(cookie.value()).expect("header value"),
    );
    assert!(matches!(
        protector.verify_request(&duplicate_token_request),
        Err(Error::DuplicateCsrfHeader {
            label: "submitted token"
        })
    ));

    let mut duplicate_origin_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        Some("https://example.com"),
        None,
    );
    duplicate_origin_request
        .headers_mut()
        .append(ORIGIN, HeaderValue::from_static("https://example.com"));
    assert!(matches!(
        protector.verify_request(&duplicate_origin_request),
        Err(Error::DuplicateCsrfHeader { label: "Origin" })
    ));

    let mut duplicate_referer_request = request_with_headers(
        Method::POST,
        "example.com",
        Some(&cookie),
        Some(cookie.value()),
        None,
        None,
        Some("https://example.com"),
    );
    duplicate_referer_request
        .headers_mut()
        .append(REFERER, HeaderValue::from_static("https://example.com"));
    assert!(matches!(
        protector.verify_request(&duplicate_referer_request),
        Err(Error::DuplicateCsrfHeader { label: "Referer" })
    ));
}
