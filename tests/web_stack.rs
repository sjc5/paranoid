use std::convert::Infallible;
use std::future::{Future, Ready, ready};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use cookie::Cookie;
use http::header::{COOKIE, HOST, ORIGIN, SET_COOKIE};
use http::{HeaderValue, Method, Request, Response};
use paranoid::crypto::{KEY32_SIZE, Key32, derive_keyset_from_latest_first_keys};
use paranoid::web::{
    CookieManager, CookieManagerConfig, CookieMaxAgeSeconds, CsrfBinding, CsrfLayer, CsrfProtector,
    CsrfProtectorConfig, Error, SecureCookie, SecureCookieConfig,
};
use serde::{Deserialize, Serialize};
use tower_layer::Layer;
use tower_service::Service;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct AppSession {
    session_id: String,
    user_id: String,
}

#[derive(Clone, Debug)]
struct AppService;

impl Service<Request<()>> for AppService {
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

fn key(byte: u8) -> Key32 {
    Key32::try_from(&[byte; KEY32_SIZE][..]).expect("key")
}

fn cookie_manager() -> CookieManager {
    cookie_manager_with_key(42)
}

fn cookie_manager_with_key(byte: u8) -> CookieManager {
    let root_keyset =
        Arc::new(derive_keyset_from_latest_first_keys([key(byte)], "dogfood.app").expect("keyset"));
    let config = CookieManagerConfig::new(move || Ok(root_keyset.clone()));
    CookieManager::new(config)
}

fn app_session_cookie(cookie_manager: &CookieManager) -> SecureCookie<AppSession> {
    let mut config = SecureCookieConfig::new("session");
    config.max_age = Some(CookieMaxAgeSeconds::new(900).expect("max age"));
    cookie_manager
        .secure_cookie(config)
        .expect("session cookie")
}

fn csrf_protector(
    cookie_manager: CookieManager,
    session_cookie: SecureCookie<AppSession>,
) -> Arc<CsrfProtector> {
    let mut config = CsrfProtectorConfig::new(cookie_manager);
    config.allowed_origins = vec!["https://example.com".to_owned()];
    config.extract_binding_from_headers = Arc::new(move |headers| {
        let session = session_cookie.get_optional_from_headers(headers)?;
        match session {
            Some(session) => {
                CsrfBinding::from_non_empty_bytes(session.session_id.as_bytes()).map(Some)
            }
            None => Ok(None),
        }
    });
    Arc::new(CsrfProtector::new(config).expect("csrf protector"))
}

fn forbidden_response(error: Error) -> Response<String> {
    Response::builder()
        .status(403)
        .body(format!("forbidden: {error}"))
        .expect("response")
}

fn request(
    method: Method,
    cookie_header: Option<String>,
    csrf_header: Option<&str>,
    origin: Option<&str>,
) -> Request<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri("https://example.com/account")
        .header(HOST, "example.com");
    if let Some(cookie_header) = cookie_header {
        builder = builder.header(COOKIE, cookie_header);
    }
    if let Some(csrf_header) = csrf_header {
        builder = builder.header("X-CSRF-Token", csrf_header);
    }
    if let Some(origin) = origin {
        builder = builder.header(ORIGIN, origin);
    }
    builder.body(()).expect("request")
}

fn cookie_header(cookies: &[&Cookie<'_>]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn tamper_cookie_value(cookie: &Cookie<'_>) -> Cookie<'static> {
    Cookie::new(cookie.name().to_owned(), cookie.value().to_owned() + "A")
}

fn set_cookie_response_cookie(response: &Response<String>) -> Cookie<'static> {
    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .expect("set-cookie text");
    Cookie::parse(set_cookie.to_owned())
        .expect("set-cookie parse")
        .into_owned()
}

fn response_set_cookies(response: &Response<String>) -> Vec<Cookie<'static>> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .into_iter()
        .map(|header| {
            let header = header.to_str().expect("set-cookie text");
            Cookie::parse(header.to_owned())
                .expect("set-cookie parse")
                .into_owned()
        })
        .collect()
}

fn set_response_cookie(response: &mut Response<String>, cookie: &Cookie<'_>) {
    let value = HeaderValue::from_str(&cookie.to_string()).expect("set-cookie header value");
    response.headers_mut().append(SET_COOKIE, value);
}

struct ExampleWebApp {
    session_cookie: SecureCookie<AppSession>,
    csrf: Arc<CsrfProtector>,
}

impl ExampleWebApp {
    fn new() -> Self {
        let root_keyset = Arc::new(
            derive_keyset_from_latest_first_keys([key(42)], "dogfood.app").expect("keyset"),
        );
        let cookie_manager_config = CookieManagerConfig::new(move || Ok(root_keyset.clone()));
        let cookie_manager = CookieManager::new(cookie_manager_config);

        let mut session_cookie_config = SecureCookieConfig::new("session");
        session_cookie_config.max_age = Some(CookieMaxAgeSeconds::new(900).expect("max age"));
        let session_cookie = cookie_manager
            .secure_cookie::<AppSession>(session_cookie_config)
            .expect("session cookie");

        let mut csrf_config = CsrfProtectorConfig::new(cookie_manager);
        csrf_config.allowed_origins = vec!["https://example.com".to_owned()];
        csrf_config.extract_binding_from_headers = Arc::new({
            let session_cookie = session_cookie.clone();
            move |headers| {
                let session = session_cookie.get_optional_from_headers(headers)?;
                match session {
                    Some(session) => {
                        CsrfBinding::from_non_empty_bytes(session.session_id.as_bytes()).map(Some)
                    }
                    None => Ok(None),
                }
            }
        });
        let csrf = Arc::new(CsrfProtector::new(csrf_config).expect("csrf protector"));

        Self {
            session_cookie,
            csrf,
        }
    }

    fn csrf_layer(&self) -> CsrfLayer<String> {
        CsrfLayer::new(self.csrf.clone(), forbidden_response)
    }

    fn login_response(&self, session: &AppSession) -> Response<String> {
        let session_binding =
            CsrfBinding::from_non_empty_bytes(session.session_id.as_bytes()).expect("binding");
        let session_cookie = self
            .session_cookie
            .new_cookie(session)
            .expect("session cookie");
        let csrf_cookie = self
            .csrf
            .cycle_token_cookie_for_binding(Some(&session_binding))
            .expect("csrf cookie");
        let mut response = Response::builder()
            .status(204)
            .body(String::new())
            .expect("response");

        set_response_cookie(&mut response, &session_cookie);
        set_response_cookie(&mut response, &csrf_cookie);
        response
    }

    fn logout_response(&self) -> Response<String> {
        let session_cookie = self.session_cookie.deletion_cookie();
        let csrf_cookie = self
            .csrf
            .cycle_token_cookie_for_binding(None)
            .expect("anonymous csrf cookie");
        let mut response = Response::builder()
            .status(204)
            .body(String::new())
            .expect("response");

        set_response_cookie(&mut response, &session_cookie);
        set_response_cookie(&mut response, &csrf_cookie);
        response
    }
}

#[test]
fn public_web_stack_usage_is_natural_and_enforces_csrf_session_binding() {
    let cookie_manager = cookie_manager();
    let session_cookie = app_session_cookie(&cookie_manager);
    let csrf = csrf_protector(cookie_manager, session_cookie.clone());
    let csrf_layer = CsrfLayer::new(csrf.clone(), forbidden_response);
    let mut service = csrf_layer.layer(AppService);

    let session_one = AppSession {
        session_id: "session-1".to_owned(),
        user_id: "user-123".to_owned(),
    };
    let session_one_cookie = session_cookie
        .new_cookie(&session_one)
        .expect("session cookie");
    let get_response = block_on_ready(service.call(request(
        Method::GET,
        Some(cookie_header(&[&session_one_cookie])),
        None,
        None,
    )))
    .expect("get response");
    let csrf_cookie = set_cookie_response_cookie(&get_response);

    assert_eq!(get_response.status(), 200);
    assert_eq!(
        session_cookie
            .get_from_cookie(&session_one_cookie)
            .expect("session round trip"),
        session_one
    );
    assert_eq!(csrf_cookie.name(), csrf.cookie_name());

    let post_response = block_on_ready(service.call(request(
        Method::POST,
        Some(cookie_header(&[&session_one_cookie, &csrf_cookie])),
        Some(csrf_cookie.value()),
        Some("https://example.com"),
    )))
    .expect("post response");

    assert_eq!(post_response.status(), 200);
    assert!(post_response.headers().get(SET_COOKIE).is_none());

    let session_two_cookie = session_cookie
        .new_cookie(&AppSession {
            session_id: "session-2".to_owned(),
            user_id: "user-123".to_owned(),
        })
        .expect("session cookie");
    let rejected_response = block_on_ready(service.call(request(
        Method::POST,
        Some(cookie_header(&[&session_two_cookie, &csrf_cookie])),
        Some(csrf_cookie.value()),
        Some("https://example.com"),
    )))
    .expect("rejected response");
    let replacement_csrf_cookie = set_cookie_response_cookie(&rejected_response);

    assert_eq!(rejected_response.status(), 403);
    assert_eq!(replacement_csrf_cookie.name(), csrf.cookie_name());
    assert_ne!(replacement_csrf_cookie.value(), csrf_cookie.value());
}

#[test]
fn public_csrf_layer_rejects_tampered_session_cookie_without_self_healing() {
    let cookie_manager = cookie_manager();
    let session_cookie = app_session_cookie(&cookie_manager);
    let csrf = csrf_protector(cookie_manager, session_cookie.clone());
    let csrf_layer = CsrfLayer::new(csrf.clone(), forbidden_response);
    let mut service = csrf_layer.layer(AppService);

    let session_cookie = session_cookie
        .new_cookie(&AppSession {
            session_id: "session-1".to_owned(),
            user_id: "user-123".to_owned(),
        })
        .expect("session cookie");
    let tampered_session_cookie = tamper_cookie_value(&session_cookie);
    let csrf_cookie = csrf
        .cycle_token_cookie_for_binding(None)
        .expect("anonymous csrf cookie");

    let rejected_response = block_on_ready(service.call(request(
        Method::POST,
        Some(cookie_header(&[&tampered_session_cookie, &csrf_cookie])),
        Some(csrf_cookie.value()),
        Some("https://example.com"),
    )))
    .expect("rejected response");

    assert_eq!(rejected_response.status(), 403);
    assert!(rejected_response.headers().get(SET_COOKIE).is_none());
}

#[test]
fn public_csrf_layer_rejects_safe_request_with_tampered_session_cookie() {
    let cookie_manager = cookie_manager();
    let session_cookie = app_session_cookie(&cookie_manager);
    let csrf = csrf_protector(cookie_manager, session_cookie.clone());
    let csrf_layer = CsrfLayer::new(csrf, forbidden_response);
    let mut service = csrf_layer.layer(AppService);

    let session_cookie = session_cookie
        .new_cookie(&AppSession {
            session_id: "session-1".to_owned(),
            user_id: "user-123".to_owned(),
        })
        .expect("session cookie");
    let tampered_session_cookie = tamper_cookie_value(&session_cookie);

    let rejected_response = block_on_ready(service.call(request(
        Method::GET,
        Some(cookie_header(&[&tampered_session_cookie])),
        None,
        None,
    )))
    .expect("rejected response");

    assert_eq!(rejected_response.status(), 403);
    assert!(rejected_response.headers().get(SET_COOKIE).is_none());
}

#[test]
fn public_login_logout_flow_can_set_session_and_cycle_csrf_token() {
    let app = ExampleWebApp::new();
    let mut service = app.csrf_layer().layer(AppService);

    let session = AppSession {
        session_id: "session-login".to_owned(),
        user_id: "user-123".to_owned(),
    };
    let login_response = app.login_response(&session);
    let login_set_cookies = response_set_cookies(&login_response);
    assert_eq!(login_set_cookies.len(), 2);
    let login_session_cookie = login_set_cookies
        .iter()
        .find(|cookie| cookie.name() == app.session_cookie.name())
        .expect("session cookie");
    let login_csrf_cookie = login_set_cookies
        .iter()
        .find(|cookie| cookie.name() == app.csrf.cookie_name())
        .expect("csrf cookie");

    let post_response = block_on_ready(service.call(request(
        Method::POST,
        Some(cookie_header(&[login_session_cookie, login_csrf_cookie])),
        Some(login_csrf_cookie.value()),
        Some("https://example.com"),
    )))
    .expect("post response");

    assert_eq!(post_response.status(), 200);

    let logout_response = app.logout_response();
    let logout_set_cookies = response_set_cookies(&logout_response);
    assert_eq!(logout_set_cookies.len(), 2);
    let logout_session_cookie = logout_set_cookies
        .iter()
        .find(|cookie| cookie.name() == app.session_cookie.name())
        .expect("session deletion cookie");
    let logout_csrf_cookie = logout_set_cookies
        .iter()
        .find(|cookie| cookie.name() == app.csrf.cookie_name())
        .expect("anonymous csrf cookie");
    assert_eq!(
        logout_session_cookie
            .max_age()
            .map(|max_age| max_age.whole_seconds()),
        Some(0)
    );
    assert_ne!(logout_csrf_cookie.value(), login_csrf_cookie.value());

    let stale_login_token_response = block_on_ready(service.call(request(
        Method::POST,
        Some(cookie_header(&[login_csrf_cookie])),
        Some(login_csrf_cookie.value()),
        Some("https://example.com"),
    )))
    .expect("stale login token response");
    assert_eq!(stale_login_token_response.status(), 403);
    assert!(
        stale_login_token_response
            .headers()
            .get(SET_COOKIE)
            .is_some()
    );

    let anonymous_post_response = block_on_ready(service.call(request(
        Method::POST,
        Some(cookie_header(&[logout_csrf_cookie])),
        Some(logout_csrf_cookie.value()),
        Some("https://example.com"),
    )))
    .expect("anonymous post response");
    assert_eq!(anonymous_post_response.status(), 200);
}

#[test]
fn public_web_error_wraps_crypto_failures_explicitly() {
    let first_session_cookie = app_session_cookie(&cookie_manager_with_key(1));
    let second_session_cookie = app_session_cookie(&cookie_manager_with_key(2));
    let emitted = first_session_cookie
        .new_cookie(&AppSession {
            session_id: "session-1".to_owned(),
            user_id: "user-123".to_owned(),
        })
        .expect("session cookie");

    assert!(matches!(
        second_session_cookie.get_from_cookie(&emitted),
        Err(Error::Crypto(paranoid::crypto::Error::DecryptionFailed))
    ));
}
