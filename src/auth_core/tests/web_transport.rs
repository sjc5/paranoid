use super::*;

struct OneShotAtomicCommitAdapter {
    result: Vec<(CoreStorageTarget, &'static [u8])>,
}

impl AtomicCommitAdapter for OneShotAtomicCommitAdapter {
    type Error = &'static str;

    fn commit_atomic_work(
        &mut self,
        _request: AtomicCommitRequest<'_>,
    ) -> Result<Vec<MaterializedFreshCredentialSecret>, Self::Error> {
        Ok(self
            .result
            .drain(..)
            .map(|(target, secret)| {
                MaterializedFreshCredentialSecret::new(
                    target,
                    AuthCredentialSecret::try_from(secret).expect("credential secret"),
                )
            })
            .collect())
    }
}

fn auth_web_transport() -> AuthWebTransport {
    let cookie_manager =
        crate::web::CookieManager::from_keyset(test_keyset("tests.auth.web.transport.v1"));
    let csrf_protector = crate::web::CsrfProtector::new(crate::web::CsrfProtectorConfig::new(
        cookie_manager.clone(),
    ))
    .expect("csrf protector");
    AuthWebTransport::new(AuthWebTransportConfig::new(
        cookie_manager,
        csrf_protector,
        test_keyset("tests.auth.web.transport.fast-fail.v1"),
    ))
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([7_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}

fn set_cookie_pair(header: &AuthSetCookieHeader) -> &str {
    header
        .as_str()
        .split(';')
        .next()
        .expect("Set-Cookie starts with name=value")
}

fn assert_auth_set_cookie_header_fits_budget(header: &AuthSetCookieHeader) {
    assert!(
        header.as_str().len() <= AUTH_SET_COOKIE_HEADER_MAX_BYTES,
        "auth Set-Cookie header must fit the single-cookie browser budget; header had {} bytes",
        header.as_str().len(),
    );
}

fn credential_secret(bytes: &'static [u8]) -> AuthCredentialSecret {
    AuthCredentialSecret::try_from(bytes).expect("credential secret")
}

#[test]
fn auth_web_transport_renders_session_cookie_and_csrf_set_cookie_headers() {
    let loaded = loaded_session(100);
    let prepared = PreparedCommandExecution::prepare(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    )
    .expect("prepared execution");
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let mut adapter = OneShotAtomicCommitAdapter {
        result: vec![(
            CoreStorageTarget::SessionCredentialSecret {
                session_id: id("session"),
                secret_version: version(4),
            },
            b"fresh-session",
        )],
    };
    let materialized = planned
        .complete_with_commit_adapter_and_materialize_response(
            &mut adapter,
            PresentedAuthCookieSecrets::default(),
        )
        .expect("materialized execution");
    let transport = auth_web_transport();

    let set_cookie_headers = transport
        .render_set_cookie_headers(at(85), materialized.into_parts().1)
        .expect("set cookie headers");

    assert_eq!(set_cookie_headers.as_slice().len(), 2);
    assert!(set_cookie_headers.as_slice().iter().any(|header| {
        header
            .as_str()
            .starts_with("__Host-__paranoid_auth_session=")
    }));
    assert!(
        set_cookie_headers
            .as_slice()
            .iter()
            .any(|header| header.as_str().starts_with("__Host-csrf_token="))
    );

    let session_cookie_header = set_cookie_headers
        .as_slice()
        .iter()
        .map(set_cookie_pair)
        .find(|header| header.starts_with("__Host-__paranoid_auth_session="))
        .expect("session cookie pair");
    let decoded = transport
        .decode_presented_cookies_from_cookie_header(session_cookie_header)
        .expect("decoded session cookie");
    let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
    let session_cookie = presented_cookies
        .session_cookie
        .expect("presented session cookie");
    let session_secret = presented_cookie_secrets
        .session()
        .expect("presented session secret");

    assert_eq!(session_cookie.session_id, id("session"));
    assert_eq!(session_cookie.secret_version, version(4));
    assert_eq!(session_secret.secret().expose_secret(), b"fresh-session");
}

#[test]
fn auth_web_transport_cookie_families_fit_single_cookie_budget() {
    let transport = auth_web_transport();
    let cases = [
        (
            "session",
            MaterializedResponseEffect::IssueSessionCookie(MaterializedSessionCookieResponse::new(
                session_cookie(100),
                credential_secret(b"session-cookie-secret"),
            )),
        ),
        (
            "trusted device",
            MaterializedResponseEffect::IssueTrustedDeviceCookie(
                MaterializedTrustedDeviceCookieResponse::new(
                    trusted_device_cookie(90, 100),
                    credential_secret(b"trusted-device-cookie-secret"),
                ),
            ),
        ),
        (
            "active proof challenge",
            MaterializedResponseEffect::IssueActiveProofChallengeCookie(
                active_proof_challenge_cookie(),
            ),
        ),
        (
            "active proof continuation",
            MaterializedResponseEffect::IssueActiveProofContinuationCookie(
                MaterializedActiveProofContinuationCookieResponse::new(
                    ActiveProofContinuationCookieDraft {
                        attempt_id: id("active-proof-continuation-attempt"),
                        proof_use: ProofUse::RecoverOrReplaceCredential,
                        subject_id: Some(id("active-proof-continuation-subject")),
                        subject_binding:
                            ActiveProofContinuationSubjectBinding::VerifiedProofBoundSubject,
                        attempt_fast_fail_until: at(100),
                    },
                    credential_secret(b"active-proof-continuation-secret"),
                ),
            ),
        ),
    ];

    for (case_name, effect) in cases {
        let headers = transport
            .render_set_cookie_headers(at(10), MaterializedResponseEffects::from_vec(vec![effect]))
            .unwrap_or_else(|error| panic!("{case_name}: render Set-Cookie header: {error}"));
        assert_eq!(headers.as_slice().len(), 1, "{case_name}");
        assert_auth_set_cookie_header_fits_budget(&headers.as_slice()[0]);
    }
}

#[test]
fn auth_web_transport_rejects_over_budget_active_proof_challenge_cookie() {
    let transport = auth_web_transport();
    let method_challenge_state = ActiveProofMethodChallengeState::try_from_bytes(vec![
        7_u8;
        ACTIVE_PROOF_METHOD_CHALLENGE_STATE_MAX_BYTES
    ])
    .expect("oversized-for-cookie but method-bounded challenge state");
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_with_method_challenge_state(
        ActiveProofChallengeCookieContext::new(
            id("over-budget-attempt"),
            id("over-budget-challenge"),
            ProofSummary::new(ProofFamily::MessageSignature, "password_derived_signature")
                .expect("proof"),
            at(30),
            at(70),
            ActiveProofChallengeFastFailNonce::from_bytes(
                &[29_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
            )
            .expect("nonce"),
        )
        .expect("challenge cookie context"),
        method_challenge_state,
    )
    .expect("challenge cookie");

    let error = transport
        .render_set_cookie_headers(
            at(30),
            MaterializedResponseEffects::from_vec(vec![
                MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie),
            ]),
        )
        .expect_err("over-budget challenge cookie must reject before header emission");

    assert!(matches!(
        error,
        AuthWebTransportError::Core(Error::InputTooLong {
            input_name: "auth Set-Cookie header",
            max_bytes: AUTH_SET_COOKIE_HEADER_MAX_BYTES,
        })
    ));
}

#[test]
fn auth_web_transport_renders_delete_cookie_and_logout_csrf_cycle() {
    let transport = auth_web_transport();
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::DeleteSessionCookie,
        MaterializedResponseEffect::CycleCsrfToken { session_id: None },
    ]);

    let set_cookie_headers = transport
        .render_set_cookie_headers(at(10), effects)
        .expect("set cookie headers");

    assert_eq!(set_cookie_headers.as_slice().len(), 2);
    assert!(set_cookie_headers.as_slice().iter().any(|header| {
        header
            .as_str()
            .starts_with("__Host-__paranoid_auth_session=")
            && header.as_str().contains("Max-Age=0")
    }));
    assert!(
        set_cookie_headers
            .as_slice()
            .iter()
            .any(|header| header.as_str().starts_with("__Host-csrf_token="))
    );
}

#[test]
fn auth_web_transport_round_trips_active_proof_challenge_cookie() {
    let transport = auth_web_transport();
    let challenge_cookie = active_proof_challenge_cookie();
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie.clone()),
    ]);

    let set_cookie_headers = transport
        .render_set_cookie_headers(at(30), effects)
        .expect("set cookie headers");

    assert_eq!(set_cookie_headers.as_slice().len(), 1);
    let challenge_cookie_header = set_cookie_headers
        .as_slice()
        .iter()
        .map(set_cookie_pair)
        .find(|header| header.starts_with("__Host-__paranoid_auth_active_proof_challenge="))
        .expect("active proof challenge cookie pair");
    let decoded = transport
        .decode_presented_cookies_from_cookie_header(challenge_cookie_header)
        .expect("decoded active proof challenge cookie");
    let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();

    assert_eq!(
        presented_cookies.active_proof_challenge_cookie,
        Some(challenge_cookie)
    );
    assert!(presented_cookies.session_cookie.is_none());
    assert!(presented_cookies.trusted_device_cookie.is_none());
    assert!(presented_cookie_secrets.session().is_none());
    assert!(presented_cookie_secrets.trusted_device().is_none());
}

#[test]
fn auth_web_transport_round_trips_active_proof_method_challenge_state() {
    let transport = auth_web_transport();
    let method_challenge_state =
        ActiveProofMethodChallengeState::try_from_bytes(b"canonical-method-state".to_vec())
            .expect("method challenge state");
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_with_method_challenge_state(
        ActiveProofChallengeCookieContext::new(
            id("attempt"),
            id("challenge"),
            ProofSummary::new(ProofFamily::MessageSignature, "password_derived_signature")
                .expect("proof"),
            at(30),
            at(70),
            ActiveProofChallengeFastFailNonce::from_bytes(
                &[29_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
            )
            .expect("nonce"),
        )
        .expect("challenge cookie context"),
        method_challenge_state.clone(),
    )
    .expect("challenge cookie");
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie.clone()),
    ]);

    let set_cookie_headers = transport
        .render_set_cookie_headers(at(30), effects)
        .expect("set cookie headers");
    let challenge_cookie_header = set_cookie_headers
        .as_slice()
        .iter()
        .map(set_cookie_pair)
        .find(|header| header.starts_with("__Host-__paranoid_auth_active_proof_challenge="))
        .expect("active proof challenge cookie pair");
    let decoded = transport
        .decode_presented_cookies_from_cookie_header(challenge_cookie_header)
        .expect("decoded active proof challenge cookie");
    let (presented_cookies, _) = decoded.into_parts();
    let decoded_challenge_cookie = presented_cookies
        .active_proof_challenge_cookie
        .expect("active proof challenge cookie");

    assert_eq!(decoded_challenge_cookie, challenge_cookie);
    assert_eq!(
        decoded_challenge_cookie
            .method_challenge_state
            .expect("method challenge state")
            .as_bytes(),
        method_challenge_state.as_bytes()
    );
}

#[test]
fn auth_web_transport_rejects_cookie_issue_with_expired_max_age() {
    let transport = auth_web_transport();
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueSessionCookie(MaterializedSessionCookieResponse::new(
            SessionCookieDraft {
                session_id: id("session"),
                subject_id: id("subject"),
                secret_version: version(1),
                session_fast_fail_until: at(10),
                safe_read_valid_until: None,
                step_up_valid_until: None,
            },
            AuthCredentialSecret::try_from(b"session-secret".as_slice())
                .expect("credential secret"),
        )),
    ]);

    let error = transport
        .render_set_cookie_headers(at(10), effects)
        .expect_err("expired cookie max-age is rejected");

    assert!(matches!(error, AuthWebTransportError::Web(_)));
}
