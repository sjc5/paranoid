use super::*;

fn required_for(command: Command, presented: PresentedAuthCookies) -> Vec<LoadedStateRequirement> {
    CommandLoadedStateContract::for_command(&config(), &command, &presented)
        .expect("load contract")
        .required()
        .to_vec()
}

fn presented_session(cookie: SessionCookieDraft) -> PresentedAuthCookies {
    PresentedAuthCookies {
        session_cookie: Some(cookie),
        trusted_device_cookie: None,
        active_proof_challenge_cookie: None,
        active_proof_continuation_cookie: None,
    }
}

fn presented_trusted_device(cookie: TrustedDeviceCookieDraft) -> PresentedAuthCookies {
    PresentedAuthCookies {
        session_cookie: None,
        trusted_device_cookie: Some(cookie),
        active_proof_challenge_cookie: None,
        active_proof_continuation_cookie: None,
    }
}

fn presented_session_requirement() -> LoadedStateRequirement {
    LoadedStateRequirement::PresentedSessionCookie {
        session_id: id("session"),
    }
}

fn authoritative_session_requirements() -> Vec<LoadedStateRequirement> {
    vec![
        presented_session_requirement(),
        LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
            session_id: id("session"),
        },
        LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject {
            session_id: id("session"),
        },
    ]
}

fn presented_device_requirement() -> LoadedStateRequirement {
    LoadedStateRequirement::PresentedTrustedDeviceCookie {
        device_credential_id: id("device"),
    }
}

fn authoritative_device_requirements() -> Vec<LoadedStateRequirement> {
    vec![
        presented_device_requirement(),
        LoadedStateRequirement::TrustedDeviceRecordAndSecretMatchForPresentedCookie {
            device_credential_id: id("device"),
        },
        LoadedStateRequirement::SubjectRevocationForLoadedTrustedDeviceSubject {
            device_credential_id: id("device"),
        },
    ]
}

fn active_attempt_requirements() -> Vec<LoadedStateRequirement> {
    vec![
        LoadedStateRequirement::ActiveProofAttempt {
            attempt_id: id("attempt"),
        },
        LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
            attempt_id: id("attempt"),
        },
    ]
}

#[test]
fn request_resolution_load_contract_uses_safe_read_cache_without_authoritative_loads() {
    let mut cookie = session_cookie(200);
    cookie.safe_read_valid_until = Some(at(80));

    assert_eq!(
        required_for(
            Command::ResolveRequest(ResolveRequest {
                now: at(50),
                request_kind: RequestKind::SafeRead,
                fresh_session_id: None,
            }),
            presented_session(cookie),
        ),
        vec![presented_session_requirement()]
    );
}

#[test]
fn request_resolution_load_contract_loads_authoritative_session_when_safe_read_cannot_apply() {
    assert_eq!(
        required_for(
            Command::ResolveRequest(ResolveRequest {
                now: at(50),
                request_kind: RequestKind::StateChanging,
                fresh_session_id: None,
            }),
            presented_session(session_cookie(200)),
        ),
        authoritative_session_requirements()
    );
}

#[test]
fn request_resolution_load_contract_fast_fails_expired_session_cookie_without_db_load() {
    assert_eq!(
        required_for(
            Command::ResolveRequest(ResolveRequest {
                now: at(200),
                request_kind: RequestKind::StateChanging,
                fresh_session_id: None,
            }),
            presented_session(session_cookie(200)),
        ),
        vec![presented_session_requirement()]
    );
}

#[test]
fn request_resolution_load_contract_loads_authoritative_trusted_device_until_fast_fail_deadline() {
    assert_eq!(
        required_for(
            Command::ResolveRequest(ResolveRequest {
                now: at(100),
                request_kind: RequestKind::StateChanging,
                fresh_session_id: Some(id("new-session")),
            }),
            presented_trusted_device(trusted_device_cookie(500, 1_000)),
        ),
        authoritative_device_requirements()
    );
}

#[test]
fn request_resolution_load_contract_fast_fails_expired_trusted_device_cookie_without_db_load() {
    assert_eq!(
        required_for(
            Command::ResolveRequest(ResolveRequest {
                now: at(1_000),
                request_kind: RequestKind::StateChanging,
                fresh_session_id: Some(id("new-session")),
            }),
            presented_trusted_device(trusted_device_cookie(500, 1_000)),
        ),
        vec![presented_device_requirement()]
    );
}

#[test]
fn request_resolution_load_contract_disables_safe_read_when_trusted_device_cookie_is_present() {
    let mut session = session_cookie(200);
    session.safe_read_valid_until = Some(at(80));

    let mut expected = authoritative_session_requirements();
    expected.extend(authoritative_device_requirements());

    assert_eq!(
        required_for(
            Command::ResolveRequest(ResolveRequest {
                now: at(50),
                request_kind: RequestKind::SafeRead,
                fresh_session_id: None,
            }),
            PresentedAuthCookies {
                session_cookie: Some(session),
                trusted_device_cookie: Some(trusted_device_cookie(500, 1_000)),
                active_proof_challenge_cookie: None,
                active_proof_continuation_cookie: None,
            },
        ),
        expected
    );
}

#[test]
fn active_proof_load_contract_names_attempt_challenge_and_resolved_subject_requirements() {
    let mut expected = active_attempt_requirements();
    expected.push(
        LoadedStateRequirement::SubjectRevocationForVerifiedActiveProofSubject {
            subject_id: id("subject"),
        },
    );
    expected.push(LoadedStateRequirement::ActiveProofChallenge {
        challenge_id: id("challenge"),
    });

    assert_eq!(
        required_for(
            Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: Some(id("challenge")),
                verified_proof: verified_proof(ProofFamily::OutOfBandCode, Some(id("subject"))),
                stateless_fast_fail: verified_stateless_fast_fail(),
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            }),
            PresentedAuthCookies::default(),
        ),
        expected
    );
}

#[test]
fn active_proof_load_contract_names_attempt_only_for_stateless_failure_and_issue_paths() {
    assert_eq!(
        required_for(
            Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
                now: at(30),
                attempt_id: id("attempt"),
                challenge_id: id("challenge"),
                method: proof_method(ProofFamily::OutOfBandCode),
                challenge_dedupe_key: dedupe_key("login:email-hash:window"),
                recipient_handle: "opaque-email-handle".to_owned(),
                idempotency_key: "mail-idempotency-key".to_owned(),
                stateless_fast_fail_cookie: active_proof_challenge_cookie(),
                method_commit_work: Vec::new(),
            }),
            PresentedAuthCookies::default(),
        ),
        active_attempt_requirements()
    );

    assert_eq!(
        required_for(
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: at(40),
                attempt_id: id("attempt"),
                method: proof_method(ProofFamily::SharedSecretOtp),
                weak_proof_gate: verified_proof_of_work_gate(),
            }),
            PresentedAuthCookies::default(),
        ),
        active_attempt_requirements()
    );
}

#[test]
fn lifecycle_completion_load_contract_derives_subject_and_device_from_loaded_state() {
    assert_eq!(
        required_for(
            Command::CompleteFullAuthentication(CompleteFullAuthentication {
                now: at(20),
                attempt_id: id("attempt"),
                fresh_session_id: id("session"),
                trust_device: Some(TrustDeviceAfterFullAuthentication {
                    device_credential_id: id("device"),
                    display_label: Some("laptop".to_owned()),
                }),
            }),
            PresentedAuthCookies::default(),
        ),
        active_attempt_requirements()
    );

    let mut expected = authoritative_device_requirements();
    expected.extend(active_attempt_requirements());

    assert_eq!(
        required_for(
            Command::CompleteTrustedDeviceRevivalWithActiveProof(
                CompleteTrustedDeviceRevivalWithActiveProof {
                    now: at(600),
                    attempt_id: id("attempt"),
                    fresh_session_id: id("new-session"),
                },
            ),
            presented_trusted_device(trusted_device_cookie(500, 1_000)),
        ),
        expected
    );
}

#[test]
fn step_up_load_contract_requires_current_session_and_attempt_only_when_session_cookie_is_live() {
    let mut expected = authoritative_session_requirements();
    expected.extend(active_attempt_requirements());

    assert_eq!(
        required_for(
            Command::CompleteStepUp(CompleteStepUp {
                now: at(50),
                attempt_id: id("attempt"),
            }),
            presented_session(session_cookie(200)),
        ),
        expected
    );

    assert_eq!(
        required_for(
            Command::CompleteStepUp(CompleteStepUp {
                now: at(200),
                attempt_id: id("attempt"),
            }),
            presented_session(session_cookie(200)),
        ),
        vec![presented_session_requirement()]
    );
}

#[test]
fn revocation_load_contract_uses_presented_cookies_only_for_response_cleanup() {
    assert_eq!(
        required_for(
            Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                now: at(50),
                subject_id: id("subject"),
                reason: RevocationReason::SubjectAuthStateChanged,
            }),
            PresentedAuthCookies {
                session_cookie: Some(session_cookie(200)),
                trusted_device_cookie: Some(trusted_device_cookie(500, 1_000)),
                active_proof_challenge_cookie: None,
                active_proof_continuation_cookie: None,
            },
        ),
        vec![
            presented_session_requirement(),
            presented_device_requirement()
        ]
    );
}

#[test]
fn load_contract_rejects_secret_match_evidence_for_a_different_credential() {
    let session_contract = CommandLoadedStateContract::for_command(
        &config(),
        &Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &presented_session(session_cookie(200)),
    )
    .expect("session load contract");
    let session_error = session_contract
        .validate_loaded_state(&LoadedState {
            session_cookie: Some(session_cookie(200)),
            session_record: Some(session_record(200)),
            session_secret_match: Some(LoadedSessionSecretMatch::new(
                id("other-session"),
                StoredSecretMatch::Current,
            )),
            subject_revocations: no_subject_revocations(),
            ..LoadedState::default()
        })
        .expect_err("session secret match must be bound to the loaded session");
    assert_eq!(
        session_error,
        Error::LoadedStateDoesNotSatisfyLoadContract(
            "loaded session secret match id differs from required session id",
        )
    );

    let device_contract = CommandLoadedStateContract::for_command(
        &config(),
        &Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &presented_trusted_device(trusted_device_cookie(500, 1_000)),
    )
    .expect("trusted-device load contract");
    let device_error = device_contract
        .validate_loaded_state(&LoadedState {
            trusted_device_cookie: Some(trusted_device_cookie(500, 1_000)),
            trusted_device_record: Some(trusted_device_record(500, 1_000)),
            trusted_device_secret_match: Some(LoadedTrustedDeviceSecretMatch::new(
                id("other-device"),
                StoredSecretMatch::Current,
            )),
            subject_revocations: no_subject_revocations(),
            ..LoadedState::default()
        })
        .expect_err("trusted-device secret match must be bound to the loaded credential");
    assert_eq!(
        device_error,
        Error::LoadedStateDoesNotSatisfyLoadContract(
            "loaded trusted-device secret match id differs from required trusted-device id",
        )
    );
}
