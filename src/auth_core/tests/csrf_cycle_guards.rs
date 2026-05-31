use super::*;

#[test]
fn csrf_cycles_exactly_for_session_identity_or_freshness_changes() {
    let expired_session_loaded = LoadedState {
        session_cookie: Some(session_cookie(40)),
        ..LoadedState::default()
    };
    let missing_session_record_loaded = LoadedState {
        session_cookie: Some(session_cookie(200)),
        ..LoadedState::default()
    };
    let safe_read_cache_loaded = {
        let mut loaded = LoadedState {
            session_cookie: Some(session_cookie(200)),
            ..LoadedState::default()
        };
        loaded
            .session_cookie
            .as_mut()
            .expect("session cookie")
            .safe_read_valid_until = Some(at(70));
        loaded
    };
    let mut subject_revoked_session_loaded = loaded_session(200);
    subject_revoked_session_loaded.subject_revocations = loaded_subject_revocations(40);
    let regular_session_loaded = loaded_session(200);
    let previous_session_secret_loaded = {
        let mut loaded = loaded_session(200);
        loaded
            .session_cookie
            .as_mut()
            .expect("session cookie")
            .secret_version = version(2);
        loaded.session_secret_match = Some(loaded_session_secret_match(
            StoredSecretMatch::PreviousWithinGrace,
        ));
        loaded
    };
    let current_trusted_device_loaded = LoadedState {
        trusted_device_cookie: Some(TrustedDeviceCookieDraft {
            device_credential_id: id("device"),
            subject_id: id("subject"),
            secret_version: version(8),
            device_fast_fail_until: at(1_000),
            silent_revival_fast_fail_until: at(500),
        }),
        ..LoadedState::default()
    };
    let expired_session_cookie_with_valid_trusted_device_loaded = LoadedState {
        session_cookie: Some(session_cookie(40)),
        ..loaded_trusted_device(500, 1_000)
    };
    let matching_current_session_for_subject_revocation = LoadedState {
        session_cookie: Some(session_cookie(200)),
        trusted_device_cookie: Some(TrustedDeviceCookieDraft {
            device_credential_id: id("device"),
            subject_id: id("subject"),
            secret_version: version(8),
            device_fast_fail_until: at(1_000),
            silent_revival_fast_fail_until: at(500),
        }),
        ..LoadedState::default()
    };
    let matching_only_device_for_subject_revocation = LoadedState {
        trusted_device_cookie: Some(TrustedDeviceCookieDraft {
            device_credential_id: id("device"),
            subject_id: id("subject"),
            secret_version: version(8),
            device_fast_fail_until: at(1_000),
            silent_revival_fast_fail_until: at(500),
        }),
        ..LoadedState::default()
    };

    let cases = vec![
        (
            "safe-read cache hit",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(60),
                    request_kind: RequestKind::SafeRead,
                    fresh_session_id: None,
                }),
                &safe_read_cache_loaded,
            ),
            vec![],
        ),
        (
            "regular authoritative session",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(50),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &regular_session_loaded,
            ),
            vec![],
        ),
        (
            "previous session secret grace acceptance",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(50),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &previous_session_secret_loaded,
            ),
            vec![],
        ),
        (
            "trusted device needs active proof",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(600),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: Some(id("unused-session")),
                }),
                &loaded_trusted_device(500, 1_000),
            ),
            vec![],
        ),
        (
            "active proof completion",
            reduced_plan(
                Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
                    now: at(40),
                    attempt_id: id("attempt"),
                    challenge_id: Some(id("challenge")),
                    verified_proof: verified(
                        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                        Some(id("subject")),
                    ),
                    stateless_fast_fail: verified_stateless_fast_fail(),
                    weak_proof_gate: WeakProofGateStatus::NotRequired,
                    method_commit_work: Vec::new(),
                }),
                &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
            ),
            vec![],
        ),
        (
            "revoke noncurrent session",
            reduced_plan(
                Command::RevokeSession(RevokeSession {
                    now: at(50),
                    subject_id: id("subject"),
                    session_id: id("other-session"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &loaded_session(200),
            ),
            vec![],
        ),
        (
            "revoke current trusted device",
            reduced_plan(
                Command::RevokeTrustedDevice(RevokeTrustedDevice {
                    now: at(50),
                    subject_id: id("subject"),
                    device_credential_id: id("device"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &current_trusted_device_loaded,
            ),
            vec![],
        ),
        (
            "subject revocation with only matching device cookie",
            reduced_plan(
                Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                    now: at(50),
                    subject_id: id("subject"),
                    reason: RevocationReason::SubjectAuthStateChanged,
                }),
                &matching_only_device_for_subject_revocation,
            ),
            vec![],
        ),
        (
            "expired session cookie",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(50),
                    request_kind: RequestKind::SafeRead,
                    fresh_session_id: None,
                }),
                &expired_session_loaded,
            ),
            vec![None],
        ),
        (
            "missing session record",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(50),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &missing_session_record_loaded,
            ),
            vec![None],
        ),
        (
            "subject-revoked session record",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(60),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &subject_revoked_session_loaded,
            ),
            vec![None],
        ),
        (
            "session refresh",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(85),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &loaded_session(100),
            ),
            vec![Some(id("session"))],
        ),
        (
            "trusted-device silent revival",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(100),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: Some(id("new-session")),
                }),
                &loaded_trusted_device(500, 1_000),
            ),
            vec![Some(id("new-session"))],
        ),
        (
            "expired session cookie plus trusted-device silent revival",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(100),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: Some(id("new-session")),
                }),
                &expired_session_cookie_with_valid_trusted_device_loaded,
            ),
            vec![Some(id("new-session"))],
        ),
        (
            "full authentication",
            reduced_plan(
                Command::CompleteFullAuthentication(CompleteFullAuthentication {
                    now: at(20),
                    attempt_id: id("attempt"),
                    fresh_session_id: id("session"),
                    trust_device: None,
                }),
                &loaded_attempt_with_satisfied_proofs(
                    ProofUse::ContributeToFullAuthentication,
                    vec![proof(ProofFamily::OutOfBandCode)],
                ),
            ),
            vec![Some(id("session"))],
        ),
        (
            "step-up",
            reduced_plan(
                Command::CompleteStepUp(CompleteStepUp {
                    now: at(50),
                    attempt_id: id("attempt"),
                }),
                &loaded_session_and_attempt(
                    200,
                    ProofUse::SatisfyStepUp,
                    vec![proof(ProofFamily::SharedSecretOtp)],
                ),
            ),
            vec![Some(id("session"))],
        ),
        (
            "trusted-device active-proof revival",
            reduced_plan(
                Command::CompleteTrustedDeviceRevivalWithActiveProof(
                    CompleteTrustedDeviceRevivalWithActiveProof {
                        now: at(600),
                        attempt_id: id("attempt"),
                        fresh_session_id: id("new-session"),
                    },
                ),
                &loaded_trusted_device_and_attempt(
                    500,
                    2_000,
                    ProofUse::ReviveTrustedDeviceWithActiveProof,
                    vec![proof(ProofFamily::MessageSignature)],
                ),
            ),
            vec![Some(id("new-session"))],
        ),
        (
            "logout current session",
            reduced_plan(
                Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
                &loaded_session(200),
            ),
            vec![None],
        ),
        (
            "revoke current session",
            reduced_plan(
                Command::RevokeSession(RevokeSession {
                    now: at(50),
                    subject_id: id("subject"),
                    session_id: id("session"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &loaded_session(200),
            ),
            vec![None],
        ),
        (
            "subject revocation with matching session cookie",
            reduced_plan(
                Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                    now: at(50),
                    subject_id: id("subject"),
                    reason: RevocationReason::SubjectAuthStateChanged,
                }),
                &matching_current_session_for_subject_revocation,
            ),
            vec![None],
        ),
    ];

    for (case_name, plan, expected_targets) in cases {
        assert_eq!(
            csrf_cycle_targets(&plan),
            expected_targets,
            "{case_name}: unexpected CSRF cycle targets",
        );
    }
}
