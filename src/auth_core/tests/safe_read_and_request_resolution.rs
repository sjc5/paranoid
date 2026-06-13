use super::*;

#[test]
fn safe_read_cache_authenticates_without_commit_work() {
    let mut cookie = session_cookie(200);
    cookie.safe_read_valid_until = Some(at(70));
    let loaded = LoadedState {
        session_cookie: Some(cookie),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SafeReadCache,
            ..
        })
    ));
    assert_eq!(transition.commit_plan, CommitPlan::default());
}

#[test]
fn safe_read_cache_can_use_loaded_absent_subject_revocations() {
    let mut cookie = session_cookie(200);
    cookie.safe_read_valid_until = Some(at(70));
    let loaded = LoadedState {
        session_cookie: Some(cookie),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SafeReadCache,
            ..
        })
    ));
    assert_eq!(transition.commit_plan, CommitPlan::default());
}

#[test]
fn safe_read_cache_is_not_used_when_authoritative_state_is_loaded() {
    let mut loaded = loaded_session(200);
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .safe_read_valid_until = Some(at(70));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            ..
        })
    ));
    assert!(
        transition
            .commit_plan
            .preconditions
            .iter()
            .any(|precondition| {
                matches!(precondition, Precondition::SessionStillMatches { .. })
            })
    );
}

#[test]
fn authoritative_session_requires_loaded_subject_revocations() {
    let mut loaded = loaded_session(200);
    loaded.subject_revocations = LoadedSubjectRevocations::not_loaded();

    let error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect_err("authoritative session must require subject revocation status");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "subject revocation state was not loaded for required subject",
        )
    );
}

#[test]
fn authoritative_session_rejects_subject_revocations_for_different_subject() {
    let mut loaded = loaded_session(200);
    loaded.subject_revocations = LoadedSubjectRevocations::loaded(id("other-subject"), None);

    let error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect_err("authoritative session must require matching subject revocation status");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "subject revocation state was not loaded for required subject",
        )
    );
}

#[test]
fn authoritative_trusted_device_requires_loaded_subject_revocations() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded.subject_revocations = LoadedSubjectRevocations::not_loaded();

    let error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect_err("authoritative trusted device must require subject revocation status");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "subject revocation state was not loaded for required subject",
        )
    );
}

#[test]
fn active_proof_completion_requires_loaded_subject_revocations() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded.subject_revocations = LoadedSubjectRevocations::not_loaded();

    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(30),
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
        &loaded,
    )
    .expect_err("active proof completion must require subject revocation status");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "subject revocation state was not loaded for required subject",
        )
    );
}

#[test]
fn safe_read_cache_cannot_authenticate_state_changing_requests() {
    let mut cookie = session_cookie(200);
    cookie.safe_read_valid_until = Some(at(70));
    let loaded = LoadedState {
        session_cookie: Some(cookie),
        session_record: Some(session_record(200)),
        session_secret_match: Some(loaded_session_secret_match(StoredSecretMatch::Current)),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            ..
        })
    ));
    assert!(
        transition
            .commit_plan
            .preconditions
            .iter()
            .any(|precondition| {
                matches!(precondition, Precondition::SessionStillMatches { .. })
            })
    );
}

#[test]
fn request_resolution_does_not_require_network_or_user_agent_identity() {
    let loaded = loaded_session(200);

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("request resolution should use auth cookies and authoritative state");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            ..
        })
    ));
}

#[test]
fn safe_read_cache_cannot_authenticate_sensitive_requests() {
    let mut loaded = loaded_session(200);
    loaded
        .session_record
        .as_mut()
        .expect("session record")
        .step_up_expires_at = Some(at(90));
    let cookie = loaded.session_cookie.as_mut().expect("session cookie");
    cookie.safe_read_valid_until = Some(at(70));
    cookie.step_up_valid_until = Some(at(90));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
            ..
        })
    ));
    assert!(
        transition
            .commit_plan
            .preconditions
            .iter()
            .any(|precondition| {
                matches!(precondition, Precondition::SessionStillMatches { .. })
            })
    );
}

#[test]
fn safe_read_cache_cannot_bypass_refresh_window() {
    let mut cookie = session_cookie(100);
    cookie.safe_read_valid_until = Some(at(95));
    let loaded = LoadedState {
        session_cookie: Some(cookie),
        session_record: Some(session_record(100)),
        session_secret_match: Some(loaded_session_secret_match(StoredSecretMatch::Current)),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::RefreshedSession,
            ..
        })
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::RefreshSession { .. }]
    ));
}

#[test]
fn safe_read_cache_cannot_bypass_subject_wide_revocation_state() {
    let mut cookie = session_cookie(200);
    cookie.safe_read_valid_until = Some(at(70));
    let loaded = LoadedState {
        session_cookie: Some(cookie),
        subject_revocations: loaded_subject_revocations(40),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("transition");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
}
