use super::*;

#[test]
fn expired_session_cookie_is_cleared() {
    let loaded = LoadedState {
        session_cookie: Some(session_cookie(40)),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
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

#[test]
fn subject_wide_revocation_invalidates_loaded_session_during_request_resolution() {
    let mut loaded = loaded_session(200);
    loaded.subject_revocations = loaded_subject_revocations(40);

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

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
    assert!(transition.commit_plan.mutations.is_empty());
}

#[test]
fn subject_wide_revocation_invalidates_session_created_at_the_cutoff() {
    let mut loaded = loaded_session(200);
    loaded
        .session_record
        .as_mut()
        .expect("session record")
        .created_at = at(40);
    loaded.subject_revocations = loaded_subject_revocations(40);

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

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
}

#[test]
fn live_session_cookie_without_authoritative_record_is_cleared() {
    let loaded = LoadedState {
        session_cookie: Some(session_cookie(200)),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
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

#[test]
fn subject_wide_revocation_invalidates_trusted_device_during_request_resolution() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded.subject_revocations = loaded_subject_revocations(40);

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect("transition");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
    assert!(transition.commit_plan.mutations.is_empty());
}

#[test]
fn subject_wide_revocation_invalidates_trusted_device_created_at_the_cutoff() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded
        .trusted_device_record
        .as_mut()
        .expect("trusted-device record")
        .created_at = at(40);
    loaded.subject_revocations = loaded_subject_revocations(40);

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect("transition");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
}

#[test]
fn live_trusted_device_cookie_without_authoritative_record_is_cleared() {
    let loaded = LoadedState {
        trusted_device_cookie: Some(trusted_device_cookie(500, 1_000)),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("unused-session")),
        }),
        &loaded,
    )
    .expect("transition");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
}
