use super::*;

#[test]
fn authoritative_session_in_refresh_window_rotates_session_and_csrf() {
    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded_session(100),
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
        [Mutation::RefreshSession {
            new_secret_version,
            expires_at,
            ..
        }] if *new_secret_version == version(4) && *expires_at == at(185)
    ));
    assert_eq!(
        transition.commit_plan.fresh_credential_secrets,
        vec![fresh_session_secret("session", 4)]
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .iter()
            .any(|effect| matches!(effect, ResponseEffect::CycleCsrfToken { .. }))
    );
}

#[test]
fn previous_session_secret_within_grace_authenticates_without_reissuing_current_cookie() {
    let mut loaded = loaded_session(200);
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .secret_version = version(2);
    loaded.session_secret_match = Some(loaded_session_secret_match(
        StoredSecretMatch::PreviousWithinGrace,
    ));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("previous session secret should be accepted inside grace");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            ..
        })
    ));
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [Precondition::SessionStillMatches {
            session_id,
            current_secret_version,
            ..
        }] if *session_id == id("session") && *current_secret_version == version(3)
    ));
    assert!(transition.commit_plan.mutations.is_empty());
    assert!(
        transition
            .commit_plan
            .response_effects
            .iter()
            .all(|effect| !matches!(effect, ResponseEffect::IssueSessionCookie(_))),
        "a MAC-only adapter cannot recover and reissue the already-current plaintext secret"
    );
}

#[test]
fn previous_session_secret_grace_can_authenticate_after_old_fast_fail_deadline() {
    let mut loaded = loaded_session(200);
    let cookie = loaded.session_cookie.as_mut().expect("session cookie");
    cookie.secret_version = version(2);
    cookie.session_fast_fail_until = at(40);
    loaded.session_secret_match = Some(loaded_session_secret_match(
        StoredSecretMatch::PreviousWithinGrace,
    ));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("authoritative previous-secret grace should accept a stale cookie");

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
            .response_effects
            .iter()
            .all(|effect| !matches!(effect, ResponseEffect::IssueSessionCookie(_))),
        "a MAC-only adapter cannot recover and reissue the already-current plaintext secret"
    );
    assert!(
        !transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteSessionCookie)
    );
    assert_eq!(csrf_cycle_targets(&transition.commit_plan), Vec::new());
}

#[test]
fn session_previous_secret_reported_within_grace_after_deadline_is_rejected() {
    let mut loaded = loaded_session(200);
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .secret_version = version(2);
    loaded.session_secret_match = Some(loaded_session_secret_match(
        StoredSecretMatch::PreviousWithinGrace,
    ));

    let error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(55),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect_err("within-grace classification must match the record deadline");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "session previous secret reported within grace after grace deadline",
        )
    );
}

#[test]
fn expired_previous_session_secret_audits_and_deletes_cookie_without_revoking_session() {
    let mut loaded = loaded_session(200);
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .secret_version = version(2);
    loaded.session_secret_match = Some(loaded_session_secret_match(
        StoredSecretMatch::PreviousExpired,
    ));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(55),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("expired previous secret is a mismatch, not a reducer error");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::CredentialMismatch
                && event.session_id == Some(id("session")))
    );
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
    assert!(
        !transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(mutation, Mutation::RevokeSession { .. }))
    );
}

#[test]
fn session_credential_mismatch_audit_survives_when_trusted_device_replaces_session() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded.session_cookie = Some(session_cookie(200));
    loaded.session_record = Some(session_record(200));
    loaded.session_secret_match = Some(loaded_session_secret_match(StoredSecretMatch::Unknown));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect("trusted device should replace the bad session cookie");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            ..
        })
    ));
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::CredentialMismatch
                && event.session_id == Some(id("session")))
    );
    assert!(
        !transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteSessionCookie)
    );
    assert_eq!(
        csrf_cycle_targets(&transition.commit_plan),
        vec![Some(id("new-session"))],
    );
}

#[test]
fn trusted_device_replaces_bad_cross_subject_session_after_loading_both_subject_revocations() {
    let mut store = InMemoryCommitStore::default();
    let mut session_record = session_record(200);
    session_record.subject_id = id("other-subject");
    store.sessions.insert(id("session"), session_record);
    store
        .trusted_devices
        .insert(id("device"), trusted_device_record(500, 1_000));

    let mut session_cookie = session_cookie(200);
    session_cookie.subject_id = id("other-subject");
    session_cookie.secret_version = version(99);
    let trusted_device_cookie = trusted_device_cookie(500, 1_000);

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &store.loaded_for_session_and_trusted_device_cookies(
            session_cookie,
            trusted_device_cookie,
            at(100),
        ),
    )
    .expect("trusted device should replace the bad cross-subject session cookie");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            subject_id,
            ..
        }) if subject_id == id("subject")
    ));
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::CredentialMismatch
                && event.subject_id == Some(id("other-subject"))
                && event.session_id == Some(id("session")))
    );
}

#[test]
fn unknown_session_secret_audits_and_deletes_cookie_without_revoking_session() {
    let mut loaded = loaded_session(200);
    loaded.session_secret_match = Some(loaded_session_secret_match(StoredSecretMatch::Unknown));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect("unknown session secret is a mismatch, not a reducer error");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::CredentialMismatch
                && event.session_id == Some(id("session")))
    );
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
    assert!(
        !transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(mutation, Mutation::RevokeSession { .. }))
    );
}

#[test]
fn current_session_secret_match_must_match_cookie_version() {
    let mut loaded = loaded_session(200);
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .secret_version = version(2);
    loaded.session_secret_match = Some(loaded_session_secret_match(StoredSecretMatch::Current));

    let error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded,
    )
    .expect_err("current match must correspond to the current cookie version");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "session current secret match version differs from cookie version",
        )
    );
}
