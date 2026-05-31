use super::*;

#[test]
fn logout_current_session_revokes_session_and_clears_response_state() {
    let transition = reduce_command(
        &config(),
        Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
        &loaded_session(200),
    )
    .expect("transition");

    assert_eq!(
        transition.outcome,
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::CurrentSession,
        })
    );
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::RevokeSession {
            session_id,
            reason: RevocationReason::Logout,
            revoked_at,
        }] if *session_id == id("session") && *revoked_at == at(50)
    ));
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteSessionCookie)
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::CycleCsrfToken { session_id: None })
    );
}

#[test]
fn revoke_noncurrent_session_is_guarded_by_subject_ownership() {
    let transition = reduce_command(
        &config(),
        Command::RevokeSession(RevokeSession {
            now: at(50),
            subject_id: id("subject"),
            session_id: id("other-session"),
            reason: RevocationReason::RemoteRevocation,
        }),
        &loaded_session(200),
    )
    .expect("transition");

    assert_eq!(
        transition.outcome,
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(id("subject")),
            target: RevocationTarget::Session(id("other-session")),
        })
    );
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [Precondition::SessionBelongsToSubject {
            session_id,
            subject_id,
        }] if *session_id == id("other-session") && *subject_id == id("subject")
    ));
    assert!(transition.commit_plan.response_effects.is_empty());
}

#[test]
fn revoke_current_trusted_device_deletes_device_cookie() {
    let loaded = LoadedState {
        trusted_device_cookie: Some(TrustedDeviceCookieDraft {
            device_credential_id: id("device"),
            subject_id: id("subject"),
            secret_version: version(8),
            device_fast_fail_until: at(1_000),
            silent_revival_fast_fail_until: at(500),
        }),
        ..LoadedState::default()
    };

    let transition = reduce_command(
        &config(),
        Command::RevokeTrustedDevice(RevokeTrustedDevice {
            now: at(50),
            subject_id: id("subject"),
            device_credential_id: id("device"),
            reason: RevocationReason::RemoteRevocation,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [Precondition::TrustedDeviceBelongsToSubject {
            device_credential_id,
            subject_id,
        }] if *device_credential_id == id("device") && *subject_id == id("subject")
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::RevokeTrustedDeviceCredential {
            device_credential_id,
            reason: RevocationReason::RemoteRevocation,
            revoked_at,
        }] if *device_credential_id == id("device") && *revoked_at == at(50)
    ));
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
}

#[test]
fn subject_auth_state_revocation_clears_matching_current_cookies() {
    let loaded = LoadedState {
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

    let transition = reduce_command(
        &config(),
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(50),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id,
            revoke_records_created_at_or_before,
            reason: RevocationReason::SubjectAuthStateChanged,
        }] if *subject_id == id("subject") && *revoke_records_created_at_or_before == at(50)
    ));
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteSessionCookie)
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteTrustedDeviceCookie)
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::CycleCsrfToken { session_id: None })
    );
}
