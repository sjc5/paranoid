use super::*;

#[test]
fn loaded_state_contradictions_reject_mismatched_cookie_record_identity() {
    let mut mismatched_session_id = loaded_session(200);
    mismatched_session_id
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .session_id = id("other-session");
    let session_id_error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &mismatched_session_id,
    )
    .expect_err("session cookie and record ids must agree");
    assert_eq!(
        session_id_error,
        Error::LoadedStateContradiction("session cookie and record ids differ")
    );

    let mut mismatched_session_subject = loaded_session(200);
    mismatched_session_subject
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .subject_id = id("other-subject");
    let session_subject_error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &mismatched_session_subject,
    )
    .expect_err("session cookie and record subjects must agree");
    assert_eq!(
        session_subject_error,
        Error::LoadedStateContradiction("session cookie and record subjects differ")
    );

    let mut mismatched_device_id = loaded_trusted_device(500, 1_000);
    mismatched_device_id
        .trusted_device_cookie
        .as_mut()
        .expect("trusted-device cookie")
        .device_credential_id = id("other-device");
    let device_id_error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &mismatched_device_id,
    )
    .expect_err("trusted-device cookie and record ids must agree");
    assert_eq!(
        device_id_error,
        Error::LoadedStateContradiction("trusted-device cookie and record ids differ")
    );

    let mut mismatched_device_subject = loaded_trusted_device(500, 1_000);
    mismatched_device_subject
        .trusted_device_cookie
        .as_mut()
        .expect("trusted-device cookie")
        .subject_id = id("other-subject");
    let device_subject_error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &mismatched_device_subject,
    )
    .expect_err("trusted-device cookie and record subjects must agree");
    assert_eq!(
        device_subject_error,
        Error::LoadedStateContradiction("trusted-device cookie and record subjects differ")
    );
}

#[test]
fn loaded_state_contradictions_reject_incomplete_previous_secret_metadata() {
    let mut incomplete_session_previous_secret = loaded_session(200);
    incomplete_session_previous_secret
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .secret_version = version(2);
    let session_record = incomplete_session_previous_secret
        .session_record
        .as_mut()
        .expect("session record");
    session_record.previous_secret_version = Some(version(2));
    session_record.previous_secret_accept_until = None;
    incomplete_session_previous_secret.session_secret_match = Some(loaded_session_secret_match(
        StoredSecretMatch::PreviousWithinGrace,
    ));
    let session_error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &incomplete_session_previous_secret,
    )
    .expect_err("session previous secret metadata must be complete");
    assert_eq!(
        session_error,
        Error::LoadedStateContradiction(
            "session previous secret version and deadline must both be present or absent",
        )
    );

    let mut incomplete_device_previous_secret = loaded_trusted_device(500, 1_000);
    incomplete_device_previous_secret
        .trusted_device_cookie
        .as_mut()
        .expect("trusted-device cookie")
        .secret_version = version(7);
    let trusted_device_record = incomplete_device_previous_secret
        .trusted_device_record
        .as_mut()
        .expect("trusted-device record");
    trusted_device_record.previous_secret_version = Some(version(7));
    trusted_device_record.previous_secret_accept_until = None;
    incomplete_device_previous_secret.trusted_device_secret_match = Some(
        loaded_trusted_device_secret_match(StoredSecretMatch::PreviousWithinGrace),
    );
    let device_error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &incomplete_device_previous_secret,
    )
    .expect_err("trusted-device previous secret metadata must be complete");
    assert_eq!(
        device_error,
        Error::LoadedStateContradiction(
            "trusted-device previous secret version and deadline must both be present or absent",
        )
    );
}
