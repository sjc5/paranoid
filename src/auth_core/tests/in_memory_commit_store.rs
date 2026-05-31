use super::*;

#[test]
fn in_memory_commit_adapter_runs_full_session_lifecycle_script() {
    let mut store = InMemoryCommitStore::default();

    let start_login_attempt = reduce_command(
        &config(),
        Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: at(10),
            attempt_id: id("login-attempt"),
            proof_use: ProofUse::ContributeToFullAuthentication,
            subject_id: None,
        }),
        &LoadedState::default(),
    )
    .expect("start login attempt");
    assert!(
        store
            .commit_plan(start_login_attempt.commit_plan)
            .expect("login attempt commit")
            .is_empty()
    );

    let issue_login_challenge = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(20),
            attempt_id: id("login-attempt"),
            challenge_id: id("login-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:subject:20"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "login-mail-20".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "login-attempt",
                "login-challenge",
                at(20),
                at(60),
            ),
            method_commit_work: Vec::new(),
        }),
        &store.loaded_for_attempt(&id("login-attempt")),
    )
    .expect("issue login challenge");
    assert_only_issued_active_proof_challenge_cookie(
        store
            .commit_plan(issue_login_challenge.commit_plan)
            .expect("login challenge commit"),
        id("login-challenge"),
    );

    let complete_login_challenge = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(30),
            attempt_id: id("login-attempt"),
            challenge_id: Some(id("login-challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &with_no_subject_revocations(
            store.loaded_for_attempt_and_challenge(&id("login-attempt"), &id("login-challenge")),
        ),
    )
    .expect("complete login challenge");
    assert_only_deleted_active_proof_challenge_cookie(
        store
            .commit_plan(complete_login_challenge.commit_plan)
            .expect("complete login challenge commit"),
    );
    assert_eq!(
        store
            .active_proof_attempts
            .get(&id("login-attempt"))
            .expect("login attempt")
            .subject_id,
        Some(id("subject"))
    );

    let complete_full_authentication = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("login-attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &store.loaded_for_attempt(&id("login-attempt")),
    )
    .expect("complete full authentication");
    let full_auth_response_effects = store
        .commit_plan(complete_full_authentication.commit_plan)
        .expect("full authentication commit");
    let mut session_cookie = session_cookie_from_response_effects(&full_auth_response_effects);
    assert!(
        !store
            .active_proof_attempts
            .contains_key(&id("login-attempt"))
    );
    assert_eq!(
        store
            .sessions
            .get(&id("session"))
            .expect("session")
            .current_secret_version,
        version(1)
    );
    assert!(
        full_auth_response_effects.contains(&ResponseEffect::CycleCsrfToken {
            session_id: Some(id("session")),
        })
    );

    let safe_read = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(45),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &LoadedState {
            session_cookie: Some(session_cookie.clone()),
            ..LoadedState::default()
        },
    )
    .expect("safe read cache");
    assert!(matches!(
        safe_read.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SafeReadCache,
            ..
        })
    ));
    assert_eq!(safe_read.commit_plan, CommitPlan::default());

    let authoritative_read = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(session_cookie.clone(), at(60)),
    )
    .expect("authoritative request");
    assert!(matches!(
        authoritative_read.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
            ..
        })
    ));
    let authoritative_read_response_effects = store
        .commit_plan(authoritative_read.commit_plan)
        .expect("authoritative request commit");
    session_cookie = session_cookie_from_response_effects(&authoritative_read_response_effects);

    let refresh = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(125),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(session_cookie.clone(), at(125)),
    )
    .expect("refresh request");
    assert!(matches!(
        refresh.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::RefreshedSession,
            step_up_is_fresh: false,
            ..
        })
    ));
    let refresh_response_effects = store
        .commit_plan(refresh.commit_plan)
        .expect("refresh commit");
    session_cookie = session_cookie_from_response_effects(&refresh_response_effects);
    let refreshed_session = store.sessions.get(&id("session")).expect("session");
    assert_eq!(refreshed_session.current_secret_version, version(2));
    assert_eq!(refreshed_session.previous_secret_version, Some(version(1)));
    assert_eq!(refreshed_session.expires_at, at(225));

    let sensitive_request_without_fresh_step_up = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(130),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(session_cookie.clone(), at(130)),
    )
    .expect("sensitive request without fresh step-up");
    assert_eq!(
        sensitive_request_without_fresh_step_up.outcome,
        Outcome::NeedsStepUp {
            session_id: id("session"),
            subject_id: id("subject"),
        }
    );
    assert_eq!(
        sensitive_request_without_fresh_step_up.commit_plan,
        CommitPlan::default()
    );

    let start_step_up_attempt = reduce_command(
        &config(),
        Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: at(131),
            attempt_id: id("step-up-attempt"),
            proof_use: ProofUse::SatisfyStepUp,
            subject_id: Some(id("subject")),
        }),
        &LoadedState::default(),
    )
    .expect("start step-up attempt");
    store
        .commit_plan(start_step_up_attempt.commit_plan)
        .expect("step-up attempt commit");

    let issue_step_up_challenge = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(132),
            attempt_id: id("step-up-attempt"),
            challenge_id: id("step-up-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("step-up:subject:132"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "step-up-mail-132".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "step-up-attempt",
                "step-up-challenge",
                at(132),
                at(172),
            ),
            method_commit_work: Vec::new(),
        }),
        &store.loaded_for_attempt(&id("step-up-attempt")),
    )
    .expect("issue step-up challenge");
    store
        .commit_plan(issue_step_up_challenge.commit_plan)
        .expect("step-up challenge commit");

    let complete_step_up_challenge = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(133),
            attempt_id: id("step-up-attempt"),
            challenge_id: Some(id("step-up-challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &store.loaded_for_attempt_and_challenge(&id("step-up-attempt"), &id("step-up-challenge")),
    )
    .expect("complete step-up challenge");
    store
        .commit_plan(complete_step_up_challenge.commit_plan)
        .expect("complete step-up challenge commit");

    let complete_step_up = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(135),
            attempt_id: id("step-up-attempt"),
        }),
        &store.loaded_for_session_cookie_and_attempt(
            session_cookie.clone(),
            at(135),
            &id("step-up-attempt"),
        ),
    )
    .expect("complete step-up");
    let step_up_response_effects = store
        .commit_plan(complete_step_up.commit_plan)
        .expect("step-up commit");
    session_cookie = session_cookie_from_response_effects(&step_up_response_effects);
    assert!(
        !store
            .active_proof_attempts
            .contains_key(&id("step-up-attempt"))
    );
    let stepped_up_session = store.sessions.get(&id("session")).expect("session");
    assert_eq!(stepped_up_session.current_secret_version, version(3));
    assert_eq!(stepped_up_session.step_up_expires_at, Some(at(165)));

    let sensitive_request_after_step_up = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(140),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(session_cookie.clone(), at(140)),
    )
    .expect("sensitive request after step-up");
    assert!(matches!(
        sensitive_request_after_step_up.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
            ..
        })
    ));
    let sensitive_response_effects = store
        .commit_plan(sensitive_request_after_step_up.commit_plan)
        .expect("sensitive request commit");
    session_cookie = session_cookie_from_response_effects(&sensitive_response_effects);

    let logout = reduce_command(
        &config(),
        Command::LogoutCurrentSession(LogoutCurrentSession { now: at(150) }),
        &store.loaded_for_session_cookie(session_cookie.clone(), at(150)),
    )
    .expect("logout");
    let logout_response_effects = store
        .commit_plan(logout.commit_plan)
        .expect("logout commit");
    assert!(logout_response_effects.contains(&ResponseEffect::DeleteSessionCookie));
    assert!(logout_response_effects.contains(&ResponseEffect::CycleCsrfToken { session_id: None }));
    assert_eq!(
        store
            .sessions
            .get(&id("session"))
            .expect("session")
            .revoked_at,
        Some(at(150))
    );

    let request_after_logout = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(151),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(session_cookie, at(151)),
    )
    .expect("request after logout");
    assert_eq!(
        request_after_logout.outcome,
        Outcome::NeedsFullAuthentication
    );
    assert_eq!(
        request_after_logout.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );

    let audit_kinds = store
        .audit_events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    for expected_kind in [
        AuditEventKind::ActiveProofAttemptStarted,
        AuditEventKind::OutOfBandChallengeIssued,
        AuditEventKind::ActiveProofSucceeded,
        AuditEventKind::ActiveProofAttemptClosed,
        AuditEventKind::SessionCreated,
        AuditEventKind::SessionRefreshed,
        AuditEventKind::StepUpCompleted,
        AuditEventKind::SessionRevoked,
    ] {
        assert!(
            audit_kinds.contains(&expected_kind),
            "missing audit event: {expected_kind:?}"
        );
    }
    assert_eq!(
        store
            .durable_effects
            .iter()
            .filter(|effect| matches!(effect, DurableEffectCommand::SendOutOfBandMessage(_)))
            .count(),
        2
    );
}

#[test]
fn in_memory_commit_adapter_runs_trusted_device_lifecycle_script() {
    let mut store = InMemoryCommitStore::default();
    let mut login_attempt = active_attempt_with_satisfied_proofs(
        ProofUse::ContributeToFullAuthentication,
        vec![proof(ProofFamily::OutOfBandCode)],
    );
    login_attempt.attempt_id = id("trusted-login-attempt");
    store
        .active_proof_attempts
        .insert(id("trusted-login-attempt"), login_attempt);

    let full_auth_with_trusted_device = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(10),
            attempt_id: id("trusted-login-attempt"),
            fresh_session_id: id("trusted-session-1"),
            trust_device: Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: id("device"),
                display_label: Some("work laptop".to_owned()),
            }),
        }),
        &store.loaded_for_attempt(&id("trusted-login-attempt")),
    )
    .expect("full authentication with trusted device");
    let full_auth_response_effects = store
        .commit_plan(full_auth_with_trusted_device.commit_plan)
        .expect("full authentication with trusted device commit");
    let mut session_cookie = session_cookie_from_response_effects(&full_auth_response_effects);
    let mut trusted_device_cookie =
        trusted_device_cookie_from_response_effects(&full_auth_response_effects);
    let trusted_device = store.trusted_devices.get(&id("device")).expect("device");
    assert_eq!(trusted_device.current_secret_version, version(1));
    assert_eq!(trusted_device.silent_revival_until, at(510));
    assert_eq!(trusted_device.expires_at, at(1_010));
    assert!(store.durable_effects.iter().any(|effect| {
        matches!(
            effect,
            DurableEffectCommand::NotifySecurityEvent(SecurityNotificationCommand {
                kind: SecurityNotificationKind::TrustedDeviceCreated,
                subject_id,
            }) if *subject_id == id("subject")
        )
    }));

    let silent_revival = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(120),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("trusted-session-2")),
        }),
        &store.loaded_for_session_and_trusted_device_cookies(
            session_cookie,
            trusted_device_cookie.clone(),
            at(120),
        ),
    )
    .expect("trusted device silent revival");
    assert!(matches!(
        silent_revival.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            session_id,
            step_up_is_fresh: false,
            ..
        }) if session_id == id("trusted-session-2")
    ));
    let silent_revival_response_effects = store
        .commit_plan(silent_revival.commit_plan)
        .expect("trusted device silent revival commit");
    assert!(!silent_revival_response_effects.contains(&ResponseEffect::DeleteSessionCookie));
    assert!(
        !silent_revival_response_effects
            .contains(&ResponseEffect::CycleCsrfToken { session_id: None })
    );
    let silent_revival_session_cookie =
        session_cookie_from_response_effects(&silent_revival_response_effects);
    assert_eq!(
        silent_revival_session_cookie.session_id,
        id("trusted-session-2")
    );
    trusted_device_cookie =
        trusted_device_cookie_from_response_effects(&silent_revival_response_effects);
    let silently_rotated_device = store.trusted_devices.get(&id("device")).expect("device");
    assert_eq!(silently_rotated_device.current_secret_version, version(2));
    assert_eq!(
        silently_rotated_device.previous_secret_version,
        Some(version(1))
    );
    assert_eq!(
        silently_rotated_device.previous_secret_accept_until,
        Some(at(125))
    );
    assert_eq!(silently_rotated_device.silent_revival_until, at(620));
    assert_eq!(
        store
            .sessions
            .get(&id("trusted-session-2"))
            .expect("session")
            .device_credential_id,
        Some(id("device"))
    );

    let after_silent_revival_window = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(621),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("trusted-session-unused")),
        }),
        &store.loaded_for_trusted_device_cookie(trusted_device_cookie.clone(), at(621)),
    )
    .expect("trusted device after silent revival window");
    assert_eq!(
        after_silent_revival_window.outcome,
        Outcome::NeedsActiveProofFromTrustedDevice {
            device_credential_id: id("device"),
            subject_id: id("subject"),
        }
    );
    assert_eq!(
        after_silent_revival_window.commit_plan,
        CommitPlan::default()
    );

    let start_revival_attempt = reduce_command(
        &config(),
        Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: at(622),
            attempt_id: id("device-revival-attempt"),
            proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
            subject_id: Some(id("subject")),
        }),
        &LoadedState::default(),
    )
    .expect("start trusted-device active proof attempt");
    store
        .commit_plan(start_revival_attempt.commit_plan)
        .expect("trusted-device active proof attempt commit");

    let issue_revival_challenge = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(623),
            attempt_id: id("device-revival-attempt"),
            challenge_id: id("device-revival-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("device-revival:subject:623"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "device-revival-mail-623".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "device-revival-attempt",
                "device-revival-challenge",
                at(623),
                at(663),
            ),
            method_commit_work: Vec::new(),
        }),
        &store.loaded_for_attempt(&id("device-revival-attempt")),
    )
    .expect("issue trusted-device active proof challenge");
    store
        .commit_plan(issue_revival_challenge.commit_plan)
        .expect("trusted-device active proof challenge commit");

    let complete_revival_challenge = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(624),
            attempt_id: id("device-revival-attempt"),
            challenge_id: Some(id("device-revival-challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &store.loaded_for_attempt_and_challenge(
            &id("device-revival-attempt"),
            &id("device-revival-challenge"),
        ),
    )
    .expect("complete trusted-device active proof challenge");
    store
        .commit_plan(complete_revival_challenge.commit_plan)
        .expect("complete trusted-device active proof challenge commit");

    let active_proof_revival = reduce_command(
        &config(),
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(625),
                attempt_id: id("device-revival-attempt"),
                fresh_session_id: id("trusted-session-3"),
            },
        ),
        &store.loaded_for_trusted_device_cookie_and_attempt(
            trusted_device_cookie.clone(),
            at(625),
            &id("device-revival-attempt"),
        ),
    )
    .expect("trusted-device active proof revival");
    assert!(matches!(
        active_proof_revival.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::TrustedDeviceRevivalWithActiveProof,
            session_id,
            step_up_is_fresh: true,
            ..
        }) if session_id == id("trusted-session-3")
    ));
    let active_proof_revival_response_effects = store
        .commit_plan(active_proof_revival.commit_plan)
        .expect("trusted-device active proof revival commit");
    session_cookie = session_cookie_from_response_effects(&active_proof_revival_response_effects);
    trusted_device_cookie =
        trusted_device_cookie_from_response_effects(&active_proof_revival_response_effects);
    let actively_rotated_device = store.trusted_devices.get(&id("device")).expect("device");
    assert_eq!(actively_rotated_device.current_secret_version, version(3));
    assert_eq!(
        actively_rotated_device.previous_secret_version,
        Some(version(2))
    );
    assert_eq!(
        actively_rotated_device.previous_secret_accept_until,
        Some(at(630))
    );
    assert_eq!(actively_rotated_device.silent_revival_until, at(1_010));
    assert_eq!(
        store
            .sessions
            .get(&id("trusted-session-3"))
            .expect("session")
            .step_up_expires_at,
        Some(at(655))
    );
    assert!(
        !store
            .active_proof_attempts
            .contains_key(&id("device-revival-attempt"))
    );

    let revoke_trusted_device = reduce_command(
        &config(),
        Command::RevokeTrustedDevice(RevokeTrustedDevice {
            now: at(630),
            subject_id: id("subject"),
            device_credential_id: id("device"),
            reason: RevocationReason::RemoteRevocation,
        }),
        &store.loaded_for_trusted_device_cookie(trusted_device_cookie.clone(), at(630)),
    )
    .expect("revoke trusted device");
    let revoke_response_effects = store
        .commit_plan(revoke_trusted_device.commit_plan)
        .expect("revoke trusted device commit");
    assert_eq!(
        revoke_response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
    assert_eq!(
        store
            .trusted_devices
            .get(&id("device"))
            .expect("device")
            .revoked_at,
        Some(at(630))
    );

    let request_after_device_revocation = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(631),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("trusted-session-unused-after-revocation")),
        }),
        &store.loaded_for_trusted_device_cookie(trusted_device_cookie, at(631)),
    )
    .expect("request after trusted-device revocation");
    assert_eq!(
        request_after_device_revocation.outcome,
        Outcome::NeedsFullAuthentication
    );
    assert_eq!(
        request_after_device_revocation.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );

    let audit_kinds = store
        .audit_events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    for expected_kind in [
        AuditEventKind::TrustedDeviceCreated,
        AuditEventKind::TrustedDeviceSilentRevival,
        AuditEventKind::TrustedDeviceActiveProofRevival,
        AuditEventKind::TrustedDeviceRotated,
        AuditEventKind::TrustedDeviceRevoked,
    ] {
        assert!(
            audit_kinds.contains(&expected_kind),
            "missing audit event: {expected_kind:?}"
        );
    }
    assert_eq!(
        store
            .durable_effects
            .iter()
            .filter(|effect| matches!(effect, DurableEffectCommand::SendOutOfBandMessage(_)))
            .count(),
        1
    );
    assert_eq!(session_cookie.session_id, id("trusted-session-3"));
}
