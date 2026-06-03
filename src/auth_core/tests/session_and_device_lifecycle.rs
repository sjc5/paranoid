use super::*;

#[test]
fn completing_step_up_rotates_session_secret_and_marks_freshness() {
    let transition = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session_and_attempt(
            200,
            ProofUse::SatisfyStepUp,
            vec![proof(ProofFamily::SharedSecretOtp)],
        ),
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::StepUp,
            step_up_is_fresh: true,
            ..
        })
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::DeleteActiveProofAttempt { attempt_id },
            Mutation::RecordStepUp {
                new_secret_version,
                step_up_expires_at,
                ..
            },
        ] if *attempt_id == id("attempt")
            && *new_secret_version == version(4)
            && *step_up_expires_at == at(80)
    ));
    assert_eq!(
        transition.commit_plan.fresh_credential_secrets,
        vec![fresh_session_secret("session", 4)]
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::ActiveProofAttemptClosed)
    );
}

#[test]
fn completing_step_up_without_authoritative_session_clears_session_cookie() {
    let transition = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &LoadedState {
            session_cookie: Some(session_cookie(200)),
            ..LoadedState::default()
        },
    )
    .expect("missing session during step-up should clear local session state");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ],
    );
}

#[test]
fn trusted_device_cannot_satisfy_step_up_because_it_is_passive() {
    let error = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session_and_attempt(
            200,
            ProofUse::SatisfyStepUp,
            vec![proof(ProofFamily::TrustedDevice)],
        ),
    )
    .expect_err("trusted device must not satisfy step-up");

    assert_eq!(
        error,
        Error::ProofFamilyCannotSatisfyUse {
            family: ProofFamily::TrustedDevice,
            proof_use: ProofUse::SatisfyStepUp,
        }
    );
}

#[test]
fn trusted_device_silent_revival_creates_session_and_rotates_device() {
    let loaded = loaded_trusted_device(500, 1_000);

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

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            step_up_is_fresh: false,
            ..
        })
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::CreateSession(session),
            Mutation::RotateTrustedDeviceCredential {
                new_secret_version,
                previous_secret_version,
                last_used_at,
                silent_revival_until,
                expires_at,
                ..
            },
        ] if session.session_id == id("new-session")
            && *new_secret_version == version(9)
            && *previous_secret_version == version(8)
            && *last_used_at == at(100)
            && *silent_revival_until == at(600)
            && *expires_at == at(1_000)
    ));
    assert_eq!(
        transition.commit_plan.fresh_credential_secrets,
        vec![
            fresh_session_secret("new-session", 1),
            fresh_trusted_device_secret("device", 9),
        ]
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::TrustedDeviceSilentRevival)
    );
}

#[test]
fn trusted_device_silent_revival_caps_revival_deadline_at_device_expiration() {
    let mut config = config();
    config.trusted_device_silent_revival_lifetime = DurationSeconds::new(1_000);

    let transition = reduce_command(
        &config,
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded_trusted_device(500, 550),
    )
    .expect("transition");

    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::CreateSession(_),
            Mutation::RotateTrustedDeviceCredential {
                silent_revival_until,
                expires_at,
                ..
            },
        ] if *silent_revival_until == at(550) && *expires_at == at(550)
    ));
}

#[test]
fn previous_trusted_device_secret_within_grace_can_silently_revive_session() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded
        .trusted_device_cookie
        .as_mut()
        .expect("trusted-device cookie")
        .secret_version = version(7);
    let device_record = loaded
        .trusted_device_record
        .as_mut()
        .expect("trusted-device record");
    device_record.previous_secret_version = Some(version(7));
    device_record.previous_secret_accept_until = Some(at(105));
    loaded.trusted_device_secret_match = Some(loaded_trusted_device_secret_match(
        StoredSecretMatch::PreviousWithinGrace,
    ));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect("previous trusted-device secret should be accepted inside grace");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            ..
        })
    ));
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [
            Precondition::TrustedDeviceBelongsToSubject {
                device_credential_id,
                subject_id,
            },
            Precondition::TrustedDeviceStillMatches {
                device_credential_id: matched_device_credential_id,
                current_secret_version,
                ..
            },
        ] if *device_credential_id == id("device")
            && *subject_id == id("subject")
            && *matched_device_credential_id == id("device")
            && *current_secret_version == version(8)
    ));
    assert!(transition.commit_plan.response_effects.iter().any(
        |effect| matches!(effect, ResponseEffect::IssueTrustedDeviceCookie(cookie)
                if cookie.secret_version == version(9))
    ));
}

#[test]
fn trusted_device_previous_secret_reported_within_grace_after_deadline_is_rejected() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded
        .trusted_device_cookie
        .as_mut()
        .expect("trusted-device cookie")
        .secret_version = version(7);
    let device_record = loaded
        .trusted_device_record
        .as_mut()
        .expect("trusted-device record");
    device_record.previous_secret_version = Some(version(7));
    device_record.previous_secret_accept_until = Some(at(105));
    loaded.trusted_device_secret_match = Some(loaded_trusted_device_secret_match(
        StoredSecretMatch::PreviousWithinGrace,
    ));

    let error = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(105),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect_err("within-grace classification must match the device deadline");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "trusted-device previous secret reported within grace after grace deadline",
        )
    );
}

#[test]
fn previous_after_grace_trusted_device_secret_triggers_device_tripwire() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded
        .trusted_device_cookie
        .as_mut()
        .expect("trusted-device cookie")
        .secret_version = version(7);
    let device_record = loaded
        .trusted_device_record
        .as_mut()
        .expect("trusted-device record");
    device_record.previous_secret_version = Some(version(7));
    device_record.previous_secret_accept_until = Some(at(105));
    loaded.trusted_device_secret_match = Some(loaded_trusted_device_secret_match(
        StoredSecretMatch::PreviousAfterGrace,
    ));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(105),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect("previous-after-grace device secret is a mismatch, not a reducer error");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::CredentialMismatch
                && event.device_credential_id == Some(id("device")))
    );
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
    assert!(
        transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(
                mutation,
                Mutation::RevokeTrustedDeviceCredential {
                    device_credential_id,
                    reason: RevocationReason::Tripwire,
                    revoked_at,
                } if *device_credential_id == id("device") && *revoked_at == at(105)
            ))
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::TrustedDeviceRevoked
                && event.device_credential_id == Some(id("device")))
    );
}

#[test]
fn unknown_trusted_device_secret_triggers_device_tripwire() {
    let mut loaded = loaded_trusted_device(500, 1_000);
    loaded.trusted_device_secret_match = Some(loaded_trusted_device_secret_match(
        StoredSecretMatch::Unknown,
    ));

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &loaded,
    )
    .expect("unknown trusted-device secret is a mismatch, not a reducer error");

    assert_eq!(transition.outcome, Outcome::NeedsFullAuthentication);
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::CredentialMismatch
                && event.device_credential_id == Some(id("device")))
    );
    assert_eq!(
        transition.commit_plan.response_effects,
        vec![ResponseEffect::DeleteTrustedDeviceCookie]
    );
    assert!(
        transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(
                mutation,
                Mutation::RevokeTrustedDeviceCredential {
                    device_credential_id,
                    reason: RevocationReason::Tripwire,
                    revoked_at,
                } if *device_credential_id == id("device") && *revoked_at == at(100)
            ))
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::TrustedDeviceRevoked
                && event.device_credential_id == Some(id("device")))
    );
}

#[test]
fn trusted_device_past_silent_revival_requires_active_proof() {
    let loaded = loaded_trusted_device(500, 1_000);

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(600),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("unused-session")),
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::NeedsActiveProofFromTrustedDevice { .. }
    ));
    assert!(transition.commit_plan.mutations.is_empty());
}

#[test]
fn trusted_device_at_silent_revival_deadline_requires_active_proof() {
    let loaded = loaded_trusted_device(500, 1_000);

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(500),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("unused-session")),
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::NeedsActiveProofFromTrustedDevice { .. }
    ));
    assert!(transition.commit_plan.mutations.is_empty());
}

#[test]
fn trusted_device_active_proof_completion_creates_fresh_session_and_resets_revival() {
    let transition = reduce_command(
        &config(),
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
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::TrustedDeviceRevivalWithActiveProof,
            step_up_is_fresh: true,
            ..
        })
    ));
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [
            Precondition::TrustedDeviceBelongsToSubject {
                device_credential_id,
                subject_id,
            },
            Precondition::TrustedDeviceStillMatches {
                device_credential_id: matched_device_credential_id,
                current_secret_version,
                ..
            },
            Precondition::ActiveProofAttemptStillOpen { attempt_id, .. },
        ] if *device_credential_id == id("device")
            && *subject_id == id("subject")
            && *matched_device_credential_id == id("device")
            && *current_secret_version == version(8)
            && *attempt_id == id("attempt")
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::DeleteActiveProofAttempt { attempt_id },
            Mutation::CreateSession(session),
            Mutation::RotateTrustedDeviceCredential {
                device_credential_id,
                new_secret_version,
                previous_secret_version,
                previous_secret_accept_until,
                last_used_at,
                silent_revival_until,
                expires_at,
            },
        ] if *attempt_id == id("attempt")
            && session.session_id == id("new-session")
            && session.step_up_expires_at == Some(at(630))
            && *device_credential_id == id("device")
            && *new_secret_version == version(9)
            && *previous_secret_version == version(8)
            && *previous_secret_accept_until == at(605)
            && *last_used_at == at(600)
            && *silent_revival_until == at(1_100)
            && *expires_at == at(2_000)
    ));
    assert_eq!(
        transition.commit_plan.fresh_credential_secrets,
        vec![
            fresh_session_secret("new-session", 1),
            fresh_trusted_device_secret("device", 9),
        ]
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::TrustedDeviceActiveProofRevival)
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::ActiveProofAttemptClosed)
    );
    assert!(transition.commit_plan.response_effects.iter().any(
        |effect| matches!(effect, ResponseEffect::IssueSessionCookie(cookie)
                if cookie.session_id == id("new-session")
                    && cookie.step_up_valid_until == Some(at(630)))
    ));
    assert!(transition.commit_plan.response_effects.iter().any(
        |effect| matches!(effect, ResponseEffect::IssueTrustedDeviceCookie(cookie)
                if cookie.device_credential_id == id("device")
                    && cookie.secret_version == version(9)
                    && cookie.silent_revival_fast_fail_until == at(1_100))
    ));
}

#[test]
fn trusted_device_active_proof_completion_rejects_passive_device_proof() {
    let error = reduce_command(
        &config(),
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &loaded_trusted_device_and_attempt(
            500,
            1_000,
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            vec![proof(ProofFamily::TrustedDevice)],
        ),
    )
    .expect_err("trusted device alone must not satisfy its own active proof");

    assert_eq!(
        error,
        Error::ProofFamilyCannotSatisfyUse {
            family: ProofFamily::TrustedDevice,
            proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
        }
    );
}

#[test]
fn trusted_device_active_proof_completion_allows_totp_because_device_fixed_subject_context() {
    let transition = reduce_command(
        &config(),
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
            vec![proof(ProofFamily::SharedSecretOtp)],
        ),
    )
    .expect("trusted device plus TOTP should satisfy active revival");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::TrustedDeviceRevivalWithActiveProof,
            step_up_is_fresh: true,
            ..
        })
    ));
}

#[test]
fn trusted_device_active_proof_completion_requires_same_subject() {
    let mut loaded = loaded_trusted_device_and_attempt(
        500,
        1_000,
        ProofUse::ReviveTrustedDeviceWithActiveProof,
        vec![proof(ProofFamily::SharedSecretOtp)],
    );
    loaded
        .active_proof_attempt_record
        .as_mut()
        .expect("loaded attempt")
        .subject_id = Some(id("other-subject"));
    loaded
        .subject_revocations
        .push_loaded(id("other-subject"), None)
        .expect("loaded other subject revocations");

    let error = reduce_command(
        &config(),
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &loaded,
    )
    .expect_err("active proof must belong to the trusted-device subject");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "active-proof attempt subject differs from required subject",
        )
    );
}

#[test]
fn full_authentication_requires_a_core_tracked_attempt() {
    let error = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &LoadedState::default(),
    )
    .expect_err("full authentication must consume a loaded active-proof attempt");

    assert_eq!(
        error,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );
}

#[test]
fn full_authentication_requires_attempt_bound_to_final_subject() {
    let mut attempt = active_attempt_with_satisfied_proofs(
        ProofUse::ContributeToFullAuthentication,
        vec![proof(ProofFamily::OutOfBandCode)],
    );
    attempt.subject_id = None;

    let error = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &LoadedState {
            active_proof_attempt_record: Some(attempt),
            ..LoadedState::default()
        },
    )
    .expect_err("full authentication must consume a subject-bound attempt");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "full authentication completion requires a subject-bound attempt",
        )
    );
}

#[test]
fn full_authentication_rejects_totp_without_a_full_authentication_anchor() {
    let error = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::SharedSecretOtp)],
        ),
    )
    .expect_err("TOTP alone must not complete full authentication");

    assert_eq!(
        error,
        Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::ContributeToFullAuthentication,
        }
    );
}

#[test]
fn full_authentication_can_atomically_create_session_and_trusted_device() {
    let transition = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: id("device"),
                display_label: Some("laptop".to_owned()),
            }),
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    )
    .expect("transition");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::FullAuthentication,
            step_up_is_fresh: true,
            ..
        })
    ));
    assert_eq!(transition.commit_plan.mutations.len(), 3);
    assert_eq!(
        transition.commit_plan.fresh_credential_secrets,
        vec![
            fresh_session_secret("session", 1),
            fresh_trusted_device_secret("device", 1),
        ]
    );
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(|event| event.kind == AuditEventKind::ActiveProofAttemptClosed)
    );
    assert!(
        transition
            .commit_plan
            .durable_effects
            .iter()
            .any(|effect| matches!(
                effect,
                DurableEffectCommand::NotifySecurityEvent(notification)
                    if notification.kind == SecurityNotificationKind::TrustedDeviceCreated
                        && notification.subject_id == id("subject")
            ))
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .iter()
            .any(|effect| matches!(effect, ResponseEffect::IssueTrustedDeviceCookie(_)))
    );
}

#[test]
fn core_security_notifications_are_limited_to_trusted_device_creation() {
    let full_authentication_without_trusted_device = reduce_command(
        &config(),
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
    )
    .expect("full authentication");
    assert!(
        security_notification_kinds(&full_authentication_without_trusted_device.commit_plan)
            .is_empty()
    );

    let session_refresh = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded_session(100),
    )
    .expect("session refresh");
    assert!(security_notification_kinds(&session_refresh.commit_plan).is_empty());

    let step_up = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session_and_attempt(
            200,
            ProofUse::SatisfyStepUp,
            vec![proof(ProofFamily::SharedSecretOtp)],
        ),
    )
    .expect("step-up");
    assert!(security_notification_kinds(&step_up.commit_plan).is_empty());

    let subject_revocation = reduce_command(
        &config(),
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(50),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &LoadedState::default(),
    )
    .expect("subject revocation");
    assert!(security_notification_kinds(&subject_revocation.commit_plan).is_empty());

    let full_authentication_with_trusted_device = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: id("device"),
                display_label: Some("laptop".to_owned()),
            }),
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    )
    .expect("full authentication with trusted device");

    assert_eq!(
        security_notification_kinds(&full_authentication_with_trusted_device.commit_plan),
        vec![SecurityNotificationKind::TrustedDeviceCreated]
    );
}

#[test]
fn full_authentication_caps_trusted_device_revival_deadline_at_device_expiration() {
    let mut config = config();
    config.trusted_device_silent_revival_lifetime = DurationSeconds::new(1_000);
    config.trusted_device_credential_lifetime = DurationSeconds::new(100);

    let transition = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: id("device"),
                display_label: Some("laptop".to_owned()),
            }),
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    )
    .expect("transition");

    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::DeleteActiveProofAttempt { .. },
            Mutation::CreateSession(_),
            Mutation::CreateTrustedDeviceCredential(device),
        ] if device.expires_at == at(120) && device.silent_revival_until == at(120)
    ));
}

#[test]
fn full_authentication_requires_a_core_accepted_active_proof_family() {
    let error = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::TrustedDevice)],
        ),
    )
    .expect_err("trusted device alone cannot complete full authentication");

    assert_eq!(
        error,
        Error::ProofFamilyCannotSatisfyUse {
            family: ProofFamily::TrustedDevice,
            proof_use: ProofUse::ContributeToFullAuthentication,
        }
    );
}
