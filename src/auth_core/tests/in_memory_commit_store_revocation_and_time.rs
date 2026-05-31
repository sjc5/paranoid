use super::*;

#[test]
fn in_memory_commit_adapter_applies_subject_wide_revocation_to_live_session_and_device() {
    let mut store = InMemoryCommitStore::default();
    store.sessions.insert(id("session"), session_record(200));
    store
        .trusted_devices
        .insert(id("device"), trusted_device_record(500, 1_000));
    let session_cookie = session_cookie(200);
    let trusted_device_cookie = trusted_device_cookie(500, 1_000);

    let subject_revocation = reduce_command(
        &config(),
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(50),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &store.loaded_for_session_and_trusted_device_cookies(
            session_cookie.clone(),
            trusted_device_cookie.clone(),
            at(50),
        ),
    )
    .expect("subject-wide revocation");
    let revocation_response_effects = store
        .commit_plan(subject_revocation.commit_plan)
        .expect("subject-wide revocation commit");
    assert_eq!(
        revocation_response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
            ResponseEffect::DeleteTrustedDeviceCookie,
        ]
    );

    let request_after_subject_revocation = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(51),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("unused-session-after-subject-revocation")),
        }),
        &store.loaded_for_session_and_trusted_device_cookies(
            session_cookie,
            trusted_device_cookie,
            at(51),
        ),
    )
    .expect("request after subject-wide revocation");
    assert_eq!(
        request_after_subject_revocation.outcome,
        Outcome::NeedsFullAuthentication
    );
    assert_eq!(
        request_after_subject_revocation
            .commit_plan
            .response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
            ResponseEffect::DeleteTrustedDeviceCookie,
        ]
    );
    assert!(
        request_after_subject_revocation
            .commit_plan
            .mutations
            .is_empty()
    );
}

#[test]
fn in_memory_commit_adapter_enforces_time_bounded_preconditions() {
    let mut session_store = InMemoryCommitStore::default();
    session_store
        .sessions
        .insert(id("session"), session_record(200));
    let session_plan = reduced_plan(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &session_store.loaded_for_session_cookie(session_cookie(200), at(50)),
    );
    session_store
        .sessions
        .get_mut(&id("session"))
        .expect("session")
        .expires_at = at(50);
    let session_store_before_commit = session_store.clone();
    let session_error = session_store
        .commit_plan(session_plan)
        .expect_err("session that expired before commit must fail its precondition");
    assert_eq!(
        session_error,
        InMemoryCommitError::PreconditionFailed("session still matches")
    );
    assert_eq!(session_store, session_store_before_commit);

    let mut device_store = InMemoryCommitStore::default();
    device_store
        .trusted_devices
        .insert(id("device"), trusted_device_record(500, 1_000));
    let trusted_device_plan = reduced_plan(
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("new-session")),
        }),
        &device_store.loaded_for_trusted_device_cookie(trusted_device_cookie(500, 1_000), at(100)),
    );
    device_store
        .trusted_devices
        .get_mut(&id("device"))
        .expect("trusted device")
        .expires_at = at(100);
    let device_store_before_commit = device_store.clone();
    let device_error = device_store
        .commit_plan(trusted_device_plan)
        .expect_err("trusted device that expired before commit must fail its precondition");
    assert_eq!(
        device_error,
        InMemoryCommitError::PreconditionFailed("trusted device still matches")
    );
    assert_eq!(device_store, device_store_before_commit);
    assert!(!device_store.sessions.contains_key(&id("new-session")));

    let mut attempt_store = InMemoryCommitStore::default();
    attempt_store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    let challenge_issue_plan = reduced_plan(
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:subject:30"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-30".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie(),
            method_commit_work: Vec::new(),
        }),
        &attempt_store.loaded_for_attempt(&id("attempt")),
    );
    attempt_store
        .active_proof_attempts
        .get_mut(&id("attempt"))
        .expect("attempt")
        .expires_at = at(30);
    let attempt_store_before_commit = attempt_store.clone();
    let attempt_error = attempt_store
        .commit_plan(challenge_issue_plan)
        .expect_err("attempt that expired before commit must fail its precondition");
    assert_eq!(
        attempt_error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert_eq!(attempt_store, attempt_store_before_commit);
    assert!(attempt_store.active_proof_challenges.is_empty());
    assert!(attempt_store.durable_effects.is_empty());

    let mut challenge_store = InMemoryCommitStore::default();
    challenge_store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    challenge_store
        .active_proof_challenges
        .insert(id("challenge"), out_of_band_challenge());
    let challenge_completion_plan = reduced_plan(
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
        &challenge_store.loaded_for_attempt_and_challenge(&id("attempt"), &id("challenge")),
    );
    challenge_store
        .active_proof_challenges
        .get_mut(&id("challenge"))
        .expect("challenge")
        .expires_at = at(40);
    let challenge_store_before_commit = challenge_store.clone();
    let challenge_error = challenge_store
        .commit_plan(challenge_completion_plan)
        .expect_err("challenge that expired before commit must fail its precondition");
    assert_eq!(
        challenge_error,
        InMemoryCommitError::PreconditionFailed("active proof challenge still open")
    );
    assert_eq!(challenge_store, challenge_store_before_commit);
    assert!(
        challenge_store
            .active_proof_attempts
            .get(&id("attempt"))
            .expect("attempt")
            .satisfied_proofs
            .is_empty()
    );
}

#[test]
fn in_memory_commit_adapter_ignores_expired_out_of_band_dedupe_challenges() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    let mut expired_challenge = out_of_band_challenge();
    expired_challenge.challenge_id = id("expired-challenge");
    expired_challenge.expires_at = at(20);
    store
        .active_proof_challenges
        .insert(id("expired-challenge"), expired_challenge);

    let issue_replacement_challenge = reduced_plan(
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("replacement-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "replacement-mail-30".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "attempt",
                "replacement-challenge",
                at(30),
                at(70),
            ),
            method_commit_work: Vec::new(),
        }),
        &with_no_subject_revocations(store.loaded_for_attempt(&id("attempt"))),
    );

    assert_only_issued_active_proof_challenge_cookie(
        store
            .commit_plan(issue_replacement_challenge)
            .expect("expired dedupe challenge must not block replacement"),
        id("replacement-challenge"),
    );
    assert!(
        store
            .active_proof_challenges
            .contains_key(&id("expired-challenge"))
    );
    assert!(
        store
            .active_proof_challenges
            .contains_key(&id("replacement-challenge"))
    );
    assert_eq!(
        store
            .durable_effects
            .iter()
            .filter(|effect| matches!(effect, DurableEffectCommand::SendOutOfBandMessage(_)))
            .count(),
        1
    );
}
