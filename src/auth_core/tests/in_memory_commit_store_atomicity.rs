use super::*;

#[test]
fn in_memory_commit_adapter_accepts_stale_session_cookie_inside_race_grace_only() {
    let mut store = InMemoryCommitStore::default();
    store.sessions.insert(id("session"), session_record(100));
    let stale_after_refresh_cookie = session_cookie(100);

    let refresh = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(stale_after_refresh_cookie.clone(), at(85)),
    )
    .expect("refresh transition");
    let refresh_response_effects = store
        .commit_plan(refresh.commit_plan)
        .expect("refresh commit");
    let refreshed_cookie = session_cookie_from_response_effects(&refresh_response_effects);
    assert_eq!(refreshed_cookie.secret_version, version(4));
    assert_eq!(
        store
            .sessions
            .get(&id("session"))
            .expect("session")
            .previous_secret_accept_until,
        Some(at(90))
    );

    let stale_cookie_inside_grace = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(86),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(stale_after_refresh_cookie.clone(), at(86)),
    )
    .expect("stale cookie inside race grace");
    assert!(matches!(
        stale_cookie_inside_grace.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            ..
        })
    ));
    let stale_cookie_response_effects = store
        .commit_plan(stale_cookie_inside_grace.commit_plan)
        .expect("stale-cookie commit");
    assert!(
        !stale_cookie_response_effects.contains(&ResponseEffect::DeleteSessionCookie),
        "inside-grace stale cookies must be accepted, not cleared"
    );
    assert!(
        stale_cookie_response_effects
            .iter()
            .all(|effect| !matches!(effect, ResponseEffect::IssueSessionCookie(_))),
        "a MAC-only adapter cannot recover and reissue the already-current plaintext secret"
    );

    let stale_cookie_after_grace = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(90),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(stale_after_refresh_cookie, at(90)),
    )
    .expect("stale cookie after race grace");
    assert_eq!(
        stale_cookie_after_grace.outcome,
        Outcome::NeedsFullAuthentication
    );
    let reject_response_effects = store
        .commit_plan(stale_cookie_after_grace.commit_plan)
        .expect("stale-cookie rejection commit");
    assert_eq!(
        reject_response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
    assert_eq!(
        store
            .sessions
            .get(&id("session"))
            .expect("session")
            .revoked_at,
        Some(at(90)),
        "stale cookies after grace must tripwire-revoke the live session"
    );
}

#[test]
fn in_memory_commit_adapter_rejects_second_concurrent_session_refresh_atomically() {
    let mut store = InMemoryCommitStore::default();
    store.sessions.insert(id("session"), session_record(100));
    let request_cookie = session_cookie(100);
    let loaded_before_refresh = store.loaded_for_session_cookie(request_cookie, at(85));

    let first_refresh = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded_before_refresh,
    )
    .expect("first refresh");
    let second_refresh = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &loaded_before_refresh,
    )
    .expect("second refresh planned from same snapshot");

    store
        .commit_plan(first_refresh.commit_plan)
        .expect("first refresh commit");
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(second_refresh.commit_plan)
        .expect_err("second concurrent refresh must fail");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("session still matches")
    );
    assert_eq!(store, after_first_commit);
}

#[test]
fn in_memory_commit_adapter_rejects_second_concurrent_trusted_device_rotation_atomically() {
    let mut store = InMemoryCommitStore::default();
    store
        .trusted_devices
        .insert(id("device"), trusted_device_record(500, 1_000));
    let request_cookie = trusted_device_cookie(500, 1_000);
    let loaded_before_rotation = store.loaded_for_trusted_device_cookie(request_cookie, at(100));

    let first_revival = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("first-session")),
        }),
        &loaded_before_rotation,
    )
    .expect("first trusted-device revival");
    let second_revival = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(100),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: Some(id("second-session")),
        }),
        &loaded_before_rotation,
    )
    .expect("second trusted-device revival planned from same snapshot");

    let first_response_effects = store
        .commit_plan(first_revival.commit_plan)
        .expect("first trusted-device revival commit");
    assert!(first_response_effects.iter().any(
        |effect| matches!(effect, ResponseEffect::IssueSessionCookie(cookie)
                if cookie.session_id == id("first-session"))
    ));
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(second_revival.commit_plan)
        .expect_err("second concurrent trusted-device rotation must fail");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("trusted device still matches")
    );
    assert_eq!(store, after_first_commit);
    assert!(
        !store.sessions.contains_key(&id("second-session")),
        "failed concurrent revival must not create its fresh session"
    );
}

#[test]
fn in_memory_commit_adapter_rejects_replayed_active_proof_challenge_completion_atomically() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    store
        .active_proof_challenges
        .insert(id("challenge"), out_of_band_challenge());
    let loaded_before_completion =
        store.loaded_for_attempt_and_challenge(&id("attempt"), &id("challenge"));

    let first_completion = reduce_command(
        &config(),
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
        &loaded_before_completion,
    )
    .expect("first challenge completion");
    let replayed_completion = reduce_command(
        &config(),
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
        &loaded_before_completion,
    )
    .expect("replayed challenge completion planned from same snapshot");

    assert_only_deleted_active_proof_challenge_cookie(
        store
            .commit_plan(first_completion.commit_plan)
            .expect("first completion commit"),
    );
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(replayed_completion.commit_plan)
        .expect_err("replayed challenge completion must fail");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof challenge still open")
    );
    assert_eq!(store, after_first_commit);
    assert_eq!(
        store
            .active_proof_attempts
            .get(&id("attempt"))
            .expect("attempt")
            .satisfied_proofs
            .len(),
        1
    );
}

#[test]
fn in_memory_commit_adapter_rejects_duplicate_out_of_band_challenge_issue_atomically() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    let loaded_before_issue = store.loaded_for_attempt(&id("attempt"));

    let first_issue = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(20),
            attempt_id: id("attempt"),
            challenge_id: id("first-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:subject:20"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-20-first".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "attempt",
                "first-challenge",
                at(20),
                at(60),
            ),
            method_commit_work: Vec::new(),
        }),
        &loaded_before_issue,
    )
    .expect("first challenge issue");
    let duplicate_issue = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(20),
            attempt_id: id("attempt"),
            challenge_id: id("duplicate-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:subject:20"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-20-duplicate".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "attempt",
                "duplicate-challenge",
                at(20),
                at(60),
            ),
            method_commit_work: Vec::new(),
        }),
        &loaded_before_issue,
    )
    .expect("duplicate challenge issue planned from same snapshot");

    assert_only_issued_active_proof_challenge_cookie(
        store
            .commit_plan(first_issue.commit_plan)
            .expect("first challenge issue commit"),
        id("first-challenge"),
    );
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(duplicate_issue.commit_plan)
        .expect_err("duplicate challenge issue must fail");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("no open out of band challenge for dedupe key")
    );
    assert_eq!(store, after_first_commit);
    assert_eq!(store.active_proof_challenges.len(), 1);
    assert_eq!(
        store
            .durable_effects
            .iter()
            .filter(|effect| matches!(effect, DurableEffectCommand::SendOutOfBandMessage(_)))
            .count(),
        1
    );
}

#[test]
fn in_memory_commit_adapter_rejects_second_concurrent_out_of_band_resend_atomically() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    store
        .active_proof_challenges
        .insert(id("challenge"), out_of_band_challenge());
    let loaded_before_resend =
        store.loaded_for_attempt_and_challenge(&id("attempt"), &id("challenge"));

    let first_resend = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded_before_resend,
    )
    .expect("first resend");
    let second_resend = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-2".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded_before_resend,
    )
    .expect("second resend planned from same snapshot");

    assert!(
        store
            .commit_plan(first_resend.commit_plan)
            .expect("first resend commit")
            .is_empty()
    );
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(second_resend.commit_plan)
        .expect_err("second concurrent resend must fail");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("out of band challenge resend still allowed")
    );
    assert_eq!(store, after_first_commit);
    assert_eq!(
        store
            .active_proof_challenges
            .get(&id("challenge"))
            .expect("challenge")
            .resend_count,
        1
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
