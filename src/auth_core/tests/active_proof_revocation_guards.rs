use super::*;

#[test]
fn subject_wide_revocation_invalidates_subject_bound_active_proof_attempts() {
    let loaded = LoadedState {
        subject_revocations: loaded_subject_revocations(20),
        active_proof_attempt_record: Some(active_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        )),
        active_proof_challenge_record: Some(out_of_band_challenge()),
        ..LoadedState::default()
    };

    let issue_challenge_error = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-idempotency-key".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie(),
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("revoked subject must not receive new challenge work");
    assert_eq!(issue_challenge_error, Error::ActiveProofAttemptNotOpen);

    let resend_challenge_error = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("revoked subject must not resend challenge work");
    assert_eq!(resend_challenge_error, Error::ActiveProofAttemptNotOpen);

    let complete_challenge_error = reduce_command(
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
        &loaded,
    )
    .expect_err("revoked subject must not complete active proof");
    assert_eq!(complete_challenge_error, Error::ActiveProofAttemptNotOpen);

    let record_failure_error = reduce_command(
        &config(),
        Command::RecordActiveProofFailure(RecordActiveProofFailure {
            now: at(40),
            attempt_id: id("attempt"),
            method: proof_method(ProofFamily::SharedSecretOtp),
            weak_proof_gate: verified_proof_of_work_gate(),
        }),
        &loaded,
    )
    .expect_err("revoked subject must not accumulate weak proof failures");
    assert_eq!(record_failure_error, Error::ActiveProofAttemptNotOpen);

    let complete_full_authentication_error = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded,
    )
    .expect_err("revoked subject must not consume old proof stack");
    assert_eq!(
        complete_full_authentication_error,
        Error::ActiveProofAttemptNotOpen
    );
}

#[test]
fn subject_wide_revocation_invalidates_unbound_attempt_when_proof_resolves_revoked_subject() {
    let loaded = LoadedState {
        subject_revocations: loaded_subject_revocations(20),
        active_proof_attempt_record: Some(unbound_active_attempt(
            ProofUse::ContributeToFullAuthentication,
        )),
        ..LoadedState::default()
    };

    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::MessageSignature, Some(id("subject"))),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: verified_proof_of_work_gate(),
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("unbound attempt cannot bind to a revoked subject");

    assert_eq!(error, Error::ActiveProofAttemptNotOpen);
}

#[test]
fn active_proof_attempt_commit_guard_rejects_concurrent_subject_wide_revocation() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );

    let issue_challenge = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-idempotency-key".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie(),
            method_commit_work: Vec::new(),
        }),
        &with_no_subject_revocations(store.loaded_for_attempt(&id("attempt"))),
    )
    .expect("challenge issue plan");

    let revoke_subject = reduce_command(
        &config(),
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(40),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &LoadedState::default(),
    )
    .expect("subject revocation");
    store
        .commit_plan(revoke_subject.commit_plan)
        .expect("subject revocation commit");

    let error = store
        .commit_plan(issue_challenge.commit_plan)
        .expect_err("stale challenge issue must fail after concurrent subject revocation");
    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert!(store.active_proof_challenges.is_empty());
}

#[test]
fn out_of_band_resend_commit_guard_rejects_concurrent_subject_wide_revocation() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    store
        .active_proof_challenges
        .insert(id("challenge"), out_of_band_challenge());

    let resend_challenge = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &store.loaded_for_attempt_and_challenge(&id("attempt"), &id("challenge")),
    )
    .expect("challenge resend plan");

    let revoke_subject = reduce_command(
        &config(),
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(40),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &LoadedState::default(),
    )
    .expect("subject revocation");
    store
        .commit_plan(revoke_subject.commit_plan)
        .expect("subject revocation commit");

    let error = store
        .commit_plan(resend_challenge.commit_plan)
        .expect_err("stale challenge resend must fail after concurrent subject revocation");
    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert!(store.durable_effects.is_empty());
}

#[test]
fn unbound_active_proof_completion_guard_rejects_concurrent_subject_revocation_after_binding() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        unbound_active_attempt(ProofUse::ContributeToFullAuthentication),
    );

    let complete_proof = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::MessageSignature, Some(id("subject"))),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: verified_proof_of_work_gate(),
            method_commit_work: Vec::new(),
        }),
        &with_no_subject_revocations(store.loaded_for_attempt(&id("attempt"))),
    )
    .expect("proof completion plan");

    let revoke_subject = reduce_command(
        &config(),
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(40),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &LoadedState::default(),
    )
    .expect("subject revocation");
    store
        .commit_plan(revoke_subject.commit_plan)
        .expect("subject revocation commit");

    let error = store
        .commit_plan(complete_proof.commit_plan)
        .expect_err("stale proof completion must fail after concurrent subject revocation");
    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert!(
        store
            .active_proof_attempts
            .get(&id("attempt"))
            .expect("attempt")
            .satisfied_proofs
            .is_empty()
    );
}
