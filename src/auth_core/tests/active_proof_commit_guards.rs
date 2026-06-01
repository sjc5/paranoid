use super::*;

#[test]
fn active_proof_attempt_commit_guard_rejects_concurrent_proof_stack_update() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    let loaded_before_proof_completion = store.loaded_for_attempt(&id("attempt"));

    let password_completion = reduce_command(
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
        &loaded_before_proof_completion,
    )
    .expect("password proof completion");
    let totp_completion = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::SharedSecretOtp, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: verified_proof_of_work_gate(),
            method_commit_work: Vec::new(),
        }),
        &loaded_before_proof_completion,
    )
    .expect("totp proof completion from same snapshot");

    store
        .commit_plan(password_completion.commit_plan)
        .expect("password proof commit");
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(totp_completion.commit_plan)
        .expect_err("stale proof completion must fail after proof stack changed");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert_eq!(store, after_first_commit);
    assert_eq!(
        store
            .active_proof_attempts
            .get(&id("attempt"))
            .expect("attempt")
            .satisfied_proofs,
        vec![satisfied_proof(proof(ProofFamily::MessageSignature))]
    );
}

#[test]
fn active_proof_attempt_commit_guard_rejects_concurrent_weak_failure_update() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    let loaded_before_failure = store.loaded_for_attempt(&id("attempt"));

    let first_failure = reduce_command(
        &config(),
        Command::RecordActiveProofFailure(RecordActiveProofFailure {
            now: at(40),
            attempt_id: id("attempt"),
            method: proof_method(ProofFamily::SharedSecretOtp),
            weak_proof_gate: verified_proof_of_work_gate(),
        }),
        &loaded_before_failure,
    )
    .expect("first weak proof failure");
    let concurrent_failure = reduce_command(
        &config(),
        Command::RecordActiveProofFailure(RecordActiveProofFailure {
            now: at(40),
            attempt_id: id("attempt"),
            method: proof_method(ProofFamily::SharedSecretOtp),
            weak_proof_gate: verified_proof_of_work_gate(),
        }),
        &loaded_before_failure,
    )
    .expect("concurrent weak proof failure from same snapshot");

    store
        .commit_plan(first_failure.commit_plan)
        .expect("first weak proof failure commit");
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(concurrent_failure.commit_plan)
        .expect_err("stale weak proof failure must fail after count changed");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert_eq!(store, after_first_commit);
    assert_eq!(
        store
            .active_proof_attempts
            .get(&id("attempt"))
            .expect("attempt")
            .weak_proof_failures,
        1
    );
}

#[test]
fn active_proof_completion_rejects_duplicate_satisfied_proof_family() {
    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::SharedSecretOtp, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: verified_proof_of_work_gate(),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::SharedSecretOtp)],
        ),
    )
    .expect_err("same proof family must not be recorded twice");

    assert_eq!(error, Error::ActiveProofAlreadySatisfied);
}

#[test]
fn active_proof_closure_guard_rejects_concurrent_full_authentication() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    );
    let loaded_before_closure = store.loaded_for_attempt(&id("attempt"));

    let first_full_authentication = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("attempt"),
            fresh_session_id: id("session-1"),
            trust_device: None,
        }),
        &loaded_before_closure,
    )
    .expect("first full authentication");
    let concurrent_full_authentication = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("attempt"),
            fresh_session_id: id("session-2"),
            trust_device: None,
        }),
        &loaded_before_closure,
    )
    .expect("concurrent full authentication from same snapshot");

    store
        .commit_plan(first_full_authentication.commit_plan)
        .expect("first full authentication commit");
    let after_first_commit = store.clone();
    let error = store
        .commit_plan(concurrent_full_authentication.commit_plan)
        .expect_err("stale full authentication must fail after attempt closure");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof attempt still open")
    );
    assert_eq!(store, after_first_commit);
    assert!(store.sessions.contains_key(&id("session-1")));
    assert!(!store.sessions.contains_key(&id("session-2")));
}
