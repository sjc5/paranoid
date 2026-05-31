use super::*;

#[test]
fn starting_active_proof_attempt_creates_bounded_attempt() {
    let transition = reduce_command(
        &config(),
        Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: at(20),
            attempt_id: id("attempt"),
            proof_use: ProofUse::ContributeToFullAuthentication,
            subject_id: Some(id("subject")),
        }),
        &LoadedState::default(),
    )
    .expect("transition");

    assert_eq!(
        transition.outcome,
        Outcome::ActiveProofAttemptStarted {
            attempt_id: id("attempt"),
            expires_at: at(140),
        }
    );
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::CreateActiveProofAttempt(attempt)]
            if attempt.attempt_id == id("attempt")
                && attempt.proof_use == ProofUse::ContributeToFullAuthentication
                && attempt.subject_id == Some(id("subject"))
                && attempt.max_weak_proof_failures == 3
                && attempt.expires_at == at(140)
    ));
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(
                |event| event.kind == AuditEventKind::ActiveProofAttemptStarted
                    && event.attempt_id == Some(id("attempt"))
            )
    );
}

#[test]
fn active_proof_attempt_cannot_target_passive_only_use() {
    let error = reduce_command(
        &config(),
        Command::StartActiveProofAttempt(StartActiveProofAttempt {
            now: at(20),
            attempt_id: id("attempt"),
            proof_use: ProofUse::SilentlyReviveTrustedDeviceSession,
            subject_id: Some(id("subject")),
        }),
        &LoadedState::default(),
    )
    .expect_err("silent trusted-device revival is not an active-proof transition");

    assert_eq!(
        error,
        Error::ActiveProofUseCannotBeSatisfiedByActiveProof {
            proof_use: ProofUse::SilentlyReviveTrustedDeviceSession,
        }
    );
}

#[test]
fn issuing_out_of_band_challenge_queues_delivery_and_dedupe_precondition() {
    let transition = reduce_command(
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
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("transition");

    assert_eq!(
        transition.outcome,
        Outcome::OutOfBandChallengeIssued {
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            expires_at: at(70),
        }
    );
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [
            Precondition::ActiveProofAttemptStillOpen { attempt_id, .. },
            Precondition::NoOpenOutOfBandChallengeForDedupeKey {
                challenge_dedupe_key,
                ..
            },
        ] if *attempt_id == id("attempt")
            && challenge_dedupe_key.as_str() == "login:email-hash:window"
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::CreateActiveProofChallenge(challenge)]
            if challenge.challenge_id == id("challenge")
                && challenge.attempt_id == id("attempt")
                && challenge.proof == ProofSummary::new(
                    ProofFamily::OutOfBandCode,
                    "email_otp",
                ).expect("proof")
                && challenge.recipient_handle.as_deref() == Some("opaque-email-handle")
                && challenge.used_delivery_idempotency_keys == vec!["mail-idempotency-key".to_owned()]
                && challenge.resend_count == 0
                && challenge.max_resends == 1
                && challenge.requires_stateless_fast_fail
                && challenge.expires_at == at(70)
    ));
    assert!(matches!(
        transition.commit_plan.durable_effects.as_slice(),
        [DurableEffectCommand::SendOutOfBandMessage(command)]
            if command.challenge_id == id("challenge")
                && command.proof_method_label == "email_otp"
                && command.recipient_handle == "opaque-email-handle"
                && command.idempotency_key == "mail-idempotency-key"
                && command.expires_at == at(70)
    ));
}

#[test]
fn issuing_out_of_band_challenge_uses_method_declaration_semantics() {
    let method =
        ProofMethodDeclaration::new_online_guessable(ProofFamily::OutOfBandCode, "short_sms_otp")
            .expect("method declaration");
    let expected_proof = method.verified_proof_summary();

    let transition = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            method,
            challenge_dedupe_key: dedupe_key("login:sms-hash:window"),
            recipient_handle: "opaque-sms-handle".to_owned(),
            idempotency_key: "sms-idempotency-key".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue_proof(
                "attempt",
                "challenge",
                expected_proof.clone(),
                at(30),
                at(70),
            ),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("transition");

    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::CreateActiveProofChallenge(challenge)]
            if challenge.proof == expected_proof
                && challenge.proof.uses_weak_attempt_failure_budget()
                && challenge.requires_stateless_fast_fail
    ));
    assert!(matches!(
        transition.commit_plan.durable_effects.as_slice(),
        [DurableEffectCommand::SendOutOfBandMessage(command)]
            if command.proof_method_label == "short_sms_otp"
    ));
}

#[test]
fn issuing_out_of_band_challenge_rejects_non_out_of_band_method() {
    let error = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:totp:window"),
            recipient_handle: "totp-has-no-delivery-target".to_owned(),
            idempotency_key: "totp-idempotency-key".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie(),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("only out-of-band methods can issue out-of-band challenges");

    assert_eq!(
        error,
        Error::ProofMethodCannotIssueOutOfBandChallenge {
            family: ProofFamily::SharedSecretOtp,
        }
    );
}

#[test]
fn issuing_out_of_band_challenge_carries_method_commit_work_atomically() {
    let transition = reduce_command(
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
            method_commit_work: vec![out_of_band_method_commit_work()],
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("transition");

    assert_eq!(
        transition.commit_plan.method_commit_work,
        vec![out_of_band_method_commit_work()]
    );
}

#[test]
fn issuing_out_of_band_challenge_rejects_mismatched_method_commit_work() {
    let error = reduce_command(
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
            method_commit_work: vec![recovery_code_method_commit_work()],
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("out-of-band issue work must belong to the out-of-band proof");

    assert_eq!(error, Error::MethodCommitWorkProofMismatch);
}

#[test]
fn resending_out_of_band_challenge_records_budget_and_queues_delivery() {
    let transition = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("transition");

    assert_eq!(
        transition.outcome,
        Outcome::OutOfBandChallengeResent {
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            resend_count: 1,
            expires_at: at(60),
        }
    );
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [
            Precondition::ActiveProofAttemptStillOpen { attempt_id, .. },
            Precondition::OutOfBandChallengeResendStillAllowed {
                challenge_id,
                observed_resend_count,
                observed_used_delivery_idempotency_keys,
                ..
            },
        ] if *attempt_id == id("attempt")
            && *challenge_id == id("challenge")
            && *observed_resend_count == 0
            && *observed_used_delivery_idempotency_keys == vec!["mail-idempotency-key".to_owned()]
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::RecordOutOfBandChallengeResent {
            challenge_id,
            resend_count,
            used_delivery_idempotency_keys,
            resent_at,
        }] if *challenge_id == id("challenge")
            && *resend_count == 1
            && *used_delivery_idempotency_keys == vec![
                "mail-idempotency-key".to_owned(),
                "mail-idempotency-key-resend-1".to_owned(),
            ]
            && *resent_at == at(40)
    ));
    assert!(matches!(
        transition.commit_plan.durable_effects.as_slice(),
        [DurableEffectCommand::SendOutOfBandMessage(command)]
            if command.challenge_id == id("challenge")
                && command.proof_method_label == "email_otp"
                && command.recipient_handle == "opaque-email-handle"
                && command.idempotency_key == "mail-idempotency-key-resend-1"
                && command.expires_at == at(60)
    ));
    assert!(
        transition
            .commit_plan
            .audit_events
            .iter()
            .any(
                |event| event.kind == AuditEventKind::OutOfBandChallengeResent
                    && event.challenge_id == Some(id("challenge"))
            )
    );
}

#[test]
fn resending_out_of_band_challenge_carries_method_commit_work_atomically() {
    let transition = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: vec![out_of_band_method_commit_work()],
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("transition");

    assert_eq!(
        transition.commit_plan.method_commit_work,
        vec![out_of_band_method_commit_work()]
    );
}

#[test]
fn resending_out_of_band_challenge_rejects_reused_delivery_idempotency_key() {
    let error = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("user-visible resend must use a fresh delivery idempotency key");

    assert_eq!(error, Error::OutOfBandDeliveryIdempotencyKeyAlreadyUsed);
}

#[test]
fn resending_out_of_band_challenge_rejects_any_previously_used_delivery_idempotency_key() {
    let mut config = config();
    config.max_out_of_band_challenge_resends_per_challenge = 2;
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    let challenge = loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge");
    challenge.max_resends = 2;
    challenge.resend_count = 1;
    challenge.used_delivery_idempotency_keys = vec![
        "mail-idempotency-key".to_owned(),
        "mail-idempotency-key-resend-1".to_owned(),
    ];

    let error = reduce_command(
        &config,
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(45),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("any previously used delivery idempotency key must be rejected");

    assert_eq!(error, Error::OutOfBandDeliveryIdempotencyKeyAlreadyUsed);
}

#[test]
fn resending_out_of_band_challenge_rejects_exhausted_resend_budget() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    let challenge = loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge");
    challenge.resend_count = 1;
    challenge.used_delivery_idempotency_keys = vec![
        "mail-idempotency-key".to_owned(),
        "mail-idempotency-key-resend-1".to_owned(),
    ];

    let error = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(45),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-2".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("resend budget should be exhausted");

    assert_eq!(error, Error::OutOfBandChallengeResendBudgetExhausted);
}

#[test]
fn issue_and_resend_out_of_band_challenge_reject_already_satisfied_out_of_band_proof() {
    let issue_error = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("new-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:email-hash:later-window"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-idempotency-key-later".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "attempt",
                "new-challenge",
                at(30),
                at(70),
            ),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    )
    .expect_err("already satisfied out-of-band proof must not receive new challenge work");
    assert_eq!(issue_error, Error::ActiveProofAlreadySatisfied);

    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_attempt_record
        .as_mut()
        .expect("attempt")
        .satisfied_proofs
        .push(proof(ProofFamily::OutOfBandCode));

    let resend_error = reduce_command(
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
    .expect_err("already satisfied out-of-band proof must not receive resend work");
    assert_eq!(resend_error, Error::ActiveProofAlreadySatisfied);
}

#[test]
fn completing_out_of_band_challenge_requires_stateless_fast_fail() {
    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("out-of-band challenge must require stateless fast-fail");

    assert_eq!(error, Error::StatelessFastFailVerificationRequired);
}

#[test]
fn completing_out_of_band_challenge_closes_challenge_family_and_records_proof() {
    let completed_proof =
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof");
    let transition = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("challenge")),
            verified_proof: verified(completed_proof.clone(), Some(id("subject"))),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("transition");

    assert_eq!(
        transition.outcome,
        Outcome::ActiveProofCompleted {
            attempt_id: id("attempt"),
            proof: completed_proof.clone(),
        }
    );
    assert!(matches!(
        transition.commit_plan.preconditions.as_slice(),
        [
            Precondition::ActiveProofChallengeStillOpen { challenge_id, .. },
            Precondition::ActiveProofAttemptStillOpen { attempt_id, .. },
        ] if *challenge_id == id("challenge") && *attempt_id == id("attempt")
    ));
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
                attempt_id: close_attempt_id,
                proof_family,
                closed_at,
            },
            Mutation::RecordActiveProofSucceeded {
                attempt_id,
                subject_id,
                proof,
                satisfied_at,
            },
        ] if *close_attempt_id == id("attempt")
            && *proof_family == ProofFamily::OutOfBandCode
            && *closed_at == at(40)
            && *attempt_id == id("attempt")
            && *subject_id == Some(id("subject"))
            && *proof == completed_proof
            && *satisfied_at == at(40)
    ));
}

#[test]
fn completing_active_proof_carries_method_commit_work_atomically() {
    let transition = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::RecoveryCode, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: vec![recovery_code_method_commit_work()],
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("recovery-code proof completion");

    assert_eq!(
        transition.commit_plan.method_commit_work,
        vec![recovery_code_method_commit_work()]
    );
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [Mutation::RecordActiveProofSucceeded { proof: succeeded_proof, .. }]
            if *succeeded_proof == proof(ProofFamily::RecoveryCode)
    ));
}

#[test]
fn completing_active_proof_rejects_invalid_method_commit_work() {
    let missing_method_work_error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::RecoveryCode, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("one-time recovery proof completion must carry method work");
    assert_eq!(
        missing_method_work_error,
        Error::MissingMethodCommitWorkForOneTimeProof
    );

    let mismatched_method_error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::RecoveryCode, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: vec![MethodCommitWork {
                proof: ProofSummary::new(ProofFamily::SharedSecretOtp, "RecoveryCode")
                    .expect("proof"),
                ..recovery_code_method_commit_work()
            }],
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("method work must belong to the completed proof method");
    assert_eq!(
        mismatched_method_error,
        Error::MethodCommitWorkProofMismatch
    );

    let empty_method_work_error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified_proof(ProofFamily::RecoveryCode, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: vec![MethodCommitWork {
                proof: proof(ProofFamily::RecoveryCode),
                preconditions: Vec::new(),
                mutations: Vec::new(),
                durable_effect_commands: Vec::new(),
            }],
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("empty method work must not be accepted");
    assert_eq!(empty_method_work_error, Error::EmptyMethodCommitWork);
}

#[test]
fn completing_out_of_band_challenge_closes_same_family_sibling_challenges_atomically() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    store.active_proof_attempts.insert(
        id("other-attempt"),
        ActiveProofAttemptRecord {
            attempt_id: id("other-attempt"),
            ..active_attempt(ProofUse::ContributeToFullAuthentication)
        },
    );
    store
        .active_proof_challenges
        .insert(id("challenge"), out_of_band_challenge());
    store.active_proof_challenges.insert(
        id("sibling-challenge"),
        ActiveProofChallengeRecord {
            challenge_id: id("sibling-challenge"),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "sms_otp").expect("proof"),
            challenge_dedupe_key: Some(dedupe_key("login:sms:window")),
            ..out_of_band_challenge()
        },
    );
    store.active_proof_challenges.insert(
        id("other-attempt-challenge"),
        ActiveProofChallengeRecord {
            challenge_id: id("other-attempt-challenge"),
            attempt_id: id("other-attempt"),
            challenge_dedupe_key: Some(dedupe_key("other-attempt:email:window")),
            ..out_of_band_challenge()
        },
    );

    let transition = reduce_command(
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
        &store.loaded_for_attempt_and_challenge(&id("attempt"), &id("challenge")),
    )
    .expect("transition");

    assert_only_deleted_active_proof_challenge_cookie(
        store.commit_plan(transition.commit_plan).expect("commit"),
    );
    assert_eq!(
        store
            .active_proof_challenges
            .get(&id("challenge"))
            .expect("challenge")
            .closed_at,
        Some(at(40))
    );
    assert_eq!(
        store
            .active_proof_challenges
            .get(&id("sibling-challenge"))
            .expect("sibling challenge")
            .closed_at,
        Some(at(40))
    );
    assert_eq!(
        store
            .active_proof_challenges
            .get(&id("other-attempt-challenge"))
            .expect("other attempt challenge")
            .closed_at,
        None
    );
}
