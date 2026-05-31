use super::*;

fn one_byte_too_long(max_bytes: usize) -> String {
    "x".repeat(max_bytes + 1)
}

fn issue_email_challenge_command() -> IssueOutOfBandChallenge {
    IssueOutOfBandChallenge {
        now: at(20),
        attempt_id: id("attempt"),
        challenge_id: id("challenge"),
        method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
            .expect("method declaration"),
        challenge_dedupe_key: dedupe_key("login:email-hash:window"),
        recipient_handle: "opaque-email-handle".to_owned(),
        idempotency_key: "mail-idempotency-key".to_owned(),
        stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
            "attempt",
            "challenge",
            at(20),
            at(60),
        ),
        method_commit_work: Vec::new(),
    }
}

#[test]
fn auth_ids_are_bounded() {
    let error = SubjectId::from_bytes(vec![0_u8; ID_MAX_BYTES + 1])
        .expect_err("auth ids must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "auth id",
            max_bytes: ID_MAX_BYTES,
        }
    );
}

#[test]
fn proof_method_labels_are_bounded_and_identifier_shaped() {
    let error = ProofSummary::new(
        ProofFamily::OutOfBandCode,
        one_byte_too_long(METHOD_LABEL_MAX_BYTES),
    )
    .expect_err("proof method labels must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "proof method label",
            max_bytes: METHOD_LABEL_MAX_BYTES,
        }
    );

    let error = ProofSummary::new(ProofFamily::OutOfBandCode, "email otp")
        .expect_err("proof method labels must be identifier-shaped");

    assert_eq!(
        error,
        Error::InvalidIdentifierString {
            input_name: "proof method label",
        }
    );
}

#[test]
fn weak_proof_gate_method_labels_are_bounded_and_identifier_shaped() {
    let error = WeakProofGateSummary::new(
        WeakProofGateKind::ProofOfWork,
        one_byte_too_long(WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES),
    )
    .expect_err("weak-proof gate labels must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "weak-proof gate method label",
            max_bytes: WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES,
        }
    );

    let error = WeakProofGateSummary::new(WeakProofGateKind::ProofOfWork, "hash cash")
        .expect_err("weak-proof gate labels must be identifier-shaped");

    assert_eq!(
        error,
        Error::InvalidIdentifierString {
            input_name: "weak-proof gate method label",
        }
    );
}

#[test]
fn active_proof_method_challenge_state_is_non_empty_and_bounded() {
    let error = ActiveProofMethodChallengeState::try_from_bytes(Vec::new())
        .expect_err("method challenge state must not be empty");

    assert_eq!(error, Error::EmptyActiveProofMethodChallengeState);

    let error = ActiveProofMethodChallengeState::try_from_bytes(vec![
        0_u8;
        ACTIVE_PROOF_METHOD_CHALLENGE_STATE_MAX_BYTES
            + 1
    ])
    .expect_err("method challenge state must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "active-proof method challenge state",
            max_bytes: ACTIVE_PROOF_METHOD_CHALLENGE_STATE_MAX_BYTES,
        }
    );
}

#[test]
fn out_of_band_dedupe_keys_are_bounded_and_identifier_shaped() {
    let error = OutOfBandChallengeDedupeKey::new(one_byte_too_long(
        OUT_OF_BAND_CHALLENGE_DEDUPE_KEY_MAX_BYTES,
    ))
    .expect_err("dedupe keys must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "out-of-band challenge dedupe key",
            max_bytes: OUT_OF_BAND_CHALLENGE_DEDUPE_KEY_MAX_BYTES,
        }
    );

    let error = OutOfBandChallengeDedupeKey::new("login email")
        .expect_err("dedupe keys must be identifier-shaped");

    assert_eq!(
        error,
        Error::InvalidIdentifierString {
            input_name: "out-of-band challenge dedupe key",
        }
    );
}

#[test]
fn method_commit_operations_and_payloads_are_bounded() {
    let error =
        MethodCommitPrecondition::new(one_byte_too_long(METHOD_COMMIT_OPERATION_MAX_BYTES), [])
            .expect_err("method commit operation labels must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "method commit operation",
            max_bytes: METHOD_COMMIT_OPERATION_MAX_BYTES,
        }
    );

    let error = MethodCommitMutation::new("consume recovery code", [])
        .expect_err("method commit operation labels must be identifier-shaped");

    assert_eq!(
        error,
        Error::InvalidIdentifierString {
            input_name: "method commit operation",
        }
    );

    let payload = vec![0_u8; METHOD_COMMIT_PAYLOAD_MAX_BYTES + 1];
    let error = MethodCommitDurableEffectCommand::new("consume_recovery_code", payload)
        .expect_err("method commit payloads must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "method commit payload",
            max_bytes: METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        }
    );
}

#[test]
fn out_of_band_issue_commands_bound_recipient_handles_and_idempotency_keys() {
    let mut command = issue_email_challenge_command();
    command.recipient_handle = one_byte_too_long(OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES);
    let error = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(command),
        &loaded_attempt_state(ProofUse::BindSubjectToActiveProofAttempt),
    )
    .expect_err("recipient handles must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "out-of-band recipient handle",
            max_bytes: OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
        }
    );

    let mut command = issue_email_challenge_command();
    command.idempotency_key = "mail idempotency key".to_owned();
    let error = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(command),
        &loaded_attempt_state(ProofUse::BindSubjectToActiveProofAttempt),
    )
    .expect_err("delivery idempotency keys must be identifier-shaped");

    assert_eq!(
        error,
        Error::InvalidIdentifierString {
            input_name: "out-of-band delivery idempotency key",
        }
    );
}

#[test]
fn trusted_device_display_labels_are_bounded() {
    let mut store = InMemoryCommitStore::default();
    let attempt_id = id("attempt");
    let subject_id = id("subject");
    store
        .commit_plan(
            reduce_command(
                &config(),
                Command::StartActiveProofAttempt(StartActiveProofAttempt {
                    now: at(10),
                    attempt_id: attempt_id.clone(),
                    proof_use: ProofUse::ContributeToFullAuthentication,
                    subject_id: Some(subject_id.clone()),
                }),
                &LoadedState::default(),
            )
            .expect("transition")
            .commit_plan,
        )
        .expect("commit");
    store
        .commit_plan(
            reduce_command(
                &config(),
                Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
                    now: at(11),
                    attempt_id: attempt_id.clone(),
                    challenge_id: None,
                    verified_proof: verified_proof(
                        ProofFamily::MessageSignature,
                        Some(subject_id.clone()),
                    ),
                    stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                    weak_proof_gate: verified_proof_of_work_gate(),
                    method_commit_work: Vec::new(),
                }),
                &store.loaded_for_attempt(&attempt_id),
            )
            .expect("transition")
            .commit_plan,
        )
        .expect("commit");

    let loaded = store.loaded_for_attempt(&attempt_id);
    let error = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(12),
            attempt_id,
            fresh_session_id: id("session"),
            trust_device: Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: id("device"),
                display_label: Some(one_byte_too_long(TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES)),
            }),
        }),
        &loaded,
    )
    .expect_err("trusted-device display labels must be resource-bounded");

    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "trusted-device display label",
            max_bytes: TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES,
        }
    );
}
