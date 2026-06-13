use super::*;

#[test]
fn stale_sibling_challenge_completion_fails_after_same_family_challenge_closure() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
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
    let loaded_before_email_completion =
        store.loaded_for_attempt_and_challenge(&id("attempt"), &id("challenge"));
    let loaded_before_sms_completion =
        store.loaded_for_attempt_and_challenge(&id("attempt"), &id("sibling-challenge"));

    let email_completion = reduce_command(
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
        &loaded_before_email_completion,
    )
    .expect("email completion");
    let stale_sms_completion = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("sibling-challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "sms_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_before_sms_completion,
    )
    .expect("stale sms completion");

    assert_only_deleted_active_proof_challenge_cookie(
        store
            .commit_plan(email_completion.commit_plan)
            .expect("first commit"),
    );
    let store_after_first_commit = store.clone();
    let error = store
        .commit_plan(stale_sms_completion.commit_plan)
        .expect_err("stale sibling completion must fail");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("active proof challenge still open")
    );
    assert_eq!(store, store_after_first_commit);
}

#[test]
fn completing_active_proof_challenge_rejects_subject_mismatch() {
    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("other-subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("completed proof subject must match the attempt subject");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "active-proof supplied subject differs from attempt subject",
        )
    );
}

#[test]
fn completing_active_proof_challenge_can_bind_unbound_attempt_to_resolved_subject() {
    let completed_proof =
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof");
    let completed_source = proof_source("email-identifier");
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded.active_proof_attempt_record = Some(unbound_active_attempt(
        ProofUse::ContributeToFullAuthentication,
    ));

    let transition = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("challenge")),
            verified_proof: verified_with_source(
                completed_proof.clone(),
                Some(id("subject")),
                completed_source.clone(),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect("transition");

    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily { .. },
            Mutation::RecordActiveProofSucceeded {
                attempt_id,
                subject_id,
                proof,
                satisfied_at,
            },
        ] if *attempt_id == id("attempt")
            && *subject_id == Some(id("subject"))
            && proof.proof() == &completed_proof
            && proof.source() == Some(&completed_source)
            && *satisfied_at == at(40)
    ));
}

#[test]
fn reserving_identifier_change_candidate_binding_creates_pending_binding_without_authorizing_change()
 {
    let candidate_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        id("candidate-email-source"),
    );

    let transition = reduce_command(
        &config(),
        Command::ReserveOutOfBandIdentifierChangeCandidateBinding(
            ReserveOutOfBandIdentifierChangeCandidateBinding {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: id("challenge"),
                candidate_identifier_source: candidate_source.clone(),
                stateless_fast_fail: verified_stateless_fast_fail(),
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: vec![out_of_band_method_commit_work()],
            },
        ),
        &loaded_attempt_and_challenge_state(ProofUse::ProveOutOfBandIdentifierChangeCandidate),
    )
    .expect("candidate binding reservation");

    assert_eq!(
        transition.outcome,
        Outcome::OutOfBandIdentifierChangeCandidateBindingReserved(
            OutOfBandIdentifierChangeCandidateBindingReservationOutcome {
                subject_id: id("subject"),
                candidate_identifier_source_id: id("candidate-email-source"),
            },
        )
    );
    assert!(matches!(
        transition.commit_plan.mutations.as_slice(),
        [
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
                attempt_id,
                proof_family,
                closed_at,
            },
            Mutation::DeleteActiveProofAttempt {
                attempt_id: deleted_attempt_id,
            },
            Mutation::CreateOutOfBandIdentifierBinding {
                record,
                created_at,
            },
        ] if *attempt_id == id("attempt")
            && *proof_family == ProofFamily::OutOfBandCode
            && *closed_at == at(40)
            && *deleted_attempt_id == id("attempt")
            && record.source() == &candidate_source
            && record.subject_id() == &id("subject")
            && record.proof_method_label() == "email_otp"
            && record.lifecycle_state()
                == OutOfBandIdentifierBindingLifecycleState::PendingActivation
            && *created_at == at(40)
    ));
    assert_eq!(
        transition.commit_plan.method_commit_work,
        vec![out_of_band_method_commit_work()]
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteActiveProofChallengeCookie)
    );
    assert!(
        transition
            .commit_plan
            .response_effects
            .contains(&ResponseEffect::DeleteActiveProofContinuationCookie)
    );
    assert!(transition.commit_plan.audit_events.iter().any(|event| {
        event.kind == AuditEventKind::OutOfBandIdentifierChangeCandidateBindingReserved
            && event.subject_id == Some(id("subject"))
            && event.attempt_id == Some(id("attempt"))
            && event.challenge_id == Some(id("challenge"))
    }));
}

#[test]
fn identifier_change_candidate_binding_requires_subject_bound_candidate_proof_ceremony() {
    let candidate_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        id("candidate-email-source"),
    );
    let command = Command::ReserveOutOfBandIdentifierChangeCandidateBinding(
        ReserveOutOfBandIdentifierChangeCandidateBinding {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            candidate_identifier_source: candidate_source,
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        },
    );

    let wrong_use_error = reduce_command(
        &config(),
        command.clone(),
        &loaded_attempt_and_challenge_state(ProofUse::SatisfyStepUp),
    )
    .expect_err("candidate binding must require the dedicated proof use");
    assert_eq!(
        wrong_use_error,
        Error::LoadedStateContradiction(
            "identifier-change candidate binding requires the candidate identifier proof use",
        )
    );

    let mut unbound_loaded =
        loaded_attempt_and_challenge_state(ProofUse::ProveOutOfBandIdentifierChangeCandidate);
    unbound_loaded.active_proof_attempt_record = Some(unbound_active_attempt(
        ProofUse::ProveOutOfBandIdentifierChangeCandidate,
    ));
    let unbound_error = reduce_command(&config(), command, &unbound_loaded)
        .expect_err("candidate binding must already be bound to the current subject");
    assert_eq!(
        unbound_error,
        Error::LoadedStateContradiction(
            "identifier-change candidate binding requires a subject-bound active-proof attempt",
        )
    );
}

#[test]
fn identifier_change_candidate_binding_requires_stateless_fast_fail_and_out_of_band_source() {
    let loaded =
        loaded_attempt_and_challenge_state(ProofUse::ProveOutOfBandIdentifierChangeCandidate);
    let missing_fast_fail_error = reduce_command(
        &config(),
        Command::ReserveOutOfBandIdentifierChangeCandidateBinding(
            ReserveOutOfBandIdentifierChangeCandidateBinding {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: id("challenge"),
                candidate_identifier_source: VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    id("candidate-email-source"),
                ),
                stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            },
        ),
        &loaded,
    )
    .expect_err("candidate binding must require challenge-cookie fast fail");
    assert_eq!(
        missing_fast_fail_error,
        Error::StatelessFastFailVerificationRequired
    );

    let wrong_source_error = reduce_command(
        &config(),
        Command::ReserveOutOfBandIdentifierChangeCandidateBinding(
            ReserveOutOfBandIdentifierChangeCandidateBinding {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: id("challenge"),
                candidate_identifier_source: VerifiedProofSource::new(
                    VerifiedProofSourceKind::CredentialInstance,
                    id("candidate-email-source"),
                ),
                stateless_fast_fail: verified_stateless_fast_fail(),
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            },
        ),
        &loaded,
    )
    .expect_err("candidate binding must come from an out-of-band identifier proof source");
    assert_eq!(
        wrong_source_error,
        Error::InvalidConfig(
            "identifier-change candidate source must be an out-of-band identifier"
        )
    );
}

#[test]
fn completing_webauthn_or_oidc_can_bind_unbound_attempt_to_resolved_subject() {
    for proof in [
        ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
            .expect("method declaration")
            .verified_proof_summary(),
        ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
            .expect("method declaration")
            .verified_proof_summary(),
    ] {
        let transition = reduce_command(
            &config(),
            Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: None,
                verified_proof: verified(proof.clone(), Some(id("subject"))),
                stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            }),
            &LoadedState {
                active_proof_attempt_record: Some(unbound_active_attempt(
                    ProofUse::ContributeToFullAuthentication,
                )),
                subject_revocations: no_subject_revocations(),
                ..LoadedState::default()
            },
        )
        .expect("WebAuthn or OIDC proof should bind resolved subject");

        assert!(matches!(
            transition.commit_plan.mutations.as_slice(),
            [
                Mutation::RecordActiveProofSucceeded {
                    attempt_id,
                    subject_id,
                    proof: completed_proof,
                    satisfied_at,
                },
            ] if *attempt_id == id("attempt")
                && *subject_id == Some(id("subject"))
                && completed_proof.proof() == &proof
                && *satisfied_at == at(40)
        ));
    }
}

#[test]
fn completing_active_proof_challenge_rejects_shared_secret_otp_binding_an_unbound_attempt() {
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
        &LoadedState {
            active_proof_attempt_record: Some(unbound_active_attempt(ProofUse::SatisfyStepUp)),
            ..LoadedState::default()
        },
    )
    .expect_err("shared-secret OTP requires a known subject before proof completion");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "active-proof completion did not resolve subject for unbound attempt",
        )
    );
}

#[test]
fn configured_secret_proofs_complete_without_stateful_challenge_for_bound_attempt() {
    let totp_transition = reduce_command(
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
        &loaded_attempt_state(ProofUse::SatisfyStepUp),
    )
    .expect("TOTP should complete against the known attempt subject without a challenge");
    assert_eq!(
        totp_transition.outcome,
        Outcome::ActiveProofCompleted {
            attempt_id: id("attempt"),
            proof: proof(ProofFamily::SharedSecretOtp),
        }
    );
    assert!(totp_transition.commit_plan.response_effects.is_empty());

    let recovery_transition = reduce_command(
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
        &loaded_attempt_state(ProofUse::RecoverOrReplaceCredential),
    )
    .expect("recovery code should complete against the known attempt subject without a challenge");
    assert_eq!(
        recovery_transition.outcome,
        Outcome::ActiveProofCompleted {
            attempt_id: id("attempt"),
            proof: proof(ProofFamily::RecoveryCode),
        }
    );
    assert_eq!(
        recovery_transition.commit_plan.response_effects,
        vec![ResponseEffect::IssueActiveProofContinuationCookie(
            ActiveProofContinuationCookieDraft {
                attempt_id: id("attempt"),
                proof_use: ProofUse::RecoverOrReplaceCredential,
                subject_id: Some(id("subject")),
                subject_binding: ActiveProofContinuationSubjectBinding::VerifiedProofBoundSubject,
                attempt_fast_fail_until: at(130),
            }
        )]
    );
}

#[test]
fn configured_secret_proofs_reject_stateful_challenge_completion() {
    let proof_family = ProofFamily::SharedSecretOtp;
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::SatisfyStepUp);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .proof = proof(proof_family);

    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("challenge")),
            verified_proof: verified_proof(proof_family, None),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: verified_proof_of_work_gate(),
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("known-subject proofs must not complete through challenge records");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "known-subject proof family cannot complete through this active-proof challenge",
        )
    );
}

#[test]
fn configured_secret_methods_cannot_issue_active_proof_challenges() {
    for proof_family in [ProofFamily::SharedSecretOtp, ProofFamily::RecoveryCode] {
        let error = reduce_command(
            &config(),
            Command::IssueActiveProofMethodChallenge(IssueActiveProofMethodChallenge {
                now: at(30),
                attempt_id: id("attempt"),
                challenge_id: id("challenge"),
                method: proof_method(proof_family),
                challenge_issue_kind: ActiveProofMethodChallengeIssueKind::NormalActiveMethod,
                challenge_cookie: active_proof_challenge_cookie(),
                method_challenge: ActiveProofMethodChallengePresentation::try_from_bytes(
                    b"challenge".as_slice(),
                )
                .expect("method challenge"),
                method_commit_work: Vec::new(),
            }),
            &loaded_attempt_state(ProofUse::SatisfyStepUp),
        )
        .expect_err("known-subject configured methods must not issue challenge cookies");

        assert_eq!(
            error,
            Error::ProofMethodCannotIssueActiveProofMethodChallenge {
                family: proof_family,
            }
        );
    }
}

#[test]
fn completing_weak_active_proof_requires_weak_gate() {
    for proof_family in [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp] {
        let subject_id = match proof_family {
            ProofFamily::MessageSignature => Some(id("subject")),
            ProofFamily::SharedSecretOtp => None,
            _ => unreachable!("test only covers weak proof families"),
        };
        let error = reduce_command(
            &config(),
            Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: None,
                verified_proof: verified_proof(proof_family, subject_id),
                stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            }),
            &loaded_attempt_state(ProofUse::SatisfyStepUp),
        )
        .expect_err("successful weak active proof still requires the weak-proof gate");

        assert_eq!(error, Error::WeakProofGateVerificationRequired);
    }
}

#[test]
fn completing_non_online_guessable_message_signature_does_not_require_weak_gate() {
    let transition = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified(
                ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::SatisfyStepUp),
    )
    .expect("non-online-guessable message-signature proof should not require weak gate");

    assert_eq!(
        transition.outcome,
        Outcome::ActiveProofCompleted {
            attempt_id: id("attempt"),
            proof: ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("proof"),
        }
    );
}

#[test]
fn completing_active_proof_challenge_rejects_challenge_from_another_attempt() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .attempt_id = id("other-attempt");

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
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("challenge from another attempt must be rejected");

    assert_eq!(
        error,
        Error::LoadedStateContradiction("active-proof challenge belongs to a different attempt",)
    );
}

#[test]
fn completing_active_proof_challenge_rejects_closed_challenge() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .closed_at = Some(at(35));

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
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("closed challenge must not be reusable");

    assert_eq!(error, Error::ActiveProofChallengeNotOpen);
}

#[test]
fn completing_active_proof_challenge_rejects_expired_challenge() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .expires_at = at(40);

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
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("expired challenge must not be accepted");

    assert_eq!(error, Error::ActiveProofChallengeNotOpen);
}

#[test]
fn resending_out_of_band_challenge_rejects_closed_challenge() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .closed_at = Some(at(35));

    let error = reduce_command(
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
    .expect_err("closed challenge must not be resent");

    assert_eq!(error, Error::ActiveProofChallengeNotOpen);
}

#[test]
fn resending_out_of_band_challenge_rejects_expired_challenge() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .expires_at = at(40);

    let error = reduce_command(
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
    .expect_err("expired challenge must not be resent");

    assert_eq!(error, Error::ActiveProofChallengeNotOpen);
}

#[test]
fn completing_active_proof_challenge_rejects_challenge_proof_mismatch() {
    let mut loaded = loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication);
    loaded
        .active_proof_challenge_record
        .as_mut()
        .expect("challenge")
        .proof = ProofSummary::new(ProofFamily::OutOfBandCode, "sms_otp").expect("proof");

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
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded,
    )
    .expect_err("challenge proof must match the completed proof");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "active-proof challenge proof differs from satisfied proof",
        )
    );
}

#[test]
fn completing_active_proof_challenge_rejects_wrong_challenge_id() {
    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: Some(id("other-challenge")),
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("wrong challenge id must be rejected");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "active-proof command challenge id differs from loaded challenge id",
        )
    );
}

#[test]
fn completing_active_proof_challenge_rejects_missing_challenge_record() {
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
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("stateful challenge completion requires loaded challenge record");

    assert_eq!(
        error,
        Error::LoadedStateContradiction("active-proof challenge record missing")
    );
}

#[test]
fn completing_out_of_band_proof_rejects_missing_challenge_id() {
    let error = reduce_command(
        &config(),
        Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            verified_proof: verified(
                ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                Some(id("subject")),
            ),
            stateless_fast_fail: verified_stateless_fast_fail(),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("out-of-band proof completion must name a challenge");

    assert_eq!(
        error,
        Error::MissingFreshValue("challenge_id for out-of-band proof")
    );
}

#[test]
fn commands_requiring_open_active_proof_attempts_reject_closed_and_expired_attempts() {
    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "issue out-of-band challenge",
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
        loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
        at(30),
    );

    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "complete active-proof challenge",
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
        loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
        at(40),
    );

    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "resend out-of-band challenge",
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
        at(40),
    );

    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "record active-proof failure",
        Command::RecordActiveProofFailure(RecordActiveProofFailure {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            method: proof_method(ProofFamily::SharedSecretOtp),
            weak_proof_gate: verified_proof_of_work_gate(),
        }),
        loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
        at(40),
    );

    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "complete full authentication",
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
        at(40),
    );

    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "complete step-up",
        Command::CompleteStepUp(CompleteStepUp {
            now: at(40),
            attempt_id: id("attempt"),
        }),
        loaded_session_and_attempt(
            200,
            ProofUse::SatisfyStepUp,
            vec![proof(ProofFamily::SharedSecretOtp)],
        ),
        at(40),
    );

    assert_command_rejects_closed_and_expired_active_proof_attempt(
        "complete trusted-device active-proof revival",
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        loaded_trusted_device_and_attempt(
            500,
            2_000,
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            vec![proof(ProofFamily::MessageSignature)],
        ),
        at(600),
    );
}
