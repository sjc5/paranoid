use super::*;

#[test]
fn weak_active_proof_failure_requires_weak_proof_gate() {
    for proof_family in [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp] {
        let error = reduce_command(
            &config(),
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: None,
                method: proof_method(proof_family),
                weak_proof_gate: WeakProofGateStatus::NotRequired,
            }),
            &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
        )
        .expect_err("weak proof failures must require a pre-state-load gate");

        assert_eq!(error, Error::WeakProofGateVerificationRequired);
    }
}

#[test]
fn non_online_guessable_message_signature_failure_does_not_consume_weak_budget() {
    let transition = reduce_command(
        &config(),
        Command::RecordActiveProofFailure(RecordActiveProofFailure {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: None,
            method: proof_method_matching(
                &ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            ),
            weak_proof_gate: WeakProofGateStatus::NotRequired,
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect("non-online-guessable message-signature failure should not require weak gate");

    assert_eq!(
        transition.outcome,
        Outcome::ActiveProofFailureRecorded {
            attempt_id: id("attempt"),
            attempt_was_deleted: false,
        }
    );
    assert!(transition.commit_plan.mutations.is_empty());
}

#[test]
fn weak_active_proof_failure_increments_attempt_budget_before_limit() {
    for proof_family in [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp] {
        let transition = reduce_command(
            &config(),
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: None,
                method: proof_method(proof_family),
                weak_proof_gate: verified_proof_of_work_gate(),
            }),
            &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
        )
        .expect("transition");

        assert_eq!(
            transition.outcome,
            Outcome::ActiveProofFailureRecorded {
                attempt_id: id("attempt"),
                attempt_was_deleted: false,
            }
        );
        assert!(matches!(
            transition.commit_plan.mutations.as_slice(),
            [Mutation::RecordWeakProofFailure {
                attempt_id,
                weak_proof_failures,
            }] if *attempt_id == id("attempt") && *weak_proof_failures == 1
        ));
        assert!(
            transition
                .commit_plan
                .audit_events
                .iter()
                .any(|event| event.kind == AuditEventKind::ActiveProofFailed
                    && event.weak_proof_gate == Some(proof_of_work_gate_summary()))
        );
    }
}

#[test]
fn weak_active_proof_failures_hard_delete_attempt_at_budget() {
    for proof_family in [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp] {
        let mut attempt = active_attempt(ProofUse::ContributeToFullAuthentication);
        attempt.weak_proof_failures = 2;
        let loaded = LoadedState {
            active_proof_attempt_record: Some(attempt),
            subject_revocations: no_subject_revocations(),
            ..LoadedState::default()
        };

        let transition = reduce_command(
            &config(),
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: None,
                method: proof_method(proof_family),
                weak_proof_gate: verified_proof_of_work_gate(),
            }),
            &loaded,
        )
        .expect("transition");

        assert_eq!(
            transition.outcome,
            Outcome::ActiveProofFailureRecorded {
                attempt_id: id("attempt"),
                attempt_was_deleted: true,
            }
        );
        assert!(matches!(
            transition.commit_plan.mutations.as_slice(),
            [Mutation::DeleteActiveProofAttempt { attempt_id }]
                if *attempt_id == id("attempt")
        ));
        assert!(transition.commit_plan.method_commit_work.is_empty());
        assert!(transition.commit_plan.fresh_credential_secrets.is_empty());
        assert!(transition.commit_plan.durable_effects.is_empty());
        assert_eq!(
            transition.commit_plan.response_effects,
            vec![ResponseEffect::DeleteActiveProofContinuationCookie],
            "budget exhaustion must delete only the current continuation cookie, not emit account-level effects",
        );
        assert!(
            transition
                .commit_plan
                .audit_events
                .iter()
                .any(|event| event.kind
                    == AuditEventKind::ActiveProofAttemptDeletedAfterWeakProofFailures
                    && event.weak_proof_gate == Some(proof_of_work_gate_summary()))
        );
    }
}
