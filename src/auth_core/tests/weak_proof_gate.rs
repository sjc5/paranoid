use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn hashcash_weak_gate_accepts_only_the_exact_bound_active_method_response() {
    let verifier = hashcash_verifier_for_test();
    let proof = ProofMethodDeclaration::new_online_guessable(
        ProofFamily::MessageSignature,
        "password_derived_signature",
    )
    .expect("password-derived signature method")
    .verified_proof_summary();
    let challenge = ActiveProofMethodChallengeMaterial {
        attempt_id: id("hashcash-bound-attempt"),
        challenge_id: id("hashcash-bound-challenge"),
        proof: proof.clone(),
        issued_at: at(20),
        expires_at: at(80),
        nonce: ActiveProofChallengeFastFailNonce::from_bytes(
            &[42_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
        )
        .expect("challenge nonce"),
        method_challenge_state: ActiveProofMethodChallengeState::try_from_bytes(
            b"sealed-password-verifier-state".as_slice(),
        )
        .expect("method challenge state"),
    };
    let first_response =
        ActiveProofMethodResponsePayload::try_from_bytes(b"first-submitted-signature".as_slice())
            .expect("first response payload");
    let first_binding =
        WeakProofGateBinding::for_active_method_response(&challenge, &first_response)
            .expect("first weak-gate binding");
    let solved_response = proof_of_work_gate_response_for_test(at(30), &proof, &first_binding);

    verifier
        .verify_weak_proof_gate_before_state_load(
            WeakProofGateVerificationRequest::new_with_binding(
                at(30),
                &proof,
                &solved_response,
                Some(&first_binding),
            ),
        )
        .expect("Hashcash response bound to exact active-method response");

    let missing_binding_error = verifier
        .verify_weak_proof_gate_before_state_load(WeakProofGateVerificationRequest::new(
            at(30),
            &proof,
            &solved_response,
        ))
        .expect_err("Hashcash weak gates must require runtime-derived binding");
    assert!(matches!(
        missing_binding_error,
        Error::WeakProofGateVerificationFailed
    ));

    let second_response =
        ActiveProofMethodResponsePayload::try_from_bytes(b"second-submitted-signature".as_slice())
            .expect("second response payload");
    let second_binding =
        WeakProofGateBinding::for_active_method_response(&challenge, &second_response)
            .expect("second weak-gate binding");
    let wrong_binding_error = verifier
        .verify_weak_proof_gate_before_state_load(
            WeakProofGateVerificationRequest::new_with_binding(
                at(30),
                &proof,
                &solved_response,
                Some(&second_binding),
            ),
        )
        .expect_err("Hashcash solved for one submitted response must not verify another");
    assert!(matches!(
        wrong_binding_error,
        Error::WeakProofGateVerificationFailed
    ));
}

#[test]
fn hashcash_challenge_issue_preflight_binds_proof_use_and_method() {
    let verifier = hashcash_verifier_for_test();
    let email_method = ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
        .expect("email OTP method");
    let email_proof = email_method.verified_proof_summary();
    let response = challenge_issue_preflight_response_for_test(
        at(40),
        ProofUse::ContributeToFullAuthentication,
        &email_method,
    );

    verifier
        .verify_challenge_issue_preflight_before_state_load(
            ChallengeIssuePreflightVerificationRequest::new(
                at(40),
                ProofUse::ContributeToFullAuthentication,
                &email_proof,
                &response,
            ),
        )
        .expect("Hashcash preflight bound to exact email OTP challenge issue");

    let wrong_use_error = verifier
        .verify_challenge_issue_preflight_before_state_load(
            ChallengeIssuePreflightVerificationRequest::new(
                at(40),
                ProofUse::SatisfyStepUp,
                &email_proof,
                &response,
            ),
        )
        .expect_err("Hashcash preflight must bind the requested proof use");
    assert!(matches!(
        wrong_use_error,
        Error::WeakProofGateVerificationFailed
    ));

    let totp_method =
        ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp").expect("TOTP method");
    let wrong_method_error = verifier
        .verify_challenge_issue_preflight_before_state_load(
            ChallengeIssuePreflightVerificationRequest::new(
                at(40),
                ProofUse::ContributeToFullAuthentication,
                &totp_method.verified_proof_summary(),
                &response,
            ),
        )
        .expect_err("Hashcash preflight must bind the requested proof method");
    assert!(matches!(
        wrong_method_error,
        Error::WeakProofGateVerificationFailed
    ));
}

#[test]
fn hashcash_response_expires_before_state_load() {
    let verifier = hashcash_verifier_for_test();
    let proof = ProofMethodDeclaration::new_online_guessable(
        ProofFamily::MessageSignature,
        "password_derived_signature",
    )
    .expect("password-derived signature method")
    .verified_proof_summary();
    let continuation = ActiveProofContinuationCookieDraft {
        attempt_id: id("hashcash-expiry-attempt"),
        proof_use: ProofUse::SatisfyStepUp,
        subject_id: Some(id("hashcash-expiry-subject")),
        subject_binding: ActiveProofContinuationSubjectBinding::RuntimeBoundSubject,
        attempt_fast_fail_until: at(120),
    };
    let secret_response =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"123456".as_slice())
            .expect("known-subject secret response");
    let binding = WeakProofGateBinding::for_known_subject_secret_response(
        &continuation,
        &proof,
        &secret_response,
    )
    .expect("known-subject weak-gate binding");
    let response = proof_of_work_gate_response_for_test(at(10), &proof, &binding);

    let expired_error = verifier
        .verify_weak_proof_gate_before_state_load(
            WeakProofGateVerificationRequest::new_with_binding(
                at(70),
                &proof,
                &response,
                Some(&binding),
            ),
        )
        .expect_err("Hashcash response must not verify at its expiry boundary");
    assert!(matches!(
        expired_error,
        Error::WeakProofGateVerificationFailed
    ));
}

#[test]
fn human_challenge_adapter_receives_runtime_owned_strong_proof_binding() {
    let summary = WeakProofGateSummary::new(WeakProofGateKind::HumanChallenge, "turnstile")
        .expect("human challenge summary");
    let proof = ProofMethodDeclaration::new_online_guessable(
        ProofFamily::MessageSignature,
        "password_derived_signature",
    )
    .expect("password-derived signature method")
    .verified_proof_summary();
    let challenge = ActiveProofMethodChallengeMaterial {
        attempt_id: id("human-gate-attempt"),
        challenge_id: id("human-gate-challenge"),
        proof: proof.clone(),
        issued_at: at(20),
        expires_at: at(80),
        nonce: ActiveProofChallengeFastFailNonce::from_bytes(
            &[7_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
        )
        .expect("challenge nonce"),
        method_challenge_state: ActiveProofMethodChallengeState::try_from_bytes(
            b"sealed-password-verifier-state".as_slice(),
        )
        .expect("method challenge state"),
    };
    let first_response =
        ActiveProofMethodResponsePayload::try_from_bytes(b"first-submitted-signature".as_slice())
            .expect("first response payload");
    let first_binding =
        WeakProofGateBinding::for_active_method_response(&challenge, &first_response)
            .expect("first weak-gate binding");
    let second_response =
        ActiveProofMethodResponsePayload::try_from_bytes(b"second-submitted-signature".as_slice())
            .expect("second response payload");
    let second_binding =
        WeakProofGateBinding::for_active_method_response(&challenge, &second_response)
            .expect("second weak-gate binding");
    let gate_response = WeakProofGateResponse::try_from_bytes(
        summary.kind(),
        summary.method_label(),
        b"provider-token-for-first-signature".as_slice(),
    )
    .expect("human challenge response");
    let call_count = Arc::new(AtomicUsize::new(0));
    let adapter_summary = summary.clone();
    let adapter_proof = proof.clone();
    let adapter_call_count = Arc::clone(&call_count);
    let adapter = WeakProofGateAdapter::new(summary.clone(), move |request| {
        adapter_call_count.fetch_add(1, Ordering::SeqCst);
        if request.now() != at(30)
            || request.proof() != &adapter_proof
            || request.response_summary() != &adapter_summary
            || request.response_payload() != b"provider-token-for-first-signature"
        {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        match request.context() {
            WeakProofGateAdapterVerificationContext::StrongProof { binding }
                if binding == &first_binding =>
            {
                Ok(())
            }
            WeakProofGateAdapterVerificationContext::StrongProof { .. }
            | WeakProofGateAdapterVerificationContext::ChallengeIssuePreflight { .. } => {
                Err(Error::WeakProofGateVerificationFailed)
            }
        }
    })
    .expect("human challenge adapter");
    let registry = WeakProofGateAdapterRegistry::new([adapter]).expect("weak gate registry");

    let missing_binding_error = registry
        .verify_weak_proof_gate_before_state_load(WeakProofGateVerificationRequest::new(
            at(30),
            &proof,
            &gate_response,
        ))
        .expect_err("adapter weak gates must require runtime-derived binding");
    assert!(matches!(
        missing_binding_error,
        Error::WeakProofGateVerificationFailed
    ));
    assert_eq!(call_count.load(Ordering::SeqCst), 0);

    registry
        .verify_weak_proof_gate_before_state_load(
            WeakProofGateVerificationRequest::new_with_binding(
                at(30),
                &proof,
                &gate_response,
                Some(&first_binding),
            ),
        )
        .expect("human challenge adapter verifies exact binding");
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    let wrong_binding_error = registry
        .verify_weak_proof_gate_before_state_load(
            WeakProofGateVerificationRequest::new_with_binding(
                at(30),
                &proof,
                &gate_response,
                Some(&second_binding),
            ),
        )
        .expect_err("human challenge adapter must see wrong proof-material binding");
    assert!(matches!(
        wrong_binding_error,
        Error::WeakProofGateVerificationFailed
    ));
    assert_eq!(call_count.load(Ordering::SeqCst), 2);
}

#[test]
fn risk_decision_adapter_receives_challenge_issue_preflight_context() {
    let summary = WeakProofGateSummary::new(WeakProofGateKind::RiskDecision, "risk_engine")
        .expect("risk decision summary");
    let email_method = ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
        .expect("email OTP method");
    let email_proof = email_method.verified_proof_summary();
    let response = ChallengeIssuePreflightResponse::try_from_bytes(
        summary.kind(),
        summary.method_label(),
        b"risk-engine-allows-email-full-auth".as_slice(),
    )
    .expect("risk decision response");
    let adapter_summary = summary.clone();
    let adapter_proof = email_proof.clone();
    let adapter = WeakProofGateAdapter::new(summary.clone(), move |request| {
        if request.response_summary() != &adapter_summary
            || request.response_payload() != b"risk-engine-allows-email-full-auth"
            || request.proof() != &adapter_proof
        {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        match request.context() {
            WeakProofGateAdapterVerificationContext::ChallengeIssuePreflight {
                proof_use: ProofUse::ContributeToFullAuthentication,
            } => Ok(()),
            WeakProofGateAdapterVerificationContext::ChallengeIssuePreflight { .. }
            | WeakProofGateAdapterVerificationContext::StrongProof { .. } => {
                Err(Error::WeakProofGateVerificationFailed)
            }
        }
    })
    .expect("risk decision adapter");
    let registry = WeakProofGateAdapterRegistry::new([adapter]).expect("weak gate registry");

    registry
        .verify_challenge_issue_preflight_before_state_load(
            ChallengeIssuePreflightVerificationRequest::new(
                at(40),
                ProofUse::ContributeToFullAuthentication,
                &email_proof,
                &response,
            ),
        )
        .expect("risk decision adapter verifies exact preflight context");

    let wrong_use_error = registry
        .verify_challenge_issue_preflight_before_state_load(
            ChallengeIssuePreflightVerificationRequest::new(
                at(40),
                ProofUse::SatisfyStepUp,
                &email_proof,
                &response,
            ),
        )
        .expect_err("risk decision adapter must see the requested proof use");
    assert!(matches!(
        wrong_use_error,
        Error::WeakProofGateVerificationFailed
    ));

    let totp_proof = ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
        .expect("TOTP method")
        .verified_proof_summary();
    let wrong_method_error = registry
        .verify_challenge_issue_preflight_before_state_load(
            ChallengeIssuePreflightVerificationRequest::new(
                at(40),
                ProofUse::ContributeToFullAuthentication,
                &totp_proof,
                &response,
            ),
        )
        .expect_err("risk decision adapter must see the requested proof method");
    assert!(matches!(
        wrong_method_error,
        Error::WeakProofGateVerificationFailed
    ));
}

#[test]
fn weak_gate_adapter_registry_fails_closed_for_unsupported_or_ambiguous_gates() {
    let human_summary = WeakProofGateSummary::new(WeakProofGateKind::HumanChallenge, "turnstile")
        .expect("human challenge summary");
    let adapter = WeakProofGateAdapter::new(human_summary.clone(), |_| Ok(()))
        .expect("human challenge adapter");

    let duplicate_error = WeakProofGateAdapterRegistry::new([adapter.clone(), adapter.clone()])
        .expect_err("duplicate weak-gate adapters must be rejected");
    assert!(matches!(duplicate_error, Error::InvalidConfig(_)));

    let proof_of_work_summary =
        WeakProofGateSummary::new(WeakProofGateKind::ProofOfWork, "hashcash")
            .expect("proof of work summary");
    let proof_of_work_adapter_error = WeakProofGateAdapter::new(proof_of_work_summary, |_| Ok(()))
        .expect_err("adapter callbacks must not impersonate native proof-of-work");
    assert!(matches!(
        proof_of_work_adapter_error,
        Error::InvalidConfig(_)
    ));

    let registry = WeakProofGateAdapterRegistry::new([adapter]).expect("weak gate registry");
    let proof = ProofMethodDeclaration::new_online_guessable(
        ProofFamily::MessageSignature,
        "password_derived_signature",
    )
    .expect("password-derived signature method")
    .verified_proof_summary();
    let other_response =
        WeakProofGateResponse::try_from_bytes(WeakProofGateKind::HumanChallenge, "recaptcha", b"x")
            .expect("unregistered weak-gate response");
    let binding = WeakProofGateBinding::for_known_subject_secret_response(
        &ActiveProofContinuationCookieDraft {
            attempt_id: id("unregistered-gate-attempt"),
            proof_use: ProofUse::ContributeToFullAuthentication,
            subject_id: Some(id("unregistered-gate-subject")),
            subject_binding: ActiveProofContinuationSubjectBinding::RuntimeBoundSubject,
            attempt_fast_fail_until: at(100),
        },
        &proof,
        &KnownSubjectActiveProofSecretResponse::try_from_bytes(b"123456".as_slice())
            .expect("known-subject response"),
    )
    .expect("known-subject weak-gate binding");
    let unregistered_error = registry
        .verify_weak_proof_gate_before_state_load(
            WeakProofGateVerificationRequest::new_with_binding(
                at(50),
                &proof,
                &other_response,
                Some(&binding),
            ),
        )
        .expect_err("unregistered weak-gate responses must fail closed");
    assert!(matches!(
        unregistered_error,
        Error::WeakProofGateVerificationFailed
    ));
}
