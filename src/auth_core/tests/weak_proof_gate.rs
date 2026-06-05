use super::*;

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
