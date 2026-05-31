use super::*;

#[test]
fn state_dependent_mutations_have_commit_time_guards() {
    let plans = vec![
        (
            "start active proof attempt",
            reduced_plan(
                Command::StartActiveProofAttempt(StartActiveProofAttempt {
                    now: at(20),
                    attempt_id: id("attempt"),
                    proof_use: ProofUse::ContributeToFullAuthentication,
                    subject_id: Some(id("subject")),
                }),
                &LoadedState::default(),
            ),
        ),
        (
            "issue out-of-band challenge",
            reduced_plan(
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
            ),
        ),
        (
            "complete out-of-band challenge",
            reduced_plan(
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
                &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
            ),
        ),
        (
            "resend out-of-band challenge",
            reduced_plan(
                Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
                    now: at(40),
                    attempt_id: id("attempt"),
                    challenge_id: id("challenge"),
                    idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
                    method_commit_work: Vec::new(),
                }),
                &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
            ),
        ),
        (
            "record weak proof failure",
            reduced_plan(
                Command::RecordActiveProofFailure(RecordActiveProofFailure {
                    now: at(40),
                    attempt_id: id("attempt"),
                    method: proof_method(ProofFamily::SharedSecretOtp),
                    weak_proof_gate: verified_proof_of_work_gate(),
                }),
                &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
            ),
        ),
        ("delete failed attempt at budget", {
            let mut attempt = active_attempt(ProofUse::ContributeToFullAuthentication);
            attempt.weak_proof_failures = 2;
            reduced_plan(
                Command::RecordActiveProofFailure(RecordActiveProofFailure {
                    now: at(40),
                    attempt_id: id("attempt"),
                    method: proof_method(ProofFamily::SharedSecretOtp),
                    weak_proof_gate: verified_proof_of_work_gate(),
                }),
                &LoadedState {
                    active_proof_attempt_record: Some(attempt),
                    subject_revocations: no_subject_revocations(),
                    ..LoadedState::default()
                },
            )
        }),
        (
            "refresh session",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(85),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &loaded_session(100),
            ),
        ),
        (
            "trusted-device silent revival",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(100),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: Some(id("new-session")),
                }),
                &loaded_trusted_device(500, 1_000),
            ),
        ),
        (
            "complete step-up",
            reduced_plan(
                Command::CompleteStepUp(CompleteStepUp {
                    now: at(50),
                    attempt_id: id("attempt"),
                }),
                &loaded_session_and_attempt(
                    200,
                    ProofUse::SatisfyStepUp,
                    vec![proof(ProofFamily::SharedSecretOtp)],
                ),
            ),
        ),
        (
            "complete full authentication",
            reduced_plan(
                Command::CompleteFullAuthentication(CompleteFullAuthentication {
                    now: at(20),
                    attempt_id: id("attempt"),
                    fresh_session_id: id("session"),
                    trust_device: Some(TrustDeviceAfterFullAuthentication {
                        device_credential_id: id("device"),
                        display_label: Some("laptop".to_owned()),
                    }),
                }),
                &loaded_attempt_with_satisfied_proofs(
                    ProofUse::ContributeToFullAuthentication,
                    vec![proof(ProofFamily::OutOfBandCode)],
                ),
            ),
        ),
        (
            "trusted-device active-proof revival",
            reduced_plan(
                Command::CompleteTrustedDeviceRevivalWithActiveProof(
                    CompleteTrustedDeviceRevivalWithActiveProof {
                        now: at(600),
                        attempt_id: id("attempt"),
                        fresh_session_id: id("new-session"),
                    },
                ),
                &loaded_trusted_device_and_attempt(
                    500,
                    2_000,
                    ProofUse::ReviveTrustedDeviceWithActiveProof,
                    vec![proof(ProofFamily::MessageSignature)],
                ),
            ),
        ),
        (
            "logout current session",
            reduced_plan(
                Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
                &loaded_session(200),
            ),
        ),
        (
            "revoke noncurrent session",
            reduced_plan(
                Command::RevokeSession(RevokeSession {
                    now: at(50),
                    subject_id: id("subject"),
                    session_id: id("other-session"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &loaded_session(200),
            ),
        ),
        (
            "revoke trusted device",
            reduced_plan(
                Command::RevokeTrustedDevice(RevokeTrustedDevice {
                    now: at(50),
                    subject_id: id("subject"),
                    device_credential_id: id("device"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &loaded_trusted_device(500, 1_000),
            ),
        ),
        (
            "revoke subject auth state",
            reduced_plan(
                Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                    now: at(50),
                    subject_id: id("subject"),
                    reason: RevocationReason::SubjectAuthStateChanged,
                }),
                &loaded_session(200),
            ),
        ),
    ];

    for (plan_name, plan) in plans {
        assert_state_dependent_mutations_have_commit_time_guards(plan_name, &plan);
    }
}

#[test]
fn command_commit_guard_matrix_is_stable() {
    let cases = vec![
        (
            "start active proof attempt",
            reduced_plan(
                Command::StartActiveProofAttempt(StartActiveProofAttempt {
                    now: at(20),
                    attempt_id: id("attempt"),
                    proof_use: ProofUse::ContributeToFullAuthentication,
                    subject_id: Some(id("subject")),
                }),
                &LoadedState::default(),
            ),
            vec![],
        ),
        (
            "issue out-of-band challenge",
            reduced_plan(
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
            ),
            vec![
                "active_proof_attempt_still_open",
                "no_open_out_of_band_challenge_for_dedupe_key",
            ],
        ),
        (
            "complete stateful active proof",
            reduced_plan(
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
                &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
            ),
            vec![
                "active_proof_challenge_still_open",
                "active_proof_attempt_still_open",
            ],
        ),
        (
            "resend out-of-band challenge",
            reduced_plan(
                Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
                    now: at(40),
                    attempt_id: id("attempt"),
                    challenge_id: id("challenge"),
                    idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
                    method_commit_work: Vec::new(),
                }),
                &loaded_attempt_and_challenge_state(ProofUse::ContributeToFullAuthentication),
            ),
            vec![
                "active_proof_attempt_still_open",
                "out_of_band_challenge_resend_still_allowed",
            ],
        ),
        (
            "complete stateless active proof",
            reduced_plan(
                Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
                    now: at(40),
                    attempt_id: id("attempt"),
                    challenge_id: None,
                    verified_proof: verified_proof(
                        ProofFamily::MessageSignature,
                        Some(id("subject")),
                    ),
                    stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                    weak_proof_gate: verified_proof_of_work_gate(),
                    method_commit_work: Vec::new(),
                }),
                &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
            ),
            vec!["active_proof_attempt_still_open"],
        ),
        (
            "record weak proof failure",
            reduced_plan(
                Command::RecordActiveProofFailure(RecordActiveProofFailure {
                    now: at(40),
                    attempt_id: id("attempt"),
                    method: proof_method(ProofFamily::SharedSecretOtp),
                    weak_proof_gate: verified_proof_of_work_gate(),
                }),
                &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
            ),
            vec!["active_proof_attempt_still_open"],
        ),
        (
            "full authentication",
            reduced_plan(
                Command::CompleteFullAuthentication(CompleteFullAuthentication {
                    now: at(20),
                    attempt_id: id("attempt"),
                    fresh_session_id: id("session"),
                    trust_device: Some(TrustDeviceAfterFullAuthentication {
                        device_credential_id: id("device"),
                        display_label: Some("laptop".to_owned()),
                    }),
                }),
                &loaded_attempt_with_satisfied_proofs(
                    ProofUse::ContributeToFullAuthentication,
                    vec![proof(ProofFamily::OutOfBandCode)],
                ),
            ),
            vec!["active_proof_attempt_still_open"],
        ),
        (
            "session refresh",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(85),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: None,
                }),
                &loaded_session(100),
            ),
            vec!["session_still_matches"],
        ),
        (
            "trusted-device silent revival",
            reduced_plan(
                Command::ResolveRequest(ResolveRequest {
                    now: at(100),
                    request_kind: RequestKind::StateChanging,
                    fresh_session_id: Some(id("new-session")),
                }),
                &loaded_trusted_device(500, 1_000),
            ),
            vec![
                "trusted_device_belongs_to_subject",
                "trusted_device_still_matches",
            ],
        ),
        (
            "step-up",
            reduced_plan(
                Command::CompleteStepUp(CompleteStepUp {
                    now: at(50),
                    attempt_id: id("attempt"),
                }),
                &loaded_session_and_attempt(
                    200,
                    ProofUse::SatisfyStepUp,
                    vec![proof(ProofFamily::SharedSecretOtp)],
                ),
            ),
            vec!["session_still_matches", "active_proof_attempt_still_open"],
        ),
        (
            "trusted-device active-proof revival",
            reduced_plan(
                Command::CompleteTrustedDeviceRevivalWithActiveProof(
                    CompleteTrustedDeviceRevivalWithActiveProof {
                        now: at(600),
                        attempt_id: id("attempt"),
                        fresh_session_id: id("new-session"),
                    },
                ),
                &loaded_trusted_device_and_attempt(
                    500,
                    2_000,
                    ProofUse::ReviveTrustedDeviceWithActiveProof,
                    vec![proof(ProofFamily::MessageSignature)],
                ),
            ),
            vec![
                "trusted_device_belongs_to_subject",
                "trusted_device_still_matches",
                "active_proof_attempt_still_open",
            ],
        ),
        (
            "logout current session",
            reduced_plan(
                Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
                &loaded_session(200),
            ),
            vec!["session_still_matches"],
        ),
        (
            "revoke session",
            reduced_plan(
                Command::RevokeSession(RevokeSession {
                    now: at(50),
                    subject_id: id("subject"),
                    session_id: id("session"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &LoadedState::default(),
            ),
            vec!["session_belongs_to_subject"],
        ),
        (
            "revoke trusted device",
            reduced_plan(
                Command::RevokeTrustedDevice(RevokeTrustedDevice {
                    now: at(50),
                    subject_id: id("subject"),
                    device_credential_id: id("device"),
                    reason: RevocationReason::RemoteRevocation,
                }),
                &LoadedState::default(),
            ),
            vec!["trusted_device_belongs_to_subject"],
        ),
        (
            "revoke subject auth state",
            reduced_plan(
                Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
                    now: at(50),
                    subject_id: id("subject"),
                    reason: RevocationReason::SubjectAuthStateChanged,
                }),
                &LoadedState::default(),
            ),
            vec![],
        ),
    ];

    for (case_name, plan, expected_precondition_kinds) in cases {
        assert_eq!(
            precondition_kind_names(&plan),
            expected_precondition_kinds,
            "{case_name}"
        );
    }
}

#[test]
fn commands_reject_missing_required_loaded_state_before_planning_mutations() {
    let issue_challenge_without_attempt = reduce_command(
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
        &LoadedState::default(),
    )
    .expect_err("issuing a challenge requires a loaded attempt");
    assert_eq!(
        issue_challenge_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let complete_proof_without_attempt = reduce_command(
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
        &LoadedState::default(),
    )
    .expect_err("completing a proof requires a loaded attempt");
    assert_eq!(
        complete_proof_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let complete_stateful_proof_without_challenge = reduce_command(
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
    .expect_err("stateful proof completion requires a loaded challenge");
    assert_eq!(
        complete_stateful_proof_without_challenge,
        Error::LoadedStateContradiction("active-proof challenge record missing")
    );

    let resend_without_attempt = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &LoadedState::default(),
    )
    .expect_err("resending a challenge requires a loaded attempt");
    assert_eq!(
        resend_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let resend_without_challenge = reduce_command(
        &config(),
        Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
            now: at(40),
            attempt_id: id("attempt"),
            challenge_id: id("challenge"),
            idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::ContributeToFullAuthentication),
    )
    .expect_err("resending a challenge requires a loaded challenge");
    assert_eq!(
        resend_without_challenge,
        Error::LoadedStateContradiction("active-proof challenge record missing")
    );

    let record_failure_without_attempt = reduce_command(
        &config(),
        Command::RecordActiveProofFailure(RecordActiveProofFailure {
            now: at(40),
            attempt_id: id("attempt"),
            method: proof_method(ProofFamily::SharedSecretOtp),
            weak_proof_gate: verified_proof_of_work_gate(),
        }),
        &LoadedState::default(),
    )
    .expect_err("recording proof failure requires a loaded attempt");
    assert_eq!(
        record_failure_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let full_auth_without_attempt = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &LoadedState::default(),
    )
    .expect_err("full authentication requires a loaded attempt");
    assert_eq!(
        full_auth_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let step_up_without_session_cookie = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &LoadedState {
            session_record: Some(session_record(200)),
            session_secret_match: Some(loaded_session_secret_match(StoredSecretMatch::Current)),
            active_proof_attempt_record: Some(active_attempt_with_satisfied_proofs(
                ProofUse::SatisfyStepUp,
                vec![proof(ProofFamily::SharedSecretOtp)],
            )),
            ..LoadedState::default()
        },
    )
    .expect_err("loaded step-up session record requires its cookie");
    assert_eq!(
        step_up_without_session_cookie,
        Error::LoadedStateContradiction("step-up completion requires session cookie")
    );

    let step_up_without_secret_match = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &LoadedState {
            session_cookie: Some(session_cookie(200)),
            session_record: Some(session_record(200)),
            subject_revocations: no_subject_revocations(),
            active_proof_attempt_record: Some(active_attempt_with_satisfied_proofs(
                ProofUse::SatisfyStepUp,
                vec![proof(ProofFamily::SharedSecretOtp)],
            )),
            ..LoadedState::default()
        },
    )
    .expect_err("loaded step-up session record requires secret classification");
    assert_eq!(
        step_up_without_secret_match,
        Error::LoadedStateContradiction("step-up completion requires session secret match")
    );

    let step_up_without_attempt = reduce_command(
        &config(),
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session(200),
    )
    .expect_err("step-up requires a loaded active-proof attempt");
    assert_eq!(
        step_up_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let trusted_device_revival_without_cookie = reduce_command(
        &config(),
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &LoadedState {
            trusted_device_record: Some(trusted_device_record(500, 2_000)),
            trusted_device_secret_match: Some(loaded_trusted_device_secret_match(
                StoredSecretMatch::Current,
            )),
            active_proof_attempt_record: Some(active_attempt_with_satisfied_proofs(
                ProofUse::ReviveTrustedDeviceWithActiveProof,
                vec![proof(ProofFamily::MessageSignature)],
            )),
            ..LoadedState::default()
        },
    )
    .expect_err("loaded trusted-device record requires its cookie");
    assert_eq!(
        trusted_device_revival_without_cookie,
        Error::LoadedStateContradiction(
            "trusted-device active-proof completion requires trusted-device cookie",
        )
    );

    let trusted_device_revival_without_secret_match = reduce_command(
        &config(),
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &LoadedState {
            trusted_device_cookie: Some(trusted_device_cookie(500, 2_000)),
            trusted_device_record: Some(trusted_device_record(500, 2_000)),
            subject_revocations: no_subject_revocations(),
            active_proof_attempt_record: Some(active_attempt_with_satisfied_proofs(
                ProofUse::ReviveTrustedDeviceWithActiveProof,
                vec![proof(ProofFamily::MessageSignature)],
            )),
            ..LoadedState::default()
        },
    )
    .expect_err("loaded trusted-device record requires secret classification");
    assert_eq!(
        trusted_device_revival_without_secret_match,
        Error::LoadedStateContradiction(
            "trusted-device active-proof completion requires trusted-device secret match",
        )
    );

    let trusted_device_revival_without_attempt = reduce_command(
        &config(),
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &loaded_trusted_device(500, 2_000),
    )
    .expect_err("trusted-device active revival requires a loaded attempt");
    assert_eq!(
        trusted_device_revival_without_attempt,
        Error::LoadedStateContradiction("active-proof attempt record missing")
    );

    let logout_without_cookie = reduce_command(
        &config(),
        Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
        &LoadedState {
            session_record: Some(session_record(200)),
            session_secret_match: Some(loaded_session_secret_match(StoredSecretMatch::Current)),
            ..LoadedState::default()
        },
    )
    .expect_err("loaded logout session record requires its cookie");
    assert_eq!(
        logout_without_cookie,
        Error::LoadedStateContradiction(
            "logout requires session cookie when session record is loaded"
        )
    );

    let logout_without_secret_match = reduce_command(
        &config(),
        Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
        &LoadedState {
            session_cookie: Some(session_cookie(200)),
            session_record: Some(session_record(200)),
            ..LoadedState::default()
        },
    )
    .expect_err("loaded logout session record requires secret classification");
    assert_eq!(
        logout_without_secret_match,
        Error::LoadedStateContradiction(
            "logout requires session secret match when session record is loaded"
        )
    );
}
