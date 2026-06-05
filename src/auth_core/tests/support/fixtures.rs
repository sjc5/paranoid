use super::*;

pub(super) fn id<K>(label: &str) -> Id<K> {
    Id::from_bytes(label.as_bytes().to_vec()).expect("id")
}

pub(super) fn version(version: u64) -> SecretVersion {
    SecretVersion::new(version).expect("version")
}

pub(super) fn verified_stateless_fast_fail() -> StatelessFastFailStatus {
    StatelessFastFailStatus::verified_before_state_load()
}

pub(super) fn active_proof_challenge_cookie() -> ActiveProofChallengeCookieDraft {
    active_proof_challenge_cookie_for_issue("attempt", "challenge", at(30), at(70))
}

pub(super) fn active_proof_challenge_cookie_for_issue(
    attempt_id: &str,
    challenge_id: &str,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> ActiveProofChallengeCookieDraft {
    active_proof_challenge_cookie_for_issue_proof(
        attempt_id,
        challenge_id,
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        issued_at,
        expires_at,
    )
}

pub(super) fn active_proof_challenge_cookie_for_issue_proof(
    attempt_id: &str,
    challenge_id: &str,
    proof: ProofSummary,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> ActiveProofChallengeCookieDraft {
    let mut mac = vec![17_u8; crate::crypto::MAC_OVER_SECRET_SIZE];
    mac[0] = 1;
    ActiveProofChallengeCookieDraft::new(
        ActiveProofChallengeCookieContext::new(
            id(attempt_id),
            id(challenge_id),
            proof,
            issued_at,
            expires_at,
            ActiveProofChallengeFastFailNonce::from_bytes(
                &[23_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
            )
            .expect("nonce"),
        )
        .expect("challenge cookie context"),
        ActiveProofChallengeFastFailMac::from_bytes(&mac).expect("mac"),
    )
    .expect("challenge cookie")
}

pub(super) fn fresh_session_secret(session_id: &str, secret_version: u64) -> FreshCredentialSecret {
    FreshCredentialSecret::Session {
        session_id: id(session_id),
        secret_version: version(secret_version),
    }
}

pub(super) fn fresh_trusted_device_secret(
    device_credential_id: &str,
    secret_version: u64,
) -> FreshCredentialSecret {
    FreshCredentialSecret::TrustedDevice {
        device_credential_id: id(device_credential_id),
        secret_version: version(secret_version),
    }
}

pub(super) fn at(seconds: u64) -> UnixSeconds {
    UnixSeconds::new(seconds)
}

pub(super) fn config() -> Config {
    Config {
        short_session_lifetime: DurationSeconds::new(100),
        session_refresh_window: DurationSeconds::new(20),
        trusted_device_silent_revival_lifetime: DurationSeconds::new(500),
        trusted_device_credential_lifetime: DurationSeconds::new(1_000),
        step_up_lifetime: DurationSeconds::new(30),
        safe_read_cache_lifetime: Some(DurationSeconds::new(10)),
        stale_secret_grace_lifetime: DurationSeconds::new(5),
        active_proof_attempt_lifetime: DurationSeconds::new(120),
        out_of_band_challenge_lifetime: DurationSeconds::new(40),
        max_out_of_band_challenge_resends_per_challenge: 1,
        max_weak_proof_failures_per_attempt: 3,
        unauthenticated_challenge_issue_preflight_gate: proof_of_work_gate_summary(),
        proof_policy: default_proof_policy(),
    }
}

pub(super) fn default_proof_policy() -> ProofPolicy {
    ProofPolicy::safe_defaults_for_exact_methods(
        ProofPolicyExactMethodLabels::new(
            "email_otp",
            "password_signature",
            "totp",
            "recovery_code",
        )
        .expect("exact method labels"),
    )
    .expect("proof policy")
}

pub(super) fn reduced_plan(command: Command, loaded: &LoadedState) -> CommitPlan {
    reduce_command(&config(), command, loaded)
        .expect("transition")
        .commit_plan
}

pub(super) fn session_record(expires_at: u64) -> SessionRecord {
    SessionRecord {
        session_id: id("session"),
        subject_id: id("subject"),
        device_credential_id: None,
        current_secret_version: version(3),
        previous_secret_version: Some(version(2)),
        previous_secret_accept_until: Some(at(55)),
        created_at: at(0),
        refreshed_at: at(0),
        expires_at: at(expires_at),
        step_up_expires_at: None,
        revoked_at: None,
    }
}

pub(super) fn session_cookie(expires_at: u64) -> SessionCookieDraft {
    SessionCookieDraft {
        session_id: id("session"),
        subject_id: id("subject"),
        secret_version: version(3),
        session_fast_fail_until: at(expires_at),
        safe_read_valid_until: None,
        step_up_valid_until: None,
    }
}

pub(super) fn loaded_session(expires_at: u64) -> LoadedState {
    LoadedState {
        session_cookie: Some(session_cookie(expires_at)),
        session_record: Some(session_record(expires_at)),
        session_secret_match: Some(loaded_session_secret_match(StoredSecretMatch::Current)),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    }
}

pub(super) fn loaded_session_secret_match(kind: StoredSecretMatch) -> LoadedSessionSecretMatch {
    LoadedSessionSecretMatch::new(id("session"), kind)
}

pub(super) fn subject_revocation(
    revoke_records_created_at_or_before: u64,
) -> SubjectRevocationState {
    SubjectRevocationState {
        revoke_records_created_at_or_before: at(revoke_records_created_at_or_before),
    }
}

pub(super) fn no_subject_revocations() -> LoadedSubjectRevocations {
    LoadedSubjectRevocations::loaded(id("subject"), None)
}

pub(super) fn loaded_subject_revocations(
    revoke_records_created_at_or_before: u64,
) -> LoadedSubjectRevocations {
    LoadedSubjectRevocations::loaded(
        id("subject"),
        Some(subject_revocation(revoke_records_created_at_or_before)),
    )
}

pub(super) fn with_no_subject_revocations(mut loaded: LoadedState) -> LoadedState {
    loaded.subject_revocations = no_subject_revocations();
    loaded
}

pub(super) fn trusted_device_record(
    silent_revival_until: u64,
    expires_at: u64,
) -> TrustedDeviceCredentialRecord {
    TrustedDeviceCredentialRecord {
        device_credential_id: id("device"),
        subject_id: id("subject"),
        current_secret_version: version(8),
        previous_secret_version: None,
        previous_secret_accept_until: None,
        created_at: at(0),
        last_used_at: at(10),
        expires_at: at(expires_at),
        silent_revival_until: at(silent_revival_until),
        revoked_at: None,
        display_label: Some("browser".to_owned()),
    }
}

pub(super) fn trusted_device_cookie(
    silent_revival_until: u64,
    expires_at: u64,
) -> TrustedDeviceCookieDraft {
    TrustedDeviceCookieDraft {
        device_credential_id: id("device"),
        subject_id: id("subject"),
        secret_version: version(8),
        device_fast_fail_until: at(expires_at),
        silent_revival_fast_fail_until: at(silent_revival_until),
    }
}

pub(super) fn loaded_trusted_device(silent_revival_until: u64, expires_at: u64) -> LoadedState {
    LoadedState {
        trusted_device_cookie: Some(trusted_device_cookie(silent_revival_until, expires_at)),
        trusted_device_record: Some(trusted_device_record(silent_revival_until, expires_at)),
        trusted_device_secret_match: Some(loaded_trusted_device_secret_match(
            StoredSecretMatch::Current,
        )),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    }
}

pub(super) fn loaded_trusted_device_secret_match(
    kind: StoredSecretMatch,
) -> LoadedTrustedDeviceSecretMatch {
    LoadedTrustedDeviceSecretMatch::new(id("device"), kind)
}

pub(super) fn dedupe_key(value: &str) -> OutOfBandChallengeDedupeKey {
    OutOfBandChallengeDedupeKey::new(value).expect("dedupe key")
}

pub(super) fn active_attempt(proof_use: ProofUse) -> ActiveProofAttemptRecord {
    ActiveProofAttemptRecord {
        attempt_id: id("attempt"),
        proof_use,
        subject_id: Some(id("subject")),
        satisfied_proofs: Vec::new(),
        weak_proof_failures: 0,
        max_weak_proof_failures: 3,
        created_at: at(10),
        expires_at: at(130),
        closed_at: None,
    }
}

pub(super) fn active_attempt_with_satisfied_proofs(
    proof_use: ProofUse,
    satisfied_proofs: Vec<ProofSummary>,
) -> ActiveProofAttemptRecord {
    active_attempt_with_satisfied_proof_records(
        proof_use,
        satisfied_proofs
            .into_iter()
            .map(SatisfiedProof::new_without_source)
            .collect(),
    )
}

pub(super) fn active_attempt_with_satisfied_proof_records(
    proof_use: ProofUse,
    satisfied_proofs: Vec<SatisfiedProof>,
) -> ActiveProofAttemptRecord {
    ActiveProofAttemptRecord {
        satisfied_proofs,
        ..active_attempt(proof_use)
    }
}

pub(super) fn unbound_active_attempt(proof_use: ProofUse) -> ActiveProofAttemptRecord {
    ActiveProofAttemptRecord {
        subject_id: None,
        ..active_attempt(proof_use)
    }
}

pub(super) fn out_of_band_challenge() -> ActiveProofChallengeRecord {
    ActiveProofChallengeRecord {
        challenge_id: id("challenge"),
        attempt_id: id("attempt"),
        proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        challenge_dedupe_key: Some(dedupe_key("login:email-hash:window")),
        recipient_handle: Some("opaque-email-handle".to_owned()),
        used_delivery_idempotency_keys: vec!["mail-idempotency-key".to_owned()],
        resend_count: 0,
        max_resends: 1,
        requires_stateless_fast_fail: true,
        created_at: at(20),
        expires_at: at(60),
        closed_at: None,
    }
}

pub(super) fn loaded_attempt_state(proof_use: ProofUse) -> LoadedState {
    LoadedState {
        active_proof_attempt_record: Some(active_attempt(proof_use)),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    }
}

pub(super) fn loaded_attempt_and_challenge_state(proof_use: ProofUse) -> LoadedState {
    LoadedState {
        active_proof_attempt_record: Some(active_attempt(proof_use)),
        active_proof_challenge_record: Some(out_of_band_challenge()),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    }
}

pub(super) fn loaded_attempt_with_satisfied_proofs(
    proof_use: ProofUse,
    satisfied_proofs: Vec<ProofSummary>,
) -> LoadedState {
    loaded_attempt_with_satisfied_proof_records(
        proof_use,
        satisfied_proofs
            .into_iter()
            .map(SatisfiedProof::new_without_source)
            .collect(),
    )
}

pub(super) fn loaded_attempt_with_satisfied_proof_records(
    proof_use: ProofUse,
    satisfied_proofs: Vec<SatisfiedProof>,
) -> LoadedState {
    LoadedState {
        active_proof_attempt_record: Some(active_attempt_with_satisfied_proof_records(
            proof_use,
            satisfied_proofs,
        )),
        subject_revocations: no_subject_revocations(),
        ..LoadedState::default()
    }
}

pub(super) fn loaded_session_and_attempt(
    expires_at: u64,
    proof_use: ProofUse,
    satisfied_proofs: Vec<ProofSummary>,
) -> LoadedState {
    loaded_session_and_attempt_with_satisfied_proof_records(
        expires_at,
        proof_use,
        satisfied_proofs
            .into_iter()
            .map(SatisfiedProof::new_without_source)
            .collect(),
    )
}

pub(super) fn loaded_session_and_attempt_with_satisfied_proof_records(
    expires_at: u64,
    proof_use: ProofUse,
    satisfied_proofs: Vec<SatisfiedProof>,
) -> LoadedState {
    LoadedState {
        active_proof_attempt_record: Some(active_attempt_with_satisfied_proof_records(
            proof_use,
            satisfied_proofs,
        )),
        ..loaded_session(expires_at)
    }
}

pub(super) fn loaded_trusted_device_and_attempt(
    silent_revival_until: u64,
    expires_at: u64,
    proof_use: ProofUse,
    satisfied_proofs: Vec<ProofSummary>,
) -> LoadedState {
    loaded_trusted_device_and_attempt_with_satisfied_proof_records(
        silent_revival_until,
        expires_at,
        proof_use,
        satisfied_proofs
            .into_iter()
            .map(SatisfiedProof::new_without_source)
            .collect(),
    )
}

pub(super) fn loaded_trusted_device_and_attempt_with_satisfied_proof_records(
    silent_revival_until: u64,
    expires_at: u64,
    proof_use: ProofUse,
    satisfied_proofs: Vec<SatisfiedProof>,
) -> LoadedState {
    let mut attempt = active_attempt_with_satisfied_proof_records(proof_use, satisfied_proofs);
    attempt.expires_at = at(1_000);
    LoadedState {
        active_proof_attempt_record: Some(attempt),
        ..loaded_trusted_device(silent_revival_until, expires_at)
    }
}

pub(super) fn proof(family: ProofFamily) -> ProofSummary {
    proof_method(family).verified_proof_summary()
}

pub(super) fn satisfied_proof(proof: ProofSummary) -> SatisfiedProof {
    SatisfiedProof::new_without_source(proof)
}

pub(super) fn satisfied_proof_with_source(
    proof: ProofSummary,
    source: VerifiedProofSource,
) -> SatisfiedProof {
    SatisfiedProof::new(proof, Some(source))
}

pub(super) fn proof_source(value: &str) -> VerifiedProofSource {
    VerifiedProofSource::new(VerifiedProofSourceKind::CredentialInstance, id(value))
}

pub(super) fn message_signature_credential_metadata(
    credential_instance_id: &str,
) -> CredentialInstanceMetadata {
    CredentialInstanceMetadata::new(
        id(credential_instance_id),
        id("subject"),
        CredentialInstanceKind::MessageSignatureVerifier,
        "password_signature",
        CredentialLifecycleState::Active,
    )
    .expect("credential metadata")
}

pub(super) fn credential_lifecycle_context<
    const AUTHORITY_COUNT: usize,
    const EVIDENCE_COUNT: usize,
>(
    target_credential: CredentialInstanceMetadata,
    authorities: [CredentialRecoveryAuthority; AUTHORITY_COUNT],
    evidence: [LifecycleAuthorityEvidence; EVIDENCE_COUNT],
) -> CredentialLifecycleActionContext {
    CredentialLifecycleActionContext::new(
        target_credential,
        CredentialRecoveryAuthorityGraph::new(authorities).expect("authority graph"),
        evidence,
    )
}

pub(super) fn credential_instance_lifecycle_evidence<const N: usize>(
    source_id: &str,
    authority_ids: [RecoveryAuthorityId; N],
) -> LifecycleAuthorityEvidence {
    LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(VerifiedProofSourceKind::CredentialInstance, id(source_id)),
        authority_ids,
    )
    .expect("lifecycle evidence")
}

pub(super) fn out_of_band_identifier_lifecycle_evidence<const N: usize>(
    source_id: &str,
    authority_ids: [RecoveryAuthorityId; N],
) -> LifecycleAuthorityEvidence {
    LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(VerifiedProofSourceKind::OutOfBandIdentifier, id(source_id)),
        authority_ids,
    )
    .expect("lifecycle evidence")
}

pub(super) fn proof_method(family: ProofFamily) -> ProofMethodDeclaration {
    let method_label = match family {
        ProofFamily::OutOfBandCode => "email_otp",
        ProofFamily::SharedSecretOtp => "totp",
        ProofFamily::TrustedDevice => "trusted_device",
        ProofFamily::RecoveryCode => "recovery_code",
        ProofFamily::OriginBoundPublicKey => "webauthn_passkey",
        ProofFamily::FederatedIdentityAssertion => "oidc_google",
        ProofFamily::MessageSignature => {
            return ProofMethodDeclaration::new_online_guessable(family, "password_signature")
                .expect("method declaration");
        }
    };
    ProofMethodDeclaration::new(family, method_label).expect("method declaration")
}

pub(super) fn proof_method_matching(proof: &ProofSummary) -> ProofMethodDeclaration {
    ProofMethodDeclaration::new_with_online_guessing_risk(
        proof.family(),
        proof.method_label(),
        proof.online_guessing_risk(),
    )
    .expect("method declaration")
}

pub(super) fn verified(proof: ProofSummary, subject_id: Option<SubjectId>) -> VerifiedActiveProof {
    VerifiedActiveProof::from_summary(proof, subject_id).expect("verified proof")
}

pub(super) fn verified_with_source(
    proof: ProofSummary,
    subject_id: Option<SubjectId>,
    source: VerifiedProofSource,
) -> VerifiedActiveProof {
    VerifiedActiveProof::from_summary_with_source(proof, subject_id, source)
        .expect("verified proof")
}

pub(super) fn verified_proof(
    family: ProofFamily,
    subject_id: Option<SubjectId>,
) -> VerifiedActiveProof {
    VerifiedActiveProof::from_summary(proof_method(family).verified_proof_summary(), subject_id)
        .expect("verified proof")
}

pub(super) fn proof_of_work_gate_summary() -> WeakProofGateSummary {
    hashcash_verifier_for_test().summary().clone()
}

pub(super) fn verified_proof_of_work_gate() -> WeakProofGateStatus {
    WeakProofGateStatus::verified_before_state_load(proof_of_work_gate_summary())
}

pub(super) fn hashcash_verifier_for_test() -> HashcashProofOfWorkVerifier {
    HashcashProofOfWorkVerifier::new(HashcashProofOfWorkConfig::new(8, DurationSeconds::new(300)))
        .expect("test Hashcash verifier")
}

pub(super) fn proof_of_work_gate_response_for_test(
    now: UnixSeconds,
    proof: &ProofSummary,
    binding: &WeakProofGateBinding,
) -> WeakProofGateResponse {
    hashcash_verifier_for_test().solve_weak_proof_gate_response_for_test(now, proof, binding)
}

pub(super) fn challenge_issue_preflight_response_for_test(
    now: UnixSeconds,
    proof_use: ProofUse,
    method: &ProofMethodDeclaration,
) -> ChallengeIssuePreflightResponse {
    hashcash_verifier_for_test().solve_challenge_issue_preflight_response_for_test(
        now,
        proof_use,
        &method.verified_proof_summary(),
    )
}

pub(super) fn email_otp_challenge_issue_preflight_response_at(
    now: UnixSeconds,
) -> ChallengeIssuePreflightResponse {
    challenge_issue_preflight_response_for_test(
        now,
        ProofUse::ContributeToFullAuthentication,
        &ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
            .expect("email OTP method"),
    )
}

pub(super) fn invalid_challenge_issue_preflight_response() -> ChallengeIssuePreflightResponse {
    ChallengeIssuePreflightResponse::try_from_bytes(
        WeakProofGateKind::ProofOfWork,
        "hashcash",
        b"invalid-hashcash".as_slice(),
    )
    .expect("challenge issue preflight response")
}

pub(super) fn mismatched_challenge_issue_preflight_response() -> ChallengeIssuePreflightResponse {
    ChallengeIssuePreflightResponse::try_from_bytes(
        WeakProofGateKind::HumanChallenge,
        "turnstile",
        b"valid-hashcash".as_slice(),
    )
    .expect("challenge issue preflight response")
}

pub(super) fn invalid_proof_of_work_gate_response() -> WeakProofGateResponse {
    WeakProofGateResponse::try_from_bytes(
        WeakProofGateKind::ProofOfWork,
        "hashcash",
        b"invalid-hashcash".as_slice(),
    )
    .expect("weak proof gate response")
}

pub(super) fn recovery_code_method_commit_work() -> MethodCommitWork {
    MethodCommitWork::new(
        proof(ProofFamily::RecoveryCode),
        vec![
            MethodCommitPrecondition::new(
                "recovery_code_still_unused",
                b"recovery-code-id".as_slice(),
            )
            .expect("method work item"),
        ],
        vec![
            MethodCommitMutation::new("consume_recovery_code", b"recovery-code-id".as_slice())
                .expect("method work item"),
        ],
        Vec::new(),
    )
    .expect("method commit work")
}

pub(super) fn password_reset_method_commit_work(payload: &[u8]) -> MethodCommitWork {
    MethodCommitWork::new(
        proof(ProofFamily::MessageSignature),
        vec![
            MethodCommitPrecondition::new("password_verifier_version_current", payload)
                .expect("method work item"),
        ],
        vec![
            MethodCommitMutation::new("replace_password_verifier", payload)
                .expect("method work item"),
        ],
        Vec::new(),
    )
    .expect("method commit work")
}

pub(super) fn out_of_band_method_commit_work() -> MethodCommitWork {
    MethodCommitWork::new(
        proof(ProofFamily::OutOfBandCode),
        vec![
            MethodCommitPrecondition::new("otp_state_absent", b"challenge")
                .expect("method work item"),
        ],
        vec![MethodCommitMutation::new("store_otp_state", b"challenge").expect("method work item")],
        vec![
            MethodCommitDurableEffectCommand::new("queue_email_body", b"challenge")
                .expect("method work item"),
        ],
    )
    .expect("method commit work")
}

pub(super) fn plan_has_active_proof_attempt_guard(
    plan: &CommitPlan,
    attempt_id: &ActiveProofAttemptId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::ActiveProofAttemptStillOpen {
                attempt_id: guarded_attempt_id,
                ..
            }
                if guarded_attempt_id == attempt_id
        )
    })
}

pub(super) fn plan_has_any_active_proof_attempt_guard(plan: &CommitPlan) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::ActiveProofAttemptStillOpen { .. }
        )
    })
}

pub(super) fn plan_has_any_active_proof_challenge_guard(plan: &CommitPlan) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::ActiveProofChallengeStillOpen { .. }
                | Precondition::OutOfBandChallengeResendStillAllowed { .. }
        )
    })
}

pub(super) fn plan_has_out_of_band_dedupe_guard(
    plan: &CommitPlan,
    challenge_dedupe_key: &OutOfBandChallengeDedupeKey,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::NoOpenOutOfBandChallengeForDedupeKey {
                challenge_dedupe_key: guarded_challenge_dedupe_key,
                ..
            } if guarded_challenge_dedupe_key == challenge_dedupe_key
        )
    })
}

pub(super) fn plan_has_session_still_matches_guard(
    plan: &CommitPlan,
    session_id: &SessionId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::SessionStillMatches { session_id: guarded_session_id, .. }
                if guarded_session_id == session_id
        )
    })
}

pub(super) fn plan_has_session_ownership_guard(plan: &CommitPlan, session_id: &SessionId) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::SessionBelongsToSubject { session_id: guarded_session_id, .. }
                if guarded_session_id == session_id
        )
    })
}

pub(super) fn plan_has_trusted_device_still_matches_guard(
    plan: &CommitPlan,
    device_credential_id: &TrustedDeviceCredentialId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::TrustedDeviceStillMatches {
                device_credential_id: guarded_device_credential_id,
                ..
            } if guarded_device_credential_id == device_credential_id
        )
    })
}

pub(super) fn plan_has_trusted_device_ownership_guard(
    plan: &CommitPlan,
    device_credential_id: &TrustedDeviceCredentialId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::TrustedDeviceBelongsToSubject {
                device_credential_id: guarded_device_credential_id,
                ..
            } if guarded_device_credential_id == device_credential_id
        )
    })
}

pub(super) fn plan_has_credential_instance_still_active_guard(
    plan: &CommitPlan,
    credential_instance_id: &VerifiedProofSourceId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::CredentialInstanceStillActive {
                credential_instance_id: guarded_credential_instance_id,
                ..
            } if guarded_credential_instance_id == credential_instance_id
        )
    })
}

pub(super) fn plan_has_no_open_pending_lifecycle_action_guard(
    plan: &CommitPlan,
    target_credential_instance_id: &VerifiedProofSourceId,
    action: CredentialLifecycleAction,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
                target_credential_instance_id: guarded_target_credential_instance_id,
                action: guarded_action,
                ..
            } if guarded_target_credential_instance_id == target_credential_instance_id
                && *guarded_action == action
        )
    })
}

pub(super) fn plan_has_pending_lifecycle_action_executable_guard(
    plan: &CommitPlan,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::PendingCredentialLifecycleActionStillExecutable {
                pending_action_id: guarded_pending_action_id,
                ..
            } if guarded_pending_action_id == pending_action_id
        )
    })
}

pub(super) fn plan_has_pending_lifecycle_action_cancellable_for_target_guard(
    plan: &CommitPlan,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
                pending_action_id: guarded_pending_action_id,
                ..
            } if guarded_pending_action_id == pending_action_id
        )
    })
}

pub(super) fn precondition_kind_names(plan: &CommitPlan) -> Vec<&'static str> {
    plan.preconditions
        .iter()
        .map(|precondition| match precondition {
            Precondition::SessionStillMatches { .. } => "session_still_matches",
            Precondition::TrustedDeviceStillMatches { .. } => "trusted_device_still_matches",
            Precondition::SessionBelongsToSubject { .. } => "session_belongs_to_subject",
            Precondition::TrustedDeviceBelongsToSubject { .. } => {
                "trusted_device_belongs_to_subject"
            }
            Precondition::ActiveProofAttemptStillOpen { .. } => "active_proof_attempt_still_open",
            Precondition::ActiveProofChallengeStillOpen { .. } => {
                "active_proof_challenge_still_open"
            }
            Precondition::OutOfBandChallengeResendStillAllowed { .. } => {
                "out_of_band_challenge_resend_still_allowed"
            }
            Precondition::NoOpenOutOfBandChallengeForDedupeKey { .. } => {
                "no_open_out_of_band_challenge_for_dedupe_key"
            }
            Precondition::CredentialInstanceStillActive { .. } => {
                "credential_instance_still_active"
            }
            Precondition::NoOpenPendingCredentialLifecycleActionForTarget { .. } => {
                "no_open_pending_credential_lifecycle_action_for_target"
            }
            Precondition::PendingCredentialLifecycleActionStillExecutable { .. } => {
                "pending_credential_lifecycle_action_still_executable"
            }
            Precondition::PendingCredentialLifecycleActionStillCancellableForTarget { .. } => {
                "pending_credential_lifecycle_action_still_cancellable_for_target"
            }
            Precondition::NoOpenPendingSubjectLifecycleActionForSubject { .. } => {
                "no_open_pending_subject_lifecycle_action_for_subject"
            }
            Precondition::PendingSubjectLifecycleActionStillExecutable { .. } => {
                "pending_subject_lifecycle_action_still_executable"
            }
            Precondition::PendingSubjectLifecycleActionStillCancellableForSubject { .. } => {
                "pending_subject_lifecycle_action_still_cancellable_for_subject"
            }
        })
        .collect()
}

pub(super) fn plan_has_no_open_pending_subject_lifecycle_action_guard(
    plan: &CommitPlan,
    subject_id: &SubjectId,
    action: SubjectLifecycleAction,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
                subject_id: guarded_subject_id,
                action: guarded_action,
                ..
            } if guarded_subject_id == subject_id && *guarded_action == action
        )
    })
}

pub(super) fn plan_has_pending_subject_lifecycle_action_executable_guard(
    plan: &CommitPlan,
    pending_action_id: &PendingSubjectLifecycleActionId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::PendingSubjectLifecycleActionStillExecutable {
                pending_action_id: guarded_pending_action_id,
                ..
            } if guarded_pending_action_id == pending_action_id
        )
    })
}

pub(super) fn plan_has_pending_subject_lifecycle_action_cancellable_guard(
    plan: &CommitPlan,
    pending_action_id: &PendingSubjectLifecycleActionId,
) -> bool {
    plan.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
                pending_action_id: guarded_pending_action_id,
                ..
            } if guarded_pending_action_id == pending_action_id
        )
    })
}

pub(super) fn assert_state_dependent_mutations_have_commit_time_guards(
    plan_name: &str,
    plan: &CommitPlan,
) {
    for mutation in &plan.mutations {
        match mutation {
            Mutation::CreateSession(session) => {
                let has_active_proof_guard = plan_has_any_active_proof_attempt_guard(plan);
                let has_device_guard =
                    session
                        .device_credential_id
                        .as_ref()
                        .is_some_and(|device_credential_id| {
                            plan_has_trusted_device_ownership_guard(plan, device_credential_id)
                                && plan_has_trusted_device_still_matches_guard(
                                    plan,
                                    device_credential_id,
                                )
                        });
                assert!(
                    has_active_proof_guard || has_device_guard,
                    "{plan_name}: session creation must be guarded by active proof or trusted device"
                );
            }
            Mutation::RefreshSession { session_id, .. }
            | Mutation::RecordStepUp { session_id, .. } => {
                assert!(
                    plan_has_session_still_matches_guard(plan, session_id),
                    "{plan_name}: session mutation must guard the accepted session version"
                );
            }
            Mutation::CreateTrustedDeviceCredential(_) => {
                assert!(
                    plan_has_any_active_proof_attempt_guard(plan),
                    "{plan_name}: trusted-device creation must be guarded by active-proof attempt closure"
                );
            }
            Mutation::CreateActiveProofChallenge(challenge) => {
                assert!(
                    plan_has_active_proof_attempt_guard(plan, &challenge.attempt_id),
                    "{plan_name}: challenge creation must guard its active-proof attempt"
                );
                if let Some(challenge_dedupe_key) = &challenge.challenge_dedupe_key {
                    assert!(
                        plan_has_out_of_band_dedupe_guard(plan, challenge_dedupe_key),
                        "{plan_name}: out-of-band challenge creation must guard the dedupe key"
                    );
                }
            }
            Mutation::RecordWeakProofFailure { attempt_id, .. }
            | Mutation::RecordActiveProofSucceeded { attempt_id, .. }
            | Mutation::DeleteActiveProofAttempt { attempt_id } => {
                assert!(
                    plan_has_active_proof_attempt_guard(plan, attempt_id),
                    "{plan_name}: active-proof attempt mutation must guard the attempt"
                );
            }
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
                attempt_id, ..
            } => {
                assert!(
                    plan_has_active_proof_attempt_guard(plan, attempt_id),
                    "{plan_name}: same-family challenge closure must guard the attempt"
                );
                assert!(
                    plan_has_any_active_proof_challenge_guard(plan),
                    "{plan_name}: same-family challenge closure must guard the completed challenge"
                );
            }
            Mutation::RecordOutOfBandChallengeResent { .. } => {
                assert!(
                    plan_has_any_active_proof_attempt_guard(plan),
                    "{plan_name}: challenge resend must guard the active-proof attempt"
                );
                assert!(
                    plan_has_any_active_proof_challenge_guard(plan),
                    "{plan_name}: challenge resend must guard the challenge"
                );
            }
            Mutation::RotateTrustedDeviceCredential {
                device_credential_id,
                ..
            } => {
                assert!(
                    plan_has_trusted_device_still_matches_guard(plan, device_credential_id),
                    "{plan_name}: trusted-device rotation must guard the accepted device version"
                );
                assert!(
                    plan_has_trusted_device_ownership_guard(plan, device_credential_id),
                    "{plan_name}: trusted-device rotation must guard subject ownership"
                );
            }
            Mutation::RevokeSession { session_id, .. } => {
                assert!(
                    plan_has_session_still_matches_guard(plan, session_id)
                        || plan_has_session_ownership_guard(plan, session_id),
                    "{plan_name}: session revocation must guard either possession or ownership"
                );
            }
            Mutation::RevokeTrustedDeviceCredential {
                device_credential_id,
                ..
            } => {
                assert!(
                    plan_has_trusted_device_ownership_guard(plan, device_credential_id),
                    "{plan_name}: trusted-device revocation must guard ownership"
                );
            }
            Mutation::RecordCredentialLifecycleActionAuthorized {
                target_credential_instance_id,
                ..
            } => {
                assert!(
                    plan_has_credential_instance_still_active_guard(
                        plan,
                        target_credential_instance_id
                    ),
                    "{plan_name}: credential lifecycle authorization must guard the target credential"
                );
            }
            Mutation::CreatePendingCredentialLifecycleAction(pending_action) => {
                assert!(
                    plan_has_credential_instance_still_active_guard(
                        plan,
                        &pending_action.target_credential_instance_id,
                    ),
                    "{plan_name}: pending credential lifecycle action must guard the target credential"
                );
                assert!(
                    plan_has_no_open_pending_lifecycle_action_guard(
                        plan,
                        &pending_action.target_credential_instance_id,
                        pending_action.action,
                    ),
                    "{plan_name}: pending credential lifecycle action must guard open-action uniqueness"
                );
            }
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id,
                ..
            } => {
                assert!(
                    plan_has_credential_instance_still_active_guard(
                        plan,
                        target_credential_instance_id
                    ),
                    "{plan_name}: credential lifecycle execution must guard the target credential"
                );
            }
            Mutation::SetCredentialLifecycleState {
                credential_instance_id,
                ..
            } => {
                assert!(
                    plan_has_credential_instance_still_active_guard(plan, credential_instance_id),
                    "{plan_name}: credential lifecycle state change must guard the target credential"
                );
            }
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id, ..
            } => {
                assert!(
                    plan_has_pending_lifecycle_action_executable_guard(plan, pending_action_id)
                        || plan_has_pending_lifecycle_action_cancellable_for_target_guard(
                            plan,
                            pending_action_id
                        ),
                    "{plan_name}: pending credential lifecycle action closure must guard executable or cancellable state"
                );
            }
            Mutation::CreatePendingSubjectLifecycleAction(pending_action) => {
                assert!(
                    plan_has_no_open_pending_subject_lifecycle_action_guard(
                        plan,
                        &pending_action.subject_id,
                        pending_action.action,
                    ),
                    "{plan_name}: pending subject lifecycle action must guard open-action uniqueness"
                );
            }
            Mutation::ClosePendingSubjectLifecycleAction {
                pending_action_id, ..
            } => {
                assert!(
                    plan_has_pending_subject_lifecycle_action_executable_guard(
                        plan,
                        pending_action_id
                    ) || plan_has_pending_subject_lifecycle_action_cancellable_guard(
                        plan,
                        pending_action_id
                    ),
                    "{plan_name}: pending subject lifecycle action closure must guard executable or cancellable state"
                );
            }
            Mutation::CreateActiveProofAttempt(_)
            | Mutation::RaiseSubjectAuthRevocationCutoff { .. } => {}
        }
    }
}

pub(super) fn assert_command_rejects_closed_and_expired_active_proof_attempt(
    command_name: &str,
    command: Command,
    loaded: LoadedState,
    now: UnixSeconds,
) {
    let mut closed_attempt_loaded = loaded.clone();
    closed_attempt_loaded
        .active_proof_attempt_record
        .as_mut()
        .expect("active-proof attempt")
        .closed_at = Some(UnixSeconds::new(now.get().saturating_sub(1)));
    let closed_attempt_error = reduce_command(&config(), command.clone(), &closed_attempt_loaded)
        .expect_err("closed active-proof attempt must be rejected");
    assert_eq!(
        closed_attempt_error,
        Error::ActiveProofAttemptNotOpen,
        "{command_name}: closed active-proof attempt"
    );

    let mut expired_attempt_loaded = loaded;
    expired_attempt_loaded
        .active_proof_attempt_record
        .as_mut()
        .expect("active-proof attempt")
        .expires_at = now;
    let expired_attempt_error = reduce_command(&config(), command, &expired_attempt_loaded)
        .expect_err("expired active-proof attempt must be rejected");
    assert_eq!(
        expired_attempt_error,
        Error::ActiveProofAttemptNotOpen,
        "{command_name}: expired active-proof attempt"
    );
}

pub(super) fn csrf_cycle_targets(plan: &CommitPlan) -> Vec<Option<SessionId>> {
    plan.response_effects
        .iter()
        .filter_map(|effect| match effect {
            ResponseEffect::CycleCsrfToken { session_id } => Some(session_id.clone()),
            ResponseEffect::IssueSessionCookie(_)
            | ResponseEffect::DeleteSessionCookie
            | ResponseEffect::IssueTrustedDeviceCookie(_)
            | ResponseEffect::DeleteTrustedDeviceCookie
            | ResponseEffect::IssueActiveProofChallengeCookie(_)
            | ResponseEffect::DeleteActiveProofChallengeCookie
            | ResponseEffect::IssueActiveProofContinuationCookie(_)
            | ResponseEffect::DeleteActiveProofContinuationCookie => None,
        })
        .collect()
}

pub(super) fn assert_only_issued_active_proof_challenge_cookie(
    effects: Vec<ResponseEffect>,
    challenge_id: ActiveProofChallengeId,
) {
    assert!(
        matches!(
            effects.as_slice(),
            [ResponseEffect::IssueActiveProofChallengeCookie(cookie)]
                if cookie.challenge_id == challenge_id
        ),
        "expected exactly one active-proof challenge cookie issue effect, got {effects:?}"
    );
}

pub(super) fn assert_only_deleted_active_proof_challenge_cookie(effects: Vec<ResponseEffect>) {
    assert!(
        matches!(
            effects.as_slice(),
            [ResponseEffect::DeleteActiveProofChallengeCookie]
        ),
        "expected exactly one active-proof challenge cookie delete effect, got {effects:?}"
    );
}

pub(super) fn security_notification_kinds(plan: &CommitPlan) -> Vec<SecurityNotificationKind> {
    plan.durable_effects
        .iter()
        .filter_map(|effect| match effect {
            DurableEffectCommand::NotifySecurityEvent(command) => Some(command.kind),
            DurableEffectCommand::SendOutOfBandMessage(_) => None,
        })
        .collect()
}
