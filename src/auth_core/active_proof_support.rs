use super::proof_policy::validate_satisfied_proof_stack_for_use;
use super::*;

pub(super) fn validate_proof_use_can_be_satisfied_by_active_proof(
    proof_use: ProofUse,
) -> Result<(), Error> {
    let active_proof_can_satisfy = [
        ProofFamily::OutOfBandCode,
        ProofFamily::MessageSignature,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
        ProofFamily::SharedSecretOtp,
        ProofFamily::RecoveryCode,
    ]
    .into_iter()
    .any(|family| family.supports_use(proof_use));

    if !active_proof_can_satisfy {
        return Err(Error::ActiveProofUseCannotBeSatisfiedByActiveProof { proof_use });
    }
    Ok(())
}

pub(super) fn validate_proof_for_use(
    proof: &ProofSummary,
    proof_use: ProofUse,
) -> Result<(), Error> {
    if proof.method_label.is_empty() {
        return Err(Error::EmptyProofMethodLabel);
    }
    if !proof.family.supports_use(proof_use) {
        return Err(Error::ProofFamilyCannotSatisfyUse {
            family: proof.family,
            proof_use,
        });
    }
    Ok(())
}

pub(crate) fn validate_known_subject_active_proof_method(
    method: &ProofMethodDeclaration,
) -> Result<(), Error> {
    let contract = MethodAdapterContract::for_method(method.clone());
    if method.semantics().subject_role != ProofSubjectRole::RequiresKnownSubject
        || method.semantics().interaction != ProofInteraction::Active
        || contract.challenge_cookie().kind() != MethodChallengeCookieKind::NotUsed
    {
        return Err(Error::ProofMethodCannotCompleteKnownSubjectActiveProof {
            family: method.family(),
        });
    }
    Ok(())
}

pub(super) fn active_proof_subject_id_after_completion(
    attempt: &ActiveProofAttemptRecord,
    proof: &ProofSummary,
    supplied_subject_id: Option<SubjectId>,
) -> Result<Option<SubjectId>, Error> {
    match (&attempt.subject_id, supplied_subject_id) {
        (Some(attempt_subject_id), Some(supplied_subject_id)) => {
            if attempt_subject_id != &supplied_subject_id {
                return Err(Error::LoadedStateContradiction(
                    "active-proof supplied subject differs from attempt subject",
                ));
            }
            Ok(Some(supplied_subject_id))
        }
        (Some(attempt_subject_id), None) => Ok(Some(attempt_subject_id.clone())),
        (None, Some(supplied_subject_id)) => {
            validate_proof_can_bind_subject(proof)?;
            Ok(Some(supplied_subject_id))
        }
        (None, None) => Err(Error::LoadedStateContradiction(
            "active-proof completion did not resolve subject for unbound attempt",
        )),
    }
}

fn validate_proof_can_bind_subject(proof: &ProofSummary) -> Result<(), Error> {
    match proof.family.semantics().subject_role {
        ProofSubjectRole::CanBindSubjectFromIdentifier
        | ProofSubjectRole::CanBindExistingSubjectFromVerifier
        | ProofSubjectRole::CanBindSubjectFromExternalAssertion => Ok(()),
        ProofSubjectRole::RequiresKnownSubject
        | ProofSubjectRole::BoundToTrustedDeviceCredential => Err(Error::LoadedStateContradiction(
            "proof family cannot bind an unbound active-proof attempt to a subject",
        )),
    }
}

pub(super) fn validate_weak_proof_gate_for_proof(
    proof: &ProofSummary,
    weak_proof_gate: &WeakProofGateStatus,
) -> Result<(), Error> {
    if proof.uses_weak_attempt_failure_budget()
        && !matches!(
            weak_proof_gate,
            WeakProofGateStatus::VerifiedBeforeStateLoad(_)
        )
    {
        return Err(Error::WeakProofGateVerificationRequired);
    }
    Ok(())
}

pub(super) fn verify_weak_proof_gate_before_state_load(
    now: UnixSeconds,
    proof: &ProofSummary,
    response: Option<&WeakProofGateResponse>,
    verifier: &(impl WeakProofGateVerifier + ?Sized),
) -> Result<WeakProofGateStatus, Error> {
    if !proof.uses_weak_attempt_failure_budget() {
        if response.is_some() {
            return Err(Error::UnexpectedWeakProofGateResponse);
        }
        return Ok(WeakProofGateStatus::NotRequired);
    }

    let response = response.ok_or(Error::WeakProofGateVerificationRequired)?;
    verifier.verify_weak_proof_gate_before_state_load(WeakProofGateVerificationRequest::new(
        now, proof, response,
    ))?;
    Ok(WeakProofGateStatus::verified_before_state_load(
        response.summary().clone(),
    ))
}

pub(super) fn verify_challenge_issue_preflight_before_state_load(
    config: &Config,
    now: UnixSeconds,
    proof_use: ProofUse,
    proof: &ProofSummary,
    response: &ChallengeIssuePreflightResponse,
    verifier: &(impl WeakProofGateVerifier + ?Sized),
) -> Result<(), Error> {
    validate_proof_for_use(proof, proof_use)?;
    if response.summary() != &config.unauthenticated_challenge_issue_preflight_gate {
        return Err(Error::ChallengeIssuePreflightGateMismatch);
    }
    verifier.verify_challenge_issue_preflight_before_state_load(
        ChallengeIssuePreflightVerificationRequest::new(now, proof_use, proof, response),
    )
}

pub(super) fn validate_used_delivery_idempotency_keys(
    challenge: &ActiveProofChallengeRecord,
) -> Result<(), Error> {
    if challenge.used_delivery_idempotency_keys.is_empty()
        || challenge
            .used_delivery_idempotency_keys
            .iter()
            .any(String::is_empty)
    {
        return Err(Error::LoadedStateContradiction(
            "out-of-band challenge used delivery idempotency keys must be non-empty",
        ));
    }
    for idempotency_key in &challenge.used_delivery_idempotency_keys {
        validate_auth_identifier_string(
            "stored out-of-band delivery idempotency key",
            idempotency_key,
            DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
        )?;
    }
    Ok(())
}

pub(super) fn validate_method_commit_work_for_proof(
    proof: &ProofSummary,
    method_commit_work: &[MethodCommitWork],
) -> Result<(), Error> {
    if proof.family.requires_method_commit_work_on_success() && method_commit_work.is_empty() {
        return Err(Error::MissingMethodCommitWorkForOneTimeProof);
    }
    for work in method_commit_work {
        work.validate()?;
        if work.proof() != proof {
            return Err(Error::MethodCommitWorkProofMismatch);
        }
    }
    Ok(())
}

pub(super) fn ensure_active_proof_not_already_satisfied(
    attempt: &ActiveProofAttemptRecord,
    family: ProofFamily,
) -> Result<(), Error> {
    if attempt
        .satisfied_proofs
        .iter()
        .any(|proof| proof.family() == family)
    {
        return Err(Error::ActiveProofAlreadySatisfied);
    }
    Ok(())
}

pub(super) fn loaded_active_attempt(
    loaded: &LoadedState,
) -> Result<&ActiveProofAttemptRecord, Error> {
    let attempt =
        loaded
            .active_proof_attempt_record
            .as_ref()
            .ok_or(Error::LoadedStateContradiction(
                "active-proof attempt record missing",
            ))?;
    if let Some(secret_match) = &loaded.active_proof_continuation_secret_match {
        if secret_match.attempt_id() != &attempt.attempt_id {
            return Err(Error::LoadedStateContradiction(
                "active-proof continuation secret was checked against a different attempt",
            ));
        }
        if !secret_match.kind().is_accepted() {
            return Err(Error::ActiveProofContinuationSecretMismatch);
        }
    }
    Ok(attempt)
}

pub(super) fn loaded_active_challenge(
    loaded: &LoadedState,
) -> Result<&ActiveProofChallengeRecord, Error> {
    loaded
        .active_proof_challenge_record
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "active-proof challenge record missing",
        ))
}

pub(super) fn validate_active_proof_attempt_id(
    attempt_id: &ActiveProofAttemptId,
    attempt: &ActiveProofAttemptRecord,
) -> Result<(), Error> {
    if attempt_id != &attempt.attempt_id {
        return Err(Error::LoadedStateContradiction(
            "active-proof command attempt id differs from loaded attempt id",
        ));
    }
    Ok(())
}

pub(super) fn require_active_proof_continuation_before_state_load(
    presented_cookies: &PresentedAuthCookies,
    now: UnixSeconds,
) -> Result<&ActiveProofContinuationCookieDraft, Error> {
    let continuation = presented_cookies
        .active_proof_continuation_cookie
        .as_ref()
        .ok_or(Error::MissingActiveProofContinuationCookie)?;
    continuation.validate_unexpired_before_state_load(now)?;
    Ok(continuation)
}

pub(super) fn require_active_proof_continuation_for_use_before_state_load(
    presented_cookies: &PresentedAuthCookies,
    now: UnixSeconds,
    proof_use: ProofUse,
) -> Result<&ActiveProofContinuationCookieDraft, Error> {
    let continuation = require_active_proof_continuation_before_state_load(presented_cookies, now)?;
    continuation.validate_for_use_before_state_load(now, proof_use)?;
    Ok(continuation)
}

pub(super) fn validate_active_proof_challenge_id(
    challenge_id: &ActiveProofChallengeId,
    challenge: &ActiveProofChallengeRecord,
) -> Result<(), Error> {
    if challenge_id != &challenge.challenge_id {
        return Err(Error::LoadedStateContradiction(
            "active-proof command challenge id differs from loaded challenge id",
        ));
    }
    Ok(())
}

pub(super) fn validate_challenge_attempt_pair(
    attempt: &ActiveProofAttemptRecord,
    challenge: &ActiveProofChallengeRecord,
) -> Result<(), Error> {
    if challenge.attempt_id != attempt.attempt_id {
        return Err(Error::LoadedStateContradiction(
            "active-proof challenge belongs to a different attempt",
        ));
    }
    Ok(())
}

pub(super) fn ensure_active_proof_attempt_is_open(
    now: UnixSeconds,
    attempt: &ActiveProofAttemptRecord,
) -> Result<(), Error> {
    if attempt.closed_at.is_some() || now >= attempt.expires_at {
        return Err(Error::ActiveProofAttemptNotOpen);
    }
    Ok(())
}

pub(super) fn ensure_active_proof_challenge_is_open(
    now: UnixSeconds,
    challenge: &ActiveProofChallengeRecord,
) -> Result<(), Error> {
    if challenge.closed_at.is_some() || now >= challenge.expires_at {
        return Err(Error::ActiveProofChallengeNotOpen);
    }
    Ok(())
}

pub(super) fn validate_active_proof_attempt_satisfies_use<'a>(
    proof_policy: &ProofPolicy,
    loaded: &'a LoadedState,
    attempt_id: &ActiveProofAttemptId,
    now: UnixSeconds,
    proof_use: ProofUse,
) -> Result<&'a ActiveProofAttemptRecord, Error> {
    let attempt = loaded_active_attempt(loaded)?;
    validate_active_proof_attempt_id(attempt_id, attempt)?;
    ensure_active_proof_attempt_is_open(now, attempt)?;
    ensure_active_proof_attempt_not_subject_revoked(loaded, attempt, attempt.subject_id.as_ref())?;
    if attempt.proof_use != proof_use {
        return Err(Error::LoadedStateContradiction(
            "active-proof attempt use differs from required use",
        ));
    }
    validate_satisfied_proof_stack_for_use(proof_policy, &attempt.satisfied_proofs, proof_use)?;
    Ok(attempt)
}

pub(super) fn ensure_active_proof_attempt_matches_subject(
    attempt: &ActiveProofAttemptRecord,
    subject_id: &SubjectId,
) -> Result<(), Error> {
    if attempt.subject_id.as_ref() != Some(subject_id) {
        return Err(Error::LoadedStateContradiction(
            "active-proof attempt subject differs from required subject",
        ));
    }
    Ok(())
}

pub(super) fn append_active_proof_attempt_closure_to_plan(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    attempt: &ActiveProofAttemptRecord,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
    device_credential_id: Option<TrustedDeviceCredentialId>,
) {
    push_active_proof_attempt_still_open_precondition(plan, attempt, now, subject_id.clone());
    plan.mutations.push(Mutation::DeleteActiveProofAttempt {
        attempt_id: attempt.attempt_id.clone(),
    });
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::ActiveProofAttemptClosed,
            occurred_at: now,
            subject_id,
            session_id,
            device_credential_id,
            attempt_id: Some(attempt.attempt_id.clone()),
            challenge_id: None,
            weak_proof_gate: None,
        }));
    plan.response_effects
        .push(ResponseEffect::DeleteActiveProofContinuationCookie);
}

pub(super) fn ensure_active_proof_attempt_not_subject_revoked(
    loaded: &LoadedState,
    attempt: &ActiveProofAttemptRecord,
    subject_id_for_revocation: Option<&SubjectId>,
) -> Result<(), Error> {
    if let Some(subject_id_for_revocation) = subject_id_for_revocation {
        let subject_revocation = loaded
            .subject_revocations
            .required_revocation_for_subject(subject_id_for_revocation)?;
        if matches!(
            subject_revocation,
            Some(revocation)
                if attempt.created_at <= revocation.revoke_records_created_at_or_before
        ) {
            return Err(Error::ActiveProofAttemptNotOpen);
        }
    }
    Ok(())
}

pub(super) fn push_active_proof_attempt_still_open_precondition(
    plan: &mut CommitPlan,
    attempt: &ActiveProofAttemptRecord,
    now: UnixSeconds,
    subject_id_for_revocation: Option<SubjectId>,
) {
    plan.preconditions
        .push(Precondition::ActiveProofAttemptStillOpen {
            attempt_id: attempt.attempt_id.clone(),
            now,
            observed_subject_id: attempt.subject_id.clone(),
            observed_satisfied_proofs: attempt.satisfied_proofs.clone(),
            observed_weak_proof_failures: attempt.weak_proof_failures,
            subject_id_for_revocation,
            created_at: attempt.created_at,
        });
}
