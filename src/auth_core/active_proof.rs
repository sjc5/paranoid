use std::cmp::min;

use super::active_proof_support::*;
use super::*;

pub(super) use super::active_proof_support::{
    append_active_proof_attempt_closure_to_plan, ensure_active_proof_attempt_matches_subject,
    validate_active_proof_attempt_satisfies_use,
};

pub(super) fn start_active_proof_attempt(
    config: &Config,
    command: StartActiveProofAttempt,
) -> Result<Transition, Error> {
    validate_proof_use_can_be_satisfied_by_active_proof(command.proof_use)?;
    start_active_proof_attempt_for_subject(
        config,
        command.now,
        command.attempt_id,
        command.proof_use,
        command.subject_id,
        None,
        None,
    )
}

pub(super) fn start_active_proof_attempt_for_current_session(
    config: &Config,
    command: StartActiveProofAttemptForCurrentSession,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    validate_proof_use_can_be_satisfied_by_active_proof(command.proof_use)?;
    let Some(cookie) = loaded.session_cookie.as_ref() else {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            CommitPlan::default(),
        ));
    };
    if command.now >= cookie.session_fast_fail_until {
        let mut plan = CommitPlan::default();
        super::session_lifecycle_helpers::push_delete_session_cookie_and_cycle_csrf(&mut plan);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    }
    let Some(record) = loaded.session_record.as_ref() else {
        let mut plan = CommitPlan::default();
        super::session_lifecycle_helpers::push_delete_session_cookie_and_cycle_csrf(&mut plan);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    };
    super::session_lifecycle_helpers::validate_session_cookie_record_pair(cookie, record)?;
    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || command.now >= record.expires_at
        || super::session_lifecycle_helpers::subject_revocation_invalidates_record(
            subject_revocation,
            record.created_at,
        )
    {
        let mut plan = CommitPlan::default();
        super::session_lifecycle_helpers::push_delete_session_cookie_and_cycle_csrf(&mut plan);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    }
    let secret_match = loaded
        .session_secret_match
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "session-bound active-proof start requires session secret match",
        ))?
        .kind();
    super::session_lifecycle_helpers::validate_session_secret_match_consistency(
        command.now,
        secret_match,
        cookie,
        record,
    )?;
    if !secret_match.is_accepted() {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            super::session_lifecycle_helpers::session_tripwire_plan(command.now, record),
        ));
    }
    let mut transition = start_active_proof_attempt_for_subject(
        config,
        command.now,
        command.attempt_id,
        command.proof_use,
        Some(record.subject_id.clone()),
        Some(record.session_id.clone()),
        record.device_credential_id.clone(),
    )?;
    transition
        .commit_plan
        .preconditions
        .push(Precondition::SessionStillMatches {
            session_id: record.session_id.clone(),
            subject_id: record.subject_id.clone(),
            now: command.now,
            current_secret_version: record.current_secret_version,
        });
    Ok(transition)
}

pub(super) fn start_active_proof_attempt_for_current_trusted_device(
    config: &Config,
    command: StartActiveProofAttemptForCurrentTrustedDevice,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    validate_proof_use_can_be_satisfied_by_active_proof(command.proof_use)?;
    let Some(cookie) = loaded.trusted_device_cookie.as_ref() else {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            CommitPlan::default(),
        ));
    };
    if command.now >= cookie.device_fast_fail_until {
        let mut plan = CommitPlan::default();
        plan.response_effects
            .push(ResponseEffect::DeleteTrustedDeviceCookie);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    }
    let Some(record) = loaded.trusted_device_record.as_ref() else {
        let mut plan = CommitPlan::default();
        plan.response_effects
            .push(ResponseEffect::DeleteTrustedDeviceCookie);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    };
    super::session_lifecycle_helpers::validate_device_cookie_record_pair(cookie, record)?;
    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || command.now >= record.expires_at
        || super::session_lifecycle_helpers::subject_revocation_invalidates_record(
            subject_revocation,
            record.created_at,
        )
    {
        let mut plan = CommitPlan::default();
        plan.response_effects
            .push(ResponseEffect::DeleteTrustedDeviceCookie);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    }
    let secret_match =
        loaded
            .trusted_device_secret_match
            .as_ref()
            .ok_or(Error::LoadedStateContradiction(
                "trusted-device-bound active-proof start requires trusted-device secret match",
            ))?;
    let secret_match = super::session_lifecycle_helpers::validate_device_secret_match_consistency(
        command.now,
        secret_match,
        cookie,
        record,
    )?;
    if !secret_match.is_accepted() {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            super::session_lifecycle_helpers::trusted_device_tripwire_plan(command.now, record),
        ));
    }
    let mut transition = start_active_proof_attempt_for_subject(
        config,
        command.now,
        command.attempt_id,
        command.proof_use,
        Some(record.subject_id.clone()),
        None,
        Some(record.device_credential_id.clone()),
    )?;
    transition
        .commit_plan
        .preconditions
        .push(Precondition::TrustedDeviceStillMatches {
            device_credential_id: record.device_credential_id.clone(),
            subject_id: record.subject_id.clone(),
            now: command.now,
            current_secret_version: record.current_secret_version,
        });
    Ok(transition)
}

fn start_active_proof_attempt_for_subject(
    config: &Config,
    now: UnixSeconds,
    attempt_id: ActiveProofAttemptId,
    proof_use: ProofUse,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
    device_credential_id: Option<TrustedDeviceCredentialId>,
) -> Result<Transition, Error> {
    let expires_at = now.checked_add_duration(config.active_proof_attempt_lifetime)?;
    let record = ActiveProofAttemptRecord {
        attempt_id: attempt_id.clone(),
        proof_use,
        subject_id: subject_id.clone(),
        satisfied_proofs: Vec::new(),
        weak_proof_failures: 0,
        max_weak_proof_failures: config.max_weak_proof_failures_per_attempt,
        created_at: now,
        expires_at,
        closed_at: None,
    };

    let mut plan = CommitPlan::default();
    plan.mutations
        .push(Mutation::CreateActiveProofAttempt(record));
    plan.fresh_credential_secrets
        .push(FreshCredentialSecret::ActiveProofContinuation {
            attempt_id: attempt_id.clone(),
        });
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::ActiveProofAttemptStarted,
            occurred_at: now,
            subject_id: subject_id.clone(),
            session_id,
            device_credential_id,
            attempt_id: Some(attempt_id.clone()),
            challenge_id: None,
            weak_proof_gate: None,
        }));
    plan.response_effects
        .push(ResponseEffect::IssueActiveProofContinuationCookie(
            ActiveProofContinuationCookieDraft {
                attempt_id: attempt_id.clone(),
                proof_use,
                subject_id: subject_id.clone(),
                attempt_fast_fail_until: expires_at,
            },
        ));

    Ok(transition(
        Outcome::ActiveProofAttemptStarted {
            attempt_id,
            expires_at,
        },
        plan,
    ))
}

pub(super) fn issue_out_of_band_challenge(
    config: &Config,
    command: IssueOutOfBandChallenge,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    if command.recipient_handle.is_empty() {
        return Err(Error::EmptyOutOfBandRecipientHandle);
    }
    validate_auth_string_not_too_long(
        "out-of-band recipient handle",
        &command.recipient_handle,
        OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
    )?;
    if command.idempotency_key.is_empty() {
        return Err(Error::EmptyOutOfBandDeliveryIdempotencyKey);
    }
    validate_auth_identifier_string(
        "out-of-band delivery idempotency key",
        &command.idempotency_key,
        DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
    )?;
    if command.method.family() != ProofFamily::OutOfBandCode {
        return Err(Error::ProofMethodCannotIssueOutOfBandChallenge {
            family: command.method.family(),
        });
    }
    let proof = command.method.verified_proof_summary();
    validate_method_commit_work_for_proof(&proof, &command.method_commit_work)?;
    validate_proof_for_use(&proof, loaded_active_attempt(loaded)?.proof_use)?;
    let attempt = loaded_active_attempt(loaded)?;
    validate_active_proof_attempt_id(&command.attempt_id, attempt)?;
    ensure_active_proof_attempt_is_open(command.now, attempt)?;
    ensure_active_proof_attempt_not_subject_revoked(loaded, attempt, attempt.subject_id.as_ref())?;
    ensure_active_proof_not_already_satisfied(attempt, proof.family)?;

    let expires_at = min(
        command
            .now
            .checked_add_duration(config.out_of_band_challenge_lifetime)?,
        attempt.expires_at,
    );
    validate_active_proof_challenge_cookie_for_issue(
        &command.stateless_fast_fail_cookie,
        &command.attempt_id,
        &command.challenge_id,
        &proof,
        command.now,
        expires_at,
    )?;
    let challenge_record = ActiveProofChallengeRecord {
        challenge_id: command.challenge_id.clone(),
        attempt_id: command.attempt_id.clone(),
        proof: proof.clone(),
        challenge_dedupe_key: Some(command.challenge_dedupe_key.clone()),
        recipient_handle: Some(command.recipient_handle.clone()),
        used_delivery_idempotency_keys: vec![command.idempotency_key.clone()],
        resend_count: 0,
        max_resends: config.max_out_of_band_challenge_resends_per_challenge,
        requires_stateless_fast_fail: true,
        created_at: command.now,
        expires_at,
        closed_at: None,
    };

    let mut plan = CommitPlan::default();
    push_active_proof_attempt_still_open_precondition(
        &mut plan,
        attempt,
        command.now,
        attempt.subject_id.clone(),
    );
    plan.preconditions
        .push(Precondition::NoOpenOutOfBandChallengeForDedupeKey {
            challenge_dedupe_key: command.challenge_dedupe_key,
            now: command.now,
        });
    plan.mutations
        .push(Mutation::CreateActiveProofChallenge(challenge_record));
    plan.method_commit_work.extend(command.method_commit_work);
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::OutOfBandChallengeIssued,
            occurred_at: command.now,
            subject_id: attempt.subject_id.clone(),
            session_id: None,
            device_credential_id: None,
            attempt_id: Some(command.attempt_id.clone()),
            challenge_id: Some(command.challenge_id.clone()),
            weak_proof_gate: None,
        }));
    plan.durable_effects
        .push(DurableEffectCommand::SendOutOfBandMessage(
            OutOfBandMessageCommand {
                challenge_id: command.challenge_id.clone(),
                proof_method_label: proof.method_label,
                recipient_handle: command.recipient_handle,
                idempotency_key: command.idempotency_key,
                expires_at,
            },
        ));
    plan.response_effects
        .push(ResponseEffect::IssueActiveProofChallengeCookie(
            command.stateless_fast_fail_cookie,
        ));

    Ok(transition(
        Outcome::OutOfBandChallengeIssued {
            attempt_id: command.attempt_id,
            challenge_id: command.challenge_id,
            expires_at,
        },
        plan,
    ))
}

pub(super) fn issue_active_proof_method_challenge(
    config: &Config,
    command: IssueActiveProofMethodChallenge,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let _challenge_cookie_kind = match command.challenge_issue_kind {
        ActiveProofMethodChallengeIssueKind::NormalActiveMethod => {
            let challenge_cookie_kind = MethodAdapterContract::for_method(command.method.clone())
                .challenge_cookie()
                .kind();
            if command.method.family() == ProofFamily::OutOfBandCode
                || command.method.semantics().interaction != ProofInteraction::Active
                || challenge_cookie_kind == MethodChallengeCookieKind::NotUsed
            {
                return Err(Error::ProofMethodCannotIssueActiveProofMethodChallenge {
                    family: command.method.family(),
                });
            }
            challenge_cookie_kind
        }
        ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail => {
            MethodAdapterContract::for_challenge_bound_configured_secret_method(
                command.method.clone(),
            )?
            .challenge_cookie()
            .kind()
        }
    };
    let proof = command.method.verified_proof_summary();
    validate_method_commit_work_for_proof(&proof, &command.method_commit_work)?;
    validate_proof_for_use(&proof, loaded_active_attempt(loaded)?.proof_use)?;
    let attempt = loaded_active_attempt(loaded)?;
    validate_active_proof_attempt_id(&command.attempt_id, attempt)?;
    ensure_active_proof_attempt_is_open(command.now, attempt)?;
    ensure_active_proof_attempt_not_subject_revoked(loaded, attempt, attempt.subject_id.as_ref())?;
    ensure_active_proof_not_already_satisfied(attempt, proof.family)?;
    if command.challenge_issue_kind
        == ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail
        && attempt.subject_id.is_none()
    {
        return Err(Error::LoadedStateContradiction(
            "challenge-bound configured-secret proof requires a subject-bound attempt",
        ));
    }

    let expires_at = min(
        command
            .now
            .checked_add_duration(config.out_of_band_challenge_lifetime)?,
        attempt.expires_at,
    );
    validate_active_proof_challenge_cookie_for_issue(
        &command.challenge_cookie,
        &command.attempt_id,
        &command.challenge_id,
        &proof,
        command.now,
        expires_at,
    )?;
    let requires_stateless_fast_fail = command.challenge_issue_kind
        == ActiveProofMethodChallengeIssueKind::ChallengeBoundConfiguredSecretFastFail;
    if command.challenge_cookie.requires_stateless_fast_fail() != requires_stateless_fast_fail {
        return Err(Error::LoadedStateContradiction(
            "active-proof method challenge cookie stateless fast-fail requirement does not match challenge lane",
        ));
    }
    let challenge_record = ActiveProofChallengeRecord {
        challenge_id: command.challenge_id.clone(),
        attempt_id: command.attempt_id.clone(),
        proof: proof.clone(),
        challenge_dedupe_key: None,
        recipient_handle: None,
        used_delivery_idempotency_keys: Vec::new(),
        resend_count: 0,
        max_resends: 0,
        requires_stateless_fast_fail,
        created_at: command.now,
        expires_at,
        closed_at: None,
    };

    let mut plan = CommitPlan::default();
    push_active_proof_attempt_still_open_precondition(
        &mut plan,
        attempt,
        command.now,
        attempt.subject_id.clone(),
    );
    plan.mutations
        .push(Mutation::CreateActiveProofChallenge(challenge_record));
    plan.method_commit_work.extend(command.method_commit_work);
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::ActiveProofMethodChallengeIssued,
            occurred_at: command.now,
            subject_id: attempt.subject_id.clone(),
            session_id: None,
            device_credential_id: None,
            attempt_id: Some(command.attempt_id.clone()),
            challenge_id: Some(command.challenge_id.clone()),
            weak_proof_gate: None,
        }));
    plan.response_effects
        .push(ResponseEffect::IssueActiveProofChallengeCookie(
            command.challenge_cookie,
        ));

    Ok(transition(
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: command.attempt_id,
            challenge_id: command.challenge_id,
            proof,
            method_challenge: command.method_challenge,
            expires_at,
        },
        plan,
    ))
}

pub(super) fn resend_out_of_band_challenge(
    command: ResendOutOfBandChallenge,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    if command.idempotency_key.is_empty() {
        return Err(Error::EmptyOutOfBandDeliveryIdempotencyKey);
    }
    validate_auth_identifier_string(
        "out-of-band delivery idempotency key",
        &command.idempotency_key,
        DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
    )?;
    let attempt = loaded_active_attempt(loaded)?;
    validate_active_proof_attempt_id(&command.attempt_id, attempt)?;
    ensure_active_proof_attempt_is_open(command.now, attempt)?;
    ensure_active_proof_attempt_not_subject_revoked(loaded, attempt, attempt.subject_id.as_ref())?;
    ensure_active_proof_not_already_satisfied(attempt, ProofFamily::OutOfBandCode)?;
    let challenge = loaded_active_challenge(loaded)?;
    validate_active_proof_challenge_id(&command.challenge_id, challenge)?;
    validate_challenge_attempt_pair(attempt, challenge)?;
    ensure_active_proof_challenge_is_open(command.now, challenge)?;
    if challenge.proof.family != ProofFamily::OutOfBandCode {
        return Err(Error::LoadedStateContradiction(
            "non-out-of-band challenge cannot be resent",
        ));
    }
    let Some(recipient_handle) = challenge.recipient_handle.clone() else {
        return Err(Error::LoadedStateContradiction(
            "out-of-band challenge is missing recipient handle",
        ));
    };
    if challenge.challenge_dedupe_key.is_none() || !challenge.requires_stateless_fast_fail {
        return Err(Error::LoadedStateContradiction(
            "out-of-band resend loaded a non-out-of-band challenge",
        ));
    }
    validate_method_commit_work_for_proof(&challenge.proof, &command.method_commit_work)?;
    validate_used_delivery_idempotency_keys(challenge)?;
    if challenge
        .used_delivery_idempotency_keys
        .contains(&command.idempotency_key)
    {
        return Err(Error::OutOfBandDeliveryIdempotencyKeyAlreadyUsed);
    }
    if challenge.resend_count >= challenge.max_resends {
        return Err(Error::OutOfBandChallengeResendBudgetExhausted);
    }
    let resend_count =
        challenge
            .resend_count
            .checked_add(1)
            .ok_or(Error::LoadedStateContradiction(
                "out-of-band challenge resend count overflow",
            ))?;

    let mut plan = CommitPlan::default();
    push_active_proof_attempt_still_open_precondition(
        &mut plan,
        attempt,
        command.now,
        attempt.subject_id.clone(),
    );
    plan.preconditions
        .push(Precondition::OutOfBandChallengeResendStillAllowed {
            challenge_id: challenge.challenge_id.clone(),
            now: command.now,
            observed_resend_count: challenge.resend_count,
            observed_used_delivery_idempotency_keys: challenge
                .used_delivery_idempotency_keys
                .clone(),
        });
    let mut used_delivery_idempotency_keys = challenge.used_delivery_idempotency_keys.clone();
    used_delivery_idempotency_keys.push(command.idempotency_key.clone());
    plan.mutations
        .push(Mutation::RecordOutOfBandChallengeResent {
            challenge_id: challenge.challenge_id.clone(),
            resend_count,
            used_delivery_idempotency_keys,
            resent_at: command.now,
        });
    plan.method_commit_work.extend(command.method_commit_work);
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::OutOfBandChallengeResent,
            occurred_at: command.now,
            subject_id: attempt.subject_id.clone(),
            session_id: None,
            device_credential_id: None,
            attempt_id: Some(attempt.attempt_id.clone()),
            challenge_id: Some(challenge.challenge_id.clone()),
            weak_proof_gate: None,
        }));
    plan.durable_effects
        .push(DurableEffectCommand::SendOutOfBandMessage(
            OutOfBandMessageCommand {
                challenge_id: challenge.challenge_id.clone(),
                proof_method_label: challenge.proof.method_label.clone(),
                recipient_handle,
                idempotency_key: command.idempotency_key,
                expires_at: challenge.expires_at,
            },
        ));

    Ok(transition(
        Outcome::OutOfBandChallengeResent {
            attempt_id: command.attempt_id,
            challenge_id: command.challenge_id,
            resend_count,
            expires_at: challenge.expires_at,
        },
        plan,
    ))
}

pub(super) fn complete_active_proof_challenge(
    command: CompleteActiveProofChallenge,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let (satisfied_proof, supplied_subject_id) = command.verified_proof.into_parts();
    let proof = satisfied_proof.proof().clone();
    let attempt = loaded_active_attempt(loaded)?;
    validate_active_proof_attempt_id(&command.attempt_id, attempt)?;
    ensure_active_proof_attempt_is_open(command.now, attempt)?;
    validate_proof_for_use(&proof, attempt.proof_use)?;
    validate_weak_proof_gate_for_proof(&proof, &command.weak_proof_gate)?;
    let subject_id_after_completion =
        active_proof_subject_id_after_completion(attempt, &proof, supplied_subject_id)?;
    ensure_active_proof_attempt_not_subject_revoked(
        loaded,
        attempt,
        subject_id_after_completion.as_ref(),
    )?;
    ensure_active_proof_not_already_satisfied(attempt, proof.family)?;
    validate_method_commit_work_for_proof(&proof, &command.method_commit_work)?;
    let weak_proof_gate = command.weak_proof_gate.verified_summary();

    let mut plan = CommitPlan::default();

    if proof.family == ProofFamily::OutOfBandCode && command.challenge_id.is_none() {
        return Err(Error::MissingFreshValue(
            "challenge_id for out-of-band proof",
        ));
    }
    if let Some(challenge_id) = &command.challenge_id {
        let challenge = loaded_active_challenge(loaded)?;
        validate_active_proof_challenge_id(challenge_id, challenge)?;
        validate_challenge_attempt_pair(attempt, challenge)?;
        ensure_active_proof_challenge_is_open(command.now, challenge)?;
        if challenge.proof != proof {
            return Err(Error::LoadedStateContradiction(
                "active-proof challenge proof differs from satisfied proof",
            ));
        }
        if proof.family.semantics().subject_role == ProofSubjectRole::RequiresKnownSubject
            && !(proof.family == ProofFamily::SharedSecretOtp
                && challenge.requires_stateless_fast_fail
                && command.stateless_fast_fail.was_verified_before_state_load())
        {
            return Err(Error::LoadedStateContradiction(
                "known-subject proof family cannot complete through this active-proof challenge",
            ));
        }
        if challenge.requires_stateless_fast_fail
            && !command.stateless_fast_fail.was_verified_before_state_load()
        {
            return Err(Error::StatelessFastFailVerificationRequired);
        }
        plan.preconditions
            .push(Precondition::ActiveProofChallengeStillOpen {
                challenge_id: challenge.challenge_id.clone(),
                now: command.now,
            });
        plan.mutations.push(
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
                attempt_id: attempt.attempt_id.clone(),
                proof_family: challenge.proof.family,
                closed_at: command.now,
            },
        );
        plan.response_effects
            .push(ResponseEffect::DeleteActiveProofChallengeCookie);
    }

    push_active_proof_attempt_still_open_precondition(
        &mut plan,
        attempt,
        command.now,
        subject_id_after_completion.clone(),
    );

    plan.mutations.push(Mutation::RecordActiveProofSucceeded {
        attempt_id: command.attempt_id.clone(),
        subject_id: subject_id_after_completion.clone(),
        proof: satisfied_proof,
        satisfied_at: command.now,
    });
    plan.method_commit_work.extend(command.method_commit_work);
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::ActiveProofSucceeded,
            occurred_at: command.now,
            subject_id: subject_id_after_completion,
            session_id: None,
            device_credential_id: None,
            attempt_id: Some(command.attempt_id.clone()),
            challenge_id: command.challenge_id.clone(),
            weak_proof_gate,
        }));

    Ok(transition(
        Outcome::ActiveProofCompleted {
            attempt_id: command.attempt_id,
            proof,
        },
        plan,
    ))
}

fn validate_active_proof_challenge_cookie_for_issue(
    cookie: &ActiveProofChallengeCookieDraft,
    attempt_id: &ActiveProofAttemptId,
    challenge_id: &ActiveProofChallengeId,
    proof: &ProofSummary,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> Result<(), Error> {
    if cookie.attempt_id != *attempt_id
        || cookie.challenge_id != *challenge_id
        || cookie.proof != *proof
        || cookie.issued_at != issued_at
        || cookie.expires_at != expires_at
    {
        return Err(Error::ActiveProofChallengeCookieCommandMismatch);
    }
    Ok(())
}

pub(super) fn record_active_proof_failure(
    command: RecordActiveProofFailure,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let proof = command.method.verified_proof_summary();
    let attempt = loaded_active_attempt(loaded)?;
    validate_active_proof_attempt_id(&command.attempt_id, attempt)?;
    ensure_active_proof_attempt_is_open(command.now, attempt)?;
    ensure_active_proof_attempt_not_subject_revoked(loaded, attempt, attempt.subject_id.as_ref())?;
    validate_proof_for_use(&proof, attempt.proof_use)?;
    validate_weak_proof_gate_for_proof(&proof, &command.weak_proof_gate)?;
    let weak_proof_gate = command.weak_proof_gate.verified_summary();

    let mut plan = CommitPlan::default();
    if let Some(challenge_id) = &command.challenge_id {
        let challenge = loaded_active_challenge(loaded)?;
        validate_active_proof_challenge_id(challenge_id, challenge)?;
        validate_challenge_attempt_pair(attempt, challenge)?;
        ensure_active_proof_challenge_is_open(command.now, challenge)?;
        if challenge.proof != proof {
            return Err(Error::LoadedStateContradiction(
                "active-proof failure challenge proof differs from failed proof",
            ));
        }
        plan.preconditions
            .push(Precondition::ActiveProofChallengeStillOpen {
                challenge_id: challenge.challenge_id.clone(),
                now: command.now,
            });
    }
    push_active_proof_attempt_still_open_precondition(
        &mut plan,
        attempt,
        command.now,
        attempt.subject_id.clone(),
    );
    plan.audit_events
        .push(active_proof_audit_event(ActiveProofAuditEventInput {
            kind: AuditEventKind::ActiveProofFailed,
            occurred_at: command.now,
            subject_id: attempt.subject_id.clone(),
            session_id: None,
            device_credential_id: None,
            attempt_id: Some(command.attempt_id.clone()),
            challenge_id: command.challenge_id.clone(),
            weak_proof_gate: weak_proof_gate.clone(),
        }));

    let mut attempt_was_deleted = false;
    if proof.uses_weak_attempt_failure_budget() {
        let weak_proof_failures =
            attempt
                .weak_proof_failures
                .checked_add(1)
                .ok_or(Error::LoadedStateContradiction(
                    "weak proof failure count overflow",
                ))?;
        if weak_proof_failures >= attempt.max_weak_proof_failures {
            attempt_was_deleted = true;
            plan.mutations.push(Mutation::DeleteActiveProofAttempt {
                attempt_id: command.attempt_id.clone(),
            });
            plan.response_effects
                .push(ResponseEffect::DeleteActiveProofContinuationCookie);
            plan.audit_events
                .push(active_proof_audit_event(ActiveProofAuditEventInput {
                    kind: AuditEventKind::ActiveProofAttemptDeletedAfterWeakProofFailures,
                    occurred_at: command.now,
                    subject_id: attempt.subject_id.clone(),
                    session_id: None,
                    device_credential_id: None,
                    attempt_id: Some(command.attempt_id.clone()),
                    challenge_id: None,
                    weak_proof_gate,
                }));
        } else {
            plan.mutations.push(Mutation::RecordWeakProofFailure {
                attempt_id: command.attempt_id.clone(),
                weak_proof_failures,
            });
        }
    }

    Ok(transition(
        Outcome::ActiveProofFailureRecorded {
            attempt_id: command.attempt_id,
            attempt_was_deleted,
        },
        plan,
    ))
}
