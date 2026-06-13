use std::cmp::min;

use super::prelude::*;
use super::session_lifecycle_helpers::*;
use super::{active_proof, audit_event, transition};

pub(super) fn complete_full_authentication(
    config: &Config,
    command: CompleteFullAuthentication,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let attempt = active_proof::validate_active_proof_attempt_satisfies_use(
        &config.proof_policy,
        loaded,
        &command.attempt_id,
        command.now,
        ProofUse::ContributeToFullAuthentication,
    )?;
    let subject_id = attempt
        .subject_id
        .clone()
        .ok_or(Error::LoadedStateContradiction(
            "full authentication completion requires a subject-bound attempt",
        ))?;

    let session_secret_version = SecretVersion::new(1)?;
    let session_expires_at = command
        .now
        .checked_add_duration(config.short_session_lifetime)?;
    let step_up_expires_at = command.now.checked_add_duration(config.step_up_lifetime)?;
    let session_record = SessionRecord {
        session_id: command.fresh_session_id.clone(),
        subject_id: subject_id.clone(),
        device_credential_id: command
            .trust_device
            .as_ref()
            .map(|device| device.device_credential_id.clone()),
        current_secret_version: session_secret_version,
        previous_secret_version: None,
        previous_secret_accept_until: None,
        created_at: command.now,
        refreshed_at: command.now,
        expires_at: session_expires_at,
        step_up_expires_at: Some(step_up_expires_at),
        revoked_at: None,
    };

    let mut plan = CommitPlan::default();
    active_proof::append_active_proof_attempt_closure_to_plan(
        &mut plan,
        command.now,
        attempt,
        Some(subject_id.clone()),
        Some(command.fresh_session_id.clone()),
        command
            .trust_device
            .as_ref()
            .map(|device| device.device_credential_id.clone()),
    );
    plan.mutations
        .push(Mutation::CreateSession(session_record.clone()));
    push_fresh_session_secret(
        &mut plan,
        session_record.session_id.clone(),
        session_secret_version,
    );
    plan.audit_events.push(audit_event(
        AuditEventKind::SessionCreated,
        command.now,
        Some(subject_id.clone()),
        Some(command.fresh_session_id.clone()),
        command
            .trust_device
            .as_ref()
            .map(|device| device.device_credential_id.clone()),
    ));
    plan.response_effects
        .push(ResponseEffect::IssueSessionCookie(
            session_cookie_for_record(config, command.now, &session_record)?,
        ));
    plan.response_effects.push(ResponseEffect::CycleCsrfToken {
        session_id: Some(command.fresh_session_id.clone()),
    });

    if let Some(device) = command.trust_device {
        if let Some(display_label) = &device.display_label {
            validate_auth_string_not_too_long(
                "trusted-device display label",
                display_label,
                TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES,
            )?;
        }
        let expires_at = command
            .now
            .checked_add_duration(config.trusted_device_credential_lifetime)?;
        let silent_revival_until = min(
            command
                .now
                .checked_add_duration(config.trusted_device_silent_revival_lifetime)?,
            expires_at,
        );
        let device_record = TrustedDeviceCredentialRecord {
            device_credential_id: device.device_credential_id.clone(),
            subject_id: subject_id.clone(),
            current_secret_version: SecretVersion::new(1)?,
            previous_secret_version: None,
            previous_secret_accept_until: None,
            created_at: command.now,
            last_used_at: command.now,
            expires_at,
            silent_revival_until,
            revoked_at: None,
            display_label: device.display_label,
        };
        plan.mutations.push(Mutation::CreateTrustedDeviceCredential(
            device_record.clone(),
        ));
        push_fresh_trusted_device_secret(
            &mut plan,
            device_record.device_credential_id.clone(),
            device_record.current_secret_version,
        );
        plan.audit_events.push(audit_event(
            AuditEventKind::TrustedDeviceCreated,
            command.now,
            Some(subject_id.clone()),
            Some(command.fresh_session_id.clone()),
            Some(device.device_credential_id.clone()),
        ));
        plan.durable_effects
            .push(DurableEffectCommand::NotifySecurityEvent(
                SecurityNotificationCommand {
                    kind: SecurityNotificationKind::TrustedDeviceCreated,
                    subject_id: subject_id.clone(),
                },
            ));
        plan.response_effects
            .push(ResponseEffect::IssueTrustedDeviceCookie(
                device_cookie_for_record(&device_record),
            ));
    }

    Ok(transition(
        Outcome::Authenticated(Authenticated {
            subject_id,
            session_id: command.fresh_session_id,
            source: AuthenticationSource::FullAuthentication,
            step_up_is_fresh: true,
        }),
        plan,
    ))
}

pub(super) fn complete_step_up(
    config: &Config,
    command: CompleteStepUp,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let record = match &loaded.session_record {
        Some(record) => record,
        None => {
            let mut plan = CommitPlan::default();
            if loaded.session_cookie.is_some() {
                push_delete_session_cookie_and_cycle_csrf(&mut plan);
            }
            return Ok(transition(Outcome::NeedsFullAuthentication, plan));
        }
    };
    let cookie = loaded
        .session_cookie
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "step-up completion requires session cookie",
        ))?;
    validate_session_cookie_record_pair(cookie, record)?;
    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || command.now >= record.expires_at
        || subject_revocation_invalidates_record(subject_revocation, record.created_at)
    {
        let mut plan = CommitPlan::default();
        push_delete_session_cookie_and_cycle_csrf(&mut plan);
        return Ok(transition(Outcome::NeedsFullAuthentication, plan));
    }
    let secret_match = loaded
        .session_secret_match
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "step-up completion requires session secret match",
        ))?
        .kind();
    validate_session_secret_match_consistency(command.now, secret_match, cookie, record)?;
    if !secret_match.is_accepted() {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            session_tripwire_plan(command.now, record),
        ));
    }
    let attempt = active_proof::validate_active_proof_attempt_satisfies_use(
        &config.proof_policy,
        loaded,
        &command.attempt_id,
        command.now,
        ProofUse::SatisfyStepUp,
    )?;
    active_proof::ensure_active_proof_attempt_matches_subject(attempt, &record.subject_id)?;

    let new_secret_version = record.current_secret_version.next()?;
    let previous_secret_accept_until = command
        .now
        .checked_add_duration(config.stale_secret_grace_lifetime)?;
    let step_up_expires_at = command.now.checked_add_duration(config.step_up_lifetime)?;
    let mut stepped_up_record = record.clone();
    stepped_up_record.current_secret_version = new_secret_version;
    stepped_up_record.previous_secret_version = Some(record.current_secret_version);
    stepped_up_record.previous_secret_accept_until = Some(previous_secret_accept_until);
    stepped_up_record.step_up_expires_at = Some(step_up_expires_at);

    let mut plan = CommitPlan::default();
    plan.preconditions.push(Precondition::SessionStillMatches {
        session_id: record.session_id.clone(),
        subject_id: record.subject_id.clone(),
        now: command.now,
        current_secret_version: record.current_secret_version,
    });
    active_proof::append_active_proof_attempt_closure_to_plan(
        &mut plan,
        command.now,
        attempt,
        Some(record.subject_id.clone()),
        Some(record.session_id.clone()),
        record.device_credential_id.clone(),
    );
    plan.mutations.push(Mutation::RecordStepUp {
        session_id: record.session_id.clone(),
        new_secret_version,
        previous_secret_version: record.current_secret_version,
        previous_secret_accept_until,
        step_up_expires_at,
    });
    push_fresh_session_secret(&mut plan, record.session_id.clone(), new_secret_version);
    plan.audit_events.push(audit_event(
        AuditEventKind::StepUpCompleted,
        command.now,
        Some(record.subject_id.clone()),
        Some(record.session_id.clone()),
        record.device_credential_id.clone(),
    ));
    plan.response_effects
        .push(ResponseEffect::IssueSessionCookie(
            session_cookie_for_record(config, command.now, &stepped_up_record)?,
        ));
    plan.response_effects.push(ResponseEffect::CycleCsrfToken {
        session_id: Some(record.session_id.clone()),
    });

    Ok(transition(
        Outcome::Authenticated(Authenticated {
            subject_id: record.subject_id.clone(),
            session_id: record.session_id.clone(),
            source: AuthenticationSource::StepUp,
            step_up_is_fresh: true,
        }),
        plan,
    ))
}

pub(super) fn complete_trusted_device_revival_with_active_proof(
    config: &Config,
    command: CompleteTrustedDeviceRevivalWithActiveProof,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let record = match &loaded.trusted_device_record {
        Some(record) => record,
        None => {
            let mut plan = CommitPlan::default();
            if loaded.trusted_device_cookie.is_some() {
                plan.response_effects
                    .push(ResponseEffect::DeleteTrustedDeviceCookie);
            }
            return Ok(transition(Outcome::NeedsFullAuthentication, plan));
        }
    };
    let cookie = loaded
        .trusted_device_cookie
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "trusted-device active-proof completion requires trusted-device cookie",
        ))?;
    validate_device_cookie_record_pair(cookie, record)?;
    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || command.now >= record.expires_at
        || subject_revocation_invalidates_record(subject_revocation, record.created_at)
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
                "trusted-device active-proof completion requires trusted-device secret match",
            ))?;
    let secret_match =
        validate_device_secret_match_consistency(command.now, secret_match, cookie, record)?;
    if !secret_match.is_accepted() {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            trusted_device_tripwire_plan(command.now, record),
        ));
    }
    let attempt = active_proof::validate_active_proof_attempt_satisfies_use(
        &config.proof_policy,
        loaded,
        &command.attempt_id,
        command.now,
        ProofUse::ReviveTrustedDeviceWithActiveProof,
    )?;
    active_proof::ensure_active_proof_attempt_matches_subject(attempt, &record.subject_id)?;

    let session_secret_version = SecretVersion::new(1)?;
    let device_secret_version = record.current_secret_version.next()?;
    let previous_secret_accept_until = command
        .now
        .checked_add_duration(config.stale_secret_grace_lifetime)?;
    let session_expires_at = command
        .now
        .checked_add_duration(config.short_session_lifetime)?;
    let step_up_expires_at = command.now.checked_add_duration(config.step_up_lifetime)?;
    let silent_revival_until = min(
        command
            .now
            .checked_add_duration(config.trusted_device_silent_revival_lifetime)?,
        record.expires_at,
    );
    let session_record = SessionRecord {
        session_id: command.fresh_session_id.clone(),
        subject_id: record.subject_id.clone(),
        device_credential_id: Some(record.device_credential_id.clone()),
        current_secret_version: session_secret_version,
        previous_secret_version: None,
        previous_secret_accept_until: None,
        created_at: command.now,
        refreshed_at: command.now,
        expires_at: session_expires_at,
        step_up_expires_at: Some(step_up_expires_at),
        revoked_at: None,
    };
    let mut rotated_device = record.clone();
    rotated_device.current_secret_version = device_secret_version;
    rotated_device.previous_secret_version = Some(record.current_secret_version);
    rotated_device.previous_secret_accept_until = Some(previous_secret_accept_until);
    rotated_device.last_used_at = command.now;
    rotated_device.silent_revival_until = silent_revival_until;

    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::TrustedDeviceBelongsToSubject {
            device_credential_id: record.device_credential_id.clone(),
            subject_id: record.subject_id.clone(),
        });
    plan.preconditions
        .push(Precondition::TrustedDeviceStillMatches {
            device_credential_id: record.device_credential_id.clone(),
            subject_id: record.subject_id.clone(),
            now: command.now,
            current_secret_version: record.current_secret_version,
        });
    active_proof::append_active_proof_attempt_closure_to_plan(
        &mut plan,
        command.now,
        attempt,
        Some(record.subject_id.clone()),
        Some(command.fresh_session_id.clone()),
        Some(record.device_credential_id.clone()),
    );
    plan.mutations
        .push(Mutation::CreateSession(session_record.clone()));
    push_fresh_session_secret(
        &mut plan,
        session_record.session_id.clone(),
        session_secret_version,
    );
    plan.mutations
        .push(Mutation::RotateTrustedDeviceCredential {
            device_credential_id: record.device_credential_id.clone(),
            new_secret_version: device_secret_version,
            previous_secret_version: record.current_secret_version,
            previous_secret_accept_until,
            last_used_at: command.now,
            silent_revival_until,
            expires_at: record.expires_at,
        });
    push_fresh_trusted_device_secret(
        &mut plan,
        record.device_credential_id.clone(),
        device_secret_version,
    );
    plan.audit_events.push(audit_event(
        AuditEventKind::SessionCreated,
        command.now,
        Some(record.subject_id.clone()),
        Some(command.fresh_session_id.clone()),
        Some(record.device_credential_id.clone()),
    ));
    plan.audit_events.push(audit_event(
        AuditEventKind::TrustedDeviceActiveProofRevival,
        command.now,
        Some(record.subject_id.clone()),
        Some(command.fresh_session_id.clone()),
        Some(record.device_credential_id.clone()),
    ));
    plan.audit_events.push(audit_event(
        AuditEventKind::TrustedDeviceRotated,
        command.now,
        Some(record.subject_id.clone()),
        None,
        Some(record.device_credential_id.clone()),
    ));
    plan.response_effects
        .push(ResponseEffect::IssueSessionCookie(
            session_cookie_for_record(config, command.now, &session_record)?,
        ));
    plan.response_effects
        .push(ResponseEffect::IssueTrustedDeviceCookie(
            device_cookie_for_record(&rotated_device),
        ));
    plan.response_effects.push(ResponseEffect::CycleCsrfToken {
        session_id: Some(command.fresh_session_id.clone()),
    });

    Ok(transition(
        Outcome::Authenticated(Authenticated {
            subject_id: record.subject_id.clone(),
            session_id: command.fresh_session_id,
            source: AuthenticationSource::TrustedDeviceRevivalWithActiveProof,
            step_up_is_fresh: true,
        }),
        plan,
    ))
}
