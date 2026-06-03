use std::cmp::min;

use super::session_lifecycle_helpers::*;
use super::{audit_event, transition, *};

pub(super) fn resolve_request(
    config: &Config,
    command: ResolveRequest,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    if let Some(authenticated) = authenticate_from_safe_read_cache(config, &command, loaded)? {
        return Ok(transition(
            Outcome::Authenticated(authenticated),
            CommitPlan::default(),
        ));
    }

    let mut pending_session_rejection_plan = None;
    if loaded.session_cookie.is_some() {
        if loaded.session_record.is_some() {
            let session_plan =
                resolve_loaded_session(config, command.now, command.request_kind, loaded)?;
            match session_plan {
                LoadedSessionResolution::Authenticated(authenticated, session_plan) => {
                    return Ok(transition(
                        Outcome::Authenticated(authenticated),
                        session_plan,
                    ));
                }
                LoadedSessionResolution::NeedsStepUp {
                    session_id,
                    subject_id,
                } => {
                    return Ok(transition(
                        Outcome::NeedsStepUp {
                            session_id,
                            subject_id,
                        },
                        CommitPlan::default(),
                    ));
                }
                LoadedSessionResolution::Rejected(rejection_plan) => {
                    pending_session_rejection_plan = Some(rejection_plan);
                }
            }
        } else {
            let mut plan = CommitPlan::default();
            push_delete_session_cookie_and_cycle_csrf(&mut plan);
            pending_session_rejection_plan = Some(plan);
        }
    }

    if let Some(device_cookie) = &loaded.trusted_device_cookie {
        if pending_session_rejection_plan.as_ref().is_some_and(|plan| {
            plan_revokes_trusted_device(plan, &device_cookie.device_credential_id)
        }) {
            let mut plan = pending_session_rejection_plan.unwrap_or_default();
            if !plan
                .response_effects
                .contains(&ResponseEffect::DeleteTrustedDeviceCookie)
            {
                plan.response_effects
                    .push(ResponseEffect::DeleteTrustedDeviceCookie);
            }
            return Ok(transition(Outcome::NeedsFullAuthentication, plan));
        }
        let mut device_resolution = if command.now >= device_cookie.device_fast_fail_until {
            let mut plan = CommitPlan::default();
            plan.response_effects
                .push(ResponseEffect::DeleteTrustedDeviceCookie);
            transition(Outcome::NeedsFullAuthentication, plan)
        } else if loaded.trusted_device_record.is_some() {
            resolve_loaded_trusted_device(config, command.now, command.fresh_session_id, loaded)?
        } else {
            let mut plan = CommitPlan::default();
            plan.response_effects
                .push(ResponseEffect::DeleteTrustedDeviceCookie);
            transition(Outcome::NeedsFullAuthentication, plan)
        };
        if let Some(pending_plan) = pending_session_rejection_plan {
            if matches!(device_resolution.outcome, Outcome::Authenticated(_)) {
                merge_session_rejection_before_replacement_session(
                    &mut device_resolution.commit_plan,
                    pending_plan,
                );
            } else {
                let mut merged_plan = pending_plan;
                merged_plan.merge(device_resolution.commit_plan);
                device_resolution.commit_plan = merged_plan;
            }
        }
        return Ok(device_resolution);
    }

    let plan = pending_session_rejection_plan.unwrap_or_default();
    Ok(transition(Outcome::NeedsFullAuthentication, plan))
}

fn resolve_loaded_session(
    config: &Config,
    now: UnixSeconds,
    request_kind: RequestKind,
    loaded: &LoadedState,
) -> Result<LoadedSessionResolution, Error> {
    let cookie = loaded
        .session_cookie
        .as_ref()
        .ok_or(Error::LoadedStateContradiction("session cookie missing"))?;
    let record = loaded
        .session_record
        .as_ref()
        .ok_or(Error::LoadedStateContradiction("session record missing"))?;
    validate_session_cookie_record_pair(cookie, record)?;

    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || now >= record.expires_at
        || subject_revocation_invalidates_record(subject_revocation, record.created_at)
    {
        let mut plan = CommitPlan::default();
        push_delete_session_cookie_and_cycle_csrf(&mut plan);
        return Ok(LoadedSessionResolution::Rejected(plan));
    }

    let secret_match = loaded
        .session_secret_match
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "session secret match missing",
        ))?
        .kind();
    validate_session_secret_match_consistency(now, secret_match, cookie, record)?;
    if !secret_match.is_accepted() {
        return Ok(LoadedSessionResolution::Rejected(session_tripwire_plan(
            now, record,
        )));
    }

    if request_kind == RequestKind::Sensitive && !step_up_is_fresh(record.step_up_expires_at, now) {
        return Ok(LoadedSessionResolution::NeedsStepUp {
            session_id: record.session_id.clone(),
            subject_id: record.subject_id.clone(),
        });
    }

    if session_is_inside_refresh_window(config, now, record.expires_at) {
        return refresh_session(config, now, record);
    }

    let mut plan = CommitPlan::default();
    plan.preconditions.push(Precondition::SessionStillMatches {
        session_id: record.session_id.clone(),
        subject_id: record.subject_id.clone(),
        now,
        current_secret_version: record.current_secret_version,
    });
    if secret_match == StoredSecretMatch::Current && config.safe_read_cache_lifetime.is_some() {
        plan.response_effects
            .push(ResponseEffect::IssueSessionCookie(
                session_cookie_for_record(config, now, record)?,
            ));
    }
    let authenticated = Authenticated {
        subject_id: record.subject_id.clone(),
        session_id: record.session_id.clone(),
        source: AuthenticationSource::AuthoritativeSession,
        step_up_is_fresh: step_up_is_fresh(record.step_up_expires_at, now),
    };
    Ok(LoadedSessionResolution::Authenticated(authenticated, plan))
}

fn refresh_session(
    config: &Config,
    now: UnixSeconds,
    record: &SessionRecord,
) -> Result<LoadedSessionResolution, Error> {
    let new_secret_version = record.current_secret_version.next()?;
    let previous_secret_accept_until =
        now.checked_add_duration(config.stale_secret_grace_lifetime)?;
    let expires_at = now.checked_add_duration(config.short_session_lifetime)?;
    let mut refreshed_record = record.clone();
    refreshed_record.current_secret_version = new_secret_version;
    refreshed_record.previous_secret_version = Some(record.current_secret_version);
    refreshed_record.previous_secret_accept_until = Some(previous_secret_accept_until);
    refreshed_record.refreshed_at = now;
    refreshed_record.expires_at = expires_at;

    let mut plan = CommitPlan::default();
    plan.preconditions.push(Precondition::SessionStillMatches {
        session_id: record.session_id.clone(),
        subject_id: record.subject_id.clone(),
        now,
        current_secret_version: record.current_secret_version,
    });
    plan.mutations.push(Mutation::RefreshSession {
        session_id: record.session_id.clone(),
        new_secret_version,
        previous_secret_version: record.current_secret_version,
        previous_secret_accept_until,
        refreshed_at: now,
        expires_at,
    });
    push_fresh_session_secret(&mut plan, record.session_id.clone(), new_secret_version);
    plan.audit_events.push(audit_event(
        AuditEventKind::SessionRefreshed,
        now,
        Some(record.subject_id.clone()),
        Some(record.session_id.clone()),
        record.device_credential_id.clone(),
    ));
    plan.response_effects
        .push(ResponseEffect::IssueSessionCookie(
            session_cookie_for_record(config, now, &refreshed_record)?,
        ));
    plan.response_effects.push(ResponseEffect::CycleCsrfToken {
        session_id: Some(record.session_id.clone()),
    });

    let authenticated = Authenticated {
        subject_id: record.subject_id.clone(),
        session_id: record.session_id.clone(),
        source: AuthenticationSource::RefreshedSession,
        step_up_is_fresh: step_up_is_fresh(record.step_up_expires_at, now),
    };
    Ok(LoadedSessionResolution::Authenticated(authenticated, plan))
}

fn resolve_loaded_trusted_device(
    config: &Config,
    now: UnixSeconds,
    fresh_session_id: Option<SessionId>,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let cookie = loaded
        .trusted_device_cookie
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "trusted-device cookie missing",
        ))?;
    let record = loaded
        .trusted_device_record
        .as_ref()
        .ok_or(Error::LoadedStateContradiction(
            "trusted-device record missing",
        ))?;
    validate_device_cookie_record_pair(cookie, record)?;

    let subject_revocation = loaded
        .subject_revocations
        .required_revocation_for_subject(&record.subject_id)?;
    if record.revoked_at.is_some()
        || now >= record.expires_at
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
                "trusted-device secret match missing",
            ))?;
    let secret_match = validate_device_secret_match_consistency(now, secret_match, cookie, record)?;
    if !secret_match.is_accepted() {
        return Ok(transition(
            Outcome::NeedsFullAuthentication,
            trusted_device_tripwire_plan(now, record),
        ));
    }

    if now >= record.silent_revival_until {
        return Ok(transition(
            Outcome::NeedsActiveProofFromTrustedDevice {
                device_credential_id: record.device_credential_id.clone(),
                subject_id: record.subject_id.clone(),
            },
            CommitPlan::default(),
        ));
    }

    let session_id = fresh_session_id.ok_or(Error::MissingFreshValue(
        "fresh_session_id for silent trusted-device revival",
    ))?;
    let session_secret_version = SecretVersion::new(1)?;
    let device_secret_version = record.current_secret_version.next()?;
    let previous_secret_accept_until =
        now.checked_add_duration(config.stale_secret_grace_lifetime)?;
    let session_expires_at = now.checked_add_duration(config.short_session_lifetime)?;
    let session_record = SessionRecord {
        session_id: session_id.clone(),
        subject_id: record.subject_id.clone(),
        device_credential_id: Some(record.device_credential_id.clone()),
        current_secret_version: session_secret_version,
        previous_secret_version: None,
        previous_secret_accept_until: None,
        created_at: now,
        refreshed_at: now,
        expires_at: session_expires_at,
        step_up_expires_at: None,
        revoked_at: None,
    };
    let mut rotated_device = record.clone();
    rotated_device.current_secret_version = device_secret_version;
    rotated_device.previous_secret_version = Some(record.current_secret_version);
    rotated_device.previous_secret_accept_until = Some(previous_secret_accept_until);
    rotated_device.last_used_at = now;
    rotated_device.silent_revival_until = min(
        now.checked_add_duration(config.trusted_device_silent_revival_lifetime)?,
        record.expires_at,
    );

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
            now,
            current_secret_version: record.current_secret_version,
        });
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
            last_used_at: now,
            silent_revival_until: rotated_device.silent_revival_until,
            expires_at: record.expires_at,
        });
    push_fresh_trusted_device_secret(
        &mut plan,
        record.device_credential_id.clone(),
        device_secret_version,
    );
    plan.audit_events.push(audit_event(
        AuditEventKind::SessionCreated,
        now,
        Some(record.subject_id.clone()),
        Some(session_id.clone()),
        Some(record.device_credential_id.clone()),
    ));
    plan.audit_events.push(audit_event(
        AuditEventKind::TrustedDeviceSilentRevival,
        now,
        Some(record.subject_id.clone()),
        Some(session_id.clone()),
        Some(record.device_credential_id.clone()),
    ));
    plan.audit_events.push(audit_event(
        AuditEventKind::TrustedDeviceRotated,
        now,
        Some(record.subject_id.clone()),
        None,
        Some(record.device_credential_id.clone()),
    ));
    plan.response_effects
        .push(ResponseEffect::IssueSessionCookie(
            session_cookie_for_record(config, now, &session_record)?,
        ));
    plan.response_effects
        .push(ResponseEffect::IssueTrustedDeviceCookie(
            device_cookie_for_record(&rotated_device),
        ));
    plan.response_effects.push(ResponseEffect::CycleCsrfToken {
        session_id: Some(session_id.clone()),
    });

    Ok(transition(
        Outcome::Authenticated(Authenticated {
            subject_id: record.subject_id.clone(),
            session_id,
            source: AuthenticationSource::SilentTrustedDeviceRevival,
            step_up_is_fresh: false,
        }),
        plan,
    ))
}

enum LoadedSessionResolution {
    Authenticated(Authenticated, CommitPlan),
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
    Rejected(CommitPlan),
}
