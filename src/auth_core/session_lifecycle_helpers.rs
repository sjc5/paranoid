use std::cmp::min;

use super::{audit_event, *};

pub(super) fn authenticate_from_safe_read_cache(
    config: &Config,
    command: &ResolveRequest,
    loaded: &LoadedState,
) -> Result<Option<Authenticated>, Error> {
    if command.request_kind != RequestKind::SafeRead {
        return Ok(None);
    }
    if loaded.session_record.is_some()
        || loaded.session_secret_match.is_some()
        || loaded.trusted_device_cookie.is_some()
        || loaded.trusted_device_record.is_some()
        || loaded.trusted_device_secret_match.is_some()
        || loaded.active_proof_attempt_record.is_some()
        || loaded.active_proof_challenge_record.is_some()
    {
        return Ok(None);
    }
    let cookie = match loaded.session_cookie.as_ref() {
        Some(cookie) => cookie,
        None => return Ok(None),
    };
    if loaded
        .subject_revocations
        .optional_revocation_for_subject_if_loaded(&cookie.subject_id)?
        .is_some()
    {
        return Ok(None);
    }
    let safe_read_valid_until = match cookie.safe_read_valid_until {
        Some(deadline) => deadline,
        None => return Ok(None),
    };
    let refresh_cutoff = cookie
        .session_fast_fail_until
        .checked_sub_duration(config.session_refresh_window);
    let Some(refresh_cutoff) = refresh_cutoff else {
        return Ok(None);
    };
    if command.now < safe_read_valid_until && command.now < refresh_cutoff {
        Ok(Some(Authenticated {
            subject_id: cookie.subject_id.clone(),
            session_id: cookie.session_id.clone(),
            source: AuthenticationSource::SafeReadCache,
            step_up_is_fresh: false,
        }))
    } else {
        Ok(None)
    }
}

pub(super) fn session_is_inside_refresh_window(
    config: &Config,
    now: UnixSeconds,
    expires_at: UnixSeconds,
) -> bool {
    match expires_at.checked_sub_duration(config.session_refresh_window) {
        Some(refresh_starts_at) => now >= refresh_starts_at,
        None => true,
    }
}

pub(super) fn session_cookie_for_record(
    config: &Config,
    now: UnixSeconds,
    record: &SessionRecord,
) -> Result<SessionCookieDraft, Error> {
    Ok(SessionCookieDraft {
        session_id: record.session_id.clone(),
        subject_id: record.subject_id.clone(),
        secret_version: record.current_secret_version,
        session_fast_fail_until: record.expires_at,
        safe_read_valid_until: safe_read_valid_until(config, now, record.expires_at)?,
        step_up_valid_until: record.step_up_expires_at,
    })
}

pub(super) fn device_cookie_for_record(
    record: &TrustedDeviceCredentialRecord,
) -> TrustedDeviceCookieDraft {
    TrustedDeviceCookieDraft {
        device_credential_id: record.device_credential_id.clone(),
        subject_id: record.subject_id.clone(),
        secret_version: record.current_secret_version,
        device_fast_fail_until: record.expires_at,
        silent_revival_fast_fail_until: record.silent_revival_until,
    }
}

pub(super) fn safe_read_valid_until(
    config: &Config,
    now: UnixSeconds,
    expires_at: UnixSeconds,
) -> Result<Option<UnixSeconds>, Error> {
    let Some(safe_read_cache_lifetime) = config.safe_read_cache_lifetime else {
        return Ok(None);
    };
    let Some(refresh_cutoff) = expires_at.checked_sub_duration(config.session_refresh_window)
    else {
        return Ok(None);
    };
    if now >= refresh_cutoff {
        return Ok(None);
    }
    let requested = now.checked_add_duration(safe_read_cache_lifetime)?;
    Ok(Some(min(requested, refresh_cutoff)))
}

pub(super) fn step_up_is_fresh(step_up_expires_at: Option<UnixSeconds>, now: UnixSeconds) -> bool {
    matches!(step_up_expires_at, Some(expires_at) if now < expires_at)
}

pub(super) fn validate_session_secret_match_consistency(
    now: UnixSeconds,
    secret_match: StoredSecretMatch,
    cookie: &SessionCookieDraft,
    record: &SessionRecord,
) -> Result<(), Error> {
    validate_secret_match_consistency(
        now,
        secret_match,
        cookie.secret_version,
        record.current_secret_version,
        record.previous_secret_version,
        record.previous_secret_accept_until,
        SecretMatchLabels {
            previous_fields_mismatched: "session previous secret version and deadline must both be present or absent",
            current_version_mismatch: "session current secret match version differs from cookie version",
            previous_version_missing: "session previous secret match missing previous version",
            previous_deadline_missing: "session previous secret match missing previous grace deadline",
            previous_version_mismatch: "session previous secret match version differs from cookie version",
            previous_within_grace_after_deadline: "session previous secret reported within grace after grace deadline",
            previous_expired_before_deadline: "session previous secret reported expired inside grace deadline",
        },
    )
}

pub(super) fn validate_device_secret_match_consistency(
    now: UnixSeconds,
    secret_match: StoredSecretMatch,
    cookie: &TrustedDeviceCookieDraft,
    record: &TrustedDeviceCredentialRecord,
) -> Result<(), Error> {
    validate_secret_match_consistency(
        now,
        secret_match,
        cookie.secret_version,
        record.current_secret_version,
        record.previous_secret_version,
        record.previous_secret_accept_until,
        SecretMatchLabels {
            previous_fields_mismatched: "trusted-device previous secret version and deadline must both be present or absent",
            current_version_mismatch: "trusted-device current secret match version differs from cookie version",
            previous_version_missing: "trusted-device previous secret match missing previous version",
            previous_deadline_missing: "trusted-device previous secret match missing previous grace deadline",
            previous_version_mismatch: "trusted-device previous secret match version differs from cookie version",
            previous_within_grace_after_deadline: "trusted-device previous secret reported within grace after grace deadline",
            previous_expired_before_deadline: "trusted-device previous secret reported expired inside grace deadline",
        },
    )
}

#[derive(Clone, Copy)]
struct SecretMatchLabels {
    previous_fields_mismatched: &'static str,
    current_version_mismatch: &'static str,
    previous_version_missing: &'static str,
    previous_deadline_missing: &'static str,
    previous_version_mismatch: &'static str,
    previous_within_grace_after_deadline: &'static str,
    previous_expired_before_deadline: &'static str,
}

fn validate_secret_match_consistency(
    now: UnixSeconds,
    secret_match: StoredSecretMatch,
    presented_version: SecretVersion,
    current_secret_version: SecretVersion,
    previous_secret_version: Option<SecretVersion>,
    previous_secret_accept_until: Option<UnixSeconds>,
    labels: SecretMatchLabels,
) -> Result<(), Error> {
    if previous_secret_version.is_some() != previous_secret_accept_until.is_some() {
        return Err(Error::LoadedStateContradiction(
            labels.previous_fields_mismatched,
        ));
    }

    match secret_match {
        StoredSecretMatch::Current => {
            if presented_version != current_secret_version {
                return Err(Error::LoadedStateContradiction(
                    labels.current_version_mismatch,
                ));
            }
        }
        StoredSecretMatch::PreviousWithinGrace => {
            let previous_secret_version = previous_secret_version.ok_or(
                Error::LoadedStateContradiction(labels.previous_version_missing),
            )?;
            let previous_secret_accept_until = previous_secret_accept_until.ok_or(
                Error::LoadedStateContradiction(labels.previous_deadline_missing),
            )?;
            if presented_version != previous_secret_version {
                return Err(Error::LoadedStateContradiction(
                    labels.previous_version_mismatch,
                ));
            }
            if now >= previous_secret_accept_until {
                return Err(Error::LoadedStateContradiction(
                    labels.previous_within_grace_after_deadline,
                ));
            }
        }
        StoredSecretMatch::PreviousExpired => {
            let previous_secret_version = previous_secret_version.ok_or(
                Error::LoadedStateContradiction(labels.previous_version_missing),
            )?;
            let previous_secret_accept_until = previous_secret_accept_until.ok_or(
                Error::LoadedStateContradiction(labels.previous_deadline_missing),
            )?;
            if presented_version != previous_secret_version {
                return Err(Error::LoadedStateContradiction(
                    labels.previous_version_mismatch,
                ));
            }
            if now < previous_secret_accept_until {
                return Err(Error::LoadedStateContradiction(
                    labels.previous_expired_before_deadline,
                ));
            }
        }
        StoredSecretMatch::Unknown => {}
    }

    Ok(())
}

pub(super) fn validate_session_cookie_record_pair(
    cookie: &SessionCookieDraft,
    record: &SessionRecord,
) -> Result<(), Error> {
    if cookie.session_id != record.session_id {
        return Err(Error::LoadedStateContradiction(
            "session cookie and record ids differ",
        ));
    }
    if cookie.subject_id != record.subject_id {
        return Err(Error::LoadedStateContradiction(
            "session cookie and record subjects differ",
        ));
    }
    Ok(())
}

pub(super) fn validate_device_cookie_record_pair(
    cookie: &TrustedDeviceCookieDraft,
    record: &TrustedDeviceCredentialRecord,
) -> Result<(), Error> {
    if cookie.device_credential_id != record.device_credential_id {
        return Err(Error::LoadedStateContradiction(
            "trusted-device cookie and record ids differ",
        ));
    }
    if cookie.subject_id != record.subject_id {
        return Err(Error::LoadedStateContradiction(
            "trusted-device cookie and record subjects differ",
        ));
    }
    Ok(())
}

pub(super) fn subject_revocation_invalidates_record(
    subject_revocation: Option<&SubjectRevocationState>,
    created_at: UnixSeconds,
) -> bool {
    matches!(subject_revocation, Some(revocation) if created_at <= revocation.revoke_records_created_at_or_before)
}

pub(super) fn credential_mismatch_plan(
    now: UnixSeconds,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
    device_credential_id: Option<TrustedDeviceCredentialId>,
    response_effect: ResponseEffect,
) -> CommitPlan {
    let mut plan = CommitPlan::default();
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialMismatch,
        now,
        subject_id,
        session_id,
        device_credential_id,
    ));
    plan.response_effects.push(response_effect);
    plan
}

pub(super) fn session_credential_mismatch_plan(
    now: UnixSeconds,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
) -> CommitPlan {
    let mut plan = credential_mismatch_plan(
        now,
        subject_id,
        session_id,
        None,
        ResponseEffect::DeleteSessionCookie,
    );
    push_delete_session_cookie_and_cycle_csrf(&mut plan);
    plan
}

pub(super) fn merge_session_rejection_before_replacement_session(
    target: &mut CommitPlan,
    mut rejected_session_plan: CommitPlan,
) {
    rejected_session_plan.response_effects.retain(|effect| {
        !matches!(
            effect,
            ResponseEffect::DeleteSessionCookie
                | ResponseEffect::CycleCsrfToken { session_id: None }
        )
    });
    target.merge(rejected_session_plan);
}

pub(super) fn push_delete_session_cookie_and_cycle_csrf(plan: &mut CommitPlan) {
    if !plan
        .response_effects
        .contains(&ResponseEffect::DeleteSessionCookie)
    {
        plan.response_effects
            .push(ResponseEffect::DeleteSessionCookie);
    }
    if !plan
        .response_effects
        .contains(&ResponseEffect::CycleCsrfToken { session_id: None })
    {
        plan.response_effects
            .push(ResponseEffect::CycleCsrfToken { session_id: None });
    }
}

pub(super) fn push_fresh_session_secret(
    plan: &mut CommitPlan,
    session_id: SessionId,
    secret_version: SecretVersion,
) {
    plan.fresh_credential_secrets
        .push(FreshCredentialSecret::Session {
            session_id,
            secret_version,
        });
}

pub(super) fn push_fresh_trusted_device_secret(
    plan: &mut CommitPlan,
    device_credential_id: TrustedDeviceCredentialId,
    secret_version: SecretVersion,
) {
    plan.fresh_credential_secrets
        .push(FreshCredentialSecret::TrustedDevice {
            device_credential_id,
            secret_version,
        });
}
