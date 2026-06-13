use super::prelude::*;
use super::session_lifecycle_helpers::*;
use super::{audit_event, transition};

pub(super) fn logout_current_session(
    command: LogoutCurrentSession,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    let mut subject_id = None;

    if let Some(record) = &loaded.session_record
        && record.revoked_at.is_none()
    {
        let secret_match = loaded
            .session_secret_match
            .as_ref()
            .ok_or(Error::LoadedStateContradiction(
                "logout requires session secret match when session record is loaded",
            ))?
            .kind();
        let cookie = loaded
            .session_cookie
            .as_ref()
            .ok_or(Error::LoadedStateContradiction(
                "logout requires session cookie when session record is loaded",
            ))?;
        validate_session_secret_match_consistency(command.now, secret_match, cookie, record)?;
        if secret_match.is_accepted() {
            subject_id = Some(record.subject_id.clone());
            plan.preconditions.push(Precondition::SessionStillMatches {
                session_id: record.session_id.clone(),
                subject_id: record.subject_id.clone(),
                now: command.now,
                current_secret_version: record.current_secret_version,
            });
            plan.mutations.push(Mutation::RevokeSession {
                session_id: record.session_id.clone(),
                reason: RevocationReason::Logout,
                revoked_at: command.now,
            });
            plan.audit_events.push(audit_event(
                AuditEventKind::SessionRevoked,
                command.now,
                Some(record.subject_id.clone()),
                Some(record.session_id.clone()),
                record.device_credential_id.clone(),
            ));
        } else {
            plan.merge(session_tripwire_plan(command.now, record));
        }
    }

    if loaded.session_cookie.is_some() {
        push_delete_session_cookie_and_cycle_csrf(&mut plan);
    }

    Ok(transition(
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id,
            target: RevocationTarget::CurrentSession,
        }),
        plan,
    ))
}

pub(super) fn revoke_session(
    command: RevokeSession,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::SessionBelongsToSubject {
            session_id: command.session_id.clone(),
            subject_id: command.subject_id.clone(),
        });
    plan.mutations.push(Mutation::RevokeSession {
        session_id: command.session_id.clone(),
        reason: command.reason,
        revoked_at: command.now,
    });
    plan.audit_events.push(audit_event(
        AuditEventKind::SessionRevoked,
        command.now,
        Some(command.subject_id.clone()),
        Some(command.session_id.clone()),
        None,
    ));
    if loaded
        .session_cookie
        .as_ref()
        .is_some_and(|cookie| cookie.session_id == command.session_id)
    {
        push_delete_session_cookie_and_cycle_csrf(&mut plan);
    }

    Ok(transition(
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(command.subject_id),
            target: RevocationTarget::Session(command.session_id),
        }),
        plan,
    ))
}

pub(super) fn revoke_trusted_device(
    command: RevokeTrustedDevice,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::TrustedDeviceBelongsToSubject {
            device_credential_id: command.device_credential_id.clone(),
            subject_id: command.subject_id.clone(),
        });
    plan.mutations
        .push(Mutation::RevokeTrustedDeviceCredential {
            device_credential_id: command.device_credential_id.clone(),
            reason: command.reason,
            revoked_at: command.now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::TrustedDeviceRevoked,
        command.now,
        Some(command.subject_id.clone()),
        None,
        Some(command.device_credential_id.clone()),
    ));
    if loaded
        .trusted_device_cookie
        .as_ref()
        .is_some_and(|cookie| cookie.device_credential_id == command.device_credential_id)
    {
        plan.response_effects
            .push(ResponseEffect::DeleteTrustedDeviceCookie);
    }

    Ok(transition(
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(command.subject_id),
            target: RevocationTarget::TrustedDevice(command.device_credential_id),
        }),
        plan,
    ))
}

pub(super) fn revoke_subject_auth_state(
    command: RevokeSubjectAuthState,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: command.subject_id.clone(),
            revoke_records_created_at_or_before: command.now,
            reason: command.reason,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::SubjectAuthStateRevoked,
        command.now,
        Some(command.subject_id.clone()),
        None,
        None,
    ));
    let current_session_matches = loaded
        .session_cookie
        .as_ref()
        .is_some_and(|cookie| cookie.subject_id == command.subject_id);
    let current_device_matches = loaded
        .trusted_device_cookie
        .as_ref()
        .is_some_and(|cookie| cookie.subject_id == command.subject_id);
    if current_session_matches {
        push_delete_session_cookie_and_cycle_csrf(&mut plan);
    }
    if current_device_matches {
        plan.response_effects
            .push(ResponseEffect::DeleteTrustedDeviceCookie);
    }

    Ok(transition(
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(command.subject_id.clone()),
            target: RevocationTarget::SubjectAuthState(command.subject_id),
        }),
        plan,
    ))
}
