use super::*;

#[test]
fn sensitive_request_with_live_session_requires_step_up_when_not_fresh() {
    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &loaded_session(200),
    )
    .expect("transition");

    assert!(matches!(transition.outcome, Outcome::NeedsStepUp { .. }));
    assert!(transition.commit_plan.mutations.is_empty());
}

#[test]
fn sensitive_request_uses_authoritative_step_up_deadline_not_cookie_deadline() {
    let mut cookie_claims_step_up = loaded_session(200);
    cookie_claims_step_up
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .step_up_valid_until = Some(at(90));

    let stale_record_transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &cookie_claims_step_up,
    )
    .expect("transition");

    assert_eq!(
        stale_record_transition.outcome,
        Outcome::NeedsStepUp {
            session_id: id("session"),
            subject_id: id("subject"),
        }
    );
    assert_eq!(stale_record_transition.commit_plan, CommitPlan::default());

    let mut record_claims_step_up = loaded_session(200);
    record_claims_step_up
        .session_record
        .as_mut()
        .expect("session record")
        .step_up_expires_at = Some(at(90));

    let fresh_record_transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &record_claims_step_up,
    )
    .expect("transition");

    assert!(matches!(
        fresh_record_transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
            ..
        })
    ));

    let mut record_deadline_arrived = loaded_session(200);
    record_deadline_arrived
        .session_record
        .as_mut()
        .expect("session record")
        .step_up_expires_at = Some(at(60));
    record_deadline_arrived
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .step_up_valid_until = Some(at(90));

    let at_deadline_transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(60),
            request_kind: RequestKind::Sensitive,
            fresh_session_id: None,
        }),
        &record_deadline_arrived,
    )
    .expect("transition");

    assert_eq!(
        at_deadline_transition.outcome,
        Outcome::NeedsStepUp {
            session_id: id("session"),
            subject_id: id("subject"),
        }
    );
}
