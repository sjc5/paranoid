use super::*;

#[test]
fn mounted_admin_support_staff_verification_is_scoped_to_loaded_candidate() {
    let intervention = support_intervention_record(
        "mounted-support-scope-intervention",
        "mounted-support-scope-subject",
        "mounted-support-scope-target",
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
    );

    let request = MountedAdminSupportStaffVerificationRequest::for_open_intervention_approval(
        &intervention,
        at(120),
    )
    .expect("open intervention should create staff verification request");

    assert_eq!(
        request.staff_action(),
        MountedAdminSupportStaffAction::ApproveIntervention
    );
    assert_eq!(request.requested_at(), at(120));
    assert_eq!(
        request.candidate().intervention_id(),
        &id("mounted-support-scope-intervention")
    );
    assert_eq!(
        request.candidate().subject_id(),
        &id("mounted-support-scope-subject")
    );
    assert_eq!(
        request.candidate().target_credential_instance_id(),
        &id("mounted-support-scope-target")
    );
    assert_eq!(
        request.candidate().action(),
        CredentialLifecycleAction::Reset
    );
    assert_eq!(request.candidate().requested_at(), at(100));
    assert_eq!(request.candidate().expires_at(), at(200));

    let verified = MountedAdminSupportVerifiedStaffAction::from_staff_authorization(
        request,
        MountedAdminSupportStaffAuthorization::Authorized,
        at(130),
    )
    .expect("authorized callback should mint scoped staff action");

    assert_eq!(
        verified.staff_action(),
        MountedAdminSupportStaffAction::ApproveIntervention
    );
    assert_eq!(verified.verified_at(), at(130));
    assert_eq!(
        verified.candidate().subject_id(),
        &id("mounted-support-scope-subject")
    );
    assert_eq!(
        verified.candidate().target_credential_instance_id(),
        &id("mounted-support-scope-target")
    );
    assert_eq!(
        verified.approve_runtime_input(at(140)),
        Some(ApproveAdminSupportInterventionInput {
            now: at(140),
            intervention_id: id("mounted-support-scope-intervention"),
        })
    );
    assert_eq!(verified.deny_runtime_input(at(140)), None);
}

#[test]
fn mounted_admin_support_staff_callback_rejection_creates_no_runtime_input() {
    let intervention = support_intervention_record(
        "mounted-support-rejected-intervention",
        "mounted-support-rejected-subject",
        "mounted-support-rejected-target",
        CredentialLifecycleAction::Remove,
        at(100),
        at(200),
    );
    let request = MountedAdminSupportStaffVerificationRequest::for_open_intervention_denial(
        &intervention,
        at(120),
    )
    .expect("open intervention should create denial verification request");

    assert_eq!(
        MountedAdminSupportVerifiedStaffAction::from_staff_authorization(
            request,
            MountedAdminSupportStaffAuthorization::Rejected,
            at(130),
        ),
        None,
        "staff authorization rejection must not become a denial mutation"
    );
}

#[test]
fn mounted_admin_support_staff_verification_rejects_closed_or_expired_candidates() {
    let expired_intervention = support_intervention_record(
        "mounted-support-expired-intervention",
        "mounted-support-expired-subject",
        "mounted-support-expired-target",
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
    );

    assert_eq!(
        MountedAdminSupportStaffVerificationRequest::for_open_intervention_approval(
            &expired_intervention,
            at(200),
        ),
        Err(Error::AdminSupportInterventionNotApprovable)
    );
    assert_eq!(
        MountedAdminSupportStaffVerificationRequest::for_open_intervention_denial(
            &expired_intervention,
            at(200),
        ),
        Err(Error::AdminSupportInterventionNotDeniable)
    );

    let mut denied_intervention = support_intervention_record(
        "mounted-support-denied-intervention",
        "mounted-support-denied-subject",
        "mounted-support-denied-target",
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
    );
    denied_intervention.status = AdminSupportInterventionStatus::Denied;
    denied_intervention.closed_at = Some(at(120));

    assert_eq!(
        MountedAdminSupportStaffVerificationRequest::for_open_intervention_approval(
            &denied_intervention,
            at(130),
        ),
        Err(Error::AdminSupportInterventionNotApprovable)
    );
}

#[test]
fn mounted_admin_support_expiry_cleanup_is_deadline_derived_without_staff_verification() {
    let intervention = support_intervention_record(
        "mounted-support-expiry-intervention",
        "mounted-support-expiry-subject",
        "mounted-support-expiry-target",
        CredentialLifecycleAction::Replace,
        at(100),
        at(200),
    );

    assert_eq!(
        MountedAdminSupportExpiryCleanupRequest::from_expired_open_intervention(
            &intervention,
            at(199),
        ),
        Err(Error::AdminSupportInterventionNotExpirable)
    );

    let cleanup = MountedAdminSupportExpiryCleanupRequest::from_expired_open_intervention(
        &intervention,
        at(200),
    )
    .expect("expired open intervention should create cleanup input");

    assert_eq!(
        cleanup.intervention_id(),
        &id("mounted-support-expiry-intervention")
    );
    assert_eq!(cleanup.subject_id(), &id("mounted-support-expiry-subject"));
    assert_eq!(
        cleanup.target_credential_instance_id(),
        &id("mounted-support-expiry-target")
    );
    assert_eq!(cleanup.action(), CredentialLifecycleAction::Replace);
    assert_eq!(cleanup.expired_at(), at(200));
    assert_eq!(
        cleanup.expire_runtime_input(at(201)),
        ExpireAdminSupportInterventionInput {
            now: at(201),
            intervention_id: id("mounted-support-expiry-intervention"),
        }
    );
}

#[test]
fn mounted_admin_support_committed_outcome_surface_maps_only_support_outcomes() {
    assert_eq!(
        MountedAdminSupportCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::AdminSupportInterventionRequested(AdminSupportInterventionRequestOutcome {
                intervention_id: id("mounted-support-request-outcome"),
                subject_id: id("mounted-support-request-subject"),
                target_credential_instance_id: id("mounted-support-request-target"),
                action: CredentialLifecycleAction::Reset,
                expires_at: at(200),
            })
        ),
        Some(MountedAdminSupportCommittedOutcome::InterventionRequested {
            intervention_id: id("mounted-support-request-outcome"),
            subject_id: id("mounted-support-request-subject"),
            target_credential_instance_id: id("mounted-support-request-target"),
            action: CredentialLifecycleAction::Reset,
            expires_at: at(200),
        })
    );
    assert_eq!(
        MountedAdminSupportCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
                AdminSupportCredentialLifecycleInterventionOutcome::AuthorizedImmediate {
                    intervention_id: id("mounted-support-immediate-outcome"),
                    subject_id: id("mounted-support-immediate-subject"),
                    target_credential_instance_id: id("mounted-support-immediate-target"),
                    action: CredentialLifecycleAction::Replace,
                }
            )
        ),
        Some(
            MountedAdminSupportCommittedOutcome::ApprovalAuthorizedImmediate {
                intervention_id: id("mounted-support-immediate-outcome"),
                subject_id: id("mounted-support-immediate-subject"),
                target_credential_instance_id: id("mounted-support-immediate-target"),
                action: CredentialLifecycleAction::Replace,
            }
        )
    );
    assert_eq!(
        MountedAdminSupportCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
                AdminSupportCredentialLifecycleInterventionOutcome::PendingActionCreated {
                    intervention_id: id("mounted-support-delayed-outcome"),
                    subject_id: id("mounted-support-delayed-subject"),
                    target_credential_instance_id: id("mounted-support-delayed-target"),
                    action: CredentialLifecycleAction::Remove,
                    pending_action_id: id("mounted-support-delayed-pending"),
                    earliest_execute_at: at(250),
                    expires_at: at(300),
                }
            )
        ),
        Some(
            MountedAdminSupportCommittedOutcome::ApprovalScheduledDelayedAction {
                intervention_id: id("mounted-support-delayed-outcome"),
                subject_id: id("mounted-support-delayed-subject"),
                target_credential_instance_id: id("mounted-support-delayed-target"),
                action: CredentialLifecycleAction::Remove,
                pending_action_id: id("mounted-support-delayed-pending"),
                earliest_execute_at: at(250),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedAdminSupportCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::AdminSupportInterventionDenied(AdminSupportInterventionClosureOutcome {
                intervention_id: id("mounted-support-denied-outcome"),
                subject_id: id("mounted-support-denied-subject"),
                target_credential_instance_id: id("mounted-support-denied-target"),
                action: CredentialLifecycleAction::Reset,
            })
        ),
        Some(MountedAdminSupportCommittedOutcome::InterventionDenied {
            intervention_id: id("mounted-support-denied-outcome"),
            subject_id: id("mounted-support-denied-subject"),
            target_credential_instance_id: id("mounted-support-denied-target"),
            action: CredentialLifecycleAction::Reset,
        })
    );
    assert_eq!(
        MountedAdminSupportCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::AdminSupportInterventionExpired(AdminSupportInterventionClosureOutcome {
                intervention_id: id("mounted-support-expired-outcome"),
                subject_id: id("mounted-support-expired-subject"),
                target_credential_instance_id: id("mounted-support-expired-target"),
                action: CredentialLifecycleAction::Reset,
            })
        ),
        Some(MountedAdminSupportCommittedOutcome::InterventionExpired {
            intervention_id: id("mounted-support-expired-outcome"),
            subject_id: id("mounted-support-expired-subject"),
            target_credential_instance_id: id("mounted-support-expired-target"),
            action: CredentialLifecycleAction::Reset,
        })
    );
    assert_eq!(
        MountedAdminSupportCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::NeedsFullAuthentication
        ),
        None,
        "mounted support response surface must not reinterpret unrelated runtime outcomes"
    );
}

fn support_intervention_record(
    intervention_id: &'static str,
    subject_id: &'static str,
    target_credential_instance_id: &'static str,
    action: CredentialLifecycleAction,
    requested_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> AdminSupportInterventionRecord {
    AdminSupportInterventionRecord::new_requested(
        id(intervention_id),
        id(subject_id),
        id(target_credential_instance_id),
        action,
        requested_at,
        expires_at,
    )
    .expect("valid support intervention record")
}
