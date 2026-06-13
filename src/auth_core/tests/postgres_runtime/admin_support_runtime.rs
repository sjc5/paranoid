use super::*;

#[tokio::test]
async fn postgres_runtime_admin_support_intervention_request_and_denial_are_candidate_owned() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("support-request-denial-subject");
    let target_credential_id = id("support-request-denial-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;
    harness.database_operation_observer.clear();

    let requested = runtime
        .execute_admin_support_intervention_request_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request support intervention");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.close_expired_admin_support_interventions",
            "auth_core.precondition.no_open_admin_support_intervention",
            "auth_core.mutation.create_admin_support_intervention",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "admin/support intervention request must stay inside one target-active guard, open-candidate guard, candidate creation, audit, notice, and commit",
    );
    let intervention_id = match requested.outcome() {
        Outcome::AdminSupportInterventionRequested(outcome) => {
            assert_eq!(&outcome.subject_id, &subject_id);
            assert_eq!(
                &outcome.target_credential_instance_id,
                &target_credential_id
            );
            assert_eq!(outcome.action, CredentialLifecycleAction::Reset);
            assert_eq!(outcome.expires_at, at(620));
            outcome.intervention_id.clone()
        }
        outcome => panic!("expected support intervention request outcome, got {outcome:?}"),
    };
    let requested_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("requested support intervention row");
    assert_eq!(
        requested_record.status,
        AdminSupportInterventionStatus::Requested
    );
    assert_eq!(requested_record.closed_at, None);
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "request must commit a security notice with the candidate row"
    );

    let duplicate_request_error = runtime
        .execute_admin_support_intervention_request_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(25),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect_err("open support intervention candidate must block duplicate request");
    assert!(matches!(
        duplicate_request_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            super::super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(
                "admin support intervention already exists"
            )
        )
    ));
    harness.database_operation_observer.clear();

    let denied = runtime
        .execute_admin_support_intervention_denial_from_headers(
            &HeaderMap::new(),
            DenyAdminSupportInterventionInput {
                now: at(30),
                intervention_id: intervention_id.clone(),
            },
        )
        .await
        .expect("deny support intervention");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.precondition.admin_support_intervention_still_open",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "admin/support intervention denial must stay inside one candidate load, open-candidate guard, close, audit, notice, and commit",
    );
    assert_eq!(
        denied.outcome(),
        &Outcome::AdminSupportInterventionDenied(AdminSupportInterventionClosureOutcome {
            intervention_id: intervention_id.clone(),
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
            action: CredentialLifecycleAction::Reset,
        })
    );
    let denied_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("denied support intervention row");
    assert_eq!(denied_record.status, AdminSupportInterventionStatus::Denied);
    assert_eq!(denied_record.closed_at, Some(at(30)));
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        2,
        "request and denial must both commit security notices"
    );

    let replay_error = runtime
        .execute_admin_support_intervention_denial_from_headers(
            &HeaderMap::new(),
            DenyAdminSupportInterventionInput {
                now: at(35),
                intervention_id,
            },
        )
        .await
        .expect_err("closed support intervention denial must not replay");
    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionNotDeniable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_admin_support_intervention_request_rejects_subject_target_mismatch() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let owner_subject_id = id("support-request-owner-subject");
    let requested_subject_id = id("support-request-wrong-subject");
    let target_credential_id = id("support-request-wrong-subject-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        owner_subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;

    let error = runtime
        .execute_admin_support_intervention_request_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: requested_subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect_err(
            "support intervention request must reject a target credential owned by another subject",
        );
    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
            super::super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(
                "credential instance is not active for subject"
            )
        )
    ));
    assert_eq!(
        count_admin_support_interventions_for_subject_target_and_action(
            pool,
            store_config,
            &requested_subject_id,
            &target_credential_id,
            CredentialLifecycleAction::Reset,
        )
        .await,
        0,
        "failed subject-target support request must not create an intervention candidate"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &requested_subject_id)
            .await,
        0,
        "failed subject-target support request must not schedule notices for the requested subject"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &owner_subject_id)
            .await,
        0,
        "failed subject-target support request must not schedule notices for the credential owner"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_admin_support_intervention_expiry_is_deadline_derived() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("support-expiry-subject");
    let target_credential_id = id("support-expiry-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;

    let requested = runtime
        .execute_admin_support_intervention_request_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request support intervention for expiry");
    let intervention_id = match requested.outcome() {
        Outcome::AdminSupportInterventionRequested(outcome) => outcome.intervention_id.clone(),
        outcome => panic!("expected support intervention request outcome, got {outcome:?}"),
    };

    let too_early_error = runtime
        .execute_admin_support_intervention_expiry_from_headers(
            &HeaderMap::new(),
            ExpireAdminSupportInterventionInput {
                now: at(619),
                intervention_id: intervention_id.clone(),
            },
        )
        .await
        .expect_err("unexpired support intervention must not expire");
    assert!(matches!(
        too_early_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionNotExpirable
        )
    ));
    harness.database_operation_observer.clear();

    let expired = runtime
        .execute_admin_support_intervention_expiry_from_headers(
            &HeaderMap::new(),
            ExpireAdminSupportInterventionInput {
                now: at(620),
                intervention_id: intervention_id.clone(),
            },
        )
        .await
        .expect("expire support intervention at deadline");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.precondition.admin_support_intervention_still_expired_open",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "admin/support intervention expiry must stay inside one candidate load, expired-open guard, close, audit, notice, and commit",
    );
    assert_eq!(
        expired.outcome(),
        &Outcome::AdminSupportInterventionExpired(AdminSupportInterventionClosureOutcome {
            intervention_id: intervention_id.clone(),
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            action: CredentialLifecycleAction::Reset,
        })
    );
    let expired_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("expired support intervention row");
    assert_eq!(
        expired_record.status,
        AdminSupportInterventionStatus::Expired
    );
    assert_eq!(expired_record.closed_at, Some(at(620)));
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        2,
        "request and expiry must both commit security notices"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_admin_support_intervention_approval_enters_immediate_lifecycle_policy() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("support-immediate-approval-subject");
    let target_credential_id = id("support-immediate-approval-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;

    let requested = runtime
        .execute_admin_support_intervention_request_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request support intervention for immediate approval");
    let intervention_id = match requested.outcome() {
        Outcome::AdminSupportInterventionRequested(outcome) => outcome.intervention_id.clone(),
        outcome => panic!("expected support intervention request outcome, got {outcome:?}"),
    };
    harness.database_operation_observer.clear();

    let approved = runtime
        .execute_admin_support_intervention_approval_from_headers(
            &HeaderMap::new(),
            ApproveAdminSupportInterventionInput {
                now: at(30),
                intervention_id: intervention_id.clone(),
            },
        )
        .await
        .expect("approve support intervention");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.precondition.admin_support_intervention_still_open",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.mutation.record_credential_lifecycle_action_authorized",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "admin/support immediate approval must stay inside one candidate load, lifecycle-context load, open-candidate guard, authorization record, auth-state revocation, notices, and commit",
    );
    assert_eq!(
        approved.outcome(),
        &Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::AuthorizedImmediate {
                intervention_id: intervention_id.clone(),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            }
        )
    );
    let approved_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("approved support intervention row");
    assert_eq!(
        approved_record.status,
        AdminSupportInterventionStatus::Approved
    );
    assert_eq!(approved_record.closed_at, Some(at(30)));
    assert_eq!(
        count_open_pending_credential_reset_actions_for_target(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        0,
        "immediate support approval must not create delayed pending reset work"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        3,
        "request, approval closure, and lifecycle authorization must all commit notices"
    );

    let replay_error = runtime
        .execute_admin_support_intervention_approval_from_headers(
            &HeaderMap::new(),
            ApproveAdminSupportInterventionInput {
                now: at(35),
                intervention_id,
            },
        )
        .await
        .expect_err("closed support approval must not replay");
    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::AdminSupportInterventionNotApprovable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_admin_support_intervention_approval_can_schedule_delayed_lifecycle_work()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("support-delayed-approval-subject");
    let target_credential_id = id("support-delayed-approval-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Delayed,
        at(10),
    )
    .await;

    let requested = runtime
        .execute_admin_support_intervention_request_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request support intervention for delayed approval");
    let intervention_id = match requested.outcome() {
        Outcome::AdminSupportInterventionRequested(outcome) => outcome.intervention_id.clone(),
        outcome => panic!("expected support intervention request outcome, got {outcome:?}"),
    };
    harness.database_operation_observer.clear();

    let approved = runtime
        .execute_admin_support_intervention_approval_from_headers(
            &HeaderMap::new(),
            ApproveAdminSupportInterventionInput {
                now: at(30),
                intervention_id: intervention_id.clone(),
            },
        )
        .await
        .expect("approve support intervention as delayed lifecycle work");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "auth_core.load.credential_instance_metadata",
            "auth_core.load.credential_recovery_authorities",
            "auth_core.precondition.admin_support_intervention_still_open",
            "auth_core.precondition.credential_instance_still_active",
            "auth_core.precondition.close_expired_pending_credential_lifecycle_actions",
            "auth_core.precondition.no_open_pending_credential_lifecycle_action",
            "auth_core.mutation.close_admin_support_intervention",
            "auth_core.mutation.create_pending_credential_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "admin/support delayed approval must stay inside one candidate load, lifecycle-context load, open-candidate guard, pending-action uniqueness guard, pending creation, notices, and commit",
    );
    let pending_action_id = match approved.outcome() {
        Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::PendingActionCreated {
                intervention_id: actual_intervention_id,
                subject_id: actual_subject_id,
                target_credential_instance_id,
                action,
                pending_action_id,
                earliest_execute_at,
                expires_at,
            },
        ) => {
            assert_eq!(actual_intervention_id, &intervention_id);
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            assert_eq!(action, &CredentialLifecycleAction::Reset);
            assert_eq!(earliest_execute_at, &at(150));
            assert_eq!(expires_at, &at(250));
            pending_action_id.clone()
        }
        outcome => panic!("expected delayed support intervention approval, got {outcome:?}"),
    };
    let approved_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("approved delayed support intervention row");
    assert_eq!(
        approved_record.status,
        AdminSupportInterventionStatus::Approved
    );
    assert_eq!(approved_record.closed_at, Some(at(30)));
    assert_eq!(
        count_open_pending_credential_reset_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
        )
        .await,
        1,
        "delayed support approval must commit exactly one pending reset action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        3,
        "request, approval closure, and delayed lifecycle scheduling must all commit notices"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_mounted_admin_support_approval_runs_staff_authorization_before_runtime_commit() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let mounted_service = MountedAdminSupportPostgresService::new(runtime);
    let subject_id = id("mounted-support-approval-subject");
    let target_credential_id = id("mounted-support-approval-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        subject_id.clone(),
        target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;

    let requested = mounted_service
        .request_intervention_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request support intervention through mounted service");
    let intervention_id = match requested.committed_outcome() {
        MountedAdminSupportCommittedOutcome::InterventionRequested {
            intervention_id,
            subject_id: actual_subject_id,
            target_credential_instance_id,
            action,
            expires_at,
        } => {
            assert_eq!(actual_subject_id, &subject_id);
            assert_eq!(target_credential_instance_id, &target_credential_id);
            assert_eq!(*action, CredentialLifecycleAction::Reset);
            assert_eq!(*expires_at, at(620));
            intervention_id.clone()
        }
        outcome => panic!("expected mounted request outcome, got {outcome:?}"),
    };
    assert!(
        requested
            .runtime_execution()
            .set_cookie_headers()
            .is_empty()
    );

    harness.database_operation_observer.clear();
    let direct_approval_staff_request = runtime
        .mounted_admin_support_approval_staff_verification_request(
            &ApproveAdminSupportInterventionInput {
                now: at(30),
                intervention_id: intervention_id.clone(),
            },
        )
        .await
        .expect("direct approval staff-verification snapshot should load requested candidate");
    assert_eq!(
        direct_approval_staff_request.staff_action(),
        MountedAdminSupportStaffAction::ApproveIntervention
    );
    assert_eq!(direct_approval_staff_request.requested_at(), at(30));
    assert_eq!(
        direct_approval_staff_request.candidate().intervention_id(),
        &intervention_id
    );
    assert_eq!(
        direct_approval_staff_request.candidate().subject_id(),
        &subject_id
    );
    assert_eq!(
        direct_approval_staff_request
            .candidate()
            .target_credential_instance_id(),
        &target_credential_id
    );
    assert_eq!(
        direct_approval_staff_request.candidate().action(),
        CredentialLifecycleAction::Reset
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "db.tx.rollback",
        ],
        "direct mounted admin/support approval staff-verification snapshot must be a PgBouncer-backed read-only transaction",
    );

    let rejecting_authorizer = RecordingMountedSupportStaffAuthorizer::new(
        MountedAdminSupportStaffAuthorization::Rejected,
    );
    let rejection = mounted_service
        .approve_intervention_from_headers(
            &HeaderMap::new(),
            ApproveAdminSupportInterventionInput {
                now: at(30),
                intervention_id: intervention_id.clone(),
            },
            &rejecting_authorizer,
        )
        .await
        .expect_err("staff rejection must not approve intervention");
    assert!(matches!(
        rejection,
        MountedAdminSupportServiceError::StaffAuthorizationRejected
    ));
    let rejected_requests = rejecting_authorizer.recorded_requests();
    assert_eq!(rejected_requests.len(), 1);
    assert_eq!(
        rejected_requests[0].staff_action(),
        MountedAdminSupportStaffAction::ApproveIntervention
    );
    assert_eq!(rejected_requests[0].requested_at(), at(30));
    assert_eq!(
        rejected_requests[0].candidate().intervention_id(),
        &intervention_id
    );
    assert_eq!(rejected_requests[0].candidate().subject_id(), &subject_id);
    assert_eq!(
        rejected_requests[0]
            .candidate()
            .target_credential_instance_id(),
        &target_credential_id
    );
    assert_eq!(
        rejected_requests[0].candidate().action(),
        CredentialLifecycleAction::Reset
    );
    assert_eq!(rejected_requests[0].candidate().requested_at(), at(20));
    assert_eq!(rejected_requests[0].candidate().expires_at(), at(620));
    let still_requested_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("support intervention row after staff rejection");
    assert_eq!(
        still_requested_record.status,
        AdminSupportInterventionStatus::Requested
    );
    assert_eq!(still_requested_record.closed_at, None);
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "staff callback rejection must not enqueue support denial or approval notices"
    );

    let approving_authorizer = RecordingMountedSupportStaffAuthorizer::new(
        MountedAdminSupportStaffAuthorization::Authorized,
    );
    let approved = mounted_service
        .approve_intervention_from_headers(
            &HeaderMap::new(),
            ApproveAdminSupportInterventionInput {
                now: at(40),
                intervention_id: intervention_id.clone(),
            },
            &approving_authorizer,
        )
        .await
        .expect("staff-approved intervention should enter runtime approval");
    assert_eq!(
        approved.committed_outcome(),
        &MountedAdminSupportCommittedOutcome::ApprovalAuthorizedImmediate {
            intervention_id: intervention_id.clone(),
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id,
            action: CredentialLifecycleAction::Reset,
        }
    );
    let approved_record =
        load_admin_support_intervention_for_runtime_test(pool, store_config, &intervention_id)
            .await
            .expect("approved intervention row");
    assert_eq!(
        approved_record.status,
        AdminSupportInterventionStatus::Approved
    );
    assert_eq!(approved_record.closed_at, Some(at(40)));
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        3,
        "mounted approval must use the private runtime path that commits support and lifecycle notices"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_mounted_admin_support_denial_and_expiry_use_mounted_boundary() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let mounted_service = MountedAdminSupportPostgresService::new(runtime);
    let denial_subject_id = id("mounted-support-denial-subject");
    let denial_target_credential_id = id("mounted-support-denial-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        denial_subject_id.clone(),
        denial_target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;

    let requested = mounted_service
        .request_intervention_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(20),
                subject_id: denial_subject_id.clone(),
                target_credential_instance_id: denial_target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
            },
        )
        .await
        .expect("request support intervention before denial");
    let denial_intervention_id = match requested.committed_outcome() {
        MountedAdminSupportCommittedOutcome::InterventionRequested {
            intervention_id, ..
        } => intervention_id.clone(),
        outcome => panic!("expected mounted request outcome, got {outcome:?}"),
    };
    harness.database_operation_observer.clear();
    let direct_denial_staff_request = runtime
        .mounted_admin_support_denial_staff_verification_request(
            &DenyAdminSupportInterventionInput {
                now: at(30),
                intervention_id: denial_intervention_id.clone(),
            },
        )
        .await
        .expect("direct denial staff-verification snapshot should load requested candidate");
    assert_eq!(
        direct_denial_staff_request.staff_action(),
        MountedAdminSupportStaffAction::DenyIntervention
    );
    assert_eq!(direct_denial_staff_request.requested_at(), at(30));
    assert_eq!(
        direct_denial_staff_request.candidate().intervention_id(),
        &denial_intervention_id
    );
    assert_eq!(
        direct_denial_staff_request.candidate().subject_id(),
        &denial_subject_id
    );
    assert_eq!(
        direct_denial_staff_request
            .candidate()
            .target_credential_instance_id(),
        &denial_target_credential_id
    );
    assert_eq!(
        direct_denial_staff_request.candidate().action(),
        CredentialLifecycleAction::Remove
    );
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.admin_support_intervention",
            "db.tx.rollback",
        ],
        "direct mounted admin/support denial staff-verification snapshot must be a PgBouncer-backed read-only transaction",
    );

    let denying_authorizer = RecordingMountedSupportStaffAuthorizer::new(
        MountedAdminSupportStaffAuthorization::Authorized,
    );
    let denied = mounted_service
        .deny_intervention_from_headers(
            &HeaderMap::new(),
            DenyAdminSupportInterventionInput {
                now: at(30),
                intervention_id: denial_intervention_id.clone(),
            },
            &denying_authorizer,
        )
        .await
        .expect("staff-authorized denial should close intervention");
    assert_eq!(
        denied.committed_outcome(),
        &MountedAdminSupportCommittedOutcome::InterventionDenied {
            intervention_id: denial_intervention_id.clone(),
            subject_id: denial_subject_id.clone(),
            target_credential_instance_id: denial_target_credential_id,
            action: CredentialLifecycleAction::Remove,
        }
    );
    assert_eq!(
        denying_authorizer.recorded_requests()[0].staff_action(),
        MountedAdminSupportStaffAction::DenyIntervention
    );
    assert_eq!(
        denying_authorizer.recorded_requests()[0]
            .candidate()
            .intervention_id(),
        &denial_intervention_id
    );
    assert_eq!(
        denying_authorizer.recorded_requests()[0]
            .candidate()
            .subject_id(),
        &denial_subject_id
    );
    assert_eq!(
        denying_authorizer.recorded_requests()[0]
            .candidate()
            .action(),
        CredentialLifecycleAction::Remove
    );
    assert_eq!(
        denying_authorizer.recorded_requests()[0].requested_at(),
        at(30)
    );

    let expiry_subject_id = id("mounted-support-expiry-subject");
    let expiry_target_credential_id = id("mounted-support-expiry-target");
    seed_admin_support_target_credential_for_runtime_test(
        pool,
        store_config,
        expiry_subject_id.clone(),
        expiry_target_credential_id.clone(),
        RecoveryAuthorityTiming::Immediate,
        at(10),
    )
    .await;
    let expiry_request = mounted_service
        .request_intervention_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: at(40),
                subject_id: expiry_subject_id.clone(),
                target_credential_instance_id: expiry_target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request support intervention before expiry");
    let expiry_intervention_id = match expiry_request.committed_outcome() {
        MountedAdminSupportCommittedOutcome::InterventionRequested {
            intervention_id, ..
        } => intervention_id.clone(),
        outcome => panic!("expected mounted request outcome, got {outcome:?}"),
    };

    let expiry_cleanup = runtime
        .mounted_admin_support_expiry_cleanup_request(&ExpireAdminSupportInterventionInput {
            now: at(640),
            intervention_id: expiry_intervention_id.clone(),
        })
        .await
        .expect("mounted expiry helper should derive cleanup request from expired candidate");
    assert_eq!(expiry_cleanup.intervention_id(), &expiry_intervention_id);
    assert_eq!(expiry_cleanup.subject_id(), &expiry_subject_id);
    assert_eq!(
        expiry_cleanup.target_credential_instance_id(),
        &expiry_target_credential_id
    );
    assert_eq!(expiry_cleanup.action(), CredentialLifecycleAction::Reset);
    assert_eq!(expiry_cleanup.expired_at(), at(640));
    assert_eq!(
        expiry_cleanup.expire_runtime_input(at(640)),
        ExpireAdminSupportInterventionInput {
            now: at(640),
            intervention_id: expiry_intervention_id.clone(),
        }
    );
    assert_eq!(
        load_admin_support_intervention_for_runtime_test(
            pool,
            store_config,
            &expiry_intervention_id
        )
        .await
        .expect("expiry helper must leave the candidate row unchanged")
        .status,
        AdminSupportInterventionStatus::Requested,
        "mounted expiry helper is a pre-dispatch read and must not close the candidate"
    );

    let too_early_expiry = mounted_service
        .expire_intervention_from_headers(
            &HeaderMap::new(),
            ExpireAdminSupportInterventionInput {
                now: at(639),
                intervention_id: expiry_intervention_id.clone(),
            },
        )
        .await
        .expect_err("mounted expiry must be deadline-derived");
    assert!(matches!(
        too_early_expiry,
        MountedAdminSupportServiceError::Runtime(
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
                Error::AdminSupportInterventionNotExpirable
            )
        )
    ));

    let expired = mounted_service
        .expire_intervention_from_headers(
            &HeaderMap::new(),
            ExpireAdminSupportInterventionInput {
                now: at(640),
                intervention_id: expiry_intervention_id.clone(),
            },
        )
        .await
        .expect("mounted expiry should close expired candidate");
    assert_eq!(
        expired.committed_outcome(),
        &MountedAdminSupportCommittedOutcome::InterventionExpired {
            intervention_id: expiry_intervention_id.clone(),
            subject_id: expiry_subject_id,
            target_credential_instance_id: expiry_target_credential_id,
            action: CredentialLifecycleAction::Reset,
        }
    );

    harness.drop_schema().await;
}
