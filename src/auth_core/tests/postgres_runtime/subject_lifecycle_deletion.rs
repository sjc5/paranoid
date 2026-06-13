use super::*;

#[tokio::test]
async fn postgres_runtime_authenticated_subject_auth_state_deletion_scheduling_derives_subject_and_policy_timing()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("subject-deletion-schedule-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "subject-deletion-schedule-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .schedule_authenticated_subject_auth_state_deletion_from_headers(
            &headers,
            ScheduleAuthenticatedSubjectAuthStateDeletionInput { now: at(90) },
        )
        .await
        .expect("schedule subject auth-state deletion through Postgres runtime");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.precondition.close_expired_pending_subject_lifecycle_actions",
            "auth_core.precondition.no_open_pending_subject_lifecycle_action",
            "auth_core.mutation.create_pending_subject_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated subject auth-state deletion scheduling must stay inside one live-session load, pending-action uniqueness guard, pending creation, audit, notice, and commit",
    );

    let pending_action_id = match execution.outcome() {
        Outcome::SubjectAuthStateDeletionScheduled(outcome) => {
            assert_eq!(outcome.subject_id, subject_id);
            assert_eq!(outcome.earliest_execute_at, at(1090));
            assert_eq!(outcome.expires_at, at(10090));
            outcome.pending_action_id.clone()
        }
        outcome => panic!("expected subject auth-state deletion scheduling, got {outcome:?}"),
    };
    assert!(
        execution.set_cookie_headers().is_empty(),
        "subject auth-state deletion scheduling must not emit response cookies"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_subject(
            pool,
            store_config,
            &subject_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "runtime scheduling must create one pending deletion action for the authenticated subject"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "runtime-generated pending deletion action id must be committed"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "runtime scheduling must atomically schedule the deletion notice"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_mature_pending_subject_auth_state_deletion_closes_action_and_revokes_auth_state()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("pending-subject-deletion-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-subject-deletion-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let pending_action_id = id("pending-subject-deletion-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_mature_pending_subject_auth_state_deletion_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingSubjectAuthStateDeletionInput {
                now: at(250),
                pending_action_id: pending_action_id.clone(),
                application_subject_data_lifecycle_action: Some(
                    ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
                ),
            },
        )
        .await
        .expect("execute mature pending subject auth-state deletion");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.pending_subject_lifecycle_action",
            "auth_core.precondition.pending_subject_lifecycle_action_still_executable",
            "auth_core.mutation.close_pending_subject_lifecycle_action",
            "auth_core.precondition.materialize_subject_auth_state",
            "auth_core.precondition.lock_subject_auth_state",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "auth_core.effect.append_application_subject_data_lifecycle",
            "db.tx.commit",
        ],
        "mature pending subject auth-state deletion execution must stay inside one pending-action load, executable guard, pending closure, auth-state revocation, durable effects, and commit",
    );

    assert_eq!(
        execution.outcome(),
        &Outcome::PendingSubjectAuthStateDeletionExecuted(
            PendingSubjectAuthStateDeletionExecutionOutcome {
                subject_id: subject_id.clone(),
                pending_action_id: pending_action_id.clone(),
            }
        )
    );
    assert!(
        execution.set_cookie_headers().is_empty(),
        "subject auth-state deletion execution must not emit response cookies"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "execution must close the pending subject auth-state deletion action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "execution must commit the subject auth-state deletion security notice"
    );
    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(())));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(())));
    let application_subject_data_integrator =
        Arc::new(RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())));
    let mounted_worker_service =
        mounted_auth_durable_effect_worker_service_for_test_with_application_subject_data_integrator(
        &harness,
        &queue_test_store,
        out_of_band_deliverer.clone(),
        security_notification_deliverer.clone(),
        application_subject_data_integrator.clone(),
    );
    let dispatch_summary = mounted_worker_service
        .dispatch_available_durable_effects_to_queue(MountedAuthDurableEffectDispatchRequest::new(
            NonZeroU32::new(10).expect("nonzero core dispatch limit"),
            NonZeroU32::new(10).expect("nonzero method dispatch limit"),
            at(270),
        ))
        .await
        .expect("mounted worker should dispatch subject deletion notice");
    assert_eq!(dispatch_summary.core_summary().enqueued_effect_count(), 3);
    assert_eq!(dispatch_summary.method_summary().enqueued_effect_count(), 1);
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
        )
        .await,
        1,
        "mounted worker should also dispatch the earlier committed login delivery effect"
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
        )
        .await,
        1,
        "mounted worker should also dispatch the earlier committed method-owned email delivery effect"
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
        )
        .await,
        1
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME,
        )
        .await,
        1
    );
    let worker_summary = mounted_worker_service
        .process_available_delivery_jobs_once_for_worker(
            "mounted-subject-deletion-notice-delivery",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("mounted worker should deliver subject deletion notice");
    assert_eq!(worker_summary.claimed_count, 3);
    assert_eq!(worker_summary.succeeded_count, 3);
    assert_eq!(worker_summary.dead_lettered_count, 0);
    assert_eq!(out_of_band_deliverer.recorded_requests().len(), 1);
    let delivered_notifications = security_notification_deliverer.recorded_requests();
    assert_eq!(delivered_notifications.len(), 1);
    assert_eq!(
        delivered_notifications[0].notification_kind(),
        "subject_auth_state_deletion_executed"
    );
    assert_eq!(delivered_notifications[0].subject_id(), &subject_id);
    let application_subject_data_requests = application_subject_data_integrator.recorded_requests();
    assert_eq!(application_subject_data_requests.len(), 1);
    assert_eq!(
        application_subject_data_requests[0].action(),
        ApplicationSubjectDataLifecycleAction::DeleteSubjectData
    );
    assert_eq!(
        application_subject_data_requests[0].subject_id(),
        &subject_id
    );
    assert_eq!(application_subject_data_requests[0].requested_at(), at(250));

    let resolved_after_deletion = runtime
        .execute_request_resolution_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            ResolveRequestInput {
                now: at(260),
                request_kind: RequestKind::StateChanging,
            },
        )
        .await
        .expect("resolve original session after subject auth-state deletion");
    assert_eq!(
        resolved_after_deletion.outcome(),
        &Outcome::NeedsFullAuthentication,
        "subject auth-state deletion must invalidate sessions created before the deletion cutoff"
    );

    let replay_error = runtime
        .execute_mature_pending_subject_auth_state_deletion_from_headers(
            &HeaderMap::new(),
            ExecuteMaturePendingSubjectAuthStateDeletionInput {
                now: at(260),
                pending_action_id,
                application_subject_data_lifecycle_action: Some(
                    ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
                ),
            },
        )
        .await
        .expect_err("closed pending subject auth-state deletion must not replay");

    assert!(matches!(
        replay_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::PendingSubjectLifecycleActionNotExecutable
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_subject_auth_state_deletion_cancellation_closes_open_action()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let mounted_subject_lifecycle_service = MountedSubjectLifecyclePostgresService::new(runtime);
    let subject_id = id("pending-subject-deletion-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-subject-deletion-cancel-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let pending_action_id = id("pending-subject-deletion-cancel-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let cancellation = mounted_subject_lifecycle_service
        .cancel_delayed_subject_auth_state_deletion_from_headers(
            &headers,
            CancelMountedDelayedSubjectAuthStateDeletionInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("cancel pending subject auth-state deletion");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.load.session_with_secret_macs",
            "auth_core.load.subject_revocation",
            "auth_core.load.pending_subject_lifecycle_action",
            "auth_core.precondition.pending_subject_lifecycle_action_still_cancellable_for_subject",
            "auth_core.mutation.close_pending_subject_lifecycle_action",
            "auth_core.audit.append_event",
            "auth_core.effect.append_security_notification",
            "db.tx.commit",
        ],
        "authenticated pending subject auth-state deletion cancellation must stay inside one live-session load, pending-action load, cancellable guard, pending closure, audit, notice, and commit",
    );

    assert_eq!(
        cancellation.committed_outcome(),
        &MountedSubjectLifecycleCommittedOutcome::SubjectAuthStateDeletionCancelled {
            subject_id: subject_id.clone(),
            pending_action_id: pending_action_id.clone(),
        }
    );
    assert!(
        cancellation
            .runtime_execution()
            .set_cookie_headers()
            .is_empty()
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        0,
        "cancellation must close the pending subject auth-state deletion action"
    );
    assert_eq!(
        count_security_notification_effects_for_subject(pool, store_config, &subject_id).await,
        1,
        "cancellation must commit the subject auth-state deletion cancellation notice"
    );

    let replay_error = mounted_subject_lifecycle_service
        .cancel_delayed_subject_auth_state_deletion_from_headers(
            &headers,
            CancelMountedDelayedSubjectAuthStateDeletionInput {
                now: at(100),
                pending_action_id,
            },
        )
        .await
        .expect_err("closed pending subject auth-state deletion cancellation must not replay");

    assert!(matches!(
        replay_error,
        MountedSubjectLifecycleServiceError::Runtime(
            super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
                Error::PendingSubjectLifecycleActionNotCancellable
            )
        )
    ));

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_pending_subject_auth_state_deletion_cancellation_requires_fresh_step_up_before_pending_load()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let subject_id = id("stale-step-up-subject-deletion-cancel-subject");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "stale-step-up-subject-deletion-cancel-bootstrap",
        20,
        subject_id.clone(),
        false,
    )
    .await;
    let pending_action_id = id("stale-step-up-subject-deletion-cancel-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                subject_id.clone(),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();

    let execution = runtime
        .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
            &headers,
            CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect("stale subject deletion cancellation returns step-up outcome");

    assert_eq!(
        execution.outcome(),
        &Outcome::NeedsStepUp {
            session_id: issued_auth.session_id,
            subject_id,
        }
    );
    let observed = harness.database_operation_observer.records();
    assert!(
        !observed
            .iter()
            .any(|record| record.label == "auth_core.load.pending_subject_lifecycle_action"),
        "stale subject deletion cancellation must not load pending action state; observed database operations: {observed:?}"
    );
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "stale cancellation must leave the pending subject auth-state deletion action open"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_subject_auth_state_deletion_cancellation_rejects_wrong_subject_session() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let pending_subject_id = id("pending-subject-deletion-owner");
    let session_subject_id = id("pending-subject-deletion-other-session");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "pending-subject-deletion-wrong-session-bootstrap",
        50,
        session_subject_id,
        false,
    )
    .await;
    let pending_action_id = id("pending-subject-deletion-wrong-session-action");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_pending_subject_lifecycle_actions_for_test(
            pool,
            &[PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id.clone(),
                pending_subject_id,
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject auth-state deletion action")],
        )
        .await
        .expect("seed pending subject auth-state deletion action");

    let cancellation_error = runtime
        .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
            &headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]),
            CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
                now: at(90),
                pending_action_id: pending_action_id.clone(),
            },
        )
        .await
        .expect_err("wrong subject session must not cancel pending subject auth-state deletion");

    assert!(matches!(
        cancellation_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::CredentialLifecycleActionNotAuthorized
        )
    ));
    assert_eq!(
        count_open_pending_subject_lifecycle_actions_for_pending_action(
            pool,
            store_config,
            &pending_action_id,
            SubjectLifecycleAction::DeleteSubjectAuthState,
        )
        .await,
        1,
        "wrong-subject cancellation must leave the pending subject auth-state deletion action open"
    );

    harness.drop_schema().await;
}
