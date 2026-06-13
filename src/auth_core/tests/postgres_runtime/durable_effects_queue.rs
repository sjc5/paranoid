use super::*;

#[tokio::test]
async fn postgres_runtime_commits_core_durable_effects_atomically() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "durable-effect",
        20,
        id("durable-effect-subject"),
    )
    .await;
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        1
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(
            pool,
            store_config,
            &challenge.challenge_id
        )
        .await,
        1
    );

    let resent = runtime
        .execute_out_of_band_challenge_resend_from_headers(
            &headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]),
            ResendOutOfBandChallengeRequest {
                now: at(40),
                idempotency_key: "durable-effect-mail-idempotency-key-2".to_owned(),
            },
        )
        .await
        .expect("resend challenge through Postgres runtime");
    assert!(matches!(
        resent.outcome(),
        Outcome::OutOfBandChallengeResent { .. }
    ));
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        2
    );
    assert_eq!(
        count_out_of_band_durable_effects_for_challenge(
            pool,
            store_config,
            &challenge.challenge_id
        )
        .await,
        2
    );

    complete_out_of_band_challenge_response_through_runtime(runtime, &challenge, at(50)).await;
    let continuation_headers =
        headers_from_cookie_pairs(&[challenge.continuation_cookie_pair.as_str()]);
    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &continuation_headers,
            CompleteFullAuthenticationInput {
                now: at(55),
                trust_device: Some(TrustDeviceAfterFullAuthenticationInput {
                    display_label: Some("durable effect browser".to_owned()),
                }),
            },
        )
        .await
        .expect("complete full authentication through Postgres runtime");
    assert!(matches!(
        full_authentication.outcome(),
        Outcome::Authenticated(_)
    ));
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        3
    );
    assert_eq!(
        count_security_notification_effects_for_subject(
            pool,
            store_config,
            &id("durable-effect-subject")
        )
        .await,
        1
    );

    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let dispatcher = PostgresAuthDurableEffectQueueDispatcher::new(store_config.clone());
    let dispatch_summary = dispatcher
        .enqueue_available_core_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(70),
        )
        .await
        .expect("dispatch committed auth durable effects to queue");
    assert_eq!(dispatch_summary.enqueued_effect_count(), 3);
    assert_eq!(dispatch_summary.deduplicated_queue_job_count(), 0);
    assert_eq!(
        count_core_durable_effect_queue_dispatches(pool, store_config).await,
        3
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
        )
        .await,
        2
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
    let out_of_band_payload = fetch_one_queue_payload_json_for_task(
        pool,
        &queue_test_store.jobs_table,
        AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
    )
    .await;
    assert_eq!(out_of_band_payload["effect_command_id"], 1);
    assert_eq!(out_of_band_payload["proof_method_label"], "email_otp");
    assert_eq!(
        out_of_band_payload["recipient_handle"],
        recipient_handle_for_test_subject("durable-effect", &id("durable-effect-subject"))
    );
    assert_eq!(
        out_of_band_payload["delivery_idempotency_key"],
        "durable-effect-mail-idempotency-key"
    );
    assert_eq!(
        out_of_band_payload["challenge_id"],
        serde_json::to_value(challenge.challenge_id.as_bytes().to_vec())
            .expect("challenge id should serialize to JSON")
    );
    let security_payload = fetch_one_queue_payload_json_for_task(
        pool,
        &queue_test_store.jobs_table,
        AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
    )
    .await;
    assert_eq!(security_payload["effect_command_id"], 3);
    assert_eq!(
        security_payload["notification_kind"],
        "trusted_device_created"
    );
    assert_eq!(
        security_payload["subject_id"],
        serde_json::to_value(
            id::<SubjectId>("durable-effect-subject")
                .as_bytes()
                .to_vec()
        )
        .expect("subject id should serialize to JSON")
    );

    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(())));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(())));
    let application_subject_data_integrator =
        Arc::new(RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())));
    let mut task_registry = crate::queue::TaskRegistry::new();
    let out_of_band_delivery_trait: Arc<dyn CoreAuthOutOfBandMessageDeliverer> =
        out_of_band_deliverer.clone();
    let security_notification_delivery_trait: Arc<dyn CoreAuthSecurityNotificationDeliverer> =
        security_notification_deliverer.clone();
    let application_subject_data_trait: Arc<dyn CoreAuthApplicationSubjectDataLifecycleIntegrator> =
        application_subject_data_integrator.clone();
    register_core_auth_durable_effect_queue_handlers(
        &mut task_registry,
        out_of_band_delivery_trait,
        security_notification_delivery_trait,
        application_subject_data_trait,
    )
    .expect("register auth durable-effect queue handlers");
    let worker_summary = queue_test_store
        .store
        .process_available_jobs_once_for_worker(
            &harness.write_pool,
            &task_registry,
            "auth-durable-effect-delivery",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("process auth durable-effect delivery jobs");
    assert_eq!(worker_summary.claimed_count, 3);
    assert_eq!(worker_summary.succeeded_count, 3);
    assert_eq!(worker_summary.retried_count, 0);
    assert_eq!(worker_summary.failed_count, 0);
    assert_eq!(worker_summary.dead_lettered_count, 0);
    assert_eq!(worker_summary.lost_ownership_count, 0);

    let mut out_of_band_requests = out_of_band_deliverer.recorded_requests();
    out_of_band_requests.sort_by_key(|request| request.effect_command_id());
    assert_eq!(out_of_band_requests.len(), 2);
    assert_eq!(out_of_band_requests[0].effect_command_id(), 1);
    assert_eq!(
        out_of_band_requests[0].effect_idempotency_key(),
        "paranoid.auth.core_effect.1"
    );
    assert_eq!(out_of_band_requests[0].retry_count(), 0);
    assert_eq!(
        out_of_band_requests[0].max_retries(),
        crate::queue::DEFAULT_MAX_RETRIES
    );
    assert_eq!(
        out_of_band_requests[0].queue_job_id().as_bytes().len(),
        crate::queue::JOB_ID_SIZE
    );
    assert_eq!(
        out_of_band_requests[0].challenge_id(),
        &challenge.challenge_id
    );
    assert_eq!(out_of_band_requests[0].proof_method_label(), "email_otp");
    assert_eq!(
        out_of_band_requests[0].recipient_handle(),
        recipient_handle_for_test_subject("durable-effect", &id("durable-effect-subject"))
    );
    assert_eq!(
        out_of_band_requests[0].delivery_idempotency_key(),
        "durable-effect-mail-idempotency-key"
    );
    let expected_out_of_band_expiry = at(30)
        .checked_add_duration(config().out_of_band_challenge_lifetime)
        .expect("configured out-of-band challenge lifetime should not overflow");
    assert_eq!(
        out_of_band_requests[0].expires_at(),
        expected_out_of_band_expiry
    );
    assert_eq!(out_of_band_requests[1].effect_command_id(), 2);
    assert_eq!(
        out_of_band_requests[1].effect_idempotency_key(),
        "paranoid.auth.core_effect.2"
    );
    assert_eq!(
        out_of_band_requests[1].delivery_idempotency_key(),
        "durable-effect-mail-idempotency-key-2"
    );

    let security_notification_requests = security_notification_deliverer.recorded_requests();
    assert_eq!(security_notification_requests.len(), 1);
    assert_eq!(security_notification_requests[0].effect_command_id(), 3);
    assert_eq!(
        security_notification_requests[0].effect_idempotency_key(),
        "paranoid.auth.core_effect.3"
    );
    assert_eq!(security_notification_requests[0].retry_count(), 0);
    assert_eq!(
        security_notification_requests[0].max_retries(),
        crate::queue::DEFAULT_MAX_RETRIES
    );
    assert_eq!(
        security_notification_requests[0]
            .queue_job_id()
            .as_bytes()
            .len(),
        crate::queue::JOB_ID_SIZE
    );
    assert_eq!(
        security_notification_requests[0].notification_kind(),
        "trusted_device_created"
    );
    assert_eq!(
        security_notification_requests[0].subject_id(),
        &id("durable-effect-subject")
    );

    let second_dispatch_summary = dispatcher
        .enqueue_available_core_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(80),
        )
        .await
        .expect("second dispatch pass should observe already dispatched effects");
    assert_eq!(second_dispatch_summary.enqueued_effect_count(), 0);
    assert_eq!(second_dispatch_summary.deduplicated_queue_job_count(), 0);
    assert_eq!(
        count_core_durable_effect_queue_dispatches(pool, store_config).await,
        3
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
        )
        .await,
        2
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

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rolls_back_durable_effect_dispatch_marker_when_queue_enqueue_fails() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let _challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "durable-effect-rollback",
        20,
        id("durable-effect-rollback-subject"),
    )
    .await;
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        1
    );
    assert_eq!(
        count_core_durable_effect_queue_dispatches(pool, store_config).await,
        0
    );

    let missing_queue_jobs_table = PgQualifiedTableName::new(
        Some(harness.schema.clone()),
        PgIdentifier::new("__paranoid_missing_auth_queue_jobs").expect("missing queue jobs table"),
    );
    let missing_queue_dead_letter_table = PgQualifiedTableName::new(
        Some(harness.schema.clone()),
        PgIdentifier::new("__paranoid_missing_auth_queue_dead_letters")
            .expect("missing queue dead-letter table"),
    );
    let missing_queue_pause_table = PgQualifiedTableName::new(
        Some(harness.schema.clone()),
        PgIdentifier::new("__paranoid_missing_auth_queue_pauses")
            .expect("missing queue pause table"),
    );
    let missing_queue_config = crate::db::queue::StoreConfig {
        table_name: missing_queue_jobs_table,
        dead_letter_table_name: missing_queue_dead_letter_table,
        pause_table_name: missing_queue_pause_table,
        schema_ledger_table_name: harness
            .store_config
            .schema_ledger_table_name()
            .expect("auth schema ledger table"),
        payload_json_limit_bytes: crate::db::queue::DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
    };
    let missing_queue_store =
        crate::db::queue::Store::new_inner(missing_queue_config).expect("queue store config");
    let dispatcher = PostgresAuthDurableEffectQueueDispatcher::new(store_config.clone());
    let dispatch_error = dispatcher
        .enqueue_available_core_durable_effects_to_queue(
            &harness.write_pool,
            &missing_queue_store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(70),
        )
        .await
        .expect_err("missing queue table should fail durable effect dispatch");
    assert!(matches!(
        dispatch_error,
        PostgresAuthDurableEffectQueueDispatchError::Queue(_)
    ));
    assert_eq!(
        count_core_durable_effect_commands(pool, store_config).await,
        1
    );
    assert_eq!(
        count_core_durable_effect_queue_dispatches(pool, store_config).await,
        0
    );

    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let recovered_dispatch_summary = dispatcher
        .enqueue_available_core_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(80),
        )
        .await
        .expect("dispatch should recover after failed queue enqueue rollback");
    assert_eq!(recovered_dispatch_summary.enqueued_effect_count(), 1);
    assert_eq!(
        count_core_durable_effect_queue_dispatches(pool, store_config).await,
        1
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
        )
        .await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_auth_durable_effect_queue_worker_retries_retryable_delivery_failure() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;

    let _challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp_plugin_for_harness(&harness),
        "durable-effect-retry",
        20,
        id("durable-effect-retry-subject"),
    )
    .await;
    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let dispatcher = PostgresAuthDurableEffectQueueDispatcher::new(store_config.clone());
    dispatcher
        .enqueue_available_core_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(70),
        )
        .await
        .expect("dispatch committed auth durable effect to queue");

    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Err(
        CoreAuthDurableEffectDeliveryError::retryable("temporary delivery failure"),
    )));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(())));
    let mut task_registry = crate::queue::TaskRegistry::new();
    let out_of_band_delivery_trait: Arc<dyn CoreAuthOutOfBandMessageDeliverer> =
        out_of_band_deliverer.clone();
    let security_notification_delivery_trait: Arc<dyn CoreAuthSecurityNotificationDeliverer> =
        security_notification_deliverer;
    let application_subject_data_trait: Arc<dyn CoreAuthApplicationSubjectDataLifecycleIntegrator> =
        Arc::new(RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())));
    register_core_auth_durable_effect_queue_handlers(
        &mut task_registry,
        out_of_band_delivery_trait,
        security_notification_delivery_trait,
        application_subject_data_trait,
    )
    .expect("register auth durable-effect queue handlers");

    let worker_summary = queue_test_store
        .store
        .process_available_jobs_once_for_worker(
            &harness.write_pool,
            &task_registry,
            "auth-durable-effect-delivery-retry",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("process retryable auth durable-effect delivery job");
    assert_eq!(worker_summary.claimed_count, 1);
    assert_eq!(worker_summary.succeeded_count, 0);
    assert_eq!(worker_summary.retried_count, 1);
    assert_eq!(worker_summary.dead_lettered_count, 0);
    assert_eq!(out_of_band_deliverer.recorded_requests().len(), 1);
    let queued_retry_state = fetch_one_queue_job_retry_state_for_task(
        pool,
        &queue_test_store.jobs_table,
        AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
    )
    .await;
    assert_eq!(queued_retry_state.status.as_str(), "pending");
    assert_eq!(queued_retry_state.retry_count, 1);
    assert_eq!(
        queued_retry_state.last_error.as_deref(),
        Some("temporary delivery failure")
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_auth_durable_effect_queue_worker_dead_letters_malformed_payload_and_permanent_delivery_failure()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required().await;
    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    queue_test_store
        .store
        .enqueue_json(
            &harness.write_pool,
            AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
            &serde_json::json!({
                "effect_command_id": 0,
                "notification_kind": "trusted_device_created",
                "subject_id": id::<SubjectId>("malformed-payload-subject").as_bytes(),
            }),
            crate::queue::EnqueueOptions::default(),
        )
        .await
        .expect("enqueue malformed auth security notification payload");
    queue_test_store
        .store
        .enqueue_json(
            &harness.write_pool,
            AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
            &serde_json::json!({
                "effect_command_id": 44,
                "notification_kind": "trusted_device_created",
                "subject_id": id::<SubjectId>("permanent-failure-subject").as_bytes(),
            }),
            crate::queue::EnqueueOptions::default(),
        )
        .await
        .expect("enqueue permanent-failure auth security notification payload");

    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(())));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Err(
            CoreAuthDurableEffectDeliveryError::permanent("permanent provider failure"),
        )));
    let mut task_registry = crate::queue::TaskRegistry::new();
    let out_of_band_delivery_trait: Arc<dyn CoreAuthOutOfBandMessageDeliverer> =
        out_of_band_deliverer;
    let security_notification_delivery_trait: Arc<dyn CoreAuthSecurityNotificationDeliverer> =
        security_notification_deliverer.clone();
    let application_subject_data_trait: Arc<dyn CoreAuthApplicationSubjectDataLifecycleIntegrator> =
        Arc::new(RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())));
    register_core_auth_durable_effect_queue_handlers(
        &mut task_registry,
        out_of_band_delivery_trait,
        security_notification_delivery_trait,
        application_subject_data_trait,
    )
    .expect("register auth durable-effect queue handlers");

    let worker_summary = queue_test_store
        .store
        .process_available_jobs_once_for_worker(
            &harness.write_pool,
            &task_registry,
            "auth-durable-effect-delivery-malformed",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("process malformed and permanent-failure auth durable-effect delivery jobs");
    assert_eq!(worker_summary.claimed_count, 2);
    assert_eq!(worker_summary.succeeded_count, 0);
    assert_eq!(worker_summary.retried_count, 0);
    assert_eq!(worker_summary.dead_lettered_count, 2);
    let recorded_security_notifications = security_notification_deliverer.recorded_requests();
    assert_eq!(
        recorded_security_notifications.len(),
        1,
        "only the valid payload should reach the delivery callback"
    );
    assert_eq!(
        recorded_security_notifications[0].subject_id(),
        &id("permanent-failure-subject")
    );
    let dead_letters = queue_test_store
        .store
        .list_dead_letter_jobs(
            &harness.write_pool,
            crate::queue::ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list auth delivery dead letters");
    assert_eq!(dead_letters.jobs.len(), 2);
    assert!(
        dead_letters
            .jobs
            .iter()
            .all(|job| { job.reason == crate::queue::DeadLetterReason::PermanentError })
    );
    let mut dead_letter_errors = dead_letters
        .jobs
        .iter()
        .map(|job| job.last_error.as_str())
        .collect::<Vec<_>>();
    dead_letter_errors.sort_unstable();
    assert_eq!(
        dead_letter_errors,
        vec![
            "permanent provider failure",
            "queued auth durable effect id must be positive"
        ]
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_method_durable_effect_queue_dispatches_email_otp_delivery_through_registry()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let email_otp_deliverer = Arc::new(RecordingEmailOtpDeliveryMessageDeliverer::new(Ok(())));
    let email_otp_delivery_trait: Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer> =
        email_otp_deliverer.clone();
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_email_otp_delivery_message_deliverer(
            email_otp_delivery_trait,
        )
        .await;
    let pool = &harness.pool;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let method_registry = harness
        .method_registry
        .as_ref()
        .expect("method registry with email otp plugin");

    let challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp,
        "method-durable-effect",
        20,
        id("method-durable-effect-subject"),
    )
    .await;
    assert_eq!(
        email_otp
            .count_delivery_commands_for_test(pool)
            .await
            .expect("count email otp delivery commands"),
        1
    );
    assert_eq!(
        email_otp
            .count_dispatched_delivery_commands_for_test(pool)
            .await
            .expect("count dispatched email otp delivery commands"),
        0
    );

    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let dispatch_summary = method_registry
        .enqueue_available_method_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(70),
        )
        .await
        .expect("dispatch committed method durable effects to queue");
    assert_eq!(dispatch_summary.enqueued_effect_count(), 1);
    assert_eq!(dispatch_summary.deduplicated_queue_job_count(), 0);
    assert_eq!(
        email_otp
            .count_dispatched_delivery_commands_for_test(pool)
            .await
            .expect("count dispatched email otp delivery commands"),
        1
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
        )
        .await,
        1
    );
    let queued_payload = fetch_one_queue_payload_json_for_task(
        pool,
        &queue_test_store.jobs_table,
        EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
    )
    .await;
    assert_eq!(
        queued_payload["challenge_id"],
        serde_json::to_value(challenge.challenge_id.as_bytes().to_vec())
            .expect("challenge id should serialize to JSON")
    );
    assert_eq!(
        queued_payload["delivery_idempotency_key"],
        "method-durable-effect-mail-idempotency-key"
    );

    let second_dispatch_summary = method_registry
        .enqueue_available_method_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(80),
        )
        .await
        .expect("second method dispatch pass should observe already dispatched effects");
    assert_eq!(second_dispatch_summary.enqueued_effect_count(), 0);
    assert_eq!(second_dispatch_summary.deduplicated_queue_job_count(), 0);
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
        )
        .await,
        1
    );

    let mut task_registry = crate::queue::TaskRegistry::new();
    method_registry
        .register_durable_effect_queue_handlers(&mut task_registry)
        .expect("register method durable-effect queue handlers");
    let worker_summary = queue_test_store
        .store
        .process_available_jobs_once_for_worker(
            &harness.write_pool,
            &task_registry,
            "auth-method-durable-effect-delivery",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("process email otp method durable-effect delivery job");
    assert_eq!(worker_summary.claimed_count, 1);
    assert_eq!(worker_summary.succeeded_count, 1);
    assert_eq!(worker_summary.retried_count, 0);
    assert_eq!(worker_summary.dead_lettered_count, 0);

    let recorded_requests = email_otp_deliverer.recorded_requests();
    assert_eq!(recorded_requests.len(), 1);
    assert_eq!(
        recorded_requests[0].queue_job_id.as_bytes().len(),
        crate::queue::JOB_ID_SIZE
    );
    assert_eq!(recorded_requests[0].retry_count, 0);
    assert_eq!(
        recorded_requests[0].max_retries,
        crate::queue::DEFAULT_MAX_RETRIES
    );
    assert_eq!(recorded_requests[0].challenge_id, challenge.challenge_id);
    assert_eq!(
        recorded_requests[0].delivery_idempotency_key,
        "method-durable-effect-mail-idempotency-key"
    );
    assert_eq!(
        recorded_requests[0].recipient_handle,
        recipient_handle_for_test_subject(
            "method-durable-effect",
            &id("method-durable-effect-subject")
        )
    );
    assert_eq!(
        recorded_requests[0].response_secret,
        challenge.response_secret.expose_secret()
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_method_durable_effect_queue_worker_retries_provider_failure_and_rejects_spoofed_email_otp_payload()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let email_otp_deliverer = Arc::new(RecordingEmailOtpDeliveryMessageDeliverer::new(Err(
        AuthDurableEffectDeliveryError::retryable("temporary email otp provider failure"),
    )));
    let email_otp_delivery_trait: Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer> =
        email_otp_deliverer.clone();
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_email_otp_delivery_message_deliverer(
            email_otp_delivery_trait,
        )
        .await;
    let pool = &harness.pool;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let method_registry = harness
        .method_registry
        .as_ref()
        .expect("method registry with email otp plugin");

    let challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp,
        "method-durable-effect-retry",
        20,
        id("method-durable-effect-retry-subject"),
    )
    .await;
    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    method_registry
        .enqueue_available_method_durable_effects_to_queue(
            &harness.write_pool,
            &queue_test_store.store,
            NonZeroU32::new(10).expect("nonzero dispatch limit"),
            at(70),
        )
        .await
        .expect("dispatch committed method durable effect to queue");
    queue_test_store
        .store
        .enqueue_json(
            &harness.write_pool,
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
            &serde_json::json!({
                "challenge_id": id::<ActiveProofChallengeId>("spoofed-email-otp-challenge").as_bytes(),
                "delivery_idempotency_key": "spoofed_email_otp_delivery_key",
            }),
            crate::queue::EnqueueOptions::default(),
        )
        .await
        .expect("enqueue spoofed email otp method delivery payload");

    let mut task_registry = crate::queue::TaskRegistry::new();
    method_registry
        .register_durable_effect_queue_handlers(&mut task_registry)
        .expect("register method durable-effect queue handlers");
    let worker_summary = queue_test_store
        .store
        .process_available_jobs_once_for_worker(
            &harness.write_pool,
            &task_registry,
            "auth-method-durable-effect-delivery-retry",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("process email otp method durable-effect delivery jobs");
    assert_eq!(worker_summary.claimed_count, 2);
    assert_eq!(worker_summary.succeeded_count, 0);
    assert_eq!(worker_summary.retried_count, 1);
    assert_eq!(worker_summary.dead_lettered_count, 1);

    let recorded_requests = email_otp_deliverer.recorded_requests();
    assert_eq!(
        recorded_requests.len(),
        1,
        "spoofed queued payload must not reach the method delivery callback"
    );
    assert_eq!(recorded_requests[0].challenge_id, challenge.challenge_id);
    assert_eq!(
        recorded_requests[0].response_secret,
        challenge.response_secret.expose_secret()
    );
    let queued_retry_state = fetch_one_queue_job_retry_state_for_task(
        pool,
        &queue_test_store.jobs_table,
        EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
    )
    .await;
    assert_eq!(queued_retry_state.status.as_str(), "pending");
    assert_eq!(queued_retry_state.retry_count, 1);
    assert_eq!(
        queued_retry_state.last_error.as_deref(),
        Some("temporary email otp provider failure")
    );
    let dead_letters = queue_test_store
        .store
        .list_dead_letter_jobs(
            &harness.write_pool,
            crate::queue::ListDeadLetterJobsOptions::default(),
        )
        .await
        .expect("list method delivery dead letters");
    assert_eq!(dead_letters.jobs.len(), 1);
    assert_eq!(
        dead_letters.jobs[0].last_error,
        "queued email otp delivery does not reference a committed dispatched row"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_durable_effect_worker_service_dispatches_and_processes_core_and_method_effects()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let email_otp_deliverer = Arc::new(RecordingEmailOtpDeliveryMessageDeliverer::new(Ok(())));
    let email_otp_delivery_trait: Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer> =
        email_otp_deliverer.clone();
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_email_otp_delivery_message_deliverer(
            email_otp_delivery_trait,
        )
        .await;
    let pool = &harness.pool;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(())));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(())));

    let challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp,
        "mounted-durable-effect",
        20,
        id("mounted-durable-effect-subject"),
    )
    .await;
    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let service = mounted_auth_durable_effect_worker_service_for_test(
        &harness,
        &queue_test_store,
        out_of_band_deliverer.clone(),
        security_notification_deliverer.clone(),
    );
    let task_registry = service
        .build_task_registry()
        .expect("build mounted auth durable-effect task registry");
    let task_names = task_registry.registered_task_names();
    assert_eq!(
        task_names,
        vec![
            AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME.to_owned(),
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME.to_owned(),
            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME.to_owned(),
            AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME.to_owned(),
        ]
    );

    harness.database_operation_observer.clear();
    let dispatch_summary = service
        .dispatch_available_durable_effects_to_queue(MountedAuthDurableEffectDispatchRequest::new(
            NonZeroU32::new(10).expect("nonzero core dispatch limit"),
            NonZeroU32::new(10).expect("nonzero method dispatch limit"),
            at(70),
        ))
        .await
        .expect("mounted worker service should dispatch committed auth durable effects");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "auth_core.durable_effect_queue.lock_undispatched_effects",
            "queue.dedupe_enqueue",
            "auth_core.durable_effect_queue.insert_dispatch",
            "auth_core.email_otp.delivery_queue.lock_undispatched_deliveries",
            "queue.dedupe_enqueue",
            "auth_core.email_otp.delivery_queue.mark_delivery_dispatched",
            "db.tx.commit",
        ],
        "mounted durable-effect dispatch must lock committed core and method effects, enqueue Queue jobs, record dispatch markers, and commit in one bounded transaction",
    );
    assert_eq!(dispatch_summary.core_summary().enqueued_effect_count(), 1);
    assert_eq!(dispatch_summary.method_summary().enqueued_effect_count(), 1);
    assert_eq!(dispatch_summary.total_enqueued_effect_count(), 2);
    assert_eq!(dispatch_summary.total_deduplicated_queue_job_count(), 0);
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
        )
        .await,
        1
    );
    assert_eq!(
        count_queue_jobs_for_task(
            pool,
            &queue_test_store.jobs_table,
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
        )
        .await,
        1
    );

    let worker_pressure = service
        .fetch_delivery_worker_pressure()
        .await
        .expect("fetch mounted auth delivery worker pressure");
    assert!(!worker_pressure.queue_paused);
    assert_eq!(worker_pressure.registered_task_count, 4);
    assert_eq!(worker_pressure.pending_job_count, 2);
    assert_eq!(worker_pressure.running_job_count, 0);
    assert!(
        service
            .fetch_orphaned_delivery_task_names()
            .await
            .expect("fetch mounted auth orphaned delivery task names")
            .is_empty()
    );

    let mut worker_config = auth_runtime_queue_worker_config();
    worker_config.concurrency = 1;
    harness.database_operation_observer.clear();
    let core_worker_summary = service
        .process_available_delivery_jobs_once_for_worker(
            "mounted-auth-durable-effect-core-delivery",
            worker_config,
        )
        .await
        .expect("mounted worker service should process committed core delivery job");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "queue.set_local_statement_timeout",
            "queue.claim_available_jobs",
            "db.tx.commit",
            "db.begin_transaction",
            "queue.set_local_statement_timeout",
            "queue.mark_job_started",
            "db.tx.commit",
            "db.begin_transaction",
            "queue.set_local_statement_timeout",
            "queue.mark_job_completed",
            "db.tx.commit",
        ],
        "mounted durable-effect worker must claim once, complete the committed core delivery job, and avoid auth storage work for the core Queue payload",
    );
    assert_eq!(core_worker_summary.claimed_count, 1);
    assert_eq!(core_worker_summary.succeeded_count, 1);
    assert_eq!(core_worker_summary.retried_count, 0);
    assert_eq!(core_worker_summary.failed_count, 0);
    assert_eq!(core_worker_summary.dead_lettered_count, 0);
    assert_eq!(core_worker_summary.lost_ownership_count, 0);
    let core_requests = out_of_band_deliverer.recorded_requests();
    assert_eq!(core_requests.len(), 1);
    assert_eq!(core_requests[0].challenge_id(), &challenge.challenge_id);
    assert_eq!(core_requests[0].proof_method_label(), "email_otp");
    assert_eq!(
        core_requests[0].recipient_handle(),
        recipient_handle_for_test_subject(
            "mounted-durable-effect",
            &id("mounted-durable-effect-subject")
        )
    );

    let mut worker_config = auth_runtime_queue_worker_config();
    worker_config.concurrency = 1;
    harness.database_operation_observer.clear();
    let method_worker_summary = service
        .process_available_delivery_jobs_once_for_worker(
            "mounted-auth-durable-effect-method-delivery",
            worker_config,
        )
        .await
        .expect("mounted worker service should process committed method delivery job");
    assert_database_operation_labels_exact(
        &harness.database_operation_observer,
        &[
            "db.begin_transaction",
            "queue.set_local_statement_timeout",
            "queue.claim_available_jobs",
            "db.tx.commit",
            "db.begin_transaction",
            "queue.set_local_statement_timeout",
            "queue.mark_job_started",
            "db.tx.commit",
            "db.begin_transaction",
            "auth_core.email_otp.delivery_queue.load_queued_delivery",
            "db.tx.rollback",
            "db.begin_transaction",
            "queue.set_local_statement_timeout",
            "queue.mark_job_completed",
            "db.tx.commit",
        ],
        "mounted durable-effect worker must claim once, load the committed method delivery row, complete the method Queue job, and avoid extra auth storage work",
    );
    assert_eq!(method_worker_summary.claimed_count, 1);
    assert_eq!(method_worker_summary.succeeded_count, 1);
    assert_eq!(method_worker_summary.retried_count, 0);
    assert_eq!(method_worker_summary.failed_count, 0);
    assert_eq!(method_worker_summary.dead_lettered_count, 0);
    assert_eq!(method_worker_summary.lost_ownership_count, 0);
    let method_requests = email_otp_deliverer.recorded_requests();
    assert_eq!(method_requests.len(), 1);
    assert_eq!(method_requests[0].challenge_id, challenge.challenge_id);
    assert_eq!(
        method_requests[0].response_secret,
        challenge.response_secret.expose_secret()
    );
    assert!(
        security_notification_deliverer
            .recorded_requests()
            .is_empty()
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn mounted_auth_durable_effect_worker_service_reclaims_stale_claimed_delivery_jobs() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let email_otp_deliverer = Arc::new(RecordingEmailOtpDeliveryMessageDeliverer::new(Ok(())));
    let email_otp_delivery_trait: Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer> =
        email_otp_deliverer.clone();
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_email_otp_delivery_message_deliverer(
            email_otp_delivery_trait,
        )
        .await;
    let pool = &harness.pool;
    let runtime = &harness.runtime;
    let email_otp = email_otp_plugin_for_harness(&harness);
    let out_of_band_deliverer = Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(())));
    let security_notification_deliverer =
        Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(())));

    let challenge = start_and_issue_out_of_band_challenge_through_runtime(
        runtime,
        pool,
        email_otp,
        "mounted-stale-delivery",
        20,
        id("mounted-stale-delivery-subject"),
    )
    .await;
    let queue_test_store = migrate_queue_store_for_auth_runtime_test(&harness).await;
    let service = mounted_auth_durable_effect_worker_service_for_test(
        &harness,
        &queue_test_store,
        out_of_band_deliverer.clone(),
        security_notification_deliverer,
    );
    service
        .dispatch_available_durable_effects_to_queue(MountedAuthDurableEffectDispatchRequest::new(
            NonZeroU32::new(10).expect("nonzero core dispatch limit"),
            NonZeroU32::new(10).expect("nonzero method dispatch limit"),
            at(70),
        ))
        .await
        .expect("dispatch committed auth durable effects before stale reclaim");

    let task_registry = service
        .build_task_registry()
        .expect("build mounted auth durable-effect task registry");
    let task_names = task_registry.registered_task_names();
    let stale_worker_owner =
        crate::queue::WorkerOwnerId::new_unique_for_worker_name("mounted-auth-stale-delivery")
            .expect("stale worker owner id");
    let claimed = queue_test_store
        .store
        .claim_available_jobs_for_worker(
            &harness.write_pool,
            &task_names,
            1,
            stale_worker_owner.as_str(),
        )
        .await
        .expect("claim one auth delivery job without processing it");
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        service
            .fetch_delivery_worker_pressure()
            .await
            .expect("fetch pressure after stale claim")
            .running_job_count,
        1
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let reclaim_result = service
        .reclaim_available_stale_delivery_jobs_once(Duration::from_micros(1), 10, false)
        .await
        .expect("mounted service should reclaim stale auth delivery job");
    assert_eq!(
        reclaim_result.never_started_jobs_returned_to_pending.len(),
        1
    );
    assert_eq!(
        service
            .fetch_delivery_worker_pressure()
            .await
            .expect("fetch pressure after stale reclaim")
            .pending_job_count,
        2
    );

    let worker_summary = service
        .process_available_delivery_jobs_once_for_worker(
            "mounted-auth-stale-delivery-recovered",
            auth_runtime_queue_worker_config(),
        )
        .await
        .expect("mounted worker should process reclaimed auth delivery jobs");
    assert_eq!(worker_summary.claimed_count, 2);
    assert_eq!(worker_summary.succeeded_count, 2);
    let recorded_requests = out_of_band_deliverer.recorded_requests();
    assert_eq!(recorded_requests.len(), 1);
    assert_eq!(recorded_requests[0].challenge_id(), &challenge.challenge_id);
    let email_otp_requests = email_otp_deliverer.recorded_requests();
    assert_eq!(email_otp_requests.len(), 1);
    assert_eq!(email_otp_requests[0].challenge_id, challenge.challenge_id);

    harness.drop_schema().await;
}
