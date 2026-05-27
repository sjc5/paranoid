use super::*;

#[tokio::test]
async fn fleet_subscription_polling_loop_advances_cursor_after_handler_success() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("polling-success").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: Some(5),
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for id in 1..=3 {
        topic
            .publish(&test_database.paranoid_pool, TestEvent { id })
            .await
            .expect("publish");
    }

    let handled_count = Arc::new(AtomicUsize::new(0));
    let handled_count_for_handler = Arc::clone(&handled_count);
    subscription
        .run_polling_until_stopped_or_handler_error(
            &test_database.paranoid_pool,
            Duration::ZERO,
            tokio::time::sleep(Duration::from_millis(50)),
            move |events| {
                let handled_count_for_handler = Arc::clone(&handled_count_for_handler);
                async move {
                    assert_eq!(events.len(), 3);
                    assert_eq!(events[0].data().id, 1);
                    assert_eq!(events[2].data().id, 3);
                    handled_count_for_handler.fetch_add(events.len(), Ordering::SeqCst);
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
        .expect("run polling loop");

    assert_eq!(handled_count.load(Ordering::SeqCst), 3);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("fetch cursor after handler success"),
        3
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_polling_loop_immediately_repolls_when_backlog_remains() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("immediate-repoll").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: Some(5),
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for id in 1..=20 {
        topic
            .publish(&test_database.paranoid_pool, TestEvent { id })
            .await
            .expect("publish backlog event");
    }

    let batch_count = Arc::new(AtomicUsize::new(0));
    let total_events = Arc::new(AtomicUsize::new(0));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let stop_sender = Arc::new(Mutex::new(Some(stop_sender)));
    let batch_count_for_handler = Arc::clone(&batch_count);
    let total_events_for_handler = Arc::clone(&total_events);
    let stop_sender_for_handler = Arc::clone(&stop_sender);

    tokio::time::timeout(
        Duration::from_secs(2),
        subscription.run_polling_until_stopped_or_handler_error(
            &test_database.paranoid_pool,
            Duration::from_secs(60),
            async move {
                let _ = stop_receiver.await;
            },
            move |events| {
                let batch_count_for_handler = Arc::clone(&batch_count_for_handler);
                let total_events_for_handler = Arc::clone(&total_events_for_handler);
                let stop_sender_for_handler = Arc::clone(&stop_sender_for_handler);
                async move {
                    batch_count_for_handler.fetch_add(1, Ordering::SeqCst);
                    let new_total = total_events_for_handler
                        .fetch_add(events.len(), Ordering::SeqCst)
                        + events.len();
                    if new_total >= 20
                        && let Some(stop_sender) = stop_sender_for_handler
                            .lock()
                            .expect("lock stop sender")
                            .take()
                    {
                        let _ = stop_sender.send(());
                    }
                    Ok::<_, TestComputeError>(())
                }
            },
        ),
    )
    .await
    .expect("subscription should drain backlog without waiting for long poll interval")
    .expect("subscription loop should stop cleanly");

    assert_eq!(total_events.load(Ordering::SeqCst), 20);
    assert_eq!(batch_count.load(Ordering::SeqCst), 4);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after immediate repoll"),
        20
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_start_handle_stops_after_handler_success() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("subscription-handle-success").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: Some(5),
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for id in 1..=3 {
        topic
            .publish(&test_database.paranoid_pool, TestEvent { id })
            .await
            .expect("publish");
    }

    let handled_count = Arc::new(AtomicUsize::new(0));
    let handled_count_for_handler = Arc::clone(&handled_count);
    let handle = subscription.start_polling_until_stopped_or_handler_error(
        test_database.paranoid_pool.clone(),
        Duration::ZERO,
        move |events| {
            let handled_count_for_handler = Arc::clone(&handled_count_for_handler);
            async move {
                assert_eq!(events.len(), 3);
                assert_eq!(events[0].data().id, 1);
                assert_eq!(events[2].data().id, 3);
                handled_count_for_handler.fetch_add(events.len(), Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        },
    );

    wait_until(
        "subscription cursor advanced",
        Duration::from_secs(2),
        || {
            let subscription = subscription.clone();
            let pool = test_database.paranoid_pool.clone();
            async move { matches!(subscription.fetch_cursor(&pool).await, Ok(3)) }
        },
    )
    .await;
    assert_eq!(handled_count.load(Ordering::SeqCst), 3);
    handle
        .stop_and_wait()
        .await
        .expect("subscription handle should stop cleanly");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_stop_during_handler_waits_for_success_and_advances_cursor() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("subscription-stop-during-handler").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: Some(5),
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish event");

    let handler_started = Arc::new(tokio::sync::Notify::new());
    let handler_may_finish = Arc::new(tokio::sync::Notify::new());
    let handled_count = Arc::new(AtomicUsize::new(0));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let run_subscription = subscription.clone();
    let run_pool = test_database.paranoid_pool.clone();
    let handler_started_for_run = Arc::clone(&handler_started);
    let handler_may_finish_for_run = Arc::clone(&handler_may_finish);
    let handled_count_for_run = Arc::clone(&handled_count);
    let run_handle = tokio::spawn(async move {
        run_subscription
            .run_polling_until_stopped_or_handler_error(
                &run_pool,
                Duration::from_secs(60),
                async move {
                    let _ = stop_receiver.await;
                },
                move |events| {
                    let handler_started_for_run = Arc::clone(&handler_started_for_run);
                    let handler_may_finish_for_run = Arc::clone(&handler_may_finish_for_run);
                    let handled_count_for_run = Arc::clone(&handled_count_for_run);
                    async move {
                        assert_eq!(events.len(), 1);
                        assert_eq!(events[0].data().id, 1);
                        handler_started_for_run.notify_one();
                        handler_may_finish_for_run.notified().await;
                        handled_count_for_run.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), handler_started.notified())
        .await
        .expect("subscription handler should start");
    let _ = stop_sender.send(());
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor while handler is blocked"),
        0
    );

    handler_may_finish.notify_one();
    tokio::time::timeout(Duration::from_secs(2), run_handle)
        .await
        .expect("subscription loop should stop after handler success")
        .expect("subscription task should not panic")
        .expect("subscription loop should stop cleanly");

    assert_eq!(handled_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after handler success despite stop"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_polling_loop_serializes_same_subscription_handlers() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("same-subscription-guarded").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: Some(5),
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish event");

    let handler_started = Arc::new(tokio::sync::Notify::new());
    let handler_may_finish = Arc::new(tokio::sync::Notify::new());
    let handler_entries = Arc::new(AtomicUsize::new(0));
    let (first_stop_sender, first_stop_receiver) = tokio::sync::oneshot::channel();
    let (second_stop_sender, second_stop_receiver) = tokio::sync::oneshot::channel();

    let spawn_runner = |stop_receiver| {
        let subscription = subscription.clone();
        let pool = test_database.paranoid_pool.clone();
        let handler_started = Arc::clone(&handler_started);
        let handler_may_finish = Arc::clone(&handler_may_finish);
        let handler_entries = Arc::clone(&handler_entries);
        tokio::spawn(async move {
            subscription
                .run_polling_until_stopped_or_handler_error(
                    &pool,
                    Duration::from_secs(60),
                    async move {
                        let _ = stop_receiver.await;
                    },
                    move |events| {
                        let handler_started = Arc::clone(&handler_started);
                        let handler_may_finish = Arc::clone(&handler_may_finish);
                        let handler_entries = Arc::clone(&handler_entries);
                        async move {
                            assert_eq!(events.len(), 1);
                            assert_eq!(events[0].data().id, 1);
                            handler_entries.fetch_add(1, Ordering::SeqCst);
                            handler_started.notify_one();
                            handler_may_finish.notified().await;
                            Ok::<_, TestComputeError>(())
                        }
                    },
                )
                .await
        })
    };

    let first_runner = spawn_runner(first_stop_receiver);
    let second_runner = spawn_runner(second_stop_receiver);

    tokio::time::timeout(Duration::from_secs(2), handler_started.notified())
        .await
        .expect("one same-subscription handler should start");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(handler_entries.load(Ordering::SeqCst), 1);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor while handler is blocked"),
        0
    );

    let _ = first_stop_sender.send(());
    let _ = second_stop_sender.send(());
    handler_may_finish.notify_one();

    tokio::time::timeout(Duration::from_secs(2), first_runner)
        .await
        .expect("first same-subscription runner should stop")
        .expect("first same-subscription task should not panic")
        .expect("first same-subscription runner should stop cleanly");
    tokio::time::timeout(Duration::from_secs(2), second_runner)
        .await
        .expect("second same-subscription runner should stop")
        .expect("second same-subscription task should not panic")
        .expect("second same-subscription runner should stop cleanly");

    assert_eq!(handler_entries.load(Ordering::SeqCst), 1);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after same-subscription guarded handling"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_polling_loop_does_not_advance_cursor_after_handler_error() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("polling-error").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish");

    let err = subscription
        .run_polling_until_stopped_or_handler_error(
            &test_database.paranoid_pool,
            Duration::from_millis(1),
            tokio::time::sleep(Duration::from_secs(60)),
            |events| async move {
                assert_eq!(events.len(), 1);
                Err::<(), _>(TestComputeError("handler failed"))
            },
        )
        .await
        .expect_err("handler error should stop polling");
    assert!(matches!(err, SubscriptionRunError::Handler { .. }));
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor should not advance after handler error"),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_stops_after_cursor_advance_error_without_rehandling_events() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("polling-cursor-advance-error").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish");

    let handler_count = Arc::new(AtomicUsize::new(0));
    let handler_count_for_handler = Arc::clone(&handler_count);
    let sqlx_pool_for_handler = test_database.sqlx_pool.clone();
    let config_for_handler = test_database.config.clone();
    let err = subscription
        .run_polling_until_stopped_or_handler_error(
            &test_database.paranoid_pool,
            Duration::from_millis(1),
            tokio::time::sleep(Duration::from_secs(60)),
            move |events| {
                let handler_count_for_handler = Arc::clone(&handler_count_for_handler);
                let sqlx_pool_for_handler = sqlx_pool_for_handler.clone();
                let config_for_handler = config_for_handler.clone();
                async move {
                    assert_eq!(events.len(), 1);
                    assert_eq!(events[0].data().id, 1);
                    handler_count_for_handler.fetch_add(1, Ordering::SeqCst);
                    drop_fleet_test_tables(&sqlx_pool_for_handler, &config_for_handler).await;
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
        .expect_err("cursor advance error after handler success should stop polling");
    assert!(
        matches!(
            err,
            SubscriptionRunError::Fleet(_)
                | SubscriptionRunError::FleetAndPollingGuardRelease { .. }
        ),
        "error = {err:?}"
    );
    assert_eq!(handler_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fleet_subscription_poll_error_policy_is_not_called_for_nontransient_database_error() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("subscription-poll-error-stop").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let handler_count = Arc::new(AtomicUsize::new(0));
    let handler_count_for_handler = Arc::clone(&handler_count);
    let poll_error_count = Arc::new(AtomicUsize::new(0));
    let poll_error_count_for_policy = Arc::clone(&poll_error_count);
    let err = subscription
        .run_polling_until_stopped_or_handler_error_with_poll_error_policy(
            &test_database.paranoid_pool,
            Duration::from_millis(1),
            tokio::time::sleep(Duration::from_secs(60)),
            move |_| {
                let handler_count_for_handler = Arc::clone(&handler_count_for_handler);
                async move {
                    handler_count_for_handler.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestComputeError>(())
                }
            },
            move |error| {
                poll_error_count_for_policy.fetch_add(1, Ordering::SeqCst);
                panic!("nontransient database error should not reach poll-error policy: {error:?}")
            },
        )
        .await
        .expect_err("nontransient database error should stop polling");
    assert!(
        matches!(err, SubscriptionRunError::Fleet(_)),
        "error = {err:?}"
    );
    assert_eq!(poll_error_count.load(Ordering::SeqCst), 0);
    assert_eq!(handler_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fleet_subscription_default_polling_stops_after_nontransient_initial_database_error() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("default-poll-error-nontransient").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let handled_count = Arc::new(AtomicUsize::new(0));
    let handled_count_for_handler = Arc::clone(&handled_count);
    let handle = subscription.start_polling_until_stopped_or_handler_error(
        test_database.paranoid_pool.clone(),
        Duration::from_millis(10),
        move |events| {
            let handled_count_for_handler = Arc::clone(&handled_count_for_handler);
            async move {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].data().id, 1);
                handled_count_for_handler.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        },
    );

    let err = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .expect("subscription handle should stop after nontransient database error")
        .expect_err("nontransient database error should be returned");
    assert!(
        matches!(
            err,
            SubscriptionRunHandleError::Run {
                source: SubscriptionRunError::Fleet(_)
            }
        ),
        "error = {err:?}"
    );
    assert_eq!(handled_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fleet_subscription_background_policy_is_not_called_for_nontransient_database_error() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("background-poll-error-nontransient").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let handled_count = Arc::new(AtomicUsize::new(0));
    let handled_count_for_handler = Arc::clone(&handled_count);
    let poll_error_count = Arc::new(AtomicUsize::new(0));
    let poll_error_count_for_policy = Arc::clone(&poll_error_count);
    let handle = subscription.start_polling_until_stopped_or_handler_error_with_poll_error_policy(
        test_database.paranoid_pool.clone(),
        Duration::from_millis(10),
        move |events| {
            let handled_count_for_handler = Arc::clone(&handled_count_for_handler);
            async move {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].data().id, 1);
                handled_count_for_handler.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TestComputeError>(())
            }
        },
        move |error| {
            poll_error_count_for_policy.fetch_add(1, Ordering::SeqCst);
            panic!("nontransient database error should not reach poll-error policy: {error:?}")
        },
    );

    let err = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .expect("subscription handle should stop after nontransient database error")
        .expect_err("nontransient database error should be returned");
    assert!(
        matches!(
            err,
            SubscriptionRunHandleError::Run {
                source: SubscriptionRunError::Fleet(_)
            }
        ),
        "error = {err:?}"
    );
    assert_eq!(poll_error_count.load(Ordering::SeqCst), 0);
    assert_eq!(handled_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fleet_subscription_start_handle_reports_handler_error_without_advancing_cursor() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("subscription-handle-error").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish");

    let handle = subscription.start_polling_until_stopped_or_handler_error(
        test_database.paranoid_pool.clone(),
        Duration::from_millis(1),
        |events| async move {
            assert_eq!(events.len(), 1);
            Err::<(), _>(TestComputeError("subscription handle failed"))
        },
    );
    let err = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .expect("subscription handle should stop after handler error")
        .expect_err("handler error should be returned");
    assert!(
        matches!(
            err,
            SubscriptionRunHandleError::Run {
                source: SubscriptionRunError::Handler {
                    source: TestComputeError("subscription handle failed")
                }
            }
        ),
        "error = {err:?}"
    );
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor should not advance after handler error"),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_start_handle_handler_panic_does_not_advance_cursor() {
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    async fn panic_subscription_handler(
        _: Vec<TopicEvent<TestEvent>>,
    ) -> Result<(), TestComputeError> {
        panic!("subscription handler panic")
    }

    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("subscription-handler-panic").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish");

    let handle = subscription.start_polling_until_stopped_or_handler_error(
        test_database.paranoid_pool.clone(),
        Duration::from_millis(1),
        panic_subscription_handler,
    );
    let err = tokio::time::timeout(Duration::from_secs(2), handle.wait())
        .await
        .expect("subscription handle should stop after handler panic")
        .expect_err("handler panic should be returned as a join error");
    match err {
        SubscriptionRunHandleError::Join { source } => assert!(source.is_panic()),
        other => panic!("error = {other:?}, want panic join error"),
    }
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor should not advance after handler panic"),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_polling_loop_stops_before_first_database_poll() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("stop-before-first-poll").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;

    let handler_count = Arc::new(AtomicUsize::new(0));
    let handler_count_for_handler = Arc::clone(&handler_count);
    subscription
        .run_polling_until_stopped_or_handler_error(
            &test_database.paranoid_pool,
            Duration::from_millis(10),
            std::future::ready(()),
            move |_| {
                let handler_count_for_handler = Arc::clone(&handler_count_for_handler);
                async move {
                    handler_count_for_handler.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
        .expect("already-stopped polling loop should return cleanly");
    assert_eq!(handler_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fleet_subscription_polling_loop_stops_during_poll_error_backoff() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };
    let timeout_database_url = direct_test_database_url()
        .or_else(test_database_url)
        .expect("test database URL");
    let timeout_pool =
        connect_paranoid_pool_with_statement_timeout(&timeout_database_url, "50ms").await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic_key = TopicKey::new("stop-during-poll-error-backoff").expect("topic key");
    let subscription_key = SubscriptionKey::new("worker").expect("subscription key");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: topic_key.clone(),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: subscription_key.clone(),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");
    insert_live_subscription_polling_mutex_lease_row(
        &test_database.sqlx_pool,
        &test_database.config,
        &topic_key,
        &subscription_key,
    )
    .await;
    let row_lock_tx = begin_transaction_locking_coordination_row(
        &test_database.sqlx_pool,
        &test_database.config,
        &persisted_subscription_polling_mutex_lease_key(
            &test_database.config,
            &topic_key,
            &subscription_key,
        ),
    )
    .await;

    let handler_count = Arc::new(AtomicUsize::new(0));
    let handler_count_for_handler = Arc::clone(&handler_count);
    let poll_error_count = Arc::new(AtomicUsize::new(0));
    let poll_error_count_for_policy = Arc::clone(&poll_error_count);
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let stop_sender = Arc::new(Mutex::new(Some(stop_sender)));
    let stop_sender_for_policy = Arc::clone(&stop_sender);

    subscription
        .run_polling_until_stopped_or_handler_error_with_poll_error_policy(
            &timeout_pool,
            Duration::from_millis(10),
            async move {
                let _ = stop_receiver.await;
            },
            move |_| {
                let handler_count_for_handler = Arc::clone(&handler_count_for_handler);
                async move {
                    handler_count_for_handler.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestComputeError>(())
                }
            },
            move |error| {
                assert!(
                    is_subscription_statement_timeout_error(error),
                    "error = {error:?}"
                );
                poll_error_count_for_policy.fetch_add(1, Ordering::SeqCst);
                if let Some(stop_sender) = stop_sender_for_policy
                    .lock()
                    .expect("lock stop sender")
                    .take()
                {
                    let _ = stop_sender.send(());
                }
                SubscriptionPollErrorAction::ContinueAfter(Duration::from_secs(60))
            },
        )
        .await
        .expect("polling loop should stop cleanly during poll-error backoff");
    row_lock_tx
        .rollback()
        .await
        .expect("rollback subscription polling mutex row lock transaction");
    assert_eq!(poll_error_count.load(Ordering::SeqCst), 1);
    assert_eq!(handler_count.load(Ordering::SeqCst), 0);
    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_polling_loop_reuses_loaded_cursor_between_successful_polls() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("reuse-loaded-cursor").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: Some(10),
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish first event");

    let handled_batches = Arc::new(Mutex::new(Vec::<Vec<i64>>::new()));
    let handled_batches_for_handler = Arc::clone(&handled_batches);
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let stop_sender = Arc::new(Mutex::new(Some(stop_sender)));
    let stop_sender_for_handler = Arc::clone(&stop_sender);
    let run_pool = test_database.paranoid_pool.clone();
    let run_subscription = subscription.clone();

    let run_handle = tokio::spawn(async move {
        run_subscription
            .run_polling_until_stopped_or_handler_error(
                &run_pool,
                Duration::from_millis(25),
                async move {
                    let _ = stop_receiver.await;
                },
                move |events| {
                    let handled_batches_for_handler = Arc::clone(&handled_batches_for_handler);
                    let stop_sender_for_handler = Arc::clone(&stop_sender_for_handler);
                    async move {
                        let sequences = events.iter().map(TopicEvent::sequence).collect::<Vec<_>>();
                        if sequences.contains(&2)
                            && let Some(stop_sender) = stop_sender_for_handler
                                .lock()
                                .expect("lock stop sender")
                                .take()
                        {
                            let _ = stop_sender.send(());
                        }
                        handled_batches_for_handler
                            .lock()
                            .expect("lock handled batches")
                            .push(sequences);
                        Ok::<_, TestComputeError>(())
                    }
                },
            )
            .await
    });

    wait_until(
        "subscription cursor advanced to first event",
        Duration::from_secs(2),
        || {
            let subscription = subscription.clone();
            let pool = test_database.paranoid_pool.clone();
            async move { matches!(subscription.fetch_cursor(&pool).await, Ok(1)) }
        },
    )
    .await;

    subscription
        .delete_cursor(&test_database.paranoid_pool)
        .await
        .expect("delete cursor after loop cached it");
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor absent after explicit delete"),
        0
    );

    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 2 })
        .await
        .expect("publish second event");

    tokio::time::timeout(Duration::from_secs(2), run_handle)
        .await
        .expect("polling loop should stop after second event")
        .expect("polling task should not panic")
        .expect("polling loop should stop cleanly");

    assert_eq!(
        handled_batches
            .lock()
            .expect("lock handled batches")
            .as_slice(),
        &[vec![1], vec![2]]
    );
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after second event"),
        2
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
