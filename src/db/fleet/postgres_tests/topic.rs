use super::*;

#[tokio::test]
async fn fleet_topic_publish_subscribe_and_cursor_persistence() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
        message: String,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("notifications").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("worker").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    assert_eq!(subscription.poll_limit(), DEFAULT_SUBSCRIPTION_POLL_LIMIT);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(
        topic
            .fetch_latest_sequence(&test_database.paranoid_pool)
            .await
            .expect("fetch initial sequence"),
        0
    );

    let first_sequence = topic
        .publish(
            &test_database.paranoid_pool,
            TestEvent {
                id: 1,
                message: "hello".to_owned(),
            },
        )
        .await
        .expect("publish first event");
    let second_sequence = topic
        .publish(
            &test_database.paranoid_pool,
            TestEvent {
                id: 2,
                message: "world".to_owned(),
            },
        )
        .await
        .expect("publish second event");

    assert_eq!(first_sequence, 1);
    assert_eq!(second_sequence, 2);
    assert_eq!(
        topic
            .fetch_latest_sequence(&test_database.paranoid_pool)
            .await
            .expect("fetch latest sequence"),
        2
    );

    let events = subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("poll events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence(), 1);
    assert_eq!(events[0].data().message, "hello");
    assert_eq!(events[1].sequence(), 2);
    assert_eq!(events[1].data().message, "world");
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("fetch cursor"),
        2
    );

    let empty_events = subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("poll again");
    assert!(empty_events.is_empty());

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_topic_multiple_subscribers_and_fetch_events_after_are_independent() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        value: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("fanout").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let first_subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("first").expect("subscription key"),
            poll_limit: None,
        })
        .expect("first subscription");
    let second_subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("second").expect("subscription key"),
            poll_limit: None,
        })
        .expect("second subscription");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { value: 10 })
        .await
        .expect("publish first");
    assert_eq!(
        first_subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("first poll")
            .len(),
        1
    );

    topic
        .publish(&test_database.paranoid_pool, TestEvent { value: 20 })
        .await
        .expect("publish second");
    let first_events = first_subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("first catches up");
    let second_events = second_subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("second catches up");

    assert_eq!(first_events.len(), 1);
    assert_eq!(first_events[0].data().value, 20);
    assert_eq!(second_events.len(), 2);
    assert_eq!(second_events[0].data().value, 10);
    assert_eq!(second_events[1].data().value, 20);

    let after_first = second_subscription
        .fetch_events_after(&test_database.paranoid_pool, 1)
        .await
        .expect("get events after");
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].sequence(), 2);
    assert_eq!(
        second_subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor unchanged by fetch_events_after"),
        2
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_set_delete_cursor_and_default_poll_limit() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("cursor-management").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("default-limit").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let event_count = DEFAULT_SUBSCRIPTION_POLL_LIMIT + 5;
    for id in 1..=event_count {
        topic
            .publish(&test_database.paranoid_pool, TestEvent { id })
            .await
            .expect("publish event");
    }

    subscription
        .set_cursor(&test_database.paranoid_pool, 5)
        .await
        .expect("set cursor");
    let events_after_set_cursor = subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("poll after set cursor");
    assert_eq!(
        events_after_set_cursor.len(),
        usize::try_from(DEFAULT_SUBSCRIPTION_POLL_LIMIT).expect("poll limit fits usize")
    );
    assert_eq!(events_after_set_cursor[0].sequence(), 6);
    assert_eq!(events_after_set_cursor[0].data().id, 6);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after limited poll"),
        i64::from(5 + DEFAULT_SUBSCRIPTION_POLL_LIMIT)
    );

    subscription
        .delete_cursor(&test_database.paranoid_pool)
        .await
        .expect("delete cursor");
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after delete"),
        0
    );
    assert_eq!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("default-limited poll after cursor delete")
            .len(),
        usize::try_from(DEFAULT_SUBSCRIPTION_POLL_LIMIT).expect("poll limit fits usize")
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_topic_event_ttl_and_purge_do_not_reset_sequence() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        value: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("retention").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(1)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("late").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent { value: 1 })
        .await
        .expect("publish expiring event");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("poll expired event")
            .is_empty()
    );

    topic
        .publish(&test_database.paranoid_pool, TestEvent { value: 2 })
        .await
        .expect("publish retained event");
    assert_eq!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("poll retained event")[0]
            .data()
            .value,
        2
    );

    let deleted = topic
        .purge_retained_events_atomically(&test_database.paranoid_pool)
        .await
        .expect("purge events");
    assert_eq!(deleted, 2);
    subscription
        .delete_cursor(&test_database.paranoid_pool)
        .await
        .expect("delete cursor");
    assert!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("poll after purge")
            .is_empty()
    );

    let next_sequence = topic
        .publish(&test_database.paranoid_pool, TestEvent { value: 3 })
        .await
        .expect("publish after purge");
    assert_eq!(next_sequence, 3);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_poll_limit_and_sequence_validation() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("limited").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("batch").expect("subscription key"),
            poll_limit: Some(10),
        })
        .expect("subscribe");

    assert!(matches!(
        topic.subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("bad-zero").expect("subscription key"),
            poll_limit: Some(0),
        }),
        Err(Error::InvalidSubscriptionPollLimit { .. })
    ));
    assert!(matches!(
        topic.subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("bad-large").expect("subscription key"),
            poll_limit: Some(MAX_SUBSCRIPTION_POLL_LIMIT + 1),
        }),
        Err(Error::InvalidSubscriptionPollLimit { .. })
    ));

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    for _ in 0..25 {
        topic
            .publish(&test_database.paranoid_pool, TestEvent)
            .await
            .expect("publish");
    }

    assert_eq!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("first limited poll")
            .len(),
        10
    );
    assert_eq!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await
            .expect("second limited poll")
            .len(),
        10
    );
    assert!(matches!(
        subscription
            .fetch_events_after(&test_database.paranoid_pool, -1)
            .await,
        Err(Error::TopicSequenceMustBeNonNegative)
    ));
    assert!(matches!(
        subscription
            .set_cursor(&test_database.paranoid_pool, -1)
            .await,
        Err(Error::TopicSequenceMustBeNonNegative)
    ));
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor unchanged after rejected negative sequence"),
        20
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_topic_publish_rolls_back_sequence_when_event_serialization_fails() {
    #[derive(Clone, Debug, Deserialize)]
    struct FailingSerializeEvent;

    impl Serialize for FailingSerializeEvent {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom(
                "forced topic event serialization failure",
            ))
        }
    }

    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<FailingSerializeEvent>(TopicConfig {
            key: TopicKey::new("serialize-error").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let err = topic
        .publish(&test_database.paranoid_pool, FailingSerializeEvent)
        .await
        .expect_err("publish should return serialization error");
    assert!(
        matches!(err, Error::Kv(KvError::Codec(_))),
        "error = {err:?}"
    );
    assert_eq!(
        topic
            .fetch_latest_sequence(&test_database.paranoid_pool)
            .await
            .expect("sequence mutation should roll back with failed event serialization"),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_topic_publish_rejects_incompatible_persisted_sequence_state() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic_key = TopicKey::new("corrupt-sequence").expect("topic key");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: topic_key.clone(),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    topic
        .publish(&test_database.paranoid_pool, TestEvent)
        .await
        .expect("publish before corrupting sequence state");
    RawKvStore::new(
        KvStoreConfig::new(test_database.config.state_table_name.clone()).expect("kv config"),
    )
    .expect("kv store")
    .set_bytes(
        &test_database.paranoid_pool,
        &persisted_topic_sequence_key(&test_database.config, &topic_key),
        &[0xff],
        KvTtl::no_expiration(),
    )
    .await
    .expect("corrupt topic sequence state");

    let err = topic
        .publish(&test_database.paranoid_pool, TestEvent)
        .await
        .expect_err("publish should reject incompatible sequence state");
    assert!(
        matches!(err, Error::Kv(KvError::Codec(_))),
        "error = {err:?}"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_read_new_events_and_advance_cursor_in_current_transaction_returns_event_scan_error()
 {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic_key = TopicKey::new("transactional-event-scan-error").expect("topic key");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: topic_key.clone(),
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
        .publish(&test_database.paranoid_pool, TestEvent)
        .await
        .expect("publish before corrupting event");
    RawKvStore::new(
        KvStoreConfig::new(test_database.config.state_table_name.clone()).expect("kv config"),
    )
    .expect("kv store")
    .set_bytes(
        &test_database.paranoid_pool,
        &persisted_topic_event_key(&test_database.config, &topic_key, 1),
        &[0xff],
        KvTtl::no_expiration(),
    )
    .await
    .expect("corrupt event payload");

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin poll transaction");
    let err = subscription
        .read_new_events_and_advance_cursor_in_current_transaction(&mut tx)
        .await
        .expect_err("transactional poll should return event scan decode error");
    assert!(
        matches!(err, Error::Kv(KvError::Codec(_))),
        "error = {err:?}"
    );
    tx.rollback().await.expect("rollback poll transaction");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_read_new_events_and_advance_cursor_in_current_transaction_returns_cursor_advance_error()
 {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic_key = TopicKey::new("transactional-cursor-advance-error").expect("topic key");
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

    topic
        .publish(&test_database.paranoid_pool, TestEvent)
        .await
        .expect("publish before installing cursor write failure");
    let cursor_key =
        persisted_subscription_cursor_key(&test_database.config, &topic_key, &subscription_key);
    let failure_function = install_write_failure_trigger_on_kv_key(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
        &cursor_key,
    )
    .await;

    let mut tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin poll transaction");
    let err = subscription
        .read_new_events_and_advance_cursor_in_current_transaction(&mut tx)
        .await
        .expect_err("transactional poll should return cursor advance error");
    assert!(
        matches!(err, Error::Kv(KvError::Database(_))),
        "error = {err:?}"
    );
    tx.rollback()
        .await
        .expect("rollback failed cursor advance transaction");
    drop_test_function_cascade(&test_database.sqlx_pool, &failure_function).await;
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor write should not partially succeed"),
        0
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_rejects_corrupted_negative_persisted_cursor() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic_key = TopicKey::new("negative-cursor").expect("topic key");
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

    set_subscription_cursor_directly(
        &test_database.paranoid_pool,
        &test_database.config,
        &topic_key,
        &subscription_key,
        -1,
    )
    .await;

    assert!(matches!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await,
        Err(Error::TopicSequenceMustBeNonNegative)
    ));
    assert!(matches!(
        subscription
            .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
            .await,
        Err(Error::TopicSequenceMustBeNonNegative)
    ));

    let handler_count = Arc::new(AtomicUsize::new(0));
    let handler_count_for_handler = Arc::clone(&handler_count);
    let err = subscription
        .run_polling_until_stopped_or_handler_error(
            &test_database.paranoid_pool,
            Duration::from_millis(10),
            tokio::time::sleep(Duration::from_secs(60)),
            move |_| {
                let handler_count_for_handler = Arc::clone(&handler_count_for_handler);
                async move {
                    handler_count_for_handler.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestComputeError>(())
                }
            },
        )
        .await
        .expect_err("polling loop should reject corrupted negative cursor");
    assert!(
        matches!(
            err,
            SubscriptionRunError::Fleet(Error::TopicSequenceMustBeNonNegative)
        ),
        "error = {err:?}"
    );
    assert_eq!(handler_count.load(Ordering::SeqCst), 0);

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
