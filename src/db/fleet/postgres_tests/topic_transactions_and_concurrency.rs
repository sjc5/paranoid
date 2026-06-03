use super::*;

#[tokio::test]
async fn fleet_topic_transactional_publish_and_poll_respect_commit_boundaries() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("transactional").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("reader").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    topic
        .publish_in_current_transaction(&mut rollback_tx, TestEvent { id: 1 })
        .await
        .expect("publish inside rollback transaction");
    assert_eq!(
        topic
            .fetch_latest_sequence_in_current_transaction(&mut rollback_tx)
            .await
            .expect("fetch sequence inside rollback transaction"),
        1
    );
    rollback_tx.rollback().await.expect("rollback");
    assert_eq!(
        topic
            .fetch_latest_sequence(&test_database.paranoid_pool)
            .await
            .expect("fetch after rollback"),
        0
    );

    let mut publish_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin publish transaction");
    topic
        .publish_in_current_transaction(&mut publish_tx, TestEvent { id: 2 })
        .await
        .expect("publish first committed event");
    topic
        .publish_in_current_transaction(&mut publish_tx, TestEvent { id: 3 })
        .await
        .expect("publish second committed event");
    publish_tx.commit().await.expect("commit published events");

    let mut poll_rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin poll rollback transaction");
    assert_eq!(
        subscription
            .read_new_events_and_advance_cursor_in_current_transaction(&mut poll_rollback_tx)
            .await
            .expect("poll inside rollback transaction")
            .len(),
        2
    );
    poll_rollback_tx.rollback().await.expect("rollback poll");
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after poll rollback"),
        0
    );

    let mut poll_commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin poll commit transaction");
    let events = subscription
        .read_new_events_and_advance_cursor_in_current_transaction(&mut poll_commit_tx)
        .await
        .expect("poll inside commit transaction");
    poll_commit_tx.commit().await.expect("commit poll");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].data().id, 2);
    assert_eq!(events[1].data().id, 3);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after poll commit"),
        2
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_subscription_pool_read_and_advance_rolls_back_when_cancelled_during_cursor_advance()
{
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        id: u32,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic_key = TopicKey::new("cancelled-pool-poll").expect("topic key");
    let subscription_key = SubscriptionKey::new("reader").expect("subscription key");
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

    subscription
        .set_cursor(&test_database.paranoid_pool, 0)
        .await
        .expect("create cursor row to lock");
    topic
        .publish(&test_database.paranoid_pool, TestEvent { id: 1 })
        .await
        .expect("publish event");
    let cursor_key =
        persisted_subscription_cursor_key(&test_database.config, &topic_key, &subscription_key);
    let row_lock_transaction = begin_transaction_locking_raw_kv_row(
        &test_database.sqlx_pool,
        &test_database.config.state_table_name,
        &cursor_key,
    )
    .await;

    tokio::time::timeout(
        Duration::from_millis(200),
        subscription.read_new_events_and_advance_cursor(&test_database.paranoid_pool),
    )
    .await
    .expect_err("blocked read-and-advance future should be cancellable");

    row_lock_transaction
        .rollback()
        .await
        .expect("rollback subscription cursor row lock transaction");
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after cancelled read-and-advance"),
        0,
        "cancelled pool-owned read-and-advance must not commit cursor movement"
    );

    let events = subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("retry read-and-advance after cancellation");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence(), 1);
    assert_eq!(events[0].data().id, 1);
    assert_eq!(
        subscription
            .fetch_cursor(&test_database.paranoid_pool)
            .await
            .expect("cursor after retry read-and-advance"),
        1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_topic_concurrent_publish_sequences_are_unique_and_gapless() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent {
        publisher: usize,
        index: usize,
    }

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = Arc::new(
        store
            .new_topic::<TestEvent>(TopicConfig {
                key: TopicKey::new("concurrent-publish").expect("topic key"),
                event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
            })
            .expect("new topic"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let publisher_count = 8;
    let events_per_publisher = 6;
    let barrier = Arc::new(Barrier::new(publisher_count));
    let mut handles = Vec::with_capacity(publisher_count);

    for publisher in 0..publisher_count {
        let topic = Arc::clone(&topic);
        let pool = test_database.paranoid_pool.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut sequences = Vec::with_capacity(events_per_publisher);
            for index in 0..events_per_publisher {
                let sequence = topic
                    .publish(&pool, TestEvent { publisher, index })
                    .await
                    .expect("publish concurrently");
                sequences.push(sequence);
            }
            sequences
        }));
    }

    let mut all_sequences = Vec::with_capacity(publisher_count * events_per_publisher);
    for handle in handles {
        all_sequences.extend(handle.await.expect("join publisher"));
    }
    all_sequences.sort_unstable();

    let expected_count = publisher_count * events_per_publisher;
    let expected_sequences =
        (1..=i64::try_from(expected_count).expect("count fits i64")).collect::<Vec<_>>();
    assert_eq!(all_sequences, expected_sequences);
    assert_eq!(
        topic
            .fetch_latest_sequence(&test_database.paranoid_pool)
            .await
            .expect("fetch latest sequence"),
        i64::try_from(expected_count).expect("count fits i64")
    );

    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("collector").expect("subscription key"),
            poll_limit: Some(100),
        })
        .expect("subscribe collector");
    let events = subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("poll all events");
    assert_eq!(events.len(), expected_count);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(
            event.sequence(),
            i64::try_from(index + 1).expect("sequence fits i64")
        );
    }

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_topic_events_expose_database_publication_timestamp() {
    let test_database = TestDatabase::connect().await;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct TestEvent;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let topic = store
        .new_topic::<TestEvent>(TopicConfig {
            key: TopicKey::new("timestamps").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("event ttl"),
        })
        .expect("new topic");
    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("reader").expect("subscription key"),
            poll_limit: None,
        })
        .expect("subscribe");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let before = unix_microseconds_now();
    topic
        .publish(&test_database.paranoid_pool, TestEvent)
        .await
        .expect("publish timestamped event");
    let after = unix_microseconds_now();

    let events = subscription
        .read_new_events_and_advance_cursor(&test_database.paranoid_pool)
        .await
        .expect("poll event");
    assert_eq!(events.len(), 1);
    assert!(
        events[0].published_at_unix_microseconds() >= before - 1_000_000,
        "published timestamp should not be far before publish call"
    );
    assert!(
        events[0].published_at_unix_microseconds() <= after + 1_000_000,
        "published timestamp should not be far after publish call"
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
