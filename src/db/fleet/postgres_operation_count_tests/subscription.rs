use super::*;

#[tokio::test]
async fn fleet_subscription_polling_loop_emits_expected_database_operation_records() {
    let database_url = test_database_url();

    let observed = prepare_observed_fleet_store(&database_url).await;
    let store = observed.store.clone();
    let observer = observed.observer.clone();
    let observed_pool = observed.observed_pool.clone();

    let topic = store
        .new_topic::<CachePayload>(TopicConfig {
            key: TopicKey::new("operation-count-topic-loop").expect("topic key"),
            event_ttl: KvTtl::expires_after(Duration::from_secs(60)).expect("topic event ttl"),
        })
        .expect("topic");
    topic
        .publish(&observed.observed_pool, CachePayload { value: 777 })
        .await
        .expect("publish event before observed polling loop");
    observer.clear();

    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("operation-count-subscription-loop")
                .expect("subscription key"),
            poll_limit: Some(10),
        })
        .expect("subscription");
    let handler_started = Arc::new(Notify::new());
    let handler_finish = Arc::new(Notify::new());
    let stop = Arc::new(Notify::new());
    let subscription_for_run = subscription.clone();
    let pool_for_run = observed_pool.clone();
    let handler_started_for_run = Arc::clone(&handler_started);
    let handler_finish_for_run = Arc::clone(&handler_finish);
    let stop_for_run = Arc::clone(&stop);
    let run_task = tokio::spawn(async move {
        subscription_for_run
            .run_polling_until_stopped_or_handler_error(
                &pool_for_run,
                Duration::from_secs(60),
                async move {
                    stop_for_run.notified().await;
                },
                move |events| {
                    let handler_started_for_run = Arc::clone(&handler_started_for_run);
                    let handler_finish_for_run = Arc::clone(&handler_finish_for_run);
                    async move {
                        assert_eq!(events.len(), 1);
                        assert_eq!(events[0].sequence(), 1);
                        assert_eq!(events[0].data(), &CachePayload { value: 777 });
                        handler_started_for_run.notify_one();
                        handler_finish_for_run.notified().await;
                        Ok::<_, std::io::Error>(())
                    }
                },
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), handler_started.notified())
        .await
        .expect("subscription handler should receive event");
    stop.notify_one();
    handler_finish.notify_one();
    run_task
        .await
        .expect("subscription run task should join")
        .expect("subscription polling loop should stop cleanly");

    expect_operation_shapes(
        &observer,
        &[
            transaction_shapes([(DatabaseOperationKind::FetchOptional, LEASE_OPERATION_CLAIM)]),
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchOptional,
                KV_OPERATION_GET_BYTES,
            )]),
            rollback_transaction_shapes([(
                DatabaseOperationKind::FetchAll,
                KV_OPERATION_SCAN_BYTES_WITH_PREFIX,
            )]),
            transaction_shapes([
                (
                    DatabaseOperationKind::FetchOptional,
                    KV_OPERATION_LOCK_KEY_FOR_ATOMIC_MUTATION,
                ),
                (
                    DatabaseOperationKind::Execute,
                    KV_OPERATION_SET_BYTES_FOR_ATOMIC_MUTATION,
                ),
            ]),
            transaction_shapes([(DatabaseOperationKind::Execute, LEASE_OPERATION_RELEASE)]),
        ]
        .concat(),
    );

    observed.drop_tables().await;
}
