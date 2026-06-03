use super::*;

pub(super) async fn exercise_fleet_public_db_handle_surface(pool: &WritePool, store: &FleetStore) {
    let read_pool: &crate::db::Pool = pool;
    let ttl = KvTtl::no_expiration();
    let claim_duration = ClaimDuration::expires_after(Duration::from_secs(30)).expect("claim");
    let holder_id = HolderId::new("marker_holder").expect("holder");
    let guard_config = MutexGuardConfig {
        heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
        acquire_retry_interval: Some(Duration::from_millis(10)),
        max_acquire_retry_interval: Some(Duration::from_millis(20)),
        max_consecutive_renewal_failures: Some(1),
    };

    store
        .validate_schema(read_pool)
        .await
        .expect("Fleet validate_schema should only require SELECT");
    let mut read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin Fleet read tx");
    store
        .validate_schema_in_current_transaction(&mut read_tx)
        .await
        .expect("Fleet tx validate_schema should only require SELECT");
    read_tx.rollback().await.expect("rollback Fleet read tx");

    let counter = store
        .new_counter(CounterKey::new("marker_counter").expect("counter key"))
        .expect("counter");
    counter
        .fetch_value(read_pool)
        .await
        .expect("Fleet counter fetch should only require SELECT");
    let mut counter_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin counter read tx");
    counter
        .fetch_value_in_current_transaction(&mut counter_read_tx)
        .await
        .expect("Fleet counter tx fetch should only require SELECT");
    counter_read_tx
        .rollback()
        .await
        .expect("rollback counter read tx");

    let mutex = store
        .new_mutex(
            MutexKey::new("marker_mutex").expect("mutex key"),
            claim_duration,
        )
        .expect("mutex");
    mutex
        .fetch_live_holder(read_pool)
        .await
        .expect("Fleet mutex holder fetch should only require SELECT");
    let mut mutex_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin mutex read tx");
    mutex
        .fetch_live_holder_in_current_transaction(&mut mutex_read_tx)
        .await
        .expect("Fleet mutex tx holder fetch should only require SELECT");
    mutex_read_tx
        .rollback()
        .await
        .expect("rollback mutex read tx");

    let cron = store
        .new_cron(CronConfig {
            key: CronKey::new("marker_cron").expect("cron key"),
            interval: MIN_CRON_INTERVAL,
            claim_duration: Some(claim_duration),
            heartbeat_interval: Some(MIN_MUTEX_HEARTBEAT_INTERVAL),
            acquire_retry_interval: Some(Duration::from_millis(10)),
            max_consecutive_renewal_failures: Some(1),
        })
        .expect("cron");
    cron.fetch_live_leader(read_pool)
        .await
        .expect("Fleet cron leader fetch should only require SELECT");

    let semaphore = store
        .new_semaphore(
            SemaphoreKey::new("marker_semaphore").expect("semaphore key"),
            2,
            Duration::from_secs(30),
        )
        .expect("semaphore");
    semaphore
        .fetch_status(read_pool)
        .await
        .expect("Fleet semaphore status fetch should only require SELECT");
    let mut semaphore_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin semaphore read tx");
    semaphore
        .fetch_status_in_current_transaction(&mut semaphore_read_tx)
        .await
        .expect("Fleet semaphore tx status fetch should only require SELECT");
    semaphore_read_tx
        .rollback()
        .await
        .expect("rollback semaphore read tx");

    let throttler = store
        .new_throttler(ThrottlerConfig {
            key: ThrottlerKey::new("marker_throttler").expect("throttler key"),
            rate_limit: Some(ThrottlerRateLimit {
                requests_per_interval: 10,
                interval: Duration::from_secs(60),
            }),
            concurrency_limit: Some(ThrottlerConcurrencyLimit {
                max_concurrent: 2,
                max_hold_duration: Some(Duration::from_secs(30)),
            }),
            circuit_breaker: Some(ThrottlerCircuitBreaker {
                failure_threshold: 2,
                recovery_timeout: Duration::from_secs(30),
            }),
        })
        .expect("throttler");
    throttler
        .fetch_status(read_pool)
        .await
        .expect("Fleet throttler status fetch should only require SELECT");
    let mut throttler_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin throttler read tx");
    throttler
        .fetch_status_in_current_transaction(&mut throttler_read_tx)
        .await
        .expect("Fleet throttler tx status fetch should only require SELECT");
    throttler_read_tx
        .rollback()
        .await
        .expect("rollback throttler read tx");

    let rate_limiter = store
        .new_rate_limiter(
            RateLimiterKey::new("marker_rate_limiter").expect("rate limiter key"),
            RateLimitConfig {
                requests_per_interval: 10,
                interval: Duration::from_secs(60),
            },
        )
        .expect("rate limiter");
    rate_limiter
        .fetch_status(read_pool)
        .await
        .expect("Fleet rate limiter status fetch should only require SELECT");

    let circuit_breaker = store
        .new_circuit_breaker(
            CircuitBreakerKey::new("marker_circuit_breaker").expect("circuit breaker key"),
            CircuitBreakerConfig {
                failure_threshold: 2,
                recovery_timeout: Duration::from_secs(30),
            },
        )
        .expect("circuit breaker");
    circuit_breaker
        .fetch_status(read_pool)
        .await
        .expect("Fleet circuit breaker status fetch should only require SELECT");

    let once = store
        .new_once(
            OnceKey::new("marker_once").expect("once key"),
            claim_duration,
        )
        .expect("once");
    once.check_done(read_pool)
        .await
        .expect("Fleet once check_done should only require SELECT");
    let mut once_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin once read tx");
    once.check_done_in_current_transaction(&mut once_read_tx)
        .await
        .expect("Fleet once tx check_done should only require SELECT");
    once_read_tx
        .rollback()
        .await
        .expect("rollback once read tx");

    let cache = store
        .new_coalescing_cache::<TestPayload>(CoalescingCacheConfig {
            key: CoalescingCacheKey::new("marker_cache").expect("cache key"),
            value_ttl: ttl,
            lock_wait_timeout: Some(Duration::from_millis(100)),
            compute_timeout: Some(Duration::from_millis(100)),
        })
        .expect("cache");

    let topic = store
        .new_topic::<TestPayload>(TopicConfig {
            key: TopicKey::new("marker_topic").expect("topic key"),
            event_ttl: ttl,
        })
        .expect("topic");
    topic
        .fetch_latest_sequence(read_pool)
        .await
        .expect("Fleet topic latest sequence should only require SELECT");
    let mut topic_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin topic read tx");
    topic
        .fetch_latest_sequence_in_current_transaction(&mut topic_read_tx)
        .await
        .expect("Fleet topic tx latest sequence should only require SELECT");
    topic_read_tx
        .rollback()
        .await
        .expect("rollback topic read tx");

    let subscription = topic
        .subscribe(SubscriptionConfig {
            key: SubscriptionKey::new("marker_subscription").expect("subscription key"),
            poll_limit: Some(10),
        })
        .expect("subscription");
    subscription
        .fetch_events_after(read_pool, 0)
        .await
        .expect("Fleet subscription event fetch should only require SELECT");
    subscription
        .fetch_cursor(read_pool)
        .await
        .expect("Fleet subscription cursor fetch should only require SELECT");
    let mut subscription_read_tx = read_pool
        .begin_transaction()
        .await
        .expect("begin subscription read tx");
    subscription
        .fetch_events_after_in_current_transaction(&mut subscription_read_tx, 0)
        .await
        .expect("Fleet subscription tx event fetch should only require SELECT");
    subscription
        .fetch_cursor_in_current_transaction(&mut subscription_read_tx)
        .await
        .expect("Fleet subscription tx cursor fetch should only require SELECT");
    subscription_read_tx
        .rollback()
        .await
        .expect("rollback subscription read tx");

    assert_fails_with_insufficient_privilege!(
        "Fleet migrate_schema",
        store.migrate_schema(pool),
        db_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet migrate_schema_in_current_transaction",
        tx,
        store.migrate_schema_in_current_transaction(tx),
        db_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet counter add",
        counter.add(pool, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet counter add_in_current_transaction",
        tx,
        counter.add_in_current_transaction(tx, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet counter set_value",
        counter.set_value(pool, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet counter set_value_in_current_transaction",
        tx,
        counter.set_value_in_current_transaction(tx, 1),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_claim_guard",
        mutex.try_claim_guard(pool, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_claim_guard_for_holder",
        mutex.try_claim_guard_for_holder(pool, &holder_id, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex claim_guard_when_available",
        mutex.claim_guard_when_available(pool, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex claim_guard_for_holder_when_available",
        mutex.claim_guard_for_holder_when_available(pool, &holder_id, guard_config),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_run_task",
        mutex.try_run_task::<_, TestTaskError, _, _>(pool, guard_config, |_snapshot| async {
            Ok::<_, TestTaskError>(())
        }),
        mutex_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex try_run_task_for_holder",
        mutex.try_run_task_for_holder::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            guard_config,
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        mutex_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex run_task_when_available",
        mutex.run_task_when_available::<_, TestTaskError, _, _>(
            pool,
            guard_config,
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        mutex_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet mutex run_task_for_holder_when_available",
        mutex.run_task_for_holder_when_available::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            guard_config,
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        mutex_run_error_is_insufficient_privilege
    );

    let mutex_protocol = mutex.begin_manual_renewal_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual mutex try_claim",
        mutex_protocol.try_claim(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual mutex try_claim_in_current_transaction",
        tx,
        mutex_protocol.try_claim_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual mutex try_claim_for_holder",
        mutex_protocol.try_claim_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual mutex try_claim_for_holder_in_current_transaction",
        tx,
        mutex_protocol.try_claim_for_holder_in_current_transaction(tx, &holder_id),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet cron try_run_once",
        cron.try_run_once::<_, TestTaskError, _, _>(pool, |_snapshot| async {
            Ok::<_, TestTaskError>(())
        }),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_once",
        cron.run_once::<_, TestTaskError, _, _>(pool, |_snapshot| async {
            Ok::<_, TestTaskError>(())
        }),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_until_stopped_or_task_error",
        cron.run_until_stopped_or_task_error::<_, TestTaskError, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_until_stopped_with_task_error_policy",
        cron.run_until_stopped_with_task_error_policy::<_, TestTaskError, _, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_continuously_until_stopped_or_task_error",
        cron.run_continuously_until_stopped_or_task_error::<_, TestTaskError, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) }
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cron run_continuously_until_stopped_with_task_error_policy",
        cron.run_continuously_until_stopped_with_task_error_policy::<_, TestTaskError, _, _, _>(
            pool,
            std::future::pending::<()>(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop
        ),
        cron_run_error_is_insufficient_privilege
    );
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_until_stopped_or_task_error",
        cron.start_until_stopped_or_task_error::<TestTaskError, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
        ),
    )
    .await;
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_until_stopped_with_task_error_policy",
        cron.start_until_stopped_with_task_error_policy::<TestTaskError, _, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop,
        ),
    )
    .await;
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_continuously_until_stopped_or_task_error",
        cron.start_continuously_until_stopped_or_task_error::<TestTaskError, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
        ),
    )
    .await;
    assert_cron_handle_fails_with_insufficient_privilege(
        "Fleet cron start_continuously_until_stopped_with_task_error_policy",
        cron.start_continuously_until_stopped_with_task_error_policy::<TestTaskError, _, _, _>(
            pool.clone(),
            |_snapshot| async { Ok::<_, TestTaskError>(()) },
            |_error| CronTaskErrorAction::Stop,
        ),
    )
    .await;

    assert_fails_with_insufficient_privilege!(
        "Fleet cache fetch_or_compute",
        cache.fetch_or_compute::<_, _, TestTaskError, _, _>(pool, ["missing"], || async {
            Ok::<_, TestTaskError>(TestPayload { value: 1 })
        }),
        coalescing_cache_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cache set",
        cache.set(pool, ["missing"], TestPayload { value: 1 }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cache invalidate",
        cache.invalidate(pool, ["missing"]),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet cache invalidate_all",
        cache.invalidate_all(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet cache invalidate_all_in_current_transaction",
        tx,
        cache.invalidate_all_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet topic publish",
        topic.publish(pool, TestPayload { value: 1 }),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet topic publish_in_current_transaction",
        tx,
        topic.publish_in_current_transaction(tx, TestPayload { value: 1 }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet topic purge_retained_events_atomically",
        topic.purge_retained_events_atomically(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet topic purge_retained_events_in_current_transaction",
        tx,
        topic.purge_retained_events_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription read_new_events_and_advance_cursor",
        subscription.read_new_events_and_advance_cursor(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet subscription read_new_events_and_advance_cursor_in_current_transaction",
        tx,
        subscription.read_new_events_and_advance_cursor_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription run_polling_until_stopped_or_handler_error",
        subscription.run_polling_until_stopped_or_handler_error::<_, TestTaskError, _, _>(
            pool,
            Duration::from_millis(10),
            std::future::pending::<()>(),
            |_event| async { Ok::<_, TestTaskError>(()) }
        ),
        subscription_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription run_polling_until_stopped_or_handler_error_with_poll_error_policy",
        subscription.run_polling_until_stopped_or_handler_error_with_poll_error_policy::<
            _,
            TestTaskError,
            _,
            _,
            _,
        >(
            pool,
            Duration::from_millis(10),
            std::future::pending::<()>(),
            |_event| async { Ok::<_, TestTaskError>(()) },
            |_error| crate::fleet::SubscriptionPollErrorAction::Stop
        ),
        subscription_run_error_is_insufficient_privilege
    );
    assert_subscription_handle_fails_with_insufficient_privilege(
        "Fleet subscription start_polling_until_stopped_or_handler_error",
        subscription.start_polling_until_stopped_or_handler_error::<TestTaskError, _, _>(
            pool.clone(),
            Duration::from_millis(10),
            |_event| async { Ok::<_, TestTaskError>(()) },
        ),
    )
    .await;
    assert_subscription_handle_fails_with_insufficient_privilege(
        "Fleet subscription start_polling_until_stopped_or_handler_error_with_poll_error_policy",
        subscription.start_polling_until_stopped_or_handler_error_with_poll_error_policy::<
            TestTaskError,
            _,
            _,
            _,
        >(
            pool.clone(),
            Duration::from_millis(10),
            |_event| async { Ok::<_, TestTaskError>(()) },
            |_error| crate::fleet::SubscriptionPollErrorAction::Stop,
        ),
    )
    .await;
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription set_cursor",
        subscription.set_cursor(pool, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet subscription set_cursor_in_current_transaction",
        tx,
        subscription.set_cursor_in_current_transaction(tx, 1),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet subscription delete_cursor",
        subscription.delete_cursor(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet subscription delete_cursor_in_current_transaction",
        tx,
        subscription.delete_cursor_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore try_acquire_guard",
        semaphore.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore try_acquire_guard_for_holder",
        semaphore.try_acquire_guard_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore acquire_guard_when_available",
        semaphore.acquire_guard_when_available(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore reset",
        semaphore.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet semaphore reset_in_current_transaction",
        tx,
        semaphore.reset_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore try_run_task",
        semaphore.try_run_task::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet semaphore run_task_when_available",
        semaphore.run_task_when_available::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    let semaphore_protocol = semaphore.begin_manual_claim_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual semaphore try_acquire_claim",
        semaphore_protocol.try_acquire_claim(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual semaphore try_acquire_claim_for_holder",
        semaphore_protocol.try_acquire_claim_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual semaphore try_acquire_claim_in_current_transaction",
        tx,
        semaphore_protocol.try_acquire_claim_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual semaphore try_acquire_claim_for_holder_in_current_transaction",
        tx,
        semaphore_protocol.try_acquire_claim_for_holder_in_current_transaction(tx, &holder_id),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_acquire_guard",
        throttler.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler acquire_guard_when_ready",
        throttler.acquire_guard_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_run_task",
        throttler.try_run_task::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler run_task_when_ready",
        throttler.run_task_when_ready::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_acquire_guard_for_holder",
        throttler.try_acquire_guard_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler acquire_guard_for_holder_when_ready",
        throttler.acquire_guard_for_holder_when_ready(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler try_run_task_for_holder",
        throttler.try_run_task_for_holder::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            |_permit| async { Ok::<_, TestTaskError>(()) }
        ),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler run_task_for_holder_when_ready",
        throttler.run_task_for_holder_when_ready::<_, TestTaskError, _, _>(
            pool,
            &holder_id,
            |_permit| async { Ok::<_, TestTaskError>(()) }
        ),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler reset",
        throttler.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet throttler reset_in_current_transaction",
        tx,
        throttler.reset_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler open_circuit",
        throttler.open_circuit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet throttler open_circuit_in_current_transaction",
        tx,
        throttler.open_circuit_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet throttler close_circuit",
        throttler.close_circuit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet throttler close_circuit_in_current_transaction",
        tx,
        throttler.close_circuit_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    let throttler_protocol = throttler.begin_manual_permit_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler try_acquire_permit",
        throttler_protocol.try_acquire_permit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler acquire_permit_when_ready",
        throttler_protocol.acquire_permit_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler try_acquire_permit_for_holder",
        throttler_protocol.try_acquire_permit_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual throttler acquire_permit_for_holder_when_ready",
        throttler_protocol.acquire_permit_for_holder_when_ready(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual throttler try_acquire_permit_in_current_transaction",
        tx,
        throttler_protocol.try_acquire_permit_in_current_transaction(tx),
        fleet_error_is_insufficient_privilege
    );
    assert_write_tx_fails_with_insufficient_privilege!(
        pool,
        "Fleet manual throttler try_acquire_permit_for_holder_in_current_transaction",
        tx,
        throttler_protocol.try_acquire_permit_for_holder_in_current_transaction(tx, &holder_id),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter try_acquire_guard",
        rate_limiter.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter acquire_guard_when_ready",
        rate_limiter.acquire_guard_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter try_run_task",
        rate_limiter.try_run_task::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter run_task_when_ready",
        rate_limiter.run_task_when_ready::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet rate limiter reset",
        rate_limiter.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    let rate_limiter_protocol = rate_limiter.begin_manual_permit_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual rate limiter try_acquire_permit",
        rate_limiter_protocol.try_acquire_permit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual rate limiter acquire_permit_when_ready",
        rate_limiter_protocol.acquire_permit_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker try_acquire_guard",
        circuit_breaker.try_acquire_guard(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker acquire_guard_when_ready",
        circuit_breaker.acquire_guard_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker try_run_task",
        circuit_breaker.try_run_task::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker run_task_when_ready",
        circuit_breaker.run_task_when_ready::<_, TestTaskError, _, _>(pool, |_permit| async {
            Ok::<_, TestTaskError>(())
        }),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker reset",
        circuit_breaker.reset(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker open",
        circuit_breaker.open(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet circuit breaker close",
        circuit_breaker.close(pool),
        fleet_error_is_insufficient_privilege
    );
    let circuit_breaker_protocol = circuit_breaker.begin_manual_permit_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual circuit breaker try_acquire_permit",
        circuit_breaker_protocol.try_acquire_permit(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual circuit breaker acquire_permit_when_ready",
        circuit_breaker_protocol.acquire_permit_when_ready(pool),
        fleet_error_is_insufficient_privilege
    );

    assert_fails_with_insufficient_privilege!(
        "Fleet once try_run_task",
        once.try_run_task::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        once_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet once run_task_when_available",
        once.run_task_when_available::<_, TestTaskError, _, _>(pool, |_claim| async {
            Ok::<_, TestTaskError>(())
        }),
        once_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet once try_run_task_atomically",
        once.try_run_task_atomically::<_, TestTaskError, _>(pool, |_claim, _tx| {
            Box::pin(async { Ok::<_, TestTaskError>(()) })
        }),
        once_transactional_run_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet once run_task_atomically_when_available",
        once.run_task_atomically_when_available::<_, TestTaskError, _>(pool, |_claim, _tx| {
            Box::pin(async { Ok::<_, TestTaskError>(()) })
        }),
        once_transactional_run_error_is_insufficient_privilege
    );
    let once_protocol = once.begin_manual_run_lifecycle();
    assert_fails_with_insufficient_privilege!(
        "Fleet manual once try_start_run",
        once_protocol.try_start_run(pool),
        fleet_error_is_insufficient_privilege
    );
    assert_fails_with_insufficient_privilege!(
        "Fleet manual once try_start_run_for_holder",
        once_protocol.try_start_run_for_holder(pool, &holder_id),
        fleet_error_is_insufficient_privilege
    );
}
