use super::*;

impl<T> Topic<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Returns this topic's key.
    pub fn key(&self) -> &TopicKey {
        &self.key
    }

    /// Returns this topic's event TTL.
    pub fn event_ttl(&self) -> KvTtl {
        self.event_ttl
    }

    /// Creates a subscription handle for this topic.
    pub fn subscribe(&self, config: SubscriptionConfig) -> Result<Subscription<T>, Error> {
        let poll_limit = config.poll_limit.unwrap_or(DEFAULT_SUBSCRIPTION_POLL_LIMIT);
        validate_subscription_poll_limit(poll_limit)?;
        let cursor_prefix = build_subscription_cursor_prefix(
            self.root_key.as_str(),
            self.key.as_str(),
            config.key.as_str(),
        )
        .map_err(|source| Error::InvalidSubscriptionKeyForCursor { source })?;
        let polling_mutex_lease_key = build_subscription_polling_mutex_lease_key(
            self.root_key.as_str(),
            self.key.as_str(),
            config.key.as_str(),
        )
        .map_err(|source| Error::InvalidSubscriptionKeyForPollingMutex { source })?;
        let polling_mutex = Mutex {
            lease_store: self.polling_mutex_lease_store.clone(),
            key: MutexKey(config.key.as_str().to_owned()),
            lease_key: polling_mutex_lease_key,
            claim_duration: ClaimDuration::expires_after(
                DEFAULT_SUBSCRIPTION_POLLING_LOOP_CLAIM_DURATION,
            )?,
        };
        let polling_mutex_guard_config = MutexGuardConfig::default();
        polling_mutex_guard_config.resolve_for_claim_duration(polling_mutex.claim_duration())?;

        Ok(Subscription {
            topic_key: self.key.clone(),
            key: config.key,
            poll_limit,
            event_item: KvItem::new_plain(self.cursor_store.clone(), self.event_prefix.clone()),
            cursor_item: KvItem::new_plain(self.cursor_store.clone(), cursor_prefix),
            polling_mutex,
            polling_mutex_guard_config,
        })
    }

    /// Publishes an event and returns its assigned sequence.
    pub async fn publish(&self, pool: &Pool, event: T) -> Result<i64, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.publish_in_current_transaction(&mut tx, event).await;
        finish_fleet_pool_transaction(FLEET_OPERATION_TOPIC_PUBLISH, tx, result).await
    }

    /// Transactional variant of `publish`.
    pub async fn publish_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        event: T,
    ) -> Result<i64, Error> {
        let mut sequence = None;
        let mut published_at_unix_microseconds = None;
        self.sequence_item
            .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
                tx,
                std::iter::empty::<&str>(),
                |_| Ok::<_, Error>((0, KvTtl::no_expiration())),
                |current| {
                    let next_sequence = current
                        .live_value()
                        .checked_add(1)
                        .ok_or(Error::TopicSequenceOverflow)?;
                    sequence = Some(next_sequence);
                    published_at_unix_microseconds = Some(current.database_timestamp().as_i64());
                    Ok(KvItemAtomicMutation::SetValue {
                        value: next_sequence,
                        ttl: KvTtl::no_expiration(),
                    })
                },
            )
            .await?;

        let sequence = sequence.ok_or(Error::TopicPublishMutationDidNotAssignSequence)?;
        let event_key_suffix = topic_sequence_key_suffix(sequence)?;
        let envelope = TopicEventEnvelope {
            published_at_unix_microseconds: published_at_unix_microseconds
                .ok_or(Error::TopicPublishMutationDidNotObserveTimestamp)?,
            data: event,
        };
        self.event_item
            .set_in_current_transaction(tx, [event_key_suffix.as_str()], &envelope, self.event_ttl)
            .await?;
        Ok(sequence)
    }

    /// Fetches the latest sequence assigned by this topic.
    pub async fn fetch_latest_sequence(&self, pool: &Pool) -> Result<i64, Error> {
        match self
            .sequence_item
            .get(pool, std::iter::empty::<&str>())
            .await
        {
            Ok(sequence) => {
                validate_non_negative_topic_sequence(sequence)?;
                Ok(sequence)
            }
            Err(KvError::KeyNotFound) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// Transactional variant of `fetch_latest_sequence`.
    pub async fn fetch_latest_sequence_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<i64, Error> {
        match self
            .sequence_item
            .get_in_current_transaction(tx, std::iter::empty::<&str>())
            .await
        {
            Ok(sequence) => {
                validate_non_negative_topic_sequence(sequence)?;
                Ok(sequence)
            }
            Err(KvError::KeyNotFound) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// Deletes all retained events inside one transaction without resetting the topic sequence.
    pub async fn purge_retained_events_atomically(&self, pool: &Pool) -> Result<u64, Error> {
        self.event_item
            .delete_entire_namespace_atomically(pool)
            .await
            .map_err(Error::from)
    }

    /// Deletes all retained events inside the caller's transaction without resetting the topic sequence.
    pub async fn purge_retained_events_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<u64, Error> {
        self.event_item
            .delete_entire_namespace_in_current_transaction(tx)
            .await
            .map_err(Error::from)
    }
}

impl<T> Subscription<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Returns this subscription's topic key.
    pub fn topic_key(&self) -> &TopicKey {
        &self.topic_key
    }

    /// Returns this subscription's key.
    pub fn key(&self) -> &SubscriptionKey {
        &self.key
    }

    /// Returns this subscription's poll limit.
    pub fn poll_limit(&self) -> u32 {
        self.poll_limit
    }

    /// Reads new events after the persisted cursor and advances the cursor if events are found.
    pub async fn read_new_events_and_advance_cursor(
        &self,
        pool: &Pool,
    ) -> Result<Vec<TopicEvent<T>>, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .read_new_events_and_advance_cursor_in_current_transaction(&mut tx)
            .await;
        finish_fleet_pool_transaction(
            FLEET_OPERATION_TOPIC_READ_NEW_EVENTS_AND_ADVANCE_CURSOR,
            tx,
            result,
        )
        .await
    }

    /// Transactional variant of `read_new_events_and_advance_cursor`.
    pub async fn read_new_events_and_advance_cursor_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<Vec<TopicEvent<T>>, Error> {
        let cursor = self.fetch_cursor_in_current_transaction(tx).await?;
        let events = self
            .fetch_events_after_in_current_transaction(tx, cursor)
            .await?;
        if let Some(new_cursor) = events.last().map(TopicEvent::sequence) {
            self.advance_cursor_if_needed_in_current_transaction(tx, new_cursor)
                .await?;
        }
        Ok(events)
    }

    /// Polls repeatedly until `stop` resolves or the handler fails, advancing the cursor only after handler success.
    pub async fn run_polling_until_stopped_or_handler_error<Stop, E, HandlerFuture, Handler>(
        &self,
        pool: &Pool,
        poll_interval: Duration,
        stop: Stop,
        handle_events: Handler,
    ) -> Result<(), SubscriptionRunError<E>>
    where
        Stop: Future<Output = ()>,
        HandlerFuture: Future<Output = Result<(), E>>,
        Handler: FnMut(Vec<TopicEvent<T>>) -> HandlerFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let default_retry_delay_microseconds = Arc::new(AtomicU64::new(
            duration_to_microseconds_for_subscription_retry_delay(
                DEFAULT_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL,
            ),
        ));
        let default_retry_delay_for_error = Arc::clone(&default_retry_delay_microseconds);
        let default_retry_delay_for_success = Arc::clone(&default_retry_delay_microseconds);
        self.run_polling_until_stopped_or_handler_error_with_poll_error_policy_and_success_hook(
            pool,
            poll_interval,
            stop,
            handle_events,
            move |_| {
                let retry_delay_microseconds =
                    default_retry_delay_for_error.load(Ordering::Relaxed);
                let next_retry_delay_microseconds = retry_delay_microseconds.saturating_mul(2).min(
                    duration_to_microseconds_for_subscription_retry_delay(
                        MAX_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL,
                    ),
                );
                default_retry_delay_for_error
                    .store(next_retry_delay_microseconds, Ordering::Relaxed);
                SubscriptionPollErrorAction::ContinueAfter(Duration::from_micros(
                    retry_delay_microseconds,
                ))
            },
            move || {
                default_retry_delay_for_success.store(
                    duration_to_microseconds_for_subscription_retry_delay(
                        DEFAULT_SUBSCRIPTION_POLL_ERROR_RETRY_INTERVAL,
                    ),
                    Ordering::Relaxed,
                );
            },
        )
        .await
    }

    /// Polls repeatedly until `stop` resolves or the handler fails, applying an explicit database poll-error policy.
    pub async fn run_polling_until_stopped_or_handler_error_with_poll_error_policy<
        Stop,
        E,
        HandlerFuture,
        Handler,
        OnPollError,
    >(
        &self,
        pool: &Pool,
        poll_interval: Duration,
        stop: Stop,
        handle_events: Handler,
        on_poll_error: OnPollError,
    ) -> Result<(), SubscriptionRunError<E>>
    where
        Stop: Future<Output = ()>,
        HandlerFuture: Future<Output = Result<(), E>>,
        Handler: FnMut(Vec<TopicEvent<T>>) -> HandlerFuture,
        OnPollError: FnMut(&Error) -> SubscriptionPollErrorAction,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.run_polling_until_stopped_or_handler_error_with_poll_error_policy_and_success_hook(
            pool,
            poll_interval,
            stop,
            handle_events,
            on_poll_error,
            || {},
        )
        .await
    }

    async fn run_polling_until_stopped_or_handler_error_with_poll_error_policy_and_success_hook<
        Stop,
        E,
        HandlerFuture,
        Handler,
        OnPollError,
        OnPollSuccess,
    >(
        &self,
        pool: &Pool,
        poll_interval: Duration,
        stop: Stop,
        mut handle_events: Handler,
        mut on_poll_error: OnPollError,
        mut on_poll_success: OnPollSuccess,
    ) -> Result<(), SubscriptionRunError<E>>
    where
        Stop: Future<Output = ()>,
        HandlerFuture: Future<Output = Result<(), E>>,
        Handler: FnMut(Vec<TopicEvent<T>>) -> HandlerFuture,
        OnPollError: FnMut(&Error) -> SubscriptionPollErrorAction,
        OnPollSuccess: FnMut(),
        E: std::error::Error + Send + Sync + 'static,
    {
        let poll_interval = normalize_subscription_poll_interval(poll_interval);
        tokio::pin!(stop);

        let resolved_guard_config = self
            .polling_mutex_guard_config
            .resolve_for_claim_duration(self.polling_mutex.claim_duration())?;
        let mut acquire_retry_interval = resolved_guard_config.acquire_retry_interval;
        let guard = loop {
            let claim_result = tokio::select! {
                () = &mut stop => return Ok(()),
                claim_result = self.polling_mutex.try_claim_guard(pool, self.polling_mutex_guard_config) => claim_result,
            };
            match claim_result {
                Ok(Some(guard)) => break guard,
                Ok(None) => {
                    let retry_delay =
                        fleet_mutex_acquire_retry_delay_with_jitter(acquire_retry_interval)?;
                    tokio::select! {
                        () = &mut stop => return Ok(()),
                        () = tokio::time::sleep(retry_delay) => {}
                    }
                    acquire_retry_interval = acquire_retry_interval
                        .saturating_mul(2)
                        .min(resolved_guard_config.max_acquire_retry_interval);
                }
                Err(error) => {
                    let retry_delay =
                        subscription_poll_error_retry_delay_from_policy(error, &mut on_poll_error)?;
                    tokio::select! {
                        () = &mut stop => return Ok(()),
                        () = tokio::time::sleep(retry_delay) => {}
                    }
                }
            }
        };

        let mut cursor: Option<i64> = None;

        let run_result = loop {
            if guard.leadership_lost() {
                break Err(SubscriptionRunError::PollingGuardLost);
            }
            if cursor.is_none() {
                cursor = Some(
                    match tokio::select! {
                        () = &mut stop => break Ok(()),
                        cursor = self.fetch_cursor(pool) => cursor,
                    } {
                        Ok(cursor) => cursor,
                        Err(error) => {
                            let retry_delay = match subscription_poll_error_retry_delay_from_policy(
                                error,
                                &mut on_poll_error,
                            ) {
                                Ok(retry_delay) => retry_delay,
                                Err(error) => break Err(error),
                            };
                            tokio::select! {
                                () = &mut stop => break Ok(()),
                                () = tokio::time::sleep(retry_delay) => {}
                            }
                            continue;
                        }
                    },
                );
            }
            let Some(current_cursor) = cursor else {
                continue;
            };
            let events = tokio::select! {
                () = &mut stop => break Ok(()),
                events = self.fetch_events_after(pool, current_cursor) => events,
            };
            let events = match events {
                Ok(events) => {
                    on_poll_success();
                    events
                }
                Err(error) => {
                    let retry_delay = match subscription_poll_error_retry_delay_from_policy(
                        error,
                        &mut on_poll_error,
                    ) {
                        Ok(retry_delay) => retry_delay,
                        Err(error) => break Err(error),
                    };
                    tokio::select! {
                        () = &mut stop => break Ok(()),
                        () = tokio::time::sleep(retry_delay) => {}
                    }
                    continue;
                }
            };

            let Some(new_cursor) = events.last().map(TopicEvent::sequence) else {
                tokio::select! {
                    () = &mut stop => break Ok(()),
                    () = tokio::time::sleep(poll_interval) => {}
                }
                continue;
            };

            if guard.leadership_lost() {
                break Err(SubscriptionRunError::PollingGuardLost);
            }
            if let Err(source) = handle_events(events).await {
                break Err(SubscriptionRunError::Handler { source });
            }
            if guard.leadership_lost() {
                break Err(SubscriptionRunError::PollingGuardLost);
            }
            if let Err(source) = self.advance_cursor_if_needed(pool, new_cursor).await {
                break Err(SubscriptionRunError::Fleet(source));
            }
            if guard.leadership_lost() {
                break Err(SubscriptionRunError::PollingGuardLost);
            }
            tokio::select! {
                biased;
                () = &mut stop => break Ok(()),
                () = std::future::ready(()) => {}
            }
            cursor = Some(new_cursor);
        };

        let release_result = guard.release().await;
        combine_subscription_run_and_polling_guard_release_results(run_result, release_result)
    }

    /// Starts a background polling task that runs until stopped or until the handler fails.
    pub fn start_polling_until_stopped_or_handler_error<E, HandlerFuture, Handler>(
        &self,
        pool: Pool,
        poll_interval: Duration,
        handle_events: Handler,
    ) -> SubscriptionRunHandle<E>
    where
        T: Send + Sync + 'static,
        HandlerFuture: Future<Output = Result<(), E>> + Send + 'static,
        Handler: FnMut(Vec<TopicEvent<T>>) -> HandlerFuture + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let subscription = <Subscription<T> as Clone>::clone(self);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            subscription
                .run_polling_until_stopped_or_handler_error(
                    &pool,
                    poll_interval,
                    async move {
                        let _ = stop_receiver.await;
                    },
                    handle_events,
                )
                .await
        });
        SubscriptionRunHandle {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
        }
    }

    /// Starts a background polling task that applies an explicit database poll-error policy.
    pub fn start_polling_until_stopped_or_handler_error_with_poll_error_policy<
        E,
        HandlerFuture,
        Handler,
        OnPollError,
    >(
        &self,
        pool: Pool,
        poll_interval: Duration,
        handle_events: Handler,
        on_poll_error: OnPollError,
    ) -> SubscriptionRunHandle<E>
    where
        T: Send + Sync + 'static,
        HandlerFuture: Future<Output = Result<(), E>> + Send + 'static,
        Handler: FnMut(Vec<TopicEvent<T>>) -> HandlerFuture + Send + 'static,
        OnPollError: FnMut(&Error) -> SubscriptionPollErrorAction + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let subscription = <Subscription<T> as Clone>::clone(self);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            subscription
                .run_polling_until_stopped_or_handler_error_with_poll_error_policy(
                    &pool,
                    poll_interval,
                    async move {
                        let _ = stop_receiver.await;
                    },
                    handle_events,
                    on_poll_error,
                )
                .await
        });
        SubscriptionRunHandle {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
        }
    }

    /// Reads retained events after `after_sequence` without updating the persisted cursor.
    pub async fn fetch_events_after(
        &self,
        pool: &Pool,
        after_sequence: i64,
    ) -> Result<Vec<TopicEvent<T>>, Error> {
        validate_non_negative_topic_sequence(after_sequence)?;
        let after_key_suffix = topic_sequence_key_suffix(after_sequence)?;
        let rows = self
            .event_item
            .scan(pool, Some(after_key_suffix.as_str()), self.poll_limit)
            .await?;
        scanned_topic_events_to_public_events(rows)
    }

    /// Transactional variant of `fetch_events_after`.
    pub async fn fetch_events_after_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        after_sequence: i64,
    ) -> Result<Vec<TopicEvent<T>>, Error> {
        validate_non_negative_topic_sequence(after_sequence)?;
        let after_key_suffix = topic_sequence_key_suffix(after_sequence)?;
        let rows = self
            .event_item
            .scan_in_current_transaction(tx, Some(after_key_suffix.as_str()), self.poll_limit)
            .await?;
        scanned_topic_events_to_public_events(rows)
    }

    /// Fetches the persisted subscription cursor.
    pub async fn fetch_cursor(&self, pool: &Pool) -> Result<i64, Error> {
        match self.cursor_item.get(pool, std::iter::empty::<&str>()).await {
            Ok(cursor) => {
                validate_non_negative_topic_sequence(cursor)?;
                Ok(cursor)
            }
            Err(KvError::KeyNotFound) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// Transactional variant of `fetch_cursor`.
    pub async fn fetch_cursor_in_current_transaction(&self, tx: &mut Tx<'_>) -> Result<i64, Error> {
        match self
            .cursor_item
            .get_in_current_transaction(tx, std::iter::empty::<&str>())
            .await
        {
            Ok(cursor) => {
                validate_non_negative_topic_sequence(cursor)?;
                Ok(cursor)
            }
            Err(KvError::KeyNotFound) => Ok(0),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// Sets the persisted subscription cursor exactly.
    pub async fn set_cursor(&self, pool: &Pool, sequence: i64) -> Result<(), Error> {
        validate_non_negative_topic_sequence(sequence)?;
        self.cursor_item
            .set(
                pool,
                std::iter::empty::<&str>(),
                &sequence,
                KvTtl::no_expiration(),
            )
            .await?;
        Ok(())
    }

    /// Transactional variant of `set_cursor`.
    pub async fn set_cursor_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        sequence: i64,
    ) -> Result<(), Error> {
        validate_non_negative_topic_sequence(sequence)?;
        self.cursor_item
            .set_in_current_transaction(
                tx,
                std::iter::empty::<&str>(),
                &sequence,
                KvTtl::no_expiration(),
            )
            .await?;
        Ok(())
    }

    /// Deletes the persisted subscription cursor.
    pub async fn delete_cursor(&self, pool: &Pool) -> Result<(), Error> {
        match self
            .cursor_item
            .delete(pool, std::iter::empty::<&str>())
            .await
        {
            Ok(()) | Err(KvError::KeyNotFound) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }

    /// Transactional variant of `delete_cursor`.
    pub async fn delete_cursor_in_current_transaction(&self, tx: &mut Tx<'_>) -> Result<(), Error> {
        match self
            .cursor_item
            .delete_in_current_transaction(tx, std::iter::empty::<&str>())
            .await
        {
            Ok(()) | Err(KvError::KeyNotFound) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }

    async fn advance_cursor_if_needed(&self, pool: &Pool, sequence: i64) -> Result<(), Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .advance_cursor_if_needed_in_current_transaction(&mut tx, sequence)
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_TOPIC_ADVANCE_CURSOR, tx, result).await
    }

    async fn advance_cursor_if_needed_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        sequence: i64,
    ) -> Result<(), Error> {
        validate_non_negative_topic_sequence(sequence)?;
        self.cursor_item
            .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
                tx,
                std::iter::empty::<&str>(),
                |_| Ok::<_, Error>((sequence, KvTtl::no_expiration())),
                |current| {
                    let current_sequence = *current.live_value();
                    validate_non_negative_topic_sequence(current_sequence)?;
                    if current_sequence >= sequence {
                        return Ok(KvItemAtomicMutation::KeepExisting);
                    }
                    Ok(KvItemAtomicMutation::SetValue {
                        value: sequence,
                        ttl: KvTtl::no_expiration(),
                    })
                },
            )
            .await?;
        Ok(())
    }
}

fn duration_to_microseconds_for_subscription_retry_delay(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl<T> TopicEvent<T> {
    /// Returns this event's monotonic sequence.
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// Returns this event's database publication timestamp as Unix microseconds.
    pub fn published_at_unix_microseconds(&self) -> i64 {
        self.published_at_unix_microseconds
    }

    /// Returns this event's payload.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Consumes this event and returns its payload.
    pub fn into_data(self) -> T {
        self.data
    }
}
