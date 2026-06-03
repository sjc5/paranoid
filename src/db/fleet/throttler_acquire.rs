use super::*;

impl Throttler {
    pub(super) async fn try_acquire_with_optional_holder(
        &self,
        pool: &WritePool,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .try_acquire_with_optional_holder_in_current_transaction(&mut tx, holder_id)
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_THROTTLER_ACQUIRE, tx, result).await
    }

    pub(super) async fn try_acquire_guard_with_optional_holder(
        &self,
        pool: &WritePool,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerGuardAcquireResult, Error> {
        match self
            .try_acquire_with_optional_holder(pool, holder_id)
            .await?
        {
            ThrottlerManualPermitAcquireResult::Acquired(permit) => Ok(
                ThrottlerGuardAcquireResult::Acquired(self.guard_for_permit(pool, permit)),
            ),
            ThrottlerManualPermitAcquireResult::Throttled { retry_after } => {
                Ok(ThrottlerGuardAcquireResult::Throttled { retry_after })
            }
            ThrottlerManualPermitAcquireResult::CircuitOpen => {
                Ok(ThrottlerGuardAcquireResult::CircuitOpen)
            }
        }
    }

    pub(super) async fn acquire_with_optional_holder_when_ready(
        &self,
        pool: &WritePool,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerPermit, Error> {
        loop {
            match self
                .try_acquire_with_optional_holder(pool, holder_id)
                .await?
            {
                ThrottlerManualPermitAcquireResult::Acquired(permit) => return Ok(permit),
                ThrottlerManualPermitAcquireResult::Throttled { retry_after } => {
                    tokio::time::sleep(
                        retry_after.unwrap_or(DEFAULT_FLEET_THROTTLER_BLOCKING_RETRY_INTERVAL),
                    )
                    .await;
                }
                ThrottlerManualPermitAcquireResult::CircuitOpen => {
                    tokio::time::sleep(self.circuit_open_wait()).await;
                }
            }
        }
    }

    pub(super) async fn acquire_guard_with_optional_holder_when_ready(
        &self,
        pool: &WritePool,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerPermitGuard, Error> {
        let permit = self
            .acquire_with_optional_holder_when_ready(pool, holder_id)
            .await?;
        Ok(self.guard_for_permit(pool, permit))
    }

    pub(super) async fn try_acquire_with_optional_holder_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerManualPermitAcquireResult, Error> {
        let mut acquire_result = ThrottlerManualPermitAcquireResult::CircuitOpen;
        self.state_item
            .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
                tx,
                [FLEET_THROTTLER_STATE_KEY_PART],
                |database_timestamp| {
                    Ok::<_, Error>((
                        self.initial_state(database_timestamp.as_i64()),
                        self.state_ttl,
                    ))
                },
                |current| {
                    let now = current.database_timestamp().as_i64();
                    let mutation_outcome = self.evaluate_try_acquire_manual_permit(
                        current.live_value(),
                        now,
                        holder_id,
                    )?;
                    acquire_result = mutation_outcome.acquire_result;
                    if mutation_outcome.should_write {
                        return Ok(KvItemAtomicMutation::SetValue {
                            value: mutation_outcome.state,
                            ttl: self.state_ttl,
                        });
                    }
                    Ok(KvItemAtomicMutation::KeepExisting)
                },
            )
            .await?;
        Ok(acquire_result)
    }

    pub(super) fn evaluate_try_acquire_manual_permit(
        &self,
        current: &ThrottlerState,
        now: i64,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerMutationOutcome, Error> {
        let mut state = current.clone();
        let mut permit = ThrottlerPermit {
            throttler_key: self.key.clone(),
            holder_id: holder_id.cloned(),
            slot_suffix: None,
            probe_acquired: false,
        };

        let probe_attempt_allowed = match self.should_block_for_open_circuit(&state, now, holder_id)
        {
            CircuitGateDecision::AllowNormally => false,
            CircuitGateDecision::AllowProbe => true,
            CircuitGateDecision::Block => {
                return Ok(ThrottlerMutationOutcome {
                    acquire_result: ThrottlerManualPermitAcquireResult::CircuitOpen,
                    state,
                    should_write: false,
                });
            }
        };

        let concurrency_outcome =
            self.acquire_concurrency_slot_if_configured(&mut state, now, holder_id)?;
        if concurrency_outcome.no_slot_available {
            return Ok(ThrottlerMutationOutcome {
                acquire_result: ThrottlerManualPermitAcquireResult::Throttled { retry_after: None },
                state,
                should_write: concurrency_outcome.state_was_modified,
            });
        }
        permit.slot_suffix = concurrency_outcome.acquired_slot_suffix;

        let rate_limit_outcome = self.consume_rate_limit_token_if_configured(
            &mut state,
            now,
            permit.slot_suffix.as_deref(),
        );
        if rate_limit_outcome.blocked_by_rate_limit {
            if rate_limit_outcome.released_acquired_slot {
                permit.slot_suffix = None;
            }
            return Ok(ThrottlerMutationOutcome {
                acquire_result: ThrottlerManualPermitAcquireResult::Throttled {
                    retry_after: Some(rate_limit_outcome.retry_after),
                },
                state,
                should_write: true,
            });
        }

        if probe_attempt_allowed {
            let holder_id = holder_id.ok_or(Error::ThrottlerHolderIdRequired)?;
            state.probe_holder_id = Some(holder_id.as_str().to_owned());
            state.probe_expires_at_unix_microseconds = Some(add_duration_to_timestamp(
                now,
                DEFAULT_FLEET_THROTTLER_PROBE_WINDOW,
            )?);
            permit.probe_acquired = true;
        }

        Ok(ThrottlerMutationOutcome {
            acquire_result: ThrottlerManualPermitAcquireResult::Acquired(permit),
            state,
            should_write: true,
        })
    }

    pub(super) fn should_block_for_open_circuit(
        &self,
        state: &ThrottlerState,
        now: i64,
        holder_id: Option<&HolderId>,
    ) -> CircuitGateDecision {
        let Some(circuit_breaker) = self.circuit_breaker else {
            return CircuitGateDecision::AllowNormally;
        };
        if state.circuit_state != ThrottlerCircuitState::Open {
            return CircuitGateDecision::AllowNormally;
        }

        let Some(opened_at) = state.circuit_opened_at_unix_microseconds else {
            return CircuitGateDecision::AllowProbe;
        };
        if now.saturating_sub(opened_at)
            < duration_to_microseconds_lossy(circuit_breaker.recovery_timeout)
        {
            return CircuitGateDecision::Block;
        }

        let Some(probe_holder_id) = state.probe_holder_id.as_deref() else {
            return CircuitGateDecision::AllowProbe;
        };
        let probe_is_live = state
            .probe_expires_at_unix_microseconds
            .is_some_and(|expires_at| now < expires_at);
        let holder_matches_probe =
            holder_id.is_some_and(|holder_id| holder_id.as_str() == probe_holder_id);
        if probe_is_live && !holder_matches_probe {
            return CircuitGateDecision::Block;
        }

        CircuitGateDecision::AllowProbe
    }

    pub(super) fn acquire_concurrency_slot_if_configured(
        &self,
        state: &mut ThrottlerState,
        now: i64,
        holder_id: Option<&HolderId>,
    ) -> Result<ThrottlerConcurrencyAcquireOutcome, Error> {
        let Some(concurrency_limit) = self.concurrency_limit else {
            return Ok(ThrottlerConcurrencyAcquireOutcome {
                state_was_modified: false,
                no_slot_available: false,
                acquired_slot_suffix: None,
            });
        };
        let holder_id = holder_id.ok_or(Error::ThrottlerHolderIdRequired)?;

        let before_len = state.slots.len();
        state
            .slots
            .retain(|_, slot| now < slot.expires_at_unix_microseconds);
        let mut state_was_modified = state.slots.len() != before_len;

        for slot_number in 1..=concurrency_limit.max_concurrent {
            let suffix = slot_number.to_string();
            if state.slots.contains_key(&suffix) {
                continue;
            }
            state.slots.insert(
                suffix.clone(),
                ThrottlerSlot {
                    holder_id: holder_id.as_str().to_owned(),
                    expires_at_unix_microseconds: add_duration_to_timestamp(
                        now,
                        concurrency_limit.max_hold_duration,
                    )?,
                },
            );
            state_was_modified = true;
            return Ok(ThrottlerConcurrencyAcquireOutcome {
                state_was_modified,
                no_slot_available: false,
                acquired_slot_suffix: Some(suffix),
            });
        }

        Ok(ThrottlerConcurrencyAcquireOutcome {
            state_was_modified,
            no_slot_available: true,
            acquired_slot_suffix: None,
        })
    }

    pub(super) fn consume_rate_limit_token_if_configured(
        &self,
        state: &mut ThrottlerState,
        now: i64,
        acquired_slot_suffix: Option<&str>,
    ) -> ThrottlerRateLimitOutcome {
        let Some(rate_limit) = self.rate_limit else {
            return ThrottlerRateLimitOutcome {
                blocked_by_rate_limit: false,
                released_acquired_slot: false,
                retry_after: Duration::ZERO,
            };
        };

        let elapsed_seconds = now
            .saturating_sub(state.last_refill_unix_microseconds)
            .max(0) as f64
            / 1_000_000.0;
        state.tokens = (state.tokens + elapsed_seconds * rate_limit.refill_rate_per_second())
            .min(f64::from(rate_limit.requests_per_interval));
        state.last_refill_unix_microseconds = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            return ThrottlerRateLimitOutcome {
                blocked_by_rate_limit: false,
                released_acquired_slot: false,
                retry_after: Duration::ZERO,
            };
        }

        let mut released_acquired_slot = false;
        if let Some(acquired_slot_suffix) = acquired_slot_suffix {
            released_acquired_slot = state.slots.remove(acquired_slot_suffix).is_some();
        }

        ThrottlerRateLimitOutcome {
            blocked_by_rate_limit: true,
            released_acquired_slot,
            retry_after: compute_rate_limit_retry_after_duration(
                state.tokens,
                rate_limit.refill_rate_per_second(),
            ),
        }
    }

    pub(super) fn generate_holder_id_if_needed(&self) -> Result<Option<HolderId>, Error> {
        if self.concurrency_limit.is_some() || self.circuit_breaker.is_some() {
            return generate_holder_id().map(Some);
        }
        Ok(None)
    }

    pub(super) fn circuit_open_wait(&self) -> Duration {
        let wait = self.circuit_breaker.map_or(
            DEFAULT_FLEET_THROTTLER_BLOCKING_RETRY_INTERVAL,
            |circuit_breaker| circuit_breaker.recovery_timeout / 10,
        );
        wait.max(MIN_FLEET_THROTTLER_CIRCUIT_OPEN_WAIT)
    }
}

impl ResolvedThrottlerRateLimit {
    pub(super) fn refill_rate_per_second(self) -> f64 {
        f64::from(self.requests_per_interval) / self.interval.as_secs_f64()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CircuitGateDecision {
    AllowNormally,
    AllowProbe,
    Block,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_store() -> Store {
        Store::new(StoreConfig::default()).expect("fleet store")
    }

    fn concurrency_throttler(max_concurrent: u16) -> Throttler {
        test_store()
            .new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("test_concurrency").expect("throttler key"),
                rate_limit: None,
                concurrency_limit: Some(ThrottlerConcurrencyLimit {
                    max_concurrent,
                    max_hold_duration: Some(Duration::from_secs(60)),
                }),
                circuit_breaker: None,
            })
            .expect("concurrency throttler")
    }

    fn circuit_throttler(recovery_timeout: Duration) -> Throttler {
        test_store()
            .new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("test_circuit").expect("throttler key"),
                rate_limit: None,
                concurrency_limit: None,
                circuit_breaker: Some(ThrottlerCircuitBreaker {
                    failure_threshold: 1,
                    recovery_timeout,
                }),
            })
            .expect("circuit throttler")
    }

    fn rate_limited_throttler() -> Throttler {
        test_store()
            .new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("test_rate").expect("throttler key"),
                rate_limit: Some(ThrottlerRateLimit {
                    requests_per_interval: 2,
                    interval: Duration::from_secs(1),
                }),
                concurrency_limit: None,
                circuit_breaker: None,
            })
            .expect("rate-limited throttler")
    }

    fn custom_rate_limited_throttler(requests_per_interval: u32, interval: Duration) -> Throttler {
        test_store()
            .new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new("test_custom_rate").expect("throttler key"),
                rate_limit: Some(ThrottlerRateLimit {
                    requests_per_interval,
                    interval,
                }),
                concurrency_limit: None,
                circuit_breaker: None,
            })
            .expect("custom rate-limited throttler")
    }

    fn throttler_for_sql_shape(
        key: &str,
        rate_limit: bool,
        concurrency_limit: bool,
        circuit_breaker: bool,
    ) -> Throttler {
        test_store()
            .new_throttler(ThrottlerConfig {
                key: ThrottlerKey::new(key).expect("throttler key"),
                rate_limit: rate_limit.then_some(ThrottlerRateLimit {
                    requests_per_interval: 100,
                    interval: Duration::from_secs(1),
                }),
                concurrency_limit: concurrency_limit.then_some(ThrottlerConcurrencyLimit {
                    max_concurrent: 5,
                    max_hold_duration: Some(Duration::from_secs(5)),
                }),
                circuit_breaker: circuit_breaker.then_some(ThrottlerCircuitBreaker {
                    failure_threshold: 5,
                    recovery_timeout: Duration::from_secs(1),
                }),
            })
            .expect("throttler for SQL shape")
    }

    fn empty_state(now: i64) -> ThrottlerState {
        ThrottlerState {
            tokens: 0.0,
            last_refill_unix_microseconds: now,
            slots: BTreeMap::new(),
            consecutive_failures: 0,
            circuit_state: ThrottlerCircuitState::Closed,
            circuit_opened_at_unix_microseconds: None,
            probe_holder_id: None,
            probe_expires_at_unix_microseconds: None,
        }
    }

    fn holder_for_sql_shape(throttler: &Throttler) -> Option<HolderId> {
        (throttler.concurrency_limit.is_some() || throttler.circuit_breaker.is_some())
            .then(|| HolderId::new("holder").expect("holder"))
    }

    fn no_op_task_statement_count(
        throttler: &Throttler,
        state: &mut ThrottlerState,
        holder: Option<&HolderId>,
        now: i64,
    ) -> usize {
        let acquire_outcome = throttler
            .evaluate_try_acquire_manual_permit(state, now, holder)
            .expect("evaluate acquire");
        let mut statement_count = 1;
        if acquire_outcome.should_write {
            statement_count += 1;
            *state = acquire_outcome.state.clone();
        }
        let ThrottlerManualPermitAcquireResult::Acquired(permit) = acquire_outcome.acquire_result
        else {
            panic!("SQL-shape task should acquire");
        };

        if throttler.needs_state_cleanup(&permit) {
            statement_count += 1;
            let mut release_state = state.clone();
            let release_result = throttler.apply_release_and_outcome(
                &mut release_state,
                now + 1,
                &permit,
                ThrottlerTaskOutcome::Succeeded,
            );
            if release_result.state_was_modified() {
                statement_count += 1;
                *state = release_state;
            }
        }
        statement_count
    }

    #[test]
    fn throttler_concurrency_acquire_reuses_expired_slots_and_cleans_stale_extras() {
        let now = 1_000_000_i64;
        let throttler = concurrency_throttler(2);
        let holder = HolderId::new("holder-a").expect("holder");
        let mut state = empty_state(now);
        state.slots.insert(
            "1".to_owned(),
            ThrottlerSlot {
                holder_id: "expired-holder".to_owned(),
                expires_at_unix_microseconds: now,
            },
        );

        let outcome = throttler
            .acquire_concurrency_slot_if_configured(&mut state, now, Some(&holder))
            .expect("acquire slot");
        assert!(outcome.state_was_modified);
        assert!(!outcome.no_slot_available);
        assert_eq!(outcome.acquired_slot_suffix.as_deref(), Some("1"));
        assert_eq!(
            state.slots.get("1").map(|slot| slot.holder_id.as_str()),
            Some("holder-a")
        );

        let throttler = concurrency_throttler(2);
        let mut full_state = empty_state(now);
        for suffix in ["1", "2"] {
            full_state.slots.insert(
                suffix.to_owned(),
                ThrottlerSlot {
                    holder_id: format!("holder-{suffix}"),
                    expires_at_unix_microseconds: now + 60_000_000,
                },
            );
        }
        let full_outcome = throttler
            .acquire_concurrency_slot_if_configured(&mut full_state, now, Some(&holder))
            .expect("full slot acquire");
        assert!(!full_outcome.state_was_modified);
        assert!(full_outcome.no_slot_available);
        assert_eq!(full_outcome.acquired_slot_suffix, None);

        let throttler = concurrency_throttler(1);
        let mut stale_extra_state = empty_state(now);
        stale_extra_state.slots.insert(
            "1".to_owned(),
            ThrottlerSlot {
                holder_id: "active-holder".to_owned(),
                expires_at_unix_microseconds: now + 60_000_000,
            },
        );
        stale_extra_state.slots.insert(
            "expired-extra".to_owned(),
            ThrottlerSlot {
                holder_id: "expired-holder".to_owned(),
                expires_at_unix_microseconds: now - 1,
            },
        );
        let stale_extra_outcome = throttler
            .acquire_concurrency_slot_if_configured(&mut stale_extra_state, now, Some(&holder))
            .expect("stale extra acquire");
        assert!(stale_extra_outcome.state_was_modified);
        assert!(stale_extra_outcome.no_slot_available);
        assert!(!stale_extra_state.slots.contains_key("expired-extra"));
        assert!(stale_extra_state.slots.contains_key("1"));
    }

    #[test]
    fn throttler_sql_shape_preserves_minimal_database_call_cases() {
        let scenarios = [
            ("rate-only", true, false, false, 2),
            ("concurrency-only", false, true, false, 4),
            ("circuit-only", false, false, true, 3),
            ("concurrency-and-circuit", false, true, true, 4),
            ("all-controls", true, true, true, 4),
            ("rate-and-concurrency", true, true, false, 4),
            ("rate-and-circuit", true, false, true, 3),
            ("run-blocking-rate-only", true, false, false, 2),
            ("run-blocking-all-controls", true, true, true, 4),
        ];

        for (name, rate_limit, concurrency_limit, circuit_breaker, expected_count) in scenarios {
            let throttler =
                throttler_for_sql_shape(name, rate_limit, concurrency_limit, circuit_breaker);
            let holder = holder_for_sql_shape(&throttler);
            let mut state = throttler.initial_state(1_000_000);
            let _ = no_op_task_statement_count(&throttler, &mut state, holder.as_ref(), 1_000_000);

            let actual_count =
                no_op_task_statement_count(&throttler, &mut state, holder.as_ref(), 1_100_000);
            assert_eq!(actual_count, expected_count, "{name}");
        }

        let throttler = concurrency_throttler(1);
        let first_holder = HolderId::new("first-holder").expect("first holder");
        let second_holder = HolderId::new("second-holder").expect("second holder");
        let mut state = throttler.initial_state(1_000_000);
        let first_acquire = throttler
            .evaluate_try_acquire_manual_permit(&state, 1_000_000, Some(&first_holder))
            .expect("first acquire");
        assert!(first_acquire.should_write);
        state = first_acquire.state;

        let full_acquire = throttler
            .evaluate_try_acquire_manual_permit(&state, 1_100_000, Some(&second_holder))
            .expect("full acquire");
        assert!(matches!(
            full_acquire.acquire_result,
            ThrottlerManualPermitAcquireResult::Throttled { retry_after: None }
        ));
        assert!(!full_acquire.should_write);
        assert_eq!(1 + usize::from(full_acquire.should_write), 1);
    }

    #[test]
    fn throttler_rate_limit_consumption_releases_acquired_slot_when_token_missing() {
        let now = 1_000_000_i64;
        let throttler = rate_limited_throttler();
        let mut blocked_state = empty_state(now);
        blocked_state.tokens = 0.0;
        blocked_state.slots.insert(
            "1".to_owned(),
            ThrottlerSlot {
                holder_id: "holder-1".to_owned(),
                expires_at_unix_microseconds: now + 60_000_000,
            },
        );

        let blocked_outcome =
            throttler.consume_rate_limit_token_if_configured(&mut blocked_state, now, Some("1"));
        assert!(blocked_outcome.blocked_by_rate_limit);
        assert!(blocked_outcome.released_acquired_slot);
        assert!(blocked_outcome.retry_after > Duration::ZERO);
        assert!(!blocked_state.slots.contains_key("1"));

        let mut allowed_state = empty_state(now);
        allowed_state.tokens = 1.0;
        let allowed_outcome =
            throttler.consume_rate_limit_token_if_configured(&mut allowed_state, now, None);
        assert!(!allowed_outcome.blocked_by_rate_limit);
        assert!(!allowed_outcome.released_acquired_slot);
        assert_eq!(allowed_state.tokens, 0.0);
    }

    #[test]
    fn throttler_rate_limit_partial_refill_uses_elapsed_database_time() {
        let now = 1_000_000_i64;
        let throttler = custom_rate_limited_throttler(4, Duration::from_millis(400));
        let mut state = empty_state(now);
        state.tokens = 0.0;
        state.last_refill_unix_microseconds = now - 200_000;

        let first = throttler.consume_rate_limit_token_if_configured(&mut state, now, None);
        assert!(!first.blocked_by_rate_limit);
        assert_eq!(state.tokens, 1.0);

        let second = throttler.consume_rate_limit_token_if_configured(&mut state, now, None);
        assert!(!second.blocked_by_rate_limit);
        assert_eq!(state.tokens, 0.0);

        let third = throttler.consume_rate_limit_token_if_configured(&mut state, now, None);
        assert!(third.blocked_by_rate_limit);
        assert!(third.retry_after > Duration::ZERO);
    }

    #[test]
    fn throttler_open_circuit_gate_blocks_until_recovery_and_coordinates_probe_holder() {
        let now = 120_000_000_i64;
        let holder_a = HolderId::new("holder-a").expect("holder a");
        let holder_b = HolderId::new("holder-b").expect("holder b");
        let disabled_throttler = rate_limited_throttler();
        let mut state = empty_state(now);
        state.circuit_state = ThrottlerCircuitState::Open;
        state.circuit_opened_at_unix_microseconds = Some(now - 30_000_000);
        assert_eq!(
            disabled_throttler.should_block_for_open_circuit(&state, now, Some(&holder_a)),
            CircuitGateDecision::AllowNormally
        );

        let circuit_throttler = circuit_throttler(Duration::from_secs(60));
        assert_eq!(
            circuit_throttler.should_block_for_open_circuit(&state, now, Some(&holder_a)),
            CircuitGateDecision::Block
        );

        state.circuit_opened_at_unix_microseconds = Some(now - 120_000_000);
        state.probe_holder_id = Some("holder-b".to_owned());
        state.probe_expires_at_unix_microseconds = Some(now + 30_000_000);
        assert_eq!(
            circuit_throttler.should_block_for_open_circuit(&state, now, Some(&holder_a)),
            CircuitGateDecision::Block
        );
        assert_eq!(
            circuit_throttler.should_block_for_open_circuit(&state, now, Some(&holder_b)),
            CircuitGateDecision::AllowProbe
        );

        state.probe_expires_at_unix_microseconds = Some(now - 1);
        assert_eq!(
            circuit_throttler.should_block_for_open_circuit(&state, now, Some(&holder_a)),
            CircuitGateDecision::AllowProbe
        );
    }

    proptest! {
        #[test]
        fn throttler_generated_concurrency_acquire_preserves_slot_bounds_and_removes_expired_slots(
            max_concurrent in 1_u16..=16,
            requested_active_count in 0_usize..32,
            expired_extra_count in 0_usize..32,
            now in 1_000_000_i64..9_000_000_000_i64,
        ) {
            let active_count = requested_active_count.min(usize::from(max_concurrent));
            let throttler = concurrency_throttler(max_concurrent);
            let holder = HolderId::new("generated-holder").expect("holder");
            let mut state = empty_state(now);

            for slot_number in 1..=active_count {
                state.slots.insert(
                    slot_number.to_string(),
                    ThrottlerSlot {
                        holder_id: format!("active-holder-{slot_number}"),
                        expires_at_unix_microseconds: now + 60_000_000,
                    },
                );
            }
            for expired_number in 0..expired_extra_count {
                state.slots.insert(
                    format!("expired-extra-{expired_number}"),
                    ThrottlerSlot {
                        holder_id: format!("expired-holder-{expired_number}"),
                        expires_at_unix_microseconds: now - 1,
                    },
                );
            }

            let outcome = throttler
                .acquire_concurrency_slot_if_configured(&mut state, now, Some(&holder))
                .expect("acquire generated concurrency slot");

            prop_assert!(state
                .slots
                .values()
                .all(|slot| now < slot.expires_at_unix_microseconds));
            prop_assert!(state.slots.len() <= usize::from(max_concurrent));

            if active_count < usize::from(max_concurrent) {
                prop_assert!(outcome.state_was_modified);
                prop_assert!(!outcome.no_slot_available);
                let acquired_slot_suffix = outcome
                    .acquired_slot_suffix
                    .as_deref()
                    .expect("acquired slot suffix");
                prop_assert_eq!(
                    state
                        .slots
                        .get(acquired_slot_suffix)
                        .map(|slot| slot.holder_id.as_str()),
                    Some(holder.as_str())
                );
                prop_assert_eq!(state.slots.len(), active_count + 1);
            } else {
                prop_assert_eq!(outcome.state_was_modified, expired_extra_count > 0);
                prop_assert!(outcome.no_slot_available);
                prop_assert_eq!(outcome.acquired_slot_suffix, None);
                prop_assert_eq!(state.slots.len(), usize::from(max_concurrent));
            }
        }

        #[test]
        fn throttler_generated_rate_limit_consumption_keeps_token_bucket_in_bounds(
            requests_per_interval in 1_u32..=1_000,
            interval_micros in 1_000_u64..=60_000_000,
            initial_tokens_numerator in 0_u32..=2_000,
            elapsed_micros in 0_i64..=120_000_000,
            now in 1_000_000_i64..9_000_000_000_i64,
        ) {
            let interval = Duration::from_micros(interval_micros);
            let throttler = custom_rate_limited_throttler(requests_per_interval, interval);
            let max_tokens = f64::from(requests_per_interval);
            let mut state = empty_state(now);
            state.tokens = (f64::from(initial_tokens_numerator) / 2.0).min(max_tokens);
            state.last_refill_unix_microseconds = now - elapsed_micros;

            let outcome = throttler.consume_rate_limit_token_if_configured(&mut state, now, None);

            prop_assert!(state.tokens >= 0.0);
            prop_assert!(state.tokens <= max_tokens);
            prop_assert_eq!(state.last_refill_unix_microseconds, now);
            if outcome.blocked_by_rate_limit {
                prop_assert!(outcome.retry_after > Duration::ZERO);
            } else {
                prop_assert_eq!(outcome.retry_after, Duration::ZERO);
            }
        }

        #[test]
        fn throttler_generated_circuit_release_transitions_preserve_expected_state(
            failure_threshold in 1_u32..=20,
            starting_failures in 0_u32..=40,
            initially_open in any::<bool>(),
            outcome_index in 0_u8..=2,
            now in 1_000_000_i64..9_000_000_000_i64,
        ) {
            let throttler = test_store()
                .new_throttler(ThrottlerConfig {
                    key: ThrottlerKey::new("generated-circuit").expect("throttler key"),
                    rate_limit: None,
                    concurrency_limit: None,
                    circuit_breaker: Some(ThrottlerCircuitBreaker {
                        failure_threshold,
                        recovery_timeout: Duration::from_secs(60),
                    }),
                })
                .expect("circuit throttler");
            let mut state = throttler.initial_state(now);
            state.consecutive_failures = starting_failures;
            if initially_open {
                state.circuit_state = ThrottlerCircuitState::Open;
                state.circuit_opened_at_unix_microseconds = Some(now - 1);
            }
            let before = state.clone();
            let outcome = match outcome_index {
                0 => ThrottlerTaskOutcome::NotExecuted,
                1 => ThrottlerTaskOutcome::Succeeded,
                _ => ThrottlerTaskOutcome::Failed,
            };

            let changed = throttler.apply_task_outcome_to_circuit_state(&mut state, now, outcome);

            match outcome {
                ThrottlerTaskOutcome::NotExecuted => {
                    prop_assert!(!changed);
                    prop_assert_eq!(state, before);
                }
                ThrottlerTaskOutcome::Succeeded => {
                    prop_assert_eq!(state.circuit_state, ThrottlerCircuitState::Closed);
                    prop_assert_eq!(state.consecutive_failures, 0);
                    prop_assert_eq!(state.circuit_opened_at_unix_microseconds, None);
                    prop_assert_eq!(
                        changed,
                        before.consecutive_failures != 0
                            || before.circuit_state != ThrottlerCircuitState::Closed
                            || before.circuit_opened_at_unix_microseconds.is_some()
                    );
                }
                ThrottlerTaskOutcome::Failed => {
                    prop_assert!(changed);
                    prop_assert_eq!(
                        state.consecutive_failures,
                        before.consecutive_failures.saturating_add(1)
                    );
                    if before.circuit_state == ThrottlerCircuitState::Open
                        || state.consecutive_failures >= failure_threshold
                    {
                        prop_assert_eq!(state.circuit_state, ThrottlerCircuitState::Open);
                        prop_assert_eq!(state.circuit_opened_at_unix_microseconds, Some(now));
                    } else {
                        prop_assert_eq!(state.circuit_state, ThrottlerCircuitState::Closed);
                        prop_assert_eq!(state.circuit_opened_at_unix_microseconds, None);
                    }
                }
            }
        }
    }
}
