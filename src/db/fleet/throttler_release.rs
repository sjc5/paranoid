use super::*;

impl Throttler {
    pub(super) async fn extend_probe_reservation(
        &self,
        pool: &WritePool,
        permit: &ThrottlerPermit,
    ) -> Result<bool, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .extend_probe_reservation_in_current_transaction(&mut tx, permit)
            .await;
        finish_fleet_pool_transaction(FLEET_OPERATION_THROTTLER_EXTEND_PROBE, tx, result).await
    }

    pub(super) async fn extend_probe_reservation_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        permit: &ThrottlerPermit,
    ) -> Result<bool, Error> {
        self.require_permit_matches_throttler(permit)?;
        if !permit.probe_acquired {
            return Ok(false);
        }
        let holder_id = permit
            .holder_id
            .as_ref()
            .ok_or(Error::ThrottlerHolderIdRequired)?;

        let mut extended = false;
        let mutation_result = self
            .state_item
            .mutate_live_atomically_in_current_transaction(
                tx,
                [FLEET_THROTTLER_STATE_KEY_PART],
                |current| {
                    let now = current.database_timestamp().as_i64();
                    let mut state = current.live_value().clone();

                    if state.circuit_state != ThrottlerCircuitState::Open
                        || state.probe_holder_id.as_deref() != Some(holder_id.as_str())
                    {
                        return Ok::<_, Error>(KvItemAtomicMutation::KeepExisting);
                    }
                    let Some(probe_expires_at) = state.probe_expires_at_unix_microseconds else {
                        return Ok(KvItemAtomicMutation::KeepExisting);
                    };
                    if now >= probe_expires_at {
                        return Ok(KvItemAtomicMutation::KeepExisting);
                    }

                    state.probe_expires_at_unix_microseconds = Some(add_duration_to_timestamp(
                        now,
                        DEFAULT_FLEET_THROTTLER_PROBE_WINDOW,
                    )?);
                    extended = true;
                    Ok(KvItemAtomicMutation::SetValue {
                        value: state,
                        ttl: self.state_ttl,
                    })
                },
            )
            .await;

        match mutation_result {
            Ok(_) => Ok(extended),
            Err(Error::Kv(KvError::KeyNotFound)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub(super) async fn set_circuit_state_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        circuit_state: ThrottlerCircuitState,
        set_opened_at: bool,
        reset_consecutive_failures: bool,
    ) -> Result<(), Error> {
        if self.circuit_breaker.is_none() {
            return Ok(());
        }

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
                    let mut state = current.live_value().clone();
                    state.circuit_state = circuit_state;
                    state.circuit_opened_at_unix_microseconds = set_opened_at.then_some(now);
                    state.probe_holder_id = None;
                    state.probe_expires_at_unix_microseconds = None;
                    if reset_consecutive_failures {
                        state.consecutive_failures = 0;
                    }
                    Ok(KvItemAtomicMutation::SetValue {
                        value: state,
                        ttl: self.state_ttl,
                    })
                },
            )
            .await?;
        Ok(())
    }

    pub(super) fn apply_release_and_outcome(
        &self,
        state: &mut ThrottlerState,
        now: i64,
        permit: &ThrottlerPermit,
        outcome: ThrottlerTaskOutcome,
    ) -> ThrottlerReleaseResult {
        let mut result = ThrottlerReleaseResult {
            concurrency_slot_released: self.release_owned_concurrency_slot(state, permit),
            ..ThrottlerReleaseResult::default()
        };

        if self.circuit_breaker.is_some() {
            result.circuit_state_updated =
                self.apply_task_outcome_to_circuit_state(state, now, outcome);
            result.probe_released = clear_probe_if_owned(state, permit);
        }

        result
    }

    pub(super) fn release_owned_concurrency_slot(
        &self,
        state: &mut ThrottlerState,
        permit: &ThrottlerPermit,
    ) -> bool {
        if self.concurrency_limit.is_none() {
            return false;
        }
        let Some(slot_suffix) = permit.slot_suffix.as_deref() else {
            return false;
        };
        let Some(holder_id) = permit.holder_id.as_ref() else {
            return false;
        };
        let Some(slot) = state.slots.get(slot_suffix) else {
            return false;
        };
        if slot.holder_id != holder_id.as_str() {
            return false;
        }
        state.slots.remove(slot_suffix);
        true
    }

    pub(super) fn apply_task_outcome_to_circuit_state(
        &self,
        state: &mut ThrottlerState,
        now: i64,
        outcome: ThrottlerTaskOutcome,
    ) -> bool {
        let Some(circuit_breaker) = self.circuit_breaker else {
            return false;
        };
        match outcome {
            ThrottlerTaskOutcome::NotExecuted => false,
            ThrottlerTaskOutcome::Failed => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                if state.circuit_state == ThrottlerCircuitState::Closed
                    && state.consecutive_failures >= circuit_breaker.failure_threshold
                {
                    state.circuit_state = ThrottlerCircuitState::Open;
                    state.circuit_opened_at_unix_microseconds = Some(now);
                } else if state.circuit_state == ThrottlerCircuitState::Open {
                    state.circuit_opened_at_unix_microseconds = Some(now);
                }
                true
            }
            ThrottlerTaskOutcome::Succeeded => {
                if state.consecutive_failures == 0
                    && state.circuit_state == ThrottlerCircuitState::Closed
                    && state.circuit_opened_at_unix_microseconds.is_none()
                {
                    return false;
                }
                state.consecutive_failures = 0;
                state.circuit_state = ThrottlerCircuitState::Closed;
                state.circuit_opened_at_unix_microseconds = None;
                true
            }
        }
    }
}
