use super::throttler_guard::run_throttler_probe_heartbeat;
use super::*;

impl Throttler {
    pub(super) fn status_from_state(&self, state: &ThrottlerState, now: i64) -> ThrottlerStatus {
        let mut status = self.empty_status();
        if let Some(rate_limit) = self.rate_limit {
            let elapsed_seconds = now
                .saturating_sub(state.last_refill_unix_microseconds)
                .max(0) as f64
                / 1_000_000.0;
            status.available_tokens = (state.tokens
                + elapsed_seconds * rate_limit.refill_rate_per_second())
            .min(status.max_tokens);
        }
        if self.concurrency_limit.is_some() {
            status.current_concurrency = state
                .slots
                .values()
                .filter(|slot| now < slot.expires_at_unix_microseconds)
                .count()
                .try_into()
                .unwrap_or(u16::MAX);
        }
        if self.circuit_breaker.is_some() {
            status.circuit_state = state.circuit_state;
            status.consecutive_failures = state.consecutive_failures;
        }
        status
    }

    pub(super) fn empty_status(&self) -> ThrottlerStatus {
        ThrottlerStatus {
            available_tokens: self.rate_limit.map_or(0.0, |rate_limit| {
                f64::from(rate_limit.requests_per_interval)
            }),
            max_tokens: self.rate_limit.map_or(0.0, |rate_limit| {
                f64::from(rate_limit.requests_per_interval)
            }),
            current_concurrency: 0,
            max_concurrency: self
                .concurrency_limit
                .map_or(0, |concurrency_limit| concurrency_limit.max_concurrent),
            circuit_state: ThrottlerCircuitState::Closed,
            consecutive_failures: 0,
        }
    }

    pub(super) fn initial_state(&self, now: i64) -> ThrottlerState {
        ThrottlerState {
            tokens: self.rate_limit.map_or(0.0, |rate_limit| {
                f64::from(rate_limit.requests_per_interval)
            }),
            last_refill_unix_microseconds: now,
            slots: BTreeMap::new(),
            consecutive_failures: 0,
            circuit_state: ThrottlerCircuitState::Closed,
            circuit_opened_at_unix_microseconds: None,
            probe_holder_id: None,
            probe_expires_at_unix_microseconds: None,
        }
    }

    pub(super) fn guard_for_permit(
        &self,
        pool: &Pool,
        permit: ThrottlerPermit,
    ) -> ThrottlerPermitGuard {
        let probe_heartbeat = self.start_probe_heartbeat_if_needed(pool, &permit);
        ThrottlerPermitGuard {
            throttler: Box::new(self.clone()),
            pool: pool.clone(),
            runtime_handle: RuntimeHandle::current(),
            permit: Some(permit),
            drop_outcome: ThrottlerTaskOutcome::NotExecuted,
            probe_heartbeat,
        }
    }

    pub(super) fn start_probe_heartbeat_if_needed(
        &self,
        pool: &Pool,
        permit: &ThrottlerPermit,
    ) -> Option<ThrottlerProbeHeartbeat> {
        if !permit.probe_acquired {
            return None;
        }

        let stop_heartbeat = Arc::new(AtomicBool::new(false));
        let stop_heartbeat_notify = Arc::new(Notify::new());
        let heartbeat_task = tokio::spawn(run_throttler_probe_heartbeat(
            self.clone(),
            pool.clone(),
            permit.clone(),
            Arc::clone(&stop_heartbeat),
            Arc::clone(&stop_heartbeat_notify),
        ));

        Some(ThrottlerProbeHeartbeat {
            stop_heartbeat,
            stop_heartbeat_notify,
            heartbeat_task,
        })
    }

    pub(super) fn needs_state_cleanup(&self, permit: &ThrottlerPermit) -> bool {
        (self.concurrency_limit.is_some() && permit.slot_suffix.is_some())
            || self.circuit_breaker.is_some()
    }

    pub(super) fn require_permit_matches_throttler(
        &self,
        permit: &ThrottlerPermit,
    ) -> Result<(), Error> {
        if permit.throttler_key != self.key {
            return Err(Error::ThrottlerPermitBelongsToDifferentThrottler);
        }
        Ok(())
    }
}
