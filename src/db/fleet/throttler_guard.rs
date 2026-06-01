use super::*;

impl ThrottlerPermit {
    /// Returns the throttler key.
    pub fn throttler_key(&self) -> &ThrottlerKey {
        &self.throttler_key
    }

    /// Returns the holder identifier when this permit needs one.
    pub fn holder_id(&self) -> Option<&HolderId> {
        self.holder_id.as_ref()
    }

    /// Returns the concurrency slot suffix when this permit holds one.
    pub fn slot_suffix(&self) -> Option<&str> {
        self.slot_suffix.as_deref()
    }

    /// Reports whether this permit reserved a half-open circuit probe.
    pub fn probe_acquired(&self) -> bool {
        self.probe_acquired
    }
}

impl ThrottlerPermitGuard {
    /// Returns the permit while the guard still owns it.
    pub fn live_permit(&self) -> Option<&ThrottlerPermit> {
        self.permit.as_ref()
    }

    /// Runs a task and releases the guard according to the task result.
    pub async fn run_task<T, E, Fut, F>(mut self, task: F) -> ThrottlerGuardedTaskResult<T, E>
    where
        Fut: Future<Output = Result<T, E>>,
        F: FnOnce(ThrottlerPermit) -> Fut,
    {
        let Some(permit) = self.permit.clone() else {
            unreachable!("ThrottlerPermitGuard cannot run a task after consuming release")
        };
        self.drop_outcome = ThrottlerTaskOutcome::Failed;

        match task(permit).await {
            Ok(value) => {
                let release_result = self
                    .release_live_permit_after_task_outcome(ThrottlerTaskOutcome::Succeeded)
                    .await;
                ThrottlerGuardedTaskResult::Succeeded {
                    value,
                    release_result,
                }
            }
            Err(error) => {
                let release_result = self
                    .release_live_permit_after_task_outcome(ThrottlerTaskOutcome::Failed)
                    .await;
                ThrottlerGuardedTaskResult::Failed {
                    error,
                    release_result,
                }
            }
        }
    }

    /// Releases the guarded permit after a successful task.
    pub async fn release_after_success(mut self) -> Result<ThrottlerReleaseResult, Error> {
        self.release_live_permit_after_task_outcome(ThrottlerTaskOutcome::Succeeded)
            .await
    }

    /// Releases the guarded permit after a failed task.
    pub async fn release_after_failure(mut self) -> Result<ThrottlerReleaseResult, Error> {
        self.release_live_permit_after_task_outcome(ThrottlerTaskOutcome::Failed)
            .await
    }

    /// Releases the guarded permit without recording task outcome.
    pub async fn release_without_task_outcome(mut self) -> Result<ThrottlerReleaseResult, Error> {
        self.release_live_permit_after_task_outcome(ThrottlerTaskOutcome::NotExecuted)
            .await
    }

    /// Releases the guarded permit and records task outcome.
    pub async fn release_after_task_outcome(
        mut self,
        outcome: ThrottlerTaskOutcome,
    ) -> Result<ThrottlerReleaseResult, Error> {
        self.release_live_permit_after_task_outcome(outcome).await
    }

    pub(super) async fn release_live_permit_after_task_outcome(
        &mut self,
        outcome: ThrottlerTaskOutcome,
    ) -> Result<ThrottlerReleaseResult, Error> {
        let Some(permit) = self.permit.as_ref() else {
            self.stop_probe_heartbeat().await?;
            return Ok(ThrottlerReleaseResult::default());
        };
        self.drop_outcome = outcome;
        let result = self
            .throttler
            .release_manual_permit_after_task_outcome(&self.pool, permit, outcome)
            .await?;
        self.permit = None;
        self.stop_probe_heartbeat().await?;
        Ok(result)
    }

    pub(super) async fn stop_probe_heartbeat(&mut self) -> Result<(), Error> {
        let Some(probe_heartbeat) = self.probe_heartbeat.take() else {
            return Ok(());
        };
        stop_throttler_probe_heartbeat(probe_heartbeat).await
    }
}

impl Drop for ThrottlerPermitGuard {
    fn drop(&mut self) {
        let probe_heartbeat = self.probe_heartbeat.take();
        let Some(permit) = self.permit.take() else {
            if let Some(probe_heartbeat) = probe_heartbeat {
                self.runtime_handle.spawn(async move {
                    let _ = stop_throttler_probe_heartbeat(probe_heartbeat).await;
                });
            }
            return;
        };
        let throttler = self.throttler.clone();
        let pool = self.pool.clone();
        let outcome = self.drop_outcome;
        self.runtime_handle.spawn(async move {
            let _ = throttler
                .release_manual_permit_after_task_outcome(&pool, &permit, outcome)
                .await;
            if let Some(probe_heartbeat) = probe_heartbeat {
                let _ = stop_throttler_probe_heartbeat(probe_heartbeat).await;
            }
        });
    }
}

async fn stop_throttler_probe_heartbeat(
    probe_heartbeat: ThrottlerProbeHeartbeat,
) -> Result<(), Error> {
    probe_heartbeat.stop_heartbeat.store(true, Ordering::SeqCst);
    probe_heartbeat.stop_heartbeat_notify.notify_waiters();
    probe_heartbeat
        .heartbeat_task
        .await
        .map_err(|source| Error::ThrottlerProbeHeartbeatTaskFailed { source })
}

pub(super) async fn run_throttler_probe_heartbeat(
    throttler: Throttler,
    pool: WritePool,
    permit: ThrottlerPermit,
    stop_heartbeat: Arc<AtomicBool>,
    stop_heartbeat_notify: Arc<Notify>,
) {
    let mut consecutive_failures = 0_u32;

    loop {
        let sleep = tokio::time::sleep(DEFAULT_FLEET_THROTTLER_PROBE_HEARTBEAT_INTERVAL);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = stop_heartbeat_notify.notified() => {
                if stop_heartbeat.load(Ordering::SeqCst) {
                    return;
                }
                continue;
            }
        }

        if stop_heartbeat.load(Ordering::SeqCst) {
            return;
        }

        match throttler.extend_probe_reservation(&pool, &permit).await {
            Ok(true) => {
                consecutive_failures = 0;
            }
            Ok(false) => return,
            Err(_) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures
                    >= DEFAULT_FLEET_THROTTLER_PROBE_MAX_CONSECUTIVE_HEARTBEAT_FAILURES
                {
                    return;
                }
            }
        }
    }
}

impl fmt::Debug for ThrottlerPermitGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrottlerPermitGuard")
            .field("permit", &self.permit)
            .field("drop_outcome", &self.drop_outcome)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_throttler_probe_heartbeat_signals_and_waits_for_task_completion() {
        let stop_heartbeat = Arc::new(AtomicBool::new(false));
        let stop_heartbeat_notify = Arc::new(Notify::new());
        let task_observed_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_task = tokio::spawn({
            let stop_heartbeat = Arc::clone(&stop_heartbeat);
            let stop_heartbeat_notify = Arc::clone(&stop_heartbeat_notify);
            let task_observed_stop = Arc::clone(&task_observed_stop);
            async move {
                loop {
                    if stop_heartbeat.load(Ordering::SeqCst) {
                        task_observed_stop.store(true, Ordering::SeqCst);
                        return;
                    }
                    stop_heartbeat_notify.notified().await;
                    if stop_heartbeat.load(Ordering::SeqCst) {
                        task_observed_stop.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            }
        });

        stop_throttler_probe_heartbeat(ThrottlerProbeHeartbeat {
            stop_heartbeat,
            stop_heartbeat_notify,
            heartbeat_task,
        })
        .await
        .expect("stop heartbeat");

        assert!(task_observed_stop.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stop_throttler_probe_heartbeat_reports_task_join_errors() {
        let heartbeat_task = tokio::spawn(std::future::pending::<()>());
        heartbeat_task.abort();

        let error = stop_throttler_probe_heartbeat(ThrottlerProbeHeartbeat {
            stop_heartbeat: Arc::new(AtomicBool::new(false)),
            stop_heartbeat_notify: Arc::new(Notify::new()),
            heartbeat_task,
        })
        .await
        .expect_err("heartbeat join error should be reported");

        assert!(
            matches!(error, Error::ThrottlerProbeHeartbeatTaskFailed { .. }),
            "error = {error:?}"
        );
    }
}
