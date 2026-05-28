use super::*;

impl MutexGuard {
    /// Returns whether this guard has detected that it no longer owns leadership.
    pub fn leadership_lost(&self) -> bool {
        self.leadership_lost.load(Ordering::SeqCst)
    }

    /// Waits until this guard detects that it no longer owns leadership.
    pub async fn wait_until_leadership_lost(&self) {
        loop {
            let notified = self.leadership_lost_notify.notified();
            if self.leadership_lost() {
                return;
            }
            notified.await;
        }
    }

    /// Returns a non-secret snapshot of the current live claim held by this guard.
    pub async fn live_claim_snapshot(&self) -> Option<MutexGuardSnapshot> {
        if self.leadership_lost() {
            return None;
        }
        self.current_claim
            .lock()
            .await
            .as_ref()
            .map(MutexManualRenewalClaim::guard_snapshot)
    }

    /// Releases the guarded mutex claim and stops the heartbeat loop.
    pub async fn release(mut self) -> Result<bool, Error> {
        self.try_release().await
    }

    /// Tries to release the guarded mutex claim while retaining retry authority on release failure.
    pub async fn try_release(&mut self) -> Result<bool, Error> {
        let release_result = self.release_current_claim().await;
        match release_result {
            Ok(released) => combine_mutex_guard_stop_and_release_results(
                self.stop_heartbeat_loop().await,
                Ok(released),
            ),
            Err(error) => Err(error),
        }
    }

    pub(super) async fn stop_heartbeat_and_take_current_claim(
        mut self,
    ) -> (
        Mutex,
        Pool,
        Option<MutexManualRenewalClaim>,
        Result<(), Error>,
    ) {
        let stop_result = self.stop_heartbeat_loop().await;
        let claim = self.current_claim.lock().await.take();
        (self.mutex.clone(), self.pool.clone(), claim, stop_result)
    }

    pub(super) async fn stop_heartbeat_loop(&mut self) -> Result<(), Error> {
        self.stop_heartbeat.store(true, Ordering::SeqCst);
        self.stop_heartbeat_notify.notify_waiters();
        if let Some(heartbeat_task) = self.heartbeat_task.take() {
            heartbeat_task
                .await
                .map_err(|source| Error::MutexHeartbeatTaskFailed { source })?;
        }
        Ok(())
    }

    pub(super) async fn release_current_claim(&self) -> Result<bool, Error> {
        let mut current_claim = self.current_claim.lock().await;
        let Some(claim) = current_claim.as_ref() else {
            return Ok(false);
        };
        let released = self
            .mutex
            .release_manual_renewal_claim(&self.pool, claim)
            .await?;
        current_claim.take();
        Ok(released)
    }
}

impl Drop for MutexGuard {
    fn drop(&mut self) {
        self.stop_heartbeat.store(true, Ordering::SeqCst);
        self.stop_heartbeat_notify.notify_waiters();

        let Some(heartbeat_task) = self.heartbeat_task.take() else {
            return;
        };
        let mutex = self.mutex.clone();
        let pool = self.pool.clone();
        let current_claim = Arc::clone(&self.current_claim);

        self.runtime_handle.spawn(async move {
            let _ = heartbeat_task.await;
            if let Some(claim) = current_claim.lock().await.take() {
                let _ = mutex.release_manual_renewal_claim(&pool, &claim).await;
            }
        });
    }
}

impl fmt::Debug for MutexGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutexGuard")
            .field("mutex_key", &self.mutex.key)
            .field("leadership_lost", &self.leadership_lost())
            .finish_non_exhaustive()
    }
}

impl MutexGuardSnapshot {
    /// Returns the mutex key.
    pub fn mutex_key(&self) -> &MutexKey {
        &self.mutex_key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        &self.holder_id
    }

    /// Returns this guard claim's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the guarded claim expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.expires_at_unix_microseconds
    }
}

pub(super) async fn run_mutex_guard_heartbeat(
    runtime: MutexHeartbeatRuntime,
    config: ResolvedMutexGuardConfig,
) {
    let mut consecutive_failures = 0_u32;

    loop {
        let sleep = tokio::time::sleep(config.heartbeat_interval);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = runtime.stop_heartbeat_notify.notified() => {
                if runtime.stop_heartbeat.load(Ordering::SeqCst) {
                    return;
                }
                continue;
            }
        }

        if runtime.stop_heartbeat.load(Ordering::SeqCst) {
            return;
        }

        let mut claim_guard = runtime.current_claim.lock().await;
        let Some(current_claim_ref) = claim_guard.as_ref() else {
            return;
        };

        match runtime
            .mutex
            .try_renew_manual_renewal_claim(&runtime.pool, current_claim_ref)
            .await
        {
            Ok(Some(renewed_claim)) => {
                *claim_guard = Some(renewed_claim);
                consecutive_failures = 0;
            }
            Ok(None) => {
                *claim_guard = None;
                mark_mutex_guard_lost(&runtime.leadership_lost, &runtime.leadership_lost_notify);
                return;
            }
            Err(_) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= config.max_consecutive_renewal_failures {
                    mark_mutex_guard_lost(
                        &runtime.leadership_lost,
                        &runtime.leadership_lost_notify,
                    );
                    return;
                }
            }
        }
    }
}

pub(super) fn mark_mutex_guard_lost(leadership_lost: &AtomicBool, leadership_lost_notify: &Notify) {
    if !leadership_lost.swap(true, Ordering::SeqCst) {
        leadership_lost_notify.notify_waiters();
    }
}

pub(super) fn send_stop_signal(stop_sender: &mut Option<oneshot::Sender<()>>) -> bool {
    match stop_sender.take() {
        Some(stop_sender) => stop_sender.send(()).is_ok(),
        None => false,
    }
}

pub(super) async fn run_task_once_under_mutex_guard<T, E, TaskFuture, Task>(
    guard: MutexGuard,
    task: Task,
) -> Result<T, MutexRunError<E>>
where
    TaskFuture: Future<Output = Result<T, E>>,
    Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
    E: std::error::Error + Send + Sync + 'static,
{
    let task_result = execute_task_while_mutex_guarded(&guard, task).await;
    let release_result = guard.release().await;
    combine_mutex_task_and_release_results(task_result, release_result)
}

pub(super) async fn execute_task_while_mutex_guarded<T, E, TaskFuture, Task>(
    guard: &MutexGuard,
    task: Task,
) -> Result<T, MutexRunError<E>>
where
    TaskFuture: Future<Output = Result<T, E>>,
    Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
    E: std::error::Error + Send + Sync + 'static,
{
    let Some(snapshot) = guard.live_claim_snapshot().await else {
        return Err(MutexRunError::LeadershipLost);
    };
    let value = task(snapshot)
        .await
        .map_err(|source| MutexRunError::Task { source })?;
    if guard.leadership_lost() {
        return Err(MutexRunError::LeadershipLost);
    }
    Ok(value)
}

#[allow(clippy::result_large_err)]
pub(super) fn combine_mutex_task_and_release_results<T, E>(
    task_result: Result<T, MutexRunError<E>>,
    release_result: Result<bool, Error>,
) -> Result<T, MutexRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match (task_result, release_result) {
        (Ok(value), Ok(true)) => Ok(value),
        (Ok(_), Ok(false)) => Err(MutexRunError::LeadershipLost),
        (Ok(_), Err(source)) => Err(MutexRunError::Release { source }),
        (Err(MutexRunError::Task { source }), Ok(false)) => {
            Err(MutexRunError::TaskAndLeadershipLost { source })
        }
        (Err(MutexRunError::Fleet(source)), Ok(false)) => {
            Err(MutexRunError::FleetAndLeadershipLost { source })
        }
        (Err(MutexRunError::Task { source }), Ok(true)) => Err(MutexRunError::Task { source }),
        (Err(MutexRunError::Task { source }), Err(release_error)) => {
            Err(MutexRunError::TaskAndRelease {
                source,
                release_error,
            })
        }
        (Err(MutexRunError::Fleet(source)), Err(release_error)) => {
            Err(MutexRunError::FleetAndRelease {
                source,
                release_error,
            })
        }
        (Err(MutexRunError::LeadershipLost), Err(release_error)) => {
            Err(MutexRunError::LeadershipLostAndRelease { release_error })
        }
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(_)) => Err(error),
    }
}

pub(super) fn combine_mutex_guard_stop_and_release_results(
    stop_result: Result<(), Error>,
    release_result: Result<bool, Error>,
) -> Result<bool, Error> {
    match (stop_result, release_result) {
        (Ok(()), Ok(released)) => Ok(released),
        (Ok(()), Err(release_error)) => Err(release_error),
        (Err(stop_error), Ok(_)) => Err(stop_error),
        (Err(stop_error), Err(release_error)) => Err(Error::MutexGuardStopAndReleaseFailed {
            stop_error: Box::new(stop_error),
            release_error: Box::new(release_error),
        }),
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn combine_cron_task_and_release_results<T, E>(
    task_result: Result<T, CronRunError<E>>,
    release_result: Result<bool, Error>,
) -> Result<T, CronRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match (task_result, release_result) {
        (Ok(value), Ok(true)) => Ok(value),
        (Ok(_), Ok(false)) => Err(CronRunError::LeadershipLost),
        (Ok(_), Err(source)) => Err(CronRunError::Release { source }),
        (Err(CronRunError::Task { source }), Ok(false)) => {
            Err(CronRunError::TaskAndLeadershipLost { source })
        }
        (Err(CronRunError::Fleet(source)), Ok(false)) => {
            Err(CronRunError::FleetAndLeadershipLost { source })
        }
        (Err(CronRunError::Task { source }), Ok(true)) => Err(CronRunError::Task { source }),
        (Err(CronRunError::Task { source }), Err(release_error)) => {
            Err(CronRunError::TaskAndRelease {
                source,
                release_error,
            })
        }
        (Err(CronRunError::Fleet(source)), Err(release_error)) => {
            Err(CronRunError::FleetAndRelease {
                source,
                release_error,
            })
        }
        (Err(CronRunError::LeadershipLost), Err(release_error)) => {
            Err(CronRunError::LeadershipLostAndRelease { release_error })
        }
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(_)) => Err(error),
    }
}

pub(super) fn require_coalescing_cache_mutex_released(
    release_result: Result<bool, Error>,
) -> Result<(), Error> {
    match release_result {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::CoalescingCacheComputeMutexLost),
        Err(error) => Err(error),
    }
}

pub(super) fn require_once_task_mutex_released(
    release_result: Result<bool, Error>,
) -> Result<(), Error> {
    match release_result {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::RunOnceManualRunClaimNoLongerLive),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    struct TestTaskError(&'static str);

    impl fmt::Display for TestTaskError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for TestTaskError {}

    #[test]
    fn mutex_task_and_release_combiner_preserves_both_failures_when_release_fails() {
        assert!(matches!(
            combine_mutex_task_and_release_results::<_, TestTaskError>(Ok(7), Ok(true)),
            Ok(7)
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<_, TestTaskError>(Ok(7), Ok(false)),
            Err(MutexRunError::LeadershipLost)
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<_, TestTaskError>(
                Ok(7),
                Err(Error::CoalescingCacheComputeMutexLost),
            ),
            Err(MutexRunError::Release {
                source: Error::CoalescingCacheComputeMutexLost
            })
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<(), _>(
                Err(MutexRunError::Task {
                    source: TestTaskError("task")
                }),
                Ok(false),
            ),
            Err(MutexRunError::TaskAndLeadershipLost {
                source: TestTaskError("task")
            })
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<(), _>(
                Err(MutexRunError::Task {
                    source: TestTaskError("task")
                }),
                Ok(true),
            ),
            Err(MutexRunError::Task {
                source: TestTaskError("task")
            })
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<(), _>(
                Err(MutexRunError::Task {
                    source: TestTaskError("task")
                }),
                Err(Error::CounterArithmeticOverflow),
            ),
            Err(MutexRunError::TaskAndRelease {
                source: TestTaskError("task"),
                release_error: Error::CounterArithmeticOverflow
            })
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<(), TestTaskError>(
                Err(MutexRunError::LeadershipLost),
                Err(Error::TopicSequenceOverflow),
            ),
            Err(MutexRunError::LeadershipLostAndRelease {
                release_error: Error::TopicSequenceOverflow
            })
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<(), TestTaskError>(
                Err(MutexRunError::Fleet(Error::InvalidThrottlerHasNoControls)),
                Ok(false),
            ),
            Err(MutexRunError::FleetAndLeadershipLost {
                source: Error::InvalidThrottlerHasNoControls
            })
        ));
        assert!(matches!(
            combine_mutex_task_and_release_results::<(), TestTaskError>(
                Err(MutexRunError::Fleet(Error::InvalidThrottlerHasNoControls)),
                Err(Error::CoalescingCacheComputeMutexLost),
            ),
            Err(MutexRunError::FleetAndRelease {
                source: Error::InvalidThrottlerHasNoControls,
                release_error: Error::CoalescingCacheComputeMutexLost
            })
        ));
    }

    #[test]
    fn cron_task_and_release_combiner_preserves_both_failures_when_release_fails() {
        assert!(matches!(
            combine_cron_task_and_release_results::<_, TestTaskError>(Ok(7), Ok(true)),
            Ok(7)
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<_, TestTaskError>(Ok(7), Ok(false)),
            Err(CronRunError::LeadershipLost)
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<_, TestTaskError>(
                Ok(7),
                Err(Error::CoalescingCacheComputeMutexLost),
            ),
            Err(CronRunError::Release {
                source: Error::CoalescingCacheComputeMutexLost
            })
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<(), _>(
                Err(CronRunError::Task {
                    source: TestTaskError("task")
                }),
                Ok(false),
            ),
            Err(CronRunError::TaskAndLeadershipLost {
                source: TestTaskError("task")
            })
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<(), _>(
                Err(CronRunError::Task {
                    source: TestTaskError("task")
                }),
                Ok(true),
            ),
            Err(CronRunError::Task {
                source: TestTaskError("task")
            })
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<(), _>(
                Err(CronRunError::Task {
                    source: TestTaskError("task")
                }),
                Err(Error::CounterArithmeticOverflow),
            ),
            Err(CronRunError::TaskAndRelease {
                source: TestTaskError("task"),
                release_error: Error::CounterArithmeticOverflow
            })
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<(), TestTaskError>(
                Err(CronRunError::LeadershipLost),
                Err(Error::TopicSequenceOverflow),
            ),
            Err(CronRunError::LeadershipLostAndRelease {
                release_error: Error::TopicSequenceOverflow
            })
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<(), TestTaskError>(
                Err(CronRunError::Fleet(Error::InvalidThrottlerHasNoControls)),
                Ok(false),
            ),
            Err(CronRunError::FleetAndLeadershipLost {
                source: Error::InvalidThrottlerHasNoControls
            })
        ));
        assert!(matches!(
            combine_cron_task_and_release_results::<(), TestTaskError>(
                Err(CronRunError::Fleet(Error::InvalidThrottlerHasNoControls)),
                Err(Error::CoalescingCacheComputeMutexLost),
            ),
            Err(CronRunError::FleetAndRelease {
                source: Error::InvalidThrottlerHasNoControls,
                release_error: Error::CoalescingCacheComputeMutexLost
            })
        ));
    }

    #[test]
    fn mutex_guard_stop_and_release_combiner_preserves_stop_and_release_failures() {
        assert!(matches!(
            combine_mutex_guard_stop_and_release_results(Ok(()), Ok(true)),
            Ok(true)
        ));
        assert!(matches!(
            combine_mutex_guard_stop_and_release_results(
                Ok(()),
                Err(Error::CoalescingCacheComputeMutexLost),
            ),
            Err(Error::CoalescingCacheComputeMutexLost)
        ));
        assert!(matches!(
            combine_mutex_guard_stop_and_release_results(
                Err(Error::CounterArithmeticOverflow),
                Ok(false),
            ),
            Err(Error::CounterArithmeticOverflow)
        ));
        assert!(matches!(
            combine_mutex_guard_stop_and_release_results(
                Err(Error::CounterArithmeticOverflow),
                Err(Error::CoalescingCacheComputeMutexLost),
            ),
            Err(Error::MutexGuardStopAndReleaseFailed {
                stop_error,
                release_error,
            }) if matches!(*stop_error, Error::CounterArithmeticOverflow)
                && matches!(*release_error, Error::CoalescingCacheComputeMutexLost)
        ));
    }
}
