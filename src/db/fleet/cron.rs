use super::*;
use std::pin::Pin;

impl Cron {
    /// Returns this cron's key.
    pub fn key(&self) -> &CronKey {
        &self.key
    }

    /// Returns this cron's task interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Returns this cron's leadership claim duration.
    pub fn claim_duration(&self) -> ClaimDuration {
        self.mutex.claim_duration()
    }

    /// Fetches the current live leader without exposing release or renewal authority.
    pub async fn fetch_live_leader(
        &self,
        pool: &Pool,
    ) -> Result<Option<MutexHolderSnapshot>, Error> {
        self.mutex.fetch_live_holder(pool).await
    }

    /// Attempts to run the task once without waiting for leadership.
    pub async fn try_run_once<T, E, TaskFuture, Task>(
        &self,
        pool: &Pool,
        task: Task,
    ) -> Result<CronTryRunOnceResult<T>, CronRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let Some(guard) = self
            .mutex
            .try_claim_guard(pool, self.guard_config)
            .await
            .map_err(CronRunError::Fleet)?
        else {
            return Ok(CronTryRunOnceResult::LeadershipHeld);
        };

        self.run_task_once_under_guard(guard, task)
            .await
            .map(CronTryRunOnceResult::Ran)
    }

    /// Runs the task once, waiting until leadership is available.
    pub async fn run_once<T, E, TaskFuture, Task>(
        &self,
        pool: &Pool,
        task: Task,
    ) -> Result<T, CronRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let guard = self
            .mutex
            .claim_guard_when_available(pool, self.guard_config)
            .await
            .map_err(CronRunError::Fleet)?;
        self.run_task_once_under_guard(guard, task).await
    }

    /// Runs the task immediately and then every interval while leadership is held, until `stop` resolves or the task fails.
    pub async fn run_until_stopped_or_task_error<Stop, E, TaskFuture, Task>(
        &self,
        pool: &Pool,
        stop: Stop,
        task: Task,
    ) -> Result<(), CronRunError<E>>
    where
        Stop: Future<Output = ()>,
        TaskFuture: Future<Output = Result<(), E>>,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.run_until_stopped_with_task_error_policy(pool, stop, task, |_| {
            CronTaskErrorAction::Stop
        })
        .await
    }

    /// Starts a background task that runs this cron until stopped, leadership is lost, or the task fails.
    pub fn start_until_stopped_or_task_error<E, TaskFuture, Task>(
        &self,
        pool: Pool,
        task: Task,
    ) -> CronRunHandle<E>
    where
        TaskFuture: Future<Output = Result<(), E>> + Send + 'static,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let cron = <Cron as Clone>::clone(self);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            cron.run_until_stopped_or_task_error(
                &pool,
                async move {
                    let _ = stop_receiver.await;
                },
                task,
            )
            .await
        });
        CronRunHandle {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
        }
    }

    /// Runs the task immediately and then every interval while leadership is held, applying an explicit task-error policy.
    pub async fn run_until_stopped_with_task_error_policy<Stop, E, TaskFuture, Task, OnTaskError>(
        &self,
        pool: &Pool,
        stop: Stop,
        mut task: Task,
        mut on_task_error: OnTaskError,
    ) -> Result<(), CronRunError<E>>
    where
        Stop: Future<Output = ()>,
        TaskFuture: Future<Output = Result<(), E>>,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture,
        OnTaskError: FnMut(&E) -> CronTaskErrorAction,
        E: std::error::Error + Send + Sync + 'static,
    {
        tokio::pin!(stop);
        match self
            .run_single_leadership_tenure_until_stopped_with_task_error_policy(
                pool,
                stop.as_mut(),
                &mut task,
                &mut on_task_error,
            )
            .await?
        {
            CronLeadershipTenureOutcome::StopRequested => Ok(()),
            CronLeadershipTenureOutcome::LeadershipLost => Err(CronRunError::LeadershipLost),
        }
    }

    /// Runs the task on this process whenever it holds leadership, reacquiring leadership after benign loss until stopped or the task fails.
    pub async fn run_continuously_until_stopped_or_task_error<Stop, E, TaskFuture, Task>(
        &self,
        pool: &Pool,
        stop: Stop,
        task: Task,
    ) -> Result<(), CronRunError<E>>
    where
        Stop: Future<Output = ()>,
        TaskFuture: Future<Output = Result<(), E>>,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.run_continuously_until_stopped_with_task_error_policy(pool, stop, task, |_| {
            CronTaskErrorAction::Stop
        })
        .await
    }

    /// Runs the task on this process whenever it holds leadership, reacquiring leadership after benign loss and applying an explicit task-error policy.
    pub async fn run_continuously_until_stopped_with_task_error_policy<
        Stop,
        E,
        TaskFuture,
        Task,
        OnTaskError,
    >(
        &self,
        pool: &Pool,
        stop: Stop,
        mut task: Task,
        mut on_task_error: OnTaskError,
    ) -> Result<(), CronRunError<E>>
    where
        Stop: Future<Output = ()>,
        TaskFuture: Future<Output = Result<(), E>>,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture,
        OnTaskError: FnMut(&E) -> CronTaskErrorAction,
        E: std::error::Error + Send + Sync + 'static,
    {
        tokio::pin!(stop);
        loop {
            match self
                .run_single_leadership_tenure_until_stopped_with_task_error_policy(
                    pool,
                    stop.as_mut(),
                    &mut task,
                    &mut on_task_error,
                )
                .await?
            {
                CronLeadershipTenureOutcome::StopRequested => return Ok(()),
                CronLeadershipTenureOutcome::LeadershipLost => {
                    let reacquire_delay = fleet_mutex_acquire_retry_delay_with_jitter(
                        self.guard_config
                            .acquire_retry_interval
                            .unwrap_or(DEFAULT_FLEET_MUTEX_ACQUIRE_RETRY_INTERVAL),
                    )
                    .map_err(CronRunError::Fleet)?;
                    tokio::select! {
                        () = stop.as_mut() => return Ok(()),
                        () = tokio::time::sleep(reacquire_delay) => {}
                    }
                }
            }
        }
    }

    /// Starts a background task that continuously reacquires leadership until stopped or the task fails.
    pub fn start_continuously_until_stopped_or_task_error<E, TaskFuture, Task>(
        &self,
        pool: Pool,
        task: Task,
    ) -> CronRunHandle<E>
    where
        TaskFuture: Future<Output = Result<(), E>> + Send + 'static,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let cron = <Cron as Clone>::clone(self);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            cron.run_continuously_until_stopped_or_task_error(
                &pool,
                async move {
                    let _ = stop_receiver.await;
                },
                task,
            )
            .await
        });
        CronRunHandle {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
        }
    }

    /// Starts a background task that continuously reacquires leadership and applies an explicit task-error policy.
    pub fn start_continuously_until_stopped_with_task_error_policy<
        E,
        TaskFuture,
        Task,
        OnTaskError,
    >(
        &self,
        pool: Pool,
        task: Task,
        on_task_error: OnTaskError,
    ) -> CronRunHandle<E>
    where
        TaskFuture: Future<Output = Result<(), E>> + Send + 'static,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture + Send + 'static,
        OnTaskError: FnMut(&E) -> CronTaskErrorAction + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let cron = <Cron as Clone>::clone(self);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            cron.run_continuously_until_stopped_with_task_error_policy(
                &pool,
                async move {
                    let _ = stop_receiver.await;
                },
                task,
                on_task_error,
            )
            .await
        });
        CronRunHandle {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
        }
    }

    async fn run_single_leadership_tenure_until_stopped_with_task_error_policy<
        Stop,
        E,
        TaskFuture,
        Task,
        OnTaskError,
    >(
        &self,
        pool: &Pool,
        mut stop: Pin<&mut Stop>,
        task: &mut Task,
        on_task_error: &mut OnTaskError,
    ) -> Result<CronLeadershipTenureOutcome, CronRunError<E>>
    where
        Stop: Future<Output = ()>,
        TaskFuture: Future<Output = Result<(), E>>,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture,
        OnTaskError: FnMut(&E) -> CronTaskErrorAction,
        E: std::error::Error + Send + Sync + 'static,
    {
        let guard = loop {
            let acquire_result = tokio::select! {
                () = stop.as_mut() => return Ok(CronLeadershipTenureOutcome::StopRequested),
                acquire_result = self.mutex.claim_guard_when_available(pool, self.guard_config) => {
                    acquire_result
                }
            };
            match acquire_result {
                Ok(guard) => break guard,
                Err(error) if is_retryable_cron_leadership_acquire_error(&error) => {
                    let retry_delay = fleet_mutex_acquire_retry_delay_with_jitter(
                        self.guard_config
                            .acquire_retry_interval
                            .unwrap_or(DEFAULT_FLEET_MUTEX_ACQUIRE_RETRY_INTERVAL),
                    )
                    .map_err(CronRunError::Fleet)?;
                    tokio::select! {
                        () = stop.as_mut() => return Ok(CronLeadershipTenureOutcome::StopRequested),
                        () = tokio::time::sleep(retry_delay) => {}
                    }
                }
                Err(error) => return Err(CronRunError::Fleet(error)),
            }
        };

        loop {
            match self.execute_task_while_guarded(&guard, &mut *task).await {
                Ok(()) => {}
                Err(CronRunError::Task { source }) => {
                    let action = on_task_error(&source);
                    if action == CronTaskErrorAction::Stop {
                        let release_result = guard.release().await;
                        return combine_cron_task_and_release_results(
                            Err(CronRunError::Task { source }),
                            release_result,
                        );
                    }
                    if guard.leadership_lost() {
                        return release_cron_guard_after_leadership_lost(guard.release().await);
                    }
                }
                Err(CronRunError::LeadershipLost) => {
                    return release_cron_guard_after_leadership_lost(guard.release().await);
                }
                Err(error) => {
                    let release_result = guard.release().await;
                    return combine_cron_task_and_release_results::<(), E>(
                        Err(error),
                        release_result,
                    )
                    .map(|()| CronLeadershipTenureOutcome::LeadershipLost);
                }
            }

            let sleep = tokio::time::sleep(self.interval);
            tokio::pin!(sleep);
            tokio::select! {
                () = stop.as_mut() => {
                    guard.release().await.map_err(|source| CronRunError::Release { source })?;
                    return Ok(CronLeadershipTenureOutcome::StopRequested);
                }
                () = guard.wait_until_leadership_lost() => {
                    return release_cron_guard_after_leadership_lost(guard.release().await);
                }
                () = &mut sleep => {}
            }
        }
    }

    /// Starts a background task that applies an explicit task-error policy while this cron holds leadership.
    pub fn start_until_stopped_with_task_error_policy<E, TaskFuture, Task, OnTaskError>(
        &self,
        pool: Pool,
        task: Task,
        on_task_error: OnTaskError,
    ) -> CronRunHandle<E>
    where
        TaskFuture: Future<Output = Result<(), E>> + Send + 'static,
        Task: FnMut(MutexGuardSnapshot) -> TaskFuture + Send + 'static,
        OnTaskError: FnMut(&E) -> CronTaskErrorAction + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let cron = <Cron as Clone>::clone(self);
        let (stop_sender, stop_receiver) = oneshot::channel();
        let join_handle = tokio::spawn(async move {
            cron.run_until_stopped_with_task_error_policy(
                &pool,
                async move {
                    let _ = stop_receiver.await;
                },
                task,
                on_task_error,
            )
            .await
        });
        CronRunHandle {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
        }
    }

    async fn run_task_once_under_guard<T, E, TaskFuture, Task>(
        &self,
        guard: MutexGuard,
        task: Task,
    ) -> Result<T, CronRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let task_result = self.execute_task_while_guarded(&guard, task).await;
        let release_result = guard.release().await;
        combine_cron_task_and_release_results(task_result, release_result)
    }

    async fn execute_task_while_guarded<T, E, TaskFuture, Task>(
        &self,
        guard: &MutexGuard,
        task: Task,
    ) -> Result<T, CronRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(MutexGuardSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        let Some(snapshot) = guard.live_claim_snapshot().await else {
            return Err(CronRunError::LeadershipLost);
        };
        let value = task(snapshot)
            .await
            .map_err(|source| CronRunError::Task { source })?;
        if guard.leadership_lost() {
            return Err(CronRunError::LeadershipLost);
        }
        Ok(value)
    }
}

fn release_cron_guard_after_leadership_lost<E>(
    release_result: Result<bool, Error>,
) -> Result<CronLeadershipTenureOutcome, CronRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match release_result {
        Ok(_) => Ok(CronLeadershipTenureOutcome::LeadershipLost),
        Err(release_error) => Err(CronRunError::LeadershipLostAndRelease { release_error }),
    }
}

fn is_retryable_cron_leadership_acquire_error(error: &Error) -> bool {
    match error {
        Error::Database(source) | Error::Coordination(CoordinationError::Database(source)) => {
            is_retryable_database_operation_error(source)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database_query_error(sql_state: Option<PgSqlState>) -> DbError {
        DbError::Query {
            sql_state,
            source: Box::new(std::io::Error::other("query error")),
        }
    }

    fn database_transaction_error() -> DbError {
        DbError::Transaction {
            source: Box::new(std::io::Error::other("transaction error")),
        }
    }

    #[test]
    fn cron_leadership_acquire_retries_database_shaped_transient_failures_only() {
        assert!(is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(database_transaction_error()))
        ));
        assert!(is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(database_query_error(Some(
                PgSqlState::SerializationFailure,
            ))))
        ));
        assert!(is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(database_query_error(Some(
                PgSqlState::DeadlockDetected,
            ))))
        ));
        assert!(is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(database_query_error(Some(
                PgSqlState::Other("08006".to_owned()),
            ))))
        ));
        assert!(is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(database_query_error(None)))
        ));

        assert!(!is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(database_query_error(Some(
                PgSqlState::Other("42P01".to_owned()),
            ))))
        ));
        assert!(!is_retryable_cron_leadership_acquire_error(
            &Error::Coordination(CoordinationError::Database(DbError::schema_mismatch(
                "schema mismatch"
            )))
        ));
        assert!(!is_retryable_cron_leadership_acquire_error(
            &Error::InvalidMutexAcquireRetryInterval
        ));
    }

    #[test]
    fn cron_leadership_lost_release_helper_preserves_release_failure() {
        let ok_result = release_cron_guard_after_leadership_lost::<std::io::Error>(Ok(false))
            .expect("lost leadership without release error");
        assert_eq!(ok_result, CronLeadershipTenureOutcome::LeadershipLost);

        let error = release_cron_guard_after_leadership_lost::<std::io::Error>(Err(
            Error::CounterArithmeticOverflow,
        ))
        .expect_err("release error should be preserved");
        assert!(matches!(
            error,
            CronRunError::LeadershipLostAndRelease {
                release_error: Error::CounterArithmeticOverflow,
            }
        ));
    }
}
