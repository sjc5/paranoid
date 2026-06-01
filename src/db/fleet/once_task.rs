use super::*;

async fn rollback_transaction_and_release_after_task_error<T, E>(
    tx: WriteTx<'_>,
    guard: MutexGuard,
    source: E,
) -> Result<OnceRunTaskResult<T>, OnceTransactionalRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let rollback_result = tx.rollback().await.map_err(Error::from);
    let release_result = require_once_task_mutex_released(guard.release().await);
    match (rollback_result, release_result) {
        (Ok(()), Ok(())) => Err(OnceTransactionalRunError::Task { source }),
        (Ok(()), Err(release_error)) => Err(OnceTransactionalRunError::TaskAndRelease {
            source,
            release_error,
        }),
        (Err(rollback_error), Ok(())) => {
            Err(OnceTransactionalRunError::TaskAndTransactionRollback {
                source,
                rollback_error,
            })
        }
        (Err(rollback_error), Err(release_error)) => Err(
            OnceTransactionalRunError::TaskTransactionRollbackAndRelease {
                source,
                rollback_error,
                release_error,
            },
        ),
    }
}

async fn rollback_transaction_and_release_after_fleet_error<T, E>(
    tx: WriteTx<'_>,
    guard: MutexGuard,
    source: Error,
) -> Result<OnceRunTaskResult<T>, OnceTransactionalRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let rollback_result = tx.rollback().await.map_err(Error::from);
    let release_result = require_once_task_mutex_released(guard.release().await);
    match (rollback_result, release_result) {
        (Ok(()), Ok(())) => Err(OnceTransactionalRunError::Fleet(source)),
        (Ok(()), Err(release_error)) => Err(OnceTransactionalRunError::TransactionAndRelease {
            source,
            release_error,
        }),
        (Err(rollback_error), Ok(())) => Err(OnceTransactionalRunError::Fleet(rollback_error)),
        (Err(rollback_error), Err(release_error)) => {
            Err(OnceTransactionalRunError::TransactionAndRelease {
                source: rollback_error,
                release_error,
            })
        }
    }
}

async fn rollback_transaction_after_stopped_guard_without_claim<T, E>(
    tx: WriteTx<'_>,
    source: Error,
) -> Result<OnceRunTaskResult<T>, OnceTransactionalRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match tx.rollback().await.map_err(Error::from) {
        Ok(()) => Err(OnceTransactionalRunError::Fleet(source)),
        Err(rollback_error) => Err(OnceTransactionalRunError::Fleet(rollback_error)),
    }
}

async fn release_after_completed_atomic_once_transaction(
    mutex: &Mutex,
    pool: &WritePool,
    renewed_claim: &MutexManualRenewalClaim,
) -> Result<(), Error> {
    require_once_task_mutex_released(
        mutex
            .release_manual_renewal_claim(pool, renewed_claim)
            .await,
    )
}

async fn release_after_failed_atomic_once_transaction(
    mutex: &Mutex,
    pool: &WritePool,
    renewed_claim: &MutexManualRenewalClaim,
    original_claim: &MutexManualRenewalClaim,
) -> Result<(), Error> {
    if mutex
        .release_manual_renewal_claim(pool, renewed_claim)
        .await
        .is_ok_and(|released| released)
    {
        return Ok(());
    }
    require_once_task_mutex_released(
        mutex
            .release_manual_renewal_claim(pool, original_claim)
            .await,
    )
}

impl Once {
    pub(super) async fn run_task_after_acquiring_guard<T, E, TaskFuture, Task>(
        &self,
        pool: &WritePool,
        guard: MutexGuard,
        task: Task,
    ) -> Result<OnceRunTaskResult<T>, OnceRunError<E>>
    where
        TaskFuture: Future<Output = Result<T, E>>,
        Task: FnOnce(OnceRunClaimSnapshot) -> TaskFuture,
        E: std::error::Error + Send + Sync + 'static,
    {
        if let Some(completion) = self.check_done(pool).await? {
            require_once_task_mutex_released(guard.release().await)?;
            return Ok(OnceRunTaskResult::AlreadyDone(completion));
        }

        let Some(mutex_snapshot) = guard.live_claim_snapshot().await else {
            require_once_task_mutex_released(guard.release().await)?;
            return Err(Error::RunOnceManualRunClaimNoLongerLive.into());
        };
        let snapshot = self.snapshot_from_mutex_guard_snapshot(mutex_snapshot);

        let task_result = task(snapshot.clone()).await;
        let value = match task_result {
            Ok(value) => value,
            Err(source) => {
                return match require_once_task_mutex_released(guard.release().await) {
                    Ok(()) => Err(OnceRunError::Task { source }),
                    Err(release_error) => Err(OnceRunError::TaskAndRelease {
                        source,
                        release_error,
                    }),
                };
            }
        };

        let completion_result = if guard.leadership_lost() {
            Err(Error::RunOnceManualRunClaimNoLongerLive)
        } else {
            self.mark_completion(pool, &snapshot)
                .await
                .and_then(|marked| {
                    if marked {
                        Ok(())
                    } else {
                        Err(Error::RunOnceCompletionAlreadyRecordedAfterStart)
                    }
                })
        };
        let release_result = require_once_task_mutex_released(guard.release().await);

        match (completion_result, release_result) {
            (Ok(()), Ok(())) => Ok(OnceRunTaskResult::Ran(value)),
            (Ok(()), Err(source)) => Err(OnceRunError::Release { source }),
            (Err(source), Ok(())) => Err(OnceRunError::TaskSucceededButCompletionFailed { source }),
            (Err(source), Err(release_error)) => {
                Err(OnceRunError::TaskSucceededButCompletionAndReleaseFailed {
                    source,
                    release_error,
                })
            }
        }
    }

    pub(super) async fn run_task_atomically_after_acquiring_guard<T, E, Task>(
        &self,
        pool: &WritePool,
        guard: MutexGuard,
        task: Task,
    ) -> Result<OnceRunTaskResult<T>, OnceTransactionalRunError<E>>
    where
        Task: for<'a, 'tx> FnOnce(
            OnceRunClaimSnapshot,
            &'a mut WriteTx<'tx>,
        ) -> OnceTransactionalTaskFuture<'a, T, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut tx = pool.begin_transaction().await.map_err(Error::from)?;
        if let Some(completion) = self.check_done_in_current_transaction(&mut tx).await? {
            let rollback_result = tx.rollback().await.map_err(Error::from);
            let release_result = require_once_task_mutex_released(guard.release().await);
            return match (rollback_result, release_result) {
                (Ok(()), Ok(())) => Ok(OnceRunTaskResult::AlreadyDone(completion)),
                (Ok(()), Err(source)) => Err(OnceTransactionalRunError::Release { source }),
                (Err(source), Ok(())) => Err(OnceTransactionalRunError::Fleet(source)),
                (Err(source), Err(release_error)) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source,
                        release_error,
                    })
                }
            };
        }

        let Some(mutex_snapshot) = guard.live_claim_snapshot().await else {
            return rollback_transaction_and_release_after_fleet_error(
                tx,
                guard,
                Error::RunOnceManualRunClaimNoLongerLive,
            )
            .await;
        };
        let snapshot = self.snapshot_from_mutex_guard_snapshot(mutex_snapshot);

        let task_result = task(snapshot, &mut tx).await;
        let value = match task_result {
            Ok(value) => value,
            Err(source) => {
                return rollback_transaction_and_release_after_task_error(tx, guard, source).await;
            }
        };

        let (mutex, release_pool, current_claim, stop_result) =
            guard.stop_heartbeat_and_take_current_claim().await;
        if let Err(source) = stop_result {
            let rollback_result = tx.rollback().await.map_err(Error::from);
            let release_result = match current_claim.as_ref() {
                Some(claim) => require_once_task_mutex_released(
                    mutex
                        .release_manual_renewal_claim(&release_pool, claim)
                        .await,
                ),
                None => Ok(()),
            };
            return match (rollback_result, release_result) {
                (Ok(()), Ok(())) => Err(OnceTransactionalRunError::Fleet(source)),
                (Ok(()), Err(release_error)) | (Err(release_error), Ok(())) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source,
                        release_error,
                    })
                }
                (Err(rollback_error), Err(release_error)) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source: rollback_error,
                        release_error,
                    })
                }
            };
        }
        let Some(current_claim) = current_claim else {
            return rollback_transaction_after_stopped_guard_without_claim(
                tx,
                Error::RunOnceManualRunClaimNoLongerLive,
            )
            .await;
        };
        let Some(renewed_claim) = mutex
            .try_renew_manual_renewal_claim_in_current_transaction(&mut tx, &current_claim)
            .await?
        else {
            let source = Error::RunOnceManualRunClaimNoLongerLive;
            let rollback_result = tx.rollback().await.map_err(Error::from);
            let release_result = require_once_task_mutex_released(
                mutex
                    .release_manual_renewal_claim(&release_pool, &current_claim)
                    .await,
            );
            return match (rollback_result, release_result) {
                (Ok(()), Ok(())) => Err(OnceTransactionalRunError::Fleet(source)),
                (Ok(()), Err(release_error)) | (Err(release_error), Ok(())) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source,
                        release_error,
                    })
                }
                (Err(rollback_error), Err(release_error)) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source: rollback_error,
                        release_error,
                    })
                }
            };
        };

        let marked_done = self
            .mark_completion_in_current_transaction(
                &mut tx,
                renewed_claim.holder_id().as_str().to_owned(),
                renewed_claim.fencing_token().as_i64(),
            )
            .await?;
        if !marked_done {
            let source = Error::RunOnceCompletionAlreadyRecordedAfterStart;
            let rollback_result = tx.rollback().await.map_err(Error::from);
            let release_result = release_after_failed_atomic_once_transaction(
                &mutex,
                &release_pool,
                &renewed_claim,
                &current_claim,
            )
            .await;
            return match (rollback_result, release_result) {
                (Ok(()), Ok(())) => Err(OnceTransactionalRunError::Fleet(source)),
                (Ok(()), Err(release_error)) | (Err(release_error), Ok(())) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source,
                        release_error,
                    })
                }
                (Err(rollback_error), Err(release_error)) => {
                    Err(OnceTransactionalRunError::TransactionAndRelease {
                        source: rollback_error,
                        release_error,
                    })
                }
            };
        }

        let commit_result = tx.commit().await.map_err(Error::from);
        match commit_result {
            Ok(()) => {
                release_after_completed_atomic_once_transaction(
                    &mutex,
                    &release_pool,
                    &renewed_claim,
                )
                .await
                .map_err(|source| OnceTransactionalRunError::Release { source })?;
                Ok(OnceRunTaskResult::Ran(value))
            }
            Err(source) => {
                let release_result = release_after_failed_atomic_once_transaction(
                    &mutex,
                    &release_pool,
                    &renewed_claim,
                    &current_claim,
                )
                .await;
                match release_result {
                    Ok(()) => Err(OnceTransactionalRunError::Fleet(source)),
                    Err(release_error) => Err(OnceTransactionalRunError::TransactionAndRelease {
                        source,
                        release_error,
                    }),
                }
            }
        }
    }
}
