use super::*;

impl WorkerRunOnceSummary {
    pub(in crate::db::queue) fn record_processed_job_outcome(
        &mut self,
        outcome: ProcessedJobOutcome,
    ) {
        match outcome {
            ProcessedJobOutcome::Succeeded => self.succeeded_count += 1,
            ProcessedJobOutcome::Retried => self.retried_count += 1,
            ProcessedJobOutcome::Failed => self.failed_count += 1,
            ProcessedJobOutcome::DeadLettered => self.dead_lettered_count += 1,
            ProcessedJobOutcome::LostOwnership => self.lost_ownership_count += 1,
        }
    }
}

impl WorkerRunLoopSummary {
    pub(in crate::db::queue) fn record_claimed_count(
        &mut self,
        claimed_count: usize,
    ) -> Result<(), Error> {
        let claimed_count: u32 =
            claimed_count
                .try_into()
                .map_err(|_| Error::UnexpectedOutcome {
                    operation: "queue worker run loop",
                    outcome: "claimed more jobs than fit in u32".to_owned(),
                })?;
        self.claimed_count = self
            .claimed_count
            .checked_add(claimed_count)
            .ok_or_else(|| Error::UnexpectedOutcome {
                operation: "queue worker run loop",
                outcome: "claimed job count overflowed".to_owned(),
            })?;
        Ok(())
    }

    pub(in crate::db::queue) fn record_processed_job_outcome(
        &mut self,
        outcome: ProcessedJobOutcome,
    ) -> Result<(), Error> {
        let counter = match outcome {
            ProcessedJobOutcome::Succeeded => &mut self.succeeded_count,
            ProcessedJobOutcome::Retried => &mut self.retried_count,
            ProcessedJobOutcome::Failed => &mut self.failed_count,
            ProcessedJobOutcome::DeadLettered => &mut self.dead_lettered_count,
            ProcessedJobOutcome::LostOwnership => &mut self.lost_ownership_count,
        };
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::UnexpectedOutcome {
                operation: "queue worker run loop",
                outcome: "processed job count overflowed".to_owned(),
            })?;
        Ok(())
    }
}

impl WorkerHandle {
    /// Requests graceful worker shutdown. Returns true if shutdown had not already been requested.
    pub fn request_stop(&self) -> bool {
        self.worker_shutdown_signal.request_cancellation()
    }

    /// Returns whether the worker task has finished.
    pub fn is_finished(&self) -> bool {
        match self.join_handle.as_ref() {
            Some(join_handle) => join_handle.is_finished(),
            None => true,
        }
    }

    /// Waits for the worker task to finish.
    pub async fn wait(mut self) -> Result<WorkerRunLoopSummary, Error> {
        let Some(join_handle) = self.join_handle.take() else {
            return Err(Error::UnexpectedOutcome {
                operation: "queue worker handle wait",
                outcome: "worker join handle was already consumed".to_owned(),
            });
        };
        queue_worker_run_loop_result_from_join_result(join_handle.await)
    }

    /// Requests graceful worker shutdown, then waits for the worker task to finish.
    pub async fn stop_and_wait(self) -> Result<WorkerRunLoopSummary, Error> {
        self.request_stop();
        self.wait().await
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        let _stop_requested = self.worker_shutdown_signal.request_cancellation();
    }
}
