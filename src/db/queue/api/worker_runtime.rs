use super::*;

impl Store {
    /// Claims and processes one batch of due jobs under a logical worker name.
    pub async fn process_available_jobs_once_for_worker(
        &self,
        pool: &Pool,
        task_registry: &TaskRegistry,
        worker_name: impl AsRef<str>,
        config: WorkerConfig,
    ) -> Result<WorkerRunOnceSummary, Error> {
        let worker_owner_id = WorkerOwnerId::new_unique_for_worker_name(worker_name)?;
        let resolved_config = ResolvedWorkerConfig::new(config)?;
        process_available_jobs_once_for_worker(
            self.clone(),
            pool.clone(),
            task_registry.clone(),
            worker_owner_id,
            resolved_config,
        )
        .await
    }

    /// Starts a long-running worker task under a logical worker name.
    pub fn start_worker(
        &self,
        pool: Pool,
        task_registry: TaskRegistry,
        worker_name: impl AsRef<str>,
        config: WorkerConfig,
    ) -> Result<WorkerHandle, Error> {
        let worker_owner_id = WorkerOwnerId::new_unique_for_worker_name(worker_name)?;
        let resolved_config = ResolvedWorkerConfig::new(config)?;
        let worker_shutdown_signal = RuntimeCancellationSignal::new();
        let runtime = WorkerRuntime {
            queue: self.clone(),
            pool,
            task_registry,
            worker_owner_id,
            config: resolved_config,
            worker_shutdown_signal: worker_shutdown_signal.clone(),
        };
        let join_handle = tokio::spawn(run_queue_worker_loop(runtime));
        Ok(WorkerHandle {
            worker_shutdown_signal,
            join_handle: Some(join_handle),
        })
    }

    /// Starts a long-running worker task with Fleet-backed reclaim and cleanup maintenance under a logical worker name.
    pub fn start_worker_with_fleet_maintenance(
        &self,
        pool: Pool,
        fleet_store: crate::fleet::Store,
        task_registry: TaskRegistry,
        worker_name: impl AsRef<str>,
        worker_config: WorkerConfig,
        maintenance_config: WorkerMaintenanceConfig,
    ) -> Result<WorkerHandle, Error> {
        let worker_owner_id = WorkerOwnerId::new_unique_for_worker_name(worker_name)?;
        let resolved_worker_config = ResolvedWorkerConfig::new(worker_config)?;
        let resolved_maintenance_config =
            ResolvedWorkerMaintenanceConfig::new(&self.config, maintenance_config)?;
        let reclaim_cron = fleet_store.new_cron(CronConfig {
            key: resolved_maintenance_config.reclaim_cron_key.clone(),
            interval: resolved_maintenance_config.reclaim_interval,
            claim_duration: None,
            heartbeat_interval: None,
            acquire_retry_interval: None,
            max_consecutive_renewal_failures: None,
        })?;
        let cleanup_cron = fleet_store.new_cron(CronConfig {
            key: resolved_maintenance_config.cleanup_cron_key.clone(),
            interval: resolved_maintenance_config.cleanup_interval,
            claim_duration: None,
            heartbeat_interval: None,
            acquire_retry_interval: None,
            max_consecutive_renewal_failures: None,
        })?;
        let worker_shutdown_signal = RuntimeCancellationSignal::new();
        let runtime = WorkerRuntime {
            queue: self.clone(),
            pool,
            task_registry,
            worker_owner_id,
            config: resolved_worker_config,
            worker_shutdown_signal: worker_shutdown_signal.clone(),
        };
        let join_handle = tokio::spawn(run_queue_worker_loop_with_fleet_maintenance(
            runtime,
            reclaim_cron,
            cleanup_cron,
            resolved_maintenance_config,
        ));
        Ok(WorkerHandle {
            worker_shutdown_signal,
            join_handle: Some(join_handle),
        })
    }
}
