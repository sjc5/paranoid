use super::*;

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            strategy: RetryBackoffStrategy::Exponential {
                base: DEFAULT_QUEUE_RETRY_EXPONENTIAL_BASE,
            },
            max_backoff: DEFAULT_QUEUE_RETRY_MAX_BACKOFF,
            jitter_fraction: DEFAULT_QUEUE_RETRY_JITTER_FRACTION,
        }
    }
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_QUEUE_WORKER_POLL_INTERVAL,
            startup_jitter_max_delay: None,
            concurrency: DEFAULT_QUEUE_WORKER_CONCURRENCY,
            stale_threshold: DEFAULT_QUEUE_WORKER_STALE_THRESHOLD,
            execution_heartbeat_interval: DEFAULT_QUEUE_WORKER_EXECUTION_HEARTBEAT_INTERVAL,
            default_job_timeout: WorkerDefaultJobTimeout::default(),
            retry_policy: RetryPolicy::default(),
            dead_letter_enabled: true,
            shutdown_grace_period: DEFAULT_QUEUE_WORKER_SHUTDOWN_GRACE_PERIOD,
            database_operation_timeout: DEFAULT_QUEUE_WORKER_DATABASE_OPERATION_TIMEOUT,
        }
    }
}

impl Default for WorkerMaintenanceConfig {
    fn default() -> Self {
        Self {
            cron_key_namespace: None,
            reclaim_interval: DEFAULT_QUEUE_WORKER_RECLAIM_INTERVAL,
            cleanup_interval: DEFAULT_QUEUE_WORKER_CLEANUP_INTERVAL,
            completed_job_retention: DEFAULT_QUEUE_COMPLETED_JOB_RETENTION,
            failed_job_retention: DEFAULT_QUEUE_FAILED_JOB_RETENTION,
            dead_letter_job_retention: DEFAULT_QUEUE_DEAD_LETTER_JOB_RETENTION,
            reclaim_batch_size: DEFAULT_QUEUE_RECLAIM_BATCH_SIZE,
            cleanup_batch_size: DEFAULT_QUEUE_CLEANUP_BATCH_SIZE,
            delay_between_cleanup_batches: DEFAULT_QUEUE_CLEANUP_BATCH_DELAY,
        }
    }
}

impl ResolvedWorkerConfig {
    pub(in crate::db::queue) fn new(config: WorkerConfig) -> Result<Self, Error> {
        let poll_interval = validate_positive_worker_duration(
            config.poll_interval,
            "poll interval must be positive",
        )?;
        let startup_jitter_max_delay = resolve_queue_worker_startup_jitter_max_delay(
            poll_interval,
            config.startup_jitter_max_delay,
        );
        let concurrency = resolve_queue_worker_concurrency(config.concurrency)?;
        let stale_threshold = validate_positive_worker_duration(
            config.stale_threshold,
            "stale threshold must be positive",
        )?;
        let execution_heartbeat_interval = validate_positive_worker_duration(
            config.execution_heartbeat_interval,
            "execution heartbeat interval must be positive",
        )?;
        let default_job_timeout =
            resolve_queue_worker_default_job_timeout(config.default_job_timeout)?;
        validate_worker_timing(
            stale_threshold,
            execution_heartbeat_interval,
            config.default_job_timeout,
            default_job_timeout,
        )?;
        let shutdown_grace_period = config.shutdown_grace_period;
        let database_operation_timeout = validate_positive_worker_duration(
            config.database_operation_timeout,
            "database operation timeout must be positive",
        )?;
        let retry_policy = resolve_queue_retry_policy(config.retry_policy)?;
        Ok(Self {
            poll_interval,
            startup_jitter_max_delay,
            concurrency,
            stale_threshold,
            execution_heartbeat_interval,
            default_job_timeout,
            retry_policy,
            dead_letter_enabled: config.dead_letter_enabled,
            shutdown_grace_period,
            database_operation_timeout,
        })
    }
}

impl ResolvedWorkerMaintenanceConfig {
    pub(in crate::db::queue) fn new(
        queue_config: &StoreConfig,
        config: WorkerMaintenanceConfig,
    ) -> Result<Self, Error> {
        let cron_key_namespace =
            resolve_queue_maintenance_cron_key_namespace(queue_config, config.cron_key_namespace)?;
        let reclaim_interval = resolve_queue_maintenance_interval(config.reclaim_interval)?;
        let cleanup_interval = resolve_queue_maintenance_interval(config.cleanup_interval)?;
        let completed_job_retention =
            resolve_queue_maintenance_retention(config.completed_job_retention)?;
        let failed_job_retention =
            resolve_queue_maintenance_retention(config.failed_job_retention)?;
        let dead_letter_job_retention =
            resolve_queue_maintenance_retention(config.dead_letter_job_retention)?;
        validate_reclaim_batch_size(config.reclaim_batch_size)?;
        let reclaim_batch_size = config.reclaim_batch_size;
        validate_cleanup_batch_size(config.cleanup_batch_size)?;
        let cleanup_batch_size = config.cleanup_batch_size;
        let delay_between_cleanup_batches = config.delay_between_cleanup_batches;
        Ok(Self {
            reclaim_cron_key: CronKey::new(format!("{}.reclaim", cron_key_namespace.as_str()))?,
            cleanup_cron_key: CronKey::new(format!("{}.cleanup", cron_key_namespace.as_str()))?,
            reclaim_interval,
            cleanup_interval,
            completed_job_retention,
            failed_job_retention,
            dead_letter_job_retention,
            reclaim_batch_size,
            cleanup_batch_size,
            delay_between_cleanup_batches,
        })
    }
}
