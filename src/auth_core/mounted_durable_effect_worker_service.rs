use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::db::{WritePool, queue};

use super::postgres_durable_effect_queue::{
    CoreAuthApplicationSubjectDataLifecycleIntegrator, CoreAuthOutOfBandMessageDeliverer,
    CoreAuthSecurityNotificationDeliverer, PostgresAuthDurableEffectQueueDispatchError,
    PostgresAuthDurableEffectQueueDispatchSummary, PostgresAuthDurableEffectQueueDispatcher,
    register_core_auth_durable_effect_queue_handlers,
};
use super::postgres_method_runtime::{
    PostgresAuthMethodDurableEffectQueueRegistrationError, PostgresAuthMethodRegistry,
};
use super::postgres_runtime::PostgresAuthWebRuntime;
use super::prelude::*;

const MOUNTED_AUTH_DURABLE_EFFECT_DISPATCH_OPERATION: &str =
    "auth_core.mounted_durable_effect_worker.dispatch";

/// Mounted/operator workflow for committed auth durable-effect delivery.
pub(crate) struct MountedAuthDurableEffectPostgresWorkerService {
    write_pool: WritePool,
    queue_store: queue::Store,
    core_dispatcher: PostgresAuthDurableEffectQueueDispatcher,
    method_registry: Option<Arc<PostgresAuthMethodRegistry>>,
    integrations: MountedAuthDurableEffectWorkerIntegrations,
}

impl MountedAuthDurableEffectPostgresWorkerService {
    pub(crate) fn new(
        write_pool: WritePool,
        queue_store: queue::Store,
        runtime: &PostgresAuthWebRuntime,
        integrations: MountedAuthDurableEffectWorkerIntegrations,
    ) -> Self {
        Self {
            write_pool,
            queue_store,
            core_dispatcher: PostgresAuthDurableEffectQueueDispatcher::new(
                runtime.store_config().clone(),
            ),
            method_registry: runtime.method_registry_arc(),
            integrations,
        }
    }

    pub(crate) async fn dispatch_available_durable_effects_to_queue(
        &self,
        request: MountedAuthDurableEffectDispatchRequest,
    ) -> Result<MountedAuthDurableEffectDispatchSummary, PostgresAuthDurableEffectQueueDispatchError>
    {
        let mut tx = self.write_pool.begin_transaction().await?;
        let result = self
            .dispatch_available_durable_effects_to_queue_in_current_transaction(&mut tx, request)
            .await;

        match result {
            Ok(summary) => {
                tx.commit().await?;
                Ok(summary)
            }
            Err(error) => {
                let rollback_result = tx.rollback().await;
                if let Err(rollback_error) = rollback_result {
                    return Err(
                        PostgresAuthDurableEffectQueueDispatchError::DatabaseOperationRollbackFailed {
                            operation: MOUNTED_AUTH_DURABLE_EFFECT_DISPATCH_OPERATION,
                            operation_error: Box::new(error),
                            rollback_error: Box::new(rollback_error),
                        },
                    );
                }
                Err(error)
            }
        }
    }

    async fn dispatch_available_durable_effects_to_queue_in_current_transaction(
        &self,
        tx: &mut crate::db::WriteTx<'_>,
        request: MountedAuthDurableEffectDispatchRequest,
    ) -> Result<MountedAuthDurableEffectDispatchSummary, PostgresAuthDurableEffectQueueDispatchError>
    {
        let core_summary = self
            .core_dispatcher
            .enqueue_available_core_durable_effects_to_queue_in_current_transaction(
                tx,
                &self.queue_store,
                request.core_effect_limit,
                request.enqueued_at,
            )
            .await?;
        let method_summary = match self.method_registry.as_ref() {
            Some(method_registry) => {
                method_registry
                    .enqueue_available_method_durable_effects_to_queue_in_current_transaction(
                        tx,
                        &self.queue_store,
                        request.method_effect_limit_per_method,
                        request.enqueued_at,
                    )
                    .await?
            }
            None => PostgresAuthDurableEffectQueueDispatchSummary::default(),
        };
        Ok(MountedAuthDurableEffectDispatchSummary {
            core_summary,
            method_summary,
        })
    }

    pub(crate) fn build_task_registry(
        &self,
    ) -> Result<queue::TaskRegistry, MountedAuthDurableEffectWorkerError> {
        let mut task_registry = queue::TaskRegistry::new();
        self.register_task_handlers(&mut task_registry)?;
        Ok(task_registry)
    }

    pub(crate) fn register_task_handlers(
        &self,
        task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), MountedAuthDurableEffectWorkerError> {
        register_core_auth_durable_effect_queue_handlers(
            task_registry,
            Arc::clone(&self.integrations.out_of_band_message_deliverer),
            Arc::clone(&self.integrations.security_notification_deliverer),
            Arc::clone(&self.integrations.application_subject_data_integrator),
        )?;
        if let Some(method_registry) = self.method_registry.as_ref() {
            method_registry.register_durable_effect_queue_handlers(task_registry)?;
        }
        Ok(())
    }

    pub(crate) async fn process_available_delivery_jobs_once_for_worker(
        &self,
        worker_name: impl AsRef<str>,
        config: queue::WorkerConfig,
    ) -> Result<queue::WorkerRunOnceSummary, MountedAuthDurableEffectWorkerError> {
        let task_registry = self.build_task_registry()?;
        self.queue_store
            .process_available_jobs_once_for_worker(
                &self.write_pool,
                &task_registry,
                worker_name,
                config,
            )
            .await
            .map_err(MountedAuthDurableEffectWorkerError::Queue)
    }

    pub(crate) fn start_delivery_worker(
        &self,
        worker_name: impl AsRef<str>,
        config: queue::WorkerConfig,
    ) -> Result<queue::WorkerHandle, MountedAuthDurableEffectWorkerError> {
        let task_registry = self.build_task_registry()?;
        self.queue_store
            .start_worker(self.write_pool.clone(), task_registry, worker_name, config)
            .map_err(MountedAuthDurableEffectWorkerError::Queue)
    }

    pub(crate) fn start_delivery_worker_with_fleet_maintenance(
        &self,
        fleet_store: crate::fleet::Store,
        worker_name: impl AsRef<str>,
        worker_config: queue::WorkerConfig,
        maintenance_config: queue::WorkerMaintenanceConfig,
    ) -> Result<queue::WorkerHandle, MountedAuthDurableEffectWorkerError> {
        let task_registry = self.build_task_registry()?;
        self.queue_store
            .start_worker_with_fleet_maintenance(
                self.write_pool.clone(),
                fleet_store,
                task_registry,
                worker_name,
                worker_config,
                maintenance_config,
            )
            .map_err(MountedAuthDurableEffectWorkerError::Queue)
    }

    pub(crate) async fn fetch_delivery_worker_pressure(
        &self,
    ) -> Result<queue::WorkerPressure, MountedAuthDurableEffectWorkerError> {
        let task_registry = self.build_task_registry()?;
        self.queue_store
            .fetch_worker_pressure(&self.write_pool, &task_registry)
            .await
            .map_err(MountedAuthDurableEffectWorkerError::Queue)
    }

    pub(crate) async fn fetch_orphaned_delivery_task_names(
        &self,
    ) -> Result<Vec<String>, MountedAuthDurableEffectWorkerError> {
        let task_registry = self.build_task_registry()?;
        self.queue_store
            .fetch_orphaned_task_names(&self.write_pool, &task_registry)
            .await
            .map_err(MountedAuthDurableEffectWorkerError::Queue)
    }

    pub(crate) async fn reclaim_available_stale_delivery_jobs_once(
        &self,
        stale_threshold: Duration,
        reclaim_batch_size: u32,
        move_expired_max_retry_jobs_to_dead_letter: bool,
    ) -> Result<queue::ReclaimStaleRunningJobsResult, MountedAuthDurableEffectWorkerError> {
        self.queue_store
            .reclaim_available_stale_running_jobs_once(
                &self.write_pool,
                stale_threshold,
                reclaim_batch_size,
                move_expired_max_retry_jobs_to_dead_letter,
            )
            .await
            .map_err(MountedAuthDurableEffectWorkerError::Queue)
    }
}

/// Application integrations needed by mounted auth delivery workers.
#[derive(Clone)]
pub(crate) struct MountedAuthDurableEffectWorkerIntegrations {
    out_of_band_message_deliverer: Arc<dyn CoreAuthOutOfBandMessageDeliverer>,
    security_notification_deliverer: Arc<dyn CoreAuthSecurityNotificationDeliverer>,
    application_subject_data_integrator: Arc<dyn CoreAuthApplicationSubjectDataLifecycleIntegrator>,
}

impl MountedAuthDurableEffectWorkerIntegrations {
    pub(crate) fn new(
        out_of_band_message_deliverer: Arc<dyn CoreAuthOutOfBandMessageDeliverer>,
        security_notification_deliverer: Arc<dyn CoreAuthSecurityNotificationDeliverer>,
        application_subject_data_integrator: Arc<
            dyn CoreAuthApplicationSubjectDataLifecycleIntegrator,
        >,
    ) -> Self {
        Self {
            out_of_band_message_deliverer,
            security_notification_deliverer,
            application_subject_data_integrator,
        }
    }
}

/// Input for one mounted auth durable-effect dispatch pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthDurableEffectDispatchRequest {
    core_effect_limit: NonZeroU32,
    method_effect_limit_per_method: NonZeroU32,
    enqueued_at: UnixSeconds,
}

impl MountedAuthDurableEffectDispatchRequest {
    pub(crate) fn new(
        core_effect_limit: NonZeroU32,
        method_effect_limit_per_method: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Self {
        Self {
            core_effect_limit,
            method_effect_limit_per_method,
            enqueued_at,
        }
    }
}

/// Summary returned by one mounted auth durable-effect dispatch pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MountedAuthDurableEffectDispatchSummary {
    core_summary: PostgresAuthDurableEffectQueueDispatchSummary,
    method_summary: PostgresAuthDurableEffectQueueDispatchSummary,
}

impl MountedAuthDurableEffectDispatchSummary {
    pub(crate) const fn core_summary(self) -> PostgresAuthDurableEffectQueueDispatchSummary {
        self.core_summary
    }

    pub(crate) const fn method_summary(self) -> PostgresAuthDurableEffectQueueDispatchSummary {
        self.method_summary
    }

    pub(crate) const fn total_enqueued_effect_count(self) -> u32 {
        self.core_summary.enqueued_effect_count() + self.method_summary.enqueued_effect_count()
    }

    pub(crate) const fn total_deduplicated_queue_job_count(self) -> u32 {
        self.core_summary.deduplicated_queue_job_count()
            + self.method_summary.deduplicated_queue_job_count()
    }
}

/// Error returned by mounted auth durable-effect worker setup or execution.
#[derive(Debug)]
pub(crate) enum MountedAuthDurableEffectWorkerError {
    Queue(queue::Error),
    MethodRegistration(PostgresAuthMethodDurableEffectQueueRegistrationError),
}

impl fmt::Display for MountedAuthDurableEffectWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queue(error) => write!(f, "auth durable-effect worker queue error: {error}"),
            Self::MethodRegistration(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MountedAuthDurableEffectWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Queue(error) => Some(error),
            Self::MethodRegistration(error) => Some(error),
        }
    }
}

impl From<queue::Error> for MountedAuthDurableEffectWorkerError {
    fn from(error: queue::Error) -> Self {
        Self::Queue(error)
    }
}

impl From<PostgresAuthMethodDurableEffectQueueRegistrationError>
    for MountedAuthDurableEffectWorkerError
{
    fn from(error: PostgresAuthMethodDurableEffectQueueRegistrationError) -> Self {
        Self::MethodRegistration(error)
    }
}
