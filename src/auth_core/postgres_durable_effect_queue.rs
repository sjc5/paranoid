use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;

use crate::db::{
    DatabaseOperationKind, DbError, WritePool, WriteTx, pooler_safe_query, pooler_safe_query_as,
};
use crate::db::{queue, queue::EnqueueOptions};

use super::postgres_store::{
    DURABLE_EFFECT_KIND_DELETE_APPLICATION_SUBJECT_DATA,
    DURABLE_EFFECT_KIND_DISABLE_APPLICATION_SUBJECT_DATA,
    DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT, DURABLE_EFFECT_KIND_SEND_OUT_OF_BAND_MESSAGE,
    PostgresAuthStoreConfig, PostgresAuthStoreError, i64_from_unix_seconds, unix_seconds_from_i64,
};
use super::prelude::*;

pub(super) const AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME: &str =
    "paranoid.auth.out_of_band_message.v1";
pub(super) const AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME: &str =
    "paranoid.auth.security_notification.v1";
pub(super) const AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME: &str =
    "paranoid.auth.application_subject_data_lifecycle.v1";
const AUTH_QUEUE_DEDUPE_KEY_PREFIX: &str = "paranoid.auth.core_effect.";
const AUTH_DURABLE_EFFECT_DISPATCH_OPERATION: &str = "auth_core.durable_effect_queue.dispatch";
type CoreAuthDeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>;

pub(crate) type AuthDurableEffectDeliveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), AuthDurableEffectDeliveryError>> + Send + 'a>>;

/// Auth-owned callback for delivering one queued out-of-band message.
pub(crate) trait CoreAuthOutOfBandMessageDeliverer: Send + Sync + 'static {
    /// Delivers one committed out-of-band auth message.
    fn deliver_out_of_band_message<'a>(
        &'a self,
        request: CoreAuthOutOfBandMessageDeliveryRequest,
    ) -> CoreAuthDeliveryFuture<'a>;
}

/// Auth-owned callback for delivering one queued security notification.
pub(crate) trait CoreAuthSecurityNotificationDeliverer: Send + Sync + 'static {
    /// Delivers one committed auth security notification.
    fn deliver_security_notification<'a>(
        &'a self,
        request: CoreAuthSecurityNotificationDeliveryRequest,
    ) -> CoreAuthDeliveryFuture<'a>;
}

/// Auth-owned callback for applying one queued app-owned subject data action.
pub(crate) trait CoreAuthApplicationSubjectDataLifecycleIntegrator:
    Send + Sync + 'static
{
    /// Applies one committed app-owned subject data lifecycle action.
    fn apply_application_subject_data_lifecycle_action<'a>(
        &'a self,
        request: CoreAuthApplicationSubjectDataLifecycleRequest,
    ) -> CoreAuthDeliveryFuture<'a>;
}

/// Error returned by an auth durable-effect delivery callback.
pub(crate) type CoreAuthDurableEffectDeliveryError = AuthDurableEffectDeliveryError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthDurableEffectDeliveryError {
    message: String,
    permanent: bool,
}

impl AuthDurableEffectDeliveryError {
    /// Creates a retryable delivery error.
    pub(crate) fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
        }
    }

    /// Creates a permanent delivery error.
    pub(crate) fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: true,
        }
    }

    pub(crate) fn into_queue_task_error(self) -> queue::TaskError {
        if self.permanent {
            queue::TaskError::permanent(self.message)
        } else {
            queue::TaskError::retryable(self.message)
        }
    }
}

/// Typed delivery request for one committed out-of-band auth message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoreAuthOutOfBandMessageDeliveryRequest {
    effect_command_id: i64,
    effect_idempotency_key: String,
    queue_job_id: queue::JobId,
    retry_count: u32,
    max_retries: u32,
    challenge_id: ActiveProofChallengeId,
    proof_method_label: String,
    recipient_handle: String,
    delivery_idempotency_key: String,
    expires_at: UnixSeconds,
}

impl CoreAuthOutOfBandMessageDeliveryRequest {
    /// Returns the durable auth effect row id.
    pub(crate) const fn effect_command_id(&self) -> i64 {
        self.effect_command_id
    }

    /// Returns the stable idempotency key for the core auth effect.
    pub(crate) fn effect_idempotency_key(&self) -> &str {
        &self.effect_idempotency_key
    }

    /// Returns the Queue job id currently delivering this effect.
    pub(crate) const fn queue_job_id(&self) -> queue::JobId {
        self.queue_job_id
    }

    /// Returns the current Queue retry count.
    pub(crate) const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns the Queue max retry count.
    pub(crate) const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns the active-proof challenge id this message belongs to.
    pub(crate) fn challenge_id(&self) -> &ActiveProofChallengeId {
        &self.challenge_id
    }

    /// Returns the proof method label.
    pub(crate) fn proof_method_label(&self) -> &str {
        &self.proof_method_label
    }

    /// Returns the opaque recipient handle.
    pub(crate) fn recipient_handle(&self) -> &str {
        &self.recipient_handle
    }

    /// Returns the method/core-provided delivery idempotency key.
    pub(crate) fn delivery_idempotency_key(&self) -> &str {
        &self.delivery_idempotency_key
    }

    /// Returns the auth challenge expiry.
    pub(crate) const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }
}

/// Typed delivery request for one committed auth security notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoreAuthSecurityNotificationDeliveryRequest {
    effect_command_id: i64,
    effect_idempotency_key: String,
    queue_job_id: queue::JobId,
    retry_count: u32,
    max_retries: u32,
    notification_kind: String,
    subject_id: SubjectId,
}

impl CoreAuthSecurityNotificationDeliveryRequest {
    /// Returns the durable auth effect row id.
    pub(crate) const fn effect_command_id(&self) -> i64 {
        self.effect_command_id
    }

    /// Returns the stable idempotency key for the core auth effect.
    pub(crate) fn effect_idempotency_key(&self) -> &str {
        &self.effect_idempotency_key
    }

    /// Returns the Queue job id currently delivering this effect.
    pub(crate) const fn queue_job_id(&self) -> queue::JobId {
        self.queue_job_id
    }

    /// Returns the current Queue retry count.
    pub(crate) const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns the Queue max retry count.
    pub(crate) const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns the committed notification kind label.
    pub(crate) fn notification_kind(&self) -> &str {
        &self.notification_kind
    }

    /// Returns the notification subject.
    pub(crate) fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }
}

/// Typed delivery request for one committed app-owned subject data lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoreAuthApplicationSubjectDataLifecycleRequest {
    effect_command_id: i64,
    effect_idempotency_key: String,
    queue_job_id: queue::JobId,
    retry_count: u32,
    max_retries: u32,
    action: ApplicationSubjectDataLifecycleAction,
    subject_id: SubjectId,
    requested_at: UnixSeconds,
}

impl CoreAuthApplicationSubjectDataLifecycleRequest {
    /// Returns the durable auth effect row id.
    pub(crate) const fn effect_command_id(&self) -> i64 {
        self.effect_command_id
    }

    /// Returns the stable idempotency key for the core auth effect.
    pub(crate) fn effect_idempotency_key(&self) -> &str {
        &self.effect_idempotency_key
    }

    /// Returns the Queue job id currently applying this action.
    pub(crate) const fn queue_job_id(&self) -> queue::JobId {
        self.queue_job_id
    }

    /// Returns the current Queue retry count.
    pub(crate) const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Returns the Queue max retry count.
    pub(crate) const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns the app-owned subject data lifecycle action.
    pub(crate) const fn action(&self) -> ApplicationSubjectDataLifecycleAction {
        self.action
    }

    /// Returns the subject whose app-owned data should be updated.
    pub(crate) fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    /// Returns when the auth transition committed this request.
    pub(crate) const fn requested_at(&self) -> UnixSeconds {
        self.requested_at
    }
}

/// Registers Queue handlers for core auth durable-effect delivery tasks.
pub(crate) fn register_core_auth_durable_effect_queue_handlers(
    task_registry: &mut queue::TaskRegistry,
    out_of_band_deliverer: Arc<dyn CoreAuthOutOfBandMessageDeliverer>,
    security_notification_deliverer: Arc<dyn CoreAuthSecurityNotificationDeliverer>,
    application_subject_data_integrator: Arc<dyn CoreAuthApplicationSubjectDataLifecycleIntegrator>,
) -> Result<(), queue::Error> {
    task_registry.register_json_task_handler(
        AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
        move |context, payload: QueuedOutOfBandMessagePayload| {
            let out_of_band_deliverer = Arc::clone(&out_of_band_deliverer);
            async move {
                let request = payload.into_delivery_request(&context)?;
                out_of_band_deliverer
                    .deliver_out_of_band_message(request)
                    .await
                    .map_err(CoreAuthDurableEffectDeliveryError::into_queue_task_error)
            }
        },
    )?;

    task_registry.register_json_task_handler(
        AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
        move |context, payload: QueuedSecurityNotificationPayload| {
            let security_notification_deliverer = Arc::clone(&security_notification_deliverer);
            async move {
                let request = payload.into_delivery_request(&context)?;
                security_notification_deliverer
                    .deliver_security_notification(request)
                    .await
                    .map_err(CoreAuthDurableEffectDeliveryError::into_queue_task_error)
            }
        },
    )?;

    task_registry.register_json_task_handler(
        AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME,
        move |context, payload: QueuedApplicationSubjectDataLifecyclePayload| {
            let application_subject_data_integrator =
                Arc::clone(&application_subject_data_integrator);
            async move {
                let request = payload.into_delivery_request(&context)?;
                application_subject_data_integrator
                    .apply_application_subject_data_lifecycle_action(request)
                    .await
                    .map_err(CoreAuthDurableEffectDeliveryError::into_queue_task_error)
            }
        },
    )
}

/// Private dispatcher that hands committed auth durable effects to Paranoid Queue.
#[derive(Clone, Debug)]
pub(crate) struct PostgresAuthDurableEffectQueueDispatcher {
    store_config: PostgresAuthStoreConfig,
}

/// Summary returned by one durable-effect queue dispatch pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PostgresAuthDurableEffectQueueDispatchSummary {
    enqueued_effect_count: u32,
    deduplicated_queue_job_count: u32,
}

impl PostgresAuthDurableEffectQueueDispatchSummary {
    /// Returns the number of effect rows handed to Queue.
    pub(crate) const fn enqueued_effect_count(self) -> u32 {
        self.enqueued_effect_count
    }

    /// Returns the number of effects whose Queue job reused an active dedupe entry.
    pub(crate) const fn deduplicated_queue_job_count(self) -> u32 {
        self.deduplicated_queue_job_count
    }

    pub(crate) fn add(&mut self, other: Self) {
        self.enqueued_effect_count += other.enqueued_effect_count;
        self.deduplicated_queue_job_count += other.deduplicated_queue_job_count;
    }

    pub(crate) fn record_enqueue(&mut self, deduplicated: bool) {
        self.enqueued_effect_count += 1;
        if deduplicated {
            self.deduplicated_queue_job_count += 1;
        }
    }
}

#[derive(Debug)]
pub(crate) enum PostgresAuthDurableEffectQueueDispatchError {
    Database(DbError),
    AuthStore(PostgresAuthStoreError),
    InvalidStoredData(&'static str),
    Queue(queue::Error),
    DatabaseOperationRollbackFailed {
        operation: &'static str,
        operation_error: Box<PostgresAuthDurableEffectQueueDispatchError>,
        rollback_error: Box<DbError>,
    },
}

impl fmt::Display for PostgresAuthDurableEffectQueueDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "auth durable-effect queue database error: {error}"),
            Self::AuthStore(error) => write!(f, "auth durable-effect queue store error: {error}"),
            Self::InvalidStoredData(reason) => {
                write!(
                    f,
                    "auth durable-effect queue loaded invalid stored data: {reason}"
                )
            }
            Self::Queue(error) => write!(f, "auth durable-effect queue enqueue failed: {error}"),
            Self::DatabaseOperationRollbackFailed {
                operation,
                operation_error,
                rollback_error,
            } => write!(
                f,
                "auth durable-effect queue operation {operation} failed, then rollback failed: {operation_error}; rollback: {rollback_error}"
            ),
        }
    }
}

impl std::error::Error for PostgresAuthDurableEffectQueueDispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::AuthStore(error) => Some(error),
            Self::Queue(error) => Some(error),
            Self::DatabaseOperationRollbackFailed {
                operation_error, ..
            } => Some(operation_error),
            Self::InvalidStoredData(_) => None,
        }
    }
}

impl From<DbError> for PostgresAuthDurableEffectQueueDispatchError {
    fn from(error: DbError) -> Self {
        Self::Database(error)
    }
}

impl From<PostgresAuthStoreError> for PostgresAuthDurableEffectQueueDispatchError {
    fn from(error: PostgresAuthStoreError) -> Self {
        Self::AuthStore(error)
    }
}

impl From<queue::Error> for PostgresAuthDurableEffectQueueDispatchError {
    fn from(error: queue::Error) -> Self {
        Self::Queue(error)
    }
}

impl PostgresAuthDurableEffectQueueDispatcher {
    pub(crate) fn new(store_config: PostgresAuthStoreConfig) -> Self {
        Self { store_config }
    }

    pub(crate) async fn enqueue_available_core_durable_effects_to_queue(
        &self,
        pool: &WritePool,
        queue_store: &queue::Store,
        limit: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Result<
        PostgresAuthDurableEffectQueueDispatchSummary,
        PostgresAuthDurableEffectQueueDispatchError,
    > {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .enqueue_available_core_durable_effects_to_queue_in_current_transaction(
                &mut tx,
                queue_store,
                limit,
                enqueued_at,
            )
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
                            operation: AUTH_DURABLE_EFFECT_DISPATCH_OPERATION,
                            operation_error: Box::new(error),
                            rollback_error: Box::new(rollback_error),
                        },
                    );
                }
                Err(error)
            }
        }
    }

    pub(crate) async fn enqueue_available_core_durable_effects_to_queue_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        queue_store: &queue::Store,
        limit: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Result<
        PostgresAuthDurableEffectQueueDispatchSummary,
        PostgresAuthDurableEffectQueueDispatchError,
    > {
        let rows =
            load_undispatched_core_durable_effect_rows_for_update(tx, &self.store_config, limit)
                .await?;
        let mut summary = PostgresAuthDurableEffectQueueDispatchSummary::default();
        for row in rows {
            let effect = CoreDurableEffectQueueDispatchWork::try_from(row)?;
            let dedupe_key = queue_dedupe_key_for_effect_command_id(effect.effect_command_id);
            let enqueue_options = EnqueueOptions {
                dedupe_key: Some(dedupe_key.clone()),
                ..EnqueueOptions::default()
            };
            let enqueue_result = match effect.payload {
                CoreDurableEffectQueuePayload::OutOfBandMessage(payload) => {
                    queue_store
                        .enqueue_json_in_current_transaction(
                            tx,
                            AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
                            &payload,
                            enqueue_options,
                        )
                        .await?
                }
                CoreDurableEffectQueuePayload::SecurityNotification(payload) => {
                    queue_store
                        .enqueue_json_in_current_transaction(
                            tx,
                            AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
                            &payload,
                            enqueue_options,
                        )
                        .await?
                }
                CoreDurableEffectQueuePayload::ApplicationSubjectDataLifecycle(payload) => {
                    queue_store
                        .enqueue_json_in_current_transaction(
                            tx,
                            AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME,
                            &payload,
                            enqueue_options,
                        )
                        .await?
                }
            };
            insert_core_durable_effect_queue_dispatch(
                tx,
                &self.store_config,
                effect.effect_command_id,
                enqueue_result.job_id.as_bytes(),
                effect.task_name,
                dedupe_key,
                enqueued_at,
            )
            .await?;
            summary.record_enqueue(enqueue_result.deduplicated);
        }
        Ok(summary)
    }
}

type CoreDurableEffectRow = (
    i64,
    i32,
    Option<Vec<u8>>,
    Option<i32>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    i64,
);

#[derive(Debug)]
struct CoreDurableEffectQueueDispatchWork {
    effect_command_id: i64,
    task_name: &'static str,
    payload: CoreDurableEffectQueuePayload,
}

#[derive(Debug)]
enum CoreDurableEffectQueuePayload {
    OutOfBandMessage(QueuedOutOfBandMessagePayload),
    SecurityNotification(QueuedSecurityNotificationPayload),
    ApplicationSubjectDataLifecycle(QueuedApplicationSubjectDataLifecyclePayload),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct QueuedOutOfBandMessagePayload {
    effect_command_id: i64,
    challenge_id: Vec<u8>,
    proof_method_label: String,
    recipient_handle: String,
    delivery_idempotency_key: String,
    expires_at_unix_seconds: u64,
}

impl QueuedOutOfBandMessagePayload {
    fn into_delivery_request(
        self,
        context: &queue::JobExecutionContext,
    ) -> Result<CoreAuthOutOfBandMessageDeliveryRequest, queue::TaskError> {
        validate_queued_effect_command_id(self.effect_command_id)?;
        validate_auth_identifier_string(
            "queued out-of-band proof method label",
            &self.proof_method_label,
            METHOD_LABEL_MAX_BYTES,
        )
        .map_err(permanent_task_error_from_core_error)?;
        if self.recipient_handle.is_empty() {
            return Err(queue::TaskError::permanent(
                "queued out-of-band recipient handle is empty",
            ));
        }
        validate_auth_string_not_too_long(
            "queued out-of-band recipient handle",
            &self.recipient_handle,
            OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
        )
        .map_err(permanent_task_error_from_core_error)?;
        validate_auth_identifier_string(
            "queued out-of-band delivery idempotency key",
            &self.delivery_idempotency_key,
            DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
        )
        .map_err(permanent_task_error_from_core_error)?;

        let challenge_id = ActiveProofChallengeId::from_bytes(self.challenge_id)
            .map_err(permanent_task_error_from_core_error)?;
        Ok(CoreAuthOutOfBandMessageDeliveryRequest {
            effect_command_id: self.effect_command_id,
            effect_idempotency_key: queue_dedupe_key_for_effect_command_id(self.effect_command_id),
            queue_job_id: context.job_id(),
            retry_count: context.retry_count(),
            max_retries: context.max_retries(),
            challenge_id,
            proof_method_label: self.proof_method_label,
            recipient_handle: self.recipient_handle,
            delivery_idempotency_key: self.delivery_idempotency_key,
            expires_at: UnixSeconds::new(self.expires_at_unix_seconds),
        })
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct QueuedSecurityNotificationPayload {
    effect_command_id: i64,
    notification_kind: String,
    subject_id: Vec<u8>,
}

impl QueuedSecurityNotificationPayload {
    fn into_delivery_request(
        self,
        context: &queue::JobExecutionContext,
    ) -> Result<CoreAuthSecurityNotificationDeliveryRequest, queue::TaskError> {
        validate_queued_effect_command_id(self.effect_command_id)?;
        validate_auth_identifier_string(
            "queued security notification kind",
            &self.notification_kind,
            METHOD_LABEL_MAX_BYTES,
        )
        .map_err(permanent_task_error_from_core_error)?;
        let subject_id =
            SubjectId::from_bytes(self.subject_id).map_err(permanent_task_error_from_core_error)?;
        Ok(CoreAuthSecurityNotificationDeliveryRequest {
            effect_command_id: self.effect_command_id,
            effect_idempotency_key: queue_dedupe_key_for_effect_command_id(self.effect_command_id),
            queue_job_id: context.job_id(),
            retry_count: context.retry_count(),
            max_retries: context.max_retries(),
            notification_kind: self.notification_kind,
            subject_id,
        })
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct QueuedApplicationSubjectDataLifecyclePayload {
    effect_command_id: i64,
    action: String,
    subject_id: Vec<u8>,
    requested_at_unix_seconds: u64,
}

impl QueuedApplicationSubjectDataLifecyclePayload {
    fn into_delivery_request(
        self,
        context: &queue::JobExecutionContext,
    ) -> Result<CoreAuthApplicationSubjectDataLifecycleRequest, queue::TaskError> {
        validate_queued_effect_command_id(self.effect_command_id)?;
        let action = application_subject_data_lifecycle_action_from_label(&self.action)
            .map_err(permanent_task_error_from_core_error)?;
        let subject_id =
            SubjectId::from_bytes(self.subject_id).map_err(permanent_task_error_from_core_error)?;
        Ok(CoreAuthApplicationSubjectDataLifecycleRequest {
            effect_command_id: self.effect_command_id,
            effect_idempotency_key: queue_dedupe_key_for_effect_command_id(self.effect_command_id),
            queue_job_id: context.job_id(),
            retry_count: context.retry_count(),
            max_retries: context.max_retries(),
            action,
            subject_id,
            requested_at: UnixSeconds::new(self.requested_at_unix_seconds),
        })
    }
}

impl TryFrom<CoreDurableEffectRow> for CoreDurableEffectQueueDispatchWork {
    type Error = PostgresAuthDurableEffectQueueDispatchError;

    fn try_from(row: CoreDurableEffectRow) -> Result<Self, Self::Error> {
        let (
            effect_command_id,
            kind,
            subject_id,
            security_notification_kind,
            challenge_id,
            proof_method_label,
            recipient_handle,
            delivery_idempotency_key,
            expires_at,
            created_at,
        ) = row;
        match kind {
            DURABLE_EFFECT_KIND_SEND_OUT_OF_BAND_MESSAGE => {
                require_absent(subject_id, "out-of-band command subject_id must be null")?;
                require_absent(
                    security_notification_kind,
                    "out-of-band command security_notification_kind must be null",
                )?;
                let challenge_id =
                    require_present(challenge_id, "out-of-band command challenge_id is missing")?;
                let proof_method_label = require_present(
                    proof_method_label,
                    "out-of-band command proof_method_label is missing",
                )?;
                let recipient_handle = require_present(
                    recipient_handle,
                    "out-of-band command recipient_handle is missing",
                )?;
                let delivery_idempotency_key = require_present(
                    delivery_idempotency_key,
                    "out-of-band command delivery_idempotency_key is missing",
                )?;
                let expires_at =
                    require_present(expires_at, "out-of-band command expires_at is missing")?;
                Ok(Self {
                    effect_command_id,
                    task_name: AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME,
                    payload: CoreDurableEffectQueuePayload::OutOfBandMessage(
                        QueuedOutOfBandMessagePayload {
                            effect_command_id,
                            challenge_id,
                            proof_method_label,
                            recipient_handle,
                            delivery_idempotency_key,
                            expires_at_unix_seconds: unix_seconds_from_i64(expires_at)?.get(),
                        },
                    ),
                })
            }
            DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT => {
                require_absent(
                    challenge_id,
                    "security notification command challenge_id must be null",
                )?;
                require_absent(
                    proof_method_label,
                    "security notification command proof_method_label must be null",
                )?;
                require_absent(
                    recipient_handle,
                    "security notification command recipient_handle must be null",
                )?;
                require_absent(
                    delivery_idempotency_key,
                    "security notification command delivery_idempotency_key must be null",
                )?;
                require_absent(
                    expires_at,
                    "security notification command expires_at must be null",
                )?;
                let subject_id =
                    require_present(subject_id, "security notification subject_id is missing")?;
                let security_notification_kind = require_present(
                    security_notification_kind,
                    "security notification kind is missing",
                )?;
                Ok(Self {
                    effect_command_id,
                    task_name: AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME,
                    payload: CoreDurableEffectQueuePayload::SecurityNotification(
                        QueuedSecurityNotificationPayload {
                            effect_command_id,
                            notification_kind: security_notification_kind_label(
                                security_notification_kind,
                            )?
                            .to_owned(),
                            subject_id,
                        },
                    ),
                })
            }
            DURABLE_EFFECT_KIND_DELETE_APPLICATION_SUBJECT_DATA
            | DURABLE_EFFECT_KIND_DISABLE_APPLICATION_SUBJECT_DATA => {
                require_absent(
                    security_notification_kind,
                    "application subject data command security_notification_kind must be null",
                )?;
                require_absent(
                    challenge_id,
                    "application subject data command challenge_id must be null",
                )?;
                require_absent(
                    proof_method_label,
                    "application subject data command proof_method_label must be null",
                )?;
                require_absent(
                    recipient_handle,
                    "application subject data command recipient_handle must be null",
                )?;
                require_absent(
                    delivery_idempotency_key,
                    "application subject data command delivery_idempotency_key must be null",
                )?;
                require_absent(
                    expires_at,
                    "application subject data command expires_at must be null",
                )?;
                let subject_id =
                    require_present(subject_id, "application subject data subject_id is missing")?;
                let action = application_subject_data_lifecycle_action_from_effect_kind(kind)?;
                Ok(Self {
                    effect_command_id,
                    task_name: AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME,
                    payload: CoreDurableEffectQueuePayload::ApplicationSubjectDataLifecycle(
                        QueuedApplicationSubjectDataLifecyclePayload {
                            effect_command_id,
                            action: action.label().to_owned(),
                            subject_id,
                            requested_at_unix_seconds: unix_seconds_from_i64(created_at)?.get(),
                        },
                    ),
                })
            }
            _ => Err(
                PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
                    "unknown durable effect kind",
                ),
            ),
        }
    }
}

async fn load_undispatched_core_durable_effect_rows_for_update(
    tx: &mut WriteTx<'_>,
    store_config: &PostgresAuthStoreConfig,
    limit: NonZeroU32,
) -> Result<Vec<CoreDurableEffectRow>, PostgresAuthDurableEffectQueueDispatchError> {
    let effect_table = store_config.table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)?;
    let dispatch_table =
        store_config.table_name(PostgresAuthCoreTable::CoreDurableEffectQueueDispatch)?;
    let statement = format!(
        r#"
        SELECT
            effect.effect_command_id,
            effect.kind,
            effect.subject_id,
            effect.security_notification_kind,
            effect.challenge_id,
            effect.proof_method_label,
            effect.recipient_handle,
            effect.delivery_idempotency_key,
            effect.expires_at,
            effect.created_at
        FROM {} effect
        LEFT JOIN {} dispatch
          ON dispatch.effect_command_id = effect.effect_command_id
        WHERE dispatch.effect_command_id IS NULL
        ORDER BY effect.effect_command_id
        LIMIT $1
        FOR UPDATE OF effect SKIP LOCKED
        "#,
        effect_table.quoted(),
        dispatch_table.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.durable_effect_queue.lock_undispatched_effects",
        Some(statement.as_str()),
    );
    pooler_safe_query_as::<CoreDurableEffectRow>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(i64::from(limit.get()))
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)
        .map_err(PostgresAuthDurableEffectQueueDispatchError::from)
}

async fn insert_core_durable_effect_queue_dispatch(
    tx: &mut WriteTx<'_>,
    store_config: &PostgresAuthStoreConfig,
    effect_command_id: i64,
    queue_job_id: &[u8],
    task_name: &'static str,
    dedupe_key: String,
    enqueued_at: UnixSeconds,
) -> Result<(), PostgresAuthDurableEffectQueueDispatchError> {
    let dispatch_table =
        store_config.table_name(PostgresAuthCoreTable::CoreDurableEffectQueueDispatch)?;
    let statement = format!(
        r#"
        INSERT INTO {} (effect_command_id, queue_job_id, task_name, dedupe_key, enqueued_at)
        VALUES ($1,$2,$3,$4,$5)
        "#,
        dispatch_table.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.durable_effect_queue.insert_dispatch",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(effect_command_id)
        .bind(queue_job_id)
        .bind(task_name)
        .bind(dedupe_key.as_str())
        .bind(i64_from_unix_seconds(enqueued_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

fn queue_dedupe_key_for_effect_command_id(effect_command_id: i64) -> String {
    format!("{AUTH_QUEUE_DEDUPE_KEY_PREFIX}{effect_command_id}")
}

fn validate_queued_effect_command_id(effect_command_id: i64) -> Result<(), queue::TaskError> {
    if effect_command_id > 0 {
        Ok(())
    } else {
        Err(queue::TaskError::permanent(
            "queued auth durable effect id must be positive",
        ))
    }
}

fn permanent_task_error_from_core_error(error: Error) -> queue::TaskError {
    queue::TaskError::permanent(error.to_string())
}

fn application_subject_data_lifecycle_action_from_effect_kind(
    kind: i32,
) -> Result<ApplicationSubjectDataLifecycleAction, PostgresAuthDurableEffectQueueDispatchError> {
    match kind {
        DURABLE_EFFECT_KIND_DELETE_APPLICATION_SUBJECT_DATA => {
            Ok(ApplicationSubjectDataLifecycleAction::DeleteSubjectData)
        }
        DURABLE_EFFECT_KIND_DISABLE_APPLICATION_SUBJECT_DATA => {
            Ok(ApplicationSubjectDataLifecycleAction::DisableSubjectData)
        }
        _ => Err(
            PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
                "unknown application subject data lifecycle effect kind",
            ),
        ),
    }
}

fn application_subject_data_lifecycle_action_from_label(
    label: &str,
) -> Result<ApplicationSubjectDataLifecycleAction, Error> {
    match label {
        "delete_subject_data" => Ok(ApplicationSubjectDataLifecycleAction::DeleteSubjectData),
        "disable_subject_data" => Ok(ApplicationSubjectDataLifecycleAction::DisableSubjectData),
        _ => Err(Error::LoadedStateContradiction(
            "queued application subject data lifecycle action is unknown",
        )),
    }
}

fn security_notification_kind_label(
    value: i32,
) -> Result<&'static str, PostgresAuthDurableEffectQueueDispatchError> {
    match value {
        1 => Ok("trusted_device_created"),
        2 => Ok("credential_reset_authorized"),
        3 => Ok("credential_reset_pending_action_scheduled"),
        4 => Ok("credential_reset_executed"),
        5 => Ok("credential_reset_pending_action_cancelled"),
        6 => Ok("credential_replacement_executed"),
        7 => Ok("credential_replacement_pending_action_cancelled"),
        8 => Ok("credential_removal_executed"),
        9 => Ok("credential_removal_pending_action_cancelled"),
        10 => Ok("credential_regeneration_executed"),
        11 => Ok("credential_regeneration_pending_action_cancelled"),
        12 => Ok("subject_auth_state_deletion_pending_action_scheduled"),
        13 => Ok("subject_auth_state_deletion_executed"),
        14 => Ok("subject_auth_state_deletion_pending_action_cancelled"),
        15 => Ok("admin_support_credential_lifecycle_intervention_authorized"),
        16 => Ok("admin_support_credential_lifecycle_intervention_pending_action_scheduled"),
        17 => Ok("admin_support_intervention_requested"),
        18 => Ok("admin_support_intervention_approved"),
        19 => Ok("admin_support_intervention_denied"),
        20 => Ok("admin_support_intervention_expired"),
        21 => Ok("credential_added"),
        22 => Ok("credential_replacement_authorized"),
        23 => Ok("credential_replacement_pending_action_scheduled"),
        24 => Ok("credential_removal_authorized"),
        25 => Ok("credential_removal_pending_action_scheduled"),
        26 => Ok("credential_rotated"),
        27 => Ok("out_of_band_identifier_changed"),
        28 => Ok("out_of_band_identifier_change_pending_action_scheduled"),
        29 => Ok("out_of_band_identifier_change_pending_action_cancelled"),
        30 => Ok("credential_regeneration_authorized"),
        31 => Ok("credential_regeneration_pending_action_scheduled"),
        _ => Err(
            PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
                "unknown security notification kind",
            ),
        ),
    }
}

fn require_present<T>(
    value: Option<T>,
    reason: &'static str,
) -> Result<T, PostgresAuthDurableEffectQueueDispatchError> {
    value.ok_or(PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(reason))
}

fn require_absent<T>(
    value: Option<T>,
    reason: &'static str,
) -> Result<(), PostgresAuthDurableEffectQueueDispatchError> {
    if value.is_none() {
        Ok(())
    } else {
        Err(PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(reason))
    }
}
