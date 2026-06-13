use super::*;

use std::convert::Infallible;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use super::super::email_otp_method::{
    EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME, EmailOtpCompleteChallengeResponse, EmailOtpResendChallenge,
    PostgresEmailOtpDeliveryMessageDeliverer, PostgresEmailOtpDeliveryMessageRequest,
    PostgresEmailOtpMethodPlugin, PostgresEmailOtpMethodPluginConfig,
    PostgresEmailOtpSubjectResolver, PostgresEmailOtpVerifiedIdentifier,
};
use super::super::postgres_durable_effect_queue::{
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::super::postgres_method_runtime::{
    PostgresAuthMethodDurableEffectQueueRegistrationError, PostgresAuthMethodPlugin,
    enqueue_no_method_durable_effects_to_queue_in_current_transaction,
    register_no_queue_handlers_for_method_durable_effects,
};
use super::super::postgres_password_derived_signature_method::{
    PasswordDerivedSignatureVerifierForTest, PostgresPasswordDerivedSignatureMethodPlugin,
    PostgresPasswordDerivedSignatureMethodPluginConfig,
};
use super::super::postgres_recovery_code_method::{
    PostgresRecoveryCodeMethodPlugin, PostgresRecoveryCodeMethodPluginConfig,
};
use super::super::postgres_totp_method::{
    PostgresTotpCodeVerifier, PostgresTotpMethodError, PostgresTotpMethodPlugin,
    PostgresTotpMethodPluginConfig,
};
use crate::crypto::{
    PASSWORD_KDF_MIN_ITERATIONS, PASSWORD_KDF_MIN_MEMORY_COST_KIB, PASSWORD_KDF_SALT_SIZE,
    PasswordKdfParams, PasswordKdfSalt, SecretBytes,
};
use crate::db::queue;
use crate::db::{
    BootstrapConfig, DatabaseOperationObserver, PgIdentifier, PgQualifiedTableName, PgSchemaName,
    Pool, PoolConfig, Tx, WritePool, WriteTx, pooler_safe_query, pooler_safe_query_as,
    pooler_safe_query_scalar, unparameterized_simple_query,
};
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use http::header::{CONTENT_TYPE, COOKIE, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::Full;
use secrecy::SecretString;
use tower_layer::Layer;
use tower_service::Service;

static AUTH_POSTGRES_RUNTIME_TEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static AUTH_POSTGRES_RUNTIME_TEST_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

macro_rules! auth_runtime_test_fetch_one_in_transaction {
    ($pool:expr, $query:expr, $expect_message:literal) => {{
        let mut tx = $pool
            .begin_transaction()
            .await
            .expect("begin auth runtime test read transaction");
        let value = $query
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .expect($expect_message);
        tx.rollback()
            .await
            .expect("rollback auth runtime test read transaction");
        value
    }};
}

macro_rules! auth_runtime_test_fetch_optional_in_transaction {
    ($pool:expr, $query:expr, $expect_message:literal) => {{
        let mut tx = $pool
            .begin_transaction()
            .await
            .expect("begin auth runtime test read transaction");
        let value = $query
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .expect($expect_message);
        tx.rollback()
            .await
            .expect("rollback auth runtime test read transaction");
        value
    }};
}

fn auth_runtime_test_json_response_body(response: &http::Response<Vec<u8>>) -> serde_json::Value {
    serde_json::from_slice(response.body()).expect("mounted auth response body must be JSON")
}

#[derive(Clone, Copy)]
struct MountedAuthRequestStateEchoService;

impl Service<Request<Full<Bytes>>> for MountedAuthRequestStateEchoService {
    type Response = http::Response<Vec<u8>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
        let state = request
            .extensions()
            .get::<MountedAuthRequestState>()
            .cloned()
            .expect("mounted auth request state extension");
        Box::pin(async move {
            let body = match state.outcome() {
                MountedAuthRequestResolutionOutcome::Authenticated { .. } => "authenticated",
                MountedAuthRequestResolutionOutcome::NeedsStepUp { .. } => "needs_step_up",
                MountedAuthRequestResolutionOutcome::NeedsActiveProofFromTrustedDevice {
                    ..
                } => "needs_active_proof_from_trusted_device",
                MountedAuthRequestResolutionOutcome::NeedsFullAuthentication => {
                    "needs_full_authentication"
                }
            };
            Ok(http::Response::new(body.as_bytes().to_vec()))
        })
    }
}

#[derive(Clone)]
struct RecordingPostgresMountedSubjectMapper {
    recorded: Arc<Mutex<Vec<MountedAuthApplicationSubjectMappingRequest>>>,
}

impl RecordingPostgresMountedSubjectMapper {
    fn new(recorded: Arc<Mutex<Vec<MountedAuthApplicationSubjectMappingRequest>>>) -> Self {
        Self { recorded }
    }
}

impl MountedAuthApplicationSubjectMapper for RecordingPostgresMountedSubjectMapper {
    type ApplicationSubject = String;
    type Error = Infallible;

    fn map_application_subject<'a>(
        &'a self,
        request: MountedAuthApplicationSubjectMappingRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ApplicationSubject, Self::Error>> + 'a>> {
        Box::pin(async move {
            self.recorded
                .lock()
                .expect("record mapped application subject requests")
                .push(request);
            Ok("mapped-application-subject".to_owned())
        })
    }
}

#[derive(Clone, Copy)]
struct MountedAuthMappedApplicationSubjectEchoService;

impl Service<Request<Full<Bytes>>> for MountedAuthMappedApplicationSubjectEchoService {
    type Response = http::Response<Vec<u8>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Full<Bytes>>) -> Self::Future {
        let mapped = request
            .extensions()
            .get::<MountedAuthMappedApplicationSubject<String>>()
            .expect("mapped application subject extension")
            .clone();
        let request_state = request
            .extensions()
            .get::<MountedAuthRequestState>()
            .expect("mounted auth request state extension")
            .clone();
        Box::pin(async move {
            assert!(matches!(
                request_state.outcome(),
                MountedAuthRequestResolutionOutcome::Authenticated { .. }
            ));
            Ok(http::Response::new(
                mapped.application_subject().as_bytes().to_vec(),
            ))
        })
    }
}

struct PostgresRuntimeTestHarness {
    write_pool: WritePool,
    pool: Pool,
    database_operation_observer: DatabaseOperationObserver,
    store_config: super::super::postgres_store::PostgresAuthStoreConfig,
    runtime: super::super::postgres_runtime::PostgresAuthWebRuntime,
    schema: PgSchemaName,
    method_registry: Option<Arc<super::super::postgres_method_runtime::PostgresAuthMethodRegistry>>,
    method_plugin: Option<Arc<TestPostgresAuthMethodPlugin>>,
    email_otp_plugin: Option<Arc<PostgresEmailOtpMethodPlugin>>,
    totp_plugin: Option<Arc<PostgresTotpMethodPlugin<TestTotpCodeVerifier>>>,
    recovery_code_plugin: Option<Arc<PostgresRecoveryCodeMethodPlugin>>,
    password_derived_signature_plugin: Option<Arc<PostgresPasswordDerivedSignatureMethodPlugin>>,
}

#[derive(Clone, Copy, Default)]
struct FirstPartyMethodSelection {
    include_totp_plugin: bool,
    include_recovery_code_plugin: bool,
    include_password_derived_signature_plugin: bool,
}

fn recovery_code_id_for_runtime_test(tag: u8) -> [u8; 32] {
    [tag; 32]
}

struct RecordingMountedSupportStaffAuthorizer {
    authorization: Arc<Mutex<MountedAdminSupportStaffAuthorization>>,
    recorded_intervention_request_authorizations:
        Arc<Mutex<Vec<MountedAdminSupportInterventionRequestVerificationRequest>>>,
    recorded_requests: Arc<Mutex<Vec<MountedAdminSupportStaffVerificationRequest>>>,
}

impl RecordingMountedSupportStaffAuthorizer {
    fn new(authorization: MountedAdminSupportStaffAuthorization) -> Self {
        Self {
            authorization: Arc::new(Mutex::new(authorization)),
            recorded_intervention_request_authorizations: Arc::new(Mutex::new(Vec::new())),
            recorded_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_authorization(&self, authorization: MountedAdminSupportStaffAuthorization) {
        *self
            .authorization
            .lock()
            .expect("staff authorization mutex poisoned") = authorization;
    }

    fn recorded_intervention_request_authorizations(
        &self,
    ) -> Vec<MountedAdminSupportInterventionRequestVerificationRequest> {
        self.recorded_intervention_request_authorizations
            .lock()
            .expect("staff intervention request authorization mutex poisoned")
            .clone()
    }

    fn recorded_requests(&self) -> Vec<MountedAdminSupportStaffVerificationRequest> {
        self.recorded_requests
            .lock()
            .expect("staff authorization request mutex poisoned")
            .clone()
    }
}

struct RecordingCoreAuthOutOfBandMessageDeliverer {
    result: Result<(), CoreAuthDurableEffectDeliveryError>,
    recorded_requests: Arc<Mutex<Vec<CoreAuthOutOfBandMessageDeliveryRequest>>>,
}

impl RecordingCoreAuthOutOfBandMessageDeliverer {
    fn new(result: Result<(), CoreAuthDurableEffectDeliveryError>) -> Self {
        Self {
            result,
            recorded_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn recorded_requests(&self) -> Vec<CoreAuthOutOfBandMessageDeliveryRequest> {
        self.recorded_requests
            .lock()
            .expect("out-of-band delivery request mutex poisoned")
            .clone()
    }
}

impl CoreAuthOutOfBandMessageDeliverer for RecordingCoreAuthOutOfBandMessageDeliverer {
    fn deliver_out_of_band_message<'a>(
        &'a self,
        request: CoreAuthOutOfBandMessageDeliveryRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>
    {
        self.recorded_requests
            .lock()
            .expect("out-of-band delivery request mutex poisoned")
            .push(request);
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

struct RecordingCoreAuthSecurityNotificationDeliverer {
    result: Result<(), CoreAuthDurableEffectDeliveryError>,
    recorded_requests: Arc<Mutex<Vec<CoreAuthSecurityNotificationDeliveryRequest>>>,
}

impl RecordingCoreAuthSecurityNotificationDeliverer {
    fn new(result: Result<(), CoreAuthDurableEffectDeliveryError>) -> Self {
        Self {
            result,
            recorded_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn recorded_requests(&self) -> Vec<CoreAuthSecurityNotificationDeliveryRequest> {
        self.recorded_requests
            .lock()
            .expect("security notification delivery request mutex poisoned")
            .clone()
    }
}

impl CoreAuthSecurityNotificationDeliverer for RecordingCoreAuthSecurityNotificationDeliverer {
    fn deliver_security_notification<'a>(
        &'a self,
        request: CoreAuthSecurityNotificationDeliveryRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>
    {
        self.recorded_requests
            .lock()
            .expect("security notification delivery request mutex poisoned")
            .push(request);
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

struct RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator {
    result: Result<(), CoreAuthDurableEffectDeliveryError>,
    recorded_requests: Arc<Mutex<Vec<CoreAuthApplicationSubjectDataLifecycleRequest>>>,
}

impl RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator {
    fn new(result: Result<(), CoreAuthDurableEffectDeliveryError>) -> Self {
        Self {
            result,
            recorded_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn recorded_requests(&self) -> Vec<CoreAuthApplicationSubjectDataLifecycleRequest> {
        self.recorded_requests
            .lock()
            .expect("application subject data lifecycle request mutex poisoned")
            .clone()
    }
}

impl CoreAuthApplicationSubjectDataLifecycleIntegrator
    for RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator
{
    fn apply_application_subject_data_lifecycle_action<'a>(
        &'a self,
        request: CoreAuthApplicationSubjectDataLifecycleRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>
    {
        self.recorded_requests
            .lock()
            .expect("application subject data lifecycle request mutex poisoned")
            .push(request);
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordedEmailOtpDeliveryMessageRequest {
    queue_job_id: crate::queue::JobId,
    retry_count: u32,
    max_retries: u32,
    challenge_id: ActiveProofChallengeId,
    delivery_idempotency_key: String,
    recipient_handle: String,
    response_secret: Vec<u8>,
}

struct RecordingEmailOtpDeliveryMessageDeliverer {
    result: Result<(), AuthDurableEffectDeliveryError>,
    recorded_requests: Arc<Mutex<Vec<RecordedEmailOtpDeliveryMessageRequest>>>,
}

impl RecordingEmailOtpDeliveryMessageDeliverer {
    fn new(result: Result<(), AuthDurableEffectDeliveryError>) -> Self {
        Self {
            result,
            recorded_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn recorded_requests(&self) -> Vec<RecordedEmailOtpDeliveryMessageRequest> {
        self.recorded_requests
            .lock()
            .expect("email otp delivery request mutex poisoned")
            .clone()
    }
}

impl PostgresEmailOtpDeliveryMessageDeliverer for RecordingEmailOtpDeliveryMessageDeliverer {
    fn deliver_email_otp_message<'a>(
        &'a self,
        request: PostgresEmailOtpDeliveryMessageRequest,
    ) -> AuthDurableEffectDeliveryFuture<'a> {
        self.recorded_requests
            .lock()
            .expect("email otp delivery request mutex poisoned")
            .push(RecordedEmailOtpDeliveryMessageRequest {
                queue_job_id: request.queue_job_id(),
                retry_count: request.retry_count(),
                max_retries: request.max_retries(),
                challenge_id: request.challenge_id().clone(),
                delivery_idempotency_key: request.delivery_idempotency_key().to_owned(),
                recipient_handle: request.recipient_handle().to_owned(),
                response_secret: request.response_secret().expose_secret().to_vec(),
            });
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

impl MountedAdminSupportStaffAuthorizer for RecordingMountedSupportStaffAuthorizer {
    fn authorize_admin_support_intervention_request<'a>(
        &'a self,
        _headers: &'a HeaderMap,
        request: MountedAdminSupportInterventionRequestVerificationRequest,
    ) -> Pin<Box<dyn Future<Output = MountedAdminSupportStaffAuthorization> + Send + 'a>> {
        self.recorded_intervention_request_authorizations
            .lock()
            .expect("staff intervention request authorization mutex poisoned")
            .push(request);
        let authorization = *self
            .authorization
            .lock()
            .expect("staff authorization mutex poisoned");
        Box::pin(std::future::ready(authorization))
    }

    fn authorize_admin_support_staff_action<'a>(
        &'a self,
        _headers: &'a HeaderMap,
        request: MountedAdminSupportStaffVerificationRequest,
    ) -> Pin<Box<dyn Future<Output = MountedAdminSupportStaffAuthorization> + Send + 'a>> {
        self.recorded_requests
            .lock()
            .expect("staff authorization request mutex poisoned")
            .push(request);
        let authorization = *self
            .authorization
            .lock()
            .expect("staff authorization mutex poisoned");
        Box::pin(std::future::ready(authorization))
    }
}

impl PostgresRuntimeTestHarness {
    async fn connect_required() -> Self {
        Self::connect_required_with_registered_plugins(None, true).await
    }

    async fn connect_required_without_method_registry() -> Self {
        Self::connect_required_with_registered_plugins(None, false).await
    }

    async fn connect_required_with_method_plugin(
        failure_mode: Option<TestMethodCommitFailureMode>,
    ) -> Self {
        Self::connect_required_with_registered_plugins(failure_mode, false).await
    }

    async fn connect_required_with_email_otp_method() -> Self {
        Self::connect_required_with_registered_plugins(None, true).await
    }

    async fn connect_required_with_email_otp_delivery_message_deliverer(
        delivery_message_deliverer: Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer>,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection::default(),
            config(),
            Some(delivery_message_deliverer),
        )
        .await
    }

    async fn connect_required_with_email_otp_subject_resolver(
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            None,
            true,
            Some(subject_resolver),
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection::default(),
        )
        .await
    }

    async fn connect_required_with_message_signature_method() -> Self {
        Self::connect_required_with_registered_test_method(
            ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("message signature method"),
        )
        .await
    }

    async fn connect_required_with_origin_bound_public_key_method() -> Self {
        Self::connect_required_with_registered_test_method(
            ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
                .expect("origin-bound public-key method"),
        )
        .await
    }

    async fn connect_required_with_federated_identity_method() -> Self {
        Self::connect_required_with_registered_test_method(
            ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
                .expect("federated identity method"),
        )
        .await
    }

    async fn connect_required_with_totp_method() -> Self {
        Self::connect_required_with_configured_secret_plugins(true, false).await
    }

    async fn connect_required_with_recovery_code_method() -> Self {
        Self::connect_required_with_configured_secret_plugins(false, true).await
    }

    async fn connect_required_with_password_derived_signature_method() -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_password_derived_signature_plugin: true,
                ..FirstPartyMethodSelection::default()
            },
        )
        .await
    }

    async fn connect_required_with_configured_secret_plugins(
        include_totp_plugin: bool,
        include_recovery_code_plugin: bool,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_totp_plugin,
                include_recovery_code_plugin,
                ..FirstPartyMethodSelection::default()
            },
        )
        .await
    }

    async fn connect_required_with_registered_test_method(method: ProofMethodDeclaration) -> Self {
        Self::connect_required_with_registered_test_method_and_verification_mode(
            method,
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await
    }

    async fn connect_required_with_registered_authoritative_test_method(
        method: ProofMethodDeclaration,
    ) -> Self {
        Self::connect_required_with_registered_test_method_and_verification_mode(
            method,
            TestActiveMethodVerificationMode::AuthoritativeConfirmation,
        )
        .await
    }

    async fn connect_required_with_registered_test_method_and_verification_mode(
        method: ProofMethodDeclaration,
        active_method_verification_mode: TestActiveMethodVerificationMode,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method(
            Some(TestMethodCommitFailureMode::None),
            false,
            None,
            Some(method),
            active_method_verification_mode,
        )
        .await
    }

    async fn connect_required_with_registered_plugins(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method(
            failure_mode,
            include_email_otp_plugin,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
        )
        .await
    }

    async fn connect_required_with_registered_plugins_for_test_method(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
        email_otp_subject_resolver: Option<Arc<dyn PostgresEmailOtpSubjectResolver>>,
        test_method: Option<ProofMethodDeclaration>,
        active_method_verification_mode: TestActiveMethodVerificationMode,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_and_configured_methods(
            failure_mode,
            include_email_otp_plugin,
            email_otp_subject_resolver,
            test_method,
            active_method_verification_mode,
            FirstPartyMethodSelection::default(),
        )
        .await
    }

    async fn connect_required_with_registered_plugins_for_test_method_and_configured_methods(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
        email_otp_subject_resolver: Option<Arc<dyn PostgresEmailOtpSubjectResolver>>,
        test_method: Option<ProofMethodDeclaration>,
        active_method_verification_mode: TestActiveMethodVerificationMode,
        first_party_methods: FirstPartyMethodSelection,
    ) -> Self {
        Self::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            failure_mode,
            include_email_otp_plugin,
            email_otp_subject_resolver,
            test_method,
            active_method_verification_mode,
            first_party_methods,
            config(),
            None,
        )
        .await
    }

    async fn connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
        failure_mode: Option<TestMethodCommitFailureMode>,
        include_email_otp_plugin: bool,
        email_otp_subject_resolver: Option<Arc<dyn PostgresEmailOtpSubjectResolver>>,
        test_method: Option<ProofMethodDeclaration>,
        active_method_verification_mode: TestActiveMethodVerificationMode,
        first_party_methods: FirstPartyMethodSelection,
        runtime_config: Config,
        email_otp_delivery_message_deliverer: Option<
            Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer>,
        >,
    ) -> Self {
        let database_url = required_auth_postgres_runtime_test_database_url();

        let write_pool =
            WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
                .await
                .expect("connect write test database");
        let raw_pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
            .await
            .expect("connect test database");
        let database_operation_observer = DatabaseOperationObserver::default();
        let pool =
            raw_pool.clone_with_database_operation_observer(database_operation_observer.clone());
        let db_bootstrap_config =
            BootstrapConfig::new(PgSchemaName::new(unique_runtime_test_schema_name()));
        let schema = db_bootstrap_config.schema_name().clone();
        db_bootstrap_config
            .migrate_schema(&write_pool)
            .await
            .expect("migrate DB foundation before auth runtime schema");

        let store_config =
            super::super::postgres_store::PostgresAuthStoreConfig::for_db_bootstrap_config(
                &db_bootstrap_config,
            )
            .expect("store config");
        let method_plugin = match (failure_mode, test_method) {
            (Some(failure_mode), Some(method)) => Some(Arc::new(
                TestPostgresAuthMethodPlugin::with_method_and_verification_mode(
                    &schema,
                    method,
                    failure_mode,
                    active_method_verification_mode,
                ),
            )),
            (Some(failure_mode), None) => Some(Arc::new(TestPostgresAuthMethodPlugin::new(
                &schema,
                failure_mode,
            ))),
            (None, Some(method)) => Some(Arc::new(
                TestPostgresAuthMethodPlugin::with_method_and_verification_mode(
                    &schema,
                    method,
                    TestMethodCommitFailureMode::None,
                    active_method_verification_mode,
                ),
            )),
            (None, None) => None,
        };
        let email_otp_plugin = if include_email_otp_plugin {
            let mut plugin = PostgresEmailOtpMethodPlugin::new(
                PostgresEmailOtpMethodPluginConfig::for_db_bootstrap_config(&db_bootstrap_config)
                    .expect("email otp method config"),
                test_keyset("tests.auth.postgres-runtime.email-otp.v1"),
            )
            .expect("email otp method plugin");
            let subject_resolver = email_otp_subject_resolver
                .unwrap_or_else(|| Arc::new(EmbeddedSubjectEmailOtpResolver));
            plugin = plugin.with_subject_resolver(subject_resolver);
            if let Some(deliverer) = email_otp_delivery_message_deliverer {
                plugin = plugin.with_delivery_message_deliverer(deliverer);
            }
            Some(Arc::new(plugin))
        } else {
            None
        };
        let totp_plugin = if first_party_methods.include_totp_plugin {
            Some(Arc::new(
                PostgresTotpMethodPlugin::new(
                    PostgresTotpMethodPluginConfig::for_db_bootstrap_config(&db_bootstrap_config)
                        .expect("totp method config"),
                    test_keyset("tests.auth.postgres-runtime.totp.v1"),
                    TestTotpCodeVerifier,
                )
                .expect("totp method plugin"),
            ))
        } else {
            None
        };
        let recovery_code_plugin = if first_party_methods.include_recovery_code_plugin {
            Some(Arc::new(
                PostgresRecoveryCodeMethodPlugin::new(
                    PostgresRecoveryCodeMethodPluginConfig::for_db_bootstrap_config(
                        &db_bootstrap_config,
                    )
                    .expect("recovery code method config"),
                    test_keyset("tests.auth.postgres-runtime.recovery-code.v1"),
                )
                .expect("recovery code method plugin"),
            ))
        } else {
            None
        };
        let password_derived_signature_plugin =
            if first_party_methods.include_password_derived_signature_plugin {
                Some(Arc::new(
                    PostgresPasswordDerivedSignatureMethodPlugin::new(
                        PostgresPasswordDerivedSignatureMethodPluginConfig::for_db_bootstrap_config(
                            &db_bootstrap_config,
                        )
                        .expect("password-derived signature method config"),
                    )
                    .expect("password-derived signature method plugin"),
                ))
            } else {
                None
            };
        let mut store = super::super::postgres_store::PostgresAuthStore::new(
            store_config.clone(),
            test_keyset("tests.auth.postgres-runtime.credentials.v1"),
        );
        let mut plugins: Vec<
            Arc<dyn super::super::postgres_method_runtime::PostgresAuthMethodPlugin>,
        > = Vec::new();
        if let Some(plugin) = method_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = email_otp_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = totp_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = recovery_code_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        if let Some(plugin) = password_derived_signature_plugin.as_ref() {
            plugins.push(plugin.clone());
        }
        let method_registry = if plugins.is_empty() {
            None
        } else {
            Some(Arc::new(
                super::super::postgres_method_runtime::PostgresAuthMethodRegistry::new(plugins)
                    .expect("test method registry"),
            ))
        };
        if let Some(registry) = method_registry.as_ref() {
            store = store.with_method_registry(Arc::clone(registry));
        }
        store
            .migrate_schema(&write_pool)
            .await
            .expect("migrate auth schema");
        let runtime = super::super::postgres_runtime::PostgresAuthWebRuntime::new(
            AuthWebRuntime::new(runtime_config, auth_web_transport()),
            pool.clone(),
            store,
            Arc::new(hashcash_verifier_for_test()),
        );
        let write_pool =
            write_pool.clone_with_database_operation_observer(database_operation_observer.clone());

        Self {
            write_pool,
            pool,
            database_operation_observer,
            store_config,
            runtime,
            schema,
            method_registry,
            method_plugin,
            email_otp_plugin,
            totp_plugin,
            recovery_code_plugin,
            password_derived_signature_plugin,
        }
    }

    async fn drop_schema(&self) {
        let drop_schema = format!("DROP SCHEMA {} CASCADE", self.schema.identifier().quoted());
        unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
            .execute(self.pool.sqlx_pool())
            .await
            .expect("drop auth runtime test schema");
    }
}

struct AuthRuntimeQueueTestStore {
    store: crate::db::queue::Store,
    jobs_table: PgQualifiedTableName,
}

async fn migrate_queue_store_for_auth_runtime_test(
    harness: &PostgresRuntimeTestHarness,
) -> AuthRuntimeQueueTestStore {
    let jobs_table = PgQualifiedTableName::new(
        Some(harness.schema.clone()),
        PgIdentifier::new("__paranoid_auth_queue_jobs").expect("queue jobs table"),
    );
    let dead_letter_table = PgQualifiedTableName::new(
        Some(harness.schema.clone()),
        PgIdentifier::new("__paranoid_auth_queue_dead_letters").expect("queue dead-letter table"),
    );
    let pause_table = PgQualifiedTableName::new(
        Some(harness.schema.clone()),
        PgIdentifier::new("__paranoid_auth_queue_pauses").expect("queue pause table"),
    );
    let queue_config = crate::db::queue::StoreConfig {
        table_name: jobs_table.clone(),
        dead_letter_table_name: dead_letter_table,
        pause_table_name: pause_table,
        schema_ledger_table_name: harness
            .store_config
            .schema_ledger_table_name()
            .expect("auth schema ledger table"),
        payload_json_limit_bytes: crate::db::queue::DEFAULT_QUEUE_PAYLOAD_JSON_LIMIT_BYTES,
    };
    let store = crate::db::queue::Store::new_inner(queue_config).expect("queue store config");
    store
        .migrate_schema(&harness.write_pool)
        .await
        .expect("migrate auth runtime queue schema");
    AuthRuntimeQueueTestStore { store, jobs_table }
}

fn auth_runtime_queue_worker_config() -> crate::queue::WorkerConfig {
    crate::queue::WorkerConfig {
        concurrency: 10,
        startup_jitter_max_delay: Some(Duration::ZERO),
        default_job_timeout: crate::queue::WorkerDefaultJobTimeout::NoTimeout,
        retry_policy: crate::queue::RetryPolicy {
            strategy: crate::queue::RetryBackoffStrategy::Fixed {
                backoff: Duration::from_millis(1),
            },
            jitter_fraction: 0.0,
            ..crate::queue::RetryPolicy::default()
        },
        ..crate::queue::WorkerConfig::default()
    }
}

fn mounted_auth_durable_effect_worker_service_for_test(
    harness: &PostgresRuntimeTestHarness,
    queue_test_store: &AuthRuntimeQueueTestStore,
    out_of_band_deliverer: Arc<dyn CoreAuthOutOfBandMessageDeliverer>,
    security_notification_deliverer: Arc<dyn CoreAuthSecurityNotificationDeliverer>,
) -> MountedAuthDurableEffectPostgresWorkerService {
    let application_subject_data_integrator =
        Arc::new(RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(())));
    mounted_auth_durable_effect_worker_service_for_test_with_application_subject_data_integrator(
        harness,
        queue_test_store,
        out_of_band_deliverer,
        security_notification_deliverer,
        application_subject_data_integrator,
    )
}

fn mounted_auth_durable_effect_worker_service_for_test_with_application_subject_data_integrator(
    harness: &PostgresRuntimeTestHarness,
    queue_test_store: &AuthRuntimeQueueTestStore,
    out_of_band_deliverer: Arc<dyn CoreAuthOutOfBandMessageDeliverer>,
    security_notification_deliverer: Arc<dyn CoreAuthSecurityNotificationDeliverer>,
    application_subject_data_integrator: Arc<dyn CoreAuthApplicationSubjectDataLifecycleIntegrator>,
) -> MountedAuthDurableEffectPostgresWorkerService {
    MountedAuthDurableEffectPostgresWorkerService::new(
        harness.write_pool.clone(),
        queue_test_store.store.clone(),
        &harness.runtime,
        MountedAuthDurableEffectWorkerIntegrations::new(
            out_of_band_deliverer,
            security_notification_deliverer,
            application_subject_data_integrator,
        ),
    )
}

fn assert_no_database_operations(observer: &DatabaseOperationObserver, expectation: &str) {
    let records = observer.records();
    assert!(
        records.is_empty(),
        "{expectation}; observed database operations: {records:?}"
    );
}

fn assert_database_operations_include_label(
    observer: &DatabaseOperationObserver,
    expected_label: &'static str,
    expectation: &'static str,
) {
    let records = observer.records();
    assert!(
        records.iter().any(|record| record.label == expected_label),
        "{expectation}; expected database operation label {expected_label:?}; observed database operations: {records:?}"
    );
}

fn assert_database_operation_labels_exact(
    observer: &DatabaseOperationObserver,
    expected_labels: &[&'static str],
    expectation: &'static str,
) {
    let records = observer.records();
    let actual_labels = records
        .iter()
        .map(|record| record.label)
        .collect::<Vec<_>>();
    assert_eq!(
        actual_labels, expected_labels,
        "{expectation}; observed database operations: {records:?}"
    );
}

fn assert_missing_active_proof_continuation_error(
    error: super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
) {
    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::MissingActiveProofContinuationCookie
        )
    ));
}

fn assert_invalid_active_proof_continuation_payload_error(
    error: super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
) {
    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::InvalidActiveProofContinuationCookiePayload
        )
    ));
}

fn assert_expired_active_proof_continuation_error(
    error: super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
) {
    assert!(matches!(
        error,
        super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::ActiveProofAttemptNotOpen
        )
    ));
}

async fn runtime_bound_recovery_continuation_headers_for_runtime_test(
    harness: &PostgresRuntimeTestHarness,
    subject_label: &str,
    authentication_label: &str,
) -> HeaderMap {
    let subject_id: SubjectId = id(subject_label);
    let issued_auth = complete_full_authentication_through_runtime(
        &harness.runtime,
        &harness.pool,
        &harness.store_config,
        email_otp_plugin_for_harness(harness),
        authentication_label,
        20,
        subject_id,
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        &harness.runtime,
        issued_auth.session_cookie_pair.as_str(),
        at(70),
        ProofUse::RecoverOrReplaceCredential,
    )
    .await;
    headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()])
}

fn rendered_active_proof_continuation_cookie_pair_for_runtime_test(
    proof_use: ProofUse,
    subject_id: Option<SubjectId>,
    issued_at: UnixSeconds,
    attempt_fast_fail_until: UnixSeconds,
) -> String {
    let attempt_id = id("rendered-continuation-cookie-attempt");
    let continuation_cookie = MaterializedActiveProofContinuationCookieResponse::new(
        ActiveProofContinuationCookieDraft {
            attempt_id,
            proof_use,
            subject_binding: match (&proof_use, &subject_id) {
                (ProofUse::RecoverOrReplaceCredential, Some(_)) => {
                    ActiveProofContinuationSubjectBinding::VerifiedProofBoundSubject
                }
                (_, Some(_)) => ActiveProofContinuationSubjectBinding::RuntimeBoundSubject,
                (_, None) => ActiveProofContinuationSubjectBinding::NoSubject,
            },
            subject_id,
            attempt_fast_fail_until,
        },
        AuthCredentialSecret::try_from(b"rendered-continuation-cookie-secret".as_slice())
            .expect("continuation credential secret"),
    );
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofContinuationCookie(continuation_cookie),
    ]);
    let headers = auth_web_transport()
        .render_set_cookie_headers(issued_at, effects)
        .expect("render active-proof continuation cookie");
    active_proof_continuation_cookie_pair_from_set_cookie(&headers).to_owned()
}

fn rendered_session_cookie_pair_for_runtime_test(
    draft: SessionCookieDraft,
    issued_at: UnixSeconds,
) -> String {
    let session_cookie = MaterializedSessionCookieResponse::new(
        draft,
        AuthCredentialSecret::try_from(b"rendered-session-cookie-secret".as_slice())
            .expect("session credential secret"),
    );
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueSessionCookie(session_cookie),
    ]);
    let headers = auth_web_transport()
        .render_set_cookie_headers(issued_at, effects)
        .expect("render session cookie");
    cookie_pair_from_set_cookie(&headers, "__Host-__paranoid_auth_session=").to_owned()
}

fn rendered_trusted_device_cookie_pair_for_runtime_test(
    draft: TrustedDeviceCookieDraft,
    issued_at: UnixSeconds,
) -> String {
    let trusted_device_cookie = MaterializedTrustedDeviceCookieResponse::new(
        draft,
        AuthCredentialSecret::try_from(b"rendered-trusted-device-cookie-secret".as_slice())
            .expect("trusted-device credential secret"),
    );
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueTrustedDeviceCookie(trusted_device_cookie),
    ]);
    let headers = auth_web_transport()
        .render_set_cookie_headers(issued_at, effects)
        .expect("render trusted-device cookie");
    cookie_pair_from_set_cookie(&headers, "__Host-__paranoid_auth_trusted_device=").to_owned()
}

fn config_with_divergent_credential_reset_role_policies() -> Config {
    let mut value = config();
    value.credential_lifecycle_policy.credential_reset = CredentialResetLifecyclePolicies {
        ordinary_credential: CredentialResetLifecyclePolicy {
            independent_evidence_requirement:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            delayed_action_timing: Some(DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(120),
                expires_after: DurationSeconds::new(220),
            }),
            authenticated_planning_step_up_freshness: StepUpFreshnessRequirement::NotRequired,
            authenticated_execution_step_up_freshness: StepUpFreshnessRequirement::NotRequired,
            authenticated_cancellation_step_up_freshness: StepUpFreshnessRequirement::NotRequired,
        },
        second_factor_credential: CredentialResetLifecyclePolicy {
            independent_evidence_requirement:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            delayed_action_timing: Some(DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(300),
                expires_after: DurationSeconds::new(500),
            }),
            authenticated_planning_step_up_freshness: StepUpFreshnessRequirement::Required,
            authenticated_execution_step_up_freshness: StepUpFreshnessRequirement::Required,
            authenticated_cancellation_step_up_freshness: StepUpFreshnessRequirement::Required,
        },
    };
    value
}

fn email_otp_plugin_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> &PostgresEmailOtpMethodPlugin {
    harness
        .email_otp_plugin
        .as_ref()
        .expect("email otp method plugin")
}

fn password_derived_signature_plugin_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> &PostgresPasswordDerivedSignatureMethodPlugin {
    harness
        .password_derived_signature_plugin
        .as_ref()
        .expect("password-derived signature method plugin")
}

fn totp_plugin_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> &PostgresTotpMethodPlugin<TestTotpCodeVerifier> {
    harness.totp_plugin.as_ref().expect("TOTP method plugin")
}

async fn complete_password_derived_signature_full_authentication_proof_for_runtime_test(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    plugin: &PostgresPasswordDerivedSignatureMethodPlugin,
    lookup_handle: &[u8],
    password: &[u8],
    issued_at: UnixSeconds,
    completed_at: UnixSeconds,
) -> ActiveProofAttemptId {
    let empty_headers = HeaderMap::new();
    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: issued_at,
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                issued_at,
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), method_challenge),
        outcome => panic!("expected password-derived challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        password,
        method_challenge,
    )
    .expect("password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &response_payload,
        completed_at,
    );
    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: completed_at,
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete password-derived signature proof");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: plugin.method().verified_proof_summary(),
        }
    );
    attempt_id
}

async fn complete_totp_step_up_proof_for_runtime_test(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    email_otp: &PostgresEmailOtpMethodPlugin,
    plugin: &PostgresTotpMethodPlugin<TestTotpCodeVerifier>,
    subject_id: SubjectId,
    flow_label: &str,
    auth_start_at: u64,
    step_up_start_at: UnixSeconds,
    proof_completed_at: UnixSeconds,
    secret: &[u8],
) -> ActiveProofAttemptId {
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp,
        flow_label,
        auth_start_at,
        subject_id,
        false,
    )
    .await;
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        issued_auth.session_cookie_pair.as_str(),
        step_up_start_at,
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let secret_response = totp_test_method_response_payload(secret, proof_completed_at);
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_known_subject_completion(
        &continuation_headers,
        plugin.method(),
        &secret_response,
        proof_completed_at,
    );
    let completed = runtime
        .execute_known_subject_active_proof_method_response_from_headers(
            &continuation_headers,
            CompleteKnownSubjectActiveProofMethodResponse {
                now: proof_completed_at,
                method: plugin.method().clone(),
                secret_response,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete TOTP step-up proof");
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: started.attempt_id.clone(),
            proof: plugin.method().verified_proof_summary(),
        }
    );
    started.attempt_id
}

struct EmbeddedSubjectEmailOtpResolver;

impl PostgresEmailOtpSubjectResolver for EmbeddedSubjectEmailOtpResolver {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        super::super::email_otp_method::PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(subject_label) = recipient_handle
                .rsplit_once(":subject:")
                .map(|(_, label)| label)
            else {
                return Ok(PostgresEmailOtpVerifiedIdentifier::new(
                    None,
                    id("embedded-email-otp-unresolved-source"),
                ));
            };
            let subject_id = SubjectId::from_bytes(subject_label.as_bytes().to_vec())
                .map_err(super::super::email_otp_method::PostgresEmailOtpMethodError::Core)?;
            Ok(PostgresEmailOtpVerifiedIdentifier::new(
                Some(subject_id),
                id(&format!("embedded-email-source:{subject_label}")),
            ))
        })
    }
}

struct StaticEmailOtpSubjectResolver {
    recipient_handle: String,
    subject_id: SubjectId,
    source_id: VerifiedProofSourceId,
    calls: AtomicU64,
}

impl StaticEmailOtpSubjectResolver {
    fn new(
        recipient_handle: &str,
        subject_id: SubjectId,
        source_id: VerifiedProofSourceId,
    ) -> Self {
        Self {
            recipient_handle: recipient_handle.to_owned(),
            subject_id,
            source_id,
            calls: AtomicU64::new(0),
        }
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PostgresEmailOtpSubjectResolver for StaticEmailOtpSubjectResolver {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        super::super::email_otp_method::PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if recipient_handle == self.recipient_handle {
                Ok(PostgresEmailOtpVerifiedIdentifier::new(
                    Some(self.subject_id.clone()),
                    self.source_id.clone(),
                ))
            } else {
                Ok(PostgresEmailOtpVerifiedIdentifier::new(
                    None,
                    id("static-email-otp-unresolved-source"),
                ))
            }
        })
    }
}

#[derive(Clone, Copy)]
enum TestMethodCommitFailureMode {
    None,
    FailMutation,
    FailDurableEffectCommand,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TestActiveMethodVerificationMode {
    BeforeStateLoad,
    AuthoritativeConfirmation,
}

struct TestPostgresAuthMethodPlugin {
    method: ProofMethodDeclaration,
    state_table: PgQualifiedTableName,
    durable_effect_table: PgQualifiedTableName,
    failure_mode: TestMethodCommitFailureMode,
    active_method_verification_mode: TestActiveMethodVerificationMode,
}

#[derive(Clone, Copy)]
struct TestTotpCodeVerifier;

impl PostgresTotpCodeVerifier for TestTotpCodeVerifier {
    fn verify_totp_code(
        &self,
        secret: &SecretBytes,
        submitted_code: &[u8],
        now: UnixSeconds,
    ) -> Result<bool, PostgresTotpMethodError> {
        Ok(submitted_code == test_totp_code_bytes(secret.expose_secret(), now))
    }

    fn accepted_totp_codes_for_challenge_window(
        &self,
        secret: &SecretBytes,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Vec<KnownSubjectActiveProofSecretResponse>, PostgresTotpMethodError> {
        if expires_at <= issued_at {
            return Err(PostgresTotpMethodError::Core(
                Error::ActiveProofChallengeCookieExpiresAtOrBeforeIssuedAt,
            ));
        }
        let first_step = issued_at.get() / 30;
        let last_step = expires_at
            .get()
            .checked_sub(1)
            .ok_or(PostgresTotpMethodError::Core(Error::TimeOverflow))?
            / 30;
        let mut accepted_codes = Vec::new();
        for step in first_step..=last_step {
            let step_time = step
                .checked_mul(30)
                .ok_or(PostgresTotpMethodError::Core(Error::TimeOverflow))?;
            accepted_codes.push(
                KnownSubjectActiveProofSecretResponse::try_from_bytes(test_totp_code_bytes(
                    secret.expose_secret(),
                    UnixSeconds::new(step_time),
                ))
                .map_err(PostgresTotpMethodError::Core)?,
            );
        }
        Ok(accepted_codes)
    }
}

impl TestPostgresAuthMethodPlugin {
    fn new(schema: &PgSchemaName, failure_mode: TestMethodCommitFailureMode) -> Self {
        Self {
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("test method declaration"),
            state_table: PgQualifiedTableName::new(
                Some(schema.clone()),
                PgIdentifier::new("__paranoid_auth_test_method_state").expect("state table name"),
            ),
            durable_effect_table: PgQualifiedTableName::new(
                Some(schema.clone()),
                PgIdentifier::new("__paranoid_auth_test_method_durable_effects")
                    .expect("durable effect table name"),
            ),
            failure_mode,
            active_method_verification_mode: TestActiveMethodVerificationMode::BeforeStateLoad,
        }
    }

    fn with_method(
        schema: &PgSchemaName,
        method: ProofMethodDeclaration,
        failure_mode: TestMethodCommitFailureMode,
    ) -> Self {
        let mut plugin = Self::new(schema, failure_mode);
        plugin.method = method;
        plugin
    }

    fn with_method_and_verification_mode(
        schema: &PgSchemaName,
        method: ProofMethodDeclaration,
        failure_mode: TestMethodCommitFailureMode,
        active_method_verification_mode: TestActiveMethodVerificationMode,
    ) -> Self {
        let mut plugin = Self::with_method(schema, method, failure_mode);
        plugin.active_method_verification_mode = active_method_verification_mode;
        plugin
    }

    async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
        let state_statement = format!(
            r#"
            CREATE TABLE {} (
                payload BYTEA PRIMARY KEY,
                proof_family INTEGER NOT NULL,
                method_label TEXT COLLATE "C" NOT NULL,
                mutation_operation TEXT COLLATE "C" NOT NULL
            )
            "#,
            self.state_table.quoted()
        );
        tx.record_database_operation(
            crate::db::DatabaseOperationKind::Execute,
            "auth_core.test_method.schema.create_state_table",
            Some(state_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(state_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(crate::db::DbError::query)?;
        let durable_effect_statement = format!(
            r#"
            CREATE TABLE {} (
                method_effect_id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                payload BYTEA NOT NULL,
                proof_family INTEGER NOT NULL,
                method_label TEXT COLLATE "C" NOT NULL,
                durable_effect_operation TEXT COLLATE "C" NOT NULL
            )
            "#,
            self.durable_effect_table.quoted()
        );
        tx.record_database_operation(
            crate::db::DatabaseOperationKind::Execute,
            "auth_core.test_method.schema.create_durable_effect_table",
            Some(durable_effect_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(durable_effect_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(crate::db::DbError::query)?;
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
        validate_test_method_table_exists(tx, &self.state_table).await?;
        validate_test_method_table_exists(tx, &self.durable_effect_table).await
    }

    async fn count_state_rows(&self, pool: &Pool) -> i64 {
        let statement = format!("SELECT count(*) FROM {}", self.state_table.quoted());
        auth_runtime_test_fetch_one_in_transaction!(
            pool,
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
            "count test method state rows"
        )
    }

    async fn count_durable_effect_rows(&self, pool: &Pool) -> i64 {
        let statement = format!(
            "SELECT count(*) FROM {}",
            self.durable_effect_table.quoted()
        );
        auth_runtime_test_fetch_one_in_transaction!(
            pool,
            pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
            "count test method durable effect rows"
        )
    }

    fn validate_operation(
        actual: &str,
        expected: &'static str,
    ) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
        if actual == expected {
            Ok(())
        } else {
            Err(
                super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(
                    actual.to_owned(),
                ),
            )
        }
    }

    fn challenge_presentation_prefix(
        &self,
    ) -> Result<&'static [u8], super::super::postgres_method_runtime::PostgresAuthMethodBuildError>
    {
        test_challenge_presentation_prefix(self.method.family()).ok_or_else(|| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_method_challenge_issue",
                "test plugin cannot issue this proof family".to_owned(),
            )
        })
    }

    fn response_challenge_prefix(
        &self,
    ) -> Result<&'static [u8], super::super::postgres_method_runtime::PostgresAuthMethodBuildError>
    {
        test_response_challenge_prefix(self.method.family()).ok_or_else(|| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                "test plugin cannot complete this proof family".to_owned(),
            )
        })
    }

    fn parse_active_method_response_subject_and_source(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<
        (SubjectId, VerifiedProofSourceId),
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        if challenge.proof != self.method.verified_proof_summary() {
            return Err(
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response used a different proof".to_owned(),
                ),
            );
        }
        let response_after_prefix = response
            .response_payload
            .as_bytes()
            .strip_prefix(self.response_challenge_prefix()?)
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response payload is malformed".to_owned(),
                )
            })?;
        let nonce_len = challenge.nonce.as_bytes().len();
        if response_after_prefix.len() <= nonce_len {
            return Err(
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response payload is missing subject binding".to_owned(),
                ),
            );
        }
        let (response_nonce, response_after_nonce) = response_after_prefix.split_at(nonce_len);
        if response_nonce != challenge.nonce.as_bytes() {
            return Err(
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response nonce does not match the runtime challenge".to_owned(),
                ),
            );
        }
        let response_after_state = response_after_nonce
            .strip_prefix(b";state:")
            .and_then(|after_marker| {
                after_marker.strip_prefix(challenge.method_challenge_state.as_bytes())
            })
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response method state does not match the sealed challenge state"
                        .to_owned(),
                )
            })?;
        let subject_and_source = response_after_state
            .strip_prefix(b";subject:")
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response subject binding is malformed".to_owned(),
                )
            })?;
        let source_marker = b";source:";
        let source_marker_start = subject_and_source
            .windows(source_marker.len())
            .position(|window| window == source_marker)
            .ok_or_else(|| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    "active proof response source binding is missing".to_owned(),
                )
            })?;
        let (subject_id_bytes, source_with_marker) =
            subject_and_source.split_at(source_marker_start);
        let source_id_bytes = &source_with_marker[source_marker.len()..];
        let subject_id = SubjectId::from_bytes(subject_id_bytes.to_vec()).map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })?;
        let source_id = VerifiedProofSourceId::from_bytes(source_id_bytes.to_vec()).map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })?;
        Ok((subject_id, source_id))
    }

    fn verify_active_method_response(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<
        super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse,
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        let (subject_id, source_id) =
            self.parse_active_method_response_subject_and_source(challenge, response)?;
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            challenge.proof.clone(),
            Some(subject_id),
            test_active_method_proof_source(self.method.family(), source_id),
        )
        .map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })?;
        super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse::new(
            verified_proof,
            Vec::new(),
        )
        .map_err(|error| {
            super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "active_proof_completion",
                error.to_string(),
            )
        })
    }
}

fn test_challenge_presentation_prefix(family: ProofFamily) -> Option<&'static [u8]> {
    match family {
        ProofFamily::MessageSignature => Some(b"test-message-signature-challenge:"),
        ProofFamily::OriginBoundPublicKey => Some(
            b"test-origin-bound-public-key-challenge:rp=example.test;origin=https://example.test;nonce:",
        ),
        ProofFamily::FederatedIdentityAssertion => Some(
            b"test-federated-identity-state:issuer=https://issuer.example;audience=paranoid-client;redirect=https://app.example/auth/callback;state:",
        ),
        _ => None,
    }
}

fn test_active_method_proof_source(
    family: ProofFamily,
    source_id: VerifiedProofSourceId,
) -> VerifiedProofSource {
    let source_kind = match family {
        ProofFamily::MessageSignature | ProofFamily::OriginBoundPublicKey => {
            VerifiedProofSourceKind::CredentialInstance
        }
        ProofFamily::FederatedIdentityAssertion => VerifiedProofSourceKind::ExternalAuthority,
        other => panic!("unexpected active method proof family {other:?}"),
    };
    VerifiedProofSource::new(source_kind, source_id)
}

fn test_known_subject_method_proof_source(
    family: ProofFamily,
    subject_id: &SubjectId,
) -> Option<VerifiedProofSource> {
    match family {
        ProofFamily::SharedSecretOtp | ProofFamily::RecoveryCode => {
            let mut source_id = b"known-subject-method-source:".to_vec();
            source_id.extend_from_slice(format!("{family:?}:").as_bytes());
            source_id.extend_from_slice(subject_id.as_bytes());
            Some(VerifiedProofSource::new(
                VerifiedProofSourceKind::CredentialInstance,
                VerifiedProofSourceId::from_bytes(source_id)
                    .expect("known-subject test method source id"),
            ))
        }
        _ => None,
    }
}

fn test_active_method_source_id(
    family: ProofFamily,
    subject_id: &SubjectId,
) -> VerifiedProofSourceId {
    let prefix = match family {
        ProofFamily::MessageSignature => b"message-signature-key:".as_slice(),
        ProofFamily::OriginBoundPublicKey => b"origin-bound-public-key-credential:".as_slice(),
        ProofFamily::FederatedIdentityAssertion => {
            b"federated-identity-subject-mapping:".as_slice()
        }
        other => panic!("unexpected active method proof family {other:?}"),
    };
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(subject_id.as_bytes());
    VerifiedProofSourceId::from_bytes(bytes).expect("test active method source id")
}

fn test_response_challenge_prefix(family: ProofFamily) -> Option<&'static [u8]> {
    match family {
        ProofFamily::MessageSignature => Some(b"test-message-signature-response:nonce:"),
        ProofFamily::OriginBoundPublicKey => Some(
            b"test-origin-bound-public-key-response:rp=example.test;origin=https://example.test;nonce:",
        ),
        ProofFamily::FederatedIdentityAssertion => Some(
            b"test-federated-identity-assertion:issuer=https://issuer.example;audience=paranoid-client;redirect=https://app.example/auth/callback;state:",
        ),
        _ => None,
    }
}

fn test_method_runtime_challenge_bytes(
    method_challenge: &ActiveProofMethodChallengePresentation,
    family: ProofFamily,
) -> &[u8] {
    method_challenge
        .as_bytes()
        .strip_prefix(
            test_challenge_presentation_prefix(family).expect("test method challenge prefix"),
        )
        .expect("method challenge presentation must contain runtime nonce")
}

fn test_method_response_payload(
    family: ProofFamily,
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    test_method_response_payload_with_prefix(
        test_response_challenge_prefix(family).expect("test method response prefix"),
        family,
        nonce,
        subject_id,
    )
}

fn test_method_response_payload_with_prefix(
    response_prefix: &[u8],
    family: ProofFamily,
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    let mut response_payload = response_prefix.to_vec();
    response_payload.extend_from_slice(nonce);
    response_payload.extend_from_slice(b";subject:");
    response_payload.extend_from_slice(subject_id.as_bytes());
    response_payload.extend_from_slice(b";source:");
    response_payload.extend_from_slice(test_active_method_source_id(family, subject_id).as_bytes());
    ActiveProofMethodResponsePayload::try_from_bytes(response_payload)
        .expect("test method response payload")
}

fn mismatched_runtime_challenge_test_method_response_payload(
    family: ProofFamily,
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    let mut mismatched_nonce = nonce.to_vec();
    let first = mismatched_nonce
        .first_mut()
        .expect("runtime challenge nonce is non-empty");
    *first ^= 0x01;
    test_method_response_payload(family, &mismatched_nonce, subject_id)
}

fn mismatched_federated_issuer_test_method_response_payload(
    nonce: &[u8],
    subject_id: &SubjectId,
) -> ActiveProofMethodResponsePayload {
    test_method_response_payload_with_prefix(
        b"test-federated-identity-assertion:issuer=https://evil.example;audience=paranoid-client;redirect=https://app.example/auth/callback;state:",
        ProofFamily::FederatedIdentityAssertion,
        nonce,
        subject_id,
    )
}

fn known_subject_test_method_response_payload(
    subject_id: &SubjectId,
) -> KnownSubjectActiveProofSecretResponse {
    let mut payload = b"test-known-subject-proof:subject:".to_vec();
    payload.extend_from_slice(subject_id.as_bytes());
    KnownSubjectActiveProofSecretResponse::try_from_bytes(payload)
        .expect("known-subject test method response payload")
}

fn mismatched_known_subject_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse
{
    let mut payload = b"test-known-subject-proof:subject:".to_vec();
    payload.extend_from_slice(b"other-subject");
    KnownSubjectActiveProofSecretResponse::try_from_bytes(payload)
        .expect("mismatched known-subject test method response payload")
}

fn test_totp_code_bytes(secret: &[u8], now: UnixSeconds) -> Vec<u8> {
    let mut payload = b"test-totp-code:".to_vec();
    payload.extend_from_slice(secret);
    payload.extend_from_slice(b":step:");
    payload.extend_from_slice(&(now.get() / 30).to_string().into_bytes());
    payload
}

fn totp_test_method_response_payload(
    secret: &[u8],
    now: UnixSeconds,
) -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(test_totp_code_bytes(secret, now))
        .expect("totp test method response payload")
}

fn mismatched_totp_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(b"test-totp-code:wrong".as_slice())
        .expect("mismatched totp test method response payload")
}

fn mismatched_recovery_code_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse
{
    KnownSubjectActiveProofSecretResponse::try_from_bytes(b"wrong-recovery-code".as_slice())
        .expect("mismatched recovery code test method response payload")
}

fn generated_recovery_code_test_method_response_payload(
    code: &GeneratedRecoveryCode,
) -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(code.expose_secret())
        .expect("generated recovery code response payload")
}

fn minimum_accepted_password_kdf_params_for_tests() -> PasswordKdfParams {
    PasswordKdfParams::new(
        PASSWORD_KDF_MIN_MEMORY_COST_KIB,
        PASSWORD_KDF_MIN_ITERATIONS,
        1,
    )
    .expect("minimum accepted password KDF params")
}

fn guessed_recovery_code_test_method_response_payload() -> KnownSubjectActiveProofSecretResponse {
    KnownSubjectActiveProofSecretResponse::try_from_bytes(b"1111111111111111".as_slice())
        .expect("guessed recovery code test method response payload")
}

async fn validate_test_method_table_exists(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
) -> Result<(), super::super::postgres_store::PostgresAuthMethodCommitError> {
    let schema = table
        .schema()
        .expect("test method table must be schema-qualified")
        .as_str();
    let table_name = table.table().as_str();
    let statement = r#"
        SELECT count(*)
        FROM information_schema.tables
        WHERE table_schema = $1 AND table_name = $2
    "#;
    tx.record_database_operation(
        crate::db::DatabaseOperationKind::FetchOne,
        "auth_core.test_method.schema.validate_table",
        Some(statement),
    );
    let count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement))
        .bind(schema)
        .bind(table_name)
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(crate::db::DbError::query)?;
    if count == 1 {
        Ok(())
    } else {
        Err(
            super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(format!(
                "missing test method table {}",
                table.quoted()
            )),
        )
    }
}

impl super::super::postgres_method_runtime::PostgresAuthMethodPlugin
    for TestPostgresAuthMethodPlugin
{
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn build_out_of_band_issue(
        &self,
        _request: &IssueOutOfBandChallengeRequest,
    ) -> Result<
        super::super::postgres_method_runtime::PostgresOutOfBandChallengeIssueBuild,
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        Ok(
            super::super::postgres_method_runtime::PostgresOutOfBandChallengeIssueBuild::new(
                ActiveProofChallengeResponseSecret::try_from(b"123456".as_slice())
                    .expect("test response secret"),
                vec![out_of_band_method_commit_work()],
            ),
        )
    }

    fn build_active_proof_method_challenge<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: &'a IssueActiveProofMethodChallengeRequest,
        challenge: &'a ActiveProofMethodChallengeSeed,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::ActiveProofMethodChallengeBuild,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.method != self.method {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_method_challenge_issue",
                        "active proof challenge issue used a different method".to_owned(),
                    ),
                );
            }
            if challenge.proof != self.method.verified_proof_summary() {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_method_challenge_issue",
                        "active proof challenge material used a different proof".to_owned(),
                    ),
                );
            }
            let mut method_challenge_state = b"sealed-method-state:".to_vec();
            method_challenge_state.extend_from_slice(challenge.nonce.as_bytes());
            let method_challenge_state =
                ActiveProofMethodChallengeState::try_from_bytes(method_challenge_state).map_err(
                    |error| {
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                            self.method(),
                            "active_proof_method_challenge_issue",
                            error.to_string(),
                        )
                    },
                )?;
            let mut presentation = self.challenge_presentation_prefix()?.to_vec();
            presentation.extend_from_slice(challenge.nonce.as_bytes());
            presentation.extend_from_slice(b";state:");
            presentation.extend_from_slice(method_challenge_state.as_bytes());
            let presentation =
                ActiveProofMethodChallengePresentation::try_from_bytes(presentation).map_err(
                    |error| {
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                            self.method(),
                            "active_proof_method_challenge_issue",
                            error.to_string(),
                        )
                    },
                )?;
            Ok(
                super::super::postgres_method_runtime::ActiveProofMethodChallengeBuild::new(
                    presentation,
                    method_challenge_state,
                    Vec::new(),
                ),
            )
        })
    }

    fn verify_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<
        super::super::postgres_method_runtime::ActiveProofMethodPreStateVerification,
        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        self.parse_active_method_response_subject_and_source(challenge, response)?;
        match self.active_method_verification_mode {
            TestActiveMethodVerificationMode::BeforeStateLoad => Ok(
                super::super::postgres_method_runtime::ActiveProofMethodPreStateVerification::Accepted(
                    self.verify_active_method_response(challenge, response)?,
                ),
            ),
            TestActiveMethodVerificationMode::AuthoritativeConfirmation => Ok(
                super::super::postgres_method_runtime::ActiveProofMethodPreStateVerification::AcceptedNeedsAuthoritativeConfirmation(
                    self.verify_active_method_response(challenge, response)?,
                ),
            ),
        }
    }

    fn verify_active_proof_method_response_with_authoritative_state<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        context: super::super::postgres_method_runtime::ActiveProofMethodAuthoritativeVerificationContext<'a>,
        pre_state_verified: &'a super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse,
        response: &'a CompleteActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::ActiveProofMethodAuthoritativeConfirmation,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    >{
        Box::pin(async move {
            if context.attempt_record().attempt_id != context.challenge().attempt_id {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "loaded attempt does not match the sealed challenge".to_owned(),
                    ),
                );
            }
            if context.challenge_record().challenge_id != context.challenge().challenge_id {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "loaded challenge does not match the sealed challenge".to_owned(),
                    ),
                );
            }
            if context.challenge_record().proof != context.challenge().proof {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "loaded challenge proof does not match the sealed challenge".to_owned(),
                    ),
                );
            }
            let expected_verified =
                self.verify_active_method_response(context.challenge(), response)?;
            if pre_state_verified != &expected_verified {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "active_proof_authoritative_confirmation",
                        "pre-state proof verification changed before authoritative confirmation"
                            .to_owned(),
                    ),
                );
            }
            Ok(super::super::postgres_method_runtime::ActiveProofMethodAuthoritativeConfirmation::new(
                Vec::new(),
            ))
        })
    }

    fn verify_known_subject_active_proof_method_response<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        subject_id: &'a SubjectId,
        response: &'a CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::KnownSubjectActiveProofMethodVerification,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    >{
        Box::pin(async move {
            if response.method != self.method {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "known_subject_active_proof_completion",
                        "known-subject proof completion used a different method".to_owned(),
                    ),
                );
            }
            let subject_after_prefix = response
                .secret_response
                .expose_secret()
                .strip_prefix(b"test-known-subject-proof:subject:")
                .ok_or_else(|| {
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "known_subject_active_proof_completion",
                        "known-subject proof response payload is malformed".to_owned(),
                    )
                })?;
            if subject_after_prefix != subject_id.as_bytes() {
                return Ok(
                    super::super::postgres_method_runtime::KnownSubjectActiveProofMethodVerification::Rejected,
                );
            }
            let method_commit_work = if self.method.family() == ProofFamily::RecoveryCode {
                vec![recovery_code_method_commit_work()]
            } else {
                Vec::new()
            };
            let verified_proof = match test_known_subject_method_proof_source(
                self.method.family(),
                subject_id,
            ) {
                Some(source) => VerifiedActiveProof::from_summary_with_source(
                    self.method.verified_proof_summary(),
                    None,
                    source,
                ),
                None => VerifiedActiveProof::from_summary(
                    self.method.verified_proof_summary(),
                    None,
                ),
            }
            .map_err(|error| {
                super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    self.method(),
                    "known_subject_active_proof_completion",
                    error.to_string(),
                )
            })?;
            Ok(super::super::postgres_method_runtime::KnownSubjectActiveProofMethodVerification::Accepted(
                super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse::new(
                    verified_proof,
                    method_commit_work,
                )
                .map_err(|error| {
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "known_subject_active_proof_completion",
                        error.to_string(),
                    )
                })?,
            ))
        })
    }

    fn build_credential_reset_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: super::super::postgres_method_runtime::CredentialResetMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Vec<MethodCommitWork>,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.target_credential.proof_family() != self.method.family()
                || request.target_credential.method_label() != self.method.method_label()
            {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "credential_reset",
                        "credential reset target used a different method".to_owned(),
                    ),
                );
            }
            Ok(vec![
                MethodCommitWork::new(
                    self.method.verified_proof_summary(),
                    vec![
                        MethodCommitPrecondition::new(
                            "password_verifier_version_current",
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    vec![
                        MethodCommitMutation::new(
                            "replace_password_verifier",
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    Vec::new(),
                )
                .expect("credential reset method commit work"),
            ])
        })
    }

    fn build_credential_creation_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: super::super::postgres_method_runtime::CredentialCreationMethodWorkBuildRequest<
            'a,
        >,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::CredentialMethodWorkBuild,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.new_credential.proof_family() != self.method.family()
                || request.new_credential.method_label() != self.method.method_label()
            {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "credential_creation",
                        "credential creation target used a different method".to_owned(),
                    ),
                );
            }
            Ok(super::super::postgres_method_runtime::CredentialMethodWorkBuild::from_method_commit_work(vec![
                MethodCommitWork::new(
                    self.method.verified_proof_summary(),
                    vec![
                        MethodCommitPrecondition::new(
                            "password_verifier_absent",
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    vec![
                        MethodCommitMutation::new(
                            "create_password_verifier",
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    Vec::new(),
                )
                .expect("credential creation method commit work"),
            ]))
        })
    }

    fn build_credential_lifecycle_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: super::super::postgres_method_runtime::CredentialLifecycleMethodWorkBuildRequest<
            'a,
        >,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::super::postgres_method_runtime::CredentialMethodWorkBuild,
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.target_credential.proof_family() != self.method.family()
                || request.target_credential.method_label() != self.method.method_label()
            {
                return Err(
                    super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        self.method(),
                        "credential_lifecycle",
                        "credential lifecycle target used a different method".to_owned(),
                    ),
                );
            }
            let (precondition_operation, mutation_operation) = match (
                request.action,
                request.authority,
            ) {
                (
                    CredentialLifecycleAction::Replace,
                    super::super::postgres_method_runtime::CredentialLifecycleMethodWorkAuthority::ImmediateReplacement { .. },
                ) => (
                    "replacement_candidate_current",
                    "replace_credential_immediately",
                ),
                (
                    CredentialLifecycleAction::Rotate,
                    super::super::postgres_method_runtime::CredentialLifecycleMethodWorkAuthority::ImmediateRotation { .. },
                ) => (
                    "rotation_candidate_current",
                    "rotate_credential_immediately",
                ),
                (
                    CredentialLifecycleAction::Replace,
                    super::super::postgres_method_runtime::CredentialLifecycleMethodWorkAuthority::MaturePendingAction { .. },
                ) => (
                    "replacement_candidate_current",
                    "replace_credential_from_pending_action",
                ),
                (
                    CredentialLifecycleAction::Regenerate,
                    super::super::postgres_method_runtime::CredentialLifecycleMethodWorkAuthority::ImmediateRegeneration { .. },
                ) => (
                    "regeneration_candidate_current",
                    "regenerate_credential_immediately",
                ),
                (
                    CredentialLifecycleAction::Regenerate,
                    super::super::postgres_method_runtime::CredentialLifecycleMethodWorkAuthority::MaturePendingAction { .. },
                ) => (
                    "regeneration_candidate_current",
                    "regenerate_credential_from_pending_action",
                ),
                _ => {
                    return Err(
                        super::super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                            self.method(),
                            "credential_lifecycle",
                            "credential lifecycle action does not require method work".to_owned(),
                        ),
                    );
                }
            };
            Ok(super::super::postgres_method_runtime::CredentialMethodWorkBuild::from_method_commit_work(vec![
                MethodCommitWork::new(
                    self.method.verified_proof_summary(),
                    vec![
                        MethodCommitPrecondition::new(
                            precondition_operation,
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    vec![
                        MethodCommitMutation::new(
                            mutation_operation,
                            request.method_payload.as_bytes(),
                        )
                        .expect("method work item"),
                    ],
                    Vec::new(),
                )
                .expect("credential lifecycle method commit work"),
            ]))
        })
    }

    fn migrate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.migrate_schema_in_current_transaction(tx).await })
    }

    fn validate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.validate_schema_in_current_transaction(tx).await })
    }

    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match precondition.operation().as_str() {
                "otp_state_absent"
                | "recovery_code_still_unused"
                | "password_verifier_absent"
                | "password_verifier_version_current"
                | "replacement_candidate_current"
                | "rotation_candidate_current"
                | "regeneration_candidate_current" => {}
                other => Self::validate_operation(other, "otp_state_absent")?,
            }
            let statement = format!(
                "SELECT 1 FROM {} WHERE payload = $1 FOR UPDATE",
                self.state_table.quoted()
            );
            tx.record_database_operation(
                crate::db::DatabaseOperationKind::FetchOptional,
                "auth_core.test_method_commit.precondition.otp_state_absent",
                Some(statement.as_str()),
            );
            let exists = pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(precondition.payload())
                .fetch_optional(tx.sqlx_transaction().as_mut())
                .await
                .map_err(crate::db::DbError::query)?
                .is_some();
            if exists {
                Err(
                    super::super::postgres_store::PostgresAuthMethodCommitError::PreconditionFailed(
                        "method state already exists",
                    ),
                )
            } else {
                Ok(())
            }
        })
    }

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match mutation.operation().as_str() {
                "store_otp_state"
                | "consume_recovery_code"
                | "create_password_verifier"
                | "replace_password_verifier"
                | "replace_credential_immediately"
                | "rotate_credential_immediately"
                | "replace_credential_from_pending_action"
                | "regenerate_credential_from_pending_action" => {}
                other => Self::validate_operation(other, "store_otp_state")?,
            }
            if matches!(self.failure_mode, TestMethodCommitFailureMode::FailMutation) {
                return Err(
                    super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(
                        "forced_mutation_failure".to_owned(),
                    ),
                );
            }
            let statement = format!(
                r#"
                INSERT INTO {} (
                    payload, proof_family, method_label, mutation_operation
                )
                VALUES ($1,$2,$3,$4)
                "#,
                self.state_table.quoted()
            );
            tx.record_database_operation(
                crate::db::DatabaseOperationKind::Execute,
                "auth_core.test_method_commit.mutation.store_otp_state",
                Some(statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(mutation.payload())
                .bind(super::super::postgres_store::i32_from_proof_family(
                    work.proof().family(),
                ))
                .bind(work.proof().method_label())
                .bind(mutation.operation().as_str())
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(crate::db::DbError::query)?;
            Ok(())
        })
    }

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (),
                        super::super::postgres_store::PostgresAuthMethodCommitError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Self::validate_operation(command.operation().as_str(), "queue_email_body")?;
            if matches!(
                self.failure_mode,
                TestMethodCommitFailureMode::FailDurableEffectCommand
            ) {
                return Err(
                    super::super::postgres_store::PostgresAuthMethodCommitError::InvalidOperation(
                        "forced_durable_effect_failure".to_owned(),
                    ),
                );
            }
            let statement = format!(
                r#"
                INSERT INTO {} (
                    payload, proof_family, method_label, durable_effect_operation
                )
                VALUES ($1,$2,$3,$4)
                "#,
                self.durable_effect_table.quoted()
            );
            tx.record_database_operation(
                crate::db::DatabaseOperationKind::Execute,
                "auth_core.test_method_commit.effect.queue_email_body",
                Some(statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(command.payload())
                .bind(super::super::postgres_store::i32_from_proof_family(
                    work.proof().family(),
                ))
                .bind(work.proof().method_label())
                .bind(command.operation().as_str())
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(crate::db::DbError::query)?;
            Ok(())
        })
    }

    fn register_durable_effect_queue_handlers(
        &self,
        task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError> {
        register_no_queue_handlers_for_method_durable_effects(task_registry)
    }

    fn enqueue_available_durable_effects_to_queue_in_current_transaction<'a, 'tx>(
        &'a self,
        tx: &'a mut WriteTx<'tx>,
        queue_store: &'a queue::Store,
        limit: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresAuthDurableEffectQueueDispatchSummary,
                        PostgresAuthDurableEffectQueueDispatchError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        enqueue_no_method_durable_effects_to_queue_in_current_transaction(
            tx,
            queue_store,
            limit,
            enqueued_at,
        )
    }
}

mod active_proof_start_and_direct_guards;
mod admin_support_runtime;
mod bootstrap_and_schema;
mod credential_lifecycle_planning;
mod credential_removal_regeneration_execution;
mod credential_reset_replacement_execution;
mod durable_effects_queue;
mod message_signature_methods;
mod method_work_atomicity;
mod mounted_admin_and_delayed_routes;
mod mounted_credential_addition_inventory;
mod mounted_credential_mutation_routes;
mod mounted_recovery_routes;
mod mounted_route_guards;
mod mounted_subject_lifecycle_routes;
mod out_of_band_identifier_change;
mod pending_credential_lifecycle_execution;
mod recovery_code_methods;
mod revocation_and_stale_commits;
mod session_device_request_resolution;
mod subject_lifecycle_deletion;
mod totp_methods;
mod unauthenticated_recovery_reset_execution;
mod unauthenticated_recovery_reset_scheduling;

fn auth_web_transport() -> AuthWebTransport {
    let cookie_manager =
        crate::web::CookieManager::from_keyset(test_keyset("tests.auth.postgres-runtime.web.v1"));
    let csrf_protector = crate::web::CsrfProtector::new(crate::web::CsrfProtectorConfig::new(
        cookie_manager.clone(),
    ))
    .expect("csrf protector");
    AuthWebTransport::new(AuthWebTransportConfig::new(
        cookie_manager,
        csrf_protector,
        test_keyset("tests.auth.postgres-runtime.fast-fail.v1"),
    ))
}

fn postgres_runtime_test_store(
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> super::super::postgres_store::PostgresAuthStore {
    super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    )
}

fn postgres_runtime_test_store_with_method_registry_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> super::super::postgres_store::PostgresAuthStore {
    let store = postgres_runtime_test_store(&harness.store_config);
    match harness.method_registry.as_ref() {
        Some(registry) => store.with_method_registry(Arc::clone(registry)),
        None => store,
    }
}

fn first_party_postgres_auth_bootstrap_for_test(
    db_bootstrap_config: BootstrapConfig,
) -> super::super::postgres_bootstrap::PostgresAuthBootstrap {
    super::super::postgres_bootstrap::PostgresAuthBootstrap::new(
        db_bootstrap_config,
        test_keyset("tests.auth.postgres-bootstrap.credentials.v1"),
    )
    .with_email_otp_method(
        test_keyset("tests.auth.postgres-bootstrap.email-otp.v1"),
        Arc::new(EmbeddedSubjectEmailOtpResolver),
    )
    .expect("add email otp method")
    .with_totp_method(
        test_keyset("tests.auth.postgres-bootstrap.totp.v1"),
        TestTotpCodeVerifier,
    )
    .expect("add totp method")
    .with_recovery_code_method(test_keyset(
        "tests.auth.postgres-bootstrap.recovery-code.v1",
    ))
    .expect("add recovery code method")
    .with_password_derived_signature_method()
    .expect("add password-derived signature method")
}

fn required_auth_postgres_runtime_test_database_url() -> String {
    std::env::var("PARANOID_TEST_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("TEST_DSN")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .expect("required auth Postgres runtime test database URL missing; run through the isolated DB harness so TEST_DSN or PARANOID_TEST_DATABASE_URL is set")
}

async fn auth_runtime_test_table_exists(
    pool: &Pool,
    schema: &PgSchemaName,
    table_name: &str,
) -> bool {
    let statement = r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = $1 AND table_name = $2
        )
    "#;
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<bool>(sqlx::AssertSqlSafe(statement))
            .bind(schema.as_str())
            .bind(table_name),
        "check auth runtime test table exists"
    )
}

async fn count_auth_schema_ledger_rows(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let schema_ledger_table = store_config
        .schema_ledger_table_name()
        .expect("auth schema ledger table name");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE component = $1 AND instance_key = $2",
        schema_ledger_table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind("auth_core")
            .bind(super::super::postgres_store::schema_instance_key(
                store_config,
            )),
        "count auth schema ledger rows"
    )
}

async fn seed_admin_support_target_credential_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: SubjectId,
    target_credential_id: VerifiedProofSourceId,
    support_authority_timing: RecoveryAuthorityTiming,
    now: UnixSeconds,
) {
    let seed_store = postgres_runtime_test_store(store_config);
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id,
                CredentialInstanceKind::MessageSignatureVerifier,
                "password_signature",
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("support target credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id,
                CredentialLifecycleAction::Reset,
                id("support-authority"),
                support_authority_timing,
            )],
            &[],
            now,
        )
        .await
        .expect("seed support target credential metadata");
}

async fn request_and_approve_delayed_support_reset_for_runtime_test(
    mounted_service: &MountedAdminSupportPostgresService<'_>,
    subject_id: &SubjectId,
    target_credential_id: &VerifiedProofSourceId,
    requested_at: UnixSeconds,
    approved_at: UnixSeconds,
) -> PendingCredentialLifecycleActionId {
    let requested = mounted_service
        .request_intervention_from_headers(
            &HeaderMap::new(),
            RequestAdminSupportInterventionInput {
                now: requested_at,
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
            },
        )
        .await
        .expect("request delayed support reset intervention");
    let intervention_id = match requested.committed_outcome() {
        MountedAdminSupportCommittedOutcome::InterventionRequested {
            intervention_id,
            subject_id: actual_subject_id,
            target_credential_instance_id,
            action,
            ..
        } => {
            assert_eq!(actual_subject_id, subject_id);
            assert_eq!(target_credential_instance_id, target_credential_id);
            assert_eq!(*action, CredentialLifecycleAction::Reset);
            intervention_id.clone()
        }
        outcome => panic!("expected support intervention request outcome, got {outcome:?}"),
    };
    let authorizer = RecordingMountedSupportStaffAuthorizer::new(
        MountedAdminSupportStaffAuthorization::Authorized,
    );
    let approved = mounted_service
        .approve_intervention_from_headers(
            &HeaderMap::new(),
            ApproveAdminSupportInterventionInput {
                now: approved_at,
                intervention_id: intervention_id.clone(),
            },
            &authorizer,
        )
        .await
        .expect("approve delayed support reset intervention");
    match approved.committed_outcome() {
        MountedAdminSupportCommittedOutcome::ApprovalScheduledDelayedAction {
            intervention_id: actual_intervention_id,
            subject_id: actual_subject_id,
            target_credential_instance_id,
            action,
            pending_action_id,
            ..
        } => {
            assert_eq!(actual_intervention_id, &intervention_id);
            assert_eq!(actual_subject_id, subject_id);
            assert_eq!(target_credential_instance_id, target_credential_id);
            assert_eq!(*action, CredentialLifecycleAction::Reset);
            pending_action_id.clone()
        }
        outcome => panic!("expected delayed support approval outcome, got {outcome:?}"),
    }
}

async fn load_admin_support_intervention_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    intervention_id: &AdminSupportInterventionId,
) -> Option<AdminSupportInterventionRecord> {
    let store = postgres_runtime_test_store(store_config);
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin support intervention read transaction");
    let record = store
        .load_admin_support_intervention_in_current_transaction(&mut tx, intervention_id)
        .await
        .expect("load support intervention record");
    tx.rollback()
        .await
        .expect("rollback support intervention read transaction");
    record
}

async fn count_admin_support_interventions_for_subject_target_and_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
    target_credential_instance_id: &VerifiedProofSourceId,
    action: CredentialLifecycleAction,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::AdminSupportIntervention)
        .expect("admin support intervention table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE subject_id = $1 AND target_credential_instance_id = $2 AND lifecycle_action = $3",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(target_credential_instance_id.as_bytes())
            .bind(super::super::postgres_store::i32_from_credential_lifecycle_action(action),),
        "count admin support interventions for subject target and action"
    )
}

async fn drop_auth_runtime_test_schema(pool: &Pool, schema: &PgSchemaName) {
    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema.identifier().quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_schema.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth runtime test schema");
}

async fn drop_first_check_constraint_matching_for_auth_runtime_test(
    pool: &Pool,
    table: &PgQualifiedTableName,
    expression_pattern: &str,
) {
    let find_constraint_statement = r#"
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND pg_get_expr(con.conbin, con.conrelid) LIKE $2
        LIMIT 1
        "#;
    let constraint_name = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<String>(find_constraint_statement)
            .bind(table.quoted().to_string())
            .bind(expression_pattern),
        "find auth method check constraint"
    );
    let constraint_name = PgIdentifier::new(constraint_name).expect("constraint identifier");
    let drop_constraint_statement = format!(
        "ALTER TABLE {} DROP CONSTRAINT {}",
        table.quoted(),
        constraint_name.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_constraint_statement.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth method check constraint");
}

async fn drop_auth_runtime_test_index(
    pool: &Pool,
    table: &PgQualifiedTableName,
    index_name: PgIdentifier,
) {
    let qualified_index_name = PgQualifiedTableName::new(table.schema().cloned(), index_name);
    let drop_index_statement = format!("DROP INDEX {}", qualified_index_name.quoted());
    unparameterized_simple_query(sqlx::AssertSqlSafe(drop_index_statement.as_str()))
        .execute(pool.sqlx_pool())
        .await
        .expect("drop auth method index");
}

fn cookie_pair_from_set_cookie<'a>(
    headers: &'a AuthSetCookieHeaders,
    cookie_prefix: &str,
) -> &'a str {
    headers
        .as_slice()
        .iter()
        .find_map(|header| {
            header
                .as_str()
                .split(';')
                .next()
                .filter(|pair| pair.starts_with(cookie_prefix))
        })
        .expect("set-cookie pair")
}

fn active_proof_continuation_cookie_pair_from_set_cookie(headers: &AuthSetCookieHeaders) -> &str {
    cookie_pair_from_set_cookie(headers, "__Host-__paranoid_auth_active_proof_continuation=")
}

fn cookie_pair_from_http_response_set_cookie<B>(
    response: &http::Response<B>,
    cookie_prefix: &str,
) -> String {
    response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .find_map(|header| {
            header
                .to_str()
                .ok()?
                .split(';')
                .next()
                .filter(|pair| pair.starts_with(cookie_prefix))
                .map(str::to_owned)
        })
        .expect("HTTP response set-cookie pair")
}

fn csrf_cookie_pair_from_set_cookie(headers: &AuthSetCookieHeaders) -> &str {
    cookie_pair_from_set_cookie(headers, "__Host-csrf_token=")
}

fn set_cookie_headers_contain_prefix(headers: &AuthSetCookieHeaders, cookie_prefix: &str) -> bool {
    headers
        .as_slice()
        .iter()
        .any(|header| header.as_str().starts_with(cookie_prefix))
}

fn assert_http_response_has_no_set_cookie<B>(response: &http::Response<B>, context: &str) {
    assert!(
        response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .next()
            .is_none(),
        "{context}"
    );
}

fn headers_from_cookie_pairs(cookie_pairs: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookie_pairs.join("; ")).expect("cookie header"),
    );
    headers
}

fn request_with_cookie_pairs(method: Method, cookie_pairs: &[&str]) -> Request<()> {
    request_with_body_and_cookie_pairs(method, cookie_pairs, ())
}

fn request_with_body_and_cookie_pairs<B>(
    method: Method,
    cookie_pairs: &[&str],
    body: B,
) -> Request<B> {
    let mut builder = Request::builder()
        .method(method)
        .uri("https://example.com/auth");
    if !cookie_pairs.is_empty() {
        builder = builder.header(COOKIE, cookie_pairs.join("; "));
    }
    builder.body(body).expect("auth route request")
}

fn unsafe_request_with_valid_csrf_and_cookie_pairs(cookie_pairs: &[&str]) -> Request<()> {
    let csrf_issue_request = request_with_cookie_pairs(Method::GET, &[]);
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue csrf cookie for auth route test")
        .expect("csrf cookie was needed");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("csrf Set-Cookie starts with name=value")
        .to_owned();
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("csrf cookie pair contains equals")
        .1
        .to_owned();
    let mut all_cookie_pairs = Vec::with_capacity(cookie_pairs.len() + 1);
    all_cookie_pairs.extend(cookie_pairs.iter().copied());
    all_cookie_pairs.push(csrf_cookie_pair.as_str());
    Request::builder()
        .method(Method::POST)
        .uri("https://example.com/auth")
        .header(COOKIE, all_cookie_pairs.join("; "))
        .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
        .body(())
        .expect("csrf-protected auth route request")
}

fn bound_proof_of_work_gate_response_for_active_method_completion(
    headers: &HeaderMap,
    response_payload: &ActiveProofMethodResponsePayload,
    now: UnixSeconds,
) -> WeakProofGateResponse {
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode active-method challenge cookie for weak-gate binding");
    let challenge_cookie = decoded
        .presented_cookies()
        .active_proof_challenge_cookie
        .as_ref()
        .expect("active-method challenge cookie for weak-gate binding");
    let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(challenge_cookie)
        .expect("active-method challenge material for weak-gate binding");
    let binding =
        WeakProofGateBinding::for_active_method_response(&challenge_material, response_payload)
            .expect("active-method weak-gate binding");
    proof_of_work_gate_response_for_test(now, &challenge_material.proof, &binding)
}

fn bound_proof_of_work_gate_response_for_challenge_bound_totp_completion(
    headers: &HeaderMap,
    secret_response: &KnownSubjectActiveProofSecretResponse,
    now: UnixSeconds,
) -> WeakProofGateResponse {
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode challenge-bound TOTP cookie for weak-gate binding");
    let challenge_cookie = decoded
        .presented_cookies()
        .active_proof_challenge_cookie
        .as_ref()
        .expect("challenge-bound TOTP cookie for weak-gate binding");
    let challenge_material = ActiveProofMethodChallengeMaterial::from_cookie(challenge_cookie)
        .expect("challenge-bound TOTP material for weak-gate binding");
    let binding = WeakProofGateBinding::for_challenge_bound_known_subject_secret_response(
        &challenge_material,
        secret_response,
    )
    .expect("challenge-bound TOTP weak-gate binding");
    proof_of_work_gate_response_for_test(now, &challenge_material.proof, &binding)
}

fn bound_proof_of_work_gate_response_for_known_subject_completion(
    headers: &HeaderMap,
    method: &ProofMethodDeclaration,
    secret_response: &KnownSubjectActiveProofSecretResponse,
    now: UnixSeconds,
) -> WeakProofGateResponse {
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode continuation cookie for known-subject weak-gate binding");
    let continuation_cookie = decoded
        .presented_cookies()
        .active_proof_continuation_cookie
        .as_ref()
        .expect("continuation cookie for known-subject weak-gate binding");
    let proof = method.verified_proof_summary();
    let binding = WeakProofGateBinding::for_known_subject_secret_response(
        continuation_cookie,
        &proof,
        secret_response,
    )
    .expect("known-subject weak-gate binding");
    proof_of_work_gate_response_for_test(now, &proof, &binding)
}

fn set_cookie_headers_contain_deletion(
    headers: &AuthSetCookieHeaders,
    cookie_prefix: &str,
) -> bool {
    headers.as_slice().iter().any(|header| {
        header.as_str().starts_with(cookie_prefix) && header.as_str().contains("Max-Age=0")
    })
}

struct PlannedLoadedStateRuntimeCommand {
    planned: PlannedCommandExecution,
    planned_storage_boundary_contract: PlannedStorageBoundaryContract,
}

async fn plan_loaded_state_command_in_current_transaction(
    tx: &mut Tx<'_>,
    store: &super::super::postgres_store::PostgresAuthStore,
    headers: &HeaderMap,
    command: Command,
) -> PlannedLoadedStateRuntimeCommand {
    let now = command.now();
    let decoded = auth_web_transport()
        .decode_presented_cookies_from_headers(headers)
        .expect("decode presented cookies for stale runtime command");
    let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
    let prepared = PreparedCommandExecution::prepare(&config(), command, presented_cookies)
        .expect("prepare stale runtime command");
    let prepared_storage_boundary_contract =
        PreparedStorageBoundaryContract::for_prepared_command(&prepared);
    assert_eq!(
        prepared_storage_boundary_contract.boundary_before_reduce(),
        StorageBoundaryBeforeReduce::OpenBeforeStateLoad,
        "stale race test must keep the loaded-state transaction open through commit"
    );
    let loaded = store
        .load_state_in_current_transaction(
            tx,
            AuthLoadStateRequest::new(
                now,
                prepared.presented_cookies(),
                &presented_cookie_secrets,
                prepared.loaded_state_contract(),
                &prepared_storage_boundary_contract,
            ),
        )
        .await
        .expect("load stale runtime command state");
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("reduce stale runtime command");
    let planned_storage_boundary_contract = PlannedStorageBoundaryContract::for_planned_execution(
        &prepared_storage_boundary_contract,
        &planned,
    )
    .expect("build stale runtime command storage boundary");
    assert_eq!(
        planned_storage_boundary_contract.atomic_commit_boundary(),
        AtomicCommitBoundary::LoadedStateBoundary,
        "stale race test must commit through the loaded-state boundary"
    );
    PlannedLoadedStateRuntimeCommand {
        planned,
        planned_storage_boundary_contract,
    }
}

async fn commit_planned_work_in_current_transaction_expect_precondition_error(
    tx: &mut Tx<'_>,
    store: &super::super::postgres_store::PostgresAuthStore,
    planned: &PlannedLoadedStateRuntimeCommand,
) -> super::super::postgres_store::PostgresAuthStoreError {
    let request = AtomicCommitRequest::for_atomic_work_with_storage_boundary(
        planned.planned.atomic_commit_work(),
        planned.planned_storage_boundary_contract.clone(),
    )
    .expect("build stale runtime command commit request");
    store
        .commit_atomic_work_in_current_transaction(tx, request)
        .await
        .expect_err("stale runtime command commit must fail")
}

async fn seed_pending_credential_reset_for_runtime_test(
    pool: &Pool,
    store: &super::super::postgres_store::PostgresAuthStore,
    target_credential_id: VerifiedProofSourceId,
    email_authority: RecoveryAuthorityId,
    pending_action_id: PendingCredentialLifecycleActionId,
) {
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_lifecycle_context(
                CredentialInstanceMetadata::new(
                    target_credential_id.clone(),
                    id("pending-reset-subject"),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    "password_signature",
                    CredentialResetPolicyRole::OrdinaryCredential,
                    CredentialLifecycleState::Active,
                )
                .expect("pending reset credential metadata"),
                [CredentialRecoveryAuthority::new(
                    target_credential_id,
                    CredentialLifecycleAction::Reset,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [out_of_band_identifier_lifecycle_evidence(
                    "pending-reset-email-source",
                    [email_authority],
                )],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id,
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("plan pending credential reset");
    let (atomic_work, response_effects) = transition
        .commit_plan
        .try_into_validated_atomic_work_and_response_effects()
        .expect("valid pending reset atomic work");
    assert!(
        response_effects.is_empty(),
        "pending reset seed should not emit response-local effects"
    );
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin pending reset seed tx");
    let request = AtomicCommitRequest::for_atomic_work(&atomic_work)
        .expect("pending reset seed commit request");
    let commit_result = store
        .commit_atomic_work_in_current_transaction(&mut tx, request)
        .await;
    match commit_result {
        Ok(_) => tx.commit().await.expect("commit pending reset seed"),
        Err(error) => {
            tx.rollback().await.expect("rollback pending reset seed");
            panic!("commit pending reset seed failed: {error:?}");
        }
    }
}

fn assert_precondition_failed(
    error: &super::super::postgres_store::PostgresAuthStoreError,
    expected_reason: &'static str,
) {
    assert!(
        matches!(
            error,
            super::super::postgres_store::PostgresAuthStoreError::PreconditionFailed(reason)
                if *reason == expected_reason
        ),
        "expected precondition failure {expected_reason:?}, got {error:?}"
    );
}

fn assert_method_registry_not_configured(
    error: &super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
) {
    assert!(
        matches!(
            error,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
                super::super::postgres_store::PostgresAuthStoreError::MethodRegistryNotConfigured
            )
        ),
        "expected unconfigured method registry error, got {error:?}"
    );
}

fn assert_method_commit_work_failed(
    error: &super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError,
    expected_stage: super::super::postgres_store::PostgresAuthMethodCommitStage,
    expected_operation: &'static str,
) {
    assert!(
        matches!(
            error,
            super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Store(
                super::super::postgres_store::PostgresAuthStoreError::MethodCommitWorkFailed {
                    stage,
                    operation,
                    ..
                }
            )
                if *stage == expected_stage && operation == expected_operation
        ),
        "expected method commit work failure during {expected_stage:?} for {expected_operation}, got {error:?}"
    );
}

struct IssuedRuntimeAuth {
    session_id: SessionId,
    session_cookie_pair: String,
    trusted_device_credential_id: Option<TrustedDeviceCredentialId>,
    trusted_device_cookie_pair: Option<String>,
}

struct IssuedRuntimeChallenge {
    attempt_id: ActiveProofAttemptId,
    challenge_id: ActiveProofChallengeId,
    response_secret: ActiveProofChallengeResponseSecret,
    continuation_cookie_pair: String,
    challenge_cookie_pair: String,
}

struct IssuedRuntimeChallengeBoundTotpChallenge {
    attempt_id: ActiveProofAttemptId,
    challenge_id: ActiveProofChallengeId,
    challenge_cookie_pair: String,
}

struct StartedRuntimeAttempt {
    attempt_id: ActiveProofAttemptId,
    continuation_cookie_pair: String,
}

fn recipient_handle_for_test_subject(flow_label: &str, subject_id: &SubjectId) -> String {
    let subject_label = std::str::from_utf8(subject_id.as_bytes())
        .expect("test subject ids embedded in recipient handles must be UTF-8 labels");
    format!("{flow_label}-opaque-email-handle:subject:{subject_label}")
}

async fn start_current_session_active_proof_attempt_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    session_cookie_pair: &str,
    now: UnixSeconds,
    proof_use: ProofUse,
) -> StartedRuntimeAttempt {
    let headers = headers_from_cookie_pairs(&[session_cookie_pair]);
    let started = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &headers,
            StartCurrentSessionActiveProofAttemptInput { now, proof_use },
        )
        .await
        .expect("start active proof attempt from current session through Postgres runtime");
    let attempt_id = match started.outcome() {
        Outcome::ActiveProofAttemptStarted { attempt_id, .. } => attempt_id.clone(),
        outcome => panic!("expected active proof attempt start, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started.set_cookie_headers())
            .to_owned();
    StartedRuntimeAttempt {
        attempt_id,
        continuation_cookie_pair,
    }
}

async fn start_unauthenticated_recovery_active_proof_attempt_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    now: UnixSeconds,
) -> StartedRuntimeAttempt {
    let empty_headers = HeaderMap::new();
    let method = proof_method(ProofFamily::RecoveryCode);
    let started = runtime
        .execute_unauthenticated_recovery_active_proof_attempt_start_from_headers(
            &empty_headers,
            StartUnauthenticatedRecoveryActiveProofAttemptInput {
                now,
                method: method.clone(),
            },
            challenge_issue_preflight_response_for_test(
                now,
                ProofUse::RecoverOrReplaceCredential,
                &method,
            ),
        )
        .await
        .expect("start unauthenticated recovery active-proof attempt through Postgres runtime");
    let attempt_id = match started.outcome() {
        Outcome::ActiveProofAttemptStarted { attempt_id, .. } => attempt_id.clone(),
        outcome => panic!("expected recovery active proof attempt start, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(started.set_cookie_headers())
            .to_owned();
    StartedRuntimeAttempt {
        attempt_id,
        continuation_cookie_pair,
    }
}

async fn start_and_issue_out_of_band_challenge_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    email_otp: &PostgresEmailOtpMethodPlugin,
    flow_label: &str,
    start_at: u64,
    subject_id: SubjectId,
) -> IssuedRuntimeChallenge {
    let empty_headers = HeaderMap::new();

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(start_at + 10),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(&format!("{flow_label}:email-hash:window")),
                recipient_handle: recipient_handle_for_test_subject(flow_label, &subject_id),
                idempotency_key: format!("{flow_label}-mail-idempotency-key"),
            },
            email_otp_challenge_issue_preflight_response_at(at(start_at + 10)),
        )
        .await
        .expect("issue challenge through Postgres runtime");
    let (attempt_id, challenge_id) = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            ..
        } => (attempt_id.clone(), challenge_id.clone()),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(issued.set_cookie_headers())
            .to_owned();
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    IssuedRuntimeChallenge {
        attempt_id,
        challenge_id,
        response_secret,
        continuation_cookie_pair,
        challenge_cookie_pair,
    }
}

async fn start_current_session_and_issue_out_of_band_challenge_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    email_otp: &PostgresEmailOtpMethodPlugin,
    flow_label: &str,
    start_at: u64,
    subject_id: SubjectId,
    session_cookie_pair: &str,
) -> IssuedRuntimeChallenge {
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_cookie_pair,
        at(start_at),
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);

    let issued = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            IssueOutOfBandChallengeInput {
                now: at(start_at + 10),
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(&format!("{flow_label}:email-hash:window")),
                recipient_handle: recipient_handle_for_test_subject(flow_label, &subject_id),
                idempotency_key: format!("{flow_label}-mail-idempotency-key"),
            },
        )
        .await
        .expect("issue subject-bound challenge through Postgres runtime");
    let challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    IssuedRuntimeChallenge {
        attempt_id: started.attempt_id,
        challenge_id,
        response_secret,
        continuation_cookie_pair: started.continuation_cookie_pair,
        challenge_cookie_pair,
    }
}

async fn start_current_session_and_issue_challenge_bound_totp_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    session_cookie_pair: &str,
    attempt_start_at: UnixSeconds,
    challenge_issue_at: UnixSeconds,
) -> IssuedRuntimeChallengeBoundTotpChallenge {
    let started = start_current_session_active_proof_attempt_through_runtime(
        runtime,
        session_cookie_pair,
        attempt_start_at,
        ProofUse::SatisfyStepUp,
    )
    .await;
    let continuation_headers =
        headers_from_cookie_pairs(&[started.continuation_cookie_pair.as_str()]);
    let issued = runtime
        .execute_challenge_bound_known_subject_active_proof_method_challenge_issue_from_headers(
            &continuation_headers,
            IssueChallengeBoundKnownSubjectActiveProofMethodChallengeInput {
                now: challenge_issue_at,
                method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
                    .expect("TOTP method"),
                method_challenge_request_payload: None,
            },
        )
        .await
        .expect("issue challenge-bound TOTP challenge through Postgres runtime");
    let challenge_id = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            proof,
            ..
        } => {
            assert_eq!(attempt_id, &started.attempt_id);
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::SharedSecretOtp, "totp").expect("proof"),
            );
            challenge_id.clone()
        }
        outcome => panic!("expected challenge-bound TOTP challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();

    IssuedRuntimeChallengeBoundTotpChallenge {
        attempt_id: started.attempt_id,
        challenge_id,
        challenge_cookie_pair,
    }
}

async fn complete_out_of_band_challenge_response_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    challenge: &IssuedRuntimeChallenge,
    now: UnixSeconds,
) -> AuthWebRuntimeExecution {
    let headers = headers_from_cookie_pairs(&[challenge.challenge_cookie_pair.as_str()]);
    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            CompleteOutOfBandChallengeResponse {
                now,
                secret_response: ActiveProofChallengeResponseSecret::try_from(
                    challenge.response_secret.expose_secret(),
                )
                .expect("challenge response secret"),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete challenge through Postgres runtime");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));
    completed
}

fn complete_out_of_band_challenge_command(
    challenge: &IssuedRuntimeChallenge,
    now: UnixSeconds,
    subject_id: SubjectId,
) -> Command {
    let proof = ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof");
    Command::CompleteActiveProofChallenge(CompleteActiveProofChallenge {
        now,
        attempt_id: challenge.attempt_id.clone(),
        challenge_id: Some(challenge.challenge_id.clone()),
        verified_proof: VerifiedActiveProof::from_summary(proof, Some(subject_id))
            .expect("verified out-of-band proof"),
        stateless_fast_fail: verified_stateless_fast_fail(),
        weak_proof_gate: WeakProofGateStatus::NotRequired,
        method_commit_work: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn complete_full_authentication_through_runtime(
    runtime: &super::super::postgres_runtime::PostgresAuthWebRuntime,
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    email_otp: &PostgresEmailOtpMethodPlugin,
    flow_label: &str,
    start_at: u64,
    subject_id: SubjectId,
    trust_device: bool,
) -> IssuedRuntimeAuth {
    let empty_headers = HeaderMap::new();

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_out_of_band_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueOutOfBandChallengeInput {
                now: at(start_at),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                    .expect("method declaration"),
                challenge_dedupe_key: dedupe_key(&format!("{flow_label}:email-hash:window")),
                recipient_handle: recipient_handle_for_test_subject(flow_label, &subject_id),
                idempotency_key: format!("{flow_label}-mail-idempotency-key"),
            },
            email_otp_challenge_issue_preflight_response_at(at(start_at)),
        )
        .await
        .expect("issue challenge through Postgres runtime");
    let challenge_id = match issued.outcome() {
        Outcome::OutOfBandChallengeIssued { challenge_id, .. } => challenge_id.clone(),
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    let continuation_cookie_pair =
        active_proof_continuation_cookie_pair_from_set_cookie(issued.set_cookie_headers())
            .to_owned();
    let continuation_headers = headers_from_cookie_pairs(&[continuation_cookie_pair.as_str()]);
    let response_secret = email_otp
        .fetch_response_secret_for_test(pool, &challenge_id)
        .await
        .expect("fetch generated email otp response secret");
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    );
    let challenge_headers = headers_from_cookie_pairs(&[challenge_cookie_pair]);

    let completed = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &challenge_headers,
            CompleteOutOfBandChallengeResponse {
                now: at(start_at + 20),
                secret_response: response_secret,
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete challenge through Postgres runtime");
    assert!(matches!(
        completed.outcome(),
        Outcome::ActiveProofCompleted { .. }
    ));

    let full_authentication = runtime
        .execute_full_authentication_completion_from_headers(
            &continuation_headers,
            CompleteFullAuthenticationInput {
                now: at(start_at + 25),
                trust_device: trust_device.then(|| TrustDeviceAfterFullAuthenticationInput {
                    display_label: Some(format!("{flow_label} test browser")),
                }),
            },
        )
        .await
        .expect("complete full authentication through Postgres runtime");
    let session_id = match full_authentication.outcome() {
        Outcome::Authenticated(authenticated) => authenticated.session_id.clone(),
        outcome => panic!("expected full authentication, got {outcome:?}"),
    };
    let session_cookie_pair = cookie_pair_from_set_cookie(
        full_authentication.set_cookie_headers(),
        "__Host-__paranoid_auth_session=",
    )
    .to_owned();
    let trusted_device_cookie_pair = full_authentication
        .set_cookie_headers()
        .as_slice()
        .iter()
        .find_map(|header| {
            header
                .as_str()
                .split(';')
                .next()
                .filter(|pair| pair.starts_with("__Host-__paranoid_auth_trusted_device="))
                .map(str::to_owned)
        });
    let trusted_device_credential_id = if trust_device {
        Some(
            fetch_trusted_device_id_by_display_label(
                pool,
                store_config,
                &format!("{flow_label} test browser"),
            )
            .await
            .expect("trusted device id by display label"),
        )
    } else {
        None
    };

    IssuedRuntimeAuth {
        session_id,
        session_cookie_pair,
        trusted_device_credential_id,
        trusted_device_cookie_pair,
    }
}

async fn count_satisfied_proofs_for_attempt(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
        .expect("satisfied proof table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "count satisfied proofs"
    )
}

async fn fetch_satisfied_proof_source_for_attempt(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> Option<VerifiedProofSource> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
        .expect("satisfied proof table");
    let statement = format!(
        "SELECT proof_source_kind, proof_source_id FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    let row = auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_as::<(Option<i32>, Option<Vec<u8>>)>(sqlx::AssertSqlSafe(
            statement.as_str(),
        ))
        .bind(attempt_id.as_bytes()),
        "fetch satisfied proof source"
    )?;
    match row {
        (None, None) => None,
        (Some(kind), Some(source_id)) => Some(VerifiedProofSource::new(
            super::super::postgres_store::verified_proof_source_kind_from_i32(kind)
                .expect("parse proof source kind"),
            VerifiedProofSourceId::from_bytes(source_id).expect("parse proof source id"),
        )),
        _ => panic!("satisfied proof source kind/id must both be present or both absent"),
    }
}

async fn fetch_out_of_band_identifier_binding_for_source(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    source_id: &VerifiedProofSourceId,
) -> Option<(SubjectId, String, OutOfBandIdentifierBindingLifecycleState)> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::OutOfBandIdentifierBinding)
        .expect("identifier binding table");
    let statement = format!(
        "SELECT subject_id, proof_method_label, lifecycle_state FROM {} WHERE source_id = $1",
        table.quoted()
    );
    let row = auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_as::<(Vec<u8>, String, i32)>(sqlx::AssertSqlSafe(statement.as_str(),))
            .bind(source_id.as_bytes()),
        "fetch out-of-band identifier binding"
    )?;
    Some((
        SubjectId::from_bytes(row.0).expect("parse identifier binding subject id"),
        row.1,
        super::super::postgres_store::out_of_band_identifier_binding_lifecycle_state_from_i32(
            row.2,
        )
        .expect("parse identifier binding lifecycle state"),
    ))
}

async fn seed_out_of_band_identifier_change_runtime_state(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
    session_id: &SessionId,
    current_identifier_source_id: &VerifiedProofSourceId,
    candidate_identifier_source_id: &VerifiedProofSourceId,
    current_identifier_authority: RecoveryAuthorityId,
    session_authority: RecoveryAuthorityId,
    authority_timing: RecoveryAuthorityTiming,
) {
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.identifier-change.v1"),
    );
    seed_store
        .store_subject_lifecycle_metadata_for_test(
            pool,
            &[SubjectLifecycleAuthority::new(
                subject_id.clone(),
                SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                session_authority.clone(),
                authority_timing,
            )],
            &[
                LifecycleAuthorityEvidence::authenticated_session(
                    session_id.clone(),
                    [session_authority],
                )
                .expect("session lifecycle evidence"),
                LifecycleAuthorityEvidence::from_verified_proof_source(
                    VerifiedProofSource::new(
                        VerifiedProofSourceKind::OutOfBandIdentifier,
                        current_identifier_source_id.clone(),
                    ),
                    [current_identifier_authority],
                )
                .expect("current identifier lifecycle evidence"),
            ],
            at(50),
        )
        .await
        .expect("seed identifier-change lifecycle metadata");
    seed_store
        .store_out_of_band_identifier_bindings_for_test(
            pool,
            &[
                OutOfBandIdentifierBindingRecord::new(
                    VerifiedProofSource::new(
                        VerifiedProofSourceKind::OutOfBandIdentifier,
                        current_identifier_source_id.clone(),
                    ),
                    subject_id.clone(),
                    "email_otp",
                    OutOfBandIdentifierBindingLifecycleState::Active,
                )
                .expect("current identifier binding"),
                OutOfBandIdentifierBindingRecord::new(
                    VerifiedProofSource::new(
                        VerifiedProofSourceKind::OutOfBandIdentifier,
                        candidate_identifier_source_id.clone(),
                    ),
                    subject_id.clone(),
                    "email_otp",
                    OutOfBandIdentifierBindingLifecycleState::PendingActivation,
                )
                .expect("candidate identifier binding"),
            ],
            at(50),
        )
        .await
        .expect("seed identifier-change bindings");
}

async fn load_pending_subject_lifecycle_action_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingSubjectLifecycleActionId,
) -> Option<PendingSubjectLifecycleActionRecord> {
    let seed_store = super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.pending-subject-action-read.v1"),
    );
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin pending subject action read transaction");
    let value = seed_store
        .load_pending_subject_lifecycle_action_for_execution_in_current_transaction(
            &mut tx,
            pending_action_id,
        )
        .await
        .expect("load pending subject action");
    tx.rollback()
        .await
        .expect("rollback pending subject action read transaction");
    value
}

async fn fetch_active_proof_attempt_subject_id(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> Option<SubjectId> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!(
        "SELECT subject_id FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<Vec<u8>>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "fetch active proof attempt subject"
    )
    .flatten()
    .map(SubjectId::from_bytes)
    .transpose()
    .expect("parse subject id")
}

async fn count_open_pending_credential_reset_actions_for_target(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    target_credential_instance_id: &VerifiedProofSourceId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE target_credential_instance_id = $1 AND lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(target_credential_instance_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "count open pending credential reset actions for target"
    )
}

async fn count_open_pending_credential_reset_actions_for_subject_and_target(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
    target_credential_instance_id: &VerifiedProofSourceId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE subject_id = $1 AND target_credential_instance_id = $2 AND lifecycle_action = $3 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(target_credential_instance_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "count open pending credential reset actions for subject and target"
    )
}

async fn count_open_pending_credential_reset_actions_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE pending_action_id = $1 AND lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "count open pending credential reset actions for pending action"
    )
}

async fn pending_credential_reset_closed_at_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> Option<i64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT closed_at FROM {} WHERE pending_action_id = $1 AND lifecycle_action = $2",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_action(
                    CredentialLifecycleAction::Reset,
                ),
            ),
        "read pending credential reset closed_at"
    )
}

async fn count_open_pending_credential_lifecycle_actions_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingCredentialLifecycleActionId,
    action: CredentialLifecycleAction,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
        .expect("pending credential lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE pending_action_id = $1 AND lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(super::super::postgres_store::i32_from_credential_lifecycle_action(action),),
        "count open pending credential lifecycle actions for pending action"
    )
}

async fn count_open_pending_subject_lifecycle_actions_for_pending_action(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    pending_action_id: &PendingSubjectLifecycleActionId,
    action: SubjectLifecycleAction,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
        .expect("pending subject lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE pending_action_id = $1 AND subject_lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(pending_action_id.as_bytes())
            .bind(super::super::postgres_store::i32_from_subject_lifecycle_action(action),),
        "count open pending subject lifecycle actions for pending action"
    )
}

async fn count_open_pending_subject_lifecycle_actions_for_subject(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
    action: SubjectLifecycleAction,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
        .expect("pending subject lifecycle action table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE subject_id = $1 AND subject_lifecycle_action = $2 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(super::super::postgres_store::i32_from_subject_lifecycle_action(action),),
        "count open pending subject lifecycle actions for subject"
    )
}

async fn credential_lifecycle_state_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    credential_instance_id: &VerifiedProofSourceId,
) -> CredentialLifecycleState {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CredentialInstance)
        .expect("credential instance table");
    let statement = format!(
        "SELECT lifecycle_state FROM {} WHERE credential_instance_id = $1",
        table.quoted()
    );
    let raw_state = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(credential_instance_id.as_bytes()),
        "read credential lifecycle state"
    );
    super::super::postgres_store::credential_lifecycle_state_from_i32(raw_state)
        .expect("stored credential lifecycle state")
}

async fn count_active_credential_instances_for_subject_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CredentialInstance)
        .expect("credential instance table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE subject_id = $1 AND lifecycle_state = $2",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(
                super::super::postgres_store::i32_from_credential_lifecycle_state(
                    CredentialLifecycleState::Active,
                ),
            ),
        "count active credential instances for subject"
    )
}

async fn count_credential_recovery_authorities_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    credential_instance_id: &VerifiedProofSourceId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CredentialRecoveryAuthority)
        .expect("credential recovery authority table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE target_credential_instance_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(credential_instance_id.as_bytes()),
        "count credential recovery authorities"
    )
}

async fn fetch_credential_recovery_authorities_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    credential_instance_id: &VerifiedProofSourceId,
) -> Vec<CredentialRecoveryAuthority> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CredentialRecoveryAuthority)
        .expect("credential recovery authority table");
    let statement = format!(
        "SELECT lifecycle_action, authority_id, authority_timing FROM {} WHERE target_credential_instance_id = $1 ORDER BY lifecycle_action ASC, authority_id ASC, authority_timing ASC",
        table.quoted()
    );
    let rows = {
        let mut tx = pool
            .begin_transaction()
            .await
            .expect("begin credential recovery authority fetch transaction");
        let rows =
            pooler_safe_query_as::<(i32, Vec<u8>, i32)>(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(credential_instance_id.as_bytes())
                .fetch_all(tx.sqlx_transaction().as_mut())
                .await
                .expect("fetch credential recovery authorities");
        tx.rollback()
            .await
            .expect("rollback credential recovery authority fetch transaction");
        rows
    };
    rows.into_iter()
        .map(|(action, authority_id, timing)| {
            CredentialRecoveryAuthority::new(
                credential_instance_id.clone(),
                super::super::postgres_store::credential_lifecycle_action_from_i32(action)
                    .expect("stored credential lifecycle action should parse"),
                RecoveryAuthorityId::from_bytes(authority_id)
                    .expect("stored recovery authority id should parse"),
                super::super::postgres_store::recovery_authority_timing_from_i32(timing)
                    .expect("stored recovery authority timing should parse"),
            )
        })
        .collect()
}

async fn count_lifecycle_authority_sources_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    source_kind: LifecycleAuthoritySourceKind,
    source_id: &VerifiedProofSourceId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::LifecycleAuthoritySource)
        .expect("lifecycle authority source table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE source_kind = $1 AND source_id = $2",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(
                super::super::postgres_store::i32_from_lifecycle_authority_source_kind(source_kind,)
            )
            .bind(source_id.as_bytes()),
        "count lifecycle authority sources"
    )
}

async fn fetch_lifecycle_authority_ids_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    source_kind: LifecycleAuthoritySourceKind,
    source_id: &VerifiedProofSourceId,
) -> Vec<RecoveryAuthorityId> {
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin lifecycle authority id fetch transaction");
    let table = store_config
        .table_name(PostgresAuthCoreTable::LifecycleAuthoritySource)
        .expect("lifecycle authority source table");
    let statement = format!(
        "SELECT authority_id FROM {} WHERE source_kind = $1 AND source_id = $2 ORDER BY authority_id ASC",
        table.quoted()
    );
    let rows = pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(super::super::postgres_store::i32_from_lifecycle_authority_source_kind(source_kind))
        .bind(source_id.as_bytes())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .expect("fetch lifecycle authority ids");
    tx.rollback()
        .await
        .expect("rollback lifecycle authority id fetch transaction");
    rows.into_iter()
        .map(|authority_id| {
            RecoveryAuthorityId::from_bytes(authority_id)
                .expect("stored lifecycle authority id should parse")
        })
        .collect()
}

async fn count_open_challenges(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    count_open_challenges_for_challenge(pool, store_config, &id("challenge")).await
}

async fn count_open_challenges_for_challenge(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("challenge table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1 AND closed_at IS NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count open challenges"
    )
}

async fn count_challenges_for_challenge(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("challenge table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count challenges"
    )
}

async fn fetch_out_of_band_challenge_resend_count(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> u32 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("challenge table");
    let statement = format!(
        "SELECT resend_count FROM {} WHERE challenge_id = $1",
        table.quoted()
    );
    let stored = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "fetch challenge resend count"
    );
    u32::try_from(stored).expect("stored resend count must fit u32")
}

async fn count_challenge_delivery_keys(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
        .expect("challenge delivery key table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count challenge delivery keys"
    )
}

async fn count_core_durable_effect_commands(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count core durable effect commands"
    )
}

async fn count_auth_audit_events(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::AuditEvent)
        .expect("auth audit event table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count auth audit events"
    )
}

async fn count_core_durable_effect_queue_dispatches(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectQueueDispatch)
        .expect("core durable effect queue dispatch table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count core durable effect queue dispatches"
    )
}

async fn count_queue_jobs_for_task(
    pool: &Pool,
    jobs_table: &PgQualifiedTableName,
    task_name: &str,
) -> i64 {
    let statement = format!(
        r#"SELECT count(*) FROM {} WHERE task_name = $1"#,
        jobs_table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())).bind(task_name),
        "count auth delivery queue jobs for task"
    )
}

struct QueueJobRetryState {
    status: String,
    retry_count: i32,
    last_error: Option<String>,
}

async fn fetch_one_queue_job_retry_state_for_task(
    pool: &Pool,
    jobs_table: &PgQualifiedTableName,
    task_name: &str,
) -> QueueJobRetryState {
    let statement = format!(
        r#"
        SELECT status::text, retry_count, last_error
        FROM {}
        WHERE task_name = $1
        ORDER BY id
        LIMIT 1
        "#,
        jobs_table.quoted()
    );
    let row = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_as::<(String, i32, Option<String>)>(sqlx::AssertSqlSafe(
            statement.as_str()
        ))
        .bind(task_name),
        "fetch auth delivery queue retry state"
    );
    QueueJobRetryState {
        status: row.0,
        retry_count: row.1,
        last_error: row.2,
    }
}

async fn fetch_one_queue_payload_json_for_task(
    pool: &Pool,
    jobs_table: &PgQualifiedTableName,
    task_name: &str,
) -> serde_json::Value {
    let statement = format!(
        r#"
        SELECT payload::text FROM {}
        WHERE task_name = $1
        ORDER BY id
        LIMIT 1
        "#,
        jobs_table.quoted()
    );
    let payload_json = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(statement.as_str())).bind(task_name),
        "fetch auth delivery queue payload"
    );
    serde_json::from_str(payload_json.as_str()).expect("queued payload must be JSON")
}

async fn count_all_active_proof_attempts(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count active proof attempts"
    )
}

async fn count_all_active_proof_challenges(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("active proof challenge table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count active proof challenges"
    )
}

async fn fetch_only_active_proof_challenge_id(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> ActiveProofChallengeId {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("active proof challenge table");
    let statement = format!("SELECT challenge_id FROM {} LIMIT 1", table.quoted());
    let challenge_id = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str())),
        "fetch only active proof challenge id"
    );
    ActiveProofChallengeId::from_bytes(challenge_id).expect("parse active proof challenge id")
}

async fn fetch_only_open_active_proof_challenge_id(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> ActiveProofChallengeId {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofChallenge)
        .expect("active proof challenge table");
    let statement = format!(
        "SELECT challenge_id FROM {} WHERE closed_at IS NULL",
        table.quoted()
    );
    let challenge_id = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str())),
        "fetch only open active proof challenge id"
    );
    ActiveProofChallengeId::from_bytes(challenge_id).expect("parse active proof challenge id")
}

async fn count_out_of_band_durable_effects_for_challenge(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    challenge_id: &ActiveProofChallengeId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE challenge_id = $1 AND delivery_idempotency_key IS NOT NULL",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes()),
        "count out-of-band durable effects"
    )
}

async fn count_security_notification_effects_for_subject(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!(
        r#"
        SELECT count(*) FROM {}
        WHERE subject_id = $1
            AND kind = $2
            AND challenge_id IS NULL
            AND delivery_idempotency_key IS NULL
        "#,
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(super::super::postgres_store::DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT),
        "count security notification effects"
    )
}

async fn count_application_subject_data_lifecycle_effects_for_subject_and_kind(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
    effect_kind: i32,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::CoreDurableEffectCommand)
        .expect("core durable effect command table");
    let statement = format!(
        r#"
        SELECT count(*) FROM {}
        WHERE subject_id = $1
            AND kind = $2
            AND challenge_id IS NULL
            AND delivery_idempotency_key IS NULL
        "#,
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(effect_kind),
        "count application subject data lifecycle effects"
    )
}

async fn count_all_sessions(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count sessions"
    )
}

async fn count_sessions_for_session(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    session_id: &SessionId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE session_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(session_id.as_bytes()),
        "count sessions for session"
    )
}

async fn count_session_secret_macs_for_session(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    session_id: &SessionId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::SessionCredentialSecretMac)
        .expect("session secret MAC table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE session_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(session_id.as_bytes()),
        "count session secret MACs"
    )
}

async fn count_all_trusted_devices(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!("SELECT count(*) FROM {}", table.quoted());
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str())),
        "count trusted devices"
    )
}

async fn count_trusted_device_secret_macs_for_device(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    device_credential_id: &TrustedDeviceCredentialId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
        .expect("trusted device secret MAC table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE device_credential_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(device_credential_id.as_bytes()),
        "count trusted device secret MACs"
    )
}

async fn fetch_trusted_device_id_by_display_label(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    display_label: &str,
) -> Option<TrustedDeviceCredentialId> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!(
        "SELECT device_credential_id FROM {} WHERE display_label = $1",
        table.quoted()
    );
    let bytes = auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(display_label),
        "fetch trusted device id by display label"
    )?;
    Some(TrustedDeviceCredentialId::from_bytes(bytes).expect("trusted device id bytes"))
}

async fn fetch_trusted_device_current_secret_version(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    device_credential_id: &TrustedDeviceCredentialId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!(
        "SELECT current_secret_version FROM {} WHERE device_credential_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(device_credential_id.as_bytes()),
        "fetch trusted device current secret version"
    )
}

async fn fetch_session_revoked_at(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    session_id: &SessionId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::Session)
        .expect("session table");
    let statement = format!(
        "SELECT revoked_at FROM {} WHERE session_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(session_id.as_bytes()),
        "fetch session revoked_at"
    )
    .map(|value| u64::try_from(value).expect("stored revoked_at must fit u64"))
}

async fn fetch_trusted_device_revoked_at(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    device_credential_id: &TrustedDeviceCredentialId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::TrustedDeviceCredential)
        .expect("trusted device table");
    let statement = format!(
        "SELECT revoked_at FROM {} WHERE device_credential_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(device_credential_id.as_bytes()),
        "fetch trusted device revoked_at"
    )
    .map(|value| u64::try_from(value).expect("stored revoked_at must fit u64"))
}

async fn fetch_subject_revocation_cutoff(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::SubjectAuthState)
        .expect("subject auth state table");
    let statement = format!(
        "SELECT revoke_records_created_at_or_before FROM {} WHERE subject_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes()),
        "fetch subject revocation cutoff"
    )
    .map(|value| u64::try_from(value).expect("stored cutoff must fit u64"))
}

async fn fetch_optional_subject_revocation_cutoff_for_runtime_test(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    subject_id: &SubjectId,
) -> Option<u64> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::SubjectAuthState)
        .expect("subject auth state table");
    let statement = format!(
        "SELECT revoke_records_created_at_or_before FROM {} WHERE subject_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<Option<i64>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes()),
        "fetch optional subject revocation cutoff"
    )
    .flatten()
    .map(|value| u64::try_from(value).expect("stored cutoff must fit u64"))
}

async fn count_active_proof_attempts_for_attempt(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> i64 {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!(
        "SELECT count(*) FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "count active proof attempts"
    )
}

async fn fetch_active_proof_attempt_weak_failures(
    pool: &Pool,
    store_config: &super::super::postgres_store::PostgresAuthStoreConfig,
    attempt_id: &ActiveProofAttemptId,
) -> Option<i32> {
    let table = store_config
        .table_name(PostgresAuthCoreTable::ActiveProofAttempt)
        .expect("active proof attempt table");
    let statement = format!(
        "SELECT weak_proof_failures FROM {} WHERE attempt_id = $1",
        table.quoted()
    );
    auth_runtime_test_fetch_optional_in_transaction!(
        pool,
        pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes()),
        "fetch active proof attempt weak failures"
    )
}

fn unique_runtime_test_schema_name() -> PgIdentifier {
    let counter = AUTH_POSTGRES_RUNTIME_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    PgIdentifier::new(format!(
        "__paranoid_auth_runtime_test_{}_{}",
        std::process::id(),
        counter
    ))
    .expect("test schema name")
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([37_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}
