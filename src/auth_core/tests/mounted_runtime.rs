use super::*;

use data_encoding::BASE64URL_NOPAD;
use http::{HeaderMap, Request, header};
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

use crate::db::{BootstrapConfig, Tx, WriteTx, queue};

use super::super::email_otp_method::{
    PostgresEmailOtpMethodError, PostgresEmailOtpMethodPlugin, PostgresEmailOtpMethodPluginConfig,
    PostgresEmailOtpSubjectResolver, PostgresEmailOtpVerifiedIdentifier,
};
use super::super::postgres_durable_effect_queue::{
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::super::postgres_method_runtime::{
    PostgresAuthMethodDurableEffectQueueRegistrationError, PostgresAuthMethodPlugin,
    PostgresAuthMethodRegistry,
};
use super::super::postgres_password_derived_signature_method::{
    PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL, PostgresPasswordDerivedSignatureMethodPlugin,
    PostgresPasswordDerivedSignatureMethodPluginConfig,
};
use super::super::postgres_recovery_code_method::{
    PostgresRecoveryCodeMethodPlugin, PostgresRecoveryCodeMethodPluginConfig,
};
use super::super::postgres_store::PostgresAuthMethodCommitError;

struct MountedRuntimeNoopOutOfBandDeliverer;

impl CoreAuthOutOfBandMessageDeliverer for MountedRuntimeNoopOutOfBandDeliverer {
    fn deliver_out_of_band_message<'a>(
        &'a self,
        _request: CoreAuthOutOfBandMessageDeliveryRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>
    {
        Box::pin(std::future::ready(Ok(())))
    }
}

struct MountedRuntimeNoopSecurityNotificationDeliverer;

impl CoreAuthSecurityNotificationDeliverer for MountedRuntimeNoopSecurityNotificationDeliverer {
    fn deliver_security_notification<'a>(
        &'a self,
        _request: CoreAuthSecurityNotificationDeliveryRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>
    {
        Box::pin(std::future::ready(Ok(())))
    }
}

struct MountedRuntimeNoopApplicationSubjectDataIntegrator;

impl CoreAuthApplicationSubjectDataLifecycleIntegrator
    for MountedRuntimeNoopApplicationSubjectDataIntegrator
{
    fn apply_application_subject_data_lifecycle_action<'a>(
        &'a self,
        _request: CoreAuthApplicationSubjectDataLifecycleRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreAuthDurableEffectDeliveryError>> + Send + 'a>>
    {
        Box::pin(std::future::ready(Ok(())))
    }
}

struct MountedRuntimeAllowStaffAuthorizer;

impl MountedAdminSupportStaffAuthorizer for MountedRuntimeAllowStaffAuthorizer {
    fn authorize_admin_support_intervention_request<'a>(
        &'a self,
        _headers: &'a HeaderMap,
        _request: MountedAdminSupportInterventionRequestVerificationRequest,
    ) -> Pin<Box<dyn Future<Output = MountedAdminSupportStaffAuthorization> + Send + 'a>> {
        Box::pin(std::future::ready(
            MountedAdminSupportStaffAuthorization::Authorized,
        ))
    }

    fn authorize_admin_support_staff_action<'a>(
        &'a self,
        _headers: &'a HeaderMap,
        _request: MountedAdminSupportStaffVerificationRequest,
    ) -> Pin<Box<dyn Future<Output = MountedAdminSupportStaffAuthorization> + Send + 'a>> {
        Box::pin(std::future::ready(
            MountedAdminSupportStaffAuthorization::Authorized,
        ))
    }
}

struct MountedRuntimeNoCapabilityMethodPlugin {
    method: ProofMethodDeclaration,
}

impl MountedRuntimeNoCapabilityMethodPlugin {
    fn new(method: ProofMethodDeclaration) -> Self {
        Self { method }
    }
}

impl PostgresAuthMethodPlugin for MountedRuntimeNoCapabilityMethodPlugin {
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn migrate_schema<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn validate_schema<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn enforce_precondition<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        _precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(std::future::ready(Err(
            PostgresAuthMethodCommitError::InvalidOperation(
                "mounted runtime no-capability test plugin does not enforce method work".to_owned(),
            ),
        )))
    }

    fn apply_mutation<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        _mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(std::future::ready(Err(
            PostgresAuthMethodCommitError::InvalidOperation(
                "mounted runtime no-capability test plugin does not apply method work".to_owned(),
            ),
        )))
    }

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        _command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(std::future::ready(Err(
            PostgresAuthMethodCommitError::InvalidOperation(
                "mounted runtime no-capability test plugin does not append durable effects"
                    .to_owned(),
            ),
        )))
    }

    fn register_durable_effect_queue_handlers(
        &self,
        _task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError> {
        Ok(())
    }

    fn enqueue_available_durable_effects_to_queue_in_current_transaction<'a, 'tx>(
        &'a self,
        _tx: &'a mut WriteTx<'tx>,
        _queue_store: &'a queue::Store,
        _limit: NonZeroU32,
        _enqueued_at: UnixSeconds,
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
        Box::pin(std::future::ready(Ok(
            PostgresAuthDurableEffectQueueDispatchSummary::default(),
        )))
    }
}

struct MountedRuntimeNoopEmailOtpSubjectResolver;

impl PostgresEmailOtpSubjectResolver for MountedRuntimeNoopEmailOtpSubjectResolver {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        Box::pin(async move {
            Ok(PostgresEmailOtpVerifiedIdentifier::new(
                None,
                VerifiedProofSourceId::from_bytes(recipient_handle.as_bytes())
                    .map_err(PostgresEmailOtpMethodError::Core)?,
            ))
        })
    }
}

fn mounted_runtime_noop_durable_effect_integrations() -> MountedAuthDurableEffectWorkerIntegrations
{
    MountedAuthDurableEffectWorkerIntegrations::new(
        Arc::new(MountedRuntimeNoopOutOfBandDeliverer),
        Arc::new(MountedRuntimeNoopSecurityNotificationDeliverer),
        Arc::new(MountedRuntimeNoopApplicationSubjectDataIntegrator),
    )
}

fn mounted_runtime_test_web_transport() -> AuthWebTransport {
    let cookie_manager = crate::web::CookieManager::from_keyset(mounted_runtime_test_keyset(
        "tests.auth.mounted-runtime.web.v1",
    ));
    let csrf_protector = crate::web::CsrfProtector::new(crate::web::CsrfProtectorConfig::new(
        cookie_manager.clone(),
    ))
    .expect("csrf protector");
    AuthWebTransport::new(AuthWebTransportConfig::new(
        cookie_manager,
        csrf_protector,
        mounted_runtime_test_keyset("tests.auth.mounted-runtime.fast-fail.v1"),
    ))
}

fn mounted_runtime_test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([7_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}

fn mounted_runtime_password_derived_signature_method() -> ProofMethodDeclaration {
    ProofMethodDeclaration::new_online_guessable(
        ProofFamily::MessageSignature,
        PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL,
    )
    .expect("password-derived signature method")
}

#[test]
fn mounted_auth_runtime_config_owns_no_session_recovery_flow() {
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let reset_target_method = proof_method(ProofFamily::MessageSignature);
    let flow = MountedNoSessionCredentialRecoveryFlow::new(
        recovery_method.clone(),
        reset_target_method.clone(),
    )
    .expect("mounted no-session recovery flow");
    let config = MountedAuthRuntimeConfig::default().with_no_session_credential_recovery_flow(flow);

    let configured_flow = config
        .no_session_credential_recovery_flow()
        .expect("configured no-session recovery flow");
    assert_eq!(configured_flow.recovery_method(), &recovery_method);
    assert_eq!(configured_flow.reset_target_method(), &reset_target_method);
}

#[test]
fn mounted_auth_runtime_config_owns_full_authentication_out_of_band_method() {
    let method = proof_method(ProofFamily::OutOfBandCode);
    let config = MountedAuthRuntimeConfig::default()
        .with_full_authentication_out_of_band_method(method.clone())
        .expect("configured full-authentication out-of-band method");

    assert_eq!(
        config.full_authentication_out_of_band_method(),
        Some(&method)
    );

    let mount_path = MountedAuthRouteMountPath::new("/auth").expect("mount path");
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 3);
    for endpoint in MountedFullAuthenticationEndpoint::all() {
        assert!(
            manifest.routes().iter().any(|route| route.kind()
                == MountedAuthRouteKind::FullAuthentication(endpoint)
                && route.method() == &endpoint.method()
                && route.path() == format!("/auth{}", endpoint.path())
                && !route.requires_csrf()
                && route.max_collected_body_bytes() == endpoint.max_collected_http_body_bytes()),
            "manifest must advertise full-authentication endpoint {endpoint:?}"
        );
    }
}

fn mounted_runtime_test_credential_addition_route(
    route_segment: &'static str,
) -> MountedCredentialAdditionRoute {
    let addition_method = MountedCredentialAdditionMethod::new(
        proof_method(ProofFamily::MessageSignature),
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-runtime-add-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-runtime-add-new-authority")],
    )
    .expect("mounted credential addition method");
    MountedCredentialAdditionRoute::new(route_segment, addition_method)
        .expect("mounted credential addition route")
}

fn mounted_runtime_test_password_derived_signature_credential_addition_route(
    route_segment: &'static str,
) -> MountedCredentialAdditionRoute {
    mounted_runtime_test_credential_addition_route_for_method(
        route_segment,
        mounted_runtime_password_derived_signature_method(),
    )
}

fn mounted_runtime_test_credential_addition_route_for_method(
    route_segment: &'static str,
    method: ProofMethodDeclaration,
) -> MountedCredentialAdditionRoute {
    let addition_method = MountedCredentialAdditionMethod::new(
        method,
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-runtime-add-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-runtime-add-new-authority")],
    )
    .expect("mounted credential addition method");
    MountedCredentialAdditionRoute::new(route_segment, addition_method)
        .expect("mounted credential addition route")
}

fn mounted_runtime_method_registry_for_capability_tests(
    plugins: Vec<Arc<dyn PostgresAuthMethodPlugin>>,
) -> PostgresAuthMethodRegistry {
    PostgresAuthMethodRegistry::new(plugins).expect("method registry")
}

fn mounted_runtime_email_otp_method_plugin() -> Arc<dyn PostgresAuthMethodPlugin> {
    let bootstrap_config =
        BootstrapConfig::from_schema_name_text("__mounted_runtime_email_otp_capability")
            .expect("bootstrap config");
    Arc::new(
        PostgresEmailOtpMethodPlugin::new(
            PostgresEmailOtpMethodPluginConfig::for_db_bootstrap_config(&bootstrap_config)
                .expect("email OTP method config"),
            mounted_runtime_test_keyset("tests.auth.mounted-runtime.email-otp.capability.v1"),
        )
        .expect("email OTP method")
        .with_subject_resolver(Arc::new(MountedRuntimeNoopEmailOtpSubjectResolver)),
    )
}

fn mounted_runtime_password_derived_signature_method_plugin() -> Arc<dyn PostgresAuthMethodPlugin> {
    let bootstrap_config =
        BootstrapConfig::from_schema_name_text("__mounted_runtime_password_capability")
            .expect("bootstrap config");
    Arc::new(
        PostgresPasswordDerivedSignatureMethodPlugin::new(
            PostgresPasswordDerivedSignatureMethodPluginConfig::for_db_bootstrap_config(
                &bootstrap_config,
            )
            .expect("password-derived signature method config"),
        )
        .expect("password-derived signature method"),
    )
}

fn mounted_runtime_recovery_code_method_plugin() -> Arc<dyn PostgresAuthMethodPlugin> {
    let bootstrap_config =
        BootstrapConfig::from_schema_name_text("__mounted_runtime_recovery_capability")
            .expect("bootstrap config");
    Arc::new(
        PostgresRecoveryCodeMethodPlugin::new(
            PostgresRecoveryCodeMethodPluginConfig::for_db_bootstrap_config(&bootstrap_config)
                .expect("recovery-code method config"),
            mounted_runtime_test_keyset("tests.auth.mounted-runtime.recovery-code.capability.v1"),
        )
        .expect("recovery-code method"),
    )
}

#[test]
fn mounted_auth_runtime_config_owns_credential_addition_routes() {
    let route = mounted_runtime_test_credential_addition_route("password-signature");
    let config = MountedAuthRuntimeConfig::default()
        .try_with_credential_addition_route(route.clone())
        .expect("configured credential addition route");

    assert_eq!(config.credential_addition_routes(), &[route]);
    let duplicate_route_result = MountedAuthRuntimeConfig::default()
        .try_with_credential_addition_route(mounted_runtime_test_credential_addition_route(
            "duplicate",
        ))
        .expect("first route")
        .try_with_credential_addition_route(mounted_runtime_test_credential_addition_route(
            "duplicate",
        ));
    assert!(matches!(
        duplicate_route_result,
        Err(Error::InvalidConfig(
            "mounted credential addition route segments must be unique",
        ))
    ));
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_credential_reset_routes() {
    let config = MountedAuthRuntimeConfig::default().with_authenticated_credential_reset_routes();

    assert!(config.authenticated_credential_reset_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_credential_replacement_routes() {
    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_replacement_routes();

    assert!(config.authenticated_credential_replacement_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_credential_removal_routes() {
    let config = MountedAuthRuntimeConfig::default().with_authenticated_credential_removal_routes();

    assert!(config.authenticated_credential_removal_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_credential_regeneration_routes() {
    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_regeneration_routes();

    assert!(config.authenticated_credential_regeneration_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_credential_rotation_routes() {
    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_rotation_routes();

    assert!(config.authenticated_credential_rotation_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_credential_inventory_route() {
    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_inventory_route();

    assert!(config.authenticated_credential_inventory_route_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_delayed_credential_lifecycle_routes() {
    let config = MountedAuthRuntimeConfig::default().with_delayed_credential_lifecycle_routes();

    assert!(config.delayed_credential_lifecycle_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_authenticated_out_of_band_identifier_change_routes() {
    let config = MountedAuthRuntimeConfig::default()
        .with_authenticated_out_of_band_identifier_change_routes();

    assert!(config.authenticated_out_of_band_identifier_change_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_delayed_subject_auth_state_deletion_routes() {
    let config =
        MountedAuthRuntimeConfig::default().with_delayed_subject_auth_state_deletion_routes();

    assert!(config.delayed_subject_auth_state_deletion_routes_enabled());
}

#[test]
fn mounted_auth_runtime_config_owns_admin_support_routes() {
    let config = MountedAuthRuntimeConfig::default()
        .with_admin_support_routes(Arc::new(MountedRuntimeAllowStaffAuthorizer));

    assert!(config.admin_support_routes_enabled());
    assert!(config.admin_support_staff_authorizer().is_some());
}

#[test]
fn mounted_auth_runtime_config_owns_durable_effect_worker_integrations() {
    let config =
        MountedAuthRuntimeConfig::default().with_durable_effect_worker_integrations(
            mounted_runtime_noop_durable_effect_integrations(),
        );

    assert!(config.durable_effect_worker_integrations().is_some());
}

#[test]
fn auth_system_config_owns_runtime_gate_and_configured_routes() {
    let core_config = config();
    let auth_system_config = AuthSystemConfig::new(
        core_config.clone(),
        mounted_runtime_test_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_email_otp_full_authentication_method(
        mounted_runtime_test_keyset("tests.auth.mounted-system.email-otp.v1"),
        Arc::new(MountedRuntimeNoopEmailOtpSubjectResolver),
    )
    .expect("email otp full-authentication method");

    let (runtime, _weak_proof_gate_verifier, configured_system, method_setups) =
        auth_system_config.into_runtime_and_configured_system_for_test();
    assert_eq!(runtime.config(), &core_config);
    assert_eq!(method_setups.len(), 1);

    let (mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("mounted system routes");
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::FullAuthentication(
            MountedFullAuthenticationEndpoint::StartOutOfBandChallenge,
        ),
    ));
}

#[test]
fn auth_system_config_derives_no_session_recovery_from_first_party_method_setups() {
    let auth_system_config = AuthSystemConfig::new(
        config(),
        mounted_runtime_test_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_recovery_code_to_password_derived_signature_no_session_recovery(
        mounted_runtime_test_keyset("tests.auth.mounted-system.recovery-code.v1"),
    )
    .expect("first-party no-session recovery flow");

    let (_runtime, _weak_proof_gate_verifier, configured_system, method_setups) =
        auth_system_config.into_runtime_and_configured_system_for_test();
    assert_eq!(method_setups.len(), 2);

    let (mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("mounted system routes");
    let flow = config
        .no_session_credential_recovery_flow()
        .expect("configured no-session recovery flow");
    assert_eq!(flow.recovery_method().method_label(), "recovery_code");
    assert_eq!(
        flow.reset_target_method().method_label(),
        "password_derived_signature"
    );

    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::NoSessionCredentialRecovery(
            MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset,
        ),
    ));
}

#[test]
fn auth_system_config_derives_credential_addition_from_first_party_method_setup() {
    let auth_system_config = AuthSystemConfig::new(
        config(),
        mounted_runtime_test_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_password_derived_signature_credential_addition_route(
        "password-signature",
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-system-add-session-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-system-add-new-authority")],
    )
    .expect("first-party credential addition route");

    let (_runtime, _weak_proof_gate_verifier, configured_system, method_setups) =
        auth_system_config.into_runtime_and_configured_system_for_test();
    assert_eq!(method_setups.len(), 1);
    assert!(matches!(
        method_setups[0],
        MountedAuthPostgresMethodSetup::PasswordDerivedSignature
    ));

    let (mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("mounted system routes");
    assert_eq!(config.credential_addition_routes().len(), 1);
    let route = &config.credential_addition_routes()[0];
    assert_eq!(route.route_segment(), "password-signature");
    assert_eq!(
        route.method_config().method().method_label(),
        PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL
    );
    assert_eq!(
        route.method_config().reset_policy_role(),
        CredentialResetPolicyRole::OrdinaryCredential
    );

    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::AuthenticatedCredentialAddition,
    ));
}

#[test]
fn auth_system_config_reuses_password_method_setup_across_mounted_flows() {
    let auth_system_config = AuthSystemConfig::new(
        config(),
        mounted_runtime_test_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_recovery_code_to_password_derived_signature_no_session_recovery(
        mounted_runtime_test_keyset("tests.auth.mounted-system.shared-recovery-code.v1"),
    )
    .expect("first-party no-session recovery flow")
    .with_password_derived_signature_credential_addition_route(
        "password-signature",
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-system-shared-add-session-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-system-shared-add-new-authority")],
    )
    .expect("shared password-derived credential addition route");

    let (_runtime, _weak_proof_gate_verifier, configured_system, method_setups) =
        auth_system_config.into_runtime_and_configured_system_for_test();
    assert_eq!(method_setups.len(), 2);
    assert_eq!(
        method_setups
            .iter()
            .filter(|setup| matches!(
                setup,
                MountedAuthPostgresMethodSetup::PasswordDerivedSignature
            ))
            .count(),
        1
    );

    let (_mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("mounted system routes");
    assert!(config.no_session_credential_recovery_flow().is_some());
    assert_eq!(config.credential_addition_routes().len(), 1);
}

#[test]
fn postgres_auth_system_config_owns_storage_methods_routes_and_runtime_surface() {
    let postgres_auth_system_config = PostgresAuthSystemConfig::new(
        BootstrapConfig::from_schema_name_text("__mounted_auth_system_config")
            .expect("DB bootstrap config"),
        mounted_runtime_test_keyset("tests.auth.mounted-system.credential-secrets.v1"),
        config(),
        mounted_runtime_test_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_email_otp_full_authentication_method(
        mounted_runtime_test_keyset("tests.auth.mounted-system.email-otp.v1"),
        Arc::new(MountedRuntimeNoopEmailOtpSubjectResolver),
    )
    .expect("first-party email OTP method")
    .with_recovery_code_to_password_derived_signature_no_session_recovery(
        mounted_runtime_test_keyset("tests.auth.mounted-system.postgres-recovery-code.v1"),
    )
    .expect("first-party no-session recovery flow")
    .with_password_derived_signature_credential_addition_route(
        "password-signature",
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-system-postgres-add-session-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-system-postgres-add-new-authority")],
    )
    .expect("credential addition route");

    let (db_bootstrap_config, _credential_secret_keyset, auth_system_config) =
        postgres_auth_system_config.into_parts();
    assert_eq!(
        db_bootstrap_config.schema_name().as_str(),
        "__mounted_auth_system_config"
    );

    let (_runtime, _weak_proof_gate_verifier, configured_system, method_setups) =
        auth_system_config.into_runtime_and_configured_system_for_test();
    assert_eq!(method_setups.len(), 3);

    let (mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("configured mounted auth system");
    assert_eq!(mount_path.as_str(), "/auth");
    assert!(config.no_session_credential_recovery_flow().is_some());
    assert_eq!(config.credential_addition_routes().len(), 1);

    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::NoSessionCredentialRecovery(
            MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt,
        ),
    ));
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::AuthenticatedCredentialAddition,
    ));
}

#[test]
fn auth_system_config_rejects_duplicate_first_party_method_setups() {
    let auth_system_config = AuthSystemConfig::new(
        config(),
        mounted_runtime_test_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_recovery_code_method(mounted_runtime_test_keyset(
        "tests.auth.mounted-system.first-recovery-code.v1",
    ))
    .expect("first recovery code method setup");

    let error = match auth_system_config.with_recovery_code_method(mounted_runtime_test_keyset(
        "tests.auth.mounted-system.second-recovery-code.v1",
    )) {
        Ok(_) => panic!("duplicate recovery-code method setup must reject"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        Error::InvalidConfig("mounted auth first-party method setups must be unique"),
    );
}

#[test]
fn mounted_auth_configured_system_enables_coherent_auth_surface() {
    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    let addition_route = mounted_runtime_test_credential_addition_route("password-signature");
    let configured_system = MountedAuthConfiguredSystem::new(
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_full_authentication_out_of_band_method(proof_method(ProofFamily::OutOfBandCode))
    .expect("configured full-authentication method")
    .with_no_session_credential_recovery_flow(recovery_flow)
    .try_with_credential_addition_route(addition_route)
    .expect("configured credential addition route")
    .with_admin_support_routes(Arc::new(MountedRuntimeAllowStaffAuthorizer));
    let (mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("configured mounted auth system");

    assert!(config.durable_effect_worker_integrations().is_some());
    assert!(config.full_authentication_out_of_band_method().is_some());
    assert!(config.no_session_credential_recovery_flow().is_some());
    assert_eq!(config.credential_addition_routes().len(), 1);
    assert!(config.authenticated_credential_inventory_route_enabled());
    assert!(config.authenticated_credential_reset_routes_enabled());
    assert!(config.authenticated_credential_replacement_routes_enabled());
    assert!(config.authenticated_credential_removal_routes_enabled());
    assert!(config.authenticated_credential_regeneration_routes_enabled());
    assert!(config.authenticated_credential_rotation_routes_enabled());
    assert!(config.delayed_credential_lifecycle_routes_enabled());
    assert!(config.authenticated_out_of_band_identifier_change_routes_enabled());
    assert!(config.delayed_subject_auth_state_deletion_routes_enabled());
    assert!(config.admin_support_routes_enabled());

    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 32);
    for endpoint in MountedFullAuthenticationEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::FullAuthentication(endpoint),
        ));
    }
    for endpoint in MountedNoSessionCredentialRecoveryEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::NoSessionCredentialRecovery(endpoint),
        ));
    }
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::AuthenticatedCredentialInventory,
    ));
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::AuthenticatedCredentialAddition,
    ));
    for endpoint in MountedAuthenticatedCredentialResetEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AuthenticatedCredentialReset(endpoint),
        ));
    }
    for endpoint in MountedAuthenticatedCredentialReplacementEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AuthenticatedCredentialReplacement(endpoint),
        ));
    }
    for endpoint in MountedAuthenticatedCredentialRemovalEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AuthenticatedCredentialRemoval(endpoint),
        ));
    }
    for endpoint in MountedAuthenticatedCredentialRegenerationEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AuthenticatedCredentialRegeneration(endpoint),
        ));
    }
    for endpoint in MountedAuthenticatedCredentialRotationEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AuthenticatedCredentialRotation(endpoint),
        ));
    }
    for endpoint in MountedDelayedCredentialLifecycleEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::DelayedCredentialLifecycle(endpoint),
        ));
    }
    for endpoint in MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(endpoint),
        ));
    }
    for endpoint in MountedDelayedOutOfBandIdentifierChangeEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(endpoint),
        ));
    }
    for endpoint in MountedDelayedSubjectAuthStateDeletionEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(endpoint),
        ));
    }
    for endpoint in MountedAdminSupportEndpoint::all() {
        assert!(mounted_route_manifest_contains_kind(
            &manifest,
            MountedAuthRouteKind::AdminSupport(endpoint),
        ));
    }
}

#[test]
fn mounted_auth_configured_system_rejects_duplicate_addition_route_segments() {
    let first_route = mounted_runtime_test_credential_addition_route("password-signature");
    let second_route = mounted_runtime_test_credential_addition_route("password-signature");
    let configured_system = MountedAuthConfiguredSystem::new(
        MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .try_with_credential_addition_route(first_route)
    .expect("first addition route");
    let error = match configured_system.try_with_credential_addition_route(second_route) {
        Ok(_) => panic!("duplicate addition route segment must reject"),
        Err(error) => error,
    };

    assert_eq!(
        error,
        Error::InvalidConfig("mounted credential addition route segments must be unique"),
    );
}

#[test]
fn mounted_auth_configured_system_owns_mount_path_and_coherent_routes() {
    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    let mount_path = MountedAuthRouteMountPath::new("/auth").expect("auth mount path");
    let configured_system = MountedAuthConfiguredSystem::new(
        mount_path.clone(),
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_no_session_credential_recovery_flow(recovery_flow);

    assert_eq!(configured_system.mount_path(), &mount_path);

    let (configured_mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("configured mounted auth system");
    assert_eq!(configured_mount_path, mount_path);
    let manifest =
        MountedAuthRouteManifest::from_config_and_mount_path(&config, &configured_mount_path);

    assert_eq!(manifest.routes().len(), 24);
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::NoSessionCredentialRecovery(
            MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset,
        ),
    ));
    assert!(mounted_route_manifest_contains_kind(
        &manifest,
        MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(
            MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion,
        ),
    ));
}

fn mounted_route_manifest_contains_kind(
    manifest: &MountedAuthRouteManifest,
    kind: MountedAuthRouteKind,
) -> bool {
    manifest.routes().iter().any(|route| route.kind() == kind)
}

#[test]
fn mounted_auth_runtime_config_rejects_unregistered_named_methods() {
    let empty_registry =
        PostgresAuthMethodRegistry::new(std::iter::empty::<Arc<dyn PostgresAuthMethodPlugin>>())
            .expect("empty method registry");
    MountedAuthRuntimeConfig::default()
        .validate_against_runtime_dependencies(None)
        .expect("empty mounted config has no named method to validate");

    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let reset_target_method = proof_method(ProofFamily::MessageSignature);
    let recovery_flow =
        MountedNoSessionCredentialRecoveryFlow::new(recovery_method.clone(), reset_target_method)
            .expect("mounted no-session recovery flow");
    let recovery_config =
        MountedAuthRuntimeConfig::default()
            .with_no_session_credential_recovery_flow(recovery_flow)
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            );
    let recovery_error = recovery_config
        .validate_against_runtime_dependencies(Some(&empty_registry))
        .expect_err("unregistered recovery method must reject mounted config");
    assert!(
        matches!(
            recovery_error,
            MountedAuthRuntimeError::ConfiguredMethodNotRegistered {
                family: ProofFamily::RecoveryCode,
                ref method_label,
            } if method_label == recovery_method.method_label()
        ),
        "unexpected mounted recovery config error: {recovery_error:?}"
    );

    let addition_route = mounted_runtime_test_credential_addition_route("password-signature");
    let addition_method = addition_route.method_config().method().clone();
    let addition_config =
        MountedAuthRuntimeConfig::default()
            .try_with_credential_addition_route(addition_route)
            .expect("configured credential addition route")
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            );
    let addition_error = addition_config
        .validate_against_runtime_dependencies(Some(&empty_registry))
        .expect_err("unregistered addition method must reject mounted config");
    assert!(
        matches!(
            addition_error,
            MountedAuthRuntimeError::ConfiguredMethodNotRegistered {
                family: ProofFamily::MessageSignature,
                ref method_label,
            } if method_label == addition_method.method_label()
        ),
        "unexpected mounted addition config error: {addition_error:?}"
    );
}

#[test]
fn mounted_auth_runtime_config_rejects_registered_named_methods_without_route_capability() {
    let method = proof_method(ProofFamily::OutOfBandCode);
    let registry = mounted_runtime_method_registry_for_capability_tests(vec![Arc::new(
        MountedRuntimeNoCapabilityMethodPlugin::new(method.clone()),
    )]);
    let full_auth_config =
        MountedAuthRuntimeConfig::default()
            .with_full_authentication_out_of_band_method(method.clone())
            .expect("configured full-authentication out-of-band route")
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            );
    let full_auth_error = full_auth_config
        .validate_against_runtime_dependencies(Some(&registry))
        .expect_err("registered method without out-of-band capability must reject");
    assert!(
        matches!(
            full_auth_error,
            MountedAuthRuntimeError::ConfiguredMethodLacksMountedRouteCapability {
                family: ProofFamily::OutOfBandCode,
                ref method_label,
                route_family: "full-authentication out-of-band routes",
                capability: "out-of-band full-authentication challenge work",
            } if method_label == method.method_label()
        ),
        "unexpected mounted full-authentication capability error: {full_auth_error:?}"
    );
}

#[test]
fn mounted_auth_runtime_config_rejects_route_families_without_required_method_capability() {
    let registry = mounted_runtime_method_registry_for_capability_tests(vec![
        mounted_runtime_email_otp_method_plugin(),
    ]);
    let reset_config =
        MountedAuthRuntimeConfig::default()
            .with_authenticated_credential_reset_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            );
    assert_eq!(
        reset_config
            .validate_against_runtime_dependencies(Some(&registry))
            .expect_err("credential reset routes require reset-capable methods"),
        MountedAuthRuntimeError::MountedRoutesRequireMethodCapability {
            route_family: "authenticated credential reset routes",
            capability: "credential reset work",
        }
    );
}

#[test]
fn mounted_auth_runtime_config_accepts_complete_method_capabilities_for_product_routes() {
    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        mounted_runtime_password_derived_signature_method(),
    )
    .expect("mounted no-session recovery flow");
    let mount_path = MountedAuthRouteMountPath::new("/auth").expect("auth mount path");
    let configured_system = MountedAuthConfiguredSystem::new(
        mount_path,
        mounted_runtime_noop_durable_effect_integrations(),
    )
    .with_full_authentication_out_of_band_method(proof_method(ProofFamily::OutOfBandCode))
    .expect("full authentication out-of-band method")
    .with_no_session_credential_recovery_flow(recovery_flow)
    .try_with_credential_addition_route(
        mounted_runtime_test_password_derived_signature_credential_addition_route(
            "password-signature",
        ),
    )
    .expect("credential addition route");
    let (_mount_path, config) = configured_system
        .into_mount_path_and_runtime_config()
        .expect("configured mounted auth system");
    let registry = mounted_runtime_method_registry_for_capability_tests(vec![
        mounted_runtime_email_otp_method_plugin(),
        mounted_runtime_password_derived_signature_method_plugin(),
        mounted_runtime_recovery_code_method_plugin(),
    ]);

    config
        .validate_against_runtime_dependencies(Some(&registry))
        .expect("complete first-party mounted route capabilities");
}

#[test]
fn mounted_auth_runtime_config_requires_durable_effect_worker_integrations_for_mutation_routes() {
    MountedAuthRuntimeConfig::default()
        .with_authenticated_credential_inventory_route()
        .validate_against_runtime_dependencies(None)
        .expect("read-only credential inventory route does not require durable effect workers");

    let reset_config_without_workers =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_reset_routes();
    assert_eq!(
        reset_config_without_workers
            .validate_against_runtime_dependencies(None)
            .expect_err("credential reset routes schedule notices and require workers"),
        MountedAuthRuntimeError::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes
    );

    MountedAuthRuntimeConfig::default()
        .with_delayed_subject_auth_state_deletion_routes()
        .with_durable_effect_worker_integrations(mounted_runtime_noop_durable_effect_integrations())
        .validate_against_runtime_dependencies(None)
        .expect("subject deletion routes with durable effect workers are valid");

    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_delayed_subject_auth_state_deletion_routes()
            .validate_against_runtime_dependencies(None)
            .expect_err("subject deletion routes schedule notices and app-data lifecycle effects"),
        MountedAuthRuntimeError::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes
    );

    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_admin_support_routes(Arc::new(MountedRuntimeAllowStaffAuthorizer))
            .validate_against_runtime_dependencies(None)
            .expect_err("admin support routes schedule notices and require workers"),
        MountedAuthRuntimeError::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes
    );
}

#[test]
fn mounted_auth_runtime_config_requires_method_registry_for_dynamic_method_mutation_routes() {
    MountedAuthRuntimeConfig::default()
        .with_authenticated_credential_inventory_route()
        .validate_against_runtime_dependencies(None)
        .expect("read-only credential inventory route does not require method registry");

    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_no_session_credential_recovery_flow(recovery_flow)
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("no-session recovery routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );

    MountedAuthRuntimeConfig::default()
        .with_authenticated_credential_removal_routes()
        .with_durable_effect_worker_integrations(mounted_runtime_noop_durable_effect_integrations())
        .validate_against_runtime_dependencies(None)
        .expect("core-owned credential removal routes do not require method registry");

    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .try_with_credential_addition_route(mounted_runtime_test_credential_addition_route(
                "password-signature",
            ))
            .expect("configured credential addition route")
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("credential addition routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_authenticated_credential_reset_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("credential reset routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_authenticated_credential_replacement_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("credential replacement routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_authenticated_credential_regeneration_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("credential regeneration routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_authenticated_credential_rotation_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("credential rotation routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_delayed_credential_lifecycle_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("delayed credential lifecycle routes include method mutation lanes"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
    assert_eq!(
        MountedAuthRuntimeConfig::default()
            .with_authenticated_out_of_band_identifier_change_routes()
            .with_durable_effect_worker_integrations(
                mounted_runtime_noop_durable_effect_integrations(),
            )
            .validate_against_runtime_dependencies(None)
            .expect_err("identifier change routes require method registry"),
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes
    );
}

#[test]
fn mounted_auth_runtime_error_explains_missing_no_session_recovery_flow() {
    assert_eq!(
        MountedAuthRuntimeError::NoSessionCredentialRecoveryFlowNotConfigured.to_string(),
        "auth core: no-session credential recovery flow is not configured"
    );
}

#[test]
fn mounted_auth_runtime_error_explains_missing_durable_effect_integrations() {
    assert_eq!(
        MountedAuthRuntimeError::DurableEffectWorkerIntegrationsNotConfigured.to_string(),
        "auth core: durable-effect worker integrations are not configured"
    );
    assert_eq!(
        MountedAuthRuntimeError::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes
            .to_string(),
        "auth core: configured mounted auth routes require durable-effect worker integrations"
    );
    assert_eq!(
        MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes.to_string(),
        "auth core: configured mounted auth routes require an auth method registry"
    );
}

#[test]
fn mounted_auth_runtime_error_explains_missing_admin_support_staff_authorizer() {
    assert_eq!(
        MountedAuthRuntimeError::AdminSupportStaffAuthorizerNotConfigured.to_string(),
        "auth core: admin support staff authorizer is not configured"
    );
}

#[test]
fn mounted_auth_runtime_error_explains_unregistered_configured_method() {
    assert_eq!(
        MountedAuthRuntimeError::ConfiguredMethodNotRegistered {
            family: ProofFamily::MessageSignature,
            method_label: "password_derived_signature".to_owned(),
        }
        .to_string(),
        "auth core: mounted auth config references unregistered method MessageSignature/password_derived_signature"
    );
    assert_eq!(
        MountedAuthRuntimeError::ConfiguredMethodLacksMountedRouteCapability {
            family: ProofFamily::OutOfBandCode,
            method_label: "email_otp".to_owned(),
            route_family: "credential addition routes",
            capability: "credential creation work",
        }
        .to_string(),
        "auth core: mounted auth credential addition routes require method OutOfBandCode/email_otp to support credential creation work"
    );
    assert_eq!(
        MountedAuthRuntimeError::MountedRoutesRequireMethodCapability {
            route_family: "authenticated credential reset routes",
            capability: "credential reset work",
        }
        .to_string(),
        "auth core: mounted auth authenticated credential reset routes require a registered method that supports credential reset work"
    );
}

#[test]
fn mounted_auth_route_mount_path_validates_and_strips_request_paths() {
    let mount_path = MountedAuthRouteMountPath::new("/auth").expect("auth mount path");
    assert_eq!(mount_path.as_str(), "/auth");
    assert_eq!(
        mount_path.relative_path_for_request_path("/auth/credential-recovery/start"),
        Some("/credential-recovery/start")
    );
    assert_eq!(
        mount_path.relative_path_for_request_path("/auth"),
        Some("/")
    );
    assert_eq!(
        mount_path.relative_path_for_request_path("/authentic"),
        None
    );
    assert_eq!(
        mount_path.relative_path_for_request_path("/other/credential-recovery/start"),
        None
    );

    let root_mount_path = MountedAuthRouteMountPath::new("/").expect("root auth mount path");
    assert_eq!(
        root_mount_path.relative_path_for_request_path("/credential-recovery/start"),
        Some("/credential-recovery/start")
    );

    assert_eq!(
        MountedAuthRouteMountPath::new("").expect_err("empty mount path must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath("auth route mount path must not be empty",)
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("auth").expect_err("relative mount path must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath("auth route mount path must start with '/'",)
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("/auth/").expect_err("trailing slash must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path must not end with '/'",
        )
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("/auth//v1").expect_err("empty segment must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path must not contain empty segments",
        )
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("/auth/./v1").expect_err("dot segment must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path must not contain dot segments",
        )
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("/auth/../v1").expect_err("dot-dot segment must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path must not contain dot segments",
        )
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("/auth?next=/admin")
            .expect_err("query-shaped mount path must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path segments must contain only ASCII letters, digits, dots, underscores, or hyphens",
        )
    );
    assert_eq!(
        MountedAuthRouteMountPath::new("/auth/%2f")
            .expect_err("percent-encoded-looking mount path must reject"),
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path segments must contain only ASCII letters, digits, dots, underscores, or hyphens",
        )
    );
}

#[test]
fn mounted_auth_route_manifest_exposes_only_configured_routes() {
    let mount_path = MountedAuthRouteMountPath::new("/auth").expect("auth mount path");
    let empty_manifest = MountedAuthRouteManifest::from_config_and_mount_path(
        &MountedAuthRuntimeConfig::default(),
        &mount_path,
    );
    assert!(empty_manifest.routes().is_empty());

    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    let config =
        MountedAuthRuntimeConfig::default().with_no_session_credential_recovery_flow(recovery_flow);
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);

    assert_eq!(manifest.routes().len(), 4);
    let start_route = &manifest.routes()[0];
    assert_eq!(
        start_route.kind(),
        MountedAuthRouteKind::NoSessionCredentialRecovery(
            MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt
        )
    );
    assert_eq!(start_route.method(), &http::Method::POST);
    assert_eq!(start_route.path(), "/auth/credential-recovery/start");
    assert!(!start_route.requires_csrf());
    assert_eq!(
        start_route.max_collected_body_bytes(),
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt
            .max_collected_http_body_bytes()
    );

    let schedule_route = &manifest.routes()[2];
    assert_eq!(
        schedule_route.kind(),
        MountedAuthRouteKind::NoSessionCredentialRecovery(
            MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset
        )
    );
    assert!(schedule_route.requires_csrf());
    assert_eq!(schedule_route.max_collected_body_bytes(), 0);

    let root_manifest = MountedAuthRouteManifest::from_config_and_mount_path(
        &config,
        &MountedAuthRouteMountPath::new("/").expect("root mount path"),
    );
    assert_eq!(
        root_manifest.routes()[0].path(),
        MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
    );

    let addition_route = mounted_runtime_test_credential_addition_route("password-signature");
    let config = MountedAuthRuntimeConfig::default()
        .try_with_credential_addition_route(addition_route)
        .expect("configured credential addition route");
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 1);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialAddition
    );
    assert_eq!(manifest.routes()[0].method(), &http::Method::POST);
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/credentials/add/password-signature"
    );
    assert!(manifest.routes()[0].requires_csrf());
    assert!(
        manifest.routes()[0].max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );

    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_inventory_route();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 1);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialInventory
    );
    assert_eq!(manifest.routes()[0].method(), &http::Method::GET);
    assert_eq!(manifest.routes()[0].path(), "/auth/credentials");
    assert!(!manifest.routes()[0].requires_csrf());
    assert_eq!(manifest.routes()[0].max_collected_body_bytes(), 0);

    let config = MountedAuthRuntimeConfig::default().with_authenticated_credential_reset_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 2);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialReset(
            MountedAuthenticatedCredentialResetEndpoint::PlanReset
        )
    );
    assert_eq!(manifest.routes()[0].path(), "/auth/credentials/reset/plan");
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialReset(
            MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/credentials/reset/execute"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_replacement_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 2);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialReplacement(
            MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement
        )
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/credentials/replace/plan"
    );
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialReplacement(
            MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/credentials/replace/execute"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config = MountedAuthRuntimeConfig::default().with_authenticated_credential_removal_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 2);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialRemoval(
            MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval
        )
    );
    assert_eq!(manifest.routes()[0].path(), "/auth/credentials/remove/plan");
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialRemoval(
            MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/credentials/remove/execute"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_regeneration_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 2);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialRegeneration(
            MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration
        )
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/credentials/regenerate/plan"
    );
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialRegeneration(
            MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/credentials/regenerate/execute"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config =
        MountedAuthRuntimeConfig::default().with_authenticated_credential_rotation_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 1);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedCredentialRotation(
            MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation
        )
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/credentials/rotate/execute"
    );
    assert!(manifest.routes()[0].requires_csrf());
    assert!(
        manifest.routes()[0].max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );

    let config = MountedAuthRuntimeConfig::default().with_delayed_credential_lifecycle_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 3);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::DelayedCredentialLifecycle(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteReset
        )
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/credentials/delayed/reset/execute"
    );
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::DelayedCredentialLifecycle(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/credentials/delayed/replace-or-regenerate/execute"
    );
    assert_eq!(
        manifest.routes()[2].kind(),
        MountedAuthRouteKind::DelayedCredentialLifecycle(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval
        )
    );
    assert_eq!(
        manifest.routes()[2].path(),
        "/auth/credentials/delayed/remove/execute"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config = MountedAuthRuntimeConfig::default()
        .with_authenticated_out_of_band_identifier_change_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 4);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
        )
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/out-of-band-identifiers/change/plan"
    );
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/out-of-band-identifiers/change/execute"
    );
    assert_eq!(
        manifest.routes()[2].kind(),
        MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(
            MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange
        )
    );
    assert_eq!(
        manifest.routes()[2].path(),
        "/auth/out-of-band-identifiers/change/delayed/execute"
    );
    assert_eq!(
        manifest.routes()[3].kind(),
        MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(
            MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange
        )
    );
    assert_eq!(
        manifest.routes()[3].path(),
        "/auth/out-of-band-identifiers/change/delayed/cancel"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config =
        MountedAuthRuntimeConfig::default().with_delayed_subject_auth_state_deletion_routes();
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 3);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(
            MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion
        )
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/subject-auth-state/delete/schedule"
    );
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(
            MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion
        )
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/subject-auth-state/delete/execute"
    );
    assert_eq!(
        manifest.routes()[2].kind(),
        MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(
            MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion
        )
    );
    assert_eq!(
        manifest.routes()[2].path(),
        "/auth/subject-auth-state/delete/cancel"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );

    let config = MountedAuthRuntimeConfig::default()
        .with_admin_support_routes(Arc::new(MountedRuntimeAllowStaffAuthorizer));
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);
    assert_eq!(manifest.routes().len(), 4);
    assert_eq!(
        manifest.routes()[0].kind(),
        MountedAuthRouteKind::AdminSupport(MountedAdminSupportEndpoint::RequestIntervention)
    );
    assert_eq!(
        manifest.routes()[0].path(),
        "/auth/admin-support/interventions/request"
    );
    assert_eq!(
        manifest.routes()[1].kind(),
        MountedAuthRouteKind::AdminSupport(MountedAdminSupportEndpoint::ApproveIntervention)
    );
    assert_eq!(
        manifest.routes()[1].path(),
        "/auth/admin-support/interventions/approve"
    );
    assert_eq!(
        manifest.routes()[2].kind(),
        MountedAuthRouteKind::AdminSupport(MountedAdminSupportEndpoint::DenyIntervention)
    );
    assert_eq!(
        manifest.routes()[2].path(),
        "/auth/admin-support/interventions/deny"
    );
    assert_eq!(
        manifest.routes()[3].kind(),
        MountedAuthRouteKind::AdminSupport(MountedAdminSupportEndpoint::ExpireIntervention)
    );
    assert_eq!(
        manifest.routes()[3].path(),
        "/auth/admin-support/interventions/expire"
    );
    assert!(manifest.routes().iter().all(|route| route.requires_csrf()));
    assert!(
        manifest.routes().iter().all(
            |route| route.max_collected_body_bytes() < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        )
    );
}

#[test]
fn mounted_auth_route_errors_explain_configuration_and_dispatch_failures() {
    assert_eq!(
        MountedAuthRuntimeError::InvalidRouteMountPath(
            "auth route mount path must start with '/'",
        )
        .to_string(),
        "auth core: invalid auth route mount path: auth route mount path must start with '/'"
    );
    assert_eq!(
        MountedAuthRouteServiceError::RouteNotFound {
            method: http::Method::POST,
            path: "/auth/unknown".to_owned(),
        }
        .to_string(),
        "auth core: mounted auth route not found for POST /auth/unknown"
    );
}

#[test]
fn mounted_auth_http_body_limits_are_endpoint_specific() {
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset
            .max_collected_http_body_bytes(),
        0
    );
    assert!(
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt
            .max_collected_http_body_bytes()
            > MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof
                .max_collected_http_body_bytes()
    );
    assert!(
        MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof
            .max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
    assert!(
        MountedNoSessionCredentialRecoveryEndpoint::ExecuteImmediateReset
            .max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
    assert!(
        MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement
            .max_collected_http_body_bytes()
            < MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement
                .max_collected_http_body_bytes()
    );
    assert_eq!(
        MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval.max_collected_http_body_bytes(),
        MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval
            .max_collected_http_body_bytes()
    );
    assert!(
        MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration
            .max_collected_http_body_bytes()
            < MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration
                .max_collected_http_body_bytes()
    );
    assert!(
        MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation
            .max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
    assert_eq!(
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReset.max_collected_http_body_bytes(),
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate
            .max_collected_http_body_bytes()
    );
    assert!(
        MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval.max_collected_http_body_bytes()
            < MountedDelayedCredentialLifecycleEndpoint::ExecuteReset
                .max_collected_http_body_bytes()
    );
    assert!(
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReset.max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
    assert_eq!(
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
            .max_collected_http_body_bytes(),
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange
            .max_collected_http_body_bytes()
    );
    assert!(
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
            .max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
    assert_eq!(
        MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange
            .max_collected_http_body_bytes(),
        MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange
            .max_collected_http_body_bytes()
    );
    assert!(
        MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange
            .max_collected_http_body_bytes()
            < MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
                .max_collected_http_body_bytes()
    );
    assert!(
        MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion
            .max_collected_http_body_bytes()
            < MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion
                .max_collected_http_body_bytes()
    );
    assert!(
        MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion
            .max_collected_http_body_bytes()
            < MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion
                .max_collected_http_body_bytes()
    );
    assert!(
        MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion
            .max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
    assert!(
        MountedAdminSupportEndpoint::ApproveIntervention.max_collected_http_body_bytes()
            < MountedAdminSupportEndpoint::RequestIntervention.max_collected_http_body_bytes()
    );
    assert!(
        MountedAdminSupportEndpoint::RequestIntervention.max_collected_http_body_bytes()
            < MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
    );
}

#[test]
fn mounted_auth_http_global_body_limit_covers_every_advertised_route_limit() {
    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    let addition_route = mounted_runtime_test_credential_addition_route("password-signature");
    let config = MountedAuthRuntimeConfig::default()
        .with_full_authentication_out_of_band_method(proof_method(ProofFamily::OutOfBandCode))
        .expect("configured full-authentication method")
        .with_no_session_credential_recovery_flow(recovery_flow)
        .try_with_credential_addition_route(addition_route)
        .expect("configured credential addition route")
        .with_authenticated_credential_reset_routes()
        .with_authenticated_credential_replacement_routes()
        .with_authenticated_credential_removal_routes()
        .with_authenticated_credential_regeneration_routes()
        .with_authenticated_credential_rotation_routes()
        .with_authenticated_credential_inventory_route()
        .with_delayed_credential_lifecycle_routes()
        .with_authenticated_out_of_band_identifier_change_routes()
        .with_delayed_subject_auth_state_deletion_routes()
        .with_admin_support_routes(Arc::new(MountedRuntimeAllowStaffAuthorizer));
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(
        &config,
        &MountedAuthRouteMountPath::new("/auth").expect("auth mount path"),
    );

    assert!(!manifest.routes().is_empty());
    for route in manifest.routes() {
        assert!(
            route.max_collected_body_bytes() <= MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES,
            "{} advertises route limit {} above the mounted service global limit {}",
            route.path(),
            route.max_collected_body_bytes(),
            MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        );
    }
}

#[test]
fn mounted_auth_route_manifest_is_guard_route_source_of_truth() {
    let recovery_flow = MountedNoSessionCredentialRecoveryFlow::new(
        proof_method(ProofFamily::RecoveryCode),
        proof_method(ProofFamily::MessageSignature),
    )
    .expect("mounted no-session recovery flow");
    let addition_route = mounted_runtime_test_credential_addition_route("password-signature");
    let config = MountedAuthRuntimeConfig::default()
        .with_full_authentication_out_of_band_method(proof_method(ProofFamily::OutOfBandCode))
        .expect("configured full-authentication method")
        .with_no_session_credential_recovery_flow(recovery_flow)
        .try_with_credential_addition_route(addition_route)
        .expect("configured credential addition route")
        .with_authenticated_credential_reset_routes()
        .with_authenticated_credential_replacement_routes()
        .with_authenticated_credential_removal_routes()
        .with_authenticated_credential_regeneration_routes()
        .with_authenticated_credential_rotation_routes()
        .with_authenticated_credential_inventory_route()
        .with_delayed_credential_lifecycle_routes()
        .with_authenticated_out_of_band_identifier_change_routes()
        .with_delayed_subject_auth_state_deletion_routes()
        .with_admin_support_routes(Arc::new(MountedRuntimeAllowStaffAuthorizer));
    let mount_path = MountedAuthRouteMountPath::new("/auth").expect("auth mount path");
    let manifest = MountedAuthRouteManifest::from_config_and_mount_path(&config, &mount_path);

    assert!(!manifest.routes().is_empty());
    for descriptor in manifest.routes() {
        let looked_up = manifest
            .descriptor_for_method_and_path(descriptor.method(), descriptor.path())
            .expect("advertised mounted auth route must be lookupable");
        assert_eq!(looked_up, descriptor);

        let guarded_route = descriptor
            .guarded_route(&config, &mount_path)
            .expect("advertised mounted auth route must build a guarded route");
        assert_eq!(
            guarded_route.route_kind_name(),
            descriptor.kind().route_kind_name()
        );
    }

    assert!(
        manifest
            .descriptor_for_method_and_path(&http::Method::POST, "/auth/not-configured")
            .is_none()
    );
}

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8"
            .parse()
            .expect("content-type header value"),
    );
    headers
}

#[test]
fn mounted_auth_http_body_parser_builds_no_session_recovery_submitted_bodies() {
    let headers = json_headers();
    let preflight_payload = BASE64URL_NOPAD.encode(b"preflight-response");
    let start_body = format!(
        r#"{{
            "preflight_gate_kind": "proof_of_work",
            "preflight_gate_method_label": "hashcash",
            "preflight_gate_payload_base64url": "{preflight_payload}"
        }}"#
    )
    .into_bytes();
    let submitted = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt,
        &headers,
        start_body,
    )
    .expect("parse recovery start body");
    assert_eq!(
        submitted.step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );
    assert_eq!(
        submitted
            .into_endpoint_request_body()
            .expect("validate start submitted body")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );

    let proof_payload = BASE64URL_NOPAD.encode(b"sealed-recovery-code");
    let proof_body = format!(r#"{{"secret_response_base64url":"{proof_payload}"}}"#).into_bytes();
    let submitted = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof,
        &headers,
        proof_body,
    )
    .expect("parse recovery proof body");
    assert_eq!(
        submitted.step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );
    assert_eq!(
        submitted
            .into_endpoint_request_body()
            .expect("validate proof submitted body")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );

    let submitted = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset,
        &HeaderMap::new(),
        Vec::new(),
    )
    .expect("parse empty schedule body");
    assert_eq!(
        submitted.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );
    assert_eq!(
        submitted
            .into_endpoint_request_body()
            .expect("validate empty schedule submitted body")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );

    let reset_payload = BASE64URL_NOPAD.encode(b"new-password-verifier");
    let reset_body = format!(r#"{{"method_payload_base64url":"{reset_payload}"}}"#).into_bytes();
    let submitted = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::ExecuteImmediateReset,
        &headers,
        reset_body,
    )
    .expect("parse immediate reset body");
    assert_eq!(
        submitted.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
    assert_eq!(
        submitted
            .into_endpoint_request_body()
            .expect("validate immediate reset submitted body")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_full_authentication_submitted_bodies() {
    let headers = json_headers();
    let method_payload = BASE64URL_NOPAD.encode(b"email-address-or-method-start-payload");
    let preflight_payload = BASE64URL_NOPAD.encode(b"preflight-response");
    let start_body = format!(
        r#"{{
            "method_payload_base64url": "{method_payload}",
            "preflight_gate_kind": "proof_of_work",
            "preflight_gate_method_label": "hashcash",
            "preflight_gate_payload_base64url": "{preflight_payload}"
        }}"#
    )
    .into_bytes();
    let start = full_authentication_submitted_body_from_collected_http_request(
        MountedFullAuthenticationEndpoint::StartOutOfBandChallenge,
        &headers,
        start_body,
    )
    .expect("parse full-authentication out-of-band start body");
    match start {
        MountedFullAuthenticationSubmittedRouteBody::StartOutOfBandChallenge {
            method_payload,
            preflight_gate_kind,
            preflight_gate_method_label,
            preflight_gate_payload,
        } => {
            assert_eq!(method_payload, b"email-address-or-method-start-payload");
            assert_eq!(preflight_gate_kind, WeakProofGateKind::ProofOfWork);
            assert_eq!(preflight_gate_method_label, "hashcash");
            assert_eq!(preflight_gate_payload, b"preflight-response");
        }
        body => panic!("expected start body, got {body:?}"),
    }

    let secret_response = BASE64URL_NOPAD.encode(b"123456");
    let weak_gate_payload = BASE64URL_NOPAD.encode(b"weak-gate-response");
    let proof_body = format!(
        r#"{{
            "secret_response_base64url": "{secret_response}",
            "weak_proof_gate": {{
                "kind": "human_challenge",
                "method_label": "turnstile",
                "payload_base64url": "{weak_gate_payload}"
            }}
        }}"#
    )
    .into_bytes();
    let proof = full_authentication_submitted_body_from_collected_http_request(
        MountedFullAuthenticationEndpoint::SubmitOutOfBandProof,
        &headers,
        proof_body,
    )
    .expect("parse full-authentication out-of-band proof body");
    match proof {
        MountedFullAuthenticationSubmittedRouteBody::SubmitOutOfBandProof {
            secret_response,
            weak_proof_gate_response,
        } => {
            assert_eq!(secret_response, b"123456");
            let weak_gate = weak_proof_gate_response
                .expect("weak gate present")
                .into_response()
                .expect("weak gate response");
            assert_eq!(
                weak_gate.summary().kind(),
                WeakProofGateKind::HumanChallenge
            );
            assert_eq!(weak_gate.summary().method_label(), "turnstile");
            assert_eq!(weak_gate.payload(), b"weak-gate-response");
        }
        body => panic!("expected proof body, got {body:?}"),
    }

    let complete_body = br#"{
        "trust_device": true,
        "trusted_device_display_label": "Work browser"
    }"#
    .to_vec();
    let complete = full_authentication_submitted_body_from_collected_http_request(
        MountedFullAuthenticationEndpoint::CompleteFullAuthentication,
        &headers,
        complete_body,
    )
    .expect("parse full-authentication completion body");
    match complete {
        MountedFullAuthenticationSubmittedRouteBody::CompleteFullAuthentication {
            trust_device,
            trusted_device_display_label,
        } => {
            assert!(trust_device);
            assert_eq!(
                trusted_device_display_label.as_deref(),
                Some("Work browser")
            );
        }
        body => panic!("expected completion body, got {body:?}"),
    }
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_full_authentication_inputs() {
    let missing_content_type = full_authentication_submitted_body_from_collected_http_request(
        MountedFullAuthenticationEndpoint::StartOutOfBandChallenge,
        &HeaderMap::new(),
        b"{}".to_vec(),
    )
    .expect_err("full-authentication JSON routes must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let unknown_gate_kind = full_authentication_submitted_body_from_collected_http_request(
        MountedFullAuthenticationEndpoint::StartOutOfBandChallenge,
        &json_headers(),
        br#"{
            "method_payload_base64url": "bWV0aG9k",
            "preflight_gate_kind": "mystery_gate",
            "preflight_gate_method_label": "hashcash",
            "preflight_gate_payload_base64url": "cGF5bG9hZA"
        }"#
        .to_vec(),
    )
    .expect_err("unknown full-authentication weak-proof gate kind must reject");
    assert!(matches!(
        unknown_gate_kind,
        MountedAuthHttpBodyError::UnknownWeakProofGateKind { .. }
    ));

    let disabled_trusted_device_label =
        full_authentication_submitted_body_from_collected_http_request(
            MountedFullAuthenticationEndpoint::CompleteFullAuthentication,
            &json_headers(),
            br#"{
                "trust_device": false,
                "trusted_device_display_label": "not allowed"
            }"#
            .to_vec(),
        )
        .expect_err("display label must reject when trust_device is false");
    assert!(matches!(
        disabled_trusted_device_label,
        MountedAuthHttpBodyError::UnexpectedFieldForDisabledOption {
            field_name: "trusted_device_display_label",
            option_name: "trust_device",
        }
    ));

    let oversized_label = "x".repeat(TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES + 1);
    let oversized_body = format!(
        r#"{{
            "trust_device": true,
            "trusted_device_display_label": "{oversized_label}"
        }}"#
    )
    .into_bytes();
    let oversized_error = full_authentication_submitted_body_from_collected_http_request(
        MountedFullAuthenticationEndpoint::CompleteFullAuthentication,
        &json_headers(),
        oversized_body,
    )
    .expect_err("oversized trusted-device display label must reject");
    assert!(matches!(
        oversized_error,
        MountedAuthHttpBodyError::EncodedFieldTooLong {
            field_name: "trusted_device_display_label",
            ..
        }
    ));
}

#[test]
fn mounted_full_authentication_endpoint_selection_and_limits_are_explicit() {
    for endpoint in MountedFullAuthenticationEndpoint::all() {
        assert_eq!(
            MountedFullAuthenticationEndpoint::from_method_and_path(
                &endpoint.method(),
                endpoint.path()
            ),
            Some(endpoint)
        );
        assert!(
            endpoint.max_collected_http_body_bytes() <= MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES
        );
    }
    assert_eq!(
        MountedFullAuthenticationEndpoint::from_method_and_path(
            &http::Method::GET,
            MOUNTED_FULL_AUTHENTICATION_COMPLETE_ROUTE_PATH,
        ),
        None
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_credential_addition_submitted_body() {
    let payload = BASE64URL_NOPAD.encode(b"credential-creation-payload");
    let body = format!(r#"{{"method_payload_base64url":"{payload}"}}"#).into_bytes();
    let submitted =
        credential_addition_submitted_body_from_collected_http_request(&json_headers(), body)
            .expect("parse credential addition body");

    let request_body = submitted
        .into_endpoint_request_body()
        .expect("validate credential addition body");
    let runtime_input = request_body.into_route_request(at(123));
    assert_eq!(runtime_input.now, at(123));
    assert_eq!(
        runtime_input.method_payload.as_bytes(),
        b"credential-creation-payload"
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_authenticated_credential_reset_submitted_bodies() {
    let credential_handle = b"mounted-reset-target";
    let credential_handle_base64url = BASE64URL_NOPAD.encode(credential_handle);
    let plan_body = format!(
        r#"{{
            "credential_handle_base64url": "{}"
        }}"#,
        credential_handle_base64url
    )
    .into_bytes();
    let plan = authenticated_credential_reset_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialResetEndpoint::PlanReset,
        &json_headers(),
        plan_body,
    )
    .expect("parse credential reset plan body");
    assert_eq!(
        plan.endpoint(),
        MountedAuthenticatedCredentialResetEndpoint::PlanReset
    );
    assert_eq!(
        plan.into_route_request(at(123))
            .expect("build reset plan route request"),
        MountedAuthenticatedCredentialResetRouteRequest::PlanReset(
            PlanMountedAuthenticatedCredentialResetInput {
                now: at(123),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-reset-target"
                )),
            }
        )
    );

    let method_payload = b"mounted-reset-payload";
    let method_payload_base64url = BASE64URL_NOPAD.encode(method_payload);
    let execute_body = format!(
        r#"{{
            "credential_handle_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        credential_handle_base64url, method_payload_base64url
    )
    .into_bytes();
    let execute = authenticated_credential_reset_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset,
        &json_headers(),
        execute_body,
    )
    .expect("parse credential reset execution body");
    assert_eq!(
        execute.endpoint(),
        MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset
    );
    assert_eq!(
        execute
            .into_route_request(at(124))
            .expect("build reset execution route request"),
        MountedAuthenticatedCredentialResetRouteRequest::ExecuteImmediateReset(
            ExecuteMountedAuthenticatedCredentialResetInput {
                now: at(124),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-reset-target"
                )),
                method_payload: CredentialResetMethodPayload::try_from_bytes(
                    method_payload.as_slice()
                )
                .expect("reset payload"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_authenticated_credential_replacement_submitted_bodies() {
    let credential_handle = b"mounted-replace-target";
    let credential_handle_base64url = BASE64URL_NOPAD.encode(credential_handle);
    let plan_body = format!(
        r#"{{
            "credential_handle_base64url": "{}"
        }}"#,
        credential_handle_base64url
    )
    .into_bytes();
    let plan = authenticated_credential_replacement_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement,
        &json_headers(),
        plan_body,
    )
    .expect("parse credential replacement plan body");
    assert_eq!(
        plan.endpoint(),
        MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement
    );
    assert_eq!(
        plan.into_route_request(at(123))
            .expect("build replacement plan route request"),
        MountedAuthenticatedCredentialReplacementRouteRequest::PlanReplacement(
            PlanMountedAuthenticatedCredentialReplacementInput {
                now: at(123),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-replace-target"
                )),
            }
        )
    );

    let method_payload = b"mounted-replacement-payload";
    let method_payload_base64url = BASE64URL_NOPAD.encode(method_payload);
    let execute_body = format!(
        r#"{{
            "credential_handle_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        credential_handle_base64url, method_payload_base64url
    )
    .into_bytes();
    let execute = authenticated_credential_replacement_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement,
        &json_headers(),
        execute_body,
    )
    .expect("parse credential replacement execution body");
    assert_eq!(
        execute.endpoint(),
        MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement
    );
    assert_eq!(
        execute
            .into_route_request(at(124))
            .expect("build replacement execution route request"),
        MountedAuthenticatedCredentialReplacementRouteRequest::ExecuteImmediateReplacement(
            ExecuteMountedAuthenticatedCredentialReplacementInput {
                now: at(124),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-replace-target"
                )),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    method_payload.as_slice()
                )
                .expect("replacement payload"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_authenticated_credential_removal_submitted_bodies() {
    let credential_handle = b"mounted-remove-target";
    let credential_handle_base64url = BASE64URL_NOPAD.encode(credential_handle);
    let plan_body = format!(
        r#"{{
            "credential_handle_base64url": "{}"
        }}"#,
        credential_handle_base64url
    )
    .into_bytes();
    let plan = authenticated_credential_removal_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval,
        &json_headers(),
        plan_body,
    )
    .expect("parse credential removal plan body");
    assert_eq!(
        plan.endpoint(),
        MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval
    );
    assert_eq!(
        plan.into_route_request(at(123))
            .expect("build removal plan route request"),
        MountedAuthenticatedCredentialRemovalRouteRequest::PlanRemoval(
            PlanMountedAuthenticatedCredentialRemovalInput {
                now: at(123),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-remove-target"
                )),
            }
        )
    );

    let execute_body = format!(
        r#"{{
            "credential_handle_base64url": "{}"
        }}"#,
        credential_handle_base64url
    )
    .into_bytes();
    let execute = authenticated_credential_removal_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval,
        &json_headers(),
        execute_body,
    )
    .expect("parse credential removal execution body");
    assert_eq!(
        execute.endpoint(),
        MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval
    );
    assert_eq!(
        execute
            .into_route_request(at(124))
            .expect("build removal execution route request"),
        MountedAuthenticatedCredentialRemovalRouteRequest::ExecuteImmediateRemoval(
            ExecuteMountedAuthenticatedCredentialRemovalInput {
                now: at(124),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-remove-target"
                )),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_authenticated_credential_regeneration_submitted_bodies() {
    let credential_handle = b"mounted-regenerate-target";
    let credential_handle_base64url = BASE64URL_NOPAD.encode(credential_handle);
    let plan_body = format!(
        r#"{{
            "credential_handle_base64url": "{}"
        }}"#,
        credential_handle_base64url
    )
    .into_bytes();
    let plan = authenticated_credential_regeneration_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration,
        &json_headers(),
        plan_body,
    )
    .expect("parse credential regeneration plan body");
    assert_eq!(
        plan.endpoint(),
        MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration
    );
    assert_eq!(
        plan.into_route_request(at(123))
            .expect("build regeneration plan route request"),
        MountedAuthenticatedCredentialRegenerationRouteRequest::PlanRegeneration(
            PlanMountedAuthenticatedCredentialRegenerationInput {
                now: at(123),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-regenerate-target"
                )),
            }
        )
    );

    let method_payload = b"mounted-regeneration-payload";
    let method_payload_base64url = BASE64URL_NOPAD.encode(method_payload);
    let execute_body = format!(
        r#"{{
            "credential_handle_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        credential_handle_base64url, method_payload_base64url
    )
    .into_bytes();
    let execute = authenticated_credential_regeneration_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration,
        &json_headers(),
        execute_body,
    )
    .expect("parse credential regeneration execution body");
    assert_eq!(
        execute.endpoint(),
        MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration
    );
    assert_eq!(
        execute
            .into_route_request(at(124))
            .expect("build regeneration execution route request"),
        MountedAuthenticatedCredentialRegenerationRouteRequest::ExecuteImmediateRegeneration(
            ExecuteMountedAuthenticatedCredentialRegenerationInput {
                now: at(124),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-regenerate-target"
                )),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    method_payload.as_slice()
                )
                .expect("regeneration payload"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_authenticated_credential_rotation_submitted_body() {
    let credential_handle = b"mounted-rotate-target";
    let credential_handle_base64url = BASE64URL_NOPAD.encode(credential_handle);
    let method_payload = b"mounted-rotation-payload";
    let method_payload_base64url = BASE64URL_NOPAD.encode(method_payload);
    let body = format!(
        r#"{{
            "credential_handle_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        credential_handle_base64url, method_payload_base64url
    )
    .into_bytes();
    let submitted = authenticated_credential_rotation_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation,
        &json_headers(),
        body,
    )
    .expect("parse credential rotation execution body");
    assert_eq!(
        submitted.endpoint(),
        MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation
    );
    assert_eq!(
        submitted
            .into_route_request(at(124))
            .expect("build rotation execution route request"),
        MountedAuthenticatedCredentialRotationRouteRequest::ExecuteImmediateRotation(
            ExecuteMountedAuthenticatedCredentialRotationInput {
                now: at(124),
                credential_handle: MountedCredentialHandle::from_credential_instance_id(id(
                    "mounted-rotate-target"
                )),
                method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                    method_payload.as_slice()
                )
                .expect("rotation payload"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_delayed_credential_lifecycle_submitted_bodies() {
    let pending_action_id = b"mounted-delayed-credential-action";
    let pending_action_id_base64url = BASE64URL_NOPAD.encode(pending_action_id);
    let method_payload = b"mounted-delayed-method-payload";
    let method_payload_base64url = BASE64URL_NOPAD.encode(method_payload);
    let reset_body = format!(
        r#"{{
            "pending_action_id_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        pending_action_id_base64url, method_payload_base64url
    )
    .into_bytes();
    let reset = delayed_credential_lifecycle_submitted_body_from_collected_http_request(
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReset,
        &json_headers(),
        reset_body,
    )
    .expect("parse delayed credential reset execution body");
    assert_eq!(
        reset.endpoint(),
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReset
    );
    assert_eq!(
        reset
            .into_route_request(at(123))
            .expect("build delayed reset route request"),
        MountedDelayedCredentialLifecycleRouteRequest::Execute(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(123),
                pending_action_id: id("mounted-delayed-credential-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::Reset(
                    CredentialResetMethodPayload::try_from_bytes(method_payload.as_slice())
                        .expect("reset payload"),
                ),
            }
        )
    );

    let replace_or_regenerate_body = format!(
        r#"{{
            "pending_action_id_base64url": "{}",
            "method_payload_base64url": "{}"
        }}"#,
        pending_action_id_base64url, method_payload_base64url
    )
    .into_bytes();
    let replace_or_regenerate =
        delayed_credential_lifecycle_submitted_body_from_collected_http_request(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate,
            &json_headers(),
            replace_or_regenerate_body,
        )
        .expect("parse delayed credential replacement/regeneration execution body");
    assert_eq!(
        replace_or_regenerate.endpoint(),
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate
    );
    assert_eq!(
        replace_or_regenerate
            .into_route_request(at(124))
            .expect("build delayed replace/regenerate route request"),
        MountedDelayedCredentialLifecycleRouteRequest::Execute(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(124),
                pending_action_id: id("mounted-delayed-credential-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(
                    CredentialLifecycleMethodPayload::try_from_bytes(method_payload.as_slice())
                        .expect("replace/regenerate payload"),
                ),
            }
        )
    );

    let removal_body = format!(
        r#"{{
            "pending_action_id_base64url": "{}"
        }}"#,
        pending_action_id_base64url
    )
    .into_bytes();
    let removal = delayed_credential_lifecycle_submitted_body_from_collected_http_request(
        MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval,
        &json_headers(),
        removal_body,
    )
    .expect("parse delayed credential removal execution body");
    assert_eq!(
        removal.endpoint(),
        MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval
    );
    assert_eq!(
        removal
            .into_route_request(at(125))
            .expect("build delayed removal route request"),
        MountedDelayedCredentialLifecycleRouteRequest::Execute(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(125),
                pending_action_id: id("mounted-delayed-credential-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_authenticated_out_of_band_identifier_change_submitted_bodies()
 {
    let current_identifier_source_id = b"mounted-identifier-change-current";
    let candidate_identifier_source_id = b"mounted-identifier-change-candidate";
    let current_identifier_source_id_base64url =
        BASE64URL_NOPAD.encode(current_identifier_source_id);
    let candidate_identifier_source_id_base64url =
        BASE64URL_NOPAD.encode(candidate_identifier_source_id);
    let plan_body = format!(
        r#"{{
            "current_identifier_source_id_base64url": "{}",
            "candidate_identifier_source_id_base64url": "{}"
        }}"#,
        current_identifier_source_id_base64url, candidate_identifier_source_id_base64url
    )
    .into_bytes();
    let plan =
        authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange,
            &json_headers(),
            plan_body,
        )
        .expect("parse out-of-band identifier change plan body");
    assert_eq!(
        plan.endpoint(),
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
    );
    assert_eq!(
        plan.into_route_request(at(123))
            .expect("build identifier change plan route request"),
        MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest::PlanChange(
            PlanMountedAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(123),
                current_identifier_source_id: id("mounted-identifier-change-current"),
                candidate_identifier_source_id: id("mounted-identifier-change-candidate"),
            }
        )
    );

    let execute_body = format!(
        r#"{{
            "current_identifier_source_id_base64url": "{}",
            "candidate_identifier_source_id_base64url": "{}"
        }}"#,
        current_identifier_source_id_base64url, candidate_identifier_source_id_base64url
    )
    .into_bytes();
    let execute =
        authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange,
            &json_headers(),
            execute_body,
        )
        .expect("parse out-of-band identifier change execution body");
    assert_eq!(
        execute.endpoint(),
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange
    );
    assert_eq!(
        execute
            .into_route_request(at(124))
            .expect("build identifier change execution route request"),
        MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest::ExecuteImmediateChange(
            ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput {
                now: at(124),
                current_identifier_source_id: id("mounted-identifier-change-current"),
                candidate_identifier_source_id: id("mounted-identifier-change-candidate"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_delayed_out_of_band_identifier_change_submitted_bodies() {
    let pending_action_id = b"mounted-delayed-identifier-change-action";
    let pending_action_id_base64url = BASE64URL_NOPAD.encode(pending_action_id);
    let execute_body =
        format!(r#"{{"pending_action_id_base64url":"{pending_action_id_base64url}"}}"#)
            .into_bytes();
    let execute = delayed_out_of_band_identifier_change_submitted_body_from_collected_http_request(
        MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange,
        &json_headers(),
        execute_body,
    )
    .expect("parse delayed identifier-change execution body");
    assert_eq!(
        execute.endpoint(),
        MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange
    );
    assert_eq!(
        execute
            .into_route_request(at(123))
            .expect("build delayed identifier-change execution request"),
        MountedDelayedOutOfBandIdentifierChangeRouteRequest::ExecuteChange(
            ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
                now: at(123),
                pending_action_id: id("mounted-delayed-identifier-change-action"),
            }
        )
    );

    let cancel_body =
        format!(r#"{{"pending_action_id_base64url":"{pending_action_id_base64url}"}}"#)
            .into_bytes();
    let cancel = delayed_out_of_band_identifier_change_submitted_body_from_collected_http_request(
        MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange,
        &json_headers(),
        cancel_body,
    )
    .expect("parse delayed identifier-change cancellation body");
    assert_eq!(
        cancel.endpoint(),
        MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange
    );
    assert_eq!(
        cancel
            .into_route_request(at(124))
            .expect("build delayed identifier-change cancellation request"),
        MountedDelayedOutOfBandIdentifierChangeRouteRequest::CancelChange(
            CancelMountedDelayedOutOfBandIdentifierChangeInput {
                now: at(124),
                pending_action_id: id("mounted-delayed-identifier-change-action"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_subject_auth_state_deletion_submitted_bodies() {
    let pending_action_id = b"mounted-subject-deletion-action";
    let pending_action_id_base64url = BASE64URL_NOPAD.encode(pending_action_id);
    let schedule = subject_auth_state_deletion_submitted_body_from_collected_http_request(
        MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion,
        &HeaderMap::new(),
        Vec::new(),
    )
    .expect("parse empty subject auth-state deletion scheduling body");
    assert_eq!(
        schedule.endpoint(),
        MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion
    );
    assert_eq!(
        schedule
            .into_route_request(at(122))
            .expect("build subject auth-state deletion scheduling request"),
        MountedDelayedSubjectAuthStateDeletionRouteRequest::ScheduleDeletion(
            ScheduleMountedSubjectAuthStateDeletionInput { now: at(122) }
        )
    );

    let execute_body = format!(
        r#"{{
            "pending_action_id_base64url": "{}",
            "application_subject_data_lifecycle_action": "delete_subject_data"
        }}"#,
        pending_action_id_base64url
    )
    .into_bytes();
    let execute = subject_auth_state_deletion_submitted_body_from_collected_http_request(
        MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion,
        &json_headers(),
        execute_body,
    )
    .expect("parse subject auth-state deletion execution body");
    assert_eq!(
        execute.endpoint(),
        MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion
    );
    assert_eq!(
        execute
            .into_route_request(at(123))
            .expect("build subject auth-state deletion execution request"),
        MountedDelayedSubjectAuthStateDeletionRouteRequest::ExecuteDeletion(
            ExecuteMountedDelayedSubjectAuthStateDeletionInput {
                now: at(123),
                pending_action_id: id("mounted-subject-deletion-action"),
                application_subject_data_lifecycle_action:
                    ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
            }
        )
    );

    let cancel_body = format!(
        r#"{{
            "pending_action_id_base64url": "{}"
        }}"#,
        pending_action_id_base64url
    )
    .into_bytes();
    let cancel = subject_auth_state_deletion_submitted_body_from_collected_http_request(
        MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion,
        &json_headers(),
        cancel_body,
    )
    .expect("parse subject auth-state deletion cancellation body");
    assert_eq!(
        cancel.endpoint(),
        MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion
    );
    assert_eq!(
        cancel
            .into_route_request(at(124))
            .expect("build subject auth-state deletion cancellation request"),
        MountedDelayedSubjectAuthStateDeletionRouteRequest::CancelDeletion(
            CancelMountedDelayedSubjectAuthStateDeletionInput {
                now: at(124),
                pending_action_id: id("mounted-subject-deletion-action"),
            }
        )
    );
}

#[test]
fn mounted_auth_http_body_parser_builds_admin_support_submitted_bodies() {
    let subject_id = b"mounted-support-subject";
    let target_credential_instance_id = b"mounted-support-target";
    let subject_id_base64url = BASE64URL_NOPAD.encode(subject_id);
    let target_credential_instance_id_base64url =
        BASE64URL_NOPAD.encode(target_credential_instance_id);
    let request_body = format!(
        r#"{{
            "subject_id_base64url": "{}",
            "target_credential_instance_id_base64url": "{}",
            "credential_lifecycle_action": "reset"
        }}"#,
        subject_id_base64url, target_credential_instance_id_base64url
    )
    .into_bytes();
    let request = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::RequestIntervention,
        &json_headers(),
        request_body,
    )
    .expect("parse admin support request body");
    assert_eq!(
        request.endpoint(),
        MountedAdminSupportEndpoint::RequestIntervention
    );
    assert_eq!(
        request
            .into_route_request(at(123))
            .expect("build admin support request route request"),
        MountedAdminSupportRouteRequest::RequestIntervention(
            RequestAdminSupportInterventionInput {
                now: at(123),
                subject_id: id("mounted-support-subject"),
                target_credential_instance_id: id("mounted-support-target"),
                action: CredentialLifecycleAction::Reset,
            }
        )
    );

    let intervention_handle = b"mounted-support-intervention";
    let intervention_handle_base64url = BASE64URL_NOPAD.encode(intervention_handle);
    let handle_body = format!(
        r#"{{
            "intervention_handle_base64url": "{}"
        }}"#,
        intervention_handle_base64url
    )
    .into_bytes();
    let approve = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::ApproveIntervention,
        &json_headers(),
        handle_body.clone(),
    )
    .expect("parse admin support approval body");
    assert_eq!(
        approve.endpoint(),
        MountedAdminSupportEndpoint::ApproveIntervention
    );
    assert_eq!(
        approve
            .into_route_request(at(124))
            .expect("build admin support approval route request"),
        MountedAdminSupportRouteRequest::ApproveIntervention(
            ApproveAdminSupportInterventionInput {
                now: at(124),
                intervention_id: id("mounted-support-intervention"),
            }
        )
    );

    let deny = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::DenyIntervention,
        &json_headers(),
        handle_body.clone(),
    )
    .expect("parse admin support denial body");
    assert_eq!(
        deny.into_route_request(at(125))
            .expect("build admin support denial route request"),
        MountedAdminSupportRouteRequest::DenyIntervention(DenyAdminSupportInterventionInput {
            now: at(125),
            intervention_id: id("mounted-support-intervention"),
        })
    );

    let expire = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::ExpireIntervention,
        &json_headers(),
        handle_body,
    )
    .expect("parse admin support expiry body");
    assert_eq!(
        expire
            .into_route_request(at(126))
            .expect("build admin support expiry route request"),
        MountedAdminSupportRouteRequest::ExpireIntervention(ExpireAdminSupportInterventionInput {
            now: at(126),
            intervention_id: id("mounted-support-intervention"),
        })
    );
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_credential_addition_inputs() {
    let missing_content_type = credential_addition_submitted_body_from_collected_http_request(
        &HeaderMap::new(),
        b"{}".to_vec(),
    )
    .expect_err("credential addition JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_base64 = credential_addition_submitted_body_from_collected_http_request(
        &json_headers(),
        br#"{"method_payload_base64url":"not base64"}"#.to_vec(),
    )
    .expect_err("invalid base64url must reject");
    assert!(matches!(
        invalid_base64,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "method_payload_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_authenticated_credential_reset_inputs() {
    let missing_content_type =
        authenticated_credential_reset_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialResetEndpoint::PlanReset,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("credential reset JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_target = authenticated_credential_reset_submitted_body_from_collected_http_request(
        MountedAuthenticatedCredentialResetEndpoint::PlanReset,
        &json_headers(),
        br#"{"credential_handle_base64url":"not base64"}"#.to_vec(),
    )
    .expect_err("invalid credential handle base64url must reject");
    assert!(matches!(
        invalid_target,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "credential_handle_base64url",
            ..
        }
    ));

    let invalid_payload =
        authenticated_credential_reset_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset,
            &json_headers(),
            br#"{
            "credential_handle_base64url":"dGFyZ2V0",
            "method_payload_base64url":"not base64"
        }"#
            .to_vec(),
        )
        .expect_err("invalid reset payload base64url must reject");
    assert!(matches!(
        invalid_payload,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "method_payload_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_authenticated_credential_replacement_inputs() {
    let missing_content_type =
        authenticated_credential_replacement_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("credential replacement JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_target =
        authenticated_credential_replacement_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement,
            &json_headers(),
            br#"{"credential_handle_base64url":"not base64"}"#.to_vec(),
        )
        .expect_err("invalid credential handle base64url must reject");
    assert!(matches!(
        invalid_target,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "credential_handle_base64url",
            ..
        }
    ));

    let invalid_payload =
        authenticated_credential_replacement_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement,
            &json_headers(),
            br#"{
            "credential_handle_base64url":"dGFyZ2V0",
            "method_payload_base64url":"not base64"
        }"#
            .to_vec(),
        )
        .expect_err("invalid replacement payload base64url must reject");
    assert!(matches!(
        invalid_payload,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "method_payload_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_authenticated_credential_removal_inputs() {
    let missing_content_type =
        authenticated_credential_removal_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("credential removal JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_target =
        authenticated_credential_removal_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval,
            &json_headers(),
            br#"{"credential_handle_base64url":"not base64"}"#.to_vec(),
        )
        .expect_err("invalid credential handle base64url must reject");
    assert!(matches!(
        invalid_target,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "credential_handle_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_authenticated_credential_regeneration_inputs() {
    let missing_content_type =
        authenticated_credential_regeneration_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("credential regeneration JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_target =
        authenticated_credential_regeneration_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration,
            &json_headers(),
            br#"{"credential_handle_base64url":"not base64"}"#.to_vec(),
        )
        .expect_err("invalid regeneration credential handle base64url must reject");
    assert!(matches!(
        invalid_target,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "credential_handle_base64url",
            ..
        }
    ));

    let invalid_payload =
        authenticated_credential_regeneration_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration,
            &json_headers(),
            br#"{
            "credential_handle_base64url":"dGFyZ2V0",
            "method_payload_base64url":"not base64"
        }"#
            .to_vec(),
        )
        .expect_err("invalid regeneration payload base64url must reject");
    assert!(matches!(
        invalid_payload,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "method_payload_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_authenticated_credential_rotation_inputs() {
    let missing_content_type =
        authenticated_credential_rotation_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("credential rotation JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_target =
        authenticated_credential_rotation_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation,
            &json_headers(),
            br#"{
            "credential_handle_base64url":"not base64",
            "method_payload_base64url":"cGF5bG9hZA"
        }"#
            .to_vec(),
        )
        .expect_err("invalid rotation credential handle base64url must reject");
    assert!(matches!(
        invalid_target,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "credential_handle_base64url",
            ..
        }
    ));

    let invalid_payload =
        authenticated_credential_rotation_submitted_body_from_collected_http_request(
            MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation,
            &json_headers(),
            br#"{
            "credential_handle_base64url":"dGFyZ2V0",
            "method_payload_base64url":"not base64"
        }"#
            .to_vec(),
        )
        .expect_err("invalid rotation payload base64url must reject");
    assert!(matches!(
        invalid_payload,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "method_payload_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_delayed_credential_lifecycle_inputs() {
    let missing_content_type =
        delayed_credential_lifecycle_submitted_body_from_collected_http_request(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteReset,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("delayed credential lifecycle JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_pending_action_id =
        delayed_credential_lifecycle_submitted_body_from_collected_http_request(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteReset,
            &json_headers(),
            br#"{
            "pending_action_id_base64url": "not base64",
            "method_payload_base64url": "cGF5bG9hZA"
        }"#
            .to_vec(),
        )
        .expect_err("invalid delayed lifecycle pending action id base64url must reject");
    assert!(matches!(
        invalid_pending_action_id,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "pending_action_id_base64url",
            ..
        }
    ));

    let invalid_method_payload =
        delayed_credential_lifecycle_submitted_body_from_collected_http_request(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate,
            &json_headers(),
            br#"{
            "pending_action_id_base64url": "cGVuZGluZw",
            "method_payload_base64url": "not base64"
        }"#
            .to_vec(),
        )
        .expect_err("invalid delayed lifecycle method payload base64url must reject");
    assert!(matches!(
        invalid_method_payload,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "method_payload_base64url",
            ..
        }
    ));

    let unexpected_method_payload_on_removal =
        delayed_credential_lifecycle_submitted_body_from_collected_http_request(
            MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval,
            &json_headers(),
            br#"{
            "pending_action_id_base64url": "cGVuZGluZw",
            "method_payload_base64url": "cGF5bG9hZA"
        }"#
            .to_vec(),
        )
        .expect_err("delayed lifecycle removal must reject method payload fields");
    assert!(matches!(
        unexpected_method_payload_on_removal,
        MountedAuthHttpBodyError::InvalidJson { .. }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_authenticated_out_of_band_identifier_change_inputs()
 {
    let missing_content_type =
        authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("identifier change JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_current_source =
        authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange,
            &json_headers(),
            br#"{
                "current_identifier_source_id_base64url": "not base64",
                "candidate_identifier_source_id_base64url": "Y2FuZGlkYXRl"
            }"#
            .to_vec(),
        )
        .expect_err("invalid current source base64url must reject");
    assert!(matches!(
        invalid_current_source,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "current_identifier_source_id_base64url",
            ..
        }
    ));

    let invalid_candidate_source =
        authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange,
            &json_headers(),
            br#"{
                "current_identifier_source_id_base64url": "Y3VycmVudA",
                "candidate_identifier_source_id_base64url": "not base64"
            }"#
            .to_vec(),
        )
        .expect_err("invalid candidate source base64url must reject");
    assert!(matches!(
        invalid_candidate_source,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "candidate_identifier_source_id_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_delayed_out_of_band_identifier_change_inputs() {
    let missing_content_type =
        delayed_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("delayed identifier change JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_pending_action_id =
        delayed_out_of_band_identifier_change_submitted_body_from_collected_http_request(
            MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange,
            &json_headers(),
            br#"{"pending_action_id_base64url":"not base64"}"#.to_vec(),
        )
        .expect_err("invalid pending action id base64url must reject");
    assert!(matches!(
        invalid_pending_action_id,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "pending_action_id_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_subject_auth_state_deletion_inputs() {
    let missing_content_type =
        subject_auth_state_deletion_submitted_body_from_collected_http_request(
            MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect_err("subject auth-state deletion JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_pending_action_id =
        subject_auth_state_deletion_submitted_body_from_collected_http_request(
            MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion,
            &json_headers(),
            br#"{"pending_action_id_base64url":"not base64"}"#.to_vec(),
        )
        .expect_err("invalid pending action id base64url must reject");
    assert!(matches!(
        invalid_pending_action_id,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "pending_action_id_base64url",
            ..
        }
    ));

    let non_empty_schedule =
        subject_auth_state_deletion_submitted_body_from_collected_http_request(
            MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion,
            &HeaderMap::new(),
            b"{}".to_vec(),
        )
        .expect("non-empty schedule body should parse as submitted material")
        .into_route_request(at(100))
        .expect_err("non-empty schedule body must reject before runtime");
    assert_eq!(
        non_empty_schedule,
        Error::NonEmptyMountedSubjectAuthStateDeletionScheduleRouteBody
    );

    let unknown_action = subject_auth_state_deletion_submitted_body_from_collected_http_request(
        MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion,
        &json_headers(),
        br#"{
            "pending_action_id_base64url": "YWN0aW9u",
            "application_subject_data_lifecycle_action": "destroy_everything"
        }"#
        .to_vec(),
    )
    .expect_err("unknown app subject data lifecycle action must reject");
    assert!(matches!(
        unknown_action,
        MountedAuthHttpBodyError::UnknownApplicationSubjectDataLifecycleAction { .. }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_admin_support_inputs() {
    let missing_content_type = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::RequestIntervention,
        &HeaderMap::new(),
        b"{}".to_vec(),
    )
    .expect_err("admin support JSON must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let invalid_subject = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::RequestIntervention,
        &json_headers(),
        br#"{
            "subject_id_base64url": "not base64",
            "target_credential_instance_id_base64url": "dGFyZ2V0",
            "credential_lifecycle_action": "reset"
        }"#
        .to_vec(),
    )
    .expect_err("invalid subject id base64url must reject");
    assert!(matches!(
        invalid_subject,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "subject_id_base64url",
            ..
        }
    ));

    let unknown_action = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::RequestIntervention,
        &json_headers(),
        br#"{
            "subject_id_base64url": "c3ViamVjdA",
            "target_credential_instance_id_base64url": "dGFyZ2V0",
            "credential_lifecycle_action": "invent"
        }"#
        .to_vec(),
    )
    .expect_err("unknown admin support lifecycle action must reject");
    assert!(matches!(
        unknown_action,
        MountedAuthHttpBodyError::UnknownCredentialLifecycleAction { .. }
    ));

    let invalid_handle = admin_support_submitted_body_from_collected_http_request(
        MountedAdminSupportEndpoint::ApproveIntervention,
        &json_headers(),
        br#"{"intervention_handle_base64url":"not base64"}"#.to_vec(),
    )
    .expect_err("invalid support intervention handle base64url must reject");
    assert!(matches!(
        invalid_handle,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "intervention_handle_base64url",
            ..
        }
    ));
}

#[test]
fn mounted_auth_http_body_parser_rejects_invalid_no_session_recovery_inputs() {
    let missing_content_type = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt,
        &HeaderMap::new(),
        b"{}".to_vec(),
    )
    .expect_err("JSON routes must require content-type");
    assert!(matches!(
        missing_content_type,
        MountedAuthHttpBodyError::UnsupportedContentType { actual: None, .. }
    ));

    let unknown_gate_kind = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt,
        &json_headers(),
        br#"{
            "preflight_gate_kind": "mystery_gate",
            "preflight_gate_method_label": "hashcash",
            "preflight_gate_payload_base64url": "cGF5bG9hZA"
        }"#
        .to_vec(),
    )
    .expect_err("unknown weak-proof gate kind must reject");
    assert!(matches!(
        unknown_gate_kind,
        MountedAuthHttpBodyError::UnknownWeakProofGateKind { .. }
    ));

    let invalid_base64 = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof,
        &json_headers(),
        br#"{"secret_response_base64url":"not base64"}"#.to_vec(),
    )
    .expect_err("invalid base64url must reject");
    assert!(matches!(
        invalid_base64,
        MountedAuthHttpBodyError::InvalidBase64Url {
            field_name: "secret_response_base64url",
            ..
        }
    ));

    let oversized_body = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof,
        &json_headers(),
        vec![b' '; MOUNTED_AUTH_HTTP_JSON_BODY_MAX_BYTES + 1],
    )
    .expect_err("oversized collected body must reject");
    assert!(matches!(
        oversized_body,
        MountedAuthHttpBodyError::BodyTooLong {
            input_name: "no-session recovery proof body",
            ..
        }
    ));

    let non_empty_schedule = no_session_recovery_submitted_body_from_collected_http_request(
        MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset,
        &HeaderMap::new(),
        b"{}".to_vec(),
    )
    .expect_err("non-empty schedule body must reject at collected HTTP body boundary");
    assert!(matches!(
        non_empty_schedule,
        MountedAuthHttpBodyError::UnexpectedBody {
            input_name: "no-session recovery delayed-reset body",
            actual_bytes: 2,
        }
    ));
}

#[derive(Clone, Copy)]
struct MountedRuntimeRouteRequirementEchoService;

impl Service<Request<()>> for MountedRuntimeRouteRequirementEchoService {
    type Response = http::Response<&'static str>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<()>) -> Self::Future {
        Box::pin(async { Ok(http::Response::new("passed")) })
    }
}

fn mounted_route_requirement_request_with_state(outcome: Outcome) -> Request<()> {
    let mut request = Request::new(());
    request.extensions_mut().insert(
        MountedAuthRequestState::from_request_resolution_outcome(outcome)
            .expect("mounted request state"),
    );
    request
}

fn authenticated_route_requirement_outcome(step_up_is_fresh: bool) -> Outcome {
    Outcome::Authenticated(Authenticated {
        subject_id: id("mounted-route-requirement-subject"),
        session_id: id("mounted-route-requirement-session"),
        source: AuthenticationSource::AuthoritativeSession,
        step_up_is_fresh,
    })
}

#[test]
fn mounted_auth_protected_route_policy_constructors_preserve_request_kind_and_requirement() {
    let safe_read = MountedAuthProtectedRoutePolicy::authenticated_subject_for_safe_read();
    assert_eq!(safe_read.request_kind(), RequestKind::SafeRead);
    assert_eq!(
        safe_read.requirement(),
        MountedAuthRouteRequirement::AuthenticatedSubject
    );

    let state_changing =
        MountedAuthProtectedRoutePolicy::authenticated_subject_for_state_changing_request();
    assert_eq!(state_changing.request_kind(), RequestKind::StateChanging);
    assert_eq!(
        state_changing.requirement(),
        MountedAuthRouteRequirement::AuthenticatedSubject
    );

    let sensitive = MountedAuthProtectedRoutePolicy::fresh_step_up_for_sensitive_request();
    assert_eq!(sensitive.request_kind(), RequestKind::Sensitive);
    assert_eq!(
        sensitive.requirement(),
        MountedAuthRouteRequirement::FreshStepUp
    );
}

#[tokio::test]
async fn mounted_auth_route_requirement_layer_rejects_missing_request_state() {
    let mut service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::AuthenticatedSubject)
            .layer(MountedRuntimeRouteRequirementEchoService);

    let error = service
        .call(Request::new(()))
        .await
        .expect_err("missing mounted request state must reject");

    assert!(matches!(
        error,
        MountedAuthRouteRequirementServiceError::Requirement(
            MountedAuthRouteRequirementError::MissingRequestState
        )
    ));
}

#[tokio::test]
async fn mounted_auth_route_requirement_layer_allows_authenticated_subject_without_step_up() {
    let mut service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::AuthenticatedSubject)
            .layer(MountedRuntimeRouteRequirementEchoService);

    let response = service
        .call(mounted_route_requirement_request_with_state(
            authenticated_route_requirement_outcome(false),
        ))
        .await
        .expect("authenticated subject requirement should pass");

    assert_eq!(response.body(), &"passed");
}

#[tokio::test]
async fn mounted_auth_route_requirement_layer_rejects_unauthenticated_states() {
    let subject_id: SubjectId = id("mounted-route-requirement-needed-subject");
    let session_id: SessionId = id("mounted-route-requirement-needed-session");
    let device_credential_id: TrustedDeviceCredentialId =
        id("mounted-route-requirement-needed-device");

    let mut needs_full_auth_service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::AuthenticatedSubject)
            .layer(MountedRuntimeRouteRequirementEchoService);
    let needs_full_auth_error = needs_full_auth_service
        .call(mounted_route_requirement_request_with_state(
            Outcome::NeedsFullAuthentication,
        ))
        .await
        .expect_err("full authentication requirement must reject unauthenticated state");
    assert!(matches!(
        needs_full_auth_error,
        MountedAuthRouteRequirementServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsFullAuthentication
        )
    ));

    let mut needs_step_up_service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::AuthenticatedSubject)
            .layer(MountedRuntimeRouteRequirementEchoService);
    let needs_step_up_error = needs_step_up_service
        .call(mounted_route_requirement_request_with_state(
            Outcome::NeedsStepUp {
                subject_id: subject_id.clone(),
                session_id: session_id.clone(),
            },
        ))
        .await
        .expect_err("authenticated subject requirement must reject stale sessions");
    assert!(matches!(
        needs_step_up_error,
        MountedAuthRouteRequirementServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsStepUp {
                subject_id: actual_subject_id,
                session_id: actual_session_id,
            }
        ) if actual_subject_id == subject_id && actual_session_id == session_id
    ));

    let mut needs_active_device_proof_service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::AuthenticatedSubject)
            .layer(MountedRuntimeRouteRequirementEchoService);
    let needs_active_device_proof_error = needs_active_device_proof_service
        .call(mounted_route_requirement_request_with_state(
            Outcome::NeedsActiveProofFromTrustedDevice {
                subject_id: subject_id.clone(),
                device_credential_id: device_credential_id.clone(),
            },
        ))
        .await
        .expect_err(
            "authenticated subject requirement must reject trusted-device active proof state",
        );
    assert!(matches!(
        needs_active_device_proof_error,
        MountedAuthRouteRequirementServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsActiveProofFromTrustedDevice {
                subject_id: actual_subject_id,
                device_credential_id: actual_device_credential_id,
            }
        ) if actual_subject_id == subject_id
            && actual_device_credential_id == device_credential_id
    ));
}

#[tokio::test]
async fn mounted_auth_route_requirement_layer_requires_fresh_step_up_when_requested() {
    let mut stale_step_up_service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::FreshStepUp)
            .layer(MountedRuntimeRouteRequirementEchoService);
    let stale_error = stale_step_up_service
        .call(mounted_route_requirement_request_with_state(
            authenticated_route_requirement_outcome(false),
        ))
        .await
        .expect_err("fresh step-up requirement must reject stale authenticated sessions");
    assert!(matches!(
        stale_error,
        MountedAuthRouteRequirementServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsStepUp { .. }
        )
    ));

    let mut fresh_step_up_service =
        MountedAuthRouteRequirementLayer::new(MountedAuthRouteRequirement::FreshStepUp)
            .layer(MountedRuntimeRouteRequirementEchoService);
    let response = fresh_step_up_service
        .call(mounted_route_requirement_request_with_state(
            authenticated_route_requirement_outcome(true),
        ))
        .await
        .expect("fresh step-up requirement should pass for fresh authenticated sessions");

    assert_eq!(response.body(), &"passed");
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountedRuntimeTestApplicationSubject {
    app_subject_id: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountedRuntimeRecordedSubjectMappingRequest {
    subject_id: SubjectId,
    session_id: SessionId,
    source: AuthenticationSource,
    step_up_is_fresh: bool,
}

#[derive(Clone)]
struct MountedRuntimeRecordingSubjectMapper {
    result: Result<MountedRuntimeTestApplicationSubject, MountedRuntimeSubjectMapperError>,
    recorded: Arc<Mutex<Vec<MountedRuntimeRecordedSubjectMappingRequest>>>,
}

impl MountedRuntimeRecordingSubjectMapper {
    fn returning(
        subject: MountedRuntimeTestApplicationSubject,
        recorded: Arc<Mutex<Vec<MountedRuntimeRecordedSubjectMappingRequest>>>,
    ) -> Self {
        Self {
            result: Ok(subject),
            recorded,
        }
    }

    fn failing(
        error: MountedRuntimeSubjectMapperError,
        recorded: Arc<Mutex<Vec<MountedRuntimeRecordedSubjectMappingRequest>>>,
    ) -> Self {
        Self {
            result: Err(error),
            recorded,
        }
    }
}

impl MountedAuthApplicationSubjectMapper for MountedRuntimeRecordingSubjectMapper {
    type ApplicationSubject = MountedRuntimeTestApplicationSubject;
    type Error = MountedRuntimeSubjectMapperError;

    fn map_application_subject<'a>(
        &'a self,
        request: MountedAuthApplicationSubjectMappingRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ApplicationSubject, Self::Error>> + 'a>> {
        Box::pin(async move {
            self.recorded
                .lock()
                .expect("recorded subject mapping requests")
                .push(MountedRuntimeRecordedSubjectMappingRequest {
                    subject_id: request.subject_id().clone(),
                    session_id: request.session_id().clone(),
                    source: request.source().clone(),
                    step_up_is_fresh: request.step_up_is_fresh(),
                });
            self.result.clone()
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MountedRuntimeSubjectMapperError(&'static str);

impl fmt::Display for MountedRuntimeSubjectMapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for MountedRuntimeSubjectMapperError {}

#[derive(Clone, Copy)]
struct MountedRuntimeMappedSubjectEchoService;

impl Service<Request<()>> for MountedRuntimeMappedSubjectEchoService {
    type Response =
        http::Response<MountedAuthMappedApplicationSubject<MountedRuntimeTestApplicationSubject>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<()>) -> Self::Future {
        let mapped = request
            .extensions()
            .get::<MountedAuthMappedApplicationSubject<MountedRuntimeTestApplicationSubject>>()
            .expect("mapped application subject")
            .clone();
        Box::pin(async move { Ok(http::Response::new(mapped)) })
    }
}

#[tokio::test]
async fn mounted_auth_application_subject_mapping_layer_maps_authenticated_subject() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mapper = MountedRuntimeRecordingSubjectMapper::returning(
        MountedRuntimeTestApplicationSubject {
            app_subject_id: "app-subject",
        },
        Arc::clone(&recorded),
    );
    let mut service = MountedAuthApplicationSubjectMappingLayer::new(mapper)
        .layer(MountedRuntimeMappedSubjectEchoService);

    let response = service
        .call(mounted_route_requirement_request_with_state(
            authenticated_route_requirement_outcome(true),
        ))
        .await
        .expect("authenticated subject mapping should pass");

    assert_eq!(
        recorded
            .lock()
            .expect("recorded subject mapping")
            .as_slice(),
        &[MountedRuntimeRecordedSubjectMappingRequest {
            subject_id: id("mounted-route-requirement-subject"),
            session_id: id("mounted-route-requirement-session"),
            source: AuthenticationSource::AuthoritativeSession,
            step_up_is_fresh: true,
        }]
    );
    assert_eq!(
        response.body().paranoid_subject_id(),
        &id("mounted-route-requirement-subject")
    );
    assert_eq!(
        response.body().session_id(),
        &id("mounted-route-requirement-session")
    );
    assert_eq!(
        response.body().source(),
        &AuthenticationSource::AuthoritativeSession
    );
    assert!(response.body().step_up_is_fresh());
    assert_eq!(
        response.body().application_subject(),
        &MountedRuntimeTestApplicationSubject {
            app_subject_id: "app-subject",
        }
    );
}

#[tokio::test]
async fn mounted_auth_application_subject_mapping_layer_rejects_before_mapper_without_authentication()
 {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mapper = MountedRuntimeRecordingSubjectMapper::returning(
        MountedRuntimeTestApplicationSubject {
            app_subject_id: "must-not-map",
        },
        Arc::clone(&recorded),
    );
    let mut service = MountedAuthApplicationSubjectMappingLayer::new(mapper)
        .layer(MountedRuntimeMappedSubjectEchoService);

    let error = service
        .call(mounted_route_requirement_request_with_state(
            Outcome::NeedsFullAuthentication,
        ))
        .await
        .expect_err("missing authenticated subject must reject before mapping");

    assert!(matches!(
        error,
        MountedAuthApplicationSubjectMappingServiceError::Requirement(
            MountedAuthRouteRequirementError::NeedsFullAuthentication
        )
    ));
    assert!(
        recorded
            .lock()
            .expect("recorded subject mapping")
            .is_empty(),
        "unauthenticated request state must not call the application mapper"
    );
}

#[tokio::test]
async fn mounted_auth_application_subject_mapping_layer_stops_on_mapper_error() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mapper = MountedRuntimeRecordingSubjectMapper::failing(
        MountedRuntimeSubjectMapperError("subject mapping failed"),
        Arc::clone(&recorded),
    );
    let mut service = MountedAuthApplicationSubjectMappingLayer::new(mapper)
        .layer(MountedRuntimeMappedSubjectEchoService);

    let error = service
        .call(mounted_route_requirement_request_with_state(
            authenticated_route_requirement_outcome(false),
        ))
        .await
        .expect_err("mapper failure must stop before inner app service");

    assert!(matches!(
        error,
        MountedAuthApplicationSubjectMappingServiceError::Mapper(MountedRuntimeSubjectMapperError(
            "subject mapping failed"
        ))
    ));
    assert_eq!(
        recorded.lock().expect("recorded subject mapping").len(),
        1,
        "authenticated mapping should call the mapper exactly once"
    );
}
