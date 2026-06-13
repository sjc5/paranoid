use std::sync::Arc;

use crate::crypto::Keyset;
use crate::db::{BootstrapConfig, WritePool, queue};

use super::email_otp_method::PostgresEmailOtpSubjectResolver;
use super::postgres_totp_method::PostgresTotpCodeVerifier;
#[cfg(test)]
use super::{
    AuthWebRuntime, MountedAuthConfiguredSystem, MountedAuthPostgresHttpMount,
    MountedAuthPostgresMethodSetup,
};
use super::{
    AuthWebTransport, Config, CredentialAdditionRecoveryAuthorityRule, CredentialResetPolicyRole,
    Error, MountedAdminSupportStaffAuthorizer, MountedAuthDurableEffectPostgresWorkerService,
    MountedAuthDurableEffectWorkerIntegrations, MountedAuthPostgresHttpService,
    MountedAuthPostgresSystem, MountedAuthProtectedApplicationSubjectMappingLayer,
    MountedAuthProtectedRouteLayer, MountedAuthProtectedRoutePolicy, MountedAuthRouteManifest,
    MountedAuthRouteMountPath, MountedAuthRuntimeError, MountedAuthSystemConfig,
    RecoveryAuthorityId, WeakProofGateVerifier,
};

/// High-level mounted auth system configuration.
pub(crate) struct AuthSystemConfig {
    mounted: MountedAuthSystemConfig,
}

impl AuthSystemConfig {
    pub(crate) fn new(
        core_config: Config,
        web_transport: AuthWebTransport,
        weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
        mount_path: MountedAuthRouteMountPath,
        durable_effect_worker_integrations: MountedAuthDurableEffectWorkerIntegrations,
    ) -> Self {
        Self {
            mounted: MountedAuthSystemConfig::new(
                core_config,
                web_transport,
                weak_proof_gate_verifier,
                mount_path,
                durable_effect_worker_integrations,
            ),
        }
    }

    pub(crate) fn with_email_otp_method(
        self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, Error> {
        Ok(Self {
            mounted: self
                .mounted
                .with_email_otp_method(response_secret_keyset, subject_resolver)?,
        })
    }

    pub(crate) fn with_email_otp_full_authentication_method(
        self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, Error> {
        Ok(Self {
            mounted: self.mounted.with_email_otp_full_authentication_method(
                response_secret_keyset,
                subject_resolver,
            )?,
        })
    }

    pub(crate) fn with_totp_method<V>(
        self,
        secret_keyset: Keyset,
        verifier: V,
    ) -> Result<Self, Error>
    where
        V: PostgresTotpCodeVerifier + 'static,
    {
        Ok(Self {
            mounted: self.mounted.with_totp_method(secret_keyset, verifier)?,
        })
    }

    pub(crate) fn with_standard_totp_method(self, secret_keyset: Keyset) -> Result<Self, Error> {
        Ok(Self {
            mounted: self.mounted.with_standard_totp_method(secret_keyset)?,
        })
    }

    pub(crate) fn with_recovery_code_method(self, secret_keyset: Keyset) -> Result<Self, Error> {
        Ok(Self {
            mounted: self.mounted.with_recovery_code_method(secret_keyset)?,
        })
    }

    pub(crate) fn with_password_derived_signature_method(self) -> Result<Self, Error> {
        Ok(Self {
            mounted: self.mounted.with_password_derived_signature_method()?,
        })
    }

    pub(crate) fn with_recovery_code_to_password_derived_signature_no_session_recovery(
        self,
        recovery_code_secret_keyset: Keyset,
    ) -> Result<Self, Error> {
        Ok(Self {
            mounted: self
                .mounted
                .with_recovery_code_to_password_derived_signature_no_session_recovery(
                    recovery_code_secret_keyset,
                )?,
        })
    }

    pub(crate) fn with_password_derived_signature_credential_addition_route(
        self,
        route_segment: impl Into<String>,
        reset_policy_role: CredentialResetPolicyRole,
        recovery_authority_rules: Vec<CredentialAdditionRecoveryAuthorityRule>,
        new_credential_authority_ids: Vec<RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        Ok(Self {
            mounted: self
                .mounted
                .with_password_derived_signature_credential_addition_route(
                    route_segment,
                    reset_policy_role,
                    recovery_authority_rules,
                    new_credential_authority_ids,
                )?,
        })
    }

    pub(crate) fn with_admin_support_routes(
        self,
        staff_authorizer: Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>,
    ) -> Self {
        Self {
            mounted: self.mounted.with_admin_support_routes(staff_authorizer),
        }
    }

    pub(super) fn into_mounted_config(self) -> MountedAuthSystemConfig {
        self.mounted
    }

    #[cfg(test)]
    pub(crate) fn into_runtime_and_configured_system_for_test(
        self,
    ) -> (
        AuthWebRuntime,
        Arc<dyn WeakProofGateVerifier + Send + Sync>,
        MountedAuthConfiguredSystem,
        Vec<MountedAuthPostgresMethodSetup>,
    ) {
        self.mounted.into_runtime_and_configured_system()
    }
}

/// High-level Postgres-backed mounted auth system configuration.
pub(crate) struct PostgresAuthSystemConfig {
    db_bootstrap_config: BootstrapConfig,
    credential_secret_keyset: Keyset,
    auth_system_config: AuthSystemConfig,
}

impl PostgresAuthSystemConfig {
    pub(crate) fn new(
        db_bootstrap_config: BootstrapConfig,
        credential_secret_keyset: Keyset,
        core_config: Config,
        web_transport: AuthWebTransport,
        weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
        mount_path: MountedAuthRouteMountPath,
        durable_effect_worker_integrations: MountedAuthDurableEffectWorkerIntegrations,
    ) -> Self {
        Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: AuthSystemConfig::new(
                core_config,
                web_transport,
                weak_proof_gate_verifier,
                mount_path,
                durable_effect_worker_integrations,
            ),
        }
    }

    pub(crate) fn with_email_otp_method(
        self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config
                .with_email_otp_method(response_secret_keyset, subject_resolver)?,
        })
    }

    pub(crate) fn with_email_otp_full_authentication_method(
        self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config.with_email_otp_full_authentication_method(
                response_secret_keyset,
                subject_resolver,
            )?,
        })
    }

    pub(crate) fn with_totp_method<V>(
        self,
        secret_keyset: Keyset,
        verifier: V,
    ) -> Result<Self, Error>
    where
        V: PostgresTotpCodeVerifier + 'static,
    {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config.with_totp_method(secret_keyset, verifier)?,
        })
    }

    pub(crate) fn with_standard_totp_method(self, secret_keyset: Keyset) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config.with_standard_totp_method(secret_keyset)?,
        })
    }

    pub(crate) fn with_recovery_code_method(self, secret_keyset: Keyset) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config.with_recovery_code_method(secret_keyset)?,
        })
    }

    pub(crate) fn with_password_derived_signature_method(self) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config.with_password_derived_signature_method()?,
        })
    }

    pub(crate) fn with_recovery_code_to_password_derived_signature_no_session_recovery(
        self,
        recovery_code_secret_keyset: Keyset,
    ) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config
                .with_recovery_code_to_password_derived_signature_no_session_recovery(
                    recovery_code_secret_keyset,
                )?,
        })
    }

    pub(crate) fn with_password_derived_signature_credential_addition_route(
        self,
        route_segment: impl Into<String>,
        reset_policy_role: CredentialResetPolicyRole,
        recovery_authority_rules: Vec<CredentialAdditionRecoveryAuthorityRule>,
        new_credential_authority_ids: Vec<RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Ok(Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config
                .with_password_derived_signature_credential_addition_route(
                    route_segment,
                    reset_policy_role,
                    recovery_authority_rules,
                    new_credential_authority_ids,
                )?,
        })
    }

    pub(crate) fn with_admin_support_routes(
        self,
        staff_authorizer: Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>,
    ) -> Self {
        let Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config,
        } = self;
        Self {
            db_bootstrap_config,
            credential_secret_keyset,
            auth_system_config: auth_system_config.with_admin_support_routes(staff_authorizer),
        }
    }

    pub(super) fn into_parts(self) -> (BootstrapConfig, Keyset, AuthSystemConfig) {
        (
            self.db_bootstrap_config,
            self.credential_secret_keyset,
            self.auth_system_config,
        )
    }
}

/// Bootstrapped mounted auth system backed by Postgres.
pub(crate) struct PostgresAuthSystem {
    mounted: MountedAuthPostgresSystem,
}

impl PostgresAuthSystem {
    pub(super) fn new(mounted: MountedAuthPostgresSystem) -> Self {
        Self { mounted }
    }

    pub(crate) const fn mount_path(&self) -> &MountedAuthRouteMountPath {
        self.mounted.mount_path()
    }

    pub(crate) fn route_manifest(&self) -> MountedAuthRouteManifest {
        self.mounted.route_manifest()
    }

    pub(crate) fn http_route_service(&self) -> MountedAuthPostgresHttpService<'_> {
        self.mounted.http_route_service()
    }

    pub(crate) const fn protected_route_layer(
        &self,
        policy: MountedAuthProtectedRoutePolicy,
    ) -> MountedAuthProtectedRouteLayer<'_> {
        self.mounted.protected_route_layer(policy)
    }

    pub(crate) const fn protected_application_subject_mapping_layer<M>(
        &self,
        policy: MountedAuthProtectedRoutePolicy,
        mapper: M,
    ) -> MountedAuthProtectedApplicationSubjectMappingLayer<'_, M> {
        self.mounted
            .protected_application_subject_mapping_layer(policy, mapper)
    }

    pub(crate) fn durable_effect_worker(
        &self,
        write_pool: WritePool,
        queue_store: queue::Store,
    ) -> Result<MountedAuthDurableEffectPostgresWorkerService, MountedAuthRuntimeError> {
        self.mounted
            .configured_durable_effect_worker(write_pool, queue_store)
    }

    #[cfg(test)]
    pub(crate) fn http_mount(&self) -> MountedAuthPostgresHttpMount<'_> {
        self.mounted.http_mount()
    }
}
