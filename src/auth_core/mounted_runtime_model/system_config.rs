use super::*;

/// Coherent mounted auth route set for the configured auth product surface.
#[derive(Clone)]
struct MountedAuthConfiguredSystemRoutes {
    durable_effect_worker_integrations: MountedAuthDurableEffectWorkerIntegrations,
    full_authentication_out_of_band_method: Option<ProofMethodDeclaration>,
    no_session_credential_recovery_flow: Option<MountedNoSessionCredentialRecoveryFlow>,
    credential_addition_routes: Vec<MountedCredentialAdditionRoute>,
    admin_support_staff_authorizer:
        Option<Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>>,
}

impl MountedAuthConfiguredSystemRoutes {
    fn new(durable_effect_worker_integrations: MountedAuthDurableEffectWorkerIntegrations) -> Self {
        Self {
            durable_effect_worker_integrations,
            full_authentication_out_of_band_method: None,
            no_session_credential_recovery_flow: None,
            credential_addition_routes: Vec::new(),
            admin_support_staff_authorizer: None,
        }
    }

    fn with_full_authentication_out_of_band_method(
        mut self,
        method: ProofMethodDeclaration,
    ) -> Result<Self, Error> {
        validate_mounted_full_authentication_out_of_band_method(&method)?;
        self.full_authentication_out_of_band_method = Some(method);
        Ok(self)
    }

    fn with_no_session_credential_recovery_flow(
        mut self,
        flow: MountedNoSessionCredentialRecoveryFlow,
    ) -> Self {
        self.no_session_credential_recovery_flow = Some(flow);
        self
    }

    fn try_with_credential_addition_route(
        mut self,
        route: MountedCredentialAdditionRoute,
    ) -> Result<Self, Error> {
        validate_unique_mounted_credential_addition_route_segment(
            &self.credential_addition_routes,
            route.route_segment(),
        )?;
        self.credential_addition_routes.push(route);
        Ok(self)
    }

    fn with_admin_support_routes(
        mut self,
        staff_authorizer: Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>,
    ) -> Self {
        self.admin_support_staff_authorizer = Some(staff_authorizer);
        self
    }
}

/// Coherent mounted auth system configuration for the configured auth product surface.
#[derive(Clone)]
pub(crate) struct MountedAuthConfiguredSystem {
    mount_path: MountedAuthRouteMountPath,
    routes: MountedAuthConfiguredSystemRoutes,
}

impl MountedAuthConfiguredSystem {
    pub(crate) fn new(
        mount_path: MountedAuthRouteMountPath,
        durable_effect_worker_integrations: MountedAuthDurableEffectWorkerIntegrations,
    ) -> Self {
        Self {
            mount_path,
            routes: MountedAuthConfiguredSystemRoutes::new(durable_effect_worker_integrations),
        }
    }

    pub(crate) fn with_full_authentication_out_of_band_method(
        mut self,
        method: ProofMethodDeclaration,
    ) -> Result<Self, Error> {
        self.routes = self
            .routes
            .with_full_authentication_out_of_band_method(method)?;
        Ok(self)
    }

    pub(crate) fn with_no_session_credential_recovery_flow(
        mut self,
        flow: MountedNoSessionCredentialRecoveryFlow,
    ) -> Self {
        self.routes = self.routes.with_no_session_credential_recovery_flow(flow);
        self
    }

    pub(crate) fn try_with_credential_addition_route(
        mut self,
        route: MountedCredentialAdditionRoute,
    ) -> Result<Self, Error> {
        self.routes = self.routes.try_with_credential_addition_route(route)?;
        Ok(self)
    }

    pub(crate) fn with_admin_support_routes(
        mut self,
        staff_authorizer: Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>,
    ) -> Self {
        self.routes = self.routes.with_admin_support_routes(staff_authorizer);
        self
    }

    pub(crate) const fn mount_path(&self) -> &MountedAuthRouteMountPath {
        &self.mount_path
    }

    fn into_parts(self) -> (MountedAuthRouteMountPath, MountedAuthConfiguredSystemRoutes) {
        (self.mount_path, self.routes)
    }

    pub(crate) fn into_mount_path_and_runtime_config(
        self,
    ) -> Result<(MountedAuthRouteMountPath, MountedAuthRuntimeConfig), Error> {
        let (mount_path, routes) = self.into_parts();
        Ok((
            mount_path,
            MountedAuthRuntimeConfig::try_from_configured_system_routes(routes)?,
        ))
    }
}

/// First-party Postgres method setup owned by the mounted auth system config.
pub(crate) enum MountedAuthPostgresMethodSetup {
    EmailOtp {
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    },
    Totp {
        secret_keyset: Keyset,
        verifier: Arc<dyn PostgresTotpCodeVerifier>,
    },
    RecoveryCode {
        secret_keyset: Keyset,
    },
    PasswordDerivedSignature,
}

impl MountedAuthPostgresMethodSetup {
    fn identity(&self) -> (ProofFamily, &'static str) {
        match self {
            Self::EmailOtp { .. } => (ProofFamily::OutOfBandCode, EMAIL_OTP_METHOD_LABEL),
            Self::Totp { .. } => (ProofFamily::SharedSecretOtp, TOTP_METHOD_LABEL),
            Self::RecoveryCode { .. } => (ProofFamily::RecoveryCode, RECOVERY_CODE_METHOD_LABEL),
            Self::PasswordDerivedSignature => (
                ProofFamily::MessageSignature,
                PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL,
            ),
        }
    }

    pub(crate) fn method_declaration(&self) -> Result<ProofMethodDeclaration, Error> {
        let (family, method_label) = self.identity();
        if matches!(self, Self::PasswordDerivedSignature) {
            ProofMethodDeclaration::new_online_guessable(family, method_label)
        } else {
            ProofMethodDeclaration::new(family, method_label)
        }
    }
}

/// Private one-config mounted auth system shape for bootstrap construction.
pub(crate) struct MountedAuthSystemConfig {
    runtime: AuthWebRuntime,
    weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
    configured_system: MountedAuthConfiguredSystem,
    method_setups: Vec<MountedAuthPostgresMethodSetup>,
}

impl MountedAuthSystemConfig {
    pub(crate) fn new(
        core_config: Config,
        web_transport: AuthWebTransport,
        weak_proof_gate_verifier: Arc<dyn WeakProofGateVerifier + Send + Sync>,
        mount_path: MountedAuthRouteMountPath,
        durable_effect_worker_integrations: MountedAuthDurableEffectWorkerIntegrations,
    ) -> Self {
        Self {
            runtime: AuthWebRuntime::new(core_config, web_transport),
            weak_proof_gate_verifier,
            configured_system: MountedAuthConfiguredSystem::new(
                mount_path,
                durable_effect_worker_integrations,
            ),
            method_setups: Vec::new(),
        }
    }

    fn push_method_setup(
        &mut self,
        method_setup: MountedAuthPostgresMethodSetup,
    ) -> Result<ProofMethodDeclaration, Error> {
        let identity = method_setup.identity();
        if self
            .method_setups
            .iter()
            .any(|existing| existing.identity() == identity)
        {
            return Err(Error::InvalidConfig(
                "mounted auth first-party method setups must be unique",
            ));
        }
        let method = method_setup.method_declaration()?;
        self.method_setups.push(method_setup);
        Ok(method)
    }

    fn ensure_password_derived_signature_method_setup(
        &mut self,
    ) -> Result<ProofMethodDeclaration, Error> {
        let identity = (
            ProofFamily::MessageSignature,
            PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL,
        );
        if let Some(existing) = self
            .method_setups
            .iter()
            .find(|existing| existing.identity() == identity)
        {
            return existing.method_declaration();
        }
        self.push_method_setup(MountedAuthPostgresMethodSetup::PasswordDerivedSignature)
    }

    pub(crate) fn with_email_otp_method(
        mut self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, Error> {
        self.push_method_setup(MountedAuthPostgresMethodSetup::EmailOtp {
            response_secret_keyset,
            subject_resolver,
        })?;
        Ok(self)
    }

    pub(crate) fn with_email_otp_full_authentication_method(
        mut self,
        response_secret_keyset: Keyset,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Result<Self, Error> {
        let method = self.push_method_setup(MountedAuthPostgresMethodSetup::EmailOtp {
            response_secret_keyset,
            subject_resolver,
        })?;
        self.configured_system = self
            .configured_system
            .with_full_authentication_out_of_band_method(method)?;
        Ok(self)
    }

    pub(crate) fn with_totp_method<V>(
        mut self,
        secret_keyset: Keyset,
        verifier: V,
    ) -> Result<Self, Error>
    where
        V: PostgresTotpCodeVerifier + 'static,
    {
        self.push_method_setup(MountedAuthPostgresMethodSetup::Totp {
            secret_keyset,
            verifier: Arc::new(verifier),
        })?;
        Ok(self)
    }

    pub(crate) fn with_standard_totp_method(self, secret_keyset: Keyset) -> Result<Self, Error> {
        self.with_totp_method(secret_keyset, StandardTotpCodeVerifier::default())
    }

    pub(crate) fn with_recovery_code_method(
        mut self,
        secret_keyset: Keyset,
    ) -> Result<Self, Error> {
        self.push_method_setup(MountedAuthPostgresMethodSetup::RecoveryCode { secret_keyset })?;
        Ok(self)
    }

    pub(crate) fn with_password_derived_signature_method(mut self) -> Result<Self, Error> {
        self.push_method_setup(MountedAuthPostgresMethodSetup::PasswordDerivedSignature)?;
        Ok(self)
    }

    pub(crate) fn with_recovery_code_to_password_derived_signature_no_session_recovery(
        mut self,
        recovery_code_secret_keyset: Keyset,
    ) -> Result<Self, Error> {
        let recovery_method =
            self.push_method_setup(MountedAuthPostgresMethodSetup::RecoveryCode {
                secret_keyset: recovery_code_secret_keyset,
            })?;
        let reset_target_method = self.ensure_password_derived_signature_method_setup()?;
        let flow =
            MountedNoSessionCredentialRecoveryFlow::new(recovery_method, reset_target_method)?;
        self.configured_system = self
            .configured_system
            .with_no_session_credential_recovery_flow(flow);
        Ok(self)
    }

    pub(crate) fn with_password_derived_signature_credential_addition_route(
        mut self,
        route_segment: impl Into<String>,
        reset_policy_role: CredentialResetPolicyRole,
        recovery_authority_rules: Vec<CredentialAdditionRecoveryAuthorityRule>,
        new_credential_authority_ids: Vec<RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        let method = self.ensure_password_derived_signature_method_setup()?;
        let addition_method = MountedCredentialAdditionMethod::new(
            method,
            reset_policy_role,
            recovery_authority_rules,
            new_credential_authority_ids,
        )?;
        let route = MountedCredentialAdditionRoute::new(route_segment, addition_method)?;
        self.configured_system = self
            .configured_system
            .try_with_credential_addition_route(route)?;
        Ok(self)
    }

    pub(crate) fn with_admin_support_routes(
        mut self,
        staff_authorizer: Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>,
    ) -> Self {
        self.configured_system = self
            .configured_system
            .with_admin_support_routes(staff_authorizer);
        self
    }

    pub(crate) fn into_runtime_and_configured_system(
        self,
    ) -> (
        AuthWebRuntime,
        Arc<dyn WeakProofGateVerifier + Send + Sync>,
        MountedAuthConfiguredSystem,
        Vec<MountedAuthPostgresMethodSetup>,
    ) {
        (
            self.runtime,
            self.weak_proof_gate_verifier,
            self.configured_system,
            self.method_setups,
        )
    }
}

/// Private mounted auth configuration for route and operator service construction.
#[derive(Clone, Default)]
pub(crate) struct MountedAuthRuntimeConfig {
    full_authentication_out_of_band_method: Option<ProofMethodDeclaration>,
    no_session_credential_recovery_flow: Option<MountedNoSessionCredentialRecoveryFlow>,
    authenticated_credential_inventory_route_enabled: bool,
    credential_addition_routes: Vec<MountedCredentialAdditionRoute>,
    authenticated_credential_reset_routes_enabled: bool,
    authenticated_credential_replacement_routes_enabled: bool,
    authenticated_credential_removal_routes_enabled: bool,
    authenticated_credential_regeneration_routes_enabled: bool,
    authenticated_credential_rotation_routes_enabled: bool,
    delayed_credential_lifecycle_routes_enabled: bool,
    authenticated_out_of_band_identifier_change_routes_enabled: bool,
    delayed_subject_auth_state_deletion_routes_enabled: bool,
    admin_support_staff_authorizer:
        Option<Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>>,
    durable_effect_worker_integrations: Option<MountedAuthDurableEffectWorkerIntegrations>,
}

impl MountedAuthRuntimeConfig {
    fn set_full_authentication_out_of_band_method(
        &mut self,
        method: ProofMethodDeclaration,
    ) -> Result<(), Error> {
        validate_mounted_full_authentication_out_of_band_method(&method)?;
        self.full_authentication_out_of_band_method = Some(method);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_full_authentication_out_of_band_method(
        mut self,
        method: ProofMethodDeclaration,
    ) -> Result<Self, Error> {
        self.set_full_authentication_out_of_band_method(method)?;
        Ok(self)
    }

    fn try_from_configured_system_routes(
        routes: MountedAuthConfiguredSystemRoutes,
    ) -> Result<Self, Error> {
        Self::default().try_with_configured_system_routes(routes)
    }

    fn try_with_configured_system_routes(
        mut self,
        routes: MountedAuthConfiguredSystemRoutes,
    ) -> Result<Self, Error> {
        self.durable_effect_worker_integrations = Some(routes.durable_effect_worker_integrations);
        if let Some(method) = routes.full_authentication_out_of_band_method {
            self.set_full_authentication_out_of_band_method(method)?;
        }
        if let Some(flow) = routes.no_session_credential_recovery_flow {
            self.no_session_credential_recovery_flow = Some(flow);
        }
        for route in routes.credential_addition_routes {
            self.push_credential_addition_route(route)?;
        }
        self.enable_configured_product_route_set();
        if let Some(staff_authorizer) = routes.admin_support_staff_authorizer {
            self.admin_support_staff_authorizer = Some(staff_authorizer);
        }
        Ok(self)
    }

    fn enable_configured_product_route_set(&mut self) {
        self.authenticated_credential_inventory_route_enabled = true;
        self.authenticated_credential_reset_routes_enabled = true;
        self.authenticated_credential_replacement_routes_enabled = true;
        self.authenticated_credential_removal_routes_enabled = true;
        self.authenticated_credential_regeneration_routes_enabled = true;
        self.authenticated_credential_rotation_routes_enabled = true;
        self.delayed_credential_lifecycle_routes_enabled = true;
        self.authenticated_out_of_band_identifier_change_routes_enabled = true;
        self.delayed_subject_auth_state_deletion_routes_enabled = true;
    }

    fn push_credential_addition_route(
        &mut self,
        route: MountedCredentialAdditionRoute,
    ) -> Result<(), Error> {
        validate_unique_mounted_credential_addition_route_segment(
            &self.credential_addition_routes,
            route.route_segment(),
        )?;
        self.credential_addition_routes.push(route);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_no_session_credential_recovery_flow(
        mut self,
        flow: MountedNoSessionCredentialRecoveryFlow,
    ) -> Self {
        self.no_session_credential_recovery_flow = Some(flow);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_durable_effect_worker_integrations(
        mut self,
        integrations: MountedAuthDurableEffectWorkerIntegrations,
    ) -> Self {
        self.durable_effect_worker_integrations = Some(integrations);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_credential_inventory_route(mut self) -> Self {
        self.authenticated_credential_inventory_route_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_credential_reset_routes(mut self) -> Self {
        self.authenticated_credential_reset_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_credential_replacement_routes(mut self) -> Self {
        self.authenticated_credential_replacement_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_credential_removal_routes(mut self) -> Self {
        self.authenticated_credential_removal_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_credential_regeneration_routes(mut self) -> Self {
        self.authenticated_credential_regeneration_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_credential_rotation_routes(mut self) -> Self {
        self.authenticated_credential_rotation_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_delayed_credential_lifecycle_routes(mut self) -> Self {
        self.delayed_credential_lifecycle_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_authenticated_out_of_band_identifier_change_routes(mut self) -> Self {
        self.authenticated_out_of_band_identifier_change_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_delayed_subject_auth_state_deletion_routes(mut self) -> Self {
        self.delayed_subject_auth_state_deletion_routes_enabled = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_admin_support_routes(
        mut self,
        staff_authorizer: Arc<dyn MountedAdminSupportStaffAuthorizer + Send + Sync>,
    ) -> Self {
        self.admin_support_staff_authorizer = Some(staff_authorizer);
        self
    }

    #[cfg(test)]
    pub(crate) fn try_with_credential_addition_route(
        mut self,
        route: MountedCredentialAdditionRoute,
    ) -> Result<Self, Error> {
        self.push_credential_addition_route(route)?;
        Ok(self)
    }

    pub(crate) const fn no_session_credential_recovery_flow(
        &self,
    ) -> Option<&MountedNoSessionCredentialRecoveryFlow> {
        self.no_session_credential_recovery_flow.as_ref()
    }

    pub(crate) const fn full_authentication_out_of_band_method(
        &self,
    ) -> Option<&ProofMethodDeclaration> {
        self.full_authentication_out_of_band_method.as_ref()
    }

    pub(crate) fn credential_addition_routes(&self) -> &[MountedCredentialAdditionRoute] {
        &self.credential_addition_routes
    }

    pub(crate) const fn authenticated_credential_inventory_route_enabled(&self) -> bool {
        self.authenticated_credential_inventory_route_enabled
    }

    pub(crate) const fn authenticated_credential_reset_routes_enabled(&self) -> bool {
        self.authenticated_credential_reset_routes_enabled
    }

    pub(crate) const fn authenticated_credential_replacement_routes_enabled(&self) -> bool {
        self.authenticated_credential_replacement_routes_enabled
    }

    pub(crate) const fn authenticated_credential_removal_routes_enabled(&self) -> bool {
        self.authenticated_credential_removal_routes_enabled
    }

    pub(crate) const fn authenticated_credential_regeneration_routes_enabled(&self) -> bool {
        self.authenticated_credential_regeneration_routes_enabled
    }

    pub(crate) const fn authenticated_credential_rotation_routes_enabled(&self) -> bool {
        self.authenticated_credential_rotation_routes_enabled
    }

    pub(crate) const fn delayed_credential_lifecycle_routes_enabled(&self) -> bool {
        self.delayed_credential_lifecycle_routes_enabled
    }

    pub(crate) const fn authenticated_out_of_band_identifier_change_routes_enabled(&self) -> bool {
        self.authenticated_out_of_band_identifier_change_routes_enabled
    }

    pub(crate) const fn delayed_subject_auth_state_deletion_routes_enabled(&self) -> bool {
        self.delayed_subject_auth_state_deletion_routes_enabled
    }

    pub(crate) fn admin_support_routes_enabled(&self) -> bool {
        self.admin_support_staff_authorizer.is_some()
    }

    pub(crate) fn admin_support_staff_authorizer(
        &self,
    ) -> Option<&(dyn MountedAdminSupportStaffAuthorizer + Send + Sync)> {
        self.admin_support_staff_authorizer.as_deref()
    }

    pub(crate) const fn durable_effect_worker_integrations(
        &self,
    ) -> Option<&MountedAuthDurableEffectWorkerIntegrations> {
        self.durable_effect_worker_integrations.as_ref()
    }

    pub(crate) fn validate_against_runtime_dependencies(
        &self,
        registry: Option<&PostgresAuthMethodRegistry>,
    ) -> Result<(), MountedAuthRuntimeError> {
        if self.configured_routes_require_durable_effect_worker_integrations()
            && self.durable_effect_worker_integrations().is_none()
        {
            return Err(
                MountedAuthRuntimeError::DurableEffectWorkerIntegrationsRequiredForConfiguredRoutes,
            );
        }
        if self.configured_routes_require_method_registry() && registry.is_none() {
            return Err(MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes);
        }
        if let Some(method) = self.full_authentication_out_of_band_method() {
            ensure_mounted_auth_config_method_supports_capability(
                registry,
                method,
                FULL_AUTHENTICATION_OUT_OF_BAND_ROUTE_FAMILY,
                OUT_OF_BAND_FULL_AUTHENTICATION_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::out_of_band_full_authentication,
            )?;
        }
        if let Some(flow) = self.no_session_credential_recovery_flow() {
            ensure_mounted_auth_config_method_supports_capability(
                registry,
                flow.recovery_method(),
                NO_SESSION_CREDENTIAL_RECOVERY_ROUTE_FAMILY,
                NO_SESSION_RECOVERY_CREDENTIAL_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::no_session_recovery_credential,
            )?;
            ensure_mounted_auth_config_method_supports_capability(
                registry,
                flow.reset_target_method(),
                NO_SESSION_CREDENTIAL_RECOVERY_ROUTE_FAMILY,
                CREDENTIAL_RESET_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_reset,
            )?;
        }
        for route in self.credential_addition_routes() {
            ensure_mounted_auth_config_method_supports_capability(
                registry,
                route.method_config().method(),
                CREDENTIAL_ADDITION_ROUTE_FAMILY,
                CREDENTIAL_CREATION_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_creation,
            )?;
        }
        if self.authenticated_credential_reset_routes_enabled() {
            ensure_mounted_auth_registry_supports_capability(
                registry,
                AUTHENTICATED_CREDENTIAL_RESET_ROUTE_FAMILY,
                CREDENTIAL_RESET_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_reset,
            )?;
        }
        if self.authenticated_credential_replacement_routes_enabled() {
            ensure_mounted_auth_registry_supports_capability(
                registry,
                AUTHENTICATED_CREDENTIAL_REPLACEMENT_ROUTE_FAMILY,
                CREDENTIAL_REPLACEMENT_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_replacement,
            )?;
        }
        if self.authenticated_credential_regeneration_routes_enabled() {
            ensure_mounted_auth_registry_supports_capability(
                registry,
                AUTHENTICATED_CREDENTIAL_REGENERATION_ROUTE_FAMILY,
                CREDENTIAL_REGENERATION_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_regeneration,
            )?;
        }
        if self.authenticated_credential_rotation_routes_enabled() {
            ensure_mounted_auth_registry_supports_capability(
                registry,
                AUTHENTICATED_CREDENTIAL_ROTATION_ROUTE_FAMILY,
                CREDENTIAL_ROTATION_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_rotation,
            )?;
        }
        if self.delayed_credential_lifecycle_routes_enabled() {
            ensure_mounted_auth_registry_supports_capability(
                registry,
                DELAYED_CREDENTIAL_LIFECYCLE_ROUTE_FAMILY,
                CREDENTIAL_RESET_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_reset,
            )?;
            ensure_mounted_auth_registry_supports_capability(
                registry,
                DELAYED_CREDENTIAL_LIFECYCLE_ROUTE_FAMILY,
                CREDENTIAL_REPLACEMENT_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_replacement,
            )?;
            ensure_mounted_auth_registry_supports_capability(
                registry,
                DELAYED_CREDENTIAL_LIFECYCLE_ROUTE_FAMILY,
                CREDENTIAL_REGENERATION_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::credential_regeneration,
            )?;
        }
        if self.authenticated_out_of_band_identifier_change_routes_enabled() {
            ensure_mounted_auth_registry_supports_capability(
                registry,
                AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_ROUTE_FAMILY,
                OUT_OF_BAND_IDENTIFIER_CHANGE_METHOD_CAPABILITY,
                PostgresAuthMethodMountedRouteCapabilities::out_of_band_identifier_change,
            )?;
        }
        Ok(())
    }

    fn configured_routes_require_durable_effect_worker_integrations(&self) -> bool {
        self.full_authentication_out_of_band_method().is_some()
            || self.no_session_credential_recovery_flow().is_some()
            || !self.credential_addition_routes().is_empty()
            || self.authenticated_credential_reset_routes_enabled()
            || self.authenticated_credential_replacement_routes_enabled()
            || self.authenticated_credential_removal_routes_enabled()
            || self.authenticated_credential_regeneration_routes_enabled()
            || self.authenticated_credential_rotation_routes_enabled()
            || self.delayed_credential_lifecycle_routes_enabled()
            || self.authenticated_out_of_band_identifier_change_routes_enabled()
            || self.delayed_subject_auth_state_deletion_routes_enabled()
            || self.admin_support_routes_enabled()
    }

    fn configured_routes_require_method_registry(&self) -> bool {
        self.full_authentication_out_of_band_method().is_some()
            || self.no_session_credential_recovery_flow().is_some()
            || !self.credential_addition_routes().is_empty()
            || self.authenticated_credential_reset_routes_enabled()
            || self.authenticated_credential_replacement_routes_enabled()
            || self.authenticated_credential_regeneration_routes_enabled()
            || self.authenticated_credential_rotation_routes_enabled()
            || self.delayed_credential_lifecycle_routes_enabled()
            || self.authenticated_out_of_band_identifier_change_routes_enabled()
    }
}

const FULL_AUTHENTICATION_OUT_OF_BAND_ROUTE_FAMILY: &str = "full-authentication out-of-band routes";
const NO_SESSION_CREDENTIAL_RECOVERY_ROUTE_FAMILY: &str = "no-session credential recovery routes";
const CREDENTIAL_ADDITION_ROUTE_FAMILY: &str = "credential addition routes";
const AUTHENTICATED_CREDENTIAL_RESET_ROUTE_FAMILY: &str = "authenticated credential reset routes";
const AUTHENTICATED_CREDENTIAL_REPLACEMENT_ROUTE_FAMILY: &str =
    "authenticated credential replacement routes";
const AUTHENTICATED_CREDENTIAL_REGENERATION_ROUTE_FAMILY: &str =
    "authenticated credential regeneration routes";
const AUTHENTICATED_CREDENTIAL_ROTATION_ROUTE_FAMILY: &str =
    "authenticated credential rotation routes";
const DELAYED_CREDENTIAL_LIFECYCLE_ROUTE_FAMILY: &str = "delayed credential lifecycle routes";
const AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_ROUTE_FAMILY: &str =
    "authenticated out-of-band identifier change routes";

const OUT_OF_BAND_FULL_AUTHENTICATION_METHOD_CAPABILITY: &str =
    "out-of-band full-authentication challenge work";
const NO_SESSION_RECOVERY_CREDENTIAL_METHOD_CAPABILITY: &str =
    "no-session recovery credential proof work";
const CREDENTIAL_CREATION_METHOD_CAPABILITY: &str = "credential creation work";
const CREDENTIAL_RESET_METHOD_CAPABILITY: &str = "credential reset work";
const CREDENTIAL_REPLACEMENT_METHOD_CAPABILITY: &str = "credential replacement work";
const CREDENTIAL_REGENERATION_METHOD_CAPABILITY: &str = "credential regeneration work";
const CREDENTIAL_ROTATION_METHOD_CAPABILITY: &str = "credential rotation work";
const OUT_OF_BAND_IDENTIFIER_CHANGE_METHOD_CAPABILITY: &str =
    "out-of-band identifier change candidate binding work";

fn validate_mounted_full_authentication_out_of_band_method(
    method: &ProofMethodDeclaration,
) -> Result<(), Error> {
    if method.family() != ProofFamily::OutOfBandCode
        || method.semantics().interaction != ProofInteraction::Active
    {
        return Err(Error::ProofMethodCannotIssueOutOfBandChallenge {
            family: method.family(),
        });
    }
    Ok(())
}

fn validate_unique_mounted_credential_addition_route_segment(
    existing_routes: &[MountedCredentialAdditionRoute],
    route_segment: &str,
) -> Result<(), Error> {
    if existing_routes
        .iter()
        .any(|existing| existing.route_segment() == route_segment)
    {
        return Err(Error::InvalidConfig(
            "mounted credential addition route segments must be unique",
        ));
    }
    Ok(())
}

fn ensure_mounted_auth_config_method_is_registered(
    registry: Option<&PostgresAuthMethodRegistry>,
    method: &ProofMethodDeclaration,
) -> Result<(), MountedAuthRuntimeError> {
    if registry.is_some_and(|registry| registry.contains_method(method)) {
        Ok(())
    } else {
        Err(MountedAuthRuntimeError::ConfiguredMethodNotRegistered {
            family: method.family(),
            method_label: method.method_label().to_owned(),
        })
    }
}

fn ensure_mounted_auth_config_method_supports_capability(
    registry: Option<&PostgresAuthMethodRegistry>,
    method: &ProofMethodDeclaration,
    route_family: &'static str,
    capability: &'static str,
    predicate: impl Fn(PostgresAuthMethodMountedRouteCapabilities) -> bool,
) -> Result<(), MountedAuthRuntimeError> {
    ensure_mounted_auth_config_method_is_registered(registry, method)?;
    let Some(capabilities) =
        registry.and_then(|registry| registry.mounted_route_capabilities_for_method(method))
    else {
        return Err(MountedAuthRuntimeError::ConfiguredMethodNotRegistered {
            family: method.family(),
            method_label: method.method_label().to_owned(),
        });
    };
    if predicate(capabilities) {
        Ok(())
    } else {
        Err(
            MountedAuthRuntimeError::ConfiguredMethodLacksMountedRouteCapability {
                family: method.family(),
                method_label: method.method_label().to_owned(),
                route_family,
                capability,
            },
        )
    }
}

fn ensure_mounted_auth_registry_supports_capability(
    registry: Option<&PostgresAuthMethodRegistry>,
    route_family: &'static str,
    capability: &'static str,
    predicate: impl Fn(PostgresAuthMethodMountedRouteCapabilities) -> bool,
) -> Result<(), MountedAuthRuntimeError> {
    let registry =
        registry.ok_or(MountedAuthRuntimeError::MethodRegistryRequiredForConfiguredRoutes)?;
    if registry.any_method_supports_mounted_route_capability(predicate) {
        Ok(())
    } else {
        Err(
            MountedAuthRuntimeError::MountedRoutesRequireMethodCapability {
                route_family,
                capability,
            },
        )
    }
}
