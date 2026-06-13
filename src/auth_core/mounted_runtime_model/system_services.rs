use super::*;

/// Private mounted auth runtime assembled from the Postgres runtime plus mounted config.
pub(crate) struct MountedAuthPostgresRuntime {
    runtime: PostgresAuthWebRuntime,
    config: MountedAuthRuntimeConfig,
}

impl MountedAuthPostgresRuntime {
    fn new_after_config_validation(
        runtime: PostgresAuthWebRuntime,
        config: MountedAuthRuntimeConfig,
    ) -> Self {
        Self { runtime, config }
    }

    pub(crate) fn try_new(
        runtime: PostgresAuthWebRuntime,
        config: MountedAuthRuntimeConfig,
    ) -> Result<Self, MountedAuthRuntimeError> {
        let registry = runtime.method_registry_arc();
        config.validate_against_runtime_dependencies(registry.as_deref())?;
        Ok(Self::new_after_config_validation(runtime, config))
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_without_runtime_dependency_validation(
        runtime: PostgresAuthWebRuntime,
        config: MountedAuthRuntimeConfig,
    ) -> Self {
        Self { runtime, config }
    }

    const fn internal_services(&self) -> MountedAuthPostgresServices<'_> {
        MountedAuthPostgresServices {
            mounted_runtime: self,
        }
    }

    #[cfg(test)]
    pub(crate) const fn services(&self) -> MountedAuthPostgresServices<'_> {
        self.internal_services()
    }
}

/// Private configured mounted auth system assembled from bootstrap.
pub(crate) struct MountedAuthPostgresSystem {
    runtime: MountedAuthPostgresRuntime,
    mount_path: MountedAuthRouteMountPath,
}

impl MountedAuthPostgresSystem {
    pub(crate) fn new(
        runtime: MountedAuthPostgresRuntime,
        mount_path: MountedAuthRouteMountPath,
    ) -> Self {
        Self {
            runtime,
            mount_path,
        }
    }

    pub(crate) const fn mount_path(&self) -> &MountedAuthRouteMountPath {
        &self.mount_path
    }

    fn http_mount_for_configured_system(&self) -> MountedAuthPostgresHttpMount<'_> {
        self.runtime
            .internal_services()
            .http_mount(self.mount_path.clone())
    }

    #[cfg(test)]
    pub(crate) fn http_mount(&self) -> MountedAuthPostgresHttpMount<'_> {
        self.http_mount_for_configured_system()
    }

    pub(crate) fn route_manifest(&self) -> MountedAuthRouteManifest {
        self.http_mount_for_configured_system().route_manifest()
    }

    pub(crate) fn http_route_service(&self) -> MountedAuthPostgresHttpService<'_> {
        self.http_mount_for_configured_system().http_route_service()
    }

    pub(crate) const fn protected_route_layer(
        &self,
        policy: MountedAuthProtectedRoutePolicy,
    ) -> MountedAuthProtectedRouteLayer<'_> {
        MountedAuthProtectedRouteLayer::new(&self.runtime.runtime, policy)
    }

    pub(crate) const fn protected_application_subject_mapping_layer<M>(
        &self,
        policy: MountedAuthProtectedRoutePolicy,
        mapper: M,
    ) -> MountedAuthProtectedApplicationSubjectMappingLayer<'_, M> {
        MountedAuthProtectedApplicationSubjectMappingLayer::new(
            &self.runtime.runtime,
            policy,
            mapper,
        )
    }

    pub(crate) fn configured_durable_effect_worker(
        &self,
        write_pool: WritePool,
        queue_store: queue::Store,
    ) -> Result<MountedAuthDurableEffectPostgresWorkerService, MountedAuthRuntimeError> {
        self.runtime
            .internal_services()
            .configured_durable_effect_worker(write_pool, queue_store)
    }
}

/// Private mounted auth service bundle for route and operator construction.
#[derive(Clone, Copy)]
pub(crate) struct MountedAuthPostgresServices<'a> {
    mounted_runtime: &'a MountedAuthPostgresRuntime,
}

impl<'a> MountedAuthPostgresServices<'a> {
    pub(super) const fn config(&self) -> &'a MountedAuthRuntimeConfig {
        &self.mounted_runtime.config
    }

    pub(super) const fn postgres_runtime(&self) -> &'a PostgresAuthWebRuntime {
        &self.mounted_runtime.runtime
    }

    pub(crate) fn http_mount(
        &self,
        mount_path: MountedAuthRouteMountPath,
    ) -> MountedAuthPostgresHttpMount<'a> {
        MountedAuthPostgresHttpMount {
            services: *self,
            mount_path,
        }
    }

    pub(super) fn routes(
        &self,
        mount_path: MountedAuthRouteMountPath,
    ) -> MountedAuthPostgresRouteService<'a> {
        MountedAuthPostgresRouteService::new(
            MountedAuthPostgresServices {
                mounted_runtime: self.mounted_runtime,
            },
            mount_path,
        )
    }

    pub(super) fn configured_no_session_credential_recovery_routes(
        &self,
    ) -> Result<MountedNoSessionCredentialRecoveryPostgresRouteService<'a>, MountedAuthRuntimeError>
    {
        let flow = self
            .config()
            .no_session_credential_recovery_flow()
            .ok_or(MountedAuthRuntimeError::NoSessionCredentialRecoveryFlowNotConfigured)?;
        Ok(MountedNoSessionCredentialRecoveryPostgresRouteService::new(
            self.postgres_runtime(),
            flow.clone(),
        ))
    }

    pub(super) fn configured_admin_support_staff_authorizer(
        &self,
    ) -> Result<&(dyn MountedAdminSupportStaffAuthorizer + Send + Sync), MountedAuthRuntimeError>
    {
        self.config()
            .admin_support_staff_authorizer()
            .ok_or(MountedAuthRuntimeError::AdminSupportStaffAuthorizerNotConfigured)
    }

    pub(crate) fn configured_durable_effect_worker(
        &self,
        write_pool: WritePool,
        queue_store: queue::Store,
    ) -> Result<MountedAuthDurableEffectPostgresWorkerService, MountedAuthRuntimeError> {
        let integrations = self
            .config()
            .durable_effect_worker_integrations()
            .ok_or(MountedAuthRuntimeError::DurableEffectWorkerIntegrationsNotConfigured)?
            .clone();
        Ok(MountedAuthDurableEffectPostgresWorkerService::new(
            write_pool,
            queue_store,
            self.postgres_runtime(),
            integrations,
        ))
    }
}

/// Private mounted HTTP surface for route and request-resolution construction.
#[derive(Clone)]
pub(crate) struct MountedAuthPostgresHttpMount<'a> {
    services: MountedAuthPostgresServices<'a>,
    mount_path: MountedAuthRouteMountPath,
}

impl<'a> MountedAuthPostgresHttpMount<'a> {
    pub(crate) const fn mount_path(&self) -> &MountedAuthRouteMountPath {
        &self.mount_path
    }

    pub(crate) fn route_manifest(&self) -> MountedAuthRouteManifest {
        MountedAuthRouteManifest::from_config_and_mount_path(
            self.services.config(),
            &self.mount_path,
        )
    }

    pub(crate) fn http_route_service(&self) -> MountedAuthPostgresHttpService<'a> {
        self.services
            .routes(self.mount_path.clone())
            .into_http_service()
    }

    #[cfg(test)]
    pub(crate) fn request_resolution_layer(
        &self,
        request_kind: RequestKind,
    ) -> MountedAuthRequestResolutionLayer<'a> {
        MountedAuthRequestResolutionLayer::new(self.services.postgres_runtime(), request_kind)
    }

    #[cfg(test)]
    pub(crate) const fn route_requirement_layer(
        &self,
        requirement: MountedAuthRouteRequirement,
    ) -> MountedAuthRouteRequirementLayer {
        MountedAuthRouteRequirementLayer::new(requirement)
    }

    pub(crate) const fn protected_route_layer(
        &self,
        policy: MountedAuthProtectedRoutePolicy,
    ) -> MountedAuthProtectedRouteLayer<'a> {
        MountedAuthProtectedRouteLayer::new(self.services.postgres_runtime(), policy)
    }

    #[cfg(test)]
    pub(crate) const fn application_subject_mapping_layer<M>(
        &self,
        mapper: M,
    ) -> MountedAuthApplicationSubjectMappingLayer<M> {
        MountedAuthApplicationSubjectMappingLayer::new(mapper)
    }

    pub(crate) const fn protected_application_subject_mapping_layer<M>(
        &self,
        policy: MountedAuthProtectedRoutePolicy,
        mapper: M,
    ) -> MountedAuthProtectedApplicationSubjectMappingLayer<'a, M> {
        MountedAuthProtectedApplicationSubjectMappingLayer::new(
            self.services.postgres_runtime(),
            policy,
            mapper,
        )
    }
}
