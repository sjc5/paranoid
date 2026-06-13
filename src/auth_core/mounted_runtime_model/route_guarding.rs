use super::*;

impl<'a> MountedAuthPostgresRouteService<'a> {
    pub(crate) fn guarded_route_match_for_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<MountedAuthGuardedRouteMatch, MountedAuthRouteServiceError> {
        let method = request.method();
        let path = request.uri().path();
        let manifest = self.route_manifest();
        let descriptor = manifest
            .descriptor_for_method_and_path(method, path)
            .cloned()
            .ok_or_else(|| MountedAuthRouteServiceError::RouteNotFound {
                method: method.clone(),
                path: path.to_owned(),
            })?;

        if descriptor.requires_csrf() {
            self.services
                .postgres_runtime()
                .verify_csrf_request(request)
                .map_err(|error| {
                    mounted_auth_csrf_error_for_route_kind(descriptor.kind(), error)
                })?;
        }

        let route = descriptor
            .guarded_route(self.services.config(), &self.mount_path)
            .ok_or_else(|| MountedAuthRouteServiceError::RouteNotFound {
                method: method.clone(),
                path: path.to_owned(),
            })?;

        Ok(MountedAuthGuardedRouteMatch::new(descriptor, route))
    }

    pub(crate) fn guarded_route_for_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<MountedAuthGuardedRoute, MountedAuthRouteServiceError> {
        self.guarded_route_match_for_request(request)
            .map(MountedAuthGuardedRouteMatch::into_route)
    }
}

fn mounted_auth_csrf_error_for_route_kind(
    route_kind: MountedAuthRouteKind,
    error: AuthPostgresWebRuntimeExecutionError,
) -> MountedAuthRouteServiceError {
    match route_kind {
        MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(_)
        | MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(_) => {
            MountedSubjectLifecycleServiceError::from(error).into()
        }
        MountedAuthRouteKind::AdminSupport(_) => {
            MountedAdminSupportServiceError::from(error).into()
        }
        MountedAuthRouteKind::FullAuthentication(_)
        | MountedAuthRouteKind::NoSessionCredentialRecovery(_)
        | MountedAuthRouteKind::AuthenticatedCredentialInventory
        | MountedAuthRouteKind::AuthenticatedCredentialAddition
        | MountedAuthRouteKind::AuthenticatedCredentialReset(_)
        | MountedAuthRouteKind::AuthenticatedCredentialReplacement(_)
        | MountedAuthRouteKind::AuthenticatedCredentialRemoval(_)
        | MountedAuthRouteKind::AuthenticatedCredentialRegeneration(_)
        | MountedAuthRouteKind::AuthenticatedCredentialRotation(_)
        | MountedAuthRouteKind::DelayedCredentialLifecycle(_)
        | MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(_) => {
            MountedCredentialLifecycleServiceError::from(error).into()
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MountedAuthGuardedRouteMatch {
    descriptor: MountedAuthRouteDescriptor,
    route: MountedAuthGuardedRoute,
}

impl MountedAuthGuardedRouteMatch {
    fn new(descriptor: MountedAuthRouteDescriptor, route: MountedAuthGuardedRoute) -> Self {
        Self { descriptor, route }
    }

    pub(crate) const fn max_collected_body_bytes(&self) -> usize {
        self.descriptor.max_collected_body_bytes()
    }

    pub(crate) fn into_route(self) -> MountedAuthGuardedRoute {
        self.route
    }
}

#[derive(Clone, Debug)]
pub(crate) enum MountedAuthGuardedRoute {
    FullAuthentication(MountedFullAuthenticationEndpoint),
    NoSessionCredentialRecovery(MountedAuthRouteGuardedNoSessionRecoveryEndpoint),
    AuthenticatedCredentialInventory,
    AuthenticatedCredentialAddition(MountedCredentialAdditionRoute),
    AuthenticatedCredentialReset(MountedAuthenticatedCredentialResetEndpoint),
    AuthenticatedCredentialReplacement(MountedAuthenticatedCredentialReplacementEndpoint),
    AuthenticatedCredentialRemoval(MountedAuthenticatedCredentialRemovalEndpoint),
    AuthenticatedCredentialRegeneration(MountedAuthenticatedCredentialRegenerationEndpoint),
    AuthenticatedCredentialRotation(MountedAuthenticatedCredentialRotationEndpoint),
    DelayedCredentialLifecycle(MountedDelayedCredentialLifecycleEndpoint),
    AuthenticatedOutOfBandIdentifierChange(MountedAuthenticatedOutOfBandIdentifierChangeEndpoint),
    DelayedOutOfBandIdentifierChange(MountedDelayedOutOfBandIdentifierChangeEndpoint),
    DelayedSubjectAuthStateDeletion(MountedDelayedSubjectAuthStateDeletionEndpoint),
    AdminSupport(MountedAdminSupportEndpoint),
}

impl MountedAuthGuardedRoute {
    pub(crate) const fn route_kind_name(&self) -> &'static str {
        match self {
            Self::FullAuthentication(endpoint) => {
                MountedAuthRouteKind::FullAuthentication(*endpoint).route_kind_name()
            }
            Self::NoSessionCredentialRecovery(endpoint) => {
                MountedAuthRouteKind::NoSessionCredentialRecovery(endpoint.endpoint())
                    .route_kind_name()
            }
            Self::AuthenticatedCredentialInventory => {
                MountedAuthRouteKind::AuthenticatedCredentialInventory.route_kind_name()
            }
            Self::AuthenticatedCredentialAddition(_) => {
                MountedAuthRouteKind::AuthenticatedCredentialAddition.route_kind_name()
            }
            Self::AuthenticatedCredentialReset(endpoint) => {
                MountedAuthRouteKind::AuthenticatedCredentialReset(*endpoint).route_kind_name()
            }
            Self::AuthenticatedCredentialReplacement(endpoint) => {
                MountedAuthRouteKind::AuthenticatedCredentialReplacement(*endpoint)
                    .route_kind_name()
            }
            Self::AuthenticatedCredentialRemoval(endpoint) => {
                MountedAuthRouteKind::AuthenticatedCredentialRemoval(*endpoint).route_kind_name()
            }
            Self::AuthenticatedCredentialRegeneration(endpoint) => {
                MountedAuthRouteKind::AuthenticatedCredentialRegeneration(*endpoint)
                    .route_kind_name()
            }
            Self::AuthenticatedCredentialRotation(endpoint) => {
                MountedAuthRouteKind::AuthenticatedCredentialRotation(*endpoint).route_kind_name()
            }
            Self::DelayedCredentialLifecycle(endpoint) => {
                MountedAuthRouteKind::DelayedCredentialLifecycle(*endpoint).route_kind_name()
            }
            Self::AuthenticatedOutOfBandIdentifierChange(endpoint) => {
                MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(*endpoint)
                    .route_kind_name()
            }
            Self::DelayedOutOfBandIdentifierChange(endpoint) => {
                MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(*endpoint).route_kind_name()
            }
            Self::DelayedSubjectAuthStateDeletion(endpoint) => {
                MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(*endpoint).route_kind_name()
            }
            Self::AdminSupport(endpoint) => {
                MountedAuthRouteKind::AdminSupport(*endpoint).route_kind_name()
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MountedAuthRouteGuardedNoSessionRecoveryEndpoint {
    endpoint: MountedNoSessionCredentialRecoveryEndpoint,
}

impl MountedAuthRouteGuardedNoSessionRecoveryEndpoint {
    pub(crate) const fn new(endpoint: MountedNoSessionCredentialRecoveryEndpoint) -> Self {
        Self { endpoint }
    }

    pub(crate) const fn endpoint(self) -> MountedNoSessionCredentialRecoveryEndpoint {
        self.endpoint
    }

    pub(crate) const fn step(self) -> MountedNoSessionCredentialRecoveryRouteStep {
        self.endpoint.step()
    }
}
