use super::*;

/// Mount path for the private WIP auth route service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthRouteMountPath {
    path: String,
}

impl MountedAuthRouteMountPath {
    pub(crate) fn new(path: impl Into<String>) -> Result<Self, MountedAuthRuntimeError> {
        let path = path.into();
        if path.is_empty() {
            return Err(MountedAuthRuntimeError::InvalidRouteMountPath(
                "auth route mount path must not be empty",
            ));
        }
        if !path.starts_with('/') {
            return Err(MountedAuthRuntimeError::InvalidRouteMountPath(
                "auth route mount path must start with '/'",
            ));
        }
        if path.len() > 1 && path.ends_with('/') {
            return Err(MountedAuthRuntimeError::InvalidRouteMountPath(
                "auth route mount path must not end with '/'",
            ));
        }
        if path.contains("//") {
            return Err(MountedAuthRuntimeError::InvalidRouteMountPath(
                "auth route mount path must not contain empty segments",
            ));
        }
        if path != "/" {
            for segment in path.split('/').skip(1) {
                if segment == "." || segment == ".." {
                    return Err(MountedAuthRuntimeError::InvalidRouteMountPath(
                        "auth route mount path must not contain dot segments",
                    ));
                }
                if !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                {
                    return Err(MountedAuthRuntimeError::InvalidRouteMountPath(
                        "auth route mount path segments must contain only ASCII letters, digits, dots, underscores, or hyphens",
                    ));
                }
            }
        }
        Ok(Self { path })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.path
    }

    pub(crate) fn relative_path_for_request_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        if self.path == "/" {
            return Some(path);
        }
        let suffix = path.strip_prefix(&self.path)?;
        if suffix.is_empty() {
            return Some("/");
        }
        suffix.starts_with('/').then_some(suffix)
    }

    fn mounted_path_for_relative_path(&self, relative_path: &str) -> String {
        if self.path == "/" {
            relative_path.to_owned()
        } else {
            format!("{}{}", self.path, relative_path)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthRouteManifest {
    routes: Vec<MountedAuthRouteDescriptor>,
}

impl MountedAuthRouteManifest {
    pub(crate) fn from_config_and_mount_path(
        config: &MountedAuthRuntimeConfig,
        mount_path: &MountedAuthRouteMountPath,
    ) -> Self {
        let mut routes = Vec::new();
        if config.full_authentication_out_of_band_method().is_some() {
            routes.extend(
                MountedFullAuthenticationEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::full_authentication(mount_path, endpoint)
                    }),
            );
        }
        if config.no_session_credential_recovery_flow().is_some() {
            routes.extend(
                MountedNoSessionCredentialRecoveryEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::no_session_credential_recovery(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        routes.extend(config.credential_addition_routes().iter().map(|route| {
            MountedAuthRouteDescriptor::authenticated_credential_addition(mount_path, route)
        }));
        if config.authenticated_credential_inventory_route_enabled() {
            routes.push(MountedAuthRouteDescriptor::authenticated_credential_inventory(mount_path));
        }
        if config.authenticated_credential_reset_routes_enabled() {
            routes.extend(
                MountedAuthenticatedCredentialResetEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::authenticated_credential_reset(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.authenticated_credential_replacement_routes_enabled() {
            routes.extend(
                MountedAuthenticatedCredentialReplacementEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::authenticated_credential_replacement(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.authenticated_credential_removal_routes_enabled() {
            routes.extend(
                MountedAuthenticatedCredentialRemovalEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::authenticated_credential_removal(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.authenticated_credential_regeneration_routes_enabled() {
            routes.extend(
                MountedAuthenticatedCredentialRegenerationEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::authenticated_credential_regeneration(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.authenticated_credential_rotation_routes_enabled() {
            routes.extend(
                MountedAuthenticatedCredentialRotationEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::authenticated_credential_rotation(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.delayed_credential_lifecycle_routes_enabled() {
            routes.extend(
                MountedDelayedCredentialLifecycleEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::delayed_credential_lifecycle(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.authenticated_out_of_band_identifier_change_routes_enabled() {
            routes.extend(
                MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::authenticated_out_of_band_identifier_change(
                            mount_path, endpoint,
                        )
                    }),
            );
            routes.extend(
                MountedDelayedOutOfBandIdentifierChangeEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::delayed_out_of_band_identifier_change(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.delayed_subject_auth_state_deletion_routes_enabled() {
            routes.extend(
                MountedDelayedSubjectAuthStateDeletionEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::delayed_subject_auth_state_deletion(
                            mount_path, endpoint,
                        )
                    }),
            );
        }
        if config.admin_support_routes_enabled() {
            routes.extend(
                MountedAdminSupportEndpoint::all()
                    .into_iter()
                    .map(|endpoint| {
                        MountedAuthRouteDescriptor::admin_support(mount_path, endpoint)
                    }),
            );
        }
        Self { routes }
    }

    pub(crate) fn routes(&self) -> &[MountedAuthRouteDescriptor] {
        &self.routes
    }

    pub(crate) fn descriptor_for_method_and_path(
        &self,
        method: &Method,
        path: &str,
    ) -> Option<&MountedAuthRouteDescriptor> {
        self.routes
            .iter()
            .find(|route| route.method() == method && route.path() == path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAuthRouteDescriptor {
    kind: MountedAuthRouteKind,
    method: Method,
    path: String,
    requires_csrf: bool,
    max_collected_body_bytes: usize,
}

impl MountedAuthRouteDescriptor {
    fn full_authentication(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedFullAuthenticationEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::FullAuthentication(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: false,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn no_session_credential_recovery(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedNoSessionCredentialRecoveryEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::NoSessionCredentialRecovery(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: endpoint.step().requires_csrf(),
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn authenticated_credential_addition(
        mount_path: &MountedAuthRouteMountPath,
        route: &MountedCredentialAdditionRoute,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialAddition,
            method: Method::POST,
            path: mount_path.mounted_path_for_relative_path(&route.relative_path()),
            requires_csrf: true,
            max_collected_body_bytes: MOUNTED_AUTH_HTTP_CREDENTIAL_ADDITION_BODY_MAX_BYTES,
        }
    }

    fn authenticated_credential_inventory(mount_path: &MountedAuthRouteMountPath) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialInventory,
            method: Method::GET,
            path: mount_path
                .mounted_path_for_relative_path(MOUNTED_AUTH_CREDENTIAL_INVENTORY_ROUTE_PATH),
            requires_csrf: false,
            max_collected_body_bytes: 0,
        }
    }

    fn authenticated_credential_reset(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAuthenticatedCredentialResetEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialReset(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn authenticated_credential_replacement(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAuthenticatedCredentialReplacementEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialReplacement(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn authenticated_credential_removal(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAuthenticatedCredentialRemovalEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialRemoval(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn authenticated_credential_regeneration(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAuthenticatedCredentialRegenerationEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialRegeneration(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn authenticated_credential_rotation(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAuthenticatedCredentialRotationEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedCredentialRotation(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn delayed_credential_lifecycle(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedDelayedCredentialLifecycleEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::DelayedCredentialLifecycle(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn authenticated_out_of_band_identifier_change(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAuthenticatedOutOfBandIdentifierChangeEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn delayed_out_of_band_identifier_change(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedDelayedOutOfBandIdentifierChangeEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn delayed_subject_auth_state_deletion(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedDelayedSubjectAuthStateDeletionEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    fn admin_support(
        mount_path: &MountedAuthRouteMountPath,
        endpoint: MountedAdminSupportEndpoint,
    ) -> Self {
        Self {
            kind: MountedAuthRouteKind::AdminSupport(endpoint),
            method: endpoint.method(),
            path: mount_path.mounted_path_for_relative_path(endpoint.path()),
            requires_csrf: true,
            max_collected_body_bytes: endpoint.max_collected_http_body_bytes(),
        }
    }

    pub(crate) const fn kind(&self) -> MountedAuthRouteKind {
        self.kind
    }

    pub(crate) fn method(&self) -> &Method {
        &self.method
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) const fn requires_csrf(&self) -> bool {
        self.requires_csrf
    }

    pub(crate) const fn max_collected_body_bytes(&self) -> usize {
        self.max_collected_body_bytes
    }

    pub(crate) fn guarded_route(
        &self,
        config: &MountedAuthRuntimeConfig,
        mount_path: &MountedAuthRouteMountPath,
    ) -> Option<MountedAuthGuardedRoute> {
        match self.kind {
            MountedAuthRouteKind::FullAuthentication(endpoint) => {
                Some(MountedAuthGuardedRoute::FullAuthentication(endpoint))
            }
            MountedAuthRouteKind::NoSessionCredentialRecovery(endpoint) => {
                Some(MountedAuthGuardedRoute::NoSessionCredentialRecovery(
                    MountedAuthRouteGuardedNoSessionRecoveryEndpoint::new(endpoint),
                ))
            }
            MountedAuthRouteKind::AuthenticatedCredentialInventory => {
                Some(MountedAuthGuardedRoute::AuthenticatedCredentialInventory)
            }
            MountedAuthRouteKind::AuthenticatedCredentialAddition => config
                .credential_addition_routes()
                .iter()
                .find(|route| {
                    self.method == Method::POST
                        && self.path
                            == mount_path.mounted_path_for_relative_path(&route.relative_path())
                })
                .cloned()
                .map(MountedAuthGuardedRoute::AuthenticatedCredentialAddition),
            MountedAuthRouteKind::AuthenticatedCredentialReset(endpoint) => Some(
                MountedAuthGuardedRoute::AuthenticatedCredentialReset(endpoint),
            ),
            MountedAuthRouteKind::AuthenticatedCredentialReplacement(endpoint) => Some(
                MountedAuthGuardedRoute::AuthenticatedCredentialReplacement(endpoint),
            ),
            MountedAuthRouteKind::AuthenticatedCredentialRemoval(endpoint) => Some(
                MountedAuthGuardedRoute::AuthenticatedCredentialRemoval(endpoint),
            ),
            MountedAuthRouteKind::AuthenticatedCredentialRegeneration(endpoint) => {
                Some(MountedAuthGuardedRoute::AuthenticatedCredentialRegeneration(endpoint))
            }
            MountedAuthRouteKind::AuthenticatedCredentialRotation(endpoint) => Some(
                MountedAuthGuardedRoute::AuthenticatedCredentialRotation(endpoint),
            ),
            MountedAuthRouteKind::DelayedCredentialLifecycle(endpoint) => Some(
                MountedAuthGuardedRoute::DelayedCredentialLifecycle(endpoint),
            ),
            MountedAuthRouteKind::AuthenticatedOutOfBandIdentifierChange(endpoint) => {
                Some(MountedAuthGuardedRoute::AuthenticatedOutOfBandIdentifierChange(endpoint))
            }
            MountedAuthRouteKind::DelayedOutOfBandIdentifierChange(endpoint) => Some(
                MountedAuthGuardedRoute::DelayedOutOfBandIdentifierChange(endpoint),
            ),
            MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(endpoint) => Some(
                MountedAuthGuardedRoute::DelayedSubjectAuthStateDeletion(endpoint),
            ),
            MountedAuthRouteKind::AdminSupport(endpoint) => {
                Some(MountedAuthGuardedRoute::AdminSupport(endpoint))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthRouteKind {
    FullAuthentication(MountedFullAuthenticationEndpoint),
    NoSessionCredentialRecovery(MountedNoSessionCredentialRecoveryEndpoint),
    AuthenticatedCredentialInventory,
    AuthenticatedCredentialAddition,
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

impl MountedAuthRouteKind {
    pub(crate) const fn route_kind_name(self) -> &'static str {
        match self {
            Self::FullAuthentication(_) => "full_authentication",
            Self::NoSessionCredentialRecovery(_) => "no_session_credential_recovery",
            Self::AuthenticatedCredentialInventory => "authenticated_credential_inventory",
            Self::AuthenticatedCredentialAddition => "authenticated_credential_addition",
            Self::AuthenticatedCredentialReset(_) => "authenticated_credential_reset",
            Self::AuthenticatedCredentialReplacement(_) => "authenticated_credential_replacement",
            Self::AuthenticatedCredentialRemoval(_) => "authenticated_credential_removal",
            Self::AuthenticatedCredentialRegeneration(_) => "authenticated_credential_regeneration",
            Self::AuthenticatedCredentialRotation(_) => "authenticated_credential_rotation",
            Self::DelayedCredentialLifecycle(_) => "delayed_credential_lifecycle",
            Self::AuthenticatedOutOfBandIdentifierChange(_) => {
                "authenticated_out_of_band_identifier_change"
            }
            Self::DelayedOutOfBandIdentifierChange(_) => "delayed_out_of_band_identifier_change",
            Self::DelayedSubjectAuthStateDeletion(_) => "delayed_subject_auth_state_deletion",
            Self::AdminSupport(_) => "admin_support",
        }
    }
}
