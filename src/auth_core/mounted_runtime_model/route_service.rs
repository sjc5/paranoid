use super::*;

/// Private mounted auth route service over all configured auth endpoints.
#[derive(Clone)]
pub(super) struct MountedAuthPostgresRouteService<'a> {
    pub(super) services: MountedAuthPostgresServices<'a>,
    pub(super) mount_path: MountedAuthRouteMountPath,
}

impl<'a> MountedAuthPostgresRouteService<'a> {
    pub(super) const fn new(
        services: MountedAuthPostgresServices<'a>,
        mount_path: MountedAuthRouteMountPath,
    ) -> Self {
        Self {
            services,
            mount_path,
        }
    }

    pub(super) fn route_manifest(&self) -> MountedAuthRouteManifest {
        MountedAuthRouteManifest::from_config_and_mount_path(
            self.services.config(),
            &self.mount_path,
        )
    }

    pub(super) fn into_http_service(self) -> MountedAuthPostgresHttpService<'a> {
        MountedAuthPostgresHttpService::new(
            self,
            MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES,
            MountedAuthHttpNowSource::System,
        )
    }
}
