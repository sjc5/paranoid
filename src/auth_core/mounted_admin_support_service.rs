use std::future::Future;
use std::pin::Pin;

use http::HeaderMap;

use super::postgres_runtime::{AuthPostgresWebRuntimeExecutionError, PostgresAuthWebRuntime};
use super::prelude::*;

/// Application callback that authorizes one staff/support action against one candidate.
pub(crate) trait MountedAdminSupportStaffAuthorizer: Send + Sync {
    fn authorize_admin_support_intervention_request<'a>(
        &'a self,
        headers: &'a HeaderMap,
        request: MountedAdminSupportInterventionRequestVerificationRequest,
    ) -> Pin<Box<dyn Future<Output = MountedAdminSupportStaffAuthorization> + Send + 'a>>;

    fn authorize_admin_support_staff_action<'a>(
        &'a self,
        headers: &'a HeaderMap,
        request: MountedAdminSupportStaffVerificationRequest,
    ) -> Pin<Box<dyn Future<Output = MountedAdminSupportStaffAuthorization> + Send + 'a>>;
}

/// Mounted admin/support workflow over the concrete Postgres auth runtime.
pub(crate) struct MountedAdminSupportPostgresService<'a> {
    runtime: &'a PostgresAuthWebRuntime,
}

impl<'a> MountedAdminSupportPostgresService<'a> {
    pub(crate) fn new(runtime: &'a PostgresAuthWebRuntime) -> Self {
        Self { runtime }
    }

    pub(crate) async fn request_intervention_from_headers(
        &self,
        headers: &HeaderMap,
        request: RequestAdminSupportInterventionInput,
    ) -> Result<MountedAdminSupportServiceExecution, MountedAdminSupportServiceError> {
        let execution = self
            .runtime
            .execute_admin_support_intervention_request_from_headers(headers, request)
            .await?;
        MountedAdminSupportServiceExecution::from_runtime_execution(execution)
    }

    pub(crate) async fn approve_intervention_from_headers(
        &self,
        headers: &HeaderMap,
        request: ApproveAdminSupportInterventionInput,
        staff_authorizer: &(dyn MountedAdminSupportStaffAuthorizer + Send + Sync),
    ) -> Result<MountedAdminSupportServiceExecution, MountedAdminSupportServiceError> {
        let staff_request = self
            .runtime
            .mounted_admin_support_approval_staff_verification_request(&request)
            .await?;
        let staff_authorization = staff_authorizer
            .authorize_admin_support_staff_action(headers, staff_request.clone())
            .await;
        let Some(verified_staff_action) =
            MountedAdminSupportVerifiedStaffAction::from_staff_authorization(
                staff_request,
                staff_authorization,
                request.now,
            )
        else {
            return Err(MountedAdminSupportServiceError::StaffAuthorizationRejected);
        };
        let runtime_input = verified_staff_action
            .approve_runtime_input(request.now)
            .ok_or(MountedAdminSupportServiceError::StaffActionDidNotMatchRequestedRuntimeInput)?;
        let execution = self
            .runtime
            .execute_admin_support_intervention_approval_from_headers(headers, runtime_input)
            .await?;
        MountedAdminSupportServiceExecution::from_runtime_execution(execution)
    }

    pub(crate) async fn deny_intervention_from_headers(
        &self,
        headers: &HeaderMap,
        request: DenyAdminSupportInterventionInput,
        staff_authorizer: &(dyn MountedAdminSupportStaffAuthorizer + Send + Sync),
    ) -> Result<MountedAdminSupportServiceExecution, MountedAdminSupportServiceError> {
        let staff_request = self
            .runtime
            .mounted_admin_support_denial_staff_verification_request(&request)
            .await?;
        let staff_authorization = staff_authorizer
            .authorize_admin_support_staff_action(headers, staff_request.clone())
            .await;
        let Some(verified_staff_action) =
            MountedAdminSupportVerifiedStaffAction::from_staff_authorization(
                staff_request,
                staff_authorization,
                request.now,
            )
        else {
            return Err(MountedAdminSupportServiceError::StaffAuthorizationRejected);
        };
        let runtime_input = verified_staff_action
            .deny_runtime_input(request.now)
            .ok_or(MountedAdminSupportServiceError::StaffActionDidNotMatchRequestedRuntimeInput)?;
        let execution = self
            .runtime
            .execute_admin_support_intervention_denial_from_headers(headers, runtime_input)
            .await?;
        MountedAdminSupportServiceExecution::from_runtime_execution(execution)
    }

    pub(crate) async fn expire_intervention_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExpireAdminSupportInterventionInput,
    ) -> Result<MountedAdminSupportServiceExecution, MountedAdminSupportServiceError> {
        let cleanup = self
            .runtime
            .mounted_admin_support_expiry_cleanup_request(&request)
            .await?;
        let execution = self
            .runtime
            .execute_admin_support_intervention_expiry_from_headers(
                headers,
                cleanup.expire_runtime_input(request.now),
            )
            .await?;
        MountedAdminSupportServiceExecution::from_runtime_execution(execution)
    }
}

/// Completed mounted admin/support workflow execution.
#[derive(Debug)]
pub(crate) struct MountedAdminSupportServiceExecution {
    committed_outcome: MountedAdminSupportCommittedOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedAdminSupportServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedAdminSupportServiceError> {
        let committed_outcome =
            MountedAdminSupportCommittedOutcome::from_committed_runtime_execution(
                &runtime_execution,
            )
            .ok_or(MountedAdminSupportServiceError::UnexpectedRuntimeOutcome)?;
        let response_projection =
            AuthWebRuntimeResponseProjection::from_runtime_execution(runtime_execution);
        Ok(Self {
            committed_outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn committed_outcome(&self) -> &MountedAdminSupportCommittedOutcome {
        &self.committed_outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedAdminSupportRouteResponseBody {
        MountedAdminSupportRouteResponseBody::from_service_outcome(&self.committed_outcome)
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (MountedAdminSupportCommittedOutcome, AuthWebRuntimeExecution) {
        (
            self.committed_outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Error returned by mounted admin/support workflow execution.
#[derive(Debug)]
pub(crate) enum MountedAdminSupportServiceError {
    Runtime(AuthPostgresWebRuntimeExecutionError),
    Core(Error),
    StaffAuthorizationRejected,
    StaffActionDidNotMatchRequestedRuntimeInput,
    UnexpectedRuntimeOutcome,
}

impl From<AuthPostgresWebRuntimeExecutionError> for MountedAdminSupportServiceError {
    fn from(error: AuthPostgresWebRuntimeExecutionError) -> Self {
        Self::Runtime(error)
    }
}

impl std::fmt::Display for MountedAdminSupportServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "{error}"),
            Self::Core(error) => write!(f, "{error}"),
            Self::StaffAuthorizationRejected => {
                write!(f, "auth core: staff authorization rejected")
            }
            Self::StaffActionDidNotMatchRequestedRuntimeInput => write!(
                f,
                "auth core: staff action did not match requested runtime input",
            ),
            Self::UnexpectedRuntimeOutcome => {
                write!(f, "auth core: unexpected mounted admin support outcome")
            }
        }
    }
}

impl std::error::Error for MountedAdminSupportServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Core(error) => Some(error),
            Self::StaffAuthorizationRejected
            | Self::StaffActionDidNotMatchRequestedRuntimeInput
            | Self::UnexpectedRuntimeOutcome => None,
        }
    }
}
