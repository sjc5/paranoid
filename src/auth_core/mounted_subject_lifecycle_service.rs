use http::HeaderMap;

use super::postgres_runtime::{AuthPostgresWebRuntimeExecutionError, PostgresAuthWebRuntime};
use super::prelude::*;

/// Mounted execution workflow for delayed subject lifecycle actions.
pub(crate) struct MountedSubjectLifecyclePostgresService<'a> {
    runtime: &'a PostgresAuthWebRuntime,
}

impl<'a> MountedSubjectLifecyclePostgresService<'a> {
    pub(crate) fn new(runtime: &'a PostgresAuthWebRuntime) -> Self {
        Self { runtime }
    }

    pub(crate) async fn schedule_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: ScheduleMountedSubjectAuthStateDeletionInput,
    ) -> Result<MountedSubjectAuthStateDeletionScheduling, MountedSubjectLifecycleServiceError>
    {
        let runtime_execution = self
            .runtime
            .schedule_authenticated_subject_auth_state_deletion_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectAuthStateDeletionScheduling::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn plan_authenticated_out_of_band_identifier_change_from_headers(
        &self,
        headers: &HeaderMap,
        request: PlanMountedAuthenticatedOutOfBandIdentifierChangeInput,
    ) -> Result<
        MountedOutOfBandIdentifierChangePlanningExecution,
        MountedSubjectLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_out_of_band_identifier_change_planning_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedOutOfBandIdentifierChangePlanningExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_authenticated_out_of_band_identifier_change_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput,
    ) -> Result<MountedOutOfBandIdentifierChangeExecution, MountedSubjectLifecycleServiceError>
    {
        let runtime_execution = self
            .runtime
            .execute_authenticated_out_of_band_identifier_change_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedOutOfBandIdentifierChangeExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_delayed_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedDelayedSubjectAuthStateDeletionInput,
    ) -> Result<MountedSubjectLifecycleServiceExecution, MountedSubjectLifecycleServiceError> {
        let runtime_execution = self
            .runtime
            .execute_mature_pending_subject_auth_state_deletion_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectLifecycleServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedDelayedSubjectAuthStateDeletionInput,
    ) -> Result<MountedSubjectAuthStateDeletionExecution, MountedSubjectLifecycleServiceError> {
        let runtime_execution = self
            .runtime
            .execute_mature_pending_subject_auth_state_deletion_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectAuthStateDeletionExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_delayed_out_of_band_identifier_change_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedDelayedOutOfBandIdentifierChangeInput,
    ) -> Result<MountedSubjectLifecycleServiceExecution, MountedSubjectLifecycleServiceError> {
        let runtime_execution = self
            .runtime
            .execute_mature_pending_out_of_band_identifier_change_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectLifecycleServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn execute_out_of_band_identifier_change_from_pending_action_from_headers(
        &self,
        headers: &HeaderMap,
        request: ExecuteMountedDelayedOutOfBandIdentifierChangeInput,
    ) -> Result<MountedDelayedOutOfBandIdentifierChangeExecution, MountedSubjectLifecycleServiceError>
    {
        let runtime_execution = self
            .runtime
            .execute_mature_pending_out_of_band_identifier_change_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedDelayedOutOfBandIdentifierChangeExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn cancel_delayed_out_of_band_identifier_change_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelMountedDelayedOutOfBandIdentifierChangeInput,
    ) -> Result<MountedSubjectLifecycleServiceExecution, MountedSubjectLifecycleServiceError> {
        let runtime_execution = self
            .runtime
            .execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectLifecycleServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn cancel_out_of_band_identifier_change_from_pending_action_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelMountedDelayedOutOfBandIdentifierChangeInput,
    ) -> Result<
        MountedDelayedOutOfBandIdentifierChangeCancellation,
        MountedSubjectLifecycleServiceError,
    > {
        let runtime_execution = self
            .runtime
            .execute_authenticated_pending_out_of_band_identifier_change_cancellation_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedDelayedOutOfBandIdentifierChangeCancellation::from_runtime_execution(
            runtime_execution,
        )
    }

    pub(crate) async fn cancel_delayed_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelMountedDelayedSubjectAuthStateDeletionInput,
    ) -> Result<MountedSubjectLifecycleServiceExecution, MountedSubjectLifecycleServiceError> {
        let runtime_execution = self
            .runtime
            .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectLifecycleServiceExecution::from_runtime_execution(runtime_execution)
    }

    pub(crate) async fn cancel_subject_auth_state_deletion_from_headers(
        &self,
        headers: &HeaderMap,
        request: CancelMountedDelayedSubjectAuthStateDeletionInput,
    ) -> Result<MountedSubjectAuthStateDeletionCancellation, MountedSubjectLifecycleServiceError>
    {
        let runtime_execution = self
            .runtime
            .execute_authenticated_pending_subject_auth_state_deletion_cancellation_from_headers(
                headers,
                request.runtime_input(),
            )
            .await?;
        MountedSubjectAuthStateDeletionCancellation::from_runtime_execution(runtime_execution)
    }
}

fn project_subject_lifecycle_runtime_execution<O>(
    runtime_execution: AuthWebRuntimeExecution,
    derive_outcome: impl FnOnce(&AuthWebRuntimeExecution) -> Option<O>,
) -> Result<(O, AuthWebRuntimeResponseProjection), MountedSubjectLifecycleServiceError> {
    let outcome = derive_outcome(&runtime_execution)
        .ok_or(MountedSubjectLifecycleServiceError::UnexpectedRuntimeOutcome)?;
    let response_projection =
        AuthWebRuntimeResponseProjection::from_runtime_execution(runtime_execution);
    Ok((outcome, response_projection))
}

/// Completed mounted subject-auth-state deletion scheduling.
#[derive(Debug)]
pub(crate) struct MountedSubjectAuthStateDeletionScheduling {
    outcome: MountedSubjectAuthStateDeletionSchedulingOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedSubjectAuthStateDeletionScheduling {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedSubjectAuthStateDeletionSchedulingOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedSubjectAuthStateDeletionSchedulingOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedSubjectAuthStateDeletionRouteResponseBody {
        MountedSubjectAuthStateDeletionRouteResponseBody::from_scheduling_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedSubjectAuthStateDeletionSchedulingOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated out-of-band identifier change planning.
#[derive(Debug)]
pub(crate) struct MountedOutOfBandIdentifierChangePlanningExecution {
    outcome: MountedOutOfBandIdentifierChangePlanningOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedOutOfBandIdentifierChangePlanningExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedOutOfBandIdentifierChangePlanningOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedOutOfBandIdentifierChangePlanningOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedOutOfBandIdentifierChangeRouteResponseBody {
        MountedOutOfBandIdentifierChangeRouteResponseBody::from_planning_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedOutOfBandIdentifierChangePlanningOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted authenticated immediate out-of-band identifier change.
#[derive(Debug)]
pub(crate) struct MountedOutOfBandIdentifierChangeExecution {
    outcome: MountedOutOfBandIdentifierChangeExecutionOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedOutOfBandIdentifierChangeExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedOutOfBandIdentifierChangeExecutionOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedOutOfBandIdentifierChangeExecutionOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedOutOfBandIdentifierChangeRouteResponseBody {
        MountedOutOfBandIdentifierChangeRouteResponseBody::from_execution_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedOutOfBandIdentifierChangeExecutionOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted delayed subject-auth-state deletion execution.
#[derive(Debug)]
pub(crate) struct MountedSubjectAuthStateDeletionExecution {
    outcome: MountedSubjectAuthStateDeletionExecutionOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedSubjectAuthStateDeletionExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedSubjectAuthStateDeletionExecutionOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedSubjectAuthStateDeletionExecutionOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedSubjectAuthStateDeletionRouteResponseBody {
        MountedSubjectAuthStateDeletionRouteResponseBody::from_execution_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedSubjectAuthStateDeletionExecutionOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted delayed subject-auth-state deletion cancellation.
#[derive(Debug)]
pub(crate) struct MountedSubjectAuthStateDeletionCancellation {
    outcome: MountedSubjectAuthStateDeletionCancellationOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedSubjectAuthStateDeletionCancellation {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedSubjectAuthStateDeletionCancellationOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedSubjectAuthStateDeletionCancellationOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(&self) -> MountedSubjectAuthStateDeletionRouteResponseBody {
        MountedSubjectAuthStateDeletionRouteResponseBody::from_cancellation_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedSubjectAuthStateDeletionCancellationOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted delayed subject lifecycle execution.
#[derive(Debug)]
pub(crate) struct MountedSubjectLifecycleServiceExecution {
    committed_outcome: MountedSubjectLifecycleCommittedOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedSubjectLifecycleServiceExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (committed_outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedSubjectLifecycleCommittedOutcome::from_committed_runtime_execution,
        )?;
        Ok(Self {
            committed_outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn committed_outcome(&self) -> &MountedSubjectLifecycleCommittedOutcome {
        &self.committed_outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }

    #[cfg(test)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        MountedSubjectLifecycleCommittedOutcome,
        AuthWebRuntimeExecution,
    ) {
        (
            self.committed_outcome,
            self.response_projection.into_runtime_execution(),
        )
    }
}

/// Completed mounted delayed out-of-band identifier-change execution.
#[derive(Debug)]
pub(crate) struct MountedDelayedOutOfBandIdentifierChangeExecution {
    outcome: MountedDelayedOutOfBandIdentifierChangeExecutionOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedDelayedOutOfBandIdentifierChangeExecution {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedDelayedOutOfBandIdentifierChangeExecutionOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(&self) -> &MountedDelayedOutOfBandIdentifierChangeExecutionOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(
        &self,
    ) -> MountedDelayedOutOfBandIdentifierChangeRouteResponseBody {
        MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::from_execution_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }
}

/// Completed mounted delayed out-of-band identifier-change cancellation.
#[derive(Debug)]
pub(crate) struct MountedDelayedOutOfBandIdentifierChangeCancellation {
    outcome: MountedDelayedOutOfBandIdentifierChangeCancellationOutcome,
    response_projection: AuthWebRuntimeResponseProjection,
}

impl MountedDelayedOutOfBandIdentifierChangeCancellation {
    fn from_runtime_execution(
        runtime_execution: AuthWebRuntimeExecution,
    ) -> Result<Self, MountedSubjectLifecycleServiceError> {
        let (outcome, response_projection) = project_subject_lifecycle_runtime_execution(
            runtime_execution,
            MountedDelayedOutOfBandIdentifierChangeCancellationOutcome::from_runtime_execution,
        )?;
        Ok(Self {
            outcome,
            response_projection,
        })
    }

    #[cfg(test)]
    pub(crate) const fn outcome(
        &self,
    ) -> &MountedDelayedOutOfBandIdentifierChangeCancellationOutcome {
        &self.outcome
    }

    pub(crate) fn set_cookie_headers(&self) -> &AuthSetCookieHeaders {
        self.response_projection.set_cookie_headers()
    }

    pub(crate) fn route_response_body(
        &self,
    ) -> MountedDelayedOutOfBandIdentifierChangeRouteResponseBody {
        MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::from_cancellation_service_outcome(
            &self.outcome,
        )
    }

    #[cfg(test)]
    pub(crate) const fn runtime_execution(&self) -> &AuthWebRuntimeExecution {
        self.response_projection.runtime_execution()
    }
}

/// Error returned by mounted delayed subject lifecycle execution.
#[derive(Debug)]
pub(crate) enum MountedSubjectLifecycleServiceError {
    Core(Error),
    Runtime(AuthPostgresWebRuntimeExecutionError),
    UnexpectedRuntimeOutcome,
}

impl From<Error> for MountedSubjectLifecycleServiceError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}

impl From<AuthPostgresWebRuntimeExecutionError> for MountedSubjectLifecycleServiceError {
    fn from(error: AuthPostgresWebRuntimeExecutionError) -> Self {
        Self::Runtime(error)
    }
}

impl std::fmt::Display for MountedSubjectLifecycleServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Runtime(error) => write!(f, "{error}"),
            Self::UnexpectedRuntimeOutcome => {
                write!(f, "auth core: unexpected mounted subject lifecycle outcome")
            }
        }
    }
}

impl std::error::Error for MountedSubjectLifecycleServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::UnexpectedRuntimeOutcome => None,
        }
    }
}
