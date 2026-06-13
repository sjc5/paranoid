use http::Method;

use super::prelude::*;

/// Mounted input for scheduling delayed subject auth-state deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleMountedSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

impl ScheduleMountedSubjectAuthStateDeletionInput {
    pub(crate) const fn runtime_input(&self) -> ScheduleAuthenticatedSubjectAuthStateDeletionInput {
        ScheduleAuthenticatedSubjectAuthStateDeletionInput { now: self.now }
    }
}

/// Mounted input for executing one matured delayed subject auth-state deletion action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedDelayedSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque pending subject action handle returned by the scheduling transition.
    pub pending_action_id: PendingSubjectLifecycleActionId,
    /// App-owned data action the mounted flow must durably request with auth deletion.
    pub application_subject_data_lifecycle_action: ApplicationSubjectDataLifecycleAction,
}

impl ExecuteMountedDelayedSubjectAuthStateDeletionInput {
    pub(crate) fn runtime_input(&self) -> ExecuteMaturePendingSubjectAuthStateDeletionInput {
        ExecuteMaturePendingSubjectAuthStateDeletionInput {
            now: self.now,
            pending_action_id: self.pending_action_id.clone(),
            application_subject_data_lifecycle_action: Some(
                self.application_subject_data_lifecycle_action,
            ),
        }
    }
}

/// Mounted input for cancelling one open delayed subject auth-state deletion action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CancelMountedDelayedSubjectAuthStateDeletionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque pending subject action handle returned by the scheduling transition.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

impl CancelMountedDelayedSubjectAuthStateDeletionInput {
    pub(crate) fn runtime_input(&self) -> CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
        CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
            now: self.now,
            pending_action_id: self.pending_action_id.clone(),
        }
    }
}

/// Mounted delayed subject-auth-state deletion route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedDelayedSubjectAuthStateDeletionEndpoint {
    /// Schedule delayed subject-auth-state deletion for the current authenticated subject.
    ScheduleDeletion,
    /// Execute one matured delayed subject-auth-state deletion action.
    ExecuteDeletion,
    /// Cancel one open delayed subject-auth-state deletion action.
    CancelDeletion,
}

pub(crate) const MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_SCHEDULE_ROUTE_PATH: &str =
    "/subject-auth-state/delete/schedule";
pub(crate) const MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_EXECUTE_ROUTE_PATH: &str =
    "/subject-auth-state/delete/execute";
pub(crate) const MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_CANCEL_ROUTE_PATH: &str =
    "/subject-auth-state/delete/cancel";

impl MountedDelayedSubjectAuthStateDeletionEndpoint {
    pub(crate) const fn all() -> [Self; 3] {
        [
            Self::ScheduleDeletion,
            Self::ExecuteDeletion,
            Self::CancelDeletion,
        ]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_SCHEDULE_ROUTE_PATH => {
                Some(Self::ScheduleDeletion)
            }
            MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteDeletion)
            }
            MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_CANCEL_ROUTE_PATH => {
                Some(Self::CancelDeletion)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::ScheduleDeletion => {
                MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_SCHEDULE_ROUTE_PATH
            }
            Self::ExecuteDeletion => MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_EXECUTE_ROUTE_PATH,
            Self::CancelDeletion => MOUNTED_DELAYED_SUBJECT_AUTH_STATE_DELETION_CANCEL_ROUTE_PATH,
        }
    }
}

/// Submitted body material accepted by delayed subject-auth-state deletion routes.
#[derive(Debug)]
pub(crate) enum MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody {
    /// Submitted body for delayed deletion scheduling.
    ScheduleDeletion { body: Vec<u8> },
    /// Submitted body for matured deletion execution.
    ExecuteDeletion {
        pending_action_id: Vec<u8>,
        application_subject_data_lifecycle_action: ApplicationSubjectDataLifecycleAction,
    },
    /// Submitted body for deletion cancellation.
    CancelDeletion { pending_action_id: Vec<u8> },
}

impl MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody {
    pub(crate) fn schedule_deletion(body: impl Into<Vec<u8>>) -> Self {
        Self::ScheduleDeletion { body: body.into() }
    }

    pub(crate) fn execute_deletion(
        pending_action_id: impl Into<Vec<u8>>,
        application_subject_data_lifecycle_action: ApplicationSubjectDataLifecycleAction,
    ) -> Self {
        Self::ExecuteDeletion {
            pending_action_id: pending_action_id.into(),
            application_subject_data_lifecycle_action,
        }
    }

    pub(crate) fn cancel_deletion(pending_action_id: impl Into<Vec<u8>>) -> Self {
        Self::CancelDeletion {
            pending_action_id: pending_action_id.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedDelayedSubjectAuthStateDeletionEndpoint {
        match self {
            Self::ScheduleDeletion { .. } => {
                MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion
            }
            Self::ExecuteDeletion { .. } => {
                MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion
            }
            Self::CancelDeletion { .. } => {
                MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedDelayedSubjectAuthStateDeletionRouteRequest, Error> {
        match self {
            Self::ScheduleDeletion { body } => {
                if !body.is_empty() {
                    return Err(Error::NonEmptyMountedSubjectAuthStateDeletionScheduleRouteBody);
                }
                Ok(
                    MountedDelayedSubjectAuthStateDeletionRouteRequest::ScheduleDeletion(
                        ScheduleMountedSubjectAuthStateDeletionInput { now },
                    ),
                )
            }
            Self::ExecuteDeletion {
                pending_action_id,
                application_subject_data_lifecycle_action,
            } => Ok(
                MountedDelayedSubjectAuthStateDeletionRouteRequest::ExecuteDeletion(
                    ExecuteMountedDelayedSubjectAuthStateDeletionInput {
                        now,
                        pending_action_id: PendingSubjectLifecycleActionId::from_bytes(
                            pending_action_id,
                        )?,
                        application_subject_data_lifecycle_action,
                    },
                ),
            ),
            Self::CancelDeletion { pending_action_id } => Ok(
                MountedDelayedSubjectAuthStateDeletionRouteRequest::CancelDeletion(
                    CancelMountedDelayedSubjectAuthStateDeletionInput {
                        now,
                        pending_action_id: PendingSubjectLifecycleActionId::from_bytes(
                            pending_action_id,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted subject-auth-state deletion route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedSubjectAuthStateDeletionRouteRequest {
    /// Schedule delayed subject-auth-state deletion for the current authenticated subject.
    ScheduleDeletion(ScheduleMountedSubjectAuthStateDeletionInput),
    /// Execute one matured delayed subject-auth-state deletion action.
    ExecuteDeletion(ExecuteMountedDelayedSubjectAuthStateDeletionInput),
    /// Cancel one open delayed subject-auth-state deletion action.
    CancelDeletion(CancelMountedDelayedSubjectAuthStateDeletionInput),
}

impl MountedDelayedSubjectAuthStateDeletionRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedDelayedSubjectAuthStateDeletionEndpoint {
        match self {
            Self::ScheduleDeletion(_) => {
                MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion
            }
            Self::ExecuteDeletion(_) => {
                MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion
            }
            Self::CancelDeletion(_) => {
                MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion
            }
        }
    }
}

/// Mounted input for planning an authenticated out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanMountedAuthenticatedOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active identifier source being replaced or superseded.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Proven pending candidate identifier source.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

impl PlanMountedAuthenticatedOutOfBandIdentifierChangeInput {
    pub(crate) fn runtime_input(&self) -> PlanAuthenticatedOutOfBandIdentifierChangeInput {
        PlanAuthenticatedOutOfBandIdentifierChangeInput {
            now: self.now,
            current_identifier_source_id: self.current_identifier_source_id.clone(),
            candidate_identifier_source_id: self.candidate_identifier_source_id.clone(),
        }
    }
}

/// Mounted input for immediately executing an authenticated out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active identifier source being replaced or superseded.
    pub current_identifier_source_id: VerifiedProofSourceId,
    /// Proven pending candidate identifier source.
    pub candidate_identifier_source_id: VerifiedProofSourceId,
}

impl ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput {
    pub(crate) fn runtime_input(&self) -> ExecuteAuthenticatedOutOfBandIdentifierChangeInput {
        ExecuteAuthenticatedOutOfBandIdentifierChangeInput {
            now: self.now,
            current_identifier_source_id: self.current_identifier_source_id.clone(),
            candidate_identifier_source_id: self.candidate_identifier_source_id.clone(),
        }
    }
}

/// Mounted authenticated out-of-band identifier-change route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAuthenticatedOutOfBandIdentifierChangeEndpoint {
    /// Plan a current-to-candidate identifier change for the authenticated subject.
    PlanChange,
    /// Execute an immediately authorized current-to-candidate identifier change.
    ExecuteImmediateChange,
}

pub(crate) const MOUNTED_AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_PLAN_ROUTE_PATH: &str =
    "/out-of-band-identifiers/change/plan";
pub(crate) const MOUNTED_AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_EXECUTE_ROUTE_PATH: &str =
    "/out-of-band-identifiers/change/execute";
pub(crate) const MOUNTED_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_EXECUTE_ROUTE_PATH: &str =
    "/out-of-band-identifiers/change/delayed/execute";
pub(crate) const MOUNTED_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_CANCEL_ROUTE_PATH: &str =
    "/out-of-band-identifiers/change/delayed/cancel";

impl MountedAuthenticatedOutOfBandIdentifierChangeEndpoint {
    pub(crate) const fn all() -> [Self; 2] {
        [Self::PlanChange, Self::ExecuteImmediateChange]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_PLAN_ROUTE_PATH => {
                Some(Self::PlanChange)
            }
            MOUNTED_AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteImmediateChange)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::PlanChange => MOUNTED_AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_PLAN_ROUTE_PATH,
            Self::ExecuteImmediateChange => {
                MOUNTED_AUTHENTICATED_OUT_OF_BAND_IDENTIFIER_CHANGE_EXECUTE_ROUTE_PATH
            }
        }
    }
}

/// Mounted delayed out-of-band identifier-change route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedDelayedOutOfBandIdentifierChangeEndpoint {
    /// Execute one matured delayed identifier-change action.
    ExecuteChange,
    /// Cancel one open delayed identifier-change action.
    CancelChange,
}

impl MountedDelayedOutOfBandIdentifierChangeEndpoint {
    pub(crate) const fn all() -> [Self; 2] {
        [Self::ExecuteChange, Self::CancelChange]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteChange)
            }
            MOUNTED_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_CANCEL_ROUTE_PATH => {
                Some(Self::CancelChange)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::ExecuteChange => MOUNTED_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_EXECUTE_ROUTE_PATH,
            Self::CancelChange => MOUNTED_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_CANCEL_ROUTE_PATH,
        }
    }
}

/// Submitted body material accepted by authenticated out-of-band identifier-change routes.
#[derive(Debug)]
pub(crate) enum MountedAuthenticatedOutOfBandIdentifierChangeSubmittedRouteBody {
    /// Submitted body for planning identifier change.
    PlanChange {
        current_identifier_source_id: Vec<u8>,
        candidate_identifier_source_id: Vec<u8>,
    },
    /// Submitted body for immediate identifier-change execution.
    ExecuteImmediateChange {
        current_identifier_source_id: Vec<u8>,
        candidate_identifier_source_id: Vec<u8>,
    },
}

impl MountedAuthenticatedOutOfBandIdentifierChangeSubmittedRouteBody {
    pub(crate) fn plan_change(
        current_identifier_source_id: impl Into<Vec<u8>>,
        candidate_identifier_source_id: impl Into<Vec<u8>>,
    ) -> Self {
        Self::PlanChange {
            current_identifier_source_id: current_identifier_source_id.into(),
            candidate_identifier_source_id: candidate_identifier_source_id.into(),
        }
    }

    pub(crate) fn execute_immediate_change(
        current_identifier_source_id: impl Into<Vec<u8>>,
        candidate_identifier_source_id: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteImmediateChange {
            current_identifier_source_id: current_identifier_source_id.into(),
            candidate_identifier_source_id: candidate_identifier_source_id.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedOutOfBandIdentifierChangeEndpoint {
        match self {
            Self::PlanChange { .. } => {
                MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
            }
            Self::ExecuteImmediateChange { .. } => {
                MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest, Error> {
        match self {
            Self::PlanChange {
                current_identifier_source_id,
                candidate_identifier_source_id,
            } => Ok(
                MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest::PlanChange(
                    PlanMountedAuthenticatedOutOfBandIdentifierChangeInput {
                        now,
                        current_identifier_source_id: VerifiedProofSourceId::from_bytes(
                            current_identifier_source_id,
                        )?,
                        candidate_identifier_source_id: VerifiedProofSourceId::from_bytes(
                            candidate_identifier_source_id,
                        )?,
                    },
                ),
            ),
            Self::ExecuteImmediateChange {
                current_identifier_source_id,
                candidate_identifier_source_id,
            } => Ok(
                MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest::ExecuteImmediateChange(
                    ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput {
                        now,
                        current_identifier_source_id: VerifiedProofSourceId::from_bytes(
                            current_identifier_source_id,
                        )?,
                        candidate_identifier_source_id: VerifiedProofSourceId::from_bytes(
                            candidate_identifier_source_id,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Submitted body material accepted by delayed out-of-band identifier-change routes.
#[derive(Debug)]
pub(crate) enum MountedDelayedOutOfBandIdentifierChangeSubmittedRouteBody {
    /// Submitted body for matured identifier-change execution.
    ExecuteChange { pending_action_id: Vec<u8> },
    /// Submitted body for identifier-change cancellation.
    CancelChange { pending_action_id: Vec<u8> },
}

impl MountedDelayedOutOfBandIdentifierChangeSubmittedRouteBody {
    pub(crate) fn execute_change(pending_action_id: impl Into<Vec<u8>>) -> Self {
        Self::ExecuteChange {
            pending_action_id: pending_action_id.into(),
        }
    }

    pub(crate) fn cancel_change(pending_action_id: impl Into<Vec<u8>>) -> Self {
        Self::CancelChange {
            pending_action_id: pending_action_id.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedDelayedOutOfBandIdentifierChangeEndpoint {
        match self {
            Self::ExecuteChange { .. } => {
                MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange
            }
            Self::CancelChange { .. } => {
                MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedDelayedOutOfBandIdentifierChangeRouteRequest, Error> {
        match self {
            Self::ExecuteChange { pending_action_id } => Ok(
                MountedDelayedOutOfBandIdentifierChangeRouteRequest::ExecuteChange(
                    ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
                        now,
                        pending_action_id: PendingSubjectLifecycleActionId::from_bytes(
                            pending_action_id,
                        )?,
                    },
                ),
            ),
            Self::CancelChange { pending_action_id } => Ok(
                MountedDelayedOutOfBandIdentifierChangeRouteRequest::CancelChange(
                    CancelMountedDelayedOutOfBandIdentifierChangeInput {
                        now,
                        pending_action_id: PendingSubjectLifecycleActionId::from_bytes(
                            pending_action_id,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted out-of-band identifier-change route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest {
    /// Plan an authenticated out-of-band identifier change.
    PlanChange(PlanMountedAuthenticatedOutOfBandIdentifierChangeInput),
    /// Execute an immediate authenticated out-of-band identifier change.
    ExecuteImmediateChange(ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput),
}

impl MountedAuthenticatedOutOfBandIdentifierChangeRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedOutOfBandIdentifierChangeEndpoint {
        match self {
            Self::PlanChange(_) => {
                MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange
            }
            Self::ExecuteImmediateChange(_) => {
                MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange
            }
        }
    }
}

/// Typed mounted delayed out-of-band identifier-change route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedOutOfBandIdentifierChangeRouteRequest {
    /// Execute one matured delayed identifier-change action.
    ExecuteChange(ExecuteMountedDelayedOutOfBandIdentifierChangeInput),
    /// Cancel one open delayed identifier-change action.
    CancelChange(CancelMountedDelayedOutOfBandIdentifierChangeInput),
}

impl MountedDelayedOutOfBandIdentifierChangeRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedDelayedOutOfBandIdentifierChangeEndpoint {
        match self {
            Self::ExecuteChange(_) => {
                MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange
            }
            Self::CancelChange(_) => MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange,
        }
    }
}

/// Mounted input for executing one matured delayed out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque pending subject action handle returned by the scheduling transition.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

impl ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
    pub(crate) fn runtime_input(&self) -> ExecuteMaturePendingOutOfBandIdentifierChangeInput {
        ExecuteMaturePendingOutOfBandIdentifierChangeInput {
            now: self.now,
            pending_action_id: self.pending_action_id.clone(),
        }
    }
}

/// Mounted input for cancelling one open delayed out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CancelMountedDelayedOutOfBandIdentifierChangeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque pending subject action handle returned by the scheduling transition.
    pub pending_action_id: PendingSubjectLifecycleActionId,
}

impl CancelMountedDelayedOutOfBandIdentifierChangeInput {
    pub(crate) fn runtime_input(&self) -> CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
        CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
            now: self.now,
            pending_action_id: self.pending_action_id.clone(),
        }
    }
}

/// Mounted response surface for delayed out-of-band identifier-change execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedOutOfBandIdentifierChangeExecutionOutcome {
    /// The matured identifier-change action executed.
    OutOfBandIdentifierChangeExecuted {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
}

impl MountedDelayedOutOfBandIdentifierChangeExecutionOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::PendingOutOfBandIdentifierChangeExecuted(outcome) => {
                Some(Self::OutOfBandIdentifierChangeExecuted {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                    current_identifier_source_id: outcome.current_identifier_source_id.clone(),
                    candidate_identifier_source_id: outcome.candidate_identifier_source_id.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Mounted response surface for delayed out-of-band identifier-change cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedOutOfBandIdentifierChangeCancellationOutcome {
    /// The delayed identifier-change action was cancelled.
    OutOfBandIdentifierChangeCancelled {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before cancelling identifier change.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedDelayedOutOfBandIdentifierChangeCancellationOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::PendingOutOfBandIdentifierChangeCancelled(outcome) => {
                Some(Self::OutOfBandIdentifierChangeCancelled {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                    current_identifier_source_id: outcome.current_identifier_source_id.clone(),
                    candidate_identifier_source_id: outcome.candidate_identifier_source_id.clone(),
                })
            }
            Outcome::NeedsFullAuthentication => Some(Self::NeedsFullAuthentication),
            Outcome::NeedsStepUp {
                session_id,
                subject_id,
            } => Some(Self::NeedsStepUp {
                session_id: session_id.clone(),
                subject_id: subject_id.clone(),
            }),
            _ => None,
        }
    }
}

/// User-visible route body for delayed out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedOutOfBandIdentifierChangeRouteResponseBody {
    /// The matured identifier-change action executed.
    IdentifierChanged,
    /// The delayed identifier-change action was cancelled.
    IdentifierChangeCancelled,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before cancelling identifier change.
    NeedsStepUp,
}

impl MountedDelayedOutOfBandIdentifierChangeRouteResponseBody {
    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedDelayedOutOfBandIdentifierChangeExecutionOutcome,
    ) -> Self {
        match outcome {
            MountedDelayedOutOfBandIdentifierChangeExecutionOutcome::OutOfBandIdentifierChangeExecuted {
                ..
            } => Self::IdentifierChanged,
        }
    }

    pub(crate) fn from_cancellation_service_outcome(
        outcome: &MountedDelayedOutOfBandIdentifierChangeCancellationOutcome,
    ) -> Self {
        match outcome {
            MountedDelayedOutOfBandIdentifierChangeCancellationOutcome::OutOfBandIdentifierChangeCancelled {
                ..
            } => Self::IdentifierChangeCancelled,
            MountedDelayedOutOfBandIdentifierChangeCancellationOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedDelayedOutOfBandIdentifierChangeCancellationOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for authenticated out-of-band identifier change planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedOutOfBandIdentifierChangePlanningOutcome {
    /// Identifier change may execute immediately in the current ceremony.
    AuthorizedImmediate {
        subject_id: SubjectId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
    /// Identifier change must wait until the pending action matures.
    PendingActionCreated {
        subject_id: SubjectId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
        pending_action_id: PendingSubjectLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before planning identifier change.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedOutOfBandIdentifierChangePlanningOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::OutOfBandIdentifierChangePlanned(
                OutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate {
                    subject_id,
                    current_identifier_source_id,
                    candidate_identifier_source_id,
                },
            ) => Some(Self::AuthorizedImmediate {
                subject_id: subject_id.clone(),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
            }),
            Outcome::OutOfBandIdentifierChangePlanned(
                OutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
                    subject_id,
                    current_identifier_source_id,
                    candidate_identifier_source_id,
                    pending_action_id,
                    earliest_execute_at,
                    expires_at,
                },
            ) => Some(Self::PendingActionCreated {
                subject_id: subject_id.clone(),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            }),
            Outcome::NeedsFullAuthentication => Some(Self::NeedsFullAuthentication),
            Outcome::NeedsStepUp {
                session_id,
                subject_id,
            } => Some(Self::NeedsStepUp {
                session_id: session_id.clone(),
                subject_id: subject_id.clone(),
            }),
            _ => None,
        }
    }
}

/// Mounted response surface for authenticated immediate out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedOutOfBandIdentifierChangeExecutionOutcome {
    /// Identifier change executed and existing subject auth state was revoked.
    IdentifierChanged {
        subject_id: SubjectId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before executing identifier change.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedOutOfBandIdentifierChangeExecutionOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::OutOfBandIdentifierChanged(outcome) => Some(Self::IdentifierChanged {
                subject_id: outcome.subject_id.clone(),
                current_identifier_source_id: outcome.current_identifier_source_id.clone(),
                candidate_identifier_source_id: outcome.candidate_identifier_source_id.clone(),
            }),
            Outcome::NeedsFullAuthentication => Some(Self::NeedsFullAuthentication),
            Outcome::NeedsStepUp {
                session_id,
                subject_id,
            } => Some(Self::NeedsStepUp {
                session_id: session_id.clone(),
                subject_id: subject_id.clone(),
            }),
            _ => None,
        }
    }
}

/// User-visible route body for authenticated out-of-band identifier change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedOutOfBandIdentifierChangeRouteResponseBody {
    /// Identifier change was authorized for immediate execution.
    IdentifierChangeAuthorizedImmediate,
    /// Identifier change was scheduled as a delayed pending action.
    DelayedIdentifierChangeScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Identifier change executed after commit.
    IdentifierChanged,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before changing the identifier.
    NeedsStepUp,
}

impl MountedOutOfBandIdentifierChangeRouteResponseBody {
    pub(crate) fn from_planning_service_outcome(
        outcome: &MountedOutOfBandIdentifierChangePlanningOutcome,
    ) -> Self {
        match outcome {
            MountedOutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate { .. } => {
                Self::IdentifierChangeAuthorizedImmediate
            }
            MountedOutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedIdentifierChangeScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedOutOfBandIdentifierChangePlanningOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedOutOfBandIdentifierChangePlanningOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }

    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedOutOfBandIdentifierChangeExecutionOutcome,
    ) -> Self {
        match outcome {
            MountedOutOfBandIdentifierChangeExecutionOutcome::IdentifierChanged { .. } => {
                Self::IdentifierChanged
            }
            MountedOutOfBandIdentifierChangeExecutionOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedOutOfBandIdentifierChangeExecutionOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for delayed subject-auth-state deletion scheduling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedSubjectAuthStateDeletionSchedulingOutcome {
    /// The delayed subject auth-state deletion action was scheduled.
    SubjectAuthStateDeletionScheduled {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before scheduling deletion.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedSubjectAuthStateDeletionSchedulingOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::SubjectAuthStateDeletionScheduled(outcome) => {
                Some(Self::SubjectAuthStateDeletionScheduled {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                    earliest_execute_at: outcome.earliest_execute_at,
                    expires_at: outcome.expires_at,
                })
            }
            Outcome::NeedsFullAuthentication => Some(Self::NeedsFullAuthentication),
            Outcome::NeedsStepUp {
                session_id,
                subject_id,
            } => Some(Self::NeedsStepUp {
                session_id: session_id.clone(),
                subject_id: subject_id.clone(),
            }),
            _ => None,
        }
    }
}

/// Mounted response surface for delayed subject-auth-state deletion execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedSubjectAuthStateDeletionExecutionOutcome {
    /// The matured subject auth-state deletion action executed.
    SubjectAuthStateDeleted {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
    },
}

impl MountedSubjectAuthStateDeletionExecutionOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::PendingSubjectAuthStateDeletionExecuted(outcome) => {
                Some(Self::SubjectAuthStateDeleted {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Mounted response surface for delayed subject-auth-state deletion cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedSubjectAuthStateDeletionCancellationOutcome {
    /// The delayed subject auth-state deletion action was cancelled.
    SubjectAuthStateDeletionCancelled {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before cancelling deletion.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedSubjectAuthStateDeletionCancellationOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::PendingSubjectAuthStateDeletionCancelled(outcome) => {
                Some(Self::SubjectAuthStateDeletionCancelled {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                })
            }
            Outcome::NeedsFullAuthentication => Some(Self::NeedsFullAuthentication),
            Outcome::NeedsStepUp {
                session_id,
                subject_id,
            } => Some(Self::NeedsStepUp {
                session_id: session_id.clone(),
                subject_id: subject_id.clone(),
            }),
            _ => None,
        }
    }
}

/// User-visible route body for delayed subject-auth-state deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedSubjectAuthStateDeletionRouteResponseBody {
    /// Delayed subject auth-state deletion was scheduled.
    SubjectAuthStateDeletionScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// The matured subject auth-state deletion action executed.
    SubjectAuthStateDeleted,
    /// The delayed subject auth-state deletion action was cancelled.
    SubjectAuthStateDeletionCancelled,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before mutating subject deletion state.
    NeedsStepUp,
}

impl MountedSubjectAuthStateDeletionRouteResponseBody {
    pub(crate) fn from_scheduling_service_outcome(
        outcome: &MountedSubjectAuthStateDeletionSchedulingOutcome,
    ) -> Self {
        match outcome {
            MountedSubjectAuthStateDeletionSchedulingOutcome::SubjectAuthStateDeletionScheduled {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::SubjectAuthStateDeletionScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedSubjectAuthStateDeletionSchedulingOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedSubjectAuthStateDeletionSchedulingOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }

    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedSubjectAuthStateDeletionExecutionOutcome,
    ) -> Self {
        match outcome {
            MountedSubjectAuthStateDeletionExecutionOutcome::SubjectAuthStateDeleted { .. } => {
                Self::SubjectAuthStateDeleted
            }
        }
    }

    pub(crate) fn from_cancellation_service_outcome(
        outcome: &MountedSubjectAuthStateDeletionCancellationOutcome,
    ) -> Self {
        match outcome {
            MountedSubjectAuthStateDeletionCancellationOutcome::SubjectAuthStateDeletionCancelled {
                ..
            } => Self::SubjectAuthStateDeletionCancelled,
            MountedSubjectAuthStateDeletionCancellationOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedSubjectAuthStateDeletionCancellationOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for committed delayed subject lifecycle work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedSubjectLifecycleCommittedOutcome {
    /// A delayed subject auth-state deletion was scheduled.
    SubjectAuthStateDeletionScheduled {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// A delayed subject auth-state deletion executed.
    SubjectAuthStateDeletionExecuted {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
    },
    /// A delayed subject auth-state deletion was cancelled.
    SubjectAuthStateDeletionCancelled {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
    },
    /// A delayed out-of-band identifier change executed.
    OutOfBandIdentifierChangeExecuted {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
    /// A delayed out-of-band identifier change was cancelled.
    OutOfBandIdentifierChangeCancelled {
        subject_id: SubjectId,
        pending_action_id: PendingSubjectLifecycleActionId,
        current_identifier_source_id: VerifiedProofSourceId,
        candidate_identifier_source_id: VerifiedProofSourceId,
    },
}

impl MountedSubjectLifecycleCommittedOutcome {
    pub(crate) fn from_committed_runtime_execution(
        execution: &AuthWebRuntimeExecution,
    ) -> Option<Self> {
        Self::from_committed_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_committed_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::SubjectAuthStateDeletionScheduled(outcome) => {
                Some(Self::SubjectAuthStateDeletionScheduled {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                    earliest_execute_at: outcome.earliest_execute_at,
                    expires_at: outcome.expires_at,
                })
            }
            Outcome::PendingSubjectAuthStateDeletionExecuted(outcome) => {
                Some(Self::SubjectAuthStateDeletionExecuted {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                })
            }
            Outcome::PendingSubjectAuthStateDeletionCancelled(outcome) => {
                Some(Self::SubjectAuthStateDeletionCancelled {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                })
            }
            Outcome::PendingOutOfBandIdentifierChangeExecuted(outcome) => {
                Some(Self::OutOfBandIdentifierChangeExecuted {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                    current_identifier_source_id: outcome.current_identifier_source_id.clone(),
                    candidate_identifier_source_id: outcome.candidate_identifier_source_id.clone(),
                })
            }
            Outcome::PendingOutOfBandIdentifierChangeCancelled(outcome) => {
                Some(Self::OutOfBandIdentifierChangeCancelled {
                    subject_id: outcome.subject_id.clone(),
                    pending_action_id: outcome.pending_action_id.clone(),
                    current_identifier_source_id: outcome.current_identifier_source_id.clone(),
                    candidate_identifier_source_id: outcome.candidate_identifier_source_id.clone(),
                })
            }
            _ => None,
        }
    }
}
