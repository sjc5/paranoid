use http::Method;

use super::prelude::*;

/// Mounted admin/support route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAdminSupportEndpoint {
    /// Request one scoped admin/support intervention candidate.
    RequestIntervention,
    /// Approve one open admin/support intervention candidate.
    ApproveIntervention,
    /// Deny one open admin/support intervention candidate.
    DenyIntervention,
    /// Expire one already-expired admin/support intervention candidate.
    ExpireIntervention,
}

pub(crate) const MOUNTED_ADMIN_SUPPORT_REQUEST_ROUTE_PATH: &str =
    "/admin-support/interventions/request";
pub(crate) const MOUNTED_ADMIN_SUPPORT_APPROVE_ROUTE_PATH: &str =
    "/admin-support/interventions/approve";
pub(crate) const MOUNTED_ADMIN_SUPPORT_DENY_ROUTE_PATH: &str = "/admin-support/interventions/deny";
pub(crate) const MOUNTED_ADMIN_SUPPORT_EXPIRE_ROUTE_PATH: &str =
    "/admin-support/interventions/expire";

impl MountedAdminSupportEndpoint {
    pub(crate) const fn all() -> [Self; 4] {
        [
            Self::RequestIntervention,
            Self::ApproveIntervention,
            Self::DenyIntervention,
            Self::ExpireIntervention,
        ]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_ADMIN_SUPPORT_REQUEST_ROUTE_PATH => Some(Self::RequestIntervention),
            MOUNTED_ADMIN_SUPPORT_APPROVE_ROUTE_PATH => Some(Self::ApproveIntervention),
            MOUNTED_ADMIN_SUPPORT_DENY_ROUTE_PATH => Some(Self::DenyIntervention),
            MOUNTED_ADMIN_SUPPORT_EXPIRE_ROUTE_PATH => Some(Self::ExpireIntervention),
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::RequestIntervention => MOUNTED_ADMIN_SUPPORT_REQUEST_ROUTE_PATH,
            Self::ApproveIntervention => MOUNTED_ADMIN_SUPPORT_APPROVE_ROUTE_PATH,
            Self::DenyIntervention => MOUNTED_ADMIN_SUPPORT_DENY_ROUTE_PATH,
            Self::ExpireIntervention => MOUNTED_ADMIN_SUPPORT_EXPIRE_ROUTE_PATH,
        }
    }
}

/// Staff/support authorization request for creating a new intervention candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAdminSupportInterventionRequestVerificationRequest {
    subject_id: SubjectId,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
    requested_at: UnixSeconds,
}

impl MountedAdminSupportInterventionRequestVerificationRequest {
    pub(crate) fn new(request: &RequestAdminSupportInterventionInput) -> Self {
        Self {
            subject_id: request.subject_id.clone(),
            target_credential_instance_id: request.target_credential_instance_id.clone(),
            action: request.action,
            requested_at: request.now,
        }
    }

    pub(crate) const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    pub(crate) const fn target_credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.target_credential_instance_id
    }

    pub(crate) const fn action(&self) -> CredentialLifecycleAction {
        self.action
    }

    pub(crate) const fn requested_at(&self) -> UnixSeconds {
        self.requested_at
    }
}

/// Staff/support action requested against a stored intervention candidate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAdminSupportStaffAction {
    /// Approve the intervention and let Paranoid enter lifecycle policy.
    ApproveIntervention,
    /// Deny the intervention without mutating credentials.
    DenyIntervention,
}

/// Stored intervention facts presented to an application staff-authorization callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAdminSupportInterventionCandidate {
    intervention_id: AdminSupportInterventionId,
    subject_id: SubjectId,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
    requested_at: UnixSeconds,
    expires_at: UnixSeconds,
}

impl MountedAdminSupportInterventionCandidate {
    fn from_open_intervention_for_staff_action(
        intervention: &AdminSupportInterventionRecord,
        staff_action: MountedAdminSupportStaffAction,
        now: UnixSeconds,
    ) -> Result<Self, Error> {
        if !intervention.is_open_at(now) {
            return Err(match staff_action {
                MountedAdminSupportStaffAction::ApproveIntervention => {
                    Error::AdminSupportInterventionNotApprovable
                }
                MountedAdminSupportStaffAction::DenyIntervention => {
                    Error::AdminSupportInterventionNotDeniable
                }
            });
        }
        Ok(Self {
            intervention_id: intervention.intervention_id.clone(),
            subject_id: intervention.subject_id.clone(),
            target_credential_instance_id: intervention.target_credential_instance_id.clone(),
            action: intervention.action,
            requested_at: intervention.requested_at,
            expires_at: intervention.expires_at,
        })
    }

    pub(crate) const fn intervention_id(&self) -> &AdminSupportInterventionId {
        &self.intervention_id
    }

    pub(crate) const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    pub(crate) const fn target_credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.target_credential_instance_id
    }

    pub(crate) const fn action(&self) -> CredentialLifecycleAction {
        self.action
    }

    pub(crate) const fn requested_at(&self) -> UnixSeconds {
        self.requested_at
    }

    pub(crate) const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }
}

/// Callback input for app-owned staff/support authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAdminSupportStaffVerificationRequest {
    candidate: MountedAdminSupportInterventionCandidate,
    staff_action: MountedAdminSupportStaffAction,
    requested_at: UnixSeconds,
}

impl MountedAdminSupportStaffVerificationRequest {
    pub(crate) fn for_open_intervention_approval(
        intervention: &AdminSupportInterventionRecord,
        now: UnixSeconds,
    ) -> Result<Self, Error> {
        Self::for_open_intervention(
            intervention,
            MountedAdminSupportStaffAction::ApproveIntervention,
            now,
        )
    }

    pub(crate) fn for_open_intervention_denial(
        intervention: &AdminSupportInterventionRecord,
        now: UnixSeconds,
    ) -> Result<Self, Error> {
        Self::for_open_intervention(
            intervention,
            MountedAdminSupportStaffAction::DenyIntervention,
            now,
        )
    }

    fn for_open_intervention(
        intervention: &AdminSupportInterventionRecord,
        staff_action: MountedAdminSupportStaffAction,
        now: UnixSeconds,
    ) -> Result<Self, Error> {
        Ok(Self {
            candidate:
                MountedAdminSupportInterventionCandidate::from_open_intervention_for_staff_action(
                    intervention,
                    staff_action,
                    now,
                )?,
            staff_action,
            requested_at: now,
        })
    }

    pub(crate) const fn candidate(&self) -> &MountedAdminSupportInterventionCandidate {
        &self.candidate
    }

    pub(crate) const fn staff_action(&self) -> MountedAdminSupportStaffAction {
        self.staff_action
    }

    pub(crate) const fn requested_at(&self) -> UnixSeconds {
        self.requested_at
    }
}

/// Result returned by an app-owned staff/support authorization callback.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAdminSupportStaffAuthorization {
    /// The app authorizes this staff/support actor to perform the requested action.
    Authorized,
    /// The app does not authorize this staff/support actor to perform the requested action.
    Rejected,
}

/// Staff authorization that Paranoid has scoped to one stored intervention candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAdminSupportVerifiedStaffAction {
    candidate: MountedAdminSupportInterventionCandidate,
    staff_action: MountedAdminSupportStaffAction,
    verified_at: UnixSeconds,
}

impl MountedAdminSupportVerifiedStaffAction {
    pub(crate) fn from_staff_authorization(
        request: MountedAdminSupportStaffVerificationRequest,
        authorization: MountedAdminSupportStaffAuthorization,
        verified_at: UnixSeconds,
    ) -> Option<Self> {
        match authorization {
            MountedAdminSupportStaffAuthorization::Authorized => Some(Self {
                candidate: request.candidate,
                staff_action: request.staff_action,
                verified_at,
            }),
            MountedAdminSupportStaffAuthorization::Rejected => None,
        }
    }

    pub(crate) const fn candidate(&self) -> &MountedAdminSupportInterventionCandidate {
        &self.candidate
    }

    pub(crate) const fn staff_action(&self) -> MountedAdminSupportStaffAction {
        self.staff_action
    }

    pub(crate) const fn verified_at(&self) -> UnixSeconds {
        self.verified_at
    }

    pub(crate) fn approve_runtime_input(
        &self,
        now: UnixSeconds,
    ) -> Option<ApproveAdminSupportInterventionInput> {
        matches!(
            self.staff_action,
            MountedAdminSupportStaffAction::ApproveIntervention
        )
        .then(|| ApproveAdminSupportInterventionInput {
            now,
            intervention_id: self.candidate.intervention_id.clone(),
        })
    }

    pub(crate) fn deny_runtime_input(
        &self,
        now: UnixSeconds,
    ) -> Option<DenyAdminSupportInterventionInput> {
        matches!(
            self.staff_action,
            MountedAdminSupportStaffAction::DenyIntervention
        )
        .then(|| DenyAdminSupportInterventionInput {
            now,
            intervention_id: self.candidate.intervention_id.clone(),
        })
    }
}

/// Expiry cleanup input derived from an already-expired intervention candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedAdminSupportExpiryCleanupRequest {
    intervention_id: AdminSupportInterventionId,
    subject_id: SubjectId,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
    expired_at: UnixSeconds,
}

impl MountedAdminSupportExpiryCleanupRequest {
    pub(crate) fn from_expired_open_intervention(
        intervention: &AdminSupportInterventionRecord,
        now: UnixSeconds,
    ) -> Result<Self, Error> {
        if !intervention.is_expired_open_at(now) {
            return Err(Error::AdminSupportInterventionNotExpirable);
        }
        Ok(Self {
            intervention_id: intervention.intervention_id.clone(),
            subject_id: intervention.subject_id.clone(),
            target_credential_instance_id: intervention.target_credential_instance_id.clone(),
            action: intervention.action,
            expired_at: now,
        })
    }

    pub(crate) const fn intervention_id(&self) -> &AdminSupportInterventionId {
        &self.intervention_id
    }

    pub(crate) const fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    pub(crate) const fn target_credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.target_credential_instance_id
    }

    pub(crate) const fn action(&self) -> CredentialLifecycleAction {
        self.action
    }

    pub(crate) const fn expired_at(&self) -> UnixSeconds {
        self.expired_at
    }

    pub(crate) fn expire_runtime_input(
        &self,
        now: UnixSeconds,
    ) -> ExpireAdminSupportInterventionInput {
        ExpireAdminSupportInterventionInput {
            now,
            intervention_id: self.intervention_id.clone(),
        }
    }
}

/// Mounted response surface for committed admin/support workflow outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAdminSupportCommittedOutcome {
    /// Intervention candidate was accepted and stored.
    InterventionRequested {
        intervention_id: AdminSupportInterventionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        expires_at: UnixSeconds,
    },
    /// Support approval authorized immediate follow-on lifecycle work.
    ApprovalAuthorizedImmediate {
        intervention_id: AdminSupportInterventionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    },
    /// Support approval scheduled delayed lifecycle work.
    ApprovalScheduledDelayedAction {
        intervention_id: AdminSupportInterventionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Intervention was denied and closed without credential mutation.
    InterventionDenied {
        intervention_id: AdminSupportInterventionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    },
    /// Intervention was expired and closed without credential mutation.
    InterventionExpired {
        intervention_id: AdminSupportInterventionId,
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
    },
}

impl MountedAdminSupportCommittedOutcome {
    pub(crate) fn from_committed_runtime_execution(
        execution: &AuthWebRuntimeExecution,
    ) -> Option<Self> {
        Self::from_committed_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_committed_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::AdminSupportInterventionRequested(outcome) => {
                Some(Self::InterventionRequested {
                    intervention_id: outcome.intervention_id.clone(),
                    subject_id: outcome.subject_id.clone(),
                    target_credential_instance_id: outcome.target_credential_instance_id.clone(),
                    action: outcome.action,
                    expires_at: outcome.expires_at,
                })
            }
            Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
                AdminSupportCredentialLifecycleInterventionOutcome::AuthorizedImmediate {
                    intervention_id,
                    subject_id,
                    target_credential_instance_id,
                    action,
                },
            ) => Some(Self::ApprovalAuthorizedImmediate {
                intervention_id: intervention_id.clone(),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
                action: *action,
            }),
            Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
                AdminSupportCredentialLifecycleInterventionOutcome::PendingActionCreated {
                    intervention_id,
                    subject_id,
                    target_credential_instance_id,
                    action,
                    pending_action_id,
                    earliest_execute_at,
                    expires_at,
                },
            ) => Some(Self::ApprovalScheduledDelayedAction {
                intervention_id: intervention_id.clone(),
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
                action: *action,
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            }),
            Outcome::AdminSupportInterventionDenied(outcome) => Some(Self::InterventionDenied {
                intervention_id: outcome.intervention_id.clone(),
                subject_id: outcome.subject_id.clone(),
                target_credential_instance_id: outcome.target_credential_instance_id.clone(),
                action: outcome.action,
            }),
            Outcome::AdminSupportInterventionExpired(outcome) => Some(Self::InterventionExpired {
                intervention_id: outcome.intervention_id.clone(),
                subject_id: outcome.subject_id.clone(),
                target_credential_instance_id: outcome.target_credential_instance_id.clone(),
                action: outcome.action,
            }),
            _ => None,
        }
    }
}

/// Submitted body material accepted by mounted admin/support routes.
#[derive(Debug)]
pub(crate) enum MountedAdminSupportSubmittedRouteBody {
    /// Submitted body for intervention candidate creation.
    RequestIntervention {
        subject_id: Vec<u8>,
        target_credential_instance_id: Vec<u8>,
        action: CredentialLifecycleAction,
    },
    /// Submitted body for intervention approval.
    ApproveIntervention { intervention_id: Vec<u8> },
    /// Submitted body for intervention denial.
    DenyIntervention { intervention_id: Vec<u8> },
    /// Submitted body for intervention expiry cleanup.
    ExpireIntervention { intervention_id: Vec<u8> },
}

impl MountedAdminSupportSubmittedRouteBody {
    pub(crate) fn request_intervention(
        subject_id: impl Into<Vec<u8>>,
        target_credential_instance_id: impl Into<Vec<u8>>,
        action: CredentialLifecycleAction,
    ) -> Self {
        Self::RequestIntervention {
            subject_id: subject_id.into(),
            target_credential_instance_id: target_credential_instance_id.into(),
            action,
        }
    }

    pub(crate) fn approve_intervention(intervention_id: impl Into<Vec<u8>>) -> Self {
        Self::ApproveIntervention {
            intervention_id: intervention_id.into(),
        }
    }

    pub(crate) fn deny_intervention(intervention_id: impl Into<Vec<u8>>) -> Self {
        Self::DenyIntervention {
            intervention_id: intervention_id.into(),
        }
    }

    pub(crate) fn expire_intervention(intervention_id: impl Into<Vec<u8>>) -> Self {
        Self::ExpireIntervention {
            intervention_id: intervention_id.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAdminSupportEndpoint {
        match self {
            Self::RequestIntervention { .. } => MountedAdminSupportEndpoint::RequestIntervention,
            Self::ApproveIntervention { .. } => MountedAdminSupportEndpoint::ApproveIntervention,
            Self::DenyIntervention { .. } => MountedAdminSupportEndpoint::DenyIntervention,
            Self::ExpireIntervention { .. } => MountedAdminSupportEndpoint::ExpireIntervention,
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAdminSupportRouteRequest, Error> {
        match self {
            Self::RequestIntervention {
                subject_id,
                target_credential_instance_id,
                action,
            } => Ok(MountedAdminSupportRouteRequest::RequestIntervention(
                RequestAdminSupportInterventionInput {
                    now,
                    subject_id: SubjectId::from_bytes(subject_id)?,
                    target_credential_instance_id: VerifiedProofSourceId::from_bytes(
                        target_credential_instance_id,
                    )?,
                    action,
                },
            )),
            Self::ApproveIntervention { intervention_id } => {
                Ok(MountedAdminSupportRouteRequest::ApproveIntervention(
                    ApproveAdminSupportInterventionInput {
                        now,
                        intervention_id: AdminSupportInterventionId::from_bytes(intervention_id)?,
                    },
                ))
            }
            Self::DenyIntervention { intervention_id } => {
                Ok(MountedAdminSupportRouteRequest::DenyIntervention(
                    DenyAdminSupportInterventionInput {
                        now,
                        intervention_id: AdminSupportInterventionId::from_bytes(intervention_id)?,
                    },
                ))
            }
            Self::ExpireIntervention { intervention_id } => {
                Ok(MountedAdminSupportRouteRequest::ExpireIntervention(
                    ExpireAdminSupportInterventionInput {
                        now,
                        intervention_id: AdminSupportInterventionId::from_bytes(intervention_id)?,
                    },
                ))
            }
        }
    }
}

/// Typed mounted admin/support route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAdminSupportRouteRequest {
    /// Request one scoped intervention candidate.
    RequestIntervention(RequestAdminSupportInterventionInput),
    /// Approve one scoped intervention candidate.
    ApproveIntervention(ApproveAdminSupportInterventionInput),
    /// Deny one scoped intervention candidate.
    DenyIntervention(DenyAdminSupportInterventionInput),
    /// Expire one scoped intervention candidate.
    ExpireIntervention(ExpireAdminSupportInterventionInput),
}

impl MountedAdminSupportRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAdminSupportEndpoint {
        match self {
            Self::RequestIntervention(_) => MountedAdminSupportEndpoint::RequestIntervention,
            Self::ApproveIntervention(_) => MountedAdminSupportEndpoint::ApproveIntervention,
            Self::DenyIntervention(_) => MountedAdminSupportEndpoint::DenyIntervention,
            Self::ExpireIntervention(_) => MountedAdminSupportEndpoint::ExpireIntervention,
        }
    }
}

/// User-visible body returned by mounted admin/support routes.
#[derive(Debug)]
pub(crate) enum MountedAdminSupportRouteResponseBody {
    /// Intervention candidate was accepted and stored.
    InterventionRequested {
        intervention_handle: Vec<u8>,
        expires_at: UnixSeconds,
    },
    /// Support approval authorized immediate follow-on lifecycle work.
    ApprovalAuthorizedImmediate,
    /// Support approval scheduled delayed lifecycle work.
    ApprovalScheduledDelayedAction {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Intervention was denied and closed without credential mutation.
    InterventionDenied,
    /// Intervention was expired and closed without credential mutation.
    InterventionExpired,
}

impl MountedAdminSupportRouteResponseBody {
    pub(crate) fn from_service_outcome(outcome: &MountedAdminSupportCommittedOutcome) -> Self {
        match outcome {
            MountedAdminSupportCommittedOutcome::InterventionRequested {
                intervention_id,
                expires_at,
                ..
            } => Self::InterventionRequested {
                intervention_handle: intervention_id.as_bytes().to_vec(),
                expires_at: *expires_at,
            },
            MountedAdminSupportCommittedOutcome::ApprovalAuthorizedImmediate { .. } => {
                Self::ApprovalAuthorizedImmediate
            }
            MountedAdminSupportCommittedOutcome::ApprovalScheduledDelayedAction {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::ApprovalScheduledDelayedAction {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedAdminSupportCommittedOutcome::InterventionDenied { .. } => {
                Self::InterventionDenied
            }
            MountedAdminSupportCommittedOutcome::InterventionExpired { .. } => {
                Self::InterventionExpired
            }
        }
    }
}
