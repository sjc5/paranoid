use http::Method;
use std::fmt;

use super::prelude::*;

/// Mounted configuration for one authenticated add-credential method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedCredentialAdditionMethod {
    method: ProofMethodDeclaration,
    reset_policy_role: CredentialResetPolicyRole,
    recovery_authority_rules: Vec<CredentialAdditionRecoveryAuthorityRule>,
    new_credential_authority_ids: Vec<RecoveryAuthorityId>,
}

impl MountedCredentialAdditionMethod {
    pub(crate) fn new(
        method: ProofMethodDeclaration,
        reset_policy_role: CredentialResetPolicyRole,
        recovery_authority_rules: Vec<CredentialAdditionRecoveryAuthorityRule>,
        new_credential_authority_ids: Vec<RecoveryAuthorityId>,
    ) -> Result<Self, Error> {
        CredentialInstanceKind::try_from_proof_family(method.family())?;
        if method.family() == ProofFamily::TrustedDevice {
            return Err(Error::InvalidConfig(
                "mounted credential addition method cannot create trusted-device credentials",
            ));
        }
        validate_mounted_credential_addition_authority_rules(&recovery_authority_rules)?;
        validate_mounted_credential_addition_new_credential_authorities(
            &new_credential_authority_ids,
        )?;
        Ok(Self {
            method,
            reset_policy_role,
            recovery_authority_rules,
            new_credential_authority_ids,
        })
    }

    pub(crate) const fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    pub(crate) const fn reset_policy_role(&self) -> CredentialResetPolicyRole {
        self.reset_policy_role
    }

    pub(crate) fn recovery_authority_rules(&self) -> &[CredentialAdditionRecoveryAuthorityRule] {
        &self.recovery_authority_rules
    }

    pub(crate) fn new_credential_authority_ids(&self) -> &[RecoveryAuthorityId] {
        &self.new_credential_authority_ids
    }

    pub(crate) fn runtime_input(
        &self,
        request: ExecuteMountedAuthenticatedCredentialAdditionInput,
    ) -> ExecuteAuthenticatedCredentialAdditionInput {
        ExecuteAuthenticatedCredentialAdditionInput {
            now: request.now,
            method: self.method.clone(),
            reset_policy_role: self.reset_policy_role,
            recovery_authority_rules: self.recovery_authority_rules.clone(),
            new_credential_authority_ids: self.new_credential_authority_ids.clone(),
            method_payload: request.method_payload,
        }
    }
}

/// Configured mounted route for adding one credential method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedCredentialAdditionRoute {
    route_segment: String,
    method: MountedCredentialAdditionMethod,
}

pub(crate) const MOUNTED_CREDENTIAL_ADDITION_ROUTE_PATH_PREFIX: &str = "/credentials/add/";

impl MountedCredentialAdditionRoute {
    pub(crate) fn new(
        route_segment: impl Into<String>,
        method: MountedCredentialAdditionMethod,
    ) -> Result<Self, Error> {
        let route_segment = route_segment.into();
        validate_mounted_credential_addition_route_segment(&route_segment)?;
        Ok(Self {
            route_segment,
            method,
        })
    }

    pub(crate) fn route_segment(&self) -> &str {
        &self.route_segment
    }

    pub(crate) const fn method_config(&self) -> &MountedCredentialAdditionMethod {
        &self.method
    }

    pub(crate) fn relative_path(&self) -> String {
        format!(
            "{MOUNTED_CREDENTIAL_ADDITION_ROUTE_PATH_PREFIX}{}",
            self.route_segment
        )
    }
}

fn validate_mounted_credential_addition_route_segment(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(
            "mounted credential addition route segment must not be empty",
        ));
    }
    validate_auth_string_not_too_long(
        "mounted credential addition route segment",
        value,
        METHOD_LABEL_MAX_BYTES,
    )?;
    if value == "." || value == ".." {
        return Err(Error::InvalidConfig(
            "mounted credential addition route segment must not be a dot segment",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidConfig(
            "mounted credential addition route segment must contain only ASCII letters, digits, dots, underscores, or hyphens",
        ));
    }
    Ok(())
}

/// Mounted input for adding one credential to the current authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedCredentialAdditionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Method-specific creation payload for the configured addition method.
    pub method_payload: CredentialCreationMethodPayload,
}

/// Submitted body material accepted by credential-addition routes before typed validation.
#[derive(Debug)]
pub(crate) struct MountedCredentialAdditionSubmittedRouteBody {
    method_payload: Vec<u8>,
}

impl MountedCredentialAdditionSubmittedRouteBody {
    pub(crate) fn new(method_payload: impl Into<Vec<u8>>) -> Self {
        Self {
            method_payload: method_payload.into(),
        }
    }

    pub(crate) fn into_endpoint_request_body(
        self,
    ) -> Result<MountedCredentialAdditionRouteRequestBody, Error> {
        MountedCredentialAdditionRouteRequestBody::from_submitted_creation_payload_bytes(
            self.method_payload,
        )
    }
}

/// Body material accepted by a configured credential-addition route.
#[derive(Debug)]
pub(crate) struct MountedCredentialAdditionRouteRequestBody {
    method_payload: CredentialCreationMethodPayload,
}

impl MountedCredentialAdditionRouteRequestBody {
    pub(crate) fn from_submitted_creation_payload_bytes(
        method_payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            method_payload: CredentialCreationMethodPayload::try_from_bytes(method_payload)?,
        })
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> ExecuteMountedAuthenticatedCredentialAdditionInput {
        ExecuteMountedAuthenticatedCredentialAdditionInput {
            now,
            method_payload: self.method_payload,
        }
    }
}

/// Mounted configuration for unauthenticated recovery proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedUnauthenticatedCredentialRecoveryMethod {
    method: ProofMethodDeclaration,
}

impl MountedUnauthenticatedCredentialRecoveryMethod {
    pub(crate) fn new(method: ProofMethodDeclaration) -> Result<Self, Error> {
        super::active_proof_support::validate_recovery_credential_active_proof_method(&method)?;
        Ok(Self { method })
    }

    pub(crate) const fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    pub(crate) fn start_runtime_input(
        &self,
        request: StartMountedUnauthenticatedCredentialRecoveryInput,
    ) -> StartUnauthenticatedRecoveryActiveProofAttemptInput {
        StartUnauthenticatedRecoveryActiveProofAttemptInput {
            now: request.now,
            method: self.method.clone(),
        }
    }

    pub(crate) fn completion_runtime_input(
        &self,
        request: CompleteMountedUnauthenticatedCredentialRecoveryProofInput,
    ) -> CompleteRecoveryCredentialActiveProofMethodResponse {
        CompleteRecoveryCredentialActiveProofMethodResponse {
            now: request.now,
            method: self.method.clone(),
            secret_response: request.secret_response,
        }
    }
}

/// Mounted configuration for the credential method reset by unauthenticated recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedUnauthenticatedCredentialRecoveryResetTargetMethod {
    method: ProofMethodDeclaration,
}

impl MountedUnauthenticatedCredentialRecoveryResetTargetMethod {
    pub(crate) fn new(method: ProofMethodDeclaration) -> Result<Self, Error> {
        let kind = CredentialInstanceKind::try_from_proof_family(method.family())?;
        if matches!(
            kind,
            CredentialInstanceKind::TrustedDeviceCredential
                | CredentialInstanceKind::RecoveryCodeCredential
        ) {
            return Err(Error::InvalidConfig(
                "mounted unauthenticated recovery reset target must be a resettable app credential",
            ));
        }
        Ok(Self { method })
    }

    pub(crate) const fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    pub(crate) fn schedule_runtime_input(
        &self,
        request: ScheduleMountedNoSessionCredentialRecoveryResetInput,
    ) -> ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
        ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
            now: request.now,
            target_method: self.method.clone(),
        }
    }

    pub(crate) fn execution_runtime_input(
        &self,
        request: ExecuteMountedNoSessionCredentialRecoveryResetInput,
    ) -> ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
        ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
            now: request.now,
            target_method: self.method.clone(),
            method_payload: request.method_payload,
        }
    }
}

/// Mounted configuration for one no-session credential recovery flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedNoSessionCredentialRecoveryFlow {
    recovery_method: MountedUnauthenticatedCredentialRecoveryMethod,
    reset_target_method: MountedUnauthenticatedCredentialRecoveryResetTargetMethod,
}

impl MountedNoSessionCredentialRecoveryFlow {
    pub(crate) fn new(
        recovery_method: ProofMethodDeclaration,
        reset_target_method: ProofMethodDeclaration,
    ) -> Result<Self, Error> {
        Ok(Self {
            recovery_method: MountedUnauthenticatedCredentialRecoveryMethod::new(recovery_method)?,
            reset_target_method: MountedUnauthenticatedCredentialRecoveryResetTargetMethod::new(
                reset_target_method,
            )?,
        })
    }

    pub(crate) const fn recovery_method(&self) -> &ProofMethodDeclaration {
        self.recovery_method.method()
    }

    pub(crate) const fn reset_target_method(&self) -> &ProofMethodDeclaration {
        self.reset_target_method.method()
    }

    pub(crate) fn start_runtime_input(
        &self,
        request: StartMountedNoSessionCredentialRecoveryInput,
    ) -> StartUnauthenticatedRecoveryActiveProofAttemptInput {
        self.recovery_method.start_runtime_input(
            StartMountedUnauthenticatedCredentialRecoveryInput { now: request.now },
        )
    }

    pub(crate) fn completion_runtime_input(
        &self,
        request: CompleteMountedNoSessionCredentialRecoveryProofInput,
    ) -> CompleteRecoveryCredentialActiveProofMethodResponse {
        self.recovery_method.completion_runtime_input(
            CompleteMountedUnauthenticatedCredentialRecoveryProofInput {
                now: request.now,
                secret_response: request.secret_response,
            },
        )
    }

    pub(crate) fn schedule_reset_runtime_input(
        &self,
        request: ScheduleMountedNoSessionCredentialRecoveryResetInput,
    ) -> ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
        self.reset_target_method.schedule_runtime_input(request)
    }

    pub(crate) fn execute_reset_runtime_input(
        &self,
        request: ExecuteMountedNoSessionCredentialRecoveryResetInput,
    ) -> ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
        self.reset_target_method.execution_runtime_input(request)
    }
}

/// Mounted input for starting a no-session credential recovery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartMountedNoSessionCredentialRecoveryInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Mounted input for completing a no-session credential recovery proof.
#[derive(Debug)]
pub(crate) struct CompleteMountedNoSessionCredentialRecoveryProofInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Submitted one-time recovery credential.
    pub secret_response: KnownSubjectActiveProofSecretResponse,
}

impl CompleteMountedNoSessionCredentialRecoveryProofInput {
    pub(crate) fn try_from_secret_response_bytes(
        now: UnixSeconds,
        secret_response: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            now,
            secret_response: KnownSubjectActiveProofSecretResponse::try_from_bytes(
                secret_response,
            )?,
        })
    }
}

/// Mounted input for delayed no-session recovery reset of a configured credential method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleMountedNoSessionCredentialRecoveryResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Mounted input for immediate no-session recovery reset of a configured credential method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedNoSessionCredentialRecoveryResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Method-specific reset payload for the configured target method.
    pub method_payload: CredentialResetMethodPayload,
}

impl ExecuteMountedNoSessionCredentialRecoveryResetInput {
    pub(crate) fn try_from_method_payload_bytes(
        now: UnixSeconds,
        method_payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            now,
            method_payload: CredentialResetMethodPayload::try_from_bytes(method_payload)?,
        })
    }
}

/// Mounted no-session recovery route step.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedNoSessionCredentialRecoveryRouteStep {
    /// Start the recovery ceremony after a pre-state-load write-amplification gate.
    StartRecoveryAttempt,
    /// Submit the recovery proof secret for the active ceremony.
    SubmitRecoveryProof,
    /// Schedule delayed reset from an already accepted recovery continuation.
    ScheduleDelayedReset,
    /// Execute immediate reset from an already accepted recovery continuation.
    ExecuteImmediateReset,
}

pub(crate) const MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH: &str =
    "/credential-recovery/start";
pub(crate) const MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH: &str =
    "/credential-recovery/proof";
pub(crate) const MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH: &str =
    "/credential-recovery/reset/schedule";
pub(crate) const MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH: &str =
    "/credential-recovery/reset/execute";

impl MountedNoSessionCredentialRecoveryRouteStep {
    pub(crate) const fn requires_challenge_issue_preflight(self) -> bool {
        matches!(self, Self::StartRecoveryAttempt)
    }

    pub(crate) const fn requires_submitted_recovery_secret(self) -> bool {
        matches!(self, Self::SubmitRecoveryProof)
    }

    pub(crate) const fn requires_csrf(self) -> bool {
        matches!(
            self,
            Self::ScheduleDelayedReset | Self::ExecuteImmediateReset
        )
    }
}

/// Mounted no-session recovery endpoint selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedNoSessionCredentialRecoveryEndpoint {
    /// Start the recovery ceremony after a pre-state-load write-amplification gate.
    StartRecoveryAttempt,
    /// Submit the recovery proof secret for the active ceremony.
    SubmitRecoveryProof,
    /// Schedule delayed reset from an already accepted recovery continuation.
    ScheduleDelayedReset,
    /// Execute immediate reset from an already accepted recovery continuation.
    ExecuteImmediateReset,
}

impl MountedNoSessionCredentialRecoveryEndpoint {
    pub(crate) const fn all() -> [Self; 4] {
        [
            Self::StartRecoveryAttempt,
            Self::SubmitRecoveryProof,
            Self::ScheduleDelayedReset,
            Self::ExecuteImmediateReset,
        ]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH => {
                Some(Self::StartRecoveryAttempt)
            }
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH => {
                Some(Self::SubmitRecoveryProof)
            }
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH => {
                Some(Self::ScheduleDelayedReset)
            }
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH => {
                Some(Self::ExecuteImmediateReset)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::StartRecoveryAttempt => MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH,
            Self::SubmitRecoveryProof => MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH,
            Self::ScheduleDelayedReset => {
                MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
            }
            Self::ExecuteImmediateReset => {
                MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH
            }
        }
    }

    pub(crate) const fn step(self) -> MountedNoSessionCredentialRecoveryRouteStep {
        match self {
            Self::StartRecoveryAttempt => {
                MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
            }
            Self::SubmitRecoveryProof => {
                MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
            }
            Self::ScheduleDelayedReset => {
                MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
            }
            Self::ExecuteImmediateReset => {
                MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
            }
        }
    }
}

/// Submitted body material accepted by no-session recovery routes before typed validation.
#[derive(Debug)]
pub(crate) enum MountedNoSessionCredentialRecoverySubmittedRouteBody {
    /// Submitted body for the recovery-start endpoint.
    StartRecoveryAttempt {
        preflight_gate_kind: WeakProofGateKind,
        preflight_gate_method_label: String,
        preflight_gate_payload: Vec<u8>,
    },
    /// Submitted body for the recovery-proof endpoint.
    SubmitRecoveryProof { secret_response: Vec<u8> },
    /// Submitted body bytes for the delayed-reset scheduling endpoint.
    ScheduleDelayedReset { body: Vec<u8> },
    /// Submitted body for the immediate-reset execution endpoint.
    ExecuteImmediateReset { method_payload: Vec<u8> },
}

impl MountedNoSessionCredentialRecoverySubmittedRouteBody {
    pub(crate) fn start_recovery_attempt(
        preflight_gate_kind: WeakProofGateKind,
        preflight_gate_method_label: impl Into<String>,
        preflight_gate_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::StartRecoveryAttempt {
            preflight_gate_kind,
            preflight_gate_method_label: preflight_gate_method_label.into(),
            preflight_gate_payload: preflight_gate_payload.into(),
        }
    }

    pub(crate) fn submit_recovery_proof(secret_response: impl Into<Vec<u8>>) -> Self {
        Self::SubmitRecoveryProof {
            secret_response: secret_response.into(),
        }
    }

    pub(crate) fn schedule_delayed_reset(body: impl Into<Vec<u8>>) -> Self {
        Self::ScheduleDelayedReset { body: body.into() }
    }

    pub(crate) fn execute_immediate_reset(method_payload: impl Into<Vec<u8>>) -> Self {
        Self::ExecuteImmediateReset {
            method_payload: method_payload.into(),
        }
    }

    pub(crate) const fn step(&self) -> MountedNoSessionCredentialRecoveryRouteStep {
        match self {
            Self::StartRecoveryAttempt { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
            }
            Self::SubmitRecoveryProof { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
            }
            Self::ScheduleDelayedReset { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
            }
            Self::ExecuteImmediateReset { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
            }
        }
    }

    pub(crate) fn into_endpoint_request_body(
        self,
    ) -> Result<MountedNoSessionCredentialRecoveryEndpointRequestBody, Error> {
        match self {
            Self::StartRecoveryAttempt {
                preflight_gate_kind,
                preflight_gate_method_label,
                preflight_gate_payload,
            } => Ok(MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
                preflight_gate_kind,
                preflight_gate_method_label,
                preflight_gate_payload,
            )?
            .into()),
            Self::SubmitRecoveryProof { secret_response } => {
                Ok(MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
                    secret_response,
                )?
                .into())
            }
            Self::ScheduleDelayedReset { body } => Ok(
                MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody::from_empty_route_body_bytes(
                    body,
                )?
                .into(),
            ),
            Self::ExecuteImmediateReset { method_payload } => Ok(
                MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
                    method_payload,
                )?
                .into(),
            ),
        }
    }
}

/// Body material accepted by the mounted recovery-start route.
#[derive(Debug)]
pub(crate) struct MountedNoSessionCredentialRecoveryStartRouteRequestBody {
    preflight_response: ChallengeIssuePreflightResponse,
}

impl MountedNoSessionCredentialRecoveryStartRouteRequestBody {
    pub(crate) fn from_submitted_preflight_response_parts(
        preflight_gate_kind: WeakProofGateKind,
        preflight_gate_method_label: impl Into<String>,
        preflight_gate_payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            preflight_response: ChallengeIssuePreflightResponse::try_from_bytes(
                preflight_gate_kind,
                preflight_gate_method_label,
                preflight_gate_payload,
            )?,
        })
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> MountedNoSessionCredentialRecoveryRouteRequest {
        MountedNoSessionCredentialRecoveryRouteRequest::StartRecoveryAttempt {
            request: StartMountedNoSessionCredentialRecoveryInput { now },
            preflight_response: self.preflight_response,
        }
    }
}

/// Body material accepted by the mounted recovery-proof submission route.
#[derive(Debug)]
pub(crate) struct MountedNoSessionCredentialRecoveryProofRouteRequestBody {
    secret_response: KnownSubjectActiveProofSecretResponse,
}

impl MountedNoSessionCredentialRecoveryProofRouteRequestBody {
    pub(crate) fn from_submitted_recovery_secret_bytes(
        secret_response: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            secret_response: KnownSubjectActiveProofSecretResponse::try_from_bytes(
                secret_response,
            )?,
        })
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> MountedNoSessionCredentialRecoveryRouteRequest {
        MountedNoSessionCredentialRecoveryRouteRequest::SubmitRecoveryProof {
            request: CompleteMountedNoSessionCredentialRecoveryProofInput {
                now,
                secret_response: self.secret_response,
            },
        }
    }
}

/// Empty body accepted by the mounted delayed-recovery-reset scheduling route.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody;

impl MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn from_empty_route_body_bytes(body: impl AsRef<[u8]>) -> Result<Self, Error> {
        if !body.as_ref().is_empty() {
            return Err(Error::NonEmptyMountedNoSessionCredentialRecoveryScheduleResetRouteBody);
        }
        Ok(Self)
    }

    pub(crate) const fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> MountedNoSessionCredentialRecoveryRouteRequest {
        MountedNoSessionCredentialRecoveryRouteRequest::ScheduleDelayedReset {
            request: ScheduleMountedNoSessionCredentialRecoveryResetInput { now },
        }
    }
}

/// Body material accepted by the mounted immediate-recovery-reset execution route.
#[derive(Debug)]
pub(crate) struct MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody {
    method_payload: CredentialResetMethodPayload,
}

impl MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody {
    pub(crate) fn from_submitted_reset_payload_bytes(
        method_payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            method_payload: CredentialResetMethodPayload::try_from_bytes(method_payload)?,
        })
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> MountedNoSessionCredentialRecoveryRouteRequest {
        MountedNoSessionCredentialRecoveryRouteRequest::ExecuteImmediateReset {
            request: ExecuteMountedNoSessionCredentialRecoveryResetInput {
                now,
                method_payload: self.method_payload,
            },
        }
    }
}

/// Typed body accepted by the mounted no-session recovery endpoint dispatcher.
#[derive(Debug)]
pub(crate) enum MountedNoSessionCredentialRecoveryEndpointRequestBody {
    /// Body for the recovery-start endpoint.
    StartRecoveryAttempt(MountedNoSessionCredentialRecoveryStartRouteRequestBody),
    /// Body for the recovery-proof endpoint.
    SubmitRecoveryProof(MountedNoSessionCredentialRecoveryProofRouteRequestBody),
    /// Body for the delayed-reset scheduling endpoint.
    ScheduleDelayedReset(MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody),
    /// Body for the immediate-reset execution endpoint.
    ExecuteImmediateReset(MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody),
}

impl MountedNoSessionCredentialRecoveryEndpointRequestBody {
    pub(crate) const fn step(&self) -> MountedNoSessionCredentialRecoveryRouteStep {
        match self {
            Self::StartRecoveryAttempt(_) => {
                MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
            }
            Self::SubmitRecoveryProof(_) => {
                MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
            }
            Self::ScheduleDelayedReset(_) => {
                MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
            }
            Self::ExecuteImmediateReset(_) => {
                MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> MountedNoSessionCredentialRecoveryRouteRequest {
        match self {
            Self::StartRecoveryAttempt(body) => body.into_route_request(now),
            Self::SubmitRecoveryProof(body) => body.into_route_request(now),
            Self::ScheduleDelayedReset(body) => body.into_route_request(now),
            Self::ExecuteImmediateReset(body) => body.into_route_request(now),
        }
    }
}

impl From<MountedNoSessionCredentialRecoveryStartRouteRequestBody>
    for MountedNoSessionCredentialRecoveryEndpointRequestBody
{
    fn from(body: MountedNoSessionCredentialRecoveryStartRouteRequestBody) -> Self {
        Self::StartRecoveryAttempt(body)
    }
}

impl From<MountedNoSessionCredentialRecoveryProofRouteRequestBody>
    for MountedNoSessionCredentialRecoveryEndpointRequestBody
{
    fn from(body: MountedNoSessionCredentialRecoveryProofRouteRequestBody) -> Self {
        Self::SubmitRecoveryProof(body)
    }
}

impl From<MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody>
    for MountedNoSessionCredentialRecoveryEndpointRequestBody
{
    fn from(body: MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody) -> Self {
        Self::ScheduleDelayedReset(body)
    }
}

impl From<MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody>
    for MountedNoSessionCredentialRecoveryEndpointRequestBody
{
    fn from(body: MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody) -> Self {
        Self::ExecuteImmediateReset(body)
    }
}

/// Route-owned request for one mounted no-session recovery transition.
#[derive(Debug)]
pub(crate) enum MountedNoSessionCredentialRecoveryRouteRequest {
    /// Start the recovery ceremony after challenge-issue preflight verification.
    StartRecoveryAttempt {
        request: StartMountedNoSessionCredentialRecoveryInput,
        preflight_response: ChallengeIssuePreflightResponse,
    },
    /// Submit the configured recovery proof secret.
    SubmitRecoveryProof {
        request: CompleteMountedNoSessionCredentialRecoveryProofInput,
    },
    /// Schedule delayed reset from an accepted recovery continuation.
    ScheduleDelayedReset {
        request: ScheduleMountedNoSessionCredentialRecoveryResetInput,
    },
    /// Execute immediate reset from an accepted recovery continuation.
    ExecuteImmediateReset {
        request: ExecuteMountedNoSessionCredentialRecoveryResetInput,
    },
}

impl MountedNoSessionCredentialRecoveryRouteRequest {
    pub(crate) fn start_recovery_attempt(
        now: UnixSeconds,
        preflight_response: ChallengeIssuePreflightResponse,
    ) -> Self {
        Self::StartRecoveryAttempt {
            request: StartMountedNoSessionCredentialRecoveryInput { now },
            preflight_response,
        }
    }

    pub(crate) fn submit_recovery_proof(
        now: UnixSeconds,
        secret_response: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self::SubmitRecoveryProof {
            request:
                CompleteMountedNoSessionCredentialRecoveryProofInput::try_from_secret_response_bytes(
                    now,
                    secret_response,
                )?,
        })
    }

    pub(crate) fn schedule_delayed_reset(now: UnixSeconds) -> Self {
        Self::ScheduleDelayedReset {
            request: ScheduleMountedNoSessionCredentialRecoveryResetInput { now },
        }
    }

    pub(crate) fn execute_immediate_reset(
        now: UnixSeconds,
        method_payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self::ExecuteImmediateReset {
            request:
                ExecuteMountedNoSessionCredentialRecoveryResetInput::try_from_method_payload_bytes(
                    now,
                    method_payload,
                )?,
        })
    }

    pub(crate) const fn step(&self) -> MountedNoSessionCredentialRecoveryRouteStep {
        match self {
            Self::StartRecoveryAttempt { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
            }
            Self::SubmitRecoveryProof { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
            }
            Self::ScheduleDelayedReset { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
            }
            Self::ExecuteImmediateReset { .. } => {
                MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
            }
        }
    }

    pub(crate) fn requires_challenge_issue_preflight(&self) -> bool {
        self.step().requires_challenge_issue_preflight()
    }

    pub(crate) fn requires_submitted_recovery_secret(&self) -> bool {
        self.step().requires_submitted_recovery_secret()
    }

    pub(crate) fn requires_csrf(&self) -> bool {
        self.step().requires_csrf()
    }
}

/// Route-shaped response for mounted no-session recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedNoSessionCredentialRecoveryRouteOutcome {
    /// Recovery ceremony started and response cookies were rendered.
    RecoveryAttemptStarted { expires_at: UnixSeconds },
    /// Recovery proof was accepted without exposing proof internals.
    RecoveryProofAccepted,
    /// Recovery proof was rejected without exposing attempt internals.
    RecoveryProofRejected,
    /// Delayed reset was scheduled from the recovery continuation.
    DelayedResetScheduled {
        #[cfg(test)]
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Immediate reset executed from the recovery continuation.
    ImmediateResetExecuted,
}

/// User-visible body for a mounted no-session recovery route response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedNoSessionCredentialRecoveryRouteResponseBody {
    /// Recovery ceremony started and may be continued until this time.
    RecoveryAttemptStarted { expires_at: UnixSeconds },
    /// Recovery proof was accepted without exposing proof internals.
    RecoveryProofAccepted,
    /// Recovery proof was rejected without exposing attempt internals.
    RecoveryProofRejected,
    /// Delayed reset was scheduled from the recovery continuation.
    DelayedResetScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Immediate reset executed from the recovery continuation.
    ImmediateResetExecuted,
}

impl MountedNoSessionCredentialRecoveryRouteResponseBody {
    pub(crate) fn from_route_outcome(
        outcome: &MountedNoSessionCredentialRecoveryRouteOutcome,
    ) -> Self {
        match outcome {
            MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryAttemptStarted {
                expires_at,
            } => Self::RecoveryAttemptStarted {
                expires_at: *expires_at,
            },
            MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryProofAccepted => {
                Self::RecoveryProofAccepted
            }
            MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryProofRejected => {
                Self::RecoveryProofRejected
            }
            MountedNoSessionCredentialRecoveryRouteOutcome::DelayedResetScheduled {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedResetScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedNoSessionCredentialRecoveryRouteOutcome::ImmediateResetExecuted => {
                Self::ImmediateResetExecuted
            }
        }
    }
}

impl MountedNoSessionCredentialRecoveryRouteOutcome {
    pub(crate) fn from_start_service_outcome(
        outcome: &MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome,
    ) -> Self {
        match outcome {
            MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome::RecoveryAttemptStarted {
                expires_at,
                ..
            } => Self::RecoveryAttemptStarted {
                expires_at: *expires_at,
            },
        }
    }

    pub(crate) fn from_proof_completion_service_outcome(
        outcome: &MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome,
    ) -> Self {
        match outcome {
            MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome::RecoveryProofAccepted {
                ..
            } => Self::RecoveryProofAccepted,
            MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome::RecoveryProofRejected {
                ..
            } => Self::RecoveryProofRejected,
        }
    }

    pub(crate) fn from_reset_scheduling_service_outcome(
        outcome: &MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome,
    ) -> Self {
        match outcome {
            #[cfg(test)]
            MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::PendingCredentialResetActionCreated {
                pending_action_id,
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedResetScheduled {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            #[cfg(not(test))]
            MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::PendingCredentialResetActionCreated {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedResetScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
        }
    }

    pub(crate) fn from_reset_execution_service_outcome(
        outcome: &MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome,
    ) -> Self {
        match outcome {
            MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::CredentialReset {
                ..
            } => Self::ImmediateResetExecuted,
        }
    }
}

/// User-visible generated recovery-code set returned only from committed mounted flows.
pub(crate) struct MountedGeneratedRecoveryCodeSetRouteResponseBody {
    credential_instance_id: VerifiedProofSourceId,
    codes: Vec<GeneratedRecoveryCode>,
}

impl MountedGeneratedRecoveryCodeSetRouteResponseBody {
    pub(crate) fn from_generated_recovery_code_set(generated: GeneratedRecoveryCodeSet) -> Self {
        let (credential_instance_id, codes) = generated.into_parts();
        Self {
            credential_instance_id,
            codes,
        }
    }

    pub(crate) fn credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.credential_instance_id
    }

    pub(crate) fn len(&self) -> usize {
        self.codes.len()
    }

    pub(crate) fn into_parts(self) -> (VerifiedProofSourceId, Vec<GeneratedRecoveryCode>) {
        (self.credential_instance_id, self.codes)
    }
}

impl fmt::Debug for MountedGeneratedRecoveryCodeSetRouteResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MountedGeneratedRecoveryCodeSetRouteResponseBody")
            .field("credential_instance_id", &self.credential_instance_id)
            .field("code_count", &self.codes.len())
            .finish()
    }
}

/// User-visible body for a mounted authenticated credential-addition route response.
pub(crate) enum MountedCredentialAdditionRouteResponseBody {
    /// The credential was added after commit.
    CredentialAdded {
        generated_recovery_codes: Option<MountedGeneratedRecoveryCodeSetRouteResponseBody>,
    },
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before adding this credential.
    NeedsStepUp,
}

impl fmt::Debug for MountedCredentialAdditionRouteResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialAdded {
                generated_recovery_codes,
            } => f
                .debug_struct("MountedCredentialAdditionRouteResponseBody::CredentialAdded")
                .field(
                    "generated_recovery_code_count",
                    &generated_recovery_codes
                        .as_ref()
                        .map(MountedGeneratedRecoveryCodeSetRouteResponseBody::len)
                        .unwrap_or(0),
                )
                .finish(),
            Self::NeedsFullAuthentication => {
                f.write_str("MountedCredentialAdditionRouteResponseBody::NeedsFullAuthentication")
            }
            Self::NeedsStepUp => {
                f.write_str("MountedCredentialAdditionRouteResponseBody::NeedsStepUp")
            }
        }
    }
}

/// Mounted input for starting an unauthenticated credential recovery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartMountedUnauthenticatedCredentialRecoveryInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
}

/// Mounted input for completing an unauthenticated credential recovery proof.
#[derive(Debug)]
pub(crate) struct CompleteMountedUnauthenticatedCredentialRecoveryProofInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Submitted one-time recovery credential.
    pub secret_response: KnownSubjectActiveProofSecretResponse,
}

/// Opaque mounted-route handle for one credential shown by credential inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedCredentialHandle {
    credential_instance_id: VerifiedProofSourceId,
}

impl MountedCredentialHandle {
    pub(crate) fn from_credential_instance_id(
        credential_instance_id: VerifiedProofSourceId,
    ) -> Self {
        Self {
            credential_instance_id,
        }
    }

    pub(crate) fn from_submitted_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Ok(Self::from_credential_instance_id(
            VerifiedProofSourceId::from_bytes(bytes)?,
        ))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.credential_instance_id.as_bytes()
    }

    pub(crate) fn into_credential_instance_id(self) -> VerifiedProofSourceId {
        self.credential_instance_id
    }

    #[cfg(test)]
    pub(crate) const fn credential_instance_id_for_test(&self) -> &VerifiedProofSourceId {
        &self.credential_instance_id
    }
}

/// Mounted input for planning reset of one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanMountedAuthenticatedCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
}

impl PlanMountedAuthenticatedCredentialResetInput {
    pub(crate) fn into_runtime_input(self) -> PlanAuthenticatedCredentialResetInput {
        PlanAuthenticatedCredentialResetInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
        }
    }
}

/// Mounted input for immediately resetting one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedCredentialResetInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
    /// Method-specific reset payload for the target credential's registered method.
    pub method_payload: CredentialResetMethodPayload,
}

impl ExecuteMountedAuthenticatedCredentialResetInput {
    pub(crate) fn into_runtime_input(self) -> ExecuteAuthenticatedCredentialResetInput {
        ExecuteAuthenticatedCredentialResetInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
            method_payload: self.method_payload,
        }
    }
}

/// Mounted authenticated credential-reset route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialResetEndpoint {
    /// Plan reset for one credential owned by the current authenticated subject.
    PlanReset,
    /// Execute immediate reset for one credential owned by the current authenticated subject.
    ExecuteImmediateReset,
}

pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_PLAN_ROUTE_PATH: &str =
    "/credentials/reset/plan";
pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_EXECUTE_ROUTE_PATH: &str =
    "/credentials/reset/execute";

impl MountedAuthenticatedCredentialResetEndpoint {
    pub(crate) const fn all() -> [Self; 2] {
        [Self::PlanReset, Self::ExecuteImmediateReset]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_PLAN_ROUTE_PATH => Some(Self::PlanReset),
            MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteImmediateReset)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::PlanReset => MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_PLAN_ROUTE_PATH,
            Self::ExecuteImmediateReset => {
                MOUNTED_AUTHENTICATED_CREDENTIAL_RESET_EXECUTE_ROUTE_PATH
            }
        }
    }
}

/// Submitted body material accepted by authenticated credential-reset routes.
#[derive(Debug)]
pub(crate) enum MountedAuthenticatedCredentialResetSubmittedRouteBody {
    /// Submitted body for planning reset.
    PlanReset { credential_handle: Vec<u8> },
    /// Submitted body for immediate reset execution.
    ExecuteImmediateReset {
        credential_handle: Vec<u8>,
        method_payload: Vec<u8>,
    },
}

impl MountedAuthenticatedCredentialResetSubmittedRouteBody {
    pub(crate) fn plan_reset(credential_handle: impl Into<Vec<u8>>) -> Self {
        Self::PlanReset {
            credential_handle: credential_handle.into(),
        }
    }

    pub(crate) fn execute_immediate_reset(
        credential_handle: impl Into<Vec<u8>>,
        method_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteImmediateReset {
            credential_handle: credential_handle.into(),
            method_payload: method_payload.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialResetEndpoint {
        match self {
            Self::PlanReset { .. } => MountedAuthenticatedCredentialResetEndpoint::PlanReset,
            Self::ExecuteImmediateReset { .. } => {
                MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAuthenticatedCredentialResetRouteRequest, Error> {
        match self {
            Self::PlanReset { credential_handle } => {
                Ok(MountedAuthenticatedCredentialResetRouteRequest::PlanReset(
                    PlanMountedAuthenticatedCredentialResetInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                    },
                ))
            }
            Self::ExecuteImmediateReset {
                credential_handle,
                method_payload,
            } => Ok(
                MountedAuthenticatedCredentialResetRouteRequest::ExecuteImmediateReset(
                    ExecuteMountedAuthenticatedCredentialResetInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                        method_payload: CredentialResetMethodPayload::try_from_bytes(
                            method_payload,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted credential-reset route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialResetRouteRequest {
    /// Plan a credential reset.
    PlanReset(PlanMountedAuthenticatedCredentialResetInput),
    /// Execute an immediate credential reset.
    ExecuteImmediateReset(ExecuteMountedAuthenticatedCredentialResetInput),
}

impl MountedAuthenticatedCredentialResetRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialResetEndpoint {
        match self {
            Self::PlanReset(_) => MountedAuthenticatedCredentialResetEndpoint::PlanReset,
            Self::ExecuteImmediateReset(_) => {
                MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset
            }
        }
    }
}

/// Mounted input for planning replacement of one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanMountedAuthenticatedCredentialReplacementInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
}

impl PlanMountedAuthenticatedCredentialReplacementInput {
    pub(crate) fn into_runtime_input(self) -> PlanAuthenticatedCredentialReplacementInput {
        PlanAuthenticatedCredentialReplacementInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
        }
    }
}

/// Mounted input for immediately replacing one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedCredentialReplacementInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
    /// Method-specific replacement payload for the target credential's registered method.
    pub method_payload: CredentialLifecycleMethodPayload,
}

impl ExecuteMountedAuthenticatedCredentialReplacementInput {
    pub(crate) fn into_runtime_input(self) -> ExecuteAuthenticatedCredentialReplacementInput {
        ExecuteAuthenticatedCredentialReplacementInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
            method_payload: self.method_payload,
        }
    }
}

/// Mounted authenticated credential-replacement route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialReplacementEndpoint {
    /// Plan replacement for one credential owned by the current authenticated subject.
    PlanReplacement,
    /// Execute immediate replacement for one credential owned by the current authenticated subject.
    ExecuteImmediateReplacement,
}

pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_PLAN_ROUTE_PATH: &str =
    "/credentials/replace/plan";
pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_EXECUTE_ROUTE_PATH: &str =
    "/credentials/replace/execute";

impl MountedAuthenticatedCredentialReplacementEndpoint {
    pub(crate) const fn all() -> [Self; 2] {
        [Self::PlanReplacement, Self::ExecuteImmediateReplacement]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_PLAN_ROUTE_PATH => {
                Some(Self::PlanReplacement)
            }
            MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteImmediateReplacement)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::PlanReplacement => MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_PLAN_ROUTE_PATH,
            Self::ExecuteImmediateReplacement => {
                MOUNTED_AUTHENTICATED_CREDENTIAL_REPLACEMENT_EXECUTE_ROUTE_PATH
            }
        }
    }
}

/// Submitted body material accepted by authenticated credential-replacement routes.
#[derive(Debug)]
pub(crate) enum MountedAuthenticatedCredentialReplacementSubmittedRouteBody {
    /// Submitted body for planning replacement.
    PlanReplacement { credential_handle: Vec<u8> },
    /// Submitted body for immediate replacement execution.
    ExecuteImmediateReplacement {
        credential_handle: Vec<u8>,
        method_payload: Vec<u8>,
    },
}

impl MountedAuthenticatedCredentialReplacementSubmittedRouteBody {
    pub(crate) fn plan_replacement(credential_handle: impl Into<Vec<u8>>) -> Self {
        Self::PlanReplacement {
            credential_handle: credential_handle.into(),
        }
    }

    pub(crate) fn execute_immediate_replacement(
        credential_handle: impl Into<Vec<u8>>,
        method_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteImmediateReplacement {
            credential_handle: credential_handle.into(),
            method_payload: method_payload.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialReplacementEndpoint {
        match self {
            Self::PlanReplacement { .. } => {
                MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement
            }
            Self::ExecuteImmediateReplacement { .. } => {
                MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAuthenticatedCredentialReplacementRouteRequest, Error> {
        match self {
            Self::PlanReplacement { credential_handle } => Ok(
                MountedAuthenticatedCredentialReplacementRouteRequest::PlanReplacement(
                    PlanMountedAuthenticatedCredentialReplacementInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                    },
                ),
            ),
            Self::ExecuteImmediateReplacement {
                credential_handle,
                method_payload,
            } => Ok(
                MountedAuthenticatedCredentialReplacementRouteRequest::ExecuteImmediateReplacement(
                    ExecuteMountedAuthenticatedCredentialReplacementInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                        method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                            method_payload,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted credential-replacement route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialReplacementRouteRequest {
    /// Plan a credential replacement.
    PlanReplacement(PlanMountedAuthenticatedCredentialReplacementInput),
    /// Execute an immediate credential replacement.
    ExecuteImmediateReplacement(ExecuteMountedAuthenticatedCredentialReplacementInput),
}

impl MountedAuthenticatedCredentialReplacementRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialReplacementEndpoint {
        match self {
            Self::PlanReplacement(_) => {
                MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement
            }
            Self::ExecuteImmediateReplacement(_) => {
                MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement
            }
        }
    }
}

/// Mounted input for planning removal of one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanMountedAuthenticatedCredentialRemovalInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
}

impl PlanMountedAuthenticatedCredentialRemovalInput {
    pub(crate) fn into_runtime_input(self) -> PlanAuthenticatedCredentialRemovalInput {
        PlanAuthenticatedCredentialRemovalInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
        }
    }
}

/// Mounted input for immediately removing one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedCredentialRemovalInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
}

impl ExecuteMountedAuthenticatedCredentialRemovalInput {
    pub(crate) fn into_runtime_input(self) -> ExecuteAuthenticatedCredentialRemovalInput {
        ExecuteAuthenticatedCredentialRemovalInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
        }
    }
}

/// Mounted authenticated credential-removal route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialRemovalEndpoint {
    /// Plan removal for one credential owned by the current authenticated subject.
    PlanRemoval,
    /// Execute immediate removal for one credential owned by the current authenticated subject.
    ExecuteImmediateRemoval,
}

pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_PLAN_ROUTE_PATH: &str =
    "/credentials/remove/plan";
pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_EXECUTE_ROUTE_PATH: &str =
    "/credentials/remove/execute";

impl MountedAuthenticatedCredentialRemovalEndpoint {
    pub(crate) const fn all() -> [Self; 2] {
        [Self::PlanRemoval, Self::ExecuteImmediateRemoval]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_PLAN_ROUTE_PATH => Some(Self::PlanRemoval),
            MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteImmediateRemoval)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::PlanRemoval => MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_PLAN_ROUTE_PATH,
            Self::ExecuteImmediateRemoval => {
                MOUNTED_AUTHENTICATED_CREDENTIAL_REMOVAL_EXECUTE_ROUTE_PATH
            }
        }
    }
}

/// Submitted body material accepted by authenticated credential-removal routes.
#[derive(Debug)]
pub(crate) enum MountedAuthenticatedCredentialRemovalSubmittedRouteBody {
    /// Submitted body for planning removal.
    PlanRemoval { credential_handle: Vec<u8> },
    /// Submitted body for immediate removal execution.
    ExecuteImmediateRemoval { credential_handle: Vec<u8> },
}

impl MountedAuthenticatedCredentialRemovalSubmittedRouteBody {
    pub(crate) fn plan_removal(credential_handle: impl Into<Vec<u8>>) -> Self {
        Self::PlanRemoval {
            credential_handle: credential_handle.into(),
        }
    }

    pub(crate) fn execute_immediate_removal(credential_handle: impl Into<Vec<u8>>) -> Self {
        Self::ExecuteImmediateRemoval {
            credential_handle: credential_handle.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialRemovalEndpoint {
        match self {
            Self::PlanRemoval { .. } => MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval,
            Self::ExecuteImmediateRemoval { .. } => {
                MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAuthenticatedCredentialRemovalRouteRequest, Error> {
        match self {
            Self::PlanRemoval { credential_handle } => Ok(
                MountedAuthenticatedCredentialRemovalRouteRequest::PlanRemoval(
                    PlanMountedAuthenticatedCredentialRemovalInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                    },
                ),
            ),
            Self::ExecuteImmediateRemoval { credential_handle } => Ok(
                MountedAuthenticatedCredentialRemovalRouteRequest::ExecuteImmediateRemoval(
                    ExecuteMountedAuthenticatedCredentialRemovalInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted credential-removal route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialRemovalRouteRequest {
    /// Plan a credential removal.
    PlanRemoval(PlanMountedAuthenticatedCredentialRemovalInput),
    /// Execute an immediate credential removal.
    ExecuteImmediateRemoval(ExecuteMountedAuthenticatedCredentialRemovalInput),
}

impl MountedAuthenticatedCredentialRemovalRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialRemovalEndpoint {
        match self {
            Self::PlanRemoval(_) => MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval,
            Self::ExecuteImmediateRemoval(_) => {
                MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval
            }
        }
    }
}

/// Mounted input for planning regeneration of one credential set owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanMountedAuthenticatedCredentialRegenerationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
}

impl PlanMountedAuthenticatedCredentialRegenerationInput {
    pub(crate) fn into_runtime_input(self) -> PlanAuthenticatedCredentialRegenerationInput {
        PlanAuthenticatedCredentialRegenerationInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
        }
    }
}

/// Mounted input for immediately regenerating one credential set owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedCredentialRegenerationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
    /// Method-specific regeneration payload for the target credential's registered method.
    pub method_payload: CredentialLifecycleMethodPayload,
}

impl ExecuteMountedAuthenticatedCredentialRegenerationInput {
    pub(crate) fn into_runtime_input(self) -> ExecuteAuthenticatedCredentialRegenerationInput {
        ExecuteAuthenticatedCredentialRegenerationInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
            method_payload: self.method_payload,
        }
    }
}

/// Mounted authenticated credential-regeneration route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialRegenerationEndpoint {
    /// Plan regeneration for one credential set owned by the current authenticated subject.
    PlanRegeneration,
    /// Execute immediate regeneration for one credential set owned by the current authenticated subject.
    ExecuteImmediateRegeneration,
}

pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_PLAN_ROUTE_PATH: &str =
    "/credentials/regenerate/plan";
pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_EXECUTE_ROUTE_PATH: &str =
    "/credentials/regenerate/execute";

impl MountedAuthenticatedCredentialRegenerationEndpoint {
    pub(crate) const fn all() -> [Self; 2] {
        [Self::PlanRegeneration, Self::ExecuteImmediateRegeneration]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_PLAN_ROUTE_PATH => {
                Some(Self::PlanRegeneration)
            }
            MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteImmediateRegeneration)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::PlanRegeneration => MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_PLAN_ROUTE_PATH,
            Self::ExecuteImmediateRegeneration => {
                MOUNTED_AUTHENTICATED_CREDENTIAL_REGENERATION_EXECUTE_ROUTE_PATH
            }
        }
    }
}

/// Submitted body material accepted by authenticated credential-regeneration routes.
#[derive(Debug)]
pub(crate) enum MountedAuthenticatedCredentialRegenerationSubmittedRouteBody {
    /// Submitted body for planning regeneration.
    PlanRegeneration { credential_handle: Vec<u8> },
    /// Submitted body for immediate regeneration execution.
    ExecuteImmediateRegeneration {
        credential_handle: Vec<u8>,
        method_payload: Vec<u8>,
    },
}

impl MountedAuthenticatedCredentialRegenerationSubmittedRouteBody {
    pub(crate) fn plan_regeneration(credential_handle: impl Into<Vec<u8>>) -> Self {
        Self::PlanRegeneration {
            credential_handle: credential_handle.into(),
        }
    }

    pub(crate) fn execute_immediate_regeneration(
        credential_handle: impl Into<Vec<u8>>,
        method_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteImmediateRegeneration {
            credential_handle: credential_handle.into(),
            method_payload: method_payload.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialRegenerationEndpoint {
        match self {
            Self::PlanRegeneration { .. } => {
                MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration
            }
            Self::ExecuteImmediateRegeneration { .. } => {
                MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAuthenticatedCredentialRegenerationRouteRequest, Error> {
        match self {
            Self::PlanRegeneration { credential_handle } => Ok(
                MountedAuthenticatedCredentialRegenerationRouteRequest::PlanRegeneration(
                    PlanMountedAuthenticatedCredentialRegenerationInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                    },
                ),
            ),
            Self::ExecuteImmediateRegeneration {
                credential_handle,
                method_payload,
            } => Ok(
                MountedAuthenticatedCredentialRegenerationRouteRequest::ExecuteImmediateRegeneration(
                    ExecuteMountedAuthenticatedCredentialRegenerationInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                        method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                            method_payload,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted credential-regeneration route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialRegenerationRouteRequest {
    /// Plan a credential-set regeneration.
    PlanRegeneration(PlanMountedAuthenticatedCredentialRegenerationInput),
    /// Execute an immediate credential-set regeneration.
    ExecuteImmediateRegeneration(ExecuteMountedAuthenticatedCredentialRegenerationInput),
}

impl MountedAuthenticatedCredentialRegenerationRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialRegenerationEndpoint {
        match self {
            Self::PlanRegeneration(_) => {
                MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration
            }
            Self::ExecuteImmediateRegeneration(_) => {
                MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration
            }
        }
    }
}

/// Mounted input for immediately rotating one credential owned by the authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedAuthenticatedCredentialRotationInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque credential handle returned by authenticated credential inventory.
    pub credential_handle: MountedCredentialHandle,
    /// Method-specific rotation payload for the target credential's registered method.
    pub method_payload: CredentialLifecycleMethodPayload,
}

impl ExecuteMountedAuthenticatedCredentialRotationInput {
    pub(crate) fn into_runtime_input(self) -> ExecuteAuthenticatedCredentialRotationInput {
        ExecuteAuthenticatedCredentialRotationInput {
            now: self.now,
            target_credential_instance_id: self.credential_handle.into_credential_instance_id(),
            method_payload: self.method_payload,
        }
    }
}

/// Mounted authenticated credential-rotation route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialRotationEndpoint {
    /// Execute immediate rotation for one credential owned by the current authenticated subject.
    ExecuteImmediateRotation,
}

pub(crate) const MOUNTED_AUTHENTICATED_CREDENTIAL_ROTATION_EXECUTE_ROUTE_PATH: &str =
    "/credentials/rotate/execute";

impl MountedAuthenticatedCredentialRotationEndpoint {
    pub(crate) const fn all() -> [Self; 1] {
        [Self::ExecuteImmediateRotation]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_AUTHENTICATED_CREDENTIAL_ROTATION_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteImmediateRotation)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::ExecuteImmediateRotation => {
                MOUNTED_AUTHENTICATED_CREDENTIAL_ROTATION_EXECUTE_ROUTE_PATH
            }
        }
    }
}

/// Submitted body material accepted by authenticated credential-rotation routes.
#[derive(Debug)]
pub(crate) enum MountedAuthenticatedCredentialRotationSubmittedRouteBody {
    /// Submitted body for immediate rotation execution.
    ExecuteImmediateRotation {
        credential_handle: Vec<u8>,
        method_payload: Vec<u8>,
    },
}

impl MountedAuthenticatedCredentialRotationSubmittedRouteBody {
    pub(crate) fn execute_immediate_rotation(
        credential_handle: impl Into<Vec<u8>>,
        method_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteImmediateRotation {
            credential_handle: credential_handle.into(),
            method_payload: method_payload.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialRotationEndpoint {
        match self {
            Self::ExecuteImmediateRotation { .. } => {
                MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedAuthenticatedCredentialRotationRouteRequest, Error> {
        match self {
            Self::ExecuteImmediateRotation {
                credential_handle,
                method_payload,
            } => Ok(
                MountedAuthenticatedCredentialRotationRouteRequest::ExecuteImmediateRotation(
                    ExecuteMountedAuthenticatedCredentialRotationInput {
                        now,
                        credential_handle: MountedCredentialHandle::from_submitted_bytes(
                            credential_handle,
                        )?,
                        method_payload: CredentialLifecycleMethodPayload::try_from_bytes(
                            method_payload,
                        )?,
                    },
                ),
            ),
        }
    }
}

/// Typed mounted credential-rotation route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedAuthenticatedCredentialRotationRouteRequest {
    /// Execute immediate credential rotation.
    ExecuteImmediateRotation(ExecuteMountedAuthenticatedCredentialRotationInput),
}

impl MountedAuthenticatedCredentialRotationRouteRequest {
    pub(crate) const fn endpoint(&self) -> MountedAuthenticatedCredentialRotationEndpoint {
        match self {
            Self::ExecuteImmediateRotation(_) => {
                MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation
            }
        }
    }
}

/// Mounted delayed credential lifecycle route selected by HTTP method and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedDelayedCredentialLifecycleEndpoint {
    /// Execute one matured delayed credential reset.
    ExecuteReset,
    /// Execute one matured delayed credential replacement or regeneration.
    ExecuteReplaceOrRegenerate,
    /// Execute one matured delayed credential removal.
    ExecuteRemoval,
}

pub(crate) const MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_RESET_EXECUTE_ROUTE_PATH: &str =
    "/credentials/delayed/reset/execute";
pub(crate) const MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_REPLACE_OR_REGENERATE_EXECUTE_ROUTE_PATH:
    &str = "/credentials/delayed/replace-or-regenerate/execute";
pub(crate) const MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_REMOVAL_EXECUTE_ROUTE_PATH: &str =
    "/credentials/delayed/remove/execute";

impl MountedDelayedCredentialLifecycleEndpoint {
    pub(crate) const fn all() -> [Self; 3] {
        [
            Self::ExecuteReset,
            Self::ExecuteReplaceOrRegenerate,
            Self::ExecuteRemoval,
        ]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_RESET_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteReset)
            }
            MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_REPLACE_OR_REGENERATE_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteReplaceOrRegenerate)
            }
            MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_REMOVAL_EXECUTE_ROUTE_PATH => {
                Some(Self::ExecuteRemoval)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::ExecuteReset => MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_RESET_EXECUTE_ROUTE_PATH,
            Self::ExecuteReplaceOrRegenerate => {
                MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_REPLACE_OR_REGENERATE_EXECUTE_ROUTE_PATH
            }
            Self::ExecuteRemoval => MOUNTED_DELAYED_CREDENTIAL_LIFECYCLE_REMOVAL_EXECUTE_ROUTE_PATH,
        }
    }
}

/// Method payload accepted by the mounted delayed credential lifecycle executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedCredentialLifecycleMethodPayload {
    /// Reset-specific method payload for delayed credential reset.
    Reset(CredentialResetMethodPayload),
    /// Method payload for delayed replacement or regeneration.
    ReplaceOrRegenerate(CredentialLifecycleMethodPayload),
    /// No method payload; valid for core-owned delayed removal.
    NoMethodPayload,
}

/// Mounted input for executing one matured delayed credential lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecuteMountedDelayedCredentialLifecycleActionInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Opaque pending action handle returned by the scheduling transition.
    pub pending_action_id: PendingCredentialLifecycleActionId,
    /// Method-specific execution payload, if this action requires one.
    pub method_payload: MountedDelayedCredentialLifecycleMethodPayload,
}

/// Submitted body material accepted by delayed credential lifecycle execution routes.
#[derive(Debug)]
pub(crate) enum MountedDelayedCredentialLifecycleSubmittedRouteBody {
    /// Submitted body for delayed credential reset execution.
    ExecuteReset {
        pending_action_id: Vec<u8>,
        method_payload: Vec<u8>,
    },
    /// Submitted body for delayed credential replacement or regeneration execution.
    ExecuteReplaceOrRegenerate {
        pending_action_id: Vec<u8>,
        method_payload: Vec<u8>,
    },
    /// Submitted body for delayed credential removal execution.
    ExecuteRemoval { pending_action_id: Vec<u8> },
}

impl MountedDelayedCredentialLifecycleSubmittedRouteBody {
    pub(crate) fn execute_reset(
        pending_action_id: impl Into<Vec<u8>>,
        method_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteReset {
            pending_action_id: pending_action_id.into(),
            method_payload: method_payload.into(),
        }
    }

    pub(crate) fn execute_replace_or_regenerate(
        pending_action_id: impl Into<Vec<u8>>,
        method_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::ExecuteReplaceOrRegenerate {
            pending_action_id: pending_action_id.into(),
            method_payload: method_payload.into(),
        }
    }

    pub(crate) fn execute_removal(pending_action_id: impl Into<Vec<u8>>) -> Self {
        Self::ExecuteRemoval {
            pending_action_id: pending_action_id.into(),
        }
    }

    pub(crate) const fn endpoint(&self) -> MountedDelayedCredentialLifecycleEndpoint {
        match self {
            Self::ExecuteReset { .. } => MountedDelayedCredentialLifecycleEndpoint::ExecuteReset,
            Self::ExecuteReplaceOrRegenerate { .. } => {
                MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate
            }
            Self::ExecuteRemoval { .. } => {
                MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval
            }
        }
    }

    pub(crate) fn into_route_request(
        self,
        now: UnixSeconds,
    ) -> Result<MountedDelayedCredentialLifecycleRouteRequest, Error> {
        let request = match self {
            Self::ExecuteReset {
                pending_action_id,
                method_payload,
            } => ExecuteMountedDelayedCredentialLifecycleActionInput {
                now,
                pending_action_id: PendingCredentialLifecycleActionId::from_bytes(
                    pending_action_id,
                )?,
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::Reset(
                    CredentialResetMethodPayload::try_from_bytes(method_payload)?,
                ),
            },
            Self::ExecuteReplaceOrRegenerate {
                pending_action_id,
                method_payload,
            } => ExecuteMountedDelayedCredentialLifecycleActionInput {
                now,
                pending_action_id: PendingCredentialLifecycleActionId::from_bytes(
                    pending_action_id,
                )?,
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(
                    CredentialLifecycleMethodPayload::try_from_bytes(method_payload)?,
                ),
            },
            Self::ExecuteRemoval { pending_action_id } => {
                ExecuteMountedDelayedCredentialLifecycleActionInput {
                    now,
                    pending_action_id: PendingCredentialLifecycleActionId::from_bytes(
                        pending_action_id,
                    )?,
                    method_payload: MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
                }
            }
        };
        Ok(MountedDelayedCredentialLifecycleRouteRequest::Execute(
            request,
        ))
    }
}

/// Typed mounted delayed credential lifecycle route request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedCredentialLifecycleRouteRequest {
    /// Execute one matured delayed credential lifecycle action.
    Execute(ExecuteMountedDelayedCredentialLifecycleActionInput),
}

impl MountedDelayedCredentialLifecycleRouteRequest {
    pub(crate) fn endpoint(&self) -> MountedDelayedCredentialLifecycleEndpoint {
        match self {
            Self::Execute(request) => match &request.method_payload {
                MountedDelayedCredentialLifecycleMethodPayload::Reset(_) => {
                    MountedDelayedCredentialLifecycleEndpoint::ExecuteReset
                }
                MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(_) => {
                    MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate
                }
                MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload => {
                    MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval
                }
            },
        }
    }
}

/// Stored delayed credential lifecycle action facts visible to the mounted executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedExecutableDelayedCredentialLifecycleAction {
    pending_action_id: PendingCredentialLifecycleActionId,
    subject_id: SubjectId,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
    requested_at: UnixSeconds,
    earliest_execute_at: UnixSeconds,
    expires_at: UnixSeconds,
}

impl MountedExecutableDelayedCredentialLifecycleAction {
    pub(crate) fn from_pending_action(
        pending_action: &PendingCredentialLifecycleActionRecord,
        now: UnixSeconds,
    ) -> Result<Self, Error> {
        if !pending_action.is_executable_at(now) {
            return Err(Error::PendingCredentialLifecycleActionNotExecutable);
        }
        match pending_action.action {
            CredentialLifecycleAction::Reset
            | CredentialLifecycleAction::Replace
            | CredentialLifecycleAction::Remove
            | CredentialLifecycleAction::Regenerate => {}
            CredentialLifecycleAction::Create
            | CredentialLifecycleAction::Disable
            | CredentialLifecycleAction::Rotate
            | CredentialLifecycleAction::RecoverSubjectAccess => {
                return Err(Error::CredentialLifecycleActionNotAuthorized);
            }
        }
        Ok(Self {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: pending_action.subject_id.clone(),
            target_credential_instance_id: pending_action.target_credential_instance_id.clone(),
            action: pending_action.action,
            requested_at: pending_action.requested_at,
            earliest_execute_at: pending_action.earliest_execute_at,
            expires_at: pending_action.expires_at,
        })
    }

    pub(crate) const fn pending_action_id(&self) -> &PendingCredentialLifecycleActionId {
        &self.pending_action_id
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

    pub(crate) const fn earliest_execute_at(&self) -> UnixSeconds {
        self.earliest_execute_at
    }

    pub(crate) const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    pub(crate) fn runtime_execution_input(
        &self,
        request: ExecuteMountedDelayedCredentialLifecycleActionInput,
    ) -> Result<MountedDelayedCredentialLifecycleRuntimeInput, Error> {
        if request.pending_action_id != self.pending_action_id {
            return Err(Error::LoadedStateContradiction(
                "mounted delayed credential lifecycle request and loaded action ids differ",
            ));
        }
        match (self.action, request.method_payload) {
            (
                CredentialLifecycleAction::Reset,
                MountedDelayedCredentialLifecycleMethodPayload::Reset(method_payload),
            ) => Ok(MountedDelayedCredentialLifecycleRuntimeInput::Reset(
                ExecuteMaturePendingCredentialResetInput {
                    now: request.now,
                    pending_action_id: self.pending_action_id.clone(),
                    method_payload,
                },
            )),
            (
                CredentialLifecycleAction::Reset,
                MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            ) => Err(Error::CredentialLifecycleExecutionMissingMethodCommitWork),
            (
                CredentialLifecycleAction::Reset,
                MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(_),
            ) => Err(Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch),
            (
                CredentialLifecycleAction::Replace | CredentialLifecycleAction::Regenerate,
                MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(method_payload),
            ) => Ok(
                MountedDelayedCredentialLifecycleRuntimeInput::NonResetCredentialLifecycle(
                    ExecuteMaturePendingCredentialLifecycleActionInput {
                        now: request.now,
                        pending_action_id: self.pending_action_id.clone(),
                        method_payload: Some(method_payload),
                    },
                ),
            ),
            (
                CredentialLifecycleAction::Replace | CredentialLifecycleAction::Regenerate,
                MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            ) => Err(Error::CredentialLifecycleExecutionMissingMethodCommitWork),
            (
                CredentialLifecycleAction::Replace | CredentialLifecycleAction::Regenerate,
                MountedDelayedCredentialLifecycleMethodPayload::Reset(_),
            ) => Err(Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch),
            (
                CredentialLifecycleAction::Remove,
                MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            ) => Ok(
                MountedDelayedCredentialLifecycleRuntimeInput::NonResetCredentialLifecycle(
                    ExecuteMaturePendingCredentialLifecycleActionInput {
                        now: request.now,
                        pending_action_id: self.pending_action_id.clone(),
                        method_payload: None,
                    },
                ),
            ),
            (
                CredentialLifecycleAction::Remove,
                MountedDelayedCredentialLifecycleMethodPayload::Reset(_)
                | MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(_),
            ) => Err(Error::CredentialLifecycleExecutionUnexpectedMethodCommitWork),
            (
                CredentialLifecycleAction::Create
                | CredentialLifecycleAction::Disable
                | CredentialLifecycleAction::Rotate
                | CredentialLifecycleAction::RecoverSubjectAccess,
                _,
            ) => Err(Error::CredentialLifecycleActionNotAuthorized),
        }
    }
}

/// Private runtime facade selected by the mounted delayed lifecycle executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedCredentialLifecycleRuntimeInput {
    /// Execute a delayed credential reset.
    Reset(ExecuteMaturePendingCredentialResetInput),
    /// Execute a delayed non-reset credential lifecycle action.
    NonResetCredentialLifecycle(ExecuteMaturePendingCredentialLifecycleActionInput),
}

/// Mounted response surface for a committed authenticated credential addition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialAdditionCommittedOutcome {
    /// A credential was added to the authenticated subject.
    CredentialAdded {
        subject_id: SubjectId,
        credential_instance_id: VerifiedProofSourceId,
    },
}

impl MountedCredentialAdditionCommittedOutcome {
    pub(crate) fn from_committed_runtime_execution(
        execution: &AuthWebRuntimeExecution,
    ) -> Option<Self> {
        Self::from_committed_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_committed_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialAdded(outcome) => Some(Self::CredentialAdded {
                subject_id: outcome.subject_id.clone(),
                credential_instance_id: outcome.credential_instance_id.clone(),
            }),
            _ => None,
        }
    }
}

/// Mounted response surface for authenticated credential addition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialAdditionServiceOutcome {
    /// The credential addition committed.
    CredentialAdded {
        subject_id: SubjectId,
        credential_instance_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before adding a credential.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialAdditionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialAdded(outcome) => Some(Self::CredentialAdded {
                subject_id: outcome.subject_id.clone(),
                credential_instance_id: outcome.credential_instance_id.clone(),
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

    pub(crate) fn committed_outcome(&self) -> Option<MountedCredentialAdditionCommittedOutcome> {
        match self {
            Self::CredentialAdded {
                subject_id,
                credential_instance_id,
            } => Some(MountedCredentialAdditionCommittedOutcome::CredentialAdded {
                subject_id: subject_id.clone(),
                credential_instance_id: credential_instance_id.clone(),
            }),
            Self::NeedsFullAuthentication | Self::NeedsStepUp { .. } => None,
        }
    }
}

/// Safe credential metadata shown to the authenticated subject for lifecycle targeting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedCredentialInventoryEntry {
    credential_handle: MountedCredentialHandle,
    kind: CredentialInstanceKind,
    method_label: String,
    reset_policy_role: CredentialResetPolicyRole,
}

impl MountedCredentialInventoryEntry {
    pub(crate) fn from_metadata(metadata: CredentialInstanceMetadata) -> Self {
        Self {
            credential_handle: MountedCredentialHandle::from_credential_instance_id(
                metadata.credential_instance_id().clone(),
            ),
            kind: metadata.kind(),
            method_label: metadata.method_label().to_owned(),
            reset_policy_role: metadata.reset_policy_role(),
        }
    }

    pub(crate) const fn credential_handle(&self) -> &MountedCredentialHandle {
        &self.credential_handle
    }

    pub(crate) const fn kind(&self) -> CredentialInstanceKind {
        self.kind
    }

    pub(crate) fn method_label(&self) -> &str {
        &self.method_label
    }

    pub(crate) const fn reset_policy_role(&self) -> CredentialResetPolicyRole {
        self.reset_policy_role
    }
}

/// Mounted response surface for authenticated credential inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialInventoryServiceOutcome {
    /// Active credential handles for the authenticated subject.
    Credentials {
        credentials: Vec<MountedCredentialInventoryEntry>,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
}

impl MountedCredentialInventoryServiceOutcome {
    pub(crate) fn credentials(credentials: Vec<CredentialInstanceMetadata>) -> Result<Self, Error> {
        if credentials
            .iter()
            .any(|credential| !credential.can_produce_new_proofs())
        {
            return Err(Error::LoadedStateContradiction(
                "credential inventory contains inactive credential metadata",
            ));
        }
        Ok(Self::Credentials {
            credentials: credentials
                .into_iter()
                .map(MountedCredentialInventoryEntry::from_metadata)
                .collect(),
        })
    }
}

/// User-visible body for mounted authenticated credential inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialInventoryRouteResponseBody {
    /// Active credentials for the authenticated subject.
    Credentials {
        credentials: Vec<MountedCredentialInventoryEntry>,
    },
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
}

impl MountedCredentialInventoryRouteResponseBody {
    pub(crate) fn from_service_outcome(outcome: MountedCredentialInventoryServiceOutcome) -> Self {
        match outcome {
            MountedCredentialInventoryServiceOutcome::Credentials { credentials } => {
                Self::Credentials { credentials }
            }
            MountedCredentialInventoryServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
        }
    }
}

/// Mounted response surface for unauthenticated recovery attempt start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome {
    /// The recovery attempt was started.
    RecoveryAttemptStarted {
        attempt_id: ActiveProofAttemptId,
        expires_at: UnixSeconds,
    },
}

impl MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        match execution.outcome() {
            Outcome::ActiveProofAttemptStarted {
                attempt_id,
                expires_at,
            } => Some(Self::RecoveryAttemptStarted {
                attempt_id: attempt_id.clone(),
                expires_at: *expires_at,
            }),
            _ => None,
        }
    }
}

/// Mounted response surface for unauthenticated recovery proof completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome {
    /// The recovery proof was accepted and recorded on the attempt.
    RecoveryProofAccepted {
        #[cfg(test)]
        attempt_id: ActiveProofAttemptId,
        #[cfg(test)]
        proof: ProofSummary,
    },
    /// The recovery proof was rejected authoritatively.
    RecoveryProofRejected {
        #[cfg(test)]
        attempt_id: ActiveProofAttemptId,
        #[cfg(test)]
        attempt_was_deleted: bool,
    },
}

impl MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        match execution.outcome() {
            Outcome::ActiveProofCompleted { attempt_id, proof } => {
                Some(Self::recovery_proof_accepted(attempt_id, proof))
            }
            Outcome::ActiveProofFailureRecorded {
                attempt_id,
                attempt_was_deleted,
            } => Some(Self::recovery_proof_rejected(
                attempt_id,
                *attempt_was_deleted,
            )),
            _ => None,
        }
    }

    #[cfg(test)]
    fn recovery_proof_accepted(attempt_id: &ActiveProofAttemptId, proof: &ProofSummary) -> Self {
        Self::RecoveryProofAccepted {
            attempt_id: attempt_id.clone(),
            proof: proof.clone(),
        }
    }

    #[cfg(not(test))]
    fn recovery_proof_accepted(_: &ActiveProofAttemptId, _: &ProofSummary) -> Self {
        Self::RecoveryProofAccepted {}
    }

    #[cfg(test)]
    fn recovery_proof_rejected(
        attempt_id: &ActiveProofAttemptId,
        attempt_was_deleted: bool,
    ) -> Self {
        Self::RecoveryProofRejected {
            attempt_id: attempt_id.clone(),
            attempt_was_deleted,
        }
    }

    #[cfg(not(test))]
    fn recovery_proof_rejected(_: &ActiveProofAttemptId, _: bool) -> Self {
        Self::RecoveryProofRejected {}
    }
}

/// Mounted response surface for authenticated credential reset planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialResetPlanningServiceOutcome {
    /// Reset may execute immediately in the current ceremony.
    AuthorizedImmediate {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// Reset must wait until the pending action matures.
    PendingActionCreated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before planning reset.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialResetPlanningServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
                subject_id,
                target_credential_instance_id,
            }) => Some(Self::AuthorizedImmediate {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
            }),
            Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
                subject_id,
                target_credential_instance_id,
                pending_action_id,
                earliest_execute_at,
                expires_at,
            }) => Some(Self::PendingActionCreated {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
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

/// Mounted response surface for authenticated immediate credential reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialResetExecutionServiceOutcome {
    /// The target credential was reset.
    CredentialReset {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before resetting the credential.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialResetExecutionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialResetExecuted(outcome) if outcome.pending_action_id.is_none() => {
                Some(Self::CredentialReset {
                    subject_id: outcome.subject_id.clone(),
                    target_credential_instance_id: outcome.target_credential_instance_id.clone(),
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

/// User-visible body for mounted authenticated credential-reset route responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialResetRouteResponseBody {
    /// Reset may execute immediately.
    ResetAuthorizedImmediate,
    /// Reset must wait until the delayed action matures.
    DelayedResetScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Reset executed after commit.
    CredentialReset,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before resetting this credential.
    NeedsStepUp,
}

impl MountedCredentialResetRouteResponseBody {
    pub(crate) fn from_planning_service_outcome(
        outcome: &MountedCredentialResetPlanningServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialResetPlanningServiceOutcome::AuthorizedImmediate { .. } => {
                Self::ResetAuthorizedImmediate
            }
            MountedCredentialResetPlanningServiceOutcome::PendingActionCreated {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedResetScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedCredentialResetPlanningServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialResetPlanningServiceOutcome::NeedsStepUp { .. } => Self::NeedsStepUp,
        }
    }

    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedCredentialResetExecutionServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialResetExecutionServiceOutcome::CredentialReset { .. } => {
                Self::CredentialReset
            }
            MountedCredentialResetExecutionServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialResetExecutionServiceOutcome::NeedsStepUp { .. } => Self::NeedsStepUp,
        }
    }
}

/// Mounted response surface for delayed unauthenticated credential recovery reset scheduling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome {
    /// Recovery proof scheduled a delayed reset action.
    PendingCredentialResetActionCreated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
}

impl MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
                subject_id,
                target_credential_instance_id,
                pending_action_id,
                earliest_execute_at,
                expires_at,
            }) => Some(Self::PendingCredentialResetActionCreated {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            }),
            _ => None,
        }
    }
}

/// Mounted response surface for immediate unauthenticated credential recovery reset execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome {
    /// The recovered credential was reset.
    CredentialReset {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
}

impl MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialResetExecuted(outcome) if outcome.pending_action_id.is_none() => {
                Some(Self::CredentialReset {
                    subject_id: outcome.subject_id.clone(),
                    target_credential_instance_id: outcome.target_credential_instance_id.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Mounted response surface for authenticated credential replacement planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialReplacementPlanningServiceOutcome {
    /// Replacement may execute immediately in the current ceremony.
    AuthorizedImmediate {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// Replacement must wait until the pending action matures.
    PendingActionCreated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before planning replacement.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialReplacementPlanningServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialReplacementPlanned(
                CredentialReplacementOutcome::AuthorizedImmediate {
                    subject_id,
                    target_credential_instance_id,
                },
            ) => Some(Self::AuthorizedImmediate {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
            }),
            Outcome::CredentialReplacementPlanned(
                CredentialReplacementOutcome::PendingActionCreated {
                    subject_id,
                    target_credential_instance_id,
                    pending_action_id,
                    earliest_execute_at,
                    expires_at,
                },
            ) => Some(Self::PendingActionCreated {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
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

/// Mounted response surface for authenticated immediate credential replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialReplacementExecutionServiceOutcome {
    /// The target credential was replaced and superseded.
    CredentialReplaced {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before replacing the credential.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialReplacementExecutionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialReplacementExecuted(outcome) => Some(Self::CredentialReplaced {
                subject_id: outcome.subject_id.clone(),
                target_credential_instance_id: outcome.target_credential_instance_id.clone(),
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

/// User-visible route body for authenticated credential replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialReplacementRouteResponseBody {
    /// Replacement was authorized for immediate execution.
    ReplacementAuthorizedImmediate,
    /// Replacement was scheduled as a delayed pending action.
    DelayedReplacementScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Replacement executed after commit.
    CredentialReplaced,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before replacing this credential.
    NeedsStepUp,
}

impl MountedCredentialReplacementRouteResponseBody {
    pub(crate) fn from_planning_service_outcome(
        outcome: &MountedCredentialReplacementPlanningServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialReplacementPlanningServiceOutcome::AuthorizedImmediate { .. } => {
                Self::ReplacementAuthorizedImmediate
            }
            MountedCredentialReplacementPlanningServiceOutcome::PendingActionCreated {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedReplacementScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedCredentialReplacementPlanningServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialReplacementPlanningServiceOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }

    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedCredentialReplacementExecutionServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialReplacementExecutionServiceOutcome::CredentialReplaced { .. } => {
                Self::CredentialReplaced
            }
            MountedCredentialReplacementExecutionServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialReplacementExecutionServiceOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for authenticated credential removal planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRemovalPlanningServiceOutcome {
    /// Removal may execute immediately in the current ceremony.
    AuthorizedImmediate {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// Removal must wait until the pending action matures.
    PendingActionCreated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before planning removal.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialRemovalPlanningServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::AuthorizedImmediate {
                subject_id,
                target_credential_instance_id,
            }) => Some(Self::AuthorizedImmediate {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
            }),
            Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::PendingActionCreated {
                subject_id,
                target_credential_instance_id,
                pending_action_id,
                earliest_execute_at,
                expires_at,
            }) => Some(Self::PendingActionCreated {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
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

/// Mounted response surface for authenticated immediate credential removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRemovalExecutionServiceOutcome {
    /// The target credential was removed from proof production.
    CredentialRemoved {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before removing the credential.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialRemovalExecutionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialRemovalExecuted(outcome) => Some(Self::CredentialRemoved {
                subject_id: outcome.subject_id.clone(),
                target_credential_instance_id: outcome.target_credential_instance_id.clone(),
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

/// User-visible route body for authenticated credential removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRemovalRouteResponseBody {
    /// Removal was authorized for immediate execution.
    RemovalAuthorizedImmediate,
    /// Removal was scheduled as a delayed pending action.
    DelayedRemovalScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Removal executed after commit.
    CredentialRemoved,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before removing this credential.
    NeedsStepUp,
}

impl MountedCredentialRemovalRouteResponseBody {
    pub(crate) fn from_planning_service_outcome(
        outcome: &MountedCredentialRemovalPlanningServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialRemovalPlanningServiceOutcome::AuthorizedImmediate { .. } => {
                Self::RemovalAuthorizedImmediate
            }
            MountedCredentialRemovalPlanningServiceOutcome::PendingActionCreated {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedRemovalScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedCredentialRemovalPlanningServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialRemovalPlanningServiceOutcome::NeedsStepUp { .. } => Self::NeedsStepUp,
        }
    }

    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedCredentialRemovalExecutionServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialRemovalExecutionServiceOutcome::CredentialRemoved { .. } => {
                Self::CredentialRemoved
            }
            MountedCredentialRemovalExecutionServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialRemovalExecutionServiceOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for authenticated credential-set regeneration planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRegenerationPlanningServiceOutcome {
    /// Regeneration may execute immediately in the current ceremony.
    AuthorizedImmediate {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// Regeneration must wait until the pending action matures.
    PendingActionCreated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        pending_action_id: PendingCredentialLifecycleActionId,
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before planning regeneration.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialRegenerationPlanningServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialRegenerationPlanned(
                CredentialRegenerationOutcome::AuthorizedImmediate {
                    subject_id,
                    target_credential_instance_id,
                },
            ) => Some(Self::AuthorizedImmediate {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
            }),
            Outcome::CredentialRegenerationPlanned(
                CredentialRegenerationOutcome::PendingActionCreated {
                    subject_id,
                    target_credential_instance_id,
                    pending_action_id,
                    earliest_execute_at,
                    expires_at,
                },
            ) => Some(Self::PendingActionCreated {
                subject_id: subject_id.clone(),
                target_credential_instance_id: target_credential_instance_id.clone(),
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

/// Mounted response surface for authenticated immediate credential-set regeneration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRegenerationExecutionServiceOutcome {
    /// The target credential set was regenerated in place.
    CredentialRegenerated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before regenerating the credential set.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialRegenerationExecutionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialRegenerated(outcome) => Some(Self::CredentialRegenerated {
                subject_id: outcome.subject_id.clone(),
                target_credential_instance_id: outcome.target_credential_instance_id.clone(),
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

/// User-visible route body for authenticated credential-set regeneration.
pub(crate) enum MountedCredentialRegenerationRouteResponseBody {
    /// Regeneration was authorized for immediate execution.
    RegenerationAuthorizedImmediate,
    /// Regeneration was scheduled as a delayed pending action.
    DelayedRegenerationScheduled {
        earliest_execute_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// Regeneration executed after commit.
    CredentialRegenerated {
        generated_recovery_codes: Option<MountedGeneratedRecoveryCodeSetRouteResponseBody>,
    },
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before regenerating this credential set.
    NeedsStepUp,
}

impl fmt::Debug for MountedCredentialRegenerationRouteResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegenerationAuthorizedImmediate => f.write_str(
                "MountedCredentialRegenerationRouteResponseBody::RegenerationAuthorizedImmediate",
            ),
            Self::DelayedRegenerationScheduled {
                earliest_execute_at,
                expires_at,
            } => f
                .debug_struct(
                    "MountedCredentialRegenerationRouteResponseBody::DelayedRegenerationScheduled",
                )
                .field("earliest_execute_at", earliest_execute_at)
                .field("expires_at", expires_at)
                .finish(),
            Self::CredentialRegenerated {
                generated_recovery_codes,
            } => f
                .debug_struct(
                    "MountedCredentialRegenerationRouteResponseBody::CredentialRegenerated",
                )
                .field(
                    "generated_recovery_code_count",
                    &generated_recovery_codes
                        .as_ref()
                        .map(MountedGeneratedRecoveryCodeSetRouteResponseBody::len)
                        .unwrap_or(0),
                )
                .finish(),
            Self::NeedsFullAuthentication => f.write_str(
                "MountedCredentialRegenerationRouteResponseBody::NeedsFullAuthentication",
            ),
            Self::NeedsStepUp => {
                f.write_str("MountedCredentialRegenerationRouteResponseBody::NeedsStepUp")
            }
        }
    }
}

impl MountedCredentialRegenerationRouteResponseBody {
    pub(crate) fn from_planning_service_outcome(
        outcome: &MountedCredentialRegenerationPlanningServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialRegenerationPlanningServiceOutcome::AuthorizedImmediate { .. } => {
                Self::RegenerationAuthorizedImmediate
            }
            MountedCredentialRegenerationPlanningServiceOutcome::PendingActionCreated {
                earliest_execute_at,
                expires_at,
                ..
            } => Self::DelayedRegenerationScheduled {
                earliest_execute_at: *earliest_execute_at,
                expires_at: *expires_at,
            },
            MountedCredentialRegenerationPlanningServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialRegenerationPlanningServiceOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }

    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedCredentialRegenerationExecutionServiceOutcome,
        generated_recovery_codes: Option<MountedGeneratedRecoveryCodeSetRouteResponseBody>,
    ) -> Self {
        match outcome {
            MountedCredentialRegenerationExecutionServiceOutcome::CredentialRegenerated {
                ..
            } => Self::CredentialRegenerated {
                generated_recovery_codes,
            },
            MountedCredentialRegenerationExecutionServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialRegenerationExecutionServiceOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for authenticated immediate credential rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRotationExecutionServiceOutcome {
    /// The target credential was rotated in place.
    CredentialRotated {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
    },
    /// No live authenticated session was available.
    NeedsFullAuthentication,
    /// The current session must satisfy step-up before rotating the credential.
    NeedsStepUp {
        session_id: SessionId,
        subject_id: SubjectId,
    },
}

impl MountedCredentialRotationExecutionServiceOutcome {
    pub(crate) fn from_runtime_execution(execution: &AuthWebRuntimeExecution) -> Option<Self> {
        Self::from_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialRotated(outcome) => Some(Self::CredentialRotated {
                subject_id: outcome.subject_id.clone(),
                target_credential_instance_id: outcome.target_credential_instance_id.clone(),
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

/// User-visible route body for authenticated credential rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedCredentialRotationRouteResponseBody {
    /// Rotation executed after commit.
    CredentialRotated,
    /// The caller has no live authenticated session.
    NeedsFullAuthentication,
    /// The caller must satisfy step-up before rotating this credential.
    NeedsStepUp,
}

impl MountedCredentialRotationRouteResponseBody {
    pub(crate) fn from_execution_service_outcome(
        outcome: &MountedCredentialRotationExecutionServiceOutcome,
    ) -> Self {
        match outcome {
            MountedCredentialRotationExecutionServiceOutcome::CredentialRotated { .. } => {
                Self::CredentialRotated
            }
            MountedCredentialRotationExecutionServiceOutcome::NeedsFullAuthentication => {
                Self::NeedsFullAuthentication
            }
            MountedCredentialRotationExecutionServiceOutcome::NeedsStepUp { .. } => {
                Self::NeedsStepUp
            }
        }
    }
}

/// Mounted response surface for a committed delayed credential lifecycle execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedCredentialLifecycleCommittedOutcome {
    /// A delayed credential reset executed.
    CredentialResetExecuted {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        pending_action_id: PendingCredentialLifecycleActionId,
    },
    /// A delayed non-reset credential lifecycle action executed.
    NonResetCredentialLifecycleActionExecuted {
        subject_id: SubjectId,
        target_credential_instance_id: VerifiedProofSourceId,
        action: CredentialLifecycleAction,
        pending_action_id: PendingCredentialLifecycleActionId,
    },
}

impl MountedDelayedCredentialLifecycleCommittedOutcome {
    pub(crate) fn from_committed_runtime_execution(
        execution: &AuthWebRuntimeExecution,
    ) -> Option<Self> {
        Self::from_committed_reducer_outcome(execution.outcome())
    }

    pub(crate) fn from_committed_reducer_outcome(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::CredentialResetExecuted(outcome) => {
                outcome.pending_action_id.as_ref().map(|pending_action_id| {
                    Self::CredentialResetExecuted {
                        subject_id: outcome.subject_id.clone(),
                        target_credential_instance_id: outcome
                            .target_credential_instance_id
                            .clone(),
                        pending_action_id: pending_action_id.clone(),
                    }
                })
            }
            Outcome::NonResetPendingCredentialLifecycleActionExecuted(outcome) => {
                Some(Self::NonResetCredentialLifecycleActionExecuted {
                    subject_id: outcome.subject_id.clone(),
                    target_credential_instance_id: outcome.target_credential_instance_id.clone(),
                    action: outcome.action,
                    pending_action_id: outcome.pending_action_id.clone(),
                })
            }
            _ => None,
        }
    }
}

/// User-visible route body for delayed credential lifecycle execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedDelayedCredentialLifecycleRouteResponseBody {
    /// A delayed credential reset executed after commit.
    CredentialResetExecuted,
    /// A delayed credential replacement executed after commit.
    CredentialReplacementExecuted,
    /// A delayed credential removal executed after commit.
    CredentialRemovalExecuted,
    /// A delayed credential regeneration executed after commit.
    CredentialRegenerationExecuted,
}

impl MountedDelayedCredentialLifecycleRouteResponseBody {
    pub(crate) fn from_committed_outcome(
        outcome: &MountedDelayedCredentialLifecycleCommittedOutcome,
    ) -> Self {
        match outcome {
            MountedDelayedCredentialLifecycleCommittedOutcome::CredentialResetExecuted { .. } => {
                Self::CredentialResetExecuted
            }
            MountedDelayedCredentialLifecycleCommittedOutcome::NonResetCredentialLifecycleActionExecuted {
                action,
                ..
            } => match action {
                CredentialLifecycleAction::Replace => Self::CredentialReplacementExecuted,
                CredentialLifecycleAction::Remove => Self::CredentialRemovalExecuted,
                CredentialLifecycleAction::Regenerate => Self::CredentialRegenerationExecuted,
                CredentialLifecycleAction::Create
                | CredentialLifecycleAction::Reset
                | CredentialLifecycleAction::Disable
                | CredentialLifecycleAction::Rotate
                | CredentialLifecycleAction::RecoverSubjectAccess => {
                    unreachable!(
                        "delayed credential lifecycle committed outcome exposes only non-reset executable actions"
                    )
                }
            },
        }
    }
}

fn validate_mounted_credential_addition_authority_rules(
    rules: &[CredentialAdditionRecoveryAuthorityRule],
) -> Result<(), Error> {
    if rules.is_empty() {
        return Err(Error::InvalidConfig(
            "mounted credential addition method must define recovery authority rules",
        ));
    }
    if !rules.iter().any(|rule| {
        rule.action == CredentialLifecycleAction::Create
            && rule.timing == RecoveryAuthorityTiming::Immediate
    }) {
        return Err(Error::InvalidConfig(
            "mounted credential addition method must include an immediate create authority",
        ));
    }
    if contains_duplicate_mounted_credential_addition_authority_rules(rules) {
        return Err(Error::InvalidConfig(
            "mounted credential addition method must not duplicate recovery authority rules",
        ));
    }
    Ok(())
}

fn validate_mounted_credential_addition_new_credential_authorities(
    authority_ids: &[RecoveryAuthorityId],
) -> Result<(), Error> {
    if authority_ids.is_empty() {
        return Err(Error::InvalidConfig(
            "mounted credential addition method must define new credential authorities",
        ));
    }
    if contains_duplicate_mounted_credential_addition_new_credential_authorities(authority_ids) {
        return Err(Error::InvalidConfig(
            "mounted credential addition method must not duplicate new credential authorities",
        ));
    }
    Ok(())
}

fn contains_duplicate_mounted_credential_addition_authority_rules(
    rules: &[CredentialAdditionRecoveryAuthorityRule],
) -> bool {
    rules.iter().enumerate().any(|(index, rule)| {
        rules[index + 1..].iter().any(|other| {
            other.action == rule.action
                && other.authority_id == rule.authority_id
                && other.timing == rule.timing
        })
    })
}

fn contains_duplicate_mounted_credential_addition_new_credential_authorities(
    authority_ids: &[RecoveryAuthorityId],
) -> bool {
    authority_ids
        .iter()
        .enumerate()
        .any(|(index, authority_id)| {
            authority_ids[index + 1..]
                .iter()
                .any(|other| other == authority_id)
        })
}
