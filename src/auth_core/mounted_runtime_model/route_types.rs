use super::*;

const MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES: usize = 512;
const MOUNTED_AUTH_HTTP_WEAK_PROOF_GATE_KIND_MAX_BYTES: usize = 16;
pub(crate) const MOUNTED_AUTH_HTTP_JSON_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES)
        + WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES
        + TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES
        + MOUNTED_AUTH_HTTP_WEAK_PROOF_GATE_KIND_MAX_BYTES
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
pub(crate) const MOUNTED_AUTH_HTTP_REQUEST_BODY_MAX_BYTES: usize =
    MOUNTED_AUTH_HTTP_JSON_BODY_MAX_BYTES;
const MOUNTED_AUTH_HTTP_NO_SESSION_RECOVERY_START_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES)
        + WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES
        + MOUNTED_AUTH_HTTP_WEAK_PROOF_GATE_KIND_MAX_BYTES
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_NO_SESSION_RECOVERY_PROOF_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_NO_SESSION_RECOVERY_EXECUTE_RESET_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_FULL_AUTHENTICATION_START_OUT_OF_BAND_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES)
        + WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES
        + MOUNTED_AUTH_HTTP_WEAK_PROOF_GATE_KIND_MAX_BYTES
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_FULL_AUTHENTICATION_OUT_OF_BAND_PROOF_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES)
        + WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES
        + MOUNTED_AUTH_HTTP_WEAK_PROOF_GATE_KIND_MAX_BYTES
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_FULL_AUTHENTICATION_COMPLETE_BODY_MAX_BYTES: usize =
    TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
pub(crate) const MOUNTED_AUTH_HTTP_CREDENTIAL_ADDITION_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_RESET_PLAN_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_RESET_EXECUTE_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_REPLACEMENT_PLAN_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_REPLACEMENT_EXECUTE_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_REMOVAL_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_REGENERATION_PLAN_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_REGENERATION_EXECUTE_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_ROTATION_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_DELAYED_CREDENTIAL_LIFECYCLE_EXECUTE_WITH_METHOD_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + base64url_nopad_encoded_max_bytes(METHOD_COMMIT_PAYLOAD_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_DELAYED_CREDENTIAL_LIFECYCLE_EXECUTE_REMOVAL_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_OUT_OF_BAND_IDENTIFIER_CHANGE_BODY_MAX_BYTES: usize =
    (base64url_nopad_encoded_max_bytes(ID_MAX_BYTES) * 2)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_APPLICATION_SUBJECT_DATA_LIFECYCLE_ACTION_LABEL_MAX_BYTES: usize = 32;
const MOUNTED_AUTH_HTTP_SUBJECT_AUTH_STATE_DELETION_EXECUTE_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_APPLICATION_SUBJECT_DATA_LIFECYCLE_ACTION_LABEL_MAX_BYTES
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_SUBJECT_AUTH_STATE_DELETION_CANCEL_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_CREDENTIAL_LIFECYCLE_ACTION_LABEL_MAX_BYTES: usize = 32;
const MOUNTED_AUTH_HTTP_ADMIN_SUPPORT_REQUEST_BODY_MAX_BYTES: usize =
    (base64url_nopad_encoded_max_bytes(ID_MAX_BYTES) * 2)
        + MOUNTED_AUTH_HTTP_CREDENTIAL_LIFECYCLE_ACTION_LABEL_MAX_BYTES
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
const MOUNTED_AUTH_HTTP_ADMIN_SUPPORT_INTERVENTION_HANDLE_BODY_MAX_BYTES: usize =
    base64url_nopad_encoded_max_bytes(ID_MAX_BYTES)
        + MOUNTED_AUTH_HTTP_JSON_OBJECT_OVERHEAD_MAX_BYTES;
pub(crate) const MOUNTED_AUTH_CREDENTIAL_INVENTORY_ROUTE_PATH: &str = "/credentials";

const fn base64url_nopad_encoded_max_bytes(max_decoded_bytes: usize) -> usize {
    ((max_decoded_bytes + 2) / 3) * 4
}

pub(crate) const MOUNTED_FULL_AUTHENTICATION_START_OUT_OF_BAND_ROUTE_PATH: &str =
    "/authentication/out-of-band/start";
pub(crate) const MOUNTED_FULL_AUTHENTICATION_OUT_OF_BAND_PROOF_ROUTE_PATH: &str =
    "/authentication/out-of-band/proof";
pub(crate) const MOUNTED_FULL_AUTHENTICATION_COMPLETE_ROUTE_PATH: &str = "/authentication/complete";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MountedFullAuthenticationEndpoint {
    StartOutOfBandChallenge,
    SubmitOutOfBandProof,
    CompleteFullAuthentication,
}

impl MountedFullAuthenticationEndpoint {
    pub(crate) const fn all() -> [Self; 3] {
        [
            Self::StartOutOfBandChallenge,
            Self::SubmitOutOfBandProof,
            Self::CompleteFullAuthentication,
        ]
    }

    pub(crate) fn from_method_and_path(method: &Method, path: &str) -> Option<Self> {
        if method != Method::POST {
            return None;
        }
        match path {
            MOUNTED_FULL_AUTHENTICATION_START_OUT_OF_BAND_ROUTE_PATH => {
                Some(Self::StartOutOfBandChallenge)
            }
            MOUNTED_FULL_AUTHENTICATION_OUT_OF_BAND_PROOF_ROUTE_PATH => {
                Some(Self::SubmitOutOfBandProof)
            }
            MOUNTED_FULL_AUTHENTICATION_COMPLETE_ROUTE_PATH => {
                Some(Self::CompleteFullAuthentication)
            }
            _ => None,
        }
    }

    pub(crate) fn method(self) -> Method {
        Method::POST
    }

    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::StartOutOfBandChallenge => {
                MOUNTED_FULL_AUTHENTICATION_START_OUT_OF_BAND_ROUTE_PATH
            }
            Self::SubmitOutOfBandProof => MOUNTED_FULL_AUTHENTICATION_OUT_OF_BAND_PROOF_ROUTE_PATH,
            Self::CompleteFullAuthentication => MOUNTED_FULL_AUTHENTICATION_COMPLETE_ROUTE_PATH,
        }
    }

    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::StartOutOfBandChallenge => {
                MOUNTED_AUTH_HTTP_FULL_AUTHENTICATION_START_OUT_OF_BAND_BODY_MAX_BYTES
            }
            Self::SubmitOutOfBandProof => {
                MOUNTED_AUTH_HTTP_FULL_AUTHENTICATION_OUT_OF_BAND_PROOF_BODY_MAX_BYTES
            }
            Self::CompleteFullAuthentication => {
                MOUNTED_AUTH_HTTP_FULL_AUTHENTICATION_COMPLETE_BODY_MAX_BYTES
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum MountedFullAuthenticationSubmittedRouteBody {
    StartOutOfBandChallenge {
        method_payload: Vec<u8>,
        preflight_gate_kind: WeakProofGateKind,
        preflight_gate_method_label: String,
        preflight_gate_payload: Vec<u8>,
    },
    SubmitOutOfBandProof {
        secret_response: Vec<u8>,
        weak_proof_gate_response: Option<MountedWeakProofGateSubmittedHttpBody>,
    },
    CompleteFullAuthentication {
        trust_device: bool,
        trusted_device_display_label: Option<String>,
    },
}

impl MountedFullAuthenticationSubmittedRouteBody {
    pub(crate) fn start_out_of_band_challenge(
        method_payload: impl Into<Vec<u8>>,
        preflight_gate_kind: WeakProofGateKind,
        preflight_gate_method_label: impl Into<String>,
        preflight_gate_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::StartOutOfBandChallenge {
            method_payload: method_payload.into(),
            preflight_gate_kind,
            preflight_gate_method_label: preflight_gate_method_label.into(),
            preflight_gate_payload: preflight_gate_payload.into(),
        }
    }

    pub(crate) fn submit_out_of_band_proof(
        secret_response: impl Into<Vec<u8>>,
        weak_proof_gate_response: Option<MountedWeakProofGateSubmittedHttpBody>,
    ) -> Self {
        Self::SubmitOutOfBandProof {
            secret_response: secret_response.into(),
            weak_proof_gate_response,
        }
    }

    pub(crate) fn complete_full_authentication(
        trust_device: bool,
        trusted_device_display_label: Option<String>,
    ) -> Self {
        Self::CompleteFullAuthentication {
            trust_device,
            trusted_device_display_label,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedWeakProofGateSubmittedHttpBody {
    kind: WeakProofGateKind,
    method_label: String,
    payload: Vec<u8>,
}

impl MountedWeakProofGateSubmittedHttpBody {
    pub(crate) fn new(
        kind: WeakProofGateKind,
        method_label: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind,
            method_label: method_label.into(),
            payload: payload.into(),
        }
    }

    pub(crate) fn into_response(self) -> Result<WeakProofGateResponse, Error> {
        WeakProofGateResponse::try_from_bytes(self.kind, self.method_label, self.payload)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedFullAuthenticationRouteResponseBody {
    OutOfBandChallengeAccepted { expires_at: UnixSeconds },
    OutOfBandProofAccepted,
    OutOfBandProofRejected,
    FullAuthenticationCompleted,
    FullAuthenticationNotReady,
}

impl MountedNoSessionCredentialRecoveryEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::StartRecoveryAttempt => {
                MOUNTED_AUTH_HTTP_NO_SESSION_RECOVERY_START_BODY_MAX_BYTES
            }
            Self::SubmitRecoveryProof => MOUNTED_AUTH_HTTP_NO_SESSION_RECOVERY_PROOF_BODY_MAX_BYTES,
            Self::ScheduleDelayedReset => 0,
            Self::ExecuteImmediateReset => {
                MOUNTED_AUTH_HTTP_NO_SESSION_RECOVERY_EXECUTE_RESET_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAuthenticatedCredentialResetEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::PlanReset => MOUNTED_AUTH_HTTP_CREDENTIAL_RESET_PLAN_BODY_MAX_BYTES,
            Self::ExecuteImmediateReset => {
                MOUNTED_AUTH_HTTP_CREDENTIAL_RESET_EXECUTE_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAuthenticatedCredentialReplacementEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::PlanReplacement => MOUNTED_AUTH_HTTP_CREDENTIAL_REPLACEMENT_PLAN_BODY_MAX_BYTES,
            Self::ExecuteImmediateReplacement => {
                MOUNTED_AUTH_HTTP_CREDENTIAL_REPLACEMENT_EXECUTE_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAuthenticatedCredentialRemovalEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::PlanRemoval | Self::ExecuteImmediateRemoval => {
                MOUNTED_AUTH_HTTP_CREDENTIAL_REMOVAL_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAuthenticatedCredentialRegenerationEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::PlanRegeneration => MOUNTED_AUTH_HTTP_CREDENTIAL_REGENERATION_PLAN_BODY_MAX_BYTES,
            Self::ExecuteImmediateRegeneration => {
                MOUNTED_AUTH_HTTP_CREDENTIAL_REGENERATION_EXECUTE_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAuthenticatedCredentialRotationEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::ExecuteImmediateRotation => MOUNTED_AUTH_HTTP_CREDENTIAL_ROTATION_BODY_MAX_BYTES,
        }
    }
}

impl MountedDelayedCredentialLifecycleEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::ExecuteReset | Self::ExecuteReplaceOrRegenerate => {
                MOUNTED_AUTH_HTTP_DELAYED_CREDENTIAL_LIFECYCLE_EXECUTE_WITH_METHOD_BODY_MAX_BYTES
            }
            Self::ExecuteRemoval => {
                MOUNTED_AUTH_HTTP_DELAYED_CREDENTIAL_LIFECYCLE_EXECUTE_REMOVAL_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAuthenticatedOutOfBandIdentifierChangeEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::PlanChange | Self::ExecuteImmediateChange => {
                MOUNTED_AUTH_HTTP_OUT_OF_BAND_IDENTIFIER_CHANGE_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedDelayedOutOfBandIdentifierChangeEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::ExecuteChange | Self::CancelChange => {
                MOUNTED_AUTH_HTTP_DELAYED_OUT_OF_BAND_IDENTIFIER_CHANGE_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedDelayedSubjectAuthStateDeletionEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::ScheduleDeletion => 0,
            Self::ExecuteDeletion => {
                MOUNTED_AUTH_HTTP_SUBJECT_AUTH_STATE_DELETION_EXECUTE_BODY_MAX_BYTES
            }
            Self::CancelDeletion => {
                MOUNTED_AUTH_HTTP_SUBJECT_AUTH_STATE_DELETION_CANCEL_BODY_MAX_BYTES
            }
        }
    }
}

impl MountedAdminSupportEndpoint {
    pub(crate) const fn max_collected_http_body_bytes(self) -> usize {
        match self {
            Self::RequestIntervention => MOUNTED_AUTH_HTTP_ADMIN_SUPPORT_REQUEST_BODY_MAX_BYTES,
            Self::ApproveIntervention | Self::DenyIntervention | Self::ExpireIntervention => {
                MOUNTED_AUTH_HTTP_ADMIN_SUPPORT_INTERVENTION_HANDLE_BODY_MAX_BYTES
            }
        }
    }
}

/// User-visible body returned by the private mounted auth route service.
#[derive(Debug)]
pub(super) enum MountedAuthRouteResponseBody {
    FullAuthentication(MountedFullAuthenticationRouteResponseBody),
    NoSessionCredentialRecovery(MountedNoSessionCredentialRecoveryRouteResponseBody),
    AuthenticatedCredentialInventory(MountedCredentialInventoryRouteResponseBody),
    AuthenticatedCredentialAddition(MountedCredentialAdditionRouteResponseBody),
    AuthenticatedCredentialReset(MountedCredentialResetRouteResponseBody),
    AuthenticatedCredentialReplacement(MountedCredentialReplacementRouteResponseBody),
    AuthenticatedCredentialRemoval(MountedCredentialRemovalRouteResponseBody),
    AuthenticatedCredentialRegeneration(MountedCredentialRegenerationRouteResponseBody),
    AuthenticatedCredentialRotation(MountedCredentialRotationRouteResponseBody),
    DelayedCredentialLifecycle(MountedDelayedCredentialLifecycleRouteResponseBody),
    AuthenticatedOutOfBandIdentifierChange(MountedOutOfBandIdentifierChangeRouteResponseBody),
    DelayedOutOfBandIdentifierChange(MountedDelayedOutOfBandIdentifierChangeRouteResponseBody),
    DelayedSubjectAuthStateDeletion(MountedSubjectAuthStateDeletionRouteResponseBody),
    AdminSupport(MountedAdminSupportRouteResponseBody),
}
