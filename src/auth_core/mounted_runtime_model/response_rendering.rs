use super::*;

pub(super) fn render_mounted_auth_route_response(
    response: Response<MountedAuthRouteResponseBody>,
) -> Response<Vec<u8>> {
    let (mut parts, body) = response.into_parts();
    parts.status = StatusCode::OK;
    parts.headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    Response::from_parts(parts, mounted_auth_route_response_body_json(body))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountedAuthPublicRouteResponseKind {
    FullAuthenticationOutOfBandChallengeAccepted,
    FullAuthenticationOutOfBandProofAccepted,
    FullAuthenticationOutOfBandProofRejected,
    FullAuthenticationCompleted,
    FullAuthenticationNotReady,
    CredentialRecoveryAttemptStarted,
    CredentialRecoveryProofAccepted,
    CredentialRecoveryProofRejected,
    CredentialRecoveryDelayedResetScheduled,
    CredentialRecoveryImmediateResetExecuted,
    CredentialInventory,
    NeedsFullAuthentication,
    CredentialAdded,
    NeedsStepUp,
    CredentialResetImmediateAuthorized,
    CredentialResetDelayedActionScheduled,
    CredentialResetExecuted,
    CredentialReplacementImmediateAuthorized,
    CredentialReplacementDelayedActionScheduled,
    CredentialReplaced,
    CredentialRemovalImmediateAuthorized,
    CredentialRemovalDelayedActionScheduled,
    CredentialRemoved,
    CredentialRegenerationImmediateAuthorized,
    CredentialRegenerationDelayedActionScheduled,
    CredentialRegenerated,
    CredentialRotated,
    DelayedCredentialResetExecuted,
    DelayedCredentialReplacementExecuted,
    DelayedCredentialRemovalExecuted,
    DelayedCredentialRegenerationExecuted,
    OutOfBandIdentifierChangeImmediateAuthorized,
    OutOfBandIdentifierChangeDelayedActionScheduled,
    OutOfBandIdentifierChanged,
    DelayedOutOfBandIdentifierChanged,
    DelayedOutOfBandIdentifierChangeCancelled,
    SubjectAuthStateDeletionScheduled,
    SubjectAuthStateDeleted,
    SubjectAuthStateDeletionCancelled,
    AdminSupportInterventionRequested,
    AdminSupportApprovalImmediateAuthorized,
    AdminSupportApprovalDelayedActionScheduled,
    AdminSupportInterventionDenied,
    AdminSupportInterventionExpired,
}

impl MountedAuthPublicRouteResponseKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FullAuthenticationOutOfBandChallengeAccepted => {
                "full_authentication_out_of_band_challenge_accepted"
            }
            Self::FullAuthenticationOutOfBandProofAccepted => {
                "full_authentication_out_of_band_proof_accepted"
            }
            Self::FullAuthenticationOutOfBandProofRejected => {
                "full_authentication_out_of_band_proof_rejected"
            }
            Self::FullAuthenticationCompleted => "full_authentication_completed",
            Self::FullAuthenticationNotReady => "full_authentication_not_ready",
            Self::CredentialRecoveryAttemptStarted => "credential_recovery_attempt_started",
            Self::CredentialRecoveryProofAccepted => "credential_recovery_proof_accepted",
            Self::CredentialRecoveryProofRejected => "credential_recovery_proof_rejected",
            Self::CredentialRecoveryDelayedResetScheduled => {
                "credential_recovery_delayed_reset_scheduled"
            }
            Self::CredentialRecoveryImmediateResetExecuted => {
                "credential_recovery_immediate_reset_executed"
            }
            Self::CredentialInventory => "credential_inventory",
            Self::NeedsFullAuthentication => "needs_full_authentication",
            Self::CredentialAdded => "credential_added",
            Self::NeedsStepUp => "needs_step_up",
            Self::CredentialResetImmediateAuthorized => "credential_reset_immediate_authorized",
            Self::CredentialResetDelayedActionScheduled => {
                "credential_reset_delayed_action_scheduled"
            }
            Self::CredentialResetExecuted => "credential_reset_executed",
            Self::CredentialReplacementImmediateAuthorized => {
                "credential_replacement_immediate_authorized"
            }
            Self::CredentialReplacementDelayedActionScheduled => {
                "credential_replacement_delayed_action_scheduled"
            }
            Self::CredentialReplaced => "credential_replaced",
            Self::CredentialRemovalImmediateAuthorized => "credential_removal_immediate_authorized",
            Self::CredentialRemovalDelayedActionScheduled => {
                "credential_removal_delayed_action_scheduled"
            }
            Self::CredentialRemoved => "credential_removed",
            Self::CredentialRegenerationImmediateAuthorized => {
                "credential_regeneration_immediate_authorized"
            }
            Self::CredentialRegenerationDelayedActionScheduled => {
                "credential_regeneration_delayed_action_scheduled"
            }
            Self::CredentialRegenerated => "credential_regenerated",
            Self::CredentialRotated => "credential_rotated",
            Self::DelayedCredentialResetExecuted => "delayed_credential_reset_executed",
            Self::DelayedCredentialReplacementExecuted => "delayed_credential_replacement_executed",
            Self::DelayedCredentialRemovalExecuted => "delayed_credential_removal_executed",
            Self::DelayedCredentialRegenerationExecuted => {
                "delayed_credential_regeneration_executed"
            }
            Self::OutOfBandIdentifierChangeImmediateAuthorized => {
                "out_of_band_identifier_change_immediate_authorized"
            }
            Self::OutOfBandIdentifierChangeDelayedActionScheduled => {
                "out_of_band_identifier_change_delayed_action_scheduled"
            }
            Self::OutOfBandIdentifierChanged => "out_of_band_identifier_changed",
            Self::DelayedOutOfBandIdentifierChanged => "delayed_out_of_band_identifier_changed",
            Self::DelayedOutOfBandIdentifierChangeCancelled => {
                "delayed_out_of_band_identifier_change_cancelled"
            }
            Self::SubjectAuthStateDeletionScheduled => "subject_auth_state_deletion_scheduled",
            Self::SubjectAuthStateDeleted => "subject_auth_state_deleted",
            Self::SubjectAuthStateDeletionCancelled => "subject_auth_state_deletion_cancelled",
            Self::AdminSupportInterventionRequested => "admin_support_intervention_requested",
            Self::AdminSupportApprovalImmediateAuthorized => {
                "admin_support_approval_immediate_authorized"
            }
            Self::AdminSupportApprovalDelayedActionScheduled => {
                "admin_support_approval_delayed_action_scheduled"
            }
            Self::AdminSupportInterventionDenied => "admin_support_intervention_denied",
            Self::AdminSupportInterventionExpired => "admin_support_intervention_expired",
        }
    }
}

fn mounted_auth_route_response_body_json(body: MountedAuthRouteResponseBody) -> Vec<u8> {
    let body = match body {
        MountedAuthRouteResponseBody::FullAuthentication(body) => match body {
            MountedFullAuthenticationRouteResponseBody::OutOfBandChallengeAccepted {
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::FullAuthenticationOutOfBandChallengeAccepted.as_str(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedFullAuthenticationRouteResponseBody::OutOfBandProofAccepted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::FullAuthenticationOutOfBandProofAccepted.as_str(),
                })
            }
            MountedFullAuthenticationRouteResponseBody::OutOfBandProofRejected => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::FullAuthenticationOutOfBandProofRejected.as_str(),
                })
            }
            MountedFullAuthenticationRouteResponseBody::FullAuthenticationCompleted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::FullAuthenticationCompleted.as_str(),
                })
            }
            MountedFullAuthenticationRouteResponseBody::FullAuthenticationNotReady => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::FullAuthenticationNotReady.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::NoSessionCredentialRecovery(body) => match body {
            MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryAttemptStarted {
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::CredentialRecoveryAttemptStarted.as_str(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryProofAccepted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRecoveryProofAccepted.as_str(),
                })
            }
            MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryProofRejected => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRecoveryProofRejected.as_str(),
                })
            }
            MountedNoSessionCredentialRecoveryRouteResponseBody::DelayedResetScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::CredentialRecoveryDelayedResetScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedNoSessionCredentialRecoveryRouteResponseBody::ImmediateResetExecuted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRecoveryImmediateResetExecuted.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialInventory(body) => match body {
            MountedCredentialInventoryRouteResponseBody::Credentials { credentials } => {
                let credentials: Vec<serde_json::Value> = credentials
                    .into_iter()
                    .map(credential_inventory_entry_json)
                    .collect();
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialInventory.as_str(),
                    "credentials": credentials,
                })
            }
            MountedCredentialInventoryRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialAddition(body) => match body {
            MountedCredentialAdditionRouteResponseBody::CredentialAdded {
                generated_recovery_codes,
            } => {
                let generated_recovery_codes =
                    generated_recovery_codes.map(generated_recovery_code_set_json);
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialAdded.as_str(),
                    "generated_recovery_codes": generated_recovery_codes,
                })
            }
            MountedCredentialAdditionRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedCredentialAdditionRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialReset(body) => match body {
            MountedCredentialResetRouteResponseBody::ResetAuthorizedImmediate => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialResetImmediateAuthorized.as_str(),
                })
            }
            MountedCredentialResetRouteResponseBody::DelayedResetScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::CredentialResetDelayedActionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedCredentialResetRouteResponseBody::CredentialReset => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialResetExecuted.as_str(),
                })
            }
            MountedCredentialResetRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedCredentialResetRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(body) => match body {
            MountedCredentialReplacementRouteResponseBody::ReplacementAuthorizedImmediate => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialReplacementImmediateAuthorized.as_str(),
                })
            }
            MountedCredentialReplacementRouteResponseBody::DelayedReplacementScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::CredentialReplacementDelayedActionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedCredentialReplacementRouteResponseBody::CredentialReplaced => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialReplaced.as_str(),
                })
            }
            MountedCredentialReplacementRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedCredentialReplacementRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(body) => match body {
            MountedCredentialRemovalRouteResponseBody::RemovalAuthorizedImmediate => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRemovalImmediateAuthorized.as_str(),
                })
            }
            MountedCredentialRemovalRouteResponseBody::DelayedRemovalScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::CredentialRemovalDelayedActionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedCredentialRemovalRouteResponseBody::CredentialRemoved => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRemoved.as_str(),
                })
            }
            MountedCredentialRemovalRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedCredentialRemovalRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(body) => match body {
            MountedCredentialRegenerationRouteResponseBody::RegenerationAuthorizedImmediate => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRegenerationImmediateAuthorized.as_str(),
                })
            }
            MountedCredentialRegenerationRouteResponseBody::DelayedRegenerationScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::CredentialRegenerationDelayedActionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedCredentialRegenerationRouteResponseBody::CredentialRegenerated {
                generated_recovery_codes,
            } => {
                let generated_recovery_codes =
                    generated_recovery_codes.map(generated_recovery_code_set_json);
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRegenerated.as_str(),
                    "generated_recovery_codes": generated_recovery_codes,
                })
            }
            MountedCredentialRegenerationRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedCredentialRegenerationRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedCredentialRotation(body) => match body {
            MountedCredentialRotationRouteResponseBody::CredentialRotated => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::CredentialRotated.as_str(),
                })
            }
            MountedCredentialRotationRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedCredentialRotationRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::DelayedCredentialLifecycle(body) => match body {
            MountedDelayedCredentialLifecycleRouteResponseBody::CredentialResetExecuted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::DelayedCredentialResetExecuted.as_str(),
                })
            }
            MountedDelayedCredentialLifecycleRouteResponseBody::CredentialReplacementExecuted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::DelayedCredentialReplacementExecuted.as_str(),
                })
            }
            MountedDelayedCredentialLifecycleRouteResponseBody::CredentialRemovalExecuted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::DelayedCredentialRemovalExecuted.as_str(),
                })
            }
            MountedDelayedCredentialLifecycleRouteResponseBody::CredentialRegenerationExecuted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::DelayedCredentialRegenerationExecuted.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(body) => match body {
            MountedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChangeAuthorizedImmediate => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::OutOfBandIdentifierChangeImmediateAuthorized.as_str(),
                })
            }
            MountedOutOfBandIdentifierChangeRouteResponseBody::DelayedIdentifierChangeScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::OutOfBandIdentifierChangeDelayedActionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChanged => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::OutOfBandIdentifierChanged.as_str(),
                })
            }
            MountedOutOfBandIdentifierChangeRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedOutOfBandIdentifierChangeRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::DelayedOutOfBandIdentifierChange(body) => match body {
            MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChanged => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::DelayedOutOfBandIdentifierChanged.as_str(),
                })
            }
            MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChangeCancelled => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::DelayedOutOfBandIdentifierChangeCancelled.as_str(),
                })
            }
            MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(body) => match body {
            MountedSubjectAuthStateDeletionRouteResponseBody::SubjectAuthStateDeletionScheduled {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::SubjectAuthStateDeletionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedSubjectAuthStateDeletionRouteResponseBody::SubjectAuthStateDeleted => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::SubjectAuthStateDeleted.as_str(),
                })
            }
            MountedSubjectAuthStateDeletionRouteResponseBody::SubjectAuthStateDeletionCancelled => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::SubjectAuthStateDeletionCancelled.as_str(),
                })
            }
            MountedSubjectAuthStateDeletionRouteResponseBody::NeedsFullAuthentication => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsFullAuthentication.as_str(),
                })
            }
            MountedSubjectAuthStateDeletionRouteResponseBody::NeedsStepUp => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::NeedsStepUp.as_str(),
                })
            }
        },
        MountedAuthRouteResponseBody::AdminSupport(body) => match body {
            MountedAdminSupportRouteResponseBody::InterventionRequested {
                intervention_handle,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::AdminSupportInterventionRequested.as_str(),
                "intervention_handle_base64url": BASE64URL_NOPAD.encode(&intervention_handle),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedAdminSupportRouteResponseBody::ApprovalAuthorizedImmediate => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::AdminSupportApprovalImmediateAuthorized.as_str(),
                })
            }
            MountedAdminSupportRouteResponseBody::ApprovalScheduledDelayedAction {
                earliest_execute_at,
                expires_at,
            } => serde_json::json!({
                "ok": true,
                "type": MountedAuthPublicRouteResponseKind::AdminSupportApprovalDelayedActionScheduled.as_str(),
                "earliest_execute_at_unix_seconds": earliest_execute_at.get(),
                "expires_at_unix_seconds": expires_at.get(),
            }),
            MountedAdminSupportRouteResponseBody::InterventionDenied => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::AdminSupportInterventionDenied.as_str(),
                })
            }
            MountedAdminSupportRouteResponseBody::InterventionExpired => {
                serde_json::json!({
                    "ok": true,
                    "type": MountedAuthPublicRouteResponseKind::AdminSupportInterventionExpired.as_str(),
                })
            }
        },
    };
    serde_json::to_vec(&body).expect("mounted auth route response JSON is serializable")
}

#[cfg(test)]
mod mounted_route_response_body_json_tests {
    use super::*;

    fn route_response_json(body: MountedAuthRouteResponseBody) -> serde_json::Value {
        let body: serde_json::Value =
            serde_json::from_slice(&mounted_auth_route_response_body_json(body))
                .expect("route response body is JSON");
        let serialized = body.to_string();
        for forbidden in [
            "subject_id",
            "session_id",
            "target_credential",
            "credential_instance_id",
            "pending_action_id",
            "intervention_id",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "route response leaked internal field name {forbidden}: {serialized}"
            );
        }
        body
    }

    fn route_response_type(body: MountedAuthRouteResponseBody) -> String {
        let body = route_response_json(body);
        body.get("type")
            .and_then(serde_json::Value::as_str)
            .expect("route response body carries type")
            .to_owned()
    }

    #[test]
    fn public_route_response_kind_strings_are_unique_and_public_shaped() {
        let kinds = [
            MountedAuthPublicRouteResponseKind::FullAuthenticationOutOfBandChallengeAccepted,
            MountedAuthPublicRouteResponseKind::FullAuthenticationOutOfBandProofAccepted,
            MountedAuthPublicRouteResponseKind::FullAuthenticationOutOfBandProofRejected,
            MountedAuthPublicRouteResponseKind::FullAuthenticationCompleted,
            MountedAuthPublicRouteResponseKind::FullAuthenticationNotReady,
            MountedAuthPublicRouteResponseKind::CredentialRecoveryAttemptStarted,
            MountedAuthPublicRouteResponseKind::CredentialRecoveryProofAccepted,
            MountedAuthPublicRouteResponseKind::CredentialRecoveryProofRejected,
            MountedAuthPublicRouteResponseKind::CredentialRecoveryDelayedResetScheduled,
            MountedAuthPublicRouteResponseKind::CredentialRecoveryImmediateResetExecuted,
            MountedAuthPublicRouteResponseKind::CredentialInventory,
            MountedAuthPublicRouteResponseKind::NeedsFullAuthentication,
            MountedAuthPublicRouteResponseKind::CredentialAdded,
            MountedAuthPublicRouteResponseKind::NeedsStepUp,
            MountedAuthPublicRouteResponseKind::CredentialResetImmediateAuthorized,
            MountedAuthPublicRouteResponseKind::CredentialResetDelayedActionScheduled,
            MountedAuthPublicRouteResponseKind::CredentialResetExecuted,
            MountedAuthPublicRouteResponseKind::CredentialReplacementImmediateAuthorized,
            MountedAuthPublicRouteResponseKind::CredentialReplacementDelayedActionScheduled,
            MountedAuthPublicRouteResponseKind::CredentialReplaced,
            MountedAuthPublicRouteResponseKind::CredentialRemovalImmediateAuthorized,
            MountedAuthPublicRouteResponseKind::CredentialRemovalDelayedActionScheduled,
            MountedAuthPublicRouteResponseKind::CredentialRemoved,
            MountedAuthPublicRouteResponseKind::CredentialRegenerationImmediateAuthorized,
            MountedAuthPublicRouteResponseKind::CredentialRegenerationDelayedActionScheduled,
            MountedAuthPublicRouteResponseKind::CredentialRegenerated,
            MountedAuthPublicRouteResponseKind::CredentialRotated,
            MountedAuthPublicRouteResponseKind::DelayedCredentialResetExecuted,
            MountedAuthPublicRouteResponseKind::DelayedCredentialReplacementExecuted,
            MountedAuthPublicRouteResponseKind::DelayedCredentialRemovalExecuted,
            MountedAuthPublicRouteResponseKind::DelayedCredentialRegenerationExecuted,
            MountedAuthPublicRouteResponseKind::OutOfBandIdentifierChangeImmediateAuthorized,
            MountedAuthPublicRouteResponseKind::OutOfBandIdentifierChangeDelayedActionScheduled,
            MountedAuthPublicRouteResponseKind::OutOfBandIdentifierChanged,
            MountedAuthPublicRouteResponseKind::DelayedOutOfBandIdentifierChanged,
            MountedAuthPublicRouteResponseKind::DelayedOutOfBandIdentifierChangeCancelled,
            MountedAuthPublicRouteResponseKind::SubjectAuthStateDeletionScheduled,
            MountedAuthPublicRouteResponseKind::SubjectAuthStateDeleted,
            MountedAuthPublicRouteResponseKind::SubjectAuthStateDeletionCancelled,
            MountedAuthPublicRouteResponseKind::AdminSupportInterventionRequested,
            MountedAuthPublicRouteResponseKind::AdminSupportApprovalImmediateAuthorized,
            MountedAuthPublicRouteResponseKind::AdminSupportApprovalDelayedActionScheduled,
            MountedAuthPublicRouteResponseKind::AdminSupportInterventionDenied,
            MountedAuthPublicRouteResponseKind::AdminSupportInterventionExpired,
        ];
        let mut labels: Vec<&'static str> = kinds.iter().map(|kind| kind.as_str()).collect();
        assert!(labels.iter().all(|label| !label.is_empty()));
        assert!(labels.iter().all(|label| {
            !label.contains("session_id")
                && !label.contains("credential_instance_id")
                && !label.contains("pending_action")
                && !label.contains("runtime")
        }));

        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), kinds.len());
    }

    #[test]
    fn lifecycle_planning_route_response_types_name_exact_committed_outcomes() {
        let earliest_execute_at = UnixSeconds::new(10);
        let expires_at = UnixSeconds::new(20);

        assert_eq!(
            route_response_type(MountedAuthRouteResponseBody::AuthenticatedCredentialReset(
                MountedCredentialResetRouteResponseBody::ResetAuthorizedImmediate,
            )),
            "credential_reset_immediate_authorized"
        );
        assert_eq!(
            route_response_type(MountedAuthRouteResponseBody::AuthenticatedCredentialReset(
                MountedCredentialResetRouteResponseBody::DelayedResetScheduled {
                    earliest_execute_at,
                    expires_at,
                },
            )),
            "credential_reset_delayed_action_scheduled"
        );
        assert_eq!(
            route_response_type(MountedAuthRouteResponseBody::AuthenticatedCredentialReset(
                MountedCredentialResetRouteResponseBody::CredentialReset,
            )),
            "credential_reset_executed"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(
                    MountedCredentialReplacementRouteResponseBody::ReplacementAuthorizedImmediate,
                ),
            ),
            "credential_replacement_immediate_authorized"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(
                    MountedCredentialReplacementRouteResponseBody::DelayedReplacementScheduled {
                        earliest_execute_at,
                        expires_at,
                    },
                ),
            ),
            "credential_replacement_delayed_action_scheduled"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(
                    MountedCredentialRemovalRouteResponseBody::RemovalAuthorizedImmediate,
                )
            ),
            "credential_removal_immediate_authorized"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(
                    MountedCredentialRemovalRouteResponseBody::DelayedRemovalScheduled {
                        earliest_execute_at,
                        expires_at,
                    },
                )
            ),
            "credential_removal_delayed_action_scheduled"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(
                    MountedCredentialRegenerationRouteResponseBody::RegenerationAuthorizedImmediate,
                ),
            ),
            "credential_regeneration_immediate_authorized"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(
                    MountedCredentialRegenerationRouteResponseBody::DelayedRegenerationScheduled {
                        earliest_execute_at,
                        expires_at,
                    },
                ),
            ),
            "credential_regeneration_delayed_action_scheduled"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(
                    MountedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChangeAuthorizedImmediate,
                ),
            ),
            "out_of_band_identifier_change_immediate_authorized"
        );
        assert_eq!(
            route_response_type(
                MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(
                    MountedOutOfBandIdentifierChangeRouteResponseBody::DelayedIdentifierChangeScheduled {
                        earliest_execute_at,
                        expires_at,
                    },
                ),
            ),
            "out_of_band_identifier_change_delayed_action_scheduled"
        );
        assert_eq!(
            route_response_type(MountedAuthRouteResponseBody::AdminSupport(
                MountedAdminSupportRouteResponseBody::ApprovalAuthorizedImmediate,
            )),
            "admin_support_approval_immediate_authorized"
        );
        assert_eq!(
            route_response_type(MountedAuthRouteResponseBody::AdminSupport(
                MountedAdminSupportRouteResponseBody::ApprovalScheduledDelayedAction {
                    earliest_execute_at,
                    expires_at,
                },
            )),
            "admin_support_approval_delayed_action_scheduled"
        );
    }

    #[test]
    fn route_response_types_cover_current_user_visible_outcomes() {
        let earliest_execute_at = UnixSeconds::new(30);
        let expires_at = UnixSeconds::new(40);

        let cases = [
            (
                MountedAuthRouteResponseBody::FullAuthentication(
                    MountedFullAuthenticationRouteResponseBody::OutOfBandChallengeAccepted {
                        expires_at,
                    },
                ),
                "full_authentication_out_of_band_challenge_accepted",
            ),
            (
                MountedAuthRouteResponseBody::FullAuthentication(
                    MountedFullAuthenticationRouteResponseBody::OutOfBandProofAccepted,
                ),
                "full_authentication_out_of_band_proof_accepted",
            ),
            (
                MountedAuthRouteResponseBody::FullAuthentication(
                    MountedFullAuthenticationRouteResponseBody::OutOfBandProofRejected,
                ),
                "full_authentication_out_of_band_proof_rejected",
            ),
            (
                MountedAuthRouteResponseBody::FullAuthentication(
                    MountedFullAuthenticationRouteResponseBody::FullAuthenticationCompleted,
                ),
                "full_authentication_completed",
            ),
            (
                MountedAuthRouteResponseBody::FullAuthentication(
                    MountedFullAuthenticationRouteResponseBody::FullAuthenticationNotReady,
                ),
                "full_authentication_not_ready",
            ),
            (
                MountedAuthRouteResponseBody::NoSessionCredentialRecovery(
                    MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryAttemptStarted {
                        expires_at,
                    },
                ),
                "credential_recovery_attempt_started",
            ),
            (
                MountedAuthRouteResponseBody::NoSessionCredentialRecovery(
                    MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryProofAccepted,
                ),
                "credential_recovery_proof_accepted",
            ),
            (
                MountedAuthRouteResponseBody::NoSessionCredentialRecovery(
                    MountedNoSessionCredentialRecoveryRouteResponseBody::RecoveryProofRejected,
                ),
                "credential_recovery_proof_rejected",
            ),
            (
                MountedAuthRouteResponseBody::NoSessionCredentialRecovery(
                    MountedNoSessionCredentialRecoveryRouteResponseBody::DelayedResetScheduled {
                        earliest_execute_at,
                        expires_at,
                    },
                ),
                "credential_recovery_delayed_reset_scheduled",
            ),
            (
                MountedAuthRouteResponseBody::NoSessionCredentialRecovery(
                    MountedNoSessionCredentialRecoveryRouteResponseBody::ImmediateResetExecuted,
                ),
                "credential_recovery_immediate_reset_executed",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialInventory(
                    MountedCredentialInventoryRouteResponseBody::Credentials {
                        credentials: Vec::new(),
                    },
                ),
                "credential_inventory",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialInventory(
                    MountedCredentialInventoryRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialAddition(
                    MountedCredentialAdditionRouteResponseBody::CredentialAdded {
                        generated_recovery_codes: None,
                    },
                ),
                "credential_added",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialAddition(
                    MountedCredentialAdditionRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialAddition(
                    MountedCredentialAdditionRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(
                    MountedCredentialReplacementRouteResponseBody::CredentialReplaced,
                ),
                "credential_replaced",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(
                    MountedCredentialReplacementRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialReplacement(
                    MountedCredentialReplacementRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(
                    MountedCredentialRemovalRouteResponseBody::CredentialRemoved,
                ),
                "credential_removed",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(
                    MountedCredentialRemovalRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRemoval(
                    MountedCredentialRemovalRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(
                    MountedCredentialRegenerationRouteResponseBody::CredentialRegenerated {
                        generated_recovery_codes: None,
                    },
                ),
                "credential_regenerated",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(
                    MountedCredentialRegenerationRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRegeneration(
                    MountedCredentialRegenerationRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRotation(
                    MountedCredentialRotationRouteResponseBody::CredentialRotated,
                ),
                "credential_rotated",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRotation(
                    MountedCredentialRotationRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedCredentialRotation(
                    MountedCredentialRotationRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::DelayedCredentialLifecycle(
                    MountedDelayedCredentialLifecycleRouteResponseBody::CredentialResetExecuted,
                ),
                "delayed_credential_reset_executed",
            ),
            (
                MountedAuthRouteResponseBody::DelayedCredentialLifecycle(
                    MountedDelayedCredentialLifecycleRouteResponseBody::CredentialReplacementExecuted,
                ),
                "delayed_credential_replacement_executed",
            ),
            (
                MountedAuthRouteResponseBody::DelayedCredentialLifecycle(
                    MountedDelayedCredentialLifecycleRouteResponseBody::CredentialRemovalExecuted,
                ),
                "delayed_credential_removal_executed",
            ),
            (
                MountedAuthRouteResponseBody::DelayedCredentialLifecycle(
                    MountedDelayedCredentialLifecycleRouteResponseBody::CredentialRegenerationExecuted,
                ),
                "delayed_credential_regeneration_executed",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(
                    MountedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChanged,
                ),
                "out_of_band_identifier_changed",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(
                    MountedOutOfBandIdentifierChangeRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::AuthenticatedOutOfBandIdentifierChange(
                    MountedOutOfBandIdentifierChangeRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::DelayedOutOfBandIdentifierChange(
                    MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChanged,
                ),
                "delayed_out_of_band_identifier_changed",
            ),
            (
                MountedAuthRouteResponseBody::DelayedOutOfBandIdentifierChange(
                    MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::IdentifierChangeCancelled,
                ),
                "delayed_out_of_band_identifier_change_cancelled",
            ),
            (
                MountedAuthRouteResponseBody::DelayedOutOfBandIdentifierChange(
                    MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::DelayedOutOfBandIdentifierChange(
                    MountedDelayedOutOfBandIdentifierChangeRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(
                    MountedSubjectAuthStateDeletionRouteResponseBody::SubjectAuthStateDeletionScheduled {
                        earliest_execute_at,
                        expires_at,
                    },
                ),
                "subject_auth_state_deletion_scheduled",
            ),
            (
                MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(
                    MountedSubjectAuthStateDeletionRouteResponseBody::SubjectAuthStateDeleted,
                ),
                "subject_auth_state_deleted",
            ),
            (
                MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(
                    MountedSubjectAuthStateDeletionRouteResponseBody::SubjectAuthStateDeletionCancelled,
                ),
                "subject_auth_state_deletion_cancelled",
            ),
            (
                MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(
                    MountedSubjectAuthStateDeletionRouteResponseBody::NeedsFullAuthentication,
                ),
                "needs_full_authentication",
            ),
            (
                MountedAuthRouteResponseBody::DelayedSubjectAuthStateDeletion(
                    MountedSubjectAuthStateDeletionRouteResponseBody::NeedsStepUp,
                ),
                "needs_step_up",
            ),
            (
                MountedAuthRouteResponseBody::AdminSupport(
                    MountedAdminSupportRouteResponseBody::InterventionRequested {
                        intervention_handle: b"support-handle".to_vec(),
                        expires_at,
                    },
                ),
                "admin_support_intervention_requested",
            ),
            (
                MountedAuthRouteResponseBody::AdminSupport(
                    MountedAdminSupportRouteResponseBody::InterventionDenied,
                ),
                "admin_support_intervention_denied",
            ),
            (
                MountedAuthRouteResponseBody::AdminSupport(
                    MountedAdminSupportRouteResponseBody::InterventionExpired,
                ),
                "admin_support_intervention_expired",
            ),
        ];

        for (body, expected_type) in cases {
            assert_eq!(route_response_type(body), expected_type);
        }
    }
}

fn credential_inventory_entry_json(entry: MountedCredentialInventoryEntry) -> serde_json::Value {
    serde_json::json!({
        "credential_handle_base64url": BASE64URL_NOPAD.encode(entry.credential_handle().as_bytes()),
        "credential_kind": credential_instance_kind_label(entry.kind()),
        "method_label": entry.method_label(),
        "reset_policy_role": credential_reset_policy_role_label(entry.reset_policy_role()),
    })
}

fn credential_instance_kind_label(kind: CredentialInstanceKind) -> &'static str {
    match kind {
        CredentialInstanceKind::MessageSignatureVerifier => "message_signature_verifier",
        CredentialInstanceKind::SharedSecretOtpVerifier => "shared_secret_otp_verifier",
        CredentialInstanceKind::OriginBoundPublicKeyCredential => {
            "origin_bound_public_key_credential"
        }
        CredentialInstanceKind::RecoveryCodeCredential => "recovery_code_credential",
        CredentialInstanceKind::TrustedDeviceCredential => "trusted_device_credential",
    }
}

fn credential_reset_policy_role_label(role: CredentialResetPolicyRole) -> &'static str {
    match role {
        CredentialResetPolicyRole::OrdinaryCredential => "ordinary_credential",
        CredentialResetPolicyRole::SecondFactorCredential => "second_factor_credential",
    }
}

fn generated_recovery_code_set_json(
    generated: MountedGeneratedRecoveryCodeSetRouteResponseBody,
) -> serde_json::Value {
    let (_credential_instance_id, codes) = generated.into_parts();
    let codes: Vec<String> = codes
        .into_iter()
        .map(|code| {
            String::from_utf8(code.expose_secret().to_vec())
                .expect("generated recovery codes are UTF-8 display tokens")
        })
        .collect();
    serde_json::json!({
        "codes": codes,
    })
}

pub(crate) fn render_mounted_auth_http_error_response(
    error: MountedAuthHttpServiceError,
) -> Response<Vec<u8>> {
    let (status, code) = mounted_auth_http_error_status_and_code(&error);
    let body = serde_json::json!({
        "ok": false,
        "error": code,
    });
    let mut response = Response::new(
        serde_json::to_vec(&body).expect("mounted auth error response JSON is serializable"),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response
}

fn mounted_auth_http_error_status_and_code(
    error: &MountedAuthHttpServiceError,
) -> (StatusCode, &'static str) {
    match error {
        MountedAuthHttpServiceError::Body(MountedAuthHttpBodyError::UnsupportedContentType {
            ..
        })
        | MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::HttpBody(
            MountedAuthHttpBodyError::UnsupportedContentType { .. },
        )) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"),
        MountedAuthHttpServiceError::Body(
            MountedAuthHttpBodyError::BodyTooLong { .. }
            | MountedAuthHttpBodyError::EncodedFieldTooLong { .. }
            | MountedAuthHttpBodyError::DecodedFieldTooLong { .. },
        )
        | MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::HttpBody(
            MountedAuthHttpBodyError::BodyTooLong { .. }
            | MountedAuthHttpBodyError::EncodedFieldTooLong { .. }
            | MountedAuthHttpBodyError::DecodedFieldTooLong { .. },
        )) => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
        MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::RouteNotFound {
            ..
        })
        | MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::CredentialLifecycle(
            MountedCredentialLifecycleServiceError::NoSessionRecoveryRouteNotFound { .. },
        )) => (StatusCode::NOT_FOUND, "not_found"),
        MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::CredentialLifecycle(
            MountedCredentialLifecycleServiceError::Runtime(
                AuthPostgresWebRuntimeExecutionError::Web(_),
            ),
        ))
        | MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::SubjectLifecycle(
            MountedSubjectLifecycleServiceError::Runtime(
                AuthPostgresWebRuntimeExecutionError::Web(_),
            ),
        ))
        | MountedAuthHttpServiceError::Route(MountedAuthRouteServiceError::AdminSupport(
            MountedAdminSupportServiceError::Runtime(AuthPostgresWebRuntimeExecutionError::Web(_))
            | MountedAdminSupportServiceError::StaffAuthorizationRejected,
        )) => (StatusCode::FORBIDDEN, "forbidden"),
        MountedAuthHttpServiceError::Body(_)
        | MountedAuthHttpServiceError::Route(
            MountedAuthRouteServiceError::CredentialLifecycle(
                MountedCredentialLifecycleServiceError::Core(_)
                | MountedCredentialLifecycleServiceError::NoSessionRecoveryRouteBodyMismatch {
                    ..
                },
            )
            | MountedAuthRouteServiceError::SubjectLifecycle(
                MountedSubjectLifecycleServiceError::Core(_),
            )
            | MountedAuthRouteServiceError::AdminSupport(
                MountedAdminSupportServiceError::Core(_)
                | MountedAdminSupportServiceError::StaffActionDidNotMatchRequestedRuntimeInput,
            )
            | MountedAuthRouteServiceError::HttpBody(_)
            | MountedAuthRouteServiceError::RouteBodyMismatch { .. },
        ) => (StatusCode::BAD_REQUEST, "bad_request"),
        MountedAuthHttpServiceError::Route(
            MountedAuthRouteServiceError::Runtime(_)
            | MountedAuthRouteServiceError::CredentialLifecycle(
                MountedCredentialLifecycleServiceError::Runtime(_)
                | MountedCredentialLifecycleServiceError::UnexpectedRuntimeOutcome,
            )
            | MountedAuthRouteServiceError::SubjectLifecycle(
                MountedSubjectLifecycleServiceError::Runtime(_)
                | MountedSubjectLifecycleServiceError::UnexpectedRuntimeOutcome,
            )
            | MountedAuthRouteServiceError::AdminSupport(
                MountedAdminSupportServiceError::Runtime(_)
                | MountedAdminSupportServiceError::UnexpectedRuntimeOutcome,
            ),
        )
        | MountedAuthHttpServiceError::SystemTimeBeforeUnixEpoch => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}
