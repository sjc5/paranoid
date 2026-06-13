use super::*;

pub(crate) fn no_session_recovery_submitted_body_from_collected_http_request(
    endpoint: MountedNoSessionCredentialRecoveryEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedNoSessionCredentialRecoverySubmittedRouteBody, MountedAuthHttpBodyError> {
    match endpoint {
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt => {
            require_json_content_type(headers)?;
            let body: NoSessionRecoveryStartHttpJsonBody =
                parse_mounted_auth_json_body(body, "no-session recovery start body")?;
            Ok(
                MountedNoSessionCredentialRecoverySubmittedRouteBody::start_recovery_attempt(
                    weak_proof_gate_kind_from_http_value(&body.preflight_gate_kind)?,
                    body.preflight_gate_method_label,
                    decode_base64url_http_body_field(
                        "preflight_gate_payload_base64url",
                        &body.preflight_gate_payload_base64url,
                        WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof => {
            require_json_content_type(headers)?;
            let body: NoSessionRecoveryProofHttpJsonBody =
                parse_mounted_auth_json_body(body, "no-session recovery proof body")?;
            Ok(
                MountedNoSessionCredentialRecoverySubmittedRouteBody::submit_recovery_proof(
                    decode_base64url_http_body_field(
                        "secret_response_base64url",
                        &body.secret_response_base64url,
                        ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset => {
            parse_mounted_auth_empty_body(body, "no-session recovery delayed-reset body")?;
            Ok(
                MountedNoSessionCredentialRecoverySubmittedRouteBody::schedule_delayed_reset(
                    Vec::new(),
                ),
            )
        }
        MountedNoSessionCredentialRecoveryEndpoint::ExecuteImmediateReset => {
            require_json_content_type(headers)?;
            let body: NoSessionRecoveryExecuteResetHttpJsonBody =
                parse_mounted_auth_json_body(body, "no-session recovery immediate-reset body")?;
            Ok(
                MountedNoSessionCredentialRecoverySubmittedRouteBody::execute_immediate_reset(
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn full_authentication_submitted_body_from_collected_http_request(
    endpoint: MountedFullAuthenticationEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedFullAuthenticationSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedFullAuthenticationEndpoint::StartOutOfBandChallenge => {
            let body: FullAuthenticationStartOutOfBandHttpJsonBody =
                parse_mounted_auth_json_body(body, "full-authentication out-of-band start body")?;
            Ok(
                MountedFullAuthenticationSubmittedRouteBody::start_out_of_band_challenge(
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
                    )?,
                    weak_proof_gate_kind_from_http_value(&body.preflight_gate_kind)?,
                    body.preflight_gate_method_label,
                    decode_base64url_http_body_field(
                        "preflight_gate_payload_base64url",
                        &body.preflight_gate_payload_base64url,
                        WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedFullAuthenticationEndpoint::SubmitOutOfBandProof => {
            let body: FullAuthenticationOutOfBandProofHttpJsonBody =
                parse_mounted_auth_json_body(body, "full-authentication out-of-band proof body")?;
            Ok(
                MountedFullAuthenticationSubmittedRouteBody::submit_out_of_band_proof(
                    decode_base64url_http_body_field(
                        "secret_response_base64url",
                        &body.secret_response_base64url,
                        ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
                    )?,
                    body.weak_proof_gate
                        .map(weak_proof_gate_submitted_body_from_http_json)
                        .transpose()?,
                ),
            )
        }
        MountedFullAuthenticationEndpoint::CompleteFullAuthentication => {
            let body: FullAuthenticationCompleteHttpJsonBody =
                parse_mounted_auth_json_body(body, "full-authentication completion body")?;
            if let Some(display_label) = &body.trusted_device_display_label {
                validate_http_text_field_not_too_long(
                    "trusted_device_display_label",
                    display_label,
                    TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES,
                )?;
            }
            if !body.trust_device && body.trusted_device_display_label.is_some() {
                return Err(MountedAuthHttpBodyError::UnexpectedFieldForDisabledOption {
                    field_name: "trusted_device_display_label",
                    option_name: "trust_device",
                });
            }
            Ok(
                MountedFullAuthenticationSubmittedRouteBody::complete_full_authentication(
                    body.trust_device,
                    body.trusted_device_display_label,
                ),
            )
        }
    }
}

pub(crate) fn credential_addition_submitted_body_from_collected_http_request(
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedCredentialAdditionSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    let body: CredentialAdditionHttpJsonBody =
        parse_mounted_auth_json_body(body, "credential addition body")?;
    Ok(MountedCredentialAdditionSubmittedRouteBody::new(
        decode_base64url_http_body_field(
            "method_payload_base64url",
            &body.method_payload_base64url,
            METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        )?,
    ))
}

pub(crate) fn authenticated_credential_reset_submitted_body_from_collected_http_request(
    endpoint: MountedAuthenticatedCredentialResetEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAuthenticatedCredentialResetSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedAuthenticatedCredentialResetEndpoint::PlanReset => {
            let body: CredentialResetPlanHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential reset planning body")?;
            Ok(
                MountedAuthenticatedCredentialResetSubmittedRouteBody::plan_reset(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedAuthenticatedCredentialResetEndpoint::ExecuteImmediateReset => {
            let body: CredentialResetExecuteHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential reset execution body")?;
            Ok(
                MountedAuthenticatedCredentialResetSubmittedRouteBody::execute_immediate_reset(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn authenticated_credential_removal_submitted_body_from_collected_http_request(
    endpoint: MountedAuthenticatedCredentialRemovalEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAuthenticatedCredentialRemovalSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedAuthenticatedCredentialRemovalEndpoint::PlanRemoval => {
            let body: CredentialRemovalHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential removal planning body")?;
            Ok(
                MountedAuthenticatedCredentialRemovalSubmittedRouteBody::plan_removal(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedAuthenticatedCredentialRemovalEndpoint::ExecuteImmediateRemoval => {
            let body: CredentialRemovalHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential removal execution body")?;
            Ok(
                MountedAuthenticatedCredentialRemovalSubmittedRouteBody::execute_immediate_removal(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn authenticated_credential_replacement_submitted_body_from_collected_http_request(
    endpoint: MountedAuthenticatedCredentialReplacementEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAuthenticatedCredentialReplacementSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedAuthenticatedCredentialReplacementEndpoint::PlanReplacement => {
            let body: CredentialReplacementPlanHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential replacement planning body")?;
            Ok(
                MountedAuthenticatedCredentialReplacementSubmittedRouteBody::plan_replacement(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedAuthenticatedCredentialReplacementEndpoint::ExecuteImmediateReplacement => {
            let body: CredentialReplacementExecuteHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential replacement execution body")?;
            Ok(
                MountedAuthenticatedCredentialReplacementSubmittedRouteBody::execute_immediate_replacement(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn authenticated_credential_regeneration_submitted_body_from_collected_http_request(
    endpoint: MountedAuthenticatedCredentialRegenerationEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAuthenticatedCredentialRegenerationSubmittedRouteBody, MountedAuthHttpBodyError>
{
    require_json_content_type(headers)?;
    match endpoint {
        MountedAuthenticatedCredentialRegenerationEndpoint::PlanRegeneration => {
            let body: CredentialRegenerationPlanHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential regeneration planning body")?;
            Ok(
                MountedAuthenticatedCredentialRegenerationSubmittedRouteBody::plan_regeneration(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedAuthenticatedCredentialRegenerationEndpoint::ExecuteImmediateRegeneration => {
            let body: CredentialRegenerationExecuteHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential regeneration execution body")?;
            Ok(
                MountedAuthenticatedCredentialRegenerationSubmittedRouteBody::execute_immediate_regeneration(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn authenticated_credential_rotation_submitted_body_from_collected_http_request(
    endpoint: MountedAuthenticatedCredentialRotationEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAuthenticatedCredentialRotationSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedAuthenticatedCredentialRotationEndpoint::ExecuteImmediateRotation => {
            let body: CredentialRotationExecuteHttpJsonBody =
                parse_mounted_auth_json_body(body, "credential rotation execution body")?;
            Ok(
                MountedAuthenticatedCredentialRotationSubmittedRouteBody::execute_immediate_rotation(
                    decode_base64url_http_body_field(
                        "credential_handle_base64url",
                        &body.credential_handle_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn delayed_credential_lifecycle_submitted_body_from_collected_http_request(
    endpoint: MountedDelayedCredentialLifecycleEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedDelayedCredentialLifecycleSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReset => {
            let body: DelayedCredentialLifecycleExecuteWithMethodHttpJsonBody =
                parse_mounted_auth_json_body(body, "delayed credential reset execution body")?;
            Ok(
                MountedDelayedCredentialLifecycleSubmittedRouteBody::execute_reset(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedDelayedCredentialLifecycleEndpoint::ExecuteReplaceOrRegenerate => {
            let body: DelayedCredentialLifecycleExecuteWithMethodHttpJsonBody =
                parse_mounted_auth_json_body(
                    body,
                    "delayed credential replacement or regeneration execution body",
                )?;
            Ok(
                MountedDelayedCredentialLifecycleSubmittedRouteBody::execute_replace_or_regenerate(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "method_payload_base64url",
                        &body.method_payload_base64url,
                        METHOD_COMMIT_PAYLOAD_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedDelayedCredentialLifecycleEndpoint::ExecuteRemoval => {
            let body: DelayedCredentialLifecycleExecuteRemovalHttpJsonBody =
                parse_mounted_auth_json_body(body, "delayed credential removal execution body")?;
            Ok(
                MountedDelayedCredentialLifecycleSubmittedRouteBody::execute_removal(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn authenticated_out_of_band_identifier_change_submitted_body_from_collected_http_request(
    endpoint: MountedAuthenticatedOutOfBandIdentifierChangeEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAuthenticatedOutOfBandIdentifierChangeSubmittedRouteBody, MountedAuthHttpBodyError>
{
    require_json_content_type(headers)?;
    match endpoint {
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::PlanChange => {
            let body: OutOfBandIdentifierChangeHttpJsonBody =
                parse_mounted_auth_json_body(body, "out-of-band identifier change planning body")?;
            Ok(
                MountedAuthenticatedOutOfBandIdentifierChangeSubmittedRouteBody::plan_change(
                    decode_base64url_http_body_field(
                        "current_identifier_source_id_base64url",
                        &body.current_identifier_source_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "candidate_identifier_source_id_base64url",
                        &body.candidate_identifier_source_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedAuthenticatedOutOfBandIdentifierChangeEndpoint::ExecuteImmediateChange => {
            let body: OutOfBandIdentifierChangeHttpJsonBody =
                parse_mounted_auth_json_body(body, "out-of-band identifier change execution body")?;
            Ok(
                MountedAuthenticatedOutOfBandIdentifierChangeSubmittedRouteBody::execute_immediate_change(
                    decode_base64url_http_body_field(
                        "current_identifier_source_id_base64url",
                        &body.current_identifier_source_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                    decode_base64url_http_body_field(
                        "candidate_identifier_source_id_base64url",
                        &body.candidate_identifier_source_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn delayed_out_of_band_identifier_change_submitted_body_from_collected_http_request(
    endpoint: MountedDelayedOutOfBandIdentifierChangeEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedDelayedOutOfBandIdentifierChangeSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedDelayedOutOfBandIdentifierChangeEndpoint::ExecuteChange => {
            let body: DelayedOutOfBandIdentifierChangeHttpJsonBody = parse_mounted_auth_json_body(
                body,
                "delayed out-of-band identifier change execution body",
            )?;
            Ok(
                MountedDelayedOutOfBandIdentifierChangeSubmittedRouteBody::execute_change(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
        MountedDelayedOutOfBandIdentifierChangeEndpoint::CancelChange => {
            let body: DelayedOutOfBandIdentifierChangeHttpJsonBody = parse_mounted_auth_json_body(
                body,
                "delayed out-of-band identifier change cancellation body",
            )?;
            Ok(
                MountedDelayedOutOfBandIdentifierChangeSubmittedRouteBody::cancel_change(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn subject_auth_state_deletion_submitted_body_from_collected_http_request(
    endpoint: MountedDelayedSubjectAuthStateDeletionEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody, MountedAuthHttpBodyError> {
    match endpoint {
        MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion => {
            Ok(MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody::schedule_deletion(body))
        }
        MountedDelayedSubjectAuthStateDeletionEndpoint::ExecuteDeletion => {
            require_json_content_type(headers)?;
            let body: SubjectAuthStateDeletionExecuteHttpJsonBody =
                parse_mounted_auth_json_body(body, "subject auth-state deletion execution body")?;
            Ok(
                MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody::execute_deletion(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                    application_subject_data_lifecycle_action_from_http_value(
                        &body.application_subject_data_lifecycle_action,
                    )?,
                ),
            )
        }
        MountedDelayedSubjectAuthStateDeletionEndpoint::CancelDeletion => {
            require_json_content_type(headers)?;
            let body: SubjectAuthStateDeletionCancelHttpJsonBody = parse_mounted_auth_json_body(
                body,
                "subject auth-state deletion cancellation body",
            )?;
            Ok(
                MountedDelayedSubjectAuthStateDeletionSubmittedRouteBody::cancel_deletion(
                    decode_base64url_http_body_field(
                        "pending_action_id_base64url",
                        &body.pending_action_id_base64url,
                        ID_MAX_BYTES,
                    )?,
                ),
            )
        }
    }
}

pub(crate) fn admin_support_submitted_body_from_collected_http_request(
    endpoint: MountedAdminSupportEndpoint,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> Result<MountedAdminSupportSubmittedRouteBody, MountedAuthHttpBodyError> {
    require_json_content_type(headers)?;
    match endpoint {
        MountedAdminSupportEndpoint::RequestIntervention => {
            let body: AdminSupportRequestHttpJsonBody =
                parse_mounted_auth_json_body(body, "admin support intervention request body")?;
            Ok(MountedAdminSupportSubmittedRouteBody::request_intervention(
                decode_base64url_http_body_field(
                    "subject_id_base64url",
                    &body.subject_id_base64url,
                    ID_MAX_BYTES,
                )?,
                decode_base64url_http_body_field(
                    "target_credential_instance_id_base64url",
                    &body.target_credential_instance_id_base64url,
                    ID_MAX_BYTES,
                )?,
                credential_lifecycle_action_from_http_value(&body.credential_lifecycle_action)?,
            ))
        }
        MountedAdminSupportEndpoint::ApproveIntervention => {
            let body: AdminSupportInterventionHandleHttpJsonBody =
                parse_mounted_auth_json_body(body, "admin support intervention approval body")?;
            Ok(MountedAdminSupportSubmittedRouteBody::approve_intervention(
                decode_base64url_http_body_field(
                    "intervention_handle_base64url",
                    &body.intervention_handle_base64url,
                    ID_MAX_BYTES,
                )?,
            ))
        }
        MountedAdminSupportEndpoint::DenyIntervention => {
            let body: AdminSupportInterventionHandleHttpJsonBody =
                parse_mounted_auth_json_body(body, "admin support intervention denial body")?;
            Ok(MountedAdminSupportSubmittedRouteBody::deny_intervention(
                decode_base64url_http_body_field(
                    "intervention_handle_base64url",
                    &body.intervention_handle_base64url,
                    ID_MAX_BYTES,
                )?,
            ))
        }
        MountedAdminSupportEndpoint::ExpireIntervention => {
            let body: AdminSupportInterventionHandleHttpJsonBody =
                parse_mounted_auth_json_body(body, "admin support intervention expiry body")?;
            Ok(MountedAdminSupportSubmittedRouteBody::expire_intervention(
                decode_base64url_http_body_field(
                    "intervention_handle_base64url",
                    &body.intervention_handle_base64url,
                    ID_MAX_BYTES,
                )?,
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoSessionRecoveryStartHttpJsonBody {
    preflight_gate_kind: String,
    preflight_gate_method_label: String,
    preflight_gate_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoSessionRecoveryProofHttpJsonBody {
    secret_response_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoSessionRecoveryExecuteResetHttpJsonBody {
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FullAuthenticationStartOutOfBandHttpJsonBody {
    method_payload_base64url: String,
    preflight_gate_kind: String,
    preflight_gate_method_label: String,
    preflight_gate_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FullAuthenticationOutOfBandProofHttpJsonBody {
    secret_response_base64url: String,
    weak_proof_gate: Option<FullAuthenticationWeakProofGateHttpJsonBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FullAuthenticationWeakProofGateHttpJsonBody {
    kind: String,
    method_label: String,
    payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FullAuthenticationCompleteHttpJsonBody {
    trust_device: bool,
    trusted_device_display_label: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialAdditionHttpJsonBody {
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialResetPlanHttpJsonBody {
    credential_handle_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialResetExecuteHttpJsonBody {
    credential_handle_base64url: String,
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialReplacementPlanHttpJsonBody {
    credential_handle_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialReplacementExecuteHttpJsonBody {
    credential_handle_base64url: String,
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRegenerationPlanHttpJsonBody {
    credential_handle_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRegenerationExecuteHttpJsonBody {
    credential_handle_base64url: String,
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRotationExecuteHttpJsonBody {
    credential_handle_base64url: String,
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelayedCredentialLifecycleExecuteWithMethodHttpJsonBody {
    pending_action_id_base64url: String,
    method_payload_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelayedCredentialLifecycleExecuteRemovalHttpJsonBody {
    pending_action_id_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRemovalHttpJsonBody {
    credential_handle_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutOfBandIdentifierChangeHttpJsonBody {
    current_identifier_source_id_base64url: String,
    candidate_identifier_source_id_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelayedOutOfBandIdentifierChangeHttpJsonBody {
    pending_action_id_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectAuthStateDeletionExecuteHttpJsonBody {
    pending_action_id_base64url: String,
    application_subject_data_lifecycle_action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectAuthStateDeletionCancelHttpJsonBody {
    pending_action_id_base64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSupportRequestHttpJsonBody {
    subject_id_base64url: String,
    target_credential_instance_id_base64url: String,
    credential_lifecycle_action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSupportInterventionHandleHttpJsonBody {
    intervention_handle_base64url: String,
}

fn parse_mounted_auth_json_body<T>(
    body: Vec<u8>,
    input_name: &'static str,
) -> Result<T, MountedAuthHttpBodyError>
where
    T: for<'de> Deserialize<'de>,
{
    if body.len() > MOUNTED_AUTH_HTTP_JSON_BODY_MAX_BYTES {
        return Err(MountedAuthHttpBodyError::BodyTooLong {
            input_name,
            actual_bytes: body.len(),
            max_bytes: MOUNTED_AUTH_HTTP_JSON_BODY_MAX_BYTES,
        });
    }
    serde_json::from_slice(&body)
        .map_err(|source| MountedAuthHttpBodyError::InvalidJson { input_name, source })
}

pub(crate) fn parse_mounted_auth_empty_body(
    body: Vec<u8>,
    input_name: &'static str,
) -> Result<(), MountedAuthHttpBodyError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(MountedAuthHttpBodyError::UnexpectedBody {
            input_name,
            actual_bytes: body.len(),
        })
    }
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), MountedAuthHttpBodyError> {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return Err(MountedAuthHttpBodyError::UnsupportedContentType {
            expected: "application/json",
            actual: None,
        });
    };
    let content_type =
        content_type
            .to_str()
            .map_err(|_| MountedAuthHttpBodyError::UnsupportedContentType {
                expected: "application/json",
                actual: None,
            })?;
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(MountedAuthHttpBodyError::UnsupportedContentType {
            expected: "application/json",
            actual: Some(content_type.to_owned()),
        })
    }
}

fn weak_proof_gate_kind_from_http_value(
    value: &str,
) -> Result<WeakProofGateKind, MountedAuthHttpBodyError> {
    match value {
        "proof_of_work" => Ok(WeakProofGateKind::ProofOfWork),
        "human_challenge" => Ok(WeakProofGateKind::HumanChallenge),
        "risk_decision" => Ok(WeakProofGateKind::RiskDecision),
        "other" => Ok(WeakProofGateKind::Other),
        _ => Err(MountedAuthHttpBodyError::UnknownWeakProofGateKind {
            value: value.to_owned(),
        }),
    }
}

fn application_subject_data_lifecycle_action_from_http_value(
    value: &str,
) -> Result<ApplicationSubjectDataLifecycleAction, MountedAuthHttpBodyError> {
    match value {
        "delete_subject_data" => Ok(ApplicationSubjectDataLifecycleAction::DeleteSubjectData),
        "disable_subject_data" => Ok(ApplicationSubjectDataLifecycleAction::DisableSubjectData),
        _ => Err(
            MountedAuthHttpBodyError::UnknownApplicationSubjectDataLifecycleAction {
                value: value.to_owned(),
            },
        ),
    }
}

fn credential_lifecycle_action_from_http_value(
    value: &str,
) -> Result<CredentialLifecycleAction, MountedAuthHttpBodyError> {
    match value {
        "create" => Ok(CredentialLifecycleAction::Create),
        "reset" => Ok(CredentialLifecycleAction::Reset),
        "replace" => Ok(CredentialLifecycleAction::Replace),
        "remove" => Ok(CredentialLifecycleAction::Remove),
        "disable" => Ok(CredentialLifecycleAction::Disable),
        "regenerate" => Ok(CredentialLifecycleAction::Regenerate),
        "rotate" => Ok(CredentialLifecycleAction::Rotate),
        "recover_subject_access" => Ok(CredentialLifecycleAction::RecoverSubjectAccess),
        _ => Err(MountedAuthHttpBodyError::UnknownCredentialLifecycleAction {
            value: value.to_owned(),
        }),
    }
}

fn weak_proof_gate_submitted_body_from_http_json(
    body: FullAuthenticationWeakProofGateHttpJsonBody,
) -> Result<MountedWeakProofGateSubmittedHttpBody, MountedAuthHttpBodyError> {
    Ok(MountedWeakProofGateSubmittedHttpBody::new(
        weak_proof_gate_kind_from_http_value(&body.kind)?,
        body.method_label,
        decode_base64url_http_body_field(
            "weak_proof_gate.payload_base64url",
            &body.payload_base64url,
            WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES,
        )?,
    ))
}

fn decode_base64url_http_body_field(
    field_name: &'static str,
    encoded: &str,
    max_decoded_bytes: usize,
) -> Result<Vec<u8>, MountedAuthHttpBodyError> {
    let max_encoded_bytes = ((max_decoded_bytes + 2) / 3) * 4;
    if encoded.len() > max_encoded_bytes {
        return Err(MountedAuthHttpBodyError::EncodedFieldTooLong {
            field_name,
            actual_bytes: encoded.len(),
            max_bytes: max_encoded_bytes,
        });
    }
    let decoded = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|source| MountedAuthHttpBodyError::InvalidBase64Url { field_name, source })?;
    if BASE64URL_NOPAD.encode(&decoded) != encoded {
        return Err(MountedAuthHttpBodyError::NonCanonicalBase64Url { field_name });
    }
    if decoded.len() > max_decoded_bytes {
        return Err(MountedAuthHttpBodyError::DecodedFieldTooLong {
            field_name,
            actual_bytes: decoded.len(),
            max_bytes: max_decoded_bytes,
        });
    }
    Ok(decoded)
}

fn validate_http_text_field_not_too_long(
    field_name: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), MountedAuthHttpBodyError> {
    let actual_bytes = value.len();
    if actual_bytes > max_bytes {
        return Err(MountedAuthHttpBodyError::EncodedFieldTooLong {
            field_name,
            actual_bytes,
            max_bytes,
        });
    }
    Ok(())
}
