use super::*;

#[test]
fn password_reset_by_its_recovery_email_is_not_lifecycle_independent() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        password_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let email_evidence = out_of_band_identifier_evidence("primary-email", [email_authority])
        .expect("email evidence");

    assert!(graph.evidence_can_immediately_authorize_credential_action(
        &email_evidence,
        &password_credential_id,
        CredentialLifecycleAction::Reset,
    ));
    assert!(!graph.evidence_is_independent_for_credential_action(
        &email_evidence,
        &password_credential_id,
        CredentialLifecycleAction::Reset,
    ));
}

#[test]
fn trusted_device_can_remain_independent_from_email_only_password_reset() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        password_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        email_authority,
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let trusted_device_evidence =
        credential_instance_evidence("trusted-device", [device_authority])
            .expect("trusted-device evidence");

    assert!(!graph.evidence_can_immediately_authorize_credential_action(
        &trusted_device_evidence,
        &password_credential_id,
        CredentialLifecycleAction::Reset,
    ));
    assert!(graph.evidence_is_independent_for_credential_action(
        &trusted_device_evidence,
        &password_credential_id,
        CredentialLifecycleAction::Reset,
    ));
}

#[test]
fn delayed_email_only_password_reset_does_not_count_as_immediate_recovery_authority() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        password_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        email_authority.clone(),
        RecoveryAuthorityTiming::Delayed,
    )])
    .expect("recovery graph");
    let email_evidence = out_of_band_identifier_evidence("primary-email", [email_authority])
        .expect("email evidence");

    assert!(!graph.evidence_can_immediately_authorize_credential_action(
        &email_evidence,
        &password_credential_id,
        CredentialLifecycleAction::Reset,
    ));
    assert!(graph.evidence_is_independent_for_credential_action(
        &email_evidence,
        &password_credential_id,
        CredentialLifecycleAction::Reset,
    ));

    let context = CredentialLifecycleActionContext::new(
        CredentialInstanceMetadata::new(
            password_credential_id,
            id("subject"),
            CredentialInstanceKind::MessageSignatureVerifier,
            "password_signature",
            CredentialLifecycleState::Active,
        )
        .expect("password metadata"),
        graph,
        [email_evidence],
    );
    assert_eq!(
        context.evaluate_action(
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        ),
        CredentialLifecycleActionDecision::RequiresDelayedAction,
        "delayed recovery authority should schedule delayed action instead of being ignored"
    );
}

#[test]
fn totp_reset_by_authenticated_session_is_not_lifecycle_independent_from_session() {
    let totp_credential_id: VerifiedProofSourceId = id("totp-credential");
    let session_authority: RecoveryAuthorityId = id("authenticated-session-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        totp_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        session_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let session_evidence =
        LifecycleAuthorityEvidence::authenticated_session(id("session"), [session_authority])
            .expect("session evidence");

    assert!(graph.evidence_can_immediately_authorize_credential_action(
        &session_evidence,
        &totp_credential_id,
        CredentialLifecycleAction::Reset,
    ));
    assert!(!graph.evidence_is_independent_for_credential_action(
        &session_evidence,
        &totp_credential_id,
        CredentialLifecycleAction::Reset,
    ));
}

#[test]
fn recovery_code_regeneration_by_email_is_not_lifecycle_independent() {
    let recovery_code_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        recovery_code_credential_id.clone(),
        CredentialLifecycleAction::Regenerate,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let email_evidence = out_of_band_identifier_evidence("primary-email", [email_authority])
        .expect("email evidence");

    assert!(!graph.evidence_is_independent_for_credential_action(
        &email_evidence,
        &recovery_code_credential_id,
        CredentialLifecycleAction::Regenerate,
    ));
}

#[test]
fn passkey_removal_by_session_is_not_lifecycle_independent_from_session() {
    let passkey_credential_id: VerifiedProofSourceId = id("passkey-credential");
    let session_authority: RecoveryAuthorityId = id("authenticated-session-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        passkey_credential_id.clone(),
        CredentialLifecycleAction::Remove,
        session_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let session_evidence =
        LifecycleAuthorityEvidence::authenticated_session(id("session"), [session_authority])
            .expect("session evidence");

    assert!(!graph.evidence_is_independent_for_credential_action(
        &session_evidence,
        &passkey_credential_id,
        CredentialLifecycleAction::Remove,
    ));
}

#[test]
fn oidc_and_email_with_same_upstream_authority_are_not_lifecycle_independent() {
    let upstream_authority: RecoveryAuthorityId = id("google-workspace-authority");
    let email_evidence =
        out_of_band_identifier_evidence("workspace-email", [upstream_authority.clone()])
            .expect("email evidence");
    let oidc_evidence =
        external_authority_evidence("oidc-google", [upstream_authority]).expect("OIDC evidence");

    assert!(!email_evidence.is_recovery_independent_from(&oidc_evidence));
    assert!(!oidc_evidence.is_recovery_independent_from(&email_evidence));
}

#[test]
fn immediate_admin_support_recovery_is_modeled_as_recovery_authority() {
    let target_credential_id: VerifiedProofSourceId = id("target-credential");
    let support_authority: RecoveryAuthorityId = id("support-team-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        support_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let support_evidence = LifecycleAuthorityEvidence::admin_support_intervention(
        id("support-intervention"),
        [support_authority],
    )
    .expect("support evidence");

    assert!(graph.evidence_can_immediately_authorize_credential_action(
        &support_evidence,
        &target_credential_id,
        CredentialLifecycleAction::Replace,
    ));
    assert!(!graph.evidence_is_independent_for_credential_action(
        &support_evidence,
        &target_credential_id,
        CredentialLifecycleAction::Replace,
    ));
}

#[test]
fn recovery_authority_metadata_rejects_duplicate_or_empty_effective_authorities() {
    let authority: RecoveryAuthorityId = id("authority");

    assert_eq!(
        out_of_band_identifier_evidence("email", []),
        Err(Error::InvalidConfig(
            "lifecycle authority evidence must name at least one recovery authority",
        ))
    );
    assert_eq!(
        out_of_band_identifier_evidence("email", [authority.clone(), authority]),
        Err(Error::InvalidConfig(
            "lifecycle authority evidence must not duplicate recovery authorities",
        ))
    );

    let target: VerifiedProofSourceId = id("target");
    let authority: RecoveryAuthorityId = id("authority");
    let duplicate = CredentialRecoveryAuthority::new(
        target.clone(),
        CredentialLifecycleAction::Reset,
        authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    assert_eq!(
        CredentialRecoveryAuthorityGraph::new([duplicate.clone(), duplicate]),
        Err(Error::InvalidConfig(
            "credential recovery authority graph must not contain duplicate authorities",
        ))
    );
}

#[test]
fn immediate_lifecycle_action_requires_independent_evidence_when_policy_says_so() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let context = CredentialLifecycleActionContext::new(
        CredentialInstanceMetadata::new(
            password_credential_id.clone(),
            id("subject"),
            CredentialInstanceKind::MessageSignatureVerifier,
            "password_signature",
            CredentialLifecycleState::Active,
        )
        .expect("password metadata"),
        CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
            password_credential_id,
            CredentialLifecycleAction::Reset,
            email_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )])
        .expect("authority graph"),
        [
            out_of_band_identifier_evidence("primary-email", [email_authority.clone()])
                .expect("email evidence"),
            credential_instance_evidence("trusted-device", [device_authority])
                .expect("trusted device evidence"),
        ],
    );

    assert_eq!(
        context.evaluate_action(
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        ),
        CredentialLifecycleActionDecision::AuthorizedImmediate,
        "email can authorize the reset, while trusted-device evidence prevents factor collapse"
    );

    let email_only_context = CredentialLifecycleActionContext::new(
        context.target_credential().clone(),
        context.recovery_authority_graph().clone(),
        [
            out_of_band_identifier_evidence("primary-email", [email_authority])
                .expect("email evidence"),
        ],
    );
    assert_eq!(
        email_only_context.evaluate_action(
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        ),
        CredentialLifecycleActionDecision::RequiresDelayedAction,
        "email-only reset can be a delayed action, but not an immediate non-degrading reset"
    );
}

#[test]
fn immediate_lifecycle_action_rejects_unknown_or_inactive_targets() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        password_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("authority graph");
    let email_evidence =
        out_of_band_identifier_evidence("primary-email", [email_authority]).expect("evidence");

    let no_matching_authority_context = CredentialLifecycleActionContext::new(
        CredentialInstanceMetadata::new(
            id("different-credential"),
            id("subject"),
            CredentialInstanceKind::MessageSignatureVerifier,
            "password_signature",
            CredentialLifecycleState::Active,
        )
        .expect("metadata"),
        graph.clone(),
        [email_evidence.clone()],
    );
    assert_eq!(
        no_matching_authority_context.evaluate_action(
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        ),
        CredentialLifecycleActionDecision::Rejected
    );

    let inactive_context = CredentialLifecycleActionContext::new(
        CredentialInstanceMetadata::new(
            password_credential_id,
            id("subject"),
            CredentialInstanceKind::MessageSignatureVerifier,
            "password_signature",
            CredentialLifecycleState::Revoked,
        )
        .expect("metadata"),
        graph,
        [email_evidence],
    );
    assert_eq!(
        inactive_context.evaluate_action(
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        ),
        CredentialLifecycleActionDecision::Rejected
    );
}

fn credential_instance_evidence(
    source_id: &str,
    authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
) -> Result<LifecycleAuthorityEvidence, Error> {
    LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(VerifiedProofSourceKind::CredentialInstance, id(source_id)),
        authority_ids,
    )
}

fn out_of_band_identifier_evidence<const N: usize>(
    source_id: &str,
    authority_ids: [RecoveryAuthorityId; N],
) -> Result<LifecycleAuthorityEvidence, Error> {
    LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(VerifiedProofSourceKind::OutOfBandIdentifier, id(source_id)),
        authority_ids,
    )
}

fn external_authority_evidence(
    source_id: &str,
    authority_ids: impl IntoIterator<Item = RecoveryAuthorityId>,
) -> Result<LifecycleAuthorityEvidence, Error> {
    LifecycleAuthorityEvidence::from_verified_proof_source(
        VerifiedProofSource::new(VerifiedProofSourceKind::ExternalAuthority, id(source_id)),
        authority_ids,
    )
}
