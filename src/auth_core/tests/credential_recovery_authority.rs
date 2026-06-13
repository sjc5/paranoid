use super::*;

#[test]
fn password_reset_by_its_recovery_email_is_not_lifecycle_independent() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let password_metadata = credential_metadata(password_credential_id.clone());
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
        &password_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
    assert!(!graph.evidence_is_independent_for_credential_action(
        &email_evidence,
        &password_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
}

#[test]
fn lower_risk_credential_lifecycle_policy_may_explicitly_allow_non_independent_evidence() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let password_metadata = credential_metadata(password_credential_id.clone());
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        password_credential_id,
        CredentialLifecycleAction::Reset,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let email_evidence = out_of_band_identifier_evidence("primary-email", [email_authority])
        .expect("email evidence");
    let context = CredentialLifecycleActionContext::new(password_metadata, graph, [email_evidence]);

    assert_eq!(
        context.evaluate_action_at(
            at(10),
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        ),
        CredentialLifecycleActionDecision::RequiresDelayedAction
    );
    assert_eq!(
        context.evaluate_action_at(
            at(10),
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        ),
        CredentialLifecycleActionDecision::AuthorizedImmediate
    );
}

#[test]
fn trusted_device_can_remain_independent_from_email_only_password_reset() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let password_metadata = credential_metadata(password_credential_id.clone());
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
        &password_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
    assert!(graph.evidence_is_independent_for_credential_action(
        &trusted_device_evidence,
        &password_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
}

#[test]
fn delayed_email_only_password_reset_does_not_count_as_immediate_recovery_authority() {
    let password_credential_id: VerifiedProofSourceId = id("password-credential");
    let password_metadata = credential_metadata(password_credential_id.clone());
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
        &password_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
    assert!(graph.evidence_is_independent_for_credential_action(
        &email_evidence,
        &password_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));

    let context = CredentialLifecycleActionContext::new(password_metadata, graph, [email_evidence]);
    assert_eq!(
        context.evaluate_action_at(
            at(10),
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::Required,
        ),
        CredentialLifecycleActionDecision::RequiresDelayedAction,
        "delayed recovery authority should schedule delayed action instead of being ignored"
    );
}

#[test]
fn out_of_band_identifier_change_with_current_identifier_only_requires_delay() {
    let subject_id: SubjectId = id("subject");
    let current_email_authority: RecoveryAuthorityId = id("current-email-authority");
    let current_source = out_of_band_identifier_source("current-email");
    let candidate_source = out_of_band_identifier_source("candidate-email");
    let current_email_evidence =
        out_of_band_identifier_evidence("current-email", [current_email_authority.clone()])
            .expect("current email evidence");
    let graph = SubjectLifecycleAuthorityGraph::new([SubjectLifecycleAuthority::new(
        subject_id.clone(),
        SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        current_email_authority,
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("subject lifecycle graph");
    let context = SubjectLifecycleActionContext::new(subject_id, graph, [current_email_evidence]);
    let identifier_change =
        OutOfBandIdentifierChangeContext::new(context, current_source, candidate_source)
            .expect("identifier change context");

    assert_eq!(
        identifier_change.evaluate_action_at(
            at(10),
            SubjectLifecycleIndependentEvidenceRequirement::Required,
        ),
        SubjectLifecycleActionDecision::RequiresDelayedAction,
        "proof of the current recovery identifier alone may schedule, but not instantly perform, identifier change when independent evidence is required"
    );
    assert_eq!(
        identifier_change.evaluate_action_at(
            at(10),
            SubjectLifecycleIndependentEvidenceRequirement::NotRequired,
        ),
        SubjectLifecycleActionDecision::AuthorizedImmediate,
        "only an explicit transition policy may let same-authority subject lifecycle evidence execute immediately"
    );
}

#[test]
fn out_of_band_identifier_change_with_independent_evidence_can_authorize_immediately() {
    let subject_id: SubjectId = id("subject");
    let current_email_authority: RecoveryAuthorityId = id("current-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let current_source = out_of_band_identifier_source("current-email");
    let candidate_source = out_of_band_identifier_source("candidate-email");
    let current_email_evidence =
        out_of_band_identifier_evidence("current-email", [current_email_authority.clone()])
            .expect("current email evidence");
    let device_evidence = credential_instance_evidence("trusted-device", [device_authority])
        .expect("trusted device evidence");
    let graph = SubjectLifecycleAuthorityGraph::new([SubjectLifecycleAuthority::new(
        subject_id.clone(),
        SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        current_email_authority,
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("subject lifecycle graph");
    let context = SubjectLifecycleActionContext::new(
        subject_id,
        graph,
        [current_email_evidence, device_evidence],
    );
    let identifier_change =
        OutOfBandIdentifierChangeContext::new(context, current_source, candidate_source)
            .expect("identifier change context");

    assert_eq!(
        identifier_change.evaluate_action_at(
            at(10),
            SubjectLifecycleIndependentEvidenceRequirement::Required,
        ),
        SubjectLifecycleActionDecision::AuthorizedImmediate
    );
}

#[test]
fn out_of_band_identifier_change_rejects_candidate_identifier_as_authority() {
    let subject_id: SubjectId = id("subject");
    let candidate_email_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let current_source = out_of_band_identifier_source("current-email");
    let candidate_source = out_of_band_identifier_source("candidate-email");
    let candidate_email_evidence =
        out_of_band_identifier_evidence("candidate-email", [candidate_email_authority.clone()])
            .expect("candidate email evidence");
    let graph = SubjectLifecycleAuthorityGraph::new([SubjectLifecycleAuthority::new(
        subject_id.clone(),
        SubjectLifecycleAction::ChangeOutOfBandIdentifier,
        candidate_email_authority,
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("subject lifecycle graph");
    let context = SubjectLifecycleActionContext::new(subject_id, graph, [candidate_email_evidence]);

    let error = OutOfBandIdentifierChangeContext::new(context, current_source, candidate_source)
        .expect_err("candidate identifier proof cannot authorize its own binding");

    assert_eq!(
        error,
        Error::InvalidConfig("candidate identifier proof cannot authorize its own binding")
    );
}

#[test]
fn totp_reset_by_authenticated_session_is_not_lifecycle_independent_from_session() {
    let totp_credential_id: VerifiedProofSourceId = id("totp-credential");
    let totp_metadata = credential_metadata(totp_credential_id.clone());
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
        &totp_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
    assert!(!graph.evidence_is_independent_for_credential_action(
        &session_evidence,
        &totp_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
}

#[test]
fn recovery_code_regeneration_by_email_is_not_lifecycle_independent() {
    let recovery_code_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let recovery_code_metadata = credential_metadata(recovery_code_credential_id.clone());
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
        &recovery_code_metadata,
        CredentialLifecycleAction::Regenerate,
        at(10),
    ));
}

#[test]
fn passkey_removal_by_session_is_not_lifecycle_independent_from_session() {
    let passkey_credential_id: VerifiedProofSourceId = id("passkey-credential");
    let passkey_metadata = credential_metadata(passkey_credential_id.clone());
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
        &passkey_metadata,
        CredentialLifecycleAction::Remove,
        at(10),
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
    let target_metadata = credential_metadata(target_credential_id.clone());
    let support_authority: RecoveryAuthorityId = id("support-team-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        support_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let intervention = VerifiedAdminSupportCredentialLifecycleIntervention::new(
        id("support-intervention"),
        target_metadata.subject_id().clone(),
        target_credential_id,
        CredentialLifecycleAction::Replace,
        at(9),
        at(20),
    )
    .expect("support intervention");
    let support_evidence =
        LifecycleAuthorityEvidence::admin_support_intervention(intervention, [support_authority])
            .expect("support evidence");

    assert!(graph.evidence_can_immediately_authorize_credential_action(
        &support_evidence,
        &target_metadata,
        CredentialLifecycleAction::Replace,
        at(10),
    ));
    assert!(!graph.evidence_is_independent_for_credential_action(
        &support_evidence,
        &target_metadata,
        CredentialLifecycleAction::Replace,
        at(10),
    ));
}

#[test]
fn admin_support_intervention_is_scoped_to_subject_target_action_and_lifetime() {
    let target_credential_id: VerifiedProofSourceId = id("target-credential");
    let target_metadata = credential_metadata(target_credential_id.clone());
    let support_authority: RecoveryAuthorityId = id("support-team-authority");
    let graph = CredentialRecoveryAuthorityGraph::new([CredentialRecoveryAuthority::new(
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        support_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )])
    .expect("recovery graph");
    let support_evidence = LifecycleAuthorityEvidence::admin_support_intervention(
        VerifiedAdminSupportCredentialLifecycleIntervention::new(
            id("support-intervention"),
            target_metadata.subject_id().clone(),
            target_credential_id,
            CredentialLifecycleAction::Replace,
            at(9),
            at(20),
        )
        .expect("support intervention"),
        [support_authority],
    )
    .expect("support evidence");

    assert!(!graph.evidence_can_immediately_authorize_credential_action(
        &support_evidence,
        &credential_metadata(id("other-target")),
        CredentialLifecycleAction::Replace,
        at(10),
    ));
    assert!(!graph.evidence_can_immediately_authorize_credential_action(
        &support_evidence,
        &target_metadata,
        CredentialLifecycleAction::Reset,
        at(10),
    ));
    assert!(!graph.evidence_can_immediately_authorize_credential_action(
        &support_evidence,
        &target_metadata,
        CredentialLifecycleAction::Replace,
        at(20),
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
            CredentialResetPolicyRole::OrdinaryCredential,
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
        context.evaluate_action_at(
            at(10),
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
        email_only_context.evaluate_action_at(
            at(10),
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
            CredentialResetPolicyRole::OrdinaryCredential,
            CredentialLifecycleState::Active,
        )
        .expect("metadata"),
        graph.clone(),
        [email_evidence.clone()],
    );
    assert_eq!(
        no_matching_authority_context.evaluate_action_at(
            at(10),
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
            CredentialResetPolicyRole::OrdinaryCredential,
            CredentialLifecycleState::Revoked,
        )
        .expect("metadata"),
        graph,
        [email_evidence],
    );
    assert_eq!(
        inactive_context.evaluate_action_at(
            at(10),
            CredentialLifecycleAction::Reset,
            CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
        ),
        CredentialLifecycleActionDecision::Rejected
    );
}

#[test]
fn ordinary_credential_removal_requires_an_access_preserving_survivor() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("password-credential");
    let survivor_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let trusted_device_id: VerifiedProofSourceId = id("trusted-device");
    let no_recovery_authorities = Vec::new();

    assert!(
        subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    survivor_credential_id,
                    CredentialInstanceKind::RecoveryCodeCredential,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
            ],
            &no_recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::OrdinaryCredential,
        ),
        "ordinary credential removal may leave another access-preserving credential"
    );

    assert!(
        !subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    trusted_device_id,
                    CredentialInstanceKind::TrustedDeviceCredential,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
            ],
            &no_recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::OrdinaryCredential,
        ),
        "trusted-device credentials are not durable access-preserving survivors"
    );
}

#[test]
fn ordinary_credential_removal_rejects_same_authority_survivor_collapse() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("independent-password");
    let ordinary_survivor_id: VerifiedProofSourceId = id("email-resettable-password");
    let second_factor_survivor_id: VerifiedProofSourceId = id("email-resettable-totp");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            ordinary_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            second_factor_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
    ];

    assert!(
        !subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    ordinary_survivor_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    second_factor_survivor_id,
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
            ],
            &recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::OrdinaryCredential,
        ),
        "ordinary removal must not leave an ordinary and second-factor survivor that collapse to the same immediate reset authority"
    );
}

#[test]
fn ordinary_credential_removal_accepts_distinct_authority_survivor_posture() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("independent-password");
    let ordinary_survivor_id: VerifiedProofSourceId = id("email-resettable-password");
    let second_factor_survivor_id: VerifiedProofSourceId = id("device-resettable-totp");
    let ordinary_authority: RecoveryAuthorityId = id("email-authority");
    let second_factor_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            ordinary_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            ordinary_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            second_factor_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            second_factor_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
    ];

    assert!(
        subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    ordinary_survivor_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    second_factor_survivor_id,
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
            ],
            &recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::OrdinaryCredential,
        ),
        "ordinary removal may leave ordinary and second-factor survivors when their immediate reset authorities stay distinct"
    );
}

#[test]
fn adding_second_factor_rejects_same_authority_ordinary_collapse() {
    let subject_id: SubjectId = id("subject");
    let existing_password_id: VerifiedProofSourceId = id("password-credential");
    let added_totp_id: VerifiedProofSourceId = id("totp-credential");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let existing_password = credential_metadata_with_role(
        existing_password_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let added_totp = credential_metadata_with_role(
        added_totp_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let existing_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        existing_password_id,
        CredentialLifecycleAction::Reset,
        shared_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )];
    let added_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        added_totp_id,
        CredentialLifecycleAction::Reset,
        shared_authority,
        RecoveryAuthorityTiming::Immediate,
    )];

    assert!(
        !subject_retains_required_credential_posture_after_addition(
            &[existing_password],
            &existing_recovery_authorities,
            &subject_id,
            &added_totp,
            &added_recovery_authorities,
        ),
        "adding a second factor resettable by the same immediate authority as an existing ordinary credential creates a fake second factor"
    );
}

#[test]
fn adding_ordinary_credential_rejects_same_authority_second_factor_collapse() {
    let subject_id: SubjectId = id("subject");
    let existing_totp_id: VerifiedProofSourceId = id("totp-credential");
    let added_password_id: VerifiedProofSourceId = id("password-credential");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let existing_totp = credential_metadata_with_role(
        existing_totp_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let added_password = credential_metadata_with_role(
        added_password_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let existing_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        existing_totp_id,
        CredentialLifecycleAction::Reset,
        shared_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    )];
    let added_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        added_password_id,
        CredentialLifecycleAction::Reset,
        shared_authority,
        RecoveryAuthorityTiming::Immediate,
    )];

    assert!(
        !subject_retains_required_credential_posture_after_addition(
            &[existing_totp],
            &existing_recovery_authorities,
            &subject_id,
            &added_password,
            &added_recovery_authorities,
        ),
        "adding an ordinary credential resettable by the same immediate authority as an existing second factor creates a collapsed login path"
    );
}

#[test]
fn adding_second_factor_accepts_distinct_authority_posture() {
    let subject_id: SubjectId = id("subject");
    let existing_password_id: VerifiedProofSourceId = id("password-credential");
    let added_totp_id: VerifiedProofSourceId = id("totp-credential");
    let password_authority: RecoveryAuthorityId = id("email-authority");
    let totp_authority: RecoveryAuthorityId = id("recovery-code-authority");
    let existing_password = credential_metadata_with_role(
        existing_password_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let added_totp = credential_metadata_with_role(
        added_totp_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let existing_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        existing_password_id,
        CredentialLifecycleAction::Reset,
        password_authority,
        RecoveryAuthorityTiming::Immediate,
    )];
    let added_recovery_authorities = vec![CredentialRecoveryAuthority::new(
        added_totp_id,
        CredentialLifecycleAction::Reset,
        totp_authority,
        RecoveryAuthorityTiming::Immediate,
    )];

    assert!(
        subject_retains_required_credential_posture_after_addition(
            &[existing_password],
            &existing_recovery_authorities,
            &subject_id,
            &added_totp,
            &added_recovery_authorities,
        ),
        "adding a second factor with a distinct immediate reset authority preserves honest factor posture"
    );
}

#[test]
fn second_factor_removal_requires_a_second_factor_survivor() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("totp-credential");
    let ordinary_survivor_id: VerifiedProofSourceId = id("password-credential");
    let second_factor_survivor_id: VerifiedProofSourceId = id("passkey-credential");
    let no_recovery_authorities = Vec::new();

    assert!(
        !subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
                credential_metadata_with_role(
                    ordinary_survivor_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
            ],
            &no_recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
        ),
        "a plain ordinary survivor would silently downgrade a subject that is removing a second factor"
    );

    assert!(
        subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
                credential_metadata_with_role(
                    second_factor_survivor_id,
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
            ],
            &no_recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
        ),
        "second-factor removal may proceed when another second-factor credential remains"
    );
}

#[test]
fn second_factor_removal_rejects_same_authority_survivor_collapse() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("totp-credential");
    let password_survivor_id: VerifiedProofSourceId = id("password-credential");
    let passkey_survivor_id: VerifiedProofSourceId = id("passkey-credential");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            password_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            passkey_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
    ];

    assert!(
        !subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
                credential_metadata_with_role(
                    password_survivor_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    passkey_survivor_id,
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
            ],
            &recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
        ),
        "same-authority reset paths would make the remaining second factor collapse to the ordinary survivor"
    );
}

#[test]
fn second_factor_removal_rejects_partial_same_authority_survivor_collapse() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("totp-credential");
    let same_authority_password_id: VerifiedProofSourceId = id("password-email-credential");
    let distinct_authority_password_id: VerifiedProofSourceId = id("password-device-credential");
    let second_factor_survivor_id: VerifiedProofSourceId = id("passkey-credential");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let distinct_authority: RecoveryAuthorityId = id("device-authority");
    let second_distinct_authority: RecoveryAuthorityId = id("recovery-code-authority");
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            same_authority_password_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            distinct_authority_password_id.clone(),
            CredentialLifecycleAction::Reset,
            distinct_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            second_factor_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            second_factor_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            second_distinct_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
    ];

    assert!(
        !subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
                credential_metadata_with_role(
                    same_authority_password_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    distinct_authority_password_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    second_factor_survivor_id,
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
            ],
            &recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
        ),
        "a distinct ordinary survivor must not hide another survivor path that collapses with the remaining second factor"
    );
}

#[test]
fn second_factor_removal_accepts_distinct_authority_survivor_posture() {
    let subject_id: SubjectId = id("subject");
    let removed_credential_id: VerifiedProofSourceId = id("totp-credential");
    let password_survivor_id: VerifiedProofSourceId = id("password-credential");
    let passkey_survivor_id: VerifiedProofSourceId = id("passkey-credential");
    let password_authority: RecoveryAuthorityId = id("email-authority");
    let passkey_authority: RecoveryAuthorityId = id("recovery-code-authority");
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            password_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            password_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            passkey_survivor_id.clone(),
            CredentialLifecycleAction::Reset,
            passkey_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
    ];

    assert!(
        subject_retains_required_credential_posture_after_removal(
            &[
                credential_metadata_with_role(
                    removed_credential_id.clone(),
                    CredentialInstanceKind::SharedSecretOtpVerifier,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
                credential_metadata_with_role(
                    password_survivor_id,
                    CredentialInstanceKind::MessageSignatureVerifier,
                    CredentialResetPolicyRole::OrdinaryCredential,
                ),
                credential_metadata_with_role(
                    passkey_survivor_id,
                    CredentialInstanceKind::OriginBoundPublicKeyCredential,
                    CredentialResetPolicyRole::SecondFactorCredential,
                ),
            ],
            &recovery_authorities,
            &subject_id,
            &removed_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
        ),
        "distinct immediate reset authorities preserve the remaining second-factor posture"
    );
}

#[test]
fn second_factor_replacement_rejects_successor_same_authority_collapse() {
    let subject_id: SubjectId = id("subject");
    let replaced_credential_id: VerifiedProofSourceId = id("old-totp-credential");
    let password_survivor_id: VerifiedProofSourceId = id("password-credential");
    let successor_credential_id: VerifiedProofSourceId = id("new-totp-credential");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let replaced = credential_metadata_with_role(
        replaced_credential_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let password_survivor = credential_metadata_with_role(
        password_survivor_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            password_survivor_id,
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
    ];
    let successor = CredentialReplacementSuccessor::inheriting_target_policy(
        successor_credential_id,
        &replaced,
        [CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("new-totp-authority")],
    )
    .expect("replacement successor");

    assert!(
        !subject_retains_required_credential_posture_after_replacement(
            &[replaced, password_survivor],
            &recovery_authorities,
            &subject_id,
            &replaced_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
            &successor,
        ),
        "replacing a second factor with a successor resettable by the same immediate authority as the password still collapses posture"
    );
}

#[test]
fn second_factor_replacement_rejects_partial_successor_same_authority_collapse() {
    let subject_id: SubjectId = id("subject");
    let replaced_credential_id: VerifiedProofSourceId = id("old-totp-credential");
    let same_authority_password_id: VerifiedProofSourceId = id("password-email-credential");
    let distinct_authority_password_id: VerifiedProofSourceId = id("password-device-credential");
    let successor_credential_id: VerifiedProofSourceId = id("new-totp-credential");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let distinct_authority: RecoveryAuthorityId = id("device-authority");
    let successor_distinct_authority: RecoveryAuthorityId = id("recovery-code-authority");
    let replaced = credential_metadata_with_role(
        replaced_credential_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let same_authority_password = credential_metadata_with_role(
        same_authority_password_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let distinct_authority_password = credential_metadata_with_role(
        distinct_authority_password_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            same_authority_password_id,
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            distinct_authority_password_id,
            CredentialLifecycleAction::Reset,
            distinct_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
    ];
    let successor = CredentialReplacementSuccessor::inheriting_target_policy(
        successor_credential_id,
        &replaced,
        [
            CredentialRecoveryAuthority::new(
                replaced_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                shared_authority,
                RecoveryAuthorityTiming::Immediate,
            ),
            CredentialRecoveryAuthority::new(
                replaced_credential_id.clone(),
                CredentialLifecycleAction::Reset,
                successor_distinct_authority,
                RecoveryAuthorityTiming::Immediate,
            ),
        ],
        [id("new-totp-authority")],
    )
    .expect("replacement successor");

    assert!(
        !subject_retains_required_credential_posture_after_replacement(
            &[
                replaced,
                same_authority_password,
                distinct_authority_password
            ],
            &recovery_authorities,
            &subject_id,
            &replaced_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
            &successor,
        ),
        "a distinct ordinary survivor must not hide another survivor path that collapses with the replacement second factor"
    );
}

#[test]
fn second_factor_replacement_accepts_distinct_successor_authority_posture() {
    let subject_id: SubjectId = id("subject");
    let replaced_credential_id: VerifiedProofSourceId = id("old-totp-credential");
    let password_survivor_id: VerifiedProofSourceId = id("password-credential");
    let successor_credential_id: VerifiedProofSourceId = id("new-totp-credential");
    let password_authority: RecoveryAuthorityId = id("email-authority");
    let successor_authority: RecoveryAuthorityId = id("recovery-code-authority");
    let replaced = credential_metadata_with_role(
        replaced_credential_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let password_survivor = credential_metadata_with_role(
        password_survivor_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            password_survivor_id,
            CredentialLifecycleAction::Reset,
            password_authority,
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            successor_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
    ];
    let successor = CredentialReplacementSuccessor::inheriting_target_policy(
        successor_credential_id,
        &replaced,
        [CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            successor_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("new-totp-authority")],
    )
    .expect("replacement successor");

    assert!(
        subject_retains_required_credential_posture_after_replacement(
            &[replaced, password_survivor],
            &recovery_authorities,
            &subject_id,
            &replaced_credential_id,
            CredentialResetPolicyRole::SecondFactorCredential,
            &successor,
        ),
        "replacing a second factor with a successor resettable by a distinct immediate authority preserves posture"
    );
}

#[test]
fn ordinary_replacement_rejects_successor_same_authority_collapse() {
    let subject_id: SubjectId = id("subject");
    let replaced_credential_id: VerifiedProofSourceId = id("old-password-credential");
    let second_factor_survivor_id: VerifiedProofSourceId = id("totp-credential");
    let successor_credential_id: VerifiedProofSourceId = id("new-password-credential");
    let old_password_authority: RecoveryAuthorityId = id("old-password-authority");
    let shared_authority: RecoveryAuthorityId = id("shared-email-authority");
    let replaced = credential_metadata_with_role(
        replaced_credential_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let second_factor_survivor = credential_metadata_with_role(
        second_factor_survivor_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let recovery_authorities = vec![
        CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            old_password_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
        CredentialRecoveryAuthority::new(
            second_factor_survivor_id,
            CredentialLifecycleAction::Reset,
            shared_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        ),
    ];
    let successor = CredentialReplacementSuccessor::inheriting_target_policy(
        successor_credential_id,
        &replaced,
        [CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            shared_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("new-password-authority")],
    )
    .expect("replacement successor");

    assert!(
        !subject_retains_required_credential_posture_after_replacement(
            &[replaced, second_factor_survivor],
            &recovery_authorities,
            &subject_id,
            &replaced_credential_id,
            CredentialResetPolicyRole::OrdinaryCredential,
            &successor,
        ),
        "replacing an ordinary credential with a successor resettable by the same immediate authority as an existing second factor creates a collapsed login path"
    );
}

#[test]
fn ordinary_replacement_accepts_distinct_successor_authority_posture() {
    let subject_id: SubjectId = id("subject");
    let replaced_credential_id: VerifiedProofSourceId = id("old-password-credential");
    let second_factor_survivor_id: VerifiedProofSourceId = id("totp-credential");
    let successor_credential_id: VerifiedProofSourceId = id("new-password-credential");
    let successor_authority: RecoveryAuthorityId = id("new-password-authority");
    let second_factor_authority: RecoveryAuthorityId = id("recovery-code-authority");
    let replaced = credential_metadata_with_role(
        replaced_credential_id.clone(),
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    );
    let second_factor_survivor = credential_metadata_with_role(
        second_factor_survivor_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        CredentialResetPolicyRole::SecondFactorCredential,
    );
    let recovery_authorities = vec![CredentialRecoveryAuthority::new(
        second_factor_survivor_id,
        CredentialLifecycleAction::Reset,
        second_factor_authority,
        RecoveryAuthorityTiming::Immediate,
    )];
    let successor = CredentialReplacementSuccessor::inheriting_target_policy(
        successor_credential_id,
        &replaced,
        [CredentialRecoveryAuthority::new(
            replaced_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            successor_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("new-password-authority")],
    )
    .expect("replacement successor");

    assert!(
        subject_retains_required_credential_posture_after_replacement(
            &[replaced, second_factor_survivor],
            &recovery_authorities,
            &subject_id,
            &replaced_credential_id,
            CredentialResetPolicyRole::OrdinaryCredential,
            &successor,
        ),
        "replacing an ordinary credential with a successor resettable by a distinct immediate authority preserves posture"
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

fn out_of_band_identifier_source(source_id: &str) -> VerifiedProofSource {
    VerifiedProofSource::new(VerifiedProofSourceKind::OutOfBandIdentifier, id(source_id))
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

fn credential_metadata(
    credential_instance_id: VerifiedProofSourceId,
) -> CredentialInstanceMetadata {
    credential_metadata_with_role(
        credential_instance_id,
        CredentialInstanceKind::MessageSignatureVerifier,
        CredentialResetPolicyRole::OrdinaryCredential,
    )
}

fn credential_metadata_with_role(
    credential_instance_id: VerifiedProofSourceId,
    kind: CredentialInstanceKind,
    reset_policy_role: CredentialResetPolicyRole,
) -> CredentialInstanceMetadata {
    CredentialInstanceMetadata::new(
        credential_instance_id,
        id("subject"),
        kind,
        "password_signature",
        reset_policy_role,
        CredentialLifecycleState::Active,
    )
    .expect("credential metadata")
}
