use super::*;

pub(in crate::auth_core) fn unix_seconds_from_i64(
    value: i64,
) -> Result<UnixSeconds, PostgresAuthStoreError> {
    let value = u64::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("negative Unix timestamp"))?;
    Ok(UnixSeconds::new(value))
}

pub(in crate::auth_core) fn i64_from_unix_seconds(
    value: UnixSeconds,
) -> Result<i64, PostgresAuthStoreError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("Unix timestamp too large"))
}

pub(in crate::auth_core) fn optional_i64_from_unix_seconds(
    value: Option<UnixSeconds>,
) -> Result<Option<i64>, PostgresAuthStoreError> {
    value.map(i64_from_unix_seconds).transpose()
}

pub(in crate::auth_core) fn secret_version_from_i64(
    value: i64,
) -> Result<SecretVersion, PostgresAuthStoreError> {
    let value = u64::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("negative secret version"))?;
    SecretVersion::new(value).map_err(PostgresAuthStoreError::Core)
}

pub(in crate::auth_core) fn i64_from_secret_version(
    value: SecretVersion,
) -> Result<i64, PostgresAuthStoreError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("secret version too large"))
}

pub(in crate::auth_core) fn optional_i64_from_secret_version(
    value: Option<SecretVersion>,
) -> Result<Option<i64>, PostgresAuthStoreError> {
    value.map(i64_from_secret_version).transpose()
}

pub(in crate::auth_core) fn u32_from_i32(value: i32) -> Result<u32, PostgresAuthStoreError> {
    u32::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("negative u32-backed value"))
}

pub(in crate::auth_core) fn i32_from_u32(value: u32) -> Result<i32, PostgresAuthStoreError> {
    i32::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("u32-backed value too large"))
}

pub(in crate::auth_core) fn proof_family_from_i32(
    value: i32,
) -> Result<ProofFamily, PostgresAuthStoreError> {
    let value = u8::try_from(value)
        .map_err(|_| PostgresAuthStoreError::InvalidStoredData("invalid proof family id"))?;
    proof_family_from_wire_id(value).map_err(PostgresAuthStoreError::Core)
}

pub(in crate::auth_core) fn i32_from_proof_family(value: ProofFamily) -> i32 {
    i32::from(proof_family_wire_id(value))
}

pub(in crate::auth_core) fn verified_proof_source_kind_from_i32(
    value: i32,
) -> Result<VerifiedProofSourceKind, PostgresAuthStoreError> {
    match value {
        1 => Ok(VerifiedProofSourceKind::CredentialInstance),
        2 => Ok(VerifiedProofSourceKind::OutOfBandIdentifier),
        3 => Ok(VerifiedProofSourceKind::ExternalAuthority),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid verified proof source kind",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_verified_proof_source_kind(
    value: VerifiedProofSourceKind,
) -> i32 {
    match value {
        VerifiedProofSourceKind::CredentialInstance => 1,
        VerifiedProofSourceKind::OutOfBandIdentifier => 2,
        VerifiedProofSourceKind::ExternalAuthority => 3,
    }
}

pub(in crate::auth_core) fn credential_instance_kind_from_i32(
    value: i32,
) -> Result<CredentialInstanceKind, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialInstanceKind::MessageSignatureVerifier),
        2 => Ok(CredentialInstanceKind::SharedSecretOtpVerifier),
        3 => Ok(CredentialInstanceKind::OriginBoundPublicKeyCredential),
        4 => Ok(CredentialInstanceKind::RecoveryCodeCredential),
        5 => Ok(CredentialInstanceKind::TrustedDeviceCredential),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential instance kind",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_credential_instance_kind(
    value: CredentialInstanceKind,
) -> i32 {
    match value {
        CredentialInstanceKind::MessageSignatureVerifier => 1,
        CredentialInstanceKind::SharedSecretOtpVerifier => 2,
        CredentialInstanceKind::OriginBoundPublicKeyCredential => 3,
        CredentialInstanceKind::RecoveryCodeCredential => 4,
        CredentialInstanceKind::TrustedDeviceCredential => 5,
    }
}

pub(in crate::auth_core) fn credential_reset_policy_role_from_i32(
    value: i32,
) -> Result<CredentialResetPolicyRole, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialResetPolicyRole::OrdinaryCredential),
        2 => Ok(CredentialResetPolicyRole::SecondFactorCredential),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential reset policy role",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_credential_reset_policy_role(
    value: CredentialResetPolicyRole,
) -> i32 {
    match value {
        CredentialResetPolicyRole::OrdinaryCredential => 1,
        CredentialResetPolicyRole::SecondFactorCredential => 2,
    }
}

pub(in crate::auth_core) fn credential_lifecycle_state_from_i32(
    value: i32,
) -> Result<CredentialLifecycleState, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialLifecycleState::Active),
        2 => Ok(CredentialLifecycleState::PendingActivation),
        3 => Ok(CredentialLifecycleState::PendingReplacement),
        4 => Ok(CredentialLifecycleState::PendingRemoval),
        5 => Ok(CredentialLifecycleState::ScheduledDeletion),
        6 => Ok(CredentialLifecycleState::Consumed),
        7 => Ok(CredentialLifecycleState::Revoked),
        8 => Ok(CredentialLifecycleState::Expired),
        9 => Ok(CredentialLifecycleState::Superseded),
        10 => Ok(CredentialLifecycleState::AdminSuspended),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential lifecycle state",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_credential_lifecycle_state(
    value: CredentialLifecycleState,
) -> i32 {
    match value {
        CredentialLifecycleState::Active => 1,
        CredentialLifecycleState::PendingActivation => 2,
        CredentialLifecycleState::PendingReplacement => 3,
        CredentialLifecycleState::PendingRemoval => 4,
        CredentialLifecycleState::ScheduledDeletion => 5,
        CredentialLifecycleState::Consumed => 6,
        CredentialLifecycleState::Revoked => 7,
        CredentialLifecycleState::Expired => 8,
        CredentialLifecycleState::Superseded => 9,
        CredentialLifecycleState::AdminSuspended => 10,
    }
}

pub(in crate::auth_core) fn out_of_band_identifier_binding_lifecycle_state_from_i32(
    value: i32,
) -> Result<OutOfBandIdentifierBindingLifecycleState, PostgresAuthStoreError> {
    match value {
        1 => Ok(OutOfBandIdentifierBindingLifecycleState::PendingActivation),
        2 => Ok(OutOfBandIdentifierBindingLifecycleState::Active),
        3 => Ok(OutOfBandIdentifierBindingLifecycleState::Superseded),
        4 => Ok(OutOfBandIdentifierBindingLifecycleState::Revoked),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid out-of-band identifier binding lifecycle state",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_out_of_band_identifier_binding_lifecycle_state(
    value: OutOfBandIdentifierBindingLifecycleState,
) -> i32 {
    match value {
        OutOfBandIdentifierBindingLifecycleState::PendingActivation => 1,
        OutOfBandIdentifierBindingLifecycleState::Active => 2,
        OutOfBandIdentifierBindingLifecycleState::Superseded => 3,
        OutOfBandIdentifierBindingLifecycleState::Revoked => 4,
    }
}

pub(in crate::auth_core) fn credential_lifecycle_action_from_i32(
    value: i32,
) -> Result<CredentialLifecycleAction, PostgresAuthStoreError> {
    match value {
        1 => Ok(CredentialLifecycleAction::Create),
        2 => Ok(CredentialLifecycleAction::Reset),
        3 => Ok(CredentialLifecycleAction::Replace),
        4 => Ok(CredentialLifecycleAction::Remove),
        5 => Ok(CredentialLifecycleAction::Disable),
        6 => Ok(CredentialLifecycleAction::Regenerate),
        7 => Ok(CredentialLifecycleAction::RecoverSubjectAccess),
        8 => Ok(CredentialLifecycleAction::Rotate),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid credential lifecycle action",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_credential_lifecycle_action(
    value: CredentialLifecycleAction,
) -> i32 {
    match value {
        CredentialLifecycleAction::Create => 1,
        CredentialLifecycleAction::Reset => 2,
        CredentialLifecycleAction::Replace => 3,
        CredentialLifecycleAction::Remove => 4,
        CredentialLifecycleAction::Disable => 5,
        CredentialLifecycleAction::Regenerate => 6,
        CredentialLifecycleAction::RecoverSubjectAccess => 7,
        CredentialLifecycleAction::Rotate => 8,
    }
}

pub(in crate::auth_core) fn subject_lifecycle_action_from_i32(
    value: i32,
) -> Result<SubjectLifecycleAction, PostgresAuthStoreError> {
    match value {
        1 => Ok(SubjectLifecycleAction::DeleteSubjectAuthState),
        2 => Ok(SubjectLifecycleAction::ChangeOutOfBandIdentifier),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid subject lifecycle action",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_subject_lifecycle_action(
    value: SubjectLifecycleAction,
) -> i32 {
    match value {
        SubjectLifecycleAction::DeleteSubjectAuthState => 1,
        SubjectLifecycleAction::ChangeOutOfBandIdentifier => 2,
    }
}

pub(in crate::auth_core) fn admin_support_intervention_status_from_i32(
    value: i32,
) -> Result<AdminSupportInterventionStatus, PostgresAuthStoreError> {
    match value {
        1 => Ok(AdminSupportInterventionStatus::Requested),
        2 => Ok(AdminSupportInterventionStatus::Approved),
        3 => Ok(AdminSupportInterventionStatus::Denied),
        4 => Ok(AdminSupportInterventionStatus::Expired),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid admin support intervention status",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_admin_support_intervention_status(
    value: AdminSupportInterventionStatus,
) -> i32 {
    match value {
        AdminSupportInterventionStatus::Requested => 1,
        AdminSupportInterventionStatus::Approved => 2,
        AdminSupportInterventionStatus::Denied => 3,
        AdminSupportInterventionStatus::Expired => 4,
    }
}

pub(in crate::auth_core) fn recovery_authority_timing_from_i32(
    value: i32,
) -> Result<RecoveryAuthorityTiming, PostgresAuthStoreError> {
    match value {
        1 => Ok(RecoveryAuthorityTiming::Immediate),
        2 => Ok(RecoveryAuthorityTiming::Delayed),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid recovery authority timing",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_recovery_authority_timing(
    value: RecoveryAuthorityTiming,
) -> i32 {
    match value {
        RecoveryAuthorityTiming::Immediate => 1,
        RecoveryAuthorityTiming::Delayed => 2,
    }
}

pub(in crate::auth_core) fn lifecycle_authority_source_kind_from_i32(
    value: i32,
) -> Result<LifecycleAuthoritySourceKind, PostgresAuthStoreError> {
    match value {
        1 => Ok(LifecycleAuthoritySourceKind::CredentialInstance),
        2 => Ok(LifecycleAuthoritySourceKind::OutOfBandIdentifier),
        3 => Ok(LifecycleAuthoritySourceKind::ExternalAuthority),
        4 => Ok(LifecycleAuthoritySourceKind::AuthenticatedSession),
        5 => Ok(LifecycleAuthoritySourceKind::AdminSupportIntervention),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid lifecycle authority source kind",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_lifecycle_authority_source_kind(
    value: LifecycleAuthoritySourceKind,
) -> i32 {
    match value {
        LifecycleAuthoritySourceKind::CredentialInstance => 1,
        LifecycleAuthoritySourceKind::OutOfBandIdentifier => 2,
        LifecycleAuthoritySourceKind::ExternalAuthority => 3,
        LifecycleAuthoritySourceKind::AuthenticatedSession => 4,
        LifecycleAuthoritySourceKind::AdminSupportIntervention => 5,
    }
}

pub(in crate::auth_core) fn online_guessing_risk_from_bool(value: bool) -> OnlineGuessingRisk {
    if value {
        OnlineGuessingRisk::OnlineGuessable
    } else {
        OnlineGuessingRisk::NotOnlineGuessable
    }
}

pub(in crate::auth_core) fn bool_from_online_guessing_risk(value: OnlineGuessingRisk) -> bool {
    matches!(value, OnlineGuessingRisk::OnlineGuessable)
}

pub(in crate::auth_core) fn proof_use_from_i32(
    value: i32,
) -> Result<ProofUse, PostgresAuthStoreError> {
    match value {
        1 => Ok(ProofUse::BindSubjectToActiveProofAttempt),
        2 => Ok(ProofUse::ContributeToFullAuthentication),
        3 => Ok(ProofUse::ReviveTrustedDeviceWithActiveProof),
        4 => Ok(ProofUse::SatisfyStepUp),
        5 => Ok(ProofUse::SilentlyReviveTrustedDeviceSession),
        6 => Ok(ProofUse::ReduceAuthenticationRequirement),
        7 => Ok(ProofUse::RecoverOrReplaceCredential),
        8 => Ok(ProofUse::ProveOutOfBandIdentifierChangeCandidate),
        _ => Err(PostgresAuthStoreError::InvalidStoredData(
            "invalid proof use id",
        )),
    }
}

pub(in crate::auth_core) fn i32_from_proof_use(value: ProofUse) -> i32 {
    match value {
        ProofUse::BindSubjectToActiveProofAttempt => 1,
        ProofUse::ContributeToFullAuthentication => 2,
        ProofUse::ReviveTrustedDeviceWithActiveProof => 3,
        ProofUse::SatisfyStepUp => 4,
        ProofUse::SilentlyReviveTrustedDeviceSession => 5,
        ProofUse::ReduceAuthenticationRequirement => 6,
        ProofUse::RecoverOrReplaceCredential => 7,
        ProofUse::ProveOutOfBandIdentifierChangeCandidate => 8,
    }
}

pub(in crate::auth_core) fn i32_from_audit_event_kind(value: AuditEventKind) -> i32 {
    match value {
        AuditEventKind::SessionCreated => 1,
        AuditEventKind::SessionRefreshed => 2,
        AuditEventKind::TrustedDeviceSilentRevival => 3,
        AuditEventKind::TrustedDeviceActiveProofRevival => 4,
        AuditEventKind::TrustedDeviceCreated => 5,
        AuditEventKind::TrustedDeviceRotated => 6,
        AuditEventKind::StepUpCompleted => 7,
        AuditEventKind::CredentialMismatch => 8,
        AuditEventKind::SessionRevoked => 9,
        AuditEventKind::TrustedDeviceRevoked => 10,
        AuditEventKind::SubjectAuthStateRevoked => 11,
        AuditEventKind::ActiveProofAttemptStarted => 12,
        AuditEventKind::OutOfBandChallengeIssued => 13,
        AuditEventKind::OutOfBandChallengeResent => 14,
        AuditEventKind::ActiveProofFailed => 15,
        AuditEventKind::ActiveProofSucceeded => 16,
        AuditEventKind::ActiveProofAttemptClosed => 17,
        AuditEventKind::ActiveProofAttemptDeletedAfterWeakProofFailures => 18,
        AuditEventKind::ActiveProofMethodChallengeIssued => 19,
        AuditEventKind::CredentialResetAuthorized => 20,
        AuditEventKind::CredentialResetPendingActionScheduled => 21,
        AuditEventKind::CredentialResetExecuted => 22,
        AuditEventKind::CredentialResetPendingActionCancelled => 23,
        AuditEventKind::CredentialReplacementExecuted => 24,
        AuditEventKind::CredentialReplacementPendingActionCancelled => 25,
        AuditEventKind::CredentialRemovalExecuted => 26,
        AuditEventKind::CredentialRemovalPendingActionCancelled => 27,
        AuditEventKind::CredentialRegenerationExecuted => 28,
        AuditEventKind::CredentialRegenerationPendingActionCancelled => 29,
        AuditEventKind::SubjectAuthStateDeletionPendingActionScheduled => 30,
        AuditEventKind::SubjectAuthStateDeletionExecuted => 31,
        AuditEventKind::SubjectAuthStateDeletionPendingActionCancelled => 32,
        AuditEventKind::AdminSupportCredentialLifecycleInterventionAuthorized => 33,
        AuditEventKind::AdminSupportCredentialLifecycleInterventionPendingActionScheduled => 34,
        AuditEventKind::AdminSupportInterventionRequested => 35,
        AuditEventKind::AdminSupportInterventionApproved => 36,
        AuditEventKind::AdminSupportInterventionDenied => 37,
        AuditEventKind::AdminSupportInterventionExpired => 38,
        AuditEventKind::CredentialAdded => 39,
        AuditEventKind::CredentialReplacementAuthorized => 40,
        AuditEventKind::CredentialReplacementPendingActionScheduled => 41,
        AuditEventKind::CredentialRemovalAuthorized => 42,
        AuditEventKind::CredentialRemovalPendingActionScheduled => 43,
        AuditEventKind::CredentialRotated => 44,
        AuditEventKind::OutOfBandIdentifierChanged => 45,
        AuditEventKind::OutOfBandIdentifierChangeCandidateBindingReserved => 46,
        AuditEventKind::OutOfBandIdentifierChangePendingActionScheduled => 47,
        AuditEventKind::OutOfBandIdentifierChangePendingActionCancelled => 48,
        AuditEventKind::CredentialRegenerationAuthorized => 49,
        AuditEventKind::CredentialRegenerationPendingActionScheduled => 50,
    }
}

pub(in crate::auth_core) fn i32_from_security_notification_kind(
    value: SecurityNotificationKind,
) -> i32 {
    match value {
        SecurityNotificationKind::TrustedDeviceCreated => 1,
        SecurityNotificationKind::CredentialResetAuthorized => 2,
        SecurityNotificationKind::CredentialResetPendingActionScheduled => 3,
        SecurityNotificationKind::CredentialResetExecuted => 4,
        SecurityNotificationKind::CredentialResetPendingActionCancelled => 5,
        SecurityNotificationKind::CredentialReplacementExecuted => 6,
        SecurityNotificationKind::CredentialReplacementPendingActionCancelled => 7,
        SecurityNotificationKind::CredentialRemovalExecuted => 8,
        SecurityNotificationKind::CredentialRemovalPendingActionCancelled => 9,
        SecurityNotificationKind::CredentialRegenerationExecuted => 10,
        SecurityNotificationKind::CredentialRegenerationPendingActionCancelled => 11,
        SecurityNotificationKind::SubjectAuthStateDeletionPendingActionScheduled => 12,
        SecurityNotificationKind::SubjectAuthStateDeletionExecuted => 13,
        SecurityNotificationKind::SubjectAuthStateDeletionPendingActionCancelled => 14,
        SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionAuthorized => 15,
        SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionPendingActionScheduled => 16,
        SecurityNotificationKind::AdminSupportInterventionRequested => 17,
        SecurityNotificationKind::AdminSupportInterventionApproved => 18,
        SecurityNotificationKind::AdminSupportInterventionDenied => 19,
        SecurityNotificationKind::AdminSupportInterventionExpired => 20,
        SecurityNotificationKind::CredentialAdded => 21,
        SecurityNotificationKind::CredentialReplacementAuthorized => 22,
        SecurityNotificationKind::CredentialReplacementPendingActionScheduled => 23,
        SecurityNotificationKind::CredentialRemovalAuthorized => 24,
        SecurityNotificationKind::CredentialRemovalPendingActionScheduled => 25,
        SecurityNotificationKind::CredentialRotated => 26,
        SecurityNotificationKind::OutOfBandIdentifierChanged => 27,
        SecurityNotificationKind::OutOfBandIdentifierChangePendingActionScheduled => 28,
        SecurityNotificationKind::OutOfBandIdentifierChangePendingActionCancelled => 29,
        SecurityNotificationKind::CredentialRegenerationAuthorized => 30,
        SecurityNotificationKind::CredentialRegenerationPendingActionScheduled => 31,
    }
}

pub(in crate::auth_core) fn i32_from_weak_gate_kind(value: WeakProofGateKind) -> i32 {
    match value {
        WeakProofGateKind::ProofOfWork => 1,
        WeakProofGateKind::HumanChallenge => 2,
        WeakProofGateKind::RiskDecision => 3,
        WeakProofGateKind::Other => 4,
    }
}
