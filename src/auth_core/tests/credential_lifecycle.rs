use super::*;

#[test]
fn immediate_credential_reset_records_authorization_notice_and_subject_revocation() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("primary-email", [email_authority])
                        .expect("email evidence"),
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: None,
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("credential reset transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["credential_instance_still_active"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::RecordCredentialLifecycleActionAuthorized {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Reset,
                authorized_at: at(100),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(100),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![AuditEvent {
            kind: AuditEventKind::CredentialResetAuthorized,
            subject_id: Some(id("subject")),
            session_id: None,
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(100),
        }]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetAuthorized,
                subject_id: id("subject"),
            },
        )]
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn delayed_credential_reset_creates_pending_action_notice_and_uniqueness_guard() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-reset");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("primary-email", [email_authority])
                        .expect("email evidence"),
                ],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("credential reset transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: pending_action_id.clone(),
            earliest_execute_at: at(200),
            expires_at: at(300),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "credential_instance_still_active",
            "no_open_pending_credential_lifecycle_action_for_target",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::CreatePendingCredentialLifecycleAction(
            PendingCredentialLifecycleActionRecord::new_open(
                pending_action_id,
                id("subject"),
                target_credential_id,
                CredentialLifecycleAction::Reset,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![AuditEvent {
            kind: AuditEventKind::CredentialResetPendingActionScheduled,
            subject_id: Some(id("subject")),
            session_id: None,
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(100),
        }]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetPendingActionScheduled,
                subject_id: id("subject"),
            },
        )]
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn delayed_credential_reset_requires_runtime_generated_pending_action_id_and_valid_schedule() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Reset,
            email_authority.clone(),
            RecoveryAuthorityTiming::Delayed,
        )],
        [
            out_of_band_identifier_evidence("primary-email", [email_authority])
                .expect("email evidence"),
        ],
    );

    let missing_schedule_error = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: lifecycle_context.clone(),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: None,
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed reset requires a runtime-owned pending action id");
    assert_eq!(
        missing_schedule_error,
        Error::MissingFreshValue("pending credential lifecycle action id")
    );

    let invalid_schedule_error = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context,
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-reset"),
                earliest_execute_at: at(100),
                expires_at: at(300),
            }),
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed reset requires future execution time");
    assert_eq!(
        invalid_schedule_error,
        Error::InvalidCredentialLifecyclePendingActionTiming
    );
}

#[test]
fn credential_reset_rejects_evidence_without_lifecycle_authority() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let unknown_authority: RecoveryAuthorityId = id("unknown-authority");
    let error = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id,
                    CredentialLifecycleAction::Reset,
                    id("primary-email-authority"),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("other-email", [unknown_authority])
                        .expect("email evidence"),
                ],
            ),
            active_proof_attempt_to_close: None,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-reset"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
            immediate_subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("unknown lifecycle authority must not authorize reset");

    assert_eq!(error, Error::CredentialLifecycleActionNotAuthorized);
}

#[test]
fn immediate_credential_reset_execution_applies_method_work_notice_and_revocation() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let method_work = password_reset_method_commit_work(b"new-password-verifier");
    let transition = reduce_command(
        &config(),
        Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now: at(250),
            execution_authority: CredentialResetExecutionAuthority::Immediate {
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Reset,
                        email_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [
                        out_of_band_identifier_evidence("primary-email", [email_authority])
                            .expect("email evidence"),
                        credential_instance_evidence("trusted-device", [device_authority])
                            .expect("trusted-device evidence"),
                    ],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::Required,
            },
            method_commit_work: vec![method_work.clone()],
            subject_auth_revocation: CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("credential reset execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: None,
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["credential_instance_still_active"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Reset,
                executed_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ]
    );
    assert_eq!(transition.commit_plan.method_commit_work, vec![method_work]);
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![AuditEvent {
            kind: AuditEventKind::CredentialResetExecuted,
            subject_id: Some(id("subject")),
            session_id: None,
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(250),
        }]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetExecuted,
                subject_id: id("subject"),
            },
        )]
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn matured_pending_credential_reset_execution_closes_pending_action_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-reset");
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let pending_action = PendingCredentialLifecycleActionRecord::new_open(
        pending_action_id.clone(),
        id("subject"),
        target_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending action");
    let method_work = password_reset_method_commit_work(b"new-password-verifier");

    let transition = reduce_command(
        &config(),
        Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now: at(250),
            execution_authority: CredentialResetExecutionAuthority::MaturePendingAction {
                target_credential,
                pending_action,
            },
            method_commit_work: vec![method_work.clone()],
            subject_auth_revocation: CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState,
        }),
        &LoadedState::default(),
    )
    .expect("credential reset execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: Some(pending_action_id.clone()),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "credential_instance_still_active",
            "pending_credential_lifecycle_action_still_executable",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id,
                closed_at: at(250),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Reset,
                executed_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ]
    );
    assert_eq!(transition.commit_plan.method_commit_work, vec![method_work]);
}

#[test]
fn pending_credential_reset_cancellation_closes_open_action_and_schedules_notice() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-reset");
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let pending_action = PendingCredentialLifecycleActionRecord::new_open(
        pending_action_id.clone(),
        id("subject"),
        target_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending action");

    let transition = reduce_command(
        &config(),
        Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
            now: at(150),
            target_credential,
            pending_action,
        }),
        &LoadedState::default(),
    )
    .expect("credential reset cancellation transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetPendingActionCancelled(CredentialResetCancellationOutcome {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: pending_action_id.clone(),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "credential_instance_still_active",
            "pending_credential_lifecycle_action_still_cancellable_for_target",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id,
            closed_at: at(150),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![AuditEvent {
            kind: AuditEventKind::CredentialResetPendingActionCancelled,
            subject_id: Some(id("subject")),
            session_id: None,
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(150),
        }]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetPendingActionCancelled,
                subject_id: id("subject"),
            },
        )]
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn pending_credential_reset_cancellation_rejects_closed_or_mismatched_action() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let mut closed_pending_action = PendingCredentialLifecycleActionRecord::new_open(
        id("pending-reset"),
        id("subject"),
        target_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending action");
    closed_pending_action.closed_at = Some(at(120));

    let closed_error = reduce_command(
        &config(),
        Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
            now: at(150),
            target_credential: target_credential.clone(),
            pending_action: closed_pending_action,
        }),
        &LoadedState::default(),
    )
    .expect_err("closed pending action cannot be cancelled");
    assert_eq!(
        closed_error,
        Error::PendingCredentialLifecycleActionNotCancellable
    );

    let mismatched_pending_action = PendingCredentialLifecycleActionRecord::new_open(
        id("pending-reset"),
        id("subject"),
        id("other-credential"),
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending action");
    let mismatched_error = reduce_command(
        &config(),
        Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
            now: at(150),
            target_credential,
            pending_action: mismatched_pending_action,
        }),
        &LoadedState::default(),
    )
    .expect_err("mismatched pending action cannot be cancelled");
    assert_eq!(
        mismatched_error,
        Error::PendingCredentialLifecycleActionNotCancellable
    );
}

#[test]
fn pending_credential_reset_cancellation_rejects_expired_action() {
    let target_credential = message_signature_credential_metadata("password-credential");
    let target_credential_id = target_credential.credential_instance_id().clone();
    let expired_pending_action = PendingCredentialLifecycleActionRecord::new_open(
        id("expired-pending-reset"),
        id("subject"),
        target_credential_id,
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("expired pending action");

    let error = reduce_command(
        &config(),
        Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
            now: at(300),
            target_credential,
            pending_action: expired_pending_action,
        }),
        &LoadedState::default(),
    )
    .expect_err("expired pending reset is not a cancellation");
    assert_eq!(error, Error::PendingCredentialLifecycleActionNotCancellable);
}

#[test]
fn credential_reset_execution_rejects_non_executable_pending_action() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let pending_action = PendingCredentialLifecycleActionRecord::new_open(
        id("pending-reset"),
        id("subject"),
        target_credential_id,
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending action");

    let too_early_error = reduce_command(
        &config(),
        Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now: at(199),
            execution_authority: CredentialResetExecutionAuthority::MaturePendingAction {
                target_credential: target_credential.clone(),
                pending_action: pending_action.clone(),
            },
            method_commit_work: vec![password_reset_method_commit_work(b"new-password-verifier")],
            subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("pending action cannot execute before earliest time");
    assert_eq!(
        too_early_error,
        Error::PendingCredentialLifecycleActionNotExecutable
    );

    let expired_error = reduce_command(
        &config(),
        Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now: at(300),
            execution_authority: CredentialResetExecutionAuthority::MaturePendingAction {
                target_credential,
                pending_action,
            },
            method_commit_work: vec![password_reset_method_commit_work(b"new-password-verifier")],
            subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("pending action cannot execute after expiry");
    assert_eq!(
        expired_error,
        Error::PendingCredentialLifecycleActionNotExecutable
    );
}

#[test]
fn credential_reset_execution_rejects_missing_or_mismatched_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Reset,
            email_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        [
            out_of_band_identifier_evidence("primary-email", [email_authority])
                .expect("email evidence"),
            credential_instance_evidence("trusted-device", [device_authority])
                .expect("trusted-device evidence"),
        ],
    );

    let missing_error = reduce_command(
        &config(),
        Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now: at(250),
            execution_authority: CredentialResetExecutionAuthority::Immediate {
                lifecycle_context: lifecycle_context.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::Required,
            },
            method_commit_work: Vec::new(),
            subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("reset execution requires method-owned verifier mutation work");
    assert_eq!(
        missing_error,
        Error::CredentialResetExecutionMissingMethodCommitWork
    );

    let mismatch_error = reduce_command(
        &config(),
        Command::ExecuteCredentialReset(ExecuteCredentialReset {
            now: at(250),
            execution_authority: CredentialResetExecutionAuthority::Immediate {
                lifecycle_context,
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::Required,
            },
            method_commit_work: vec![recovery_code_method_commit_work()],
            subject_auth_revocation:
                CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
        }),
        &LoadedState::default(),
    )
    .expect_err("reset method work must match the target credential family and method");
    assert_eq!(
        mismatch_error,
        Error::CredentialResetExecutionMethodCommitWorkTargetMismatch
    );
}

#[test]
fn pending_credential_replacement_execution_supersedes_target_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-replacement");
    let method_work = password_reset_method_commit_work(b"replacement-password-verifier");

    let transition = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential: target_credential_metadata(target_credential_id.clone()),
                pending_action: pending_action(
                    pending_action_id.clone(),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                ),
                method_commit_work: vec![method_work.clone()],
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::RevokeSubjectAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect("credential replacement execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
                pending_action_id: pending_action_id.clone(),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "credential_instance_still_active",
            "pending_credential_lifecycle_action_still_executable",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id,
                closed_at: at(250),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
                executed_at: at(250),
            },
            Mutation::SetCredentialLifecycleState {
                credential_instance_id: target_credential_id,
                lifecycle_state: CredentialLifecycleState::Superseded,
                updated_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ]
    );
    assert_eq!(transition.commit_plan.method_commit_work, vec![method_work]);
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialReplacementExecuted,
            at(250)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialReplacementExecuted
        )]
    );
}

#[test]
fn pending_credential_removal_execution_revokes_target_without_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-removal");

    let transition = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential: target_credential_metadata(target_credential_id.clone()),
                pending_action: pending_action(
                    pending_action_id.clone(),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                ),
                method_commit_work: Vec::new(),
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect("credential removal execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
                pending_action_id: pending_action_id.clone(),
            },
        )
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id,
                closed_at: at(250),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
                executed_at: at(250),
            },
            Mutation::SetCredentialLifecycleState {
                credential_instance_id: target_credential_id,
                lifecycle_state: CredentialLifecycleState::Revoked,
                updated_at: at(250),
            },
        ]
    );
    assert!(transition.commit_plan.method_commit_work.is_empty());
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(AuditEventKind::CredentialRemovalExecuted, at(250))]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialRemovalExecuted
        )]
    );
}

#[test]
fn pending_credential_regeneration_execution_preserves_target_state_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-regeneration");
    let method_work = recovery_code_method_commit_work();

    let transition = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential: recovery_code_credential_metadata(target_credential_id.clone()),
                pending_action: pending_action(
                    pending_action_id.clone(),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Regenerate,
                ),
                method_commit_work: vec![method_work.clone()],
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect("credential regeneration execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Regenerate,
                pending_action_id,
            },
        )
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id: id("pending-regeneration"),
                closed_at: at(250),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Regenerate,
                executed_at: at(250),
            },
        ]
    );
    assert_eq!(transition.commit_plan.method_commit_work, vec![method_work]);
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialRegenerationExecuted,
            at(250)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialRegenerationExecuted
        )]
    );
}

#[test]
fn pending_non_reset_credential_lifecycle_action_cancellation_closes_action_and_schedules_notice() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-replacement");

    let transition = reduce_command(
        &config(),
        Command::CancelNonResetPendingCredentialLifecycleAction(
            CancelNonResetPendingCredentialLifecycleAction {
                now: at(150),
                target_credential: target_credential_metadata(target_credential_id.clone()),
                pending_action: pending_action(
                    pending_action_id.clone(),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                ),
            },
        ),
        &LoadedState::default(),
    )
    .expect("credential replacement cancellation transition");

    assert_eq!(
        transition.outcome,
        Outcome::NonResetPendingCredentialLifecycleActionCancelled(
            NonResetPendingCredentialLifecycleActionCancellationOutcome {
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Replace,
                pending_action_id: pending_action_id.clone(),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "credential_instance_still_active",
            "pending_credential_lifecycle_action_still_cancellable_for_target",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id,
            closed_at: at(150),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialReplacementPendingActionCancelled,
            at(150),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialReplacementPendingActionCancelled
        )]
    );
}

#[test]
fn pending_non_reset_credential_lifecycle_action_execution_rejects_wrong_contracts() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let target_credential = target_credential_metadata(target_credential_id.clone());

    let reset_error = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential: target_credential.clone(),
                pending_action: pending_action(
                    id("pending-reset"),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Reset,
                ),
                method_commit_work: vec![password_reset_method_commit_work(b"verifier")],
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect_err("reset cannot execute through the non-reset command");
    assert_eq!(
        reset_error,
        Error::NonResetPendingCredentialLifecycleActionCannotBeReset
    );

    let missing_method_work_error = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential: target_credential.clone(),
                pending_action: pending_action(
                    id("pending-replacement"),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                ),
                method_commit_work: Vec::new(),
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect_err("replacement requires method work");
    assert_eq!(
        missing_method_work_error,
        Error::CredentialLifecycleExecutionMissingMethodCommitWork
    );

    let mismatched_method_work_error = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential: target_credential.clone(),
                pending_action: pending_action(
                    id("pending-replacement"),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                ),
                method_commit_work: vec![recovery_code_method_commit_work()],
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect_err("replacement method work must match target credential");
    assert_eq!(
        mismatched_method_work_error,
        Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch
    );

    let unexpected_method_work_error = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential,
                pending_action: pending_action(
                    id("pending-removal"),
                    target_credential_id,
                    CredentialLifecycleAction::Remove,
                ),
                method_commit_work: vec![password_reset_method_commit_work(b"cleanup")],
                subject_auth_revocation:
                    CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
            },
        ),
        &LoadedState::default(),
    )
    .expect_err("removal is a core state mutation in the current contract");
    assert_eq!(
        unexpected_method_work_error,
        Error::CredentialLifecycleExecutionUnexpectedMethodCommitWork
    );
}

#[test]
fn delayed_subject_auth_state_deletion_creates_subject_pending_action() {
    let pending_action_id: PendingSubjectLifecycleActionId = id("pending-subject-deletion");

    let transition = reduce_command(
        &config(),
        Command::ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion {
            now: at(100),
            subject_id: id("subject"),
            pending_action: PendingSubjectLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            },
        }),
        &LoadedState::default(),
    )
    .expect("subject deletion scheduling transition");

    assert_eq!(
        transition.outcome,
        Outcome::SubjectAuthStateDeletionScheduled(SubjectAuthStateDeletionScheduledOutcome {
            subject_id: id("subject"),
            pending_action_id: pending_action_id.clone(),
            earliest_execute_at: at(200),
            expires_at: at(300),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["no_open_pending_subject_lifecycle_action_for_subject"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::CreatePendingSubjectLifecycleAction(
            PendingSubjectLifecycleActionRecord::new_open(
                pending_action_id,
                id("subject"),
                SubjectLifecycleAction::DeleteSubjectAuthState,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending subject action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::SubjectAuthStateDeletionPendingActionScheduled,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::SubjectAuthStateDeletionPendingActionScheduled
        )]
    );
}

#[test]
fn delayed_subject_auth_state_deletion_rejects_invalid_schedule() {
    let error = reduce_command(
        &config(),
        Command::ScheduleSubjectAuthStateDeletion(ScheduleSubjectAuthStateDeletion {
            now: at(100),
            subject_id: id("subject"),
            pending_action: PendingSubjectLifecycleActionSchedule {
                pending_action_id: id("pending-subject-deletion"),
                earliest_execute_at: at(100),
                expires_at: at(300),
            },
        }),
        &LoadedState::default(),
    )
    .expect_err("subject deletion pending action requires future maturity");
    assert_eq!(error, Error::InvalidSubjectLifecyclePendingActionTiming);
}

#[test]
fn matured_subject_auth_state_deletion_closes_pending_action_and_revokes_subject_auth_state() {
    let pending_action_id: PendingSubjectLifecycleActionId = id("pending-subject-deletion");

    let transition = reduce_command(
        &config(),
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(250),
            pending_action: pending_subject_action(pending_action_id.clone()),
        }),
        &LoadedState::default(),
    )
    .expect("subject deletion execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::PendingSubjectAuthStateDeletionExecuted(
            PendingSubjectAuthStateDeletionExecutionOutcome {
                subject_id: id("subject"),
                pending_action_id: pending_action_id.clone(),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["pending_subject_lifecycle_action_still_executable"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::ClosePendingSubjectLifecycleAction {
                pending_action_id,
                closed_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::SubjectAuthStateDeletionExecuted,
            at(250),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::SubjectAuthStateDeletionExecuted
        )]
    );
}

#[test]
fn subject_auth_state_deletion_execution_rejects_unusable_pending_action() {
    let mut early_action = pending_subject_action(id("pending-subject-deletion"));
    let early_error = reduce_command(
        &config(),
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(150),
            pending_action: early_action.clone(),
        }),
        &LoadedState::default(),
    )
    .expect_err("subject deletion cannot execute before maturity");
    assert_eq!(
        early_error,
        Error::PendingSubjectLifecycleActionNotExecutable
    );

    early_action.closed_at = Some(at(120));
    let closed_error = reduce_command(
        &config(),
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(250),
            pending_action: early_action,
        }),
        &LoadedState::default(),
    )
    .expect_err("closed subject deletion action cannot execute");
    assert_eq!(
        closed_error,
        Error::PendingSubjectLifecycleActionNotExecutable
    );

    let expired_error = reduce_command(
        &config(),
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(300),
            pending_action: pending_subject_action(id("pending-subject-deletion")),
        }),
        &LoadedState::default(),
    )
    .expect_err("expired subject deletion action cannot execute");
    assert_eq!(
        expired_error,
        Error::PendingSubjectLifecycleActionNotExecutable
    );
}

#[test]
fn subject_auth_state_deletion_cancellation_closes_open_action_and_schedules_notice() {
    let pending_action_id: PendingSubjectLifecycleActionId = id("pending-subject-deletion");

    let transition = reduce_command(
        &config(),
        Command::CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion {
            now: at(150),
            pending_action: pending_subject_action(pending_action_id.clone()),
        }),
        &LoadedState::default(),
    )
    .expect("subject deletion cancellation transition");

    assert_eq!(
        transition.outcome,
        Outcome::PendingSubjectAuthStateDeletionCancelled(
            PendingSubjectAuthStateDeletionCancellationOutcome {
                subject_id: id("subject"),
                pending_action_id: pending_action_id.clone(),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["pending_subject_lifecycle_action_still_cancellable_for_subject"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id,
            closed_at: at(150),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::SubjectAuthStateDeletionPendingActionCancelled,
            at(150),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::SubjectAuthStateDeletionPendingActionCancelled
        )]
    );
}

#[test]
fn subject_auth_state_deletion_cancellation_rejects_closed_or_expired_action() {
    let mut closed_action = pending_subject_action(id("pending-subject-deletion"));
    closed_action.closed_at = Some(at(120));

    let closed_error = reduce_command(
        &config(),
        Command::CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion {
            now: at(150),
            pending_action: closed_action,
        }),
        &LoadedState::default(),
    )
    .expect_err("closed subject deletion action cannot cancel");
    assert_eq!(
        closed_error,
        Error::PendingSubjectLifecycleActionNotCancellable
    );

    let expired_error = reduce_command(
        &config(),
        Command::CancelPendingSubjectAuthStateDeletion(CancelPendingSubjectAuthStateDeletion {
            now: at(300),
            pending_action: pending_subject_action(id("pending-subject-deletion")),
        }),
        &LoadedState::default(),
    )
    .expect_err("expired subject deletion action cannot cancel");
    assert_eq!(
        expired_error,
        Error::PendingSubjectLifecycleActionNotCancellable
    );
}

fn credential_reset_context<const AUTHORITY_COUNT: usize, const EVIDENCE_COUNT: usize>(
    target_credential_id: VerifiedProofSourceId,
    authorities: [CredentialRecoveryAuthority; AUTHORITY_COUNT],
    evidence: [LifecycleAuthorityEvidence; EVIDENCE_COUNT],
) -> CredentialLifecycleActionContext {
    CredentialLifecycleActionContext::new(
        CredentialInstanceMetadata::new(
            target_credential_id,
            id("subject"),
            CredentialInstanceKind::MessageSignatureVerifier,
            "password_signature",
            CredentialLifecycleState::Active,
        )
        .expect("target credential metadata"),
        CredentialRecoveryAuthorityGraph::new(authorities).expect("authority graph"),
        evidence,
    )
}

fn target_credential_metadata(
    target_credential_id: VerifiedProofSourceId,
) -> CredentialInstanceMetadata {
    CredentialInstanceMetadata::new(
        target_credential_id,
        id("subject"),
        CredentialInstanceKind::MessageSignatureVerifier,
        "password_signature",
        CredentialLifecycleState::Active,
    )
    .expect("target credential metadata")
}

fn recovery_code_credential_metadata(
    target_credential_id: VerifiedProofSourceId,
) -> CredentialInstanceMetadata {
    CredentialInstanceMetadata::new(
        target_credential_id,
        id("subject"),
        CredentialInstanceKind::RecoveryCodeCredential,
        "recovery_code",
        CredentialLifecycleState::Active,
    )
    .expect("target credential metadata")
}

fn pending_action(
    pending_action_id: PendingCredentialLifecycleActionId,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
) -> PendingCredentialLifecycleActionRecord {
    PendingCredentialLifecycleActionRecord::new_open(
        pending_action_id,
        id("subject"),
        target_credential_instance_id,
        action,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending action")
}

fn pending_subject_action(
    pending_action_id: PendingSubjectLifecycleActionId,
) -> PendingSubjectLifecycleActionRecord {
    PendingSubjectLifecycleActionRecord::new_open(
        pending_action_id,
        id("subject"),
        SubjectLifecycleAction::DeleteSubjectAuthState,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending subject action")
}

fn audit(kind: AuditEventKind, occurred_at: UnixSeconds) -> AuditEvent {
    AuditEvent {
        kind,
        subject_id: Some(id("subject")),
        session_id: None,
        device_credential_id: None,
        attempt_id: None,
        challenge_id: None,
        weak_proof_gate: None,
        occurred_at,
    }
}

fn security_notice(kind: SecurityNotificationKind) -> DurableEffectCommand {
    DurableEffectCommand::NotifySecurityEvent(SecurityNotificationCommand {
        kind,
        subject_id: id("subject"),
    })
}

fn credential_instance_evidence<const N: usize>(
    source_id: &str,
    authority_ids: [RecoveryAuthorityId; N],
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
