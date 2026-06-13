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
fn unauthenticated_credential_reset_scheduling_closes_recovery_attempt_in_same_plan() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-recovery-reset");
    let recovery_attempt = active_attempt(ProofUse::RecoverOrReplaceCredential);

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
            active_proof_attempt_to_close: Some(recovery_attempt.clone()),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("credential reset recovery transition");

    assert!(
        plan_has_active_proof_attempt_guard(&transition.commit_plan, &recovery_attempt.attempt_id),
        "recovery reset scheduling must guard the active-proof attempt it consumes"
    );
    assert!(
        transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(
                mutation,
                Mutation::DeleteActiveProofAttempt { attempt_id }
                    if attempt_id == &recovery_attempt.attempt_id
            )),
        "recovery reset scheduling must close the recovery attempt atomically with the delayed reset schedule"
    );
    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id,
            pending_action_id,
            earliest_execute_at: at(200),
            expires_at: at(300),
        })
    );
}

#[test]
fn unauthenticated_credential_reset_scheduling_rejects_immediate_recovery_policy_without_consuming_attempt()
 {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let recovery_attempt = active_attempt(ProofUse::RecoverOrReplaceCredential);

    let error = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_reset_context(
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
                ],
            ),
            active_proof_attempt_to_close: Some(recovery_attempt),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-reset"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect_err("immediate recovery reset requires execution with method work");

    assert_eq!(
        error,
        Error::UnauthenticatedCredentialRecoveryResetSchedulingRequiresDelayedAction
    );
}

#[test]
fn unauthenticated_credential_reset_scheduling_rejects_non_recovery_attempt() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let error = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_reset_context(
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
                ],
            ),
            active_proof_attempt_to_close: Some(active_attempt(
                ProofUse::ContributeToFullAuthentication,
            )),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-reset"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect_err("credential reset scheduling cannot consume a non-recovery attempt");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "credential reset scheduling can consume only recover-or-replace active proofs",
        )
    );
}

#[test]
fn unauthenticated_credential_reset_scheduling_rejects_attempt_for_different_subject() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let mut mismatched_attempt = active_attempt(ProofUse::RecoverOrReplaceCredential);
    mismatched_attempt.subject_id = Some(id("different-subject"));

    let error = reduce_command(
        &config(),
        Command::PlanCredentialReset(PlanCredentialReset {
            now: at(100),
            lifecycle_context: credential_reset_context(
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
                ],
            ),
            active_proof_attempt_to_close: Some(mismatched_attempt),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-reset"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect_err("credential reset scheduling cannot consume another subject's recovery attempt");

    assert_eq!(
        error,
        Error::LoadedStateContradiction(
            "active-proof attempt subject differs from required subject",
        )
    );
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
fn immediate_credential_replacement_records_authorization_notice_without_subject_revocation() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialReplacement(PlanCredentialReplacement {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                    device_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect("credential replacement planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialReplacementPlanned(CredentialReplacementOutcome::AuthorizedImmediate {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
        },)
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["credential_instance_still_active"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target_credential_id,
            action: CredentialLifecycleAction::Replace,
            authorized_at: at(100),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialReplacementAuthorized,
            at(100)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialReplacementAuthorized
        )]
    );
    assert!(
        !transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(mutation, Mutation::RaiseSubjectAuthRevocationCutoff { .. })),
        "replacement planning must not revoke sessions before replacement executes"
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn delayed_credential_replacement_creates_pending_action_notice_and_uniqueness_guard() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-replacement");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialReplacement(PlanCredentialReplacement {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("primary-email", [email_authority])
                        .expect("email evidence"),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("credential replacement planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialReplacementPlanned(CredentialReplacementOutcome::PendingActionCreated {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            pending_action_id: pending_action_id.clone(),
            earliest_execute_at: at(200),
            expires_at: at(300),
        },)
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
                CredentialLifecycleAction::Replace,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialReplacementPendingActionScheduled,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialReplacementPendingActionScheduled
        )]
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn delayed_credential_replacement_requires_runtime_generated_pending_action_id_and_valid_schedule()
{
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Replace,
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
        Command::PlanCredentialReplacement(PlanCredentialReplacement {
            now: at(100),
            lifecycle_context: lifecycle_context.clone(),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed replacement requires a runtime-owned pending action id");
    assert_eq!(
        missing_schedule_error,
        Error::MissingFreshValue("pending credential lifecycle action id")
    );

    let invalid_schedule_error = reduce_command(
        &config(),
        Command::PlanCredentialReplacement(PlanCredentialReplacement {
            now: at(100),
            lifecycle_context,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-replacement"),
                earliest_execute_at: at(100),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed replacement requires future execution time");
    assert_eq!(
        invalid_schedule_error,
        Error::InvalidCredentialLifecyclePendingActionTiming
    );
}

#[test]
fn immediate_credential_replacement_execution_supersedes_target_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let replacement_authority = CredentialRecoveryAuthority::new(
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let successor_authority: RecoveryAuthorityId = id("replacement-password-authority");
    let successor = replacement_successor_inheriting_target_policy(
        "replacement-password-credential",
        &target_credential,
        [replacement_authority.clone()],
        [successor_authority.clone()],
    );
    let method_work = password_reset_method_commit_work(b"replacement-password-verifier");
    let transition = reduce_command(
        &config(),
        Command::ExecuteCredentialReplacement(ExecuteCredentialReplacement {
            now: at(250),
            execution_authority: CredentialReplacementExecutionAuthority {
                lifecycle_context: credential_lifecycle_context(
                    target_credential.clone(),
                    [replacement_authority],
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
            successor: successor.clone(),
            method_commit_work: vec![method_work.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("credential replacement execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "subject_retains_required_credential_posture_after_replacement",
            "credential_instance_still_active",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::CreateCredentialInstanceMetadata {
                metadata: successor.metadata().clone(),
                created_at: at(250),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: successor.recovery_authorities()[0].clone(),
                created_at: at(250),
            },
            Mutation::CreateLifecycleAuthoritySource {
                source: LifecycleAuthoritySource::VerifiedProofSource(
                    successor.metadata().verified_proof_source(),
                ),
                authority_id: successor_authority,
                created_at: at(250),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
                executed_at: at(250),
            },
            Mutation::SetCredentialLifecycleState {
                credential_instance_id: target_credential_id.clone(),
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
fn immediate_credential_replacement_execution_rejects_missing_or_mismatched_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let replacement_authority = CredentialRecoveryAuthority::new(
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        device_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let successor = replacement_successor_inheriting_target_policy(
        "replacement-password-credential",
        &target_credential,
        [replacement_authority.clone()],
        [id("replacement-password-authority")],
    );
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [replacement_authority],
        [
            credential_instance_evidence("trusted-device", [device_authority])
                .expect("trusted-device evidence"),
        ],
    );

    let missing_error = reduce_command(
        &config(),
        Command::ExecuteCredentialReplacement(ExecuteCredentialReplacement {
            now: at(250),
            execution_authority: CredentialReplacementExecutionAuthority {
                lifecycle_context: lifecycle_context.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            successor: successor.clone(),
            method_commit_work: Vec::new(),
        }),
        &LoadedState::default(),
    )
    .expect_err("replacement execution requires method-owned verifier mutation work");
    assert_eq!(
        missing_error,
        Error::CredentialLifecycleExecutionMissingMethodCommitWork
    );

    let mismatch_error = reduce_command(
        &config(),
        Command::ExecuteCredentialReplacement(ExecuteCredentialReplacement {
            now: at(250),
            execution_authority: CredentialReplacementExecutionAuthority {
                lifecycle_context,
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            successor,
            method_commit_work: vec![recovery_code_method_commit_work()],
        }),
        &LoadedState::default(),
    )
    .expect_err("replacement method work must match the target credential family and method");
    assert_eq!(
        mismatch_error,
        Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch
    );
}

#[test]
fn immediate_credential_removal_records_authorization_notice_without_subject_revocation() {
    let target_credential_id: VerifiedProofSourceId = id("totp-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialRemoval(PlanCredentialRemoval {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                    device_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect("credential removal planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::AuthorizedImmediate {
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
        vec![Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target_credential_id,
            action: CredentialLifecycleAction::Remove,
            authorized_at: at(100),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(AuditEventKind::CredentialRemovalAuthorized, at(100))]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialRemovalAuthorized
        )]
    );
    assert!(
        !transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(mutation, Mutation::RaiseSubjectAuthRevocationCutoff { .. })),
        "removal planning must not revoke sessions before removal executes"
    );
}

#[test]
fn delayed_credential_removal_creates_pending_action_notice_and_uniqueness_guard() {
    let target_credential_id: VerifiedProofSourceId = id("totp-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-removal");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialRemoval(PlanCredentialRemoval {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Remove,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("primary-email", [email_authority])
                        .expect("email evidence"),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("credential removal planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::PendingActionCreated {
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
                CredentialLifecycleAction::Remove,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialRemovalPendingActionScheduled,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialRemovalPendingActionScheduled
        )]
    );
}

#[test]
fn delayed_credential_removal_requires_runtime_generated_pending_action_id_and_valid_schedule() {
    let target_credential_id: VerifiedProofSourceId = id("totp-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Remove,
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
        Command::PlanCredentialRemoval(PlanCredentialRemoval {
            now: at(100),
            lifecycle_context: lifecycle_context.clone(),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed removal requires a runtime-owned pending action id");
    assert_eq!(
        missing_schedule_error,
        Error::MissingFreshValue("pending credential lifecycle action id")
    );

    let invalid_schedule_error = reduce_command(
        &config(),
        Command::PlanCredentialRemoval(PlanCredentialRemoval {
            now: at(100),
            lifecycle_context,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-removal"),
                earliest_execute_at: at(100),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed removal requires future execution time");
    assert_eq!(
        invalid_schedule_error,
        Error::InvalidCredentialLifecyclePendingActionTiming
    );
}

#[test]
fn immediate_credential_regeneration_records_authorization_notice_without_subject_revocation() {
    let target_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialRegeneration(PlanCredentialRegeneration {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Regenerate,
                    device_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect("credential regeneration planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRegenerationPlanned(
            CredentialRegenerationOutcome::AuthorizedImmediate {
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["credential_instance_still_active"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target_credential_id,
            action: CredentialLifecycleAction::Regenerate,
            authorized_at: at(100),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialRegenerationAuthorized,
            at(100)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialRegenerationAuthorized
        )]
    );
    assert!(
        !transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(mutation, Mutation::RaiseSubjectAuthRevocationCutoff { .. })),
        "regeneration planning must not revoke sessions before regeneration executes"
    );
}

#[test]
fn delayed_credential_regeneration_creates_pending_action_notice_and_uniqueness_guard() {
    let target_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-regeneration");
    let transition = reduce_command(
        &config(),
        Command::PlanCredentialRegeneration(PlanCredentialRegeneration {
            now: at(100),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Regenerate,
                    email_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("primary-email", [email_authority])
                        .expect("email evidence"),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("credential regeneration planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRegenerationPlanned(
            CredentialRegenerationOutcome::PendingActionCreated {
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            },
        )
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
                CredentialLifecycleAction::Regenerate,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::CredentialRegenerationPendingActionScheduled,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::CredentialRegenerationPendingActionScheduled
        )]
    );
}

#[test]
fn delayed_credential_regeneration_requires_runtime_generated_pending_action_id_and_valid_schedule()
{
    let target_credential_id: VerifiedProofSourceId = id("recovery-code-set");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Regenerate,
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
        Command::PlanCredentialRegeneration(PlanCredentialRegeneration {
            now: at(100),
            lifecycle_context: lifecycle_context.clone(),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed regeneration requires a runtime-owned pending action id");
    assert_eq!(
        missing_schedule_error,
        Error::MissingFreshValue("pending credential lifecycle action id")
    );

    let invalid_schedule_error = reduce_command(
        &config(),
        Command::PlanCredentialRegeneration(PlanCredentialRegeneration {
            now: at(100),
            lifecycle_context,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            pending_action: Some(PendingCredentialLifecycleActionSchedule {
                pending_action_id: id("pending-regeneration"),
                earliest_execute_at: at(100),
                expires_at: at(300),
            }),
        }),
        &LoadedState::default(),
    )
    .expect_err("delayed regeneration requires future execution time");
    assert_eq!(
        invalid_schedule_error,
        Error::InvalidCredentialLifecyclePendingActionTiming
    );
}

#[test]
fn immediate_credential_removal_execution_revokes_target_with_last_active_guard() {
    let target_credential_id: VerifiedProofSourceId = id("totp-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let transition = reduce_command(
        &config(),
        Command::ExecuteCredentialRemoval(ExecuteCredentialRemoval {
            now: at(250),
            execution_authority: CredentialRemovalExecutionAuthority {
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Remove,
                        device_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [
                        credential_instance_evidence("trusted-device", [device_authority])
                            .expect("trusted-device evidence"),
                    ],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
        }),
        &LoadedState::default(),
    )
    .expect("credential removal execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRemovalExecuted(CredentialRemovalExecutionOutcome {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "subject_retains_required_credential_posture_after_removal",
            "credential_instance_still_active",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
                executed_at: at(250),
            },
            Mutation::SetCredentialLifecycleState {
                credential_instance_id: target_credential_id.clone(),
                lifecycle_state: CredentialLifecycleState::Revoked,
                updated_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
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
fn immediate_credential_rotation_execution_preserves_target_state_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let method_work = password_reset_method_commit_work(b"rotated-password-verifier");
    let transition = reduce_command(
        &config(),
        Command::ExecuteCredentialRotation(ExecuteCredentialRotation {
            now: at(250),
            execution_authority: CredentialRotationExecutionAuthority {
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Rotate,
                        device_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [
                        credential_instance_evidence("trusted-device", [device_authority])
                            .expect("trusted-device evidence"),
                    ],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: vec![method_work.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("credential rotation execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRotated(CredentialRotationExecutionOutcome {
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
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Rotate,
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
        vec![audit(AuditEventKind::CredentialRotated, at(250))]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(SecurityNotificationKind::CredentialRotated)]
    );
}

#[test]
fn immediate_credential_rotation_execution_rejects_missing_or_mismatched_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let lifecycle_context = credential_reset_context(
        target_credential_id.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Rotate,
            device_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        [
            credential_instance_evidence("trusted-device", [device_authority])
                .expect("trusted-device evidence"),
        ],
    );

    let missing_error = reduce_command(
        &config(),
        Command::ExecuteCredentialRotation(ExecuteCredentialRotation {
            now: at(250),
            execution_authority: CredentialRotationExecutionAuthority {
                lifecycle_context: lifecycle_context.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: Vec::new(),
        }),
        &LoadedState::default(),
    )
    .expect_err("rotation execution requires method-owned verifier mutation work");
    assert_eq!(
        missing_error,
        Error::CredentialLifecycleExecutionMissingMethodCommitWork
    );

    let mismatch_error = reduce_command(
        &config(),
        Command::ExecuteCredentialRotation(ExecuteCredentialRotation {
            now: at(250),
            execution_authority: CredentialRotationExecutionAuthority {
                lifecycle_context,
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: vec![recovery_code_method_commit_work()],
        }),
        &LoadedState::default(),
    )
    .expect_err("rotation method work must match the target credential family and method");
    assert_eq!(
        mismatch_error,
        Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch
    );
}

#[test]
fn admin_support_intervention_authorizes_immediate_credential_lifecycle_action() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let support_authority: RecoveryAuthorityId = id("support-authority");
    let intervention = admin_support_intervention(
        "support-intervention",
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        at(90),
        at(150),
    );
    let transition = reduce_command(
        &config(),
        Command::PlanAdminSupportCredentialLifecycleIntervention(
            PlanAdminSupportCredentialLifecycleIntervention {
                now: at(100),
                intervention: intervention.clone(),
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Replace,
                        support_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [LifecycleAuthorityEvidence::admin_support_intervention(
                        intervention.clone(),
                        [support_authority],
                    )
                    .expect("support evidence")],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action: None,
            },
        ),
        &LoadedState::default(),
    )
    .expect("support intervention transition");

    assert_eq!(
        transition.outcome,
        Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::AuthorizedImmediate {
                intervention_id: intervention.intervention_id().clone(),
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["credential_instance_still_active"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::RecordCredentialLifecycleActionAuthorized {
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Replace,
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
        vec![audit(
            AuditEventKind::AdminSupportCredentialLifecycleInterventionAuthorized,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionAuthorized,
        )]
    );
}

#[test]
fn admin_support_intervention_schedules_delayed_credential_lifecycle_action() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let support_authority: RecoveryAuthorityId = id("support-authority");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-support-action");
    let intervention = admin_support_intervention(
        "support-intervention",
        target_credential_id.clone(),
        CredentialLifecycleAction::Remove,
        at(90),
        at(150),
    );
    let transition = reduce_command(
        &config(),
        Command::PlanAdminSupportCredentialLifecycleIntervention(
            PlanAdminSupportCredentialLifecycleIntervention {
                now: at(100),
                intervention: intervention.clone(),
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Remove,
                        support_authority.clone(),
                        RecoveryAuthorityTiming::Delayed,
                    )],
                    [LifecycleAuthorityEvidence::admin_support_intervention(
                        intervention.clone(),
                        [support_authority],
                    )
                    .expect("support evidence")],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action: Some(PendingCredentialLifecycleActionSchedule {
                    pending_action_id: pending_action_id.clone(),
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                }),
            },
        ),
        &LoadedState::default(),
    )
    .expect("support intervention transition");

    assert_eq!(
        transition.outcome,
        Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::PendingActionCreated {
                intervention_id: intervention.intervention_id().clone(),
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Remove,
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(200),
                expires_at: at(300),
            },
        )
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
                CredentialLifecycleAction::Remove,
                at(100),
                at(200),
                at(300),
            )
            .expect("pending action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::AdminSupportCredentialLifecycleInterventionPendingActionScheduled,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionPendingActionScheduled,
        )]
    );
}

#[test]
fn admin_support_intervention_planning_rejects_missing_or_expired_verified_intervention() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let support_authority: RecoveryAuthorityId = id("support-authority");
    let intervention = admin_support_intervention(
        "support-intervention",
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        at(90),
        at(150),
    );

    let missing_evidence_error = reduce_command(
        &config(),
        Command::PlanAdminSupportCredentialLifecycleIntervention(
            PlanAdminSupportCredentialLifecycleIntervention {
                now: at(100),
                intervention: intervention.clone(),
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Replace,
                        support_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action: None,
            },
        ),
        &LoadedState::default(),
    )
    .expect_err("support intervention must be present in lifecycle evidence");
    assert_eq!(
        missing_evidence_error,
        Error::CredentialLifecycleActionNotAuthorized
    );

    let expired_intervention = admin_support_intervention(
        "support-intervention",
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        at(90),
        at(100),
    );
    let expired_error = reduce_command(
        &config(),
        Command::PlanAdminSupportCredentialLifecycleIntervention(
            PlanAdminSupportCredentialLifecycleIntervention {
                now: at(100),
                intervention: expired_intervention.clone(),
                lifecycle_context: credential_reset_context(
                    target_credential_id.clone(),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id,
                        CredentialLifecycleAction::Replace,
                        support_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [LifecycleAuthorityEvidence::admin_support_intervention(
                        expired_intervention,
                        [support_authority],
                    )
                    .expect("support evidence")],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
                pending_action: None,
            },
        ),
        &LoadedState::default(),
    )
    .expect_err("expired support intervention must not authorize lifecycle work");
    assert_eq!(expired_error, Error::CredentialLifecycleActionNotAuthorized);
}

#[test]
fn admin_support_intervention_request_creates_scoped_candidate_notice_and_uniqueness_guard() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let transition = reduce_command(
        &config(),
        Command::RequestAdminSupportIntervention(RequestAdminSupportIntervention {
            now: at(100),
            intervention_id: id("support-intervention"),
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            action: CredentialLifecycleAction::Replace,
            expires_at: at(180),
        }),
        &LoadedState::default(),
    )
    .expect("support intervention request transition");

    assert_eq!(
        transition.outcome,
        Outcome::AdminSupportInterventionRequested(AdminSupportInterventionRequestOutcome {
            intervention_id: id("support-intervention"),
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            action: CredentialLifecycleAction::Replace,
            expires_at: at(180),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "credential_instance_still_active",
            "no_open_admin_support_intervention_for_target",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::CreateAdminSupportIntervention(
            admin_support_intervention_record(
                "support-intervention",
                target_credential_id,
                CredentialLifecycleAction::Replace,
                at(100),
                at(180),
            )
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::AdminSupportInterventionRequested,
            at(100)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::AdminSupportInterventionRequested,
        )]
    );
}

#[test]
fn admin_support_intervention_approval_closes_candidate_and_enters_lifecycle_policy() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let support_authority: RecoveryAuthorityId = id("support-authority");
    let intervention_record = admin_support_intervention_record(
        "support-intervention",
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        at(90),
        at(180),
    );
    let verified_intervention = intervention_record
        .verified_at(at(100))
        .expect("verified intervention");
    let transition = reduce_command(
        &config(),
        Command::ApproveAdminSupportIntervention(ApproveAdminSupportIntervention {
            now: at(100),
            intervention: intervention_record.clone(),
            lifecycle_context: credential_reset_context(
                target_credential_id.clone(),
                [CredentialRecoveryAuthority::new(
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                    support_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [LifecycleAuthorityEvidence::admin_support_intervention(
                    verified_intervention.clone(),
                    [support_authority],
                )
                .expect("support evidence")],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            pending_action: None,
        }),
        &LoadedState::default(),
    )
    .expect("support intervention approval transition");

    assert_eq!(
        transition.outcome,
        Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::AuthorizedImmediate {
                intervention_id: verified_intervention.intervention_id().clone(),
                subject_id: id("subject"),
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Replace,
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "admin_support_intervention_still_open",
            "credential_instance_still_active",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::CloseAdminSupportIntervention {
                intervention_id: id("support-intervention"),
                status: AdminSupportInterventionStatus::Approved,
                closed_at: at(100),
            },
            Mutation::RecordCredentialLifecycleActionAuthorized {
                target_credential_instance_id: target_credential_id,
                action: CredentialLifecycleAction::Replace,
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
        vec![
            audit(AuditEventKind::AdminSupportInterventionApproved, at(100)),
            audit(
                AuditEventKind::AdminSupportCredentialLifecycleInterventionAuthorized,
                at(100),
            ),
        ]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![
            security_notice(SecurityNotificationKind::AdminSupportInterventionApproved),
            security_notice(
                SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionAuthorized,
            ),
        ]
    );
}

#[test]
fn admin_support_intervention_denial_closes_candidate_without_credential_mutation() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let transition = reduce_command(
        &config(),
        Command::DenyAdminSupportIntervention(DenyAdminSupportIntervention {
            now: at(100),
            intervention: admin_support_intervention_record(
                "support-intervention",
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                at(90),
                at(180),
            ),
        }),
        &LoadedState::default(),
    )
    .expect("support intervention denial transition");

    assert_eq!(
        transition.outcome,
        Outcome::AdminSupportInterventionDenied(AdminSupportInterventionClosureOutcome {
            intervention_id: id("support-intervention"),
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id,
            action: CredentialLifecycleAction::Remove,
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["admin_support_intervention_still_open"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::CloseAdminSupportIntervention {
            intervention_id: id("support-intervention"),
            status: AdminSupportInterventionStatus::Denied,
            closed_at: at(100),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::AdminSupportInterventionDenied,
            at(100)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::AdminSupportInterventionDenied,
        )]
    );
}

#[test]
fn admin_support_intervention_expiry_closes_only_expired_open_candidate() {
    let target_credential_id: VerifiedProofSourceId = id("support-target");
    let transition = reduce_command(
        &config(),
        Command::ExpireAdminSupportIntervention(ExpireAdminSupportIntervention {
            now: at(200),
            intervention: admin_support_intervention_record(
                "support-intervention",
                target_credential_id.clone(),
                CredentialLifecycleAction::Remove,
                at(90),
                at(180),
            ),
        }),
        &LoadedState::default(),
    )
    .expect("support intervention expiry transition");

    assert_eq!(
        transition.outcome,
        Outcome::AdminSupportInterventionExpired(AdminSupportInterventionClosureOutcome {
            intervention_id: id("support-intervention"),
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id.clone(),
            action: CredentialLifecycleAction::Remove,
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec!["admin_support_intervention_still_expired_open"]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::CloseAdminSupportIntervention {
            intervention_id: id("support-intervention"),
            status: AdminSupportInterventionStatus::Expired,
            closed_at: at(200),
        }]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::AdminSupportInterventionExpired,
            at(200)
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::AdminSupportInterventionExpired,
        )]
    );

    let too_early_error = reduce_command(
        &config(),
        Command::ExpireAdminSupportIntervention(ExpireAdminSupportIntervention {
            now: at(100),
            intervention: admin_support_intervention_record(
                "support-intervention",
                target_credential_id,
                CredentialLifecycleAction::Remove,
                at(90),
                at(180),
            ),
        }),
        &LoadedState::default(),
    )
    .expect_err("unexpired support intervention cannot expire");
    assert_eq!(too_early_error, Error::AdminSupportInterventionNotExpirable);
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
        }),
        &LoadedState::default(),
    )
    .expect_err("unknown lifecycle authority must not authorize reset");

    assert_eq!(error, Error::CredentialLifecycleActionNotAuthorized);
}

#[test]
fn add_credential_creates_metadata_authorities_notice_and_subject_revocation() {
    let new_credential = message_signature_credential_metadata("new-password-credential");
    let new_credential_id = new_credential.credential_instance_id().clone();
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let new_password_authority: RecoveryAuthorityId = id("new-password-authority");
    let create_authority = CredentialRecoveryAuthority::new(
        new_credential_id.clone(),
        CredentialLifecycleAction::Create,
        email_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    let reset_authority = CredentialRecoveryAuthority::new(
        new_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        email_authority.clone(),
        RecoveryAuthorityTiming::Delayed,
    );
    let remove_authority = CredentialRecoveryAuthority::new(
        new_credential_id.clone(),
        CredentialLifecycleAction::Remove,
        new_password_authority.clone(),
        RecoveryAuthorityTiming::Immediate,
    );
    let method_work = password_creation_method_commit_work(b"new-password-verifier");

    let transition = reduce_command(
        &config(),
        Command::AddCredential(AddCredential {
            now: at(100),
            lifecycle_context: credential_lifecycle_context(
                new_credential.clone(),
                [
                    create_authority.clone(),
                    reset_authority.clone(),
                    remove_authority.clone(),
                ],
                [
                    out_of_band_identifier_lifecycle_evidence("primary-email", [email_authority]),
                    credential_instance_lifecycle_evidence("trusted-device", [device_authority]),
                ],
            ),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::Required,
            new_credential_authority_ids: vec![new_password_authority.clone()],
            method_commit_work: vec![method_work.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("credential addition transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialAdded(CredentialAdditionOutcome {
            subject_id: id("subject"),
            credential_instance_id: new_credential_id.clone(),
        })
    );
    assert_eq!(
        transition.commit_plan.preconditions,
        vec![
            Precondition::SubjectRetainsRequiredCredentialPostureAfterAddition {
                subject_id: id("subject"),
                added_credential: new_credential.clone(),
                added_recovery_authorities: vec![
                    create_authority.clone(),
                    reset_authority.clone(),
                    remove_authority.clone(),
                ],
            },
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::CreateCredentialInstanceMetadata {
                metadata: new_credential.clone(),
                created_at: at(100),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: create_authority,
                created_at: at(100),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: reset_authority,
                created_at: at(100),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: remove_authority,
                created_at: at(100),
            },
            Mutation::CreateLifecycleAuthoritySource {
                source: LifecycleAuthoritySource::VerifiedProofSource(
                    new_credential.verified_proof_source(),
                ),
                authority_id: new_password_authority,
                created_at: at(100),
            },
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: new_credential_id,
                action: CredentialLifecycleAction::Create,
                executed_at: at(100),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(100),
                reason: RevocationReason::SubjectAuthStateChanged,
            },
        ]
    );
    assert_eq!(transition.commit_plan.method_commit_work, vec![method_work]);
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(AuditEventKind::CredentialAdded, at(100))]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(SecurityNotificationKind::CredentialAdded)]
    );
    assert!(!transition.commit_plan.has_response_effects());
}

#[test]
fn add_credential_rejects_missing_or_mismatched_method_work() {
    let new_credential = message_signature_credential_metadata("new-password-credential");
    let new_credential_id = new_credential.credential_instance_id().clone();
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let context = credential_lifecycle_context(
        new_credential,
        [CredentialRecoveryAuthority::new(
            new_credential_id.clone(),
            CredentialLifecycleAction::Create,
            email_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        [out_of_band_identifier_lifecycle_evidence(
            "primary-email",
            [email_authority],
        )],
    );

    let missing_error = reduce_command(
        &config(),
        Command::AddCredential(AddCredential {
            now: at(100),
            lifecycle_context: context.clone(),
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            new_credential_authority_ids: vec![id("new-password-authority")],
            method_commit_work: Vec::new(),
        }),
        &LoadedState::default(),
    )
    .expect_err("credential addition must require method-owned creation work");
    assert_eq!(
        missing_error,
        Error::CredentialAdditionMissingMethodCommitWork
    );

    let mismatch_error = reduce_command(
        &config(),
        Command::AddCredential(AddCredential {
            now: at(100),
            lifecycle_context: context,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            new_credential_authority_ids: vec![id("new-password-authority")],
            method_commit_work: vec![recovery_code_method_commit_work()],
        }),
        &LoadedState::default(),
    )
    .expect_err("credential addition method work must match the credential being created");
    assert_eq!(
        mismatch_error,
        Error::CredentialAdditionMethodCommitWorkTargetMismatch
    );
}

#[test]
fn add_credential_rejects_wrong_authority_target_and_non_immediate_create_authority() {
    let new_credential = message_signature_credential_metadata("new-password-credential");
    let new_credential_id = new_credential.credential_instance_id().clone();
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let wrong_target_context = credential_lifecycle_context(
        new_credential.clone(),
        [
            CredentialRecoveryAuthority::new(
                new_credential_id.clone(),
                CredentialLifecycleAction::Create,
                email_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            ),
            CredentialRecoveryAuthority::new(
                id("other-credential"),
                CredentialLifecycleAction::Reset,
                email_authority.clone(),
                RecoveryAuthorityTiming::Delayed,
            ),
        ],
        [out_of_band_identifier_lifecycle_evidence(
            "primary-email",
            [email_authority.clone()],
        )],
    );

    let wrong_target_error = reduce_command(
        &config(),
        Command::AddCredential(AddCredential {
            now: at(100),
            lifecycle_context: wrong_target_context,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            new_credential_authority_ids: vec![id("new-password-authority")],
            method_commit_work: vec![password_creation_method_commit_work(
                b"new-password-verifier",
            )],
        }),
        &LoadedState::default(),
    )
    .expect_err("credential addition must not persist authorities for another target");
    assert_eq!(
        wrong_target_error,
        Error::CredentialAdditionRecoveryAuthorityTargetMismatch
    );

    let delayed_create_context = credential_lifecycle_context(
        new_credential,
        [CredentialRecoveryAuthority::new(
            new_credential_id,
            CredentialLifecycleAction::Create,
            email_authority.clone(),
            RecoveryAuthorityTiming::Delayed,
        )],
        [out_of_band_identifier_lifecycle_evidence(
            "primary-email",
            [email_authority],
        )],
    );

    let delayed_create_error = reduce_command(
        &config(),
        Command::AddCredential(AddCredential {
            now: at(100),
            lifecycle_context: delayed_create_context,
            independent_evidence_required:
                CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            new_credential_authority_ids: vec![id("new-password-authority")],
            method_commit_work: vec![password_creation_method_commit_work(
                b"new-password-verifier",
            )],
        }),
        &LoadedState::default(),
    )
    .expect_err("credential addition does not schedule delayed creation in this transition");
    assert_eq!(
        delayed_create_error,
        Error::CredentialLifecycleActionNotAuthorized
    );
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
            active_proof_attempt_to_close: None,
            method_commit_work: vec![method_work.clone()],
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
fn unauthenticated_immediate_credential_reset_execution_closes_recovery_attempt_in_same_plan() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let method_work = password_reset_method_commit_work(b"new-password-verifier");
    let recovery_attempt = active_attempt(ProofUse::RecoverOrReplaceCredential);
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
            active_proof_attempt_to_close: Some(recovery_attempt.clone()),
            method_commit_work: vec![method_work.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("unauthenticated recovery reset execution transition");

    assert!(
        plan_has_active_proof_attempt_guard(&transition.commit_plan, &recovery_attempt.attempt_id),
        "recovery reset execution must guard the active-proof attempt it consumes"
    );
    assert!(
        transition
            .commit_plan
            .mutations
            .iter()
            .any(|mutation| matches!(
                mutation,
                Mutation::DeleteActiveProofAttempt { attempt_id }
                    if attempt_id == &recovery_attempt.attempt_id
            )),
        "recovery reset execution must close the recovery attempt atomically with verifier mutation"
    );
    assert_eq!(
        transition.outcome,
        Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: id("subject"),
            target_credential_instance_id: target_credential_id,
            pending_action_id: None,
        })
    );
    assert_eq!(transition.commit_plan.method_commit_work, vec![method_work]);
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
            active_proof_attempt_to_close: None,
            method_commit_work: vec![method_work.clone()],
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
            active_proof_attempt_to_close: None,
            method_commit_work: vec![password_reset_method_commit_work(b"new-password-verifier")],
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
            active_proof_attempt_to_close: None,
            method_commit_work: vec![password_reset_method_commit_work(b"new-password-verifier")],
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
            active_proof_attempt_to_close: None,
            method_commit_work: Vec::new(),
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
            active_proof_attempt_to_close: None,
            method_commit_work: vec![recovery_code_method_commit_work()],
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
fn immediate_credential_regeneration_execution_preserves_target_state_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let method_work = password_reset_method_commit_work(b"regenerated-password-verifier");
    let transition = reduce_command(
        &config(),
        Command::ExecuteCredentialRegeneration(ExecuteCredentialRegeneration {
            now: at(250),
            execution_authority: CredentialRegenerationExecutionAuthority {
                lifecycle_context: credential_lifecycle_context(
                    target_credential_metadata(target_credential_id.clone()),
                    [CredentialRecoveryAuthority::new(
                        target_credential_id.clone(),
                        CredentialLifecycleAction::Regenerate,
                        device_authority.clone(),
                        RecoveryAuthorityTiming::Immediate,
                    )],
                    [
                        credential_instance_evidence("trusted-device", [device_authority])
                            .expect("trusted-device evidence"),
                    ],
                ),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: vec![method_work.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("credential regeneration execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::CredentialRegenerated(CredentialRegenerationExecutionOutcome {
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
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Regenerate,
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
fn immediate_credential_regeneration_execution_rejects_missing_or_mismatched_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let lifecycle_context = credential_lifecycle_context(
        target_credential_metadata(target_credential_id.clone()),
        [CredentialRecoveryAuthority::new(
            target_credential_id,
            CredentialLifecycleAction::Regenerate,
            device_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        [
            credential_instance_evidence("trusted-device", [device_authority])
                .expect("trusted-device evidence"),
        ],
    );

    let missing_error = reduce_command(
        &config(),
        Command::ExecuteCredentialRegeneration(ExecuteCredentialRegeneration {
            now: at(250),
            execution_authority: CredentialRegenerationExecutionAuthority {
                lifecycle_context: lifecycle_context.clone(),
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: Vec::new(),
        }),
        &LoadedState::default(),
    )
    .expect_err("regeneration execution requires method-owned work");
    assert_eq!(
        missing_error,
        Error::CredentialLifecycleExecutionMissingMethodCommitWork
    );

    let mismatch_error = reduce_command(
        &config(),
        Command::ExecuteCredentialRegeneration(ExecuteCredentialRegeneration {
            now: at(250),
            execution_authority: CredentialRegenerationExecutionAuthority {
                lifecycle_context,
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::NotRequired,
            },
            method_commit_work: vec![recovery_code_method_commit_work()],
        }),
        &LoadedState::default(),
    )
    .expect_err("regeneration method work must match the target credential family and method");
    assert_eq!(
        mismatch_error,
        Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch
    );
}

#[test]
fn pending_credential_replacement_execution_supersedes_target_and_applies_method_work() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let pending_action_id: PendingCredentialLifecycleActionId = id("pending-replacement");
    let target_credential = target_credential_metadata(target_credential_id.clone());
    let replacement_authority = CredentialRecoveryAuthority::new(
        target_credential_id.clone(),
        CredentialLifecycleAction::Replace,
        id("primary-email-authority"),
        RecoveryAuthorityTiming::Delayed,
    );
    let successor_authority: RecoveryAuthorityId = id("replacement-password-authority");
    let successor = replacement_successor_inheriting_target_policy(
        "replacement-password-credential",
        &target_credential,
        [replacement_authority],
        [successor_authority.clone()],
    );
    let method_work = password_reset_method_commit_work(b"replacement-password-verifier");

    let transition = reduce_command(
        &config(),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(
            ExecuteNonResetPendingCredentialLifecycleAction {
                now: at(250),
                target_credential,
                pending_action: pending_action(
                    pending_action_id.clone(),
                    target_credential_id.clone(),
                    CredentialLifecycleAction::Replace,
                ),
                replacement_successor: Some(successor.clone()),
                method_commit_work: vec![method_work.clone()],
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
            "subject_retains_required_credential_posture_after_replacement",
            "credential_instance_still_active",
            "pending_credential_lifecycle_action_still_executable",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::CreateCredentialInstanceMetadata {
                metadata: successor.metadata().clone(),
                created_at: at(250),
            },
            Mutation::CreateCredentialRecoveryAuthority {
                authority: successor.recovery_authorities()[0].clone(),
                created_at: at(250),
            },
            Mutation::CreateLifecycleAuthoritySource {
                source: LifecycleAuthoritySource::VerifiedProofSource(
                    successor.metadata().verified_proof_source(),
                ),
                authority_id: successor_authority,
                created_at: at(250),
            },
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
                replacement_successor: None,
                method_commit_work: Vec::new(),
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
        precondition_kind_names(&transition.commit_plan),
        vec![
            "subject_retains_required_credential_posture_after_removal",
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
                action: CredentialLifecycleAction::Remove,
                executed_at: at(250),
            },
            Mutation::SetCredentialLifecycleState {
                credential_instance_id: target_credential_id.clone(),
                lifecycle_state: CredentialLifecycleState::Revoked,
                updated_at: at(250),
            },
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: id("subject"),
                revoke_records_created_at_or_before: at(250),
                reason: RevocationReason::SubjectAuthStateChanged,
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
                replacement_successor: None,
                method_commit_work: vec![method_work.clone()],
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
                target_credential_instance_id: target_credential_id.clone(),
                action: CredentialLifecycleAction::Regenerate,
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
    let replacement_successor = replacement_successor_inheriting_target_policy(
        "replacement-password-credential",
        &target_credential,
        [CredentialRecoveryAuthority::new(
            target_credential_id.clone(),
            CredentialLifecycleAction::Replace,
            id("primary-email-authority"),
            RecoveryAuthorityTiming::Immediate,
        )],
        [id("replacement-password-authority")],
    );

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
                replacement_successor: None,
                method_commit_work: vec![password_reset_method_commit_work(b"verifier")],
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
                replacement_successor: Some(replacement_successor.clone()),
                method_commit_work: Vec::new(),
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
                replacement_successor: Some(replacement_successor),
                method_commit_work: vec![recovery_code_method_commit_work()],
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
                replacement_successor: None,
                method_commit_work: vec![password_reset_method_commit_work(b"cleanup")],
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
            application_subject_data_lifecycle_action: None,
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
fn mounted_subject_auth_state_deletion_can_commit_application_subject_data_lifecycle_effect() {
    let pending_action_id: PendingSubjectLifecycleActionId =
        id("pending-subject-deletion-with-app-data");

    let transition = reduce_command(
        &config(),
        Command::ExecutePendingSubjectAuthStateDeletion(ExecutePendingSubjectAuthStateDeletion {
            now: at(250),
            pending_action: pending_subject_action(pending_action_id),
            application_subject_data_lifecycle_action: Some(
                ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
            ),
        }),
        &LoadedState::default(),
    )
    .expect("subject deletion execution transition");

    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![
            security_notice(SecurityNotificationKind::SubjectAuthStateDeletionExecuted),
            DurableEffectCommand::ApplyApplicationSubjectDataLifecycle(
                ApplicationSubjectDataLifecycleCommand {
                    action: ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
                    subject_id: id("subject"),
                    requested_at: at(250),
                },
            ),
        ]
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
            application_subject_data_lifecycle_action: None,
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
            application_subject_data_lifecycle_action: None,
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
            application_subject_data_lifecycle_action: None,
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

#[test]
fn immediate_out_of_band_identifier_change_supersedes_current_and_activates_candidate() {
    let current_authority: RecoveryAuthorityId = id("current-email-authority");
    let candidate_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let current_source = out_of_band_identifier_source("current-email-source");
    let candidate_source = out_of_band_identifier_source("candidate-email-source");
    let transition = reduce_command(
        &config(),
        Command::ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange {
            now: at(100),
            change_context: out_of_band_identifier_change_context(
                current_source.clone(),
                candidate_source.clone(),
                [SubjectLifecycleAuthority::new(
                    id("subject"),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    current_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("current-email-source", [current_authority])
                        .expect("current email evidence"),
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement::Required,
            candidate_authority_ids: vec![candidate_authority.clone()],
        }),
        &LoadedState::default(),
    )
    .expect("identifier change transition");

    assert_eq!(
        transition.outcome,
        Outcome::OutOfBandIdentifierChanged(OutOfBandIdentifierChangeOutcome {
            subject_id: id("subject"),
            current_identifier_source_id: current_source.source_id().clone(),
            candidate_identifier_source_id: candidate_source.source_id().clone(),
        })
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "out_of_band_identifier_binding_still_active",
            "out_of_band_identifier_binding_still_pending_activation",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::SetOutOfBandIdentifierBindingLifecycleState {
                source_id: current_source.source_id().clone(),
                lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Superseded,
                updated_at: at(100),
            },
            Mutation::SetOutOfBandIdentifierBindingLifecycleState {
                source_id: candidate_source.source_id().clone(),
                lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Active,
                updated_at: at(100),
            },
            Mutation::DeleteLifecycleAuthoritySourcesForSource {
                source: LifecycleAuthoritySource::VerifiedProofSource(candidate_source.clone()),
            },
            Mutation::CreateLifecycleAuthoritySource {
                source: LifecycleAuthoritySource::VerifiedProofSource(candidate_source),
                authority_id: candidate_authority,
                created_at: at(100),
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
        vec![audit(AuditEventKind::OutOfBandIdentifierChanged, at(100))]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::OutOfBandIdentifierChanged
        )]
    );
}

#[test]
fn out_of_band_identifier_change_planning_authorizes_immediate_without_mutation() {
    let current_authority: RecoveryAuthorityId = id("current-email-authority");
    let candidate_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let current_source = out_of_band_identifier_source("current-email-source");
    let candidate_source = out_of_band_identifier_source("candidate-email-source");
    let transition = reduce_command(
        &config(),
        Command::PlanOutOfBandIdentifierChange(PlanOutOfBandIdentifierChange {
            now: at(100),
            change_context: out_of_band_identifier_change_context(
                current_source.clone(),
                candidate_source.clone(),
                [SubjectLifecycleAuthority::new(
                    id("subject"),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    current_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("current-email-source", [current_authority])
                        .expect("current email evidence"),
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement::Required,
            candidate_authority_ids: vec![candidate_authority],
            pending_action: Some(PendingSubjectLifecycleActionSchedule {
                pending_action_id: id("unused-pending-identifier-change"),
                earliest_execute_at: at(220),
                expires_at: at(320),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("identifier change planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::OutOfBandIdentifierChangePlanned(
            OutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate {
                subject_id: id("subject"),
                current_identifier_source_id: current_source.source_id().clone(),
                candidate_identifier_source_id: candidate_source.source_id().clone(),
            },
        )
    );
    assert_eq!(transition.commit_plan, CommitPlan::default());
}

#[test]
fn out_of_band_identifier_change_planning_creates_pending_subject_action() {
    let current_authority: RecoveryAuthorityId = id("current-email-authority");
    let candidate_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let current_source = out_of_band_identifier_source("current-email-source");
    let candidate_source = out_of_band_identifier_source("candidate-email-source");
    let pending_action_id = id("pending-identifier-change");
    let transition = reduce_command(
        &config(),
        Command::PlanOutOfBandIdentifierChange(PlanOutOfBandIdentifierChange {
            now: at(100),
            change_context: out_of_band_identifier_change_context(
                current_source.clone(),
                candidate_source.clone(),
                [SubjectLifecycleAuthority::new(
                    id("subject"),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    current_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("current-email-source", [current_authority])
                        .expect("current email evidence"),
                ],
            ),
            independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement::Required,
            candidate_authority_ids: vec![candidate_authority.clone()],
            pending_action: Some(PendingSubjectLifecycleActionSchedule {
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(220),
                expires_at: at(320),
            }),
        }),
        &LoadedState::default(),
    )
    .expect("delayed identifier change planning transition");

    assert_eq!(
        transition.outcome,
        Outcome::OutOfBandIdentifierChangePlanned(
            OutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
                subject_id: id("subject"),
                current_identifier_source_id: current_source.source_id().clone(),
                candidate_identifier_source_id: candidate_source.source_id().clone(),
                pending_action_id: pending_action_id.clone(),
                earliest_execute_at: at(220),
                expires_at: at(320),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "out_of_band_identifier_binding_still_active",
            "out_of_band_identifier_binding_still_pending_activation",
            "no_open_pending_subject_lifecycle_action_for_subject",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![Mutation::CreatePendingSubjectLifecycleAction(
            PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
                pending_action_id,
                id("subject"),
                current_source.source_id().clone(),
                candidate_source.source_id().clone(),
                vec![candidate_authority],
                at(100),
                at(220),
                at(320),
            )
            .expect("pending identifier change action"),
        )]
    );
    assert_eq!(
        transition.commit_plan.audit_events,
        vec![audit(
            AuditEventKind::OutOfBandIdentifierChangePendingActionScheduled,
            at(100),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::OutOfBandIdentifierChangePendingActionScheduled
        )]
    );
}

#[test]
fn immediate_out_of_band_identifier_change_rejects_when_only_delayed_authority_is_available() {
    let current_authority: RecoveryAuthorityId = id("current-email-authority");
    let error = reduce_command(
        &config(),
        Command::ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange {
            now: at(100),
            change_context: out_of_band_identifier_change_context(
                out_of_band_identifier_source("current-email-source"),
                out_of_band_identifier_source("candidate-email-source"),
                [SubjectLifecycleAuthority::new(
                    id("subject"),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    current_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("current-email-source", [current_authority])
                        .expect("current email evidence"),
                ],
            ),
            independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement::Required,
            candidate_authority_ids: vec![id("candidate-email-authority")],
        }),
        &LoadedState::default(),
    )
    .expect_err("current identifier alone must not immediately change identifier");

    assert_eq!(error, Error::CredentialLifecycleActionNotAuthorized);
}

#[test]
fn out_of_band_identifier_change_rejects_duplicate_candidate_authorities() {
    let current_authority: RecoveryAuthorityId = id("current-email-authority");
    let device_authority: RecoveryAuthorityId = id("trusted-device-authority");
    let candidate_authority: RecoveryAuthorityId = id("candidate-email-authority");
    let error = reduce_command(
        &config(),
        Command::ExecuteOutOfBandIdentifierChange(ExecuteOutOfBandIdentifierChange {
            now: at(100),
            change_context: out_of_band_identifier_change_context(
                out_of_band_identifier_source("current-email-source"),
                out_of_band_identifier_source("candidate-email-source"),
                [SubjectLifecycleAuthority::new(
                    id("subject"),
                    SubjectLifecycleAction::ChangeOutOfBandIdentifier,
                    current_authority.clone(),
                    RecoveryAuthorityTiming::Immediate,
                )],
                [
                    out_of_band_identifier_evidence("current-email-source", [current_authority])
                        .expect("current email evidence"),
                    credential_instance_evidence("trusted-device", [device_authority])
                        .expect("trusted-device evidence"),
                ],
            ),
            independent_evidence_required: SubjectLifecycleIndependentEvidenceRequirement::Required,
            candidate_authority_ids: vec![candidate_authority.clone(), candidate_authority],
        }),
        &LoadedState::default(),
    )
    .expect_err("duplicate candidate authorities must be rejected");

    assert_eq!(
        error,
        Error::InvalidConfig("identifier change candidate must not duplicate recovery authorities")
    );
}

#[test]
fn pending_out_of_band_identifier_change_execution_closes_action_and_changes_binding() {
    let pending_action_id: PendingSubjectLifecycleActionId = id("pending-identifier-change");
    let current_identifier_source_id = id("pending-identifier-change-current");
    let candidate_identifier_source_id = id("pending-identifier-change-candidate");
    let candidate_authority = id("pending-identifier-change-candidate-authority");

    let transition = reduce_command(
        &config(),
        Command::ExecutePendingOutOfBandIdentifierChange(ExecutePendingOutOfBandIdentifierChange {
            now: at(250),
            pending_action: pending_identifier_change_subject_action(
                pending_action_id.clone(),
                current_identifier_source_id.clone(),
                candidate_identifier_source_id.clone(),
                vec![candidate_authority.clone()],
            ),
        }),
        &LoadedState::default(),
    )
    .expect("pending identifier-change execution transition");

    assert_eq!(
        transition.outcome,
        Outcome::PendingOutOfBandIdentifierChangeExecuted(
            PendingOutOfBandIdentifierChangeExecutionOutcome {
                subject_id: id("subject"),
                pending_action_id: pending_action_id.clone(),
                current_identifier_source_id: current_identifier_source_id.clone(),
                candidate_identifier_source_id: candidate_identifier_source_id.clone(),
            },
        )
    );
    assert_eq!(
        precondition_kind_names(&transition.commit_plan),
        vec![
            "pending_subject_lifecycle_action_still_executable",
            "out_of_band_identifier_binding_still_active",
            "out_of_band_identifier_binding_still_pending_activation",
        ]
    );
    assert_eq!(
        transition.commit_plan.mutations,
        vec![
            Mutation::ClosePendingSubjectLifecycleAction {
                pending_action_id,
                closed_at: at(250),
            },
            Mutation::SetOutOfBandIdentifierBindingLifecycleState {
                source_id: current_identifier_source_id.clone(),
                lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Superseded,
                updated_at: at(250),
            },
            Mutation::SetOutOfBandIdentifierBindingLifecycleState {
                source_id: candidate_identifier_source_id.clone(),
                lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Active,
                updated_at: at(250),
            },
            Mutation::DeleteLifecycleAuthoritySourcesForSource {
                source: LifecycleAuthoritySource::VerifiedProofSource(VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    candidate_identifier_source_id.clone(),
                )),
            },
            Mutation::CreateLifecycleAuthoritySource {
                source: LifecycleAuthoritySource::VerifiedProofSource(VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    candidate_identifier_source_id,
                )),
                authority_id: candidate_authority,
                created_at: at(250),
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
        vec![audit(AuditEventKind::OutOfBandIdentifierChanged, at(250))]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::OutOfBandIdentifierChanged
        )]
    );
}

#[test]
fn pending_out_of_band_identifier_change_execution_rejects_unusable_action() {
    let early_error = reduce_command(
        &config(),
        Command::ExecutePendingOutOfBandIdentifierChange(ExecutePendingOutOfBandIdentifierChange {
            now: at(150),
            pending_action: pending_identifier_change_subject_action(
                id("early-pending-identifier-change"),
                id("early-pending-identifier-change-current"),
                id("early-pending-identifier-change-candidate"),
                vec![id("early-pending-identifier-change-authority")],
            ),
        }),
        &LoadedState::default(),
    )
    .expect_err("identifier change cannot execute before maturity");
    assert_eq!(
        early_error,
        Error::PendingSubjectLifecycleActionNotExecutable
    );

    let wrong_action_error = reduce_command(
        &config(),
        Command::ExecutePendingOutOfBandIdentifierChange(ExecutePendingOutOfBandIdentifierChange {
            now: at(250),
            pending_action: pending_subject_action(id("wrong-action-subject-action")),
        }),
        &LoadedState::default(),
    )
    .expect_err("subject deletion pending action cannot execute as identifier change");
    assert_eq!(
        wrong_action_error,
        Error::PendingSubjectLifecycleActionNotExecutable
    );
}

#[test]
fn pending_out_of_band_identifier_change_cancellation_closes_action_and_schedules_notice() {
    let pending_action_id: PendingSubjectLifecycleActionId = id("pending-identifier-change");
    let current_identifier_source_id = id("pending-identifier-change-current");
    let candidate_identifier_source_id = id("pending-identifier-change-candidate");

    let transition = reduce_command(
        &config(),
        Command::CancelPendingOutOfBandIdentifierChange(CancelPendingOutOfBandIdentifierChange {
            now: at(150),
            pending_action: pending_identifier_change_subject_action(
                pending_action_id.clone(),
                current_identifier_source_id.clone(),
                candidate_identifier_source_id.clone(),
                vec![id("pending-identifier-change-candidate-authority")],
            ),
        }),
        &LoadedState::default(),
    )
    .expect("pending identifier-change cancellation transition");

    assert_eq!(
        transition.outcome,
        Outcome::PendingOutOfBandIdentifierChangeCancelled(
            PendingOutOfBandIdentifierChangeCancellationOutcome {
                subject_id: id("subject"),
                pending_action_id: pending_action_id.clone(),
                current_identifier_source_id,
                candidate_identifier_source_id,
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
            AuditEventKind::OutOfBandIdentifierChangePendingActionCancelled,
            at(150),
        )]
    );
    assert_eq!(
        transition.commit_plan.durable_effects,
        vec![security_notice(
            SecurityNotificationKind::OutOfBandIdentifierChangePendingActionCancelled
        )]
    );
}

#[test]
fn pending_out_of_band_identifier_change_cancellation_rejects_closed_or_expired_action() {
    let mut closed_action = pending_identifier_change_subject_action(
        id("closed-pending-identifier-change"),
        id("closed-pending-identifier-change-current"),
        id("closed-pending-identifier-change-candidate"),
        vec![id("closed-pending-identifier-change-authority")],
    );
    closed_action.closed_at = Some(at(120));

    let closed_error = reduce_command(
        &config(),
        Command::CancelPendingOutOfBandIdentifierChange(CancelPendingOutOfBandIdentifierChange {
            now: at(150),
            pending_action: closed_action,
        }),
        &LoadedState::default(),
    )
    .expect_err("closed identifier-change action cannot cancel");
    assert_eq!(
        closed_error,
        Error::PendingSubjectLifecycleActionNotCancellable
    );

    let expired_error = reduce_command(
        &config(),
        Command::CancelPendingOutOfBandIdentifierChange(CancelPendingOutOfBandIdentifierChange {
            now: at(300),
            pending_action: pending_identifier_change_subject_action(
                id("expired-pending-identifier-change"),
                id("expired-pending-identifier-change-current"),
                id("expired-pending-identifier-change-candidate"),
                vec![id("expired-pending-identifier-change-authority")],
            ),
        }),
        &LoadedState::default(),
    )
    .expect_err("expired identifier-change action cannot cancel");
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
            CredentialResetPolicyRole::OrdinaryCredential,
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
        CredentialResetPolicyRole::OrdinaryCredential,
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
        CredentialResetPolicyRole::OrdinaryCredential,
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

fn pending_identifier_change_subject_action(
    pending_action_id: PendingSubjectLifecycleActionId,
    current_identifier_source_id: VerifiedProofSourceId,
    candidate_identifier_source_id: VerifiedProofSourceId,
    candidate_identifier_authority_ids: Vec<RecoveryAuthorityId>,
) -> PendingSubjectLifecycleActionRecord {
    PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
        pending_action_id,
        id("subject"),
        current_identifier_source_id,
        candidate_identifier_source_id,
        candidate_identifier_authority_ids,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending identifier-change subject action")
}

fn out_of_band_identifier_change_context<
    const AUTHORITY_COUNT: usize,
    const EVIDENCE_COUNT: usize,
>(
    current_source: VerifiedProofSource,
    candidate_source: VerifiedProofSource,
    authorities: [SubjectLifecycleAuthority; AUTHORITY_COUNT],
    evidence: [LifecycleAuthorityEvidence; EVIDENCE_COUNT],
) -> OutOfBandIdentifierChangeContext {
    OutOfBandIdentifierChangeContext::new(
        SubjectLifecycleActionContext::new(
            id("subject"),
            SubjectLifecycleAuthorityGraph::new(authorities).expect("subject lifecycle graph"),
            evidence,
        ),
        current_source,
        candidate_source,
    )
    .expect("identifier change context")
}

fn out_of_band_identifier_source(source_id: &str) -> VerifiedProofSource {
    VerifiedProofSource::new(VerifiedProofSourceKind::OutOfBandIdentifier, id(source_id))
}

fn admin_support_intervention(
    intervention_id: &str,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
    verified_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> VerifiedAdminSupportCredentialLifecycleIntervention {
    VerifiedAdminSupportCredentialLifecycleIntervention::new(
        id(intervention_id),
        id("subject"),
        target_credential_instance_id,
        action,
        verified_at,
        expires_at,
    )
    .expect("admin support intervention")
}

fn admin_support_intervention_record(
    intervention_id: &str,
    target_credential_instance_id: VerifiedProofSourceId,
    action: CredentialLifecycleAction,
    requested_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> AdminSupportInterventionRecord {
    AdminSupportInterventionRecord::new_requested(
        id(intervention_id),
        id("subject"),
        target_credential_instance_id,
        action,
        requested_at,
        expires_at,
    )
    .expect("admin support intervention record")
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
