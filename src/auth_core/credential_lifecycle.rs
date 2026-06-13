use super::prelude::*;
use super::{active_proof, audit_event, transition};

pub(super) fn plan_credential_reset(command: PlanCredentialReset) -> Result<Transition, Error> {
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        CredentialLifecycleAction::Reset,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate
            if command.active_proof_attempt_to_close.is_some() =>
        {
            Err(Error::UnauthenticatedCredentialRecoveryResetSchedulingRequiresDelayedAction)
        }
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            plan_immediate_credential_reset(command.now, target, None)
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction => plan_delayed_credential_reset(
            command.now,
            target,
            command.active_proof_attempt_to_close.as_ref(),
            command.pending_action,
        ),
        CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

pub(super) fn plan_credential_replacement(
    command: PlanCredentialReplacement,
) -> Result<Transition, Error> {
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        CredentialLifecycleAction::Replace,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            plan_immediate_credential_replacement_authorization(command.now, target)
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction => {
            plan_delayed_credential_replacement(command.now, target, command.pending_action)
        }
        CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

pub(super) fn plan_credential_removal(command: PlanCredentialRemoval) -> Result<Transition, Error> {
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        CredentialLifecycleAction::Remove,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            plan_immediate_credential_removal_authorization(command.now, target)
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction => {
            plan_delayed_credential_removal(command.now, target, command.pending_action)
        }
        CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

pub(super) fn plan_credential_regeneration(
    command: PlanCredentialRegeneration,
) -> Result<Transition, Error> {
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        CredentialLifecycleAction::Regenerate,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            plan_immediate_credential_regeneration_authorization(command.now, target)
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction => {
            plan_delayed_credential_regeneration(command.now, target, command.pending_action)
        }
        CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

pub(super) fn plan_out_of_band_identifier_change(
    command: PlanOutOfBandIdentifierChange,
) -> Result<Transition, Error> {
    validate_identifier_change_candidate_authority_ids(&command.candidate_authority_ids)?;
    let subject_id = command
        .change_context
        .subject_lifecycle_context()
        .subject_id()
        .clone();
    let current_identifier_source_id = command
        .change_context
        .current_identifier_source()
        .source_id()
        .clone();
    let candidate_identifier_source_id = command
        .change_context
        .candidate_identifier_source()
        .source_id()
        .clone();
    match command
        .change_context
        .evaluate_action_at(command.now, command.independent_evidence_required)
    {
        SubjectLifecycleActionDecision::AuthorizedImmediate => Ok(transition(
            Outcome::OutOfBandIdentifierChangePlanned(
                OutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate {
                    subject_id,
                    current_identifier_source_id,
                    candidate_identifier_source_id,
                },
            ),
            CommitPlan::default(),
        )),
        SubjectLifecycleActionDecision::RequiresDelayedAction => {
            plan_delayed_out_of_band_identifier_change(
                command.now,
                subject_id,
                current_identifier_source_id,
                candidate_identifier_source_id,
                command.candidate_authority_ids,
                command.pending_action,
            )
        }
        SubjectLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

pub(super) fn request_admin_support_intervention(
    command: RequestAdminSupportIntervention,
) -> Result<Transition, Error> {
    let record = AdminSupportInterventionRecord::new_requested(
        command.intervention_id.clone(),
        command.subject_id.clone(),
        command.target_credential_instance_id.clone(),
        command.action,
        command.now,
        command.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::CredentialInstanceStillActive {
            credential_instance_id: command.target_credential_instance_id.clone(),
            subject_id: command.subject_id.clone(),
        });
    plan.preconditions
        .push(Precondition::NoOpenAdminSupportInterventionForTarget {
            subject_id: command.subject_id.clone(),
            target_credential_instance_id: command.target_credential_instance_id.clone(),
            action: command.action,
            now: command.now,
        });
    plan.mutations
        .push(Mutation::CreateAdminSupportIntervention(record.clone()));
    plan.audit_events.push(audit_event(
        AuditEventKind::AdminSupportInterventionRequested,
        command.now,
        Some(command.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::AdminSupportInterventionRequested,
                subject_id: command.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::AdminSupportInterventionRequested(AdminSupportInterventionRequestOutcome {
            intervention_id: command.intervention_id,
            subject_id: command.subject_id,
            target_credential_instance_id: command.target_credential_instance_id,
            action: command.action,
            expires_at: record.expires_at,
        }),
        plan,
    ))
}

pub(super) fn approve_admin_support_intervention(
    command: ApproveAdminSupportIntervention,
) -> Result<Transition, Error> {
    let intervention = command.intervention.verified_at(command.now)?;
    if !lifecycle_context_contains_admin_support_intervention(
        &command.lifecycle_context,
        &intervention,
    ) {
        return Err(Error::CredentialLifecycleActionNotAuthorized);
    }
    let action = intervention.action();
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        action,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    let mut transition = match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            plan_immediate_admin_support_credential_lifecycle_intervention(
                command.now,
                &intervention,
                target,
                action,
            )
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction => {
            plan_delayed_admin_support_credential_lifecycle_intervention(
                command.now,
                &intervention,
                target,
                action,
                command.pending_action,
            )
        }
        CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }?;
    prepend_admin_support_intervention_closure(
        &mut transition.commit_plan,
        command.now,
        &command.intervention,
        AdminSupportInterventionStatus::Approved,
        AuditEventKind::AdminSupportInterventionApproved,
        SecurityNotificationKind::AdminSupportInterventionApproved,
    );
    Ok(transition)
}

pub(super) fn deny_admin_support_intervention(
    command: DenyAdminSupportIntervention,
) -> Result<Transition, Error> {
    if !command.intervention.is_open_at(command.now) {
        return Err(Error::AdminSupportInterventionNotDeniable);
    }
    let mut plan = CommitPlan::default();
    append_admin_support_intervention_still_open_guard(
        &mut plan,
        command.now,
        &command.intervention,
    );
    plan.mutations
        .push(Mutation::CloseAdminSupportIntervention {
            intervention_id: command.intervention.intervention_id.clone(),
            status: AdminSupportInterventionStatus::Denied,
            closed_at: command.now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::AdminSupportInterventionDenied,
        command.now,
        Some(command.intervention.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::AdminSupportInterventionDenied,
                subject_id: command.intervention.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::AdminSupportInterventionDenied(AdminSupportInterventionClosureOutcome {
            intervention_id: command.intervention.intervention_id,
            subject_id: command.intervention.subject_id,
            target_credential_instance_id: command.intervention.target_credential_instance_id,
            action: command.intervention.action,
        }),
        plan,
    ))
}

pub(super) fn expire_admin_support_intervention(
    command: ExpireAdminSupportIntervention,
) -> Result<Transition, Error> {
    if !command.intervention.is_expired_open_at(command.now) {
        return Err(Error::AdminSupportInterventionNotExpirable);
    }
    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::AdminSupportInterventionStillExpiredOpen {
            intervention_id: command.intervention.intervention_id.clone(),
            subject_id: command.intervention.subject_id.clone(),
            target_credential_instance_id: command
                .intervention
                .target_credential_instance_id
                .clone(),
            action: command.intervention.action,
            now: command.now,
        });
    plan.mutations
        .push(Mutation::CloseAdminSupportIntervention {
            intervention_id: command.intervention.intervention_id.clone(),
            status: AdminSupportInterventionStatus::Expired,
            closed_at: command.now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::AdminSupportInterventionExpired,
        command.now,
        Some(command.intervention.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::AdminSupportInterventionExpired,
                subject_id: command.intervention.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::AdminSupportInterventionExpired(AdminSupportInterventionClosureOutcome {
            intervention_id: command.intervention.intervention_id,
            subject_id: command.intervention.subject_id,
            target_credential_instance_id: command.intervention.target_credential_instance_id,
            action: command.intervention.action,
        }),
        plan,
    ))
}

pub(super) fn plan_admin_support_credential_lifecycle_intervention(
    command: PlanAdminSupportCredentialLifecycleIntervention,
) -> Result<Transition, Error> {
    if !lifecycle_context_contains_admin_support_intervention(
        &command.lifecycle_context,
        &command.intervention,
    ) {
        return Err(Error::CredentialLifecycleActionNotAuthorized);
    }
    let action = command.intervention.action();
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        action,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            plan_immediate_admin_support_credential_lifecycle_intervention(
                command.now,
                &command.intervention,
                target,
                action,
            )
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction => {
            plan_delayed_admin_support_credential_lifecycle_intervention(
                command.now,
                &command.intervention,
                target,
                action,
                command.pending_action,
            )
        }
        CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

pub(super) fn execute_credential_reset(
    command: ExecuteCredentialReset,
) -> Result<Transition, Error> {
    let (target, pending_action_id) =
        target_and_pending_action_for_reset_execution(command.now, &command.execution_authority)?;
    validate_credential_reset_method_work_matches_target(&command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, &target);
    push_active_proof_attempt_closure_for_reset_plan(
        &mut plan,
        command.now,
        &target,
        command.active_proof_attempt_to_close.as_ref(),
    )?;
    if let CredentialResetExecutionAuthority::MaturePendingAction { pending_action, .. } =
        &command.execution_authority
    {
        plan.preconditions.push(
            Precondition::PendingCredentialLifecycleActionStillExecutable {
                pending_action_id: pending_action.pending_action_id.clone(),
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
                action: CredentialLifecycleAction::Reset,
                now: command.now,
            },
        );
        plan.mutations
            .push(Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id: pending_action.pending_action_id.clone(),
                closed_at: command.now,
            });
    }
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Reset,
            executed_at: command.now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.method_commit_work = command.method_commit_work;
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialResetExecuted,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetExecuted,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            pending_action_id,
        }),
        plan,
    ))
}

pub(super) fn execute_credential_replacement(
    command: ExecuteCredentialReplacement,
) -> Result<Transition, Error> {
    let target =
        target_for_immediate_replacement_execution(command.now, &command.execution_authority)?;
    let contract = CredentialLifecycleAction::Replace
        .pending_credential_action_contract()
        .ok_or(Error::CredentialLifecycleActionNotAuthorized)?;
    validate_credential_replacement_successor_matches_target(&command.successor, &target)?;
    validate_non_reset_pending_action_method_work(contract, &command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
    push_subject_retains_required_credential_posture_after_replacement_guard(
        &mut plan,
        &target,
        &command.successor,
    );
    push_target_credential_guard(&mut plan, &target);
    push_credential_replacement_successor_mutations(&mut plan, command.now, &command.successor)?;
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Replace,
            executed_at: command.now,
        });
    push_credential_state_mutation_after_execution(&mut plan, command.now, &target, contract);
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.method_commit_work = command.method_commit_work;
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialReplacementExecuted,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialReplacementExecuted,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

pub(super) fn execute_credential_removal(
    command: ExecuteCredentialRemoval,
) -> Result<Transition, Error> {
    let target = target_for_immediate_removal_execution(command.now, &command.execution_authority)?;
    let contract = CredentialLifecycleAction::Remove
        .pending_credential_action_contract()
        .ok_or(Error::CredentialLifecycleActionNotAuthorized)?;

    let mut plan = CommitPlan::default();
    push_subject_retains_required_credential_posture_after_removal_guard(&mut plan, &target);
    push_target_credential_guard(&mut plan, &target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Remove,
            executed_at: command.now,
        });
    push_credential_state_mutation_after_execution(&mut plan, command.now, &target, contract);
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRemovalExecuted,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRemovalExecuted,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRemovalExecuted(CredentialRemovalExecutionOutcome {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

pub(super) fn execute_credential_rotation(
    command: ExecuteCredentialRotation,
) -> Result<Transition, Error> {
    let target =
        target_for_immediate_rotation_execution(command.now, &command.execution_authority)?;
    validate_credential_rotation_method_work_matches_target(&command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, &target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Rotate,
            executed_at: command.now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.method_commit_work = command.method_commit_work;
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRotated,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRotated,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRotated(CredentialRotationExecutionOutcome {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

pub(super) fn execute_credential_regeneration(
    command: ExecuteCredentialRegeneration,
) -> Result<Transition, Error> {
    let target =
        target_for_immediate_regeneration_execution(command.now, &command.execution_authority)?;
    let contract = CredentialLifecycleAction::Regenerate
        .pending_credential_action_contract()
        .ok_or(Error::CredentialLifecycleActionNotAuthorized)?;
    validate_non_reset_pending_action_method_work(contract, &command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, &target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Regenerate,
            executed_at: command.now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.method_commit_work = command.method_commit_work;
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRegenerationExecuted,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRegenerationExecuted,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRegenerated(CredentialRegenerationExecutionOutcome {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

pub(super) fn cancel_pending_credential_reset(
    command: CancelPendingCredentialReset,
) -> Result<Transition, Error> {
    let target = command.target_credential;
    let pending_action = command.pending_action;
    if !pending_action.matches_target_action(&target, CredentialLifecycleAction::Reset)
        || !pending_action.is_cancellable_at(command.now)
    {
        return Err(Error::PendingCredentialLifecycleActionNotCancellable);
    }

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, &target);
    plan.preconditions.push(
        Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Reset,
            now: command.now,
        },
    );
    plan.mutations
        .push(Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialResetPendingActionCancelled,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetPendingActionCancelled,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialResetPendingActionCancelled(CredentialResetCancellationOutcome {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            pending_action_id: pending_action.pending_action_id,
        }),
        plan,
    ))
}

pub(super) fn add_credential(command: AddCredential) -> Result<Transition, Error> {
    let decision = command.lifecycle_context.evaluate_action_at(
        command.now,
        CredentialLifecycleAction::Create,
        command.independent_evidence_required,
    );
    if decision != CredentialLifecycleActionDecision::AuthorizedImmediate {
        return Err(Error::CredentialLifecycleActionNotAuthorized);
    }
    let new_credential = command.lifecycle_context.target_credential();
    validate_credential_addition_method_work_matches_new_credential(
        &command.method_commit_work,
        new_credential,
    )?;
    validate_credential_addition_authorities_target_new_credential(
        command
            .lifecycle_context
            .recovery_authority_graph()
            .authorities(),
        new_credential,
    )?;
    let new_credential_authority_evidence = LifecycleAuthorityEvidence::from_verified_proof_source(
        new_credential.verified_proof_source(),
        command.new_credential_authority_ids,
    )?;

    let mut plan = CommitPlan::default();
    push_subject_retains_required_credential_posture_after_addition_guard(
        &mut plan,
        new_credential,
        command
            .lifecycle_context
            .recovery_authority_graph()
            .authorities(),
    );
    plan.mutations
        .push(Mutation::CreateCredentialInstanceMetadata {
            metadata: new_credential.clone(),
            created_at: command.now,
        });
    for authority in command
        .lifecycle_context
        .recovery_authority_graph()
        .authorities()
    {
        plan.mutations
            .push(Mutation::CreateCredentialRecoveryAuthority {
                authority: authority.clone(),
                created_at: command.now,
            });
    }
    for authority_id in new_credential_authority_evidence.authority_ids() {
        plan.mutations
            .push(Mutation::CreateLifecycleAuthoritySource {
                source: new_credential_authority_evidence.source().clone(),
                authority_id: authority_id.clone(),
                created_at: command.now,
            });
    }
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: new_credential.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Create,
            executed_at: command.now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: new_credential.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.method_commit_work = command.method_commit_work;
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialAdded,
        command.now,
        Some(new_credential.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialAdded,
                subject_id: new_credential.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialAdded(CredentialAdditionOutcome {
            subject_id: new_credential.subject_id().clone(),
            credential_instance_id: new_credential.credential_instance_id().clone(),
        }),
        plan,
    ))
}

pub(super) fn execute_non_reset_pending_credential_lifecycle_action(
    command: ExecuteNonResetPendingCredentialLifecycleAction,
) -> Result<Transition, Error> {
    let target = command.target_credential;
    let pending_action = command.pending_action;
    let action = pending_action.action;
    let contract = non_reset_pending_credential_action_contract(action)?;
    if !pending_action.matches_target_action(&target, action)
        || !pending_action.is_executable_at(command.now)
    {
        return Err(Error::PendingCredentialLifecycleActionNotExecutable);
    }
    let replacement_successor = validate_replacement_successor_for_non_reset_pending_action(
        action,
        command.replacement_successor.as_ref(),
        &target,
    )?;
    validate_non_reset_pending_action_method_work(contract, &command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
    match action {
        CredentialLifecycleAction::Replace => {
            let successor = replacement_successor
                .ok_or(Error::CredentialReplacementExecutionMissingSuccessorCredential)?;
            push_subject_retains_required_credential_posture_after_replacement_guard(
                &mut plan, &target, successor,
            );
            push_credential_replacement_successor_mutations(&mut plan, command.now, successor)?;
        }
        CredentialLifecycleAction::Remove => {
            push_subject_retains_required_credential_posture_after_removal_guard(
                &mut plan, &target,
            );
        }
        _ => {}
    }
    push_target_credential_guard(&mut plan, &target);
    plan.preconditions.push(
        Precondition::PendingCredentialLifecycleActionStillExecutable {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            now: command.now,
        },
    );
    plan.mutations
        .push(Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            executed_at: command.now,
        });
    push_credential_state_mutation_after_execution(&mut plan, command.now, &target, contract);
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.method_commit_work = command.method_commit_work;
    plan.audit_events.push(audit_event(
        non_reset_pending_action_executed_audit_kind(action)?,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: non_reset_pending_action_executed_notification_kind(action)?,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::NonResetPendingCredentialLifecycleActionExecuted(
            NonResetPendingCredentialLifecycleActionExecutionOutcome {
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
                action,
                pending_action_id: pending_action.pending_action_id,
            },
        ),
        plan,
    ))
}

pub(super) fn cancel_non_reset_pending_credential_lifecycle_action(
    command: CancelNonResetPendingCredentialLifecycleAction,
) -> Result<Transition, Error> {
    let target = command.target_credential;
    let pending_action = command.pending_action;
    let action = pending_action.action;
    non_reset_pending_credential_action_contract(action)?;
    if !pending_action.matches_target_action(&target, action)
        || !pending_action.is_cancellable_at(command.now)
    {
        return Err(Error::PendingCredentialLifecycleActionNotCancellable);
    }

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, &target);
    plan.preconditions.push(
        Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            now: command.now,
        },
    );
    plan.mutations
        .push(Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    plan.audit_events.push(audit_event(
        non_reset_pending_action_cancelled_audit_kind(action)?,
        command.now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: non_reset_pending_action_cancelled_notification_kind(action)?,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::NonResetPendingCredentialLifecycleActionCancelled(
            NonResetPendingCredentialLifecycleActionCancellationOutcome {
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
                action,
                pending_action_id: pending_action.pending_action_id,
            },
        ),
        plan,
    ))
}

pub(super) fn schedule_subject_auth_state_deletion(
    command: ScheduleSubjectAuthStateDeletion,
) -> Result<Transition, Error> {
    let action = SubjectLifecycleAction::DeleteSubjectAuthState;
    let pending_record = PendingSubjectLifecycleActionRecord::new_open(
        command.pending_action.pending_action_id.clone(),
        command.subject_id.clone(),
        action,
        command.now,
        command.pending_action.earliest_execute_at,
        command.pending_action.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    plan.preconditions.push(
        Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
            subject_id: command.subject_id.clone(),
            action,
            now: command.now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingSubjectLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::SubjectAuthStateDeletionPendingActionScheduled,
        command.now,
        Some(command.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::SubjectAuthStateDeletionPendingActionScheduled,
                subject_id: command.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::SubjectAuthStateDeletionScheduled(SubjectAuthStateDeletionScheduledOutcome {
            subject_id: command.subject_id,
            pending_action_id: pending_record.pending_action_id,
            earliest_execute_at: pending_record.earliest_execute_at,
            expires_at: pending_record.expires_at,
        }),
        plan,
    ))
}

pub(super) fn execute_pending_subject_auth_state_deletion(
    command: ExecutePendingSubjectAuthStateDeletion,
) -> Result<Transition, Error> {
    let pending_action = command.pending_action;
    let action = SubjectLifecycleAction::DeleteSubjectAuthState;
    let contract = action.pending_subject_action_contract();
    if contract.execution() != PendingLifecycleActionExecution::CoreSubjectAuthState {
        return Err(Error::LoadedStateContradiction(
            "subject deletion action must execute through subject-auth-state mutation",
        ));
    }
    if !pending_action.matches_subject_action(&pending_action.subject_id, action)
        || !pending_action.is_executable_at(command.now)
    {
        return Err(Error::PendingSubjectLifecycleActionNotExecutable);
    }

    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::PendingSubjectLifecycleActionStillExecutable {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: pending_action.subject_id.clone(),
            action,
            now: command.now,
        });
    plan.mutations
        .push(Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: pending_action.subject_id.clone(),
            revoke_records_created_at_or_before: command.now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::SubjectAuthStateDeletionExecuted,
        command.now,
        Some(pending_action.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::SubjectAuthStateDeletionExecuted,
                subject_id: pending_action.subject_id.clone(),
            },
        ));
    if let Some(action) = command.application_subject_data_lifecycle_action {
        plan.durable_effects
            .push(DurableEffectCommand::ApplyApplicationSubjectDataLifecycle(
                ApplicationSubjectDataLifecycleCommand {
                    action,
                    subject_id: pending_action.subject_id.clone(),
                    requested_at: command.now,
                },
            ));
    }

    Ok(transition(
        Outcome::PendingSubjectAuthStateDeletionExecuted(
            PendingSubjectAuthStateDeletionExecutionOutcome {
                subject_id: pending_action.subject_id,
                pending_action_id: pending_action.pending_action_id,
            },
        ),
        plan,
    ))
}

pub(super) fn cancel_pending_subject_auth_state_deletion(
    command: CancelPendingSubjectAuthStateDeletion,
) -> Result<Transition, Error> {
    let pending_action = command.pending_action;
    let action = SubjectLifecycleAction::DeleteSubjectAuthState;
    if !pending_action.matches_subject_action(&pending_action.subject_id, action)
        || !pending_action.is_cancellable_at(command.now)
    {
        return Err(Error::PendingSubjectLifecycleActionNotCancellable);
    }

    let mut plan = CommitPlan::default();
    plan.preconditions.push(
        Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: pending_action.subject_id.clone(),
            action,
            now: command.now,
        },
    );
    plan.mutations
        .push(Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::SubjectAuthStateDeletionPendingActionCancelled,
        command.now,
        Some(pending_action.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::SubjectAuthStateDeletionPendingActionCancelled,
                subject_id: pending_action.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::PendingSubjectAuthStateDeletionCancelled(
            PendingSubjectAuthStateDeletionCancellationOutcome {
                subject_id: pending_action.subject_id,
                pending_action_id: pending_action.pending_action_id,
            },
        ),
        plan,
    ))
}

pub(super) fn execute_out_of_band_identifier_change(
    command: ExecuteOutOfBandIdentifierChange,
) -> Result<Transition, Error> {
    let subject_id = command
        .change_context
        .subject_lifecycle_context()
        .subject_id()
        .clone();
    match command
        .change_context
        .evaluate_action_at(command.now, command.independent_evidence_required)
    {
        SubjectLifecycleActionDecision::AuthorizedImmediate => {}
        SubjectLifecycleActionDecision::RequiresDelayedAction
        | SubjectLifecycleActionDecision::Rejected => {
            return Err(Error::CredentialLifecycleActionNotAuthorized);
        }
    }
    validate_identifier_change_candidate_authority_ids(&command.candidate_authority_ids)?;

    let mut plan = CommitPlan::default();
    append_out_of_band_identifier_change_commit_work(
        &mut plan,
        command.now,
        &subject_id,
        command.change_context.current_identifier_source(),
        command.change_context.candidate_identifier_source(),
        &command.candidate_authority_ids,
    );
    plan.audit_events.push(audit_event(
        AuditEventKind::OutOfBandIdentifierChanged,
        command.now,
        Some(subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::OutOfBandIdentifierChanged,
                subject_id: subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::OutOfBandIdentifierChanged(OutOfBandIdentifierChangeOutcome {
            subject_id,
            current_identifier_source_id: command
                .change_context
                .current_identifier_source()
                .source_id()
                .clone(),
            candidate_identifier_source_id: command
                .change_context
                .candidate_identifier_source()
                .source_id()
                .clone(),
        }),
        plan,
    ))
}

pub(super) fn execute_pending_out_of_band_identifier_change(
    command: ExecutePendingOutOfBandIdentifierChange,
) -> Result<Transition, Error> {
    let pending_action = command.pending_action;
    let action = SubjectLifecycleAction::ChangeOutOfBandIdentifier;
    let contract = action.pending_subject_action_contract();
    if contract.execution() != PendingLifecycleActionExecution::CoreOutOfBandIdentifierBinding {
        return Err(Error::LoadedStateContradiction(
            "identifier-change action must execute through core identifier binding mutation",
        ));
    }
    pending_action.validate_target_details()?;
    if !pending_action.matches_subject_action(&pending_action.subject_id, action)
        || !pending_action.is_executable_at(command.now)
    {
        return Err(Error::PendingSubjectLifecycleActionNotExecutable);
    }
    let current_identifier_source_id =
        pending_action
            .current_identifier_source_id
            .clone()
            .ok_or(Error::InvalidConfig(
                "pending identifier change is missing current identifier source",
            ))?;
    let candidate_identifier_source_id = pending_action
        .candidate_identifier_source_id
        .clone()
        .ok_or(Error::InvalidConfig(
            "pending identifier change is missing candidate identifier source",
        ))?;
    let current_identifier_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        current_identifier_source_id.clone(),
    );
    let candidate_identifier_source = VerifiedProofSource::new(
        VerifiedProofSourceKind::OutOfBandIdentifier,
        candidate_identifier_source_id.clone(),
    );

    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::PendingSubjectLifecycleActionStillExecutable {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: pending_action.subject_id.clone(),
            action,
            now: command.now,
        });
    plan.mutations
        .push(Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    append_out_of_band_identifier_change_commit_work(
        &mut plan,
        command.now,
        &pending_action.subject_id,
        &current_identifier_source,
        &candidate_identifier_source,
        &pending_action.candidate_identifier_authority_ids,
    );
    plan.audit_events.push(audit_event(
        AuditEventKind::OutOfBandIdentifierChanged,
        command.now,
        Some(pending_action.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::OutOfBandIdentifierChanged,
                subject_id: pending_action.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::PendingOutOfBandIdentifierChangeExecuted(
            PendingOutOfBandIdentifierChangeExecutionOutcome {
                subject_id: pending_action.subject_id,
                pending_action_id: pending_action.pending_action_id,
                current_identifier_source_id,
                candidate_identifier_source_id,
            },
        ),
        plan,
    ))
}

pub(super) fn cancel_pending_out_of_band_identifier_change(
    command: CancelPendingOutOfBandIdentifierChange,
) -> Result<Transition, Error> {
    let pending_action = command.pending_action;
    let action = SubjectLifecycleAction::ChangeOutOfBandIdentifier;
    pending_action.validate_target_details()?;
    if !pending_action.matches_subject_action(&pending_action.subject_id, action)
        || !pending_action.is_cancellable_at(command.now)
    {
        return Err(Error::PendingSubjectLifecycleActionNotCancellable);
    }
    let current_identifier_source_id =
        pending_action
            .current_identifier_source_id
            .clone()
            .ok_or(Error::InvalidConfig(
                "pending identifier change is missing current identifier source",
            ))?;
    let candidate_identifier_source_id = pending_action
        .candidate_identifier_source_id
        .clone()
        .ok_or(Error::InvalidConfig(
            "pending identifier change is missing candidate identifier source",
        ))?;

    let mut plan = CommitPlan::default();
    plan.preconditions.push(
        Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
            pending_action_id: pending_action.pending_action_id.clone(),
            subject_id: pending_action.subject_id.clone(),
            action,
            now: command.now,
        },
    );
    plan.mutations
        .push(Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id: pending_action.pending_action_id.clone(),
            closed_at: command.now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::OutOfBandIdentifierChangePendingActionCancelled,
        command.now,
        Some(pending_action.subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::OutOfBandIdentifierChangePendingActionCancelled,
                subject_id: pending_action.subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::PendingOutOfBandIdentifierChangeCancelled(
            PendingOutOfBandIdentifierChangeCancellationOutcome {
                subject_id: pending_action.subject_id,
                pending_action_id: pending_action.pending_action_id,
                current_identifier_source_id,
                candidate_identifier_source_id,
            },
        ),
        plan,
    ))
}

fn append_out_of_band_identifier_change_commit_work(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    subject_id: &SubjectId,
    current_identifier_source: &VerifiedProofSource,
    candidate_identifier_source: &VerifiedProofSource,
    candidate_authority_ids: &[RecoveryAuthorityId],
) {
    let current_source_id = current_identifier_source.source_id().clone();
    let candidate_source_id = candidate_identifier_source.source_id().clone();
    plan.preconditions
        .push(Precondition::OutOfBandIdentifierBindingStillActive {
            source_id: current_source_id.clone(),
            subject_id: subject_id.clone(),
        });
    plan.preconditions.push(
        Precondition::OutOfBandIdentifierBindingStillPendingActivation {
            source_id: candidate_source_id.clone(),
            subject_id: subject_id.clone(),
        },
    );
    plan.mutations
        .push(Mutation::SetOutOfBandIdentifierBindingLifecycleState {
            source_id: current_source_id,
            lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Superseded,
            updated_at: now,
        });
    plan.mutations
        .push(Mutation::SetOutOfBandIdentifierBindingLifecycleState {
            source_id: candidate_source_id,
            lifecycle_state: OutOfBandIdentifierBindingLifecycleState::Active,
            updated_at: now,
        });
    plan.mutations
        .push(Mutation::DeleteLifecycleAuthoritySourcesForSource {
            source: LifecycleAuthoritySource::VerifiedProofSource(
                candidate_identifier_source.clone(),
            ),
        });
    for authority_id in candidate_authority_ids {
        plan.mutations
            .push(Mutation::CreateLifecycleAuthoritySource {
                source: LifecycleAuthoritySource::VerifiedProofSource(
                    candidate_identifier_source.clone(),
                ),
                authority_id: authority_id.clone(),
                created_at: now,
            });
    }
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: subject_id.clone(),
            revoke_records_created_at_or_before: now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
}

fn validate_identifier_change_candidate_authority_ids(
    candidate_authority_ids: &[RecoveryAuthorityId],
) -> Result<(), Error> {
    if candidate_authority_ids.is_empty() {
        return Err(Error::InvalidConfig(
            "identifier change candidate must name at least one recovery authority",
        ));
    }
    if candidate_authority_ids.len() > OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT {
        return Err(Error::InvalidConfig(
            "identifier change candidate names too many recovery authorities",
        ));
    }
    if contains_duplicate_recovery_authority_ids(candidate_authority_ids) {
        return Err(Error::InvalidConfig(
            "identifier change candidate must not duplicate recovery authorities",
        ));
    }
    Ok(())
}

fn target_and_pending_action_for_reset_execution(
    now: UnixSeconds,
    authority: &CredentialResetExecutionAuthority,
) -> Result<
    (
        CredentialInstanceMetadata,
        Option<PendingCredentialLifecycleActionId>,
    ),
    Error,
> {
    match authority {
        CredentialResetExecutionAuthority::Immediate {
            lifecycle_context,
            independent_evidence_required,
        } => match lifecycle_context.evaluate_action_at(
            now,
            CredentialLifecycleAction::Reset,
            *independent_evidence_required,
        ) {
            CredentialLifecycleActionDecision::AuthorizedImmediate => {
                Ok((lifecycle_context.target_credential().clone(), None))
            }
            CredentialLifecycleActionDecision::RequiresDelayedAction
            | CredentialLifecycleActionDecision::Rejected => {
                Err(Error::CredentialLifecycleActionNotAuthorized)
            }
        },
        CredentialResetExecutionAuthority::MaturePendingAction {
            target_credential,
            pending_action,
        } => {
            if !pending_action
                .matches_target_action(target_credential, CredentialLifecycleAction::Reset)
                || !pending_action.is_executable_at(now)
            {
                return Err(Error::PendingCredentialLifecycleActionNotExecutable);
            }
            Ok((
                target_credential.clone(),
                Some(pending_action.pending_action_id.clone()),
            ))
        }
    }
}

fn target_for_immediate_replacement_execution(
    now: UnixSeconds,
    authority: &CredentialReplacementExecutionAuthority,
) -> Result<CredentialInstanceMetadata, Error> {
    match authority.lifecycle_context.evaluate_action_at(
        now,
        CredentialLifecycleAction::Replace,
        authority.independent_evidence_required,
    ) {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            Ok(authority.lifecycle_context.target_credential().clone())
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction
        | CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn target_for_immediate_removal_execution(
    now: UnixSeconds,
    authority: &CredentialRemovalExecutionAuthority,
) -> Result<CredentialInstanceMetadata, Error> {
    match authority.lifecycle_context.evaluate_action_at(
        now,
        CredentialLifecycleAction::Remove,
        authority.independent_evidence_required,
    ) {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            Ok(authority.lifecycle_context.target_credential().clone())
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction
        | CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn target_for_immediate_rotation_execution(
    now: UnixSeconds,
    authority: &CredentialRotationExecutionAuthority,
) -> Result<CredentialInstanceMetadata, Error> {
    match authority.lifecycle_context.evaluate_action_at(
        now,
        CredentialLifecycleAction::Rotate,
        authority.independent_evidence_required,
    ) {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            Ok(authority.lifecycle_context.target_credential().clone())
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction
        | CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn target_for_immediate_regeneration_execution(
    now: UnixSeconds,
    authority: &CredentialRegenerationExecutionAuthority,
) -> Result<CredentialInstanceMetadata, Error> {
    match authority.lifecycle_context.evaluate_action_at(
        now,
        CredentialLifecycleAction::Regenerate,
        authority.independent_evidence_required,
    ) {
        CredentialLifecycleActionDecision::AuthorizedImmediate => {
            Ok(authority.lifecycle_context.target_credential().clone())
        }
        CredentialLifecycleActionDecision::RequiresDelayedAction
        | CredentialLifecycleActionDecision::Rejected => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn validate_credential_reset_method_work_matches_target(
    method_commit_work: &[MethodCommitWork],
    target: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    if method_commit_work.is_empty() {
        return Err(Error::CredentialResetExecutionMissingMethodCommitWork);
    }
    for work in method_commit_work {
        if work.proof().family() != target.proof_family()
            || work.proof().method_label() != target.method_label()
        {
            return Err(Error::CredentialResetExecutionMethodCommitWorkTargetMismatch);
        }
    }
    Ok(())
}

fn validate_credential_rotation_method_work_matches_target(
    method_commit_work: &[MethodCommitWork],
    target: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    if method_commit_work.is_empty() {
        return Err(Error::CredentialLifecycleExecutionMissingMethodCommitWork);
    }
    for work in method_commit_work {
        if work.proof().family() != target.proof_family()
            || work.proof().method_label() != target.method_label()
        {
            return Err(Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch);
        }
    }
    Ok(())
}

fn validate_credential_addition_method_work_matches_new_credential(
    method_commit_work: &[MethodCommitWork],
    new_credential: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    if method_commit_work.is_empty() {
        return Err(Error::CredentialAdditionMissingMethodCommitWork);
    }
    for work in method_commit_work {
        if work.proof().family() != new_credential.proof_family()
            || work.proof().method_label() != new_credential.method_label()
        {
            return Err(Error::CredentialAdditionMethodCommitWorkTargetMismatch);
        }
    }
    Ok(())
}

fn validate_credential_addition_authorities_target_new_credential(
    authorities: &[CredentialRecoveryAuthority],
    new_credential: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    for authority in authorities {
        if authority.target_credential_instance_id() != new_credential.credential_instance_id() {
            return Err(Error::CredentialAdditionRecoveryAuthorityTargetMismatch);
        }
    }
    Ok(())
}

fn validate_credential_replacement_successor_matches_target(
    successor: &CredentialReplacementSuccessor,
    target: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    let successor_metadata = successor.metadata();
    if successor_metadata.credential_instance_id() == target.credential_instance_id() {
        return Err(Error::CredentialReplacementSuccessorCredentialIdMatchesTarget);
    }
    if successor_metadata.subject_id() != target.subject_id() {
        return Err(Error::CredentialReplacementSuccessorSubjectMismatch);
    }
    if successor_metadata.kind() != target.kind()
        || successor_metadata.method_label() != target.method_label()
        || successor_metadata.reset_policy_role() != target.reset_policy_role()
        || successor_metadata.lifecycle_state() != CredentialLifecycleState::Active
    {
        return Err(Error::CredentialReplacementSuccessorMethodMismatch);
    }
    validate_credential_replacement_authorities_target_successor(
        successor.recovery_authorities(),
        successor_metadata,
    )
}

fn validate_credential_replacement_authorities_target_successor(
    authorities: &[CredentialRecoveryAuthority],
    successor_metadata: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    for authority in authorities {
        if authority.target_credential_instance_id() != successor_metadata.credential_instance_id()
        {
            return Err(Error::CredentialReplacementRecoveryAuthorityTargetMismatch);
        }
    }
    Ok(())
}

fn validate_replacement_successor_for_non_reset_pending_action<'a>(
    action: CredentialLifecycleAction,
    successor: Option<&'a CredentialReplacementSuccessor>,
    target: &CredentialInstanceMetadata,
) -> Result<Option<&'a CredentialReplacementSuccessor>, Error> {
    match (action, successor) {
        (CredentialLifecycleAction::Replace, Some(successor)) => {
            validate_credential_replacement_successor_matches_target(successor, target)?;
            Ok(Some(successor))
        }
        (CredentialLifecycleAction::Replace, None) => {
            Err(Error::CredentialReplacementExecutionMissingSuccessorCredential)
        }
        (_, Some(_)) => {
            Err(Error::CredentialLifecycleExecutionUnexpectedReplacementSuccessorCredential)
        }
        (_, None) => Ok(None),
    }
}

fn validate_non_reset_pending_action_method_work(
    contract: PendingLifecycleActionContract,
    method_commit_work: &[MethodCommitWork],
    target: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    match contract.execution() {
        PendingLifecycleActionExecution::MethodOwnedCredential => {
            if method_commit_work.is_empty() {
                return Err(Error::CredentialLifecycleExecutionMissingMethodCommitWork);
            }
            for work in method_commit_work {
                if work.proof().family() != target.proof_family()
                    || work.proof().method_label() != target.method_label()
                {
                    return Err(Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch);
                }
            }
        }
        PendingLifecycleActionExecution::CoreCredentialState => {
            if !method_commit_work.is_empty() {
                return Err(Error::CredentialLifecycleExecutionUnexpectedMethodCommitWork);
            }
        }
        PendingLifecycleActionExecution::CoreSubjectAuthState => {
            return Err(Error::LoadedStateContradiction(
                "credential-targeted command cannot execute subject-targeted pending action",
            ));
        }
        PendingLifecycleActionExecution::CoreOutOfBandIdentifierBinding => {
            return Err(Error::LoadedStateContradiction(
                "credential-targeted command cannot execute subject identifier binding action",
            ));
        }
    }
    Ok(())
}

fn push_credential_state_mutation_after_execution(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    contract: PendingLifecycleActionContract,
) {
    let lifecycle_state = match contract.credential_state_after_execution() {
        PendingCredentialStateAfterExecution::PreserveCurrentState => return,
        PendingCredentialStateAfterExecution::MarkTargetRevoked => {
            CredentialLifecycleState::Revoked
        }
        PendingCredentialStateAfterExecution::MarkTargetSuperseded => {
            CredentialLifecycleState::Superseded
        }
        PendingCredentialStateAfterExecution::NoCredentialTarget => return,
    };
    plan.mutations.push(Mutation::SetCredentialLifecycleState {
        credential_instance_id: target.credential_instance_id().clone(),
        lifecycle_state,
        updated_at: now,
    });
}

fn non_reset_pending_credential_action_contract(
    action: CredentialLifecycleAction,
) -> Result<PendingLifecycleActionContract, Error> {
    if action == CredentialLifecycleAction::Reset {
        return Err(Error::NonResetPendingCredentialLifecycleActionCannotBeReset);
    }
    action
        .pending_credential_action_contract()
        .ok_or(Error::CredentialLifecycleActionNotAuthorized)
}

fn non_reset_pending_action_executed_audit_kind(
    action: CredentialLifecycleAction,
) -> Result<AuditEventKind, Error> {
    match action {
        CredentialLifecycleAction::Replace => Ok(AuditEventKind::CredentialReplacementExecuted),
        CredentialLifecycleAction::Remove => Ok(AuditEventKind::CredentialRemovalExecuted),
        CredentialLifecycleAction::Regenerate => Ok(AuditEventKind::CredentialRegenerationExecuted),
        CredentialLifecycleAction::Reset => {
            Err(Error::NonResetPendingCredentialLifecycleActionCannotBeReset)
        }
        CredentialLifecycleAction::Create
        | CredentialLifecycleAction::Disable
        | CredentialLifecycleAction::Rotate
        | CredentialLifecycleAction::RecoverSubjectAccess => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn non_reset_pending_action_cancelled_audit_kind(
    action: CredentialLifecycleAction,
) -> Result<AuditEventKind, Error> {
    match action {
        CredentialLifecycleAction::Replace => {
            Ok(AuditEventKind::CredentialReplacementPendingActionCancelled)
        }
        CredentialLifecycleAction::Remove => {
            Ok(AuditEventKind::CredentialRemovalPendingActionCancelled)
        }
        CredentialLifecycleAction::Regenerate => {
            Ok(AuditEventKind::CredentialRegenerationPendingActionCancelled)
        }
        CredentialLifecycleAction::Reset => {
            Err(Error::NonResetPendingCredentialLifecycleActionCannotBeReset)
        }
        CredentialLifecycleAction::Create
        | CredentialLifecycleAction::Disable
        | CredentialLifecycleAction::Rotate
        | CredentialLifecycleAction::RecoverSubjectAccess => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn non_reset_pending_action_executed_notification_kind(
    action: CredentialLifecycleAction,
) -> Result<SecurityNotificationKind, Error> {
    match action {
        CredentialLifecycleAction::Replace => {
            Ok(SecurityNotificationKind::CredentialReplacementExecuted)
        }
        CredentialLifecycleAction::Remove => {
            Ok(SecurityNotificationKind::CredentialRemovalExecuted)
        }
        CredentialLifecycleAction::Regenerate => {
            Ok(SecurityNotificationKind::CredentialRegenerationExecuted)
        }
        CredentialLifecycleAction::Reset => {
            Err(Error::NonResetPendingCredentialLifecycleActionCannotBeReset)
        }
        CredentialLifecycleAction::Create
        | CredentialLifecycleAction::Disable
        | CredentialLifecycleAction::Rotate
        | CredentialLifecycleAction::RecoverSubjectAccess => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn non_reset_pending_action_cancelled_notification_kind(
    action: CredentialLifecycleAction,
) -> Result<SecurityNotificationKind, Error> {
    match action {
        CredentialLifecycleAction::Replace => {
            Ok(SecurityNotificationKind::CredentialReplacementPendingActionCancelled)
        }
        CredentialLifecycleAction::Remove => {
            Ok(SecurityNotificationKind::CredentialRemovalPendingActionCancelled)
        }
        CredentialLifecycleAction::Regenerate => {
            Ok(SecurityNotificationKind::CredentialRegenerationPendingActionCancelled)
        }
        CredentialLifecycleAction::Reset => {
            Err(Error::NonResetPendingCredentialLifecycleActionCannotBeReset)
        }
        CredentialLifecycleAction::Create
        | CredentialLifecycleAction::Disable
        | CredentialLifecycleAction::Rotate
        | CredentialLifecycleAction::RecoverSubjectAccess => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn plan_immediate_credential_reset(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    active_proof_attempt_to_close: Option<&ActiveProofAttemptRecord>,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    push_active_proof_attempt_closure_for_reset_plan(
        &mut plan,
        now,
        target,
        active_proof_attempt_to_close,
    )?;
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Reset,
            authorized_at: now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialResetAuthorized,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetAuthorized,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

fn plan_immediate_admin_support_credential_lifecycle_intervention(
    now: UnixSeconds,
    intervention: &VerifiedAdminSupportCredentialLifecycleIntervention,
    target: &CredentialInstanceMetadata,
    action: CredentialLifecycleAction,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            authorized_at: now,
        });
    plan.mutations
        .push(Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id: target.subject_id().clone(),
            revoke_records_created_at_or_before: now,
            reason: RevocationReason::SubjectAuthStateChanged,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::AdminSupportCredentialLifecycleInterventionAuthorized,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind:
                    SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionAuthorized,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::AuthorizedImmediate {
                intervention_id: intervention.intervention_id().clone(),
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
                action,
            },
        ),
        plan,
    ))
}

fn plan_immediate_credential_replacement_authorization(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Replace,
            authorized_at: now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialReplacementAuthorized,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialReplacementAuthorized,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialReplacementPlanned(CredentialReplacementOutcome::AuthorizedImmediate {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

fn plan_immediate_credential_removal_authorization(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Remove,
            authorized_at: now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRemovalAuthorized,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRemovalAuthorized,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::AuthorizedImmediate {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
        }),
        plan,
    ))
}

fn plan_immediate_credential_regeneration_authorization(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
) -> Result<Transition, Error> {
    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.mutations
        .push(Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Regenerate,
            authorized_at: now,
        });
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRegenerationAuthorized,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRegenerationAuthorized,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRegenerationPlanned(
            CredentialRegenerationOutcome::AuthorizedImmediate {
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
            },
        ),
        plan,
    ))
}

fn plan_delayed_credential_reset(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    active_proof_attempt_to_close: Option<&ActiveProofAttemptRecord>,
    pending_action: Option<PendingCredentialLifecycleActionSchedule>,
) -> Result<Transition, Error> {
    let pending_action = pending_action.ok_or(Error::MissingFreshValue(
        "pending credential lifecycle action id",
    ))?;
    let pending_record = PendingCredentialLifecycleActionRecord::new_open(
        pending_action.pending_action_id.clone(),
        target.subject_id().clone(),
        target.credential_instance_id().clone(),
        CredentialLifecycleAction::Reset,
        now,
        pending_action.earliest_execute_at,
        pending_action.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    push_active_proof_attempt_closure_for_reset_plan(
        &mut plan,
        now,
        target,
        active_proof_attempt_to_close,
    )?;
    plan.preconditions.push(
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action: CredentialLifecycleAction::Reset,
            now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingCredentialLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialResetPendingActionScheduled,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialResetPendingActionScheduled,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            pending_action_id: pending_record.pending_action_id,
            earliest_execute_at: pending_record.earliest_execute_at,
            expires_at: pending_record.expires_at,
        }),
        plan,
    ))
}

fn plan_delayed_out_of_band_identifier_change(
    now: UnixSeconds,
    subject_id: SubjectId,
    current_identifier_source_id: VerifiedProofSourceId,
    candidate_identifier_source_id: VerifiedProofSourceId,
    candidate_authority_ids: Vec<RecoveryAuthorityId>,
    pending_action: Option<PendingSubjectLifecycleActionSchedule>,
) -> Result<Transition, Error> {
    let pending_action = pending_action.ok_or(Error::MissingFreshValue(
        "pending subject lifecycle action id",
    ))?;
    let pending_record =
        PendingSubjectLifecycleActionRecord::new_open_out_of_band_identifier_change(
            pending_action.pending_action_id.clone(),
            subject_id.clone(),
            current_identifier_source_id.clone(),
            candidate_identifier_source_id.clone(),
            candidate_authority_ids,
            now,
            pending_action.earliest_execute_at,
            pending_action.expires_at,
        )?;

    let mut plan = CommitPlan::default();
    plan.preconditions
        .push(Precondition::OutOfBandIdentifierBindingStillActive {
            source_id: current_identifier_source_id.clone(),
            subject_id: subject_id.clone(),
        });
    plan.preconditions.push(
        Precondition::OutOfBandIdentifierBindingStillPendingActivation {
            source_id: candidate_identifier_source_id.clone(),
            subject_id: subject_id.clone(),
        },
    );
    plan.preconditions.push(
        Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
            subject_id: subject_id.clone(),
            action: SubjectLifecycleAction::ChangeOutOfBandIdentifier,
            now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingSubjectLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::OutOfBandIdentifierChangePendingActionScheduled,
        now,
        Some(subject_id.clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::OutOfBandIdentifierChangePendingActionScheduled,
                subject_id: subject_id.clone(),
            },
        ));

    Ok(transition(
        Outcome::OutOfBandIdentifierChangePlanned(
            OutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
                subject_id,
                current_identifier_source_id,
                candidate_identifier_source_id,
                pending_action_id: pending_record.pending_action_id,
                earliest_execute_at: pending_record.earliest_execute_at,
                expires_at: pending_record.expires_at,
            },
        ),
        plan,
    ))
}

fn plan_delayed_credential_replacement(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    pending_action: Option<PendingCredentialLifecycleActionSchedule>,
) -> Result<Transition, Error> {
    let pending_action = pending_action.ok_or(Error::MissingFreshValue(
        "pending credential lifecycle action id",
    ))?;
    let action = CredentialLifecycleAction::Replace;
    let pending_record = PendingCredentialLifecycleActionRecord::new_open(
        pending_action.pending_action_id.clone(),
        target.subject_id().clone(),
        target.credential_instance_id().clone(),
        action,
        now,
        pending_action.earliest_execute_at,
        pending_action.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.preconditions.push(
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingCredentialLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialReplacementPendingActionScheduled,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialReplacementPendingActionScheduled,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialReplacementPlanned(CredentialReplacementOutcome::PendingActionCreated {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            pending_action_id: pending_record.pending_action_id,
            earliest_execute_at: pending_record.earliest_execute_at,
            expires_at: pending_record.expires_at,
        }),
        plan,
    ))
}

fn plan_delayed_credential_removal(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    pending_action: Option<PendingCredentialLifecycleActionSchedule>,
) -> Result<Transition, Error> {
    let pending_action = pending_action.ok_or(Error::MissingFreshValue(
        "pending credential lifecycle action id",
    ))?;
    let action = CredentialLifecycleAction::Remove;
    let pending_record = PendingCredentialLifecycleActionRecord::new_open(
        pending_action.pending_action_id.clone(),
        target.subject_id().clone(),
        target.credential_instance_id().clone(),
        action,
        now,
        pending_action.earliest_execute_at,
        pending_action.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.preconditions.push(
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingCredentialLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRemovalPendingActionScheduled,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRemovalPendingActionScheduled,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::PendingActionCreated {
            subject_id: target.subject_id().clone(),
            target_credential_instance_id: target.credential_instance_id().clone(),
            pending_action_id: pending_record.pending_action_id,
            earliest_execute_at: pending_record.earliest_execute_at,
            expires_at: pending_record.expires_at,
        }),
        plan,
    ))
}

fn plan_delayed_credential_regeneration(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    pending_action: Option<PendingCredentialLifecycleActionSchedule>,
) -> Result<Transition, Error> {
    let pending_action = pending_action.ok_or(Error::MissingFreshValue(
        "pending credential lifecycle action id",
    ))?;
    let action = CredentialLifecycleAction::Regenerate;
    let pending_record = PendingCredentialLifecycleActionRecord::new_open(
        pending_action.pending_action_id.clone(),
        target.subject_id().clone(),
        target.credential_instance_id().clone(),
        action,
        now,
        pending_action.earliest_execute_at,
        pending_action.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.preconditions.push(
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingCredentialLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::CredentialRegenerationPendingActionScheduled,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::CredentialRegenerationPendingActionScheduled,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::CredentialRegenerationPlanned(
            CredentialRegenerationOutcome::PendingActionCreated {
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
                pending_action_id: pending_record.pending_action_id,
                earliest_execute_at: pending_record.earliest_execute_at,
                expires_at: pending_record.expires_at,
            },
        ),
        plan,
    ))
}

fn plan_delayed_admin_support_credential_lifecycle_intervention(
    now: UnixSeconds,
    intervention: &VerifiedAdminSupportCredentialLifecycleIntervention,
    target: &CredentialInstanceMetadata,
    action: CredentialLifecycleAction,
    pending_action: Option<PendingCredentialLifecycleActionSchedule>,
) -> Result<Transition, Error> {
    let pending_action = pending_action.ok_or(Error::MissingFreshValue(
        "pending credential lifecycle action id",
    ))?;
    let pending_record = PendingCredentialLifecycleActionRecord::new_open(
        pending_action.pending_action_id.clone(),
        target.subject_id().clone(),
        target.credential_instance_id().clone(),
        action,
        now,
        pending_action.earliest_execute_at,
        pending_action.expires_at,
    )?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, target);
    plan.preconditions.push(
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id: target.credential_instance_id().clone(),
            action,
            now,
        },
    );
    plan.mutations
        .push(Mutation::CreatePendingCredentialLifecycleAction(
            pending_record.clone(),
        ));
    plan.audit_events.push(audit_event(
        AuditEventKind::AdminSupportCredentialLifecycleInterventionPendingActionScheduled,
        now,
        Some(target.subject_id().clone()),
        None,
        None,
    ));
    plan.durable_effects
        .push(DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::AdminSupportCredentialLifecycleInterventionPendingActionScheduled,
                subject_id: target.subject_id().clone(),
            },
        ));

    Ok(transition(
        Outcome::AdminSupportCredentialLifecycleInterventionPlanned(
            AdminSupportCredentialLifecycleInterventionOutcome::PendingActionCreated {
                intervention_id: intervention.intervention_id().clone(),
                subject_id: target.subject_id().clone(),
                target_credential_instance_id: target.credential_instance_id().clone(),
                action,
                pending_action_id: pending_record.pending_action_id,
                earliest_execute_at: pending_record.earliest_execute_at,
                expires_at: pending_record.expires_at,
            },
        ),
        plan,
    ))
}

fn lifecycle_context_contains_admin_support_intervention(
    context: &CredentialLifecycleActionContext,
    intervention: &VerifiedAdminSupportCredentialLifecycleIntervention,
) -> bool {
    context.presented_evidence().iter().any(|evidence| {
        matches!(
            evidence.source(),
            LifecycleAuthoritySource::AdminSupportIntervention(presented)
                if presented == intervention
        )
    })
}

fn prepend_admin_support_intervention_closure(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    intervention: &AdminSupportInterventionRecord,
    status: AdminSupportInterventionStatus,
    audit_kind: AuditEventKind,
    notification_kind: SecurityNotificationKind,
) {
    plan.preconditions.insert(
        0,
        Precondition::AdminSupportInterventionStillOpen {
            intervention_id: intervention.intervention_id.clone(),
            subject_id: intervention.subject_id.clone(),
            target_credential_instance_id: intervention.target_credential_instance_id.clone(),
            action: intervention.action,
            now,
        },
    );
    plan.mutations.insert(
        0,
        Mutation::CloseAdminSupportIntervention {
            intervention_id: intervention.intervention_id.clone(),
            status,
            closed_at: now,
        },
    );
    plan.audit_events.insert(
        0,
        audit_event(
            audit_kind,
            now,
            Some(intervention.subject_id.clone()),
            None,
            None,
        ),
    );
    plan.durable_effects.insert(
        0,
        DurableEffectCommand::NotifySecurityEvent(SecurityNotificationCommand {
            kind: notification_kind,
            subject_id: intervention.subject_id.clone(),
        }),
    );
}

fn append_admin_support_intervention_still_open_guard(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    intervention: &AdminSupportInterventionRecord,
) {
    plan.preconditions
        .push(Precondition::AdminSupportInterventionStillOpen {
            intervention_id: intervention.intervention_id.clone(),
            subject_id: intervention.subject_id.clone(),
            target_credential_instance_id: intervention.target_credential_instance_id.clone(),
            action: intervention.action,
            now,
        });
}

fn push_target_credential_guard(plan: &mut CommitPlan, target: &CredentialInstanceMetadata) {
    plan.preconditions
        .push(Precondition::CredentialInstanceStillActive {
            credential_instance_id: target.credential_instance_id().clone(),
            subject_id: target.subject_id().clone(),
        });
}

fn push_subject_retains_required_credential_posture_after_removal_guard(
    plan: &mut CommitPlan,
    target: &CredentialInstanceMetadata,
) {
    plan.preconditions.push(
        Precondition::SubjectRetainsRequiredCredentialPostureAfterRemoval {
            subject_id: target.subject_id().clone(),
            removed_credential_instance_id: target.credential_instance_id().clone(),
            removed_credential_reset_policy_role: target.reset_policy_role(),
        },
    );
}

fn push_subject_retains_required_credential_posture_after_replacement_guard(
    plan: &mut CommitPlan,
    target: &CredentialInstanceMetadata,
    successor: &CredentialReplacementSuccessor,
) {
    plan.preconditions.push(
        Precondition::SubjectRetainsRequiredCredentialPostureAfterReplacement {
            subject_id: target.subject_id().clone(),
            replaced_credential_instance_id: target.credential_instance_id().clone(),
            replaced_credential_reset_policy_role: target.reset_policy_role(),
            successor: successor.clone(),
        },
    );
}

fn push_subject_retains_required_credential_posture_after_addition_guard(
    plan: &mut CommitPlan,
    added_credential: &CredentialInstanceMetadata,
    added_recovery_authorities: &[CredentialRecoveryAuthority],
) {
    plan.preconditions.push(
        Precondition::SubjectRetainsRequiredCredentialPostureAfterAddition {
            subject_id: added_credential.subject_id().clone(),
            added_credential: added_credential.clone(),
            added_recovery_authorities: added_recovery_authorities.to_vec(),
        },
    );
}

fn push_credential_replacement_successor_mutations(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    successor: &CredentialReplacementSuccessor,
) -> Result<(), Error> {
    plan.mutations
        .push(Mutation::CreateCredentialInstanceMetadata {
            metadata: successor.metadata().clone(),
            created_at: now,
        });
    for authority in successor.recovery_authorities() {
        plan.mutations
            .push(Mutation::CreateCredentialRecoveryAuthority {
                authority: authority.clone(),
                created_at: now,
            });
    }
    let authority_evidence = successor.authority_evidence()?;
    for authority_id in authority_evidence.authority_ids() {
        plan.mutations
            .push(Mutation::CreateLifecycleAuthoritySource {
                source: authority_evidence.source().clone(),
                authority_id: authority_id.clone(),
                created_at: now,
            });
    }
    Ok(())
}

fn push_active_proof_attempt_closure_for_reset_plan(
    plan: &mut CommitPlan,
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    active_proof_attempt_to_close: Option<&ActiveProofAttemptRecord>,
) -> Result<(), Error> {
    let Some(attempt) = active_proof_attempt_to_close else {
        return Ok(());
    };
    if attempt.proof_use != ProofUse::RecoverOrReplaceCredential {
        return Err(Error::LoadedStateContradiction(
            "credential reset scheduling can consume only recover-or-replace active proofs",
        ));
    }
    active_proof::ensure_active_proof_attempt_matches_subject(attempt, target.subject_id())?;
    active_proof::append_active_proof_attempt_closure_to_plan(
        plan,
        now,
        attempt,
        Some(target.subject_id().clone()),
        None,
        None,
    );
    Ok(())
}
