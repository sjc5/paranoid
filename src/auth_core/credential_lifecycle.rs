use super::{active_proof, audit_event, transition, *};

pub(super) fn plan_credential_reset(command: PlanCredentialReset) -> Result<Transition, Error> {
    let decision = command.lifecycle_context.evaluate_action(
        CredentialLifecycleAction::Reset,
        command.independent_evidence_required,
    );
    let target = command.lifecycle_context.target_credential();
    match decision {
        CredentialLifecycleActionDecision::AuthorizedImmediate => plan_immediate_credential_reset(
            command.now,
            target,
            command.active_proof_attempt_to_close.as_ref(),
            command.immediate_subject_auth_revocation,
        ),
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

pub(super) fn execute_credential_reset(
    command: ExecuteCredentialReset,
) -> Result<Transition, Error> {
    let (target, pending_action_id) =
        target_and_pending_action_for_reset_execution(command.now, &command.execution_authority)?;
    validate_credential_reset_method_work_matches_target(&command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
    push_target_credential_guard(&mut plan, &target);
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
    if command.subject_auth_revocation
        == CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState
    {
        plan.mutations
            .push(Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: target.subject_id().clone(),
                revoke_records_created_at_or_before: command.now,
                reason: RevocationReason::SubjectAuthStateChanged,
            });
    }
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
    validate_non_reset_pending_action_method_work(contract, &command.method_commit_work, &target)?;

    let mut plan = CommitPlan::default();
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
    if command.subject_auth_revocation
        == CredentialLifecycleSubjectAuthRevocation::RevokeSubjectAuthState
    {
        plan.mutations
            .push(Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: target.subject_id().clone(),
                revoke_records_created_at_or_before: command.now,
                reason: RevocationReason::SubjectAuthStateChanged,
            });
    }
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
        } => match lifecycle_context.evaluate_action(
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

fn validate_non_reset_pending_action_method_work(
    contract: PendingLifecycleActionContract,
    method_commit_work: &[MethodCommitWork],
    target: &CredentialInstanceMetadata,
) -> Result<(), Error> {
    match contract.execution() {
        PendingLifecycleActionExecution::MethodOwnedCredentialMutation => {
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
        PendingLifecycleActionExecution::CoreCredentialStateMutation => {
            if !method_commit_work.is_empty() {
                return Err(Error::CredentialLifecycleExecutionUnexpectedMethodCommitWork);
            }
        }
        PendingLifecycleActionExecution::CoreSubjectAuthStateMutation => {
            return Err(Error::LoadedStateContradiction(
                "credential-targeted command cannot execute subject-targeted pending action",
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
        | CredentialLifecycleAction::RecoverSubjectAccess => {
            Err(Error::CredentialLifecycleActionNotAuthorized)
        }
    }
}

fn plan_immediate_credential_reset(
    now: UnixSeconds,
    target: &CredentialInstanceMetadata,
    active_proof_attempt_to_close: Option<&ActiveProofAttemptRecord>,
    revocation: CredentialResetSubjectAuthRevocation,
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
    if revocation == CredentialResetSubjectAuthRevocation::RevokeSubjectAuthState {
        plan.mutations
            .push(Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id: target.subject_id().clone(),
                revoke_records_created_at_or_before: now,
                reason: RevocationReason::SubjectAuthStateChanged,
            });
    }
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

fn push_target_credential_guard(plan: &mut CommitPlan, target: &CredentialInstanceMetadata) {
    plan.preconditions
        .push(Precondition::CredentialInstanceStillActive {
            credential_instance_id: target.credential_instance_id().clone(),
            subject_id: target.subject_id().clone(),
        });
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
            "credential reset planning can consume only recover-or-replace active proofs",
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
