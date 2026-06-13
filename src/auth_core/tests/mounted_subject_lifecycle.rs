use super::*;

#[test]
fn mounted_subject_lifecycle_inputs_convert_to_runtime_inputs_without_extra_authority() {
    let execution = ExecuteMountedDelayedSubjectAuthStateDeletionInput {
        now: at(200),
        pending_action_id: id("mounted-subject-deletion-execute"),
        application_subject_data_lifecycle_action:
            ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
    };
    assert_eq!(
        execution.runtime_input(),
        ExecuteMaturePendingSubjectAuthStateDeletionInput {
            now: at(200),
            pending_action_id: id("mounted-subject-deletion-execute"),
            application_subject_data_lifecycle_action: Some(
                ApplicationSubjectDataLifecycleAction::DeleteSubjectData,
            ),
        }
    );

    let cancellation = CancelMountedDelayedSubjectAuthStateDeletionInput {
        now: at(120),
        pending_action_id: id("mounted-subject-deletion-cancel"),
    };
    assert_eq!(
        cancellation.runtime_input(),
        CancelAuthenticatedPendingSubjectAuthStateDeletionInput {
            now: at(120),
            pending_action_id: id("mounted-subject-deletion-cancel"),
        }
    );

    let identifier_plan = PlanMountedAuthenticatedOutOfBandIdentifierChangeInput {
        now: at(140),
        current_identifier_source_id: id("mounted-identifier-plan-current"),
        candidate_identifier_source_id: id("mounted-identifier-plan-candidate"),
    };
    assert_eq!(
        identifier_plan.runtime_input(),
        PlanAuthenticatedOutOfBandIdentifierChangeInput {
            now: at(140),
            current_identifier_source_id: id("mounted-identifier-plan-current"),
            candidate_identifier_source_id: id("mounted-identifier-plan-candidate"),
        }
    );

    let identifier_execution = ExecuteMountedAuthenticatedOutOfBandIdentifierChangeInput {
        now: at(150),
        current_identifier_source_id: id("mounted-identifier-execute-current"),
        candidate_identifier_source_id: id("mounted-identifier-execute-candidate"),
    };
    assert_eq!(
        identifier_execution.runtime_input(),
        ExecuteAuthenticatedOutOfBandIdentifierChangeInput {
            now: at(150),
            current_identifier_source_id: id("mounted-identifier-execute-current"),
            candidate_identifier_source_id: id("mounted-identifier-execute-candidate"),
        }
    );

    let delayed_identifier_execution = ExecuteMountedDelayedOutOfBandIdentifierChangeInput {
        now: at(250),
        pending_action_id: id("mounted-identifier-delayed-execute"),
    };
    assert_eq!(
        delayed_identifier_execution.runtime_input(),
        ExecuteMaturePendingOutOfBandIdentifierChangeInput {
            now: at(250),
            pending_action_id: id("mounted-identifier-delayed-execute"),
        }
    );

    let delayed_identifier_cancellation = CancelMountedDelayedOutOfBandIdentifierChangeInput {
        now: at(160),
        pending_action_id: id("mounted-identifier-delayed-cancel"),
    };
    assert_eq!(
        delayed_identifier_cancellation.runtime_input(),
        CancelAuthenticatedPendingOutOfBandIdentifierChangeInput {
            now: at(160),
            pending_action_id: id("mounted-identifier-delayed-cancel"),
        }
    );
}

#[test]
fn mounted_subject_lifecycle_committed_outcome_maps_only_subject_deletion_outcomes() {
    assert_eq!(
        MountedSubjectLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::SubjectAuthStateDeletionScheduled(SubjectAuthStateDeletionScheduledOutcome {
                subject_id: id("mounted-subject-deletion-scheduled-subject"),
                pending_action_id: id("mounted-subject-deletion-scheduled-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        ),
        Some(
            MountedSubjectLifecycleCommittedOutcome::SubjectAuthStateDeletionScheduled {
                subject_id: id("mounted-subject-deletion-scheduled-subject"),
                pending_action_id: id("mounted-subject-deletion-scheduled-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedSubjectLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::PendingSubjectAuthStateDeletionExecuted(
                PendingSubjectAuthStateDeletionExecutionOutcome {
                    subject_id: id("mounted-subject-deletion-executed-subject"),
                    pending_action_id: id("mounted-subject-deletion-executed-action"),
                }
            ),
        ),
        Some(
            MountedSubjectLifecycleCommittedOutcome::SubjectAuthStateDeletionExecuted {
                subject_id: id("mounted-subject-deletion-executed-subject"),
                pending_action_id: id("mounted-subject-deletion-executed-action"),
            }
        )
    );
    assert_eq!(
        MountedSubjectLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::PendingSubjectAuthStateDeletionCancelled(
                PendingSubjectAuthStateDeletionCancellationOutcome {
                    subject_id: id("mounted-subject-deletion-cancelled-subject"),
                    pending_action_id: id("mounted-subject-deletion-cancelled-action"),
                }
            ),
        ),
        Some(
            MountedSubjectLifecycleCommittedOutcome::SubjectAuthStateDeletionCancelled {
                subject_id: id("mounted-subject-deletion-cancelled-subject"),
                pending_action_id: id("mounted-subject-deletion-cancelled-action"),
            }
        )
    );
    assert_eq!(
        MountedSubjectLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::PendingOutOfBandIdentifierChangeExecuted(
                PendingOutOfBandIdentifierChangeExecutionOutcome {
                    subject_id: id("mounted-identifier-executed-subject"),
                    pending_action_id: id("mounted-identifier-executed-action"),
                    current_identifier_source_id: id("mounted-identifier-executed-current"),
                    candidate_identifier_source_id: id("mounted-identifier-executed-candidate"),
                }
            ),
        ),
        Some(
            MountedSubjectLifecycleCommittedOutcome::OutOfBandIdentifierChangeExecuted {
                subject_id: id("mounted-identifier-executed-subject"),
                pending_action_id: id("mounted-identifier-executed-action"),
                current_identifier_source_id: id("mounted-identifier-executed-current"),
                candidate_identifier_source_id: id("mounted-identifier-executed-candidate"),
            }
        )
    );
    assert_eq!(
        MountedSubjectLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::PendingOutOfBandIdentifierChangeCancelled(
                PendingOutOfBandIdentifierChangeCancellationOutcome {
                    subject_id: id("mounted-identifier-cancelled-subject"),
                    pending_action_id: id("mounted-identifier-cancelled-action"),
                    current_identifier_source_id: id("mounted-identifier-cancelled-current"),
                    candidate_identifier_source_id: id("mounted-identifier-cancelled-candidate"),
                }
            ),
        ),
        Some(
            MountedSubjectLifecycleCommittedOutcome::OutOfBandIdentifierChangeCancelled {
                subject_id: id("mounted-identifier-cancelled-subject"),
                pending_action_id: id("mounted-identifier-cancelled-action"),
                current_identifier_source_id: id("mounted-identifier-cancelled-current"),
                candidate_identifier_source_id: id("mounted-identifier-cancelled-candidate"),
            }
        )
    );
    assert_eq!(
        MountedSubjectLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        None,
        "mounted subject lifecycle response surface must not reinterpret unrelated runtime outcomes"
    );
}

#[test]
fn mounted_out_of_band_identifier_change_planning_outcome_maps_only_planning_and_auth_control() {
    assert_eq!(
        MountedOutOfBandIdentifierChangePlanningOutcome::from_reducer_outcome(
            &Outcome::OutOfBandIdentifierChangePlanned(
                OutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate {
                    subject_id: id("mounted-identifier-plan-subject"),
                    current_identifier_source_id: id("mounted-identifier-plan-current"),
                    candidate_identifier_source_id: id("mounted-identifier-plan-candidate"),
                }
            ),
        ),
        Some(
            MountedOutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate {
                subject_id: id("mounted-identifier-plan-subject"),
                current_identifier_source_id: id("mounted-identifier-plan-current"),
                candidate_identifier_source_id: id("mounted-identifier-plan-candidate"),
            }
        )
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangePlanningOutcome::from_reducer_outcome(
            &Outcome::OutOfBandIdentifierChangePlanned(
                OutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
                    subject_id: id("mounted-identifier-delayed-subject"),
                    current_identifier_source_id: id("mounted-identifier-delayed-current"),
                    candidate_identifier_source_id: id("mounted-identifier-delayed-candidate"),
                    pending_action_id: id("mounted-identifier-delayed-action"),
                    earliest_execute_at: at(220),
                    expires_at: at(320),
                }
            ),
        ),
        Some(
            MountedOutOfBandIdentifierChangePlanningOutcome::PendingActionCreated {
                subject_id: id("mounted-identifier-delayed-subject"),
                current_identifier_source_id: id("mounted-identifier-delayed-current"),
                candidate_identifier_source_id: id("mounted-identifier-delayed-candidate"),
                pending_action_id: id("mounted-identifier-delayed-action"),
                earliest_execute_at: at(220),
                expires_at: at(320),
            }
        )
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangePlanningOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedOutOfBandIdentifierChangePlanningOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangePlanningOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-identifier-step-up-session"),
                subject_id: id("mounted-identifier-step-up-subject"),
            },
        ),
        Some(
            MountedOutOfBandIdentifierChangePlanningOutcome::NeedsStepUp {
                session_id: id("mounted-identifier-step-up-session"),
                subject_id: id("mounted-identifier-step-up-subject"),
            }
        )
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangePlanningOutcome::from_reducer_outcome(
            &Outcome::OutOfBandIdentifierChanged(OutOfBandIdentifierChangeOutcome {
                subject_id: id("mounted-identifier-executed-subject"),
                current_identifier_source_id: id("mounted-identifier-executed-current"),
                candidate_identifier_source_id: id("mounted-identifier-executed-candidate"),
            }),
        ),
        None,
        "identifier-change planning must not report execution as planning"
    );
}

#[test]
fn mounted_out_of_band_identifier_change_execution_outcome_maps_only_immediate_execution_and_auth_control()
 {
    assert_eq!(
        MountedOutOfBandIdentifierChangeExecutionOutcome::from_reducer_outcome(
            &Outcome::OutOfBandIdentifierChanged(OutOfBandIdentifierChangeOutcome {
                subject_id: id("mounted-identifier-executed-subject"),
                current_identifier_source_id: id("mounted-identifier-executed-current"),
                candidate_identifier_source_id: id("mounted-identifier-executed-candidate"),
            }),
        ),
        Some(
            MountedOutOfBandIdentifierChangeExecutionOutcome::IdentifierChanged {
                subject_id: id("mounted-identifier-executed-subject"),
                current_identifier_source_id: id("mounted-identifier-executed-current"),
                candidate_identifier_source_id: id("mounted-identifier-executed-candidate"),
            }
        )
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangeExecutionOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedOutOfBandIdentifierChangeExecutionOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangeExecutionOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-identifier-step-up-session"),
                subject_id: id("mounted-identifier-step-up-subject"),
            },
        ),
        Some(
            MountedOutOfBandIdentifierChangeExecutionOutcome::NeedsStepUp {
                session_id: id("mounted-identifier-step-up-session"),
                subject_id: id("mounted-identifier-step-up-subject"),
            }
        )
    );
    assert_eq!(
        MountedOutOfBandIdentifierChangeExecutionOutcome::from_reducer_outcome(
            &Outcome::OutOfBandIdentifierChangePlanned(
                OutOfBandIdentifierChangePlanningOutcome::AuthorizedImmediate {
                    subject_id: id("mounted-identifier-plan-subject"),
                    current_identifier_source_id: id("mounted-identifier-plan-current"),
                    candidate_identifier_source_id: id("mounted-identifier-plan-candidate"),
                }
            ),
        ),
        None,
        "identifier-change execution must not report planning as execution"
    );
}
