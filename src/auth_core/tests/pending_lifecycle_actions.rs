use super::*;

#[test]
fn credential_targeted_pending_actions_have_explicit_execution_contracts() {
    let reset = CredentialLifecycleAction::Reset
        .pending_credential_action_contract()
        .expect("reset pending action contract");
    assert_eq!(
        reset.target(),
        PendingLifecycleActionTarget::CredentialInstance
    );
    assert_eq!(
        reset.execution(),
        PendingLifecycleActionExecution::MethodOwnedCredential
    );
    assert_eq!(
        reset.credential_state_after_execution(),
        PendingCredentialStateAfterExecution::PreserveCurrentState
    );

    let replace = CredentialLifecycleAction::Replace
        .pending_credential_action_contract()
        .expect("replace pending action contract");
    assert_eq!(
        replace.execution(),
        PendingLifecycleActionExecution::MethodOwnedCredential
    );
    assert_eq!(
        replace.credential_state_after_execution(),
        PendingCredentialStateAfterExecution::MarkTargetSuperseded
    );

    let remove = CredentialLifecycleAction::Remove
        .pending_credential_action_contract()
        .expect("remove pending action contract");
    assert_eq!(
        remove.execution(),
        PendingLifecycleActionExecution::CoreCredentialState
    );
    assert_eq!(
        remove.credential_state_after_execution(),
        PendingCredentialStateAfterExecution::MarkTargetRevoked
    );

    let regenerate = CredentialLifecycleAction::Regenerate
        .pending_credential_action_contract()
        .expect("regenerate pending action contract");
    assert_eq!(
        regenerate.execution(),
        PendingLifecycleActionExecution::MethodOwnedCredential
    );
    assert_eq!(
        regenerate.credential_state_after_execution(),
        PendingCredentialStateAfterExecution::PreserveCurrentState
    );
}

#[test]
fn pending_actions_share_cancellation_expiry_and_revocation_boundaries() {
    for action in [
        CredentialLifecycleAction::Reset,
        CredentialLifecycleAction::Replace,
        CredentialLifecycleAction::Remove,
        CredentialLifecycleAction::Regenerate,
    ] {
        let contract = action
            .pending_credential_action_contract()
            .expect("credential pending action contract");
        assert_eq!(
            contract.cancellation(),
            PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice
        );
        assert_eq!(
            contract.expiry(),
            PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup
        );
        assert_eq!(
            contract.revocation(),
            PendingLifecycleActionRevocation::ExplicitTransitionPolicy
        );
    }
}

#[test]
fn non_delayed_credential_actions_do_not_use_the_credential_pending_action_contract() {
    for action in [
        CredentialLifecycleAction::Create,
        CredentialLifecycleAction::Disable,
        CredentialLifecycleAction::Rotate,
        CredentialLifecycleAction::RecoverSubjectAccess,
    ] {
        assert_eq!(action.pending_credential_action_contract(), None);
    }
}

#[test]
fn subject_deletion_pending_action_is_not_credential_targeted() {
    let deletion = SubjectLifecycleAction::DeleteSubjectAuthState.pending_subject_action_contract();

    assert_eq!(
        deletion.target(),
        PendingLifecycleActionTarget::SubjectAuthState
    );
    assert_eq!(
        deletion.execution(),
        PendingLifecycleActionExecution::CoreSubjectAuthState
    );
    assert_eq!(
        deletion.credential_state_after_execution(),
        PendingCredentialStateAfterExecution::NoCredentialTarget
    );
    assert_eq!(
        deletion.cancellation(),
        PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice
    );
    assert_eq!(
        deletion.expiry(),
        PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup
    );
    assert_eq!(
        deletion.revocation(),
        PendingLifecycleActionRevocation::SubjectWideOnExecution
    );
}

#[test]
fn out_of_band_identifier_change_pending_action_is_not_credential_targeted() {
    let identifier_change =
        SubjectLifecycleAction::ChangeOutOfBandIdentifier.pending_subject_action_contract();

    assert_eq!(
        identifier_change.target(),
        PendingLifecycleActionTarget::SubjectOutOfBandIdentifierBinding
    );
    assert_eq!(
        identifier_change.execution(),
        PendingLifecycleActionExecution::CoreOutOfBandIdentifierBinding
    );
    assert_eq!(
        identifier_change.credential_state_after_execution(),
        PendingCredentialStateAfterExecution::NoCredentialTarget
    );
    assert_eq!(
        identifier_change.cancellation(),
        PendingLifecycleActionCancellation::ExplicitWhileUnexpiredWithNotice
    );
    assert_eq!(
        identifier_change.expiry(),
        PendingLifecycleActionExpiry::DeadlineDerivedQuietCleanup
    );
    assert_eq!(
        identifier_change.revocation(),
        PendingLifecycleActionRevocation::SubjectWideOnExecution
    );
}

#[test]
fn subject_pending_action_record_tracks_subject_action_without_credential_target() {
    let pending_action = PendingSubjectLifecycleActionRecord::new_open(
        id("pending-subject-deletion"),
        id("subject"),
        SubjectLifecycleAction::DeleteSubjectAuthState,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending subject action");

    assert!(pending_action.matches_subject_action(
        &id("subject"),
        SubjectLifecycleAction::DeleteSubjectAuthState
    ));
    assert!(!pending_action.matches_subject_action(
        &id("other-subject"),
        SubjectLifecycleAction::DeleteSubjectAuthState
    ));
    assert!(pending_action.is_open());
    assert!(!pending_action.is_executable_at(at(199)));
    assert!(pending_action.is_executable_at(at(200)));
    assert!(pending_action.is_cancellable_at(at(299)));
    assert!(!pending_action.is_cancellable_at(at(300)));
}
