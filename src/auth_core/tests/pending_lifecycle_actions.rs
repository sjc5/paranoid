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
        PendingLifecycleActionExecution::MethodOwnedCredentialMutation
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
        PendingLifecycleActionExecution::MethodOwnedCredentialMutation
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
        PendingLifecycleActionExecution::CoreCredentialStateMutation
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
        PendingLifecycleActionExecution::MethodOwnedCredentialMutation
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
        PendingLifecycleActionExecution::CoreSubjectAuthStateMutation
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
