//! Executable model for the invariant-owning authentication core.
//!
//! This module is intentionally storage-agnostic. It does not send email, set
//! HTTP cookies, or write state records. Instead, it turns a loaded state
//! snapshot plus a command into an atomic commit plan. A commit adapter is
//! responsible for enforcing the preconditions and committing the state
//! mutations, audit events, and durable effect commands as one unit. Only after
//! that commit succeeds may response effects, such as issuing cookies, be
//! applied.

pub(in crate::auth_core) mod active_proof;
mod active_proof_model;
pub(in crate::auth_core) mod active_proof_support;
mod auth_system_model;
mod challenge_cookie_model;
mod command_model;
mod commit_audit;
mod commit_effect;
mod commit_method;
mod commit_mutation;
mod commit_plan;
mod commit_transaction_model;
mod config_model;
mod core_error;
mod credential_lifecycle;
mod credential_model;
mod email_otp_method;
mod execution_model;
mod identity;
mod input_limits;
mod load_contract_model;
mod loaded_state_model;
mod method_adapter_contract_model;
mod method_response_material_model;
mod mounted_admin_support_model;
mod mounted_admin_support_service;
mod mounted_credential_lifecycle_model;
mod mounted_credential_lifecycle_service;
mod mounted_durable_effect_worker_service;
mod mounted_runtime_model;
mod mounted_subject_lifecycle_model;
mod mounted_subject_lifecycle_service;
mod outcome_model;
mod postgres_adapter_execution_model;
mod postgres_bootstrap;
mod postgres_durable_effect_queue;
mod postgres_method_runtime;
mod postgres_method_schema;
mod postgres_password_derived_signature_method;
mod postgres_recovery_code_method;
mod postgres_runtime;
mod postgres_schema_model;
pub(in crate::auth_core) mod postgres_store;
mod postgres_totp_method;
mod prelude;
mod proof_model;
mod proof_policy;
mod response_materialization_model;
mod runtime_adapter_model;
mod runtime_orchestration_model;
mod session_lifecycle;
mod session_lifecycle_helpers;
mod session_resolution;
mod session_revocation;
mod storage_adapter_boundary_model;
mod storage_contract_model;
mod weak_proof_gate;
mod web_transport_model;

use prelude::*;

pub(crate) fn reduce_command(
    config: &Config,
    command: Command,
    loaded: &LoadedState,
) -> Result<Transition, Error> {
    config.validate()?;
    match command {
        Command::ResolveRequest(command) => {
            session_resolution::resolve_request(config, command, loaded)
        }
        Command::StartActiveProofAttempt(command) => {
            active_proof::start_active_proof_attempt(config, command)
        }
        Command::StartActiveProofAttemptForCurrentSession(command) => {
            active_proof::start_active_proof_attempt_for_current_session(config, command, loaded)
        }
        Command::StartActiveProofAttemptForCurrentTrustedDevice(command) => {
            active_proof::start_active_proof_attempt_for_current_trusted_device(
                config, command, loaded,
            )
        }
        Command::IssueActiveProofMethodChallenge(command) => {
            active_proof::issue_active_proof_method_challenge(config, command, loaded)
        }
        Command::IssueOutOfBandChallenge(command) => {
            active_proof::issue_out_of_band_challenge(config, command, loaded)
        }
        Command::ResendOutOfBandChallenge(command) => {
            active_proof::resend_out_of_band_challenge(command, loaded)
        }
        Command::CompleteActiveProofChallenge(command) => {
            active_proof::complete_active_proof_challenge(command, loaded)
        }
        Command::RecordActiveProofFailure(command) => {
            active_proof::record_active_proof_failure(command, loaded)
        }
        Command::CompleteFullAuthentication(command) => {
            session_lifecycle::complete_full_authentication(config, command, loaded)
        }
        Command::CompleteStepUp(command) => {
            session_lifecycle::complete_step_up(config, command, loaded)
        }
        Command::CompleteTrustedDeviceRevivalWithActiveProof(command) => {
            session_lifecycle::complete_trusted_device_revival_with_active_proof(
                config, command, loaded,
            )
        }
        Command::LogoutCurrentSession(command) => {
            session_revocation::logout_current_session(command, loaded)
        }
        Command::RevokeSession(command) => session_revocation::revoke_session(command, loaded),
        Command::RevokeTrustedDevice(command) => {
            session_revocation::revoke_trusted_device(command, loaded)
        }
        Command::RevokeSubjectAuthState(command) => {
            session_revocation::revoke_subject_auth_state(command, loaded)
        }
        Command::PlanCredentialReset(command) => {
            credential_lifecycle::plan_credential_reset(command)
        }
        Command::ExecuteCredentialReset(command) => {
            credential_lifecycle::execute_credential_reset(command)
        }
        Command::PlanCredentialReplacement(command) => {
            credential_lifecycle::plan_credential_replacement(command)
        }
        Command::ExecuteCredentialReplacement(command) => {
            credential_lifecycle::execute_credential_replacement(command)
        }
        Command::PlanCredentialRemoval(command) => {
            credential_lifecycle::plan_credential_removal(command)
        }
        Command::ExecuteCredentialRemoval(command) => {
            credential_lifecycle::execute_credential_removal(command)
        }
        Command::PlanCredentialRegeneration(command) => {
            credential_lifecycle::plan_credential_regeneration(command)
        }
        Command::ExecuteCredentialRegeneration(command) => {
            credential_lifecycle::execute_credential_regeneration(command)
        }
        Command::ExecuteCredentialRotation(command) => {
            credential_lifecycle::execute_credential_rotation(command)
        }
        Command::CancelPendingCredentialReset(command) => {
            credential_lifecycle::cancel_pending_credential_reset(command)
        }
        Command::AddCredential(command) => credential_lifecycle::add_credential(command),
        Command::ExecuteNonResetPendingCredentialLifecycleAction(command) => {
            credential_lifecycle::execute_non_reset_pending_credential_lifecycle_action(command)
        }
        Command::CancelNonResetPendingCredentialLifecycleAction(command) => {
            credential_lifecycle::cancel_non_reset_pending_credential_lifecycle_action(command)
        }
        Command::RequestAdminSupportIntervention(command) => {
            credential_lifecycle::request_admin_support_intervention(command)
        }
        Command::ApproveAdminSupportIntervention(command) => {
            credential_lifecycle::approve_admin_support_intervention(command)
        }
        Command::DenyAdminSupportIntervention(command) => {
            credential_lifecycle::deny_admin_support_intervention(command)
        }
        Command::ExpireAdminSupportIntervention(command) => {
            credential_lifecycle::expire_admin_support_intervention(command)
        }
        Command::PlanAdminSupportCredentialLifecycleIntervention(command) => {
            credential_lifecycle::plan_admin_support_credential_lifecycle_intervention(command)
        }
        Command::ScheduleSubjectAuthStateDeletion(command) => {
            credential_lifecycle::schedule_subject_auth_state_deletion(command)
        }
        Command::ExecutePendingSubjectAuthStateDeletion(command) => {
            credential_lifecycle::execute_pending_subject_auth_state_deletion(command)
        }
        Command::CancelPendingSubjectAuthStateDeletion(command) => {
            credential_lifecycle::cancel_pending_subject_auth_state_deletion(command)
        }
        Command::ExecutePendingOutOfBandIdentifierChange(command) => {
            credential_lifecycle::execute_pending_out_of_band_identifier_change(command)
        }
        Command::CancelPendingOutOfBandIdentifierChange(command) => {
            credential_lifecycle::cancel_pending_out_of_band_identifier_change(command)
        }
        Command::PlanOutOfBandIdentifierChange(command) => {
            credential_lifecycle::plan_out_of_band_identifier_change(command)
        }
        Command::ReserveOutOfBandIdentifierChangeCandidateBinding(command) => {
            active_proof::reserve_out_of_band_identifier_change_candidate_binding(command, loaded)
        }
        Command::ExecuteOutOfBandIdentifierChange(command) => {
            credential_lifecycle::execute_out_of_band_identifier_change(command)
        }
    }
}

pub(in crate::auth_core) fn audit_event(
    kind: AuditEventKind,
    occurred_at: UnixSeconds,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
    device_credential_id: Option<TrustedDeviceCredentialId>,
) -> AuditEvent {
    AuditEvent {
        kind,
        subject_id,
        session_id,
        device_credential_id,
        attempt_id: None,
        challenge_id: None,
        weak_proof_gate: None,
        occurred_at,
    }
}

pub(in crate::auth_core) struct ActiveProofAuditEventInput {
    kind: AuditEventKind,
    occurred_at: UnixSeconds,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
    device_credential_id: Option<TrustedDeviceCredentialId>,
    attempt_id: Option<ActiveProofAttemptId>,
    challenge_id: Option<ActiveProofChallengeId>,
    weak_proof_gate: Option<WeakProofGateSummary>,
}

pub(in crate::auth_core) fn active_proof_audit_event(
    input: ActiveProofAuditEventInput,
) -> AuditEvent {
    AuditEvent {
        kind: input.kind,
        subject_id: input.subject_id,
        session_id: input.session_id,
        device_credential_id: input.device_credential_id,
        attempt_id: input.attempt_id,
        challenge_id: input.challenge_id,
        weak_proof_gate: input.weak_proof_gate,
        occurred_at: input.occurred_at,
    }
}

pub(in crate::auth_core) fn transition(outcome: Outcome, commit_plan: CommitPlan) -> Transition {
    Transition {
        outcome,
        commit_plan,
    }
}

#[cfg(test)]
mod tests;
