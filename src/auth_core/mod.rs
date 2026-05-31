//! Executable model for the invariant-owning authentication core.
//!
//! This module is intentionally storage-agnostic. It does not send email, set
//! HTTP cookies, or write state records. Instead, it turns a loaded state
//! snapshot plus a command into an atomic commit plan. A commit adapter is
//! responsible for enforcing the preconditions and committing the state
//! mutations, audit events, and durable effect commands as one unit. Only after
//! that commit succeeds may response effects, such as issuing cookies, be
//! applied.
#![allow(dead_code, unused_imports)]

mod active_proof;
mod active_proof_model;
mod active_proof_support;
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
mod email_otp_method;
mod execution_model;
mod identity;
mod input_limits;
mod load_contract_model;
mod loaded_state_model;
mod method_adapter_contract_model;
mod outcome_model;
mod postgres_adapter_execution_model;
mod postgres_method_runtime;
mod postgres_recovery_code_method;
mod postgres_runtime;
mod postgres_schema_model;
mod postgres_store;
mod postgres_totp_method;
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
mod web_transport_model;

pub(crate) use active_proof_model::{
    ActiveProofAttemptRecord, ActiveProofChallengeRecord, ActiveProofMethodChallengeMaterial,
    ActiveProofMethodChallengePresentation, ActiveProofMethodChallengeSeed,
    ActiveProofMethodChallengeState, ActiveProofMethodResponsePayload,
    ChallengeBoundConfiguredSecretFastFailBloomFilter, ChallengeIssuePreflightResponse,
    ChallengeIssuePreflightVerificationRequest, CompleteActiveProofChallenge,
    CompleteActiveProofMethodResponse, CompleteKnownSubjectActiveProofMethodResponse,
    CompleteOutOfBandChallengeResponse, IssueActiveProofMethodChallenge,
    IssueActiveProofMethodChallengeInput, IssueActiveProofMethodChallengeRequest,
    IssueOutOfBandChallenge, IssueOutOfBandChallengeInput, IssueOutOfBandChallengeRequest,
    KnownSubjectActiveProofSecretResponse, OutOfBandChallengeDedupeKey, RecordActiveProofFailure,
    ResendOutOfBandChallenge, ResendOutOfBandChallengeRequest, StartActiveProofAttempt,
    StartActiveProofAttemptForCurrentSession, StartActiveProofAttemptForCurrentTrustedDevice,
    StartAndIssueActiveProofMethodChallengeInput, StartAndIssueOutOfBandChallengeInput,
    StartCurrentSessionActiveProofAttemptInput, StartCurrentTrustedDeviceActiveProofAttemptInput,
    StatelessFastFailStatus, VerifiedWeakProofGateBeforeStateLoad, WeakProofGateKind,
    WeakProofGateResponse, WeakProofGateStatus, WeakProofGateSummary,
    WeakProofGateVerificationRequest, WeakProofGateVerifier,
};
pub(crate) use challenge_cookie_model::{
    ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES, ActiveProofChallengeCookieDraft,
    ActiveProofChallengeFastFailMac, ActiveProofChallengeFastFailNonce,
    ActiveProofChallengeResponseSecret,
};
use challenge_cookie_model::{
    online_guessing_risk_from_wire_id, online_guessing_risk_wire_id, proof_family_from_wire_id,
    proof_family_wire_id, proof_use_from_wire_id, proof_use_wire_id,
};
pub(crate) use command_model::*;
pub(crate) use commit_audit::*;
pub(crate) use commit_effect::*;
pub(crate) use commit_method::*;
pub(crate) use commit_mutation::*;
pub(crate) use commit_plan::*;
pub(crate) use commit_transaction_model::*;
pub(crate) use config_model::*;
pub(crate) use core_error::Error;
pub(crate) use execution_model::*;
pub(crate) use identity::*;
pub(crate) use input_limits::{
    ACTIVE_PROOF_METHOD_CHALLENGE_PRESENTATION_MAX_BYTES,
    ACTIVE_PROOF_METHOD_CHALLENGE_STATE_MAX_BYTES, ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
    CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_BYTES,
    CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_HASH_COUNT,
    DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES, ID_MAX_BYTES, METHOD_COMMIT_OPERATION_MAX_BYTES,
    METHOD_COMMIT_PAYLOAD_MAX_BYTES, METHOD_LABEL_MAX_BYTES,
    OUT_OF_BAND_CHALLENGE_DEDUPE_KEY_MAX_BYTES, OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
    TRUSTED_DEVICE_DISPLAY_LABEL_MAX_BYTES, WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES,
    WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES,
};
use input_limits::{
    validate_auth_bytes_not_too_long, validate_auth_identifier_string,
    validate_auth_string_not_too_long,
};
pub(crate) use load_contract_model::*;
pub(crate) use loaded_state_model::*;
pub(crate) use method_adapter_contract_model::*;
pub(crate) use outcome_model::*;
pub(crate) use postgres_adapter_execution_model::*;
pub(crate) use postgres_schema_model::*;
pub(crate) use proof_model::*;
pub(crate) use proof_policy::{
    ProofPolicy, ProofPolicyExactMethodLabels, ProofRequirement, ProofStackPolicy,
    ProofStackRequirement,
};
pub(crate) use response_materialization_model::*;
pub(crate) use runtime_adapter_model::*;
pub(crate) use runtime_orchestration_model::*;
pub(crate) use storage_adapter_boundary_model::*;
pub(crate) use storage_contract_model::*;
pub(crate) use web_transport_model::*;

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
    }
}

fn audit_event(
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

struct ActiveProofAuditEventInput {
    kind: AuditEventKind,
    occurred_at: UnixSeconds,
    subject_id: Option<SubjectId>,
    session_id: Option<SessionId>,
    device_credential_id: Option<TrustedDeviceCredentialId>,
    attempt_id: Option<ActiveProofAttemptId>,
    challenge_id: Option<ActiveProofChallengeId>,
    weak_proof_gate: Option<WeakProofGateSummary>,
}

fn active_proof_audit_event(input: ActiveProofAuditEventInput) -> AuditEvent {
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

fn transition(outcome: Outcome, commit_plan: CommitPlan) -> Transition {
    Transition {
        outcome,
        commit_plan,
    }
}

#[cfg(test)]
mod tests;
