use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm as TotpRsAlgorithm, TOTP as TotpRs};

use super::postgres_durable_effect_queue::{
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::postgres_method_runtime::{
    ActiveProofMethodChallengeBuild, CredentialCreationMethodWorkBuildRequest,
    CredentialLifecycleMethodWorkAuthority, CredentialLifecycleMethodWorkBuildRequest,
    CredentialMethodWorkBuild, CredentialResetMethodWorkBuildRequest,
    KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError,
    PostgresAuthMethodDurableEffectQueueRegistrationError,
    PostgresAuthMethodMountedRouteCapabilities, PostgresAuthMethodPlugin,
    VerifiedActiveProofMethodResponse,
    enqueue_no_method_durable_effects_to_queue_in_current_transaction,
    register_no_queue_handlers_for_method_durable_effects,
};
use super::postgres_method_schema::{
    MethodTableCheckConstraint, MethodTableColumnContract, MethodTableIndexContract,
    ensure_method_table_check_constraints_in_current_transaction, quoted_bigint_nonnegative,
    quoted_bigint_positive, quoted_len_at_least_one_and_at_most,
    validate_method_table_schema_in_current_transaction,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::prelude::*;
use crate::crypto::Keyset;
use crate::crypto::SecretBytes;
use crate::crypto::envelope::{decrypt_bytes_with_associated_data, encrypt_plaintext_bytes_as};
#[cfg(test)]
use crate::db::Pool;
#[cfg(test)]
use crate::db::pooler_safe_query_scalar;
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Tx, WriteTx, pooler_safe_query, queue, unparameterized_simple_query,
};

pub(crate) const TOTP_METHOD_LABEL: &str = "totp";
const TOTP_SECRET_CONTEXT: &[u8] = b"paranoid/auth/v1/totp-secret";
const DEFAULT_TOTP_TABLE_PREFIX: &str = "auth_totp_";
const TOTP_MIN_DIGIT_COUNT: usize = 6;
const TOTP_MAX_DIGIT_COUNT: usize = 8;
const TOTP_DEFAULT_DIGIT_COUNT: usize = 6;
const TOTP_DEFAULT_STEP_SECONDS: u64 = 30;
const TOTP_DEFAULT_ACCEPTED_ADJACENT_STEPS: u8 = 1;
const TOTP_CHALLENGE_BOUND_BLOOM_CONTEXT: &[u8] = b"paranoid/auth/v1/totp/challenge-bound-bloom";
const TOTP_CHALLENGE_BOUND_BLOOM_FILTER_BYTES: usize = 128;
const TOTP_CHALLENGE_BOUND_BLOOM_FILTER_HASH_COUNT: u8 = 10;
const TOTP_CHALLENGE_BOUND_MAX_ACCEPTED_CODES: usize = 512;
const TOTP_CHALLENGE_BOUND_PRESENTATION: &[u8] = b"totp-challenge-bound-bloom-v1";
const TOTP_SECRET_MIN_BYTES: usize = 16;
const TOTP_SECRET_MAX_BYTES: usize = 256;
const TOTP_VERIFIER_ABSENT_OPERATION: &str = "totp_verifier_absent";
const TOTP_VERIFIER_CURRENT_OPERATION: &str = "totp_verifier_current";
const TOTP_CREATE_VERIFIER_OPERATION: &str = "totp_create_verifier";
const TOTP_REPLACE_VERIFIER_OPERATION: &str = "totp_replace_verifier";

pub(crate) trait PostgresTotpCodeVerifier: Send + Sync {
    fn verify_totp_code(
        &self,
        secret: &SecretBytes,
        submitted_code: &[u8],
        now: UnixSeconds,
    ) -> Result<bool, PostgresTotpMethodError>;

    fn accepted_totp_codes_for_challenge_window(
        &self,
        secret: &SecretBytes,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Vec<KnownSubjectActiveProofSecretResponse>, PostgresTotpMethodError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StandardTotpCodeVerifier {
    config: StandardTotpCodeVerifierConfig,
}

impl StandardTotpCodeVerifier {
    pub(crate) fn new(
        config: StandardTotpCodeVerifierConfig,
    ) -> Result<Self, PostgresTotpMethodError> {
        config.validate()?;
        Ok(Self { config })
    }
}

impl PostgresTotpCodeVerifier for StandardTotpCodeVerifier {
    fn verify_totp_code(
        &self,
        secret: &SecretBytes,
        submitted_code: &[u8],
        now: UnixSeconds,
    ) -> Result<bool, PostgresTotpMethodError> {
        if submitted_code.len() != self.config.digit_count
            || submitted_code.iter().any(|byte| !byte.is_ascii_digit())
        {
            return Ok(false);
        }
        let totp = TotpRs::new(
            self.config.algorithm.into_totp_rs_algorithm(),
            self.config.digit_count,
            0,
            self.config.step_seconds,
            secret.expose_secret().to_vec(),
        )
        .map_err(PostgresTotpMethodError::Totp)?;

        let current_step = now.get() / self.config.step_seconds;
        let mut accepted = false;
        for step_index in self.config.accepted_step_indices(current_step)? {
            let Some(step_time) = step_index.checked_mul(self.config.step_seconds) else {
                return Err(PostgresTotpMethodError::Core(Error::TimeOverflow));
            };
            let expected_code = totp.generate(step_time);
            accepted |= bool::from(expected_code.as_bytes().ct_eq(submitted_code));
        }
        Ok(accepted)
    }

    fn accepted_totp_codes_for_challenge_window(
        &self,
        secret: &SecretBytes,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Vec<KnownSubjectActiveProofSecretResponse>, PostgresTotpMethodError> {
        if expires_at <= issued_at {
            return Err(PostgresTotpMethodError::Core(
                Error::ActiveProofChallengeCookieExpiresAtOrBeforeIssuedAt,
            ));
        }
        let totp = TotpRs::new(
            self.config.algorithm.into_totp_rs_algorithm(),
            self.config.digit_count,
            0,
            self.config.step_seconds,
            secret.expose_secret().to_vec(),
        )
        .map_err(PostgresTotpMethodError::Totp)?;
        let first_completion_step = issued_at.get() / self.config.step_seconds;
        let last_completion_step = expires_at
            .get()
            .checked_sub(1)
            .ok_or(PostgresTotpMethodError::Core(Error::TimeOverflow))?
            / self.config.step_seconds;
        let mut accepted_steps = BTreeSet::new();
        for completion_step in first_completion_step..=last_completion_step {
            for accepted_step in self.config.accepted_step_indices(completion_step)? {
                accepted_steps.insert(accepted_step);
                if accepted_steps.len() > TOTP_CHALLENGE_BOUND_MAX_ACCEPTED_CODES {
                    return Err(PostgresTotpMethodError::Core(Error::InvalidConfig(
                        "totp challenge window accepts too many codes for challenge-bound Bloom fast-fail",
                    )));
                }
            }
        }
        let mut codes = Vec::with_capacity(accepted_steps.len());
        for accepted_step in accepted_steps {
            let step_time = accepted_step
                .checked_mul(self.config.step_seconds)
                .ok_or(PostgresTotpMethodError::Core(Error::TimeOverflow))?;
            codes.push(
                KnownSubjectActiveProofSecretResponse::try_from_bytes(
                    totp.generate(step_time).into_bytes(),
                )
                .map_err(PostgresTotpMethodError::Core)?,
            );
        }
        Ok(codes)
    }
}

impl<T> PostgresTotpCodeVerifier for Arc<T>
where
    T: PostgresTotpCodeVerifier + ?Sized,
{
    fn verify_totp_code(
        &self,
        secret: &SecretBytes,
        submitted_code: &[u8],
        now: UnixSeconds,
    ) -> Result<bool, PostgresTotpMethodError> {
        self.as_ref().verify_totp_code(secret, submitted_code, now)
    }

    fn accepted_totp_codes_for_challenge_window(
        &self,
        secret: &SecretBytes,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Vec<KnownSubjectActiveProofSecretResponse>, PostgresTotpMethodError> {
        self.as_ref()
            .accepted_totp_codes_for_challenge_window(secret, issued_at, expires_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StandardTotpCodeVerifierConfig {
    algorithm: StandardTotpAlgorithm,
    digit_count: usize,
    step_seconds: u64,
    accepted_adjacent_steps: u8,
}

impl StandardTotpCodeVerifierConfig {
    pub(crate) fn new(
        algorithm: StandardTotpAlgorithm,
        digit_count: usize,
        step_seconds: u64,
        accepted_adjacent_steps: u8,
    ) -> Result<Self, PostgresTotpMethodError> {
        let config = Self {
            algorithm,
            digit_count,
            step_seconds,
            accepted_adjacent_steps,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), PostgresTotpMethodError> {
        if !(TOTP_MIN_DIGIT_COUNT..=TOTP_MAX_DIGIT_COUNT).contains(&self.digit_count) {
            return Err(PostgresTotpMethodError::Core(Error::InvalidConfig(
                "totp digit count must be between 6 and 8",
            )));
        }
        if self.step_seconds == 0 {
            return Err(PostgresTotpMethodError::Core(Error::InvalidConfig(
                "totp step seconds must be non-zero",
            )));
        }
        if self.accepted_adjacent_steps > 1 {
            return Err(PostgresTotpMethodError::Core(Error::InvalidConfig(
                "totp verifier may accept at most one adjacent time step",
            )));
        }
        Ok(())
    }

    fn accepted_step_indices(self, current_step: u64) -> Result<Vec<u64>, PostgresTotpMethodError> {
        let mut indices = Vec::with_capacity((self.accepted_adjacent_steps as usize * 2) + 1);
        for past_steps in (1..=self.accepted_adjacent_steps).rev() {
            if let Some(step_index) = current_step.checked_sub(past_steps as u64) {
                indices.push(step_index);
            }
        }
        indices.push(current_step);
        for future_steps in 1..=self.accepted_adjacent_steps {
            let Some(step_index) = current_step.checked_add(future_steps as u64) else {
                return Err(PostgresTotpMethodError::Core(Error::TimeOverflow));
            };
            indices.push(step_index);
        }
        Ok(indices)
    }
}

impl Default for StandardTotpCodeVerifierConfig {
    fn default() -> Self {
        Self {
            algorithm: StandardTotpAlgorithm::Sha1,
            digit_count: TOTP_DEFAULT_DIGIT_COUNT,
            step_seconds: TOTP_DEFAULT_STEP_SECONDS,
            accepted_adjacent_steps: TOTP_DEFAULT_ACCEPTED_ADJACENT_STEPS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StandardTotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl StandardTotpAlgorithm {
    fn into_totp_rs_algorithm(self) -> TotpRsAlgorithm {
        match self {
            Self::Sha1 => TotpRsAlgorithm::SHA1,
            Self::Sha256 => TotpRsAlgorithm::SHA256,
            Self::Sha512 => TotpRsAlgorithm::SHA512,
        }
    }
}

pub(crate) struct PostgresTotpMethodPlugin<V> {
    config: PostgresTotpMethodPluginConfig,
    method: ProofMethodDeclaration,
    secret_keyset: Keyset,
    verifier: V,
}

impl<V> PostgresTotpMethodPlugin<V>
where
    V: PostgresTotpCodeVerifier,
{
    pub(crate) fn new(
        config: PostgresTotpMethodPluginConfig,
        secret_keyset: Keyset,
        verifier: V,
    ) -> Result<Self, PostgresTotpMethodError> {
        Ok(Self {
            config,
            method: ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, TOTP_METHOD_LABEL)
                .map_err(PostgresTotpMethodError::Core)?,
            secret_keyset,
            verifier,
        })
    }

    fn build_verifier_creation_commit_work(
        &self,
        now: UnixSeconds,
        new_credential: &CredentialInstanceMetadata,
        method_payload: &CredentialCreationMethodPayload,
    ) -> Result<CredentialMethodWorkBuild, PostgresTotpMethodError> {
        self.validate_credential_target(new_credential)?;
        let payload = self.verifier_commit_payload(
            now,
            None,
            new_credential.credential_instance_id(),
            new_credential.subject_id(),
            method_payload.as_bytes(),
        )?;
        let encoded_payload = encode_totp_payload(&payload)?;
        let method_commit_work = MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(
                    TOTP_VERIFIER_ABSENT_OPERATION,
                    encoded_payload.clone(),
                )
                .map_err(PostgresTotpMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(TOTP_CREATE_VERIFIER_OPERATION, encoded_payload)
                    .map_err(PostgresTotpMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresTotpMethodError::Core)?;
        Ok(CredentialMethodWorkBuild::from_method_commit_work(vec![
            method_commit_work,
        ]))
    }

    fn build_verifier_reset_commit_work(
        &self,
        now: UnixSeconds,
        target_credential: &CredentialInstanceMetadata,
        method_payload: &CredentialResetMethodPayload,
    ) -> Result<Vec<MethodCommitWork>, PostgresTotpMethodError> {
        self.validate_credential_target(target_credential)?;
        self.verifier_replacement_commit_work(
            now,
            target_credential.credential_instance_id(),
            target_credential.credential_instance_id(),
            target_credential.subject_id(),
            method_payload.as_bytes(),
        )
    }

    fn build_verifier_lifecycle_commit_work(
        &self,
        now: UnixSeconds,
        target_credential: &CredentialInstanceMetadata,
        action: CredentialLifecycleAction,
        replacement_successor: Option<&CredentialReplacementSuccessor>,
        method_payload: &CredentialLifecycleMethodPayload,
    ) -> Result<CredentialMethodWorkBuild, PostgresTotpMethodError> {
        self.validate_credential_target(target_credential)?;
        let new_credential_id = match action {
            CredentialLifecycleAction::Replace => {
                let successor = replacement_successor.ok_or(PostgresTotpMethodError::Core(
                    Error::LoadedStateContradiction(
                        "totp replacement is missing successor credential metadata",
                    ),
                ))?;
                let successor_metadata = successor.metadata();
                if successor_metadata.subject_id() != target_credential.subject_id() {
                    return Err(PostgresTotpMethodError::Core(
                        Error::LoadedStateContradiction(
                            "totp replacement successor has a different subject",
                        ),
                    ));
                }
                if successor_metadata.proof_family() != self.method.family()
                    || successor_metadata.method_label() != self.method.method_label()
                {
                    return Err(PostgresTotpMethodError::Core(
                        Error::LoadedStateContradiction(
                            "totp replacement successor uses a different method",
                        ),
                    ));
                }
                successor_metadata.credential_instance_id()
            }
            CredentialLifecycleAction::Rotate => target_credential.credential_instance_id(),
            _ => {
                return Err(PostgresTotpMethodError::Core(
                    Error::LoadedStateContradiction(
                        "totp lifecycle method work supports only replacement and rotation",
                    ),
                ));
            }
        };
        let method_commit_work = self.verifier_replacement_commit_work(
            now,
            target_credential.credential_instance_id(),
            new_credential_id,
            target_credential.subject_id(),
            method_payload.as_bytes(),
        )?;
        Ok(CredentialMethodWorkBuild::from_method_commit_work(
            method_commit_work,
        ))
    }

    fn verifier_replacement_commit_work(
        &self,
        now: UnixSeconds,
        expected_credential_id: &VerifiedProofSourceId,
        new_credential_id: &VerifiedProofSourceId,
        subject_id: &SubjectId,
        method_payload: &[u8],
    ) -> Result<Vec<MethodCommitWork>, PostgresTotpMethodError> {
        let payload = self.verifier_commit_payload(
            now,
            Some(expected_credential_id),
            new_credential_id,
            subject_id,
            method_payload,
        )?;
        let encoded_payload = encode_totp_payload(&payload)?;
        let method_commit_work = MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(
                    TOTP_VERIFIER_CURRENT_OPERATION,
                    encoded_payload.clone(),
                )
                .map_err(PostgresTotpMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(TOTP_REPLACE_VERIFIER_OPERATION, encoded_payload)
                    .map_err(PostgresTotpMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresTotpMethodError::Core)?;
        Ok(vec![method_commit_work])
    }

    fn verifier_commit_payload(
        &self,
        now: UnixSeconds,
        expected_credential_id: Option<&VerifiedProofSourceId>,
        new_credential_id: &VerifiedProofSourceId,
        subject_id: &SubjectId,
        method_payload: &[u8],
    ) -> Result<TotpVerifierCommitPayload, PostgresTotpMethodError> {
        let material: TotpVerifierMethodPayload = decode_totp_payload(method_payload)?;
        validate_totp_secret(&material.secret)?;
        let encrypted_secret = encrypt_plaintext_bytes_as::<TotpSecretEnvelope>(
            &self.secret_keyset,
            &material.secret,
            &totp_secret_context(subject_id, new_credential_id),
        )
        .map_err(PostgresTotpMethodError::Crypto)?
        .into_bytes();
        Ok(TotpVerifierCommitPayload {
            expected_totp_credential_id: expected_credential_id
                .map(|credential_id| credential_id.as_bytes().to_vec()),
            new_totp_credential_id: new_credential_id.as_bytes().to_vec(),
            subject_id: subject_id.as_bytes().to_vec(),
            encrypted_secret,
            updated_at: now.get(),
        })
    }

    fn validate_credential_target(
        &self,
        credential: &CredentialInstanceMetadata,
    ) -> Result<(), PostgresTotpMethodError> {
        if credential.proof_family() != self.method.family()
            || credential.method_label() != self.method.method_label()
        {
            return Err(PostgresTotpMethodError::Core(
                Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch,
            ));
        }
        Ok(())
    }

    async fn verify_known_subject_response_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<KnownSubjectActiveProofMethodVerification, PostgresTotpMethodError> {
        if response.method != self.method {
            return Err(PostgresTotpMethodError::Core(
                Error::LoadedStateContradiction("totp response used a different method"),
            ));
        }
        let Some(verifier) = self.fetch_locked_verifier(tx, subject_id).await? else {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        };
        let secret = decrypt_bytes_with_associated_data(
            &self.secret_keyset,
            &verifier.encrypted_secret,
            &totp_secret_context(subject_id, &verifier.totp_credential_id),
        )
        .map_err(PostgresTotpMethodError::Crypto)?;
        if !self.verifier.verify_totp_code(
            &secret,
            response.secret_response.expose_secret(),
            response.now,
        )? {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        }
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            self.method.verified_proof_summary(),
            None,
            totp_proof_source(verifier.totp_credential_id),
        )
        .map_err(PostgresTotpMethodError::Core)?;
        Ok(KnownSubjectActiveProofMethodVerification::Accepted(
            VerifiedActiveProofMethodResponse::new(verified_proof, Vec::new())
                .map_err(PostgresTotpMethodError::Core)?,
        ))
    }

    async fn build_challenge_bound_challenge_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        request: &IssueActiveProofMethodChallengeRequest,
        subject_id: &SubjectId,
        challenge: &ActiveProofMethodChallengeSeed,
    ) -> Result<ActiveProofMethodChallengeBuild, PostgresTotpMethodError> {
        if request.method != self.method || challenge.proof != self.method.verified_proof_summary()
        {
            return Err(PostgresTotpMethodError::Core(
                Error::LoadedStateContradiction(
                    "totp challenge-bound issue used a different method",
                ),
            ));
        }
        let Some(verifier) = self.fetch_locked_verifier(tx, subject_id).await? else {
            return Err(PostgresTotpMethodError::Core(
                Error::LoadedStateContradiction(
                    "totp challenge-bound issue requires a configured verifier",
                ),
            ));
        };
        let secret = decrypt_bytes_with_associated_data(
            &self.secret_keyset,
            &verifier.encrypted_secret,
            &totp_secret_context(subject_id, &verifier.totp_credential_id),
        )
        .map_err(PostgresTotpMethodError::Crypto)?;
        let accepted_responses = self.verifier.accepted_totp_codes_for_challenge_window(
            &secret,
            challenge.issued_at,
            challenge.expires_at,
        )?;
        if accepted_responses.is_empty() {
            return Err(PostgresTotpMethodError::Core(Error::InvalidConfig(
                "totp challenge-bound Bloom fast-fail requires at least one accepted code",
            )));
        }
        let metadata = TotpChallengeBoundBloomMetadata {
            subject_id: subject_id.as_bytes().to_vec(),
            totp_credential_id: verifier.totp_credential_id.as_bytes().to_vec(),
            verifier_version: verifier.verifier_version,
        };
        let bloom_context = totp_challenge_bound_bloom_context(challenge, &metadata)?;
        let mut bloom = ChallengeBoundConfiguredSecretFastFailBloomFilter::new(
            TOTP_CHALLENGE_BOUND_BLOOM_FILTER_BYTES,
            TOTP_CHALLENGE_BOUND_BLOOM_FILTER_HASH_COUNT,
        )
        .map_err(PostgresTotpMethodError::Core)?;
        for response in &accepted_responses {
            bloom
                .insert_response_for_latest_key(&self.secret_keyset, &bloom_context, response)
                .map_err(PostgresTotpMethodError::Core)?;
        }
        let state = TotpChallengeBoundBloomState {
            version: 1,
            metadata,
            bloom_bitset: bloom.bitset_bytes().to_vec(),
            bloom_hash_count: bloom.hash_count(),
        };
        let encoded_state = encode_totp_payload(&state)?;
        let method_challenge_state = ActiveProofMethodChallengeState::try_from_bytes(encoded_state)
            .map_err(PostgresTotpMethodError::Core)?;
        let presentation = ActiveProofMethodChallengePresentation::try_from_bytes(
            TOTP_CHALLENGE_BOUND_PRESENTATION,
        )
        .map_err(PostgresTotpMethodError::Core)?;
        Ok(ActiveProofMethodChallengeBuild::new(
            presentation,
            method_challenge_state,
            Vec::new(),
        ))
    }

    fn verify_challenge_bound_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresTotpMethodError> {
        if challenge.proof != self.method.verified_proof_summary() {
            return Err(PostgresTotpMethodError::Core(
                Error::LoadedStateContradiction(
                    "totp challenge-bound completion used a different proof",
                ),
            ));
        }
        let state =
            decode_totp_challenge_bound_bloom_state(challenge.method_challenge_state.as_bytes())?;
        let bloom = ChallengeBoundConfiguredSecretFastFailBloomFilter::try_from_parts(
            state.bloom_bitset,
            state.bloom_hash_count,
        )
        .map_err(PostgresTotpMethodError::Core)?;
        let bloom_context =
            totp_challenge_bound_bloom_context_from_material(challenge, &state.metadata)?;
        if bloom
            .definitely_rejects_response_in_challenge_context(
                &self.secret_keyset,
                &bloom_context,
                &response.secret_response,
            )
            .map_err(PostgresTotpMethodError::Core)?
        {
            return Err(PostgresTotpMethodError::Core(
                Error::StatelessFastFailVerificationFailed,
            ));
        }
        Ok(())
    }

    async fn verify_challenge_bound_response_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Result<KnownSubjectActiveProofMethodVerification, PostgresTotpMethodError> {
        if challenge.proof != self.method.verified_proof_summary() {
            return Err(PostgresTotpMethodError::Core(
                Error::LoadedStateContradiction(
                    "totp challenge-bound completion used a different proof",
                ),
            ));
        }
        let state =
            decode_totp_challenge_bound_bloom_state(challenge.method_challenge_state.as_bytes())?;
        let state_subject_id = SubjectId::from_bytes(state.metadata.subject_id.clone())
            .map_err(PostgresTotpMethodError::Core)?;
        if &state_subject_id != subject_id {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        }
        let state_credential_id =
            VerifiedProofSourceId::from_bytes(state.metadata.totp_credential_id.clone())
                .map_err(PostgresTotpMethodError::Core)?;
        let Some(verifier) = self.fetch_locked_verifier(tx, subject_id).await? else {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        };
        if verifier.totp_credential_id != state_credential_id
            || verifier.verifier_version != state.metadata.verifier_version
        {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        }
        let secret = decrypt_bytes_with_associated_data(
            &self.secret_keyset,
            &verifier.encrypted_secret,
            &totp_secret_context(subject_id, &verifier.totp_credential_id),
        )
        .map_err(PostgresTotpMethodError::Crypto)?;
        if !self.verifier.verify_totp_code(
            &secret,
            response.secret_response.expose_secret(),
            response.now,
        )? {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        }
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            self.method.verified_proof_summary(),
            None,
            totp_proof_source(verifier.totp_credential_id),
        )
        .map_err(PostgresTotpMethodError::Core)?;
        Ok(KnownSubjectActiveProofMethodVerification::Accepted(
            VerifiedActiveProofMethodResponse::new(verified_proof, Vec::new())
                .map_err(PostgresTotpMethodError::Core)?,
        ))
    }

    async fn fetch_locked_verifier(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
    ) -> Result<Option<TotpVerifier>, PostgresTotpMethodError> {
        let statement = format!(
            r#"
            SELECT totp_credential_id, encrypted_secret, verifier_version
            FROM {}
            WHERE subject_id = $1
            FOR UPDATE
            "#,
            self.table_names()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.totp.verify.fetch_locked_verifier",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresTotpMethodError::Database)?
            .map(|row| {
                Ok(TotpVerifier {
                    totp_credential_id: VerifiedProofSourceId::from_bytes(
                        row.try_get::<Vec<u8>, _>("totp_credential_id")
                            .map_err(DbError::query)
                            .map_err(PostgresTotpMethodError::Database)?,
                    )
                    .map_err(PostgresTotpMethodError::Core)?,
                    encrypted_secret: row
                        .try_get::<Vec<u8>, _>("encrypted_secret")
                        .map_err(DbError::query)
                        .map_err(PostgresTotpMethodError::Database)?,
                    verifier_version: row
                        .try_get::<i64, _>("verifier_version")
                        .map_err(DbError::query)
                        .map_err(PostgresTotpMethodError::Database)?,
                })
            })
            .transpose()
    }

    fn table_names(&self) -> Result<TotpTableNames, PostgresTotpMethodError> {
        self.config.table_names()
    }

    fn table_names_for_commit(&self) -> Result<TotpTableNames, PostgresAuthMethodCommitError> {
        self.table_names().map_err(|error| match error {
            PostgresTotpMethodError::Database(error) => {
                PostgresAuthMethodCommitError::Database(error)
            }
            other => PostgresAuthMethodCommitError::InvalidOperation(other.to_string()),
        })
    }

    #[cfg(test)]
    pub(crate) fn verifier_table_name_for_test(
        &self,
    ) -> Result<PgQualifiedTableName, PostgresTotpMethodError> {
        Ok(self.table_names()?.verifier_table)
    }

    async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                totp_credential_id BYTEA PRIMARY KEY,
                subject_id BYTEA NOT NULL UNIQUE,
                encrypted_secret BYTEA NOT NULL,
                verifier_version BIGINT NOT NULL,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL,
                CHECK (octet_length(totp_credential_id) BETWEEN 1 AND {}),
                CHECK (octet_length(subject_id) BETWEEN 1 AND {}),
                CHECK (verifier_version > 0),
                CHECK (created_at >= 0),
                CHECK (updated_at >= 0)
            )
            "#,
            self.table_names_for_commit()?.verifier_table.quoted(),
            ID_MAX_BYTES,
            ID_MAX_BYTES,
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.totp.schema.create_verifier_table",
            Some(statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        let table = self.table_names_for_commit()?.verifier_table;
        let checks = totp_verifier_table_checks();
        ensure_method_table_check_constraints_in_current_transaction(tx, &table, &checks).await?;
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        validate_method_table_schema_in_current_transaction(
            tx,
            &self.table_names_for_commit()?.verifier_table,
            &totp_verifier_table_columns(),
            &totp_verifier_table_checks(),
            &totp_verifier_table_indexes(),
        )
        .await
    }

    async fn enforce_verifier_absent(
        &self,
        tx: &mut Tx<'_>,
        payload: &TotpVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            SELECT totp_credential_id
            FROM {}
            WHERE totp_credential_id = $1
                OR subject_id = $2
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "auth_core.totp.precondition.verifier_absent",
            Some(statement.as_str()),
        );
        let rows = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.new_totp_credential_id)
            .bind(&payload.subject_id)
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        if rows.is_empty() {
            Ok(())
        } else {
            Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "totp verifier already exists",
            ))
        }
    }

    async fn lock_current_verifier(
        &self,
        tx: &mut Tx<'_>,
        payload: &TotpVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let expected_credential_id =
            payload
                .expected_totp_credential_id
                .as_ref()
                .ok_or_else(|| {
                    PostgresAuthMethodCommitError::InvalidOperation(
                        "totp verifier precondition is missing target credential".to_owned(),
                    )
                })?;
        let statement = format!(
            r#"
            SELECT totp_credential_id
            FROM {}
            WHERE totp_credential_id = $1
                AND subject_id = $2
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.totp.precondition.verifier_current",
            Some(statement.as_str()),
        );
        let row = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(expected_credential_id)
            .bind(&payload.subject_id)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        if row.is_some() {
            Ok(())
        } else {
            Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "totp verifier is not current",
            ))
        }
    }

    async fn create_verifier(
        &self,
        tx: &mut Tx<'_>,
        payload: &TotpVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            INSERT INTO {} (
                totp_credential_id,
                subject_id,
                encrypted_secret,
                verifier_version,
                created_at,
                updated_at
            )
            VALUES ($1,$2,$3,1,$4,$4)
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.totp.mutation.create_verifier",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.new_totp_credential_id)
            .bind(&payload.subject_id)
            .bind(&payload.encrypted_secret)
            .bind(i64_from_totp_u64(payload.updated_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "totp verifier was not created",
            ));
        }
        Ok(())
    }

    async fn replace_verifier(
        &self,
        tx: &mut Tx<'_>,
        payload: &TotpVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let expected_credential_id =
            payload
                .expected_totp_credential_id
                .as_ref()
                .ok_or_else(|| {
                    PostgresAuthMethodCommitError::InvalidOperation(
                        "totp verifier mutation is missing target credential".to_owned(),
                    )
                })?;
        let statement = format!(
            r#"
            UPDATE {}
            SET totp_credential_id = $3,
                encrypted_secret = $4,
                verifier_version = CASE
                    WHEN totp_credential_id = $3 THEN verifier_version + 1
                    ELSE 1
                END,
                created_at = CASE
                    WHEN totp_credential_id = $3 THEN created_at
                    ELSE $5
                END,
                updated_at = $5
            WHERE totp_credential_id = $1
                AND subject_id = $2
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.totp.mutation.replace_verifier",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(expected_credential_id)
            .bind(&payload.subject_id)
            .bind(&payload.new_totp_credential_id)
            .bind(&payload.encrypted_secret)
            .bind(i64_from_totp_u64(payload.updated_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "totp verifier is not current",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn store_secret_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
        totp_credential_id: &VerifiedProofSourceId,
        secret: &[u8],
        now: UnixSeconds,
    ) -> Result<(), PostgresTotpMethodError> {
        let encrypted_secret = encrypt_plaintext_bytes_as::<TotpSecretEnvelope>(
            &self.secret_keyset,
            secret,
            &totp_secret_context(subject_id, totp_credential_id),
        )
        .map_err(PostgresTotpMethodError::Crypto)?
        .into_bytes();
        let statement = format!(
            r#"
            INSERT INTO {} (
                totp_credential_id,
                subject_id,
                encrypted_secret,
                verifier_version,
                created_at,
                updated_at
            )
            VALUES ($1,$2,$3,1,$4,$4)
            ON CONFLICT (subject_id)
            DO UPDATE SET
                totp_credential_id = EXCLUDED.totp_credential_id,
                encrypted_secret = EXCLUDED.encrypted_secret,
                verifier_version = {}.verifier_version + 1,
                updated_at = EXCLUDED.updated_at
            "#,
            self.table_names()?.verifier_table.quoted(),
            self.table_names()?.verifier_table.quoted(),
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresTotpMethodError::Database)?;
        let result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(totp_credential_id.as_bytes())
            .bind(subject_id.as_bytes())
            .bind(encrypted_secret)
            .bind(i64_from_unix_seconds_for_method(now)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresTotpMethodError::Database)
            .map(|_| ());
        match result {
            Ok(()) => tx.commit().await.map_err(PostgresTotpMethodError::Database),
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn count_verifiers_for_subject_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
    ) -> Result<i64, PostgresTotpMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE subject_id = $1",
            self.table_names()?.verifier_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresTotpMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresTotpMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresTotpMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) async fn verifier_version_for_subject_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
    ) -> Result<Option<i64>, PostgresTotpMethodError> {
        let statement = format!(
            "SELECT verifier_version FROM {} WHERE subject_id = $1",
            self.table_names()?.verifier_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresTotpMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresTotpMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresTotpMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) fn verifier_creation_payload_for_test(
        secret: &[u8],
    ) -> Result<CredentialCreationMethodPayload, PostgresTotpMethodError> {
        CredentialCreationMethodPayload::try_from_bytes(encode_totp_payload(
            &TotpVerifierMethodPayload {
                secret: secret.to_vec(),
            },
        )?)
        .map_err(PostgresTotpMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn verifier_reset_payload_for_test(
        secret: &[u8],
    ) -> Result<CredentialResetMethodPayload, PostgresTotpMethodError> {
        CredentialResetMethodPayload::try_from_bytes(encode_totp_payload(
            &TotpVerifierMethodPayload {
                secret: secret.to_vec(),
            },
        )?)
        .map_err(PostgresTotpMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn verifier_lifecycle_payload_for_test(
        secret: &[u8],
    ) -> Result<CredentialLifecycleMethodPayload, PostgresTotpMethodError> {
        CredentialLifecycleMethodPayload::try_from_bytes(encode_totp_payload(
            &TotpVerifierMethodPayload {
                secret: secret.to_vec(),
            },
        )?)
        .map_err(PostgresTotpMethodError::Core)
    }
}

impl<V> PostgresAuthMethodPlugin for PostgresTotpMethodPlugin<V>
where
    V: PostgresTotpCodeVerifier,
{
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn mounted_route_capabilities(&self) -> PostgresAuthMethodMountedRouteCapabilities {
        PostgresAuthMethodMountedRouteCapabilities::empty()
            .with_credential_creation()
            .with_credential_reset()
            .with_credential_replacement()
            .with_credential_rotation()
    }

    fn build_challenge_bound_known_subject_active_proof_method_challenge<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: &'a IssueActiveProofMethodChallengeRequest,
        subject_id: &'a SubjectId,
        challenge: &'a ActiveProofMethodChallengeSeed,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<ActiveProofMethodChallengeBuild, PostgresAuthMethodBuildError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.build_challenge_bound_challenge_in_current_transaction(
                tx, request, subject_id, challenge,
            )
            .await
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "challenge_bound_known_subject_active_proof_method_challenge_issue",
                    error,
                )
            })
        })
    }

    fn verify_challenge_bound_known_subject_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresAuthMethodBuildError> {
        self.verify_challenge_bound_response_before_state_load(challenge, response)
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "challenge_bound_known_subject_active_proof_completion",
                    error,
                )
            })
    }

    fn verify_challenge_bound_known_subject_active_proof_method_response<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        subject_id: &'a SubjectId,
        challenge: &'a ActiveProofMethodChallengeMaterial,
        response: &'a CompleteChallengeBoundKnownSubjectActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        KnownSubjectActiveProofMethodVerification,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.verify_challenge_bound_response_in_current_transaction(
                tx, subject_id, challenge, response,
            )
            .await
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "challenge_bound_known_subject_active_proof_completion",
                    error,
                )
            })
        })
    }

    fn verify_known_subject_active_proof_method_response<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        subject_id: &'a SubjectId,
        response: &'a CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        KnownSubjectActiveProofMethodVerification,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.verify_known_subject_response_in_current_transaction(tx, subject_id, response)
                .await
                .map_err(|error| {
                    PostgresAuthMethodBuildError::plugin_rejected(
                        &self.method,
                        "known_subject_active_proof_completion",
                        error,
                    )
                })
        })
    }

    fn build_credential_reset_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: CredentialResetMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<MethodCommitWork>, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let _ = request.authority;
            self.build_verifier_reset_commit_work(
                request.now,
                request.target_credential,
                request.method_payload,
            )
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "credential_reset",
                    error,
                )
            })
        })
    }

    fn build_credential_creation_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: CredentialCreationMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<CredentialMethodWorkBuild, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.build_verifier_creation_commit_work(
                request.now,
                request.new_credential,
                request.method_payload,
            )
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "credential_creation",
                    error,
                )
            })
        })
    }

    fn build_credential_lifecycle_commit_work<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        request: CredentialLifecycleMethodWorkBuildRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<CredentialMethodWorkBuild, PostgresAuthMethodBuildError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            match (request.action, request.authority) {
                (
                    CredentialLifecycleAction::Replace,
                    CredentialLifecycleMethodWorkAuthority::ImmediateReplacement { .. }
                    | CredentialLifecycleMethodWorkAuthority::MaturePendingAction { .. },
                )
                | (
                    CredentialLifecycleAction::Rotate,
                    CredentialLifecycleMethodWorkAuthority::ImmediateRotation { .. },
                ) => self
                    .build_verifier_lifecycle_commit_work(
                        request.now,
                        request.target_credential,
                        request.action,
                        request.replacement_successor,
                        request.method_payload,
                    )
                    .map_err(|error| {
                        PostgresAuthMethodBuildError::plugin_rejected(
                            &self.method,
                            "credential_lifecycle",
                            error,
                        )
                    }),
                _ => Err(PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "credential_lifecycle",
                    "totp method supports only replacement and rotation lifecycle work",
                )),
            }
        })
    }

    fn migrate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move { self.migrate_schema_in_current_transaction(tx).await })
    }

    fn validate_schema<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move { self.validate_schema_in_current_transaction(tx).await })
    }

    fn enforce_precondition<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            match precondition.operation().as_str() {
                TOTP_VERIFIER_ABSENT_OPERATION => {
                    let payload = decode_totp_verifier_commit_payload(precondition.payload())?;
                    self.enforce_verifier_absent(tx, &payload).await
                }
                TOTP_VERIFIER_CURRENT_OPERATION => {
                    let payload = decode_totp_verifier_commit_payload(precondition.payload())?;
                    self.lock_current_verifier(tx, &payload).await
                }
                other => Err(PostgresAuthMethodCommitError::InvalidOperation(
                    other.to_owned(),
                )),
            }
        })
    }

    fn apply_mutation<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            match mutation.operation().as_str() {
                TOTP_CREATE_VERIFIER_OPERATION => {
                    let payload = decode_totp_verifier_commit_payload(mutation.payload())?;
                    self.create_verifier(tx, &payload).await
                }
                TOTP_REPLACE_VERIFIER_OPERATION => {
                    let payload = decode_totp_verifier_commit_payload(mutation.payload())?;
                    self.replace_verifier(tx, &payload).await
                }
                other => Err(PostgresAuthMethodCommitError::InvalidOperation(
                    other.to_owned(),
                )),
            }
        })
    }

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            Err(PostgresAuthMethodCommitError::InvalidOperation(
                command.operation().as_str().to_owned(),
            ))
        })
    }

    fn register_durable_effect_queue_handlers(
        &self,
        task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError> {
        register_no_queue_handlers_for_method_durable_effects(task_registry)
    }

    fn enqueue_available_durable_effects_to_queue_in_current_transaction<'a, 'tx>(
        &'a self,
        tx: &'a mut WriteTx<'tx>,
        queue_store: &'a queue::Store,
        limit: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresAuthDurableEffectQueueDispatchSummary,
                        PostgresAuthDurableEffectQueueDispatchError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        enqueue_no_method_durable_effects_to_queue_in_current_transaction(
            tx,
            queue_store,
            limit,
            enqueued_at,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresTotpMethodPluginConfig {
    schema: Option<PgSchemaName>,
    table_prefix: PgIdentifier,
}

impl PostgresTotpMethodPluginConfig {
    pub(crate) fn new(
        schema: Option<PgSchemaName>,
        table_prefix: PgIdentifier,
    ) -> Result<Self, PostgresTotpMethodError> {
        let config = Self {
            schema,
            table_prefix,
        };
        config.table_names()?;
        Ok(config)
    }

    pub(crate) fn for_db_bootstrap_config(
        bootstrap_config: &BootstrapConfig,
    ) -> Result<Self, PostgresTotpMethodError> {
        Self::new(
            Some(bootstrap_config.schema_name().clone()),
            PgIdentifier::new(DEFAULT_TOTP_TABLE_PREFIX)
                .map_err(DbError::from)
                .map_err(PostgresTotpMethodError::Database)?,
        )
    }

    fn table_name(&self, suffix: &'static str) -> Result<PgQualifiedTableName, DbError> {
        Ok(PgQualifiedTableName::new(
            self.schema.clone(),
            PgIdentifier::new(format!("{}{}", self.table_prefix.as_str(), suffix))?,
        ))
    }

    fn table_names(&self) -> Result<TotpTableNames, PostgresTotpMethodError> {
        Ok(TotpTableNames {
            verifier_table: self
                .table_name("verifiers")
                .map_err(PostgresTotpMethodError::Database)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SHA1_SECRET: &[u8] = b"12345678901234567890";
    const RFC_SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const RFC_SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn config_for_db_bootstrap_uses_schema_local_bootstrap_tables() {
        let bootstrap_config =
            BootstrapConfig::from_schema_name_text("__paranoid").expect("bootstrap config");
        let config = PostgresTotpMethodPluginConfig::for_db_bootstrap_config(&bootstrap_config)
            .expect("totp method config");
        let table_names = config.table_names().expect("table names");

        assert_eq!(
            table_names.verifier_table.schema(),
            Some(bootstrap_config.schema_name())
        );
        assert_eq!(
            table_names.verifier_table.table().as_str(),
            "auth_totp_verifiers"
        );
    }

    #[test]
    fn standard_totp_verifier_matches_rfc6238_sha1_vectors() {
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha1,
            RFC_SHA1_SECRET,
            59,
            b"94287082",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha1,
            RFC_SHA1_SECRET,
            1_111_111_109,
            b"07081804",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha1,
            RFC_SHA1_SECRET,
            1_111_111_111,
            b"14050471",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha1,
            RFC_SHA1_SECRET,
            1_234_567_890,
            b"89005924",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha1,
            RFC_SHA1_SECRET,
            2_000_000_000,
            b"69279037",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha1,
            RFC_SHA1_SECRET,
            20_000_000_000,
            b"65353130",
        );
    }

    #[test]
    fn standard_totp_verifier_matches_rfc6238_sha256_vectors() {
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha256,
            RFC_SHA256_SECRET,
            59,
            b"46119246",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha256,
            RFC_SHA256_SECRET,
            1_111_111_109,
            b"68084774",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha256,
            RFC_SHA256_SECRET,
            1_111_111_111,
            b"67062674",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha256,
            RFC_SHA256_SECRET,
            1_234_567_890,
            b"91819424",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha256,
            RFC_SHA256_SECRET,
            2_000_000_000,
            b"90698825",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha256,
            RFC_SHA256_SECRET,
            20_000_000_000,
            b"77737706",
        );
    }

    #[test]
    fn standard_totp_verifier_matches_rfc6238_sha512_vectors() {
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha512,
            RFC_SHA512_SECRET,
            59,
            b"90693936",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha512,
            RFC_SHA512_SECRET,
            1_111_111_109,
            b"25091201",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha512,
            RFC_SHA512_SECRET,
            1_111_111_111,
            b"99943326",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha512,
            RFC_SHA512_SECRET,
            1_234_567_890,
            b"93441116",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha512,
            RFC_SHA512_SECRET,
            2_000_000_000,
            b"38618901",
        );
        assert_rfc6238_vector(
            StandardTotpAlgorithm::Sha512,
            RFC_SHA512_SECRET,
            20_000_000_000,
            b"47863826",
        );
    }

    #[test]
    fn standard_totp_verifier_accepts_adjacent_steps_when_configured() {
        let secret = SecretBytes::try_from(RFC_SHA1_SECRET).expect("secret");
        let verifier = StandardTotpCodeVerifier::new(
            StandardTotpCodeVerifierConfig::new(StandardTotpAlgorithm::Sha1, 8, 30, 1)
                .expect("config"),
        )
        .expect("verifier");

        assert!(
            verifier
                .verify_totp_code(&secret, b"94287082", UnixSeconds::new(89))
                .expect("verify")
        );
        assert!(
            !verifier
                .verify_totp_code(&secret, b"94287082", UnixSeconds::new(90))
                .expect("verify")
        );
    }

    #[test]
    fn standard_totp_verifier_rejects_malformed_submissions_without_error() {
        let secret = SecretBytes::try_from(RFC_SHA1_SECRET).expect("secret");
        let verifier = StandardTotpCodeVerifier::new(
            StandardTotpCodeVerifierConfig::new(StandardTotpAlgorithm::Sha1, 8, 30, 0)
                .expect("config"),
        )
        .expect("verifier");

        assert!(
            !verifier
                .verify_totp_code(&secret, b"9428708", UnixSeconds::new(59))
                .expect("short code rejects")
        );
        assert!(
            !verifier
                .verify_totp_code(&secret, b"9428708x", UnixSeconds::new(59))
                .expect("non-digit code rejects")
        );
        assert!(
            !verifier
                .verify_totp_code(&secret, b"942870821", UnixSeconds::new(59))
                .expect("long code rejects")
        );
    }

    #[test]
    fn standard_totp_verifier_rejects_invalid_config() {
        assert!(
            StandardTotpCodeVerifierConfig::new(StandardTotpAlgorithm::Sha1, 5, 30, 0).is_err()
        );
        assert!(
            StandardTotpCodeVerifierConfig::new(StandardTotpAlgorithm::Sha1, 9, 30, 0).is_err()
        );
        assert!(StandardTotpCodeVerifierConfig::new(StandardTotpAlgorithm::Sha1, 6, 0, 0).is_err());
        assert!(
            StandardTotpCodeVerifierConfig::new(StandardTotpAlgorithm::Sha1, 6, 30, 2).is_err()
        );
    }

    fn assert_rfc6238_vector(
        algorithm: StandardTotpAlgorithm,
        secret: &[u8],
        now: u64,
        expected_code: &[u8],
    ) {
        let secret = SecretBytes::try_from(secret).expect("secret");
        let verifier = StandardTotpCodeVerifier::new(
            StandardTotpCodeVerifierConfig::new(algorithm, 8, 30, 0).expect("config"),
        )
        .expect("verifier");

        assert!(
            verifier
                .verify_totp_code(&secret, expected_code, UnixSeconds::new(now))
                .expect("verify")
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TotpTableNames {
    verifier_table: PgQualifiedTableName,
}

#[derive(Debug)]
pub(crate) enum PostgresTotpMethodError {
    Core(Error),
    Crypto(crate::crypto::Error),
    Database(DbError),
    PayloadEncode(postcard::Error),
    PayloadDecode(postcard::Error),
    Totp(totp_rs::TotpUrlError),
}

impl fmt::Display for PostgresTotpMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Database(error) => write!(f, "{error}"),
            Self::PayloadEncode(error) => write!(f, "{error}"),
            Self::PayloadDecode(error) => write!(f, "{error}"),
            Self::Totp(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PostgresTotpMethodError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::PayloadEncode(error) => Some(error),
            Self::PayloadDecode(error) => Some(error),
            Self::Totp(error) => Some(error),
        }
    }
}

enum TotpSecretEnvelope {}

struct TotpVerifier {
    totp_credential_id: VerifiedProofSourceId,
    encrypted_secret: Vec<u8>,
    verifier_version: i64,
}

#[derive(Deserialize, Serialize)]
struct TotpVerifierMethodPayload {
    secret: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct TotpVerifierCommitPayload {
    expected_totp_credential_id: Option<Vec<u8>>,
    new_totp_credential_id: Vec<u8>,
    subject_id: Vec<u8>,
    encrypted_secret: Vec<u8>,
    updated_at: u64,
}

#[derive(Deserialize, Serialize)]
struct TotpChallengeBoundBloomState {
    version: u8,
    metadata: TotpChallengeBoundBloomMetadata,
    bloom_bitset: Vec<u8>,
    bloom_hash_count: u8,
}

#[derive(Deserialize, Serialize)]
struct TotpChallengeBoundBloomMetadata {
    subject_id: Vec<u8>,
    totp_credential_id: Vec<u8>,
    verifier_version: i64,
}

fn totp_secret_context(
    subject_id: &SubjectId,
    totp_credential_id: &VerifiedProofSourceId,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        TOTP_SECRET_CONTEXT.len()
            + 16
            + subject_id.as_bytes().len()
            + totp_credential_id.as_bytes().len(),
    );
    context.extend_from_slice(TOTP_SECRET_CONTEXT);
    push_len_prefixed_bytes(&mut context, subject_id.as_bytes());
    push_len_prefixed_bytes(&mut context, totp_credential_id.as_bytes());
    context
}

fn totp_proof_source(totp_credential_id: VerifiedProofSourceId) -> VerifiedProofSource {
    VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        totp_credential_id,
    )
}

fn push_len_prefixed_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    target.extend_from_slice(bytes);
}

fn totp_challenge_bound_bloom_context(
    challenge: &ActiveProofMethodChallengeSeed,
    metadata: &TotpChallengeBoundBloomMetadata,
) -> Result<Vec<u8>, PostgresTotpMethodError> {
    let mut context = Vec::new();
    push_len_prefixed_bytes(&mut context, TOTP_CHALLENGE_BOUND_BLOOM_CONTEXT);
    push_len_prefixed_bytes(&mut context, challenge.attempt_id.as_bytes());
    push_len_prefixed_bytes(&mut context, challenge.challenge_id.as_bytes());
    push_len_prefixed_bytes(
        &mut context,
        &[proof_family_wire_id(challenge.proof.family())],
    );
    push_len_prefixed_bytes(
        &mut context,
        &[online_guessing_risk_wire_id(
            challenge.proof.online_guessing_risk(),
        )],
    );
    push_len_prefixed_bytes(&mut context, challenge.proof.method_label().as_bytes());
    push_len_prefixed_bytes(&mut context, &challenge.issued_at.get().to_be_bytes());
    push_len_prefixed_bytes(&mut context, &challenge.expires_at.get().to_be_bytes());
    push_len_prefixed_bytes(&mut context, challenge.nonce.as_bytes());
    push_len_prefixed_bytes(&mut context, &metadata.subject_id);
    push_len_prefixed_bytes(&mut context, &metadata.totp_credential_id);
    push_len_prefixed_bytes(&mut context, &metadata.verifier_version.to_be_bytes());
    Ok(context)
}

fn totp_challenge_bound_bloom_context_from_material(
    challenge: &ActiveProofMethodChallengeMaterial,
    metadata: &TotpChallengeBoundBloomMetadata,
) -> Result<Vec<u8>, PostgresTotpMethodError> {
    totp_challenge_bound_bloom_context(
        &ActiveProofMethodChallengeSeed {
            attempt_id: challenge.attempt_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            proof: challenge.proof.clone(),
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
            nonce: challenge.nonce.clone(),
        },
        metadata,
    )
}

fn encode_totp_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>, PostgresTotpMethodError> {
    postcard::to_allocvec(payload).map_err(PostgresTotpMethodError::PayloadEncode)
}

fn decode_totp_payload<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
) -> Result<T, PostgresTotpMethodError> {
    postcard::from_bytes(payload).map_err(PostgresTotpMethodError::PayloadDecode)
}

fn validate_totp_secret(secret: &[u8]) -> Result<(), PostgresTotpMethodError> {
    if !(TOTP_SECRET_MIN_BYTES..=TOTP_SECRET_MAX_BYTES).contains(&secret.len()) {
        return Err(PostgresTotpMethodError::Core(Error::InvalidConfig(
            "totp secret length is outside the supported range",
        )));
    }
    Ok(())
}

fn decode_totp_verifier_commit_payload(
    payload: &[u8],
) -> Result<TotpVerifierCommitPayload, PostgresAuthMethodCommitError> {
    let payload: TotpVerifierCommitPayload = postcard::from_bytes(payload).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "invalid totp verifier commit payload".to_owned(),
        )
    })?;
    validate_totp_verifier_commit_payload(&payload)?;
    Ok(payload)
}

fn validate_totp_verifier_commit_payload(
    payload: &TotpVerifierCommitPayload,
) -> Result<(), PostgresAuthMethodCommitError> {
    if let Some(expected) = payload.expected_totp_credential_id.as_ref() {
        VerifiedProofSourceId::from_bytes(expected.clone()).map_err(|_| {
            PostgresAuthMethodCommitError::InvalidOperation(
                "invalid totp target credential id".to_owned(),
            )
        })?;
    }
    VerifiedProofSourceId::from_bytes(payload.new_totp_credential_id.clone()).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation("invalid totp new credential id".to_owned())
    })?;
    SubjectId::from_bytes(payload.subject_id.clone()).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation("invalid totp subject id".to_owned())
    })?;
    if payload.encrypted_secret.is_empty() {
        return Err(PostgresAuthMethodCommitError::InvalidOperation(
            "invalid totp encrypted secret".to_owned(),
        ));
    }
    i64_from_totp_u64(payload.updated_at)?;
    Ok(())
}

fn decode_totp_challenge_bound_bloom_state(
    payload: &[u8],
) -> Result<TotpChallengeBoundBloomState, PostgresTotpMethodError> {
    let state: TotpChallengeBoundBloomState = decode_totp_payload(payload)?;
    if state.version != 1 {
        return Err(PostgresTotpMethodError::Core(
            Error::InvalidActiveProofChallengeCookiePayload,
        ));
    }
    SubjectId::from_bytes(state.metadata.subject_id.clone())
        .map_err(PostgresTotpMethodError::Core)?;
    VerifiedProofSourceId::from_bytes(state.metadata.totp_credential_id.clone())
        .map_err(PostgresTotpMethodError::Core)?;
    Ok(state)
}

fn i64_from_totp_u64(value: u64) -> Result<i64, PostgresAuthMethodCommitError> {
    i64::try_from(value).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "totp timestamp exceeds Postgres BIGINT domain".to_owned(),
        )
    })
}

fn i64_from_unix_seconds_for_method(value: UnixSeconds) -> Result<i64, PostgresTotpMethodError> {
    i64::try_from(value.get()).map_err(|_| PostgresTotpMethodError::Core(Error::TimeOverflow))
}

fn totp_verifier_table_columns() -> Vec<MethodTableColumnContract> {
    vec![
        MethodTableColumnContract::bytea("totp_credential_id", true),
        MethodTableColumnContract::bytea("subject_id", true),
        MethodTableColumnContract::bytea("encrypted_secret", true),
        MethodTableColumnContract::bigint("verifier_version", true),
        MethodTableColumnContract::bigint("created_at", true),
        MethodTableColumnContract::bigint("updated_at", true),
    ]
}

fn totp_verifier_table_checks() -> Vec<MethodTableCheckConstraint> {
    vec![
        MethodTableCheckConstraint::new(
            "credential_id_len",
            quoted_len_at_least_one_and_at_most("totp_credential_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "subject_id_len",
            quoted_len_at_least_one_and_at_most("subject_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "encrypted_secret_nonempty",
            r#"octet_length("encrypted_secret") > 0"#,
        ),
        MethodTableCheckConstraint::new(
            "verifier_version_positive",
            quoted_bigint_positive("verifier_version"),
        ),
        MethodTableCheckConstraint::new(
            "created_at_nonnegative",
            quoted_bigint_nonnegative("created_at"),
        ),
        MethodTableCheckConstraint::new(
            "updated_at_nonnegative",
            quoted_bigint_nonnegative("updated_at"),
        ),
    ]
}

fn totp_verifier_table_indexes() -> Vec<MethodTableIndexContract> {
    vec![
        MethodTableIndexContract::unique("verifier primary-key", ["totp_credential_id"]),
        MethodTableIndexContract::unique("subject lookup", ["subject_id"]),
    ]
}
