use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::crypto::Keyset;
use crate::crypto::envelope::{decrypt_bytes_with_associated_data, encrypt_plaintext_bytes_as};
#[cfg(test)]
use crate::db::Pool;
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Tx, WriteTx, pooler_safe_query, pooler_safe_query_as, pooler_safe_query_scalar,
    unparameterized_simple_query,
};
use crate::db::{queue, queue::EnqueueOptions};

use super::postgres_durable_effect_queue::{
    AuthDurableEffectDeliveryError, AuthDurableEffectDeliveryFuture,
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::postgres_method_runtime::{
    PostgresAuthMethodDurableEffectQueueRegistrationError,
    PostgresAuthMethodMountedRouteCapabilities, PostgresAuthMethodPlugin,
    PostgresOutOfBandChallengeStartBuild, PostgresOutOfBandChallengeStartBuildRequest,
};
use super::postgres_method_schema::{
    MethodTableCheckConstraint, MethodTableColumnContract, MethodTableIndexContract,
    ensure_method_table_check_constraints_in_current_transaction, quoted_bigint_nonnegative,
    quoted_len_at_least_one_and_at_most, quoted_null_pair_matches,
    quoted_nullable_bigint_nonnegative, quoted_nullable_len_equals,
    validate_method_table_schema_in_current_transaction,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::prelude::*;

pub(crate) const EMAIL_OTP_METHOD_LABEL: &str = "email_otp";
const EMAIL_OTP_CLOSE_REPLACEABLE_CHALLENGES_BEFORE_ISSUE_OPERATION: &str =
    "email_otp_close_replaceable_challenges_before_issue";
const EMAIL_OTP_CHALLENGE_OPEN_OPERATION: &str = "email_otp_challenge_open";
const EMAIL_OTP_STORE_CHALLENGE_OPERATION: &str = "email_otp_store_challenge";
const EMAIL_OTP_CONSUME_CHALLENGE_OPERATION: &str = "email_otp_consume_challenge";
const EMAIL_OTP_QUEUE_DELIVERY_OPERATION: &str = "email_otp_queue_delivery";
pub(crate) const EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME: &str =
    "paranoid.auth.method.email_otp.delivery.v1";
const EMAIL_OTP_CHALLENGE_DEDUPE_KEY_PREFIX: &str = "paranoid.auth.method.email_otp.challenge.";
const EMAIL_OTP_CHALLENGE_DEDUPE_CONTEXT: &[u8] = b"paranoid/auth/v1/email-otp/challenge-dedupe";
const EMAIL_OTP_DELIVERY_IDEMPOTENCY_KEY_PREFIX: &str =
    "paranoid.auth.method.email_otp.delivery-attempt.";
const EMAIL_OTP_DELIVERY_IDEMPOTENCY_CONTEXT: &[u8] =
    b"paranoid/auth/v1/email-otp/delivery-idempotency";
const EMAIL_OTP_DELIVERY_QUEUE_DEDUPE_KEY_PREFIX: &str = "paranoid.auth.method.email_otp.delivery.";
const EMAIL_OTP_DELIVERY_QUEUE_DEDUPE_CONTEXT: &[u8] =
    b"paranoid/auth/v1/email-otp/delivery-queue-dedupe";
const EMAIL_OTP_RESPONSE_SECRET_CONTEXT: &[u8] = b"paranoid/auth/v1/email-otp-response-secret";
const EMAIL_OTP_DEFAULT_SOURCE_ID_CONTEXT: &[u8] = b"paranoid/auth/v1/email-otp/default-source-id";
const EMAIL_OTP_RESPONSE_SECRET_BYTES: usize = 16;
const DEFAULT_EMAIL_OTP_TABLE_PREFIX: &str = "auth_email_otp_";

pub(crate) struct PostgresEmailOtpMethodPlugin {
    config: PostgresEmailOtpMethodPluginConfig,
    method: ProofMethodDeclaration,
    response_secret_keyset: Arc<Keyset>,
    subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    delivery_message_deliverer: Option<Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer>>,
}

impl PostgresEmailOtpMethodPlugin {
    pub(crate) fn new(
        config: PostgresEmailOtpMethodPluginConfig,
        response_secret_keyset: Keyset,
    ) -> Result<Self, PostgresEmailOtpMethodError> {
        Ok(Self {
            config,
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, EMAIL_OTP_METHOD_LABEL)
                .map_err(PostgresEmailOtpMethodError::Core)?,
            response_secret_keyset: Arc::new(response_secret_keyset),
            subject_resolver: Arc::new(NoopEmailOtpSubjectResolver),
            delivery_message_deliverer: None,
        })
    }

    pub(crate) fn with_subject_resolver(
        mut self,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Self {
        self.subject_resolver = subject_resolver;
        self
    }

    pub(crate) fn with_delivery_message_deliverer(
        mut self,
        delivery_message_deliverer: Arc<dyn PostgresEmailOtpDeliveryMessageDeliverer>,
    ) -> Self {
        self.delivery_message_deliverer = Some(delivery_message_deliverer);
        self
    }

    pub(crate) fn issue_challenge_request(
        &self,
        input: EmailOtpIssueChallenge,
    ) -> Result<IssueOutOfBandChallengeInput, PostgresEmailOtpMethodError> {
        validate_email_otp_recipient_handle(&input.recipient_handle)?;
        validate_email_otp_delivery_idempotency_key(&input.delivery_idempotency_key)?;
        Ok(IssueOutOfBandChallengeInput {
            now: input.now,
            method: self.method.clone(),
            challenge_dedupe_key: input.challenge_dedupe_key,
            recipient_handle: input.recipient_handle,
            idempotency_key: input.delivery_idempotency_key,
        })
    }

    fn build_method_derived_out_of_band_challenge_start(
        &self,
        request: &PostgresOutOfBandChallengeStartBuildRequest<'_>,
    ) -> Result<PostgresOutOfBandChallengeStartBuild, PostgresEmailOtpMethodError> {
        let recipient_handle =
            email_otp_recipient_handle_from_start_payload(request.method_payload)?;
        let challenge_dedupe_key =
            email_otp_challenge_dedupe_key(request.proof_use, &self.method, &recipient_handle)?;
        let idempotency_key = email_otp_delivery_idempotency_key(
            request.proof_use,
            &self.method,
            request.attempt_id,
            request.challenge_id,
            &recipient_handle,
        )?;
        PostgresOutOfBandChallengeStartBuild::new(
            challenge_dedupe_key,
            recipient_handle,
            idempotency_key,
        )
        .map_err(PostgresEmailOtpMethodError::Core)
    }

    pub(crate) fn resend_challenge_request(
        &self,
        input: EmailOtpResendChallenge,
    ) -> Result<ResendOutOfBandChallengeRequest, PostgresEmailOtpMethodError> {
        validate_email_otp_delivery_idempotency_key(&input.delivery_idempotency_key)?;
        Ok(ResendOutOfBandChallengeRequest {
            now: input.now,
            idempotency_key: input.delivery_idempotency_key,
        })
    }

    pub(crate) fn complete_challenge_response(
        &self,
        input: EmailOtpCompleteChallengeResponse,
    ) -> Result<CompleteOutOfBandChallengeResponse, PostgresEmailOtpMethodError> {
        Ok(CompleteOutOfBandChallengeResponse {
            now: input.now,
            secret_response: input.secret_response,
            weak_proof_gate_response: input.weak_proof_gate_response,
        })
    }

    fn build_issue_commit_work(
        &self,
        request: &IssueOutOfBandChallengeRequest,
        response_secret: &ActiveProofChallengeResponseSecret,
    ) -> Result<Vec<MethodCommitWork>, PostgresEmailOtpMethodError> {
        self.validate_request_method(&request.method)?;
        validate_email_otp_recipient_handle(&request.recipient_handle)?;
        validate_email_otp_delivery_idempotency_key(&request.idempotency_key)?;
        let encrypted_response_secret = encrypt_plaintext_bytes_as::<EmailOtpResponseSecret>(
            &self.response_secret_keyset,
            response_secret.expose_secret(),
            &email_otp_response_secret_context(&request.challenge_id, &request.recipient_handle),
        )
        .map_err(PostgresEmailOtpMethodError::Crypto)?
        .into_bytes();
        let issue_payload = encode_method_payload(&EmailOtpIssuePayload {
            challenge_id: request.challenge_id.as_bytes().to_vec(),
            attempt_id: request.attempt_id.as_bytes().to_vec(),
            recipient_handle: request.recipient_handle.clone(),
            encrypted_response_secret,
            issued_at: request.now.get(),
            replaceable_created_at_or_before: request
                .replaceable_created_at_or_before
                .map(UnixSeconds::get),
        })?;
        let delivery_payload = encode_method_payload(&EmailOtpDeliveryPayload {
            challenge_id: request.challenge_id.as_bytes().to_vec(),
            delivery_idempotency_key: request.idempotency_key.clone(),
            queued_at: request.now.get(),
        })?;
        Ok(vec![self.method_commit_work(
            vec![MethodCommitPrecondition::new(
                EMAIL_OTP_CLOSE_REPLACEABLE_CHALLENGES_BEFORE_ISSUE_OPERATION,
                issue_payload.clone(),
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
            vec![MethodCommitMutation::new(
                EMAIL_OTP_STORE_CHALLENGE_OPERATION,
                issue_payload,
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
            vec![MethodCommitDurableEffectCommand::new(
                EMAIL_OTP_QUEUE_DELIVERY_OPERATION,
                delivery_payload,
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
        )?])
    }

    fn build_resend_commit_work(
        &self,
        request: &ResendOutOfBandChallengeRequest,
        challenge: &ActiveProofChallengeRecord,
    ) -> Result<Vec<MethodCommitWork>, PostgresEmailOtpMethodError> {
        self.validate_proof_method(&challenge.proof)?;
        validate_email_otp_delivery_idempotency_key(&request.idempotency_key)?;
        let challenge_payload = encode_method_payload(&EmailOtpChallengePayload {
            challenge_id: challenge.challenge_id.as_bytes().to_vec(),
            at: request.now.get(),
        })?;
        let delivery_payload = encode_method_payload(&EmailOtpDeliveryPayload {
            challenge_id: challenge.challenge_id.as_bytes().to_vec(),
            delivery_idempotency_key: request.idempotency_key.clone(),
            queued_at: request.now.get(),
        })?;
        Ok(vec![self.method_commit_work(
            vec![MethodCommitPrecondition::new(
                EMAIL_OTP_CHALLENGE_OPEN_OPERATION,
                challenge_payload,
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
            Vec::new(),
            vec![MethodCommitDurableEffectCommand::new(
                EMAIL_OTP_QUEUE_DELIVERY_OPERATION,
                delivery_payload,
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
        )?])
    }

    fn build_completion_commit_work(
        &self,
        challenge_id: &ActiveProofChallengeId,
        response: &CompleteOutOfBandChallengeResponse,
    ) -> Result<Vec<MethodCommitWork>, PostgresEmailOtpMethodError> {
        let challenge_payload = encode_method_payload(&EmailOtpChallengePayload {
            challenge_id: challenge_id.as_bytes().to_vec(),
            at: response.now.get(),
        })?;
        Ok(vec![self.method_commit_work(
            vec![MethodCommitPrecondition::new(
                EMAIL_OTP_CHALLENGE_OPEN_OPERATION,
                challenge_payload.clone(),
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
            vec![MethodCommitMutation::new(
                EMAIL_OTP_CONSUME_CHALLENGE_OPERATION,
                challenge_payload,
            )
            .map_err(PostgresEmailOtpMethodError::Core)?],
            Vec::new(),
        )?])
    }

    async fn resolve_verified_identifier_for_challenge(
        &self,
        tx: &mut Tx<'_>,
        challenge_id: &ActiveProofChallengeId,
    ) -> Result<
        super::postgres_method_runtime::PostgresOutOfBandProofResolution,
        PostgresEmailOtpMethodError,
    > {
        let recipient_handle = self
            .load_open_challenge_recipient_handle(tx, challenge_id)
            .await?;
        let verified_identifier = self
            .subject_resolver
            .resolve_verified_identifier_for_recipient_handle(tx, &recipient_handle)
            .await?;
        Ok(
            super::postgres_method_runtime::PostgresOutOfBandProofResolution::new(
                verified_identifier.subject_id,
                Some(VerifiedProofSource::new(
                    VerifiedProofSourceKind::OutOfBandIdentifier,
                    verified_identifier.source_id,
                )),
            ),
        )
    }

    async fn resolve_identifier_change_candidate_source_for_challenge(
        &self,
        tx: &mut Tx<'_>,
        challenge_id: &ActiveProofChallengeId,
    ) -> Result<VerifiedProofSource, PostgresEmailOtpMethodError> {
        let recipient_handle = self
            .load_open_challenge_recipient_handle(tx, challenge_id)
            .await?;
        Ok(VerifiedProofSource::new(
            VerifiedProofSourceKind::OutOfBandIdentifier,
            default_email_otp_source_id_for_recipient_handle(&recipient_handle)?,
        ))
    }

    async fn load_open_challenge_recipient_handle(
        &self,
        tx: &mut Tx<'_>,
        challenge_id: &ActiveProofChallengeId,
    ) -> Result<String, PostgresEmailOtpMethodError> {
        let statement = format!(
            "SELECT recipient_handle FROM {} WHERE challenge_id = $1 AND closed_at IS NULL",
            self.config.table_names()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.email_otp.load_open_challenge_recipient_handle",
            Some(statement.as_str()),
        );
        let recipient_handle_result = async {
            pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(challenge_id.as_bytes())
                .fetch_optional(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)
                .map_err(PostgresEmailOtpMethodError::Database)?
                .ok_or(PostgresEmailOtpMethodError::Core(
                    Error::LoadedStateContradiction(
                        "email otp challenge was not open during verified identifier resolution",
                    ),
                ))
        }
        .await;
        recipient_handle_result
    }

    fn validate_request_method(
        &self,
        method: &ProofMethodDeclaration,
    ) -> Result<(), PostgresEmailOtpMethodError> {
        if method == &self.method {
            Ok(())
        } else {
            Err(PostgresEmailOtpMethodError::Core(
                Error::LoadedStateContradiction("email otp request used a different method"),
            ))
        }
    }

    fn validate_proof_method(
        &self,
        proof: &ProofSummary,
    ) -> Result<(), PostgresEmailOtpMethodError> {
        if proof == &self.method.verified_proof_summary() {
            Ok(())
        } else {
            Err(PostgresEmailOtpMethodError::Core(
                Error::LoadedStateContradiction("email otp challenge used a different method"),
            ))
        }
    }

    fn method_commit_work(
        &self,
        preconditions: Vec<MethodCommitPrecondition>,
        mutations: Vec<MethodCommitMutation>,
        durable_effect_commands: Vec<MethodCommitDurableEffectCommand>,
    ) -> Result<MethodCommitWork, PostgresEmailOtpMethodError> {
        MethodCommitWork::new(
            self.method.verified_proof_summary(),
            preconditions,
            mutations,
            durable_effect_commands,
        )
        .map_err(PostgresEmailOtpMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) async fn count_open_method_challenges_for_test(
        &self,
        pool: &Pool,
    ) -> Result<i64, PostgresEmailOtpMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE closed_at IS NULL",
            self.config.table_names()?.challenge_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresEmailOtpMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresEmailOtpMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresEmailOtpMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) async fn count_delivery_commands_for_test(
        &self,
        pool: &Pool,
    ) -> Result<i64, PostgresEmailOtpMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {}",
            self.config.table_names()?.delivery_command_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresEmailOtpMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresEmailOtpMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresEmailOtpMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) async fn count_dispatched_delivery_commands_for_test(
        &self,
        pool: &Pool,
    ) -> Result<i64, PostgresEmailOtpMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE queue_dispatched_at IS NOT NULL",
            self.config.table_names()?.delivery_command_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresEmailOtpMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresEmailOtpMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresEmailOtpMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) async fn fetch_response_secret_for_test(
        &self,
        pool: &Pool,
        challenge_id: &ActiveProofChallengeId,
    ) -> Result<ActiveProofChallengeResponseSecret, PostgresEmailOtpMethodError> {
        let statement = format!(
            "SELECT recipient_handle, encrypted_response_secret FROM {} WHERE challenge_id = $1",
            self.config.table_names()?.challenge_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresEmailOtpMethodError::Database)?;
        let result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes())
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresEmailOtpMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresEmailOtpMethodError::Database);
        let row = match (result, rollback_result) {
            (Ok(row), Ok(())) => row,
            (Err(error), _) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
        };
        let recipient_handle: String = row
            .try_get("recipient_handle")
            .map_err(DbError::query)
            .map_err(PostgresEmailOtpMethodError::Database)?;
        let encrypted_response_secret: Vec<u8> = row
            .try_get("encrypted_response_secret")
            .map_err(DbError::query)
            .map_err(PostgresEmailOtpMethodError::Database)?;
        let plaintext = decrypt_bytes_with_associated_data(
            &self.response_secret_keyset,
            &encrypted_response_secret,
            &email_otp_response_secret_context(challenge_id, &recipient_handle),
        )
        .map_err(PostgresEmailOtpMethodError::Crypto)?;
        ActiveProofChallengeResponseSecret::try_from(plaintext.expose_secret())
            .map_err(PostgresEmailOtpMethodError::Core)
    }
}

impl PostgresAuthMethodPlugin for PostgresEmailOtpMethodPlugin {
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn mounted_route_capabilities(&self) -> PostgresAuthMethodMountedRouteCapabilities {
        PostgresAuthMethodMountedRouteCapabilities::empty()
            .with_out_of_band_full_authentication()
            .with_out_of_band_identifier_change()
    }

    fn derive_out_of_band_challenge_start(
        &self,
        request: &PostgresOutOfBandChallengeStartBuildRequest<'_>,
    ) -> Result<
        super::postgres_method_runtime::PostgresOutOfBandChallengeStartBuild,
        super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        self.build_method_derived_out_of_band_challenge_start(request)
            .map_err(|error| {
                super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "out_of_band_challenge_start_derivation",
                    error,
                )
            })
    }

    fn build_out_of_band_issue(
        &self,
        request: &IssueOutOfBandChallengeRequest,
    ) -> Result<
        super::postgres_method_runtime::PostgresOutOfBandChallengeIssueBuild,
        super::postgres_method_runtime::PostgresAuthMethodBuildError,
    > {
        let response_secret = ActiveProofChallengeResponseSecret::generate(
            EMAIL_OTP_RESPONSE_SECRET_BYTES,
        )
        .map_err(|error| {
            super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                &self.method,
                "out_of_band_issue",
                error,
            )
        })?;
        let method_commit_work = self
            .build_issue_commit_work(request, &response_secret)
            .map_err(|error| {
                super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "out_of_band_issue",
                    error,
                )
            })?;
        Ok(
            super::postgres_method_runtime::PostgresOutOfBandChallengeIssueBuild::new(
                response_secret,
                method_commit_work,
            ),
        )
    }

    fn build_out_of_band_resend_commit_work(
        &self,
        request: &ResendOutOfBandChallengeRequest,
        challenge: &ActiveProofChallengeRecord,
    ) -> Result<Vec<MethodCommitWork>, super::postgres_method_runtime::PostgresAuthMethodBuildError>
    {
        self.build_resend_commit_work(request, challenge)
            .map_err(|error| {
                super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "out_of_band_resend",
                    error,
                )
            })
    }

    fn build_out_of_band_completion_commit_work(
        &self,
        challenge_id: &ActiveProofChallengeId,
        response: &CompleteOutOfBandChallengeResponse,
    ) -> Result<Vec<MethodCommitWork>, super::postgres_method_runtime::PostgresAuthMethodBuildError>
    {
        self.build_completion_commit_work(challenge_id, response)
            .map_err(|error| {
                super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "out_of_band_completion",
                    error,
                )
            })
    }

    fn resolve_out_of_band_proof<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        challenge_id: &'a ActiveProofChallengeId,
        _response: &'a CompleteOutOfBandChallengeResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        super::postgres_method_runtime::PostgresOutOfBandProofResolution,
                        super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.resolve_verified_identifier_for_challenge(tx, challenge_id)
                .await
                .map_err(|error| {
                    super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        &self.method,
                        "out_of_band_proof_resolution",
                        error,
                    )
                })
        })
    }

    fn resolve_out_of_band_identifier_change_candidate_source<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        challenge_id: &'a ActiveProofChallengeId,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        VerifiedProofSource,
                        super::postgres_method_runtime::PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.resolve_identifier_change_candidate_source_for_challenge(tx, challenge_id)
                .await
                .map_err(|error| {
                    super::postgres_method_runtime::PostgresAuthMethodBuildError::plugin_rejected(
                        &self.method,
                        "out_of_band_identifier_change_candidate_source",
                        error,
                    )
                })
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
                EMAIL_OTP_CLOSE_REPLACEABLE_CHALLENGES_BEFORE_ISSUE_OPERATION => {
                    let payload: EmailOtpIssuePayload =
                        decode_method_payload(precondition.payload())?;
                    self.close_replaceable_challenges_before_issue(tx, &payload)
                        .await
                }
                EMAIL_OTP_CHALLENGE_OPEN_OPERATION => {
                    let payload: EmailOtpChallengePayload =
                        decode_method_payload(precondition.payload())?;
                    self.enforce_challenge_open(tx, &payload.challenge_id).await
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
                EMAIL_OTP_STORE_CHALLENGE_OPERATION => {
                    let payload: EmailOtpIssuePayload = decode_method_payload(mutation.payload())?;
                    self.store_challenge(tx, &payload).await
                }
                EMAIL_OTP_CONSUME_CHALLENGE_OPERATION => {
                    let payload: EmailOtpChallengePayload =
                        decode_method_payload(mutation.payload())?;
                    self.consume_challenge(tx, &payload).await
                }
                other => Err(PostgresAuthMethodCommitError::InvalidOperation(
                    other.to_owned(),
                )),
            }
        })
    }

    fn append_durable_effect_command<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        command: &'a MethodCommitDurableEffectCommand,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            match command.operation().as_str() {
                EMAIL_OTP_QUEUE_DELIVERY_OPERATION => {
                    let payload: EmailOtpDeliveryPayload =
                        decode_method_payload(command.payload())?;
                    self.queue_delivery(tx, &payload).await
                }
                other => Err(PostgresAuthMethodCommitError::InvalidOperation(
                    other.to_owned(),
                )),
            }
        })
    }

    fn register_durable_effect_queue_handlers(
        &self,
        task_registry: &mut queue::TaskRegistry,
    ) -> Result<(), PostgresAuthMethodDurableEffectQueueRegistrationError> {
        let Some(deliverer) = self.delivery_message_deliverer.as_ref() else {
            return Ok(());
        };
        let plugin = self.clone_for_queue_handler();
        let deliverer = Arc::clone(deliverer);
        task_registry.register_json_task_handler(
            EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
            move |context, payload: QueuedEmailOtpDeliveryPayload| {
                let plugin = plugin.clone_for_queue_handler();
                let deliverer = Arc::clone(&deliverer);
                async move {
                    let delivery_request = plugin
                        .load_queued_delivery_request(&context, payload)
                        .await?;
                    deliverer
                        .deliver_email_otp_message(delivery_request)
                        .await
                        .map_err(AuthDurableEffectDeliveryError::into_queue_task_error)
                }
            },
        )?;
        Ok(())
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
        Box::pin(async move {
            self.enqueue_available_email_otp_deliveries_to_queue_in_current_transaction(
                tx,
                queue_store,
                limit,
                enqueued_at,
            )
            .await
        })
    }
}

impl PostgresEmailOtpMethodPlugin {
    fn table_names_for_commit(&self) -> Result<EmailOtpTableNames, PostgresAuthMethodCommitError> {
        self.config.table_names().map_err(|error| match error {
            PostgresEmailOtpMethodError::Database(error) => {
                PostgresAuthMethodCommitError::Database(error)
            }
            other => PostgresAuthMethodCommitError::InvalidOperation(other.to_string()),
        })
    }

    #[cfg(test)]
    pub(crate) fn challenge_table_name_for_test(
        &self,
    ) -> Result<PgQualifiedTableName, PostgresEmailOtpMethodError> {
        Ok(self.config.table_names()?.challenge_table)
    }

    #[cfg(test)]
    pub(crate) fn delivery_command_table_name_for_test(
        &self,
    ) -> Result<PgQualifiedTableName, PostgresEmailOtpMethodError> {
        Ok(self.config.table_names()?.delivery_command_table)
    }

    async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let table_names = self.table_names_for_commit()?;
        let challenge_statement = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                challenge_id BYTEA PRIMARY KEY,
                attempt_id BYTEA NOT NULL,
                recipient_handle TEXT COLLATE "C" NOT NULL,
                encrypted_response_secret BYTEA NOT NULL,
                created_at BIGINT NOT NULL,
                closed_at BIGINT,
                CHECK (octet_length(challenge_id) >= 1 AND octet_length(challenge_id) <= {}),
                CHECK (octet_length(attempt_id) >= 1 AND octet_length(attempt_id) <= {}),
                CHECK (octet_length(recipient_handle) >= 1 AND octet_length(recipient_handle) <= {}),
                CHECK (octet_length(encrypted_response_secret) > 0),
                CHECK (created_at >= 0),
                CHECK (closed_at IS NULL OR closed_at >= 0)
            )
            "#,
            table_names.challenge_table.quoted(),
            ID_MAX_BYTES,
            ID_MAX_BYTES,
            OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.schema.create_challenge_table",
            Some(challenge_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(challenge_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;

        let delivery_statement = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                challenge_id BYTEA NOT NULL,
                delivery_idempotency_key TEXT COLLATE "C" NOT NULL,
                recipient_handle TEXT COLLATE "C" NOT NULL,
                encrypted_response_secret BYTEA NOT NULL,
                created_at BIGINT NOT NULL,
                queue_job_id BYTEA,
                queue_dispatched_at BIGINT,
                CHECK (octet_length(challenge_id) >= 1 AND octet_length(challenge_id) <= {}),
                CHECK (octet_length(delivery_idempotency_key) >= 1 AND octet_length(delivery_idempotency_key) <= {}),
                CHECK (octet_length(recipient_handle) >= 1 AND octet_length(recipient_handle) <= {}),
                CHECK (octet_length(encrypted_response_secret) > 0),
                CHECK (created_at >= 0),
                CHECK (queue_job_id IS NULL OR octet_length(queue_job_id) = {}),
                CHECK (queue_dispatched_at IS NULL OR queue_dispatched_at >= 0),
                CHECK ((queue_job_id IS NULL) = (queue_dispatched_at IS NULL)),
                PRIMARY KEY (challenge_id, delivery_idempotency_key)
            )
            "#,
            table_names.delivery_command_table.quoted(),
            ID_MAX_BYTES,
            DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
            OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
            crate::queue::JOB_ID_SIZE
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.schema.create_delivery_command_table",
            Some(delivery_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(delivery_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        let challenge_checks = email_otp_challenge_table_checks();
        ensure_method_table_check_constraints_in_current_transaction(
            tx,
            &table_names.challenge_table,
            &challenge_checks,
        )
        .await?;
        let delivery_checks = email_otp_delivery_table_checks();
        ensure_method_table_check_constraints_in_current_transaction(
            tx,
            &table_names.delivery_command_table,
            &delivery_checks,
        )
        .await?;
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let table_names = self.table_names_for_commit()?;
        validate_method_table_schema_in_current_transaction(
            tx,
            &table_names.challenge_table,
            &email_otp_challenge_table_columns(),
            &email_otp_challenge_table_checks(),
            &email_otp_challenge_table_indexes(),
        )
        .await?;
        validate_method_table_schema_in_current_transaction(
            tx,
            &table_names.delivery_command_table,
            &email_otp_delivery_table_columns(),
            &email_otp_delivery_table_checks(),
            &email_otp_delivery_table_indexes(),
        )
        .await
    }

    async fn close_replaceable_challenges_before_issue(
        &self,
        tx: &mut Tx<'_>,
        payload: &EmailOtpIssuePayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            UPDATE {}
            SET closed_at = $2
            WHERE recipient_handle = $1
              AND closed_at IS NULL
              AND ($3::BIGINT IS NOT NULL AND created_at <= $3)
            "#,
            self.table_names_for_commit()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.precondition.close_replaceable_challenges_for_recipient",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.recipient_handle)
            .bind(i64_from_unix_seconds_u64(payload.issued_at)?)
            .bind(optional_i64_from_unix_seconds_u64(
                payload.replaceable_created_at_or_before,
            )?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        Ok(())
    }

    async fn enforce_challenge_open(
        &self,
        tx: &mut Tx<'_>,
        challenge_id: &[u8],
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            "SELECT closed_at FROM {} WHERE challenge_id = $1 FOR UPDATE",
            self.table_names_for_commit()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.email_otp.precondition.challenge_open",
            Some(statement.as_str()),
        );
        let closed_at = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .map(|row| row.try_get::<Option<i64>, _>("closed_at"))
            .transpose()
            .map_err(DbError::query)?;
        match closed_at {
            Some(None) => Ok(()),
            Some(Some(_)) => Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "email otp challenge already closed",
            )),
            None => Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "email otp challenge does not exist",
            )),
        }
    }

    async fn store_challenge(
        &self,
        tx: &mut Tx<'_>,
        payload: &EmailOtpIssuePayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            INSERT INTO {} (
                challenge_id,
                attempt_id,
                recipient_handle,
                encrypted_response_secret,
                created_at
            )
            VALUES ($1,$2,$3,$4,$5)
            "#,
            self.table_names_for_commit()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.mutation.store_challenge",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.challenge_id)
            .bind(&payload.attempt_id)
            .bind(&payload.recipient_handle)
            .bind(&payload.encrypted_response_secret)
            .bind(i64_from_unix_seconds_u64(payload.issued_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        Ok(())
    }

    async fn consume_challenge(
        &self,
        tx: &mut Tx<'_>,
        payload: &EmailOtpChallengePayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            UPDATE {}
            SET closed_at = $2
            WHERE challenge_id = $1 AND closed_at IS NULL
            "#,
            self.table_names_for_commit()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.mutation.consume_challenge",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.challenge_id)
            .bind(i64_from_unix_seconds_u64(payload.at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "email otp challenge is not open",
            ));
        }
        Ok(())
    }

    async fn queue_delivery(
        &self,
        tx: &mut Tx<'_>,
        payload: &EmailOtpDeliveryPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let table_names = self.table_names_for_commit()?;
        let statement = format!(
            r#"
            WITH locked_challenge AS (
                SELECT recipient_handle, encrypted_response_secret
                FROM {}
                WHERE challenge_id = $1 AND closed_at IS NULL
                FOR UPDATE
            )
            INSERT INTO {} (
                challenge_id,
                delivery_idempotency_key,
                recipient_handle,
                encrypted_response_secret,
                created_at
            )
            SELECT
                $1,
                $2,
                recipient_handle,
                encrypted_response_secret,
                $3
            FROM locked_challenge
            "#,
            table_names.challenge_table.quoted(),
            table_names.delivery_command_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.effect.queue_delivery",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.challenge_id)
            .bind(&payload.delivery_idempotency_key)
            .bind(i64_from_unix_seconds_u64(payload.queued_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "email otp challenge is not open for delivery",
            ));
        }
        Ok(())
    }

    fn clone_for_queue_handler(&self) -> Self {
        Self {
            config: self.config.clone(),
            method: self.method.clone(),
            response_secret_keyset: Arc::clone(&self.response_secret_keyset),
            subject_resolver: Arc::clone(&self.subject_resolver),
            delivery_message_deliverer: self.delivery_message_deliverer.clone(),
        }
    }

    async fn enqueue_available_email_otp_deliveries_to_queue_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        queue_store: &queue::Store,
        limit: NonZeroU32,
        enqueued_at: UnixSeconds,
    ) -> Result<
        PostgresAuthDurableEffectQueueDispatchSummary,
        PostgresAuthDurableEffectQueueDispatchError,
    > {
        let rows = self
            .load_undispatched_delivery_rows_for_update(tx, limit)
            .await?;
        let mut summary = PostgresAuthDurableEffectQueueDispatchSummary::default();
        for row in rows {
            let work = EmailOtpDeliveryQueueDispatchWork::try_from(row)?;
            let dedupe_key = email_otp_delivery_queue_dedupe_key(
                &work.challenge_id,
                &work.delivery_idempotency_key,
            );
            let enqueue_result = queue_store
                .enqueue_json_in_current_transaction(
                    tx,
                    EMAIL_OTP_DELIVERY_QUEUE_TASK_NAME,
                    &QueuedEmailOtpDeliveryPayload {
                        challenge_id: work.challenge_id.as_bytes().to_vec(),
                        delivery_idempotency_key: work.delivery_idempotency_key.clone(),
                    },
                    EnqueueOptions {
                        dedupe_key: Some(dedupe_key),
                        ..EnqueueOptions::default()
                    },
                )
                .await?;
            self.mark_delivery_dispatched(
                tx,
                &work.challenge_id,
                &work.delivery_idempotency_key,
                enqueue_result.job_id.as_bytes(),
                enqueued_at,
            )
            .await?;
            summary.record_enqueue(enqueue_result.deduplicated);
        }
        Ok(summary)
    }

    async fn load_undispatched_delivery_rows_for_update(
        &self,
        tx: &mut WriteTx<'_>,
        limit: NonZeroU32,
    ) -> Result<Vec<EmailOtpDeliveryDispatchRow>, PostgresAuthDurableEffectQueueDispatchError> {
        let table = self
            .config
            .table_names()
            .map_err(method_error_into_dispatch_error)?
            .delivery_command_table;
        let statement = format!(
            r#"
            SELECT challenge_id, delivery_idempotency_key
            FROM {}
            WHERE queue_dispatched_at IS NULL
            ORDER BY challenge_id, delivery_idempotency_key
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            "#,
            table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "auth_core.email_otp.delivery_queue.lock_undispatched_deliveries",
            Some(statement.as_str()),
        );
        pooler_safe_query_as::<EmailOtpDeliveryDispatchRow>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(i64::from(limit.get()))
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresAuthDurableEffectQueueDispatchError::Database)
    }

    async fn mark_delivery_dispatched(
        &self,
        tx: &mut WriteTx<'_>,
        challenge_id: &ActiveProofChallengeId,
        delivery_idempotency_key: &str,
        queue_job_id: &[u8],
        enqueued_at: UnixSeconds,
    ) -> Result<(), PostgresAuthDurableEffectQueueDispatchError> {
        let table = self
            .config
            .table_names()
            .map_err(method_error_into_dispatch_error)?
            .delivery_command_table;
        let statement = format!(
            r#"
            UPDATE {}
            SET queue_job_id = $3,
                queue_dispatched_at = $4
            WHERE challenge_id = $1
              AND delivery_idempotency_key = $2
              AND queue_dispatched_at IS NULL
            "#,
            table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.email_otp.delivery_queue.mark_delivery_dispatched",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes())
            .bind(delivery_idempotency_key)
            .bind(queue_job_id)
            .bind(i64_from_unix_seconds_for_dispatch(enqueued_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(
                PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
                    "email otp delivery row was not dispatchable after queue enqueue",
                ),
            )
        }
    }

    async fn load_queued_delivery_request(
        &self,
        context: &queue::JobExecutionContext,
        payload: QueuedEmailOtpDeliveryPayload,
    ) -> Result<PostgresEmailOtpDeliveryMessageRequest, queue::TaskError> {
        let challenge_id = ActiveProofChallengeId::from_bytes(payload.challenge_id.clone())
            .map_err(permanent_task_error_from_core_error)?;
        validate_email_otp_delivery_idempotency_key(&payload.delivery_idempotency_key)
            .map_err(permanent_task_error_from_email_otp_error)?;
        let table = self
            .config
            .table_names()
            .map_err(permanent_task_error_from_email_otp_error)?
            .delivery_command_table;
        let statement = format!(
            r#"
            SELECT recipient_handle, encrypted_response_secret
            FROM {}
            WHERE challenge_id = $1
              AND delivery_idempotency_key = $2
              AND queue_job_id = $3
            "#,
            table.quoted()
        );
        let mut tx = context
            .pool()
            .begin_transaction()
            .await
            .map_err(|error| queue::TaskError::retryable(error.to_string()))?;
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.email_otp.delivery_queue.load_queued_delivery",
            Some(statement.as_str()),
        );
        let row_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id.as_bytes())
            .bind(&payload.delivery_idempotency_key)
            .bind(context.job_id().as_bytes())
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(|error| queue::TaskError::retryable(error.to_string()));
        let rollback_result = tx
            .rollback()
            .await
            .map_err(|error| queue::TaskError::retryable(error.to_string()));
        let row = match (row_result, rollback_result) {
            (Ok(row), Ok(())) => row,
            (Err(error), _) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
        };
        let row = row.ok_or_else(|| {
            queue::TaskError::permanent(
                "queued email otp delivery does not reference a committed dispatched row",
            )
        })?;
        let recipient_handle: String = row
            .try_get("recipient_handle")
            .map_err(DbError::query)
            .map_err(|error| queue::TaskError::retryable(error.to_string()))?;
        let encrypted_response_secret: Vec<u8> = row
            .try_get("encrypted_response_secret")
            .map_err(DbError::query)
            .map_err(|error| queue::TaskError::retryable(error.to_string()))?;
        let plaintext = decrypt_bytes_with_associated_data(
            &self.response_secret_keyset,
            &encrypted_response_secret,
            &email_otp_response_secret_context(&challenge_id, &recipient_handle),
        )
        .map_err(|error| queue::TaskError::permanent(error.to_string()))?;
        let response_secret =
            ActiveProofChallengeResponseSecret::try_from(plaintext.expose_secret())
                .map_err(permanent_task_error_from_core_error)?;
        Ok(PostgresEmailOtpDeliveryMessageRequest {
            queue_job_id: context.job_id(),
            retry_count: context.retry_count(),
            max_retries: context.max_retries(),
            challenge_id,
            delivery_idempotency_key: payload.delivery_idempotency_key,
            recipient_handle,
            response_secret,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresEmailOtpMethodPluginConfig {
    schema: Option<PgSchemaName>,
    table_prefix: PgIdentifier,
}

impl PostgresEmailOtpMethodPluginConfig {
    pub(crate) fn new(
        schema: Option<PgSchemaName>,
        table_prefix: PgIdentifier,
    ) -> Result<Self, PostgresEmailOtpMethodError> {
        let config = Self {
            schema,
            table_prefix,
        };
        config.table_names()?;
        Ok(config)
    }

    pub(crate) fn for_db_bootstrap_config(
        bootstrap_config: &BootstrapConfig,
    ) -> Result<Self, PostgresEmailOtpMethodError> {
        Self::new(
            Some(bootstrap_config.schema_name().clone()),
            PgIdentifier::new(DEFAULT_EMAIL_OTP_TABLE_PREFIX)
                .map_err(DbError::from)
                .map_err(PostgresEmailOtpMethodError::Database)?,
        )
    }

    fn table_name(&self, suffix: &'static str) -> Result<PgQualifiedTableName, DbError> {
        Ok(PgQualifiedTableName::new(
            self.schema.clone(),
            PgIdentifier::new(format!("{}{}", self.table_prefix.as_str(), suffix))?,
        ))
    }

    fn table_names(&self) -> Result<EmailOtpTableNames, PostgresEmailOtpMethodError> {
        Ok(EmailOtpTableNames {
            challenge_table: self
                .table_name("challenges")
                .map_err(PostgresEmailOtpMethodError::Database)?,
            delivery_command_table: self
                .table_name("delivery_commands")
                .map_err(PostgresEmailOtpMethodError::Database)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_for_db_bootstrap_uses_schema_local_bootstrap_tables() {
        let bootstrap_config =
            BootstrapConfig::from_schema_name_text("__paranoid").expect("bootstrap config");
        let config = PostgresEmailOtpMethodPluginConfig::for_db_bootstrap_config(&bootstrap_config)
            .expect("email otp method config");
        let table_names = config.table_names().expect("table names");

        assert_eq!(
            table_names.challenge_table.schema(),
            Some(bootstrap_config.schema_name())
        );
        assert_eq!(
            table_names.challenge_table.table().as_str(),
            "auth_email_otp_challenges"
        );
        assert_eq!(
            table_names.delivery_command_table.table().as_str(),
            "auth_email_otp_delivery_commands"
        );
    }
}

pub(crate) trait PostgresEmailOtpSubjectResolver: Send + Sync {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    >;
}

struct NoopEmailOtpSubjectResolver;

impl PostgresEmailOtpSubjectResolver for NoopEmailOtpSubjectResolver {
    fn resolve_verified_identifier_for_recipient_handle<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        recipient_handle: &'a str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        PostgresEmailOtpVerifiedIdentifier,
                        PostgresEmailOtpMethodError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let _ = tx;
        Box::pin(async move {
            Ok(PostgresEmailOtpVerifiedIdentifier::new(
                None,
                default_email_otp_source_id_for_recipient_handle(recipient_handle)?,
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresEmailOtpVerifiedIdentifier {
    subject_id: Option<SubjectId>,
    source_id: VerifiedProofSourceId,
}

impl PostgresEmailOtpVerifiedIdentifier {
    pub(crate) fn new(subject_id: Option<SubjectId>, source_id: VerifiedProofSourceId) -> Self {
        Self {
            subject_id,
            source_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EmailOtpTableNames {
    challenge_table: PgQualifiedTableName,
    delivery_command_table: PgQualifiedTableName,
}

pub(crate) trait PostgresEmailOtpDeliveryMessageDeliverer: Send + Sync + 'static {
    fn deliver_email_otp_message<'a>(
        &'a self,
        request: PostgresEmailOtpDeliveryMessageRequest,
    ) -> AuthDurableEffectDeliveryFuture<'a>;
}

#[derive(Debug)]
pub(crate) struct PostgresEmailOtpDeliveryMessageRequest {
    queue_job_id: queue::JobId,
    retry_count: u32,
    max_retries: u32,
    challenge_id: ActiveProofChallengeId,
    delivery_idempotency_key: String,
    recipient_handle: String,
    response_secret: ActiveProofChallengeResponseSecret,
}

impl PostgresEmailOtpDeliveryMessageRequest {
    pub(crate) const fn queue_job_id(&self) -> queue::JobId {
        self.queue_job_id
    }

    pub(crate) const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    pub(crate) const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    pub(crate) fn challenge_id(&self) -> &ActiveProofChallengeId {
        &self.challenge_id
    }

    pub(crate) fn delivery_idempotency_key(&self) -> &str {
        &self.delivery_idempotency_key
    }

    pub(crate) fn recipient_handle(&self) -> &str {
        &self.recipient_handle
    }

    pub(crate) fn response_secret(&self) -> &ActiveProofChallengeResponseSecret {
        &self.response_secret
    }
}

pub(crate) struct EmailOtpIssueChallenge {
    pub(crate) now: UnixSeconds,
    pub(crate) challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    pub(crate) recipient_handle: String,
    pub(crate) delivery_idempotency_key: String,
}

pub(crate) struct EmailOtpResendChallenge {
    pub(crate) now: UnixSeconds,
    pub(crate) delivery_idempotency_key: String,
}

pub(crate) struct EmailOtpCompleteChallengeResponse {
    pub(crate) now: UnixSeconds,
    pub(crate) secret_response: ActiveProofChallengeResponseSecret,
    pub(crate) weak_proof_gate_response: Option<WeakProofGateResponse>,
}

#[derive(Debug)]
pub(crate) enum PostgresEmailOtpMethodError {
    Core(Error),
    Crypto(crate::crypto::Error),
    Database(DbError),
    PayloadEncode(postcard::Error),
}

impl fmt::Display for PostgresEmailOtpMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Database(error) => write!(f, "{error}"),
            Self::PayloadEncode(error) => {
                write!(f, "email otp method payload could not be encoded: {error}")
            }
        }
    }
}

impl std::error::Error for PostgresEmailOtpMethodError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::PayloadEncode(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EmailOtpIssuePayload {
    challenge_id: Vec<u8>,
    attempt_id: Vec<u8>,
    recipient_handle: String,
    encrypted_response_secret: Vec<u8>,
    issued_at: u64,
    replaceable_created_at_or_before: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EmailOtpChallengePayload {
    challenge_id: Vec<u8>,
    at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EmailOtpDeliveryPayload {
    challenge_id: Vec<u8>,
    delivery_idempotency_key: String,
    queued_at: u64,
}

type EmailOtpDeliveryDispatchRow = (Vec<u8>, String);

#[derive(Debug)]
struct EmailOtpDeliveryQueueDispatchWork {
    challenge_id: ActiveProofChallengeId,
    delivery_idempotency_key: String,
}

impl TryFrom<EmailOtpDeliveryDispatchRow> for EmailOtpDeliveryQueueDispatchWork {
    type Error = PostgresAuthDurableEffectQueueDispatchError;

    fn try_from(row: EmailOtpDeliveryDispatchRow) -> Result<Self, Self::Error> {
        let (challenge_id, delivery_idempotency_key) = row;
        let challenge_id = ActiveProofChallengeId::from_bytes(challenge_id).map_err(|_| {
            PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
                "email otp delivery challenge id is invalid",
            )
        })?;
        validate_email_otp_delivery_idempotency_key(&delivery_idempotency_key).map_err(|_| {
            PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
                "email otp delivery idempotency key is invalid",
            )
        })?;
        Ok(Self {
            challenge_id,
            delivery_idempotency_key,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct QueuedEmailOtpDeliveryPayload {
    challenge_id: Vec<u8>,
    delivery_idempotency_key: String,
}

enum EmailOtpResponseSecret {}

fn encode_method_payload<T: Serialize>(
    payload: &T,
) -> Result<Vec<u8>, PostgresEmailOtpMethodError> {
    postcard::to_allocvec(payload).map_err(PostgresEmailOtpMethodError::PayloadEncode)
}

fn validate_email_otp_recipient_handle(
    recipient_handle: &str,
) -> Result<(), PostgresEmailOtpMethodError> {
    validate_auth_string_not_too_long(
        "email otp recipient handle",
        recipient_handle,
        OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
    )
    .map_err(PostgresEmailOtpMethodError::Core)
}

fn validate_email_otp_delivery_idempotency_key(
    delivery_idempotency_key: &str,
) -> Result<(), PostgresEmailOtpMethodError> {
    validate_auth_identifier_string(
        "email otp delivery idempotency key",
        delivery_idempotency_key,
        DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
    )
    .map_err(PostgresEmailOtpMethodError::Core)
}

fn email_otp_recipient_handle_from_start_payload(
    payload: &[u8],
) -> Result<String, PostgresEmailOtpMethodError> {
    if payload.is_empty() {
        return Err(PostgresEmailOtpMethodError::Core(
            Error::EmptyOutOfBandRecipientHandle,
        ));
    }
    let recipient_handle = std::str::from_utf8(payload)
        .map_err(|_| PostgresEmailOtpMethodError::Core(Error::InvalidOutOfBandRecipientHandle))?
        .to_owned();
    validate_email_otp_recipient_handle(&recipient_handle)?;
    Ok(recipient_handle)
}

fn email_otp_challenge_dedupe_key(
    proof_use: ProofUse,
    method: &ProofMethodDeclaration,
    recipient_handle: &str,
) -> Result<OutOfBandChallengeDedupeKey, PostgresEmailOtpMethodError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EMAIL_OTP_CHALLENGE_DEDUPE_CONTEXT);
    hasher.update(&[proof_use_wire_id(proof_use)]);
    hasher.update(&[proof_family_wire_id(method.family())]);
    update_email_otp_start_hash(&mut hasher, method.method_label().as_bytes());
    update_email_otp_start_hash(&mut hasher, recipient_handle.as_bytes());
    let digest = hasher.finalize();

    let mut dedupe_key = String::with_capacity(EMAIL_OTP_CHALLENGE_DEDUPE_KEY_PREFIX.len() + 64);
    dedupe_key.push_str(EMAIL_OTP_CHALLENGE_DEDUPE_KEY_PREFIX);
    push_lower_hex(&mut dedupe_key, digest.as_bytes());
    OutOfBandChallengeDedupeKey::new(dedupe_key).map_err(PostgresEmailOtpMethodError::Core)
}

fn email_otp_delivery_idempotency_key(
    proof_use: ProofUse,
    method: &ProofMethodDeclaration,
    attempt_id: &ActiveProofAttemptId,
    challenge_id: &ActiveProofChallengeId,
    recipient_handle: &str,
) -> Result<String, PostgresEmailOtpMethodError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EMAIL_OTP_DELIVERY_IDEMPOTENCY_CONTEXT);
    hasher.update(&[proof_use_wire_id(proof_use)]);
    hasher.update(&[proof_family_wire_id(method.family())]);
    update_email_otp_start_hash(&mut hasher, method.method_label().as_bytes());
    update_email_otp_start_hash(&mut hasher, attempt_id.as_bytes());
    update_email_otp_start_hash(&mut hasher, challenge_id.as_bytes());
    update_email_otp_start_hash(&mut hasher, recipient_handle.as_bytes());
    let digest = hasher.finalize();

    let mut idempotency_key =
        String::with_capacity(EMAIL_OTP_DELIVERY_IDEMPOTENCY_KEY_PREFIX.len() + 64);
    idempotency_key.push_str(EMAIL_OTP_DELIVERY_IDEMPOTENCY_KEY_PREFIX);
    push_lower_hex(&mut idempotency_key, digest.as_bytes());
    validate_email_otp_delivery_idempotency_key(&idempotency_key)?;
    Ok(idempotency_key)
}

fn update_email_otp_start_hash(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn email_otp_delivery_queue_dedupe_key(
    challenge_id: &ActiveProofChallengeId,
    delivery_idempotency_key: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EMAIL_OTP_DELIVERY_QUEUE_DEDUPE_CONTEXT);
    hasher.update(&(challenge_id.as_bytes().len() as u64).to_le_bytes());
    hasher.update(challenge_id.as_bytes());
    hasher.update(&(delivery_idempotency_key.len() as u64).to_le_bytes());
    hasher.update(delivery_idempotency_key.as_bytes());
    let digest = hasher.finalize();

    let mut dedupe_key =
        String::with_capacity(EMAIL_OTP_DELIVERY_QUEUE_DEDUPE_KEY_PREFIX.len() + 64);
    dedupe_key.push_str(EMAIL_OTP_DELIVERY_QUEUE_DEDUPE_KEY_PREFIX);
    push_lower_hex(&mut dedupe_key, digest.as_bytes());
    dedupe_key
}

fn push_lower_hex(output: &mut String, bytes: &[u8]) {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(LOWER_HEX[(byte >> 4) as usize] as char);
        output.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
    }
}

fn method_error_into_dispatch_error(
    error: PostgresEmailOtpMethodError,
) -> PostgresAuthDurableEffectQueueDispatchError {
    match error {
        PostgresEmailOtpMethodError::Database(error) => {
            PostgresAuthDurableEffectQueueDispatchError::Database(error)
        }
        _ => PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
            "email otp method config was invalid during durable-effect dispatch",
        ),
    }
}

fn permanent_task_error_from_core_error(error: Error) -> queue::TaskError {
    queue::TaskError::permanent(error.to_string())
}

fn permanent_task_error_from_email_otp_error(
    error: PostgresEmailOtpMethodError,
) -> queue::TaskError {
    queue::TaskError::permanent(error.to_string())
}

fn i64_from_unix_seconds_for_dispatch(
    value: UnixSeconds,
) -> Result<i64, PostgresAuthDurableEffectQueueDispatchError> {
    i64::try_from(value.get()).map_err(|_| {
        PostgresAuthDurableEffectQueueDispatchError::InvalidStoredData(
            "email otp delivery dispatch time is outside supported range",
        )
    })
}

fn decode_method_payload<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
) -> Result<T, PostgresAuthMethodCommitError> {
    postcard::from_bytes(payload).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "invalid email otp method payload".to_owned(),
        )
    })
}

fn email_otp_response_secret_context(
    challenge_id: &ActiveProofChallengeId,
    recipient_handle: &str,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        EMAIL_OTP_RESPONSE_SECRET_CONTEXT.len()
            + 16
            + challenge_id.as_bytes().len()
            + recipient_handle.len(),
    );
    context.extend_from_slice(EMAIL_OTP_RESPONSE_SECRET_CONTEXT);
    push_len_prefixed_bytes(&mut context, challenge_id.as_bytes());
    push_len_prefixed_bytes(&mut context, recipient_handle.as_bytes());
    context
}

fn default_email_otp_source_id_for_recipient_handle(
    recipient_handle: &str,
) -> Result<VerifiedProofSourceId, PostgresEmailOtpMethodError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EMAIL_OTP_DEFAULT_SOURCE_ID_CONTEXT);
    hasher.update(&(recipient_handle.len() as u64).to_le_bytes());
    hasher.update(recipient_handle.as_bytes());
    VerifiedProofSourceId::from_bytes(hasher.finalize().as_bytes().to_vec())
        .map_err(PostgresEmailOtpMethodError::Core)
}

fn push_len_prefixed_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    target.extend_from_slice(bytes);
}

fn i64_from_unix_seconds_u64(value: u64) -> Result<i64, PostgresAuthMethodCommitError> {
    i64::try_from(value).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "email otp timestamp exceeds Postgres BIGINT domain".to_owned(),
        )
    })
}

fn optional_i64_from_unix_seconds_u64(
    value: Option<u64>,
) -> Result<Option<i64>, PostgresAuthMethodCommitError> {
    value.map(i64_from_unix_seconds_u64).transpose()
}

fn email_otp_challenge_table_columns() -> Vec<MethodTableColumnContract> {
    vec![
        MethodTableColumnContract::bytea("challenge_id", true),
        MethodTableColumnContract::bytea("attempt_id", true),
        MethodTableColumnContract::text_collate_c("recipient_handle", true),
        MethodTableColumnContract::bytea("encrypted_response_secret", true),
        MethodTableColumnContract::bigint("created_at", true),
        MethodTableColumnContract::bigint("closed_at", false),
    ]
}

fn email_otp_challenge_table_checks() -> Vec<MethodTableCheckConstraint> {
    vec![
        MethodTableCheckConstraint::new(
            "challenge_id_len",
            quoted_len_at_least_one_and_at_most("challenge_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "attempt_id_len",
            quoted_len_at_least_one_and_at_most("attempt_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "recipient_handle_len",
            quoted_len_at_least_one_and_at_most(
                "recipient_handle",
                OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
            ),
        ),
        MethodTableCheckConstraint::new(
            "response_secret_nonempty",
            r#"octet_length("encrypted_response_secret") > 0"#,
        ),
        MethodTableCheckConstraint::new(
            "created_at_nonnegative",
            quoted_bigint_nonnegative("created_at"),
        ),
        MethodTableCheckConstraint::new(
            "closed_at_nonnegative",
            quoted_nullable_bigint_nonnegative("closed_at"),
        ),
    ]
}

fn email_otp_challenge_table_indexes() -> Vec<MethodTableIndexContract> {
    vec![MethodTableIndexContract::unique(
        "challenge primary-key",
        ["challenge_id"],
    )]
}

fn email_otp_delivery_table_columns() -> Vec<MethodTableColumnContract> {
    vec![
        MethodTableColumnContract::bytea("challenge_id", true),
        MethodTableColumnContract::text_collate_c("delivery_idempotency_key", true),
        MethodTableColumnContract::text_collate_c("recipient_handle", true),
        MethodTableColumnContract::bytea("encrypted_response_secret", true),
        MethodTableColumnContract::bigint("created_at", true),
        MethodTableColumnContract::bytea("queue_job_id", false),
        MethodTableColumnContract::bigint("queue_dispatched_at", false),
    ]
}

fn email_otp_delivery_table_checks() -> Vec<MethodTableCheckConstraint> {
    vec![
        MethodTableCheckConstraint::new(
            "challenge_id_len",
            quoted_len_at_least_one_and_at_most("challenge_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "delivery_idempotency_key_len",
            quoted_len_at_least_one_and_at_most(
                "delivery_idempotency_key",
                DELIVERY_IDEMPOTENCY_KEY_MAX_BYTES,
            ),
        ),
        MethodTableCheckConstraint::new(
            "recipient_handle_len",
            quoted_len_at_least_one_and_at_most(
                "recipient_handle",
                OUT_OF_BAND_RECIPIENT_HANDLE_MAX_BYTES,
            ),
        ),
        MethodTableCheckConstraint::new(
            "response_secret_nonempty",
            r#"octet_length("encrypted_response_secret") > 0"#,
        ),
        MethodTableCheckConstraint::new(
            "created_at_nonnegative",
            quoted_bigint_nonnegative("created_at"),
        ),
        MethodTableCheckConstraint::new(
            "queue_job_id_len",
            quoted_nullable_len_equals("queue_job_id", crate::queue::JOB_ID_SIZE),
        ),
        MethodTableCheckConstraint::new(
            "queue_dispatched_at_nonnegative",
            quoted_nullable_bigint_nonnegative("queue_dispatched_at"),
        ),
        MethodTableCheckConstraint::new(
            "queue_dispatch_pair",
            quoted_null_pair_matches("queue_job_id", "queue_dispatched_at"),
        ),
    ]
}

fn email_otp_delivery_table_indexes() -> Vec<MethodTableIndexContract> {
    vec![MethodTableIndexContract::unique(
        "delivery primary-key",
        ["challenge_id", "delivery_idempotency_key"],
    )]
}
