use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::crypto::Keyset;
use crate::crypto::envelope::{decrypt_bytes_with_associated_data, encrypt_plaintext_bytes_as};
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Pool, Tx, pooler_safe_query, pooler_safe_query_scalar,
    unparameterized_simple_query,
};

use super::postgres_method_runtime::PostgresAuthMethodPlugin;
use super::postgres_store::PostgresAuthMethodCommitError;
use super::*;

const EMAIL_OTP_METHOD_LABEL: &str = "email_otp";
const EMAIL_OTP_CHALLENGE_ABSENT_OPERATION: &str = "email_otp_challenge_absent";
const EMAIL_OTP_CHALLENGE_OPEN_OPERATION: &str = "email_otp_challenge_open";
const EMAIL_OTP_STORE_CHALLENGE_OPERATION: &str = "email_otp_store_challenge";
const EMAIL_OTP_CONSUME_CHALLENGE_OPERATION: &str = "email_otp_consume_challenge";
const EMAIL_OTP_QUEUE_DELIVERY_OPERATION: &str = "email_otp_queue_delivery";
const EMAIL_OTP_RESPONSE_SECRET_CONTEXT: &[u8] = b"paranoid/auth/v1/email-otp-response-secret";
const EMAIL_OTP_DEFAULT_SOURCE_ID_CONTEXT: &[u8] = b"paranoid/auth/v1/email-otp/default-source-id";
const EMAIL_OTP_RESPONSE_SECRET_BYTES: usize = 16;
const DEFAULT_EMAIL_OTP_TABLE_PREFIX: &str = "auth_email_otp_";

pub(crate) struct PostgresEmailOtpMethodPlugin {
    config: PostgresEmailOtpMethodPluginConfig,
    method: ProofMethodDeclaration,
    response_secret_keyset: Keyset,
    subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
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
            response_secret_keyset,
            subject_resolver: Arc::new(NoopEmailOtpSubjectResolver),
        })
    }

    pub(crate) fn with_subject_resolver(
        mut self,
        subject_resolver: Arc<dyn PostgresEmailOtpSubjectResolver>,
    ) -> Self {
        self.subject_resolver = subject_resolver;
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
        })?;
        let delivery_payload = encode_method_payload(&EmailOtpDeliveryPayload {
            challenge_id: request.challenge_id.as_bytes().to_vec(),
            delivery_idempotency_key: request.idempotency_key.clone(),
            queued_at: request.now.get(),
        })?;
        Ok(vec![self.method_commit_work(
            vec![MethodCommitPrecondition::new(
                EMAIL_OTP_CHALLENGE_ABSENT_OPERATION,
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
        let statement = format!(
            "SELECT recipient_handle FROM {} WHERE challenge_id = $1 AND consumed_at IS NULL",
            self.config.table_names()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.email_otp.resolve_verified_identifier.fetch_recipient_handle",
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
        let recipient_handle = recipient_handle_result?;
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
            "SELECT count(*) FROM {} WHERE consumed_at IS NULL",
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
                EMAIL_OTP_CHALLENGE_ABSENT_OPERATION => {
                    let payload: EmailOtpIssuePayload =
                        decode_method_payload(precondition.payload())?;
                    self.enforce_challenge_absent(tx, &payload.challenge_id)
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
                consumed_at BIGINT
            )
            "#,
            table_names.challenge_table.quoted()
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
                PRIMARY KEY (challenge_id, delivery_idempotency_key)
            )
            "#,
            table_names.delivery_command_table.quoted()
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
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let table_names = self.table_names_for_commit()?;
        validate_email_otp_table_exists(tx, &table_names.challenge_table).await?;
        validate_email_otp_table_exists(tx, &table_names.delivery_command_table).await
    }

    async fn enforce_challenge_absent(
        &self,
        tx: &mut Tx<'_>,
        challenge_id: &[u8],
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            "SELECT 1 FROM {} WHERE challenge_id = $1 FOR UPDATE",
            self.table_names_for_commit()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.email_otp.precondition.challenge_absent",
            Some(statement.as_str()),
        );
        let exists = pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .is_some();
        if exists {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "email otp challenge already exists",
            ));
        }
        Ok(())
    }

    async fn enforce_challenge_open(
        &self,
        tx: &mut Tx<'_>,
        challenge_id: &[u8],
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            "SELECT consumed_at FROM {} WHERE challenge_id = $1 FOR UPDATE",
            self.table_names_for_commit()?.challenge_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.email_otp.precondition.challenge_open",
            Some(statement.as_str()),
        );
        let consumed_at = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(challenge_id)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .map(|row| row.try_get::<Option<i64>, _>("consumed_at"))
            .transpose()
            .map_err(DbError::query)?;
        match consumed_at {
            Some(None) => Ok(()),
            Some(Some(_)) => Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "email otp challenge already consumed",
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
            SET consumed_at = $2
            WHERE challenge_id = $1 AND consumed_at IS NULL
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
                WHERE challenge_id = $1 AND consumed_at IS NULL
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

impl Default for PostgresEmailOtpMethodPluginConfig {
    fn default() -> Self {
        Self::for_db_bootstrap_config(&BootstrapConfig::default())
            .expect("default email otp method config must derive valid bootstrap table names")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_schema_local_bootstrap_tables() {
        let bootstrap_config = BootstrapConfig::default();
        let config = PostgresEmailOtpMethodPluginConfig::default();
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

async fn validate_email_otp_table_exists(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
) -> Result<(), PostgresAuthMethodCommitError> {
    let schema = table.schema().map(PgSchemaName::as_str).unwrap_or("public");
    let table_name = table.table().as_str();
    let statement = r#"
        SELECT count(*)
        FROM information_schema.tables
        WHERE table_schema = $1 AND table_name = $2
    "#;
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "auth_core.email_otp.schema.validate_table",
        Some(statement),
    );
    let count = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement))
        .bind(schema)
        .bind(table_name)
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    if count == 1 {
        Ok(())
    } else {
        Err(PostgresAuthMethodCommitError::InvalidOperation(format!(
            "missing email otp method table {}",
            table.quoted()
        )))
    }
}
