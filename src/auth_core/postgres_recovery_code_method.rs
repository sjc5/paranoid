use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use zeroize::Zeroize;

use super::postgres_durable_effect_queue::{
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::postgres_method_runtime::{
    CredentialCreationMethodWorkBuildRequest, CredentialLifecycleMethodWorkAuthority,
    CredentialLifecycleMethodWorkBuildRequest, CredentialMethodWorkBuild,
    KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError,
    PostgresAuthMethodDurableEffectQueueRegistrationError,
    PostgresAuthMethodMountedRouteCapabilities, PostgresAuthMethodPlugin,
    RecoveryCredentialActiveProofMethodVerification, VerifiedActiveProofMethodResponse,
    enqueue_no_method_durable_effects_to_queue_in_current_transaction,
    register_no_queue_handlers_for_method_durable_effects,
};
use super::postgres_method_schema::{
    MethodTableCheckConstraint, MethodTableColumnContract, MethodTableIndexContract,
    ensure_method_table_check_constraints_in_current_transaction, quoted_bigint_nonnegative,
    quoted_len_at_least_one_and_at_most, quoted_len_equals, quoted_nullable_bigint_nonnegative,
    validate_method_table_schema_in_current_transaction,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::prelude::*;
use crate::crypto::{
    Base58, Encrypted, Keyset, MacOverSecret, SecretBytes, decrypt, encrypt, random_public_bytes,
};
#[cfg(test)]
use crate::db::Pool;
#[cfg(test)]
use crate::db::pooler_safe_query_scalar;
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Tx, WriteTx, pooler_safe_query, queue, unparameterized_simple_query,
};

pub(crate) const RECOVERY_CODE_METHOD_LABEL: &str = "recovery_code";
const RECOVERY_CODE_STILL_UNUSED_OPERATION: &str = "recovery_code_still_unused";
const RECOVERY_CODE_CONSUME_OPERATION: &str = "recovery_code_consume";
const RECOVERY_CODE_SET_ABSENT_OPERATION: &str = "recovery_code_set_absent";
const RECOVERY_CODE_SET_LOCK_OPERATION: &str = "recovery_code_set_lock";
const RECOVERY_CODE_CREATE_SET_OPERATION: &str = "recovery_code_create_set";
const RECOVERY_CODE_REGENERATE_SET_OPERATION: &str = "recovery_code_regenerate_set";
const RECOVERY_CODE_SECRET_CONTEXT: &[u8] = b"paranoid/auth/v1/recovery-code-secret";
const RECOVERY_CODE_TOKEN_CONTEXT: &[u8] = b"paranoid/auth/v1/recovery-code-token";
const DEFAULT_RECOVERY_CODE_TABLE_PREFIX: &str = "auth_recovery_code_";
const RECOVERY_CODE_RANDOM_TOKEN_BYTES: usize = 32;
const RECOVERY_CODE_ID_BYTES: usize = 32;
const MAX_GENERATED_RECOVERY_CODES: u8 = 32;

pub(crate) struct PostgresRecoveryCodeMethodPlugin {
    config: PostgresRecoveryCodeMethodPluginConfig,
    method: ProofMethodDeclaration,
    secret_keyset: Keyset,
}

impl PostgresRecoveryCodeMethodPlugin {
    pub(crate) fn new(
        config: PostgresRecoveryCodeMethodPluginConfig,
        secret_keyset: Keyset,
    ) -> Result<Self, PostgresRecoveryCodeMethodError> {
        Ok(Self {
            config,
            method: ProofMethodDeclaration::new(
                ProofFamily::RecoveryCode,
                RECOVERY_CODE_METHOD_LABEL,
            )
            .map_err(PostgresRecoveryCodeMethodError::Core)?,
            secret_keyset,
        })
    }

    async fn verify_known_subject_response_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<KnownSubjectActiveProofMethodVerification, PostgresRecoveryCodeMethodError> {
        if response.method != self.method {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::LoadedStateContradiction("recovery code response used a different method"),
            ));
        }
        let token = self.decode_recovery_code_secret_response(&response.secret_response)?;
        if token.subject_id != *subject_id {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        }
        let secret_mac = token
            .random_token
            .to_mac(
                &self.secret_keyset,
                &recovery_code_secret_context(subject_id, &self.method),
            )
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let Some(recovery_code) = self
            .fetch_locked_unused_recovery_code(tx, subject_id, &secret_mac)
            .await?
        else {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        };
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            self.method.verified_proof_summary(),
            None,
            recovery_code_proof_source(recovery_code.credential_instance_id.as_bytes())?,
        )
        .map_err(PostgresRecoveryCodeMethodError::Core)?;
        let method_commit_work = vec![self.consume_recovery_code_commit_work(
            response.now,
            subject_id,
            &recovery_code.credential_instance_id,
            &recovery_code.recovery_code_id,
            &secret_mac,
        )?];
        Ok(KnownSubjectActiveProofMethodVerification::Accepted(
            VerifiedActiveProofMethodResponse::new(verified_proof, method_commit_work)
                .map_err(PostgresRecoveryCodeMethodError::Core)?,
        ))
    }

    fn verify_known_subject_response_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresRecoveryCodeMethodError> {
        if response.method != self.method {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::LoadedStateContradiction("recovery code response used a different method"),
            ));
        }
        let token = self.decode_recovery_code_secret_response(&response.secret_response)?;
        if continuation
            .subject_id
            .as_ref()
            .is_some_and(|subject_id| subject_id != &token.subject_id)
        {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::StatelessFastFailVerificationFailed,
            ));
        }
        Ok(())
    }

    fn resolve_recovery_credential_subject_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<SubjectId, PostgresRecoveryCodeMethodError> {
        if response.method != self.method {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::LoadedStateContradiction(
                    "recovery credential response used a different method",
                ),
            ));
        }
        let token = self.decode_recovery_code_secret_response(&response.secret_response)?;
        if continuation
            .subject_id
            .as_ref()
            .is_some_and(|subject_id| subject_id != &token.subject_id)
        {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::StatelessFastFailVerificationFailed,
            ));
        }
        Ok(token.subject_id)
    }

    async fn verify_recovery_credential_response_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        candidate_subject_id: &SubjectId,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<RecoveryCredentialActiveProofMethodVerification, PostgresRecoveryCodeMethodError>
    {
        if response.method != self.method {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::LoadedStateContradiction(
                    "recovery credential response used a different method",
                ),
            ));
        }
        let token = self.decode_recovery_code_secret_response(&response.secret_response)?;
        if token.subject_id != *candidate_subject_id {
            return Ok(RecoveryCredentialActiveProofMethodVerification::Rejected);
        }
        let secret_mac = token
            .random_token
            .to_mac(
                &self.secret_keyset,
                &recovery_code_secret_context(candidate_subject_id, &self.method),
            )
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let Some(recovery_code) = self
            .fetch_locked_unused_recovery_code(tx, candidate_subject_id, &secret_mac)
            .await?
        else {
            return Ok(RecoveryCredentialActiveProofMethodVerification::Rejected);
        };
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            self.method.verified_proof_summary(),
            Some(candidate_subject_id.clone()),
            recovery_code_proof_source(recovery_code.credential_instance_id.as_bytes())?,
        )
        .map_err(PostgresRecoveryCodeMethodError::Core)?;
        let method_commit_work = vec![self.consume_recovery_code_commit_work(
            response.now,
            candidate_subject_id,
            &recovery_code.credential_instance_id,
            &recovery_code.recovery_code_id,
            &secret_mac,
        )?];
        Ok(RecoveryCredentialActiveProofMethodVerification::Accepted(
            VerifiedActiveProofMethodResponse::new(verified_proof, method_commit_work)
                .map_err(PostgresRecoveryCodeMethodError::Core)?,
        ))
    }

    fn decode_recovery_code_secret_response(
        &self,
        response: &KnownSubjectActiveProofSecretResponse,
    ) -> Result<DecodedRecoveryCodeToken, PostgresRecoveryCodeMethodError> {
        let encoded = std::str::from_utf8(response.expose_secret()).map_err(|_| {
            PostgresRecoveryCodeMethodError::Core(Error::InvalidIdentifierString {
                input_name: "recovery code",
            })
        })?;
        let encrypted = Base58::<Encrypted<SealedRecoveryCodeTokenPayload>>::parse_str(encoded)
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?
            .decode()
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let mut payload = decrypt(
            &self.secret_keyset,
            &encrypted,
            &recovery_code_token_context(&self.method),
        )
        .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let subject_id = SubjectId::from_bytes(std::mem::take(&mut payload.subject_id))
            .map_err(PostgresRecoveryCodeMethodError::Core)?;
        let random_token = SecretBytes::try_from(std::mem::take(&mut payload.random_token))
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        Ok(DecodedRecoveryCodeToken {
            subject_id,
            random_token,
        })
    }

    async fn fetch_locked_unused_recovery_code(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        secret_mac: &MacOverSecret,
    ) -> Result<Option<FetchedRecoveryCode>, PostgresRecoveryCodeMethodError> {
        let statement = format!(
            r#"
            SELECT recovery_code_id, credential_instance_id
            FROM {}
            WHERE subject_id = $1
                AND recovery_code_secret_mac = $2
                AND consumed_at IS NULL
                AND superseded_at IS NULL
            FOR UPDATE
            "#,
            self.table_names()?.recovery_code_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.recovery_code.verify.fetch_locked_unused_code",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(secret_mac.as_bytes())
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)?
            .map(|row| {
                let credential_instance_id = VerifiedProofSourceId::from_bytes(
                    row.try_get::<Vec<u8>, _>("credential_instance_id")?,
                )
                .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
                Ok(FetchedRecoveryCode {
                    recovery_code_id: row.try_get::<Vec<u8>, _>("recovery_code_id")?,
                    credential_instance_id,
                })
            })
            .transpose()
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)
    }

    fn consume_recovery_code_commit_work(
        &self,
        now: UnixSeconds,
        subject_id: &SubjectId,
        credential_instance_id: &VerifiedProofSourceId,
        recovery_code_id: &[u8],
        secret_mac: &MacOverSecret,
    ) -> Result<MethodCommitWork, PostgresRecoveryCodeMethodError> {
        let payload = encode_recovery_code_payload(&RecoveryCodeConsumePayload {
            subject_id: subject_id.as_bytes().to_vec(),
            credential_instance_id: credential_instance_id.as_bytes().to_vec(),
            recovery_code_id: recovery_code_id.to_vec(),
            recovery_code_secret_mac: secret_mac.as_bytes().to_vec(),
            consumed_at: now.get(),
        })?;
        MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(
                    RECOVERY_CODE_STILL_UNUSED_OPERATION,
                    payload.clone(),
                )
                .map_err(PostgresRecoveryCodeMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(RECOVERY_CODE_CONSUME_OPERATION, payload)
                    .map_err(PostgresRecoveryCodeMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresRecoveryCodeMethodError::Core)
    }

    fn build_recovery_code_set_creation(
        &self,
        now: UnixSeconds,
        new_credential: &CredentialInstanceMetadata,
        method_payload: &CredentialCreationMethodPayload,
    ) -> Result<CredentialMethodWorkBuild, PostgresRecoveryCodeMethodError> {
        self.validate_credential_target(new_credential)?;
        let generated =
            self.generate_recovery_code_set(now, new_credential, method_payload.as_bytes())?;
        let payload = encode_recovery_code_payload(generated.payload())?;
        let method_commit_work = MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(RECOVERY_CODE_SET_ABSENT_OPERATION, payload.clone())
                    .map_err(PostgresRecoveryCodeMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(RECOVERY_CODE_CREATE_SET_OPERATION, payload)
                    .map_err(PostgresRecoveryCodeMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresRecoveryCodeMethodError::Core)?;
        Ok(CredentialMethodWorkBuild::new(
            vec![method_commit_work],
            PostCommitMethodResponseMaterial::from_generated_recovery_codes(
                generated.into_response_material()?,
            ),
        ))
    }

    fn build_recovery_code_set_regeneration(
        &self,
        now: UnixSeconds,
        target_credential: &CredentialInstanceMetadata,
        method_payload: &CredentialLifecycleMethodPayload,
    ) -> Result<CredentialMethodWorkBuild, PostgresRecoveryCodeMethodError> {
        self.validate_credential_target(target_credential)?;
        let generated =
            self.generate_recovery_code_set(now, target_credential, method_payload.as_bytes())?;
        let payload = encode_recovery_code_payload(generated.payload())?;
        let method_commit_work = MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(RECOVERY_CODE_SET_LOCK_OPERATION, payload.clone())
                    .map_err(PostgresRecoveryCodeMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(RECOVERY_CODE_REGENERATE_SET_OPERATION, payload)
                    .map_err(PostgresRecoveryCodeMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresRecoveryCodeMethodError::Core)?;
        Ok(CredentialMethodWorkBuild::new(
            vec![method_commit_work],
            PostCommitMethodResponseMaterial::from_generated_recovery_codes(
                generated.into_response_material()?,
            ),
        ))
    }

    fn validate_credential_target(
        &self,
        credential: &CredentialInstanceMetadata,
    ) -> Result<(), PostgresRecoveryCodeMethodError> {
        if credential.proof_family() != self.method.family()
            || credential.method_label() != self.method.method_label()
        {
            return Err(PostgresRecoveryCodeMethodError::Core(
                Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch,
            ));
        }
        Ok(())
    }

    fn generate_recovery_code_set(
        &self,
        now: UnixSeconds,
        credential: &CredentialInstanceMetadata,
        method_payload: &[u8],
    ) -> Result<GeneratedRecoveryCodeSetBuild, PostgresRecoveryCodeMethodError> {
        let request: RecoveryCodeGenerationRequestPayload =
            decode_recovery_code_generation_request(method_payload)?;
        if request.code_count == 0 || request.code_count > MAX_GENERATED_RECOVERY_CODES {
            return Err(PostgresRecoveryCodeMethodError::Core(Error::InvalidConfig(
                "invalid recovery code generation count",
            )));
        }
        let mut rows = Vec::with_capacity(usize::from(request.code_count));
        let mut response_codes = Vec::with_capacity(usize::from(request.code_count));
        for _ in 0..request.code_count {
            let random_token: SecretBytes = SecretBytes::random(RECOVERY_CODE_RANDOM_TOKEN_BYTES)
                .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
            let recovery_code_id = random_public_bytes(RECOVERY_CODE_ID_BYTES)
                .map_err(PostgresRecoveryCodeMethodError::Crypto)?
                .into_bytes();
            let secret_mac = random_token
                .to_mac(
                    &self.secret_keyset,
                    &recovery_code_secret_context(credential.subject_id(), &self.method),
                )
                .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
            let display_token = self
                .seal_recovery_code_token(credential.subject_id(), random_token.expose_secret())?;
            response_codes.push(
                GeneratedRecoveryCode::from_display_token(display_token)
                    .map_err(PostgresRecoveryCodeMethodError::Core)?,
            );
            rows.push(RecoveryCodeSetRowPayload {
                recovery_code_id,
                recovery_code_secret_mac: secret_mac.as_bytes().to_vec(),
            });
        }
        Ok(GeneratedRecoveryCodeSetBuild {
            payload: RecoveryCodeSetMutationPayload {
                subject_id: credential.subject_id().as_bytes().to_vec(),
                credential_instance_id: credential.credential_instance_id().as_bytes().to_vec(),
                changed_at: now.get(),
                rows,
            },
            response_material: GeneratedRecoveryCodeSet::new(
                credential.credential_instance_id().clone(),
                response_codes,
            )
            .map_err(PostgresRecoveryCodeMethodError::Core)?,
        })
    }

    fn table_names(&self) -> Result<RecoveryCodeTableNames, PostgresRecoveryCodeMethodError> {
        self.config.table_names()
    }

    fn table_names_for_commit(
        &self,
    ) -> Result<RecoveryCodeTableNames, PostgresAuthMethodCommitError> {
        self.table_names().map_err(|error| match error {
            PostgresRecoveryCodeMethodError::Database(error) => {
                PostgresAuthMethodCommitError::Database(error)
            }
            other => PostgresAuthMethodCommitError::InvalidOperation(other.to_string()),
        })
    }

    #[cfg(test)]
    pub(crate) fn recovery_code_table_name_for_test(
        &self,
    ) -> Result<PgQualifiedTableName, PostgresRecoveryCodeMethodError> {
        Ok(self.table_names()?.recovery_code_table)
    }

    async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let table = self.table_names_for_commit()?.recovery_code_table;
        let create_statement = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                recovery_code_id BYTEA PRIMARY KEY,
                credential_instance_id BYTEA NOT NULL,
                subject_id BYTEA NOT NULL,
                recovery_code_secret_mac BYTEA NOT NULL,
                created_at BIGINT NOT NULL,
                superseded_at BIGINT,
                consumed_at BIGINT,
                UNIQUE (subject_id, recovery_code_secret_mac),
                UNIQUE (credential_instance_id, recovery_code_secret_mac),
                CHECK (octet_length(recovery_code_id) = {}),
                CHECK (octet_length(credential_instance_id) >= 1 AND octet_length(credential_instance_id) <= {}),
                CHECK (octet_length(subject_id) >= 1 AND octet_length(subject_id) <= {}),
                CHECK (octet_length(recovery_code_secret_mac) = {}),
                CHECK (created_at >= 0),
                CHECK (superseded_at IS NULL OR superseded_at >= 0),
                CHECK (consumed_at IS NULL OR consumed_at >= 0)
            )
            "#,
            table.quoted(),
            RECOVERY_CODE_ID_BYTES,
            ID_MAX_BYTES,
            ID_MAX_BYTES,
            crate::crypto::MAC_OVER_SECRET_SIZE,
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.recovery_code.schema.create_recovery_code_table",
            Some(create_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(create_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;

        let lookup_index =
            PgIdentifier::new(format!("{}_unused_lookup_idx", table.table().as_str()))
                .map_err(DbError::from)
                .map_err(PostgresAuthMethodCommitError::Database)?;
        let index_statement = format!(
            r#"
            CREATE INDEX IF NOT EXISTS {}
            ON {} (subject_id, recovery_code_secret_mac)
            WHERE consumed_at IS NULL AND superseded_at IS NULL
            "#,
            lookup_index.quoted(),
            table.quoted(),
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.recovery_code.schema.create_unused_lookup_index",
            Some(index_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(index_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        let credential_index =
            PgIdentifier::new(format!("{}_active_credential_idx", table.table().as_str()))
                .map_err(DbError::from)
                .map_err(PostgresAuthMethodCommitError::Database)?;
        let credential_index_statement = format!(
            r#"
            CREATE INDEX IF NOT EXISTS {}
            ON {} (credential_instance_id)
            WHERE consumed_at IS NULL AND superseded_at IS NULL
            "#,
            credential_index.quoted(),
            table.quoted(),
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.recovery_code.schema.create_active_credential_index",
            Some(credential_index_statement.as_str()),
        );
        unparameterized_simple_query(sqlx::AssertSqlSafe(credential_index_statement.as_str()))
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        let checks = recovery_code_table_checks();
        ensure_method_table_check_constraints_in_current_transaction(tx, &table, &checks).await?;
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        validate_method_table_schema_in_current_transaction(
            tx,
            &self.table_names_for_commit()?.recovery_code_table,
            &recovery_code_table_columns(),
            &recovery_code_table_checks(),
            &recovery_code_table_indexes(),
        )
        .await
    }

    async fn enforce_recovery_code_still_unused(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeConsumePayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            SELECT recovery_code_secret_mac, consumed_at, superseded_at
            FROM {}
            WHERE recovery_code_id = $1
                AND credential_instance_id = $2
                AND subject_id = $3
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.recovery_code_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.recovery_code.precondition.still_unused",
            Some(statement.as_str()),
        );
        let row = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.recovery_code_id)
            .bind(&payload.credential_instance_id)
            .bind(&payload.subject_id)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        let Some(row) = row else {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code does not exist",
            ));
        };
        let stored_mac = row
            .try_get::<Vec<u8>, _>("recovery_code_secret_mac")
            .map_err(DbError::query)?;
        if stored_mac != payload.recovery_code_secret_mac {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code verifier changed",
            ));
        }
        let consumed_at = row
            .try_get::<Option<i64>, _>("consumed_at")
            .map_err(DbError::query)?;
        if consumed_at.is_some() {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code is already consumed",
            ));
        }
        let superseded_at = row
            .try_get::<Option<i64>, _>("superseded_at")
            .map_err(DbError::query)?;
        if superseded_at.is_some() {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code is superseded",
            ));
        }
        Ok(())
    }

    async fn enforce_recovery_code_set_absent(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeSetMutationPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            SELECT recovery_code_id
            FROM {}
            WHERE credential_instance_id = $1
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.recovery_code_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "auth_core.recovery_code.precondition.set_absent",
            Some(statement.as_str()),
        );
        let rows = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.credential_instance_id)
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        if rows.is_empty() {
            Ok(())
        } else {
            Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code credential set already exists",
            ))
        }
    }

    async fn lock_recovery_code_set(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeSetMutationPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            SELECT recovery_code_id
            FROM {}
            WHERE credential_instance_id = $1 AND subject_id = $2
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.recovery_code_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "auth_core.recovery_code.precondition.lock_set",
            Some(statement.as_str()),
        );
        let rows = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.credential_instance_id)
            .bind(&payload.subject_id)
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        if rows.is_empty() {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code credential set does not exist",
            ));
        }
        Ok(())
    }

    async fn consume_recovery_code(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeConsumePayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            UPDATE {}
            SET consumed_at = $5
            WHERE recovery_code_id = $1
                AND credential_instance_id = $2
                AND subject_id = $3
                AND recovery_code_secret_mac = $4
                AND consumed_at IS NULL
                AND superseded_at IS NULL
            "#,
            self.table_names_for_commit()?.recovery_code_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.recovery_code.mutation.consume",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.recovery_code_id)
            .bind(&payload.credential_instance_id)
            .bind(&payload.subject_id)
            .bind(&payload.recovery_code_secret_mac)
            .bind(i64_from_unix_seconds_u64(payload.consumed_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "recovery code is not unused",
            ));
        }
        Ok(())
    }

    async fn create_recovery_code_set(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeSetMutationPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        insert_recovery_code_rows(
            tx,
            &self.table_names_for_commit()?.recovery_code_table,
            payload,
        )
        .await
    }

    async fn regenerate_recovery_code_set(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeSetMutationPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            UPDATE {}
            SET superseded_at = $3
            WHERE credential_instance_id = $1
                AND subject_id = $2
                AND consumed_at IS NULL
                AND superseded_at IS NULL
            "#,
            self.table_names_for_commit()?.recovery_code_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.recovery_code.mutation.supersede_unused_set",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.credential_instance_id)
            .bind(&payload.subject_id)
            .bind(i64_from_unix_seconds_u64(payload.changed_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        insert_recovery_code_rows(
            tx,
            &self.table_names_for_commit()?.recovery_code_table,
            payload,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_recovery_code_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
        credential_instance_id: &VerifiedProofSourceId,
        recovery_code_id: &[u8],
        recovery_code_secret: &[u8],
        now: UnixSeconds,
    ) -> Result<(), PostgresRecoveryCodeMethodError> {
        let secret: SecretBytes = SecretBytes::try_from(recovery_code_secret)
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let secret_mac = secret
            .to_mac(
                &self.secret_keyset,
                &recovery_code_secret_context(subject_id, &self.method),
            )
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let statement = format!(
            r#"
            INSERT INTO {} (
                recovery_code_id,
                credential_instance_id,
                subject_id,
                recovery_code_secret_mac,
                created_at
            )
            VALUES ($1,$2,$3,$4,$5)
            "#,
            self.table_names()?.recovery_code_table.quoted(),
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresRecoveryCodeMethodError::Database)?;
        let result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(recovery_code_id)
            .bind(credential_instance_id.as_bytes())
            .bind(subject_id.as_bytes())
            .bind(secret_mac.as_bytes())
            .bind(i64_from_unix_seconds_u64_for_method(now)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)
            .map(|_| ());
        match result {
            Ok(()) => tx
                .commit()
                .await
                .map_err(PostgresRecoveryCodeMethodError::Database),
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn generation_payload_for_test(
        code_count: u8,
    ) -> Result<CredentialCreationMethodPayload, PostgresRecoveryCodeMethodError> {
        let payload =
            encode_recovery_code_payload(&RecoveryCodeGenerationRequestPayload { code_count })?;
        CredentialCreationMethodPayload::try_from_bytes(payload)
            .map_err(PostgresRecoveryCodeMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn regeneration_payload_for_test(
        code_count: u8,
    ) -> Result<CredentialLifecycleMethodPayload, PostgresRecoveryCodeMethodError> {
        let payload =
            encode_recovery_code_payload(&RecoveryCodeGenerationRequestPayload { code_count })?;
        CredentialLifecycleMethodPayload::try_from_bytes(payload)
            .map_err(PostgresRecoveryCodeMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn sealed_recovery_code_response_for_test(
        &self,
        subject_id: &SubjectId,
        recovery_code_secret: &[u8],
    ) -> Result<KnownSubjectActiveProofSecretResponse, PostgresRecoveryCodeMethodError> {
        let encoded = self.seal_recovery_code_token(subject_id, recovery_code_secret)?;
        KnownSubjectActiveProofSecretResponse::try_from_bytes(encoded.into_bytes())
            .map_err(PostgresRecoveryCodeMethodError::Core)
    }

    fn seal_recovery_code_token(
        &self,
        subject_id: &SubjectId,
        random_token: &[u8],
    ) -> Result<String, PostgresRecoveryCodeMethodError> {
        let token = SealedRecoveryCodeTokenPayload {
            subject_id: subject_id.as_bytes().to_vec(),
            random_token: random_token.to_vec(),
        };
        encrypt(
            &self.secret_keyset,
            &token,
            &recovery_code_token_context(&self.method),
        )
        .map_err(PostgresRecoveryCodeMethodError::Crypto)?
        .to_base58()
        .map_err(PostgresRecoveryCodeMethodError::Crypto)
        .map(Base58::into_exposed_string)
    }

    #[cfg(test)]
    pub(crate) async fn count_recovery_codes_for_subject_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
    ) -> Result<i64, PostgresRecoveryCodeMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE subject_id = $1",
            self.table_names()?.recovery_code_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresRecoveryCodeMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresRecoveryCodeMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) async fn count_unused_recovery_codes_for_subject_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
    ) -> Result<i64, PostgresRecoveryCodeMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE subject_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL",
            self.table_names()?.recovery_code_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresRecoveryCodeMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresRecoveryCodeMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl PostgresAuthMethodPlugin for PostgresRecoveryCodeMethodPlugin {
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn mounted_route_capabilities(&self) -> PostgresAuthMethodMountedRouteCapabilities {
        PostgresAuthMethodMountedRouteCapabilities::empty()
            .with_no_session_recovery_credential()
            .with_credential_creation()
            .with_credential_regeneration()
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
            self.build_recovery_code_set_creation(
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
            if !matches!(
                (request.action, request.authority),
                (
                    CredentialLifecycleAction::Regenerate,
                    CredentialLifecycleMethodWorkAuthority::ImmediateRegeneration { .. }
                        | CredentialLifecycleMethodWorkAuthority::MaturePendingAction { .. },
                )
            ) {
                return Err(PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "credential_lifecycle",
                    "recovery code method supports only credential regeneration lifecycle work",
                ));
            }
            self.build_recovery_code_set_regeneration(
                request.now,
                request.target_credential,
                request.method_payload,
            )
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "credential_lifecycle",
                    error,
                )
            })
        })
    }

    fn verify_known_subject_active_proof_method_response_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
    ) -> Result<(), PostgresAuthMethodBuildError> {
        self.verify_known_subject_response_before_state_load(continuation, response)
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "known_subject_active_proof_completion_pre_state",
                    error,
                )
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

    fn resolve_recovery_credential_subject_before_state_load(
        &self,
        continuation: &ActiveProofContinuationCookieDraft,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Result<SubjectId, PostgresAuthMethodBuildError> {
        self.resolve_recovery_credential_subject_before_state_load(continuation, response)
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "recovery_credential_active_proof_completion_pre_state",
                    error,
                )
            })
    }

    fn verify_recovery_credential_active_proof_method_response<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        candidate_subject_id: &'a SubjectId,
        response: &'a CompleteRecoveryCredentialActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        RecoveryCredentialActiveProofMethodVerification,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.verify_recovery_credential_response_in_current_transaction(
                tx,
                candidate_subject_id,
                response,
            )
            .await
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "recovery_credential_active_proof_completion",
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
                RECOVERY_CODE_STILL_UNUSED_OPERATION => {
                    let payload: RecoveryCodeConsumePayload =
                        decode_recovery_code_payload(precondition.payload())?;
                    self.enforce_recovery_code_still_unused(tx, &payload).await
                }
                RECOVERY_CODE_SET_ABSENT_OPERATION => {
                    let payload: RecoveryCodeSetMutationPayload =
                        decode_recovery_code_payload(precondition.payload())?;
                    self.enforce_recovery_code_set_absent(tx, &payload).await
                }
                RECOVERY_CODE_SET_LOCK_OPERATION => {
                    let payload: RecoveryCodeSetMutationPayload =
                        decode_recovery_code_payload(precondition.payload())?;
                    self.lock_recovery_code_set(tx, &payload).await
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
                RECOVERY_CODE_CONSUME_OPERATION => {
                    let payload: RecoveryCodeConsumePayload =
                        decode_recovery_code_payload(mutation.payload())?;
                    self.consume_recovery_code(tx, &payload).await
                }
                RECOVERY_CODE_CREATE_SET_OPERATION => {
                    let payload: RecoveryCodeSetMutationPayload =
                        decode_recovery_code_payload(mutation.payload())?;
                    self.create_recovery_code_set(tx, &payload).await
                }
                RECOVERY_CODE_REGENERATE_SET_OPERATION => {
                    let payload: RecoveryCodeSetMutationPayload =
                        decode_recovery_code_payload(mutation.payload())?;
                    self.regenerate_recovery_code_set(tx, &payload).await
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
pub(crate) struct PostgresRecoveryCodeMethodPluginConfig {
    schema: Option<PgSchemaName>,
    table_prefix: PgIdentifier,
}

impl PostgresRecoveryCodeMethodPluginConfig {
    pub(crate) fn new(
        schema: Option<PgSchemaName>,
        table_prefix: PgIdentifier,
    ) -> Result<Self, PostgresRecoveryCodeMethodError> {
        let config = Self {
            schema,
            table_prefix,
        };
        config.table_names()?;
        Ok(config)
    }

    pub(crate) fn for_db_bootstrap_config(
        bootstrap_config: &BootstrapConfig,
    ) -> Result<Self, PostgresRecoveryCodeMethodError> {
        Self::new(
            Some(bootstrap_config.schema_name().clone()),
            PgIdentifier::new(DEFAULT_RECOVERY_CODE_TABLE_PREFIX)
                .map_err(DbError::from)
                .map_err(PostgresRecoveryCodeMethodError::Database)?,
        )
    }

    fn table_name(&self, suffix: &'static str) -> Result<PgQualifiedTableName, DbError> {
        Ok(PgQualifiedTableName::new(
            self.schema.clone(),
            PgIdentifier::new(format!("{}{}", self.table_prefix.as_str(), suffix))?,
        ))
    }

    fn table_names(&self) -> Result<RecoveryCodeTableNames, PostgresRecoveryCodeMethodError> {
        Ok(RecoveryCodeTableNames {
            recovery_code_table: self
                .table_name("codes")
                .map_err(PostgresRecoveryCodeMethodError::Database)?,
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
        let config =
            PostgresRecoveryCodeMethodPluginConfig::for_db_bootstrap_config(&bootstrap_config)
                .expect("recovery code method config");
        let table_names = config.table_names().expect("table names");

        assert_eq!(
            table_names.recovery_code_table.schema(),
            Some(bootstrap_config.schema_name())
        );
        assert_eq!(
            table_names.recovery_code_table.table().as_str(),
            "auth_recovery_code_codes"
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryCodeTableNames {
    recovery_code_table: PgQualifiedTableName,
}

#[derive(Debug)]
pub(crate) enum PostgresRecoveryCodeMethodError {
    Core(Error),
    Crypto(crate::crypto::Error),
    Database(DbError),
    PayloadEncode(postcard::Error),
    PayloadDecode(postcard::Error),
}

impl fmt::Display for PostgresRecoveryCodeMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Database(error) => write!(f, "{error}"),
            Self::PayloadEncode(error) => {
                write!(
                    f,
                    "recovery code method payload could not be encoded: {error}"
                )
            }
            Self::PayloadDecode(error) => {
                write!(
                    f,
                    "recovery code method payload could not be decoded: {error}"
                )
            }
        }
    }
}

impl std::error::Error for PostgresRecoveryCodeMethodError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::PayloadEncode(error) => Some(error),
            Self::PayloadDecode(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryCodeGenerationRequestPayload {
    code_count: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryCodeSetMutationPayload {
    subject_id: Vec<u8>,
    credential_instance_id: Vec<u8>,
    changed_at: u64,
    rows: Vec<RecoveryCodeSetRowPayload>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryCodeSetRowPayload {
    recovery_code_id: Vec<u8>,
    recovery_code_secret_mac: Vec<u8>,
}

struct GeneratedRecoveryCodeSetBuild {
    payload: RecoveryCodeSetMutationPayload,
    response_material: GeneratedRecoveryCodeSet,
}

impl GeneratedRecoveryCodeSetBuild {
    fn payload(&self) -> &RecoveryCodeSetMutationPayload {
        &self.payload
    }

    fn into_response_material(
        self,
    ) -> Result<GeneratedRecoveryCodeSet, PostgresRecoveryCodeMethodError> {
        Ok(self.response_material)
    }
}

struct FetchedRecoveryCode {
    recovery_code_id: Vec<u8>,
    credential_instance_id: VerifiedProofSourceId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryCodeConsumePayload {
    subject_id: Vec<u8>,
    credential_instance_id: Vec<u8>,
    recovery_code_id: Vec<u8>,
    recovery_code_secret_mac: Vec<u8>,
    consumed_at: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct SealedRecoveryCodeTokenPayload {
    subject_id: Vec<u8>,
    random_token: Vec<u8>,
}

impl Drop for SealedRecoveryCodeTokenPayload {
    fn drop(&mut self) {
        self.random_token.zeroize();
    }
}

struct DecodedRecoveryCodeToken {
    subject_id: SubjectId,
    random_token: SecretBytes,
}

fn encode_recovery_code_payload<T: Serialize>(
    payload: &T,
) -> Result<Vec<u8>, PostgresRecoveryCodeMethodError> {
    postcard::to_allocvec(payload).map_err(PostgresRecoveryCodeMethodError::PayloadEncode)
}

fn decode_recovery_code_payload<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
) -> Result<T, PostgresAuthMethodCommitError> {
    postcard::from_bytes(payload).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "invalid recovery code method payload".to_owned(),
        )
    })
}

fn decode_recovery_code_generation_request(
    payload: &[u8],
) -> Result<RecoveryCodeGenerationRequestPayload, PostgresRecoveryCodeMethodError> {
    postcard::from_bytes(payload).map_err(PostgresRecoveryCodeMethodError::PayloadDecode)
}

fn recovery_code_secret_context(
    subject_id: &SubjectId,
    method: &ProofMethodDeclaration,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(
        RECOVERY_CODE_SECRET_CONTEXT.len()
            + 16
            + subject_id.as_bytes().len()
            + method.method_label().len(),
    );
    context.extend_from_slice(RECOVERY_CODE_SECRET_CONTEXT);
    push_len_prefixed_bytes(&mut context, subject_id.as_bytes());
    push_len_prefixed_bytes(&mut context, method.method_label().as_bytes());
    context
}

fn recovery_code_token_context(method: &ProofMethodDeclaration) -> Vec<u8> {
    let mut context =
        Vec::with_capacity(RECOVERY_CODE_TOKEN_CONTEXT.len() + 8 + method.method_label().len());
    context.extend_from_slice(RECOVERY_CODE_TOKEN_CONTEXT);
    push_len_prefixed_bytes(&mut context, method.method_label().as_bytes());
    context
}

fn recovery_code_proof_source(
    credential_instance_id: &[u8],
) -> Result<VerifiedProofSource, PostgresRecoveryCodeMethodError> {
    Ok(VerifiedProofSource::new(
        VerifiedProofSourceKind::CredentialInstance,
        VerifiedProofSourceId::from_bytes(credential_instance_id.to_vec())
            .map_err(PostgresRecoveryCodeMethodError::Core)?,
    ))
}

fn push_len_prefixed_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    target.extend_from_slice(bytes);
}

fn i64_from_unix_seconds_u64(value: u64) -> Result<i64, PostgresAuthMethodCommitError> {
    i64::try_from(value).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "recovery code timestamp exceeds Postgres BIGINT domain".to_owned(),
        )
    })
}

fn i64_from_unix_seconds_u64_for_method(
    value: UnixSeconds,
) -> Result<i64, PostgresRecoveryCodeMethodError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresRecoveryCodeMethodError::Core(Error::TimeOverflow))
}

fn recovery_code_table_columns() -> Vec<MethodTableColumnContract> {
    vec![
        MethodTableColumnContract::bytea("recovery_code_id", true),
        MethodTableColumnContract::bytea("credential_instance_id", true),
        MethodTableColumnContract::bytea("subject_id", true),
        MethodTableColumnContract::bytea("recovery_code_secret_mac", true),
        MethodTableColumnContract::bigint("created_at", true),
        MethodTableColumnContract::bigint("superseded_at", false),
        MethodTableColumnContract::bigint("consumed_at", false),
    ]
}

fn recovery_code_table_checks() -> Vec<MethodTableCheckConstraint> {
    vec![
        MethodTableCheckConstraint::new(
            "recovery_code_id_len",
            quoted_len_equals("recovery_code_id", RECOVERY_CODE_ID_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "credential_instance_id_len",
            quoted_len_at_least_one_and_at_most("credential_instance_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "subject_id_len",
            quoted_len_at_least_one_and_at_most("subject_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "secret_mac_len",
            quoted_len_equals(
                "recovery_code_secret_mac",
                crate::crypto::MAC_OVER_SECRET_SIZE,
            ),
        ),
        MethodTableCheckConstraint::new(
            "created_at_nonnegative",
            quoted_bigint_nonnegative("created_at"),
        ),
        MethodTableCheckConstraint::new(
            "superseded_at_nonnegative",
            quoted_nullable_bigint_nonnegative("superseded_at"),
        ),
        MethodTableCheckConstraint::new(
            "consumed_at_nonnegative",
            quoted_nullable_bigint_nonnegative("consumed_at"),
        ),
    ]
}

fn recovery_code_table_indexes() -> Vec<MethodTableIndexContract> {
    let unused_predicate = r#""consumed_at" IS NULL AND "superseded_at" IS NULL"#;
    vec![
        MethodTableIndexContract::unique("recovery-code primary-key", ["recovery_code_id"]),
        MethodTableIndexContract::unique(
            "subject secret lookup",
            ["subject_id", "recovery_code_secret_mac"],
        ),
        MethodTableIndexContract::unique(
            "credential secret lookup",
            ["credential_instance_id", "recovery_code_secret_mac"],
        ),
        MethodTableIndexContract::nonunique_partial(
            "unused lookup",
            ["subject_id", "recovery_code_secret_mac"],
            unused_predicate,
        ),
        MethodTableIndexContract::nonunique_partial(
            "active credential lookup",
            ["credential_instance_id"],
            unused_predicate,
        ),
    ]
}

async fn insert_recovery_code_rows(
    tx: &mut Tx<'_>,
    table: &PgQualifiedTableName,
    payload: &RecoveryCodeSetMutationPayload,
) -> Result<(), PostgresAuthMethodCommitError> {
    if payload.rows.is_empty() {
        return Err(PostgresAuthMethodCommitError::InvalidOperation(
            "recovery code set mutation contains no rows".to_owned(),
        ));
    }
    let row_count = payload.rows.len();
    let recovery_code_ids = payload
        .rows
        .iter()
        .map(|row| row.recovery_code_id.clone())
        .collect::<Vec<_>>();
    let credential_instance_ids = vec![payload.credential_instance_id.clone(); row_count];
    let subject_ids = vec![payload.subject_id.clone(); row_count];
    let recovery_code_secret_macs = payload
        .rows
        .iter()
        .map(|row| row.recovery_code_secret_mac.clone())
        .collect::<Vec<_>>();
    let changed_at = i64_from_unix_seconds_u64(payload.changed_at)?;
    let created_ats = vec![changed_at; row_count];
    let statement = format!(
        r#"
        INSERT INTO {} (
            recovery_code_id,
            credential_instance_id,
            subject_id,
            recovery_code_secret_mac,
            created_at
        )
        SELECT
            recovery_code_id,
            credential_instance_id,
            subject_id,
            recovery_code_secret_mac,
            created_at
        FROM UNNEST(
            $1::bytea[],
            $2::bytea[],
            $3::bytea[],
            $4::bytea[],
            $5::bigint[]
        ) AS rows(
            recovery_code_id,
            credential_instance_id,
            subject_id,
            recovery_code_secret_mac,
            created_at
        )
        "#,
        table.quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.recovery_code.mutation.insert_set",
        Some(statement.as_str()),
    );
    let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(recovery_code_ids)
        .bind(credential_instance_ids)
        .bind(subject_ids)
        .bind(recovery_code_secret_macs)
        .bind(created_ats)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?
        .rows_affected();
    if affected != row_count as u64 {
        return Err(PostgresAuthMethodCommitError::InvalidOperation(
            "recovery code set insert affected an unexpected row count".to_owned(),
        ));
    }
    Ok(())
}
