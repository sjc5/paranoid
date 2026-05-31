use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::crypto::{Keyset, MacOverSecret, SecretBytes};
#[cfg(test)]
use crate::db::Pool;
use crate::db::{
    DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName, PgSchemaName, Tx,
    pooler_safe_query, pooler_safe_query_scalar, unparameterized_simple_query,
};

use super::postgres_method_runtime::{
    KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError,
    PostgresAuthMethodPlugin, VerifiedActiveProofMethodResponse,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::*;

const RECOVERY_CODE_METHOD_LABEL: &str = "recovery_code";
const RECOVERY_CODE_STILL_UNUSED_OPERATION: &str = "recovery_code_still_unused";
const RECOVERY_CODE_CONSUME_OPERATION: &str = "recovery_code_consume";
const RECOVERY_CODE_SECRET_CONTEXT: &[u8] = b"paranoid/auth/v1/recovery-code-secret";
const DEFAULT_RECOVERY_CODE_TABLE_PREFIX: &str = "__paranoid_auth_recovery_code_";

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
        let submitted_secret: SecretBytes =
            SecretBytes::try_from(response.secret_response.expose_secret())
                .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let secret_mac = submitted_secret
            .to_mac(
                &self.secret_keyset,
                &recovery_code_secret_context(subject_id, &self.method),
            )
            .map_err(PostgresRecoveryCodeMethodError::Crypto)?;
        let Some(recovery_code_id) = self
            .fetch_locked_unused_recovery_code_id(tx, subject_id, &secret_mac)
            .await?
        else {
            return Ok(KnownSubjectActiveProofMethodVerification::Rejected);
        };
        let verified_proof =
            VerifiedActiveProof::from_summary(self.method.verified_proof_summary(), None)
                .map_err(PostgresRecoveryCodeMethodError::Core)?;
        let method_commit_work = vec![self.consume_recovery_code_commit_work(
            response.now,
            subject_id,
            &recovery_code_id,
            &secret_mac,
        )?];
        Ok(KnownSubjectActiveProofMethodVerification::Accepted(
            VerifiedActiveProofMethodResponse::new(verified_proof, method_commit_work),
        ))
    }

    async fn fetch_locked_unused_recovery_code_id(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        secret_mac: &MacOverSecret,
    ) -> Result<Option<Vec<u8>>, PostgresRecoveryCodeMethodError> {
        let statement = format!(
            r#"
            SELECT recovery_code_id
            FROM {}
            WHERE subject_id = $1
                AND recovery_code_secret_mac = $2
                AND consumed_at IS NULL
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
            .map(|row| row.try_get::<Vec<u8>, _>("recovery_code_id"))
            .transpose()
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)
    }

    fn consume_recovery_code_commit_work(
        &self,
        now: UnixSeconds,
        subject_id: &SubjectId,
        recovery_code_id: &[u8],
        secret_mac: &MacOverSecret,
    ) -> Result<MethodCommitWork, PostgresRecoveryCodeMethodError> {
        let payload = encode_recovery_code_payload(&RecoveryCodeConsumePayload {
            subject_id: subject_id.as_bytes().to_vec(),
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

    async fn migrate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let table = self.table_names_for_commit()?.recovery_code_table;
        let create_statement = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                recovery_code_id BYTEA PRIMARY KEY,
                subject_id BYTEA NOT NULL,
                recovery_code_secret_mac BYTEA NOT NULL,
                created_at BIGINT NOT NULL,
                consumed_at BIGINT,
                UNIQUE (subject_id, recovery_code_secret_mac),
                CHECK (octet_length(recovery_code_secret_mac) = {})
            )
            "#,
            table.quoted(),
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
            WHERE consumed_at IS NULL
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
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        validate_recovery_code_table_exists(tx, &self.table_names_for_commit()?.recovery_code_table)
            .await
    }

    async fn enforce_recovery_code_still_unused(
        &self,
        tx: &mut Tx<'_>,
        payload: &RecoveryCodeConsumePayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            SELECT recovery_code_secret_mac, consumed_at
            FROM {}
            WHERE recovery_code_id = $1 AND subject_id = $2
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
            SET consumed_at = $4
            WHERE recovery_code_id = $1
                AND subject_id = $2
                AND recovery_code_secret_mac = $3
                AND consumed_at IS NULL
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

    #[cfg(test)]
    pub(crate) async fn store_recovery_code_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
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
                subject_id,
                recovery_code_secret_mac,
                created_at
            )
            VALUES ($1,$2,$3,$4)
            "#,
            self.table_names()?.recovery_code_table.quoted(),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(recovery_code_id)
            .bind(subject_id.as_bytes())
            .bind(secret_mac.as_bytes())
            .bind(i64_from_unix_seconds_u64_for_method(now)?)
            .execute(pool.sqlx_pool())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)?;
        Ok(())
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
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_one(pool.sqlx_pool())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)
    }

    #[cfg(test)]
    pub(crate) async fn count_unused_recovery_codes_for_subject_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
    ) -> Result<i64, PostgresRecoveryCodeMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE subject_id = $1 AND consumed_at IS NULL",
            self.table_names()?.recovery_code_table.quoted()
        );
        pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_one(pool.sqlx_pool())
            .await
            .map_err(DbError::query)
            .map_err(PostgresRecoveryCodeMethodError::Database)
    }
}

impl PostgresAuthMethodPlugin for PostgresRecoveryCodeMethodPlugin {
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
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

impl Default for PostgresRecoveryCodeMethodPluginConfig {
    fn default() -> Self {
        Self {
            schema: None,
            table_prefix: PgIdentifier::new(DEFAULT_RECOVERY_CODE_TABLE_PREFIX)
                .expect("default recovery code table prefix must be a valid Postgres identifier"),
        }
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
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RecoveryCodeConsumePayload {
    subject_id: Vec<u8>,
    recovery_code_id: Vec<u8>,
    recovery_code_secret_mac: Vec<u8>,
    consumed_at: u64,
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

async fn validate_recovery_code_table_exists(
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
        "auth_core.recovery_code.schema.validate_table",
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
            "missing recovery code method table {}",
            table.quoted()
        )))
    }
}
