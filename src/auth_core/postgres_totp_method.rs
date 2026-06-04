use std::fmt;
use std::future::Future;
use std::pin::Pin;

use sqlx::Row;

use crate::crypto::Keyset;
use crate::crypto::SecretBytes;
use crate::crypto::envelope::{decrypt_bytes_with_associated_data, encrypt_plaintext_bytes_as};
#[cfg(test)]
use crate::db::Pool;
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Tx, pooler_safe_query, pooler_safe_query_scalar, unparameterized_simple_query,
};

use super::postgres_method_runtime::{
    KnownSubjectActiveProofMethodVerification, PostgresAuthMethodBuildError,
    PostgresAuthMethodPlugin, VerifiedActiveProofMethodResponse,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::*;

const TOTP_METHOD_LABEL: &str = "totp";
const TOTP_SECRET_CONTEXT: &[u8] = b"paranoid/auth/v1/totp-secret";
const DEFAULT_TOTP_TABLE_PREFIX: &str = "auth_totp_";

pub(crate) trait PostgresTotpCodeVerifier: Send + Sync {
    fn verify_totp_code(
        &self,
        secret: &SecretBytes,
        submitted_code: &[u8],
        now: UnixSeconds,
    ) -> Result<bool, PostgresTotpMethodError>;
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

    async fn fetch_locked_verifier(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
    ) -> Result<Option<TotpVerifier>, PostgresTotpMethodError> {
        let statement = format!(
            r#"
            SELECT totp_credential_id, encrypted_secret
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
                CHECK (octet_length(subject_id) BETWEEN 1 AND {})
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
        Ok(())
    }

    async fn validate_schema_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        validate_totp_table_exists(tx, &self.table_names_for_commit()?.verifier_table).await
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
}

impl<V> PostgresAuthMethodPlugin for PostgresTotpMethodPlugin<V>
where
    V: PostgresTotpCodeVerifier,
{
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
        _tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        precondition: &'a MethodCommitPrecondition,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            Err(PostgresAuthMethodCommitError::InvalidOperation(
                precondition.operation().as_str().to_owned(),
            ))
        })
    }

    fn apply_mutation<'a, 'tx>(
        &'a self,
        _tx: &'a mut Tx<'tx>,
        _work: &'a MethodCommitWork,
        mutation: &'a MethodCommitMutation,
    ) -> Pin<Box<dyn Future<Output = Result<(), PostgresAuthMethodCommitError>> + Send + 'a>> {
        Box::pin(async move {
            Err(PostgresAuthMethodCommitError::InvalidOperation(
                mutation.operation().as_str().to_owned(),
            ))
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

impl Default for PostgresTotpMethodPluginConfig {
    fn default() -> Self {
        Self::for_db_bootstrap_config(&BootstrapConfig::default())
            .expect("default totp method config must derive valid bootstrap table names")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_schema_local_bootstrap_tables() {
        let bootstrap_config = BootstrapConfig::default();
        let config = PostgresTotpMethodPluginConfig::default();
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
}

impl fmt::Display for PostgresTotpMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Database(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PostgresTotpMethodError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
        }
    }
}

enum TotpSecretEnvelope {}

struct TotpVerifier {
    totp_credential_id: VerifiedProofSourceId,
    encrypted_secret: Vec<u8>,
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

fn i64_from_unix_seconds_u64(value: UnixSeconds) -> Result<i64, PostgresAuthMethodCommitError> {
    i64::try_from(value.get()).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "totp timestamp exceeds Postgres BIGINT domain".to_owned(),
        )
    })
}

fn i64_from_unix_seconds_for_method(value: UnixSeconds) -> Result<i64, PostgresTotpMethodError> {
    i64::try_from(value.get()).map_err(|_| PostgresTotpMethodError::Core(Error::TimeOverflow))
}

async fn validate_totp_table_exists(
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
        "auth_core.totp.schema.validate_table",
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
            "missing totp method table {}",
            table.quoted()
        )))
    }
}
