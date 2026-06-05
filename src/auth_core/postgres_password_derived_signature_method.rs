use std::fmt;
use std::future::Future;
use std::pin::Pin;

use ring::signature::{ED25519, UnparsedPublicKey};
#[cfg(test)]
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[cfg(test)]
use crate::crypto::SecretBytes;
#[cfg(test)]
use crate::crypto::{KEY32_SIZE, derive_argon2id_key32_from_password};
use crate::crypto::{PASSWORD_KDF_SALT_SIZE, PasswordKdfParams, PasswordKdfSalt};
#[cfg(test)]
use crate::db::Pool;
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Tx, pooler_safe_query, pooler_safe_query_scalar, unparameterized_simple_query,
};

use super::postgres_method_runtime::{
    ActiveProofMethodAuthoritativeConfirmation, ActiveProofMethodAuthoritativeVerificationContext,
    ActiveProofMethodChallengeBuild, ActiveProofMethodPreStateVerification,
    PostgresAuthMethodBuildError, PostgresAuthMethodPlugin, VerifiedActiveProofMethodResponse,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::*;

const PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL: &str = "password_derived_signature";
const DEFAULT_PASSWORD_DERIVED_SIGNATURE_TABLE_PREFIX: &str = "auth_password_signature_";
const PASSWORD_DERIVED_SIGNATURE_CONTEXT: &[u8] = b"paranoid/auth/v1/password-derived-signature";
const PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES: usize = 32;
const PASSWORD_DERIVED_SIGNATURE_SIGNATURE_BYTES: usize = 64;
const PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES: usize = 2048;

pub(crate) struct PostgresPasswordDerivedSignatureMethodPlugin {
    config: PostgresPasswordDerivedSignatureMethodPluginConfig,
    method: ProofMethodDeclaration,
}

impl PostgresPasswordDerivedSignatureMethodPlugin {
    pub(crate) fn new(
        config: PostgresPasswordDerivedSignatureMethodPluginConfig,
    ) -> Result<Self, PostgresPasswordDerivedSignatureMethodError> {
        Ok(Self {
            config,
            method: ProofMethodDeclaration::new_online_guessable(
                ProofFamily::MessageSignature,
                PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL,
            )
            .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
        })
    }

    async fn build_challenge_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        request: &IssueActiveProofMethodChallengeRequest,
        challenge: &ActiveProofMethodChallengeSeed,
    ) -> Result<ActiveProofMethodChallengeBuild, PostgresPasswordDerivedSignatureMethodError> {
        if request.method != self.method {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature challenge issue used a different method",
                ),
            ));
        }
        if challenge.proof != self.method.verified_proof_summary() {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature challenge seed used a different proof",
                ),
            ));
        }
        let request_payload = decode_password_signature_payload::<
            PasswordDerivedSignatureChallengeRequestPayload,
        >(
            request
                .method_challenge_request_payload
                .as_ref()
                .ok_or(PostgresPasswordDerivedSignatureMethodError::MissingChallengeRequestPayload)?
                .as_bytes(),
        )?;
        if request_payload.lookup_handle.is_empty()
            || request_payload.lookup_handle.len()
                > PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES
        {
            return Err(PostgresPasswordDerivedSignatureMethodError::InvalidLookupHandle);
        }

        let verifier = self
            .fetch_verifier_by_lookup_handle(tx, &request_payload.lookup_handle)
            .await?;
        let material = match verifier {
            Some(verifier) => PasswordDerivedSignatureChallengeMaterial::from_verifier(verifier)?,
            None => PasswordDerivedSignatureChallengeMaterial::fake()?,
        };
        let canonical_message =
            canonical_password_signature_message(challenge, &self.method, &material)?;
        let presentation_payload = PasswordDerivedSignatureChallengePresentationPayload {
            kdf_salt: material.kdf_salt.as_bytes().to_vec(),
            kdf_memory_cost_kib: material.kdf_params.memory_cost_kib(),
            kdf_iterations: material.kdf_params.iterations(),
            kdf_parallelism: material.kdf_params.parallelism(),
            canonical_message: canonical_message.clone(),
        };
        let state_payload = PasswordDerivedSignatureChallengeStatePayload {
            subject_id: material
                .subject_id
                .map(|subject_id| subject_id.as_bytes().to_vec()),
            password_credential_id: material
                .password_credential_id
                .map(|credential_id| credential_id.as_bytes().to_vec()),
            verifier_version: material.verifier_version,
            public_key: material.public_key,
            canonical_message,
        };
        Ok(ActiveProofMethodChallengeBuild::new(
            ActiveProofMethodChallengePresentation::try_from_bytes(
                encode_password_signature_payload(&presentation_payload)?,
            )
            .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            ActiveProofMethodChallengeState::try_from_bytes(encode_password_signature_payload(
                &state_payload,
            )?)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            Vec::new(),
        ))
    }

    fn verify_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<ActiveProofMethodPreStateVerification, PostgresPasswordDerivedSignatureMethodError>
    {
        if challenge.proof != self.method.verified_proof_summary() {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature response used a different proof",
                ),
            ));
        }
        let state = decode_password_signature_payload::<
            PasswordDerivedSignatureChallengeStatePayload,
        >(challenge.method_challenge_state.as_bytes())?;
        let response_payload = decode_password_signature_payload::<
            PasswordDerivedSignatureResponsePayload,
        >(response.response_payload.as_bytes())?;
        if response_payload.signature.len() != PASSWORD_DERIVED_SIGNATURE_SIGNATURE_BYTES {
            return Err(PostgresPasswordDerivedSignatureMethodError::SignatureVerificationFailed);
        }
        verify_ed25519_signature(
            &state.public_key,
            &state.canonical_message,
            &response_payload.signature,
        )?;
        let (Some(subject_id_bytes), Some(credential_id_bytes), Some(_verifier_version)) = (
            state.subject_id,
            state.password_credential_id,
            state.verifier_version,
        ) else {
            return Err(PostgresPasswordDerivedSignatureMethodError::SignatureVerificationFailed);
        };
        let subject_id = SubjectId::from_bytes(subject_id_bytes)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?;
        let password_credential_id = VerifiedProofSourceId::from_bytes(credential_id_bytes)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?;
        let verified_proof = VerifiedActiveProof::from_summary_with_source(
            self.method.verified_proof_summary(),
            Some(subject_id),
            VerifiedProofSource::new(
                VerifiedProofSourceKind::CredentialInstance,
                password_credential_id,
            ),
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?;
        Ok(
            ActiveProofMethodPreStateVerification::AcceptedNeedsAuthoritativeConfirmation(
                VerifiedActiveProofMethodResponse::new(verified_proof, Vec::new())
                    .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            ),
        )
    }

    async fn verify_response_with_authoritative_state(
        &self,
        tx: &mut Tx<'_>,
        context: ActiveProofMethodAuthoritativeVerificationContext<'_>,
        pre_state_verified: &VerifiedActiveProofMethodResponse,
    ) -> Result<
        ActiveProofMethodAuthoritativeConfirmation,
        PostgresPasswordDerivedSignatureMethodError,
    > {
        let state = decode_password_signature_payload::<
            PasswordDerivedSignatureChallengeStatePayload,
        >(context.challenge().method_challenge_state.as_bytes())?;
        let Some(subject_id) = pre_state_verified.verified_proof().subject_id() else {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature proof is missing subject",
                ),
            ));
        };
        let Some(source) = pre_state_verified.verified_proof().source() else {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature proof is missing credential source",
                ),
            ));
        };
        if source.kind() != VerifiedProofSourceKind::CredentialInstance {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature proof source is not a credential instance",
                ),
            ));
        }
        let Some(expected_version) = state.verifier_version else {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::LoadedStateContradiction(
                    "password-derived signature challenge has no authoritative verifier",
                ),
            ));
        };
        let Some(current) = self
            .fetch_locked_verifier_by_subject_and_credential(
                tx,
                subject_id,
                source.source_id().as_bytes(),
            )
            .await?
        else {
            return Err(PostgresPasswordDerivedSignatureMethodError::AuthoritativeVerifierChanged);
        };
        if current.verifier_version != expected_version || current.public_key != state.public_key {
            return Err(PostgresPasswordDerivedSignatureMethodError::AuthoritativeVerifierChanged);
        }
        Ok(ActiveProofMethodAuthoritativeConfirmation::new(Vec::new()))
    }

    async fn fetch_verifier_by_lookup_handle(
        &self,
        tx: &mut Tx<'_>,
        lookup_handle: &[u8],
    ) -> Result<Option<PasswordDerivedSignatureVerifier>, PostgresPasswordDerivedSignatureMethodError>
    {
        let statement = format!(
            r#"
            SELECT password_credential_id, subject_id, lookup_handle, kdf_salt,
                kdf_memory_cost_kib, kdf_iterations, kdf_parallelism, public_key, verifier_version
            FROM {}
            WHERE lookup_handle = $1
            "#,
            self.table_names()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.password_derived_signature.issue.fetch_verifier_by_lookup_handle",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(lookup_handle)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?
            .map(password_signature_verifier_from_row)
            .transpose()
    }

    async fn fetch_locked_verifier_by_subject_and_credential(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        password_credential_id: &[u8],
    ) -> Result<Option<PasswordDerivedSignatureVerifier>, PostgresPasswordDerivedSignatureMethodError>
    {
        let statement = format!(
            r#"
            SELECT password_credential_id, subject_id, lookup_handle, kdf_salt,
                kdf_memory_cost_kib, kdf_iterations, kdf_parallelism, public_key, verifier_version
            FROM {}
            WHERE subject_id = $1 AND password_credential_id = $2
            FOR UPDATE
            "#,
            self.table_names()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.password_derived_signature.verify.fetch_locked_current_verifier",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .bind(password_credential_id)
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?
            .map(password_signature_verifier_from_row)
            .transpose()
    }

    fn table_names(
        &self,
    ) -> Result<PasswordDerivedSignatureTableNames, PostgresPasswordDerivedSignatureMethodError>
    {
        self.config.table_names()
    }

    fn table_names_for_commit(
        &self,
    ) -> Result<PasswordDerivedSignatureTableNames, PostgresAuthMethodCommitError> {
        self.table_names().map_err(|error| match error {
            PostgresPasswordDerivedSignatureMethodError::Database(error) => {
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
                password_credential_id BYTEA PRIMARY KEY,
                subject_id BYTEA NOT NULL UNIQUE,
                lookup_handle BYTEA NOT NULL UNIQUE,
                kdf_salt BYTEA NOT NULL,
                kdf_memory_cost_kib BIGINT NOT NULL,
                kdf_iterations BIGINT NOT NULL,
                kdf_parallelism BIGINT NOT NULL,
                public_key BYTEA NOT NULL,
                verifier_version BIGINT NOT NULL,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL,
                CHECK (octet_length(password_credential_id) BETWEEN 1 AND {}),
                CHECK (octet_length(subject_id) BETWEEN 1 AND {}),
                CHECK (octet_length(lookup_handle) BETWEEN 1 AND {}),
                CHECK (octet_length(kdf_salt) = {}),
                CHECK (octet_length(public_key) = {}),
                CHECK (kdf_memory_cost_kib > 0),
                CHECK (kdf_iterations > 0),
                CHECK (kdf_parallelism > 0),
                CHECK (verifier_version > 0)
            )
            "#,
            self.table_names_for_commit()?.verifier_table.quoted(),
            ID_MAX_BYTES,
            ID_MAX_BYTES,
            PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES,
            PASSWORD_KDF_SALT_SIZE,
            PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES,
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.password_derived_signature.schema.create_verifier_table",
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
        validate_password_signature_table_exists(tx, &self.table_names_for_commit()?.verifier_table)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn store_verifier_for_test(
        &self,
        pool: &Pool,
        verifier: PasswordDerivedSignatureVerifierForTest<'_>,
    ) -> Result<(), PostgresPasswordDerivedSignatureMethodError> {
        let public_key =
            public_key_from_password_for_test(verifier.password, verifier.salt, verifier.params)?;
        let statement = format!(
            r#"
            INSERT INTO {} (
                password_credential_id,
                subject_id,
                lookup_handle,
                kdf_salt,
                kdf_memory_cost_kib,
                kdf_iterations,
                kdf_parallelism,
                public_key,
                verifier_version,
                created_at,
                updated_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$9)
            ON CONFLICT (subject_id)
            DO UPDATE SET
                password_credential_id = EXCLUDED.password_credential_id,
                lookup_handle = EXCLUDED.lookup_handle,
                kdf_salt = EXCLUDED.kdf_salt,
                kdf_memory_cost_kib = EXCLUDED.kdf_memory_cost_kib,
                kdf_iterations = EXCLUDED.kdf_iterations,
                kdf_parallelism = EXCLUDED.kdf_parallelism,
                public_key = EXCLUDED.public_key,
                verifier_version = {}.verifier_version + 1,
                updated_at = EXCLUDED.updated_at
            "#,
            self.table_names()?.verifier_table.quoted(),
            self.table_names()?.verifier_table.quoted(),
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?;
        let result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(verifier.password_credential_id.as_bytes())
            .bind(verifier.subject_id.as_bytes())
            .bind(verifier.lookup_handle)
            .bind(verifier.salt.as_bytes())
            .bind(i64::from(verifier.params.memory_cost_kib()))
            .bind(i64::from(verifier.params.iterations()))
            .bind(i64::from(verifier.params.parallelism()))
            .bind(public_key)
            .bind(i64_from_unix_seconds_for_method(verifier.now)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database)
            .map(|_| ());
        match result {
            Ok(()) => tx
                .commit()
                .await
                .map_err(PostgresPasswordDerivedSignatureMethodError::Database),
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn challenge_request_payload_for_test(
        lookup_handle: &[u8],
    ) -> Result<ActiveProofMethodChallengeRequestPayload, PostgresPasswordDerivedSignatureMethodError>
    {
        ActiveProofMethodChallengeRequestPayload::try_from_bytes(encode_password_signature_payload(
            &PasswordDerivedSignatureChallengeRequestPayload {
                lookup_handle: lookup_handle.to_vec(),
            },
        )?)
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn response_payload_for_test(
        password: &[u8],
        presentation: &ActiveProofMethodChallengePresentation,
    ) -> Result<ActiveProofMethodResponsePayload, PostgresPasswordDerivedSignatureMethodError> {
        let presentation = decode_password_signature_payload::<
            PasswordDerivedSignatureChallengePresentationPayload,
        >(presentation.as_bytes())?;
        let salt = PasswordKdfSalt::from_bytes(&presentation.kdf_salt)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?;
        let params = PasswordKdfParams::new(
            presentation.kdf_memory_cost_kib,
            presentation.kdf_iterations,
            presentation.kdf_parallelism,
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?;
        let signature = sign_password_message_for_test(
            password,
            salt,
            params,
            &presentation.canonical_message,
        )?;
        ActiveProofMethodResponsePayload::try_from_bytes(encode_password_signature_payload(
            &PasswordDerivedSignatureResponsePayload { signature },
        )?)
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)
    }
}

impl PostgresAuthMethodPlugin for PostgresPasswordDerivedSignatureMethodPlugin {
    fn method(&self) -> &ProofMethodDeclaration {
        &self.method
    }

    fn build_active_proof_method_challenge<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        request: &'a IssueActiveProofMethodChallengeRequest,
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
            self.build_challenge_in_current_transaction(tx, request, challenge)
                .await
                .map_err(|error| {
                    PostgresAuthMethodBuildError::plugin_rejected(
                        &self.method,
                        "active_proof_method_challenge_issue",
                        error,
                    )
                })
        })
    }

    fn verify_active_proof_method_response_before_state_load(
        &self,
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &CompleteActiveProofMethodResponse,
    ) -> Result<ActiveProofMethodPreStateVerification, PostgresAuthMethodBuildError> {
        self.verify_response_before_state_load(challenge, response)
            .map_err(|error| {
                PostgresAuthMethodBuildError::plugin_rejected(
                    &self.method,
                    "active_proof_completion",
                    error,
                )
            })
    }

    fn verify_active_proof_method_response_with_authoritative_state<'a, 'tx>(
        &'a self,
        tx: &'a mut Tx<'tx>,
        context: ActiveProofMethodAuthoritativeVerificationContext<'a>,
        pre_state_verified: &'a VerifiedActiveProofMethodResponse,
        _response: &'a CompleteActiveProofMethodResponse,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ActiveProofMethodAuthoritativeConfirmation,
                        PostgresAuthMethodBuildError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.verify_response_with_authoritative_state(tx, context, pre_state_verified)
                .await
                .map_err(|error| {
                    PostgresAuthMethodBuildError::plugin_rejected(
                        &self.method,
                        "active_proof_authoritative_confirmation",
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
pub(crate) struct PostgresPasswordDerivedSignatureMethodPluginConfig {
    schema: Option<PgSchemaName>,
    table_prefix: PgIdentifier,
}

impl PostgresPasswordDerivedSignatureMethodPluginConfig {
    pub(crate) fn new(
        schema: Option<PgSchemaName>,
        table_prefix: PgIdentifier,
    ) -> Result<Self, PostgresPasswordDerivedSignatureMethodError> {
        let config = Self {
            schema,
            table_prefix,
        };
        config.table_names()?;
        Ok(config)
    }

    pub(crate) fn for_db_bootstrap_config(
        bootstrap_config: &BootstrapConfig,
    ) -> Result<Self, PostgresPasswordDerivedSignatureMethodError> {
        Self::new(
            Some(bootstrap_config.schema_name().clone()),
            PgIdentifier::new(DEFAULT_PASSWORD_DERIVED_SIGNATURE_TABLE_PREFIX)
                .map_err(DbError::from)
                .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?,
        )
    }

    fn table_name(&self, suffix: &'static str) -> Result<PgQualifiedTableName, DbError> {
        Ok(PgQualifiedTableName::new(
            self.schema.clone(),
            PgIdentifier::new(format!("{}{}", self.table_prefix.as_str(), suffix))?,
        ))
    }

    fn table_names(
        &self,
    ) -> Result<PasswordDerivedSignatureTableNames, PostgresPasswordDerivedSignatureMethodError>
    {
        Ok(PasswordDerivedSignatureTableNames {
            verifier_table: self
                .table_name("verifiers")
                .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?,
        })
    }
}

impl Default for PostgresPasswordDerivedSignatureMethodPluginConfig {
    fn default() -> Self {
        Self::for_db_bootstrap_config(&BootstrapConfig::default()).expect(
            "default password-derived signature method config must derive valid bootstrap table names",
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PasswordDerivedSignatureTableNames {
    verifier_table: PgQualifiedTableName,
}

#[derive(Debug)]
pub(crate) enum PostgresPasswordDerivedSignatureMethodError {
    Core(Error),
    Crypto(crate::crypto::Error),
    Database(DbError),
    MissingChallengeRequestPayload,
    InvalidLookupHandle,
    PayloadDecode(&'static str),
    PayloadEncode(postcard::Error),
    InvalidStoredKdfParams,
    SignatureKeyRejected,
    SignatureVerificationFailed,
    AuthoritativeVerifierChanged,
}

impl fmt::Display for PostgresPasswordDerivedSignatureMethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(f, "{error}"),
            Self::Crypto(error) => write!(f, "{error}"),
            Self::Database(error) => write!(f, "{error}"),
            Self::MissingChallengeRequestPayload => {
                write!(
                    f,
                    "password-derived signature challenge request payload is missing"
                )
            }
            Self::InvalidLookupHandle => {
                write!(f, "password-derived signature lookup handle is invalid")
            }
            Self::PayloadDecode(input_name) => {
                write!(
                    f,
                    "password-derived signature {input_name} payload is invalid"
                )
            }
            Self::PayloadEncode(error) => {
                write!(
                    f,
                    "password-derived signature payload could not be encoded: {error}"
                )
            }
            Self::InvalidStoredKdfParams => {
                write!(
                    f,
                    "stored password-derived signature KDF parameters are invalid"
                )
            }
            Self::SignatureKeyRejected => {
                write!(f, "password-derived signature public key is invalid")
            }
            Self::SignatureVerificationFailed => {
                write!(f, "password-derived signature verification failed")
            }
            Self::AuthoritativeVerifierChanged => {
                write!(f, "password-derived signature verifier changed")
            }
        }
    }
}

impl std::error::Error for PostgresPasswordDerivedSignatureMethodError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Database(error) => Some(error),
            Self::PayloadEncode(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct PasswordDerivedSignatureVerifier {
    password_credential_id: VerifiedProofSourceId,
    subject_id: SubjectId,
    kdf_salt: PasswordKdfSalt,
    kdf_params: PasswordKdfParams,
    public_key: Vec<u8>,
    verifier_version: u64,
}

#[cfg(test)]
pub(crate) struct PasswordDerivedSignatureVerifierForTest<'a> {
    pub(crate) subject_id: &'a SubjectId,
    pub(crate) password_credential_id: &'a VerifiedProofSourceId,
    pub(crate) lookup_handle: &'a [u8],
    pub(crate) password: &'a [u8],
    pub(crate) salt: PasswordKdfSalt,
    pub(crate) params: PasswordKdfParams,
    pub(crate) now: UnixSeconds,
}

#[derive(Clone, Debug)]
struct PasswordDerivedSignatureChallengeMaterial {
    subject_id: Option<SubjectId>,
    password_credential_id: Option<VerifiedProofSourceId>,
    kdf_salt: PasswordKdfSalt,
    kdf_params: PasswordKdfParams,
    public_key: Vec<u8>,
    verifier_version: Option<u64>,
}

impl PasswordDerivedSignatureChallengeMaterial {
    fn from_verifier(
        verifier: PasswordDerivedSignatureVerifier,
    ) -> Result<Self, PostgresPasswordDerivedSignatureMethodError> {
        Ok(Self {
            subject_id: Some(verifier.subject_id),
            password_credential_id: Some(verifier.password_credential_id),
            kdf_salt: verifier.kdf_salt,
            kdf_params: verifier.kdf_params,
            public_key: verifier.public_key,
            verifier_version: Some(verifier.verifier_version),
        })
    }

    fn fake() -> Result<Self, PostgresPasswordDerivedSignatureMethodError> {
        Ok(Self {
            subject_id: None,
            password_credential_id: None,
            kdf_salt: PasswordKdfSalt::generate()
                .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?,
            kdf_params: PasswordKdfParams::interactive_default(),
            public_key: crate::crypto::random_public_bytes(
                PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES,
            )
            .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?
            .into_bytes(),
            verifier_version: None,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct PasswordDerivedSignatureChallengeRequestPayload {
    lookup_handle: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct PasswordDerivedSignatureChallengePresentationPayload {
    kdf_salt: Vec<u8>,
    kdf_memory_cost_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    canonical_message: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct PasswordDerivedSignatureChallengeStatePayload {
    subject_id: Option<Vec<u8>>,
    password_credential_id: Option<Vec<u8>>,
    verifier_version: Option<u64>,
    public_key: Vec<u8>,
    canonical_message: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct PasswordDerivedSignatureResponsePayload {
    signature: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct PasswordDerivedSignatureCanonicalMessagePayload {
    context: Vec<u8>,
    proof_family: u8,
    method_label: String,
    attempt_id: Vec<u8>,
    challenge_id: Vec<u8>,
    subject_id: Option<Vec<u8>>,
    password_credential_id: Option<Vec<u8>>,
    verifier_version: Option<u64>,
    issued_at: u64,
    expires_at: u64,
    nonce: Vec<u8>,
    public_key: Vec<u8>,
}

fn canonical_password_signature_message(
    challenge: &ActiveProofMethodChallengeSeed,
    method: &ProofMethodDeclaration,
    material: &PasswordDerivedSignatureChallengeMaterial,
) -> Result<Vec<u8>, PostgresPasswordDerivedSignatureMethodError> {
    encode_password_signature_payload(&PasswordDerivedSignatureCanonicalMessagePayload {
        context: PASSWORD_DERIVED_SIGNATURE_CONTEXT.to_vec(),
        proof_family: proof_family_wire_id(method.family()),
        method_label: method.method_label().to_owned(),
        attempt_id: challenge.attempt_id.as_bytes().to_vec(),
        challenge_id: challenge.challenge_id.as_bytes().to_vec(),
        subject_id: material
            .subject_id
            .as_ref()
            .map(|subject_id| subject_id.as_bytes().to_vec()),
        password_credential_id: material
            .password_credential_id
            .as_ref()
            .map(|credential_id| credential_id.as_bytes().to_vec()),
        verifier_version: material.verifier_version,
        issued_at: challenge.issued_at.get(),
        expires_at: challenge.expires_at.get(),
        nonce: challenge.nonce.as_bytes().to_vec(),
        public_key: material.public_key.clone(),
    })
}

fn verify_ed25519_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PostgresPasswordDerivedSignatureMethodError> {
    if public_key.len() != PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES {
        return Err(PostgresPasswordDerivedSignatureMethodError::SignatureKeyRejected);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| PostgresPasswordDerivedSignatureMethodError::SignatureVerificationFailed)
}

fn password_signature_verifier_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<PasswordDerivedSignatureVerifier, PostgresPasswordDerivedSignatureMethodError> {
    let kdf_memory_cost_kib = u32::try_from(
        row.try_get::<i64, _>("kdf_memory_cost_kib")
            .map_err(password_signature_row_error)?,
    )
    .map_err(|_| PostgresPasswordDerivedSignatureMethodError::InvalidStoredKdfParams)?;
    let kdf_iterations = u32::try_from(
        row.try_get::<i64, _>("kdf_iterations")
            .map_err(password_signature_row_error)?,
    )
    .map_err(|_| PostgresPasswordDerivedSignatureMethodError::InvalidStoredKdfParams)?;
    let kdf_parallelism = u32::try_from(
        row.try_get::<i64, _>("kdf_parallelism")
            .map_err(password_signature_row_error)?,
    )
    .map_err(|_| PostgresPasswordDerivedSignatureMethodError::InvalidStoredKdfParams)?;
    let verifier_version = u64::try_from(
        row.try_get::<i64, _>("verifier_version")
            .map_err(password_signature_row_error)?,
    )
    .map_err(|_| PostgresPasswordDerivedSignatureMethodError::InvalidStoredKdfParams)?;
    let public_key = row
        .try_get::<Vec<u8>, _>("public_key")
        .map_err(password_signature_row_error)?;
    if public_key.len() != PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES {
        return Err(PostgresPasswordDerivedSignatureMethodError::SignatureKeyRejected);
    }
    Ok(PasswordDerivedSignatureVerifier {
        password_credential_id: VerifiedProofSourceId::from_bytes(
            row.try_get::<Vec<u8>, _>("password_credential_id")
                .map_err(password_signature_row_error)?,
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
        subject_id: SubjectId::from_bytes(
            row.try_get::<Vec<u8>, _>("subject_id")
                .map_err(password_signature_row_error)?,
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
        kdf_salt: PasswordKdfSalt::from_bytes(
            &row.try_get::<Vec<u8>, _>("kdf_salt")
                .map_err(password_signature_row_error)?,
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?,
        kdf_params: PasswordKdfParams::new(kdf_memory_cost_kib, kdf_iterations, kdf_parallelism)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?,
        public_key,
        verifier_version,
    })
}

fn password_signature_row_error(error: sqlx::Error) -> PostgresPasswordDerivedSignatureMethodError {
    PostgresPasswordDerivedSignatureMethodError::Database(DbError::query(error))
}

fn encode_password_signature_payload<T: Serialize>(
    payload: &T,
) -> Result<Vec<u8>, PostgresPasswordDerivedSignatureMethodError> {
    postcard::to_allocvec(payload)
        .map_err(PostgresPasswordDerivedSignatureMethodError::PayloadEncode)
}

fn decode_password_signature_payload<T: for<'de> Deserialize<'de>>(
    payload: &[u8],
) -> Result<T, PostgresPasswordDerivedSignatureMethodError> {
    postcard::from_bytes(payload).map_err(|_| {
        PostgresPasswordDerivedSignatureMethodError::PayloadDecode(std::any::type_name::<T>())
    })
}

fn i64_from_unix_seconds_for_method(
    value: UnixSeconds,
) -> Result<i64, PostgresPasswordDerivedSignatureMethodError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresPasswordDerivedSignatureMethodError::Core(Error::TimeOverflow))
}

async fn validate_password_signature_table_exists(
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
        "auth_core.password_derived_signature.schema.validate_table",
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
            "missing password-derived signature method table {}",
            table.quoted()
        )))
    }
}

#[cfg(test)]
fn public_key_from_password_for_test(
    password: &[u8],
    salt: PasswordKdfSalt,
    params: PasswordKdfParams,
) -> Result<Vec<u8>, PostgresPasswordDerivedSignatureMethodError> {
    let key = derive_password_key_for_test(password, salt, params)?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(key.expose_secret())
        .map_err(|_| PostgresPasswordDerivedSignatureMethodError::SignatureKeyRejected)?;
    Ok(key_pair.public_key().as_ref().to_vec())
}

#[cfg(test)]
fn sign_password_message_for_test(
    password: &[u8],
    salt: PasswordKdfSalt,
    params: PasswordKdfParams,
    message: &[u8],
) -> Result<Vec<u8>, PostgresPasswordDerivedSignatureMethodError> {
    let key = derive_password_key_for_test(password, salt, params)?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(key.expose_secret())
        .map_err(|_| PostgresPasswordDerivedSignatureMethodError::SignatureKeyRejected)?;
    Ok(key_pair.sign(message).as_ref().to_vec())
}

#[cfg(test)]
fn derive_password_key_for_test(
    password: &[u8],
    salt: PasswordKdfSalt,
    params: PasswordKdfParams,
) -> Result<crate::crypto::Key32, PostgresPasswordDerivedSignatureMethodError> {
    if password.is_empty() {
        return Err(PostgresPasswordDerivedSignatureMethodError::Core(
            Error::EmptyCredentialSecret,
        ));
    }
    let password =
        SecretBytes::<PasswordDerivedSignatureTestPasswordKind>::try_from(password.to_vec())
            .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?;
    let key = derive_argon2id_key32_from_password(&password, &salt, params)
        .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?;
    debug_assert_eq!(key.expose_secret().len(), KEY32_SIZE);
    Ok(key)
}

#[cfg(test)]
enum PasswordDerivedSignatureTestPasswordKind {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_schema_local_bootstrap_tables() {
        let bootstrap_config = BootstrapConfig::default();
        let config = PostgresPasswordDerivedSignatureMethodPluginConfig::default();
        let table_names = config.table_names().expect("table names");

        assert_eq!(
            table_names.verifier_table.schema(),
            Some(bootstrap_config.schema_name())
        );
        assert_eq!(
            table_names.verifier_table.table().as_str(),
            "auth_password_signature_verifiers"
        );
    }
}
