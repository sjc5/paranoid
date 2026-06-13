use std::fmt;
use std::future::Future;
use std::num::NonZeroU32;
use std::pin::Pin;

use ring::signature::{ED25519, UnparsedPublicKey};
#[cfg(test)]
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::postgres_durable_effect_queue::{
    PostgresAuthDurableEffectQueueDispatchError, PostgresAuthDurableEffectQueueDispatchSummary,
};
use super::postgres_method_runtime::{
    ActiveProofMethodAuthoritativeConfirmation, ActiveProofMethodAuthoritativeVerificationContext,
    ActiveProofMethodChallengeBuild, ActiveProofMethodPreStateVerification,
    CredentialCreationMethodWorkBuildRequest, CredentialLifecycleMethodWorkAuthority,
    CredentialLifecycleMethodWorkBuildRequest, CredentialMethodWorkBuild,
    CredentialResetMethodWorkBuildRequest, PostgresAuthMethodBuildError,
    PostgresAuthMethodDurableEffectQueueRegistrationError,
    PostgresAuthMethodMountedRouteCapabilities, PostgresAuthMethodPlugin,
    VerifiedActiveProofMethodResponse,
    enqueue_no_method_durable_effects_to_queue_in_current_transaction,
    register_no_queue_handlers_for_method_durable_effects,
};
use super::postgres_method_schema::{
    MethodTableCheckConstraint, MethodTableColumnContract, MethodTableIndexContract,
    ensure_method_table_check_constraints_in_current_transaction, quoted_bigint_nonnegative,
    quoted_bigint_positive, quoted_len_at_least_one_and_at_most, quoted_len_equals,
    validate_method_table_schema_in_current_transaction,
};
use super::postgres_store::PostgresAuthMethodCommitError;
use super::prelude::*;
#[cfg(test)]
use crate::crypto::SecretBytes;
#[cfg(test)]
use crate::crypto::{KEY32_SIZE, derive_argon2id_key32_from_password};
use crate::crypto::{PASSWORD_KDF_SALT_SIZE, PasswordKdfParams, PasswordKdfSalt};
#[cfg(test)]
use crate::db::Pool;
#[cfg(test)]
use crate::db::pooler_safe_query_scalar;
use crate::db::{
    BootstrapConfig, DatabaseOperationKind, DbError, PgIdentifier, PgQualifiedTableName,
    PgSchemaName, Tx, WriteTx, pooler_safe_query, queue, unparameterized_simple_query,
};

pub(crate) const PASSWORD_DERIVED_SIGNATURE_METHOD_LABEL: &str = "password_derived_signature";
const DEFAULT_PASSWORD_DERIVED_SIGNATURE_TABLE_PREFIX: &str = "auth_password_signature_";
const PASSWORD_DERIVED_SIGNATURE_CONTEXT: &[u8] = b"paranoid/auth/v1/password-derived-signature";
const PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES: usize = 32;
const PASSWORD_DERIVED_SIGNATURE_SIGNATURE_BYTES: usize = 64;
const PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES: usize = 2048;
const PASSWORD_DERIVED_SIGNATURE_VERIFIER_ABSENT_OPERATION: &str =
    "password_derived_signature_verifier_absent";
const PASSWORD_DERIVED_SIGNATURE_VERIFIER_CURRENT_OPERATION: &str =
    "password_derived_signature_verifier_current";
const PASSWORD_DERIVED_SIGNATURE_CREATE_VERIFIER_OPERATION: &str =
    "password_derived_signature_create_verifier";
const PASSWORD_DERIVED_SIGNATURE_REPLACE_VERIFIER_OPERATION: &str =
    "password_derived_signature_replace_verifier";

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

    fn build_verifier_creation_commit_work(
        &self,
        now: UnixSeconds,
        new_credential: &CredentialInstanceMetadata,
        method_payload: &CredentialCreationMethodPayload,
    ) -> Result<CredentialMethodWorkBuild, PostgresPasswordDerivedSignatureMethodError> {
        self.validate_credential_target(new_credential)?;
        let payload = self.verifier_commit_payload(
            now,
            None,
            new_credential.credential_instance_id(),
            new_credential.subject_id(),
            method_payload.as_bytes(),
        )?;
        let encoded_payload = encode_password_signature_payload(&payload)?;
        let method_commit_work = MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(
                    PASSWORD_DERIVED_SIGNATURE_VERIFIER_ABSENT_OPERATION,
                    encoded_payload.clone(),
                )
                .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(
                    PASSWORD_DERIVED_SIGNATURE_CREATE_VERIFIER_OPERATION,
                    encoded_payload,
                )
                .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?;
        Ok(CredentialMethodWorkBuild::from_method_commit_work(vec![
            method_commit_work,
        ]))
    }

    fn build_verifier_reset_commit_work(
        &self,
        now: UnixSeconds,
        target_credential: &CredentialInstanceMetadata,
        method_payload: &CredentialResetMethodPayload,
    ) -> Result<Vec<MethodCommitWork>, PostgresPasswordDerivedSignatureMethodError> {
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
    ) -> Result<CredentialMethodWorkBuild, PostgresPasswordDerivedSignatureMethodError> {
        self.validate_credential_target(target_credential)?;
        let new_credential_id = match action {
            CredentialLifecycleAction::Replace => {
                let successor = replacement_successor.ok_or(
                    PostgresPasswordDerivedSignatureMethodError::Core(
                        Error::LoadedStateContradiction(
                            "password-derived signature replacement is missing successor credential metadata",
                        ),
                    ),
                )?;
                let successor_metadata = successor.metadata();
                if successor_metadata.subject_id() != target_credential.subject_id() {
                    return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                        Error::LoadedStateContradiction(
                            "password-derived signature replacement successor has a different subject",
                        ),
                    ));
                }
                if successor_metadata.proof_family() != self.method.family()
                    || successor_metadata.method_label() != self.method.method_label()
                {
                    return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                        Error::LoadedStateContradiction(
                            "password-derived signature replacement successor uses a different method",
                        ),
                    ));
                }
                successor_metadata.credential_instance_id()
            }
            CredentialLifecycleAction::Rotate => target_credential.credential_instance_id(),
            _ => {
                return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                    Error::LoadedStateContradiction(
                        "password-derived signature lifecycle method work supports only replacement and rotation",
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
    ) -> Result<Vec<MethodCommitWork>, PostgresPasswordDerivedSignatureMethodError> {
        let payload = self.verifier_commit_payload(
            now,
            Some(expected_credential_id),
            new_credential_id,
            subject_id,
            method_payload,
        )?;
        let encoded_payload = encode_password_signature_payload(&payload)?;
        let method_commit_work = MethodCommitWork::new(
            self.method.verified_proof_summary(),
            vec![
                MethodCommitPrecondition::new(
                    PASSWORD_DERIVED_SIGNATURE_VERIFIER_CURRENT_OPERATION,
                    encoded_payload.clone(),
                )
                .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            ],
            vec![
                MethodCommitMutation::new(
                    PASSWORD_DERIVED_SIGNATURE_REPLACE_VERIFIER_OPERATION,
                    encoded_payload,
                )
                .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?,
            ],
            Vec::new(),
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)?;
        Ok(vec![method_commit_work])
    }

    fn verifier_commit_payload(
        &self,
        now: UnixSeconds,
        expected_credential_id: Option<&VerifiedProofSourceId>,
        new_credential_id: &VerifiedProofSourceId,
        subject_id: &SubjectId,
        method_payload: &[u8],
    ) -> Result<
        PasswordDerivedSignatureVerifierCommitPayload,
        PostgresPasswordDerivedSignatureMethodError,
    > {
        let material: PasswordDerivedSignatureVerifierMethodPayload =
            decode_password_signature_payload(method_payload)?;
        validate_lookup_handle(&material.lookup_handle)?;
        let kdf_salt = PasswordKdfSalt::from_bytes(&material.kdf_salt)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?;
        let kdf_params = PasswordKdfParams::new(
            material.kdf_memory_cost_kib,
            material.kdf_iterations,
            material.kdf_parallelism,
        )
        .map_err(PostgresPasswordDerivedSignatureMethodError::Crypto)?;
        if material.public_key.len() != PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES {
            return Err(PostgresPasswordDerivedSignatureMethodError::SignatureKeyRejected);
        }
        Ok(PasswordDerivedSignatureVerifierCommitPayload {
            expected_password_credential_id: expected_credential_id
                .map(|credential_id| credential_id.as_bytes().to_vec()),
            new_password_credential_id: new_credential_id.as_bytes().to_vec(),
            subject_id: subject_id.as_bytes().to_vec(),
            lookup_handle: material.lookup_handle,
            kdf_salt: kdf_salt.as_bytes().to_vec(),
            kdf_memory_cost_kib: kdf_params.memory_cost_kib(),
            kdf_iterations: kdf_params.iterations(),
            kdf_parallelism: kdf_params.parallelism(),
            public_key: material.public_key,
            updated_at: now.get(),
        })
    }

    fn validate_credential_target(
        &self,
        credential: &CredentialInstanceMetadata,
    ) -> Result<(), PostgresPasswordDerivedSignatureMethodError> {
        if credential.proof_family() != self.method.family()
            || credential.method_label() != self.method.method_label()
        {
            return Err(PostgresPasswordDerivedSignatureMethodError::Core(
                Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch,
            ));
        }
        Ok(())
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

    #[cfg(test)]
    pub(crate) fn verifier_table_name_for_test(
        &self,
    ) -> Result<PgQualifiedTableName, PostgresPasswordDerivedSignatureMethodError> {
        Ok(self.table_names()?.verifier_table)
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
                CHECK (verifier_version > 0),
                CHECK (created_at >= 0),
                CHECK (updated_at >= 0)
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
        let table = self.table_names_for_commit()?.verifier_table;
        let checks = password_signature_verifier_table_checks();
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
            &password_signature_verifier_table_columns(),
            &password_signature_verifier_table_checks(),
            &password_signature_verifier_table_indexes(),
        )
        .await
    }

    async fn enforce_verifier_absent(
        &self,
        tx: &mut Tx<'_>,
        payload: &PasswordDerivedSignatureVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let statement = format!(
            r#"
            SELECT password_credential_id
            FROM {}
            WHERE password_credential_id = $1
                OR subject_id = $2
                OR lookup_handle = $3
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "auth_core.password_derived_signature.precondition.verifier_absent",
            Some(statement.as_str()),
        );
        let rows = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.new_password_credential_id)
            .bind(&payload.subject_id)
            .bind(&payload.lookup_handle)
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
        if rows.is_empty() {
            Ok(())
        } else {
            Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "password-derived signature verifier already exists",
            ))
        }
    }

    async fn lock_current_verifier(
        &self,
        tx: &mut Tx<'_>,
        payload: &PasswordDerivedSignatureVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let expected_credential_id = payload
            .expected_password_credential_id
            .as_ref()
            .ok_or_else(|| {
                PostgresAuthMethodCommitError::InvalidOperation(
                    "password-derived signature verifier precondition is missing target credential"
                        .to_owned(),
                )
            })?;
        let statement = format!(
            r#"
            SELECT password_credential_id
            FROM {}
            WHERE password_credential_id = $1
                AND subject_id = $2
            FOR UPDATE
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.password_derived_signature.precondition.verifier_current",
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
                "password-derived signature verifier is not current",
            ))
        }
    }

    async fn create_verifier(
        &self,
        tx: &mut Tx<'_>,
        payload: &PasswordDerivedSignatureVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
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
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.password_derived_signature.mutation.create_verifier",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&payload.new_password_credential_id)
            .bind(&payload.subject_id)
            .bind(&payload.lookup_handle)
            .bind(&payload.kdf_salt)
            .bind(i64::from(payload.kdf_memory_cost_kib))
            .bind(i64::from(payload.kdf_iterations))
            .bind(i64::from(payload.kdf_parallelism))
            .bind(&payload.public_key)
            .bind(i64_from_password_signature_u64(payload.updated_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "password-derived signature verifier was not created",
            ));
        }
        Ok(())
    }

    async fn replace_verifier(
        &self,
        tx: &mut Tx<'_>,
        payload: &PasswordDerivedSignatureVerifierCommitPayload,
    ) -> Result<(), PostgresAuthMethodCommitError> {
        let expected_credential_id = payload
            .expected_password_credential_id
            .as_ref()
            .ok_or_else(|| {
                PostgresAuthMethodCommitError::InvalidOperation(
                    "password-derived signature verifier mutation is missing target credential"
                        .to_owned(),
                )
            })?;
        let statement = format!(
            r#"
            UPDATE {}
            SET password_credential_id = $3,
                lookup_handle = $4,
                kdf_salt = $5,
                kdf_memory_cost_kib = $6,
                kdf_iterations = $7,
                kdf_parallelism = $8,
                public_key = $9,
                verifier_version = CASE
                    WHEN password_credential_id = $3 THEN verifier_version + 1
                    ELSE 1
                END,
                created_at = CASE
                    WHEN password_credential_id = $3 THEN created_at
                    ELSE $10
                END,
                updated_at = $10
            WHERE password_credential_id = $1
                AND subject_id = $2
            "#,
            self.table_names_for_commit()?.verifier_table.quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.password_derived_signature.mutation.replace_verifier",
            Some(statement.as_str()),
        );
        let affected = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(expected_credential_id)
            .bind(&payload.subject_id)
            .bind(&payload.new_password_credential_id)
            .bind(&payload.lookup_handle)
            .bind(&payload.kdf_salt)
            .bind(i64::from(payload.kdf_memory_cost_kib))
            .bind(i64::from(payload.kdf_iterations))
            .bind(i64::from(payload.kdf_parallelism))
            .bind(&payload.public_key)
            .bind(i64_from_password_signature_u64(payload.updated_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .rows_affected();
        if affected != 1 {
            return Err(PostgresAuthMethodCommitError::PreconditionFailed(
                "password-derived signature verifier is not current",
            ));
        }
        Ok(())
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

    #[cfg(test)]
    pub(crate) fn verifier_creation_payload_for_test(
        lookup_handle: &[u8],
        password: &[u8],
        salt: PasswordKdfSalt,
        params: PasswordKdfParams,
    ) -> Result<CredentialCreationMethodPayload, PostgresPasswordDerivedSignatureMethodError> {
        let public_key = public_key_from_password_for_test(password, salt, params)?;
        CredentialCreationMethodPayload::try_from_bytes(encode_password_signature_payload(
            &PasswordDerivedSignatureVerifierMethodPayload {
                lookup_handle: lookup_handle.to_vec(),
                kdf_salt: salt.as_bytes().to_vec(),
                kdf_memory_cost_kib: params.memory_cost_kib(),
                kdf_iterations: params.iterations(),
                kdf_parallelism: params.parallelism(),
                public_key,
            },
        )?)
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn verifier_reset_payload_for_test(
        lookup_handle: &[u8],
        password: &[u8],
        salt: PasswordKdfSalt,
        params: PasswordKdfParams,
    ) -> Result<CredentialResetMethodPayload, PostgresPasswordDerivedSignatureMethodError> {
        let public_key = public_key_from_password_for_test(password, salt, params)?;
        CredentialResetMethodPayload::try_from_bytes(encode_password_signature_payload(
            &PasswordDerivedSignatureVerifierMethodPayload {
                lookup_handle: lookup_handle.to_vec(),
                kdf_salt: salt.as_bytes().to_vec(),
                kdf_memory_cost_kib: params.memory_cost_kib(),
                kdf_iterations: params.iterations(),
                kdf_parallelism: params.parallelism(),
                public_key,
            },
        )?)
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) fn verifier_lifecycle_payload_for_test(
        lookup_handle: &[u8],
        password: &[u8],
        salt: PasswordKdfSalt,
        params: PasswordKdfParams,
    ) -> Result<CredentialLifecycleMethodPayload, PostgresPasswordDerivedSignatureMethodError> {
        let public_key = public_key_from_password_for_test(password, salt, params)?;
        CredentialLifecycleMethodPayload::try_from_bytes(encode_password_signature_payload(
            &PasswordDerivedSignatureVerifierMethodPayload {
                lookup_handle: lookup_handle.to_vec(),
                kdf_salt: salt.as_bytes().to_vec(),
                kdf_memory_cost_kib: params.memory_cost_kib(),
                kdf_iterations: params.iterations(),
                kdf_parallelism: params.parallelism(),
                public_key,
            },
        )?)
        .map_err(PostgresPasswordDerivedSignatureMethodError::Core)
    }

    #[cfg(test)]
    pub(crate) async fn count_verifiers_for_subject_for_test(
        &self,
        pool: &Pool,
        subject_id: &SubjectId,
    ) -> Result<i64, PostgresPasswordDerivedSignatureMethodError> {
        let statement = format!(
            "SELECT count(*) FROM {} WHERE subject_id = $1",
            self.table_names()?.verifier_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_one(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database);
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
    ) -> Result<Option<i64>, PostgresPasswordDerivedSignatureMethodError> {
        let statement = format!(
            "SELECT verifier_version FROM {} WHERE subject_id = $1",
            self.table_names()?.verifier_table.quoted()
        );
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database)?;
        let result = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(subject_id.as_bytes())
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database);
        let rollback_result = tx
            .rollback()
            .await
            .map_err(PostgresPasswordDerivedSignatureMethodError::Database);
        match (result, rollback_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
}

impl PostgresAuthMethodPlugin for PostgresPasswordDerivedSignatureMethodPlugin {
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
                    "password-derived signature method supports only replacement and rotation lifecycle work",
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
                PASSWORD_DERIVED_SIGNATURE_VERIFIER_ABSENT_OPERATION => {
                    let payload = decode_verifier_commit_payload(precondition.payload())?;
                    self.enforce_verifier_absent(tx, &payload).await
                }
                PASSWORD_DERIVED_SIGNATURE_VERIFIER_CURRENT_OPERATION => {
                    let payload = decode_verifier_commit_payload(precondition.payload())?;
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
                PASSWORD_DERIVED_SIGNATURE_CREATE_VERIFIER_OPERATION => {
                    let payload = decode_verifier_commit_payload(mutation.payload())?;
                    self.create_verifier(tx, &payload).await
                }
                PASSWORD_DERIVED_SIGNATURE_REPLACE_VERIFIER_OPERATION => {
                    let payload = decode_verifier_commit_payload(mutation.payload())?;
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
struct PasswordDerivedSignatureVerifierMethodPayload {
    lookup_handle: Vec<u8>,
    kdf_salt: Vec<u8>,
    kdf_memory_cost_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    public_key: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct PasswordDerivedSignatureVerifierCommitPayload {
    expected_password_credential_id: Option<Vec<u8>>,
    new_password_credential_id: Vec<u8>,
    subject_id: Vec<u8>,
    lookup_handle: Vec<u8>,
    kdf_salt: Vec<u8>,
    kdf_memory_cost_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    public_key: Vec<u8>,
    updated_at: u64,
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

fn validate_lookup_handle(
    lookup_handle: &[u8],
) -> Result<(), PostgresPasswordDerivedSignatureMethodError> {
    if lookup_handle.is_empty()
        || lookup_handle.len() > PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES
    {
        return Err(PostgresPasswordDerivedSignatureMethodError::InvalidLookupHandle);
    }
    Ok(())
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

fn decode_verifier_commit_payload(
    payload: &[u8],
) -> Result<PasswordDerivedSignatureVerifierCommitPayload, PostgresAuthMethodCommitError> {
    let payload: PasswordDerivedSignatureVerifierCommitPayload = postcard::from_bytes(payload)
        .map_err(|_| {
            PostgresAuthMethodCommitError::InvalidOperation(
                "invalid password-derived signature verifier payload".to_owned(),
            )
        })?;
    validate_verifier_commit_payload(&payload)?;
    Ok(payload)
}

fn validate_verifier_commit_payload(
    payload: &PasswordDerivedSignatureVerifierCommitPayload,
) -> Result<(), PostgresAuthMethodCommitError> {
    if let Some(expected) = payload.expected_password_credential_id.as_ref() {
        VerifiedProofSourceId::from_bytes(expected.clone()).map_err(|_| {
            PostgresAuthMethodCommitError::InvalidOperation(
                "invalid password-derived signature target credential id".to_owned(),
            )
        })?;
    }
    VerifiedProofSourceId::from_bytes(payload.new_password_credential_id.clone()).map_err(
        |_| {
            PostgresAuthMethodCommitError::InvalidOperation(
                "invalid password-derived signature new credential id".to_owned(),
            )
        },
    )?;
    SubjectId::from_bytes(payload.subject_id.clone()).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "invalid password-derived signature subject id".to_owned(),
        )
    })?;
    if payload.lookup_handle.is_empty()
        || payload.lookup_handle.len() > PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES
    {
        return Err(PostgresAuthMethodCommitError::InvalidOperation(
            "invalid password-derived signature lookup handle".to_owned(),
        ));
    }
    PasswordKdfSalt::from_bytes(&payload.kdf_salt).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "invalid password-derived signature KDF salt".to_owned(),
        )
    })?;
    PasswordKdfParams::new(
        payload.kdf_memory_cost_kib,
        payload.kdf_iterations,
        payload.kdf_parallelism,
    )
    .map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation(
            "invalid password-derived signature KDF parameters".to_owned(),
        )
    })?;
    if payload.public_key.len() != PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES {
        return Err(PostgresAuthMethodCommitError::InvalidOperation(
            "invalid password-derived signature public key".to_owned(),
        ));
    }
    i64_from_password_signature_u64(payload.updated_at)?;
    Ok(())
}

fn i64_from_unix_seconds_for_method(
    value: UnixSeconds,
) -> Result<i64, PostgresPasswordDerivedSignatureMethodError> {
    i64::try_from(value.get())
        .map_err(|_| PostgresPasswordDerivedSignatureMethodError::Core(Error::TimeOverflow))
}

fn i64_from_password_signature_u64(value: u64) -> Result<i64, PostgresAuthMethodCommitError> {
    i64::try_from(value).map_err(|_| {
        PostgresAuthMethodCommitError::InvalidOperation("timestamp overflow".to_owned())
    })
}

fn password_signature_verifier_table_columns() -> Vec<MethodTableColumnContract> {
    vec![
        MethodTableColumnContract::bytea("password_credential_id", true),
        MethodTableColumnContract::bytea("subject_id", true),
        MethodTableColumnContract::bytea("lookup_handle", true),
        MethodTableColumnContract::bytea("kdf_salt", true),
        MethodTableColumnContract::bigint("kdf_memory_cost_kib", true),
        MethodTableColumnContract::bigint("kdf_iterations", true),
        MethodTableColumnContract::bigint("kdf_parallelism", true),
        MethodTableColumnContract::bytea("public_key", true),
        MethodTableColumnContract::bigint("verifier_version", true),
        MethodTableColumnContract::bigint("created_at", true),
        MethodTableColumnContract::bigint("updated_at", true),
    ]
}

fn password_signature_verifier_table_checks() -> Vec<MethodTableCheckConstraint> {
    vec![
        MethodTableCheckConstraint::new(
            "credential_id_len",
            quoted_len_at_least_one_and_at_most("password_credential_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "subject_id_len",
            quoted_len_at_least_one_and_at_most("subject_id", ID_MAX_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "lookup_handle_len",
            quoted_len_at_least_one_and_at_most(
                "lookup_handle",
                PASSWORD_DERIVED_SIGNATURE_LOOKUP_HANDLE_MAX_BYTES,
            ),
        ),
        MethodTableCheckConstraint::new(
            "kdf_salt_len",
            quoted_len_equals("kdf_salt", PASSWORD_KDF_SALT_SIZE),
        ),
        MethodTableCheckConstraint::new(
            "public_key_len",
            quoted_len_equals("public_key", PASSWORD_DERIVED_SIGNATURE_PUBLIC_KEY_BYTES),
        ),
        MethodTableCheckConstraint::new(
            "kdf_memory_cost_positive",
            quoted_bigint_positive("kdf_memory_cost_kib"),
        ),
        MethodTableCheckConstraint::new(
            "kdf_iterations_positive",
            quoted_bigint_positive("kdf_iterations"),
        ),
        MethodTableCheckConstraint::new(
            "kdf_parallelism_positive",
            quoted_bigint_positive("kdf_parallelism"),
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

fn password_signature_verifier_table_indexes() -> Vec<MethodTableIndexContract> {
    vec![
        MethodTableIndexContract::unique(
            "password credential primary-key",
            ["password_credential_id"],
        ),
        MethodTableIndexContract::unique("subject lookup", ["subject_id"]),
        MethodTableIndexContract::unique("lookup handle", ["lookup_handle"]),
    ]
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
    fn config_for_db_bootstrap_uses_schema_local_bootstrap_tables() {
        let bootstrap_config =
            BootstrapConfig::from_schema_name_text("__paranoid").expect("bootstrap config");
        let config = PostgresPasswordDerivedSignatureMethodPluginConfig::for_db_bootstrap_config(
            &bootstrap_config,
        )
        .expect("password-derived signature method config");
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
