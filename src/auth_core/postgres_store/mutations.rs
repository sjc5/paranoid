use super::*;

pub(in crate::auth_core) async fn apply_mutation(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    mutation: &Mutation,
) -> Result<(), PostgresAuthStoreError> {
    match mutation {
        Mutation::CreateSession(record) => insert_session(tx, table_names, record).await,
        Mutation::RefreshSession {
            session_id,
            new_secret_version,
            previous_secret_version,
            previous_secret_accept_until,
            refreshed_at,
            expires_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET current_secret_version = $2,
                    previous_secret_version = $3,
                    previous_secret_accept_until = $4,
                    refreshed_at = $5,
                    expires_at = $6
                WHERE session_id = $1
                "#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.refresh_session",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(i64_from_secret_version(*new_secret_version)?)
                        .bind(i64_from_secret_version(*previous_secret_version)?)
                        .bind(i64_from_unix_seconds(*previous_secret_accept_until)?)
                        .bind(i64_from_unix_seconds(*refreshed_at)?)
                        .bind(i64_from_unix_seconds(*expires_at)?))
                },
            )
            .await
        }
        Mutation::RecordStepUp {
            session_id,
            new_secret_version,
            previous_secret_version,
            previous_secret_accept_until,
            step_up_expires_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET current_secret_version = $2,
                    previous_secret_version = $3,
                    previous_secret_accept_until = $4,
                    step_up_expires_at = $5
                WHERE session_id = $1
                "#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_step_up",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(i64_from_secret_version(*new_secret_version)?)
                        .bind(i64_from_secret_version(*previous_secret_version)?)
                        .bind(i64_from_unix_seconds(*previous_secret_accept_until)?)
                        .bind(i64_from_unix_seconds(*step_up_expires_at)?))
                },
            )
            .await
        }
        Mutation::CreateTrustedDeviceCredential(record) => {
            insert_trusted_device(tx, table_names, record).await
        }
        Mutation::CreateActiveProofAttempt(record) => {
            insert_active_proof_attempt(tx, table_names, record).await
        }
        Mutation::CreateActiveProofChallenge(record) => {
            insert_active_proof_challenge(tx, table_names, record).await
        }
        Mutation::RecordWeakProofFailure {
            attempt_id,
            weak_proof_failures,
        } => {
            let statement = format!(
                r#"UPDATE {} SET weak_proof_failures = $2 WHERE attempt_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_weak_proof_failure",
                &statement,
                |query| {
                    Ok(query
                        .bind(attempt_id.as_bytes())
                        .bind(i32_from_u32(*weak_proof_failures)?))
                },
            )
            .await
        }
        Mutation::RecordActiveProofSucceeded {
            attempt_id,
            subject_id,
            proof,
            satisfied_at,
        } => {
            let update_statement = format!(
                r#"UPDATE {} SET subject_id = COALESCE(subject_id, $2) WHERE attempt_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.bind_active_proof_attempt_subject",
                &update_statement,
                |query| {
                    Ok(query
                        .bind(attempt_id.as_bytes())
                        .bind(subject_id.as_ref().map(|id| id.as_bytes().to_vec())))
                },
            )
            .await?;
            insert_satisfied_proof(tx, table_names, attempt_id, proof, *satisfied_at).await
        }
        Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
            attempt_id,
            proof_family,
            closed_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET closed_at = $3
                WHERE attempt_id = $1
                  AND proof_family = $2
                  AND closed_at IS NULL
                "#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.mutation.close_open_challenges_for_proof_family",
                Some(statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(attempt_id.as_bytes())
                .bind(i32_from_proof_family(*proof_family))
                .bind(i64_from_unix_seconds(*closed_at)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;
            Ok(())
        }
        Mutation::RecordOutOfBandChallengeResent {
            challenge_id,
            resend_count,
            used_delivery_idempotency_keys,
            resent_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET resend_count = $2 WHERE challenge_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_out_of_band_challenge_resent",
                &statement,
                |query| {
                    Ok(query
                        .bind(challenge_id.as_bytes())
                        .bind(i32_from_u32(*resend_count)?))
                },
            )
            .await?;
            for key in used_delivery_idempotency_keys {
                insert_challenge_delivery_key(tx, table_names, challenge_id, key, *resent_at)
                    .await?;
            }
            Ok(())
        }
        Mutation::DeleteActiveProofAttempt { attempt_id } => {
            hard_delete_active_proof_attempt(tx, table_names, attempt_id).await
        }
        Mutation::RotateTrustedDeviceCredential {
            device_credential_id,
            new_secret_version,
            previous_secret_version,
            previous_secret_accept_until,
            last_used_at,
            silent_revival_until,
            expires_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET current_secret_version = $2,
                    previous_secret_version = $3,
                    previous_secret_accept_until = $4,
                    last_used_at = $5,
                    silent_revival_until = $6,
                    expires_at = $7
                WHERE device_credential_id = $1
                "#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.rotate_trusted_device",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(i64_from_secret_version(*new_secret_version)?)
                        .bind(i64_from_secret_version(*previous_secret_version)?)
                        .bind(i64_from_unix_seconds(*previous_secret_accept_until)?)
                        .bind(i64_from_unix_seconds(*last_used_at)?)
                        .bind(i64_from_unix_seconds(*silent_revival_until)?)
                        .bind(i64_from_unix_seconds(*expires_at)?))
                },
            )
            .await
        }
        Mutation::RevokeSession {
            session_id,
            revoked_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET revoked_at = $2 WHERE session_id = $1"#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.revoke_session",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(i64_from_unix_seconds(*revoked_at)?))
                },
            )
            .await
        }
        Mutation::RevokeTrustedDeviceCredential {
            device_credential_id,
            revoked_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET revoked_at = $2 WHERE device_credential_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.revoke_trusted_device",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(i64_from_unix_seconds(*revoked_at)?))
                },
            )
            .await
        }
        Mutation::RaiseSubjectAuthRevocationCutoff {
            subject_id,
            revoke_records_created_at_or_before,
            ..
        } => {
            materialize_and_lock_subject_auth_state(
                tx,
                table_names,
                subject_id,
                *revoke_records_created_at_or_before,
            )
            .await
        }
        Mutation::RecordCredentialLifecycleActionAuthorized {
            target_credential_instance_id,
            authorized_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET updated_at = $2 WHERE credential_instance_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_credential_lifecycle_action_authorized",
                &statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i64_from_unix_seconds(*authorized_at)?))
                },
            )
            .await
        }
        Mutation::CreateCredentialInstanceMetadata {
            metadata,
            created_at,
        } => insert_credential_instance_metadata(tx, table_names, metadata, *created_at).await,
        Mutation::CreateCredentialRecoveryAuthority {
            authority,
            created_at,
        } => insert_credential_recovery_authority(tx, table_names, authority, *created_at).await,
        Mutation::CreateLifecycleAuthoritySource {
            source,
            authority_id,
            created_at,
        } => {
            insert_lifecycle_authority_source(tx, table_names, source, authority_id, *created_at)
                .await
        }
        Mutation::CreatePendingCredentialLifecycleAction(record) => {
            insert_pending_credential_lifecycle_action(tx, table_names, record).await
        }
        Mutation::RecordCredentialLifecycleActionExecuted {
            target_credential_instance_id,
            executed_at,
            ..
        } => {
            let statement = format!(
                r#"UPDATE {} SET updated_at = $2 WHERE credential_instance_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.record_credential_lifecycle_action_executed",
                &statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i64_from_unix_seconds(*executed_at)?))
                },
            )
            .await
        }
        Mutation::SetCredentialLifecycleState {
            credential_instance_id,
            lifecycle_state,
            updated_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET lifecycle_state = $2, updated_at = $3 WHERE credential_instance_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.set_credential_lifecycle_state",
                &statement,
                |query| {
                    Ok(query
                        .bind(credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_state(*lifecycle_state))
                        .bind(i64_from_unix_seconds(*updated_at)?))
                },
            )
            .await
        }
        Mutation::ClosePendingCredentialLifecycleAction {
            pending_action_id,
            closed_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET closed_at = $2 WHERE pending_action_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.close_pending_credential_lifecycle_action",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(i64_from_unix_seconds(*closed_at)?))
                },
            )
            .await
        }
        Mutation::CreatePendingSubjectLifecycleAction(record) => {
            insert_pending_subject_lifecycle_action(tx, table_names, record).await
        }
        Mutation::ClosePendingSubjectLifecycleAction {
            pending_action_id,
            closed_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET closed_at = $2 WHERE pending_action_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.close_pending_subject_lifecycle_action",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(i64_from_unix_seconds(*closed_at)?))
                },
            )
            .await
        }
        Mutation::CreateOutOfBandIdentifierBinding { record, created_at } => {
            insert_out_of_band_identifier_binding(tx, table_names, record, *created_at).await
        }
        Mutation::DeleteLifecycleAuthoritySourcesForSource { source } => {
            delete_lifecycle_authority_sources_for_source(tx, table_names, source).await
        }
        Mutation::SetOutOfBandIdentifierBindingLifecycleState {
            source_id,
            lifecycle_state,
            updated_at,
        } => {
            let statement = format!(
                r#"
                UPDATE {}
                SET lifecycle_state = $2,
                    updated_at = $3
                WHERE source_id = $1
                "#,
                table_names
                    .get(PostgresAuthCoreTable::OutOfBandIdentifierBinding)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.set_out_of_band_identifier_binding_lifecycle_state",
                &statement,
                |query| {
                    Ok(query
                        .bind(source_id.as_bytes())
                        .bind(i32_from_out_of_band_identifier_binding_lifecycle_state(
                            *lifecycle_state,
                        ))
                        .bind(i64_from_unix_seconds(*updated_at)?))
                },
            )
            .await
        }
        Mutation::CreateAdminSupportIntervention(record) => {
            insert_admin_support_intervention(tx, table_names, record).await
        }
        Mutation::CloseAdminSupportIntervention {
            intervention_id,
            status,
            closed_at,
        } => {
            let statement = format!(
                r#"UPDATE {} SET status = $2, closed_at = $3 WHERE intervention_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::AdminSupportIntervention)
                    .quoted()
            );
            execute_one_row_update(
                tx,
                "auth_core.mutation.close_admin_support_intervention",
                &statement,
                |query| {
                    Ok(query
                        .bind(intervention_id.as_bytes())
                        .bind(i32_from_admin_support_intervention_status(*status))
                        .bind(i64_from_unix_seconds(*closed_at)?))
                },
            )
            .await
        }
    }
}

pub(in crate::auth_core) async fn insert_session(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &SessionRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            session_id, subject_id, device_credential_id, current_secret_version,
            previous_secret_version, previous_secret_accept_until, created_at, refreshed_at,
            expires_at, step_up_expires_at, revoked_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
        table_names.get(PostgresAuthCoreTable::Session).quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_session",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.session_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(
            record
                .device_credential_id
                .as_ref()
                .map(|id| id.as_bytes().to_vec()),
        )
        .bind(i64_from_secret_version(record.current_secret_version)?)
        .bind(optional_i64_from_secret_version(
            record.previous_secret_version,
        )?)
        .bind(optional_i64_from_unix_seconds(
            record.previous_secret_accept_until,
        )?)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.refreshed_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.step_up_expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.revoked_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_trusted_device(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &TrustedDeviceCredentialRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            device_credential_id, subject_id, current_secret_version, previous_secret_version,
            previous_secret_accept_until, created_at, last_used_at, expires_at,
            silent_revival_until, revoked_at, display_label
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
        table_names
            .get(PostgresAuthCoreTable::TrustedDeviceCredential)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_trusted_device",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.device_credential_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(i64_from_secret_version(record.current_secret_version)?)
        .bind(optional_i64_from_secret_version(
            record.previous_secret_version,
        )?)
        .bind(optional_i64_from_unix_seconds(
            record.previous_secret_accept_until,
        )?)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.last_used_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(i64_from_unix_seconds(record.silent_revival_until)?)
        .bind(optional_i64_from_unix_seconds(record.revoked_at)?)
        .bind(record.display_label.as_deref())
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_active_proof_attempt(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &ActiveProofAttemptRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            attempt_id, proof_use, subject_id, weak_proof_failures,
            max_weak_proof_failures, created_at, expires_at, closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofAttempt)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_active_proof_attempt",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.attempt_id.as_bytes())
        .bind(i32_from_proof_use(record.proof_use))
        .bind(record.subject_id.as_ref().map(|id| id.as_bytes().to_vec()))
        .bind(i32_from_u32(record.weak_proof_failures)?)
        .bind(i32_from_u32(record.max_weak_proof_failures)?)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_active_proof_challenge(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &ActiveProofChallengeRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            challenge_id, attempt_id, proof_family, method_label, online_guessing_risk,
            challenge_dedupe_key, recipient_handle, resend_count, max_resends,
            requires_stateless_fast_fail, created_at, expires_at, closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallenge)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_active_proof_challenge",
        Some(statement.as_str()),
    );
    let insert_result = pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.challenge_id.as_bytes())
        .bind(record.attempt_id.as_bytes())
        .bind(i32_from_proof_family(record.proof.family()))
        .bind(record.proof.method_label())
        .bind(bool_from_online_guessing_risk(
            record.proof.online_guessing_risk(),
        ))
        .bind(record.challenge_dedupe_key.as_ref().map(|key| key.as_str()))
        .bind(record.recipient_handle.as_deref())
        .bind(i32_from_u32(record.resend_count)?)
        .bind(i32_from_u32(record.max_resends)?)
        .bind(record.requires_stateless_fast_fail)
        .bind(i64_from_unix_seconds(record.created_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await;
    match insert_result {
        Ok(_) => {}
        Err(error) if sqlx_error_is_open_challenge_dedupe_unique_violation(&error, table_names) => {
            return Err(PostgresAuthStoreError::PreconditionFailed(
                "open out-of-band challenge dedupe key already exists",
            ));
        }
        Err(error) => return Err(DbError::query(error).into()),
    }
    for key in &record.used_delivery_idempotency_keys {
        insert_challenge_delivery_key(
            tx,
            table_names,
            &record.challenge_id,
            key,
            record.created_at,
        )
        .await?;
    }
    Ok(())
}

pub(in crate::auth_core) fn sqlx_error_is_open_challenge_dedupe_unique_violation(
    error: &sqlx::Error,
    table_names: &AuthCoreTableNames,
) -> bool {
    if sql_state_from_sqlx_error(error) != Some(PgSqlState::UniqueViolation) {
        return false;
    }
    let Ok(index_name) = open_challenge_dedupe_index_name(table_names) else {
        return false;
    };
    error
        .as_database_error()
        .and_then(|database_error| database_error.constraint())
        .is_some_and(|constraint| constraint == index_name.as_str())
}

pub(in crate::auth_core) fn open_challenge_dedupe_index_name(
    table_names: &AuthCoreTableNames,
) -> Result<PgIdentifier, PostgresAuthStoreError> {
    Ok(PgIdentifier::new(format!(
        "{}{}_{}",
        table_names.index_name_prefix,
        auth_table_number(PostgresAuthCoreTable::ActiveProofChallenge),
        "active_proof_open_challenge_dedupe_key"
    ))
    .map_err(DbError::from)?)
}

pub(in crate::auth_core) async fn insert_satisfied_proof(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    attempt_id: &ActiveProofAttemptId,
    proof: &SatisfiedProof,
    satisfied_at: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            attempt_id, proof_family, method_label, online_guessing_risk,
            proof_source_kind, proof_source_id, satisfied_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_satisfied_proof",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(attempt_id.as_bytes())
        .bind(i32_from_proof_family(proof.family()))
        .bind(proof.method_label())
        .bind(bool_from_online_guessing_risk(proof.online_guessing_risk()))
        .bind(
            proof
                .source()
                .map(|source| i32_from_verified_proof_source_kind(source.kind())),
        )
        .bind(proof.source().map(|source| source.source_id().as_bytes()))
        .bind(i64_from_unix_seconds(satisfied_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_challenge_delivery_key(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    challenge_id: &ActiveProofChallengeId,
    idempotency_key: &str,
    created_at: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (challenge_id, delivery_idempotency_key, created_at)
        VALUES ($1,$2,$3)
        ON CONFLICT (challenge_id, delivery_idempotency_key) DO NOTHING
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_challenge_delivery_key",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(challenge_id.as_bytes())
        .bind(idempotency_key)
        .bind(i64_from_unix_seconds(created_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_session_secret_mac(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    session_id: &SessionId,
    secret_version: SecretVersion,
    mac_bytes: &[u8],
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (session_id, secret_version, secret_mac, created_at)
        VALUES ($1,$2,$3,0)
        "#,
        table_names
            .get(PostgresAuthCoreTable::SessionCredentialSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.secret.insert_session_mac",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(session_id.as_bytes())
        .bind(i64_from_secret_version(secret_version)?)
        .bind(mac_bytes)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_trusted_device_secret_mac(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    device_credential_id: &TrustedDeviceCredentialId,
    secret_version: SecretVersion,
    mac_bytes: &[u8],
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (device_credential_id, secret_version, secret_mac, created_at)
        VALUES ($1,$2,$3,0)
        "#,
        table_names
            .get(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.secret.insert_trusted_device_mac",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(device_credential_id.as_bytes())
        .bind(i64_from_secret_version(secret_version)?)
        .bind(mac_bytes)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_active_proof_continuation_secret_mac(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    attempt_id: &ActiveProofAttemptId,
    mac_bytes: &[u8],
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (attempt_id, secret_mac, created_at)
        VALUES ($1,$2,0)
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofContinuationSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.secret.insert_active_proof_continuation_mac",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(attempt_id.as_bytes())
        .bind(mac_bytes)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn hard_delete_active_proof_attempt(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    attempt_id: &ActiveProofAttemptId,
) -> Result<(), PostgresAuthStoreError> {
    let delivery_statement = format!(
        r#"
        DELETE FROM {}
        WHERE challenge_id IN (
            SELECT challenge_id FROM {} WHERE attempt_id = $1
        )
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
            .quoted(),
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallenge)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.delete_active_proof_delivery_keys",
        Some(delivery_statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(delivery_statement.as_str()))
        .bind(attempt_id.as_bytes())
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;

    for (label, table) in [
        (
            "auth_core.mutation.delete_active_proof_satisfied_proofs",
            PostgresAuthCoreTable::ActiveProofSatisfiedProof,
        ),
        (
            "auth_core.mutation.delete_active_proof_challenges",
            PostgresAuthCoreTable::ActiveProofChallenge,
        ),
        (
            "auth_core.mutation.delete_active_proof_continuation_secret_mac",
            PostgresAuthCoreTable::ActiveProofContinuationSecretMac,
        ),
        (
            "auth_core.mutation.delete_active_proof_attempt",
            PostgresAuthCoreTable::ActiveProofAttempt,
        ),
    ] {
        let statement = format!(
            r#"DELETE FROM {} WHERE attempt_id = $1"#,
            table_names.get(table).quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            label,
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(attempt_id.as_bytes())
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}

pub(in crate::auth_core) async fn append_audit_events(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    events: &[AuditEvent],
) -> Result<(), PostgresAuthStoreError> {
    for event in events {
        let statement = format!(
            r#"
            INSERT INTO {} (
                kind, subject_id, session_id, device_credential_id, attempt_id,
                challenge_id, weak_proof_gate_kind, weak_proof_gate_method_label, occurred_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            "#,
            table_names.get(PostgresAuthCoreTable::AuditEvent).quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            "auth_core.audit.append_event",
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(i32_from_audit_event_kind(event.kind))
            .bind(event.subject_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(event.session_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(
                event
                    .device_credential_id
                    .as_ref()
                    .map(|id| id.as_bytes().to_vec()),
            )
            .bind(event.attempt_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(event.challenge_id.as_ref().map(|id| id.as_bytes().to_vec()))
            .bind(
                event
                    .weak_proof_gate
                    .as_ref()
                    .map(|gate| i32_from_weak_gate_kind(gate.kind())),
            )
            .bind(
                event
                    .weak_proof_gate
                    .as_ref()
                    .map(WeakProofGateSummary::method_label),
            )
            .bind(i64_from_unix_seconds(event.occurred_at)?)
            .execute(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}

pub(in crate::auth_core) async fn append_core_durable_effects(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    commands: &[DurableEffectCommand],
) -> Result<(), PostgresAuthStoreError> {
    for command in commands {
        match command {
            DurableEffectCommand::SendOutOfBandMessage(command) => {
                let statement = format!(
                    r#"
                    INSERT INTO {} (
                        kind, security_notification_kind, challenge_id, proof_method_label, recipient_handle,
                        delivery_idempotency_key, expires_at, created_at
                    )
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
                    "#,
                    table_names
                        .get(PostgresAuthCoreTable::CoreDurableEffectCommand)
                        .quoted()
                );
                tx.record_database_operation(
                    DatabaseOperationKind::Execute,
                    "auth_core.effect.append_out_of_band_message",
                    Some(statement.as_str()),
                );
                pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                    .bind(DURABLE_EFFECT_KIND_SEND_OUT_OF_BAND_MESSAGE)
                    .bind(Option::<i32>::None)
                    .bind(command.challenge_id.as_bytes())
                    .bind(command.proof_method_label.as_str())
                    .bind(command.recipient_handle.as_str())
                    .bind(command.idempotency_key.as_str())
                    .bind(i64_from_unix_seconds(command.expires_at)?)
                    .execute(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            }
            DurableEffectCommand::NotifySecurityEvent(command) => {
                let statement = format!(
                    r#"
                    INSERT INTO {} (kind, security_notification_kind, subject_id, created_at)
                    VALUES ($1,$2,$3,0)
                    "#,
                    table_names
                        .get(PostgresAuthCoreTable::CoreDurableEffectCommand)
                        .quoted()
                );
                tx.record_database_operation(
                    DatabaseOperationKind::Execute,
                    "auth_core.effect.append_security_notification",
                    Some(statement.as_str()),
                );
                pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                    .bind(DURABLE_EFFECT_KIND_NOTIFY_SECURITY_EVENT)
                    .bind(i32_from_security_notification_kind(command.kind))
                    .bind(command.subject_id.as_bytes())
                    .execute(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            }
            DurableEffectCommand::ApplyApplicationSubjectDataLifecycle(command) => {
                let kind = match command.action {
                    ApplicationSubjectDataLifecycleAction::DeleteSubjectData => {
                        DURABLE_EFFECT_KIND_DELETE_APPLICATION_SUBJECT_DATA
                    }
                    ApplicationSubjectDataLifecycleAction::DisableSubjectData => {
                        DURABLE_EFFECT_KIND_DISABLE_APPLICATION_SUBJECT_DATA
                    }
                };
                let statement = format!(
                    r#"
                    INSERT INTO {} (kind, subject_id, created_at)
                    VALUES ($1,$2,$3)
                    "#,
                    table_names
                        .get(PostgresAuthCoreTable::CoreDurableEffectCommand)
                        .quoted()
                );
                tx.record_database_operation(
                    DatabaseOperationKind::Execute,
                    "auth_core.effect.append_application_subject_data_lifecycle",
                    Some(statement.as_str()),
                );
                pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
                    .bind(kind)
                    .bind(command.subject_id.as_bytes())
                    .bind(i64_from_unix_seconds(command.requested_at)?)
                    .execute(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            }
        }
    }
    Ok(())
}

pub(in crate::auth_core) async fn materialize_and_lock_subject_auth_state(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    cutoff: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let upsert_statement = format!(
        r#"
        INSERT INTO {} (subject_id, revoke_records_created_at_or_before)
        VALUES ($1,$2)
        ON CONFLICT (subject_id)
        DO UPDATE SET revoke_records_created_at_or_before = GREATEST(
            {}.revoke_records_created_at_or_before,
            EXCLUDED.revoke_records_created_at_or_before
        )
        "#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted(),
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.precondition.materialize_subject_auth_state",
        Some(upsert_statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(upsert_statement.as_str()))
        .bind(subject_id.as_bytes())
        .bind(i64_from_unix_seconds(cutoff)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;

    let lock_statement = format!(
        r#"SELECT 1 FROM {} WHERE subject_id = $1 FOR UPDATE"#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    let found = fetch_exists_for_update(
        tx,
        "auth_core.precondition.lock_subject_auth_state",
        &lock_statement,
        |query| Ok(query.bind(subject_id.as_bytes())),
    )
    .await?;
    if !found {
        return Err(PostgresAuthStoreError::PreconditionFailed(
            "subject auth state could not be locked",
        ));
    }
    Ok(())
}

pub(in crate::auth_core) async fn materialize_and_lock_subject_auth_state_once(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    cutoff: UnixSeconds,
    state: &mut CorePreconditionExecutionState,
) -> Result<(), PostgresAuthStoreError> {
    if state.subject_auth_state_is_locked(subject_id) {
        return Ok(());
    }
    materialize_and_lock_subject_auth_state(tx, table_names, subject_id, cutoff).await?;
    state.remember_subject_auth_state_locked(subject_id.clone());
    Ok(())
}

pub(in crate::auth_core) async fn validate_subject_cutoff_does_not_invalidate(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    target: CoreStorageTarget,
    state: &mut CorePreconditionExecutionState,
) -> Result<(), PostgresAuthStoreError> {
    let cutoff =
        subject_auth_state_cutoff_for_locked_subject(tx, table_names, subject_id, state).await?;
    if cutoff.get() == 0 {
        return Ok(());
    }
    let created_at = fetch_target_created_at(tx, table_names, &target).await?;
    if created_at <= cutoff {
        return Err(PostgresAuthStoreError::PreconditionFailed(
            "subject auth state invalidates target",
        ));
    }
    Ok(())
}

pub(in crate::auth_core) async fn subject_auth_state_cutoff_for_locked_subject(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    state: &mut CorePreconditionExecutionState,
) -> Result<UnixSeconds, PostgresAuthStoreError> {
    if let Some(cutoff) = state.subject_auth_state_cutoff(subject_id) {
        return Ok(cutoff);
    }
    let cutoff_statement = format!(
        r#"SELECT revoke_records_created_at_or_before FROM {} WHERE subject_id = $1"#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "auth_core.precondition.fetch_subject_cutoff",
        Some(cutoff_statement.as_str()),
    );
    let cutoff = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(cutoff_statement.as_str()))
        .bind(subject_id.as_bytes())
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    let cutoff = unix_seconds_from_i64(cutoff)?;
    state.remember_subject_auth_state_cutoff(subject_id.clone(), cutoff);
    Ok(cutoff)
}

pub(in crate::auth_core) async fn fetch_target_created_at(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    target: &CoreStorageTarget,
) -> Result<UnixSeconds, PostgresAuthStoreError> {
    let (statement, id_bytes): (String, &[u8]) = match target {
        CoreStorageTarget::Session(session_id) => (
            format!(
                r#"SELECT created_at FROM {} WHERE session_id = $1"#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            ),
            session_id.as_bytes(),
        ),
        CoreStorageTarget::TrustedDeviceCredential(device_credential_id) => (
            format!(
                r#"SELECT created_at FROM {} WHERE device_credential_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            ),
            device_credential_id.as_bytes(),
        ),
        CoreStorageTarget::ActiveProofAttempt(attempt_id) => (
            format!(
                r#"SELECT created_at FROM {} WHERE attempt_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            ),
            attempt_id.as_bytes(),
        ),
        _ => {
            return Err(PostgresAuthStoreError::InvalidStoredData(
                "subject revocation validation target does not have created_at",
            ));
        }
    };
    tx.record_database_operation(
        DatabaseOperationKind::FetchOne,
        "auth_core.precondition.fetch_target_created_at",
        Some(statement.as_str()),
    );
    let created_at = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(id_bytes)
        .fetch_one(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    unix_seconds_from_i64(created_at)
}
