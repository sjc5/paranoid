use super::*;

pub(in crate::auth_core) async fn insert_credential_instance_metadata(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    metadata: &CredentialInstanceMetadata,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            credential_instance_id,
            subject_id,
            credential_kind,
            method_label,
            reset_policy_role,
            lifecycle_state,
            created_at,
            updated_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_credential_instance_metadata",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(metadata.credential_instance_id().as_bytes())
        .bind(metadata.subject_id().as_bytes())
        .bind(i32_from_credential_instance_kind(metadata.kind()))
        .bind(metadata.method_label())
        .bind(i32_from_credential_reset_policy_role(
            metadata.reset_policy_role(),
        ))
        .bind(i32_from_credential_lifecycle_state(
            metadata.lifecycle_state(),
        ))
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_credential_recovery_authority(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    authority: &CredentialRecoveryAuthority,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            target_credential_instance_id,
            lifecycle_action,
            authority_id,
            authority_timing,
            created_at
        )
        VALUES ($1,$2,$3,$4,$5)
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialRecoveryAuthority)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_credential_recovery_authority",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(authority.target_credential_instance_id().as_bytes())
        .bind(i32_from_credential_lifecycle_action(authority.action()))
        .bind(authority.authority_id().as_bytes())
        .bind(i32_from_recovery_authority_timing(authority.timing()))
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_subject_lifecycle_authority(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    authority: &SubjectLifecycleAuthority,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            subject_id,
            subject_lifecycle_action,
            authority_id,
            authority_timing,
            created_at
        )
        VALUES ($1,$2,$3,$4,$5)
        "#,
        table_names
            .get(PostgresAuthCoreTable::SubjectLifecycleAuthority)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_subject_lifecycle_authority",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(authority.subject_id().as_bytes())
        .bind(i32_from_subject_lifecycle_action(authority.action()))
        .bind(authority.authority_id().as_bytes())
        .bind(i32_from_recovery_authority_timing(authority.timing()))
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_lifecycle_authority_source(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source: &LifecycleAuthoritySource,
    authority_id: &RecoveryAuthorityId,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let (source_kind, source_id) = lifecycle_authority_source_key(source)?;
    let statement = format!(
        r#"
        INSERT INTO {} (
            source_kind,
            source_id,
            authority_id,
            created_at
        )
        VALUES ($1,$2,$3,$4)
        "#,
        table_names
            .get(PostgresAuthCoreTable::LifecycleAuthoritySource)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_lifecycle_authority_source",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(i32_from_lifecycle_authority_source_kind(source_kind))
        .bind(source_id.as_bytes())
        .bind(authority_id.as_bytes())
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn delete_lifecycle_authority_sources_for_source(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source: &LifecycleAuthoritySource,
) -> Result<(), PostgresAuthStoreError> {
    let (source_kind, source_id) = lifecycle_authority_source_key(source)?;
    let statement = format!(
        r#"
        DELETE FROM {}
        WHERE source_kind = $1
          AND source_id = $2
        "#,
        table_names
            .get(PostgresAuthCoreTable::LifecycleAuthoritySource)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.delete_lifecycle_authority_sources_for_source",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(i32_from_lifecycle_authority_source_kind(source_kind))
        .bind(source_id.as_bytes())
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_out_of_band_identifier_binding(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &OutOfBandIdentifierBindingRecord,
    now: UnixSeconds,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            source_id,
            subject_id,
            proof_method_label,
            lifecycle_state,
            created_at,
            updated_at
        )
        VALUES ($1,$2,$3,$4,$5,$5)
        "#,
        table_names
            .get(PostgresAuthCoreTable::OutOfBandIdentifierBinding)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.insert_out_of_band_identifier_binding",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.source().source_id().as_bytes())
        .bind(record.subject_id().as_bytes())
        .bind(record.proof_method_label())
        .bind(i32_from_out_of_band_identifier_binding_lifecycle_state(
            record.lifecycle_state(),
        ))
        .bind(i64_from_unix_seconds(now)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_pending_credential_lifecycle_action(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &PendingCredentialLifecycleActionRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            lifecycle_action,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
        table_names
            .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_pending_credential_lifecycle_action",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.pending_action_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(record.target_credential_instance_id.as_bytes())
        .bind(i32_from_credential_lifecycle_action(record.action))
        .bind(i64_from_unix_seconds(record.requested_at)?)
        .bind(i64_from_unix_seconds(record.earliest_execute_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) async fn insert_pending_subject_lifecycle_action(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &PendingSubjectLifecycleActionRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            pending_action_id,
            subject_id,
            subject_lifecycle_action,
            current_identifier_source_id,
            candidate_identifier_source_id,
            candidate_identifier_authority_ids,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
        table_names
            .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_pending_subject_lifecycle_action",
        Some(statement.as_str()),
    );
    let candidate_authority_ids = encode_pending_subject_identifier_change_authority_ids(record)?;
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.pending_action_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(i32_from_subject_lifecycle_action(record.action))
        .bind(
            record
                .current_identifier_source_id
                .as_ref()
                .map(|source_id| source_id.as_bytes()),
        )
        .bind(
            record
                .candidate_identifier_source_id
                .as_ref()
                .map(|source_id| source_id.as_bytes()),
        )
        .bind(candidate_authority_ids.as_deref())
        .bind(i64_from_unix_seconds(record.requested_at)?)
        .bind(i64_from_unix_seconds(record.earliest_execute_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) fn encode_pending_subject_identifier_change_authority_ids(
    record: &PendingSubjectLifecycleActionRecord,
) -> Result<Option<Vec<u8>>, PostgresAuthStoreError> {
    let authority_ids = &record.candidate_identifier_authority_ids;
    if authority_ids.is_empty() {
        return Ok(None);
    }
    if authority_ids.len() > OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT {
        return Err(PostgresAuthStoreError::Core(Error::InvalidConfig(
            "pending identifier change candidate names too many recovery authorities",
        )));
    }
    let mut encoded = Vec::with_capacity(2 + authority_ids.len() * (2 + ID_MAX_BYTES.min(32)));
    encoded.extend_from_slice(&(authority_ids.len() as u16).to_be_bytes());
    for authority_id in authority_ids {
        let bytes = authority_id.as_bytes();
        let len = u16::try_from(bytes.len()).map_err(|_| {
            PostgresAuthStoreError::Core(Error::InputTooLong {
                input_name: "auth id",
                max_bytes: ID_MAX_BYTES,
            })
        })?;
        encoded.extend_from_slice(&len.to_be_bytes());
        encoded.extend_from_slice(bytes);
    }
    validate_auth_bytes_not_too_long(
        "pending identifier change candidate authority ids",
        &encoded,
        OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_IDS_MAX_BYTES,
    )
    .map_err(PostgresAuthStoreError::Core)?;
    Ok(Some(encoded))
}

pub(in crate::auth_core) fn decode_pending_subject_identifier_change_authority_ids(
    encoded: Option<&[u8]>,
) -> Result<Vec<RecoveryAuthorityId>, PostgresAuthStoreError> {
    let Some(encoded) = encoded else {
        return Ok(Vec::new());
    };
    if encoded.len() < 2 {
        return Err(PostgresAuthStoreError::InvalidStoredData(
            "pending identifier change authority list is truncated",
        ));
    }
    let count = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
    if count == 0 || count > OUT_OF_BAND_IDENTIFIER_CHANGE_CANDIDATE_AUTHORITY_MAX_COUNT {
        return Err(PostgresAuthStoreError::InvalidStoredData(
            "pending identifier change authority count is invalid",
        ));
    }
    let mut offset = 2;
    let mut authority_ids = Vec::with_capacity(count);
    for _ in 0..count {
        if encoded.len().saturating_sub(offset) < 2 {
            return Err(PostgresAuthStoreError::InvalidStoredData(
                "pending identifier change authority id length is truncated",
            ));
        }
        let len = u16::from_be_bytes([encoded[offset], encoded[offset + 1]]) as usize;
        offset += 2;
        if len == 0 || len > ID_MAX_BYTES || encoded.len().saturating_sub(offset) < len {
            return Err(PostgresAuthStoreError::InvalidStoredData(
                "pending identifier change authority id is malformed",
            ));
        }
        authority_ids.push(RecoveryAuthorityId::from_bytes(
            encoded[offset..offset + len].to_vec(),
        )?);
        offset += len;
    }
    if offset != encoded.len() {
        return Err(PostgresAuthStoreError::InvalidStoredData(
            "pending identifier change authority list has trailing bytes",
        ));
    }
    Ok(authority_ids)
}
pub(in crate::auth_core) async fn insert_admin_support_intervention(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    record: &AdminSupportInterventionRecord,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        INSERT INTO {} (
            intervention_id,
            subject_id,
            target_credential_instance_id,
            lifecycle_action,
            status,
            requested_at,
            expires_at,
            closed_at
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
        table_names
            .get(PostgresAuthCoreTable::AdminSupportIntervention)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::Execute,
        "auth_core.mutation.create_admin_support_intervention",
        Some(statement.as_str()),
    );
    pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(record.intervention_id.as_bytes())
        .bind(record.subject_id.as_bytes())
        .bind(record.target_credential_instance_id.as_bytes())
        .bind(i32_from_credential_lifecycle_action(record.action))
        .bind(i32_from_admin_support_intervention_status(record.status))
        .bind(i64_from_unix_seconds(record.requested_at)?)
        .bind(i64_from_unix_seconds(record.expires_at)?)
        .bind(optional_i64_from_unix_seconds(record.closed_at)?)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(())
}

pub(in crate::auth_core) fn lifecycle_authority_source_key(
    source: &LifecycleAuthoritySource,
) -> Result<(LifecycleAuthoritySourceKind, VerifiedProofSourceId), PostgresAuthStoreError> {
    match source {
        LifecycleAuthoritySource::VerifiedProofSource(source) => {
            let kind = match source.kind() {
                VerifiedProofSourceKind::CredentialInstance => {
                    LifecycleAuthoritySourceKind::CredentialInstance
                }
                VerifiedProofSourceKind::OutOfBandIdentifier => {
                    LifecycleAuthoritySourceKind::OutOfBandIdentifier
                }
                VerifiedProofSourceKind::ExternalAuthority => {
                    LifecycleAuthoritySourceKind::ExternalAuthority
                }
            };
            Ok((kind, source.source_id().clone()))
        }
        LifecycleAuthoritySource::AuthenticatedSession(session_id) => Ok((
            LifecycleAuthoritySourceKind::AuthenticatedSession,
            VerifiedProofSourceId::from_bytes(session_id.as_bytes().to_vec())?,
        )),
        LifecycleAuthoritySource::AdminSupportIntervention(intervention) => Ok((
            LifecycleAuthoritySourceKind::AdminSupportIntervention,
            VerifiedProofSourceId::from_bytes(intervention.intervention_id().as_bytes().to_vec())?,
        )),
    }
}
