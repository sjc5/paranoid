use super::*;

pub(in crate::auth_core) async fn load_subject_revocation(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    subject_id: &SubjectId,
) -> Result<(), PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT revoke_records_created_at_or_before
        FROM {}
        WHERE subject_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::SubjectAuthState)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.subject_revocation",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_scalar::<i64>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(subject_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    loaded.subject_revocations.push_loaded(
        subject_id.clone(),
        row.map(|value| {
            Ok::<_, PostgresAuthStoreError>(SubjectRevocationState {
                revoke_records_created_at_or_before: unix_seconds_from_i64(value)?,
            })
        })
        .transpose()?,
    )?;
    Ok(())
}

pub(in crate::auth_core) async fn load_subject_revocation_if_needed(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    subject_id: &SubjectId,
) -> Result<(), PostgresAuthStoreError> {
    if loaded
        .subject_revocations
        .loaded_subjects()
        .iter()
        .any(|loaded_subject| loaded_subject.subject_id() == subject_id)
    {
        return Ok(());
    }
    load_subject_revocation(tx, table_names, loaded, subject_id).await
}

pub(in crate::auth_core) async fn load_credential_instance_metadata(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    credential_instance_id: &VerifiedProofSourceId,
) -> Result<Option<CredentialInstanceMetadata>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, credential_kind, method_label, reset_policy_role, lifecycle_state
        FROM {}
        WHERE credential_instance_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.credential_instance_metadata",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>, i32, String, i32, i32)>(sqlx::AssertSqlSafe(
        statement.as_str(),
    ))
    .bind(credential_instance_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    row.map(
        |(subject_id, credential_kind, method_label, reset_policy_role, lifecycle_state)| {
            CredentialInstanceMetadata::new(
                credential_instance_id.clone(),
                SubjectId::from_bytes(subject_id)?,
                credential_instance_kind_from_i32(credential_kind)?,
                method_label,
                credential_reset_policy_role_from_i32(reset_policy_role)?,
                credential_lifecycle_state_from_i32(lifecycle_state)?,
            )
            .map_err(PostgresAuthStoreError::Core)
        },
    )
    .transpose()
}

pub(in crate::auth_core) async fn load_active_subject_credential_instances_for_update(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
) -> Result<Vec<CredentialInstanceMetadata>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT credential_instance_id, credential_kind, method_label, reset_policy_role, lifecycle_state
        FROM {}
        WHERE subject_id = $1
          AND lifecycle_state = $2
        ORDER BY credential_instance_id ASC
        FOR UPDATE
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.precondition.active_subject_credential_instances_for_update",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(Vec<u8>, i32, String, i32, i32)>(sqlx::AssertSqlSafe(
        statement.as_str(),
    ))
    .bind(subject_id.as_bytes())
    .bind(i32_from_credential_lifecycle_state(
        CredentialLifecycleState::Active,
    ))
    .fetch_all(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    rows.into_iter()
        .map(
            |(
                credential_instance_id,
                credential_kind,
                method_label,
                reset_policy_role,
                lifecycle_state,
            )| {
                CredentialInstanceMetadata::new(
                    VerifiedProofSourceId::from_bytes(credential_instance_id)?,
                    subject_id.clone(),
                    credential_instance_kind_from_i32(credential_kind)?,
                    method_label,
                    credential_reset_policy_role_from_i32(reset_policy_role)?,
                    credential_lifecycle_state_from_i32(lifecycle_state)?,
                )
                .map_err(PostgresAuthStoreError::Core)
            },
        )
        .collect()
}

pub(in crate::auth_core) async fn load_active_subject_credential_instances(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
) -> Result<Vec<CredentialInstanceMetadata>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT credential_instance_id, credential_kind, method_label, reset_policy_role, lifecycle_state
        FROM {}
        WHERE subject_id = $1
          AND lifecycle_state = $2
        ORDER BY credential_instance_id ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.active_subject_credential_inventory",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(Vec<u8>, i32, String, i32, i32)>(sqlx::AssertSqlSafe(
        statement.as_str(),
    ))
    .bind(subject_id.as_bytes())
    .bind(i32_from_credential_lifecycle_state(
        CredentialLifecycleState::Active,
    ))
    .fetch_all(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    rows.into_iter()
        .map(
            |(
                credential_instance_id,
                credential_kind,
                method_label,
                reset_policy_role,
                lifecycle_state,
            )| {
                CredentialInstanceMetadata::new(
                    VerifiedProofSourceId::from_bytes(credential_instance_id)?,
                    subject_id.clone(),
                    credential_instance_kind_from_i32(credential_kind)?,
                    method_label,
                    credential_reset_policy_role_from_i32(reset_policy_role)?,
                    credential_lifecycle_state_from_i32(lifecycle_state)?,
                )
                .map_err(PostgresAuthStoreError::Core)
            },
        )
        .collect()
}

pub(in crate::auth_core) async fn load_only_active_credential_instance_metadata_for_subject_and_method(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
    target_method: &ProofMethodDeclaration,
) -> Result<Option<CredentialInstanceMetadata>, PostgresAuthStoreError> {
    let target_kind = CredentialInstanceKind::try_from_proof_family(target_method.family())?;
    let statement = format!(
        r#"
        SELECT credential_instance_id, reset_policy_role, lifecycle_state
        FROM {}
        WHERE subject_id = $1
          AND credential_kind = $2
          AND method_label = $3
          AND lifecycle_state = $4
        ORDER BY credential_instance_id ASC
        LIMIT 2
        FOR UPDATE
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.active_credential_instance_for_subject_and_method",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(Vec<u8>, i32, i32)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(subject_id.as_bytes())
        .bind(i32_from_credential_instance_kind(target_kind))
        .bind(target_method.method_label())
        .bind(i32_from_credential_lifecycle_state(
            CredentialLifecycleState::Active,
        ))
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    if rows.len() > 1 {
        return Err(PostgresAuthStoreError::Core(
            Error::LoadedStateContradiction(
                "configured credential reset target matched more than one active credential",
            ),
        ));
    }
    rows.into_iter()
        .next()
        .map(
            |(credential_instance_id, reset_policy_role, lifecycle_state)| {
                CredentialInstanceMetadata::new(
                    VerifiedProofSourceId::from_bytes(credential_instance_id)?,
                    subject_id.clone(),
                    target_kind,
                    target_method.method_label(),
                    credential_reset_policy_role_from_i32(reset_policy_role)?,
                    credential_lifecycle_state_from_i32(lifecycle_state)?,
                )
                .map_err(PostgresAuthStoreError::Core)
            },
        )
        .transpose()
}

pub(in crate::auth_core) async fn load_credential_recovery_authorities(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    target_credential_instance_id: &VerifiedProofSourceId,
) -> Result<Vec<CredentialRecoveryAuthority>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT lifecycle_action, authority_id, authority_timing
        FROM {}
        WHERE target_credential_instance_id = $1
        ORDER BY lifecycle_action ASC, authority_id ASC, authority_timing ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialRecoveryAuthority)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.credential_recovery_authorities",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(i32, Vec<u8>, i32)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(target_credential_instance_id.as_bytes())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    rows.into_iter()
        .map(|(action, authority_id, timing)| {
            Ok(CredentialRecoveryAuthority::new(
                target_credential_instance_id.clone(),
                credential_lifecycle_action_from_i32(action)?,
                RecoveryAuthorityId::from_bytes(authority_id)?,
                recovery_authority_timing_from_i32(timing)?,
            ))
        })
        .collect()
}

pub(in crate::auth_core) async fn load_active_subject_credential_recovery_authorities_for_update(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
) -> Result<Vec<CredentialRecoveryAuthority>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT target_credential_instance_id, lifecycle_action, authority_id, authority_timing
        FROM {}
        WHERE target_credential_instance_id IN (
            SELECT credential_instance_id
            FROM {}
            WHERE subject_id = $1
              AND lifecycle_state = $2
        )
        ORDER BY target_credential_instance_id ASC, lifecycle_action ASC, authority_id ASC, authority_timing ASC
        FOR UPDATE
        "#,
        table_names
            .get(PostgresAuthCoreTable::CredentialRecoveryAuthority)
            .quoted(),
        table_names
            .get(PostgresAuthCoreTable::CredentialInstance)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.precondition.active_subject_credential_recovery_authorities_for_update",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(Vec<u8>, i32, Vec<u8>, i32)>(sqlx::AssertSqlSafe(
        statement.as_str(),
    ))
    .bind(subject_id.as_bytes())
    .bind(i32_from_credential_lifecycle_state(
        CredentialLifecycleState::Active,
    ))
    .fetch_all(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    rows.into_iter()
        .map(
            |(target_credential_instance_id, action, authority_id, timing)| {
                Ok(CredentialRecoveryAuthority::new(
                    VerifiedProofSourceId::from_bytes(target_credential_instance_id)?,
                    credential_lifecycle_action_from_i32(action)?,
                    RecoveryAuthorityId::from_bytes(authority_id)?,
                    recovery_authority_timing_from_i32(timing)?,
                ))
            },
        )
        .collect()
}

pub(in crate::auth_core) async fn load_subject_lifecycle_authorities(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    subject_id: &SubjectId,
) -> Result<Vec<SubjectLifecycleAuthority>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_lifecycle_action, authority_id, authority_timing
        FROM {}
        WHERE subject_id = $1
        ORDER BY subject_lifecycle_action ASC, authority_id ASC, authority_timing ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::SubjectLifecycleAuthority)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.subject_lifecycle_authorities",
        Some(statement.as_str()),
    );
    let rows = pooler_safe_query_as::<(i32, Vec<u8>, i32)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(subject_id.as_bytes())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    rows.into_iter()
        .map(|(action, authority_id, timing)| {
            Ok(SubjectLifecycleAuthority::new(
                subject_id.clone(),
                subject_lifecycle_action_from_i32(action)?,
                RecoveryAuthorityId::from_bytes(authority_id)?,
                recovery_authority_timing_from_i32(timing)?,
            ))
        })
        .collect()
}

pub(in crate::auth_core) async fn load_lifecycle_authority_evidence(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source: &LifecycleAuthoritySource,
) -> Result<Option<LifecycleAuthorityEvidence>, PostgresAuthStoreError> {
    let (source_kind, source_id) = lifecycle_authority_source_key(source)?;
    let statement = format!(
        r#"
        SELECT authority_id
        FROM {}
        WHERE source_kind = $1 AND source_id = $2
        ORDER BY authority_id ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::LifecycleAuthoritySource)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.lifecycle_authority_evidence",
        Some(statement.as_str()),
    );
    let authority_ids =
        pooler_safe_query_scalar::<Vec<u8>>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(i32_from_lifecycle_authority_source_kind(source_kind))
            .bind(source_id.as_bytes())
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?
            .into_iter()
            .map(RecoveryAuthorityId::from_bytes)
            .collect::<Result<Vec<_>, _>>()?;
    if authority_ids.is_empty() {
        return Ok(None);
    }
    LifecycleAuthorityEvidence::new(source.clone(), authority_ids)
        .map(Some)
        .map_err(PostgresAuthStoreError::Core)
}

pub(in crate::auth_core) async fn load_out_of_band_identifier_binding(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    source_id: &VerifiedProofSourceId,
) -> Result<Option<OutOfBandIdentifierBindingRecord>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, proof_method_label, lifecycle_state
        FROM {}
        WHERE source_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::OutOfBandIdentifierBinding)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.out_of_band_identifier_binding",
        Some(statement.as_str()),
    );
    let row =
        pooler_safe_query_as::<(Vec<u8>, String, i32)>(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(source_id.as_bytes())
            .fetch_optional(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
    row.map(|(subject_id, proof_method_label, lifecycle_state)| {
        OutOfBandIdentifierBindingRecord::new(
            VerifiedProofSource::new(
                VerifiedProofSourceKind::OutOfBandIdentifier,
                source_id.clone(),
            ),
            SubjectId::from_bytes(subject_id)?,
            proof_method_label,
            out_of_band_identifier_binding_lifecycle_state_from_i32(lifecycle_state)?,
        )
        .map_err(PostgresAuthStoreError::Core)
    })
    .transpose()
}
pub(in crate::auth_core) async fn load_pending_credential_lifecycle_action(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    pending_action_id: &PendingCredentialLifecycleActionId,
) -> Result<Option<PendingCredentialLifecycleActionRecord>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, target_credential_instance_id, lifecycle_action,
               requested_at, earliest_execute_at, expires_at, closed_at
        FROM {}
        WHERE pending_action_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.pending_credential_lifecycle_action",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>, Vec<u8>, i32, i64, i64, i64, Option<i64>)>(
        sqlx::AssertSqlSafe(statement.as_str()),
    )
    .bind(pending_action_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    row.map(
        |(
            subject_id,
            target_credential_instance_id,
            action,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at,
        )| {
            Ok(PendingCredentialLifecycleActionRecord {
                pending_action_id: pending_action_id.clone(),
                subject_id: SubjectId::from_bytes(subject_id)?,
                target_credential_instance_id: VerifiedProofSourceId::from_bytes(
                    target_credential_instance_id,
                )?,
                action: credential_lifecycle_action_from_i32(action)?,
                requested_at: unix_seconds_from_i64(requested_at)?,
                earliest_execute_at: unix_seconds_from_i64(earliest_execute_at)?,
                expires_at: unix_seconds_from_i64(expires_at)?,
                closed_at: closed_at.map(unix_seconds_from_i64).transpose()?,
            })
        },
    )
    .transpose()
}
pub(in crate::auth_core) async fn load_pending_subject_lifecycle_action(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    pending_action_id: &PendingSubjectLifecycleActionId,
) -> Result<Option<PendingSubjectLifecycleActionRecord>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, subject_lifecycle_action,
               current_identifier_source_id,
               candidate_identifier_source_id,
               candidate_identifier_authority_ids,
               requested_at, earliest_execute_at, expires_at, closed_at
        FROM {}
        WHERE pending_action_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.pending_subject_lifecycle_action",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(
        Vec<u8>,
        i32,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        i64,
        i64,
        i64,
        Option<i64>,
    )>(sqlx::AssertSqlSafe(statement.as_str()))
    .bind(pending_action_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    row.map(
        |(
            subject_id,
            action,
            current_identifier_source_id,
            candidate_identifier_source_id,
            candidate_authority_ids,
            requested_at,
            earliest_execute_at,
            expires_at,
            closed_at,
        )| {
            let record = PendingSubjectLifecycleActionRecord {
                pending_action_id: pending_action_id.clone(),
                subject_id: SubjectId::from_bytes(subject_id)?,
                action: subject_lifecycle_action_from_i32(action)?,
                current_identifier_source_id: current_identifier_source_id
                    .map(VerifiedProofSourceId::from_bytes)
                    .transpose()?,
                candidate_identifier_source_id: candidate_identifier_source_id
                    .map(VerifiedProofSourceId::from_bytes)
                    .transpose()?,
                candidate_identifier_authority_ids:
                    decode_pending_subject_identifier_change_authority_ids(
                        candidate_authority_ids.as_deref(),
                    )?,
                requested_at: unix_seconds_from_i64(requested_at)?,
                earliest_execute_at: unix_seconds_from_i64(earliest_execute_at)?,
                expires_at: unix_seconds_from_i64(expires_at)?,
                closed_at: closed_at.map(unix_seconds_from_i64).transpose()?,
            };
            record
                .validate_target_details()
                .map_err(PostgresAuthStoreError::Core)?;
            Ok(record)
        },
    )
    .transpose()
}

pub(in crate::auth_core) async fn load_admin_support_intervention(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    intervention_id: &AdminSupportInterventionId,
) -> Result<Option<AdminSupportInterventionRecord>, PostgresAuthStoreError> {
    let statement = format!(
        r#"
        SELECT subject_id, target_credential_instance_id, lifecycle_action,
               status, requested_at, expires_at, closed_at
        FROM {}
        WHERE intervention_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::AdminSupportIntervention)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.admin_support_intervention",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>, Vec<u8>, i32, i32, i64, i64, Option<i64>)>(
        sqlx::AssertSqlSafe(statement.as_str()),
    )
    .bind(intervention_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    row.map(
        |(
            subject_id,
            target_credential_instance_id,
            action,
            status,
            requested_at,
            expires_at,
            closed_at,
        )| {
            Ok(AdminSupportInterventionRecord {
                intervention_id: intervention_id.clone(),
                subject_id: SubjectId::from_bytes(subject_id)?,
                target_credential_instance_id: VerifiedProofSourceId::from_bytes(
                    target_credential_instance_id,
                )?,
                action: credential_lifecycle_action_from_i32(action)?,
                status: admin_support_intervention_status_from_i32(status)?,
                requested_at: unix_seconds_from_i64(requested_at)?,
                expires_at: unix_seconds_from_i64(expires_at)?,
                closed_at: closed_at.map(unix_seconds_from_i64).transpose()?,
            })
        },
    )
    .transpose()
}
pub(in crate::auth_core) async fn load_active_proof_attempt(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    attempt_id: &ActiveProofAttemptId,
    presented_cookie_secrets: &PresentedAuthCookieSecrets,
    credential_secret_keyset: &Keyset,
) -> Result<(), PostgresAuthStoreError> {
    let attempt_statement = format!(
        r#"
        SELECT proof_use, subject_id, weak_proof_failures, max_weak_proof_failures,
               created_at, expires_at, closed_at
        FROM {}
        WHERE attempt_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofAttempt)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.active_proof_attempt",
        Some(attempt_statement.as_str()),
    );
    let row = pooler_safe_query_as::<(i32, Option<Vec<u8>>, i32, i32, i64, i64, Option<i64>)>(
        sqlx::AssertSqlSafe(attempt_statement.as_str()),
    )
    .bind(attempt_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    let Some(row) = row else {
        return Ok(());
    };

    let satisfied_statement = format!(
        r#"
        SELECT proof_family, method_label, online_guessing_risk,
               proof_source_kind, proof_source_id, satisfied_at
        FROM {}
        WHERE attempt_id = $1
        ORDER BY satisfied_at ASC, proof_family ASC, method_label ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofSatisfiedProof)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.active_proof_satisfied_proofs",
        Some(satisfied_statement.as_str()),
    );
    let proof_rows =
        pooler_safe_query_as::<(i32, String, bool, Option<i32>, Option<Vec<u8>>, i64)>(
            sqlx::AssertSqlSafe(satisfied_statement.as_str()),
        )
        .bind(attempt_id.as_bytes())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    let mut satisfied_proofs = Vec::with_capacity(proof_rows.len());
    for (family_id, method_label, online_guessing_risk, source_kind, source_id, _) in proof_rows {
        let proof = ProofSummary::new_with_online_guessing_risk(
            proof_family_from_i32(family_id)?,
            method_label,
            online_guessing_risk_from_bool(online_guessing_risk),
        )?;
        let source = match (source_kind, source_id) {
            (Some(kind), Some(source_id)) => Some(VerifiedProofSource::new(
                verified_proof_source_kind_from_i32(kind)?,
                VerifiedProofSourceId::from_bytes(source_id)
                    .map_err(PostgresAuthStoreError::Core)?,
            )),
            (None, None) => None,
            _ => {
                return Err(PostgresAuthStoreError::InvalidStoredData(
                    "satisfied proof source kind/id must both be null or both be present",
                ));
            }
        };
        satisfied_proofs.push(SatisfiedProof::new(proof, source));
    }

    loaded.active_proof_attempt_record = Some(ActiveProofAttemptRecord {
        attempt_id: attempt_id.clone(),
        proof_use: proof_use_from_i32(row.0)?,
        subject_id: row.1.map(SubjectId::from_bytes).transpose()?,
        satisfied_proofs,
        weak_proof_failures: u32_from_i32(row.2)?,
        max_weak_proof_failures: u32_from_i32(row.3)?,
        created_at: unix_seconds_from_i64(row.4)?,
        expires_at: unix_seconds_from_i64(row.5)?,
        closed_at: row.6.map(unix_seconds_from_i64).transpose()?,
    });
    load_active_proof_continuation_secret_match(
        tx,
        table_names,
        loaded,
        attempt_id,
        presented_cookie_secrets,
        credential_secret_keyset,
    )
    .await?;
    Ok(())
}

pub(in crate::auth_core) async fn load_active_proof_continuation_secret_match(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    attempt_id: &ActiveProofAttemptId,
    presented_cookie_secrets: &PresentedAuthCookieSecrets,
    credential_secret_keyset: &Keyset,
) -> Result<(), PostgresAuthStoreError> {
    if loaded
        .active_proof_continuation_secret_match
        .as_ref()
        .is_some_and(|existing| existing.attempt_id() == attempt_id)
    {
        return Ok(());
    }
    let Some(presented_secret) = presented_cookie_secrets.active_proof_continuation() else {
        return Ok(());
    };
    if presented_secret.attempt_id() != attempt_id {
        loaded.active_proof_continuation_secret_match =
            Some(LoadedActiveProofContinuationSecretMatch::new(
                attempt_id.clone(),
                StoredSecretMatch::Unknown,
            ));
        return Ok(());
    }
    let statement = format!(
        r#"
        SELECT secret_mac
        FROM {}
        WHERE attempt_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofContinuationSecretMac)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.active_proof_continuation_secret_mac",
        Some(statement.as_str()),
    );
    let row = pooler_safe_query_as::<(Vec<u8>,)>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(attempt_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    let kind = match row {
        Some((current_mac,)) => {
            let current_target = CoreStorageTarget::ActiveProofContinuationSecret {
                attempt_id: attempt_id.clone(),
            };
            let current_mac = MacOverSecret::try_from(current_mac)
                .map_err(|_| PostgresAuthStoreError::InvalidStoredData("stored MAC malformed"))?;
            if current_mac.verify(
                credential_secret_keyset,
                presented_secret.secret().expose_secret(),
                &credential_secret_mac_context(&current_target),
            ) {
                StoredSecretMatch::Current
            } else {
                StoredSecretMatch::Unknown
            }
        }
        None => StoredSecretMatch::Unknown,
    };
    loaded.active_proof_continuation_secret_match = Some(
        LoadedActiveProofContinuationSecretMatch::new(attempt_id.clone(), kind),
    );
    Ok(())
}

pub(in crate::auth_core) async fn load_active_proof_challenge(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    loaded: &mut LoadedState,
    challenge_id: &ActiveProofChallengeId,
) -> Result<(), PostgresAuthStoreError> {
    let challenge_statement = format!(
        r#"
        SELECT attempt_id, proof_family, method_label, online_guessing_risk,
               challenge_dedupe_key, recipient_handle, resend_count, max_resends,
               requires_stateless_fast_fail, created_at, expires_at, closed_at
        FROM {}
        WHERE challenge_id = $1
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallenge)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchOptional,
        "auth_core.load.active_proof_challenge",
        Some(challenge_statement.as_str()),
    );
    let row = pooler_safe_query_as::<(
        Vec<u8>,
        i32,
        String,
        bool,
        Option<String>,
        Option<String>,
        i32,
        i32,
        bool,
        i64,
        i64,
        Option<i64>,
    )>(sqlx::AssertSqlSafe(challenge_statement.as_str()))
    .bind(challenge_id.as_bytes())
    .fetch_optional(tx.sqlx_transaction().as_mut())
    .await
    .map_err(DbError::query)?;
    let Some(row) = row else {
        return Ok(());
    };

    let delivery_statement = format!(
        r#"
        SELECT delivery_idempotency_key
        FROM {}
        WHERE challenge_id = $1
        ORDER BY created_at ASC, delivery_idempotency_key ASC
        "#,
        table_names
            .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
            .quoted()
    );
    tx.record_database_operation(
        DatabaseOperationKind::FetchAll,
        "auth_core.load.active_proof_challenge_delivery_keys",
        Some(delivery_statement.as_str()),
    );
    let used_delivery_idempotency_keys =
        pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(delivery_statement.as_str()))
            .bind(challenge_id.as_bytes())
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;

    loaded.active_proof_challenge_record = Some(ActiveProofChallengeRecord {
        challenge_id: challenge_id.clone(),
        attempt_id: ActiveProofAttemptId::from_bytes(row.0)?,
        proof: ProofSummary::new_with_online_guessing_risk(
            proof_family_from_i32(row.1)?,
            row.2,
            online_guessing_risk_from_bool(row.3),
        )?,
        challenge_dedupe_key: row.4.map(OutOfBandChallengeDedupeKey::new).transpose()?,
        recipient_handle: row.5,
        used_delivery_idempotency_keys,
        resend_count: u32_from_i32(row.6)?,
        max_resends: u32_from_i32(row.7)?,
        requires_stateless_fast_fail: row.8,
        created_at: unix_seconds_from_i64(row.9)?,
        expires_at: unix_seconds_from_i64(row.10)?,
        closed_at: row.11.map(unix_seconds_from_i64).transpose()?,
    });
    Ok(())
}
