use super::*;

#[derive(Default)]
pub(in crate::auth_core) struct CorePreconditionExecutionState {
    locked_subject_auth_state_subjects: Vec<SubjectId>,
    locked_subject_auth_state_cutoffs: Vec<(SubjectId, UnixSeconds)>,
    session_still_matches_preconditions: Vec<(SessionId, SubjectId)>,
    trusted_device_still_matches_preconditions: Vec<(TrustedDeviceCredentialId, SubjectId)>,
}

impl CorePreconditionExecutionState {
    pub(in crate::auth_core) fn for_preconditions(preconditions: &[Precondition]) -> Self {
        let mut state = Self::default();
        for precondition in preconditions {
            match precondition {
                Precondition::SessionStillMatches {
                    session_id,
                    subject_id,
                    ..
                } => state
                    .session_still_matches_preconditions
                    .push((session_id.clone(), subject_id.clone())),
                Precondition::TrustedDeviceStillMatches {
                    device_credential_id,
                    subject_id,
                    ..
                } => state
                    .trusted_device_still_matches_preconditions
                    .push((device_credential_id.clone(), subject_id.clone())),
                _ => {}
            }
        }
        state
    }

    pub(in crate::auth_core) fn has_session_still_matches_precondition(
        &self,
        session_id: &SessionId,
        subject_id: &SubjectId,
    ) -> bool {
        self.session_still_matches_preconditions.iter().any(
            |(covered_session_id, covered_subject_id)| {
                covered_session_id == session_id && covered_subject_id == subject_id
            },
        )
    }

    pub(in crate::auth_core) fn has_trusted_device_still_matches_precondition(
        &self,
        device_credential_id: &TrustedDeviceCredentialId,
        subject_id: &SubjectId,
    ) -> bool {
        self.trusted_device_still_matches_preconditions.iter().any(
            |(covered_device_id, covered_subject_id)| {
                covered_device_id == device_credential_id && covered_subject_id == subject_id
            },
        )
    }

    pub(in crate::auth_core) fn subject_auth_state_is_locked(
        &self,
        subject_id: &SubjectId,
    ) -> bool {
        self.locked_subject_auth_state_subjects
            .iter()
            .any(|locked| locked == subject_id)
    }

    pub(in crate::auth_core) fn remember_subject_auth_state_locked(
        &mut self,
        subject_id: SubjectId,
    ) {
        if !self.subject_auth_state_is_locked(&subject_id) {
            self.locked_subject_auth_state_subjects.push(subject_id);
        }
    }

    pub(in crate::auth_core) fn subject_auth_state_cutoff(
        &self,
        subject_id: &SubjectId,
    ) -> Option<UnixSeconds> {
        self.locked_subject_auth_state_cutoffs
            .iter()
            .find(|(loaded_subject_id, _)| loaded_subject_id == subject_id)
            .map(|(_, cutoff)| *cutoff)
    }

    pub(in crate::auth_core) fn remember_subject_auth_state_cutoff(
        &mut self,
        subject_id: SubjectId,
        cutoff: UnixSeconds,
    ) {
        if self.subject_auth_state_cutoff(&subject_id).is_none() {
            self.locked_subject_auth_state_cutoffs
                .push((subject_id, cutoff));
        }
    }
}

pub(in crate::auth_core) async fn enforce_precondition(
    tx: &mut Tx<'_>,
    table_names: &AuthCoreTableNames,
    precondition: &Precondition,
    state: &mut CorePreconditionExecutionState,
) -> Result<(), PostgresAuthStoreError> {
    match precondition {
        Precondition::SessionStillMatches {
            session_id,
            subject_id,
            now,
            current_secret_version,
        } => {
            materialize_and_lock_subject_auth_state_once(
                tx,
                table_names,
                subject_id,
                UnixSeconds::new(0),
                state,
            )
            .await?;
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE session_id = $1
                  AND subject_id = $2
                  AND current_secret_version = $3
                  AND revoked_at IS NULL
                  AND expires_at > $4
                FOR UPDATE
                "#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.session_still_matches",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i64_from_secret_version(*current_secret_version)?)
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "session no longer matches loaded state",
                ));
            }
            validate_subject_cutoff_does_not_invalidate(
                tx,
                table_names,
                subject_id,
                CoreStorageTarget::Session(session_id.clone()),
                state,
            )
            .await?;
        }
        Precondition::TrustedDeviceStillMatches {
            device_credential_id,
            subject_id,
            now,
            current_secret_version,
        } => {
            materialize_and_lock_subject_auth_state_once(
                tx,
                table_names,
                subject_id,
                UnixSeconds::new(0),
                state,
            )
            .await?;
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE device_credential_id = $1
                  AND subject_id = $2
                  AND current_secret_version = $3
                  AND revoked_at IS NULL
                  AND expires_at > $4
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.trusted_device_still_matches",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i64_from_secret_version(*current_secret_version)?)
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "trusted device no longer matches loaded state",
                ));
            }
            validate_subject_cutoff_does_not_invalidate(
                tx,
                table_names,
                subject_id,
                CoreStorageTarget::TrustedDeviceCredential(device_credential_id.clone()),
                state,
            )
            .await?;
        }
        Precondition::SessionBelongsToSubject {
            session_id,
            subject_id,
        } => {
            if state.has_session_still_matches_precondition(session_id, subject_id) {
                return Ok(());
            }
            let statement = format!(
                r#"SELECT 1 FROM {} WHERE session_id = $1 AND subject_id = $2 AND revoked_at IS NULL FOR UPDATE"#,
                table_names.get(PostgresAuthCoreTable::Session).quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.session_belongs_to_subject",
                &statement,
                |query| {
                    Ok(query
                        .bind(session_id.as_bytes())
                        .bind(subject_id.as_bytes()))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "session does not belong to subject",
                ));
            }
        }
        Precondition::TrustedDeviceBelongsToSubject {
            device_credential_id,
            subject_id,
        } => {
            if state.has_trusted_device_still_matches_precondition(device_credential_id, subject_id)
            {
                return Ok(());
            }
            let statement = format!(
                r#"SELECT 1 FROM {} WHERE device_credential_id = $1 AND subject_id = $2 AND revoked_at IS NULL FOR UPDATE"#,
                table_names
                    .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.trusted_device_belongs_to_subject",
                &statement,
                |query| {
                    Ok(query
                        .bind(device_credential_id.as_bytes())
                        .bind(subject_id.as_bytes()))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "trusted device does not belong to subject",
                ));
            }
        }
        Precondition::ActiveProofAttemptStillOpen {
            attempt_id,
            now,
            observed_subject_id,
            observed_weak_proof_failures,
            subject_id_for_revocation,
            created_at,
            ..
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE attempt_id = $1
                  AND weak_proof_failures = $2
                  AND created_at = $3
                  AND closed_at IS NULL
                  AND expires_at > $4
                  AND subject_id IS NOT DISTINCT FROM $5
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofAttempt)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.active_proof_attempt_still_open",
                &statement,
                |query| {
                    Ok(query
                        .bind(attempt_id.as_bytes())
                        .bind(i32_from_u32(*observed_weak_proof_failures)?)
                        .bind(i64_from_unix_seconds(*created_at)?)
                        .bind(i64_from_unix_seconds(*now)?)
                        .bind(observed_subject_id.as_ref().map(Id::as_bytes)))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "active proof attempt no longer matches loaded state",
                ));
            }
            if let Some(subject_id) = subject_id_for_revocation {
                materialize_and_lock_subject_auth_state_once(
                    tx,
                    table_names,
                    subject_id,
                    UnixSeconds::new(0),
                    state,
                )
                .await?;
                validate_subject_cutoff_does_not_invalidate(
                    tx,
                    table_names,
                    subject_id,
                    CoreStorageTarget::ActiveProofAttempt(attempt_id.clone()),
                    state,
                )
                .await?;
            }
        }
        Precondition::ActiveProofChallengeStillOpen { challenge_id, now } => {
            let statement = format!(
                r#"SELECT 1 FROM {} WHERE challenge_id = $1 AND closed_at IS NULL AND expires_at > $2 FOR UPDATE"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.active_proof_challenge_still_open",
                &statement,
                |query| {
                    Ok(query
                        .bind(challenge_id.as_bytes())
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "active proof challenge is no longer open",
                ));
            }
        }
        Precondition::OutOfBandChallengeResendStillAllowed {
            challenge_id,
            now,
            observed_resend_count,
            observed_used_delivery_idempotency_keys,
        } => {
            let open_statement = format!(
                r#"SELECT 1 FROM {} WHERE challenge_id = $1 AND closed_at IS NULL AND expires_at > $2 FOR UPDATE"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            let is_open = fetch_exists_for_update(
                tx,
                "auth_core.precondition.out_of_band_resend_challenge_still_open",
                &open_statement,
                |query| {
                    Ok(query
                        .bind(challenge_id.as_bytes())
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !is_open {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "active proof challenge is no longer open",
                ));
            }
            let count_statement = format!(
                r#"SELECT resend_count FROM {} WHERE challenge_id = $1"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::FetchOne,
                "auth_core.precondition.out_of_band_resend_count",
                Some(count_statement.as_str()),
            );
            let resend_count =
                pooler_safe_query_scalar::<i32>(sqlx::AssertSqlSafe(count_statement.as_str()))
                    .bind(challenge_id.as_bytes())
                    .fetch_one(tx.sqlx_transaction().as_mut())
                    .await
                    .map_err(DbError::query)?;
            if u32_from_i32(resend_count)? != *observed_resend_count {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "out-of-band resend count changed",
                ));
            }
            let delivery_statement = format!(
                r#"SELECT delivery_idempotency_key FROM {} WHERE challenge_id = $1 ORDER BY delivery_idempotency_key ASC"#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallengeDeliveryKey)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::FetchAll,
                "auth_core.precondition.out_of_band_delivery_keys",
                Some(delivery_statement.as_str()),
            );
            let mut stored_keys = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(
                delivery_statement.as_str(),
            ))
            .bind(challenge_id.as_bytes())
            .fetch_all(tx.sqlx_transaction().as_mut())
            .await
            .map_err(DbError::query)?;
            let mut observed = observed_used_delivery_idempotency_keys.clone();
            stored_keys.sort();
            observed.sort();
            if stored_keys != observed {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "out-of-band delivery idempotency keys changed",
                ));
            }
        }
        Precondition::NoOpenOutOfBandChallengeForDedupeKey {
            challenge_dedupe_key,
            now,
            replaceable_created_at_or_before,
        } => {
            let close_statement = format!(
                r#"
                UPDATE {}
                SET closed_at = $2
                WHERE challenge_dedupe_key = $1
                  AND closed_at IS NULL
                  AND (
                    expires_at <= $2
                    OR ($3::BIGINT IS NOT NULL AND created_at <= $3)
                  )
                "#,
                table_names
                    .get(PostgresAuthCoreTable::ActiveProofChallenge)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.precondition.close_replaceable_open_challenges_for_dedupe_key",
                Some(close_statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(close_statement.as_str()))
                .bind(challenge_dedupe_key.as_str())
                .bind(i64_from_unix_seconds(*now)?)
                .bind(optional_i64_from_unix_seconds(
                    *replaceable_created_at_or_before,
                )?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;
        }
        Precondition::CredentialInstanceStillActive {
            credential_instance_id,
            subject_id,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE credential_instance_id = $1
                  AND subject_id = $2
                  AND lifecycle_state = $3
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::CredentialInstance)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.credential_instance_still_active",
                &statement,
                |query| {
                    Ok(query
                        .bind(credential_instance_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_state(
                            CredentialLifecycleState::Active,
                        )))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "credential instance is not active for subject",
                ));
            }
        }
        Precondition::SubjectRetainsRequiredCredentialPostureAfterRemoval {
            subject_id,
            removed_credential_instance_id,
            removed_credential_reset_policy_role,
        } => {
            let credentials =
                load_active_subject_credential_instances_for_update(tx, &table_names, subject_id)
                    .await?;
            let recovery_authorities =
                load_active_subject_credential_recovery_authorities_for_update(
                    tx,
                    &table_names,
                    subject_id,
                )
                .await?;
            if !subject_retains_required_credential_posture_after_removal(
                &credentials,
                &recovery_authorities,
                subject_id,
                removed_credential_instance_id,
                *removed_credential_reset_policy_role,
            ) {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "subject does not retain required credential posture after removal",
                ));
            }
        }
        Precondition::SubjectRetainsRequiredCredentialPostureAfterReplacement {
            subject_id,
            replaced_credential_instance_id,
            replaced_credential_reset_policy_role,
            successor,
        } => {
            let credentials =
                load_active_subject_credential_instances_for_update(tx, &table_names, subject_id)
                    .await?;
            let recovery_authorities =
                load_active_subject_credential_recovery_authorities_for_update(
                    tx,
                    &table_names,
                    subject_id,
                )
                .await?;
            if !subject_retains_required_credential_posture_after_replacement(
                &credentials,
                &recovery_authorities,
                subject_id,
                replaced_credential_instance_id,
                *replaced_credential_reset_policy_role,
                successor,
            ) {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "subject does not retain required credential posture after replacement",
                ));
            }
        }
        Precondition::SubjectRetainsRequiredCredentialPostureAfterAddition {
            subject_id,
            added_credential,
            added_recovery_authorities,
        } => {
            let credentials =
                load_active_subject_credential_instances_for_update(tx, &table_names, subject_id)
                    .await?;
            let recovery_authorities =
                load_active_subject_credential_recovery_authorities_for_update(
                    tx,
                    &table_names,
                    subject_id,
                )
                .await?;
            if !subject_retains_required_credential_posture_after_addition(
                &credentials,
                &recovery_authorities,
                subject_id,
                added_credential,
                added_recovery_authorities,
            ) {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "subject does not retain required credential posture after addition",
                ));
            }
        }
        Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
            target_credential_instance_id,
            action,
            now,
        } => {
            let close_statement = format!(
                r#"
                UPDATE {}
                SET closed_at = $3
                WHERE target_credential_instance_id = $1
                  AND lifecycle_action = $2
                  AND closed_at IS NULL
                  AND expires_at <= $3
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.precondition.close_expired_pending_credential_lifecycle_actions",
                Some(close_statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(close_statement.as_str()))
                .bind(target_credential_instance_id.as_bytes())
                .bind(i32_from_credential_lifecycle_action(*action))
                .bind(i64_from_unix_seconds(*now)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;

            let open_statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE target_credential_instance_id = $1
                  AND lifecycle_action = $2
                  AND closed_at IS NULL
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.no_open_pending_credential_lifecycle_action",
                &open_statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action)))
                },
            )
            .await?;
            if found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending credential lifecycle action already exists",
                ));
            }
        }
        Precondition::PendingCredentialLifecycleActionStillExecutable {
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE pending_action_id = $1
                  AND subject_id = $2
                  AND target_credential_instance_id = $3
                  AND lifecycle_action = $4
                  AND closed_at IS NULL
                  AND earliest_execute_at <= $5
                  AND $5 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.pending_credential_lifecycle_action_still_executable",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending credential lifecycle action is not executable",
                ));
            }
        }
        Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
            pending_action_id,
            subject_id,
            target_credential_instance_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE pending_action_id = $1
                  AND subject_id = $2
                  AND target_credential_instance_id = $3
                  AND lifecycle_action = $4
                  AND closed_at IS NULL
                  AND $5 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingCredentialLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.pending_credential_lifecycle_action_still_cancellable_for_target",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending credential lifecycle action is not cancellable for target",
                ));
            }
        }
        Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
            subject_id,
            action,
            now,
        } => {
            let close_statement = format!(
                r#"
                UPDATE {}
                SET closed_at = $3
                WHERE subject_id = $1
                  AND subject_lifecycle_action = $2
                  AND closed_at IS NULL
                  AND expires_at <= $3
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.precondition.close_expired_pending_subject_lifecycle_actions",
                Some(close_statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(close_statement.as_str()))
                .bind(subject_id.as_bytes())
                .bind(i32_from_subject_lifecycle_action(*action))
                .bind(i64_from_unix_seconds(*now)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;

            let open_statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE subject_id = $1
                  AND subject_lifecycle_action = $2
                  AND closed_at IS NULL
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.no_open_pending_subject_lifecycle_action",
                &open_statement,
                |query| {
                    Ok(query
                        .bind(subject_id.as_bytes())
                        .bind(i32_from_subject_lifecycle_action(*action)))
                },
            )
            .await?;
            if found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending subject lifecycle action already exists",
                ));
            }
        }
        Precondition::PendingSubjectLifecycleActionStillExecutable {
            pending_action_id,
            subject_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE pending_action_id = $1
                  AND subject_id = $2
                  AND subject_lifecycle_action = $3
                  AND closed_at IS NULL
                  AND earliest_execute_at <= $4
                  AND $4 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.pending_subject_lifecycle_action_still_executable",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i32_from_subject_lifecycle_action(*action))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending subject lifecycle action is not executable",
                ));
            }
        }
        Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
            pending_action_id,
            subject_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE pending_action_id = $1
                  AND subject_id = $2
                  AND subject_lifecycle_action = $3
                  AND closed_at IS NULL
                  AND $4 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::PendingSubjectLifecycleAction)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.pending_subject_lifecycle_action_still_cancellable_for_subject",
                &statement,
                |query| {
                    Ok(query
                        .bind(pending_action_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(i32_from_subject_lifecycle_action(*action))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "pending subject lifecycle action is not cancellable for subject",
                ));
            }
        }
        Precondition::OutOfBandIdentifierBindingStillActive {
            source_id,
            subject_id,
        } => {
            enforce_out_of_band_identifier_binding_lifecycle_state(
                tx,
                table_names,
                source_id,
                subject_id,
                OutOfBandIdentifierBindingLifecycleState::Active,
                "auth_core.precondition.out_of_band_identifier_binding_still_active",
                "out-of-band identifier binding is not active for subject",
            )
            .await?;
        }
        Precondition::OutOfBandIdentifierBindingStillPendingActivation {
            source_id,
            subject_id,
        } => {
            enforce_out_of_band_identifier_binding_lifecycle_state(
                tx,
                table_names,
                source_id,
                subject_id,
                OutOfBandIdentifierBindingLifecycleState::PendingActivation,
                "auth_core.precondition.out_of_band_identifier_binding_still_pending_activation",
                "out-of-band identifier binding is not pending activation for subject",
            )
            .await?;
        }
        Precondition::NoOpenAdminSupportInterventionForTarget {
            target_credential_instance_id,
            action,
            now,
            ..
        } => {
            let close_statement = format!(
                r#"
                UPDATE {}
                SET status = $3, closed_at = $4
                WHERE target_credential_instance_id = $1
                  AND lifecycle_action = $2
                  AND closed_at IS NULL
                  AND expires_at <= $4
                "#,
                table_names
                    .get(PostgresAuthCoreTable::AdminSupportIntervention)
                    .quoted()
            );
            tx.record_database_operation(
                DatabaseOperationKind::Execute,
                "auth_core.precondition.close_expired_admin_support_interventions",
                Some(close_statement.as_str()),
            );
            pooler_safe_query(sqlx::AssertSqlSafe(close_statement.as_str()))
                .bind(target_credential_instance_id.as_bytes())
                .bind(i32_from_credential_lifecycle_action(*action))
                .bind(i32_from_admin_support_intervention_status(
                    AdminSupportInterventionStatus::Expired,
                ))
                .bind(i64_from_unix_seconds(*now)?)
                .execute(tx.sqlx_transaction().as_mut())
                .await
                .map_err(DbError::query)?;

            let open_statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE target_credential_instance_id = $1
                  AND lifecycle_action = $2
                  AND closed_at IS NULL
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::AdminSupportIntervention)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.no_open_admin_support_intervention",
                &open_statement,
                |query| {
                    Ok(query
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action)))
                },
            )
            .await?;
            if found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "admin support intervention already exists",
                ));
            }
        }
        Precondition::AdminSupportInterventionStillOpen {
            intervention_id,
            subject_id,
            target_credential_instance_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE intervention_id = $1
                  AND subject_id = $2
                  AND target_credential_instance_id = $3
                  AND lifecycle_action = $4
                  AND status = $5
                  AND closed_at IS NULL
                  AND $6 < expires_at
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::AdminSupportIntervention)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.admin_support_intervention_still_open",
                &statement,
                |query| {
                    Ok(query
                        .bind(intervention_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action))
                        .bind(i32_from_admin_support_intervention_status(
                            AdminSupportInterventionStatus::Requested,
                        ))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "admin support intervention is not open",
                ));
            }
        }
        Precondition::AdminSupportInterventionStillExpiredOpen {
            intervention_id,
            subject_id,
            target_credential_instance_id,
            action,
            now,
        } => {
            let statement = format!(
                r#"
                SELECT 1
                FROM {}
                WHERE intervention_id = $1
                  AND subject_id = $2
                  AND target_credential_instance_id = $3
                  AND lifecycle_action = $4
                  AND status = $5
                  AND closed_at IS NULL
                  AND expires_at <= $6
                FOR UPDATE
                "#,
                table_names
                    .get(PostgresAuthCoreTable::AdminSupportIntervention)
                    .quoted()
            );
            let found = fetch_exists_for_update(
                tx,
                "auth_core.precondition.admin_support_intervention_still_expired_open",
                &statement,
                |query| {
                    Ok(query
                        .bind(intervention_id.as_bytes())
                        .bind(subject_id.as_bytes())
                        .bind(target_credential_instance_id.as_bytes())
                        .bind(i32_from_credential_lifecycle_action(*action))
                        .bind(i32_from_admin_support_intervention_status(
                            AdminSupportInterventionStatus::Requested,
                        ))
                        .bind(i64_from_unix_seconds(*now)?))
                },
            )
            .await?;
            if !found {
                return Err(PostgresAuthStoreError::PreconditionFailed(
                    "admin support intervention is not expired and open",
                ));
            }
        }
    }
    Ok(())
}
