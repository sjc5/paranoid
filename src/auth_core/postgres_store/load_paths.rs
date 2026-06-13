use super::*;

impl PostgresAuthStore {
    pub(crate) async fn load_state_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        request: AuthLoadStateRequest<'_>,
    ) -> Result<LoadedState, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let mut loaded = LoadedState {
            session_cookie: request.presented_cookies().session_cookie.clone(),
            trusted_device_cookie: request.presented_cookies().trusted_device_cookie.clone(),
            ..LoadedState::default()
        };

        for requirement in request.loaded_state_contract().required() {
            match requirement {
                LoadedStateRequirement::PresentedSessionCookie { .. }
                | LoadedStateRequirement::PresentedTrustedDeviceCookie { .. } => {}
                LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
                    session_id,
                } => {
                    self.load_session_record_and_secret_match(
                        tx,
                        &table_names,
                        &mut loaded,
                        session_id,
                        request.presented_cookie_secrets(),
                        request.now(),
                    )
                    .await?;
                }
                LoadedStateRequirement::TrustedDeviceRecordAndSecretMatchForPresentedCookie {
                    device_credential_id,
                } => {
                    self.load_trusted_device_record_and_secret_match(
                        tx,
                        &table_names,
                        &mut loaded,
                        device_credential_id,
                        request.presented_cookie_secrets(),
                        request.now(),
                    )
                    .await?;
                }
                LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject { .. } => {
                    if let Some(subject_id) = loaded
                        .session_record
                        .as_ref()
                        .map(|record| record.subject_id.clone())
                    {
                        load_subject_revocation_if_needed(
                            tx,
                            &table_names,
                            &mut loaded,
                            &subject_id,
                        )
                        .await?;
                    }
                }
                LoadedStateRequirement::SubjectRevocationForLoadedTrustedDeviceSubject {
                    ..
                } => {
                    if let Some(subject_id) = loaded
                        .trusted_device_record
                        .as_ref()
                        .map(|record| record.subject_id.clone())
                    {
                        load_subject_revocation_if_needed(
                            tx,
                            &table_names,
                            &mut loaded,
                            &subject_id,
                        )
                        .await?;
                    }
                }
                LoadedStateRequirement::ActiveProofAttempt { attempt_id } => {
                    load_active_proof_attempt(
                        tx,
                        &table_names,
                        &mut loaded,
                        attempt_id,
                        request.presented_cookie_secrets(),
                        &self.credential_secret_keyset,
                    )
                    .await?;
                }
                LoadedStateRequirement::ActiveProofContinuationSecretMatchForPresentedCookie {
                    attempt_id,
                } => {
                    load_active_proof_continuation_secret_match(
                        tx,
                        &table_names,
                        &mut loaded,
                        attempt_id,
                        request.presented_cookie_secrets(),
                        &self.credential_secret_keyset,
                    )
                    .await?;
                }
                LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
                    ..
                } => {
                    if let Some(subject_id) = loaded
                        .active_proof_attempt_record
                        .as_ref()
                        .and_then(|record| record.subject_id.clone())
                    {
                        load_subject_revocation_if_needed(
                            tx,
                            &table_names,
                            &mut loaded,
                            &subject_id,
                        )
                        .await?;
                    }
                }
                LoadedStateRequirement::SubjectRevocationForVerifiedActiveProofSubject {
                    subject_id,
                } => {
                    load_subject_revocation_if_needed(tx, &table_names, &mut loaded, subject_id)
                        .await?;
                }
                LoadedStateRequirement::ActiveProofChallenge { challenge_id } => {
                    load_active_proof_challenge(tx, &table_names, &mut loaded, challenge_id)
                        .await?;
                }
            }
        }
        Ok(loaded)
    }
    pub(crate) async fn load_credential_lifecycle_action_context_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        target_credential_instance_id: &VerifiedProofSourceId,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Option<CredentialLifecycleActionContext>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let Some(target_credential) =
            load_credential_instance_metadata(tx, &table_names, target_credential_instance_id)
                .await?
        else {
            return Ok(None);
        };
        let authorities =
            load_credential_recovery_authorities(tx, &table_names, target_credential_instance_id)
                .await?;
        let recovery_authority_graph = CredentialRecoveryAuthorityGraph::new(authorities)?;
        let mut evidence = Vec::new();
        for source in evidence_sources {
            if let Some(loaded_evidence) =
                load_lifecycle_authority_evidence(tx, &table_names, source).await?
            {
                evidence.push(loaded_evidence);
            }
        }
        Ok(Some(CredentialLifecycleActionContext::new(
            target_credential,
            recovery_authority_graph,
            evidence,
        )))
    }

    pub(crate) async fn load_credential_lifecycle_action_context_for_subject_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        target_credential_instance_id: &VerifiedProofSourceId,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Option<CredentialLifecycleActionContext>, PostgresAuthStoreError> {
        let Some(context) = self
            .load_credential_lifecycle_action_context_in_current_transaction(
                tx,
                target_credential_instance_id,
                evidence_sources,
            )
            .await?
        else {
            return Ok(None);
        };
        if context.target_credential().subject_id() != subject_id {
            return Ok(None);
        }
        Ok(Some(context))
    }

    pub(crate) async fn load_credential_lifecycle_action_context_with_evidence_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        target_credential_instance_id: &VerifiedProofSourceId,
        evidence: Vec<LifecycleAuthorityEvidence>,
    ) -> Result<Option<CredentialLifecycleActionContext>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let Some(target_credential) =
            load_credential_instance_metadata(tx, &table_names, target_credential_instance_id)
                .await?
        else {
            return Ok(None);
        };
        let authorities =
            load_credential_recovery_authorities(tx, &table_names, target_credential_instance_id)
                .await?;
        let recovery_authority_graph = CredentialRecoveryAuthorityGraph::new(authorities)?;
        Ok(Some(CredentialLifecycleActionContext::new(
            target_credential,
            recovery_authority_graph,
            evidence,
        )))
    }

    pub(crate) async fn load_credential_lifecycle_action_context_for_subject_and_method_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        target_method: &ProofMethodDeclaration,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Option<CredentialLifecycleActionContext>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let Some(target_credential) =
            load_only_active_credential_instance_metadata_for_subject_and_method(
                tx,
                &table_names,
                subject_id,
                target_method,
            )
            .await?
        else {
            return Ok(None);
        };
        let authorities = load_credential_recovery_authorities(
            tx,
            &table_names,
            target_credential.credential_instance_id(),
        )
        .await?;
        let recovery_authority_graph = CredentialRecoveryAuthorityGraph::new(authorities)?;
        let mut evidence = Vec::new();
        for source in evidence_sources {
            if let Some(loaded_evidence) =
                load_lifecycle_authority_evidence(tx, &table_names, source).await?
            {
                evidence.push(loaded_evidence);
            }
        }
        Ok(Some(CredentialLifecycleActionContext::new(
            target_credential,
            recovery_authority_graph,
            evidence,
        )))
    }

    pub(crate) async fn load_lifecycle_authority_evidence_for_sources_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Vec<LifecycleAuthorityEvidence>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let mut evidence = Vec::new();
        for source in evidence_sources {
            if let Some(loaded_evidence) =
                load_lifecycle_authority_evidence(tx, &table_names, source).await?
            {
                evidence.push(loaded_evidence);
            }
        }
        Ok(evidence)
    }

    pub(crate) async fn load_credential_recovery_authorities_for_credential_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        target_credential_instance_id: &VerifiedProofSourceId,
    ) -> Result<Vec<CredentialRecoveryAuthority>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        load_credential_recovery_authorities(tx, &table_names, target_credential_instance_id).await
    }

    pub(crate) async fn load_active_subject_credential_inventory_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
    ) -> Result<Vec<CredentialInstanceMetadata>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        load_active_subject_credential_instances(tx, &table_names, subject_id).await
    }

    pub(crate) async fn load_subject_lifecycle_action_context_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<SubjectLifecycleActionContext, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let authorities = load_subject_lifecycle_authorities(tx, &table_names, subject_id).await?;
        let authority_graph = SubjectLifecycleAuthorityGraph::new(authorities)?;
        let mut evidence = Vec::new();
        for source in evidence_sources {
            if let Some(loaded_evidence) =
                load_lifecycle_authority_evidence(tx, &table_names, source).await?
            {
                evidence.push(loaded_evidence);
            }
        }
        Ok(SubjectLifecycleActionContext::new(
            subject_id.clone(),
            authority_graph,
            evidence,
        ))
    }

    pub(crate) async fn load_out_of_band_identifier_change_context_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        subject_id: &SubjectId,
        current_identifier_source: VerifiedProofSource,
        candidate_identifier_source: VerifiedProofSource,
        evidence_sources: &[LifecycleAuthoritySource],
    ) -> Result<Option<OutOfBandIdentifierChangeContext>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        let Some(current_binding) = load_out_of_band_identifier_binding(
            tx,
            &table_names,
            current_identifier_source.source_id(),
        )
        .await?
        else {
            return Ok(None);
        };
        let Some(candidate_binding) = load_out_of_band_identifier_binding(
            tx,
            &table_names,
            candidate_identifier_source.source_id(),
        )
        .await?
        else {
            return Ok(None);
        };
        if current_binding.subject_id() != subject_id
            || !current_binding.can_resolve_new_proofs()
            || candidate_binding.subject_id() != subject_id
            || !candidate_binding.can_be_activated_by_identifier_change()
        {
            return Ok(None);
        }
        let context = self
            .load_subject_lifecycle_action_context_in_current_transaction(
                tx,
                subject_id,
                evidence_sources,
            )
            .await?;
        OutOfBandIdentifierChangeContext::new(
            context,
            current_identifier_source,
            candidate_identifier_source,
        )
        .map(Some)
        .map_err(PostgresAuthStoreError::Core)
    }

    pub(crate) async fn load_and_evaluate_credential_lifecycle_action_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        now: UnixSeconds,
        target_credential_instance_id: &VerifiedProofSourceId,
        evidence_sources: &[LifecycleAuthoritySource],
        action: CredentialLifecycleAction,
        independent_evidence_required: CredentialLifecycleIndependentEvidenceRequirement,
    ) -> Result<Option<CredentialLifecycleActionDecision>, PostgresAuthStoreError> {
        Ok(self
            .load_credential_lifecycle_action_context_in_current_transaction(
                tx,
                target_credential_instance_id,
                evidence_sources,
            )
            .await?
            .map(|context| context.evaluate_action_at(now, action, independent_evidence_required)))
    }

    pub(crate) async fn load_pending_credential_lifecycle_action_with_target_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingCredentialLifecycleActionId,
    ) -> Result<
        Option<(
            CredentialInstanceMetadata,
            PendingCredentialLifecycleActionRecord,
        )>,
        PostgresAuthStoreError,
    > {
        let table_names = self.config.table_names()?;
        let Some(pending_action) =
            load_pending_credential_lifecycle_action(tx, &table_names, pending_action_id).await?
        else {
            return Ok(None);
        };
        let Some(target_credential) = load_credential_instance_metadata(
            tx,
            &table_names,
            &pending_action.target_credential_instance_id,
        )
        .await?
        else {
            return Ok(None);
        };
        Ok(Some((target_credential, pending_action)))
    }

    pub(crate) async fn load_pending_credential_reset_execution_authority_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingCredentialLifecycleActionId,
    ) -> Result<
        Option<(
            CredentialInstanceMetadata,
            PendingCredentialLifecycleActionRecord,
        )>,
        PostgresAuthStoreError,
    > {
        self.load_pending_credential_lifecycle_action_with_target_in_current_transaction(
            tx,
            pending_action_id,
        )
        .await
    }

    pub(crate) async fn load_pending_credential_reset_for_cancellation_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingCredentialLifecycleActionId,
    ) -> Result<
        Option<(
            CredentialInstanceMetadata,
            PendingCredentialLifecycleActionRecord,
        )>,
        PostgresAuthStoreError,
    > {
        self.load_pending_credential_reset_execution_authority_in_current_transaction(
            tx,
            pending_action_id,
        )
        .await
    }

    pub(crate) async fn load_pending_subject_lifecycle_action_for_execution_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingSubjectLifecycleActionId,
    ) -> Result<Option<PendingSubjectLifecycleActionRecord>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        load_pending_subject_lifecycle_action(tx, &table_names, pending_action_id).await
    }

    pub(crate) async fn load_pending_subject_lifecycle_action_for_cancellation_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        pending_action_id: &PendingSubjectLifecycleActionId,
    ) -> Result<Option<PendingSubjectLifecycleActionRecord>, PostgresAuthStoreError> {
        self.load_pending_subject_lifecycle_action_for_execution_in_current_transaction(
            tx,
            pending_action_id,
        )
        .await
    }

    pub(crate) async fn load_admin_support_intervention_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        intervention_id: &AdminSupportInterventionId,
    ) -> Result<Option<AdminSupportInterventionRecord>, PostgresAuthStoreError> {
        let table_names = self.config.table_names()?;
        load_admin_support_intervention(tx, &table_names, intervention_id).await
    }
}

impl PostgresAuthStore {
    async fn load_session_record_and_secret_match(
        &self,
        tx: &mut Tx<'_>,
        table_names: &AuthCoreTableNames,
        loaded: &mut LoadedState,
        session_id: &SessionId,
        presented_secrets: &PresentedAuthCookieSecrets,
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let statement = format!(
            r#"
        SELECT
            s.subject_id,
            s.device_credential_id,
            s.current_secret_version,
            s.previous_secret_version,
            s.previous_secret_accept_until,
            s.created_at,
            s.refreshed_at,
            s.expires_at,
            s.step_up_expires_at,
            s.revoked_at,
            current_mac.secret_mac,
            previous_mac.secret_mac
        FROM {} s
        LEFT JOIN {} current_mac
          ON current_mac.session_id = s.session_id
         AND current_mac.secret_version = s.current_secret_version
        LEFT JOIN {} previous_mac
          ON previous_mac.session_id = s.session_id
         AND previous_mac.secret_version = s.previous_secret_version
        WHERE s.session_id = $1
        "#,
            table_names.get(PostgresAuthCoreTable::Session).quoted(),
            table_names
                .get(PostgresAuthCoreTable::SessionCredentialSecretMac)
                .quoted(),
            table_names
                .get(PostgresAuthCoreTable::SessionCredentialSecretMac)
                .quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.load.session_with_secret_macs",
            Some(statement.as_str()),
        );
        let row = pooler_safe_query_as::<(
            Vec<u8>,
            Option<Vec<u8>>,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(session_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
        let Some(row) = row else {
            return Ok(());
        };
        let record = SessionRecord {
            session_id: session_id.clone(),
            subject_id: SubjectId::from_bytes(row.0)?,
            device_credential_id: row
                .1
                .map(TrustedDeviceCredentialId::from_bytes)
                .transpose()?,
            current_secret_version: secret_version_from_i64(row.2)?,
            previous_secret_version: row.3.map(secret_version_from_i64).transpose()?,
            previous_secret_accept_until: row.4.map(unix_seconds_from_i64).transpose()?,
            created_at: unix_seconds_from_i64(row.5)?,
            refreshed_at: unix_seconds_from_i64(row.6)?,
            expires_at: unix_seconds_from_i64(row.7)?,
            step_up_expires_at: row.8.map(unix_seconds_from_i64).transpose()?,
            revoked_at: row.9.map(unix_seconds_from_i64).transpose()?,
        };
        let match_kind = match presented_secrets.session() {
            Some(secret) => classify_presented_secret(PresentedSecretClassificationInput {
                keyset: &self.credential_secret_keyset,
                current_target: CoreStorageTarget::SessionCredentialSecret {
                    session_id: record.session_id.clone(),
                    secret_version: record.current_secret_version,
                },
                current_mac_bytes: row.10.as_deref(),
                secret: secret.secret(),
                current_version: record.current_secret_version,
                previous_target: CoreStorageTarget::SessionCredentialSecret {
                    session_id: record.session_id.clone(),
                    secret_version: record
                        .previous_secret_version
                        .unwrap_or(record.current_secret_version),
                },
                previous_mac_bytes: row.11.as_deref(),
                previous_version: record.previous_secret_version,
                previous_secret_accept_until: record.previous_secret_accept_until,
                now,
            })?,
            None => StoredSecretMatch::Unknown,
        };
        loaded.session_record = Some(record);
        loaded.session_secret_match = Some(LoadedSessionSecretMatch::new(
            session_id.clone(),
            match_kind,
        ));
        Ok(())
    }

    async fn load_trusted_device_record_and_secret_match(
        &self,
        tx: &mut Tx<'_>,
        table_names: &AuthCoreTableNames,
        loaded: &mut LoadedState,
        device_credential_id: &TrustedDeviceCredentialId,
        presented_secrets: &PresentedAuthCookieSecrets,
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let statement = format!(
            r#"
        SELECT
            d.subject_id,
            d.current_secret_version,
            d.previous_secret_version,
            d.previous_secret_accept_until,
            d.created_at,
            d.last_used_at,
            d.expires_at,
            d.silent_revival_until,
            d.revoked_at,
            d.display_label,
            current_mac.secret_mac,
            previous_mac.secret_mac
        FROM {} d
        LEFT JOIN {} current_mac
          ON current_mac.device_credential_id = d.device_credential_id
         AND current_mac.secret_version = d.current_secret_version
        LEFT JOIN {} previous_mac
          ON previous_mac.device_credential_id = d.device_credential_id
         AND previous_mac.secret_version = d.previous_secret_version
        WHERE d.device_credential_id = $1
        "#,
            table_names
                .get(PostgresAuthCoreTable::TrustedDeviceCredential)
                .quoted(),
            table_names
                .get(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
                .quoted(),
            table_names
                .get(PostgresAuthCoreTable::TrustedDeviceCredentialSecretMac)
                .quoted()
        );
        tx.record_database_operation(
            DatabaseOperationKind::FetchOptional,
            "auth_core.load.trusted_device_with_secret_macs",
            Some(statement.as_str()),
        );
        let row = pooler_safe_query_as::<(
            Vec<u8>,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )>(sqlx::AssertSqlSafe(statement.as_str()))
        .bind(device_credential_id.as_bytes())
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
        let Some(row) = row else {
            return Ok(());
        };
        let record = TrustedDeviceCredentialRecord {
            device_credential_id: device_credential_id.clone(),
            subject_id: SubjectId::from_bytes(row.0)?,
            current_secret_version: secret_version_from_i64(row.1)?,
            previous_secret_version: row.2.map(secret_version_from_i64).transpose()?,
            previous_secret_accept_until: row.3.map(unix_seconds_from_i64).transpose()?,
            created_at: unix_seconds_from_i64(row.4)?,
            last_used_at: unix_seconds_from_i64(row.5)?,
            expires_at: unix_seconds_from_i64(row.6)?,
            silent_revival_until: unix_seconds_from_i64(row.7)?,
            revoked_at: row.8.map(unix_seconds_from_i64).transpose()?,
            display_label: row.9,
        };
        let match_kind = match presented_secrets.trusted_device() {
            Some(secret) => classify_presented_secret(PresentedSecretClassificationInput {
                keyset: &self.credential_secret_keyset,
                current_target: CoreStorageTarget::TrustedDeviceCredentialSecret {
                    device_credential_id: record.device_credential_id.clone(),
                    secret_version: record.current_secret_version,
                },
                current_mac_bytes: row.10.as_deref(),
                secret: secret.secret(),
                current_version: record.current_secret_version,
                previous_target: CoreStorageTarget::TrustedDeviceCredentialSecret {
                    device_credential_id: record.device_credential_id.clone(),
                    secret_version: record
                        .previous_secret_version
                        .unwrap_or(record.current_secret_version),
                },
                previous_mac_bytes: row.11.as_deref(),
                previous_version: record.previous_secret_version,
                previous_secret_accept_until: record.previous_secret_accept_until,
                now,
            })?,
            None => StoredSecretMatch::Unknown,
        };
        loaded.trusted_device_record = Some(record);
        loaded.trusted_device_secret_match = Some(LoadedTrustedDeviceSecretMatch::new(
            device_credential_id.clone(),
            match_kind,
        ));
        Ok(())
    }
}
