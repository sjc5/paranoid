use super::*;

impl PostgresAuthStore {
    #[cfg(test)]
    pub(crate) async fn store_credential_lifecycle_metadata_for_test(
        &self,
        pool: &Pool,
        metadata: &[CredentialInstanceMetadata],
        authorities: &[CredentialRecoveryAuthority],
        authority_sources: &[LifecycleAuthorityEvidence],
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for metadata in metadata {
                insert_credential_instance_metadata(&mut tx, &table_names, metadata, now).await?;
            }
            for authority in authorities {
                insert_credential_recovery_authority(&mut tx, &table_names, authority, now).await?;
            }
            for evidence in authority_sources {
                for authority_id in evidence.authority_ids() {
                    insert_lifecycle_authority_source(
                        &mut tx,
                        &table_names,
                        evidence.source(),
                        authority_id,
                        now,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_credential_lifecycle_metadata_for_test",
            tx,
            result,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_subject_lifecycle_metadata_for_test(
        &self,
        pool: &Pool,
        authorities: &[SubjectLifecycleAuthority],
        authority_sources: &[LifecycleAuthorityEvidence],
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for authority in authorities {
                insert_subject_lifecycle_authority(&mut tx, &table_names, authority, now).await?;
            }
            for evidence in authority_sources {
                for authority_id in evidence.authority_ids() {
                    insert_lifecycle_authority_source(
                        &mut tx,
                        &table_names,
                        evidence.source(),
                        authority_id,
                        now,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_subject_lifecycle_metadata_for_test",
            tx,
            result,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_out_of_band_identifier_bindings_for_test(
        &self,
        pool: &Pool,
        records: &[OutOfBandIdentifierBindingRecord],
        now: UnixSeconds,
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for record in records {
                insert_out_of_band_identifier_binding(&mut tx, &table_names, record, now).await?;
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_out_of_band_identifier_bindings_for_test",
            tx,
            result,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_pending_credential_lifecycle_actions_for_test(
        &self,
        pool: &Pool,
        records: &[PendingCredentialLifecycleActionRecord],
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for record in records {
                insert_pending_credential_lifecycle_action(&mut tx, &table_names, record).await?;
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_pending_credential_lifecycle_actions_for_test",
            tx,
            result,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_pending_subject_lifecycle_actions_for_test(
        &self,
        pool: &Pool,
        records: &[PendingSubjectLifecycleActionRecord],
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for record in records {
                insert_pending_subject_lifecycle_action(&mut tx, &table_names, record).await?;
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_pending_subject_lifecycle_actions_for_test",
            tx,
            result,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn store_admin_support_interventions_for_test(
        &self,
        pool: &Pool,
        records: &[AdminSupportInterventionRecord],
    ) -> Result<(), PostgresAuthStoreError> {
        let mut tx = pool.begin_transaction().await?;
        let table_names = self.config.table_names()?;
        let result = async {
            for record in records {
                insert_admin_support_intervention(&mut tx, &table_names, record).await?;
            }
            Ok(())
        }
        .await;
        finish_auth_store_transaction(
            "auth_core.store_admin_support_interventions_for_test",
            tx,
            result,
        )
        .await
    }
}
