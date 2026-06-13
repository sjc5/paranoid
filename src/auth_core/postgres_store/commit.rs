use super::*;

impl PostgresAuthStore {
    pub(crate) async fn commit_atomic_work_in_current_transaction(
        &self,
        tx: &mut Tx<'_>,
        request: AtomicCommitRequest<'_>,
    ) -> Result<Vec<MaterializedFreshCredentialSecret>, PostgresAuthStoreError> {
        request.atomic_work().validate_for_commit()?;
        let method_commit_executor = self.method_commit_executor_for(request.atomic_work())?;
        let table_names = self.config.table_names()?;
        let mut precondition_state =
            CorePreconditionExecutionState::for_preconditions(&request.atomic_work().preconditions);
        for precondition in &request.atomic_work().preconditions {
            enforce_precondition(tx, &table_names, precondition, &mut precondition_state).await?;
        }
        if let Some(executor) = method_commit_executor {
            enforce_method_commit_preconditions(
                tx,
                executor,
                &request.atomic_work().method_commit_work,
            )
            .await?;
        }
        let mut materialized =
            Vec::with_capacity(request.atomic_work().fresh_credential_secrets.len());
        for fresh_secret in &request.atomic_work().fresh_credential_secrets {
            materialized.push(
                self.materialize_fresh_credential_secret(tx, &table_names, fresh_secret)
                    .await?,
            );
        }
        for mutation in &request.atomic_work().mutations {
            apply_mutation(tx, &table_names, mutation).await?;
        }
        if let Some(executor) = method_commit_executor {
            apply_method_commit_mutations(tx, executor, &request.atomic_work().method_commit_work)
                .await?;
        }
        append_audit_events(tx, &table_names, &request.atomic_work().audit_events).await?;
        append_core_durable_effects(tx, &table_names, &request.atomic_work().durable_effects)
            .await?;
        if let Some(executor) = method_commit_executor {
            append_method_commit_durable_effect_commands(
                tx,
                executor,
                &request.atomic_work().method_commit_work,
            )
            .await?;
        }
        Ok(materialized)
    }
    fn method_commit_executor_for(
        &self,
        work: &AtomicCommitWork,
    ) -> Result<Option<&dyn PostgresAuthMethodCommitExecutor>, PostgresAuthStoreError> {
        if work.method_commit_work.is_empty() {
            Ok(None)
        } else {
            match self.method_registry.as_deref() {
                Some(registry) => Ok(Some(registry as &dyn PostgresAuthMethodCommitExecutor)),
                None => Err(PostgresAuthStoreError::MethodRegistryNotConfigured),
            }
        }
    }

    async fn materialize_fresh_credential_secret(
        &self,
        tx: &mut Tx<'_>,
        table_names: &AuthCoreTableNames,
        fresh_secret: &FreshCredentialSecret,
    ) -> Result<MaterializedFreshCredentialSecret, PostgresAuthStoreError> {
        let secret = AuthCredentialSecret::from_secret_bytes(
            SecretBytes::<AuthCredentialSecretKind>::random(AUTH_CREDENTIAL_SECRET_BYTES)
                .map_err(PostgresAuthStoreError::Crypto)?,
        )?;
        let target = match fresh_secret {
            FreshCredentialSecret::Session {
                session_id,
                secret_version,
            } => {
                let target = CoreStorageTarget::SessionCredentialSecret {
                    session_id: session_id.clone(),
                    secret_version: *secret_version,
                };
                let mac = secret
                    .to_mac(
                        &self.credential_secret_keyset,
                        &credential_secret_mac_context(&target),
                    )
                    .map_err(PostgresAuthStoreError::Crypto)?;
                insert_session_secret_mac(
                    tx,
                    table_names,
                    session_id,
                    *secret_version,
                    mac.as_bytes(),
                )
                .await?;
                target
            }
            FreshCredentialSecret::TrustedDevice {
                device_credential_id,
                secret_version,
            } => {
                let target = CoreStorageTarget::TrustedDeviceCredentialSecret {
                    device_credential_id: device_credential_id.clone(),
                    secret_version: *secret_version,
                };
                let mac = secret
                    .to_mac(
                        &self.credential_secret_keyset,
                        &credential_secret_mac_context(&target),
                    )
                    .map_err(PostgresAuthStoreError::Crypto)?;
                insert_trusted_device_secret_mac(
                    tx,
                    table_names,
                    device_credential_id,
                    *secret_version,
                    mac.as_bytes(),
                )
                .await?;
                target
            }
            FreshCredentialSecret::ActiveProofContinuation { attempt_id } => {
                let target = CoreStorageTarget::ActiveProofContinuationSecret {
                    attempt_id: attempt_id.clone(),
                };
                let mac = secret
                    .to_mac(
                        &self.credential_secret_keyset,
                        &credential_secret_mac_context(&target),
                    )
                    .map_err(PostgresAuthStoreError::Crypto)?;
                insert_active_proof_continuation_secret_mac(
                    tx,
                    table_names,
                    attempt_id,
                    mac.as_bytes(),
                )
                .await?;
                target
            }
        };
        Ok(MaterializedFreshCredentialSecret::new(target, secret))
    }
}
