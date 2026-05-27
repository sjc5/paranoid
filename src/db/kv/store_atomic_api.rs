use super::*;

impl Store {
    /// Locks one key, exposes its current live value, and applies the chosen mutation.
    pub async fn mutate_key_atomically<F, E>(
        &self,
        pool: &Pool,
        key: &Key,
        decide_mutation: F,
    ) -> Result<AtomicMutationResult, E>
    where
        F: for<'current> FnOnce(AtomicMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(Error::from)
            .map_err(E::from)?;
        let result = self
            .mutate_key_atomically_in_transaction_internal(&mut tx, key, decide_mutation, false)
            .await;
        finish_kv_callback_pool_transaction(KV_OPERATION_MUTATE_KEY_ATOMICALLY, tx, result).await
    }

    /// Locks one key, requires a live value, and applies the chosen mutation.
    pub async fn mutate_live_key_atomically<F, E>(
        &self,
        pool: &Pool,
        key: &Key,
        decide_mutation: F,
    ) -> Result<AtomicLiveMutationResult, E>
    where
        F: for<'current> FnOnce(AtomicLiveMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(Error::from)
            .map_err(E::from)?;
        let result = self
            .mutate_live_key_atomically_in_transaction_internal(
                &mut tx,
                key,
                decide_mutation,
                false,
            )
            .await;
        finish_kv_callback_pool_transaction(KV_OPERATION_MUTATE_LIVE_KEY_ATOMICALLY, tx, result)
            .await
    }

    /// Transactional variant of `mutate_live_key_atomically`.
    pub async fn mutate_live_key_atomically_in_current_transaction<F, E>(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        decide_mutation: F,
    ) -> Result<AtomicLiveMutationResult, E>
    where
        F: for<'current> FnOnce(AtomicLiveMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        self.mutate_live_key_atomically_in_transaction_internal(tx, key, decide_mutation, true)
            .await
    }

    pub(in crate::db::kv) async fn mutate_live_key_atomically_in_transaction_internal<F, E>(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        decide_mutation: F,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<AtomicLiveMutationResult, E>
    where
        F: for<'current> FnOnce(AtomicLiveMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        let result = self
            .mutate_key_atomically_in_transaction_internal(
                tx,
                key,
                |current| {
                    let live_value = current
                        .live_value()
                        .ok_or_else(|| E::from(Error::KeyNotFound))?;
                    decide_mutation(AtomicLiveMutationCurrent {
                        live_value,
                        database_timestamp: current.database_timestamp(),
                    })
                },
                cleanup_absent_placeholder_on_callback_error,
            )
            .await?;
        let previous_live_value = result
            .previous_live_value
            .ok_or_else(|| E::from(Error::AtomicMutationCurrentValueWasNotCaptured))?;
        Ok(AtomicLiveMutationResult {
            previous_live_value,
            outcome: result.outcome,
        })
    }

    /// Locks one key, initializes it when absent or expired, and applies a live-value mutation.
    pub async fn mutate_live_key_or_insert_initial_value_atomically<I, F, E>(
        &self,
        pool: &Pool,
        key: &Key,
        initialize_value: I,
        decide_mutation: F,
    ) -> Result<AtomicLiveOrInitMutationResult, E>
    where
        I: FnOnce(DatabaseTimestampMicros) -> Result<(Vec<u8>, Ttl), E>,
        F: for<'current> FnOnce(AtomicLiveMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(Error::from)
            .map_err(E::from)?;
        let result = self
            .mutate_live_key_or_insert_initial_value_atomically_in_transaction_internal(
                &mut tx,
                key,
                initialize_value,
                decide_mutation,
                false,
            )
            .await;
        finish_kv_callback_pool_transaction(
            KV_OPERATION_MUTATE_LIVE_OR_INIT_KEY_ATOMICALLY,
            tx,
            result,
        )
        .await
    }

    /// Transactional variant of `mutate_live_key_or_insert_initial_value_atomically`.
    pub async fn mutate_live_key_or_insert_initial_value_atomically_in_current_transaction<
        I,
        F,
        E,
    >(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        initialize_value: I,
        decide_mutation: F,
    ) -> Result<AtomicLiveOrInitMutationResult, E>
    where
        I: FnOnce(DatabaseTimestampMicros) -> Result<(Vec<u8>, Ttl), E>,
        F: for<'current> FnOnce(AtomicLiveMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        self.mutate_live_key_or_insert_initial_value_atomically_in_transaction_internal(
            tx,
            key,
            initialize_value,
            decide_mutation,
            true,
        )
        .await
    }

    pub(in crate::db::kv) async fn mutate_live_key_or_insert_initial_value_atomically_in_transaction_internal<
        I,
        F,
        E,
    >(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        initialize_value: I,
        decide_mutation: F,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<AtomicLiveOrInitMutationResult, E>
    where
        I: FnOnce(DatabaseTimestampMicros) -> Result<(Vec<u8>, Ttl), E>,
        F: for<'current> FnOnce(AtomicLiveMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        let mut initialize_value = Some(initialize_value);
        let mut initialized = false;
        let mut live_value_seen_by_callback = None;
        let raw_result = self
            .mutate_key_atomically_in_transaction_internal::<_, E>(
                tx,
                key,
                |current| {
                    if let Some(live_value) = current.live_value() {
                        live_value_seen_by_callback = Some(live_value.to_vec());
                        return decide_mutation(AtomicLiveMutationCurrent {
                            live_value,
                            database_timestamp: current.database_timestamp(),
                        });
                    }

                    initialized = true;
                    let (initial_value, initial_ttl) =
                        initialize_value.take().ok_or_else(|| {
                            E::from(Error::AtomicMutationCallbackInvokedMoreThanOnce)
                        })?(current.database_timestamp())?;
                    initial_ttl.positive_microseconds().map_err(E::from)?;
                    live_value_seen_by_callback = Some(initial_value.clone());
                    let mutation = decide_mutation(AtomicLiveMutationCurrent {
                        live_value: &initial_value,
                        database_timestamp: current.database_timestamp(),
                    })?;
                    Ok(match mutation {
                        AtomicMutation::KeepExisting => AtomicMutation::SetBytes {
                            value: initial_value,
                            ttl: initial_ttl,
                        },
                        AtomicMutation::SetBytesPreservingExpiration { value } => {
                            AtomicMutation::SetBytes {
                                value,
                                ttl: initial_ttl,
                            }
                        }
                        mutation => mutation,
                    })
                },
                cleanup_absent_placeholder_on_callback_error,
            )
            .await?;

        Ok(AtomicLiveOrInitMutationResult {
            initialized,
            live_value_seen_by_callback: live_value_seen_by_callback
                .ok_or_else(|| E::from(Error::AtomicMutationCurrentValueWasNotCaptured))?,
            outcome: raw_result.outcome,
        })
    }

    /// Locks one key inside the caller's transaction, exposes its current live value, and applies the chosen mutation.
    pub async fn mutate_key_atomically_in_current_transaction<F, E>(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        decide_mutation: F,
    ) -> Result<AtomicMutationResult, E>
    where
        F: for<'current> FnOnce(AtomicMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        self.mutate_key_atomically_in_transaction_internal(tx, key, decide_mutation, true)
            .await
    }

    pub(in crate::db::kv) async fn mutate_key_atomically_in_transaction_internal<F, E>(
        &self,
        tx: &mut Tx<'_>,
        key: &Key,
        decide_mutation: F,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<AtomicMutationResult, E>
    where
        F: for<'current> FnOnce(AtomicMutationCurrent<'current>) -> Result<AtomicMutation, E>,
        E: From<Error>,
    {
        let (inserted_absent_placeholder, locked_row) = self
            .lock_key_for_atomic_mutation(tx, key)
            .await
            .map_err(E::from)?;
        let previous_live_value = locked_row
            .as_ref()
            .and_then(|row| row.is_live.then(|| row.value.clone()));
        let current = AtomicMutationCurrent {
            live_value: previous_live_value.as_deref(),
            database_timestamp: locked_row
                .as_ref()
                .map(|row| row.database_timestamp)
                .ok_or_else(|| E::from(Error::AtomicMutationLockReturnedNoRow))?,
        };
        let mutation = match decide_mutation(current) {
            Ok(mutation) => mutation,
            Err(err) => {
                if inserted_absent_placeholder && cleanup_absent_placeholder_on_callback_error {
                    self.delete_key_for_atomic_mutation(tx, key)
                        .await
                        .map_err(E::from)?;
                }
                return Err(err);
            }
        };
        let outcome = self
            .apply_atomic_mutation(
                tx,
                key,
                mutation,
                previous_live_value.is_some(),
                inserted_absent_placeholder,
            )
            .await
            .map_err(E::from)?;

        Ok(AtomicMutationResult {
            previous_live_value,
            outcome,
        })
    }
}
