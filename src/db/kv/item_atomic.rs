use super::*;

impl<T> Item<T>
where
    T: Plaintext,
{
    /// Fetches a typed value or initializes it atomically inside one transaction.
    pub async fn get_or_init<S, I>(
        &self,
        pool: &WritePool,
        key_parts: I,
        initial_value: T,
        ttl: Ttl,
    ) -> Result<ItemGetOrInitResult<T>, Error>
    where
        T: Clone,
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let mut tx = pool.begin_transaction().await?;
        let result = self
            .get_or_init_in_transaction_internal(&mut tx, key_parts, initial_value, ttl, false)
            .await;
        finish_kv_pool_transaction(KV_OPERATION_GET_OR_INIT_ITEM, tx, result).await
    }

    /// Fetches a typed value or initializes it atomically inside the caller's transaction.
    pub async fn get_or_init_in_current_transaction<S, I>(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        initial_value: T,
        ttl: Ttl,
    ) -> Result<ItemGetOrInitResult<T>, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        self.get_or_init_in_transaction_internal(tx, key_parts, initial_value, ttl, true)
            .await
    }

    async fn get_or_init_in_transaction_internal<S, I>(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        initial_value: T,
        ttl: Ttl,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<ItemGetOrInitResult<T>, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = self.key_from_parts(key_parts)?;
        let mut initial_value = Some(initial_value);
        let mut loaded_value = None;
        let result = self
            .store
            .mutate_key_atomically_in_transaction_internal(
                tx,
                &key,
                |current| {
                    if let Some(value_bytes) = current.live_value() {
                        let decoded = self.decode_value_for_key(&key, value_bytes)?;
                        loaded_value = Some(decoded);
                        Ok::<AtomicMutation, Error>(AtomicMutation::KeepExisting)
                    } else {
                        let value = initial_value
                            .take()
                            .ok_or(Error::AtomicMutationCallbackInvokedMoreThanOnce)?;
                        let encoded_initial_value = self.encode_value_for_key(&key, &value)?;
                        loaded_value = Some(value);
                        Ok::<AtomicMutation, Error>(AtomicMutation::SetBytes {
                            value: encoded_initial_value,
                            ttl,
                        })
                    }
                },
                cleanup_absent_placeholder_on_callback_error,
            )
            .await?;

        let value = loaded_value.ok_or(Error::AtomicMutationCurrentValueWasNotCaptured)?;
        Ok(ItemGetOrInitResult {
            value,
            initialized: matches!(result.outcome, AtomicMutationOutcome::SetBytes),
        })
    }

    /// Locks one typed item, exposes its current live value, and applies the chosen mutation.
    pub async fn mutate_atomically<S, I, F, E>(
        &self,
        pool: &WritePool,
        key_parts: I,
        decide_mutation: F,
    ) -> Result<ItemAtomicMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: for<'current> FnOnce(
            ItemAtomicMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(Error::from)
            .map_err(E::from)?;
        let result = self
            .mutate_atomically_in_transaction_internal(&mut tx, key_parts, decide_mutation, false)
            .await;
        finish_kv_callback_pool_transaction(KV_OPERATION_MUTATE_ITEM_ATOMICALLY, tx, result).await
    }

    /// Transactional variant of `mutate_atomically`.
    pub async fn mutate_atomically_in_current_transaction<S, I, F, E>(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        decide_mutation: F,
    ) -> Result<ItemAtomicMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: for<'current> FnOnce(
            ItemAtomicMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        self.mutate_atomically_in_transaction_internal(tx, key_parts, decide_mutation, true)
            .await
    }

    async fn mutate_atomically_in_transaction_internal<S, I, F, E>(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        decide_mutation: F,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<ItemAtomicMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: for<'current> FnOnce(
            ItemAtomicMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        let key = self.key_from_parts(key_parts).map_err(E::from)?;
        let mut previous_live_value = None;
        let raw_result = self
            .store
            .mutate_key_atomically_in_transaction_internal(
                tx,
                &key,
                |current| {
                    if let Some(value_bytes) = current.live_value() {
                        previous_live_value = Some(
                            self.decode_value_for_key(&key, value_bytes)
                                .map_err(E::from)?,
                        );
                    }
                    let item_current = ItemAtomicMutationCurrent {
                        live_value: previous_live_value.as_ref(),
                        database_timestamp: current.database_timestamp(),
                    };
                    let item_mutation = decide_mutation(item_current)?;
                    self.encode_atomic_mutation_for_key::<E>(&key, item_mutation)
                },
                cleanup_absent_placeholder_on_callback_error,
            )
            .await?;

        Ok(ItemAtomicMutationResult {
            previous_live_value,
            outcome: raw_result.outcome,
        })
    }

    /// Locks one live typed item, requiring it to exist and not be expired.
    pub async fn mutate_live_atomically<S, I, F, E>(
        &self,
        pool: &WritePool,
        key_parts: I,
        decide_mutation: F,
    ) -> Result<ItemAtomicLiveMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: for<'current> FnOnce(
            ItemAtomicLiveMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(Error::from)
            .map_err(E::from)?;
        let result = self
            .mutate_live_atomically_in_transaction_internal(
                &mut tx,
                key_parts,
                decide_mutation,
                false,
            )
            .await;
        finish_kv_callback_pool_transaction(KV_OPERATION_MUTATE_LIVE_ITEM_ATOMICALLY, tx, result)
            .await
    }

    /// Transactional variant of `mutate_live_atomically`.
    pub async fn mutate_live_atomically_in_current_transaction<S, I, F, E>(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        decide_mutation: F,
    ) -> Result<ItemAtomicLiveMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: for<'current> FnOnce(
            ItemAtomicLiveMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        self.mutate_live_atomically_in_transaction_internal(tx, key_parts, decide_mutation, true)
            .await
    }

    async fn mutate_live_atomically_in_transaction_internal<S, I, F, E>(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        decide_mutation: F,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<ItemAtomicLiveMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        F: for<'current> FnOnce(
            ItemAtomicLiveMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        let key = self.key_from_parts(key_parts).map_err(E::from)?;
        let mut previous_live_value = None;
        let raw_result = self
            .store
            .mutate_key_atomically_in_transaction_internal::<_, E>(
                tx,
                &key,
                |current| {
                    let value_bytes = current
                        .live_value()
                        .ok_or_else(|| E::from(Error::KeyNotFound))?;
                    previous_live_value = Some(
                        self.decode_value_for_key(&key, value_bytes)
                            .map_err(E::from)?,
                    );
                    let item_current = ItemAtomicLiveMutationCurrent {
                        live_value: previous_live_value.as_ref().ok_or_else(|| {
                            E::from(Error::AtomicMutationCurrentValueWasNotCaptured)
                        })?,
                        database_timestamp: current.database_timestamp(),
                    };
                    let item_mutation = decide_mutation(item_current)?;
                    self.encode_atomic_mutation_for_key::<E>(&key, item_mutation)
                },
                cleanup_absent_placeholder_on_callback_error,
            )
            .await?;

        let previous_live_value = previous_live_value
            .ok_or_else(|| E::from(Error::AtomicMutationCurrentValueWasNotCaptured))?;
        Ok(ItemAtomicLiveMutationResult {
            previous_live_value,
            outcome: raw_result.outcome,
        })
    }

    /// Locks one typed item, initializes it when absent or expired, and applies a live-value mutation.
    pub async fn mutate_live_or_insert_initial_value_atomically<S, I, Init, F, E>(
        &self,
        pool: &WritePool,
        key_parts: I,
        initialize_value: Init,
        decide_mutation: F,
    ) -> Result<ItemAtomicLiveOrInitMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        Init: FnOnce(DatabaseTimestampMicros) -> Result<(T, Ttl), E>,
        F: for<'current> FnOnce(
            ItemAtomicLiveMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        let mut tx = pool
            .begin_transaction()
            .await
            .map_err(Error::from)
            .map_err(E::from)?;
        let result = self
            .mutate_live_or_insert_initial_value_atomically_in_transaction_internal(
                &mut tx,
                key_parts,
                initialize_value,
                decide_mutation,
                false,
            )
            .await;
        finish_kv_callback_pool_transaction(
            KV_OPERATION_MUTATE_LIVE_OR_INIT_ITEM_ATOMICALLY,
            tx,
            result,
        )
        .await
    }

    /// Transactional variant of `mutate_live_or_insert_initial_value_atomically`.
    pub async fn mutate_live_or_insert_initial_value_atomically_in_current_transaction<
        S,
        I,
        Init,
        F,
        E,
    >(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        initialize_value: Init,
        decide_mutation: F,
    ) -> Result<ItemAtomicLiveOrInitMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        Init: FnOnce(DatabaseTimestampMicros) -> Result<(T, Ttl), E>,
        F: for<'current> FnOnce(
            ItemAtomicLiveMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        self.mutate_live_or_insert_initial_value_atomically_in_transaction_internal(
            tx,
            key_parts,
            initialize_value,
            decide_mutation,
            true,
        )
        .await
    }

    async fn mutate_live_or_insert_initial_value_atomically_in_transaction_internal<
        S,
        I,
        Init,
        F,
        E,
    >(
        &self,
        tx: &mut WriteTx<'_>,
        key_parts: I,
        initialize_value: Init,
        decide_mutation: F,
        cleanup_absent_placeholder_on_callback_error: bool,
    ) -> Result<ItemAtomicLiveOrInitMutationResult<T>, E>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
        Init: FnOnce(DatabaseTimestampMicros) -> Result<(T, Ttl), E>,
        F: for<'current> FnOnce(
            ItemAtomicLiveMutationCurrent<'current, T>,
        ) -> Result<ItemAtomicMutation<T>, E>,
        E: From<Error>,
    {
        let key = self.key_from_parts(key_parts).map_err(E::from)?;
        let mut initialize_value = Some(initialize_value);
        let mut live_value_seen_by_callback = None;
        let raw_result = self
            .store
            .mutate_live_key_or_insert_initial_value_atomically_in_transaction_internal::<_, _, E>(
                tx,
                &key,
                |database_timestamp| {
                    let (initial_value, initial_ttl) =
                        initialize_value.take().ok_or_else(|| {
                            E::from(Error::AtomicMutationCallbackInvokedMoreThanOnce)
                        })?(database_timestamp)?;
                    initial_ttl.positive_microseconds().map_err(E::from)?;
                    let encoded_initial_value = self
                        .encode_value_for_key(&key, &initial_value)
                        .map_err(E::from)?;
                    Ok((encoded_initial_value, initial_ttl))
                },
                |current| {
                    live_value_seen_by_callback = Some(
                        self.decode_value_for_key(&key, current.live_value())
                            .map_err(E::from)?,
                    );
                    let item_current = ItemAtomicLiveMutationCurrent {
                        live_value: live_value_seen_by_callback.as_ref().ok_or_else(|| {
                            E::from(Error::AtomicMutationCurrentValueWasNotCaptured)
                        })?,
                        database_timestamp: current.database_timestamp(),
                    };
                    let item_mutation = decide_mutation(item_current)?;
                    self.encode_atomic_mutation_for_key::<E>(&key, item_mutation)
                },
                cleanup_absent_placeholder_on_callback_error,
            )
            .await?;

        Ok(ItemAtomicLiveOrInitMutationResult {
            initialized: raw_result.initialized,
            live_value_seen_by_callback: live_value_seen_by_callback
                .ok_or_else(|| E::from(Error::AtomicMutationCurrentValueWasNotCaptured))?,
            outcome: raw_result.outcome,
        })
    }
}
