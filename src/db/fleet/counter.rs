use super::*;

impl Counter {
    /// Returns this counter's key.
    pub fn key(&self) -> &CounterKey {
        &self.key
    }

    /// Atomically adds `delta` and returns the new value.
    pub async fn add(&self, pool: &WritePool, delta: i64) -> Result<i64, Error> {
        let mut tx = pool.begin_transaction().await?;
        let result = self.add_in_current_transaction(&mut tx, delta).await;
        finish_fleet_pool_transaction(FLEET_OPERATION_COUNTER_ADD, tx, result).await
    }

    /// Atomically adds `delta` inside the caller's transaction.
    pub async fn add_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        delta: i64,
    ) -> Result<i64, Error> {
        let mut next_value = None;
        self.item
            .mutate_live_or_insert_initial_value_atomically_in_current_transaction(
                tx,
                [FLEET_COUNTER_VALUE_KEY_PART],
                |_| Ok::<_, Error>((0, KvTtl::no_expiration())),
                |current| {
                    let value = current
                        .live_value()
                        .checked_add(delta)
                        .ok_or(Error::CounterArithmeticOverflow)?;
                    next_value = Some(value);
                    Ok(KvItemAtomicMutation::SetValue {
                        value,
                        ttl: KvTtl::no_expiration(),
                    })
                },
            )
            .await?;
        next_value.ok_or(Error::CounterMutationDidNotAssignNextValue)
    }

    /// Fetches the current counter value, returning zero when the counter has not been stored.
    pub async fn fetch_value(&self, pool: &Pool) -> Result<i64, Error> {
        match self.item.get(pool, [FLEET_COUNTER_VALUE_KEY_PART]).await {
            Ok(value) => Ok(value),
            Err(KvError::KeyNotFound) => Ok(0),
            Err(err) => Err(Error::from(err)),
        }
    }

    /// Fetches the current counter value inside the caller's transaction.
    pub async fn fetch_value_in_current_transaction(&self, tx: &mut Tx<'_>) -> Result<i64, Error> {
        match self
            .item
            .get_in_current_transaction(tx, [FLEET_COUNTER_VALUE_KEY_PART])
            .await
        {
            Ok(value) => Ok(value),
            Err(KvError::KeyNotFound) => Ok(0),
            Err(err) => Err(Error::from(err)),
        }
    }

    /// Stores an exact counter value.
    pub async fn set_value(&self, pool: &WritePool, value: i64) -> Result<(), Error> {
        self.item
            .set(
                pool,
                [FLEET_COUNTER_VALUE_KEY_PART],
                &value,
                KvTtl::no_expiration(),
            )
            .await?;
        Ok(())
    }

    /// Stores an exact counter value inside the caller's transaction.
    pub async fn set_value_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        value: i64,
    ) -> Result<(), Error> {
        self.item
            .set_in_current_transaction(
                tx,
                [FLEET_COUNTER_VALUE_KEY_PART],
                &value,
                KvTtl::no_expiration(),
            )
            .await?;
        Ok(())
    }
}
