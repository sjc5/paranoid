use super::*;

impl<T> Item<T>
where
    T: Plaintext,
{
    pub(super) async fn acquire_prepared_slot_in_current_transaction(
        &self,
        tx: &mut WriteTx<'_>,
        prepared: PreparedSlotCandidateKeys,
        value: &T,
        ttl: Ttl,
    ) -> Result<Option<String>, Error> {
        positive_expiring_ttl_microseconds(ttl)?;
        if prepared.keys.is_empty() {
            return Ok(None);
        }
        let acquired_key = match &self.codec {
            ItemCodec::Plain => {
                let encoded = self.encode_value_for_key(&prepared.keys[0], value)?;
                self.store
                    .acquire_slot_bytes_in_current_transaction(tx, &prepared.keys, &encoded, ttl)
                    .await?
            }
            ItemCodec::Encrypted { get_keyset } => {
                let keyset = get_keyset()?;
                let plaintext = value.to_plaintext_bytes()?;
                let acquired_key = self
                    .store
                    .acquire_slot_bytes_in_current_transaction(tx, &prepared.keys, &[], ttl)
                    .await?;
                if let Some(key) = &acquired_key {
                    let associated_data = item_associated_data(key);
                    let encoded = match encrypt_plaintext_bytes_as::<T>(
                        keyset.as_ref(),
                        plaintext.expose_secret(),
                        &associated_data,
                    ) {
                        Ok(encrypted) => encrypted.into_bytes(),
                        Err(err) => {
                            self.store.delete_key_for_atomic_mutation(tx, key).await?;
                            return Err(Error::from(err));
                        }
                    };
                    self.store
                        .set_bytes_in_current_transaction(tx, key, &encoded, ttl)
                        .await?;
                }
                acquired_key
            }
        };
        Ok(acquired_key.and_then(|key| prepared.key_to_suffix.get(key.as_str()).cloned()))
    }

    pub(super) fn encode_atomic_mutation_for_key<E>(
        &self,
        key: &Key,
        item_mutation: ItemAtomicMutation<T>,
    ) -> Result<AtomicMutation, E>
    where
        E: From<Error>,
    {
        match item_mutation {
            ItemAtomicMutation::KeepExisting => Ok(AtomicMutation::KeepExisting),
            ItemAtomicMutation::SetValue { value, ttl } => Ok(AtomicMutation::SetBytes {
                value: self.encode_value_for_key(key, &value).map_err(E::from)?,
                ttl,
            }),
            ItemAtomicMutation::SetValuePreservingExpiration { value } => {
                Ok(AtomicMutation::SetBytesPreservingExpiration {
                    value: self.encode_value_for_key(key, &value).map_err(E::from)?,
                })
            }
            ItemAtomicMutation::Delete => Ok(AtomicMutation::Delete),
        }
    }

    pub(super) fn key_from_parts<S, I>(&self, key_parts: I) -> Result<Key, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        Key::from_prefix_and_parts(&self.prefix, key_parts)
    }

    pub(super) fn keys_from_parts_list_for_multi_get<S, K>(
        &self,
        key_parts_list: &[K],
    ) -> Result<Vec<Key>, Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        validate_get_multi_key_count(key_parts_list.len())?;
        let keys = self.keys_from_parts_list(key_parts_list)?;
        validate_unique_item_keys(&keys)?;
        Ok(keys)
    }

    pub(super) fn multi_set_entries<S, K>(
        &self,
        key_parts_list: &[K],
        values: &[T],
    ) -> Result<Vec<BytesSetEntry>, Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        if key_parts_list.len() != values.len() {
            return Err(Error::SetMultiLengthMismatch {
                key_count: key_parts_list.len(),
                value_count: values.len(),
            });
        }
        validate_set_multi_entry_count(key_parts_list.len())?;
        let keys = self.keys_from_parts_list(key_parts_list)?;
        validate_unique_item_keys(&keys)?;

        if keys.is_empty() {
            return Ok(Vec::new());
        }

        match &self.codec {
            ItemCodec::Plain => keys
                .iter()
                .zip(values)
                .map(|(key, value)| Ok(BytesSetEntry::new(key.clone(), encode_plain_value(value)?)))
                .collect(),
            ItemCodec::Encrypted { get_keyset } => {
                let keyset = get_keyset()?;
                keys.iter()
                    .zip(values)
                    .map(|(key, value)| {
                        Ok(BytesSetEntry::new(
                            key.clone(),
                            encode_encrypted_value_for_key(keyset.as_ref(), key, value)?,
                        ))
                    })
                    .collect()
            }
        }
    }

    pub(super) fn keys_from_parts_list<S, K>(&self, key_parts_list: &[K]) -> Result<Vec<Key>, Error>
    where
        S: AsRef<str>,
        K: AsRef<[S]>,
    {
        key_parts_list
            .iter()
            .map(|key_parts| self.key_from_parts(key_parts.as_ref().iter()))
            .collect()
    }

    pub(super) fn encode_value_for_key(&self, key: &Key, value: &T) -> Result<Vec<u8>, Error> {
        match &self.codec {
            ItemCodec::Plain => encode_plain_value(value),
            ItemCodec::Encrypted { get_keyset } => {
                let keyset = get_keyset()?;
                encode_encrypted_value_for_key(keyset.as_ref(), key, value)
            }
        }
    }

    pub(super) fn decode_value_for_key(&self, key: &Key, bytes: &[u8]) -> Result<T, Error> {
        match &self.codec {
            ItemCodec::Plain => decode_plain_value(bytes),
            ItemCodec::Encrypted { get_keyset } => {
                let keyset = get_keyset()?;
                decode_encrypted_value_for_key(keyset.as_ref(), key, bytes)
            }
        }
    }

    pub(super) fn decode_scanned_rows(
        &self,
        rows: Vec<ScannedBytes>,
    ) -> Result<Vec<ItemScannedValue<T>>, Error> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        match &self.codec {
            ItemCodec::Plain => rows
                .into_iter()
                .map(|row| {
                    let value = decode_plain_value(&row.value)?;
                    Ok(ItemScannedValue {
                        key_suffix: self.suffix_from_key(&row.key),
                        value,
                    })
                })
                .collect(),
            ItemCodec::Encrypted { get_keyset } => {
                let keyset = get_keyset()?;
                rows.into_iter()
                    .map(|row| {
                        let value =
                            decode_encrypted_value_for_key(keyset.as_ref(), &row.key, &row.value)?;
                        Ok(ItemScannedValue {
                            key_suffix: self.suffix_from_key(&row.key),
                            value,
                        })
                    })
                    .collect()
            }
        }
    }

    pub(super) fn decode_multi_values(
        &self,
        keys: &[Key],
        values: Vec<Option<Vec<u8>>>,
    ) -> Result<Vec<Option<T>>, Error> {
        if values.iter().all(Option::is_none) {
            return Ok(values.into_iter().map(|_| None).collect());
        }

        match &self.codec {
            ItemCodec::Plain => keys
                .iter()
                .zip(values)
                .map(|(_key, value)| value.as_deref().map(decode_plain_value).transpose())
                .collect(),
            ItemCodec::Encrypted { get_keyset } => {
                let keyset = get_keyset()?;
                keys.iter()
                    .zip(values)
                    .map(|(key, value)| {
                        value
                            .as_deref()
                            .map(|bytes| {
                                decode_encrypted_value_for_key(keyset.as_ref(), key, bytes)
                            })
                            .transpose()
                    })
                    .collect()
            }
        }
    }

    pub(super) fn suffix_from_key(&self, key: &Key) -> String {
        key.as_str()
            .strip_prefix(self.prefix.as_str())
            .unwrap_or_default()
            .strip_suffix(KV_KEY_SEPARATOR)
            .unwrap_or_default()
            .to_owned()
    }

    pub(super) fn after_key_from_optional_suffix(
        &self,
        after_key_suffix: Option<&str>,
    ) -> Result<Option<Key>, Error> {
        after_key_suffix
            .map(|suffix| key_from_prefix_and_raw_suffix(&self.prefix, suffix))
            .transpose()
    }

    pub(super) fn prepare_slot_candidate_keys<S>(
        &self,
        candidate_suffixes: &[S],
    ) -> Result<PreparedSlotCandidateKeys, Error>
    where
        S: AsRef<str>,
    {
        validate_acquire_slot_candidate_count(candidate_suffixes.len())?;
        let mut keys = Vec::with_capacity(candidate_suffixes.len());
        let mut key_to_suffix = HashMap::with_capacity(candidate_suffixes.len());
        for suffix in candidate_suffixes {
            let suffix = suffix.as_ref();
            let key = Key::from_prefix_and_parts(&self.prefix, [suffix])?;
            if key_to_suffix
                .insert(key.as_str().to_owned(), suffix.to_owned())
                .is_some()
            {
                return Err(Error::DuplicateKeyInBulkOperation);
            }
            keys.push(key);
        }
        Ok(PreparedSlotCandidateKeys {
            keys,
            key_to_suffix,
        })
    }
}
