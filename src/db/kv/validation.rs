use super::*;

pub(super) fn validate_distinct_table_names(config: &StoreConfig) -> Result<(), Error> {
    if pg_table_name_set_could_contain_same_relation(&[
        &config.table_name,
        &config.schema_ledger_table_name,
    ]) {
        return Err(Error::TableNamesMustBeDistinct);
    }
    Ok(())
}

pub(super) fn build_key_from_prefix_and_parts<S, I>(
    prefix: &KeyPrefix,
    suffix_parts: I,
) -> Result<String, Error>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut key = prefix.as_str().to_owned();
    let mut saw_part = false;

    for part in suffix_parts {
        let part = part.as_ref();
        validate_key_part(part)?;
        if saw_part {
            key.push_str(KV_KEY_SEPARATOR);
        }
        key.push_str(part);
        saw_part = true;
    }

    if saw_part {
        key.push_str(KV_KEY_SEPARATOR);
    }

    validate_key_length(&key)?;
    Ok(key)
}

pub(super) fn key_from_prefix_and_raw_suffix(
    prefix: &KeyPrefix,
    raw_suffix: &str,
) -> Result<Key, Error> {
    validate_raw_suffix_cursor(raw_suffix)?;
    if raw_suffix.is_empty() {
        return Ok(Key(prefix.as_str().to_owned()));
    }

    let mut key =
        String::with_capacity(prefix.as_str().len() + raw_suffix.len() + KV_KEY_SEPARATOR.len());
    key.push_str(prefix.as_str());
    key.push_str(raw_suffix);
    key.push_str(KV_KEY_SEPARATOR);
    validate_key_length(&key)?;
    Ok(Key(key))
}

pub(super) fn build_key_from_parts<S, I>(parts: I) -> Result<String, Error>
where
    S: AsRef<str>,
    I: IntoIterator<Item = S>,
{
    let mut key = String::new();
    let mut saw_part = false;

    for part in parts {
        let part = part.as_ref();
        validate_key_part(part)?;
        if saw_part {
            key.push_str(KV_KEY_SEPARATOR);
        }
        key.push_str(part);
        saw_part = true;
    }

    if !saw_part {
        return Err(Error::EmptyKey);
    }

    key.push_str(KV_KEY_SEPARATOR);
    validate_key_length(&key)?;
    Ok(key)
}

pub(super) fn encode_plain_value<T>(value: &T) -> Result<Vec<u8>, Error>
where
    T: Plaintext,
{
    Ok(value.to_plaintext_bytes()?.expose_secret().to_vec())
}

pub(super) fn encode_encrypted_value_for_key<T>(
    keyset: &Keyset,
    key: &Key,
    value: &T,
) -> Result<Vec<u8>, Error>
where
    T: Plaintext,
{
    let associated_data = item_associated_data(key);
    Ok(encrypt(keyset, value, &associated_data)?.into_bytes())
}

pub(super) fn decode_plain_value<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: Plaintext,
{
    Ok(T::from_plaintext_bytes(bytes)?)
}

pub(super) fn decode_encrypted_value_for_key<T>(
    keyset: &Keyset,
    key: &Key,
    bytes: &[u8],
) -> Result<T, Error>
where
    T: Plaintext,
{
    let encrypted = Encrypted::<T>::try_from(bytes)?;
    let associated_data = item_associated_data(key);
    Ok(decrypt(keyset, &encrypted, &associated_data)?)
}

pub(super) fn validate_raw_suffix_cursor(raw_suffix: &str) -> Result<(), Error> {
    if raw_suffix.as_bytes().contains(&0) {
        return Err(Error::KeyPartContainsNullByte);
    }
    Ok(())
}

pub(super) fn validate_key_part(part: &str) -> Result<(), Error> {
    if part.is_empty() {
        return Err(Error::EmptyKeyPart);
    }
    if part.as_bytes().contains(&b':') {
        return Err(Error::KeyPartContainsSeparatorByte);
    }
    if part.as_bytes().contains(&0) {
        return Err(Error::KeyPartContainsNullByte);
    }
    Ok(())
}

pub(super) fn validate_key_length(key: &str) -> Result<(), Error> {
    let actual = key.len();
    if actual > MAX_KV_KEY_BYTES {
        return Err(Error::KeyTooLong {
            actual,
            max: MAX_KV_KEY_BYTES,
        });
    }
    Ok(())
}

pub(super) fn validate_get_multi_key_count(key_count: usize) -> Result<(), Error> {
    if key_count > MAX_KV_GET_MULTI_KEYS {
        return Err(Error::GetMultiKeyCountTooLarge {
            actual: key_count,
            max: MAX_KV_GET_MULTI_KEYS,
        });
    }
    Ok(())
}

pub(super) fn validate_set_multi_entry_count(entry_count: usize) -> Result<(), Error> {
    if entry_count > MAX_KV_SET_MULTI_ENTRIES {
        return Err(Error::SetMultiEntryCountTooLarge {
            actual: entry_count,
            max: MAX_KV_SET_MULTI_ENTRIES,
        });
    }
    Ok(())
}

pub(super) fn validate_acquire_slot_candidate_count(candidate_count: usize) -> Result<(), Error> {
    if candidate_count > MAX_KV_ACQUIRE_SLOT_CANDIDATES {
        return Err(Error::AcquireSlotCandidateCountTooLarge {
            actual: candidate_count,
            max: MAX_KV_ACQUIRE_SLOT_CANDIDATES,
        });
    }
    Ok(())
}

pub(super) fn positive_expiring_ttl_microseconds(ttl: Ttl) -> Result<i64, Error> {
    ttl.positive_microseconds()?
        .ok_or(Error::TtlNoExpirationNotAllowed)
}

pub(super) fn prepare_unique_keys_for_multi_get(
    keys: &[Key],
) -> Result<PreparedMultiGetKeys, Error> {
    validate_get_multi_key_count(keys.len())?;

    let mut key_texts = Vec::with_capacity(keys.len());
    let mut key_to_index = HashMap::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        let key_text = key.as_str().to_owned();
        if key_to_index.insert(key_text.clone(), index).is_some() {
            return Err(Error::DuplicateKeyInBulkOperation);
        }
        key_texts.push(key_text);
    }

    Ok(PreparedMultiGetKeys {
        keys: key_texts,
        key_to_index,
    })
}

pub(super) fn prepare_unique_entries_for_multi_set(
    entries: &[BytesSetEntry],
) -> Result<(Vec<String>, Vec<Vec<u8>>), Error> {
    let mut keys = Vec::with_capacity(entries.len());
    let mut values = Vec::with_capacity(entries.len());
    let mut key_to_index = HashMap::with_capacity(entries.len());

    for (index, entry) in entries.iter().enumerate() {
        let key_text = entry.key.as_str().to_owned();
        if key_to_index.insert(key_text.clone(), index).is_some() {
            return Err(Error::DuplicateKeyInBulkOperation);
        }
        keys.push(key_text);
        values.push(entry.value.clone());
    }

    Ok((keys, values))
}

pub(super) fn prepare_unique_keys_for_slot_acquisition(keys: &[Key]) -> Result<Vec<String>, Error> {
    validate_acquire_slot_candidate_count(keys.len())?;

    let mut key_texts = Vec::with_capacity(keys.len());
    let mut key_to_index = HashMap::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        let key_text = key.as_str().to_owned();
        if key_to_index.insert(key_text.clone(), index).is_some() {
            return Err(Error::DuplicateKeyInBulkOperation);
        }
        key_texts.push(key_text);
    }

    Ok(key_texts)
}

pub(super) fn validate_unique_item_keys(keys: &[Key]) -> Result<(), Error> {
    let mut key_to_index = HashMap::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        if key_to_index.insert(key.as_str(), index).is_some() {
            return Err(Error::DuplicateKeyInBulkOperation);
        }
    }
    Ok(())
}

pub(super) fn validate_scan_limit(limit: u32) -> Result<(), Error> {
    if limit == 0 {
        return Err(Error::ScanLimitIsZero);
    }
    if limit > MAX_KV_SCAN_LIMIT {
        return Err(Error::ScanLimitTooLarge {
            actual: limit,
            max: MAX_KV_SCAN_LIMIT,
        });
    }
    Ok(())
}

pub(super) fn validate_delete_batch_size(batch_size: u32) -> Result<(), Error> {
    if batch_size == 0 {
        return Err(Error::DeleteBatchSizeIsZero);
    }
    if batch_size > MAX_KV_DELETE_BATCH_SIZE {
        return Err(Error::DeleteBatchSizeTooLarge {
            actual: batch_size,
            max: MAX_KV_DELETE_BATCH_SIZE,
        });
    }
    Ok(())
}

pub(super) fn scan_after_key_text<'a>(
    prefix: &KeyPrefix,
    after_key: Option<&'a Key>,
) -> Result<&'a str, Error> {
    let Some(after_key) = after_key else {
        return Ok("");
    };
    if !prefix.contains_key(after_key) {
        return Err(Error::ScanCursorOutsidePrefix);
    }
    Ok(after_key.as_str())
}

pub(super) fn prefix_like_pattern(prefix: &KeyPrefix) -> String {
    let mut pattern = String::with_capacity(prefix.as_str().len() + 1);
    for ch in prefix.as_str().chars() {
        if matches!(ch, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

pub(super) fn require_rows_affected(rows_affected: u64) -> Result<(), Error> {
    if rows_affected == 0 {
        return Err(Error::KeyNotFound);
    }
    Ok(())
}

pub(super) fn item_associated_data(key: &Key) -> Vec<u8> {
    let mut associated_data =
        Vec::with_capacity("paranoid.db.kv.item.v1".len() + 1 + key.as_str().len());
    associated_data.extend_from_slice(b"paranoid.db.kv.item.v1");
    associated_data.push(0);
    associated_data.extend_from_slice(key.as_str().as_bytes());
    associated_data
}

pub(super) fn duration_to_rounded_microseconds(duration: Duration) -> Result<i64, Error> {
    let nanoseconds = duration.as_nanos();
    let microseconds = (nanoseconds / 1_000) + u128::from(!nanoseconds.is_multiple_of(1_000));
    if microseconds > i64::MAX as u128 {
        return Err(Error::TtlTooLarge);
    }
    Ok(microseconds as i64)
}

pub(super) fn migration_index_identifier(
    config: &StoreConfig,
    suffix: &'static str,
) -> super::super::PgIdentifier {
    let object_name =
        migration_object_name(INDEX_KIND, &config.table_name.quoted().to_string(), suffix);
    super::super::PgIdentifier::new(object_name)
        .expect("generated migration index name must be valid")
}

pub(super) fn migration_object_name(kind: &str, table_name: &str, suffix: &str) -> String {
    let hash_input = [kind, table_name, suffix].join("\0");
    let hash = blake3::hash(hash_input.as_bytes());
    format!(
        "{}_{}_{}",
        kind,
        suffix,
        first_8_bytes_as_hex(hash.as_bytes())
    )
}

pub(super) fn first_8_bytes_as_hex(bytes: &[u8; 32]) -> String {
    crate::db::first_8_bytes_as_lower_hex(bytes)
}
