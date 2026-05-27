use super::*;

impl Key {
    /// Validates and joins key parts into a persisted KV key.
    pub fn from_parts<S, I>(parts: I) -> Result<Self, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        Ok(Self(build_key_from_parts(parts)?))
    }

    /// Validates and joins suffix parts onto an already validated key prefix.
    pub fn from_prefix_and_parts<S, I>(prefix: &KeyPrefix, suffix_parts: I) -> Result<Self, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = build_key_from_prefix_and_parts(prefix, suffix_parts)?;
        Ok(Self(key))
    }

    /// Returns the persisted key text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl KeyPrefix {
    /// Validates and joins key parts into a persisted KV key prefix.
    pub fn from_parts<S, I>(parts: I) -> Result<Self, Error>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let key = build_key_from_parts(parts)?;
        Ok(Self(key))
    }

    /// Returns the persisted prefix text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether a full persisted key belongs to this prefix.
    pub fn contains_key(&self, key: &Key) -> bool {
        key.as_str().starts_with(self.as_str())
    }
}

impl BytesSetEntry {
    /// Creates a multi-set entry from a validated key and value bytes.
    pub fn new<V>(key: Key, value: V) -> Self
    where
        V: Into<Vec<u8>>,
    {
        Self {
            key,
            value: value.into(),
        }
    }

    /// Returns the entry key.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Returns the entry value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl DatabaseTimestampMicros {
    /// Returns the Unix timestamp in microseconds.
    pub fn as_i64(self) -> i64 {
        self.0
    }
}

impl<T> fmt::Debug for Item<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("store", &self.store)
            .field("prefix", &self.prefix)
            .field(
                "is_encrypted",
                &matches!(self.codec, ItemCodec::Encrypted { .. }),
            )
            .finish_non_exhaustive()
    }
}

impl<'a, T> ItemAtomicMutationCurrent<'a, T> {
    /// Returns the live typed value observed while the key lock is held.
    pub fn live_value(&self) -> Option<&'a T> {
        self.live_value
    }

    /// Reports whether a live value exists while the key lock is held.
    pub fn has_live_value(&self) -> bool {
        self.live_value.is_some()
    }

    /// Returns the database statement timestamp observed while the key lock is held.
    pub fn database_timestamp(&self) -> DatabaseTimestampMicros {
        self.database_timestamp
    }
}

impl<'a, T> ItemAtomicLiveMutationCurrent<'a, T> {
    /// Returns the live typed value observed while the key lock is held.
    pub fn live_value(&self) -> &'a T {
        self.live_value
    }

    /// Returns the database statement timestamp observed while the key lock is held.
    pub fn database_timestamp(&self) -> DatabaseTimestampMicros {
        self.database_timestamp
    }
}
