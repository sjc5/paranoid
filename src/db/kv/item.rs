use super::*;

impl<T> Item<T>
where
    T: Plaintext,
{
    /// Creates a typed KV item that stores plaintext serialized payloads.
    pub fn new_plain(store: Store, prefix: KeyPrefix) -> Self {
        Self {
            store,
            prefix,
            codec: ItemCodec::Plain,
            marker: PhantomData,
        }
    }

    /// Creates a typed KV item that stores encrypted serialized payloads.
    pub fn new_encrypted<F>(store: Store, prefix: KeyPrefix, get_keyset: F) -> Self
    where
        F: Fn() -> Result<Arc<Keyset>, CodecError> + Send + Sync + 'static,
    {
        Self {
            store,
            prefix,
            codec: ItemCodec::Encrypted {
                get_keyset: Arc::new(get_keyset),
            },
            marker: PhantomData,
        }
    }

    /// Returns the underlying byte store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Returns the key prefix this item is scoped to.
    pub fn key_prefix(&self) -> &KeyPrefix {
        &self.prefix
    }

    /// Reports whether this item encrypts values before storage.
    pub fn is_encrypted(&self) -> bool {
        matches!(self.codec, ItemCodec::Encrypted { .. })
    }
}
