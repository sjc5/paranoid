use super::*;

impl<'a> AtomicMutationCurrent<'a> {
    /// Returns the live value observed while the key lock is held.
    pub fn live_value(&self) -> Option<&'a [u8]> {
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

impl<'a> AtomicLiveMutationCurrent<'a> {
    /// Returns the live value observed while the key lock is held.
    pub fn live_value(&self) -> &'a [u8] {
        self.live_value
    }

    /// Returns the database statement timestamp observed while the key lock is held.
    pub fn database_timestamp(&self) -> DatabaseTimestampMicros {
        self.database_timestamp
    }
}

impl Ttl {
    /// TTL value for non-expiring rows.
    pub const NO_EXPIRATION: Self = Self {
        positive_duration: None,
    };

    /// Returns a TTL value for non-expiring rows.
    pub const fn no_expiration() -> Self {
        Self::NO_EXPIRATION
    }

    /// Validates a positive TTL.
    pub fn expires_after(duration: Duration) -> Result<Self, Error> {
        if duration.is_zero() {
            return Err(Error::TtlIsZero);
        }
        if duration < MIN_KV_TTL {
            return Err(Error::TtlBelowMinimum {
                minimum: MIN_KV_TTL,
            });
        }
        duration_to_rounded_microseconds(duration)?;
        Ok(Self {
            positive_duration: Some(duration),
        })
    }

    pub(super) fn positive_microseconds(self) -> Result<Option<i64>, Error> {
        let Some(duration) = self.positive_duration else {
            return Ok(None);
        };
        Ok(Some(duration_to_rounded_microseconds(duration)?))
    }
}
