use super::*;

impl OnceManualRunClaim {
    /// Returns the run-once task key.
    pub fn once_key(&self) -> &OnceKey {
        &self.once_key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        self.mutex_claim.holder_id()
    }

    /// Returns this claim's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.mutex_claim.fencing_token()
    }

    /// Returns the claim expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.mutex_claim.expires_at_unix_microseconds()
    }
}

impl OnceRunClaimSnapshot {
    /// Returns the run-once task key.
    pub fn once_key(&self) -> &OnceKey {
        &self.once_key
    }

    /// Returns the holder identifier.
    pub fn holder_id(&self) -> &HolderId {
        &self.holder_id
    }

    /// Returns this claim's fencing token.
    pub fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the claim expiration timestamp as Unix microseconds.
    pub fn expires_at_unix_microseconds(&self) -> i64 {
        self.expires_at_unix_microseconds
    }
}

impl OnceCompletion {
    /// Returns the completion timestamp as Unix microseconds.
    pub fn finished_at_unix_microseconds(&self) -> i64 {
        self.finished_at_unix_microseconds
    }

    /// Returns the holder identifier that completed the task.
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Returns the fencing token held by the completing holder.
    pub fn fencing_token(&self) -> i64 {
        self.fencing_token
    }
}
