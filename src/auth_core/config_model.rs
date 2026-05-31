use super::*;

/// Core lifecycle configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// How long a freshly authenticated session remains alive.
    pub short_session_lifetime: DurationSeconds,
    /// Final portion of the session lifetime where authoritative validation refreshes the session.
    pub session_refresh_window: DurationSeconds,
    /// How long a recently used trusted device may silently revive a dead session.
    pub trusted_device_silent_revival_lifetime: DurationSeconds,
    /// Absolute lifetime of a trusted device credential.
    pub trusted_device_credential_lifetime: DurationSeconds,
    /// How long a completed step-up proof remains fresh for sensitive requests.
    pub step_up_lifetime: DurationSeconds,
    /// Optional bounded authoritative-validation cache for safe reads only.
    pub safe_read_cache_lifetime: Option<DurationSeconds>,
    /// How long an immediately previous credential secret remains acceptable for races.
    pub stale_secret_grace_lifetime: DurationSeconds,
    /// How long an active-proof attempt may remain open.
    pub active_proof_attempt_lifetime: DurationSeconds,
    /// How long an out-of-band challenge may remain open.
    pub out_of_band_challenge_lifetime: DurationSeconds,
    /// User-visible resends allowed for one out-of-band challenge.
    pub max_out_of_band_challenge_resends_per_challenge: u32,
    /// Weak proof failures allowed before the attempt is hard-deleted.
    pub max_weak_proof_failures_per_attempt: u32,
    /// Cheap gate required before unauthenticated active-proof challenge issue.
    pub unauthenticated_challenge_issue_preflight_gate: WeakProofGateSummary,
    /// Proof-stack policy for final auth transitions.
    pub proof_policy: ProofPolicy,
}

impl Config {
    /// Validates relationships among lifecycle durations.
    pub fn validate(&self) -> Result<(), Error> {
        if self.short_session_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "short_session_lifetime must be non-zero",
            ));
        }
        if self.session_refresh_window >= self.short_session_lifetime {
            return Err(Error::InvalidConfig(
                "session_refresh_window must be shorter than short_session_lifetime",
            ));
        }
        if self.trusted_device_silent_revival_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "trusted_device_silent_revival_lifetime must be non-zero",
            ));
        }
        if self.trusted_device_credential_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "trusted_device_credential_lifetime must be non-zero",
            ));
        }
        if self.step_up_lifetime.is_zero() {
            return Err(Error::InvalidConfig("step_up_lifetime must be non-zero"));
        }
        if self.active_proof_attempt_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "active_proof_attempt_lifetime must be non-zero",
            ));
        }
        if self.out_of_band_challenge_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "out_of_band_challenge_lifetime must be non-zero",
            ));
        }
        if self.max_weak_proof_failures_per_attempt == 0 {
            return Err(Error::InvalidConfig(
                "max_weak_proof_failures_per_attempt must be non-zero",
            ));
        }
        self.proof_policy.validate()?;
        if let Some(safe_read_cache_lifetime) = self.safe_read_cache_lifetime
            && safe_read_cache_lifetime.is_zero()
        {
            return Err(Error::InvalidConfig(
                "safe_read_cache_lifetime must be None or non-zero",
            ));
        }
        Ok(())
    }
}
