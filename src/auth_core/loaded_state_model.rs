use super::prelude::*;

/// Loaded state snapshot supplied by the storage and transport adapters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoadedState {
    /// Decoded session cookie draft, if the request carried one.
    pub session_cookie: Option<SessionCookieDraft>,
    /// Authoritative session record, if the adapter loaded one.
    pub session_record: Option<SessionRecord>,
    /// Result of comparing the session cookie secret against the loaded session's stored MACs.
    pub session_secret_match: Option<LoadedSessionSecretMatch>,
    /// Decoded trusted-device cookie draft, if the request carried one.
    pub trusted_device_cookie: Option<TrustedDeviceCookieDraft>,
    /// Authoritative trusted-device credential record, if the adapter loaded one.
    pub trusted_device_record: Option<TrustedDeviceCredentialRecord>,
    /// Result of comparing the trusted-device cookie secret against the loaded credential's stored MACs.
    pub trusted_device_secret_match: Option<LoadedTrustedDeviceSecretMatch>,
    /// Per-subject revocation states loaded for this snapshot.
    pub subject_revocations: LoadedSubjectRevocations,
    /// Authoritative active-proof attempt record, if the adapter loaded one.
    pub active_proof_attempt_record: Option<ActiveProofAttemptRecord>,
    /// Result of comparing the active-proof continuation cookie secret against the attempt's stored MAC.
    pub active_proof_continuation_secret_match: Option<LoadedActiveProofContinuationSecretMatch>,
    /// Authoritative active-proof challenge record, if the adapter loaded one.
    pub active_proof_challenge_record: Option<ActiveProofChallengeRecord>,
}

/// Result of comparing a client credential secret with stored MACs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StoredSecretMatch {
    /// The presented secret matched the current stored MAC.
    Current,
    /// The presented secret matched the previous stored MAC inside the race grace window.
    PreviousWithinGrace,
    /// The presented secret matched the previous stored MAC after the race grace window.
    PreviousAfterGrace,
    /// The presented secret did not match any stored MAC for the loaded record.
    Unknown,
}

impl StoredSecretMatch {
    pub(super) fn is_accepted(self) -> bool {
        matches!(self, Self::Current | Self::PreviousWithinGrace)
    }
}

/// Evidence that a presented session secret was checked against one session row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedSessionSecretMatch {
    session_id: SessionId,
    kind: StoredSecretMatch,
}

impl LoadedSessionSecretMatch {
    /// Creates session secret-match evidence tied to the checked session id.
    pub fn new(session_id: SessionId, kind: StoredSecretMatch) -> Self {
        Self { session_id, kind }
    }

    /// Returns the session id whose stored MACs were checked.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the match classification.
    pub const fn kind(&self) -> StoredSecretMatch {
        self.kind
    }
}

/// Evidence that a presented trusted-device secret was checked against one credential row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedTrustedDeviceSecretMatch {
    device_credential_id: TrustedDeviceCredentialId,
    kind: StoredSecretMatch,
}

/// Evidence that a presented active-proof continuation secret was checked against one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedActiveProofContinuationSecretMatch {
    attempt_id: ActiveProofAttemptId,
    kind: StoredSecretMatch,
}

impl LoadedActiveProofContinuationSecretMatch {
    /// Creates active-proof continuation secret-match evidence tied to the checked attempt id.
    pub fn new(attempt_id: ActiveProofAttemptId, kind: StoredSecretMatch) -> Self {
        Self { attempt_id, kind }
    }

    /// Returns the active-proof attempt id whose stored MAC was checked.
    pub fn attempt_id(&self) -> &ActiveProofAttemptId {
        &self.attempt_id
    }

    /// Returns the match classification.
    pub const fn kind(&self) -> StoredSecretMatch {
        self.kind
    }
}

impl LoadedTrustedDeviceSecretMatch {
    /// Creates trusted-device secret-match evidence tied to the checked credential id.
    pub fn new(device_credential_id: TrustedDeviceCredentialId, kind: StoredSecretMatch) -> Self {
        Self {
            device_credential_id,
            kind,
        }
    }

    /// Returns the trusted-device credential id whose stored MACs were checked.
    pub fn device_credential_id(&self) -> &TrustedDeviceCredentialId {
        &self.device_credential_id
    }

    /// Returns the match classification.
    pub const fn kind(&self) -> StoredSecretMatch {
        self.kind
    }
}

/// Server-side session row as understood by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    /// Session id.
    pub session_id: SessionId,
    /// Subject id that owns the session.
    pub subject_id: SubjectId,
    /// Trusted-device credential that produced this session, if any.
    pub device_credential_id: Option<TrustedDeviceCredentialId>,
    /// Current accepted session credential version.
    pub current_secret_version: SecretVersion,
    /// Previous credential version accepted only for races.
    pub previous_secret_version: Option<SecretVersion>,
    /// Last time the previous credential version may be accepted.
    pub previous_secret_accept_until: Option<UnixSeconds>,
    /// Time the session was created.
    pub created_at: UnixSeconds,
    /// Time the session was last refreshed.
    pub refreshed_at: UnixSeconds,
    /// Time the session expires unless refreshed.
    pub expires_at: UnixSeconds,
    /// Freshness deadline for sensitive operations.
    pub step_up_expires_at: Option<UnixSeconds>,
    /// Revocation timestamp, if the session has been revoked.
    pub revoked_at: Option<UnixSeconds>,
}

/// Server-side trusted-device credential row as understood by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedDeviceCredentialRecord {
    /// Trusted-device credential id.
    pub device_credential_id: TrustedDeviceCredentialId,
    /// Subject id that owns the credential.
    pub subject_id: SubjectId,
    /// Current accepted device credential version.
    pub current_secret_version: SecretVersion,
    /// Previous credential version accepted only for races.
    pub previous_secret_version: Option<SecretVersion>,
    /// Last time the previous credential version may be accepted.
    pub previous_secret_accept_until: Option<UnixSeconds>,
    /// Time the trusted-device credential was created.
    pub created_at: UnixSeconds,
    /// Time the trusted-device credential was last used.
    pub last_used_at: UnixSeconds,
    /// Absolute credential expiration.
    pub expires_at: UnixSeconds,
    /// Deadline for silent session revival.
    pub silent_revival_until: UnixSeconds,
    /// Revocation timestamp, if the credential has been revoked.
    pub revoked_at: Option<UnixSeconds>,
    /// Display label captured by the adapter.
    pub display_label: Option<String>,
}

/// Per-subject revocation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectRevocationState {
    /// Auth records created at or before this cutoff are no longer valid.
    pub revoke_records_created_at_or_before: UnixSeconds,
}

/// Per-subject revocation states loaded into one reducer snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoadedSubjectRevocations {
    loaded_subjects: Vec<LoadedSubjectRevocation>,
}

impl LoadedSubjectRevocations {
    /// Creates an empty set of loaded subject revocations.
    pub fn not_loaded() -> Self {
        Self::default()
    }

    /// Creates a loaded revocation set for one subject.
    pub fn loaded(subject_id: SubjectId, revocation: Option<SubjectRevocationState>) -> Self {
        Self {
            loaded_subjects: vec![LoadedSubjectRevocation {
                subject_id,
                revocation,
            }],
        }
    }

    /// Adds loaded revocation state for one subject.
    pub fn push_loaded(
        &mut self,
        subject_id: SubjectId,
        revocation: Option<SubjectRevocationState>,
    ) -> Result<(), Error> {
        if let Some(existing) = self
            .loaded_subjects
            .iter()
            .find(|loaded| loaded.subject_id == subject_id)
        {
            if existing.revocation == revocation {
                return Ok(());
            }
            return Err(Error::LoadedStateContradiction(
                "subject revocation state was loaded more than once with different values",
            ));
        }
        self.loaded_subjects.push(LoadedSubjectRevocation {
            subject_id,
            revocation,
        });
        Ok(())
    }

    /// Returns all loaded subject revocation entries.
    pub fn loaded_subjects(&self) -> &[LoadedSubjectRevocation] {
        &self.loaded_subjects
    }

    pub(super) fn required_revocation_for_subject(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Option<&SubjectRevocationState>, Error> {
        self.loaded_subjects
            .iter()
            .find(|loaded| loaded.subject_id == *subject_id)
            .map(|loaded| loaded.revocation.as_ref())
            .ok_or(Error::LoadedStateContradiction(
                "subject revocation state was not loaded for required subject",
            ))
    }

    pub(super) fn optional_revocation_for_subject_if_loaded(
        &self,
        subject_id: &SubjectId,
    ) -> Result<Option<&SubjectRevocationState>, Error> {
        Ok(self
            .loaded_subjects
            .iter()
            .find(|loaded| loaded.subject_id == *subject_id)
            .and_then(|loaded| loaded.revocation.as_ref()))
    }
}

/// Subject revocation state loaded for one subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedSubjectRevocation {
    /// Subject this loaded state belongs to.
    subject_id: SubjectId,
    /// Revocation state, if any exists for the subject.
    revocation: Option<SubjectRevocationState>,
}

impl LoadedSubjectRevocation {
    /// Returns the subject this loaded state belongs to.
    pub fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }

    /// Returns the loaded revocation state, if any exists.
    pub fn revocation(&self) -> Option<&SubjectRevocationState> {
        self.revocation.as_ref()
    }
}

/// Decoded session cookie payload before encryption is applied by the web adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCookieDraft {
    /// Session id.
    pub session_id: SessionId,
    /// Subject id copied into the encrypted cookie for fast local decisions.
    pub subject_id: SubjectId,
    /// Client-held credential version.
    pub secret_version: SecretVersion,
    /// Fast-fail session expiry copied from the authoritative record.
    pub session_fast_fail_until: UnixSeconds,
    /// Optional safe-read cache deadline minted only after authoritative validation.
    pub safe_read_valid_until: Option<UnixSeconds>,
    /// Optional step-up freshness deadline copied from the authoritative record.
    pub step_up_valid_until: Option<UnixSeconds>,
}

/// Decoded trusted-device cookie payload before encryption is applied by the web adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedDeviceCookieDraft {
    /// Trusted-device credential id.
    pub device_credential_id: TrustedDeviceCredentialId,
    /// Subject id copied into the encrypted cookie for fast local decisions.
    pub subject_id: SubjectId,
    /// Client-held credential version.
    pub secret_version: SecretVersion,
    /// Fast-fail absolute device credential expiry.
    pub device_fast_fail_until: UnixSeconds,
    /// Fast-fail silent-revival deadline.
    pub silent_revival_fast_fail_until: UnixSeconds,
}

/// How an active-proof continuation cookie became subject-bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActiveProofContinuationSubjectBinding {
    /// The continuation does not carry a subject.
    NoSubject,
    /// The continuation was started from an already-known runtime subject context.
    RuntimeBoundSubject,
    /// The continuation was reissued after a proof bound or confirmed the subject.
    VerifiedProofBoundSubject,
}

/// Decoded active-proof continuation cookie payload before encryption is applied by the web adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofContinuationCookieDraft {
    /// Active-proof attempt continued by this cookie.
    pub attempt_id: ActiveProofAttemptId,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
    /// Subject copied into the encrypted cookie when the attempt is already subject-bound.
    pub subject_id: Option<SubjectId>,
    /// Whether the subject binding came from a verified proof or ambient runtime context.
    pub subject_binding: ActiveProofContinuationSubjectBinding,
    /// Fast-fail attempt expiry copied from the authoritative record.
    pub attempt_fast_fail_until: UnixSeconds,
}

impl ActiveProofContinuationCookieDraft {
    pub(crate) fn validate_subject_binding(&self) -> Result<(), Error> {
        match (&self.subject_id, self.subject_binding) {
            (None, ActiveProofContinuationSubjectBinding::NoSubject)
            | (Some(_), ActiveProofContinuationSubjectBinding::RuntimeBoundSubject)
            | (Some(_), ActiveProofContinuationSubjectBinding::VerifiedProofBoundSubject) => Ok(()),
            _ => Err(Error::InvalidActiveProofContinuationCookiePayload),
        }
    }

    pub(crate) fn validate_unexpired_before_state_load(
        &self,
        now: UnixSeconds,
    ) -> Result<(), Error> {
        if now >= self.attempt_fast_fail_until {
            return Err(Error::ActiveProofAttemptNotOpen);
        }
        Ok(())
    }

    pub(crate) fn validate_for_use_before_state_load(
        &self,
        now: UnixSeconds,
        proof_use: ProofUse,
    ) -> Result<(), Error> {
        if self.proof_use != proof_use {
            return Err(Error::InvalidActiveProofContinuationCookiePayload);
        }
        self.validate_unexpired_before_state_load(now)
    }
}
