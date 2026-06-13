use super::prelude::*;

/// Reducer plan containing atomic commit work plus post-commit response effects.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitPlan {
    /// Preconditions the commit adapter must enforce at commit time.
    pub(super) preconditions: Vec<Precondition>,
    /// State mutations to commit atomically.
    pub(super) mutations: Vec<Mutation>,
    /// Audit events to commit atomically with the mutations.
    pub(super) audit_events: Vec<AuditEvent>,
    /// Method/plugin work to commit atomically with core mutations.
    pub(super) method_commit_work: Vec<MethodCommitWork>,
    /// Fresh credential secrets to generate and store as MACs atomically.
    pub(super) fresh_credential_secrets: Vec<FreshCredentialSecret>,
    /// Durable effect commands to commit atomically before external delivery.
    pub(super) durable_effects: Vec<DurableEffectCommand>,
    /// Response-local effects to apply only after the commit succeeds.
    pub(super) response_effects: Vec<ResponseEffect>,
}

impl CommitPlan {
    /// Returns whether this plan has work that requires an atomic commit boundary.
    pub fn requires_atomic_commit(&self) -> bool {
        !self.preconditions.is_empty()
            || !self.mutations.is_empty()
            || !self.audit_events.is_empty()
            || !self.method_commit_work.is_empty()
            || !self.fresh_credential_secrets.is_empty()
            || !self.durable_effects.is_empty()
    }

    /// Returns whether this plan has response-local effects.
    pub fn has_response_effects(&self) -> bool {
        !self.response_effects.is_empty()
    }

    /// Validates and separates atomic commit work from post-commit response effects.
    pub(crate) fn try_into_validated_atomic_work_and_response_effects(
        self,
    ) -> Result<(AtomicCommitWork, Vec<ResponseEffect>), Error> {
        let atomic_work = AtomicCommitWork {
            preconditions: self.preconditions,
            mutations: self.mutations,
            audit_events: self.audit_events,
            method_commit_work: self.method_commit_work,
            fresh_credential_secrets: self.fresh_credential_secrets,
            durable_effects: self.durable_effects,
        };
        atomic_work.validate_for_commit()?;
        validate_response_effects_are_commit_backed(&atomic_work, &self.response_effects)?;
        Ok((atomic_work, self.response_effects))
    }

    pub(super) fn merge(&mut self, other: Self) {
        self.preconditions.extend(other.preconditions);
        self.mutations.extend(other.mutations);
        self.audit_events.extend(other.audit_events);
        self.method_commit_work.extend(other.method_commit_work);
        self.fresh_credential_secrets
            .extend(other.fresh_credential_secrets);
        self.durable_effects.extend(other.durable_effects);
        self.response_effects.extend(other.response_effects);
    }
}

fn validate_response_effects_are_commit_backed(
    atomic_work: &AtomicCommitWork,
    response_effects: &[ResponseEffect],
) -> Result<(), Error> {
    for effect in response_effects {
        match effect {
            ResponseEffect::IssueSessionCookie(cookie) => {
                if !session_cookie_response_is_commit_backed(atomic_work, cookie) {
                    return Err(Error::UnbackedSessionCookieResponseEffect);
                }
            }
            ResponseEffect::IssueTrustedDeviceCookie(cookie) => {
                if !trusted_device_cookie_response_is_commit_backed(atomic_work, cookie) {
                    return Err(Error::UnbackedTrustedDeviceCookieResponseEffect);
                }
            }
            ResponseEffect::IssueActiveProofChallengeCookie(cookie) => {
                if !active_proof_challenge_cookie_response_is_commit_backed(atomic_work, cookie) {
                    return Err(Error::UnbackedActiveProofChallengeCookieResponseEffect);
                }
            }
            ResponseEffect::IssueActiveProofContinuationCookie(cookie) => {
                if !active_proof_continuation_cookie_response_is_commit_backed(atomic_work, cookie)
                {
                    return Err(Error::UnbackedActiveProofContinuationCookieResponseEffect);
                }
            }
            ResponseEffect::DeleteSessionCookie
            | ResponseEffect::DeleteTrustedDeviceCookie
            | ResponseEffect::DeleteActiveProofChallengeCookie
            | ResponseEffect::DeleteActiveProofContinuationCookie
            | ResponseEffect::CycleCsrfToken { .. } => {}
        }
    }
    Ok(())
}

fn session_cookie_response_is_commit_backed(
    atomic_work: &AtomicCommitWork,
    cookie: &SessionCookieDraft,
) -> bool {
    if has_session_still_matches_precondition(
        atomic_work,
        &cookie.session_id,
        &cookie.subject_id,
        Some(cookie.secret_version),
    ) {
        return true;
    }

    atomic_work.mutations.iter().any(|mutation| match mutation {
        Mutation::CreateSession(session) => {
            session.session_id.eq(&cookie.session_id)
                && session.subject_id.eq(&cookie.subject_id)
                && session.current_secret_version == cookie.secret_version
        }
        Mutation::RefreshSession {
            session_id,
            new_secret_version,
            ..
        }
        | Mutation::RecordStepUp {
            session_id,
            new_secret_version,
            ..
        } => {
            session_id == &cookie.session_id
                && *new_secret_version == cookie.secret_version
                && has_session_still_matches_precondition(
                    atomic_work,
                    &cookie.session_id,
                    &cookie.subject_id,
                    None,
                )
        }
        Mutation::CreateTrustedDeviceCredential(_)
        | Mutation::RotateTrustedDeviceCredential { .. }
        | Mutation::CreateActiveProofAttempt(_)
        | Mutation::CreateActiveProofChallenge(_)
        | Mutation::RecordWeakProofFailure { .. }
        | Mutation::RecordActiveProofSucceeded { .. }
        | Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily { .. }
        | Mutation::RecordOutOfBandChallengeResent { .. }
        | Mutation::DeleteActiveProofAttempt { .. }
        | Mutation::RevokeSession { .. }
        | Mutation::RevokeTrustedDeviceCredential { .. }
        | Mutation::RaiseSubjectAuthRevocationCutoff { .. }
        | Mutation::RecordCredentialLifecycleActionAuthorized { .. }
        | Mutation::CreateCredentialInstanceMetadata { .. }
        | Mutation::CreateCredentialRecoveryAuthority { .. }
        | Mutation::CreateLifecycleAuthoritySource { .. }
        | Mutation::DeleteLifecycleAuthoritySourcesForSource { .. }
        | Mutation::CreatePendingCredentialLifecycleAction(_)
        | Mutation::RecordCredentialLifecycleActionExecuted { .. }
        | Mutation::SetCredentialLifecycleState { .. }
        | Mutation::ClosePendingCredentialLifecycleAction { .. }
        | Mutation::CreatePendingSubjectLifecycleAction(_)
        | Mutation::ClosePendingSubjectLifecycleAction { .. }
        | Mutation::CreateOutOfBandIdentifierBinding { .. }
        | Mutation::SetOutOfBandIdentifierBindingLifecycleState { .. }
        | Mutation::CreateAdminSupportIntervention(_)
        | Mutation::CloseAdminSupportIntervention { .. } => false,
    })
}

fn active_proof_continuation_cookie_response_is_commit_backed(
    atomic_work: &AtomicCommitWork,
    cookie: &ActiveProofContinuationCookieDraft,
) -> bool {
    atomic_work.mutations.iter().any(|mutation| match mutation {
        Mutation::CreateActiveProofAttempt(attempt) => {
            attempt.attempt_id == cookie.attempt_id
                && attempt.proof_use == cookie.proof_use
                && attempt.subject_id == cookie.subject_id
                && match (&attempt.subject_id, cookie.subject_binding) {
                    (None, ActiveProofContinuationSubjectBinding::NoSubject) => true,
                    (Some(_), ActiveProofContinuationSubjectBinding::RuntimeBoundSubject) => true,
                    _ => false,
                }
                && attempt.expires_at == cookie.attempt_fast_fail_until
                && atomic_work.fresh_credential_secrets.contains(
                    &FreshCredentialSecret::ActiveProofContinuation {
                        attempt_id: cookie.attempt_id.clone(),
                    },
                )
        }
        Mutation::RecordActiveProofSucceeded {
            attempt_id,
            subject_id,
            ..
        } => {
            cookie.proof_use == ProofUse::RecoverOrReplaceCredential
                && attempt_id == &cookie.attempt_id
                && subject_id.as_ref() == cookie.subject_id.as_ref()
                && cookie.subject_binding
                    == ActiveProofContinuationSubjectBinding::VerifiedProofBoundSubject
        }
        Mutation::CreateSession(_)
        | Mutation::RefreshSession { .. }
        | Mutation::RecordStepUp { .. }
        | Mutation::CreateTrustedDeviceCredential(_)
        | Mutation::RotateTrustedDeviceCredential { .. }
        | Mutation::CreateActiveProofChallenge(_)
        | Mutation::RecordWeakProofFailure { .. }
        | Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily { .. }
        | Mutation::RecordOutOfBandChallengeResent { .. }
        | Mutation::DeleteActiveProofAttempt { .. }
        | Mutation::RevokeSession { .. }
        | Mutation::RevokeTrustedDeviceCredential { .. }
        | Mutation::RaiseSubjectAuthRevocationCutoff { .. }
        | Mutation::RecordCredentialLifecycleActionAuthorized { .. }
        | Mutation::CreateCredentialInstanceMetadata { .. }
        | Mutation::CreateCredentialRecoveryAuthority { .. }
        | Mutation::CreateLifecycleAuthoritySource { .. }
        | Mutation::DeleteLifecycleAuthoritySourcesForSource { .. }
        | Mutation::CreatePendingCredentialLifecycleAction(_)
        | Mutation::RecordCredentialLifecycleActionExecuted { .. }
        | Mutation::SetCredentialLifecycleState { .. }
        | Mutation::ClosePendingCredentialLifecycleAction { .. }
        | Mutation::CreatePendingSubjectLifecycleAction(_)
        | Mutation::ClosePendingSubjectLifecycleAction { .. }
        | Mutation::CreateOutOfBandIdentifierBinding { .. }
        | Mutation::SetOutOfBandIdentifierBindingLifecycleState { .. }
        | Mutation::CreateAdminSupportIntervention(_)
        | Mutation::CloseAdminSupportIntervention { .. } => false,
    })
}

fn trusted_device_cookie_response_is_commit_backed(
    atomic_work: &AtomicCommitWork,
    cookie: &TrustedDeviceCookieDraft,
) -> bool {
    atomic_work.mutations.iter().any(|mutation| match mutation {
        Mutation::CreateTrustedDeviceCredential(device) => {
            device.device_credential_id.eq(&cookie.device_credential_id)
                && device.subject_id.eq(&cookie.subject_id)
                && device.current_secret_version == cookie.secret_version
        }
        Mutation::RotateTrustedDeviceCredential {
            device_credential_id,
            new_secret_version,
            ..
        } => {
            device_credential_id == &cookie.device_credential_id
                && *new_secret_version == cookie.secret_version
                && has_trusted_device_still_matches_precondition(
                    atomic_work,
                    &cookie.device_credential_id,
                    &cookie.subject_id,
                    None,
                )
        }
        Mutation::CreateSession(_)
        | Mutation::RefreshSession { .. }
        | Mutation::RecordStepUp { .. }
        | Mutation::CreateActiveProofAttempt(_)
        | Mutation::CreateActiveProofChallenge(_)
        | Mutation::RecordWeakProofFailure { .. }
        | Mutation::RecordActiveProofSucceeded { .. }
        | Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily { .. }
        | Mutation::RecordOutOfBandChallengeResent { .. }
        | Mutation::DeleteActiveProofAttempt { .. }
        | Mutation::RevokeSession { .. }
        | Mutation::RevokeTrustedDeviceCredential { .. }
        | Mutation::RaiseSubjectAuthRevocationCutoff { .. }
        | Mutation::RecordCredentialLifecycleActionAuthorized { .. }
        | Mutation::CreateCredentialInstanceMetadata { .. }
        | Mutation::CreateCredentialRecoveryAuthority { .. }
        | Mutation::CreateLifecycleAuthoritySource { .. }
        | Mutation::DeleteLifecycleAuthoritySourcesForSource { .. }
        | Mutation::CreatePendingCredentialLifecycleAction(_)
        | Mutation::RecordCredentialLifecycleActionExecuted { .. }
        | Mutation::SetCredentialLifecycleState { .. }
        | Mutation::ClosePendingCredentialLifecycleAction { .. }
        | Mutation::CreatePendingSubjectLifecycleAction(_)
        | Mutation::ClosePendingSubjectLifecycleAction { .. }
        | Mutation::CreateOutOfBandIdentifierBinding { .. }
        | Mutation::SetOutOfBandIdentifierBindingLifecycleState { .. }
        | Mutation::CreateAdminSupportIntervention(_)
        | Mutation::CloseAdminSupportIntervention { .. } => false,
    })
}

fn active_proof_challenge_cookie_response_is_commit_backed(
    atomic_work: &AtomicCommitWork,
    cookie: &ActiveProofChallengeCookieDraft,
) -> bool {
    atomic_work.mutations.iter().any(|mutation| match mutation {
        Mutation::CreateActiveProofChallenge(challenge) => {
            challenge.challenge_id == cookie.challenge_id
                && challenge.attempt_id == cookie.attempt_id
                && challenge.proof == cookie.proof
                && challenge.created_at == cookie.issued_at
                && challenge.expires_at == cookie.expires_at
                && challenge.requires_stateless_fast_fail == cookie.requires_stateless_fast_fail()
        }
        Mutation::CreateSession(_)
        | Mutation::RefreshSession { .. }
        | Mutation::RecordStepUp { .. }
        | Mutation::CreateTrustedDeviceCredential(_)
        | Mutation::RotateTrustedDeviceCredential { .. }
        | Mutation::CreateActiveProofAttempt(_)
        | Mutation::RecordWeakProofFailure { .. }
        | Mutation::RecordActiveProofSucceeded { .. }
        | Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily { .. }
        | Mutation::RecordOutOfBandChallengeResent { .. }
        | Mutation::DeleteActiveProofAttempt { .. }
        | Mutation::RevokeSession { .. }
        | Mutation::RevokeTrustedDeviceCredential { .. }
        | Mutation::RaiseSubjectAuthRevocationCutoff { .. }
        | Mutation::RecordCredentialLifecycleActionAuthorized { .. }
        | Mutation::CreateCredentialInstanceMetadata { .. }
        | Mutation::CreateCredentialRecoveryAuthority { .. }
        | Mutation::CreateLifecycleAuthoritySource { .. }
        | Mutation::DeleteLifecycleAuthoritySourcesForSource { .. }
        | Mutation::CreatePendingCredentialLifecycleAction(_)
        | Mutation::RecordCredentialLifecycleActionExecuted { .. }
        | Mutation::SetCredentialLifecycleState { .. }
        | Mutation::ClosePendingCredentialLifecycleAction { .. }
        | Mutation::CreatePendingSubjectLifecycleAction(_)
        | Mutation::ClosePendingSubjectLifecycleAction { .. }
        | Mutation::CreateOutOfBandIdentifierBinding { .. }
        | Mutation::SetOutOfBandIdentifierBindingLifecycleState { .. }
        | Mutation::CreateAdminSupportIntervention(_)
        | Mutation::CloseAdminSupportIntervention { .. } => false,
    })
}

fn has_session_still_matches_precondition(
    atomic_work: &AtomicCommitWork,
    expected_session_id: &SessionId,
    expected_subject_id: &SubjectId,
    expected_current_secret_version: Option<SecretVersion>,
) -> bool {
    atomic_work.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::SessionStillMatches {
                session_id,
                subject_id,
                current_secret_version,
                ..
            } if session_id == expected_session_id
                && subject_id == expected_subject_id
                && expected_current_secret_version
                    .is_none_or(|expected| *current_secret_version == expected)
        )
    })
}

fn has_trusted_device_still_matches_precondition(
    atomic_work: &AtomicCommitWork,
    expected_device_credential_id: &TrustedDeviceCredentialId,
    expected_subject_id: &SubjectId,
    expected_current_secret_version: Option<SecretVersion>,
) -> bool {
    atomic_work.preconditions.iter().any(|precondition| {
        matches!(
            precondition,
            Precondition::TrustedDeviceStillMatches {
                device_credential_id,
                subject_id,
                current_secret_version,
                ..
            } if device_credential_id == expected_device_credential_id
                && subject_id == expected_subject_id
                && expected_current_secret_version
                    .is_none_or(|expected| *current_secret_version == expected)
        )
    })
}

/// Storage-neutral work that must commit as one atomic unit.
///
/// A commit adapter must enforce every precondition against the same state
/// snapshot it mutates. If any precondition fails, none of the mutations, audit
/// events, or durable effect commands may be committed, and response-local
/// effects from the original plan must be discarded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtomicCommitWork {
    /// Preconditions the commit adapter must enforce at commit time.
    pub preconditions: Vec<Precondition>,
    /// State mutations to commit atomically.
    pub mutations: Vec<Mutation>,
    /// Audit events to commit atomically with the mutations.
    pub audit_events: Vec<AuditEvent>,
    /// Method/plugin work to commit atomically with core mutations.
    pub method_commit_work: Vec<MethodCommitWork>,
    /// Fresh credential secrets to generate and store as MACs atomically.
    pub fresh_credential_secrets: Vec<FreshCredentialSecret>,
    /// Durable effect commands to commit atomically before external delivery.
    pub durable_effects: Vec<DurableEffectCommand>,
}

impl AtomicCommitWork {
    /// Returns whether the commit work is empty.
    pub fn is_empty(&self) -> bool {
        self.preconditions.is_empty()
            && self.mutations.is_empty()
            && self.audit_events.is_empty()
            && self.method_commit_work.is_empty()
            && self.fresh_credential_secrets.is_empty()
            && self.durable_effects.is_empty()
    }

    /// Validates adapter-facing atomic-work consistency.
    pub fn validate_for_commit(&self) -> Result<(), Error> {
        self.validate_method_commit_work()?;
        self.validate_fresh_credential_secrets()
    }

    /// Returns the ordered storage transaction contract for this atomic work.
    pub fn transaction_contract(&self) -> Result<AtomicCommitTransactionContract, Error> {
        AtomicCommitTransactionContract::for_atomic_work(self)
    }

    fn validate_method_commit_work(&self) -> Result<(), Error> {
        let mut seen = Vec::with_capacity(self.method_commit_work.len());
        for method_work in &self.method_commit_work {
            method_work.validate()?;
            if seen.contains(method_work.proof()) {
                return Err(Error::DuplicateMethodCommitWorkForProof);
            }
            seen.push(method_work.proof().clone());
        }
        Ok(())
    }

    fn validate_fresh_credential_secrets(&self) -> Result<(), Error> {
        let expected = expected_fresh_credential_secrets_for_mutations(&self.mutations);
        let mut seen_expected = Vec::with_capacity(expected.len());
        for expected_secret in &expected {
            if seen_expected.contains(expected_secret) {
                return Err(Error::DuplicateFreshCredentialSecret);
            }
            seen_expected.push(expected_secret.clone());
        }
        let mut seen = Vec::with_capacity(self.fresh_credential_secrets.len());
        for fresh_secret in &self.fresh_credential_secrets {
            if seen.contains(fresh_secret) {
                return Err(Error::DuplicateFreshCredentialSecret);
            }
            seen.push(fresh_secret.clone());
            if !expected.contains(fresh_secret) {
                return Err(Error::UnexpectedFreshCredentialSecret);
            }
        }
        for expected_secret in expected {
            if !self.fresh_credential_secrets.contains(&expected_secret) {
                return Err(Error::MissingFreshCredentialSecret);
            }
        }
        Ok(())
    }
}

fn expected_fresh_credential_secrets_for_mutations(
    mutations: &[Mutation],
) -> Vec<FreshCredentialSecret> {
    mutations
        .iter()
        .filter_map(|mutation| match mutation {
            Mutation::CreateSession(session) => Some(FreshCredentialSecret::Session {
                session_id: session.session_id.clone(),
                secret_version: session.current_secret_version,
            }),
            Mutation::RefreshSession {
                session_id,
                new_secret_version,
                ..
            }
            | Mutation::RecordStepUp {
                session_id,
                new_secret_version,
                ..
            } => Some(FreshCredentialSecret::Session {
                session_id: session_id.clone(),
                secret_version: *new_secret_version,
            }),
            Mutation::CreateTrustedDeviceCredential(trusted_device) => {
                Some(FreshCredentialSecret::TrustedDevice {
                    device_credential_id: trusted_device.device_credential_id.clone(),
                    secret_version: trusted_device.current_secret_version,
                })
            }
            Mutation::CreateActiveProofAttempt(attempt) => {
                Some(FreshCredentialSecret::ActiveProofContinuation {
                    attempt_id: attempt.attempt_id.clone(),
                })
            }
            Mutation::RotateTrustedDeviceCredential {
                device_credential_id,
                new_secret_version,
                ..
            } => Some(FreshCredentialSecret::TrustedDevice {
                device_credential_id: device_credential_id.clone(),
                secret_version: *new_secret_version,
            }),
            Mutation::CreateActiveProofChallenge(_)
            | Mutation::RecordWeakProofFailure { .. }
            | Mutation::RecordActiveProofSucceeded { .. }
            | Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily { .. }
            | Mutation::RecordOutOfBandChallengeResent { .. }
            | Mutation::DeleteActiveProofAttempt { .. }
            | Mutation::RevokeSession { .. }
            | Mutation::RevokeTrustedDeviceCredential { .. }
            | Mutation::RaiseSubjectAuthRevocationCutoff { .. }
            | Mutation::RecordCredentialLifecycleActionAuthorized { .. }
            | Mutation::CreateCredentialInstanceMetadata { .. }
            | Mutation::CreateCredentialRecoveryAuthority { .. }
            | Mutation::CreateLifecycleAuthoritySource { .. }
            | Mutation::DeleteLifecycleAuthoritySourcesForSource { .. }
            | Mutation::CreatePendingCredentialLifecycleAction(_)
            | Mutation::RecordCredentialLifecycleActionExecuted { .. }
            | Mutation::SetCredentialLifecycleState { .. }
            | Mutation::ClosePendingCredentialLifecycleAction { .. }
            | Mutation::CreatePendingSubjectLifecycleAction(_)
            | Mutation::ClosePendingSubjectLifecycleAction { .. }
            | Mutation::CreateOutOfBandIdentifierBinding { .. }
            | Mutation::SetOutOfBandIdentifierBindingLifecycleState { .. }
            | Mutation::CreateAdminSupportIntervention(_)
            | Mutation::CloseAdminSupportIntervention { .. } => None,
        })
        .collect()
}

/// Fresh credential secret the commit adapter must generate and store as a MAC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FreshCredentialSecret {
    /// Fresh session credential secret.
    Session {
        /// Session that will accept this credential secret.
        session_id: SessionId,
        /// Credential version that will be stored as current.
        secret_version: SecretVersion,
    },
    /// Fresh trusted-device credential secret.
    TrustedDevice {
        /// Trusted-device credential that will accept this credential secret.
        device_credential_id: TrustedDeviceCredentialId,
        /// Credential version that will be stored as current.
        secret_version: SecretVersion,
    },
    /// Fresh active-proof continuation credential secret.
    ActiveProofContinuation {
        /// Active-proof attempt that will accept this continuation secret.
        attempt_id: ActiveProofAttemptId,
    },
}
