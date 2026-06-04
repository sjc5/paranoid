use std::collections::BTreeMap;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum InMemoryCommitError {
    PreconditionFailed(&'static str),
    DuplicateRecord(&'static str),
    MutationTargetMissing(&'static str),
    ResponseMaterializationFailed(&'static str),
    CoreCommitWorkInvalid(Error),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct InMemoryCommitStore {
    pub(super) sessions: BTreeMap<SessionId, SessionRecord>,
    pub(super) trusted_devices: BTreeMap<TrustedDeviceCredentialId, TrustedDeviceCredentialRecord>,
    pub(super) active_proof_attempts: BTreeMap<ActiveProofAttemptId, ActiveProofAttemptRecord>,
    pub(super) active_proof_challenges:
        BTreeMap<ActiveProofChallengeId, ActiveProofChallengeRecord>,
    pub(super) credential_instances: BTreeMap<VerifiedProofSourceId, CredentialInstanceMetadata>,
    pub(super) pending_credential_lifecycle_actions:
        BTreeMap<PendingCredentialLifecycleActionId, PendingCredentialLifecycleActionRecord>,
    pub(super) pending_subject_lifecycle_actions:
        BTreeMap<PendingSubjectLifecycleActionId, PendingSubjectLifecycleActionRecord>,
    pub(super) subject_revocations: BTreeMap<SubjectId, SubjectRevocationState>,
    pub(super) audit_events: Vec<AuditEvent>,
    pub(super) method_commit_work: Vec<MethodCommitWork>,
    pub(super) durable_effects: Vec<DurableEffectCommand>,
}

impl InMemoryCommitStore {
    pub(super) fn loaded_for_session_cookie(
        &self,
        session_cookie: SessionCookieDraft,
        now: UnixSeconds,
    ) -> LoadedState {
        let session_record = self.sessions.get(&session_cookie.session_id).cloned();
        let session_secret_match = session_record.as_ref().map(|record| {
            LoadedSessionSecretMatch::new(
                record.session_id.clone(),
                classify_session_cookie_secret(&session_cookie, record, now),
            )
        });
        let subject_id_for_revocation = session_record
            .as_ref()
            .map(|record| record.subject_id.clone())
            .unwrap_or_else(|| session_cookie.subject_id.clone());
        LoadedState {
            subject_revocations: LoadedSubjectRevocations::loaded(
                subject_id_for_revocation.clone(),
                self.subject_revocations
                    .get(&subject_id_for_revocation)
                    .cloned(),
            ),
            session_cookie: Some(session_cookie),
            session_record,
            session_secret_match,
            ..LoadedState::default()
        }
    }

    pub(super) fn loaded_for_session_cookie_and_attempt(
        &self,
        session_cookie: SessionCookieDraft,
        now: UnixSeconds,
        attempt_id: &ActiveProofAttemptId,
    ) -> LoadedState {
        let mut loaded = self.loaded_for_session_cookie(session_cookie, now);
        loaded.active_proof_attempt_record = self.active_proof_attempts.get(attempt_id).cloned();
        loaded
    }

    pub(super) fn loaded_for_trusted_device_cookie(
        &self,
        trusted_device_cookie: TrustedDeviceCookieDraft,
        now: UnixSeconds,
    ) -> LoadedState {
        let trusted_device_record = self
            .trusted_devices
            .get(&trusted_device_cookie.device_credential_id)
            .cloned();
        let trusted_device_secret_match = trusted_device_record.as_ref().map(|record| {
            LoadedTrustedDeviceSecretMatch::new(
                record.device_credential_id.clone(),
                classify_trusted_device_cookie_secret(&trusted_device_cookie, record, now),
            )
        });
        let subject_id_for_revocation = trusted_device_record
            .as_ref()
            .map(|record| record.subject_id.clone())
            .unwrap_or_else(|| trusted_device_cookie.subject_id.clone());
        LoadedState {
            subject_revocations: LoadedSubjectRevocations::loaded(
                subject_id_for_revocation.clone(),
                self.subject_revocations
                    .get(&subject_id_for_revocation)
                    .cloned(),
            ),
            trusted_device_cookie: Some(trusted_device_cookie),
            trusted_device_record,
            trusted_device_secret_match,
            ..LoadedState::default()
        }
    }

    pub(super) fn loaded_for_trusted_device_cookie_and_attempt(
        &self,
        trusted_device_cookie: TrustedDeviceCookieDraft,
        now: UnixSeconds,
        attempt_id: &ActiveProofAttemptId,
    ) -> LoadedState {
        let mut loaded = self.loaded_for_trusted_device_cookie(trusted_device_cookie, now);
        loaded.active_proof_attempt_record = self.active_proof_attempts.get(attempt_id).cloned();
        loaded
    }

    pub(super) fn loaded_for_session_and_trusted_device_cookies(
        &self,
        session_cookie: SessionCookieDraft,
        trusted_device_cookie: TrustedDeviceCookieDraft,
        now: UnixSeconds,
    ) -> LoadedState {
        let mut loaded = self.loaded_for_session_cookie(session_cookie, now);
        let trusted_device_loaded =
            self.loaded_for_trusted_device_cookie(trusted_device_cookie, now);
        loaded.trusted_device_cookie = trusted_device_loaded.trusted_device_cookie;
        loaded.trusted_device_record = trusted_device_loaded.trusted_device_record;
        loaded.trusted_device_secret_match = trusted_device_loaded.trusted_device_secret_match;
        for loaded_subject in trusted_device_loaded.subject_revocations.loaded_subjects() {
            loaded
                .subject_revocations
                .push_loaded(
                    loaded_subject.subject_id().clone(),
                    loaded_subject.revocation().cloned(),
                )
                .expect("merged loaded subject revocation state");
        }
        loaded
    }

    pub(super) fn loaded_for_attempt(&self, attempt_id: &ActiveProofAttemptId) -> LoadedState {
        let active_proof_attempt_record = self.active_proof_attempts.get(attempt_id).cloned();
        let subject_revocations = active_proof_attempt_record
            .as_ref()
            .and_then(|attempt| attempt.subject_id.as_ref())
            .map(|subject_id| {
                LoadedSubjectRevocations::loaded(
                    subject_id.clone(),
                    self.subject_revocations.get(subject_id).cloned(),
                )
            })
            .unwrap_or_default();
        LoadedState {
            subject_revocations,
            active_proof_attempt_record,
            ..LoadedState::default()
        }
    }

    pub(super) fn loaded_for_attempt_and_challenge(
        &self,
        attempt_id: &ActiveProofAttemptId,
        challenge_id: &ActiveProofChallengeId,
    ) -> LoadedState {
        let mut loaded = self.loaded_for_attempt(attempt_id);
        loaded.active_proof_challenge_record =
            self.active_proof_challenges.get(challenge_id).cloned();
        loaded
    }

    pub(super) fn commit_plan(
        &mut self,
        plan: CommitPlan,
    ) -> Result<Vec<ResponseEffect>, InMemoryCommitError> {
        let (atomic_work, response_effects) = plan
            .try_into_validated_atomic_work_and_response_effects()
            .map_err(InMemoryCommitError::CoreCommitWorkInvalid)?;
        if !atomic_work.is_empty() {
            self.commit_atomic_work(atomic_work)?;
        }
        Ok(response_effects)
    }

    pub(super) fn commit_atomic_work(
        &mut self,
        work: AtomicCommitWork,
    ) -> Result<(), InMemoryCommitError> {
        work.validate_for_commit()
            .map_err(InMemoryCommitError::CoreCommitWorkInvalid)?;
        self.ensure_preconditions(&work.preconditions)?;
        let mut next = self.clone();
        for mutation in work.mutations {
            next.apply_mutation(mutation)?;
        }
        next.audit_events.extend(work.audit_events);
        next.method_commit_work.extend(work.method_commit_work);
        next.durable_effects.extend(work.durable_effects);
        *self = next;
        Ok(())
    }

    pub(super) fn ensure_preconditions(
        &self,
        preconditions: &[Precondition],
    ) -> Result<(), InMemoryCommitError> {
        for precondition in preconditions {
            self.ensure_precondition(precondition)?;
        }
        Ok(())
    }

    pub(super) fn ensure_precondition(
        &self,
        precondition: &Precondition,
    ) -> Result<(), InMemoryCommitError> {
        match precondition {
            Precondition::SessionStillMatches {
                session_id,
                subject_id,
                now,
                current_secret_version,
            } => {
                let session = self.sessions.get(session_id).ok_or(
                    InMemoryCommitError::PreconditionFailed("session still matches"),
                )?;
                if session.revoked_at.is_some()
                    || *now >= session.expires_at
                    || session.subject_id != *subject_id
                    || session.current_secret_version != *current_secret_version
                    || self
                        .subject_revocations
                        .get(subject_id)
                        .is_some_and(|revocation| {
                            session.created_at <= revocation.revoke_records_created_at_or_before
                        })
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "session still matches",
                    ));
                }
            }
            Precondition::TrustedDeviceStillMatches {
                device_credential_id,
                subject_id,
                now,
                current_secret_version,
            } => {
                let trusted_device = self.trusted_devices.get(device_credential_id).ok_or(
                    InMemoryCommitError::PreconditionFailed("trusted device still matches"),
                )?;
                if trusted_device.revoked_at.is_some()
                    || *now >= trusted_device.expires_at
                    || trusted_device.subject_id != *subject_id
                    || trusted_device.current_secret_version != *current_secret_version
                    || self
                        .subject_revocations
                        .get(subject_id)
                        .is_some_and(|revocation| {
                            trusted_device.created_at
                                <= revocation.revoke_records_created_at_or_before
                        })
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "trusted device still matches",
                    ));
                }
            }
            Precondition::SessionBelongsToSubject {
                session_id,
                subject_id,
            } => {
                let session = self.sessions.get(session_id).ok_or(
                    InMemoryCommitError::PreconditionFailed("session belongs to subject"),
                )?;
                if session.revoked_at.is_some() || session.subject_id != *subject_id {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "session belongs to subject",
                    ));
                }
            }
            Precondition::TrustedDeviceBelongsToSubject {
                device_credential_id,
                subject_id,
            } => {
                let trusted_device = self.trusted_devices.get(device_credential_id).ok_or(
                    InMemoryCommitError::PreconditionFailed("trusted device belongs to subject"),
                )?;
                if trusted_device.revoked_at.is_some() || trusted_device.subject_id != *subject_id {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "trusted device belongs to subject",
                    ));
                }
            }
            Precondition::ActiveProofAttemptStillOpen {
                attempt_id,
                now,
                observed_subject_id,
                observed_satisfied_proofs,
                observed_weak_proof_failures,
                subject_id_for_revocation,
                created_at,
            } => {
                let attempt = self.active_proof_attempts.get(attempt_id).ok_or(
                    InMemoryCommitError::PreconditionFailed("active proof attempt still open"),
                )?;
                if attempt.closed_at.is_some()
                    || *now >= attempt.expires_at
                    || attempt.created_at != *created_at
                    || attempt.subject_id != *observed_subject_id
                    || attempt.satisfied_proofs != *observed_satisfied_proofs
                    || attempt.weak_proof_failures != *observed_weak_proof_failures
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "active proof attempt still open",
                    ));
                }
                if let Some(subject_id) = subject_id_for_revocation {
                    if attempt
                        .subject_id
                        .as_ref()
                        .is_some_and(|attempt_subject_id| attempt_subject_id != subject_id)
                    {
                        return Err(InMemoryCommitError::PreconditionFailed(
                            "active proof attempt still open",
                        ));
                    }
                    if self
                        .subject_revocations
                        .get(subject_id)
                        .is_some_and(|revocation| {
                            *created_at <= revocation.revoke_records_created_at_or_before
                        })
                    {
                        return Err(InMemoryCommitError::PreconditionFailed(
                            "active proof attempt still open",
                        ));
                    }
                }
            }
            Precondition::ActiveProofChallengeStillOpen { challenge_id, now } => {
                let challenge = self.active_proof_challenges.get(challenge_id).ok_or(
                    InMemoryCommitError::PreconditionFailed("active proof challenge still open"),
                )?;
                if challenge.closed_at.is_some() || *now >= challenge.expires_at {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "active proof challenge still open",
                    ));
                }
            }
            Precondition::OutOfBandChallengeResendStillAllowed {
                challenge_id,
                now,
                observed_resend_count,
                observed_used_delivery_idempotency_keys,
            } => {
                let challenge = self.active_proof_challenges.get(challenge_id).ok_or(
                    InMemoryCommitError::PreconditionFailed(
                        "out of band challenge resend still allowed",
                    ),
                )?;
                if challenge.closed_at.is_some()
                    || *now >= challenge.expires_at
                    || challenge.resend_count != *observed_resend_count
                    || challenge.used_delivery_idempotency_keys
                        != *observed_used_delivery_idempotency_keys
                    || challenge.resend_count >= challenge.max_resends
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "out of band challenge resend still allowed",
                    ));
                }
            }
            Precondition::NoOpenOutOfBandChallengeForDedupeKey {
                challenge_dedupe_key,
                now,
            } => {
                if self.active_proof_challenges.values().any(|challenge| {
                    challenge.challenge_dedupe_key.as_ref() == Some(challenge_dedupe_key)
                        && challenge.closed_at.is_none()
                        && *now < challenge.expires_at
                }) {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "no open out of band challenge for dedupe key",
                    ));
                }
            }
            Precondition::CredentialInstanceStillActive {
                credential_instance_id,
                subject_id,
            } => {
                let credential = self
                    .credential_instances
                    .get(credential_instance_id)
                    .ok_or(InMemoryCommitError::PreconditionFailed(
                        "credential instance still active",
                    ))?;
                if credential.subject_id() != subject_id || !credential.can_produce_new_proofs() {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "credential instance still active",
                    ));
                }
            }
            Precondition::NoOpenPendingCredentialLifecycleActionForTarget {
                target_credential_instance_id,
                action,
                now,
            } => {
                if self
                    .pending_credential_lifecycle_actions
                    .values()
                    .any(|pending_action| {
                        pending_action.target_credential_instance_id
                            == *target_credential_instance_id
                            && pending_action.action == *action
                            && pending_action.closed_at.is_none()
                            && *now < pending_action.expires_at
                    })
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "no open pending credential lifecycle action for target",
                    ));
                }
            }
            Precondition::PendingCredentialLifecycleActionStillExecutable {
                pending_action_id,
                subject_id,
                target_credential_instance_id,
                action,
                now,
            } => {
                let pending_action = self
                    .pending_credential_lifecycle_actions
                    .get(pending_action_id)
                    .ok_or(InMemoryCommitError::PreconditionFailed(
                        "pending credential lifecycle action still executable",
                    ))?;
                if pending_action.subject_id != *subject_id
                    || pending_action.target_credential_instance_id
                        != *target_credential_instance_id
                    || pending_action.action != *action
                    || !pending_action.is_executable_at(*now)
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "pending credential lifecycle action still executable",
                    ));
                }
            }
            Precondition::PendingCredentialLifecycleActionStillCancellableForTarget {
                pending_action_id,
                subject_id,
                target_credential_instance_id,
                action,
                now,
            } => {
                let pending_action = self
                    .pending_credential_lifecycle_actions
                    .get(pending_action_id)
                    .ok_or(InMemoryCommitError::PreconditionFailed(
                        "pending credential lifecycle action still cancellable for target",
                    ))?;
                if pending_action.subject_id != *subject_id
                    || pending_action.target_credential_instance_id
                        != *target_credential_instance_id
                    || pending_action.action != *action
                    || !pending_action.is_cancellable_at(*now)
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "pending credential lifecycle action still cancellable for target",
                    ));
                }
            }
            Precondition::NoOpenPendingSubjectLifecycleActionForSubject {
                subject_id,
                action,
                now,
            } => {
                if self
                    .pending_subject_lifecycle_actions
                    .values()
                    .any(|pending_action| {
                        pending_action.subject_id == *subject_id
                            && pending_action.action == *action
                            && pending_action.closed_at.is_none()
                            && *now < pending_action.expires_at
                    })
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "no open pending subject lifecycle action for subject",
                    ));
                }
            }
            Precondition::PendingSubjectLifecycleActionStillExecutable {
                pending_action_id,
                subject_id,
                action,
                now,
            } => {
                let pending_action = self
                    .pending_subject_lifecycle_actions
                    .get(pending_action_id)
                    .ok_or(InMemoryCommitError::PreconditionFailed(
                        "pending subject lifecycle action still executable",
                    ))?;
                if pending_action.subject_id != *subject_id
                    || pending_action.action != *action
                    || !pending_action.is_executable_at(*now)
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "pending subject lifecycle action still executable",
                    ));
                }
            }
            Precondition::PendingSubjectLifecycleActionStillCancellableForSubject {
                pending_action_id,
                subject_id,
                action,
                now,
            } => {
                let pending_action = self
                    .pending_subject_lifecycle_actions
                    .get(pending_action_id)
                    .ok_or(InMemoryCommitError::PreconditionFailed(
                        "pending subject lifecycle action still cancellable for subject",
                    ))?;
                if pending_action.subject_id != *subject_id
                    || pending_action.action != *action
                    || !pending_action.is_cancellable_at(*now)
                {
                    return Err(InMemoryCommitError::PreconditionFailed(
                        "pending subject lifecycle action still cancellable for subject",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply_mutation(&mut self, mutation: Mutation) -> Result<(), InMemoryCommitError> {
        match mutation {
            Mutation::CreateSession(session) => {
                if self
                    .sessions
                    .insert(session.session_id.clone(), session)
                    .is_some()
                {
                    return Err(InMemoryCommitError::DuplicateRecord("session"));
                }
            }
            Mutation::RefreshSession {
                session_id,
                new_secret_version,
                previous_secret_version,
                previous_secret_accept_until,
                refreshed_at,
                expires_at,
            } => {
                let session = self
                    .sessions
                    .get_mut(&session_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing("session"))?;
                session.current_secret_version = new_secret_version;
                session.previous_secret_version = Some(previous_secret_version);
                session.previous_secret_accept_until = Some(previous_secret_accept_until);
                session.refreshed_at = refreshed_at;
                session.expires_at = expires_at;
            }
            Mutation::RecordStepUp {
                session_id,
                new_secret_version,
                previous_secret_version,
                previous_secret_accept_until,
                step_up_expires_at,
            } => {
                let session = self
                    .sessions
                    .get_mut(&session_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing("session"))?;
                session.current_secret_version = new_secret_version;
                session.previous_secret_version = Some(previous_secret_version);
                session.previous_secret_accept_until = Some(previous_secret_accept_until);
                session.step_up_expires_at = Some(step_up_expires_at);
            }
            Mutation::CreateTrustedDeviceCredential(trusted_device) => {
                if self
                    .trusted_devices
                    .insert(trusted_device.device_credential_id.clone(), trusted_device)
                    .is_some()
                {
                    return Err(InMemoryCommitError::DuplicateRecord("trusted device"));
                }
            }
            Mutation::CreateActiveProofAttempt(attempt) => {
                if self
                    .active_proof_attempts
                    .insert(attempt.attempt_id.clone(), attempt)
                    .is_some()
                {
                    return Err(InMemoryCommitError::DuplicateRecord("active proof attempt"));
                }
            }
            Mutation::CreateActiveProofChallenge(challenge) => {
                if self
                    .active_proof_challenges
                    .insert(challenge.challenge_id.clone(), challenge)
                    .is_some()
                {
                    return Err(InMemoryCommitError::DuplicateRecord(
                        "active proof challenge",
                    ));
                }
            }
            Mutation::RecordWeakProofFailure {
                attempt_id,
                weak_proof_failures,
            } => {
                let attempt = self.active_proof_attempts.get_mut(&attempt_id).ok_or(
                    InMemoryCommitError::MutationTargetMissing("active proof attempt"),
                )?;
                attempt.weak_proof_failures = weak_proof_failures;
            }
            Mutation::RecordActiveProofSucceeded {
                attempt_id,
                subject_id,
                proof,
                satisfied_at: _,
            } => {
                let attempt = self.active_proof_attempts.get_mut(&attempt_id).ok_or(
                    InMemoryCommitError::MutationTargetMissing("active proof attempt"),
                )?;
                if subject_id.is_some() {
                    attempt.subject_id = subject_id;
                }
                attempt.satisfied_proofs.push(proof);
            }
            Mutation::CloseOpenActiveProofChallengesForAttemptProofFamily {
                attempt_id,
                proof_family,
                closed_at,
            } => {
                let mut matched_any_challenge = false;
                for challenge in self.active_proof_challenges.values_mut() {
                    if challenge.attempt_id == attempt_id
                        && challenge.proof.family == proof_family
                        && challenge.closed_at.is_none()
                        && closed_at < challenge.expires_at
                    {
                        matched_any_challenge = true;
                        challenge.closed_at = Some(closed_at);
                    }
                }
                if !matched_any_challenge {
                    return Err(InMemoryCommitError::MutationTargetMissing(
                        "open active proof challenge for attempt proof family",
                    ));
                }
            }
            Mutation::RecordOutOfBandChallengeResent {
                challenge_id,
                resend_count,
                used_delivery_idempotency_keys,
                resent_at: _,
            } => {
                let challenge = self.active_proof_challenges.get_mut(&challenge_id).ok_or(
                    InMemoryCommitError::MutationTargetMissing("active proof challenge"),
                )?;
                challenge.resend_count = resend_count;
                challenge.used_delivery_idempotency_keys = used_delivery_idempotency_keys;
            }
            Mutation::DeleteActiveProofAttempt { attempt_id } => {
                self.active_proof_attempts.remove(&attempt_id).ok_or(
                    InMemoryCommitError::MutationTargetMissing("active proof attempt"),
                )?;
                self.active_proof_challenges
                    .retain(|_, challenge| challenge.attempt_id != attempt_id);
            }
            Mutation::RotateTrustedDeviceCredential {
                device_credential_id,
                new_secret_version,
                previous_secret_version,
                previous_secret_accept_until,
                last_used_at,
                silent_revival_until,
                expires_at,
            } => {
                let trusted_device = self
                    .trusted_devices
                    .get_mut(&device_credential_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing("trusted device"))?;
                trusted_device.current_secret_version = new_secret_version;
                trusted_device.previous_secret_version = Some(previous_secret_version);
                trusted_device.previous_secret_accept_until = Some(previous_secret_accept_until);
                trusted_device.last_used_at = last_used_at;
                trusted_device.silent_revival_until = silent_revival_until;
                trusted_device.expires_at = expires_at;
            }
            Mutation::RevokeSession {
                session_id,
                reason: _,
                revoked_at,
            } => {
                let session = self
                    .sessions
                    .get_mut(&session_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing("session"))?;
                session.revoked_at = Some(revoked_at);
            }
            Mutation::RevokeTrustedDeviceCredential {
                device_credential_id,
                reason: _,
                revoked_at,
            } => {
                let trusted_device = self
                    .trusted_devices
                    .get_mut(&device_credential_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing("trusted device"))?;
                trusted_device.revoked_at = Some(revoked_at);
            }
            Mutation::RaiseSubjectAuthRevocationCutoff {
                subject_id,
                revoke_records_created_at_or_before,
                reason: _,
            } => {
                let entry =
                    self.subject_revocations
                        .entry(subject_id)
                        .or_insert(SubjectRevocationState {
                            revoke_records_created_at_or_before,
                        });
                if entry.revoke_records_created_at_or_before < revoke_records_created_at_or_before {
                    entry.revoke_records_created_at_or_before = revoke_records_created_at_or_before;
                }
            }
            Mutation::RecordCredentialLifecycleActionAuthorized {
                target_credential_instance_id,
                action: _,
                authorized_at: _,
            } => {
                self.credential_instances
                    .get_mut(&target_credential_instance_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing(
                        "credential instance",
                    ))?;
            }
            Mutation::CreatePendingCredentialLifecycleAction(pending_action) => {
                if self
                    .pending_credential_lifecycle_actions
                    .insert(pending_action.pending_action_id.clone(), pending_action)
                    .is_some()
                {
                    return Err(InMemoryCommitError::DuplicateRecord(
                        "pending credential lifecycle action",
                    ));
                }
            }
            Mutation::RecordCredentialLifecycleActionExecuted {
                target_credential_instance_id,
                action: _,
                executed_at: _,
            } => {
                self.credential_instances
                    .get_mut(&target_credential_instance_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing(
                        "credential instance",
                    ))?;
            }
            Mutation::SetCredentialLifecycleState {
                credential_instance_id,
                lifecycle_state,
                updated_at: _,
            } => {
                let credential = self
                    .credential_instances
                    .get_mut(&credential_instance_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing(
                        "credential instance",
                    ))?;
                *credential = credential.with_lifecycle_state(lifecycle_state);
            }
            Mutation::ClosePendingCredentialLifecycleAction {
                pending_action_id,
                closed_at,
            } => {
                let pending_action = self
                    .pending_credential_lifecycle_actions
                    .get_mut(&pending_action_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing(
                        "pending credential lifecycle action",
                    ))?;
                pending_action.closed_at = Some(closed_at);
            }
            Mutation::CreatePendingSubjectLifecycleAction(pending_action) => {
                if self
                    .pending_subject_lifecycle_actions
                    .insert(pending_action.pending_action_id.clone(), pending_action)
                    .is_some()
                {
                    return Err(InMemoryCommitError::DuplicateRecord(
                        "pending subject lifecycle action",
                    ));
                }
            }
            Mutation::ClosePendingSubjectLifecycleAction {
                pending_action_id,
                closed_at,
            } => {
                let pending_action = self
                    .pending_subject_lifecycle_actions
                    .get_mut(&pending_action_id)
                    .ok_or(InMemoryCommitError::MutationTargetMissing(
                        "pending subject lifecycle action",
                    ))?;
                pending_action.closed_at = Some(closed_at);
            }
        }
        Ok(())
    }
}
