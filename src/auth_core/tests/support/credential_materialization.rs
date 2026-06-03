use std::collections::BTreeMap;

use super::*;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct TestCredentialSecret(pub(super) u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TestCredentialMac(pub(super) u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TestCredentialMacs {
    pub(super) current_version: SecretVersion,
    pub(super) current_mac: TestCredentialMac,
    pub(super) previous_version: Option<SecretVersion>,
    pub(super) previous_mac: Option<TestCredentialMac>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MaterializedSessionCookie {
    pub(super) draft: SessionCookieDraft,
    pub(super) secret: TestCredentialSecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MaterializedTrustedDeviceCookie {
    pub(super) draft: TrustedDeviceCookieDraft,
    pub(super) secret: TestCredentialSecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MaterializedActiveProofContinuationCookie {
    pub(super) draft: ActiveProofContinuationCookieDraft,
    pub(super) secret: TestCredentialSecret,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct PresentedMaterializedCredentials {
    pub(super) session: Option<MaterializedSessionCookie>,
    pub(super) trusted_device: Option<MaterializedTrustedDeviceCookie>,
    pub(super) active_proof_continuation: Option<MaterializedActiveProofContinuationCookie>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MaterializedAuthResponseEffect {
    IssueSessionCookie(MaterializedSessionCookie),
    DeleteSessionCookie,
    IssueTrustedDeviceCookie(MaterializedTrustedDeviceCookie),
    DeleteTrustedDeviceCookie,
    IssueActiveProofChallengeCookie(ActiveProofChallengeCookieDraft),
    DeleteActiveProofChallengeCookie,
    IssueActiveProofContinuationCookie(MaterializedActiveProofContinuationCookie),
    DeleteActiveProofContinuationCookie,
    CycleCsrfToken { session_id: Option<SessionId> },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct MaterializedSecretsGeneratedDuringCommit {
    pub(super) session_secrets: BTreeMap<(SessionId, SecretVersion), TestCredentialSecret>,
    pub(super) trusted_device_secrets:
        BTreeMap<(TrustedDeviceCredentialId, SecretVersion), TestCredentialSecret>,
    pub(super) active_proof_continuation_secrets:
        BTreeMap<ActiveProofAttemptId, TestCredentialSecret>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct CredentialMaterializingCommitStore {
    pub(super) state: InMemoryCommitStore,
    pub(super) session_secret_macs: BTreeMap<SessionId, TestCredentialMacs>,
    pub(super) trusted_device_secret_macs: BTreeMap<TrustedDeviceCredentialId, TestCredentialMacs>,
    pub(super) active_proof_continuation_secret_macs:
        BTreeMap<ActiveProofAttemptId, TestCredentialMac>,
    pub(super) next_secret_number: u64,
}

impl CredentialMaterializingCommitStore {
    pub(super) fn insert_session_with_secrets(
        &mut self,
        record: SessionRecord,
        current_secret: TestCredentialSecret,
        previous_secret: Option<TestCredentialSecret>,
    ) {
        self.session_secret_macs.insert(
            record.session_id.clone(),
            TestCredentialMacs {
                current_version: record.current_secret_version,
                current_mac: mac_for_test_secret(current_secret),
                previous_version: record.previous_secret_version,
                previous_mac: previous_secret.map(mac_for_test_secret),
            },
        );
        self.state
            .sessions
            .insert(record.session_id.clone(), record);
    }

    pub(super) fn loaded_for_session_cookie(
        &self,
        session_cookie: MaterializedSessionCookie,
        now: UnixSeconds,
    ) -> LoadedState {
        let session_record = self
            .state
            .sessions
            .get(&session_cookie.draft.session_id)
            .cloned();
        let session_secret_match = session_record.as_ref().map(|record| {
            LoadedSessionSecretMatch::new(
                record.session_id.clone(),
                self.classify_session_cookie_secret(&session_cookie, record, now),
            )
        });
        let subject_id_for_revocation = session_record
            .as_ref()
            .map(|record| record.subject_id.clone())
            .unwrap_or_else(|| session_cookie.draft.subject_id.clone());
        LoadedState {
            subject_revocations: LoadedSubjectRevocations::loaded(
                subject_id_for_revocation.clone(),
                self.state
                    .subject_revocations
                    .get(&subject_id_for_revocation)
                    .cloned(),
            ),
            session_cookie: Some(session_cookie.draft),
            session_record,
            session_secret_match,
            ..LoadedState::default()
        }
    }

    pub(super) fn loaded_for_trusted_device_cookie(
        &self,
        trusted_device_cookie: MaterializedTrustedDeviceCookie,
        now: UnixSeconds,
    ) -> LoadedState {
        let trusted_device_record = self
            .state
            .trusted_devices
            .get(&trusted_device_cookie.draft.device_credential_id)
            .cloned();
        let trusted_device_secret_match = trusted_device_record.as_ref().map(|record| {
            LoadedTrustedDeviceSecretMatch::new(
                record.device_credential_id.clone(),
                self.classify_trusted_device_cookie_secret(&trusted_device_cookie, record, now),
            )
        });
        let subject_id_for_revocation = trusted_device_record
            .as_ref()
            .map(|record| record.subject_id.clone())
            .unwrap_or_else(|| trusted_device_cookie.draft.subject_id.clone());
        LoadedState {
            subject_revocations: LoadedSubjectRevocations::loaded(
                subject_id_for_revocation.clone(),
                self.state
                    .subject_revocations
                    .get(&subject_id_for_revocation)
                    .cloned(),
            ),
            trusted_device_cookie: Some(trusted_device_cookie.draft),
            trusted_device_record,
            trusted_device_secret_match,
            ..LoadedState::default()
        }
    }

    pub(super) fn commit_plan_with_materialized_response(
        &mut self,
        plan: CommitPlan,
        presented: PresentedMaterializedCredentials,
    ) -> Result<Vec<MaterializedAuthResponseEffect>, InMemoryCommitError> {
        let (atomic_work, response_effects) = plan
            .try_into_validated_atomic_work_and_response_effects()
            .map_err(InMemoryCommitError::CoreCommitWorkInvalid)?;
        let mut next = self.clone();
        let mut generated = MaterializedSecretsGeneratedDuringCommit::default();
        if !atomic_work.is_empty() {
            next.commit_atomic_work_with_credential_materialization(atomic_work, &mut generated)?;
        }
        let materialized_response_effects =
            next.materialize_response_effects(response_effects, presented, &generated)?;
        *self = next;
        Ok(materialized_response_effects)
    }

    pub(super) fn commit_atomic_work_with_credential_materialization(
        &mut self,
        work: AtomicCommitWork,
        generated: &mut MaterializedSecretsGeneratedDuringCommit,
    ) -> Result<(), InMemoryCommitError> {
        work.validate_for_commit()
            .map_err(InMemoryCommitError::CoreCommitWorkInvalid)?;
        self.state.ensure_preconditions(&work.preconditions)?;
        let mut next = self.clone();
        for fresh_secret in &work.fresh_credential_secrets {
            next.materialize_fresh_credential_secret(fresh_secret, generated)?;
        }
        for mutation in work.mutations {
            next.state.apply_mutation(mutation)?;
        }
        next.state.audit_events.extend(work.audit_events);
        next.state
            .method_commit_work
            .extend(work.method_commit_work);
        next.state.durable_effects.extend(work.durable_effects);
        *self = next;
        Ok(())
    }

    pub(super) fn materialize_fresh_credential_secret(
        &mut self,
        fresh_secret: &FreshCredentialSecret,
        generated: &mut MaterializedSecretsGeneratedDuringCommit,
    ) -> Result<(), InMemoryCommitError> {
        match fresh_secret {
            FreshCredentialSecret::Session {
                session_id,
                secret_version,
            } => {
                let secret = self.generate_test_secret();
                let previous = self.session_secret_macs.get(session_id).cloned();
                self.session_secret_macs.insert(
                    session_id.clone(),
                    TestCredentialMacs {
                        current_version: *secret_version,
                        current_mac: mac_for_test_secret(secret),
                        previous_version: previous.as_ref().map(|macs| macs.current_version),
                        previous_mac: previous.map(|macs| macs.current_mac),
                    },
                );
                generated
                    .session_secrets
                    .insert((session_id.clone(), *secret_version), secret);
            }
            FreshCredentialSecret::TrustedDevice {
                device_credential_id,
                secret_version,
            } => {
                let secret = self.generate_test_secret();
                let previous = self
                    .trusted_device_secret_macs
                    .get(device_credential_id)
                    .cloned();
                self.trusted_device_secret_macs.insert(
                    device_credential_id.clone(),
                    TestCredentialMacs {
                        current_version: *secret_version,
                        current_mac: mac_for_test_secret(secret),
                        previous_version: previous.as_ref().map(|macs| macs.current_version),
                        previous_mac: previous.map(|macs| macs.current_mac),
                    },
                );
                generated
                    .trusted_device_secrets
                    .insert((device_credential_id.clone(), *secret_version), secret);
            }
            FreshCredentialSecret::ActiveProofContinuation { attempt_id } => {
                let secret = self.generate_test_secret();
                self.active_proof_continuation_secret_macs
                    .insert(attempt_id.clone(), mac_for_test_secret(secret));
                generated
                    .active_proof_continuation_secrets
                    .insert(attempt_id.clone(), secret);
            }
        }
        Ok(())
    }

    pub(super) fn materialize_response_effects(
        &self,
        response_effects: Vec<ResponseEffect>,
        presented: PresentedMaterializedCredentials,
        generated: &MaterializedSecretsGeneratedDuringCommit,
    ) -> Result<Vec<MaterializedAuthResponseEffect>, InMemoryCommitError> {
        response_effects
            .into_iter()
            .map(|effect| match effect {
                ResponseEffect::IssueSessionCookie(draft) => {
                    let secret =
                        self.secret_for_session_cookie_response(&draft, &presented, generated)?;
                    Ok(MaterializedAuthResponseEffect::IssueSessionCookie(
                        MaterializedSessionCookie { draft, secret },
                    ))
                }
                ResponseEffect::DeleteSessionCookie => {
                    Ok(MaterializedAuthResponseEffect::DeleteSessionCookie)
                }
                ResponseEffect::IssueTrustedDeviceCookie(draft) => {
                    let secret = self
                        .secret_for_trusted_device_cookie_response(&draft, &presented, generated)?;
                    Ok(MaterializedAuthResponseEffect::IssueTrustedDeviceCookie(
                        MaterializedTrustedDeviceCookie { draft, secret },
                    ))
                }
                ResponseEffect::DeleteTrustedDeviceCookie => {
                    Ok(MaterializedAuthResponseEffect::DeleteTrustedDeviceCookie)
                }
                ResponseEffect::IssueActiveProofChallengeCookie(draft) => {
                    Ok(MaterializedAuthResponseEffect::IssueActiveProofChallengeCookie(draft))
                }
                ResponseEffect::DeleteActiveProofChallengeCookie => {
                    Ok(MaterializedAuthResponseEffect::DeleteActiveProofChallengeCookie)
                }
                ResponseEffect::IssueActiveProofContinuationCookie(draft) => {
                    let secret = self.secret_for_active_proof_continuation_cookie_response(
                        &draft, &presented, generated,
                    )?;
                    Ok(
                        MaterializedAuthResponseEffect::IssueActiveProofContinuationCookie(
                            MaterializedActiveProofContinuationCookie { draft, secret },
                        ),
                    )
                }
                ResponseEffect::DeleteActiveProofContinuationCookie => {
                    Ok(MaterializedAuthResponseEffect::DeleteActiveProofContinuationCookie)
                }
                ResponseEffect::CycleCsrfToken { session_id } => {
                    Ok(MaterializedAuthResponseEffect::CycleCsrfToken { session_id })
                }
            })
            .collect()
    }

    pub(super) fn secret_for_session_cookie_response(
        &self,
        draft: &SessionCookieDraft,
        presented: &PresentedMaterializedCredentials,
        generated: &MaterializedSecretsGeneratedDuringCommit,
    ) -> Result<TestCredentialSecret, InMemoryCommitError> {
        if let Some(secret) = generated
            .session_secrets
            .get(&(draft.session_id.clone(), draft.secret_version))
        {
            return Ok(*secret);
        }
        let presented_cookie = presented.session.as_ref().ok_or(
            InMemoryCommitError::ResponseMaterializationFailed(
                "session response cookie needs a current presented secret or generated secret",
            ),
        )?;
        if presented_cookie.draft.session_id != draft.session_id
            || presented_cookie.draft.secret_version != draft.secret_version
        {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "session response cookie cannot use a different presented secret",
            ));
        }
        let record = self.state.sessions.get(&draft.session_id).ok_or(
            InMemoryCommitError::ResponseMaterializationFailed(
                "session response cookie has no authoritative row",
            ),
        )?;
        let candidate_cookie = MaterializedSessionCookie {
            draft: draft.clone(),
            secret: presented_cookie.secret,
        };
        if self.classify_session_cookie_secret(
            &candidate_cookie,
            record,
            draft.session_fast_fail_until,
        ) != StoredSecretMatch::Current
        {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "session response cookie presented secret is not current",
            ));
        }
        Ok(presented_cookie.secret)
    }

    pub(super) fn secret_for_trusted_device_cookie_response(
        &self,
        draft: &TrustedDeviceCookieDraft,
        presented: &PresentedMaterializedCredentials,
        generated: &MaterializedSecretsGeneratedDuringCommit,
    ) -> Result<TestCredentialSecret, InMemoryCommitError> {
        if let Some(secret) = generated
            .trusted_device_secrets
            .get(&(draft.device_credential_id.clone(), draft.secret_version))
        {
            return Ok(*secret);
        }
        let presented_cookie = presented.trusted_device.as_ref().ok_or(
            InMemoryCommitError::ResponseMaterializationFailed(
                "trusted-device response cookie needs a current presented secret or generated secret",
            ),
        )?;
        if presented_cookie.draft.device_credential_id != draft.device_credential_id
            || presented_cookie.draft.secret_version != draft.secret_version
        {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "trusted-device response cookie cannot use a different presented secret",
            ));
        }
        let record = self
            .state
            .trusted_devices
            .get(&draft.device_credential_id)
            .ok_or(InMemoryCommitError::ResponseMaterializationFailed(
                "trusted-device response cookie has no authoritative row",
            ))?;
        let candidate_cookie = MaterializedTrustedDeviceCookie {
            draft: draft.clone(),
            secret: presented_cookie.secret,
        };
        if self.classify_trusted_device_cookie_secret(
            &candidate_cookie,
            record,
            draft.device_fast_fail_until,
        ) != StoredSecretMatch::Current
        {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "trusted-device response cookie presented secret is not current",
            ));
        }
        Ok(presented_cookie.secret)
    }

    pub(super) fn secret_for_active_proof_continuation_cookie_response(
        &self,
        draft: &ActiveProofContinuationCookieDraft,
        presented: &PresentedMaterializedCredentials,
        generated: &MaterializedSecretsGeneratedDuringCommit,
    ) -> Result<TestCredentialSecret, InMemoryCommitError> {
        if let Some(secret) = generated
            .active_proof_continuation_secrets
            .get(&draft.attempt_id)
        {
            return Ok(*secret);
        }
        let presented_cookie = presented.active_proof_continuation.as_ref().ok_or(
            InMemoryCommitError::ResponseMaterializationFailed(
                "active-proof continuation response cookie needs a current presented secret or generated secret",
            ),
        )?;
        if presented_cookie.draft.attempt_id != draft.attempt_id {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "active-proof continuation response cookie cannot use a different presented secret",
            ));
        }
        let Some(stored_mac) = self
            .active_proof_continuation_secret_macs
            .get(&draft.attempt_id)
        else {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "active-proof continuation response cookie has no authoritative row",
            ));
        };
        if *stored_mac != mac_for_test_secret(presented_cookie.secret) {
            return Err(InMemoryCommitError::ResponseMaterializationFailed(
                "active-proof continuation response cookie presented secret is not current",
            ));
        }
        Ok(presented_cookie.secret)
    }

    pub(super) fn classify_session_cookie_secret(
        &self,
        cookie: &MaterializedSessionCookie,
        record: &SessionRecord,
        now: UnixSeconds,
    ) -> StoredSecretMatch {
        let Some(stored_macs) = self.session_secret_macs.get(&record.session_id) else {
            return StoredSecretMatch::Unknown;
        };
        classify_test_credential_secret(
            cookie.draft.secret_version,
            cookie.secret,
            record.current_secret_version,
            record.previous_secret_version,
            record.previous_secret_accept_until,
            stored_macs,
            now,
        )
    }

    pub(super) fn classify_trusted_device_cookie_secret(
        &self,
        cookie: &MaterializedTrustedDeviceCookie,
        record: &TrustedDeviceCredentialRecord,
        now: UnixSeconds,
    ) -> StoredSecretMatch {
        let Some(stored_macs) = self
            .trusted_device_secret_macs
            .get(&record.device_credential_id)
        else {
            return StoredSecretMatch::Unknown;
        };
        classify_test_credential_secret(
            cookie.draft.secret_version,
            cookie.secret,
            record.current_secret_version,
            record.previous_secret_version,
            record.previous_secret_accept_until,
            stored_macs,
            now,
        )
    }

    pub(super) fn generate_test_secret(&mut self) -> TestCredentialSecret {
        self.next_secret_number += 1;
        TestCredentialSecret(10_000 + self.next_secret_number)
    }
}

pub(super) fn classify_test_credential_secret(
    presented_version: SecretVersion,
    presented_secret: TestCredentialSecret,
    current_version: SecretVersion,
    previous_version: Option<SecretVersion>,
    previous_secret_accept_until: Option<UnixSeconds>,
    stored_macs: &TestCredentialMacs,
    now: UnixSeconds,
) -> StoredSecretMatch {
    let presented_mac = mac_for_test_secret(presented_secret);
    if presented_version == current_version
        && stored_macs.current_version == current_version
        && presented_mac == stored_macs.current_mac
    {
        return StoredSecretMatch::Current;
    }
    if Some(presented_version) == previous_version
        && stored_macs.previous_version == previous_version
        && Some(presented_mac) == stored_macs.previous_mac
    {
        if previous_secret_accept_until.is_some_and(|accept_until| now < accept_until) {
            return StoredSecretMatch::PreviousWithinGrace;
        }
        return StoredSecretMatch::PreviousAfterGrace;
    }
    StoredSecretMatch::Unknown
}

pub(super) fn mac_for_test_secret(secret: TestCredentialSecret) -> TestCredentialMac {
    TestCredentialMac(secret.0.wrapping_mul(1_099_511_628_211))
}

pub(super) fn classify_session_cookie_secret(
    cookie: &SessionCookieDraft,
    record: &SessionRecord,
    now: UnixSeconds,
) -> StoredSecretMatch {
    if cookie.secret_version == record.current_secret_version {
        return StoredSecretMatch::Current;
    }
    if Some(cookie.secret_version) == record.previous_secret_version {
        if record
            .previous_secret_accept_until
            .is_some_and(|accept_until| now < accept_until)
        {
            return StoredSecretMatch::PreviousWithinGrace;
        }
        return StoredSecretMatch::PreviousAfterGrace;
    }
    StoredSecretMatch::Unknown
}

pub(super) fn classify_trusted_device_cookie_secret(
    cookie: &TrustedDeviceCookieDraft,
    record: &TrustedDeviceCredentialRecord,
    now: UnixSeconds,
) -> StoredSecretMatch {
    if cookie.secret_version == record.current_secret_version {
        return StoredSecretMatch::Current;
    }
    if Some(cookie.secret_version) == record.previous_secret_version {
        if record
            .previous_secret_accept_until
            .is_some_and(|accept_until| now < accept_until)
        {
            return StoredSecretMatch::PreviousWithinGrace;
        }
        return StoredSecretMatch::PreviousAfterGrace;
    }
    StoredSecretMatch::Unknown
}

pub(super) fn session_cookie_from_response_effects(
    response_effects: &[ResponseEffect],
) -> SessionCookieDraft {
    response_effects
        .iter()
        .rev()
        .find_map(|effect| match effect {
            ResponseEffect::IssueSessionCookie(cookie) => Some(cookie.clone()),
            ResponseEffect::DeleteSessionCookie
            | ResponseEffect::IssueTrustedDeviceCookie(_)
            | ResponseEffect::DeleteTrustedDeviceCookie
            | ResponseEffect::IssueActiveProofChallengeCookie(_)
            | ResponseEffect::DeleteActiveProofChallengeCookie
            | ResponseEffect::IssueActiveProofContinuationCookie(_)
            | ResponseEffect::DeleteActiveProofContinuationCookie
            | ResponseEffect::CycleCsrfToken { .. } => None,
        })
        .expect("response effects should issue a session cookie")
}

pub(super) fn trusted_device_cookie_from_response_effects(
    response_effects: &[ResponseEffect],
) -> TrustedDeviceCookieDraft {
    response_effects
        .iter()
        .rev()
        .find_map(|effect| match effect {
            ResponseEffect::IssueTrustedDeviceCookie(cookie) => Some(cookie.clone()),
            ResponseEffect::IssueSessionCookie(_)
            | ResponseEffect::DeleteSessionCookie
            | ResponseEffect::DeleteTrustedDeviceCookie
            | ResponseEffect::IssueActiveProofChallengeCookie(_)
            | ResponseEffect::DeleteActiveProofChallengeCookie
            | ResponseEffect::IssueActiveProofContinuationCookie(_)
            | ResponseEffect::DeleteActiveProofContinuationCookie
            | ResponseEffect::CycleCsrfToken { .. } => None,
        })
        .expect("response effects should issue a trusted-device cookie")
}

pub(super) fn materialized_session_cookie_from_response_effects(
    response_effects: &[MaterializedAuthResponseEffect],
) -> MaterializedSessionCookie {
    response_effects
        .iter()
        .rev()
        .find_map(|effect| match effect {
            MaterializedAuthResponseEffect::IssueSessionCookie(cookie) => Some(cookie.clone()),
            MaterializedAuthResponseEffect::DeleteSessionCookie
            | MaterializedAuthResponseEffect::IssueTrustedDeviceCookie(_)
            | MaterializedAuthResponseEffect::DeleteTrustedDeviceCookie
            | MaterializedAuthResponseEffect::IssueActiveProofChallengeCookie(_)
            | MaterializedAuthResponseEffect::DeleteActiveProofChallengeCookie
            | MaterializedAuthResponseEffect::IssueActiveProofContinuationCookie(_)
            | MaterializedAuthResponseEffect::DeleteActiveProofContinuationCookie
            | MaterializedAuthResponseEffect::CycleCsrfToken { .. } => None,
        })
        .expect("response effects should issue a materialized session cookie")
}

pub(super) fn materialized_trusted_device_cookie_from_response_effects(
    response_effects: &[MaterializedAuthResponseEffect],
) -> MaterializedTrustedDeviceCookie {
    response_effects
        .iter()
        .rev()
        .find_map(|effect| match effect {
            MaterializedAuthResponseEffect::IssueTrustedDeviceCookie(cookie) => {
                Some(cookie.clone())
            }
            MaterializedAuthResponseEffect::IssueSessionCookie(_)
            | MaterializedAuthResponseEffect::DeleteSessionCookie
            | MaterializedAuthResponseEffect::DeleteTrustedDeviceCookie
            | MaterializedAuthResponseEffect::IssueActiveProofChallengeCookie(_)
            | MaterializedAuthResponseEffect::DeleteActiveProofChallengeCookie
            | MaterializedAuthResponseEffect::IssueActiveProofContinuationCookie(_)
            | MaterializedAuthResponseEffect::DeleteActiveProofContinuationCookie
            | MaterializedAuthResponseEffect::CycleCsrfToken { .. } => None,
        })
        .expect("response effects should issue a materialized trusted-device cookie")
}
