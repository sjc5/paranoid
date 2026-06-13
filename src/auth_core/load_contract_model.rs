use super::prelude::*;

/// Decoded request cookies available before authoritative state is loaded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PresentedAuthCookies {
    /// Decoded session cookie, if the request carried one.
    pub session_cookie: Option<SessionCookieDraft>,
    /// Decoded trusted-device cookie, if the request carried one.
    pub trusted_device_cookie: Option<TrustedDeviceCookieDraft>,
    /// Decoded active-proof challenge cookie, if the request carried one.
    pub active_proof_challenge_cookie: Option<ActiveProofChallengeCookieDraft>,
    /// Decoded active-proof continuation cookie, if the request carried one.
    pub active_proof_continuation_cookie: Option<ActiveProofContinuationCookieDraft>,
}

impl PresentedAuthCookies {
    /// Copies the presented cookie portion of a loaded-state snapshot.
    pub fn from_loaded_state(loaded: &LoadedState) -> Self {
        Self {
            session_cookie: loaded.session_cookie.clone(),
            trusted_device_cookie: loaded.trusted_device_cookie.clone(),
            active_proof_challenge_cookie: None,
            active_proof_continuation_cookie: None,
        }
    }
}

/// One loaded-state item an adapter must provide before reducing a command.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LoadedStateRequirement {
    /// Present the decoded session cookie in `LoadedState`.
    PresentedSessionCookie {
        /// Session id carried by the cookie.
        session_id: SessionId,
    },
    /// Present the decoded trusted-device cookie in `LoadedState`.
    PresentedTrustedDeviceCookie {
        /// Trusted-device credential id carried by the cookie.
        device_credential_id: TrustedDeviceCredentialId,
    },
    /// Load the session record and classify the presented session secret.
    SessionRecordAndSecretMatchForPresentedCookie {
        /// Session id carried by the cookie.
        session_id: SessionId,
    },
    /// Load the trusted-device record and classify the presented device secret.
    TrustedDeviceRecordAndSecretMatchForPresentedCookie {
        /// Trusted-device credential id carried by the cookie.
        device_credential_id: TrustedDeviceCredentialId,
    },
    /// Load subject revocation state for the subject on the loaded session record.
    SubjectRevocationForLoadedSessionSubject {
        /// Session id whose loaded record determines the subject.
        session_id: SessionId,
    },
    /// Load subject revocation state for the subject on the loaded trusted-device record.
    SubjectRevocationForLoadedTrustedDeviceSubject {
        /// Trusted-device credential id whose loaded record determines the subject.
        device_credential_id: TrustedDeviceCredentialId,
    },
    /// Load the active-proof attempt named by the command.
    ActiveProofAttempt {
        /// Attempt id named by the command.
        attempt_id: ActiveProofAttemptId,
    },
    /// Load and classify the active-proof continuation secret for the attempt.
    ActiveProofContinuationSecretMatchForPresentedCookie {
        /// Attempt id carried by the continuation cookie.
        attempt_id: ActiveProofAttemptId,
    },
    /// Load subject revocation state for the loaded active-proof attempt subject, if bound.
    SubjectRevocationForLoadedActiveProofAttemptSubject {
        /// Attempt id whose loaded record determines the subject.
        attempt_id: ActiveProofAttemptId,
    },
    /// Load subject revocation state for the subject resolved by a verified proof.
    SubjectRevocationForVerifiedActiveProofSubject {
        /// Subject resolved by the verified proof.
        subject_id: SubjectId,
    },
    /// Load the active-proof challenge named by the command.
    ActiveProofChallenge {
        /// Challenge id named by the command.
        challenge_id: ActiveProofChallengeId,
    },
}

/// Loaded-state contract for one reducer command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandLoadedStateContract {
    required: Vec<LoadedStateRequirement>,
}

impl CommandLoadedStateContract {
    /// Builds the loaded-state contract for issuing an out-of-band challenge before the
    /// runtime has materialized the challenge cookie.
    pub fn for_out_of_band_challenge_issue_request(
        config: &Config,
        request: &IssueOutOfBandChallengeRequest,
        presented_cookies: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(&request.attempt_id);
        contract.push_active_proof_continuation_requirement_if_presented(
            presented_cookies,
            &request.attempt_id,
        );
        Ok(contract)
    }

    /// Builds the loaded-state contract for issuing a method-specific active-proof challenge before the
    /// runtime has materialized the challenge cookie.
    pub fn for_active_proof_method_challenge_issue_request(
        config: &Config,
        request: &IssueActiveProofMethodChallengeRequest,
        presented_cookies: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(&request.attempt_id);
        contract.push_active_proof_continuation_requirement_if_presented(
            presented_cookies,
            &request.attempt_id,
        );
        Ok(contract)
    }

    /// Builds the loaded-state contract for completing a known-subject active-proof method before
    /// method/plugin verification has produced the core completion command.
    pub fn for_known_subject_active_proof_method_response(
        config: &Config,
        response: &CompleteKnownSubjectActiveProofMethodResponse,
        attempt_id: &ActiveProofAttemptId,
        presented_cookies: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        super::active_proof_support::validate_known_subject_active_proof_method(&response.method)?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(attempt_id);
        contract
            .push_active_proof_continuation_requirement_if_presented(presented_cookies, attempt_id);
        Ok(contract)
    }

    pub fn for_recovery_credential_active_proof_method_response(
        config: &Config,
        response: &CompleteRecoveryCredentialActiveProofMethodResponse,
        attempt_id: &ActiveProofAttemptId,
        presented_cookies: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        super::active_proof_support::validate_recovery_credential_active_proof_method(
            &response.method,
        )?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(attempt_id);
        contract
            .push_active_proof_continuation_requirement_if_presented(presented_cookies, attempt_id);
        Ok(contract)
    }

    pub(crate) fn for_active_proof_method_authoritative_verification(
        config: &Config,
        challenge_cookie: &ActiveProofChallengeCookieDraft,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(&challenge_cookie.attempt_id);
        contract.push(LoadedStateRequirement::ActiveProofChallenge {
            challenge_id: challenge_cookie.challenge_id.clone(),
        });
        Ok(contract)
    }

    pub(crate) fn for_verified_active_proof_subject_revocation(
        config: &Config,
        subject_id: &SubjectId,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        contract.push(
            LoadedStateRequirement::SubjectRevocationForVerifiedActiveProofSubject {
                subject_id: subject_id.clone(),
            },
        );
        Ok(contract)
    }

    pub(crate) fn for_authenticated_session_lifecycle_request(
        config: &Config,
        now: UnixSeconds,
        presented: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        if let Some(cookie) = &presented.session_cookie {
            contract.push_presented_session_cookie(cookie);
            if now < cookie.session_fast_fail_until {
                contract.push_authoritative_session_requirements(cookie);
            }
        }
        Ok(contract)
    }

    pub(crate) fn for_recover_or_replace_credential_lifecycle_request(
        config: &Config,
        attempt_id: &ActiveProofAttemptId,
        presented: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(attempt_id);
        contract.push_active_proof_continuation_requirement_if_presented(presented, attempt_id);
        Ok(contract)
    }

    /// Builds the loaded-state contract for resending an out-of-band challenge before
    /// method/plugin commit work has been attached.
    pub fn for_out_of_band_challenge_resend_request(
        config: &Config,
        request: &ResendOutOfBandChallengeRequest,
        challenge_cookie: &ActiveProofChallengeCookieDraft,
    ) -> Result<Self, Error> {
        config.validate()?;
        challenge_cookie.validate_for_out_of_band_resend_before_state_load(request.now)?;
        let mut contract = Self::default();
        contract.push_active_proof_attempt_requirements(&challenge_cookie.attempt_id);
        contract.push(LoadedStateRequirement::ActiveProofChallenge {
            challenge_id: challenge_cookie.challenge_id.clone(),
        });
        Ok(contract)
    }

    /// Builds the loaded-state contract for one command and decoded cookie set.
    pub fn for_command(
        config: &Config,
        command: &Command,
        presented: &PresentedAuthCookies,
    ) -> Result<Self, Error> {
        config.validate()?;
        let mut contract = Self::default();
        match command {
            Command::ResolveRequest(command) => {
                contract.add_request_resolution_requirements(config, command, presented);
            }
            Command::StartActiveProofAttempt(_) => {}
            Command::StartActiveProofAttemptForCurrentSession(command) => {
                if let Some(cookie) = &presented.session_cookie {
                    contract.push_presented_session_cookie(cookie);
                    if command.now < cookie.session_fast_fail_until {
                        contract.push_authoritative_session_requirements(cookie);
                    }
                }
            }
            Command::StartActiveProofAttemptForCurrentTrustedDevice(command) => {
                if let Some(cookie) = &presented.trusted_device_cookie {
                    contract.push_presented_trusted_device_cookie(cookie);
                    if command.now < cookie.device_fast_fail_until {
                        contract.push_authoritative_trusted_device_requirements(cookie);
                    }
                }
            }
            Command::IssueActiveProofMethodChallenge(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
            }
            Command::IssueOutOfBandChallenge(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
            }
            Command::ResendOutOfBandChallenge(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
                contract.push(LoadedStateRequirement::ActiveProofChallenge {
                    challenge_id: command.challenge_id.clone(),
                });
            }
            Command::CompleteActiveProofChallenge(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
                if let Some(subject_id) = command.verified_proof.subject_id() {
                    contract.push(
                        LoadedStateRequirement::SubjectRevocationForVerifiedActiveProofSubject {
                            subject_id: subject_id.clone(),
                        },
                    );
                }
                if let Some(challenge_id) = &command.challenge_id {
                    contract.push(LoadedStateRequirement::ActiveProofChallenge {
                        challenge_id: challenge_id.clone(),
                    });
                }
            }
            Command::RecordActiveProofFailure(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
                if let Some(challenge_id) = &command.challenge_id {
                    contract.push(LoadedStateRequirement::ActiveProofChallenge {
                        challenge_id: challenge_id.clone(),
                    });
                }
            }
            Command::CompleteFullAuthentication(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
            }
            Command::CompleteStepUp(command) => {
                if let Some(cookie) = &presented.session_cookie {
                    contract.push_presented_session_cookie(cookie);
                    if command.now < cookie.session_fast_fail_until {
                        contract.push_authoritative_session_requirements(cookie);
                        contract.push_active_proof_attempt_requirements(&command.attempt_id);
                        contract.push_active_proof_continuation_requirement_if_presented(
                            presented,
                            &command.attempt_id,
                        );
                    }
                }
            }
            Command::CompleteTrustedDeviceRevivalWithActiveProof(command) => {
                if let Some(cookie) = &presented.trusted_device_cookie {
                    contract.push_presented_trusted_device_cookie(cookie);
                    if command.now < cookie.device_fast_fail_until {
                        contract.push_authoritative_trusted_device_requirements(cookie);
                        contract.push_active_proof_attempt_requirements(&command.attempt_id);
                        contract.push_active_proof_continuation_requirement_if_presented(
                            presented,
                            &command.attempt_id,
                        );
                    }
                }
            }
            Command::LogoutCurrentSession(_) => {
                if let Some(cookie) = &presented.session_cookie {
                    contract.push_presented_session_cookie(cookie);
                    contract.push_authoritative_session_without_revocation_requirements(cookie);
                }
            }
            Command::RevokeSession(_) => {
                if let Some(cookie) = &presented.session_cookie {
                    contract.push_presented_session_cookie(cookie);
                }
            }
            Command::RevokeTrustedDevice(_) => {
                if let Some(cookie) = &presented.trusted_device_cookie {
                    contract.push_presented_trusted_device_cookie(cookie);
                }
            }
            Command::RevokeSubjectAuthState(_) => {
                if let Some(cookie) = &presented.session_cookie {
                    contract.push_presented_session_cookie(cookie);
                }
                if let Some(cookie) = &presented.trusted_device_cookie {
                    contract.push_presented_trusted_device_cookie(cookie);
                }
            }
            Command::PlanCredentialReset(_) => {}
            Command::ExecuteCredentialReset(_) => {}
            Command::PlanCredentialReplacement(_) => {}
            Command::ExecuteCredentialReplacement(_) => {}
            Command::PlanCredentialRemoval(_) => {}
            Command::ExecuteCredentialRemoval(_) => {}
            Command::PlanCredentialRegeneration(_) => {}
            Command::ExecuteCredentialRegeneration(_) => {}
            Command::ExecuteCredentialRotation(_) => {}
            Command::PlanOutOfBandIdentifierChange(_) => {}
            Command::ExecuteOutOfBandIdentifierChange(_) => {}
            Command::CancelPendingCredentialReset(_) => {}
            Command::AddCredential(_) => {}
            Command::ExecuteNonResetPendingCredentialLifecycleAction(_) => {}
            Command::CancelNonResetPendingCredentialLifecycleAction(_) => {}
            Command::RequestAdminSupportIntervention(_) => {}
            Command::ApproveAdminSupportIntervention(_) => {}
            Command::DenyAdminSupportIntervention(_) => {}
            Command::ExpireAdminSupportIntervention(_) => {}
            Command::PlanAdminSupportCredentialLifecycleIntervention(_) => {}
            Command::ScheduleSubjectAuthStateDeletion(_) => {}
            Command::ExecutePendingSubjectAuthStateDeletion(_) => {}
            Command::CancelPendingSubjectAuthStateDeletion(_) => {}
            Command::ExecutePendingOutOfBandIdentifierChange(_) => {}
            Command::CancelPendingOutOfBandIdentifierChange(_) => {}
            Command::ReserveOutOfBandIdentifierChangeCandidateBinding(command) => {
                contract.push_active_proof_attempt_requirements(&command.attempt_id);
                contract.push_active_proof_continuation_requirement_if_presented(
                    presented,
                    &command.attempt_id,
                );
                contract.push(LoadedStateRequirement::ActiveProofChallenge {
                    challenge_id: command.challenge_id.clone(),
                });
            }
        }
        Ok(contract)
    }

    /// Returns required loaded-state items in deterministic order.
    pub fn required(&self) -> &[LoadedStateRequirement] {
        &self.required
    }

    /// Validates that loaded state satisfies every requirement in this contract.
    pub fn validate_loaded_state(&self, loaded: &LoadedState) -> Result<(), Error> {
        for requirement in &self.required {
            requirement.validate_loaded_state(loaded)?;
        }
        Ok(())
    }

    fn add_request_resolution_requirements(
        &mut self,
        config: &Config,
        command: &ResolveRequest,
        presented: &PresentedAuthCookies,
    ) {
        if let Some(cookie) = &presented.session_cookie {
            self.push_presented_session_cookie(cookie);
            if request_resolution_needs_authoritative_session(config, command, presented, cookie) {
                self.push_authoritative_session_requirements(cookie);
            }
        }
        if let Some(cookie) = &presented.trusted_device_cookie {
            self.push_presented_trusted_device_cookie(cookie);
            if command.now < cookie.device_fast_fail_until {
                self.push_authoritative_trusted_device_requirements(cookie);
            }
        }
    }

    fn push_presented_session_cookie(&mut self, cookie: &SessionCookieDraft) {
        self.push(LoadedStateRequirement::PresentedSessionCookie {
            session_id: cookie.session_id.clone(),
        });
    }

    fn push_presented_trusted_device_cookie(&mut self, cookie: &TrustedDeviceCookieDraft) {
        self.push(LoadedStateRequirement::PresentedTrustedDeviceCookie {
            device_credential_id: cookie.device_credential_id.clone(),
        });
    }

    fn push_authoritative_session_requirements(&mut self, cookie: &SessionCookieDraft) {
        self.push_authoritative_session_without_revocation_requirements(cookie);
        self.push(
            LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject {
                session_id: cookie.session_id.clone(),
            },
        );
    }

    fn push_authoritative_session_without_revocation_requirements(
        &mut self,
        cookie: &SessionCookieDraft,
    ) {
        self.push(
            LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
                session_id: cookie.session_id.clone(),
            },
        );
    }

    fn push_authoritative_trusted_device_requirements(
        &mut self,
        cookie: &TrustedDeviceCookieDraft,
    ) {
        self.push(
            LoadedStateRequirement::TrustedDeviceRecordAndSecretMatchForPresentedCookie {
                device_credential_id: cookie.device_credential_id.clone(),
            },
        );
        self.push(
            LoadedStateRequirement::SubjectRevocationForLoadedTrustedDeviceSubject {
                device_credential_id: cookie.device_credential_id.clone(),
            },
        );
    }

    fn push_active_proof_attempt_requirements(&mut self, attempt_id: &ActiveProofAttemptId) {
        self.push(LoadedStateRequirement::ActiveProofAttempt {
            attempt_id: attempt_id.clone(),
        });
        self.push(
            LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
                attempt_id: attempt_id.clone(),
            },
        );
    }

    fn push_active_proof_continuation_requirement_if_presented(
        &mut self,
        presented: &PresentedAuthCookies,
        attempt_id: &ActiveProofAttemptId,
    ) {
        if presented
            .active_proof_continuation_cookie
            .as_ref()
            .is_some_and(|cookie| cookie.attempt_id == *attempt_id)
        {
            self.push(
                LoadedStateRequirement::ActiveProofContinuationSecretMatchForPresentedCookie {
                    attempt_id: attempt_id.clone(),
                },
            );
        }
    }

    fn push(&mut self, requirement: LoadedStateRequirement) {
        if !self.required.contains(&requirement) {
            self.required.push(requirement);
        }
    }
}

impl LoadedStateRequirement {
    fn validate_loaded_state(&self, loaded: &LoadedState) -> Result<(), Error> {
        match self {
            Self::PresentedSessionCookie { session_id } => {
                let Some(cookie) = &loaded.session_cookie else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required presented session cookie is missing",
                    ));
                };
                if cookie.session_id != *session_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded session cookie id differs from required session cookie id",
                    ));
                }
            }
            Self::PresentedTrustedDeviceCookie {
                device_credential_id,
            } => {
                let Some(cookie) = &loaded.trusted_device_cookie else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required presented trusted-device cookie is missing",
                    ));
                };
                if cookie.device_credential_id != *device_credential_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded trusted-device cookie id differs from required trusted-device cookie id",
                    ));
                }
            }
            Self::SessionRecordAndSecretMatchForPresentedCookie { session_id } => {
                let Some(record) = &loaded.session_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required session record is missing",
                    ));
                };
                if record.session_id != *session_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded session record id differs from required session id",
                    ));
                }
                let Some(secret_match) = &loaded.session_secret_match else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required session secret match is missing",
                    ));
                };
                if secret_match.session_id() != session_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded session secret match id differs from required session id",
                    ));
                }
            }
            Self::TrustedDeviceRecordAndSecretMatchForPresentedCookie {
                device_credential_id,
            } => {
                let Some(record) = &loaded.trusted_device_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required trusted-device record is missing",
                    ));
                };
                if record.device_credential_id != *device_credential_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded trusted-device record id differs from required trusted-device id",
                    ));
                }
                let Some(secret_match) = &loaded.trusted_device_secret_match else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required trusted-device secret match is missing",
                    ));
                };
                if secret_match.device_credential_id() != device_credential_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded trusted-device secret match id differs from required trusted-device id",
                    ));
                }
            }
            Self::SubjectRevocationForLoadedSessionSubject { session_id } => {
                let Some(record) = &loaded.session_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required session record for subject revocation is missing",
                    ));
                };
                if record.session_id != *session_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded session record id differs from required subject-revocation session id",
                    ));
                }
                loaded
                    .subject_revocations
                    .required_revocation_for_subject(&record.subject_id)?;
            }
            Self::SubjectRevocationForLoadedTrustedDeviceSubject {
                device_credential_id,
            } => {
                let Some(record) = &loaded.trusted_device_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required trusted-device record for subject revocation is missing",
                    ));
                };
                if record.device_credential_id != *device_credential_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded trusted-device record id differs from required subject-revocation trusted-device id",
                    ));
                }
                loaded
                    .subject_revocations
                    .required_revocation_for_subject(&record.subject_id)?;
            }
            Self::ActiveProofAttempt { attempt_id } => {
                let Some(attempt) = &loaded.active_proof_attempt_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required active-proof attempt is missing",
                    ));
                };
                if attempt.attempt_id != *attempt_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded active-proof attempt id differs from required attempt id",
                    ));
                }
            }
            Self::ActiveProofContinuationSecretMatchForPresentedCookie { attempt_id } => {
                let Some(secret_match) = &loaded.active_proof_continuation_secret_match else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required active-proof continuation secret match is missing",
                    ));
                };
                if secret_match.attempt_id() != attempt_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded active-proof continuation secret match id differs from required attempt id",
                    ));
                }
            }
            Self::SubjectRevocationForLoadedActiveProofAttemptSubject { attempt_id } => {
                let Some(attempt) = &loaded.active_proof_attempt_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required active-proof attempt for subject revocation is missing",
                    ));
                };
                if attempt.attempt_id != *attempt_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded active-proof attempt id differs from required subject-revocation attempt id",
                    ));
                }
                if let Some(subject_id) = &attempt.subject_id {
                    loaded
                        .subject_revocations
                        .required_revocation_for_subject(subject_id)?;
                }
            }
            Self::SubjectRevocationForVerifiedActiveProofSubject { subject_id } => {
                loaded
                    .subject_revocations
                    .required_revocation_for_subject(subject_id)?;
            }
            Self::ActiveProofChallenge { challenge_id } => {
                let Some(challenge) = &loaded.active_proof_challenge_record else {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "required active-proof challenge is missing",
                    ));
                };
                if challenge.challenge_id != *challenge_id {
                    return Err(Error::LoadedStateDoesNotSatisfyLoadContract(
                        "loaded active-proof challenge id differs from required challenge id",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn request_resolution_needs_authoritative_session(
    config: &Config,
    command: &ResolveRequest,
    presented: &PresentedAuthCookies,
    session_cookie: &SessionCookieDraft,
) -> bool {
    if command.now >= session_cookie.session_fast_fail_until {
        return false;
    }
    if presented.trusted_device_cookie.is_some() {
        return true;
    }
    if command.request_kind != RequestKind::SafeRead {
        return true;
    }
    let Some(safe_read_valid_until) = session_cookie.safe_read_valid_until else {
        return true;
    };
    let Some(refresh_cutoff) = session_cookie
        .session_fast_fail_until
        .checked_sub_duration(config.session_refresh_window)
    else {
        return true;
    };
    command.now >= safe_read_valid_until || command.now >= refresh_cutoff
}
