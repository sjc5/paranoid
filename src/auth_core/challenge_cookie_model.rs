use std::fmt;

use crate::crypto::{
    Keyset, MAC_OVER_SECRET_SIZE, MacOverSecret, SecretBytes, random_public_bytes,
};

use super::*;

/// Number of random bytes bound into an active-proof challenge fast-fail MAC.
pub const ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES: usize = 32;

const ACTIVE_PROOF_CHALLENGE_FAST_FAIL_CONTEXT: &[u8] =
    b"paranoid-auth-core/active-proof-challenge-fast-fail/v1";

/// Public nonce bound into a challenge fast-fail MAC.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActiveProofChallengeFastFailNonce([u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES]);

impl ActiveProofChallengeFastFailNonce {
    /// Generates a fresh challenge fast-fail nonce.
    pub fn generate() -> Result<Self, Error> {
        let bytes = random_public_bytes(ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES)
            .map_err(|_| Error::FreshRandomMaterialUnavailable)?;
        Self::from_bytes(bytes.as_bytes())
    }

    /// Copies exactly 32 nonce bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES {
            return Err(Error::InvalidActiveProofChallengeFastFailNonceLength {
                actual: bytes.len(),
            });
        }
        let mut nonce = [0_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES];
        nonce.copy_from_slice(bytes);
        Ok(Self(nonce))
    }

    /// Returns the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES] {
        &self.0
    }
}

/// Public MAC stored inside the encrypted active-proof challenge cookie.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActiveProofChallengeFastFailMac([u8; MAC_OVER_SECRET_SIZE]);

impl ActiveProofChallengeFastFailMac {
    /// Validates and copies a `MacOverSecret` byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != MAC_OVER_SECRET_SIZE {
            return Err(Error::InvalidActiveProofChallengeFastFailMacLength {
                actual: bytes.len(),
            });
        }
        MacOverSecret::try_from(bytes)
            .map_err(|_| Error::InvalidActiveProofChallengeFastFailMac)?;
        let mut mac = [0_u8; MAC_OVER_SECRET_SIZE];
        mac.copy_from_slice(bytes);
        Ok(Self(mac))
    }

    /// Converts a computed `MacOverSecret` into cookie MAC bytes.
    pub fn from_mac_over_secret(mac: MacOverSecret) -> Result<Self, Error> {
        let bytes = mac.into_bytes();
        Self::from_bytes(&bytes)
    }

    /// Returns the public MAC bytes.
    pub fn as_bytes(&self) -> &[u8; MAC_OVER_SECRET_SIZE] {
        &self.0
    }

    fn to_mac_over_secret(&self) -> Result<MacOverSecret, Error> {
        MacOverSecret::try_from(self.0.as_slice())
            .map_err(|_| Error::InvalidActiveProofChallengeFastFailMac)
    }
}

/// User-supplied active-proof challenge response material.
pub struct ActiveProofChallengeResponseSecret(SecretBytes<ActiveProofChallengeResponseSecretKind>);

/// Marker for active-proof challenge response bytes.
pub enum ActiveProofChallengeResponseSecretKind {}

impl ActiveProofChallengeResponseSecret {
    /// Generates random challenge response bytes for a Paranoid-owned method plugin.
    pub fn generate(byte_len: usize) -> Result<Self, Error> {
        if byte_len == 0 {
            return Err(Error::EmptyActiveProofChallengeResponseSecret);
        }
        Ok(Self(
            SecretBytes::<ActiveProofChallengeResponseSecretKind>::random(byte_len)
                .map_err(|_| Error::FreshRandomMaterialUnavailable)?,
        ))
    }

    /// Copies response bytes into zeroizing memory.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyActiveProofChallengeResponseSecret);
        }
        Ok(Self(
            SecretBytes::<ActiveProofChallengeResponseSecretKind>::try_from(bytes).map_err(
                |_| Error::LoadedStateContradiction("challenge response allocation failed"),
            )?,
        ))
    }

    /// Explicitly exposes the response bytes for MAC verification.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl TryFrom<&[u8]> for ActiveProofChallengeResponseSecret {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(value)
    }
}

impl fmt::Debug for ActiveProofChallengeResponseSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveProofChallengeResponseSecret")
            .field("len", &self.expose_secret().len())
            .finish()
    }
}

/// Decoded active-proof challenge cookie payload before transport encryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofChallengeCookieDraft {
    /// Attempt that owns the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Challenge this cookie can complete.
    pub challenge_id: ActiveProofChallengeId,
    /// Proof this challenge can satisfy.
    pub proof: ProofSummary,
    /// Time the cookie payload was minted.
    pub issued_at: UnixSeconds,
    /// Last time the cookie can pass stateless fast-fail.
    pub expires_at: UnixSeconds,
    /// Public random nonce bound into the fast-fail MAC.
    pub nonce: ActiveProofChallengeFastFailNonce,
    /// Public MAC over the user-supplied response secret and challenge context, if this challenge uses submitted-secret fast-fail.
    pub response_mac: Option<ActiveProofChallengeFastFailMac>,
    /// Method-specific state sealed inside the encrypted challenge cookie.
    pub method_challenge_state: Option<ActiveProofMethodChallengeState>,
}

/// Context that all active-proof challenge cookies bind into their sealed payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofChallengeCookieContext {
    /// Attempt that owns the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Challenge this cookie can complete.
    pub challenge_id: ActiveProofChallengeId,
    /// Proof this challenge can satisfy.
    pub proof: ProofSummary,
    /// Time the cookie payload was minted.
    pub issued_at: UnixSeconds,
    /// Last time the cookie can pass stateless fast-fail.
    pub expires_at: UnixSeconds,
    /// Public random nonce bound into the fast-fail MAC.
    pub nonce: ActiveProofChallengeFastFailNonce,
}

impl ActiveProofChallengeCookieContext {
    /// Creates the common challenge-cookie context.
    pub fn new(
        attempt_id: ActiveProofAttemptId,
        challenge_id: ActiveProofChallengeId,
        proof: ProofSummary,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        nonce: ActiveProofChallengeFastFailNonce,
    ) -> Result<Self, Error> {
        proof.validate()?;
        if expires_at <= issued_at {
            return Err(Error::ActiveProofChallengeCookieExpiresAtOrBeforeIssuedAt);
        }
        Ok(Self {
            attempt_id,
            challenge_id,
            proof,
            issued_at,
            expires_at,
            nonce,
        })
    }
}

impl ActiveProofChallengeCookieDraft {
    /// Creates a challenge cookie draft with an already-computed fast-fail MAC.
    pub fn new(
        context: ActiveProofChallengeCookieContext,
        response_mac: ActiveProofChallengeFastFailMac,
    ) -> Result<Self, Error> {
        Self::new_with_optional_response_mac_and_method_state(context, Some(response_mac), None)
    }

    /// Creates a challenge cookie draft without submitted-secret fast-fail.
    pub fn new_without_response_mac(
        context: ActiveProofChallengeCookieContext,
    ) -> Result<Self, Error> {
        Self::new_with_optional_response_mac_and_method_state(context, None, None)
    }

    /// Creates a challenge cookie draft with method-specific sealed state.
    pub fn new_with_method_challenge_state(
        context: ActiveProofChallengeCookieContext,
        method_challenge_state: ActiveProofMethodChallengeState,
    ) -> Result<Self, Error> {
        Self::new_with_optional_response_mac_and_method_state(
            context,
            None,
            Some(method_challenge_state),
        )
    }

    /// Creates a challenge cookie draft with optional submitted-secret fast-fail.
    pub fn new_with_optional_response_mac(
        context: ActiveProofChallengeCookieContext,
        response_mac: Option<ActiveProofChallengeFastFailMac>,
    ) -> Result<Self, Error> {
        Self::new_with_optional_response_mac_and_method_state(context, response_mac, None)
    }

    pub(crate) fn new_with_optional_response_mac_and_method_state(
        context: ActiveProofChallengeCookieContext,
        response_mac: Option<ActiveProofChallengeFastFailMac>,
        method_challenge_state: Option<ActiveProofMethodChallengeState>,
    ) -> Result<Self, Error> {
        Ok(Self {
            attempt_id: context.attempt_id,
            challenge_id: context.challenge_id,
            proof: context.proof,
            issued_at: context.issued_at,
            expires_at: context.expires_at,
            nonce: context.nonce,
            response_mac,
            method_challenge_state,
        })
    }

    /// Creates a challenge cookie draft by MACing the response secret.
    pub fn new_with_response_secret(
        keyset: &Keyset,
        context: ActiveProofChallengeCookieContext,
        response_secret: &ActiveProofChallengeResponseSecret,
    ) -> Result<Self, Error> {
        let context_without_mac = ActiveProofChallengeCookieDraftWithoutMac {
            attempt_id: context.attempt_id,
            challenge_id: context.challenge_id,
            proof: context.proof,
            issued_at: context.issued_at,
            expires_at: context.expires_at,
            nonce: context.nonce,
            method_challenge_state: None,
        };
        let mac_context = context_without_mac.fast_fail_mac_context()?;
        let mac = response_secret
            .0
            .to_mac(keyset, &mac_context)
            .map_err(|_| Error::InvalidActiveProofChallengeFastFailMac)?;
        Ok(Self {
            attempt_id: context_without_mac.attempt_id,
            challenge_id: context_without_mac.challenge_id,
            proof: context_without_mac.proof,
            issued_at: context_without_mac.issued_at,
            expires_at: context_without_mac.expires_at,
            nonce: context_without_mac.nonce,
            response_mac: Some(ActiveProofChallengeFastFailMac::from_mac_over_secret(mac)?),
            method_challenge_state: None,
        })
    }

    /// Verifies the submitted response before any stateful load occurs.
    pub fn verify_response_secret_before_state_load(
        &self,
        keyset: &Keyset,
        now: UnixSeconds,
        command: &CompleteActiveProofChallenge,
        response_secret: &ActiveProofChallengeResponseSecret,
    ) -> Result<StatelessFastFailStatus, Error> {
        self.validate_matches_completion_command(command)?;
        if now >= self.expires_at {
            return Err(Error::ActiveProofChallengeCookieExpired);
        }
        let Some(response_mac) = &self.response_mac else {
            return Err(
                Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                    family: self.proof.family(),
                },
            );
        };
        let context = self.fast_fail_mac_context()?;
        if !response_mac.to_mac_over_secret()?.verify(
            keyset,
            response_secret.expose_secret(),
            &context,
        ) {
            return Err(Error::StatelessFastFailVerificationFailed);
        }
        Ok(StatelessFastFailStatus::verified_before_state_load())
    }

    pub(crate) fn validate_matches_completion_command(
        &self,
        command: &CompleteActiveProofChallenge,
    ) -> Result<(), Error> {
        if self.attempt_id != command.attempt_id {
            return Err(Error::ActiveProofChallengeCookieCommandMismatch);
        }
        if command
            .challenge_id
            .as_ref()
            .is_some_and(|challenge_id| *challenge_id != self.challenge_id)
        {
            return Err(Error::ActiveProofChallengeCookieCommandMismatch);
        }
        if command.verified_proof.proof() != &self.proof {
            return Err(Error::ActiveProofChallengeCookieCommandMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_for_out_of_band_resend_before_state_load(
        &self,
        now: UnixSeconds,
    ) -> Result<(), Error> {
        if self.proof.family() != ProofFamily::OutOfBandCode || self.response_mac.is_none() {
            return Err(
                Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                    family: self.proof.family(),
                },
            );
        }
        if now >= self.expires_at {
            return Err(Error::ActiveProofChallengeCookieExpired);
        }
        Ok(())
    }

    pub(crate) fn validate_for_out_of_band_completion_before_state_load(
        &self,
        now: UnixSeconds,
    ) -> Result<(), Error> {
        if self.proof.family() != ProofFamily::OutOfBandCode || self.response_mac.is_none() {
            return Err(
                Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                    family: self.proof.family(),
                },
            );
        }
        self.validate_not_expired_before_state_load(now)
    }

    pub(crate) fn validate_for_active_method_completion_before_state_load(
        &self,
        now: UnixSeconds,
    ) -> Result<(), Error> {
        if self.proof.family() == ProofFamily::OutOfBandCode {
            return Err(Error::OutOfBandActiveProofCompletionRequiresChallengeResponse);
        }
        if self.response_mac.is_some() {
            return Err(
                Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                    family: self.proof.family(),
                },
            );
        }
        self.validate_not_expired_before_state_load(now)?;
        if self.method_challenge_state.is_none() {
            return Err(Error::MissingActiveProofMethodChallengeState);
        }
        Ok(())
    }

    pub(crate) fn validate_not_expired_before_state_load(
        &self,
        now: UnixSeconds,
    ) -> Result<(), Error> {
        if now >= self.expires_at {
            return Err(Error::ActiveProofChallengeCookieExpired);
        }
        Ok(())
    }

    pub(crate) fn requires_stateless_fast_fail(&self) -> bool {
        self.response_mac.is_some()
    }

    fn fast_fail_mac_context(&self) -> Result<Vec<u8>, Error> {
        ActiveProofChallengeCookieDraftWithoutMac {
            attempt_id: self.attempt_id.clone(),
            challenge_id: self.challenge_id.clone(),
            proof: self.proof.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            nonce: self.nonce.clone(),
            method_challenge_state: self.method_challenge_state.clone(),
        }
        .fast_fail_mac_context()
    }
}

struct ActiveProofChallengeCookieDraftWithoutMac {
    attempt_id: ActiveProofAttemptId,
    challenge_id: ActiveProofChallengeId,
    proof: ProofSummary,
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
    nonce: ActiveProofChallengeFastFailNonce,
    method_challenge_state: Option<ActiveProofMethodChallengeState>,
}

impl ActiveProofChallengeCookieDraftWithoutMac {
    fn fast_fail_mac_context(&self) -> Result<Vec<u8>, Error> {
        let mut context = Vec::new();
        append_context_part(&mut context, ACTIVE_PROOF_CHALLENGE_FAST_FAIL_CONTEXT)?;
        append_context_part(&mut context, self.attempt_id.as_bytes())?;
        append_context_part(&mut context, self.challenge_id.as_bytes())?;
        append_context_part(&mut context, &[proof_family_wire_id(self.proof.family())])?;
        append_context_part(
            &mut context,
            &[online_guessing_risk_wire_id(
                self.proof.online_guessing_risk(),
            )],
        )?;
        append_context_part(&mut context, self.proof.method_label().as_bytes())?;
        append_context_part(&mut context, &self.issued_at.get().to_be_bytes())?;
        append_context_part(&mut context, &self.expires_at.get().to_be_bytes())?;
        append_context_part(&mut context, self.nonce.as_bytes())?;
        match &self.method_challenge_state {
            Some(method_challenge_state) => {
                append_context_part(&mut context, &[1])?;
                append_context_part(&mut context, method_challenge_state.as_bytes())?;
            }
            None => append_context_part(&mut context, &[0])?,
        }
        Ok(context)
    }
}

fn append_context_part(context: &mut Vec<u8>, part: &[u8]) -> Result<(), Error> {
    let len = u64::try_from(part.len()).map_err(|_| Error::TimeOverflow)?;
    context
        .try_reserve_exact(8 + part.len())
        .map_err(|_| Error::LoadedStateContradiction("fast-fail context allocation failed"))?;
    context.extend_from_slice(&len.to_be_bytes());
    context.extend_from_slice(part);
    Ok(())
}

pub(crate) fn proof_family_wire_id(family: ProofFamily) -> u8 {
    match family {
        ProofFamily::OutOfBandCode => 1,
        ProofFamily::MessageSignature => 2,
        ProofFamily::OriginBoundPublicKey => 3,
        ProofFamily::FederatedIdentityAssertion => 4,
        ProofFamily::SharedSecretOtp => 5,
        ProofFamily::TrustedDevice => 6,
        ProofFamily::RecoveryCode => 7,
    }
}

pub(crate) fn proof_family_from_wire_id(id: u8) -> Result<ProofFamily, Error> {
    match id {
        1 => Ok(ProofFamily::OutOfBandCode),
        2 => Ok(ProofFamily::MessageSignature),
        3 => Ok(ProofFamily::OriginBoundPublicKey),
        4 => Ok(ProofFamily::FederatedIdentityAssertion),
        5 => Ok(ProofFamily::SharedSecretOtp),
        6 => Ok(ProofFamily::TrustedDevice),
        7 => Ok(ProofFamily::RecoveryCode),
        _ => Err(Error::InvalidActiveProofChallengeCookiePayload),
    }
}

pub(crate) fn online_guessing_risk_wire_id(risk: OnlineGuessingRisk) -> u8 {
    match risk {
        OnlineGuessingRisk::NotOnlineGuessable => 1,
        OnlineGuessingRisk::OnlineGuessable => 2,
    }
}

pub(crate) fn online_guessing_risk_from_wire_id(id: u8) -> Result<OnlineGuessingRisk, Error> {
    match id {
        1 => Ok(OnlineGuessingRisk::NotOnlineGuessable),
        2 => Ok(OnlineGuessingRisk::OnlineGuessable),
        _ => Err(Error::InvalidActiveProofChallengeCookiePayload),
    }
}

pub(crate) fn proof_use_wire_id(proof_use: ProofUse) -> u8 {
    match proof_use {
        ProofUse::BindSubjectToActiveProofAttempt => 1,
        ProofUse::ContributeToFullAuthentication => 2,
        ProofUse::ReviveTrustedDeviceWithActiveProof => 3,
        ProofUse::SatisfyStepUp => 4,
        ProofUse::SilentlyReviveTrustedDeviceSession => 5,
        ProofUse::ReduceAuthenticationRequirement => 6,
        ProofUse::RecoverOrReplaceCredential => 7,
    }
}

pub(crate) fn proof_use_from_wire_id(id: u8) -> Result<ProofUse, Error> {
    match id {
        1 => Ok(ProofUse::BindSubjectToActiveProofAttempt),
        2 => Ok(ProofUse::ContributeToFullAuthentication),
        3 => Ok(ProofUse::ReviveTrustedDeviceWithActiveProof),
        4 => Ok(ProofUse::SatisfyStepUp),
        5 => Ok(ProofUse::SilentlyReviveTrustedDeviceSession),
        6 => Ok(ProofUse::ReduceAuthenticationRequirement),
        7 => Ok(ProofUse::RecoverOrReplaceCredential),
        _ => Err(Error::InvalidActiveProofContinuationCookiePayload),
    }
}
