use super::prelude::*;
use crate::crypto::{Keyset, MacOverSecret, SecretBytes};

/// Active-proof attempt creation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartActiveProofAttempt {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Fresh attempt id.
    pub attempt_id: ActiveProofAttemptId,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
    /// Subject already known by the flow, if any.
    pub subject_id: Option<SubjectId>,
}

/// Active-proof attempt creation command bound to the current session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartActiveProofAttemptForCurrentSession {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Fresh attempt id.
    pub attempt_id: ActiveProofAttemptId,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
}

/// Active-proof attempt creation command bound to the current trusted device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartActiveProofAttemptForCurrentTrustedDevice {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Fresh attempt id.
    pub attempt_id: ActiveProofAttemptId,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
}

/// Runtime-facing current-session active-proof attempt start input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartCurrentSessionActiveProofAttemptInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
}

/// Runtime-facing current-trusted-device active-proof attempt start input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartCurrentTrustedDeviceActiveProofAttemptInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
}

/// Runtime-facing unauthenticated recovery active-proof attempt start input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartUnauthenticatedRecoveryActiveProofAttemptInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Recovery proof method that will complete the attempt.
    pub method: ProofMethodDeclaration,
}

/// Out-of-band challenge issue command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueOutOfBandChallengeRequest {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt receiving the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Out-of-band proof method that owns this challenge.
    pub method: ProofMethodDeclaration,
    /// Generic dedupe key for the challenge target and proof method.
    pub challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    /// Live challenges created at or before this timestamp may be replaced.
    pub(crate) replaceable_created_at_or_before: Option<UnixSeconds>,
    /// Opaque recipient handle understood by the adapter.
    pub recipient_handle: String,
    /// Delivery idempotency key the adapter must use.
    pub idempotency_key: String,
}

/// Runtime-facing out-of-band challenge issue input for an existing attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueOutOfBandChallengeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Out-of-band proof method that owns this challenge.
    pub method: ProofMethodDeclaration,
    /// Generic dedupe key for the challenge target and proof method.
    pub challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    /// Opaque recipient handle understood by the adapter.
    pub recipient_handle: String,
    /// Delivery idempotency key the adapter must use.
    pub idempotency_key: String,
}

impl IssueOutOfBandChallengeInput {
    pub(crate) fn into_request(
        self,
        attempt_id: ActiveProofAttemptId,
        challenge_id: ActiveProofChallengeId,
        replaceable_created_at_or_before: Option<UnixSeconds>,
    ) -> IssueOutOfBandChallengeRequest {
        IssueOutOfBandChallengeRequest {
            now: self.now,
            attempt_id,
            challenge_id,
            method: self.method,
            challenge_dedupe_key: self.challenge_dedupe_key,
            replaceable_created_at_or_before,
            recipient_handle: self.recipient_handle,
            idempotency_key: self.idempotency_key,
        }
    }
}

/// Runtime-facing fused unbound active-proof start plus out-of-band challenge input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartAndIssueOutOfBandChallengeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
    /// Out-of-band proof method that owns this challenge.
    pub method: ProofMethodDeclaration,
    /// Generic dedupe key for the challenge target and proof method.
    pub challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    /// Opaque recipient handle understood by the adapter.
    pub recipient_handle: String,
    /// Delivery idempotency key the adapter must use.
    pub idempotency_key: String,
}

/// Runtime-facing fused unbound active-proof start whose out-of-band delivery facts are method-derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartAndIssueMethodDerivedOutOfBandChallengeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
    /// Out-of-band proof method that owns this challenge.
    pub method: ProofMethodDeclaration,
    /// Method-specific payload used by the method plugin to derive delivery facts.
    pub method_payload: Vec<u8>,
}

impl StartAndIssueOutOfBandChallengeInput {
    pub(crate) fn into_request(
        self,
        attempt_id: ActiveProofAttemptId,
        challenge_id: ActiveProofChallengeId,
        replaceable_created_at_or_before: Option<UnixSeconds>,
    ) -> IssueOutOfBandChallengeRequest {
        IssueOutOfBandChallengeRequest {
            now: self.now,
            attempt_id,
            challenge_id,
            method: self.method,
            challenge_dedupe_key: self.challenge_dedupe_key,
            replaceable_created_at_or_before,
            recipient_handle: self.recipient_handle,
            idempotency_key: self.idempotency_key,
        }
    }
}

impl IssueOutOfBandChallengeRequest {
    pub(crate) fn into_command_with_stateless_fast_fail_cookie(
        self,
        stateless_fast_fail_cookie: ActiveProofChallengeCookieDraft,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> IssueOutOfBandChallenge {
        IssueOutOfBandChallenge {
            now: self.now,
            attempt_id: self.attempt_id,
            challenge_id: self.challenge_id,
            method: self.method,
            challenge_dedupe_key: self.challenge_dedupe_key,
            recipient_handle: self.recipient_handle,
            idempotency_key: self.idempotency_key,
            stateless_fast_fail_cookie,
            method_commit_work,
        }
    }
}

/// Active-proof method challenge issue request before runtime-owned nonce construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueActiveProofMethodChallengeRequest {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt receiving the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Active proof method that owns challenge presentation and verification.
    pub method: ProofMethodDeclaration,
    /// Method-specific opaque challenge request payload supplied to the method plugin.
    pub method_challenge_request_payload: Option<ActiveProofMethodChallengeRequestPayload>,
}

/// Runtime-facing active-proof method challenge issue input for an existing attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueActiveProofMethodChallengeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Active proof method that owns challenge presentation and verification.
    pub method: ProofMethodDeclaration,
    /// Method-specific opaque challenge request payload supplied to the method plugin.
    pub method_challenge_request_payload: Option<ActiveProofMethodChallengeRequestPayload>,
}

/// Runtime-facing challenge-bound known-subject configured-secret challenge issue input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueChallengeBoundKnownSubjectActiveProofMethodChallengeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Known-subject configured-secret method that owns challenge presentation and verification.
    pub method: ProofMethodDeclaration,
    /// Method-specific opaque challenge request payload supplied to the method plugin.
    pub method_challenge_request_payload: Option<ActiveProofMethodChallengeRequestPayload>,
}

impl IssueActiveProofMethodChallengeInput {
    pub(crate) fn into_request(
        self,
        attempt_id: ActiveProofAttemptId,
        challenge_id: ActiveProofChallengeId,
    ) -> IssueActiveProofMethodChallengeRequest {
        IssueActiveProofMethodChallengeRequest {
            now: self.now,
            attempt_id,
            challenge_id,
            method: self.method,
            method_challenge_request_payload: self.method_challenge_request_payload,
        }
    }
}

/// Runtime-facing fused unbound active-proof start plus method challenge input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartAndIssueActiveProofMethodChallengeInput {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
    /// Active proof method that owns challenge presentation and verification.
    pub method: ProofMethodDeclaration,
    /// Method-specific opaque challenge request payload supplied to the method plugin.
    pub method_challenge_request_payload: Option<ActiveProofMethodChallengeRequestPayload>,
}

impl StartAndIssueActiveProofMethodChallengeInput {
    pub(crate) fn into_request(
        self,
        attempt_id: ActiveProofAttemptId,
        challenge_id: ActiveProofChallengeId,
    ) -> IssueActiveProofMethodChallengeRequest {
        IssueActiveProofMethodChallengeRequest {
            now: self.now,
            attempt_id,
            challenge_id,
            method: self.method,
            method_challenge_request_payload: self.method_challenge_request_payload,
        }
    }
}

impl IssueActiveProofMethodChallengeRequest {
    pub(crate) fn into_command_with_challenge(
        self,
        challenge_cookie: ActiveProofChallengeCookieDraft,
        method_challenge: ActiveProofMethodChallengePresentation,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> IssueActiveProofMethodChallenge {
        IssueActiveProofMethodChallenge {
            now: self.now,
            attempt_id: self.attempt_id,
            challenge_id: self.challenge_id,
            method: self.method,
            challenge_issue_kind: ActiveProofMethodChallengeIssueKind::NormalActiveMethod,
            challenge_cookie,
            method_challenge,
            method_commit_work,
        }
    }
}

/// Active-proof method challenge issue command after runtime-owned nonce construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueActiveProofMethodChallenge {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt receiving the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Active proof method that owns challenge presentation and verification.
    pub method: ProofMethodDeclaration,
    /// Runtime-selected method challenge lane.
    pub(crate) challenge_issue_kind: ActiveProofMethodChallengeIssueKind,
    /// Challenge cookie binding completion to runtime-owned challenge material.
    pub(crate) challenge_cookie: ActiveProofChallengeCookieDraft,
    /// Method-specific public challenge material shown to the client.
    pub(crate) method_challenge: ActiveProofMethodChallengePresentation,
    /// Method/plugin work that must commit atomically with accepting this challenge.
    pub(super) method_commit_work: Vec<MethodCommitWork>,
}

/// Which active-proof method challenge lane produced a challenge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ActiveProofMethodChallengeIssueKind {
    /// Normal active method challenge, such as message signatures, WebAuthn, or OIDC.
    NormalActiveMethod,
    /// Known-subject configured-secret challenge carrying a stateless Bloom rejection gate.
    ChallengeBoundConfiguredSecretFastFail,
}

/// Out-of-band challenge issue command after runtime-owned cookie construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueOutOfBandChallenge {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt receiving the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Out-of-band proof method that owns this challenge.
    pub method: ProofMethodDeclaration,
    /// Generic dedupe key for the challenge target and proof method.
    pub challenge_dedupe_key: OutOfBandChallengeDedupeKey,
    /// Opaque recipient handle understood by the adapter.
    pub recipient_handle: String,
    /// Delivery idempotency key the adapter must use.
    pub idempotency_key: String,
    /// Challenge cookie that enables stateless fast-fail before state loading.
    pub(crate) stateless_fast_fail_cookie: ActiveProofChallengeCookieDraft,
    /// Method/plugin work that must commit atomically with accepting this challenge.
    pub(super) method_commit_work: Vec<MethodCommitWork>,
}

/// Runtime-generated challenge seed passed to a method plugin before cookie sealing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofMethodChallengeSeed {
    /// Attempt receiving the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Proof this challenge can satisfy.
    pub proof: ProofSummary,
    /// Time the challenge was issued.
    pub issued_at: UnixSeconds,
    /// Time the challenge expires.
    pub expires_at: UnixSeconds,
    /// Runtime-generated nonce the plugin must bind into its challenge presentation.
    pub nonce: ActiveProofChallengeFastFailNonce,
}

/// Runtime-sealed method challenge material passed back to a method plugin for verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofMethodChallengeMaterial {
    /// Attempt receiving the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Fresh challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Proof this challenge can satisfy.
    pub proof: ProofSummary,
    /// Time the challenge was issued.
    pub issued_at: UnixSeconds,
    /// Time the challenge expires.
    pub expires_at: UnixSeconds,
    /// Runtime-generated nonce the plugin must bind into its challenge presentation.
    pub nonce: ActiveProofChallengeFastFailNonce,
    /// Method-specific state sealed into the encrypted challenge cookie.
    pub method_challenge_state: ActiveProofMethodChallengeState,
}

impl ActiveProofMethodChallengeSeed {
    pub(crate) fn from_cookie(cookie: &ActiveProofChallengeCookieDraft) -> Self {
        Self {
            attempt_id: cookie.attempt_id.clone(),
            challenge_id: cookie.challenge_id.clone(),
            proof: cookie.proof.clone(),
            issued_at: cookie.issued_at,
            expires_at: cookie.expires_at,
            nonce: cookie.nonce.clone(),
        }
    }
}

impl ActiveProofMethodChallengeMaterial {
    pub(crate) fn from_cookie(cookie: &ActiveProofChallengeCookieDraft) -> Result<Self, Error> {
        Ok(Self {
            attempt_id: cookie.attempt_id.clone(),
            challenge_id: cookie.challenge_id.clone(),
            proof: cookie.proof.clone(),
            issued_at: cookie.issued_at,
            expires_at: cookie.expires_at,
            nonce: cookie.nonce.clone(),
            method_challenge_state: cookie
                .method_challenge_state
                .clone()
                .ok_or(Error::MissingActiveProofMethodChallengeState)?,
        })
    }
}

/// Method-specific public challenge material shown to the client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofMethodChallengePresentation(Vec<u8>);

impl ActiveProofMethodChallengePresentation {
    /// Creates a bounded non-empty method challenge presentation.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptyActiveProofMethodChallengePresentation);
        }
        validate_auth_bytes_not_too_long(
            "active-proof method challenge presentation",
            &bytes,
            ACTIVE_PROOF_METHOD_CHALLENGE_PRESENTATION_MAX_BYTES,
        )?;
        Ok(Self(bytes))
    }

    /// Returns the public challenge bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Method-specific opaque challenge request payload supplied to a method plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofMethodChallengeRequestPayload(Vec<u8>);

impl ActiveProofMethodChallengeRequestPayload {
    /// Creates a bounded non-empty method challenge request payload.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptyActiveProofMethodChallengeRequestPayload);
        }
        validate_auth_bytes_not_too_long(
            "active-proof method challenge request payload",
            &bytes,
            ACTIVE_PROOF_METHOD_CHALLENGE_REQUEST_PAYLOAD_MAX_BYTES,
        )?;
        Ok(Self(bytes))
    }

    /// Returns the opaque request bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Method-specific opaque challenge state sealed into the encrypted challenge cookie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofMethodChallengeState(Vec<u8>);

impl ActiveProofMethodChallengeState {
    /// Creates bounded non-empty method challenge state.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptyActiveProofMethodChallengeState);
        }
        validate_auth_bytes_not_too_long(
            "active-proof method challenge state",
            &bytes,
            ACTIVE_PROOF_METHOD_CHALLENGE_STATE_MAX_BYTES,
        )?;
        Ok(Self(bytes))
    }

    /// Returns the opaque state bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Method-specific opaque challenge response supplied by the client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofMethodResponsePayload(Vec<u8>);

impl ActiveProofMethodResponsePayload {
    /// Creates a bounded non-empty method response payload.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptyActiveProofMethodResponsePayload);
        }
        validate_auth_bytes_not_too_long(
            "active-proof method response payload",
            &bytes,
            ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
        )?;
        Ok(Self(bytes))
    }

    /// Returns the opaque response bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Secret response supplied for a known-subject configured-secret method.
pub struct KnownSubjectActiveProofSecretResponse(SecretBytes<KnownSubjectActiveProofSecretKind>);

impl KnownSubjectActiveProofSecretResponse {
    /// Creates a bounded non-empty secret response.
    pub fn try_from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptyKnownSubjectActiveProofSecretResponse);
        }
        validate_auth_bytes_not_too_long(
            "known-subject active-proof secret response",
            &bytes,
            ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
        )?;
        SecretBytes::<KnownSubjectActiveProofSecretKind>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::EmptyKnownSubjectActiveProofSecretResponse)
    }

    /// Explicitly exposes the submitted secret response bytes.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for KnownSubjectActiveProofSecretResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownSubjectActiveProofSecretResponse")
            .field("len", &self.0.len())
            .finish()
    }
}

enum KnownSubjectActiveProofSecretKind {}

/// Bloom filter for challenge-bound configured-secret fast-fail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeBoundConfiguredSecretFastFailBloomFilter {
    bitset: Vec<u8>,
    hash_count: u8,
}

impl ChallengeBoundConfiguredSecretFastFailBloomFilter {
    /// Creates an empty bounded Bloom filter.
    pub fn new(bitset_byte_len: usize, hash_count: u8) -> Result<Self, Error> {
        validate_challenge_bound_configured_secret_bloom_filter_parameters(
            bitset_byte_len,
            hash_count,
        )?;
        Ok(Self {
            bitset: vec![0_u8; bitset_byte_len],
            hash_count,
        })
    }

    /// Creates a Bloom filter from wire/storage parts.
    pub fn try_from_parts(bitset: Vec<u8>, hash_count: u8) -> Result<Self, Error> {
        validate_challenge_bound_configured_secret_bloom_filter_parameters(
            bitset.len(),
            hash_count,
        )?;
        Ok(Self { bitset, hash_count })
    }

    /// Returns the Bloom-filter bitset bytes.
    pub fn bitset_bytes(&self) -> &[u8] {
        &self.bitset
    }

    /// Returns the configured number of hash probes.
    pub const fn hash_count(&self) -> u8 {
        self.hash_count
    }

    /// Inserts one accepted response using the latest key in the current keyset.
    pub fn insert_response_for_latest_key(
        &mut self,
        keyset: &Keyset,
        challenge_context: &[u8],
        response: &KnownSubjectActiveProofSecretResponse,
    ) -> Result<(), Error> {
        let mac = response
            .0
            .to_mac(keyset, challenge_context)
            .map_err(|_| Error::LoadedStateContradiction("configured-secret Bloom MAC failed"))?;
        self.insert_mac(&mac);
        Ok(())
    }

    /// Returns true when the submitted response may be present in the Bloom filter.
    pub fn might_contain_response_in_challenge_context(
        &self,
        keyset: &Keyset,
        challenge_context: &[u8],
        response: &KnownSubjectActiveProofSecretResponse,
    ) -> Result<bool, Error> {
        let macs = response
            .0
            .to_macs_for_all_keyset_keys(keyset, challenge_context)
            .map_err(|_| Error::LoadedStateContradiction("configured-secret Bloom MAC failed"))?;
        let mut any_match = 0_u8;
        for mac in &macs {
            any_match |= u8::from(self.mac_might_be_present(mac));
        }
        Ok(any_match == 1)
    }

    /// Returns true when the submitted response can be rejected before state loading.
    pub fn definitely_rejects_response_in_challenge_context(
        &self,
        keyset: &Keyset,
        challenge_context: &[u8],
        response: &KnownSubjectActiveProofSecretResponse,
    ) -> Result<bool, Error> {
        self.might_contain_response_in_challenge_context(keyset, challenge_context, response)
            .map(|might_contain| !might_contain)
    }

    fn insert_mac(&mut self, mac: &MacOverSecret) {
        let (first_hash, second_hash) = bloom_hash_pair(mac);
        let bit_count = self.bitset.len() * 8;
        for index in 0..self.hash_count {
            let bit_index = bloom_index(first_hash, second_hash, bit_count, index);
            self.set_bit(bit_index);
        }
    }

    fn mac_might_be_present(&self, mac: &MacOverSecret) -> bool {
        let (first_hash, second_hash) = bloom_hash_pair(mac);
        let bit_count = self.bitset.len() * 8;
        let mut all_present = 1_u8;
        for index in 0..self.hash_count {
            let bit_index = bloom_index(first_hash, second_hash, bit_count, index);
            all_present &= u8::from(self.bit_is_set(bit_index));
        }
        all_present == 1
    }

    fn set_bit(&mut self, bit_index: usize) {
        let byte_index = bit_index / 8;
        let bit_in_byte = bit_index % 8;
        self.bitset[byte_index] |= 1_u8 << bit_in_byte;
    }

    fn bit_is_set(&self, bit_index: usize) -> bool {
        let byte_index = bit_index / 8;
        let bit_in_byte = bit_index % 8;
        self.bitset[byte_index] & (1_u8 << bit_in_byte) != 0
    }
}

fn validate_challenge_bound_configured_secret_bloom_filter_parameters(
    bitset_byte_len: usize,
    hash_count: u8,
) -> Result<(), Error> {
    if bitset_byte_len == 0 {
        return Err(Error::EmptyChallengeBoundConfiguredSecretFastFailBloomFilter);
    }
    if bitset_byte_len > CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_BYTES {
        return Err(Error::InputTooLong {
            input_name: "challenge-bound configured-secret fast-fail Bloom filter",
            max_bytes: CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_BYTES,
        });
    }
    if hash_count == 0
        || hash_count > CHALLENGE_BOUND_CONFIGURED_SECRET_FAST_FAIL_BLOOM_FILTER_MAX_HASH_COUNT
    {
        return Err(
            Error::InvalidChallengeBoundConfiguredSecretFastFailBloomFilterHashCount {
                actual: hash_count,
            },
        );
    }
    Ok(())
}

fn bloom_hash_pair(mac: &MacOverSecret) -> (u64, u64) {
    let bytes = mac.as_bytes();
    let mut first = [0_u8; 8];
    let mut second = [0_u8; 8];
    first.copy_from_slice(&bytes[1..9]);
    second.copy_from_slice(&bytes[9..17]);
    (u64::from_be_bytes(first), u64::from_be_bytes(second))
}

fn bloom_index(first_hash: u64, second_hash: u64, bit_count: usize, index: u8) -> usize {
    first_hash
        .wrapping_add(u64::from(index).wrapping_mul(second_hash | 1))
        .rem_euclid(bit_count as u64) as usize
}

/// Out-of-band challenge resend request before method/plugin commit work is attached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResendOutOfBandChallengeRequest {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Fresh delivery idempotency key the adapter must use for this resend.
    pub idempotency_key: String,
}

impl ResendOutOfBandChallengeRequest {
    pub(crate) fn into_command_with_challenge_cookie(
        self,
        challenge_cookie: &ActiveProofChallengeCookieDraft,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> ResendOutOfBandChallenge {
        ResendOutOfBandChallenge {
            now: self.now,
            attempt_id: challenge_cookie.attempt_id.clone(),
            challenge_id: challenge_cookie.challenge_id.clone(),
            idempotency_key: self.idempotency_key,
            method_commit_work,
        }
    }
}

/// Out-of-band challenge resend command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResendOutOfBandChallenge {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt that owns the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Existing open challenge to resend.
    pub challenge_id: ActiveProofChallengeId,
    /// Fresh delivery idempotency key the adapter must use for this resend.
    pub idempotency_key: String,
    /// Method/plugin work that must commit atomically with accepting this resend.
    pub(super) method_commit_work: Vec<MethodCommitWork>,
}

/// User response to an out-of-band active-proof challenge.
#[derive(Debug)]
pub struct CompleteOutOfBandChallengeResponse {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Submitted out-of-band response secret, such as the code the user received.
    pub secret_response: ActiveProofChallengeResponseSecret,
    /// Submitted weak-proof gate response material, when this method requires one.
    pub weak_proof_gate_response: Option<WeakProofGateResponse>,
}

/// User response to a non-out-of-band active-proof method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteActiveProofMethodResponse {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Method-specific opaque response material.
    pub response_payload: ActiveProofMethodResponsePayload,
    /// Submitted weak-proof gate response material, when this method requires one.
    pub weak_proof_gate_response: Option<WeakProofGateResponse>,
}

/// User response to a known-subject active-proof method such as TOTP or a recovery code.
#[derive(Debug)]
pub struct CompleteKnownSubjectActiveProofMethodResponse {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Known-subject proof method to verify.
    pub method: ProofMethodDeclaration,
    /// Method-specific secret response material.
    pub secret_response: KnownSubjectActiveProofSecretResponse,
    /// Submitted weak-proof gate response material, when this method requires one.
    pub weak_proof_gate_response: Option<WeakProofGateResponse>,
}

/// User response to a one-time recovery credential proof.
#[derive(Debug)]
pub struct CompleteRecoveryCredentialActiveProofMethodResponse {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Recovery credential proof method to verify.
    pub method: ProofMethodDeclaration,
    /// Submitted one-time recovery credential.
    pub secret_response: KnownSubjectActiveProofSecretResponse,
}

/// User response to a challenge-bound known-subject configured-secret method.
#[derive(Debug)]
pub struct CompleteChallengeBoundKnownSubjectActiveProofMethodResponse {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Method-specific secret response material.
    pub secret_response: KnownSubjectActiveProofSecretResponse,
    /// Submitted weak-proof gate response material, when this method requires one.
    pub weak_proof_gate_response: Option<WeakProofGateResponse>,
}

impl CompleteActiveProofMethodResponse {
    pub(crate) fn into_command_with_verified_proof(
        self,
        challenge_cookie: &ActiveProofChallengeCookieDraft,
        verified_proof: VerifiedActiveProof,
        weak_proof_gate: WeakProofGateStatus,
        method_commit_work: Vec<MethodCommitWork>,
    ) -> CompleteActiveProofChallenge {
        CompleteActiveProofChallenge {
            now: self.now,
            attempt_id: challenge_cookie.attempt_id.clone(),
            challenge_id: Some(challenge_cookie.challenge_id.clone()),
            verified_proof,
            stateless_fast_fail: StatelessFastFailStatus::NotRequired,
            weak_proof_gate,
            method_commit_work,
        }
    }
}

/// Active-proof challenge completion command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteActiveProofChallenge {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt that owns the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Challenge being completed, when a stateful challenge exists.
    pub challenge_id: Option<ActiveProofChallengeId>,
    /// Proof supplied by the method/plugin after verification.
    pub verified_proof: VerifiedActiveProof,
    /// Whether required stateless fast-fail verification happened before state was loaded.
    pub stateless_fast_fail: StatelessFastFailStatus,
    /// Whether the configured weak-proof gate was verified before state was loaded.
    pub weak_proof_gate: WeakProofGateStatus,
    /// Method/plugin work that must commit atomically with accepting this proof.
    pub(super) method_commit_work: Vec<MethodCommitWork>,
}

/// Active-proof failure command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordActiveProofFailure {
    /// Server time for this transition.
    pub now: UnixSeconds,
    /// Attempt that received the failed proof.
    pub attempt_id: ActiveProofAttemptId,
    /// Challenge that was authoritatively checked before recording this failure, if any.
    pub challenge_id: Option<ActiveProofChallengeId>,
    /// Proof method that failed.
    pub method: ProofMethodDeclaration,
    /// Whether the configured weak-proof gate was verified before state was loaded.
    pub weak_proof_gate: WeakProofGateStatus,
}

/// Generic dedupe key for a pending out-of-band challenge.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OutOfBandChallengeDedupeKey(String);

impl OutOfBandChallengeDedupeKey {
    /// Creates a non-empty out-of-band challenge dedupe key.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::EmptyOutOfBandChallengeDedupeKey);
        }
        validate_auth_identifier_string(
            "out-of-band challenge dedupe key",
            &value,
            OUT_OF_BAND_CHALLENGE_DEDUPE_KEY_MAX_BYTES,
        )?;
        Ok(Self(value))
    }

    /// Returns the dedupe key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether stateless fast-fail verification was performed before state loading.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum StatelessFastFailStatus {
    /// No stateless fast-fail check is required for this proof.
    NotRequired,
    /// Stateless fast-fail passed before any stateful lookup.
    VerifiedBeforeStateLoad(VerifiedStatelessFastFailBeforeStateLoad),
}

impl StatelessFastFailStatus {
    pub(crate) fn verified_before_state_load() -> Self {
        Self::VerifiedBeforeStateLoad(VerifiedStatelessFastFailBeforeStateLoad { _private: () })
    }

    pub(super) fn was_verified_before_state_load(&self) -> bool {
        matches!(self, Self::VerifiedBeforeStateLoad(_))
    }
}

/// Unforgeable evidence that stateless fast-fail passed before state loading.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedStatelessFastFailBeforeStateLoad {
    _private: (),
}

/// Whether the configured weak-proof gate was verified before state loading.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum WeakProofGateStatus {
    /// No weak-proof gate is required for this proof.
    NotRequired,
    /// The configured weak-proof gate passed before any stateful lookup.
    VerifiedBeforeStateLoad(VerifiedWeakProofGateBeforeStateLoad),
}

impl WeakProofGateStatus {
    pub(crate) fn verified_before_state_load(summary: WeakProofGateSummary) -> Self {
        Self::VerifiedBeforeStateLoad(VerifiedWeakProofGateBeforeStateLoad {
            summary,
            _private: (),
        })
    }

    pub(super) fn verified_summary(&self) -> Option<WeakProofGateSummary> {
        match self {
            Self::NotRequired => None,
            Self::VerifiedBeforeStateLoad(verified) => Some(verified.summary.clone()),
        }
    }
}

/// Unforgeable evidence that a weak-proof gate passed before state loading.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedWeakProofGateBeforeStateLoad {
    summary: WeakProofGateSummary,
    _private: (),
}

impl VerifiedWeakProofGateBeforeStateLoad {
    /// Returns the reducer-visible gate summary.
    pub fn summary(&self) -> &WeakProofGateSummary {
        &self.summary
    }
}

/// Reducer-visible summary of the gate used before a weak online proof.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WeakProofGateSummary {
    /// Gate family.
    kind: WeakProofGateKind,
    /// Adapter-specific label, such as `hashcash`, `turnstile`, or `recaptcha`.
    method_label: String,
}

impl WeakProofGateSummary {
    /// Creates a weak-proof gate summary from a gate family and adapter label.
    pub fn new(kind: WeakProofGateKind, method_label: impl Into<String>) -> Result<Self, Error> {
        let method_label = method_label.into();
        if method_label.is_empty() {
            return Err(Error::EmptyWeakProofGateMethodLabel);
        }
        validate_auth_identifier_string(
            "weak-proof gate method label",
            &method_label,
            WEAK_PROOF_GATE_METHOD_LABEL_MAX_BYTES,
        )?;
        Ok(Self { kind, method_label })
    }

    /// Returns the weak-proof gate family.
    pub const fn kind(&self) -> WeakProofGateKind {
        self.kind
    }

    /// Returns the adapter-specific weak-proof gate label.
    pub fn method_label(&self) -> &str {
        &self.method_label
    }
}

/// Submitted material for a configured weak-proof gate.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct WeakProofGateResponse {
    summary: WeakProofGateSummary,
    payload: Vec<u8>,
}

impl WeakProofGateResponse {
    /// Creates a bounded non-empty weak-proof gate response.
    pub fn try_from_bytes(
        kind: WeakProofGateKind,
        method_label: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        let summary = WeakProofGateSummary::new(kind, method_label)?;
        let payload = payload.into();
        if payload.is_empty() {
            return Err(Error::EmptyWeakProofGateResponsePayload);
        }
        validate_auth_bytes_not_too_long(
            "weak-proof gate response payload",
            &payload,
            WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES,
        )?;
        Ok(Self { summary, payload })
    }

    /// Returns the reducer-visible gate summary.
    pub fn summary(&self) -> &WeakProofGateSummary {
        &self.summary
    }

    /// Returns the submitted gate response bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Runtime-derived binding that ties a weak-proof gate to exact proof material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WeakProofGateBinding([u8; 32]);

impl WeakProofGateBinding {
    pub(crate) fn for_active_method_response(
        challenge: &ActiveProofMethodChallengeMaterial,
        response_payload: &ActiveProofMethodResponsePayload,
    ) -> Result<Self, Error> {
        let proof_family = [proof_family_wire_id(challenge.proof.family())];
        let online_guessing_risk = [online_guessing_risk_wire_id(
            challenge.proof.online_guessing_risk(),
        )];
        let issued_at = challenge.issued_at.get().to_be_bytes();
        let expires_at = challenge.expires_at.get().to_be_bytes();
        let mut hasher = blake3::Hasher::new();
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            b"paranoid/auth/v1/weak-proof-gate-binding/active-method-response",
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, challenge.attempt_id.as_bytes())?;
        update_weak_proof_gate_binding_hash(&mut hasher, challenge.challenge_id.as_bytes())?;
        update_weak_proof_gate_binding_hash(&mut hasher, &proof_family)?;
        update_weak_proof_gate_binding_hash(&mut hasher, &online_guessing_risk)?;
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            challenge.proof.method_label().as_bytes(),
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, &issued_at)?;
        update_weak_proof_gate_binding_hash(&mut hasher, &expires_at)?;
        update_weak_proof_gate_binding_hash(&mut hasher, challenge.nonce.as_bytes())?;
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            challenge.method_challenge_state.as_bytes(),
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, response_payload.as_bytes())?;
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    pub(crate) fn for_challenge_bound_known_subject_secret_response(
        challenge: &ActiveProofMethodChallengeMaterial,
        response: &KnownSubjectActiveProofSecretResponse,
    ) -> Result<Self, Error> {
        let proof_family = [proof_family_wire_id(challenge.proof.family())];
        let online_guessing_risk = [online_guessing_risk_wire_id(
            challenge.proof.online_guessing_risk(),
        )];
        let issued_at = challenge.issued_at.get().to_be_bytes();
        let expires_at = challenge.expires_at.get().to_be_bytes();
        let mut hasher = blake3::Hasher::new();
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            b"paranoid/auth/v1/weak-proof-gate-binding/challenge-bound-known-subject-secret-response",
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, challenge.attempt_id.as_bytes())?;
        update_weak_proof_gate_binding_hash(&mut hasher, challenge.challenge_id.as_bytes())?;
        update_weak_proof_gate_binding_hash(&mut hasher, &proof_family)?;
        update_weak_proof_gate_binding_hash(&mut hasher, &online_guessing_risk)?;
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            challenge.proof.method_label().as_bytes(),
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, &issued_at)?;
        update_weak_proof_gate_binding_hash(&mut hasher, &expires_at)?;
        update_weak_proof_gate_binding_hash(&mut hasher, challenge.nonce.as_bytes())?;
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            challenge.method_challenge_state.as_bytes(),
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, response.expose_secret())?;
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    pub(crate) fn for_known_subject_secret_response(
        continuation: &ActiveProofContinuationCookieDraft,
        proof: &ProofSummary,
        response: &KnownSubjectActiveProofSecretResponse,
    ) -> Result<Self, Error> {
        let proof_family = [proof_family_wire_id(proof.family())];
        let online_guessing_risk = [online_guessing_risk_wire_id(proof.online_guessing_risk())];
        let proof_use = [proof_use_wire_id(continuation.proof_use)];
        let attempt_fast_fail_until = continuation.attempt_fast_fail_until.get().to_be_bytes();
        let mut hasher = blake3::Hasher::new();
        update_weak_proof_gate_binding_hash(
            &mut hasher,
            b"paranoid/auth/v1/weak-proof-gate-binding/known-subject-secret-response",
        )?;
        update_weak_proof_gate_binding_hash(&mut hasher, continuation.attempt_id.as_bytes())?;
        update_weak_proof_gate_binding_hash(&mut hasher, &proof_use)?;
        match continuation.subject_id.as_ref() {
            Some(subject_id) => {
                update_weak_proof_gate_binding_hash(&mut hasher, &[1])?;
                update_weak_proof_gate_binding_hash(&mut hasher, subject_id.as_bytes())?;
            }
            None => update_weak_proof_gate_binding_hash(&mut hasher, &[0])?,
        }
        update_weak_proof_gate_binding_hash(&mut hasher, &attempt_fast_fail_until)?;
        update_weak_proof_gate_binding_hash(&mut hasher, &proof_family)?;
        update_weak_proof_gate_binding_hash(&mut hasher, &online_guessing_risk)?;
        update_weak_proof_gate_binding_hash(&mut hasher, proof.method_label().as_bytes())?;
        update_weak_proof_gate_binding_hash(&mut hasher, response.expose_secret())?;
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    /// Returns the binding digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn update_weak_proof_gate_binding_hash(
    hasher: &mut blake3::Hasher,
    part: &[u8],
) -> Result<(), Error> {
    let len = u64::try_from(part.len()).map_err(|_| Error::TimeOverflow)?;
    hasher.update(&len.to_be_bytes());
    hasher.update(part);
    Ok(())
}

impl std::fmt::Debug for WeakProofGateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakProofGateResponse")
            .field("summary", &self.summary)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Submitted material for the gate required before unauthenticated challenge issue.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ChallengeIssuePreflightResponse {
    response: WeakProofGateResponse,
}

impl ChallengeIssuePreflightResponse {
    /// Creates a bounded non-empty challenge-issue preflight response.
    pub fn try_from_bytes(
        kind: WeakProofGateKind,
        method_label: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, Error> {
        WeakProofGateResponse::try_from_bytes(kind, method_label, payload)
            .map(|response| Self { response })
    }

    /// Returns the reducer-visible gate summary.
    pub fn summary(&self) -> &WeakProofGateSummary {
        self.response.summary()
    }

    /// Returns the submitted gate response bytes.
    pub fn payload(&self) -> &[u8] {
        self.response.payload()
    }

    pub(crate) fn as_weak_proof_gate_response(&self) -> &WeakProofGateResponse {
        &self.response
    }
}

impl std::fmt::Debug for ChallengeIssuePreflightResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeIssuePreflightResponse")
            .field("summary", self.summary())
            .field("payload_len", &self.payload().len())
            .finish()
    }
}

/// Request passed to the challenge-issue preflight verifier before state loading.
#[derive(Clone, Copy, Debug)]
pub struct ChallengeIssuePreflightVerificationRequest<'a> {
    now: UnixSeconds,
    proof_use: ProofUse,
    proof: &'a ProofSummary,
    response: &'a ChallengeIssuePreflightResponse,
}

impl<'a> ChallengeIssuePreflightVerificationRequest<'a> {
    pub(crate) fn new(
        now: UnixSeconds,
        proof_use: ProofUse,
        proof: &'a ProofSummary,
        response: &'a ChallengeIssuePreflightResponse,
    ) -> Self {
        Self {
            now,
            proof_use,
            proof,
            response,
        }
    }

    /// Returns the server time for this verification.
    pub const fn now(&self) -> UnixSeconds {
        self.now
    }

    /// Returns the transition the challenge issue is trying to satisfy.
    pub const fn proof_use(&self) -> ProofUse {
        self.proof_use
    }

    /// Returns the proof whose challenge issue is being preflighted.
    pub const fn proof(&self) -> &ProofSummary {
        self.proof
    }

    /// Returns the submitted preflight response.
    pub const fn response(&self) -> &ChallengeIssuePreflightResponse {
        self.response
    }
}

/// Request passed to the configured weak-proof gate verifier before state loading.
#[derive(Clone, Copy, Debug)]
pub struct WeakProofGateVerificationRequest<'a> {
    now: UnixSeconds,
    proof: &'a ProofSummary,
    response: &'a WeakProofGateResponse,
    binding: Option<&'a WeakProofGateBinding>,
}

impl<'a> WeakProofGateVerificationRequest<'a> {
    pub(crate) fn new(
        now: UnixSeconds,
        proof: &'a ProofSummary,
        response: &'a WeakProofGateResponse,
    ) -> Self {
        Self {
            now,
            proof,
            response,
            binding: None,
        }
    }

    pub(crate) fn new_with_binding(
        now: UnixSeconds,
        proof: &'a ProofSummary,
        response: &'a WeakProofGateResponse,
        binding: Option<&'a WeakProofGateBinding>,
    ) -> Self {
        Self {
            now,
            proof,
            response,
            binding,
        }
    }

    /// Returns the server time for this verification.
    pub const fn now(&self) -> UnixSeconds {
        self.now
    }

    /// Returns the proof whose online-guessing gate is being verified.
    pub const fn proof(&self) -> &ProofSummary {
        self.proof
    }

    /// Returns the submitted gate response.
    pub const fn response(&self) -> &WeakProofGateResponse {
        self.response
    }

    /// Returns the exact proof-material binding required by this verification, if any.
    pub const fn binding(&self) -> Option<&WeakProofGateBinding> {
        self.binding
    }
}

/// Runtime-owned verifier for pre-state-load gates.
pub trait WeakProofGateVerifier {
    /// Verifies submitted gate material before any authoritative state load.
    fn verify_weak_proof_gate_before_state_load(
        &self,
        request: WeakProofGateVerificationRequest<'_>,
    ) -> Result<(), Error>;

    /// Verifies submitted challenge-issue preflight material before any state load.
    fn verify_challenge_issue_preflight_before_state_load(
        &self,
        request: ChallengeIssuePreflightVerificationRequest<'_>,
    ) -> Result<(), Error> {
        self.verify_weak_proof_gate_before_state_load(WeakProofGateVerificationRequest::new(
            request.now(),
            request.proof(),
            request.response().as_weak_proof_gate_response(),
        ))
    }
}

/// Gate family used before checking weak online proofs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WeakProofGateKind {
    /// Local Hashcash-style proof of work.
    ProofOfWork,
    /// CAPTCHA, Turnstile, or similar human-presence challenge.
    HumanChallenge,
    /// Application risk engine or abuse-scoring decision.
    RiskDecision,
    /// Other configured gate understood by the adapter.
    Other,
}

/// Server-side active-proof attempt row as understood by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofAttemptRecord {
    /// Attempt id.
    pub attempt_id: ActiveProofAttemptId,
    /// Transition the attempt is trying to satisfy.
    pub proof_use: ProofUse,
    /// Subject already known by the flow, if any.
    pub subject_id: Option<SubjectId>,
    /// Proofs already satisfied inside this attempt.
    pub satisfied_proofs: Vec<SatisfiedProof>,
    /// Failed weak proof count.
    pub weak_proof_failures: u32,
    /// Maximum failed weak proofs allowed before hard deletion.
    pub max_weak_proof_failures: u32,
    /// Time the attempt was created.
    pub created_at: UnixSeconds,
    /// Time the attempt expires.
    pub expires_at: UnixSeconds,
    /// Closure timestamp, if the attempt is no longer accepting proofs.
    pub closed_at: Option<UnixSeconds>,
}

/// Server-side active-proof challenge row as understood by the reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProofChallengeRecord {
    /// Challenge id.
    pub challenge_id: ActiveProofChallengeId,
    /// Attempt that owns the challenge.
    pub attempt_id: ActiveProofAttemptId,
    /// Proof this challenge can satisfy.
    pub proof: ProofSummary,
    /// Generic dedupe key for out-of-band challenge target and proof method.
    pub challenge_dedupe_key: Option<OutOfBandChallengeDedupeKey>,
    /// Opaque out-of-band recipient handle understood by the adapter.
    pub recipient_handle: Option<String>,
    /// Delivery idempotency keys already accepted by the core for this challenge.
    pub used_delivery_idempotency_keys: Vec<String>,
    /// Number of user-visible resends already accepted.
    pub resend_count: u32,
    /// Maximum user-visible resends accepted for this challenge.
    pub max_resends: u32,
    /// Whether this challenge requires pre-state-load fast-fail verification.
    pub requires_stateless_fast_fail: bool,
    /// Time the challenge was created.
    pub created_at: UnixSeconds,
    /// Time the challenge expires.
    pub expires_at: UnixSeconds,
    /// Closure timestamp, if the challenge no longer accepts completion.
    pub closed_at: Option<UnixSeconds>,
}
