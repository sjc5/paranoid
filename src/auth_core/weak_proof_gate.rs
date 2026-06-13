use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::prelude::*;

const HASHCASH_METHOD_LABEL: &str = "hashcash";
const HASHCASH_PAYLOAD_VERSION: u8 = 1;
const HASHCASH_NONCE_BYTES: usize = 16;
const HASHCASH_MAX_DIFFICULTY_BITS: u8 = 64;
const HASHCASH_WORK_CONTEXT: &[u8] = b"paranoid/auth/v1/hashcash/work";
const HASHCASH_WEAK_PROOF_RESOURCE_CONTEXT: &[u8] =
    b"paranoid/auth/v1/hashcash/resource/weak-proof";
const HASHCASH_CHALLENGE_ISSUE_PREFLIGHT_RESOURCE_CONTEXT: &[u8] =
    b"paranoid/auth/v1/hashcash/resource/challenge-issue-preflight";

/// Backend verifier for Paranoid's native Hashcash-style weak proof-of-work gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HashcashProofOfWorkVerifier {
    config: HashcashProofOfWorkConfig,
    summary: WeakProofGateSummary,
}

impl HashcashProofOfWorkVerifier {
    /// Creates a Hashcash verifier from a validated config.
    pub(crate) fn new(config: HashcashProofOfWorkConfig) -> Result<Self, Error> {
        config.validate()?;
        let summary =
            WeakProofGateSummary::new(WeakProofGateKind::ProofOfWork, HASHCASH_METHOD_LABEL)?;
        Ok(Self { config, summary })
    }

    /// Returns the weak-gate summary this verifier accepts.
    pub(crate) fn summary(&self) -> &WeakProofGateSummary {
        &self.summary
    }

    fn verify_response(
        &self,
        now: UnixSeconds,
        response: &WeakProofGateResponse,
        resource_digest: [u8; 32],
    ) -> Result<(), Error> {
        if response.summary() != &self.summary {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        let payload: HashcashProofOfWorkPayload = postcard::from_bytes(response.payload())
            .map_err(|_| Error::WeakProofGateVerificationFailed)?;
        if payload.version != HASHCASH_PAYLOAD_VERSION
            || payload.difficulty_bits != self.config.difficulty_bits
            || payload.nonce.len() != HASHCASH_NONCE_BYTES
            || payload.resource_digest != resource_digest
        {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        if now.get() >= payload.expires_at {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        let latest_acceptable_expires_at = now
            .checked_add_duration(self.config.max_response_lifetime)?
            .get();
        if payload.expires_at > latest_acceptable_expires_at {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        let digest = hashcash_work_digest(&self.summary, &payload)?;
        if !digest_has_leading_zero_bits(&digest, self.config.difficulty_bits) {
            return Err(Error::WeakProofGateVerificationFailed);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn solve_weak_proof_gate_response_for_test(
        &self,
        now: UnixSeconds,
        proof: &ProofSummary,
        binding: &WeakProofGateBinding,
    ) -> WeakProofGateResponse {
        let resource_digest = hashcash_weak_proof_resource_digest(proof, Some(binding))
            .expect("hashcash weak-proof resource digest");
        self.solve_response_for_test(now, resource_digest)
    }

    #[cfg(test)]
    pub(crate) fn solve_challenge_issue_preflight_response_for_test(
        &self,
        now: UnixSeconds,
        proof_use: ProofUse,
        proof: &ProofSummary,
    ) -> ChallengeIssuePreflightResponse {
        let resource_digest = hashcash_challenge_issue_preflight_resource_digest(proof_use, proof)
            .expect("hashcash preflight resource digest");
        let response = self.solve_response_for_test(now, resource_digest);
        ChallengeIssuePreflightResponse::try_from_bytes(
            response.summary().kind(),
            response.summary().method_label(),
            response.payload().to_vec(),
        )
        .expect("hashcash preflight response")
    }

    #[cfg(test)]
    fn solve_response_for_test(
        &self,
        now: UnixSeconds,
        resource_digest: [u8; 32],
    ) -> WeakProofGateResponse {
        let expires_at = now
            .checked_add_duration(DurationSeconds::new(60))
            .expect("hashcash test expiry")
            .get();
        let nonce = deterministic_hashcash_test_nonce(now, &resource_digest);
        for counter in 0..u64::MAX {
            let payload = HashcashProofOfWorkPayload {
                version: HASHCASH_PAYLOAD_VERSION,
                expires_at,
                difficulty_bits: self.config.difficulty_bits,
                resource_digest,
                nonce: nonce.to_vec(),
                counter,
            };
            let digest =
                hashcash_work_digest(&self.summary, &payload).expect("hashcash test work digest");
            if digest_has_leading_zero_bits(&digest, self.config.difficulty_bits) {
                let encoded = postcard::to_allocvec(&payload).expect("encode hashcash payload");
                return WeakProofGateResponse::try_from_bytes(
                    self.summary.kind(),
                    self.summary.method_label(),
                    encoded,
                )
                .expect("hashcash response");
            }
        }
        panic!("unable to solve test Hashcash proof");
    }
}

impl WeakProofGateVerifier for HashcashProofOfWorkVerifier {
    fn verify_weak_proof_gate_before_state_load(
        &self,
        request: WeakProofGateVerificationRequest<'_>,
    ) -> Result<(), Error> {
        let resource_digest =
            hashcash_weak_proof_resource_digest(request.proof(), request.binding())?;
        self.verify_response(request.now(), request.response(), resource_digest)
    }

    fn verify_challenge_issue_preflight_before_state_load(
        &self,
        request: ChallengeIssuePreflightVerificationRequest<'_>,
    ) -> Result<(), Error> {
        let resource_digest = hashcash_challenge_issue_preflight_resource_digest(
            request.proof_use(),
            request.proof(),
        )?;
        self.verify_response(
            request.now(),
            request.response().as_weak_proof_gate_response(),
            resource_digest,
        )
    }
}

type WeakProofGateAdapterVerificationFn =
    dyn for<'a> Fn(WeakProofGateAdapterVerificationRequest<'a>) -> Result<(), Error> + Send + Sync;

/// Runtime-owned verification adapter for non-native weak gates.
#[derive(Clone)]
pub(crate) struct WeakProofGateAdapter {
    summary: WeakProofGateSummary,
    verifier: Arc<WeakProofGateAdapterVerificationFn>,
}

impl WeakProofGateAdapter {
    /// Creates an adapter-backed weak-gate verifier.
    pub(crate) fn new(
        summary: WeakProofGateSummary,
        verifier: impl for<'a> Fn(WeakProofGateAdapterVerificationRequest<'a>) -> Result<(), Error>
        + Send
        + Sync
        + 'static,
    ) -> Result<Self, Error> {
        if summary.kind() == WeakProofGateKind::ProofOfWork {
            return Err(Error::InvalidConfig(
                "weak gate adapters cannot use the native proof-of-work kind",
            ));
        }
        Ok(Self {
            summary,
            verifier: Arc::new(verifier),
        })
    }

    /// Returns the exact weak-gate summary this adapter accepts.
    pub(crate) fn summary(&self) -> &WeakProofGateSummary {
        &self.summary
    }

    fn verify(&self, request: WeakProofGateAdapterVerificationRequest<'_>) -> Result<(), Error> {
        (self.verifier)(request)
    }
}

impl std::fmt::Debug for WeakProofGateAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakProofGateAdapter")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

/// Registry that dispatches non-native weak gates by exact summary.
#[derive(Clone, Debug)]
pub(crate) struct WeakProofGateAdapterRegistry {
    adapters: Vec<WeakProofGateAdapter>,
}

impl WeakProofGateAdapterRegistry {
    /// Creates a registry from validated adapter-backed weak gates.
    pub(crate) fn new(
        adapters: impl IntoIterator<Item = WeakProofGateAdapter>,
    ) -> Result<Self, Error> {
        let adapters = adapters.into_iter().collect::<Vec<_>>();
        if adapters.is_empty() {
            return Err(Error::InvalidConfig(
                "weak gate adapter registry must not be empty",
            ));
        }
        for (index, adapter) in adapters.iter().enumerate() {
            if adapters[index + 1..]
                .iter()
                .any(|other| other.summary() == adapter.summary())
            {
                return Err(Error::InvalidConfig(
                    "weak gate adapter registry must not contain duplicate summaries",
                ));
            }
        }
        Ok(Self { adapters })
    }

    fn adapter_for(&self, summary: &WeakProofGateSummary) -> Result<&WeakProofGateAdapter, Error> {
        self.adapters
            .iter()
            .find(|adapter| adapter.summary() == summary)
            .ok_or(Error::WeakProofGateVerificationFailed)
    }
}

impl WeakProofGateVerifier for WeakProofGateAdapterRegistry {
    fn verify_weak_proof_gate_before_state_load(
        &self,
        request: WeakProofGateVerificationRequest<'_>,
    ) -> Result<(), Error> {
        let adapter = self.adapter_for(request.response().summary())?;
        let binding = request
            .binding()
            .ok_or(Error::WeakProofGateVerificationFailed)?;
        adapter.verify(WeakProofGateAdapterVerificationRequest::strong_proof(
            request.now(),
            request.proof(),
            request.response().summary(),
            request.response().payload(),
            binding,
        ))
    }

    fn verify_challenge_issue_preflight_before_state_load(
        &self,
        request: ChallengeIssuePreflightVerificationRequest<'_>,
    ) -> Result<(), Error> {
        let adapter = self.adapter_for(request.response().summary())?;
        adapter.verify(
            WeakProofGateAdapterVerificationRequest::challenge_issue_preflight(
                request.now(),
                request.proof_use(),
                request.proof(),
                request.response().summary(),
                request.response().payload(),
            ),
        )
    }
}

/// Runtime-derived context supplied to adapter-backed weak gates.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WeakProofGateAdapterVerificationRequest<'a> {
    now: UnixSeconds,
    proof: &'a ProofSummary,
    response_summary: &'a WeakProofGateSummary,
    response_payload: &'a [u8],
    context: WeakProofGateAdapterVerificationContext<'a>,
}

impl<'a> WeakProofGateAdapterVerificationRequest<'a> {
    fn strong_proof(
        now: UnixSeconds,
        proof: &'a ProofSummary,
        response_summary: &'a WeakProofGateSummary,
        response_payload: &'a [u8],
        binding: &'a WeakProofGateBinding,
    ) -> Self {
        Self {
            now,
            proof,
            response_summary,
            response_payload,
            context: WeakProofGateAdapterVerificationContext::StrongProof { binding },
        }
    }

    fn challenge_issue_preflight(
        now: UnixSeconds,
        proof_use: ProofUse,
        proof: &'a ProofSummary,
        response_summary: &'a WeakProofGateSummary,
        response_payload: &'a [u8],
    ) -> Self {
        Self {
            now,
            proof,
            response_summary,
            response_payload,
            context: WeakProofGateAdapterVerificationContext::ChallengeIssuePreflight { proof_use },
        }
    }

    /// Returns the verification time.
    pub(crate) fn now(&self) -> UnixSeconds {
        self.now
    }

    /// Returns the proof whose gate is being verified.
    pub(crate) fn proof(&self) -> &ProofSummary {
        self.proof
    }

    /// Returns the exact configured gate summary.
    pub(crate) fn response_summary(&self) -> &WeakProofGateSummary {
        self.response_summary
    }

    /// Returns the opaque provider or risk-engine response bytes.
    pub(crate) fn response_payload(&self) -> &[u8] {
        self.response_payload
    }

    /// Returns the runtime-derived gate context.
    pub(crate) fn context(&self) -> WeakProofGateAdapterVerificationContext<'a> {
        self.context
    }
}

/// Runtime-derived context for a non-native weak-gate verification.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WeakProofGateAdapterVerificationContext<'a> {
    /// The gate protects a specific strong-proof response.
    StrongProof {
        /// Digest binding the gate to exact runtime-owned proof material.
        binding: &'a WeakProofGateBinding,
    },
    /// The gate protects unauthenticated challenge issue before any attempt row exists.
    ChallengeIssuePreflight {
        /// Transition the challenge issue is trying to satisfy.
        proof_use: ProofUse,
    },
}

/// Configuration for native Hashcash-style proof-of-work verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HashcashProofOfWorkConfig {
    difficulty_bits: u8,
    max_response_lifetime: DurationSeconds,
}

impl HashcashProofOfWorkConfig {
    /// Creates a Hashcash config with a required leading-zero-bit difficulty.
    pub(crate) fn new(difficulty_bits: u8, max_response_lifetime: DurationSeconds) -> Self {
        Self {
            difficulty_bits,
            max_response_lifetime,
        }
    }

    fn validate(self) -> Result<(), Error> {
        if self.difficulty_bits == 0 || self.difficulty_bits > HASHCASH_MAX_DIFFICULTY_BITS {
            return Err(Error::InvalidConfig(
                "hashcash difficulty_bits must be between 1 and 64",
            ));
        }
        if self.max_response_lifetime.is_zero() {
            return Err(Error::InvalidConfig(
                "hashcash max_response_lifetime must be non-zero",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
struct HashcashProofOfWorkPayload {
    version: u8,
    expires_at: u64,
    difficulty_bits: u8,
    resource_digest: [u8; 32],
    nonce: Vec<u8>,
    counter: u64,
}

fn hashcash_weak_proof_resource_digest(
    proof: &ProofSummary,
    binding: Option<&WeakProofGateBinding>,
) -> Result<[u8; 32], Error> {
    let Some(binding) = binding else {
        return Err(Error::WeakProofGateVerificationFailed);
    };
    let mut hasher = blake3::Hasher::new();
    update_hashcash_digest(&mut hasher, HASHCASH_WEAK_PROOF_RESOURCE_CONTEXT)?;
    update_hashcash_proof_digest(&mut hasher, proof)?;
    update_hashcash_digest(&mut hasher, binding.as_bytes())?;
    Ok(*hasher.finalize().as_bytes())
}

fn hashcash_challenge_issue_preflight_resource_digest(
    proof_use: ProofUse,
    proof: &ProofSummary,
) -> Result<[u8; 32], Error> {
    let mut hasher = blake3::Hasher::new();
    update_hashcash_digest(
        &mut hasher,
        HASHCASH_CHALLENGE_ISSUE_PREFLIGHT_RESOURCE_CONTEXT,
    )?;
    update_hashcash_digest(&mut hasher, &[proof_use_wire_id(proof_use)])?;
    update_hashcash_proof_digest(&mut hasher, proof)?;
    Ok(*hasher.finalize().as_bytes())
}

fn update_hashcash_proof_digest(
    hasher: &mut blake3::Hasher,
    proof: &ProofSummary,
) -> Result<(), Error> {
    update_hashcash_digest(hasher, &[proof_family_wire_id(proof.family())])?;
    update_hashcash_digest(
        hasher,
        &[online_guessing_risk_wire_id(proof.online_guessing_risk())],
    )?;
    update_hashcash_digest(hasher, proof.method_label().as_bytes())
}

fn hashcash_work_digest(
    summary: &WeakProofGateSummary,
    payload: &HashcashProofOfWorkPayload,
) -> Result<[u8; 32], Error> {
    let mut hasher = blake3::Hasher::new();
    update_hashcash_digest(&mut hasher, HASHCASH_WORK_CONTEXT)?;
    update_hashcash_digest(&mut hasher, &[weak_gate_kind_wire_id(summary.kind())])?;
    update_hashcash_digest(&mut hasher, summary.method_label().as_bytes())?;
    update_hashcash_digest(&mut hasher, &[payload.version])?;
    update_hashcash_digest(&mut hasher, &payload.expires_at.to_be_bytes())?;
    update_hashcash_digest(&mut hasher, &[payload.difficulty_bits])?;
    update_hashcash_digest(&mut hasher, &payload.resource_digest)?;
    update_hashcash_digest(&mut hasher, &payload.nonce)?;
    update_hashcash_digest(&mut hasher, &payload.counter.to_be_bytes())?;
    Ok(*hasher.finalize().as_bytes())
}

fn weak_gate_kind_wire_id(kind: WeakProofGateKind) -> u8 {
    match kind {
        WeakProofGateKind::ProofOfWork => 1,
        WeakProofGateKind::HumanChallenge => 2,
        WeakProofGateKind::RiskDecision => 3,
        WeakProofGateKind::Other => 4,
    }
}

fn update_hashcash_digest(hasher: &mut blake3::Hasher, part: &[u8]) -> Result<(), Error> {
    let len = u64::try_from(part.len()).map_err(|_| Error::TimeOverflow)?;
    hasher.update(&len.to_be_bytes());
    hasher.update(part);
    Ok(())
}

fn digest_has_leading_zero_bits(digest: &[u8; 32], difficulty_bits: u8) -> bool {
    let full_zero_bytes = usize::from(difficulty_bits / 8);
    if digest[..full_zero_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    let remaining_bits = difficulty_bits % 8;
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - remaining_bits);
    digest[full_zero_bytes] & mask == 0
}

#[cfg(test)]
fn deterministic_hashcash_test_nonce(now: UnixSeconds, resource_digest: &[u8; 32]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"paranoid/auth/v1/hashcash/test-nonce");
    hasher.update(&now.get().to_be_bytes());
    hasher.update(resource_digest);
    let digest = hasher.finalize();
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&digest.as_bytes()[..16]);
    nonce
}
