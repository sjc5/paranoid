use http::HeaderMap;
use http::header::{COOKIE, HeaderValue};

use super::*;

struct RuntimeTestAdapter {
    loaded: Result<LoadedState, &'static str>,
    commit_result: Result<Vec<(CoreStorageTarget, &'static [u8])>, &'static str>,
    load_calls: usize,
    commit_calls: usize,
    seen_loaded_state_contract: Option<CommandLoadedStateContract>,
    seen_prepared_storage_boundary_contract: Option<PreparedStorageBoundaryContract>,
    seen_planned_storage_boundary_contract: Option<PlannedStorageBoundaryContract>,
    seen_method_commit_boundary_contract: Option<MethodCommitBoundaryContract>,
}

impl RuntimeTestAdapter {
    fn new(loaded: LoadedState) -> Self {
        Self {
            loaded: Ok(loaded),
            commit_result: Ok(Vec::new()),
            load_calls: 0,
            commit_calls: 0,
            seen_loaded_state_contract: None,
            seen_prepared_storage_boundary_contract: None,
            seen_planned_storage_boundary_contract: None,
            seen_method_commit_boundary_contract: None,
        }
    }
}

impl AtomicCommitAdapter for RuntimeTestAdapter {
    type Error = &'static str;

    fn commit_atomic_work(
        &mut self,
        request: AtomicCommitRequest<'_>,
    ) -> Result<Vec<MaterializedFreshCredentialSecret>, Self::Error> {
        self.commit_calls += 1;
        self.seen_planned_storage_boundary_contract =
            request.planned_storage_boundary_contract().cloned();
        self.seen_method_commit_boundary_contract =
            Some(request.method_commit_boundary_contract().clone());
        let requested_targets = request
            .storage_contract()
            .fresh_credential_secrets()
            .iter()
            .map(|fresh_secret| {
                assert!(matches!(
                    fresh_secret.target(),
                    CoreStorageTarget::SessionCredentialSecret { .. }
                        | CoreStorageTarget::TrustedDeviceCredentialSecret { .. }
                        | CoreStorageTarget::ActiveProofContinuationSecret { .. }
                ));
                fresh_secret.target().clone()
            })
            .collect::<Vec<_>>();
        self.commit_result.clone().map(|materialized| {
            let materialized = if materialized.is_empty() && !requested_targets.is_empty() {
                requested_targets
                    .into_iter()
                    .map(|target| (target, b"runtime-test-secret".as_slice()))
                    .collect()
            } else {
                materialized
            };
            materialized
                .into_iter()
                .map(|(target, secret)| {
                    MaterializedFreshCredentialSecret::new(
                        target,
                        AuthCredentialSecret::try_from(secret).expect("credential secret"),
                    )
                })
                .collect()
        })
    }
}

impl AuthRuntimeStorageAdapter for RuntimeTestAdapter {
    fn load_state(
        &mut self,
        request: AuthLoadStateRequest<'_>,
    ) -> Result<LoadedState, Self::Error> {
        self.load_calls += 1;
        self.seen_loaded_state_contract = Some(request.loaded_state_contract().clone());
        self.seen_prepared_storage_boundary_contract =
            Some(request.prepared_storage_boundary_contract().clone());
        let mut loaded = self.loaded.clone()?;
        if let Some(session_cookie) = &request.presented_cookies().session_cookie {
            let presented_session_secret = request
                .presented_cookie_secrets()
                .session()
                .expect("session cookie secret");
            assert_eq!(
                presented_session_secret.session_id(),
                &session_cookie.session_id
            );
        }
        if let Some(continuation_cookie) =
            &request.presented_cookies().active_proof_continuation_cookie
        {
            let presented_continuation_secret = request
                .presented_cookie_secrets()
                .active_proof_continuation()
                .expect("active-proof continuation cookie secret");
            assert_eq!(
                presented_continuation_secret.attempt_id(),
                &continuation_cookie.attempt_id
            );
            loaded.active_proof_continuation_secret_match =
                Some(LoadedActiveProofContinuationSecretMatch::new(
                    continuation_cookie.attempt_id.clone(),
                    StoredSecretMatch::Current,
                ));
        }
        Ok(loaded)
    }
}

fn auth_web_runtime() -> AuthWebRuntime {
    AuthWebRuntime::new(config(), auth_web_transport())
}

fn auth_web_transport() -> AuthWebTransport {
    let cookie_manager =
        crate::web::CookieManager::from_keyset(test_keyset("tests.auth.web.runtime.v1"));
    let csrf_protector = crate::web::CsrfProtector::new(crate::web::CsrfProtectorConfig::new(
        cookie_manager.clone(),
    ))
    .expect("csrf protector");
    AuthWebTransport::new(AuthWebTransportConfig::new(
        cookie_manager,
        csrf_protector,
        test_keyset("tests.auth.web.runtime.fast-fail.v1"),
    ))
}

fn test_keyset(purpose: &str) -> crate::crypto::Keyset {
    let key =
        crate::crypto::Key32::try_from([7_u8; crate::crypto::KEY32_SIZE].as_slice()).expect("key");
    crate::crypto::derive_keyset_from_latest_first_keys([key], purpose).expect("keyset")
}

fn headers_with_session_cookie(transport: &AuthWebTransport) -> HeaderMap {
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueSessionCookie(MaterializedSessionCookieResponse::new(
            session_cookie(100),
            AuthCredentialSecret::try_from(b"current-session".as_slice())
                .expect("credential secret"),
        )),
    ]);
    let set_cookie_headers = transport
        .render_set_cookie_headers(at(0), effects)
        .expect("initial session cookie");
    let session_cookie_pair = set_cookie_headers
        .as_slice()
        .iter()
        .find_map(|header| {
            header
                .as_str()
                .split(';')
                .next()
                .filter(|pair| pair.starts_with("__Host-__paranoid_auth_session="))
        })
        .expect("session cookie pair");
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(session_cookie_pair).expect("cookie header"),
    );
    headers
}

fn refreshed_session_targets() -> Vec<(CoreStorageTarget, &'static [u8])> {
    vec![(
        CoreStorageTarget::SessionCredentialSecret {
            session_id: id("session"),
            secret_version: version(4),
        },
        b"fresh-session",
    )]
}

fn issue_out_of_band_challenge_command() -> Command {
    Command::IssueOutOfBandChallenge(
        issue_out_of_band_challenge_request()
            .into_request(id("attempt"), id("challenge"))
            .into_command_with_stateless_fast_fail_cookie(
                active_proof_challenge_cookie(),
                vec![out_of_band_method_commit_work()],
            ),
    )
}

fn issue_out_of_band_challenge_request() -> IssueOutOfBandChallengeInput {
    IssueOutOfBandChallengeInput {
        now: at(30),
        method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
            .expect("method declaration"),
        challenge_dedupe_key: dedupe_key("login:email-hash:window"),
        recipient_handle: "opaque-email-handle".to_owned(),
        idempotency_key: "mail-idempotency-key".to_owned(),
    }
}

fn active_proof_continuation_headers(
    runtime: &AuthWebRuntime,
    attempt_id: ActiveProofAttemptId,
    proof_use: ProofUse,
    attempt_fast_fail_until: UnixSeconds,
) -> HeaderMap {
    let response_effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofContinuationCookie(
            MaterializedActiveProofContinuationCookieResponse::new(
                ActiveProofContinuationCookieDraft {
                    attempt_id,
                    proof_use,
                    subject_id: None,
                    attempt_fast_fail_until,
                },
                AuthCredentialSecret::try_from(b"runtime-test-continuation".as_slice())
                    .expect("continuation secret"),
            ),
        ),
    ]);
    let set_cookie_headers = runtime
        .web_transport()
        .render_set_cookie_headers(at(20), response_effects)
        .expect("continuation cookie render");
    let cookie_pair = set_cookie_headers
        .as_slice()
        .iter()
        .find_map(|header| {
            header.as_str().split(';').next().filter(|pair| {
                pair.starts_with("__Host-__paranoid_auth_active_proof_continuation=")
            })
        })
        .expect("continuation cookie pair");
    headers_from_cookie_pairs(&[cookie_pair])
}

fn headers_from_cookie_pairs(cookie_pairs: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookie_pairs.join("; ")).expect("cookie header"),
    );
    headers
}

fn resend_out_of_band_challenge_command() -> Command {
    Command::ResendOutOfBandChallenge(ResendOutOfBandChallenge {
        now: at(40),
        attempt_id: id("attempt"),
        challenge_id: id("challenge"),
        idempotency_key: "mail-idempotency-key-resend-1".to_owned(),
        method_commit_work: Vec::new(),
    })
}

fn complete_out_of_band_challenge_response() -> CompleteOutOfBandChallengeResponse {
    complete_out_of_band_challenge_response_with_secret(b"123456")
}

fn complete_out_of_band_challenge_response_with_secret(
    value: &[u8],
) -> CompleteOutOfBandChallengeResponse {
    CompleteOutOfBandChallengeResponse {
        now: at(40),
        secret_response: challenge_response_secret(value),
        weak_proof_gate_response: None,
    }
}

fn challenge_response_secret(value: &[u8]) -> ActiveProofChallengeResponseSecret {
    ActiveProofChallengeResponseSecret::try_from(value).expect("challenge response secret")
}

fn runtime_active_proof_challenge_cookie() -> ActiveProofChallengeCookieDraft {
    ActiveProofChallengeCookieDraft::new_with_response_secret(
        &test_keyset("tests.auth.web.runtime.fast-fail.v1"),
        id("attempt"),
        id("challenge"),
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        at(30),
        at(70),
        ActiveProofChallengeFastFailNonce::from_bytes(
            &[41_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
        )
        .expect("nonce"),
        &challenge_response_secret(b"123456"),
    )
    .expect("challenge cookie")
}

fn headers_with_active_proof_challenge_cookie(transport: &AuthWebTransport) -> HeaderMap {
    headers_with_active_proof_challenge_cookie_draft(
        transport,
        runtime_active_proof_challenge_cookie(),
    )
}

fn headers_with_active_proof_challenge_cookie_draft(
    transport: &AuthWebTransport,
    challenge_cookie: ActiveProofChallengeCookieDraft,
) -> HeaderMap {
    let effects = MaterializedResponseEffects::from_vec(vec![
        MaterializedResponseEffect::IssueActiveProofChallengeCookie(challenge_cookie),
    ]);
    let set_cookie_headers = transport
        .render_set_cookie_headers(at(30), effects)
        .expect("active proof challenge cookie");
    let challenge_cookie_pair =
        set_cookie_headers
            .as_slice()
            .iter()
            .find_map(|header| {
                header.as_str().split(';').next().filter(|pair| {
                    pair.starts_with("__Host-__paranoid_auth_active_proof_challenge=")
                })
            })
            .expect("active proof challenge cookie pair");
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(challenge_cookie_pair).expect("cookie header"),
    );
    headers
}

#[test]
fn web_runtime_executes_refresh_end_to_end_and_renders_set_cookie_headers() {
    let runtime = auth_web_runtime();
    let headers = headers_with_session_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter::new(loaded_session(100));
    adapter.commit_result = Ok(refreshed_session_targets());

    let execution = runtime
        .execute_request_resolution_from_headers(
            &headers,
            ResolveRequestInput {
                now: at(85),
                request_kind: RequestKind::StateChanging,
            },
            &mut adapter,
        )
        .expect("runtime execution");

    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 1);
    assert_eq!(
        adapter
            .seen_prepared_storage_boundary_contract
            .as_ref()
            .expect("prepared storage boundary")
            .boundary_before_reduce(),
        StorageBoundaryBeforeReduce::OpenBeforeStateLoad
    );
    assert_eq!(
        adapter
            .seen_planned_storage_boundary_contract
            .as_ref()
            .expect("planned storage boundary")
            .atomic_commit_boundary(),
        AtomicCommitBoundary::LoadedStateBoundary
    );
    assert_eq!(
        adapter
            .seen_loaded_state_contract
            .expect("loaded state contract")
            .required(),
        &[
            LoadedStateRequirement::PresentedSessionCookie {
                session_id: id("session")
            },
            LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
                session_id: id("session")
            },
            LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject {
                session_id: id("session")
            },
        ]
    );
    assert!(matches!(
        execution.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::RefreshedSession,
            session_id,
            subject_id,
            ..
        }) if *session_id == id("session") && *subject_id == id("subject")
    ));
    assert_eq!(execution.set_cookie_headers().as_slice().len(), 2);

    let session_cookie_pair = execution
        .set_cookie_headers()
        .as_slice()
        .iter()
        .find_map(|header| {
            header
                .as_str()
                .split(';')
                .next()
                .filter(|pair| pair.starts_with("__Host-__paranoid_auth_session="))
        })
        .expect("session cookie pair");
    let decoded = runtime
        .web_transport()
        .decode_presented_cookies_from_cookie_header(session_cookie_pair)
        .expect("decoded session cookie");
    let (presented_cookies, presented_cookie_secrets) = decoded.into_parts();
    let decoded_session = presented_cookies
        .session_cookie
        .expect("decoded session cookie");

    assert_eq!(decoded_session.session_id, id("session"));
    assert_eq!(decoded_session.secret_version, version(4));
    assert_eq!(
        presented_cookie_secrets
            .session()
            .expect("session secret")
            .secret()
            .expose_secret(),
        b"fresh-session",
    );
}

#[test]
fn web_runtime_does_not_commit_or_render_when_state_load_fails() {
    let runtime = auth_web_runtime();
    let headers = headers_with_session_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter {
        loaded: Err("load failed"),
        commit_result: Ok(Vec::new()),
        load_calls: 0,
        commit_calls: 0,
        seen_loaded_state_contract: None,
        seen_prepared_storage_boundary_contract: None,
        seen_planned_storage_boundary_contract: None,
        seen_method_commit_boundary_contract: None,
    };

    let error = runtime
        .execute_request_resolution_from_headers(
            &headers,
            ResolveRequestInput {
                now: at(50),
                request_kind: RequestKind::StateChanging,
            },
            &mut adapter,
        )
        .expect_err("load failure stops execution");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::LoadState("load failed")
    ));
    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_does_not_render_when_atomic_commit_fails() {
    let runtime = auth_web_runtime();
    let headers = headers_with_session_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter::new(loaded_session(100));
    adapter.commit_result = Err("commit failed");

    let error = runtime
        .execute_request_resolution_from_headers(
            &headers,
            ResolveRequestInput {
                now: at(85),
                request_kind: RequestKind::StateChanging,
            },
            &mut adapter,
        )
        .expect_err("commit failure stops execution");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::AtomicCommit("commit failed")
    ));
    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 1);
}

#[test]
fn web_runtime_resolves_missing_auth_without_loading_state() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter {
        loaded: Err("load must not run"),
        commit_result: Ok(Vec::new()),
        load_calls: 0,
        commit_calls: 0,
        seen_loaded_state_contract: None,
        seen_prepared_storage_boundary_contract: None,
        seen_planned_storage_boundary_contract: None,
        seen_method_commit_boundary_contract: None,
    };

    let execution = runtime
        .execute_request_resolution_from_headers(
            &HeaderMap::new(),
            ResolveRequestInput {
                now: at(50),
                request_kind: RequestKind::StateChanging,
            },
            &mut adapter,
        )
        .expect("missing auth resolves without authoritative state");

    assert_eq!(execution.outcome(), &Outcome::NeedsFullAuthentication);
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
    assert!(adapter.seen_loaded_state_contract.is_none());
    assert!(adapter.seen_prepared_storage_boundary_contract.is_none());
    assert!(adapter.seen_planned_storage_boundary_contract.is_none());
}

#[test]
fn web_runtime_starts_active_proof_attempt_from_current_session() {
    let runtime = auth_web_runtime();
    let headers = headers_with_session_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter::new(loaded_session(100));

    let execution = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &headers,
            StartCurrentSessionActiveProofAttemptInput {
                now: at(20),
                proof_use: ProofUse::SatisfyStepUp,
            },
            &mut adapter,
        )
        .expect("runtime execution");

    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 1);
    assert_eq!(
        adapter
            .seen_prepared_storage_boundary_contract
            .as_ref()
            .expect("prepared storage boundary")
            .boundary_before_reduce(),
        StorageBoundaryBeforeReduce::OpenBeforeStateLoad
    );
    assert_eq!(
        adapter
            .seen_planned_storage_boundary_contract
            .as_ref()
            .expect("planned storage boundary")
            .atomic_commit_boundary(),
        AtomicCommitBoundary::LoadedStateBoundary
    );
    assert_eq!(
        adapter
            .seen_loaded_state_contract
            .expect("loaded state contract")
            .required(),
        &[
            LoadedStateRequirement::PresentedSessionCookie {
                session_id: id("session")
            },
            LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
                session_id: id("session")
            },
            LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject {
                session_id: id("session")
            },
        ]
    );
    assert!(matches!(
        execution.outcome(),
        Outcome::ActiveProofAttemptStarted { expires_at, .. } if *expires_at == at(140)
    ));
    assert_eq!(execution.set_cookie_headers().as_slice().len(), 1);
    assert!(
        execution
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_active_proof_continuation="))
    );
}

#[test]
fn web_runtime_rejects_direct_active_proof_attempt_start() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter::new(LoadedState::default());

    let error = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::StartActiveProofAttempt(StartActiveProofAttempt {
                now: at(20),
                attempt_id: id("attempt"),
                proof_use: ProofUse::ContributeToFullAuthentication,
                subject_id: None,
            }),
            &mut adapter,
        )
        .expect_err("direct attempt start must require runtime fresh ID generation");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(
            Error::ActiveProofAttemptStartRequiresRuntimeFreshIdGeneration
        )
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_rejects_direct_credential_lifecycle_commands() {
    let target_credential_id: VerifiedProofSourceId = id("password-credential");
    let email_authority: RecoveryAuthorityId = id("primary-email-authority");
    let target_credential = message_signature_credential_metadata("password-credential");
    let lifecycle_context = credential_lifecycle_context(
        target_credential.clone(),
        [CredentialRecoveryAuthority::new(
            target_credential_id.clone(),
            CredentialLifecycleAction::Reset,
            email_authority.clone(),
            RecoveryAuthorityTiming::Immediate,
        )],
        [out_of_band_identifier_lifecycle_evidence(
            "primary-email",
            [email_authority],
        )],
    );
    let pending_reset = PendingCredentialLifecycleActionRecord::new_open(
        id("pending-reset"),
        id("subject"),
        target_credential_id.clone(),
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending reset");
    let pending_replacement = PendingCredentialLifecycleActionRecord::new_open(
        id("pending-replacement"),
        id("subject"),
        target_credential_id,
        CredentialLifecycleAction::Replace,
        at(100),
        at(200),
        at(300),
    )
    .expect("pending replacement");

    let cases = [
        (
            Command::PlanCredentialReset(PlanCredentialReset {
                now: at(150),
                lifecycle_context: lifecycle_context.clone(),
                active_proof_attempt_to_close: None,
                independent_evidence_required:
                    CredentialLifecycleIndependentEvidenceRequirement::Required,
                pending_action: None,
                immediate_subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
            }),
            Error::CredentialResetPlanningRequiresRuntimeLifecycleDecision,
        ),
        (
            Command::ExecuteCredentialReset(ExecuteCredentialReset {
                now: at(250),
                execution_authority: CredentialResetExecutionAuthority::Immediate {
                    lifecycle_context,
                    independent_evidence_required:
                        CredentialLifecycleIndependentEvidenceRequirement::Required,
                },
                method_commit_work: vec![password_reset_method_commit_work(b"verifier")],
                subject_auth_revocation:
                    CredentialResetSubjectAuthRevocation::PreserveExistingAuthState,
            }),
            Error::CredentialResetExecutionRequiresRuntimeMethodDispatch,
        ),
        (
            Command::CancelPendingCredentialReset(CancelPendingCredentialReset {
                now: at(150),
                target_credential: target_credential.clone(),
                pending_action: pending_reset,
            }),
            Error::CredentialResetCancellationRequiresRuntimeLifecycleDecision,
        ),
        (
            Command::ExecuteNonResetPendingCredentialLifecycleAction(
                ExecuteNonResetPendingCredentialLifecycleAction {
                    now: at(250),
                    target_credential: target_credential.clone(),
                    pending_action: pending_replacement.clone(),
                    method_commit_work: vec![password_reset_method_commit_work(b"verifier")],
                    subject_auth_revocation:
                        CredentialLifecycleSubjectAuthRevocation::PreserveExistingAuthState,
                },
            ),
            Error::CredentialLifecycleExecutionRequiresRuntimeMethodDispatch,
        ),
        (
            Command::CancelNonResetPendingCredentialLifecycleAction(
                CancelNonResetPendingCredentialLifecycleAction {
                    now: at(150),
                    target_credential,
                    pending_action: pending_replacement,
                },
            ),
            Error::CredentialLifecycleCancellationRequiresRuntimeLifecycleDecision,
        ),
    ];

    for (command, expected_error) in cases {
        let runtime = auth_web_runtime();
        let mut adapter = RuntimeTestAdapter::new(LoadedState::default());
        let error = runtime
            .execute_from_headers(&HeaderMap::new(), command, &mut adapter)
            .expect_err("direct credential lifecycle command must be runtime-owned");

        assert!(matches!(
            error,
            AuthWebRuntimeExecutionError::Core(actual_error) if actual_error == expected_error
        ));
        assert_eq!(adapter.load_calls, 0);
        assert_eq!(adapter.commit_calls, 0);
    }
}

#[test]
fn web_runtime_current_session_active_proof_start_without_session_does_not_write() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter::new(LoadedState::default());

    let execution = runtime
        .execute_current_session_active_proof_attempt_start_from_headers(
            &HeaderMap::new(),
            StartCurrentSessionActiveProofAttemptInput {
                now: at(20),
                proof_use: ProofUse::SatisfyStepUp,
            },
            &mut adapter,
        )
        .expect("missing session resolves without writes");

    assert_eq!(execution.outcome(), &Outcome::NeedsFullAuthentication);
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_executes_out_of_band_challenge_issue_and_renders_challenge_cookie() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_state(
        ProofUse::ContributeToFullAuthentication,
    ));
    let continuation_headers = active_proof_continuation_headers(
        &runtime,
        id("attempt"),
        ProofUse::ContributeToFullAuthentication,
        at(140),
    );

    let execution = runtime
        .execute_out_of_band_challenge_issue_from_headers(
            &continuation_headers,
            issue_out_of_band_challenge_request(),
            &challenge_response_secret(b"123456"),
            &mut adapter,
        )
        .expect("runtime execution");

    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 1);
    assert_eq!(
        adapter
            .seen_prepared_storage_boundary_contract
            .as_ref()
            .expect("prepared storage boundary")
            .boundary_before_reduce(),
        StorageBoundaryBeforeReduce::OpenBeforeStateLoad
    );
    assert_eq!(
        adapter
            .seen_planned_storage_boundary_contract
            .as_ref()
            .expect("planned storage boundary")
            .atomic_commit_boundary(),
        AtomicCommitBoundary::LoadedStateBoundary
    );
    assert_eq!(
        adapter
            .seen_method_commit_boundary_contract
            .as_ref()
            .expect("method commit boundary")
            .stages(),
        &[]
    );
    assert_eq!(
        adapter
            .seen_loaded_state_contract
            .expect("loaded state contract")
            .required(),
        &[
            LoadedStateRequirement::ActiveProofAttempt {
                attempt_id: id("attempt")
            },
            LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
                attempt_id: id("attempt")
            },
            LoadedStateRequirement::ActiveProofContinuationSecretMatchForPresentedCookie {
                attempt_id: id("attempt")
            },
        ]
    );
    let challenge_id = match execution.outcome() {
        Outcome::OutOfBandChallengeIssued {
            attempt_id,
            challenge_id,
            expires_at,
        } => {
            assert_eq!(attempt_id, &id("attempt"));
            assert_eq!(expires_at, &at(70));
            challenge_id.clone()
        }
        outcome => panic!("expected out-of-band challenge issue, got {outcome:?}"),
    };
    assert_eq!(execution.set_cookie_headers().as_slice().len(), 1);
    assert!(
        execution
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_active_proof_challenge="))
    );
    let challenge_cookie_pair =
        execution
            .set_cookie_headers()
            .as_slice()
            .iter()
            .find_map(|header| {
                header.as_str().split(';').next().filter(|pair| {
                    pair.starts_with("__Host-__paranoid_auth_active_proof_challenge=")
                })
            })
            .expect("challenge cookie pair");
    let decoded = runtime
        .web_transport()
        .decode_presented_cookies_from_cookie_header(challenge_cookie_pair)
        .expect("decoded challenge cookie");
    let challenge_cookie = decoded
        .presented_cookies()
        .active_proof_challenge_cookie
        .as_ref()
        .expect("challenge cookie");
    assert_eq!(challenge_cookie.attempt_id, id("attempt"));
    assert_eq!(challenge_cookie.challenge_id, challenge_id);
    assert_eq!(challenge_cookie.issued_at, at(30));
    assert_eq!(challenge_cookie.expires_at, at(70));
    assert_eq!(
        challenge_cookie.proof,
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof")
    );
    let verified = challenge_cookie
        .verify_response_secret_before_state_load(
            runtime
                .web_transport()
                .active_proof_challenge_fast_fail_keyset(),
            at(40),
            &CompleteActiveProofChallenge {
                now: at(40),
                attempt_id: id("attempt"),
                challenge_id: Some(challenge_id),
                verified_proof: VerifiedActiveProof::from_summary(
                    ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
                    Some(id("subject")),
                )
                .expect("verified proof"),
                stateless_fast_fail: StatelessFastFailStatus::NotRequired,
                weak_proof_gate: WeakProofGateStatus::NotRequired,
                method_commit_work: Vec::new(),
            },
            &challenge_response_secret(b"123456"),
        )
        .expect("fast-fail verifies");
    assert!(verified.was_verified_before_state_load());
}

#[test]
fn web_runtime_rejects_direct_out_of_band_issue_command() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let error = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            issue_out_of_band_challenge_command(),
            &mut adapter,
        )
        .expect_err("direct issue command bypasses runtime cookie construction");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(
            Error::OutOfBandChallengeIssueRequiresRuntimeCookieConstruction
        )
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_rejects_direct_active_proof_failure_command() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_state(ProofUse::SatisfyStepUp));

    let error = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            Command::RecordActiveProofFailure(RecordActiveProofFailure {
                now: at(40),
                attempt_id: id("attempt"),
                method: proof_method(ProofFamily::SharedSecretOtp),
                weak_proof_gate: verified_proof_of_work_gate(),
            }),
            &mut adapter,
        )
        .expect_err("direct failure command bypasses runtime method dispatch");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(Error::ActiveProofFailureRequiresRuntimeMethodDispatch)
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_rejects_direct_out_of_band_resend_command() {
    let runtime = auth_web_runtime();
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_and_challenge_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let error = runtime
        .execute_from_headers(
            &HeaderMap::new(),
            resend_out_of_band_challenge_command(),
            &mut adapter,
        )
        .expect_err("web runtime must not accept direct resend commands");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(
            Error::OutOfBandChallengeResendRequiresRuntimeMethodDispatch
        )
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_executes_out_of_band_challenge_completion_after_stateless_fast_fail() {
    let runtime = auth_web_runtime();
    let headers = headers_with_active_proof_challenge_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_and_challenge_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let execution = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            complete_out_of_band_challenge_response(),
            &TestWeakProofGateVerifier,
            &mut adapter,
        )
        .expect("runtime execution");

    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 1);
    assert_eq!(
        adapter
            .seen_loaded_state_contract
            .expect("loaded state contract")
            .required(),
        &[
            LoadedStateRequirement::ActiveProofAttempt {
                attempt_id: id("attempt")
            },
            LoadedStateRequirement::SubjectRevocationForLoadedActiveProofAttemptSubject {
                attempt_id: id("attempt")
            },
            LoadedStateRequirement::ActiveProofChallenge {
                challenge_id: id("challenge")
            },
        ]
    );
    assert_eq!(
        execution.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: id("attempt"),
            proof: ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        }
    );
    assert_eq!(execution.set_cookie_headers().as_slice().len(), 1);
    assert!(
        execution
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_active_proof_challenge=")
                && header.as_str().contains("Max-Age=0"))
    );
}

#[test]
fn web_runtime_rejects_bad_challenge_response_before_loading_state() {
    let runtime = auth_web_runtime();
    let headers = headers_with_active_proof_challenge_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_and_challenge_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            complete_out_of_band_challenge_response_with_secret(b"wrong-code"),
            &TestWeakProofGateVerifier,
            &mut adapter,
        )
        .expect_err("bad challenge response fails before state load");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(Error::StatelessFastFailVerificationFailed)
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_rejects_expired_out_of_band_cookie_before_weak_gate() {
    let runtime = auth_web_runtime();
    let expired_cookie = ActiveProofChallengeCookieDraft::new_with_response_secret(
        runtime
            .web_transport()
            .active_proof_challenge_fast_fail_keyset(),
        id("attempt"),
        id("challenge"),
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        at(30),
        at(35),
        ActiveProofChallengeFastFailNonce::from_bytes(
            &[42_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
        )
        .expect("nonce"),
        &challenge_response_secret(b"123456"),
    )
    .expect("expired challenge cookie");
    let headers =
        headers_with_active_proof_challenge_cookie_draft(runtime.web_transport(), expired_cookie);
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_and_challenge_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            CompleteOutOfBandChallengeResponse {
                now: at(40),
                secret_response: challenge_response_secret(b"123456"),
                weak_proof_gate_response: Some(proof_of_work_gate_response()),
            },
            &TestWeakProofGateVerifier,
            &mut adapter,
        )
        .expect_err("expired challenge cookie must fail before weak gate");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(Error::ActiveProofChallengeCookieExpired)
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_rejects_out_of_band_cookie_without_response_mac_before_weak_gate() {
    let runtime = auth_web_runtime();
    let challenge_cookie = ActiveProofChallengeCookieDraft::new_without_response_mac(
        id("attempt"),
        id("challenge"),
        ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof"),
        at(30),
        at(70),
        ActiveProofChallengeFastFailNonce::from_bytes(
            &[43_u8; ACTIVE_PROOF_CHALLENGE_FAST_FAIL_NONCE_BYTES],
        )
        .expect("nonce"),
    )
    .expect("out-of-band challenge cookie without response MAC");
    let headers =
        headers_with_active_proof_challenge_cookie_draft(runtime.web_transport(), challenge_cookie);
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_and_challenge_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            CompleteOutOfBandChallengeResponse {
                now: at(40),
                secret_response: challenge_response_secret(b"123456"),
                weak_proof_gate_response: Some(proof_of_work_gate_response()),
            },
            &TestWeakProofGateVerifier,
            &mut adapter,
        )
        .expect_err("out-of-band challenge cookie without response MAC must fail before weak gate");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                family: ProofFamily::OutOfBandCode
            }
        )
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_rejects_submitted_secret_for_non_out_of_band_challenge_before_loading_state() {
    let runtime = auth_web_runtime();
    let challenge_cookie = active_proof_challenge_cookie_for_issue_proof(
        "attempt",
        "challenge",
        ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
        at(30),
        at(70),
    );
    let headers =
        headers_with_active_proof_challenge_cookie_draft(runtime.web_transport(), challenge_cookie);
    let mut adapter = RuntimeTestAdapter::new(loaded_attempt_and_challenge_state(
        ProofUse::ContributeToFullAuthentication,
    ));

    let error = runtime
        .execute_out_of_band_challenge_response_from_headers(
            &headers,
            complete_out_of_band_challenge_response(),
            &TestWeakProofGateVerifier,
            &mut adapter,
        )
        .expect_err("submitted-secret fast-fail is only for out-of-band challenge cookies");

    assert!(matches!(
        error,
        AuthWebRuntimeExecutionError::Core(
            Error::ActiveProofChallengeCookieProofFamilyCannotUseResponseSecret {
                family: ProofFamily::MessageSignature
            }
        )
    ));
    assert_eq!(adapter.load_calls, 0);
    assert_eq!(adapter.commit_calls, 0);
}

#[test]
fn web_runtime_executes_logout_and_renders_delete_session_and_csrf_headers() {
    let runtime = auth_web_runtime();
    let headers = headers_with_session_cookie(runtime.web_transport());
    let mut adapter = RuntimeTestAdapter::new(loaded_session(100));

    let execution = runtime
        .execute_from_headers(
            &headers,
            Command::LogoutCurrentSession(LogoutCurrentSession { now: at(50) }),
            &mut adapter,
        )
        .expect("runtime execution");

    assert_eq!(adapter.load_calls, 1);
    assert_eq!(adapter.commit_calls, 1);
    assert!(matches!(
        execution.outcome(),
        Outcome::RevocationPlanned(RevocationOutcome {
            subject_id: Some(subject_id),
            target: RevocationTarget::CurrentSession,
        }) if *subject_id == id("subject")
    ));
    assert_eq!(execution.set_cookie_headers().as_slice().len(), 2);
    assert!(
        execution
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header
                .as_str()
                .starts_with("__Host-__paranoid_auth_session=")
                && header.as_str().contains("Max-Age=0"))
    );
    assert!(
        execution
            .set_cookie_headers()
            .as_slice()
            .iter()
            .any(|header| header.as_str().starts_with("__Host-csrf_token="))
    );
}
