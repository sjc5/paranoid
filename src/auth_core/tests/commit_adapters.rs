use super::*;

#[test]
fn commit_plan_splits_atomic_work_from_response_effects() {
    let plan = CommitPlan {
        preconditions: vec![Precondition::SessionBelongsToSubject {
            session_id: id("session"),
            subject_id: id("subject"),
        }],
        mutations: vec![Mutation::RevokeSession {
            session_id: id("session"),
            reason: RevocationReason::Logout,
            revoked_at: at(50),
        }],
        audit_events: vec![AuditEvent {
            kind: AuditEventKind::SessionRevoked,
            subject_id: Some(id("subject")),
            session_id: Some(id("session")),
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(50),
        }],
        method_commit_work: vec![
            MethodCommitWork::new(
                ProofSummary::new(ProofFamily::RecoveryCode, "recovery_code").expect("proof"),
                vec![
                    MethodCommitPrecondition::new(
                        "recovery_code_still_unused",
                        b"code-id".as_slice(),
                    )
                    .expect("method work item"),
                ],
                vec![
                    MethodCommitMutation::new("consume_recovery_code", b"code-id".as_slice())
                        .expect("method work item"),
                ],
                Vec::new(),
            )
            .expect("method commit work"),
        ],
        fresh_credential_secrets: Vec::new(),
        durable_effects: vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::TrustedDeviceCreated,
                subject_id: id("subject"),
            },
        )],
        response_effects: vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ],
    };

    assert!(plan.requires_atomic_commit());
    assert!(plan.has_response_effects());

    let (atomic_work, response_effects) = plan
        .try_into_validated_atomic_work_and_response_effects()
        .expect("commit plan is valid");

    assert!(!atomic_work.is_empty());
    assert_eq!(atomic_work.preconditions.len(), 1);
    assert_eq!(atomic_work.mutations.len(), 1);
    assert_eq!(atomic_work.audit_events.len(), 1);
    assert_eq!(atomic_work.method_commit_work.len(), 1);
    assert_eq!(atomic_work.fresh_credential_secrets.len(), 0);
    assert_eq!(atomic_work.durable_effects.len(), 1);
    assert_eq!(
        response_effects,
        vec![
            ResponseEffect::DeleteSessionCookie,
            ResponseEffect::CycleCsrfToken { session_id: None },
        ]
    );
}

#[test]
fn response_only_commit_plan_requires_no_atomic_commit() {
    let plan = CommitPlan {
        response_effects: vec![ResponseEffect::DeleteSessionCookie],
        ..CommitPlan::default()
    };

    assert!(!plan.requires_atomic_commit());
    assert!(plan.has_response_effects());

    let (atomic_work, response_effects) = plan
        .try_into_validated_atomic_work_and_response_effects()
        .expect("response-only commit plan is valid");

    assert!(atomic_work.is_empty());
    assert_eq!(response_effects, vec![ResponseEffect::DeleteSessionCookie]);
}

#[test]
fn atomic_commit_work_validates_fresh_credential_secret_contract() {
    let missing_error = AtomicCommitWork {
        mutations: vec![Mutation::CreateSession(session_record(200))],
        ..AtomicCommitWork::default()
    }
    .validate_for_commit()
    .expect_err("session creation must explicitly request a fresh secret");
    assert_eq!(missing_error, Error::MissingFreshCredentialSecret);

    let unexpected_error = AtomicCommitWork {
        fresh_credential_secrets: vec![fresh_session_secret("session", 3)],
        ..AtomicCommitWork::default()
    }
    .validate_for_commit()
    .expect_err("fresh secrets without matching mutations must be rejected");
    assert_eq!(unexpected_error, Error::UnexpectedFreshCredentialSecret);

    let duplicate_error = AtomicCommitWork {
        mutations: vec![Mutation::CreateSession(session_record(200))],
        fresh_credential_secrets: vec![
            fresh_session_secret("session", 3),
            fresh_session_secret("session", 3),
        ],
        ..AtomicCommitWork::default()
    }
    .validate_for_commit()
    .expect_err("duplicate fresh secrets must be rejected");
    assert_eq!(duplicate_error, Error::DuplicateFreshCredentialSecret);

    AtomicCommitWork {
        mutations: vec![Mutation::CreateSession(session_record(200))],
        fresh_credential_secrets: vec![fresh_session_secret("session", 3)],
        ..AtomicCommitWork::default()
    }
    .validate_for_commit()
    .expect("matching fresh secret work is valid");
}

#[test]
fn atomic_commit_work_rejects_duplicate_credential_mutation_secret_targets() {
    let error = AtomicCommitWork {
        mutations: vec![
            Mutation::CreateSession(session_record(200)),
            Mutation::RefreshSession {
                session_id: id("session"),
                new_secret_version: version(3),
                previous_secret_version: version(2),
                previous_secret_accept_until: at(55),
                refreshed_at: at(50),
                expires_at: at(150),
            },
        ],
        fresh_credential_secrets: vec![fresh_session_secret("session", 3)],
        ..AtomicCommitWork::default()
    }
    .validate_for_commit()
    .expect_err("one atomic work item cannot require the same fresh secret target twice");

    assert_eq!(error, Error::DuplicateFreshCredentialSecret);
}

#[test]
fn atomic_commit_work_transaction_contract_orders_commit_stages() {
    let work = AtomicCommitWork {
        preconditions: vec![Precondition::SessionBelongsToSubject {
            session_id: id("session"),
            subject_id: id("subject"),
        }],
        mutations: vec![Mutation::CreateSession(session_record(200))],
        audit_events: vec![AuditEvent {
            kind: AuditEventKind::SessionCreated,
            subject_id: Some(id("subject")),
            session_id: Some(id("session")),
            device_credential_id: None,
            attempt_id: None,
            challenge_id: None,
            weak_proof_gate: None,
            occurred_at: at(50),
        }],
        method_commit_work: vec![recovery_code_method_commit_work()],
        fresh_credential_secrets: vec![fresh_session_secret("session", 3)],
        durable_effects: vec![DurableEffectCommand::NotifySecurityEvent(
            SecurityNotificationCommand {
                kind: SecurityNotificationKind::TrustedDeviceCreated,
                subject_id: id("subject"),
            },
        )],
    };

    let contract = work.transaction_contract().expect("transaction contract");

    assert_eq!(
        contract.stages(),
        &[
            AtomicCommitTransactionStage::ValidateAtomicWork,
            AtomicCommitTransactionStage::BeginTransaction,
            AtomicCommitTransactionStage::EnforceCorePreconditions,
            AtomicCommitTransactionStage::EnforceMethodPreconditions,
            AtomicCommitTransactionStage::MaterializeFreshCredentialSecrets,
            AtomicCommitTransactionStage::ApplyCoreMutations,
            AtomicCommitTransactionStage::ApplyMethodMutations,
            AtomicCommitTransactionStage::CommitAuditEvents,
            AtomicCommitTransactionStage::CommitCoreDurableEffectCommands,
            AtomicCommitTransactionStage::CommitTransaction,
        ]
    );
}

#[test]
fn method_commit_work_transaction_contract_orders_method_stages() {
    let method_work = out_of_band_method_commit_work();

    let contract = method_work
        .transaction_contract()
        .expect("method transaction contract");

    assert_eq!(contract.proof(), &proof(ProofFamily::OutOfBandCode));
    assert_eq!(
        contract.stages(),
        &[
            MethodCommitTransactionStage::EnforcePreconditions,
            MethodCommitTransactionStage::ApplyMutations,
            MethodCommitTransactionStage::CommitDurableEffectCommands,
        ]
    );
}

#[test]
fn atomic_commit_work_transaction_contract_includes_method_durable_effect_commands() {
    let work = AtomicCommitWork {
        method_commit_work: vec![out_of_band_method_commit_work()],
        ..AtomicCommitWork::default()
    };

    let contract = work.transaction_contract().expect("transaction contract");

    assert_eq!(
        contract.stages(),
        &[
            AtomicCommitTransactionStage::ValidateAtomicWork,
            AtomicCommitTransactionStage::BeginTransaction,
            AtomicCommitTransactionStage::EnforceMethodPreconditions,
            AtomicCommitTransactionStage::ApplyMethodMutations,
            AtomicCommitTransactionStage::CommitMethodDurableEffectCommands,
            AtomicCommitTransactionStage::CommitTransaction,
        ]
    );
}

#[test]
fn empty_atomic_commit_work_transaction_contract_does_not_open_transaction() {
    let contract = AtomicCommitWork::default()
        .transaction_contract()
        .expect("transaction contract");

    assert_eq!(
        contract.stages(),
        &[AtomicCommitTransactionStage::ValidateAtomicWork]
    );
}

#[test]
fn atomic_commit_work_rejects_duplicate_method_commit_work_for_same_proof() {
    let error = AtomicCommitWork {
        method_commit_work: vec![
            recovery_code_method_commit_work(),
            recovery_code_method_commit_work(),
        ],
        ..AtomicCommitWork::default()
    }
    .validate_for_commit()
    .expect_err("one proof must have one method work batch");

    assert_eq!(error, Error::DuplicateMethodCommitWorkForProof);
}

#[test]
fn atomic_commit_work_transaction_contract_rejects_invalid_work() {
    let error = AtomicCommitWork {
        mutations: vec![Mutation::CreateSession(session_record(200))],
        ..AtomicCommitWork::default()
    }
    .transaction_contract()
    .expect_err("invalid work has no transaction contract");

    assert_eq!(error, Error::MissingFreshCredentialSecret);
}

#[test]
fn commit_plan_refuses_to_split_invalid_atomic_work_from_response_effects() {
    let error = CommitPlan {
        mutations: vec![Mutation::CreateSession(session_record(200))],
        response_effects: vec![ResponseEffect::IssueSessionCookie(session_cookie(200))],
        ..CommitPlan::default()
    }
    .try_into_validated_atomic_work_and_response_effects()
    .expect_err("invalid atomic work must not release response effects");

    assert_eq!(error, Error::MissingFreshCredentialSecret);
}

#[test]
fn commit_plan_requires_session_cookie_response_effect_to_be_commit_backed() {
    let mut wrong_subject_cookie = session_cookie(200);
    wrong_subject_cookie.subject_id = id("other-subject");

    let error = CommitPlan {
        preconditions: vec![Precondition::SessionStillMatches {
            session_id: id("session"),
            subject_id: id("subject"),
            now: at(50),
            current_secret_version: version(3),
        }],
        response_effects: vec![ResponseEffect::IssueSessionCookie(wrong_subject_cookie)],
        ..CommitPlan::default()
    }
    .try_into_validated_atomic_work_and_response_effects()
    .expect_err("session cookie response must be subject-bound to commit work");

    assert_eq!(error, Error::UnbackedSessionCookieResponseEffect);
}

#[test]
fn commit_plan_requires_trusted_device_cookie_response_effect_to_be_commit_backed() {
    let mut wrong_subject_cookie = trusted_device_cookie(500, 1_000);
    wrong_subject_cookie.secret_version = version(9);
    wrong_subject_cookie.subject_id = id("other-subject");

    let error = CommitPlan {
        preconditions: vec![Precondition::TrustedDeviceStillMatches {
            device_credential_id: id("device"),
            subject_id: id("subject"),
            now: at(50),
            current_secret_version: version(8),
        }],
        mutations: vec![Mutation::RotateTrustedDeviceCredential {
            device_credential_id: id("device"),
            new_secret_version: version(9),
            previous_secret_version: version(8),
            previous_secret_accept_until: at(55),
            last_used_at: at(50),
            silent_revival_until: at(500),
            expires_at: at(1_000),
        }],
        fresh_credential_secrets: vec![FreshCredentialSecret::TrustedDevice {
            device_credential_id: id("device"),
            secret_version: version(9),
        }],
        response_effects: vec![ResponseEffect::IssueTrustedDeviceCookie(
            wrong_subject_cookie,
        )],
        ..CommitPlan::default()
    }
    .try_into_validated_atomic_work_and_response_effects()
    .expect_err("trusted-device cookie response must be subject-bound to commit work");

    assert_eq!(error, Error::UnbackedTrustedDeviceCookieResponseEffect);
}

#[test]
fn in_memory_commit_adapter_applies_refresh_plan_before_returning_response_effects() {
    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded_session(100),
    )
    .expect("refresh transition");
    let mut store = InMemoryCommitStore::default();
    store.sessions.insert(id("session"), session_record(100));

    let response_effects = store
        .commit_plan(transition.commit_plan)
        .expect("commit succeeds");

    let session = store.sessions.get(&id("session")).expect("session");
    assert_eq!(session.current_secret_version, version(4));
    assert_eq!(session.previous_secret_version, Some(version(3)));
    assert_eq!(session.previous_secret_accept_until, Some(at(90)));
    assert_eq!(session.refreshed_at, at(85));
    assert_eq!(session.expires_at, at(185));
    assert_eq!(store.audit_events.len(), 1);
    assert_eq!(store.audit_events[0].kind, AuditEventKind::SessionRefreshed);
    assert!(matches!(
        response_effects.as_slice(),
        [
            ResponseEffect::IssueSessionCookie(_),
            ResponseEffect::CycleCsrfToken {
                session_id: Some(session_id),
            },
        ] if *session_id == id("session")
    ));
}

#[test]
fn in_memory_commit_adapter_rejects_stale_refresh_plan_without_side_effects() {
    let plan = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        &loaded_session(100),
    )
    .expect("refresh transition")
    .commit_plan;
    let mut stale_session = session_record(100);
    stale_session.current_secret_version = version(4);
    let mut store = InMemoryCommitStore::default();
    store.sessions.insert(id("session"), stale_session);
    let before = store.clone();

    let error = store
        .commit_plan(plan)
        .expect_err("stale commit must fail before effects are returned");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("session still matches")
    );
    assert_eq!(store, before);
}

#[test]
fn in_memory_commit_adapter_rejects_session_commit_after_subject_revocation() {
    let mut store = InMemoryCommitStore::default();
    store.sessions.insert(id("session"), session_record(200));
    store
        .subject_revocations
        .insert(id("subject"), subject_revocation(100));

    let error = store
        .commit_atomic_work(AtomicCommitWork {
            preconditions: vec![Precondition::SessionStillMatches {
                session_id: id("session"),
                subject_id: id("subject"),
                now: at(50),
                current_secret_version: version(3),
            }],
            mutations: vec![Mutation::RefreshSession {
                session_id: id("session"),
                new_secret_version: version(4),
                previous_secret_version: version(3),
                previous_secret_accept_until: at(55),
                refreshed_at: at(50),
                expires_at: at(150),
            }],
            fresh_credential_secrets: vec![fresh_session_secret("session", 4)],
            ..AtomicCommitWork::default()
        })
        .expect_err("subject revocation must invalidate stale session commit");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("session still matches")
    );
    assert_eq!(
        store
            .sessions
            .get(&id("session"))
            .expect("session")
            .current_secret_version,
        version(3)
    );
}

#[test]
fn in_memory_commit_adapter_hard_deletes_active_proof_attempt_children() {
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::ContributeToFullAuthentication),
    );
    store
        .active_proof_challenges
        .insert(id("challenge"), out_of_band_challenge());

    store
        .commit_atomic_work(AtomicCommitWork {
            mutations: vec![Mutation::DeleteActiveProofAttempt {
                attempt_id: id("attempt"),
            }],
            ..AtomicCommitWork::default()
        })
        .expect("attempt hard delete");

    assert!(!store.active_proof_attempts.contains_key(&id("attempt")));
    assert!(!store.active_proof_challenges.contains_key(&id("challenge")));
}

#[test]
fn in_memory_commit_adapter_keeps_durable_effects_atomic_with_dedupe_precondition() {
    let transition = reduce_command(
        &config(),
        Command::IssueOutOfBandChallenge(IssueOutOfBandChallenge {
            now: at(30),
            attempt_id: id("attempt"),
            challenge_id: id("new-challenge"),
            method: ProofMethodDeclaration::new(ProofFamily::OutOfBandCode, "email_otp")
                .expect("method declaration"),
            challenge_dedupe_key: dedupe_key("login:email-hash:window"),
            recipient_handle: "opaque-email-handle".to_owned(),
            idempotency_key: "mail-idempotency-key".to_owned(),
            stateless_fast_fail_cookie: active_proof_challenge_cookie_for_issue(
                "attempt",
                "new-challenge",
                at(30),
                at(70),
            ),
            method_commit_work: Vec::new(),
        }),
        &loaded_attempt_state(ProofUse::BindSubjectToActiveProofAttempt),
    )
    .expect("out-of-band challenge plan");
    let mut existing_challenge = out_of_band_challenge();
    existing_challenge.challenge_id = id("existing-challenge");
    let mut store = InMemoryCommitStore::default();
    store.active_proof_attempts.insert(
        id("attempt"),
        active_attempt(ProofUse::BindSubjectToActiveProofAttempt),
    );
    store
        .active_proof_challenges
        .insert(id("existing-challenge"), existing_challenge);
    let before = store.clone();

    let error = store
        .commit_plan(transition.commit_plan)
        .expect_err("duplicate open challenge must fail atomically");

    assert_eq!(
        error,
        InMemoryCommitError::PreconditionFailed("no open out of band challenge for dedupe key")
    );
    assert_eq!(store, before);
}

#[test]
fn in_memory_commit_adapter_raises_subject_revocation_cutoff_monotonically() {
    let mut store = InMemoryCommitStore::default();
    store
        .subject_revocations
        .insert(id("subject"), subject_revocation(100));

    let earlier_plan = reduced_plan(
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(50),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &LoadedState::default(),
    );
    store
        .commit_plan(earlier_plan)
        .expect("earlier cutoff commit succeeds");
    assert_eq!(
        store
            .subject_revocations
            .get(&id("subject"))
            .expect("subject revocation")
            .revoke_records_created_at_or_before,
        at(100)
    );

    let later_plan = reduced_plan(
        Command::RevokeSubjectAuthState(RevokeSubjectAuthState {
            now: at(150),
            subject_id: id("subject"),
            reason: RevocationReason::SubjectAuthStateChanged,
        }),
        &LoadedState::default(),
    );
    store
        .commit_plan(later_plan)
        .expect("later cutoff commit succeeds");
    assert_eq!(
        store
            .subject_revocations
            .get(&id("subject"))
            .expect("subject revocation")
            .revoke_records_created_at_or_before,
        at(150)
    );
}

#[test]
fn materialized_commit_adapter_issues_cookies_backed_by_stored_secret_macs() {
    let mut store = CredentialMaterializingCommitStore::default();
    store.state.active_proof_attempts.insert(
        id("attempt"),
        active_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    );

    let transition = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: Some(TrustDeviceAfterFullAuthentication {
                device_credential_id: id("device"),
                display_label: Some("work laptop".to_owned()),
            }),
        }),
        &store.state.loaded_for_attempt(&id("attempt")),
    )
    .expect("full authentication");
    let response_effects = store
        .commit_plan_with_materialized_response(
            transition.commit_plan,
            PresentedMaterializedCredentials::default(),
        )
        .expect("full authentication commit");

    let session_cookie = materialized_session_cookie_from_response_effects(&response_effects);
    let trusted_device_cookie =
        materialized_trusted_device_cookie_from_response_effects(&response_effects);
    assert_eq!(
        store
            .loaded_for_session_cookie(session_cookie.clone(), at(41))
            .session_secret_match
            .as_ref()
            .map(LoadedSessionSecretMatch::kind),
        Some(StoredSecretMatch::Current)
    );
    assert_eq!(
        store
            .loaded_for_trusted_device_cookie(trusted_device_cookie.clone(), at(41))
            .trusted_device_secret_match
            .as_ref()
            .map(LoadedTrustedDeviceSecretMatch::kind),
        Some(StoredSecretMatch::Current)
    );

    let wrong_session_secret_cookie = MaterializedSessionCookie {
        draft: session_cookie.draft,
        secret: TestCredentialSecret(session_cookie.secret.0 + 1),
    };
    assert_eq!(
        store
            .loaded_for_session_cookie(wrong_session_secret_cookie, at(41))
            .session_secret_match
            .as_ref()
            .map(LoadedSessionSecretMatch::kind),
        Some(StoredSecretMatch::Unknown)
    );
}

#[test]
fn materialized_commit_adapter_reuses_presented_current_session_secret_for_cache_cookie() {
    let mut store = CredentialMaterializingCommitStore::default();
    let current_secret = TestCredentialSecret(3_003);
    store.insert_session_with_secrets(
        session_record(200),
        current_secret,
        Some(TestCredentialSecret(2_002)),
    );
    let presented_cookie = MaterializedSessionCookie {
        draft: session_cookie(200),
        secret: current_secret,
    };
    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(presented_cookie.clone(), at(50)),
    )
    .expect("authoritative current session");

    let response_effects = store
        .commit_plan_with_materialized_response(
            transition.commit_plan,
            PresentedMaterializedCredentials {
                session: Some(presented_cookie.clone()),
                trusted_device: None,
                active_proof_continuation: None,
            },
        )
        .expect("authoritative session commit");
    let reissued_cookie = materialized_session_cookie_from_response_effects(&response_effects);
    assert_eq!(reissued_cookie.secret, current_secret);
    assert_eq!(reissued_cookie.draft.safe_read_valid_until, Some(at(60)));

    let missing_presented_secret_error = store
        .commit_plan_with_materialized_response(
            CommitPlan {
                preconditions: vec![Precondition::SessionStillMatches {
                    session_id: id("session"),
                    subject_id: id("subject"),
                    now: at(50),
                    current_secret_version: version(3),
                }],
                response_effects: vec![ResponseEffect::IssueSessionCookie(reissued_cookie.draft)],
                ..CommitPlan::default()
            },
            PresentedMaterializedCredentials::default(),
        )
        .expect_err("non-mutating cookie reissue requires the presented secret");
    assert_eq!(
        missing_presented_secret_error,
        InMemoryCommitError::ResponseMaterializationFailed(
            "session response cookie needs a current presented secret or generated secret",
        )
    );
}

#[test]
fn materialized_commit_adapter_requires_explicit_fresh_secret_work_for_new_cookies() {
    let mut store = CredentialMaterializingCommitStore::default();
    let error = store
        .commit_plan_with_materialized_response(
            CommitPlan {
                mutations: vec![Mutation::CreateSession(session_record(200))],
                response_effects: vec![ResponseEffect::IssueSessionCookie(session_cookie(200))],
                ..CommitPlan::default()
            },
            PresentedMaterializedCredentials::default(),
        )
        .expect_err("new session cookie cannot be materialized without explicit fresh secret work");

    assert_eq!(
        error,
        InMemoryCommitError::CoreCommitWorkInvalid(Error::MissingFreshCredentialSecret)
    );
}

#[test]
fn materialized_commit_adapter_does_not_reissue_previous_grace_secret_without_rotation() {
    let mut store = CredentialMaterializingCommitStore::default();
    let previous_secret = TestCredentialSecret(2_002);
    store.insert_session_with_secrets(
        session_record(200),
        TestCredentialSecret(3_003),
        Some(previous_secret),
    );
    let mut previous_cookie_draft = session_cookie(40);
    previous_cookie_draft.secret_version = version(2);
    let previous_cookie = MaterializedSessionCookie {
        draft: previous_cookie_draft,
        secret: previous_secret,
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(previous_cookie.clone(), at(50)),
    )
    .expect("previous secret inside grace");
    let response_effects = store
        .commit_plan_with_materialized_response(
            transition.commit_plan,
            PresentedMaterializedCredentials {
                session: Some(previous_cookie),
                trusted_device: None,
                active_proof_continuation: None,
            },
        )
        .expect("previous secret inside grace commit");
    assert!(response_effects.iter().all(|effect| !matches!(
        effect,
        MaterializedAuthResponseEffect::IssueSessionCookie(_)
    )));
    assert!(!response_effects.contains(&MaterializedAuthResponseEffect::DeleteSessionCookie));
}

#[test]
fn materialized_commit_adapter_rotates_previous_grace_session_to_new_secret_in_refresh_window() {
    let mut store = CredentialMaterializingCommitStore::default();
    let current_secret = TestCredentialSecret(3_003);
    let previous_secret = TestCredentialSecret(2_002);
    let mut refreshable_session = session_record(100);
    refreshable_session.previous_secret_accept_until = Some(at(90));
    store.insert_session_with_secrets(refreshable_session, current_secret, Some(previous_secret));
    let mut previous_cookie_draft = session_cookie(100);
    previous_cookie_draft.secret_version = version(2);
    let previous_cookie = MaterializedSessionCookie {
        draft: previous_cookie_draft,
        secret: previous_secret,
    };

    let transition = reduce_command(
        &config(),
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        &store.loaded_for_session_cookie(previous_cookie.clone(), at(85)),
    )
    .expect("previous secret refresh");
    let response_effects = store
        .commit_plan_with_materialized_response(
            transition.commit_plan,
            PresentedMaterializedCredentials {
                session: Some(previous_cookie),
                trusted_device: None,
                active_proof_continuation: None,
            },
        )
        .expect("previous secret refresh commit");
    let refreshed_cookie = materialized_session_cookie_from_response_effects(&response_effects);

    assert_eq!(refreshed_cookie.draft.secret_version, version(4));
    assert_ne!(refreshed_cookie.secret, current_secret);
    assert_ne!(refreshed_cookie.secret, previous_secret);
    assert_eq!(
        store
            .loaded_for_session_cookie(refreshed_cookie, at(86))
            .session_secret_match
            .as_ref()
            .map(LoadedSessionSecretMatch::kind),
        Some(StoredSecretMatch::Current)
    );
    assert_eq!(
        store
            .session_secret_macs
            .get(&id("session"))
            .expect("session secrets")
            .previous_mac,
        Some(mac_for_test_secret(current_secret))
    );
}

#[test]
fn materialized_commit_adapter_discards_generated_secrets_when_atomic_commit_fails() {
    let mut store = CredentialMaterializingCommitStore::default();
    store.insert_session_with_secrets(session_record(200), TestCredentialSecret(3_003), None);
    store.state.active_proof_attempts.insert(
        id("attempt"),
        active_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::OutOfBandCode)],
        ),
    );
    let before = store.clone();

    let transition = reduce_command(
        &config(),
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(40),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &store.state.loaded_for_attempt(&id("attempt")),
    )
    .expect("duplicate session plan");
    let error = store
        .commit_plan_with_materialized_response(
            transition.commit_plan,
            PresentedMaterializedCredentials::default(),
        )
        .expect_err("duplicate session commit must fail atomically");

    assert_eq!(error, InMemoryCommitError::DuplicateRecord("session"));
    assert_eq!(store, before);
}
