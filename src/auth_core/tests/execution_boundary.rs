use super::*;

fn prepare(command: Command, presented_cookies: PresentedAuthCookies) -> PreparedCommandExecution {
    PreparedCommandExecution::prepare(&config(), command, presented_cookies)
        .expect("prepared command")
}

struct RecordingAtomicCommitAdapter {
    commit_calls: usize,
    seen_storage_contract: Option<AtomicCommitStorageContract>,
    result: Result<Vec<(CoreStorageTarget, &'static [u8])>, &'static str>,
}

impl Default for RecordingAtomicCommitAdapter {
    fn default() -> Self {
        Self {
            commit_calls: 0,
            seen_storage_contract: None,
            result: Ok(Vec::new()),
        }
    }
}

impl AtomicCommitAdapter for RecordingAtomicCommitAdapter {
    type Error = &'static str;

    fn commit_atomic_work(
        &mut self,
        request: AtomicCommitRequest<'_>,
    ) -> Result<Vec<MaterializedFreshCredentialSecret>, Self::Error> {
        self.commit_calls += 1;
        self.seen_storage_contract = Some(request.storage_contract().clone());
        self.result.clone().map(|secrets| {
            secrets
                .into_iter()
                .map(|(target, secret)| materialized_fresh_secret(target, secret))
                .collect()
        })
    }
}

fn materialized_fresh_secret(
    target: CoreStorageTarget,
    secret: &'static [u8],
) -> MaterializedFreshCredentialSecret {
    MaterializedFreshCredentialSecret::new(target, credential_secret(secret))
}

fn credential_secret(secret: &'static [u8]) -> AuthCredentialSecret {
    AuthCredentialSecret::try_from(secret).expect("credential secret")
}

#[test]
fn credential_secrets_must_not_be_empty() {
    assert!(matches!(
        AuthCredentialSecret::try_from([].as_slice()),
        Err(Error::EmptyCredentialSecret)
    ));
}

fn presented_session_secret(
    session_id: &str,
    secret_version: u64,
    secret: &'static [u8],
) -> PresentedSessionCookieSecret {
    PresentedSessionCookieSecret::new(
        id(session_id),
        version(secret_version),
        credential_secret(secret),
    )
}

fn successful_refresh_targets() -> Vec<(CoreStorageTarget, &'static [u8])> {
    vec![(
        CoreStorageTarget::SessionCredentialSecret {
            session_id: id("session"),
            secret_version: version(4),
        },
        b"fresh-session",
    )]
}

#[test]
fn prepared_execution_exposes_load_contract_before_loaded_state_exists() {
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies {
            session_cookie: Some(session_cookie(200)),
            trusted_device_cookie: None,
            active_proof_challenge_cookie: None,
            active_proof_continuation_cookie: None,
        },
    );

    assert_eq!(
        prepared.loaded_state_contract().required(),
        &[
            LoadedStateRequirement::PresentedSessionCookie {
                session_id: id("session"),
            },
            LoadedStateRequirement::SessionRecordAndSecretMatchForPresentedCookie {
                session_id: id("session"),
            },
            LoadedStateRequirement::SubjectRevocationForLoadedSessionSubject {
                session_id: id("session"),
            },
        ]
    );
}

#[test]
fn planned_execution_commits_through_adapter_before_releasing_response_effects() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let expected_storage_contract = planned
        .atomic_commit_storage_contract()
        .expect("storage contract");
    let mut adapter = RecordingAtomicCommitAdapter {
        result: Ok(successful_refresh_targets()),
        ..RecordingAtomicCommitAdapter::default()
    };

    let completed = planned
        .complete_with_commit_adapter(&mut adapter)
        .expect("adapter commit releases response effects");

    assert_eq!(adapter.commit_calls, 1);
    assert_eq!(
        adapter.seen_storage_contract,
        Some(expected_storage_contract)
    );
    assert!(matches!(
        completed.validated_response_effects().as_slice(),
        [
            ResponseEffect::IssueSessionCookie(_),
            ResponseEffect::CycleCsrfToken {
                session_id: Some(session_id),
            },
        ] if *session_id == id("session")
    ));
    let materialized = completed
        .materialize_response_effects(PresentedAuthCookieSecrets::default())
        .expect("response effects materialize after commit");
    assert!(matches!(
        materialized.materialized_response_effects().as_slice(),
        [
            MaterializedResponseEffect::IssueSessionCookie(cookie),
            MaterializedResponseEffect::CycleCsrfToken {
                session_id: Some(session_id),
            },
        ] if cookie.draft().session_id == id("session")
            && cookie.credential_secret().expose_secret() == b"fresh-session"
            && *session_id == id("session")
    ));
}

#[test]
fn planned_execution_does_not_call_commit_adapter_for_empty_atomic_work() {
    let mut loaded = LoadedState {
        session_cookie: Some(session_cookie(200)),
        ..LoadedState::default()
    };
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .safe_read_valid_until = Some(at(80));
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("safe-read planned execution");
    let mut adapter = RecordingAtomicCommitAdapter::default();

    let completed = planned
        .complete_with_commit_adapter(&mut adapter)
        .expect("empty work completes without adapter commit");

    assert_eq!(adapter.commit_calls, 0);
    assert!(completed.validated_response_effects().is_empty());
    let materialized = completed
        .materialize_response_effects(PresentedAuthCookieSecrets::default())
        .expect("empty response materializes");
    assert!(materialized.materialized_response_effects().is_empty());
}

#[test]
fn planned_execution_discards_response_effects_when_commit_adapter_fails() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let mut adapter = RecordingAtomicCommitAdapter {
        result: Err("commit failed"),
        ..RecordingAtomicCommitAdapter::default()
    };

    let error = planned
        .complete_with_commit_adapter(&mut adapter)
        .expect_err("commit failure must prevent completed execution");

    assert_eq!(
        error,
        RuntimeAdapterExecutionError::AtomicCommit("commit failed")
    );
    assert_eq!(adapter.commit_calls, 1);
}

#[test]
fn planned_execution_rejects_commit_adapter_wrong_fresh_secret_targets() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let mut adapter = RecordingAtomicCommitAdapter {
        result: Ok(vec![(
            CoreStorageTarget::SessionCredentialSecret {
                session_id: id("other-session"),
                secret_version: version(4),
            },
            b"wrong-session",
        )]),
        ..RecordingAtomicCommitAdapter::default()
    };

    let error = planned
        .complete_with_commit_adapter(&mut adapter)
        .expect_err("wrong materialized targets must prevent completed execution");

    assert_eq!(
        error,
        RuntimeAdapterExecutionError::Core(Error::UnexpectedMaterializedFreshCredentialSecret)
    );
    assert_eq!(adapter.commit_calls, 1);
}

#[test]
fn response_materialization_reuses_presented_current_session_secret_when_no_fresh_secret_exists() {
    let loaded = loaded_session(200);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned authoritative validation");
    let mut adapter = RecordingAtomicCommitAdapter::default();
    let materialized = planned
        .complete_with_commit_adapter_and_materialize_response(
            &mut adapter,
            PresentedAuthCookieSecrets::new(
                Some(presented_session_secret("session", 3, b"current-session")),
                None,
                None,
            ),
        )
        .expect("response materializes with presented current secret");

    assert_eq!(adapter.commit_calls, 1);
    assert!(matches!(
        materialized.materialized_response_effects().as_slice(),
        [MaterializedResponseEffect::IssueSessionCookie(cookie)]
            if cookie.draft().session_id == id("session")
                && cookie.draft().secret_version == version(3)
                && cookie.credential_secret().expose_secret() == b"current-session"
    ));
}

#[test]
fn response_materialization_rejects_missing_presented_session_secret_when_no_fresh_secret_exists() {
    let loaded = loaded_session(200);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned authoritative validation");
    let mut adapter = RecordingAtomicCommitAdapter::default();
    let error = planned
        .complete_with_commit_adapter_and_materialize_response(
            &mut adapter,
            PresentedAuthCookieSecrets::default(),
        )
        .expect_err("presented current secret is required");

    assert_eq!(
        error,
        RuntimeAdapterExecutionError::Core(Error::MissingSessionCookieResponseSecret)
    );
}

#[test]
fn response_materialization_rejects_presented_secret_for_different_cookie() {
    let loaded = loaded_session(200);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned authoritative validation");
    let mut adapter = RecordingAtomicCommitAdapter::default();
    let error = planned
        .complete_with_commit_adapter_and_materialize_response(
            &mut adapter,
            PresentedAuthCookieSecrets::new(
                Some(presented_session_secret(
                    "other-session",
                    3,
                    b"wrong-session",
                )),
                None,
                None,
            ),
        )
        .expect_err("secret must match presented cookie");

    assert_eq!(
        error,
        RuntimeAdapterExecutionError::Core(Error::PresentedSessionCookieSecretMismatch)
    );
}

#[test]
fn prepared_execution_rejects_loaded_state_from_different_presented_cookie_set() {
    let mut presented_cookie = session_cookie(200);
    presented_cookie.session_fast_fail_until = at(210);

    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies {
            session_cookie: Some(presented_cookie),
            trusted_device_cookie: None,
            active_proof_challenge_cookie: None,
            active_proof_continuation_cookie: None,
        },
    );

    let error = prepared
        .reduce_loaded_state(&config(), &loaded_session(200))
        .expect_err("loaded state must match presented cookies");

    assert_eq!(
        error,
        Error::LoadedStateDoesNotSatisfyLoadContract(
            "loaded session cookie differs from presented session cookie",
        )
    );
}

#[test]
fn prepared_execution_validates_loaded_state_contract_before_reducing() {
    let cookie = session_cookie(200);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies {
            session_cookie: Some(cookie.clone()),
            trusted_device_cookie: None,
            active_proof_challenge_cookie: None,
            active_proof_continuation_cookie: None,
        },
    );

    let error = prepared
        .reduce_loaded_state(
            &config(),
            &LoadedState {
                session_cookie: Some(cookie),
                ..LoadedState::default()
            },
        )
        .expect_err("authoritative session load is required");

    assert_eq!(
        error,
        Error::LoadedStateDoesNotSatisfyLoadContract("required session record is missing")
    );
}

#[test]
fn planned_execution_separates_atomic_work_from_validated_response_effects() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");

    assert!(matches!(
        planned.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::RefreshedSession,
            ..
        })
    ));
    assert!(!planned.atomic_commit_work().is_empty());
    let commit_success = successful_commit_for_planned_refresh(&planned);
    let completed = planned
        .finish_after_successful_atomic_commit(commit_success)
        .expect("commit succeeded");
    assert!(matches!(
        completed.validated_response_effects().as_slice(),
        [
            ResponseEffect::IssueSessionCookie(_),
            ResponseEffect::CycleCsrfToken {
                session_id: Some(session_id),
            },
        ] if *session_id == id("session")
    ));
}

#[test]
fn planned_execution_does_not_release_response_effects_when_commit_fails() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");

    let error = planned.discard_after_failed_atomic_commit("commit failed");

    assert_eq!(error, "commit failed");
}

#[test]
fn runtime_pipeline_contract_orders_prepared_and_planned_execution_stages() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );

    assert_eq!(
        prepared.runtime_pipeline_contract().stages(),
        &[
            RuntimeAdapterPipelineStage::DecodePresentedCookies,
            RuntimeAdapterPipelineStage::DeriveLoadedStateContract,
            RuntimeAdapterPipelineStage::LoadState,
            RuntimeAdapterPipelineStage::ValidateLoadedState,
            RuntimeAdapterPipelineStage::ReduceCommand,
        ]
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");

    assert_eq!(
        planned
            .runtime_pipeline_contract()
            .expect("runtime pipeline")
            .stages(),
        &[
            RuntimeAdapterPipelineStage::BuildStorageContract,
            RuntimeAdapterPipelineStage::MaterializeFreshCredentialSecrets,
            RuntimeAdapterPipelineStage::CommitAtomicStorageWork,
            RuntimeAdapterPipelineStage::MaterializeResponseEffects,
            RuntimeAdapterPipelineStage::ReleaseResponseEffects,
        ]
    );
}

#[test]
fn successful_atomic_commit_requires_exact_materialized_fresh_secret_targets() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");

    let missing_error = MaterializedFreshCredentialSecrets::for_atomic_work(
        planned.atomic_commit_work(),
        Vec::new(),
    )
    .expect_err("fresh credential secret target is required");
    assert_eq!(
        missing_error,
        Error::MissingMaterializedFreshCredentialSecret
    );

    let unexpected_error = MaterializedFreshCredentialSecrets::for_atomic_work(
        planned.atomic_commit_work(),
        vec![materialized_fresh_secret(
            CoreStorageTarget::SessionCredentialSecret {
                session_id: id("other-session"),
                secret_version: version(4),
            },
            b"wrong-session",
        )],
    )
    .expect_err("wrong fresh credential secret target is rejected");
    assert_eq!(
        unexpected_error,
        Error::UnexpectedMaterializedFreshCredentialSecret
    );

    let duplicate_error = MaterializedFreshCredentialSecrets::for_atomic_work(
        planned.atomic_commit_work(),
        vec![
            materialized_fresh_secret(
                CoreStorageTarget::SessionCredentialSecret {
                    session_id: id("session"),
                    secret_version: version(4),
                },
                b"fresh-session-a",
            ),
            materialized_fresh_secret(
                CoreStorageTarget::SessionCredentialSecret {
                    session_id: id("session"),
                    secret_version: version(4),
                },
                b"fresh-session-b",
            ),
        ],
    )
    .expect_err("duplicate fresh credential secret target is rejected");
    assert_eq!(
        duplicate_error,
        Error::DuplicateMaterializedFreshCredentialSecret
    );

    let materialized = MaterializedFreshCredentialSecrets::for_atomic_work(
        planned.atomic_commit_work(),
        vec![materialized_fresh_secret(
            CoreStorageTarget::SessionCredentialSecret {
                session_id: id("session"),
                secret_version: version(4),
            },
            b"fresh-session",
        )],
    )
    .expect("materialized targets match");
    let commit_success =
        AtomicCommitSuccess::for_atomic_work(planned.atomic_commit_work(), materialized)
            .expect("commit success");

    assert_eq!(
        commit_success
            .materialized_fresh_credential_secrets()
            .targets(),
        &[CoreStorageTarget::SessionCredentialSecret {
            session_id: id("session"),
            secret_version: version(4),
        }]
    );
}

#[test]
fn planned_execution_rejects_commit_success_for_different_atomic_work() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );
    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");
    let empty_work = AtomicCommitWork::default();
    let empty_materialized =
        MaterializedFreshCredentialSecrets::for_atomic_work(&empty_work, Vec::new())
            .expect("empty materialized targets");
    let wrong_commit_success =
        AtomicCommitSuccess::for_atomic_work(&empty_work, empty_materialized)
            .expect("wrong commit success");

    let error = planned
        .finish_after_successful_atomic_commit(wrong_commit_success)
        .expect_err("wrong commit success must not release response effects");

    assert_eq!(error, Error::AtomicCommitSuccessDoesNotMatchPlannedWork);
}

#[test]
fn safe_read_execution_releases_no_atomic_work_or_response_effects() {
    let mut loaded = LoadedState {
        session_cookie: Some(session_cookie(200)),
        ..LoadedState::default()
    };
    loaded
        .session_cookie
        .as_mut()
        .expect("session cookie")
        .safe_read_valid_until = Some(at(80));

    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(50),
            request_kind: RequestKind::SafeRead,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("safe-read planned execution");

    assert!(matches!(
        planned.outcome(),
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::SafeReadCache,
            ..
        })
    ));
    assert!(planned.atomic_commit_work().is_empty());
    let completed = planned
        .finish_without_atomic_commit()
        .expect("no atomic commit required");
    assert!(completed.validated_response_effects().is_empty());
}

#[test]
fn planned_execution_rejects_without_atomic_commit_when_atomic_work_exists() {
    let loaded = loaded_session(100);
    let prepared = prepare(
        Command::ResolveRequest(ResolveRequest {
            now: at(85),
            request_kind: RequestKind::StateChanging,
            fresh_session_id: None,
        }),
        PresentedAuthCookies::from_loaded_state(&loaded),
    );

    let planned = prepared
        .reduce_loaded_state(&config(), &loaded)
        .expect("planned execution");

    let error = planned
        .finish_without_atomic_commit()
        .expect_err("atomic commit is required");

    assert_eq!(error, Error::AtomicCommitRequiredBeforeResponseEffects);
}

fn successful_commit_for_planned_refresh(planned: &PlannedCommandExecution) -> AtomicCommitSuccess {
    let materialized = MaterializedFreshCredentialSecrets::for_atomic_work(
        planned.atomic_commit_work(),
        vec![materialized_fresh_secret(
            CoreStorageTarget::SessionCredentialSecret {
                session_id: id("session"),
                secret_version: version(4),
            },
            b"fresh-session",
        )],
    )
    .expect("materialized fresh credential secrets");
    AtomicCommitSuccess::for_atomic_work(planned.atomic_commit_work(), materialized)
        .expect("commit success")
}
