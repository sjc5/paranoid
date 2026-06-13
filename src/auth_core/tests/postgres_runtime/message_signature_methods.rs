use super::*;

#[tokio::test]
async fn postgres_runtime_completes_message_signature_through_method_registry() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_message_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("message-signature-subject");
    let method = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("message signature method");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue message signature challenge through method registry");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id: issued_attempt_id,
            challenge_id: issued_challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(
                proof,
                &ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature").expect("proof"),
            );
            (
                issued_attempt_id.clone(),
                issued_challenge_id.clone(),
                method_challenge,
            )
        }
        outcome => panic!("expected message signature challenge issue, got {outcome:?}"),
    };
    assert!(
        method_challenge.as_bytes().starts_with(
            test_challenge_presentation_prefix(ProofFamily::MessageSignature)
                .expect("message signature challenge prefix")
        )
    );
    let message_signature_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::MessageSignature);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    assert_eq!(
        count_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();
    let bad_response_error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(40),
                response_payload: mismatched_runtime_challenge_test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect_err("bad message signature response must reject before authoritative state load");
    assert!(matches!(
        bad_response_error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::MessageSignature,
                operation: "active_proof_completion",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "bad message signature response must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "bad message signature response must leave the authoritative challenge open"
    );

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(50),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete message signature proof through method registry");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("proof"),
        }
    );
    assert!(set_cookie_headers_contain_deletion(
        completed.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    ));
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::MessageSignature,
            test_active_method_source_id(ProofFamily::MessageSignature, &subject_id),
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_message_signature_after_authoritative_confirmation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let method = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("message signature method");
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_authoritative_test_method(
            method.clone(),
        )
        .await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("authoritative-message-subject");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: method.clone(),
                method_challenge_request_payload: None,
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                &method,
            ),
        )
        .await
        .expect("issue authoritative message signature challenge through method registry");
    let (attempt_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), method_challenge),
        outcome => panic!("expected message signature challenge issue, got {outcome:?}"),
    };
    let message_signature_nonce =
        test_method_runtime_challenge_bytes(method_challenge, ProofFamily::MessageSignature);
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);

    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: test_method_response_payload(
                    ProofFamily::MessageSignature,
                    message_signature_nonce,
                    &subject_id,
                ),
                weak_proof_gate_response: None,
            },
        )
        .await
        .expect("complete message signature through authoritative confirmation");

    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature")
                .expect("proof"),
        }
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(test_active_method_proof_source(
            ProofFamily::MessageSignature,
            test_active_method_source_id(ProofFamily::MessageSignature, &subject_id),
        ))
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_completes_password_derived_signature_after_authoritative_recheck() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("password-signature-subject");
    let password_credential_id: VerifiedProofSourceId = id("password-signature-credential");
    let lookup_handle = b"password-signature-lookup";
    let password = b"correct-password";
    let salt = PasswordKdfSalt::from_bytes(&[11_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password,
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            proof,
            method_challenge,
            ..
        } => {
            assert_eq!(proof, &plugin.method().verified_proof_summary());
            (attempt_id.clone(), challenge_id.clone(), method_challenge)
        }
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        password,
        method_challenge,
    )
    .expect("password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &response_payload,
        at(30),
    );

    harness.database_operation_observer.clear();
    let completed = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect("complete password-derived signature proof");

    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.password_derived_signature.verify.fetch_locked_current_verifier",
        "password-derived signature success must recheck authoritative verifier state",
    );
    assert_eq!(
        completed.outcome(),
        &Outcome::ActiveProofCompleted {
            attempt_id: attempt_id.clone(),
            proof: plugin.method().verified_proof_summary(),
        }
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        1
    );
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            password_credential_id,
        ))
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_wrong_password_derived_signature_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("wrong-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId = id("wrong-password-signature-credential");
    let lookup_handle = b"wrong-password-signature-lookup";
    let salt = PasswordKdfSalt::from_bytes(&[12_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"correct-password",
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            challenge_id,
            method_challenge,
            ..
        } => (challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        b"wrong-password",
        method_challenge,
    )
    .expect("wrong password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &response_payload,
        at(30),
    );

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("wrong password-derived signature must reject before state load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::MessageSignature,
                operation: "active_proof_completion",
                ..
            }
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "wrong password-derived signature must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "wrong password-derived signature must leave the authoritative challenge open",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_invalid_password_derived_weak_gate_before_database_work() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("invalid-gate-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId =
        id("invalid-gate-password-signature-credential");
    let lookup_handle = b"invalid-gate-password-signature-lookup";
    let salt = PasswordKdfSalt::from_bytes(&[17_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"correct-password",
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        b"correct-password",
        method_challenge,
    )
    .expect("valid password-derived signature response");

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(invalid_proof_of_work_gate_response()),
            },
        )
        .await
        .expect_err("invalid password-derived weak gate must reject before state load");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "invalid password-derived weak gate must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "invalid password-derived weak gate must leave the authoritative challenge open",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_reused_password_derived_weak_gate_for_different_signature_before_database_work()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("reused-gate-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId =
        id("reused-gate-password-signature-credential");
    let lookup_handle = b"reused-gate-password-signature-lookup";
    let salt = PasswordKdfSalt::from_bytes(&[15_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"correct-password",
                salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            challenge_id,
            method_challenge,
            ..
        } => (challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    let first_guessed_response_payload =
        PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
            b"first-wrong-password",
            method_challenge,
        )
        .expect("first guessed password-derived signature response");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &completion_headers,
        &first_guessed_response_payload,
        at(30),
    );
    let second_guessed_response_payload =
        PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
            b"second-wrong-password",
            method_challenge,
        )
        .expect("second guessed password-derived signature response");

    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload: second_guessed_response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("weak gate solved for one signature must not work for another signature");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::Core(
            Error::WeakProofGateVerificationFailed
        )
    ));
    assert_no_database_operations(
        &harness.database_operation_observer,
        "reused password-derived weak gate must reject before any database operation",
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1,
        "reused password-derived weak gate must leave the authoritative challenge open",
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_password_derived_signature_after_verifier_rotation() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let empty_headers = HeaderMap::new();
    let subject_id: SubjectId = id("rotated-password-signature-subject");
    let password_credential_id: VerifiedProofSourceId = id("rotated-password-signature-credential");
    let lookup_handle = b"rotated-password-signature-lookup";
    let first_salt =
        PasswordKdfSalt::from_bytes(&[13_u8; PASSWORD_KDF_SALT_SIZE]).expect("first KDF salt");
    let second_salt =
        PasswordKdfSalt::from_bytes(&[14_u8; PASSWORD_KDF_SALT_SIZE]).expect("second KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"old-password",
                salt: first_salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store old password-derived verifier");

    let issued = runtime
        .execute_unbound_active_proof_attempt_start_and_active_proof_method_challenge_issue_from_headers(
            &empty_headers,
            StartAndIssueActiveProofMethodChallengeInput {
                now: at(20),
                proof_use: ProofUse::ContributeToFullAuthentication,
                method: plugin.method().clone(),
                method_challenge_request_payload: Some(
                    PostgresPasswordDerivedSignatureMethodPlugin::challenge_request_payload_for_test(
                        lookup_handle,
                    )
                    .expect("password-derived challenge request payload"),
                ),
            },
            challenge_issue_preflight_response_for_test(
                at(20),
                ProofUse::ContributeToFullAuthentication,
                plugin.method(),
            ),
        )
        .await
        .expect("issue password-derived signature challenge");
    let (attempt_id, challenge_id, method_challenge) = match issued.outcome() {
        Outcome::ActiveProofMethodChallengeIssued {
            attempt_id,
            challenge_id,
            method_challenge,
            ..
        } => (attempt_id.clone(), challenge_id.clone(), method_challenge),
        outcome => panic!("expected password-derived signature challenge issue, got {outcome:?}"),
    };
    let challenge_cookie_pair = cookie_pair_from_set_cookie(
        issued.set_cookie_headers(),
        "__Host-__paranoid_auth_active_proof_challenge=",
    )
    .to_owned();
    let response_payload = PostgresPasswordDerivedSignatureMethodPlugin::response_payload_for_test(
        b"old-password",
        method_challenge,
    )
    .expect("password-derived signature response against sealed old verifier");
    let weak_proof_gate_response = bound_proof_of_work_gate_response_for_active_method_completion(
        &headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]),
        &response_payload,
        at(30),
    );

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &password_credential_id,
                lookup_handle,
                password: b"new-password",
                salt: second_salt,
                params,
                now: at(25),
            },
        )
        .await
        .expect("rotate password-derived verifier");

    let completion_headers = headers_from_cookie_pairs(&[challenge_cookie_pair.as_str()]);
    harness.database_operation_observer.clear();
    let error = runtime
        .execute_active_proof_method_response_from_headers(
            &completion_headers,
            CompleteActiveProofMethodResponse {
                now: at(30),
                response_payload,
                weak_proof_gate_response: Some(weak_proof_gate_response),
            },
        )
        .await
        .expect_err("stale password-derived signature challenge must reject after recheck");

    assert!(matches!(
        error,
        super::super::super::postgres_runtime::AuthPostgresWebRuntimeExecutionError::MethodBuild(
            super::super::super::postgres_method_runtime::PostgresAuthMethodBuildError::PluginRejected {
                family: ProofFamily::MessageSignature,
                operation: "active_proof_authoritative_confirmation",
                ..
            }
        )
    ));
    assert_database_operations_include_label(
        &harness.database_operation_observer,
        "auth_core.password_derived_signature.verify.fetch_locked_current_verifier",
        "stale password-derived signature challenge must perform authoritative verifier recheck",
    );
    assert_eq!(
        count_satisfied_proofs_for_attempt(pool, store_config, &attempt_id).await,
        0
    );
    assert_eq!(
        count_open_challenges_for_challenge(pool, store_config, &challenge_id).await,
        1
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_addition_creates_usable_password_derived_signature_verifier()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("password-add-subject");
    let lookup_handle = b"password-add-lookup";
    let password = b"new-password";
    let salt = PasswordKdfSalt::from_bytes(&[21_u8; PASSWORD_KDF_SALT_SIZE]).expect("KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "password-add-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let session_authority = id("password-add-session-authority");
    let password_authority = id("password-add-password-authority");
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[],
            &[],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed session lifecycle authority");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);
    let addition = runtime
        .execute_authenticated_credential_addition_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialAdditionInput {
                now: at(70),
                method: plugin.method().clone(),
                reset_policy_role: CredentialResetPolicyRole::OrdinaryCredential,
                recovery_authority_rules: vec![
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Create,
                        authority_id: session_authority,
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                    CredentialAdditionRecoveryAuthorityRule {
                        action: CredentialLifecycleAction::Reset,
                        authority_id: password_authority.clone(),
                        timing: RecoveryAuthorityTiming::Immediate,
                    },
                ],
                new_credential_authority_ids: vec![password_authority],
                method_payload:
                    PostgresPasswordDerivedSignatureMethodPlugin::verifier_creation_payload_for_test(
                        lookup_handle,
                        password,
                        salt,
                        params,
                    )
                    .expect("password-derived verifier creation payload"),
            },
        )
        .await
        .expect("execute password-derived credential addition");
    let added_credential_id = match addition.outcome() {
        Outcome::CredentialAdded(outcome) => {
            assert_eq!(&outcome.subject_id, &subject_id);
            outcome.credential_instance_id.clone()
        }
        outcome => panic!("expected password-derived credential addition, got {outcome:?}"),
    };
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count password-derived verifiers"),
        1,
        "credential addition must create exactly one password-derived verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch password-derived verifier version"),
        Some(1),
        "new password-derived verifier starts at version 1"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &added_credential_id).await,
        CredentialLifecycleState::Active,
        "password-derived addition must create active core credential metadata"
    );

    let attempt_id =
        complete_password_derived_signature_full_authentication_proof_for_runtime_test(
            runtime,
            plugin,
            lookup_handle,
            password,
            at(80),
            at(90),
        )
        .await;
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            added_credential_id,
        )),
        "proof from added password-derived verifier must record the new credential source"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_replacement_replaces_real_password_derived_signature_verifier()
 {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("password-replace-subject");
    let target_credential_id = id("password-replace-target");
    let session_authority = id("password-replace-session-authority");
    let old_lookup_handle = b"password-replace-old-lookup";
    let new_lookup_handle = b"password-replace-new-lookup";
    let old_password = b"old-password-replace";
    let new_password = b"new-password-replace";
    let old_salt =
        PasswordKdfSalt::from_bytes(&[31_u8; PASSWORD_KDF_SALT_SIZE]).expect("old KDF salt");
    let new_salt =
        PasswordKdfSalt::from_bytes(&[32_u8; PASSWORD_KDF_SALT_SIZE]).expect("new KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &target_credential_id,
                lookup_handle: old_lookup_handle,
                password: old_password,
                salt: old_salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store old password-derived verifier");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "password-replace-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                plugin.method().method_label(),
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("password-derived credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Replace,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[
                LifecycleAuthorityEvidence::authenticated_session(
                    issued_auth.session_id.clone(),
                    [session_authority],
                )
                .expect("session lifecycle evidence"),
                credential_instance_lifecycle_evidence(
                    "password-replace-target",
                    [id("password-replace-target-authority")],
                ),
            ],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    let execution = runtime
        .execute_authenticated_credential_replacement_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialReplacementInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload:
                    PostgresPasswordDerivedSignatureMethodPlugin::verifier_lifecycle_payload_for_test(
                        new_lookup_handle,
                        new_password,
                        new_salt,
                        params,
                    )
                    .expect("password-derived replacement payload"),
            },
        )
        .await
        .expect("execute authenticated password-derived credential replacement");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count password-derived verifiers"),
        1,
        "credential replacement must leave exactly one password-derived verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch password-derived verifier version"),
        Some(1),
        "password-derived replacement successor starts verifier version at 1"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Superseded,
        "password-derived replacement must supersede the old target credential"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "password-derived replacement execution must revoke existing subject auth state"
    );

    let attempt_id =
        complete_password_derived_signature_full_authentication_proof_for_runtime_test(
            runtime,
            plugin,
            new_lookup_handle,
            new_password,
            at(90),
            at(100),
        )
        .await;
    let proof_source = fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id)
        .await
        .expect("password-derived replacement proof source");
    assert_eq!(
        proof_source.kind(),
        VerifiedProofSourceKind::CredentialInstance
    );
    assert_ne!(
        proof_source.source_id(),
        &target_credential_id,
        "replacement proof must come from the runtime-generated successor credential, not the superseded target"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, proof_source.source_id())
            .await,
        CredentialLifecycleState::Active,
        "password-derived replacement proof source must be the active successor credential"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_authenticated_rotation_rotates_real_password_derived_signature_verifier()
{
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_password_derived_signature_method().await;
    let pool = &harness.pool;
    let store_config = &harness.store_config;
    let runtime = &harness.runtime;
    let plugin = password_derived_signature_plugin_for_harness(&harness);
    let subject_id: SubjectId = id("password-rotate-subject");
    let target_credential_id = id("password-rotate-target");
    let session_authority = id("password-rotate-session-authority");
    let old_lookup_handle = b"password-rotate-old-lookup";
    let new_lookup_handle = b"password-rotate-new-lookup";
    let old_password = b"old-password-rotate";
    let new_password = b"new-password-rotate";
    let old_salt =
        PasswordKdfSalt::from_bytes(&[33_u8; PASSWORD_KDF_SALT_SIZE]).expect("old KDF salt");
    let new_salt =
        PasswordKdfSalt::from_bytes(&[34_u8; PASSWORD_KDF_SALT_SIZE]).expect("new KDF salt");
    let params = minimum_accepted_password_kdf_params_for_tests();

    plugin
        .store_verifier_for_test(
            pool,
            PasswordDerivedSignatureVerifierForTest {
                subject_id: &subject_id,
                password_credential_id: &target_credential_id,
                lookup_handle: old_lookup_handle,
                password: old_password,
                salt: old_salt,
                params,
                now: at(10),
            },
        )
        .await
        .expect("store old password-derived verifier");
    let issued_auth = complete_full_authentication_through_runtime(
        runtime,
        pool,
        store_config,
        email_otp_plugin_for_harness(&harness),
        "password-rotate-bootstrap",
        50,
        subject_id.clone(),
        false,
    )
    .await;
    let seed_store = super::super::super::postgres_store::PostgresAuthStore::new(
        store_config.clone(),
        test_keyset("tests.auth.postgres-runtime.credentials.v1"),
    );
    seed_store
        .store_credential_lifecycle_metadata_for_test(
            pool,
            &[CredentialInstanceMetadata::new(
                target_credential_id.clone(),
                subject_id.clone(),
                CredentialInstanceKind::MessageSignatureVerifier,
                plugin.method().method_label(),
                CredentialResetPolicyRole::OrdinaryCredential,
                CredentialLifecycleState::Active,
            )
            .expect("password-derived credential metadata")],
            &[CredentialRecoveryAuthority::new(
                target_credential_id.clone(),
                CredentialLifecycleAction::Rotate,
                session_authority.clone(),
                RecoveryAuthorityTiming::Immediate,
            )],
            &[LifecycleAuthorityEvidence::authenticated_session(
                issued_auth.session_id.clone(),
                [session_authority.clone()],
            )
            .expect("session lifecycle evidence")],
            at(50),
        )
        .await
        .expect("seed credential lifecycle metadata");
    let headers = headers_from_cookie_pairs(&[issued_auth.session_cookie_pair.as_str()]);

    harness.database_operation_observer.clear();
    let execution = runtime
        .execute_authenticated_credential_rotation_from_headers(
            &headers,
            ExecuteAuthenticatedCredentialRotationInput {
                now: at(80),
                target_credential_instance_id: target_credential_id.clone(),
                method_payload:
                    PostgresPasswordDerivedSignatureMethodPlugin::verifier_lifecycle_payload_for_test(
                        new_lookup_handle,
                        new_password,
                        new_salt,
                        params,
                    )
                    .expect("password-derived rotation payload"),
            },
        )
        .await
        .expect("execute authenticated password-derived credential rotation");

    assert_eq!(
        execution.outcome(),
        &Outcome::CredentialRotated(CredentialRotationExecutionOutcome {
            subject_id: subject_id.clone(),
            target_credential_instance_id: target_credential_id.clone(),
        })
    );
    assert_eq!(
        plugin
            .count_verifiers_for_subject_for_test(pool, &subject_id)
            .await
            .expect("count password-derived verifiers"),
        1,
        "credential rotation must leave exactly one password-derived verifier row"
    );
    assert_eq!(
        plugin
            .verifier_version_for_subject_for_test(pool, &subject_id)
            .await
            .expect("fetch password-derived verifier version"),
        Some(2),
        "password-derived rotation must increment verifier version for the same credential"
    );
    assert_eq!(
        credential_lifecycle_state_for_runtime_test(pool, store_config, &target_credential_id)
            .await,
        CredentialLifecycleState::Active,
        "password-derived rotation must preserve the target credential metadata"
    );
    assert_eq!(
        fetch_credential_recovery_authorities_for_runtime_test(
            pool,
            store_config,
            &target_credential_id,
        )
        .await,
        vec![CredentialRecoveryAuthority::new(
            target_credential_id.clone(),
            CredentialLifecycleAction::Rotate,
            session_authority,
            RecoveryAuthorityTiming::Immediate,
        )],
        "password-derived rotation must preserve the target recovery-authority graph"
    );
    assert_eq!(
        fetch_subject_revocation_cutoff(pool, store_config, &subject_id).await,
        Some(80),
        "password-derived rotation execution must revoke existing subject auth state"
    );

    let attempt_id =
        complete_password_derived_signature_full_authentication_proof_for_runtime_test(
            runtime,
            plugin,
            new_lookup_handle,
            new_password,
            at(90),
            at(100),
        )
        .await;
    assert_eq!(
        fetch_satisfied_proof_source_for_attempt(pool, store_config, &attempt_id).await,
        Some(VerifiedProofSource::new(
            VerifiedProofSourceKind::CredentialInstance,
            target_credential_id,
        )),
        "rotated password-derived verifier must still prove through the same credential instance"
    );

    harness.drop_schema().await;
}
