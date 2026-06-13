use super::*;

fn mounted_credential_handle(label: &str) -> MountedCredentialHandle {
    MountedCredentialHandle::from_credential_instance_id(id(label))
}

#[test]
fn mounted_credential_addition_method_constructs_runtime_input_from_configured_policy() {
    let method = proof_method(ProofFamily::MessageSignature);
    let create_rule = CredentialAdditionRecoveryAuthorityRule {
        action: CredentialLifecycleAction::Create,
        authority_id: id("mounted-add-session-authority"),
        timing: RecoveryAuthorityTiming::Immediate,
    };
    let reset_rule = CredentialAdditionRecoveryAuthorityRule {
        action: CredentialLifecycleAction::Reset,
        authority_id: id("mounted-add-new-authority"),
        timing: RecoveryAuthorityTiming::Immediate,
    };
    let new_credential_authority_id = id("mounted-add-new-authority");
    let addition_method = MountedCredentialAdditionMethod::new(
        method.clone(),
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![create_rule.clone(), reset_rule.clone()],
        vec![new_credential_authority_id.clone()],
    )
    .expect("mounted addition method");

    assert_eq!(addition_method.method(), &method);
    assert_eq!(
        addition_method.reset_policy_role(),
        CredentialResetPolicyRole::OrdinaryCredential
    );
    assert_eq!(
        addition_method.recovery_authority_rules(),
        &[create_rule.clone(), reset_rule.clone()]
    );
    assert_eq!(
        addition_method.new_credential_authority_ids(),
        &[new_credential_authority_id.clone()]
    );

    let method_payload =
        CredentialCreationMethodPayload::try_from_bytes(b"mounted-add-payload".as_slice())
            .expect("creation payload");
    assert_eq!(
        addition_method.runtime_input(ExecuteMountedAuthenticatedCredentialAdditionInput {
            now: at(44),
            method_payload: method_payload.clone(),
        }),
        ExecuteAuthenticatedCredentialAdditionInput {
            now: at(44),
            method,
            reset_policy_role: CredentialResetPolicyRole::OrdinaryCredential,
            recovery_authority_rules: vec![create_rule, reset_rule],
            new_credential_authority_ids: vec![new_credential_authority_id],
            method_payload,
        }
    );
}

#[test]
fn mounted_credential_addition_method_rejects_invalid_configured_policy() {
    let method = proof_method(ProofFamily::MessageSignature);
    let create_rule = CredentialAdditionRecoveryAuthorityRule {
        action: CredentialLifecycleAction::Create,
        authority_id: id("mounted-add-session-authority"),
        timing: RecoveryAuthorityTiming::Immediate,
    };
    let reset_rule = CredentialAdditionRecoveryAuthorityRule {
        action: CredentialLifecycleAction::Reset,
        authority_id: id("mounted-add-new-authority"),
        timing: RecoveryAuthorityTiming::Immediate,
    };

    assert_eq!(
        MountedCredentialAdditionMethod::new(
            proof_method(ProofFamily::OutOfBandCode),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![create_rule.clone()],
            vec![id("mounted-add-new-authority")],
        ),
        Err(Error::InvalidConfig(
            "proof family is not an app-owned credential instance",
        )),
    );
    assert_eq!(
        MountedCredentialAdditionMethod::new(
            proof_method(ProofFamily::TrustedDevice),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![create_rule.clone()],
            vec![id("mounted-add-new-authority")],
        ),
        Err(Error::InvalidConfig(
            "mounted credential addition method cannot create trusted-device credentials",
        )),
    );
    assert_eq!(
        MountedCredentialAdditionMethod::new(
            method.clone(),
            CredentialResetPolicyRole::OrdinaryCredential,
            Vec::new(),
            vec![id("mounted-add-new-authority")],
        ),
        Err(Error::InvalidConfig(
            "mounted credential addition method must define recovery authority rules",
        )),
    );
    assert_eq!(
        MountedCredentialAdditionMethod::new(
            method.clone(),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![reset_rule.clone()],
            vec![id("mounted-add-new-authority")],
        ),
        Err(Error::InvalidConfig(
            "mounted credential addition method must include an immediate create authority",
        )),
    );
    assert_eq!(
        MountedCredentialAdditionMethod::new(
            method.clone(),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![create_rule.clone(), create_rule.clone()],
            vec![id("mounted-add-new-authority")],
        ),
        Err(Error::InvalidConfig(
            "mounted credential addition method must not duplicate recovery authority rules",
        )),
    );
    assert_eq!(
        MountedCredentialAdditionMethod::new(
            method.clone(),
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![create_rule.clone()],
            Vec::new(),
        ),
        Err(Error::InvalidConfig(
            "mounted credential addition method must define new credential authorities",
        )),
    );
    assert_eq!(
        MountedCredentialAdditionMethod::new(
            method,
            CredentialResetPolicyRole::OrdinaryCredential,
            vec![create_rule],
            vec![
                id("mounted-add-new-authority"),
                id("mounted-add-new-authority"),
            ],
        ),
        Err(Error::InvalidConfig(
            "mounted credential addition method must not duplicate new credential authorities",
        )),
    );
}

#[test]
fn mounted_credential_addition_route_validates_path_segment() {
    let addition_method = MountedCredentialAdditionMethod::new(
        proof_method(ProofFamily::MessageSignature),
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("mounted-add-route-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("mounted-add-route-new-authority")],
    )
    .expect("mounted credential addition method");

    let route = MountedCredentialAdditionRoute::new("password-signature", addition_method.clone())
        .expect("credential addition route");
    assert_eq!(route.route_segment(), "password-signature");
    assert_eq!(route.relative_path(), "/credentials/add/password-signature");
    assert_eq!(route.method_config(), &addition_method);

    assert_eq!(
        MountedCredentialAdditionRoute::new("", addition_method.clone()),
        Err(Error::InvalidConfig(
            "mounted credential addition route segment must not be empty",
        ))
    );
    assert_eq!(
        MountedCredentialAdditionRoute::new("..", addition_method.clone()),
        Err(Error::InvalidConfig(
            "mounted credential addition route segment must not be a dot segment",
        ))
    );
    assert_eq!(
        MountedCredentialAdditionRoute::new("password/signature", addition_method),
        Err(Error::InvalidConfig(
            "mounted credential addition route segment must contain only ASCII letters, digits, dots, underscores, or hyphens",
        ))
    );
}

#[test]
fn mounted_credential_addition_committed_outcome_maps_only_additions() {
    assert_eq!(
        MountedCredentialAdditionCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::CredentialAdded(CredentialAdditionOutcome {
                subject_id: id("mounted-add-subject"),
                credential_instance_id: id("mounted-add-credential"),
            }),
        ),
        Some(MountedCredentialAdditionCommittedOutcome::CredentialAdded {
            subject_id: id("mounted-add-subject"),
            credential_instance_id: id("mounted-add-credential"),
        })
    );
    assert_eq!(
        MountedCredentialAdditionCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        None
    );
}

#[test]
fn mounted_credential_addition_service_outcome_maps_auth_control_responses() {
    assert_eq!(
        MountedCredentialAdditionServiceOutcome::from_reducer_outcome(&Outcome::CredentialAdded(
            CredentialAdditionOutcome {
                subject_id: id("mounted-add-service-subject"),
                credential_instance_id: id("mounted-add-service-credential"),
            },
        )),
        Some(MountedCredentialAdditionServiceOutcome::CredentialAdded {
            subject_id: id("mounted-add-service-subject"),
            credential_instance_id: id("mounted-add-service-credential"),
        })
    );
    assert_eq!(
        MountedCredentialAdditionServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedCredentialAdditionServiceOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedCredentialAdditionServiceOutcome::from_reducer_outcome(&Outcome::NeedsStepUp {
            session_id: id("mounted-add-step-up-session"),
            subject_id: id("mounted-add-step-up-subject"),
        }),
        Some(MountedCredentialAdditionServiceOutcome::NeedsStepUp {
            session_id: id("mounted-add-step-up-session"),
            subject_id: id("mounted-add-step-up-subject"),
        })
    );
    assert_eq!(
        MountedCredentialAdditionServiceOutcome::NeedsStepUp {
            session_id: id("mounted-add-step-up-session"),
            subject_id: id("mounted-add-step-up-subject"),
        }
        .committed_outcome(),
        None
    );
}

#[test]
fn mounted_credential_reset_inputs_convert_to_runtime_inputs_without_extra_authority() {
    assert_eq!(
        PlanMountedAuthenticatedCredentialResetInput {
            now: at(80),
            credential_handle: mounted_credential_handle("mounted-reset-target"),
        }
        .into_runtime_input(),
        PlanAuthenticatedCredentialResetInput {
            now: at(80),
            target_credential_instance_id: id("mounted-reset-target"),
        }
    );

    let method_payload =
        CredentialResetMethodPayload::try_from_bytes(b"mounted-reset-payload".as_slice())
            .expect("reset payload");
    assert_eq!(
        ExecuteMountedAuthenticatedCredentialResetInput {
            now: at(90),
            credential_handle: mounted_credential_handle("mounted-reset-target"),
            method_payload: method_payload.clone(),
        }
        .into_runtime_input(),
        ExecuteAuthenticatedCredentialResetInput {
            now: at(90),
            target_credential_instance_id: id("mounted-reset-target"),
            method_payload,
        }
    );
}

#[test]
fn mounted_credential_reset_planning_outcome_maps_only_planning_and_auth_control() {
    assert_eq!(
        MountedCredentialResetPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
            }),
        ),
        Some(
            MountedCredentialResetPlanningServiceOutcome::AuthorizedImmediate {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialResetPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
                pending_action_id: id("mounted-reset-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        ),
        Some(
            MountedCredentialResetPlanningServiceOutcome::PendingActionCreated {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
                pending_action_id: id("mounted-reset-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedCredentialResetPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedCredentialResetPlanningServiceOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedCredentialResetPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
                pending_action_id: None,
            }),
        ),
        None
    );
}

#[test]
fn mounted_credential_reset_execution_outcome_maps_only_immediate_execution_and_auth_control() {
    assert_eq!(
        MountedCredentialResetExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
                pending_action_id: None,
            }),
        ),
        Some(
            MountedCredentialResetExecutionServiceOutcome::CredentialReset {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialResetExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-reset-step-up-session"),
                subject_id: id("mounted-reset-step-up-subject"),
            },
        ),
        Some(MountedCredentialResetExecutionServiceOutcome::NeedsStepUp {
            session_id: id("mounted-reset-step-up-session"),
            subject_id: id("mounted-reset-step-up-subject"),
        })
    );
    assert_eq!(
        MountedCredentialResetExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-reset-subject"),
                target_credential_instance_id: id("mounted-reset-target"),
                pending_action_id: Some(id("mounted-reset-pending-action")),
            }),
        ),
        None,
        "pending reset execution belongs to the mounted delayed-action service"
    );
}

#[test]
fn mounted_unauthenticated_recovery_method_accepts_only_recovery_credentials() {
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let configured_recovery =
        MountedUnauthenticatedCredentialRecoveryMethod::new(recovery_method.clone())
            .expect("mounted recovery method");
    assert_eq!(configured_recovery.method(), &recovery_method);

    for family in [
        ProofFamily::OutOfBandCode,
        ProofFamily::MessageSignature,
        ProofFamily::SharedSecretOtp,
        ProofFamily::TrustedDevice,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
    ] {
        assert_eq!(
            MountedUnauthenticatedCredentialRecoveryMethod::new(proof_method(family)),
            Err(Error::ProofMethodCannotCompleteKnownSubjectActiveProof { family }),
            "no-session recovery must not accept non-recovery proof family {family:?}"
        );
    }
}

#[test]
fn mounted_unauthenticated_recovery_reset_target_method_constructs_configured_target_runtime_inputs()
 {
    let method = proof_method(ProofFamily::MessageSignature);
    let target = MountedUnauthenticatedCredentialRecoveryResetTargetMethod::new(method.clone())
        .expect("mounted recovery reset target method");
    assert_eq!(target.method(), &method);
    assert_eq!(
        target.schedule_runtime_input(ScheduleMountedNoSessionCredentialRecoveryResetInput {
            now: at(81)
        },),
        ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
            now: at(81),
            target_method: method.clone(),
        }
    );

    let method_payload =
        CredentialResetMethodPayload::try_from_bytes(b"configured-reset-payload".as_slice())
            .expect("reset payload");
    assert_eq!(
        target.execution_runtime_input(ExecuteMountedNoSessionCredentialRecoveryResetInput {
            now: at(82),
            method_payload: method_payload.clone(),
        },),
        ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
            now: at(82),
            target_method: method,
            method_payload,
        }
    );
}

#[test]
fn mounted_unauthenticated_recovery_reset_target_method_rejects_non_resettable_targets() {
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetTargetMethod::new(proof_method(
            ProofFamily::OutOfBandCode,
        )),
        Err(Error::InvalidConfig(
            "proof family is not an app-owned credential instance",
        )),
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetTargetMethod::new(proof_method(
            ProofFamily::TrustedDevice,
        )),
        Err(Error::InvalidConfig(
            "mounted unauthenticated recovery reset target must be a resettable app credential",
        )),
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetTargetMethod::new(proof_method(
            ProofFamily::RecoveryCode,
        )),
        Err(Error::InvalidConfig(
            "mounted unauthenticated recovery reset target must be a resettable app credential",
        )),
    );
}

#[test]
fn mounted_no_session_credential_recovery_flow_constructs_only_configured_runtime_inputs() {
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let target_method = proof_method(ProofFamily::MessageSignature);
    let flow =
        MountedNoSessionCredentialRecoveryFlow::new(recovery_method.clone(), target_method.clone())
            .expect("mounted no-session recovery flow");
    assert_eq!(flow.recovery_method(), &recovery_method);
    assert_eq!(flow.reset_target_method(), &target_method);
    assert_eq!(
        flow.start_runtime_input(StartMountedNoSessionCredentialRecoveryInput { now: at(70) }),
        StartUnauthenticatedRecoveryActiveProofAttemptInput {
            now: at(70),
            method: recovery_method.clone(),
        }
    );

    let recovery_response =
        KnownSubjectActiveProofSecretResponse::try_from_bytes(b"sealed-recovery-code".as_slice())
            .expect("recovery response");
    let completion_input =
        flow.completion_runtime_input(CompleteMountedNoSessionCredentialRecoveryProofInput {
            now: at(80),
            secret_response: recovery_response,
        });
    assert_eq!(completion_input.now, at(80));
    assert_eq!(completion_input.method, recovery_method);
    assert_eq!(
        completion_input.secret_response.expose_secret(),
        b"sealed-recovery-code"
    );
    assert_eq!(
        flow.schedule_reset_runtime_input(ScheduleMountedNoSessionCredentialRecoveryResetInput {
            now: at(90),
        }),
        ScheduleUnauthenticatedCredentialResetForConfiguredMethodInput {
            now: at(90),
            target_method: target_method.clone(),
        }
    );

    let method_payload =
        CredentialResetMethodPayload::try_from_bytes(b"mounted-recovery-reset-payload".as_slice())
            .expect("reset payload");
    assert_eq!(
        flow.execute_reset_runtime_input(ExecuteMountedNoSessionCredentialRecoveryResetInput {
            now: at(100),
            method_payload,
        }),
        ExecuteUnauthenticatedCredentialResetForConfiguredMethodInput {
            now: at(100),
            target_method,
            method_payload: CredentialResetMethodPayload::try_from_bytes(
                b"mounted-recovery-reset-payload".as_slice(),
            )
            .expect("reset payload"),
        }
    );
}

#[test]
fn mounted_no_session_credential_recovery_inputs_parse_bounded_secret_material() {
    let completion =
        CompleteMountedNoSessionCredentialRecoveryProofInput::try_from_secret_response_bytes(
            at(80),
            b"sealed-recovery-code".as_slice(),
        )
        .expect("mounted no-session recovery proof input");
    assert_eq!(completion.now, at(80));
    assert_eq!(
        completion.secret_response.expose_secret(),
        b"sealed-recovery-code"
    );

    let error =
        CompleteMountedNoSessionCredentialRecoveryProofInput::try_from_secret_response_bytes(
            at(80),
            Vec::new(),
        )
        .expect_err("empty recovery proof material must reject at mounted input boundary");
    assert_eq!(error, Error::EmptyKnownSubjectActiveProofSecretResponse);

    let error =
        CompleteMountedNoSessionCredentialRecoveryProofInput::try_from_secret_response_bytes(
            at(80),
            vec![0_u8; ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES + 1],
        )
        .expect_err("oversized recovery proof material must reject at mounted input boundary");
    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "known-subject active-proof secret response",
            max_bytes: ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
        }
    );

    let reset = ExecuteMountedNoSessionCredentialRecoveryResetInput::try_from_method_payload_bytes(
        at(90),
        b"reset-payload".as_slice(),
    )
    .expect("mounted no-session reset input");
    assert_eq!(reset.now, at(90));
    assert_eq!(reset.method_payload.as_bytes(), b"reset-payload");

    let error = ExecuteMountedNoSessionCredentialRecoveryResetInput::try_from_method_payload_bytes(
        at(90),
        Vec::new(),
    )
    .expect_err("empty reset payload must reject at mounted input boundary");
    assert_eq!(error, Error::EmptyCredentialResetMethodPayload);

    let error = ExecuteMountedNoSessionCredentialRecoveryResetInput::try_from_method_payload_bytes(
        at(90),
        vec![0_u8; METHOD_COMMIT_PAYLOAD_MAX_BYTES + 1],
    )
    .expect_err("oversized reset payload must reject at mounted input boundary");
    assert_eq!(
        error,
        Error::InputTooLong {
            input_name: "credential reset method payload",
            max_bytes: METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        }
    );
}

#[test]
fn mounted_no_session_credential_recovery_route_steps_pin_preflight_secret_and_csrf_policy() {
    assert!(
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
            .requires_challenge_issue_preflight()
    );
    assert!(
        !MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
            .requires_submitted_recovery_secret()
    );
    assert!(!MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt.requires_csrf());

    assert!(
        !MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
            .requires_challenge_issue_preflight()
    );
    assert!(
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
            .requires_submitted_recovery_secret()
    );
    assert!(!MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof.requires_csrf());

    assert!(
        !MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
            .requires_challenge_issue_preflight()
    );
    assert!(
        !MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
            .requires_submitted_recovery_secret()
    );
    assert!(MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset.requires_csrf());

    assert!(
        !MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
            .requires_challenge_issue_preflight()
    );
    assert!(
        !MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
            .requires_submitted_recovery_secret()
    );
    assert!(MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset.requires_csrf());
}

#[test]
fn mounted_no_session_credential_recovery_route_requests_carry_only_step_specific_material() {
    let start = MountedNoSessionCredentialRecoveryRouteRequest::start_recovery_attempt(
        at(70),
        challenge_issue_preflight_response_for_test(
            at(70),
            ProofUse::RecoverOrReplaceCredential,
            &proof_method(ProofFamily::RecoveryCode),
        ),
    );
    assert_eq!(
        start.step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );
    assert!(start.requires_challenge_issue_preflight());
    assert!(!start.requires_submitted_recovery_secret());
    assert!(!start.requires_csrf());

    let proof = MountedNoSessionCredentialRecoveryRouteRequest::submit_recovery_proof(
        at(80),
        b"sealed-recovery-code".as_slice(),
    )
    .expect("route recovery proof input");
    assert_eq!(
        proof.step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );
    assert!(!proof.requires_challenge_issue_preflight());
    assert!(proof.requires_submitted_recovery_secret());
    assert!(!proof.requires_csrf());

    let schedule = MountedNoSessionCredentialRecoveryRouteRequest::schedule_delayed_reset(at(90));
    assert_eq!(
        schedule.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );
    assert!(!schedule.requires_challenge_issue_preflight());
    assert!(!schedule.requires_submitted_recovery_secret());
    assert!(schedule.requires_csrf());

    let execute = MountedNoSessionCredentialRecoveryRouteRequest::execute_immediate_reset(
        at(100),
        b"new-password-verifier".as_slice(),
    )
    .expect("route reset payload");
    assert_eq!(
        execute.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
    assert!(!execute.requires_challenge_issue_preflight());
    assert!(!execute.requires_submitted_recovery_secret());
    assert!(execute.requires_csrf());
}

#[test]
fn mounted_no_session_credential_recovery_route_requests_parse_bounded_payloads() {
    let proof_error =
        MountedNoSessionCredentialRecoveryRouteRequest::submit_recovery_proof(at(80), Vec::new())
            .expect_err("empty recovery proof body must reject at route request boundary");
    assert_eq!(
        proof_error,
        Error::EmptyKnownSubjectActiveProofSecretResponse
    );

    let proof_error = MountedNoSessionCredentialRecoveryRouteRequest::submit_recovery_proof(
        at(80),
        vec![0_u8; ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES + 1],
    )
    .expect_err("oversized recovery proof body must reject at route request boundary");
    assert_eq!(
        proof_error,
        Error::InputTooLong {
            input_name: "known-subject active-proof secret response",
            max_bytes: ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
        }
    );

    let reset_error =
        MountedNoSessionCredentialRecoveryRouteRequest::execute_immediate_reset(at(90), Vec::new())
            .expect_err("empty reset body must reject at route request boundary");
    assert_eq!(reset_error, Error::EmptyCredentialResetMethodPayload);

    let reset_error = MountedNoSessionCredentialRecoveryRouteRequest::execute_immediate_reset(
        at(90),
        vec![0_u8; METHOD_COMMIT_PAYLOAD_MAX_BYTES + 1],
    )
    .expect_err("oversized reset body must reject at route request boundary");
    assert_eq!(
        reset_error,
        Error::InputTooLong {
            input_name: "credential reset method payload",
            max_bytes: METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        }
    );
}

#[test]
fn mounted_no_session_credential_recovery_step_specific_bodies_build_only_their_route_requests() {
    let start_request =
        MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
            WeakProofGateKind::ProofOfWork,
            "hashcash",
            b"preflight-response".as_slice(),
        )
        .expect("start route body")
        .into_route_request(at(70));
    assert_eq!(
        start_request.step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );
    assert!(start_request.requires_challenge_issue_preflight());
    assert!(!start_request.requires_submitted_recovery_secret());
    assert!(!start_request.requires_csrf());

    let proof_request =
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
            b"sealed-recovery-code".as_slice(),
        )
        .expect("proof route body")
        .into_route_request(at(80));
    assert_eq!(
        proof_request.step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );
    assert!(!proof_request.requires_challenge_issue_preflight());
    assert!(proof_request.requires_submitted_recovery_secret());
    assert!(!proof_request.requires_csrf());

    let schedule_request =
        MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody::from_empty_route_body_bytes(
            b"",
        )
        .expect("schedule route body")
        .into_route_request(at(90));
    assert_eq!(
        schedule_request.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );
    assert!(!schedule_request.requires_challenge_issue_preflight());
    assert!(!schedule_request.requires_submitted_recovery_secret());
    assert!(schedule_request.requires_csrf());

    let execute_request =
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
            b"new-password-verifier".as_slice(),
        )
        .expect("execute route body")
        .into_route_request(at(100));
    assert_eq!(
        execute_request.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
    assert!(!execute_request.requires_challenge_issue_preflight());
    assert!(!execute_request.requires_submitted_recovery_secret());
    assert!(execute_request.requires_csrf());
}

#[test]
fn mounted_no_session_credential_recovery_endpoint_paths_select_only_post_routes() {
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            &http::Method::POST,
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH,
        ),
        Some(MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt)
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            &http::Method::POST,
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH,
        ),
        Some(MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof)
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            &http::Method::POST,
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH,
        ),
        Some(MountedNoSessionCredentialRecoveryEndpoint::ScheduleDelayedReset)
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            &http::Method::POST,
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH,
        ),
        Some(MountedNoSessionCredentialRecoveryEndpoint::ExecuteImmediateReset)
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::StartRecoveryAttempt.path(),
        MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::SubmitRecoveryProof.step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            &http::Method::GET,
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH,
        ),
        None
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryEndpoint::from_method_and_path(
            &http::Method::POST,
            "/credential-recovery/unknown",
        ),
        None
    );
}

#[test]
fn mounted_no_session_credential_recovery_endpoint_bodies_keep_step_identity() {
    let start_body =
        MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
            WeakProofGateKind::ProofOfWork,
            "hashcash",
            b"preflight-response".as_slice(),
        )
        .expect("start route body");
    let endpoint_body = MountedNoSessionCredentialRecoveryEndpointRequestBody::from(start_body);
    assert_eq!(
        endpoint_body.step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );
    assert_eq!(
        endpoint_body.into_route_request(at(70)).step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );

    let proof_body =
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(
            b"sealed-recovery-code".as_slice(),
        )
        .expect("proof route body");
    let endpoint_body = MountedNoSessionCredentialRecoveryEndpointRequestBody::from(proof_body);
    assert_eq!(
        endpoint_body.step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );
    assert_eq!(
        endpoint_body.into_route_request(at(80)).step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );

    let schedule_body =
        MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody::from_empty_route_body_bytes(
            b"",
        )
        .expect("schedule route body");
    let endpoint_body = MountedNoSessionCredentialRecoveryEndpointRequestBody::from(schedule_body);
    assert_eq!(
        endpoint_body.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );
    assert_eq!(
        endpoint_body.into_route_request(at(90)).step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );

    let execute_body =
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(
            b"new-password-verifier".as_slice(),
        )
        .expect("execute route body");
    let endpoint_body = MountedNoSessionCredentialRecoveryEndpointRequestBody::from(execute_body);
    assert_eq!(
        endpoint_body.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
    assert_eq!(
        endpoint_body.into_route_request(at(100)).step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
}

#[test]
fn mounted_no_session_credential_recovery_submitted_bodies_validate_into_endpoint_bodies() {
    let submitted_start =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::start_recovery_attempt(
            WeakProofGateKind::ProofOfWork,
            "hashcash",
            b"preflight-response".as_slice(),
        );
    assert_eq!(
        submitted_start.step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );
    assert_eq!(
        submitted_start
            .into_endpoint_request_body()
            .expect("start submitted body converts")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::StartRecoveryAttempt
    );

    let submitted_proof =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::submit_recovery_proof(
            b"sealed-recovery-code".as_slice(),
        );
    assert_eq!(
        submitted_proof.step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );
    assert_eq!(
        submitted_proof
            .into_endpoint_request_body()
            .expect("proof submitted body converts")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::SubmitRecoveryProof
    );

    let submitted_schedule =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::schedule_delayed_reset(b"");
    assert_eq!(
        submitted_schedule.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );
    assert_eq!(
        submitted_schedule
            .into_endpoint_request_body()
            .expect("schedule submitted body converts")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::ScheduleDelayedReset
    );

    let submitted_execute =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::execute_immediate_reset(
            b"new-password-verifier".as_slice(),
        );
    assert_eq!(
        submitted_execute.step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
    assert_eq!(
        submitted_execute
            .into_endpoint_request_body()
            .expect("execute submitted body converts")
            .step(),
        MountedNoSessionCredentialRecoveryRouteStep::ExecuteImmediateReset
    );
}

#[test]
fn mounted_no_session_credential_recovery_submitted_bodies_reject_invalid_material() {
    let empty_preflight_error =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::start_recovery_attempt(
            WeakProofGateKind::ProofOfWork,
            "hashcash",
            Vec::new(),
        )
        .into_endpoint_request_body()
        .expect_err("empty preflight submitted body must reject");
    assert_eq!(
        empty_preflight_error,
        Error::EmptyWeakProofGateResponsePayload
    );

    let empty_proof_error =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::submit_recovery_proof(Vec::new())
            .into_endpoint_request_body()
            .expect_err("empty proof submitted body must reject");
    assert_eq!(
        empty_proof_error,
        Error::EmptyKnownSubjectActiveProofSecretResponse
    );

    let non_empty_schedule_error =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::schedule_delayed_reset(
            b"unexpected-body".as_slice(),
        )
        .into_endpoint_request_body()
        .expect_err("non-empty schedule submitted body must reject");
    assert_eq!(
        non_empty_schedule_error,
        Error::NonEmptyMountedNoSessionCredentialRecoveryScheduleResetRouteBody
    );

    let empty_reset_error =
        MountedNoSessionCredentialRecoverySubmittedRouteBody::execute_immediate_reset(Vec::new())
            .into_endpoint_request_body()
            .expect_err("empty reset submitted body must reject");
    assert_eq!(empty_reset_error, Error::EmptyCredentialResetMethodPayload);
}

#[test]
fn mounted_no_session_credential_recovery_route_body_rejects_invalid_raw_material() {
    let preflight_error =
        MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
            WeakProofGateKind::ProofOfWork,
            "hashcash",
            Vec::new(),
        )
        .expect_err("empty preflight body must reject at route body boundary");
    assert_eq!(preflight_error, Error::EmptyWeakProofGateResponsePayload);

    let preflight_error =
        MountedNoSessionCredentialRecoveryStartRouteRequestBody::from_submitted_preflight_response_parts(
            WeakProofGateKind::ProofOfWork,
            "hashcash",
            vec![0_u8; WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES + 1],
        )
        .expect_err("oversized preflight body must reject at route body boundary");
    assert_eq!(
        preflight_error,
        Error::InputTooLong {
            input_name: "weak-proof gate response payload",
            max_bytes: WEAK_PROOF_GATE_RESPONSE_PAYLOAD_MAX_BYTES,
        }
    );

    let proof_error =
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(Vec::new())
            .expect_err("empty recovery proof body must reject at route body boundary");
    assert_eq!(
        proof_error,
        Error::EmptyKnownSubjectActiveProofSecretResponse
    );

    let proof_error =
        MountedNoSessionCredentialRecoveryProofRouteRequestBody::from_submitted_recovery_secret_bytes(vec![
            0_u8;
            ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES
                + 1
        ])
        .expect_err("oversized recovery proof body must reject at route body boundary");
    assert_eq!(
        proof_error,
        Error::InputTooLong {
            input_name: "known-subject active-proof secret response",
            max_bytes: ACTIVE_PROOF_METHOD_RESPONSE_PAYLOAD_MAX_BYTES,
        }
    );

    let schedule_error =
        MountedNoSessionCredentialRecoveryScheduleResetRouteRequestBody::from_empty_route_body_bytes(
            b"unexpected-body",
        )
        .expect_err("non-empty schedule body must reject at route body boundary");
    assert_eq!(
        schedule_error,
        Error::NonEmptyMountedNoSessionCredentialRecoveryScheduleResetRouteBody
    );

    let reset_error =
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(Vec::new())
            .expect_err("empty reset body must reject at route body boundary");
    assert_eq!(reset_error, Error::EmptyCredentialResetMethodPayload);

    let reset_error =
        MountedNoSessionCredentialRecoveryExecuteResetRouteRequestBody::from_submitted_reset_payload_bytes(vec![
            0_u8;
            METHOD_COMMIT_PAYLOAD_MAX_BYTES
                + 1
        ])
        .expect_err("oversized reset body must reject at route body boundary");
    assert_eq!(
        reset_error,
        Error::InputTooLong {
            input_name: "credential reset method payload",
            max_bytes: METHOD_COMMIT_PAYLOAD_MAX_BYTES,
        }
    );
}

#[test]
fn mounted_no_session_credential_recovery_route_outcome_hides_lower_core_details() {
    assert_eq!(
        MountedNoSessionCredentialRecoveryRouteOutcome::from_start_service_outcome(
            &MountedUnauthenticatedCredentialRecoveryAttemptStartServiceOutcome::RecoveryAttemptStarted {
                attempt_id: id("mounted-route-start-attempt"),
                expires_at: at(110),
            },
        ),
        MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryAttemptStarted {
            expires_at: at(110),
        }
    );

    assert_eq!(
        MountedNoSessionCredentialRecoveryRouteOutcome::from_proof_completion_service_outcome(
            &MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome::RecoveryProofAccepted {
                attempt_id: id("mounted-route-accepted-attempt"),
                proof: ProofSummary::new(ProofFamily::RecoveryCode, "recovery_code")
                    .expect("proof summary"),
            },
        ),
        MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryProofAccepted
    );
    assert_eq!(
        MountedNoSessionCredentialRecoveryRouteOutcome::from_proof_completion_service_outcome(
            &MountedUnauthenticatedCredentialRecoveryProofCompletionServiceOutcome::RecoveryProofRejected {
                attempt_id: id("mounted-route-rejected-attempt"),
                attempt_was_deleted: true,
            },
        ),
        MountedNoSessionCredentialRecoveryRouteOutcome::RecoveryProofRejected
    );

    assert_eq!(
        MountedNoSessionCredentialRecoveryRouteOutcome::from_reset_scheduling_service_outcome(
            &MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::PendingCredentialResetActionCreated {
                subject_id: id("mounted-route-scheduled-subject"),
                target_credential_instance_id: id("mounted-route-scheduled-target"),
                pending_action_id: id("mounted-route-scheduled-pending"),
                earliest_execute_at: at(220),
                expires_at: at(330),
            },
        ),
        MountedNoSessionCredentialRecoveryRouteOutcome::DelayedResetScheduled {
            pending_action_id: id("mounted-route-scheduled-pending"),
            earliest_execute_at: at(220),
            expires_at: at(330),
        }
    );

    assert_eq!(
        MountedNoSessionCredentialRecoveryRouteOutcome::from_reset_execution_service_outcome(
            &MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::CredentialReset {
                subject_id: id("mounted-route-executed-subject"),
                target_credential_instance_id: id("mounted-route-executed-target"),
            },
        ),
        MountedNoSessionCredentialRecoveryRouteOutcome::ImmediateResetExecuted
    );
}

#[test]
fn mounted_no_session_credential_recovery_response_body_hides_internal_pending_action_id() {
    let outcome = MountedNoSessionCredentialRecoveryRouteOutcome::DelayedResetScheduled {
        pending_action_id: id("mounted-response-body-hidden-pending"),
        earliest_execute_at: at(220),
        expires_at: at(330),
    };

    assert_eq!(
        MountedNoSessionCredentialRecoveryRouteResponseBody::from_route_outcome(&outcome),
        MountedNoSessionCredentialRecoveryRouteResponseBody::DelayedResetScheduled {
            earliest_execute_at: at(220),
            expires_at: at(330),
        }
    );
}

#[test]
fn mounted_unauthenticated_credential_recovery_reset_scheduling_outcome_maps_only_delayed_reset_scheduling()
 {
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetPlanned(CredentialResetOutcome::PendingActionCreated {
                subject_id: id("mounted-recovery-subject"),
                target_credential_instance_id: id("mounted-recovery-target"),
                pending_action_id: id("mounted-recovery-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        ),
        Some(
            MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::PendingCredentialResetActionCreated {
                subject_id: id("mounted-recovery-subject"),
                target_credential_instance_id: id("mounted-recovery-target"),
                pending_action_id: id("mounted-recovery-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        None,
        "unauthenticated recovery requires a recovery proof continuation, not a session auth-control outcome"
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
                subject_id: id("mounted-recovery-subject"),
                target_credential_instance_id: id("mounted-recovery-target"),
            }),
        ),
        None,
        "immediate unauthenticated recovery reset requires the execution facade with method payload"
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetSchedulingServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-recovery-subject"),
                target_credential_instance_id: id("mounted-recovery-target"),
                pending_action_id: None,
            }),
        ),
        None
    );
}

#[test]
fn mounted_unauthenticated_credential_recovery_reset_execution_outcome_maps_only_immediate_reset_execution()
 {
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-recovery-reset-subject"),
                target_credential_instance_id: id("mounted-recovery-reset-target"),
                pending_action_id: None,
            }),
        ),
        Some(
            MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::CredentialReset {
                subject_id: id("mounted-recovery-reset-subject"),
                target_credential_instance_id: id("mounted-recovery-reset-target"),
            }
        )
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-recovery-reset-subject"),
                target_credential_instance_id: id("mounted-recovery-reset-target"),
                pending_action_id: Some(id("mounted-recovery-reset-pending-action")),
            }),
        ),
        None,
        "pending reset execution belongs to the mounted delayed-action service"
    );
    assert_eq!(
        MountedUnauthenticatedCredentialRecoveryResetExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialResetPlanned(CredentialResetOutcome::AuthorizedImmediate {
                subject_id: id("mounted-recovery-reset-subject"),
                target_credential_instance_id: id("mounted-recovery-reset-target"),
            }),
        ),
        None,
        "unauthenticated recovery reset execution must not report mere scheduling as execution"
    );
}

#[test]
fn mounted_credential_replacement_inputs_convert_to_runtime_inputs_without_extra_authority() {
    assert_eq!(
        PlanMountedAuthenticatedCredentialReplacementInput {
            now: at(80),
            credential_handle: mounted_credential_handle("mounted-replace-target"),
        }
        .into_runtime_input(),
        PlanAuthenticatedCredentialReplacementInput {
            now: at(80),
            target_credential_instance_id: id("mounted-replace-target"),
        }
    );

    let method_payload =
        CredentialLifecycleMethodPayload::try_from_bytes(b"mounted-replacement-payload".as_slice())
            .expect("replacement payload");
    assert_eq!(
        ExecuteMountedAuthenticatedCredentialReplacementInput {
            now: at(90),
            credential_handle: mounted_credential_handle("mounted-replace-target"),
            method_payload: method_payload.clone(),
        }
        .into_runtime_input(),
        ExecuteAuthenticatedCredentialReplacementInput {
            now: at(90),
            target_credential_instance_id: id("mounted-replace-target"),
            method_payload,
        }
    );
}

#[test]
fn mounted_credential_replacement_planning_outcome_maps_only_planning_and_auth_control() {
    assert_eq!(
        MountedCredentialReplacementPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialReplacementPlanned(
                CredentialReplacementOutcome::AuthorizedImmediate {
                    subject_id: id("mounted-replace-subject"),
                    target_credential_instance_id: id("mounted-replace-target"),
                },
            ),
        ),
        Some(
            MountedCredentialReplacementPlanningServiceOutcome::AuthorizedImmediate {
                subject_id: id("mounted-replace-subject"),
                target_credential_instance_id: id("mounted-replace-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialReplacementPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialReplacementPlanned(
                CredentialReplacementOutcome::PendingActionCreated {
                    subject_id: id("mounted-replace-subject"),
                    target_credential_instance_id: id("mounted-replace-target"),
                    pending_action_id: id("mounted-replace-pending-action"),
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                },
            ),
        ),
        Some(
            MountedCredentialReplacementPlanningServiceOutcome::PendingActionCreated {
                subject_id: id("mounted-replace-subject"),
                target_credential_instance_id: id("mounted-replace-target"),
                pending_action_id: id("mounted-replace-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedCredentialReplacementPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedCredentialReplacementPlanningServiceOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedCredentialReplacementPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
                subject_id: id("mounted-replace-subject"),
                target_credential_instance_id: id("mounted-replace-target"),
            }),
        ),
        None
    );
}

#[test]
fn mounted_credential_replacement_execution_outcome_maps_only_execution_and_auth_control() {
    assert_eq!(
        MountedCredentialReplacementExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
                subject_id: id("mounted-replace-subject"),
                target_credential_instance_id: id("mounted-replace-target"),
            }),
        ),
        Some(
            MountedCredentialReplacementExecutionServiceOutcome::CredentialReplaced {
                subject_id: id("mounted-replace-subject"),
                target_credential_instance_id: id("mounted-replace-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialReplacementExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-replace-step-up-session"),
                subject_id: id("mounted-replace-step-up-subject"),
            },
        ),
        Some(
            MountedCredentialReplacementExecutionServiceOutcome::NeedsStepUp {
                session_id: id("mounted-replace-step-up-session"),
                subject_id: id("mounted-replace-step-up-subject"),
            }
        )
    );
    assert_eq!(
        MountedCredentialReplacementExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialReplacementPlanned(
                CredentialReplacementOutcome::AuthorizedImmediate {
                    subject_id: id("mounted-replace-subject"),
                    target_credential_instance_id: id("mounted-replace-target"),
                },
            ),
        ),
        None
    );
}

#[test]
fn mounted_credential_removal_inputs_convert_to_runtime_inputs_without_extra_authority() {
    assert_eq!(
        PlanMountedAuthenticatedCredentialRemovalInput {
            now: at(80),
            credential_handle: mounted_credential_handle("mounted-remove-target"),
        }
        .into_runtime_input(),
        PlanAuthenticatedCredentialRemovalInput {
            now: at(80),
            target_credential_instance_id: id("mounted-remove-target"),
        }
    );

    assert_eq!(
        ExecuteMountedAuthenticatedCredentialRemovalInput {
            now: at(90),
            credential_handle: mounted_credential_handle("mounted-remove-target"),
        }
        .into_runtime_input(),
        ExecuteAuthenticatedCredentialRemovalInput {
            now: at(90),
            target_credential_instance_id: id("mounted-remove-target"),
        }
    );
}

#[test]
fn mounted_credential_rotation_input_converts_to_runtime_input_without_extra_authority() {
    let method_payload =
        CredentialLifecycleMethodPayload::try_from_bytes(b"mounted-rotation-payload".as_slice())
            .expect("rotation payload");
    assert_eq!(
        ExecuteMountedAuthenticatedCredentialRotationInput {
            now: at(90),
            credential_handle: mounted_credential_handle("mounted-rotate-target"),
            method_payload: method_payload.clone(),
        }
        .into_runtime_input(),
        ExecuteAuthenticatedCredentialRotationInput {
            now: at(90),
            target_credential_instance_id: id("mounted-rotate-target"),
            method_payload,
        }
    );
}

#[test]
fn mounted_credential_regeneration_input_converts_to_runtime_input_without_extra_authority() {
    assert_eq!(
        PlanMountedAuthenticatedCredentialRegenerationInput {
            now: at(80),
            credential_handle: mounted_credential_handle("mounted-regenerate-target"),
        }
        .into_runtime_input(),
        PlanAuthenticatedCredentialRegenerationInput {
            now: at(80),
            target_credential_instance_id: id("mounted-regenerate-target"),
        }
    );
}

#[test]
fn mounted_credential_regeneration_execution_input_converts_to_runtime_input_without_extra_authority()
 {
    let method_payload = CredentialLifecycleMethodPayload::try_from_bytes(
        b"mounted-regeneration-payload".as_slice(),
    )
    .expect("regeneration payload");
    assert_eq!(
        ExecuteMountedAuthenticatedCredentialRegenerationInput {
            now: at(90),
            credential_handle: mounted_credential_handle("mounted-regenerate-target"),
            method_payload: method_payload.clone(),
        }
        .into_runtime_input(),
        ExecuteAuthenticatedCredentialRegenerationInput {
            now: at(90),
            target_credential_instance_id: id("mounted-regenerate-target"),
            method_payload,
        }
    );
}

#[test]
fn mounted_credential_removal_planning_outcome_maps_only_planning_and_auth_control() {
    assert_eq!(
        MountedCredentialRemovalPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::AuthorizedImmediate {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
            }),
        ),
        Some(
            MountedCredentialRemovalPlanningServiceOutcome::AuthorizedImmediate {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRemovalPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::PendingActionCreated {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
                pending_action_id: id("mounted-remove-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }),
        ),
        Some(
            MountedCredentialRemovalPlanningServiceOutcome::PendingActionCreated {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
                pending_action_id: id("mounted-remove-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedCredentialRemovalPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedCredentialRemovalPlanningServiceOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedCredentialRemovalPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRemovalExecuted(CredentialRemovalExecutionOutcome {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
            }),
        ),
        None
    );
}

#[test]
fn mounted_credential_regeneration_planning_outcome_maps_only_planning_and_auth_control() {
    assert_eq!(
        MountedCredentialRegenerationPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRegenerationPlanned(
                CredentialRegenerationOutcome::AuthorizedImmediate {
                    subject_id: id("mounted-regenerate-subject"),
                    target_credential_instance_id: id("mounted-regenerate-target"),
                },
            ),
        ),
        Some(
            MountedCredentialRegenerationPlanningServiceOutcome::AuthorizedImmediate {
                subject_id: id("mounted-regenerate-subject"),
                target_credential_instance_id: id("mounted-regenerate-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRegenerationPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRegenerationPlanned(
                CredentialRegenerationOutcome::PendingActionCreated {
                    subject_id: id("mounted-regenerate-subject"),
                    target_credential_instance_id: id("mounted-regenerate-target"),
                    pending_action_id: id("mounted-regenerate-pending-action"),
                    earliest_execute_at: at(200),
                    expires_at: at(300),
                },
            ),
        ),
        Some(
            MountedCredentialRegenerationPlanningServiceOutcome::PendingActionCreated {
                subject_id: id("mounted-regenerate-subject"),
                target_credential_instance_id: id("mounted-regenerate-target"),
                pending_action_id: id("mounted-regenerate-pending-action"),
                earliest_execute_at: at(200),
                expires_at: at(300),
            }
        )
    );
    assert_eq!(
        MountedCredentialRegenerationPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        Some(MountedCredentialRegenerationPlanningServiceOutcome::NeedsFullAuthentication)
    );
    assert_eq!(
        MountedCredentialRegenerationPlanningServiceOutcome::from_reducer_outcome(
            &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
                NonResetPendingCredentialLifecycleActionExecutionOutcome {
                    subject_id: id("mounted-regenerate-subject"),
                    target_credential_instance_id: id("mounted-regenerate-target"),
                    action: CredentialLifecycleAction::Regenerate,
                    pending_action_id: id("mounted-regenerate-pending-action"),
                },
            ),
        ),
        None
    );
}

#[test]
fn mounted_credential_removal_execution_outcome_maps_only_execution_and_auth_control() {
    assert_eq!(
        MountedCredentialRemovalExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRemovalExecuted(CredentialRemovalExecutionOutcome {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
            }),
        ),
        Some(
            MountedCredentialRemovalExecutionServiceOutcome::CredentialRemoved {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRemovalExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-remove-step-up-session"),
                subject_id: id("mounted-remove-step-up-subject"),
            },
        ),
        Some(
            MountedCredentialRemovalExecutionServiceOutcome::NeedsStepUp {
                session_id: id("mounted-remove-step-up-session"),
                subject_id: id("mounted-remove-step-up-subject"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRemovalExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRemovalPlanned(CredentialRemovalOutcome::AuthorizedImmediate {
                subject_id: id("mounted-remove-subject"),
                target_credential_instance_id: id("mounted-remove-target"),
            }),
        ),
        None
    );
}

#[test]
fn mounted_credential_rotation_execution_outcome_maps_only_execution_and_auth_control() {
    assert_eq!(
        MountedCredentialRotationExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRotated(CredentialRotationExecutionOutcome {
                subject_id: id("mounted-rotate-subject"),
                target_credential_instance_id: id("mounted-rotate-target"),
            }),
        ),
        Some(
            MountedCredentialRotationExecutionServiceOutcome::CredentialRotated {
                subject_id: id("mounted-rotate-subject"),
                target_credential_instance_id: id("mounted-rotate-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRotationExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-rotate-step-up-session"),
                subject_id: id("mounted-rotate-step-up-subject"),
            },
        ),
        Some(
            MountedCredentialRotationExecutionServiceOutcome::NeedsStepUp {
                session_id: id("mounted-rotate-step-up-session"),
                subject_id: id("mounted-rotate-step-up-subject"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRotationExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialReplacementExecuted(CredentialReplacementExecutionOutcome {
                subject_id: id("mounted-rotate-subject"),
                target_credential_instance_id: id("mounted-rotate-target"),
            }),
        ),
        None
    );
}

#[test]
fn mounted_credential_regeneration_execution_outcome_maps_only_execution_and_auth_control() {
    assert_eq!(
        MountedCredentialRegenerationExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRegenerated(CredentialRegenerationExecutionOutcome {
                subject_id: id("mounted-regenerate-subject"),
                target_credential_instance_id: id("mounted-regenerate-target"),
            }),
        ),
        Some(
            MountedCredentialRegenerationExecutionServiceOutcome::CredentialRegenerated {
                subject_id: id("mounted-regenerate-subject"),
                target_credential_instance_id: id("mounted-regenerate-target"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRegenerationExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::NeedsStepUp {
                session_id: id("mounted-regenerate-step-up-session"),
                subject_id: id("mounted-regenerate-step-up-subject"),
            },
        ),
        Some(
            MountedCredentialRegenerationExecutionServiceOutcome::NeedsStepUp {
                session_id: id("mounted-regenerate-step-up-session"),
                subject_id: id("mounted-regenerate-step-up-subject"),
            }
        )
    );
    assert_eq!(
        MountedCredentialRegenerationExecutionServiceOutcome::from_reducer_outcome(
            &Outcome::CredentialRegenerationPlanned(
                CredentialRegenerationOutcome::AuthorizedImmediate {
                    subject_id: id("mounted-regenerate-subject"),
                    target_credential_instance_id: id("mounted-regenerate-target"),
                },
            ),
        ),
        None
    );
}

#[test]
fn mounted_delayed_credential_lifecycle_snapshot_accepts_only_executable_actions() {
    let reset_pending_action = pending_action(
        "mounted-delayed-reset",
        "mounted-delayed-subject",
        "mounted-delayed-target",
        CredentialLifecycleAction::Reset,
        at(100),
        at(200),
        at(300),
    );

    let snapshot = MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
        &reset_pending_action,
        at(250),
    )
    .expect("mature reset pending action should be mounted-executable");

    assert_eq!(snapshot.pending_action_id(), &id("mounted-delayed-reset"));
    assert_eq!(snapshot.subject_id(), &id("mounted-delayed-subject"));
    assert_eq!(
        snapshot.target_credential_instance_id(),
        &id("mounted-delayed-target")
    );
    assert_eq!(snapshot.action(), CredentialLifecycleAction::Reset);
    assert_eq!(snapshot.requested_at(), at(100));
    assert_eq!(snapshot.earliest_execute_at(), at(200));
    assert_eq!(snapshot.expires_at(), at(300));

    assert_eq!(
        MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
            &reset_pending_action,
            at(199),
        ),
        Err(Error::PendingCredentialLifecycleActionNotExecutable)
    );
    assert_eq!(
        MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
            &reset_pending_action,
            at(300),
        ),
        Err(Error::PendingCredentialLifecycleActionNotExecutable)
    );

    let unsupported_action = pending_action(
        "mounted-delayed-create",
        "mounted-delayed-create-subject",
        "mounted-delayed-create-target",
        CredentialLifecycleAction::Create,
        at(100),
        at(200),
        at(300),
    );
    assert_eq!(
        MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
            &unsupported_action,
            at(250),
        ),
        Err(Error::CredentialLifecycleActionNotAuthorized)
    );

    let rotation_action = pending_action(
        "mounted-delayed-rotate",
        "mounted-delayed-rotate-subject",
        "mounted-delayed-rotate-target",
        CredentialLifecycleAction::Rotate,
        at(100),
        at(200),
        at(300),
    );
    assert_eq!(
        MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
            &rotation_action,
            at(250),
        ),
        Err(Error::CredentialLifecycleActionNotAuthorized)
    );
}

#[test]
fn mounted_delayed_credential_lifecycle_dispatches_reset_and_non_reset_runtime_inputs() {
    let reset_snapshot = executable_action(CredentialLifecycleAction::Reset);
    let reset_payload = CredentialResetMethodPayload::try_from_bytes(b"reset-payload".as_slice())
        .expect("reset payload");
    assert_eq!(
        reset_snapshot
            .runtime_execution_input(ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::Reset(
                    reset_payload.clone(),
                ),
            })
            .expect("reset should dispatch to reset runtime input"),
        MountedDelayedCredentialLifecycleRuntimeInput::Reset(
            ExecuteMaturePendingCredentialResetInput {
                now: at(250),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: reset_payload,
            }
        )
    );

    let replace_snapshot = executable_action(CredentialLifecycleAction::Replace);
    let lifecycle_payload =
        CredentialLifecycleMethodPayload::try_from_bytes(b"replacement-payload".as_slice())
            .expect("lifecycle payload");
    assert_eq!(
        replace_snapshot
            .runtime_execution_input(ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(251),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(
                    lifecycle_payload.clone(),
                ),
            })
            .expect("replacement should dispatch to non-reset runtime input"),
        MountedDelayedCredentialLifecycleRuntimeInput::NonResetCredentialLifecycle(
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(251),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: Some(lifecycle_payload),
            }
        )
    );

    let remove_snapshot = executable_action(CredentialLifecycleAction::Remove);
    assert_eq!(
        remove_snapshot
            .runtime_execution_input(ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(252),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            })
            .expect("removal should dispatch to core-owned non-reset runtime input"),
        MountedDelayedCredentialLifecycleRuntimeInput::NonResetCredentialLifecycle(
            ExecuteMaturePendingCredentialLifecycleActionInput {
                now: at(252),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: None,
            }
        )
    );
}

#[test]
fn mounted_delayed_credential_lifecycle_rejects_wrong_payload_shapes() {
    let reset_snapshot = executable_action(CredentialLifecycleAction::Reset);
    assert_eq!(
        reset_snapshot.runtime_execution_input(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
            },
        ),
        Err(Error::CredentialLifecycleExecutionMissingMethodCommitWork)
    );
    assert_eq!(
        reset_snapshot.runtime_execution_input(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"wrong-lifecycle-payload".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        ),
        Err(Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch)
    );

    let replace_snapshot = executable_action(CredentialLifecycleAction::Replace);
    assert_eq!(
        replace_snapshot.runtime_execution_input(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: id("mounted-delayed-action"),
                method_payload:
                    MountedDelayedCredentialLifecycleMethodPayload::Reset(
                        CredentialResetMethodPayload::try_from_bytes(
                            b"wrong-reset-payload".as_slice(),
                        )
                        .expect("reset payload"),
                    ),
            },
        ),
        Err(Error::CredentialLifecycleExecutionMethodCommitWorkTargetMismatch)
    );

    let remove_snapshot = executable_action(CredentialLifecycleAction::Remove);
    assert_eq!(
        remove_snapshot.runtime_execution_input(
            ExecuteMountedDelayedCredentialLifecycleActionInput {
                now: at(250),
                pending_action_id: id("mounted-delayed-action"),
                method_payload: MountedDelayedCredentialLifecycleMethodPayload::ReplaceOrRegenerate(
                    CredentialLifecycleMethodPayload::try_from_bytes(
                        b"unexpected-lifecycle-payload".as_slice(),
                    )
                    .expect("lifecycle payload"),
                ),
            },
        ),
        Err(Error::CredentialLifecycleExecutionUnexpectedMethodCommitWork)
    );
}

#[test]
fn mounted_delayed_credential_lifecycle_rejects_request_snapshot_mismatch() {
    let snapshot = executable_action(CredentialLifecycleAction::Remove);

    assert_eq!(
        snapshot.runtime_execution_input(ExecuteMountedDelayedCredentialLifecycleActionInput {
            now: at(250),
            pending_action_id: id("different-mounted-delayed-action"),
            method_payload: MountedDelayedCredentialLifecycleMethodPayload::NoMethodPayload,
        }),
        Err(Error::LoadedStateContradiction(
            "mounted delayed credential lifecycle request and loaded action ids differ",
        ))
    );
}

#[test]
fn mounted_delayed_credential_lifecycle_committed_outcome_maps_only_delayed_execution() {
    assert_eq!(
        MountedDelayedCredentialLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-delayed-reset-subject"),
                target_credential_instance_id: id("mounted-delayed-reset-target"),
                pending_action_id: Some(id("mounted-delayed-reset-action")),
            }),
        ),
        Some(
            MountedDelayedCredentialLifecycleCommittedOutcome::CredentialResetExecuted {
                subject_id: id("mounted-delayed-reset-subject"),
                target_credential_instance_id: id("mounted-delayed-reset-target"),
                pending_action_id: id("mounted-delayed-reset-action"),
            }
        )
    );
    assert_eq!(
        MountedDelayedCredentialLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::CredentialResetExecuted(CredentialResetExecutionOutcome {
                subject_id: id("mounted-immediate-reset-subject"),
                target_credential_instance_id: id("mounted-immediate-reset-target"),
                pending_action_id: None,
            }),
        ),
        None,
        "immediate reset is not a mounted delayed-action execution outcome"
    );
    assert_eq!(
        MountedDelayedCredentialLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::NonResetPendingCredentialLifecycleActionExecuted(
                NonResetPendingCredentialLifecycleActionExecutionOutcome {
                    subject_id: id("mounted-delayed-remove-subject"),
                    target_credential_instance_id: id("mounted-delayed-remove-target"),
                    action: CredentialLifecycleAction::Remove,
                    pending_action_id: id("mounted-delayed-remove-action"),
                }
            ),
        ),
        Some(
            MountedDelayedCredentialLifecycleCommittedOutcome::NonResetCredentialLifecycleActionExecuted {
                subject_id: id("mounted-delayed-remove-subject"),
                target_credential_instance_id: id("mounted-delayed-remove-target"),
                action: CredentialLifecycleAction::Remove,
                pending_action_id: id("mounted-delayed-remove-action"),
            }
        )
    );
    assert_eq!(
        MountedDelayedCredentialLifecycleCommittedOutcome::from_committed_reducer_outcome(
            &Outcome::NeedsFullAuthentication,
        ),
        None
    );
}

fn executable_action(
    action: CredentialLifecycleAction,
) -> MountedExecutableDelayedCredentialLifecycleAction {
    MountedExecutableDelayedCredentialLifecycleAction::from_pending_action(
        &pending_action(
            "mounted-delayed-action",
            "mounted-delayed-subject",
            "mounted-delayed-target",
            action,
            at(100),
            at(200),
            at(300),
        ),
        at(250),
    )
    .expect("pending action should be mounted-executable")
}

fn pending_action(
    pending_action_id: &'static str,
    subject_id: &'static str,
    target_credential_instance_id: &'static str,
    action: CredentialLifecycleAction,
    requested_at: UnixSeconds,
    earliest_execute_at: UnixSeconds,
    expires_at: UnixSeconds,
) -> PendingCredentialLifecycleActionRecord {
    PendingCredentialLifecycleActionRecord::new_open(
        id(pending_action_id),
        id(subject_id),
        id(target_credential_instance_id),
        action,
        requested_at,
        earliest_execute_at,
        expires_at,
    )
    .expect("valid pending credential lifecycle action")
}
