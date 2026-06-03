use super::super::proof_policy;
use super::*;

#[test]
fn proof_families_express_core_security_semantics() {
    assert_eq!(
        ProofFamily::OutOfBandCode.semantics(),
        ProofSemantics {
            subject_role: ProofSubjectRole::CanBindSubjectFromIdentifier,
            interaction: ProofInteraction::Active,
            mechanism: ProofMechanism::OutOfBandDeliveryCode,
        }
    );
    assert_eq!(
        ProofFamily::TrustedDevice.semantics(),
        ProofSemantics {
            subject_role: ProofSubjectRole::BoundToTrustedDeviceCredential,
            interaction: ProofInteraction::Passive,
            mechanism: ProofMechanism::RotatingBearerCredential,
        }
    );
    assert!(ProofFamily::OutOfBandCode.supports_use(ProofUse::BindSubjectToActiveProofAttempt));
    assert!(ProofFamily::MessageSignature.supports_use(ProofUse::BindSubjectToActiveProofAttempt));
    assert!(
        ProofFamily::OriginBoundPublicKey.supports_use(ProofUse::BindSubjectToActiveProofAttempt)
    );
    assert!(
        ProofFamily::FederatedIdentityAssertion
            .supports_use(ProofUse::BindSubjectToActiveProofAttempt)
    );
    assert!(!ProofFamily::SharedSecretOtp.supports_use(ProofUse::BindSubjectToActiveProofAttempt));
    assert!(ProofFamily::TrustedDevice.supports_use(ProofUse::SilentlyReviveTrustedDeviceSession));
    assert!(!ProofFamily::TrustedDevice.supports_use(ProofUse::SatisfyStepUp));
    assert!(ProofFamily::RecoveryCode.supports_use(ProofUse::RecoverOrReplaceCredential));
    assert_eq!(
        ProofFamily::SharedSecretOtp.default_online_guessing_risk(),
        OnlineGuessingRisk::OnlineGuessable
    );
    assert_eq!(
        ProofFamily::MessageSignature.default_online_guessing_risk(),
        OnlineGuessingRisk::NotOnlineGuessable
    );
    assert_eq!(
        ProofFamily::OriginBoundPublicKey.default_online_guessing_risk(),
        OnlineGuessingRisk::NotOnlineGuessable
    );
    assert_eq!(
        ProofFamily::FederatedIdentityAssertion.default_online_guessing_risk(),
        OnlineGuessingRisk::NotOnlineGuessable
    );
    assert!(proof(ProofFamily::MessageSignature).uses_weak_attempt_failure_budget());
    assert!(
        !ProofSummary::new(ProofFamily::MessageSignature, "ssh_signature")
            .expect("proof")
            .uses_weak_attempt_failure_budget()
    );
}

#[test]
fn method_declarations_validate_method_specific_risk_without_overriding_family_semantics() {
    let password_signature =
        ProofMethodDeclaration::new_online_guessable(ProofFamily::MessageSignature, "password_v1")
            .expect("method declaration");
    assert_eq!(password_signature.family(), ProofFamily::MessageSignature);
    assert_eq!(
        password_signature.online_guessing_risk(),
        OnlineGuessingRisk::OnlineGuessable
    );
    assert_eq!(
        password_signature.verified_proof_summary(),
        ProofSummary::new_online_guessable(ProofFamily::MessageSignature, "password_v1")
            .expect("proof")
    );

    let ssh_signature = ProofMethodDeclaration::new(ProofFamily::MessageSignature, "ssh_signature")
        .expect("method declaration");
    assert_eq!(
        ssh_signature.online_guessing_risk(),
        OnlineGuessingRisk::NotOnlineGuessable
    );

    assert_eq!(
        ProofMethodDeclaration::new_with_online_guessing_risk(
            ProofFamily::SharedSecretOtp,
            "totp",
            OnlineGuessingRisk::NotOnlineGuessable,
        ),
        Err(Error::InvalidConfig(
            "proof method cannot weaken family online-guessing risk",
        ))
    );
}

#[test]
fn method_declarations_expose_core_derived_semantics_without_plugin_override() {
    let webauthn =
        ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
            .expect("method declaration");
    assert_eq!(
        webauthn.semantics(),
        ProofFamily::OriginBoundPublicKey.semantics()
    );
    assert!(webauthn.supports_use(ProofUse::ContributeToFullAuthentication));
    assert!(webauthn.supports_use(ProofUse::SatisfyStepUp));
    assert!(!webauthn.supports_use(ProofUse::SilentlyReviveTrustedDeviceSession));
    assert!(!webauthn.requires_method_commit_work_on_success());
    assert!(!webauthn.uses_weak_attempt_failure_budget());

    let password_signature =
        ProofMethodDeclaration::new_online_guessable(ProofFamily::MessageSignature, "password_v1")
            .expect("method declaration");
    assert_eq!(
        password_signature.semantics(),
        ProofFamily::MessageSignature.semantics()
    );
    assert!(password_signature.supports_use(ProofUse::BindSubjectToActiveProofAttempt));
    assert!(password_signature.uses_weak_attempt_failure_budget());
    assert_eq!(
        password_signature.verified_proof_summary().family(),
        ProofFamily::MessageSignature
    );

    let totp = ProofMethodDeclaration::new(ProofFamily::SharedSecretOtp, "totp")
        .expect("method declaration");
    assert_eq!(
        VerifiedActiveProof::from_summary(totp.verified_proof_summary(), Some(id("subject"))),
        Err(Error::ProofFamilyCannotCarryVerifiedSubject {
            family: ProofFamily::SharedSecretOtp,
        })
    );
}

#[test]
fn satisfied_proof_stack_policy_distinguishes_full_authentication_from_contextual_proof() {
    let proof_policy = default_proof_policy();
    let totp = satisfied_proof(proof(ProofFamily::SharedSecretOtp));

    assert_eq!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            std::slice::from_ref(&totp),
            ProofUse::ContributeToFullAuthentication,
        ),
        Err(Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::ContributeToFullAuthentication,
        })
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            std::slice::from_ref(&totp),
            ProofUse::SatisfyStepUp
        )
        .is_ok()
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[totp],
            ProofUse::ReviveTrustedDeviceWithActiveProof,
        )
        .is_ok()
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::MessageSignature))],
            ProofUse::ContributeToFullAuthentication,
        )
        .is_ok()
    );
}

#[test]
fn safe_default_proof_policy_requires_configured_exact_method_labels() {
    let proof_policy = default_proof_policy();
    let sms_otp =
        satisfied_proof(ProofSummary::new(ProofFamily::OutOfBandCode, "sms_otp").expect("proof"));

    assert_eq!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            std::slice::from_ref(&sms_otp),
            ProofUse::ContributeToFullAuthentication,
        ),
        Err(Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::ContributeToFullAuthentication,
        })
    );

    let family_based_policy = ProofPolicy::defaults_accepting_any_method_label_in_each_family();
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &family_based_policy,
            &[sms_otp],
            ProofUse::ContributeToFullAuthentication,
        )
        .is_ok()
    );

    assert_eq!(
        ProofPolicyExactMethodLabels::new("", "password_signature", "totp", "recovery_code"),
        Err(Error::EmptyProofRequirementMethodLabel)
    );
}

#[test]
fn proof_policy_can_require_exact_method_labels_inside_a_family() {
    let mut config = config();
    config.proof_policy.full_authentication = ProofStackPolicy {
        accepted_stacks: vec![
            ProofStackRequirement::one_exact_method(ProofFamily::OutOfBandCode, "email_otp")
                .expect("proof requirement"),
        ],
    };

    let sms_error = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![ProofSummary::new(ProofFamily::OutOfBandCode, "sms_otp").expect("proof")],
        ),
    )
    .expect_err("wrong out-of-band method must not satisfy exact method policy");

    assert_eq!(
        sms_error,
        Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::ContributeToFullAuthentication,
        }
    );

    let transition = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![ProofSummary::new(ProofFamily::OutOfBandCode, "email_otp").expect("proof")],
        ),
    )
    .expect("exact out-of-band method should satisfy policy");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::FullAuthentication,
            ..
        })
    ));
}

#[test]
fn proof_policy_rejects_unsafe_full_authentication_config() {
    let mut config = config();
    config.proof_policy.full_authentication = ProofStackPolicy {
        accepted_stacks: vec![ProofStackRequirement::one_any_method_label_in_family(
            ProofFamily::SharedSecretOtp,
        )],
    };

    assert_eq!(
        config.validate(),
        Err(Error::InvalidConfig(
            "proof policy stack does not meet the required safety floor",
        ))
    );
}

#[test]
fn proof_policy_rejects_malformed_custom_stack_configurations() {
    let cases = [
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.full_authentication = ProofStackPolicy {
                accepted_stacks: Vec::new(),
            };
            (
                "full authentication accepted_stacks cannot be empty",
                proof_policy,
                Error::InvalidConfig("proof policy accepted_stacks must not be empty"),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.step_up = ProofStackPolicy {
                accepted_stacks: Vec::new(),
            };
            (
                "step-up accepted_stacks cannot be empty",
                proof_policy,
                Error::InvalidConfig("proof policy accepted_stacks must not be empty"),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.trusted_device_active_revival = ProofStackPolicy {
                accepted_stacks: Vec::new(),
            };
            (
                "trusted-device active revival accepted_stacks cannot be empty",
                proof_policy,
                Error::InvalidConfig("proof policy accepted_stacks must not be empty"),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.full_authentication = ProofStackPolicy {
                accepted_stacks: vec![ProofStackRequirement {
                    required_proofs: Vec::new(),
                    source_policy: ProofStackSourcePolicy::NoSourceConstraint,
                }],
            };
            (
                "required_proofs cannot be empty",
                proof_policy,
                Error::InvalidConfig("proof policy required_proofs must not be empty"),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.full_authentication = ProofStackPolicy {
                accepted_stacks: vec![ProofStackRequirement {
                    required_proofs: vec![
                        ProofRequirement::any_method_label_in_family(ProofFamily::MessageSignature),
                        ProofRequirement::exact_method(
                            ProofFamily::MessageSignature,
                            "password_v1",
                        )
                        .expect("proof requirement"),
                    ],
                    source_policy: ProofStackSourcePolicy::NoSourceConstraint,
                }],
            };
            (
                "required_proofs cannot contain duplicate families",
                proof_policy,
                Error::InvalidConfig(
                    "proof policy required_proofs must not contain duplicate families",
                ),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.full_authentication = ProofStackPolicy {
                accepted_stacks: vec![ProofStackRequirement::one_any_method_label_in_family(
                    ProofFamily::TrustedDevice,
                )],
            };
            (
                "trusted device cannot be configured as a full-authentication proof",
                proof_policy,
                Error::InvalidConfig("proof policy family cannot satisfy configured use"),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.step_up = ProofStackPolicy {
                accepted_stacks: vec![ProofStackRequirement::one_any_method_label_in_family(
                    ProofFamily::TrustedDevice,
                )],
            };
            (
                "trusted device cannot be configured as a step-up proof",
                proof_policy,
                Error::InvalidConfig("proof policy family cannot satisfy configured use"),
            )
        },
        {
            let mut proof_policy = default_proof_policy();
            proof_policy.trusted_device_active_revival = ProofStackPolicy {
                accepted_stacks: vec![ProofStackRequirement::one_any_method_label_in_family(
                    ProofFamily::TrustedDevice,
                )],
            };
            (
                "trusted device cannot be configured as its own active revival proof",
                proof_policy,
                Error::InvalidConfig("proof policy family cannot satisfy configured use"),
            )
        },
    ];

    for (label, proof_policy, expected_error) in cases {
        let mut config = config();
        config.proof_policy = proof_policy;
        assert_eq!(config.validate(), Err(expected_error), "{label}");
    }
}

#[test]
fn fixed_proof_uses_require_their_core_owned_proof_families() {
    let proof_policy = default_proof_policy();

    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::OutOfBandCode))],
            ProofUse::BindSubjectToActiveProofAttempt,
        )
        .is_ok()
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::MessageSignature))],
            ProofUse::BindSubjectToActiveProofAttempt,
        )
        .is_ok()
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::OriginBoundPublicKey))],
            ProofUse::BindSubjectToActiveProofAttempt,
        )
        .is_ok()
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(
                ProofFamily::FederatedIdentityAssertion,
            ))],
            ProofUse::BindSubjectToActiveProofAttempt,
        )
        .is_ok()
    );
    assert_eq!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::SharedSecretOtp))],
            ProofUse::BindSubjectToActiveProofAttempt,
        ),
        Err(Error::ProofFamilyCannotSatisfyUse {
            family: ProofFamily::SharedSecretOtp,
            proof_use: ProofUse::BindSubjectToActiveProofAttempt,
        })
    );
    assert_eq!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[],
            ProofUse::SatisfyStepUp,
        ),
        Err(Error::MissingSatisfiedProof)
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::TrustedDevice))],
            ProofUse::SilentlyReviveTrustedDeviceSession,
        )
        .is_ok()
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::TrustedDevice))],
            ProofUse::ReduceAuthenticationRequirement,
        )
        .is_ok()
    );
    assert_eq!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::OutOfBandCode))],
            ProofUse::SilentlyReviveTrustedDeviceSession,
        ),
        Err(Error::ProofFamilyCannotSatisfyUse {
            family: ProofFamily::OutOfBandCode,
            proof_use: ProofUse::SilentlyReviveTrustedDeviceSession,
        })
    );
    assert!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::RecoveryCode))],
            ProofUse::RecoverOrReplaceCredential,
        )
        .is_ok()
    );
    assert_eq!(
        proof_policy::validate_satisfied_proof_stack_for_use(
            &proof_policy,
            &[satisfied_proof(proof(ProofFamily::MessageSignature))],
            ProofUse::RecoverOrReplaceCredential,
        ),
        Err(Error::ProofFamilyCannotSatisfyUse {
            family: ProofFamily::MessageSignature,
            proof_use: ProofUse::RecoverOrReplaceCredential,
        })
    );
}

#[test]
fn policy_can_accept_webauthn_or_oidc_as_full_authentication_anchors() {
    let mut config = config();
    config.proof_policy.full_authentication = ProofStackPolicy {
        accepted_stacks: vec![
            ProofStackRequirement::one_exact_method(
                ProofFamily::OriginBoundPublicKey,
                "webauthn_passkey",
            )
            .expect("proof requirement"),
            ProofStackRequirement::one_exact_method(
                ProofFamily::FederatedIdentityAssertion,
                "oidc_google",
            )
            .expect("proof requirement"),
        ],
    };

    for proof in [
        ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
            .expect("method declaration")
            .verified_proof_summary(),
        ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
            .expect("method declaration")
            .verified_proof_summary(),
    ] {
        let transition = reduce_command(
            &config,
            Command::CompleteFullAuthentication(CompleteFullAuthentication {
                now: at(20),
                attempt_id: id("attempt"),
                fresh_session_id: id("session"),
                trust_device: None,
            }),
            &loaded_attempt_with_satisfied_proofs(
                ProofUse::ContributeToFullAuthentication,
                vec![proof],
            ),
        )
        .expect("WebAuthn or OIDC proof should satisfy configured full authentication");

        assert!(matches!(
            transition.outcome,
            Outcome::Authenticated(Authenticated {
                source: AuthenticationSource::FullAuthentication,
                ..
            })
        ));
    }
}

#[test]
fn policy_can_accept_webauthn_or_oidc_for_step_up_and_trusted_device_active_revival() {
    let mut config = config();
    config.proof_policy.step_up = ProofStackPolicy {
        accepted_stacks: vec![
            ProofStackRequirement::one_exact_method(
                ProofFamily::OriginBoundPublicKey,
                "webauthn_passkey",
            )
            .expect("proof requirement"),
            ProofStackRequirement::one_exact_method(
                ProofFamily::FederatedIdentityAssertion,
                "oidc_google",
            )
            .expect("proof requirement"),
        ],
    };
    config.proof_policy.trusted_device_active_revival = config.proof_policy.step_up.clone();

    for proof in [
        ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
            .expect("method declaration")
            .verified_proof_summary(),
        ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, "oidc_google")
            .expect("method declaration")
            .verified_proof_summary(),
    ] {
        let step_up = reduce_command(
            &config,
            Command::CompleteStepUp(CompleteStepUp {
                now: at(50),
                attempt_id: id("attempt"),
            }),
            &loaded_session_and_attempt(200, ProofUse::SatisfyStepUp, vec![proof.clone()]),
        )
        .expect("WebAuthn or OIDC proof should satisfy configured step-up");
        assert!(matches!(
            step_up.outcome,
            Outcome::Authenticated(Authenticated {
                source: AuthenticationSource::StepUp,
                step_up_is_fresh: true,
                ..
            })
        ));

        let active_revival = reduce_command(
            &config,
            Command::CompleteTrustedDeviceRevivalWithActiveProof(
                CompleteTrustedDeviceRevivalWithActiveProof {
                    now: at(600),
                    attempt_id: id("attempt"),
                    fresh_session_id: id("new-session"),
                },
            ),
            &loaded_trusted_device_and_attempt(
                500,
                2_000,
                ProofUse::ReviveTrustedDeviceWithActiveProof,
                vec![proof],
            ),
        )
        .expect("WebAuthn or OIDC proof should satisfy configured trusted-device active revival");
        assert!(matches!(
            active_revival.outcome,
            Outcome::Authenticated(Authenticated {
                source: AuthenticationSource::TrustedDeviceRevivalWithActiveProof,
                step_up_is_fresh: true,
                ..
            })
        ));
    }
}

#[test]
fn custom_full_authentication_policy_can_require_message_signature_and_totp() {
    let mut config = config();
    config.proof_policy.full_authentication = ProofStackPolicy {
        accepted_stacks: vec![ProofStackRequirement::all_any_method_label_in_each_family(
            [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp],
        )],
    };

    let message_signature_only_error = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![proof(ProofFamily::MessageSignature)],
        ),
    )
    .expect_err("custom full-authentication policy should require TOTP too");

    assert_eq!(
        message_signature_only_error,
        Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::ContributeToFullAuthentication,
        }
    );

    let source_less_error = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proofs(
            ProofUse::ContributeToFullAuthentication,
            vec![
                proof(ProofFamily::MessageSignature),
                proof(ProofFamily::SharedSecretOtp),
            ],
        ),
    )
    .expect_err("custom full-authentication policy should require source provenance");

    assert_eq!(
        source_less_error,
        Error::ProofStackRequiresKnownDistinctProofSources {
            proof_use: ProofUse::ContributeToFullAuthentication,
        }
    );

    let transition = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proof_records(
            ProofUse::ContributeToFullAuthentication,
            vec![
                satisfied_proof_with_source(
                    proof(ProofFamily::MessageSignature),
                    proof_source("message-signature-credential"),
                ),
                satisfied_proof_with_source(
                    proof(ProofFamily::SharedSecretOtp),
                    proof_source("totp-credential"),
                ),
            ],
        ),
    )
    .expect("message signature plus TOTP should satisfy custom full-authentication policy");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::FullAuthentication,
            ..
        })
    ));
}

#[test]
fn multi_proof_policy_rejects_collapsed_sources() {
    let mut config = config();
    config.proof_policy.full_authentication = ProofStackPolicy {
        accepted_stacks: vec![ProofStackRequirement::all_any_method_label_in_each_family(
            [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp],
        )],
    };
    let collapsed_source = proof_source("same-effective-credential");

    let error = reduce_command(
        &config,
        Command::CompleteFullAuthentication(CompleteFullAuthentication {
            now: at(20),
            attempt_id: id("attempt"),
            fresh_session_id: id("session"),
            trust_device: None,
        }),
        &loaded_attempt_with_satisfied_proof_records(
            ProofUse::ContributeToFullAuthentication,
            vec![
                satisfied_proof_with_source(
                    proof(ProofFamily::MessageSignature),
                    collapsed_source.clone(),
                ),
                satisfied_proof_with_source(proof(ProofFamily::SharedSecretOtp), collapsed_source),
            ],
        ),
    )
    .expect_err("proof stack must not count two proofs from the same source as independent");

    assert_eq!(
        error,
        Error::ProofStackRequiresKnownDistinctProofSources {
            proof_use: ProofUse::ContributeToFullAuthentication,
        }
    );
}

#[test]
fn custom_step_up_policy_can_require_message_signature_and_totp() {
    let mut config = config();
    config.proof_policy.step_up = ProofStackPolicy {
        accepted_stacks: vec![ProofStackRequirement::all_any_method_label_in_each_family(
            [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp],
        )],
    };

    let message_signature_only_error = reduce_command(
        &config,
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session_and_attempt(
            200,
            ProofUse::SatisfyStepUp,
            vec![proof(ProofFamily::MessageSignature)],
        ),
    )
    .expect_err("custom step-up policy should require TOTP too");

    assert_eq!(
        message_signature_only_error,
        Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::SatisfyStepUp,
        }
    );

    let source_less_error = reduce_command(
        &config,
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session_and_attempt(
            200,
            ProofUse::SatisfyStepUp,
            vec![
                proof(ProofFamily::MessageSignature),
                proof(ProofFamily::SharedSecretOtp),
            ],
        ),
    )
    .expect_err("custom step-up policy should require source provenance");

    assert_eq!(
        source_less_error,
        Error::ProofStackRequiresKnownDistinctProofSources {
            proof_use: ProofUse::SatisfyStepUp,
        }
    );

    let transition = reduce_command(
        &config,
        Command::CompleteStepUp(CompleteStepUp {
            now: at(50),
            attempt_id: id("attempt"),
        }),
        &loaded_session_and_attempt_with_satisfied_proof_records(
            200,
            ProofUse::SatisfyStepUp,
            vec![
                satisfied_proof_with_source(
                    proof(ProofFamily::MessageSignature),
                    proof_source("message-signature-credential"),
                ),
                satisfied_proof_with_source(
                    proof(ProofFamily::SharedSecretOtp),
                    proof_source("totp-credential"),
                ),
            ],
        ),
    )
    .expect("message signature plus TOTP should satisfy custom step-up policy");

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::StepUp,
            step_up_is_fresh: true,
            ..
        })
    ));
}

#[test]
fn custom_trusted_device_active_revival_policy_can_require_message_signature_and_totp() {
    let mut config = config();
    config.proof_policy.trusted_device_active_revival = ProofStackPolicy {
        accepted_stacks: vec![ProofStackRequirement::all_any_method_label_in_each_family(
            [ProofFamily::MessageSignature, ProofFamily::SharedSecretOtp],
        )],
    };

    let message_signature_only_error = reduce_command(
        &config,
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &loaded_trusted_device_and_attempt(
            500,
            2_000,
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            vec![proof(ProofFamily::MessageSignature)],
        ),
    )
    .expect_err("custom trusted-device active revival policy should require TOTP too");

    assert_eq!(
        message_signature_only_error,
        Error::SatisfiedProofStackCannotSatisfyUse {
            proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
        }
    );

    let source_less_error = reduce_command(
        &config,
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &loaded_trusted_device_and_attempt(
            500,
            2_000,
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            vec![
                proof(ProofFamily::MessageSignature),
                proof(ProofFamily::SharedSecretOtp),
            ],
        ),
    )
    .expect_err("custom trusted-device active revival policy should require source provenance");

    assert_eq!(
        source_less_error,
        Error::ProofStackRequiresKnownDistinctProofSources {
            proof_use: ProofUse::ReviveTrustedDeviceWithActiveProof,
        }
    );

    let transition = reduce_command(
        &config,
        Command::CompleteTrustedDeviceRevivalWithActiveProof(
            CompleteTrustedDeviceRevivalWithActiveProof {
                now: at(600),
                attempt_id: id("attempt"),
                fresh_session_id: id("new-session"),
            },
        ),
        &loaded_trusted_device_and_attempt_with_satisfied_proof_records(
            500,
            2_000,
            ProofUse::ReviveTrustedDeviceWithActiveProof,
            vec![
                satisfied_proof_with_source(
                    proof(ProofFamily::MessageSignature),
                    proof_source("message-signature-credential"),
                ),
                satisfied_proof_with_source(
                    proof(ProofFamily::SharedSecretOtp),
                    proof_source("totp-credential"),
                ),
            ],
        ),
    )
    .expect(
        "message signature plus TOTP should satisfy custom trusted-device active revival policy",
    );

    assert!(matches!(
        transition.outcome,
        Outcome::Authenticated(Authenticated {
            source: AuthenticationSource::TrustedDeviceRevivalWithActiveProof,
            step_up_is_fresh: true,
            ..
        })
    ));
}
