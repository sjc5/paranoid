use super::*;

#[test]
fn encrypted_challenge_cookie_contracts_include_generic_challenge_identity() {
    for family in [
        ProofFamily::OutOfBandCode,
        ProofFamily::MessageSignature,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
    ] {
        let contract = MethodAdapterContract::for_method(proof_method(family));

        assert!(
            contract
                .challenge_cookie()
                .fields()
                .contains(&MethodChallengeCookieField::AttemptId)
        );
        assert!(
            contract
                .challenge_cookie()
                .fields()
                .contains(&MethodChallengeCookieField::ChallengeId)
        );
        assert!(
            contract
                .challenge_cookie()
                .associated_data()
                .contains(&MethodChallengeCookieAssociatedData::AttemptId)
        );
        assert!(
            contract
                .challenge_cookie()
                .associated_data()
                .contains(&MethodChallengeCookieAssociatedData::ChallengeId)
        );
    }
}

#[test]
fn out_of_band_method_contract_requires_encrypted_fast_fail_cookie_and_core_delivery() {
    let contract = MethodAdapterContract::for_method(proof_method(ProofFamily::OutOfBandCode));

    assert_eq!(contract.ownership(), MethodAdapterOwnership::PluginOwned);
    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::EncryptedOutOfBandFastFail
    );
    assert!(
        contract
            .challenge_cookie()
            .fields()
            .contains(&MethodChallengeCookieField::StatelessFastFailMac)
    );
    assert!(
        contract
            .challenge_cookie()
            .associated_data()
            .contains(&MethodChallengeCookieAssociatedData::AttemptId)
    );
    assert!(contract.pre_state_load().contains(
        &MethodPreStateLoadResponsibility::StatelessFastFailMacFromEncryptedChallengeCookie
    ));
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::SubmittedSecretResponse
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::EncryptedChallengeCookie
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::MethodMayResolve
    );
    assert!(
        contract
            .durable_effects()
            .contains(&MethodDurableEffectContract::CoreOutOfBandDeliveryCommand)
    );
    assert_eq!(contract.postgres_state().len(), 1);
    assert_eq!(
        contract.postgres_state()[0].purpose(),
        MethodPostgresStatePurpose::OutOfBandChallengePrivateState
    );
    assert_eq!(
        contract.postgres_state()[0].key_policy(),
        MethodPostgresStateKeyPolicy::ChallengeId
    );
    assert_eq!(
        contract.postgres_state()[0].mutation_boundary(),
        MethodPostgresStateMutationBoundary::OnlyThroughMethodCommitWorkInsideCoreAtomicCommit
    );
}

#[test]
fn online_guessable_message_signature_method_contract_requires_weak_gate_without_changing_family_semantics()
 {
    let method =
        ProofMethodDeclaration::new_online_guessable(ProofFamily::MessageSignature, "password")
            .expect("method");
    let contract = MethodAdapterContract::for_method(method);

    assert!(
        contract
            .core_derived()
            .contains(&MethodCoreDerivedResponsibility::ProofSemantics(
                ProofFamily::MessageSignature.semantics()
            ))
    );
    assert!(contract.core_derived().contains(
        &MethodCoreDerivedResponsibility::WeakFailureBudgetUse(OnlineGuessingRisk::OnlineGuessable)
    ));
    assert!(
        contract
            .pre_state_load()
            .contains(&MethodPreStateLoadResponsibility::BoundMessageSignature)
    );
    assert!(
        contract
            .pre_state_load()
            .contains(&MethodPreStateLoadResponsibility::WeakProofGateBeforeStateLoad)
    );
    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::EncryptedMessageSignatureChallenge
    );
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::BoundMessageSignatureAssertion
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::EncryptedChallengeCookie
    );
}

#[test]
fn post_alpha_webauthn_passkey_contract_hooks_model_origin_bound_public_key_requirements() {
    let method = ProofMethodDeclaration::new(ProofFamily::OriginBoundPublicKey, "webauthn_passkey")
        .expect("WebAuthn method declaration");
    let contract = MethodAdapterContract::for_method(method.clone());

    assert_eq!(contract.method(), &method);
    assert_eq!(contract.ownership(), MethodAdapterOwnership::PluginOwned);
    assert_eq!(
        method.semantics(),
        ProofFamily::OriginBoundPublicKey.semantics()
    );
    assert!(method.supports_use(ProofUse::ContributeToFullAuthentication));
    assert!(method.supports_use(ProofUse::SatisfyStepUp));
    assert!(!method.supports_use(ProofUse::RecoverOrReplaceCredential));
    assert!(!method.uses_weak_attempt_failure_budget());
    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::EncryptedOriginBoundPublicKeyChallenge
    );
    assert!(
        contract
            .challenge_cookie()
            .fields()
            .contains(&MethodChallengeCookieField::OriginOrRelyingPartyId)
    );
    assert!(
        contract
            .challenge_cookie()
            .fields()
            .contains(&MethodChallengeCookieField::ChallengeNonce)
    );
    assert_eq!(
        contract.pre_state_load(),
        &[
            MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::OriginBoundPublicKeyAssertion,
        ]
    );
    assert!(contract.post_state_load().is_empty());
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::OriginBoundPublicKeyAssertion
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::EncryptedChallengeCookie
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::MethodMayResolve
    );
    assert_eq!(contract.postgres_state().len(), 1);
    assert_eq!(
        contract.postgres_state()[0].purpose(),
        MethodPostgresStatePurpose::VerifierRegistry
    );
    assert_eq!(
        contract.postgres_state()[0].key_policy(),
        MethodPostgresStateKeyPolicy::SubjectAndVerifierId
    );
    assert_eq!(
        contract.postgres_state()[0].mutation_boundary(),
        MethodPostgresStateMutationBoundary::ReadOnlyBeforeCommandConstruction
    );
    assert!(contract.durable_effects().is_empty());
    assert_eq!(
        contract.commit_work().success_requirement(),
        MethodCommitWorkSuccessRequirement::OptionalWhenMethodHasPrivateStateChange
    );
}

#[test]
fn post_alpha_oidc_and_saml_contract_hooks_model_federated_identity_requirements() {
    for method_label in ["oidc_google", "saml_enterprise"] {
        let method =
            ProofMethodDeclaration::new(ProofFamily::FederatedIdentityAssertion, method_label)
                .expect("federated method declaration");
        let contract = MethodAdapterContract::for_method(method.clone());

        assert_eq!(contract.method(), &method);
        assert_eq!(contract.ownership(), MethodAdapterOwnership::PluginOwned);
        assert_eq!(
            method.semantics(),
            ProofFamily::FederatedIdentityAssertion.semantics()
        );
        assert!(method.supports_use(ProofUse::ContributeToFullAuthentication));
        assert!(method.supports_use(ProofUse::SatisfyStepUp));
        assert!(!method.supports_use(ProofUse::RecoverOrReplaceCredential));
        assert!(!method.uses_weak_attempt_failure_budget());
        assert_eq!(
            contract.challenge_cookie().kind(),
            MethodChallengeCookieKind::EncryptedFederatedIdentityState
        );
        assert!(
            contract
                .challenge_cookie()
                .fields()
                .contains(&MethodChallengeCookieField::FederatedIssuer)
        );
        assert!(
            contract
                .challenge_cookie()
                .fields()
                .contains(&MethodChallengeCookieField::ChallengeNonce)
        );
        assert_eq!(
            contract.pre_state_load(),
            &[
                MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
                MethodPreStateLoadResponsibility::FederatedIdentityAssertion,
            ]
        );
        assert!(contract.post_state_load().is_empty());
        assert_eq!(
            contract.verification().completion_input(),
            MethodCompletionInputKind::FederatedIdentityAssertion
        );
        assert_eq!(
            contract.verification().verified_proof_identity(),
            MethodVerifiedProofIdentitySource::EncryptedChallengeCookie
        );
        assert_eq!(
            contract.verification().subject_binding(),
            MethodVerifiedProofSubjectBinding::MethodMayResolve
        );
        assert_eq!(contract.postgres_state().len(), 1);
        assert_eq!(
            contract.postgres_state()[0].purpose(),
            MethodPostgresStatePurpose::FederatedIdentitySubjectMapping
        );
        assert_eq!(
            contract.postgres_state()[0].key_policy(),
            MethodPostgresStateKeyPolicy::ExternalIssuerAndSubject
        );
        assert_eq!(
            contract.postgres_state()[0].mutation_boundary(),
            MethodPostgresStateMutationBoundary::ReadOnlyBeforeCommandConstruction
        );
        assert!(contract.durable_effects().is_empty());
        assert_eq!(
            contract.commit_work().success_requirement(),
            MethodCommitWorkSuccessRequirement::OptionalWhenMethodHasPrivateStateChange
        );
    }
}

#[test]
fn active_method_acceptance_requires_source_for_credential_or_external_authority_proofs() {
    for family in [
        ProofFamily::MessageSignature,
        ProofFamily::SharedSecretOtp,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
        ProofFamily::RecoveryCode,
    ] {
        let proof = proof_method(family).verified_proof_summary();
        let subject_id = match family {
            ProofFamily::MessageSignature
            | ProofFamily::OriginBoundPublicKey
            | ProofFamily::FederatedIdentityAssertion => Some(id("subject")),
            ProofFamily::SharedSecretOtp | ProofFamily::RecoveryCode => None,
            ProofFamily::OutOfBandCode | ProofFamily::TrustedDevice => None,
        };
        let verified_proof =
            VerifiedActiveProof::from_summary(proof, subject_id).expect("verified proof");

        assert_eq!(
            super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse::new(
                verified_proof,
                Vec::new(),
            )
            .expect_err("active method proof must carry source provenance"),
            Error::ProofFamilyRequiresVerifiedProofSource { family },
        );
    }

    let sourced_totp = VerifiedActiveProof::from_summary_with_source(
        proof_method(ProofFamily::SharedSecretOtp).verified_proof_summary(),
        None,
        proof_source("totp-credential"),
    )
    .expect("verified sourced TOTP proof");
    assert!(
        super::super::postgres_method_runtime::VerifiedActiveProofMethodResponse::new(
            sourced_totp,
            Vec::new(),
        )
        .is_ok()
    );
}

#[test]
fn recovery_code_contract_requires_success_commit_work_and_keeps_response_effects_forbidden() {
    let contract = MethodAdapterContract::for_method(proof_method(ProofFamily::RecoveryCode));

    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::NotUsed
    );
    assert_eq!(
        contract.commit_work().success_requirement(),
        MethodCommitWorkSuccessRequirement::RequiredForSuccessfulProofCompletion
    );
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::RecoveryCredential
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::MethodDeclaration
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::MethodMayResolve
    );
    assert!(contract.pre_state_load().is_empty());
    assert_eq!(
        contract.post_state_load(),
        &[MethodPostStateLoadResponsibility::VerifyOneTimeRecoveryProofAndConsume]
    );
    assert_eq!(contract.postgres_state().len(), 1);
    assert_eq!(
        contract.postgres_state()[0].purpose(),
        MethodPostgresStatePurpose::OneTimeRecoveryCredential
    );
    assert_eq!(
        contract.postgres_state()[0].key_policy(),
        MethodPostgresStateKeyPolicy::SubjectAndOneTimeCredentialId
    );
    assert_eq!(
        contract.postgres_state()[0].mutation_boundary(),
        MethodPostgresStateMutationBoundary::OnlyThroughMethodCommitWorkInsideCoreAtomicCommit
    );
    assert!(
        contract
            .forbidden()
            .contains(&MethodAdapterForbiddenResponsibility::EmitAuthCookies)
    );
    assert!(
        contract
            .forbidden()
            .contains(&MethodAdapterForbiddenResponsibility::CycleCsrfTokens)
    );
}

#[test]
fn shared_secret_otp_contract_uses_known_subject_configured_secret_without_challenge_cookie() {
    let contract = MethodAdapterContract::for_method(proof_method(ProofFamily::SharedSecretOtp));

    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::NotUsed
    );
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::ConfiguredSecretProof
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::MethodDeclaration
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::KnownAttemptSubject
    );
    assert_eq!(
        contract.pre_state_load(),
        &[MethodPreStateLoadResponsibility::WeakProofGateBeforeStateLoad]
    );
    assert_eq!(
        contract.post_state_load(),
        &[MethodPostStateLoadResponsibility::VerifyConfiguredSecretProofForKnownSubject]
    );
    assert_eq!(contract.postgres_state().len(), 1);
    assert_eq!(
        contract.postgres_state()[0].purpose(),
        MethodPostgresStatePurpose::ConfiguredSecretVerifier
    );
    assert_eq!(
        contract.postgres_state()[0].key_policy(),
        MethodPostgresStateKeyPolicy::SubjectId
    );
    assert_eq!(
        contract.postgres_state()[0].mutation_boundary(),
        MethodPostgresStateMutationBoundary::ReadOnlyBeforeCommandConstruction
    );
}

#[test]
fn challenge_bound_shared_secret_otp_contract_uses_configured_secret_fast_fail_bloom_filter() {
    let method = proof_method(ProofFamily::SharedSecretOtp);
    let contract = MethodAdapterContract::for_challenge_bound_configured_secret_method(method)
        .expect("challenge-bound shared-secret OTP contract");

    assert_eq!(contract.ownership(), MethodAdapterOwnership::PluginOwned);
    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::EncryptedConfiguredSecretFastFailChallenge
    );
    assert!(
        contract
            .challenge_cookie()
            .fields()
            .contains(&MethodChallengeCookieField::ConfiguredSecretFastFailBloomFilter)
    );
    assert_eq!(
        contract.pre_state_load(),
        &[
            MethodPreStateLoadResponsibility::EncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::WeakProofGateBeforeStateLoad,
            MethodPreStateLoadResponsibility::ChallengeBoundConfiguredSecretFastFailBloomFilter,
        ]
    );
    assert_eq!(
        contract.post_state_load(),
        &[MethodPostStateLoadResponsibility::VerifyConfiguredSecretProofForKnownSubject]
    );
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::ConfiguredSecretProof
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::KnownAttemptSubject
    );
    assert_eq!(
        contract.postgres_state()[0].purpose(),
        MethodPostgresStatePurpose::ConfiguredSecretVerifier
    );
}

#[test]
fn challenge_bound_configured_secret_contract_rejects_non_shared_secret_otp_families() {
    for family in [
        ProofFamily::OutOfBandCode,
        ProofFamily::MessageSignature,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
        ProofFamily::RecoveryCode,
        ProofFamily::TrustedDevice,
    ] {
        assert_eq!(
            MethodAdapterContract::for_challenge_bound_configured_secret_method(proof_method(
                family
            )),
            Err(Error::ProofMethodCannotUseChallengeBoundConfiguredSecretFastFail { family })
        );
    }
}

#[test]
fn trusted_device_method_contract_is_core_owned_not_plugin_lifecycle() {
    let contract = MethodAdapterContract::for_method(proof_method(ProofFamily::TrustedDevice));

    assert_eq!(contract.ownership(), MethodAdapterOwnership::CoreOwned);
    assert_eq!(
        contract.challenge_cookie().kind(),
        MethodChallengeCookieKind::NotUsed
    );
    assert!(contract.pre_state_load().is_empty());
    assert!(contract.postgres_state().is_empty());
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::PassiveTrustedDeviceCredential
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::TrustedDeviceCredential
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::TrustedDeviceCredentialSubject
    );
    assert!(
        contract
            .forbidden()
            .contains(&MethodAdapterForbiddenResponsibility::MutateTrustedDeviceLifecycle)
    );
}

#[test]
fn method_contract_keeps_proof_stack_and_lifecycle_authority_in_core() {
    let forbidden = [
        MethodAdapterForbiddenResponsibility::MutateCoreSessionLifecycle,
        MethodAdapterForbiddenResponsibility::MutateTrustedDeviceLifecycle,
        MethodAdapterForbiddenResponsibility::EmitAuthCookies,
        MethodAdapterForbiddenResponsibility::CycleCsrfTokens,
        MethodAdapterForbiddenResponsibility::DecideProofStackSufficiency,
        MethodAdapterForbiddenResponsibility::OverrideCoreProofSemantics,
        MethodAdapterForbiddenResponsibility::ConstructCoreCompletionCommandDirectly,
        MethodAdapterForbiddenResponsibility::MarkStatelessFastFailVerified,
        MethodAdapterForbiddenResponsibility::AppendCoreAuditEvents,
        MethodAdapterForbiddenResponsibility::DeliverExternalEffectsBeforeCommit,
    ];

    for family in [
        ProofFamily::OutOfBandCode,
        ProofFamily::MessageSignature,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
        ProofFamily::SharedSecretOtp,
        ProofFamily::RecoveryCode,
    ] {
        let contract = MethodAdapterContract::for_method(proof_method(family));

        assert_eq!(contract.ownership(), MethodAdapterOwnership::PluginOwned);
        assert_eq!(contract.forbidden(), forbidden.as_slice());
    }
}
