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
        &MethodPreStateLoadResponsibility::VerifyStatelessFastFailMacFromEncryptedChallengeCookie
    ));
    assert_eq!(
        contract.verification().completion_input(),
        MethodCompletionInputKind::SubmittedSecretResponse
    );
    assert_eq!(
        contract.verification().verified_proof_identity(),
        MethodVerifiedProofIdentitySource::CoreDerivesFromEncryptedChallengeCookie
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::MethodMayResolveSubject
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
            .contains(&MethodPreStateLoadResponsibility::VerifyBoundMessageSignature)
    );
    assert!(
        contract
            .pre_state_load()
            .contains(&MethodPreStateLoadResponsibility::VerifyWeakProofGateBeforeStateLoad)
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
        MethodVerifiedProofIdentitySource::CoreDerivesFromEncryptedChallengeCookie
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
        MethodVerifiedProofIdentitySource::CoreDerivesFromMethodDeclaration
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::MustUseKnownAttemptSubject
    );
    assert!(contract.pre_state_load().is_empty());
    assert_eq!(
        contract.post_state_load(),
        &[MethodPostStateLoadResponsibility::VerifyOneTimeRecoveryProofForKnownSubject]
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
        MethodVerifiedProofIdentitySource::CoreDerivesFromMethodDeclaration
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::MustUseKnownAttemptSubject
    );
    assert_eq!(
        contract.pre_state_load(),
        &[MethodPreStateLoadResponsibility::VerifyWeakProofGateBeforeStateLoad]
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
            MethodPreStateLoadResponsibility::VerifyEncryptedChallengeCookie,
            MethodPreStateLoadResponsibility::VerifyWeakProofGateBeforeStateLoad,
            MethodPreStateLoadResponsibility::VerifyChallengeBoundConfiguredSecretFastFailBloomFilter,
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
        MethodVerifiedProofSubjectBinding::MustUseKnownAttemptSubject
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
        MethodVerifiedProofIdentitySource::CoreDerivesFromTrustedDeviceCredential
    );
    assert_eq!(
        contract.verification().subject_binding(),
        MethodVerifiedProofSubjectBinding::CoreUsesTrustedDeviceCredentialSubject
    );
    assert!(
        contract
            .forbidden()
            .contains(&MethodAdapterForbiddenResponsibility::MutateTrustedDeviceLifecycle)
    );
}

#[test]
fn method_contract_keeps_proof_stack_and_lifecycle_authority_in_core() {
    for family in [
        ProofFamily::OutOfBandCode,
        ProofFamily::MessageSignature,
        ProofFamily::OriginBoundPublicKey,
        ProofFamily::FederatedIdentityAssertion,
        ProofFamily::SharedSecretOtp,
        ProofFamily::RecoveryCode,
    ] {
        let contract = MethodAdapterContract::for_method(proof_method(family));

        assert!(
            contract
                .forbidden()
                .contains(&MethodAdapterForbiddenResponsibility::DecideProofStackSufficiency)
        );
        assert!(
            contract
                .forbidden()
                .contains(&MethodAdapterForbiddenResponsibility::OverrideCoreProofSemantics)
        );
        assert!(
            contract
                .forbidden()
                .contains(&MethodAdapterForbiddenResponsibility::MutateCoreSessionLifecycle)
        );
        assert!(
            contract.forbidden().contains(
                &MethodAdapterForbiddenResponsibility::DeliverExternalEffectsBeforeCommit
            )
        );
        assert!(contract.forbidden().contains(
            &MethodAdapterForbiddenResponsibility::ConstructCoreCompletionCommandDirectly
        ));
        assert!(
            contract
                .forbidden()
                .contains(&MethodAdapterForbiddenResponsibility::MarkStatelessFastFailVerified)
        );
    }
}
