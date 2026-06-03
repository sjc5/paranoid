use super::*;

#[test]
fn credential_instance_metadata_records_totp_as_shared_secret_credential_source() {
    let credential_id: VerifiedProofSourceId = id("totp-credential");
    let subject_id: SubjectId = id("subject");

    let metadata = CredentialInstanceMetadata::new(
        credential_id.clone(),
        subject_id.clone(),
        CredentialInstanceKind::SharedSecretOtpVerifier,
        "totp",
        CredentialLifecycleState::Active,
    )
    .expect("TOTP credential metadata");

    assert_eq!(metadata.credential_instance_id(), &credential_id);
    assert_eq!(metadata.subject_id(), &subject_id);
    assert_eq!(
        metadata.kind(),
        CredentialInstanceKind::SharedSecretOtpVerifier
    );
    assert_eq!(metadata.proof_family(), ProofFamily::SharedSecretOtp);
    assert_eq!(metadata.method_label(), "totp");
    assert_eq!(metadata.lifecycle_state(), CredentialLifecycleState::Active);
    assert!(metadata.can_produce_new_proofs());
    assert_eq!(
        metadata.verified_proof_source(),
        VerifiedProofSource::new(VerifiedProofSourceKind::CredentialInstance, credential_id)
    );
}

#[test]
fn credential_instance_kind_only_covers_app_owned_credential_families() {
    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::MessageSignature),
        Ok(CredentialInstanceKind::MessageSignatureVerifier)
    );
    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::SharedSecretOtp),
        Ok(CredentialInstanceKind::SharedSecretOtpVerifier)
    );
    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::OriginBoundPublicKey),
        Ok(CredentialInstanceKind::OriginBoundPublicKeyCredential)
    );
    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::RecoveryCode),
        Ok(CredentialInstanceKind::RecoveryCodeCredential)
    );
    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::TrustedDevice),
        Ok(CredentialInstanceKind::TrustedDeviceCredential)
    );

    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::OutOfBandCode),
        Err(Error::InvalidConfig(
            "proof family is not an app-owned credential instance",
        ))
    );
    assert_eq!(
        CredentialInstanceKind::try_from_proof_family(ProofFamily::FederatedIdentityAssertion),
        Err(Error::InvalidConfig(
            "proof family is not an app-owned credential instance",
        ))
    );
}

#[test]
fn credential_instance_metadata_validates_method_label_domain() {
    assert_eq!(
        CredentialInstanceMetadata::new(
            id("credential"),
            id("subject"),
            CredentialInstanceKind::SharedSecretOtpVerifier,
            "",
            CredentialLifecycleState::Active,
        ),
        Err(Error::EmptyProofMethodLabel)
    );
    assert_eq!(
        CredentialInstanceMetadata::new(
            id("credential"),
            id("subject"),
            CredentialInstanceKind::SharedSecretOtpVerifier,
            "totp app",
            CredentialLifecycleState::Active,
        ),
        Err(Error::InvalidIdentifierString {
            input_name: "credential instance method label",
        })
    );
}

#[test]
fn only_active_credential_instances_can_produce_new_proofs() {
    assert!(CredentialLifecycleState::Active.can_produce_new_proofs());

    for state in [
        CredentialLifecycleState::PendingActivation,
        CredentialLifecycleState::PendingReplacement,
        CredentialLifecycleState::PendingRemoval,
        CredentialLifecycleState::ScheduledDeletion,
        CredentialLifecycleState::Consumed,
        CredentialLifecycleState::Revoked,
        CredentialLifecycleState::Expired,
        CredentialLifecycleState::Superseded,
        CredentialLifecycleState::AdminSuspended,
    ] {
        assert!(
            !state.can_produce_new_proofs(),
            "{state:?} must not produce fresh proofs"
        );
    }
}
