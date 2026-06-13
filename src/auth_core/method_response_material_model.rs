use std::fmt;

use crate::crypto::SecretBytes;

use super::prelude::*;

/// Post-commit method-owned response material.
#[derive(Default)]
pub(crate) struct PostCommitMethodResponseMaterial {
    generated_recovery_codes: Option<GeneratedRecoveryCodeSet>,
}

impl PostCommitMethodResponseMaterial {
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn from_generated_recovery_codes(
        generated_recovery_codes: GeneratedRecoveryCodeSet,
    ) -> Self {
        Self {
            generated_recovery_codes: Some(generated_recovery_codes),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.generated_recovery_codes.is_none()
    }

    pub(crate) fn generated_recovery_codes(&self) -> Option<&GeneratedRecoveryCodeSet> {
        self.generated_recovery_codes.as_ref()
    }

    pub(crate) fn into_generated_recovery_codes(self) -> Option<GeneratedRecoveryCodeSet> {
        self.generated_recovery_codes
    }

    pub(crate) fn append(&mut self, other: Self) -> Result<(), Error> {
        if let Some(generated_recovery_codes) = other.generated_recovery_codes {
            if self.generated_recovery_codes.is_some() {
                return Err(Error::LoadedStateContradiction(
                    "multiple method response material sets for generated recovery codes",
                ));
            }
            self.generated_recovery_codes = Some(generated_recovery_codes);
        }
        Ok(())
    }
}

impl fmt::Debug for PostCommitMethodResponseMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostCommitMethodResponseMaterial")
            .field(
                "generated_recovery_code_count",
                &self
                    .generated_recovery_codes
                    .as_ref()
                    .map(GeneratedRecoveryCodeSet::len)
                    .unwrap_or(0),
            )
            .finish()
    }
}

/// One committed recovery-code credential set generated for display exactly once.
pub(crate) struct GeneratedRecoveryCodeSet {
    credential_instance_id: VerifiedProofSourceId,
    codes: Vec<GeneratedRecoveryCode>,
}

impl GeneratedRecoveryCodeSet {
    pub(crate) fn new(
        credential_instance_id: VerifiedProofSourceId,
        codes: Vec<GeneratedRecoveryCode>,
    ) -> Result<Self, Error> {
        if codes.is_empty() {
            return Err(Error::LoadedStateContradiction(
                "generated recovery code set is empty",
            ));
        }
        Ok(Self {
            credential_instance_id,
            codes,
        })
    }

    pub(crate) fn credential_instance_id(&self) -> &VerifiedProofSourceId {
        &self.credential_instance_id
    }

    pub(crate) fn codes(&self) -> &[GeneratedRecoveryCode] {
        &self.codes
    }

    pub(crate) fn len(&self) -> usize {
        self.codes.len()
    }

    pub(crate) fn into_parts(self) -> (VerifiedProofSourceId, Vec<GeneratedRecoveryCode>) {
        (self.credential_instance_id, self.codes)
    }
}

impl fmt::Debug for GeneratedRecoveryCodeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedRecoveryCodeSet")
            .field("credential_instance_id", &self.credential_instance_id)
            .field("code_count", &self.codes.len())
            .finish()
    }
}

/// One generated user-visible recovery code.
pub(crate) struct GeneratedRecoveryCode {
    code: SecretBytes<GeneratedRecoveryCodeKind>,
}

pub(crate) enum GeneratedRecoveryCodeKind {}

impl GeneratedRecoveryCode {
    pub(crate) fn from_display_token(token: String) -> Result<Self, Error> {
        if token.is_empty() {
            return Err(Error::LoadedStateContradiction(
                "generated recovery code token is empty",
            ));
        }
        Ok(Self {
            code: SecretBytes::try_from(token.into_bytes()).map_err(|_| {
                Error::LoadedStateContradiction("generated recovery code could not be allocated")
            })?,
        })
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.code.expose_secret()
    }
}

impl fmt::Debug for GeneratedRecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedRecoveryCode")
            .field("byte_len", &self.code.len())
            .finish()
    }
}
