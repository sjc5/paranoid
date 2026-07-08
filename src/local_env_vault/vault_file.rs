use super::*;

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct VaultFile {
    pub(super) version: u32,
    pub(super) vault_id: String,
    pub(super) created_at_unix_seconds: u64,
    pub(super) updated_at_unix_seconds: u64,
    pub(super) kdf: StoredPasswordKdf,
    pub(super) password_check: String,
    pub(super) encrypted_env: BTreeMap<String, EncryptedEnvEntry>,
}

impl VaultFile {
    pub(super) fn new(
        password: &SecretBytes,
        kdf_params: PasswordKdfParams,
    ) -> Result<Self, Error> {
        let now = unix_now()?;
        let mut vault = Self {
            version: VAULT_VERSION,
            vault_id: encode_public_bytes(random_public_bytes(VAULT_ID_RANDOM_BYTES)?),
            created_at_unix_seconds: now,
            updated_at_unix_seconds: now,
            kdf: StoredPasswordKdf::new(kdf_params)?,
            password_check: String::new(),
            encrypted_env: BTreeMap::new(),
        };
        let keyset = derive_vault_keyset(&vault, password)?;
        let check_plaintext: SecretBytes = SecretBytes::try_from(PASSWORD_CHECK_PLAINTEXT)?;
        let encrypted = encrypt(
            &keyset,
            &check_plaintext,
            &password_check_associated_data(&vault),
        )?;
        vault.password_check = encrypted.to_base64_url()?.into_exposed_string();
        Ok(vault)
    }

    pub(super) fn set_encrypted_value(
        &mut self,
        keyset: &crate::crypto::Keyset,
        name: &EnvVarName,
        value: &SecretBytes,
    ) -> Result<(), Error> {
        let entry = EncryptedEnvEntry {
            version: ENCRYPTED_ENTRY_VERSION,
            updated_at_unix_seconds: unix_now()?,
            ciphertext: String::new(),
        };
        let associated_data = entry_associated_data(self, name, &entry);
        let encrypted = encrypt(keyset, value, &associated_data)?;
        let encoded = encrypted.to_base64_url()?.into_exposed_string();
        self.encrypted_env.insert(
            name.as_str().to_owned(),
            EncryptedEnvEntry {
                ciphertext: encoded,
                ..entry
            },
        );
        self.updated_at_unix_seconds = unix_now()?;
        Ok(())
    }

    pub(super) fn decrypt_value(
        &self,
        keyset: &crate::crypto::Keyset,
        name: &EnvVarName,
    ) -> Result<SecretBytes, Error> {
        let entry = self
            .encrypted_env
            .get(name.as_str())
            .ok_or(Error::MissingProfileValues)?;
        let encrypted =
            Base64Url::<Encrypted<SecretBytes>>::parse_str(entry.ciphertext.as_str())?.decode()?;
        let associated_data = entry_associated_data(self, name, entry);
        decrypt(keyset, &encrypted, &associated_data).map_err(Error::from)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct StoredPasswordKdf {
    pub(super) algorithm: String,
    pub(super) version: u32,
    pub(super) memory_cost_kib: u32,
    pub(super) iterations: u32,
    pub(super) parallelism: u32,
    pub(super) salt: String,
}

impl StoredPasswordKdf {
    pub(super) fn new(params: PasswordKdfParams) -> Result<Self, Error> {
        reject_password_kdf_params_above_local_bounds(&params)?;
        let salt = PasswordKdfSalt::generate()?;
        Ok(Self {
            algorithm: KDF_ALGORITHM_ARGON2ID.to_owned(),
            version: ARGON2_VERSION_0X13,
            memory_cost_kib: params.memory_cost_kib(),
            iterations: params.iterations(),
            parallelism: params.parallelism(),
            salt: encode_public_bytes(PublicBytes::try_from(salt.as_bytes().as_slice())?),
        })
    }

    pub(super) fn params(&self) -> Result<PasswordKdfParams, Error> {
        if self.algorithm != KDF_ALGORITHM_ARGON2ID || self.version != ARGON2_VERSION_0X13 {
            return Err(Error::UnsupportedPasswordKdf);
        }
        let params =
            PasswordKdfParams::new(self.memory_cost_kib, self.iterations, self.parallelism)?;
        reject_password_kdf_params_above_local_bounds(&params)?;
        Ok(params)
    }

    pub(super) fn salt(&self) -> Result<PasswordKdfSalt, Error> {
        let bytes = Base64Url::<PublicBytes>::parse_str(self.salt.as_str())?
            .decode()?
            .into_bytes();
        Ok(PasswordKdfSalt::from_bytes(bytes.as_slice())?)
    }
}

pub(super) fn reject_password_kdf_params_above_local_bounds(
    params: &PasswordKdfParams,
) -> Result<(), Error> {
    if params.memory_cost_kib() > STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB {
        return Err(Error::PasswordKdfMemoryCostTooLarge {
            actual: params.memory_cost_kib(),
            max: STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB,
        });
    }
    if params.iterations() > STORED_PASSWORD_KDF_MAX_ITERATIONS {
        return Err(Error::PasswordKdfIterationsTooMany {
            actual: params.iterations(),
            max: STORED_PASSWORD_KDF_MAX_ITERATIONS,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct EncryptedEnvEntry {
    pub(super) version: u32,
    pub(super) updated_at_unix_seconds: u64,
    pub(super) ciphertext: String,
}

pub(super) fn encode_public_bytes(bytes: PublicBytes) -> String {
    bytes
        .to_base64_url()
        .expect("public bytes base64url encoding cannot fail")
        .into_exposed_string()
}

pub(super) fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| Error::Io(io::Error::other(error)))
}
