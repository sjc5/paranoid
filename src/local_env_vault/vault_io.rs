use super::*;

pub(super) fn vault_dir_from_root_and_relative_parent(
    root: &Path,
    path_relative_to_root: &Path,
) -> Result<PathBuf, Error> {
    if !root.is_absolute() {
        return Err(Error::VaultRootMustBeAbsolute {
            path: root.to_owned(),
        });
    }
    validate_vault_parent_path_relative_to_root(path_relative_to_root)?;
    Ok(root.join(path_relative_to_root).join(VAULT_DIR_NAME))
}

pub(super) fn validate_vault_parent_path_relative_to_root(path: &Path) -> Result<(), Error> {
    if path.as_os_str().is_empty() {
        return Err(Error::VaultParentPathRelativeToRootMustNotBeEmpty);
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::VaultParentPathMustNotTraverseParent {
                    path: path.to_owned(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::VaultParentPathMustBeRelative {
                    path: path.to_owned(),
                });
            }
        }
    }
    Ok(())
}

pub(super) struct VaultLockSession {
    lock: ProcessLock,
    lock_lost: Arc<AtomicBool>,
}

impl VaultLockSession {
    pub(super) fn ensure_still_owned(&self) -> Result<(), Error> {
        ensure_vault_lock_still_owned(&self.lock, &self.lock_lost)
    }

    pub(super) fn run_while_owned<R>(
        &self,
        run: impl FnOnce() -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.ensure_still_owned()?;
        let result = run()?;
        self.ensure_still_owned()?;
        Ok(result)
    }

    #[cfg(test)]
    pub(super) fn mark_lock_lost_for_test(&self) {
        self.lock_lost.store(true, Ordering::SeqCst);
    }
}

impl Drop for VaultLockSession {
    fn drop(&mut self) {
        let _ = self.lock.release();
    }
}

pub(super) fn ensure_vault_lock_still_owned(
    lock: &ProcessLock,
    lock_lost: &AtomicBool,
) -> Result<(), Error> {
    if lock_lost.load(Ordering::SeqCst) || !lock.is_held_by_current_process() {
        return Err(Error::VaultLockLost {
            path: lock.lock_file_path().to_owned(),
        });
    }
    Ok(())
}

pub(super) fn acquire_vault_lock(vault_dir: &Path) -> Result<VaultLockSession, Error> {
    ensure_vault_directory(vault_dir)?;
    let path = vault_dir.join(VAULT_LOCK_FILE_NAME);
    let lock_lost = Arc::new(AtomicBool::new(false));
    let lock_lost_for_callback = Arc::clone(&lock_lost);
    let options = ProcessLockOptions::default()
        .with_heartbeat_interval_and_stale_after(
            VAULT_LOCK_HEARTBEAT_INTERVAL,
            VAULT_LOCK_STALE_AFTER,
        )
        .map_err(Error::Lock)?
        .with_on_lock_lost(move || {
            lock_lost_for_callback.store(true, Ordering::SeqCst);
        });
    let mut lock = ProcessLock::with_options(&path, options);
    match lock.acquire() {
        Ok(()) => Ok(VaultLockSession { lock, lock_lost }),
        Err(crate::local_lock::Error::LockHeld { path, pid }) => {
            Err(Error::VaultLocked { path, pid })
        }
        Err(error) => Err(Error::Lock(error)),
    }
}

pub(super) fn read_vault(path: &Path) -> Result<VaultFile, Error> {
    ensure_existing_vault_parent_directory(path)?;
    ensure_existing_regular_vault_file_path(path)?;
    ensure_restrictive_file_permissions(path)?;
    reject_oversized_vault_file(path)?;
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Error::VaultMissing {
                path: path.to_owned(),
            }
        } else {
            Error::Io(error)
        }
    })?;
    let vault: VaultFile = serde_json::from_slice(&bytes).map_err(Error::Json)?;
    validate_vault(&vault)?;
    Ok(vault)
}

pub(super) fn reject_oversized_vault_file(path: &Path) -> Result<(), Error> {
    let len = fs::metadata(path).map_err(Error::Io)?.len();
    if len > MAX_VAULT_FILE_BYTES {
        return Err(Error::VaultFileTooLarge {
            actual: len,
            max: MAX_VAULT_FILE_BYTES,
        });
    }
    Ok(())
}

pub(super) fn ensure_existing_vault_parent_directory(path: &Path) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            ensure_restrictive_directory_permissions(parent)
        }
        Ok(_) => Err(Error::VaultPathConflict {
            path: parent.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(Error::VaultMissing {
            path: path.to_owned(),
        }),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(super) fn ensure_existing_regular_vault_file_path(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Error::VaultMissing {
                path: path.to_owned(),
            }
        } else {
            Error::Io(error)
        }
    })?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(Error::VaultPathConflict {
            path: path.to_owned(),
        })
    }
}

pub(super) fn vault_file_exists_or_conflicts(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(Error::VaultPathConflict {
            path: path.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(super) fn ensure_replaceable_vault_file_path(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(Error::VaultPathConflict {
            path: path.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(super) fn validate_vault(vault: &VaultFile) -> Result<(), Error> {
    if vault.version != VAULT_VERSION {
        return Err(Error::UnsupportedVaultVersion {
            version: vault.version,
        });
    }
    validate_vault_id(vault.vault_id.as_str())?;
    vault.kdf.params()?;
    vault.kdf.salt()?;
    validate_encrypted_secret_envelope(vault.password_check.as_str())?;
    for (name, entry) in &vault.encrypted_env {
        EnvVarName::new(name)?;
        if entry.version != ENCRYPTED_ENTRY_VERSION {
            return Err(Error::UnsupportedEncryptedEntryVersion {
                version: entry.version,
            });
        }
        validate_encrypted_secret_envelope(entry.ciphertext.as_str())?;
    }
    Ok(())
}

pub(super) fn validate_encrypted_secret_envelope(encoded: &str) -> Result<(), Error> {
    let _ = Base64Url::<Encrypted<SecretBytes>>::parse_str(encoded)?.decode()?;
    Ok(())
}

pub(super) fn validate_vault_id(vault_id: &str) -> Result<(), Error> {
    let bytes = Base64Url::<PublicBytes>::parse_str(vault_id)?
        .decode()?
        .into_bytes();
    if bytes.len() != VAULT_ID_RANDOM_BYTES {
        return Err(Error::InvalidVaultIdLength {
            actual: bytes.len(),
        });
    }
    Ok(())
}

pub(super) fn write_vault_atomically(path: &Path, vault: &VaultFile) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() {
        ensure_vault_directory(parent)?;
    }
    ensure_replaceable_vault_file_path(path)?;
    let mut options = AtomicWriteFile::options();
    configure_atomic_vault_file_options(&mut options);
    let mut file = options.open(path).map_err(Error::Io)?;
    serde_json::to_writer_pretty(&mut file, vault).map_err(Error::Json)?;
    file.write_all(b"\n").map_err(Error::Io)?;
    file.commit().map_err(Error::Io)?;
    ensure_restrictive_file_permissions(path)
}

pub(super) fn configure_atomic_vault_file_options(options: &mut atomic_write_file::OpenOptions) {
    #[cfg(unix)]
    {
        options.preserve_mode(false);
        options.mode(VAULT_FILE_MODE);
    }
}

pub(super) fn derive_vault_keyset(
    vault: &VaultFile,
    password: &SecretBytes,
) -> Result<crate::crypto::Keyset, Error> {
    let key =
        derive_argon2id_key32_from_password(password, &vault.kdf.salt()?, vault.kdf.params()?)?;
    derive_keyset_from_latest_first_keys([key], LOCAL_ENV_VAULT_KEYSET_PURPOSE).map_err(Error::from)
}

pub(super) fn unlock_vault_keyset(
    vault: &VaultFile,
    password: &SecretBytes,
) -> Result<crate::crypto::Keyset, Error> {
    let keyset = derive_vault_keyset(vault, password)?;
    let encrypted =
        Base64Url::<Encrypted<SecretBytes>>::parse_str(vault.password_check.as_str())?.decode()?;
    let decrypted = decrypt(&keyset, &encrypted, &password_check_associated_data(vault))
        .map_err(|_| Error::PasswordRejected)?;
    if decrypted.expose_secret() != PASSWORD_CHECK_PLAINTEXT {
        return Err(Error::PasswordRejected);
    }
    Ok(keyset)
}

pub(super) fn entry_associated_data(
    vault: &VaultFile,
    name: &EnvVarName,
    entry: &EncryptedEnvEntry,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        LOCAL_ENV_VAULT_ENTRY_ASSOCIATED_DATA_DOMAIN.len()
            + vault.vault_id.len()
            + name.as_str().len()
            + 32,
    );
    push_ad_part(&mut out, LOCAL_ENV_VAULT_ENTRY_ASSOCIATED_DATA_DOMAIN);
    out.extend_from_slice(&vault.version.to_be_bytes());
    push_ad_part(&mut out, vault.vault_id.as_bytes());
    push_ad_part(&mut out, name.as_str().as_bytes());
    out.extend_from_slice(&entry.version.to_be_bytes());
    out
}

pub(super) fn password_check_associated_data(vault: &VaultFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        LOCAL_ENV_VAULT_PASSWORD_CHECK_ASSOCIATED_DATA_DOMAIN.len() + vault.vault_id.len() + 16,
    );
    push_ad_part(
        &mut out,
        LOCAL_ENV_VAULT_PASSWORD_CHECK_ASSOCIATED_DATA_DOMAIN,
    );
    out.extend_from_slice(&vault.version.to_be_bytes());
    push_ad_part(&mut out, vault.vault_id.as_bytes());
    out
}

pub(super) fn push_ad_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
    out.extend_from_slice(part);
}

pub(super) fn ensure_vault_directory_layout(vault_dir: &Path) -> Result<(), Error> {
    ensure_vault_directory(vault_dir)?;
    ensure_vault_gitignore(vault_dir)
}

pub(super) fn ensure_vault_directory(vault_dir: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(vault_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            ensure_restrictive_directory_permissions(vault_dir)
        }
        Ok(_) => Err(Error::VaultPathConflict {
            path: vault_dir.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_vault_directory(vault_dir),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(super) fn create_vault_directory(vault_dir: &Path) -> Result<(), Error> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    configure_new_restricted_directory_options(&mut builder);
    builder.create(vault_dir).map_err(Error::Io)?;
    ensure_restrictive_directory_permissions(vault_dir)
}

pub(super) fn configure_new_restricted_directory_options(builder: &mut fs::DirBuilder) {
    #[cfg(unix)]
    {
        builder.mode(VAULT_DIR_MODE);
    }
}

pub(super) fn ensure_vault_gitignore(vault_dir: &Path) -> Result<(), Error> {
    let gitignore_path = vault_dir.join(".gitignore");
    match fs::symlink_metadata(&gitignore_path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(Error::VaultPathConflict {
                path: gitignore_path,
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return write_new_vault_gitignore(&gitignore_path);
        }
        Err(error) => return Err(Error::Io(error)),
    }
    match fs::read_to_string(&gitignore_path) {
        Ok(existing) if existing == VAULT_GITIGNORE_CONTENT => {
            ensure_restrictive_file_permissions(&gitignore_path)
        }
        Ok(_) => Err(Error::VaultPathConflict {
            path: gitignore_path,
        }),
        Err(error) => Err(Error::Io(error)),
    }
}

pub(super) fn write_new_vault_gitignore(path: &Path) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_new_restricted_file_options(&mut options);
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(VAULT_GITIGNORE_CONTENT.as_bytes())
                .map_err(Error::Io)?;
            file.sync_all().map_err(Error::Io)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure_vault_gitignore(path.parent().unwrap_or_else(|| Path::new(".")))
        }
        Err(error) => Err(Error::Io(error)),
    }
}

pub(super) fn configure_new_restricted_file_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(VAULT_FILE_MODE);
    }
}

pub(super) fn ensure_restrictive_directory_permissions(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        set_mode_if_needed(path, VAULT_DIR_MODE)?;
    }
    Ok(())
}

pub(super) fn ensure_restrictive_file_permissions(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        set_mode_if_needed(path, VAULT_FILE_MODE)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn set_mode_if_needed(path: &Path, mode: u32) -> Result<(), Error> {
    let metadata = fs::metadata(path).map_err(Error::Io)?;
    let current = metadata.permissions().mode() & 0o777;
    if current != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(Error::Io)?;
    }
    Ok(())
}
