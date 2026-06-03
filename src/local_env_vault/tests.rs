use std::collections::VecDeque;

use super::*;

const APP_API_KEY: &str = "APP_API_KEY";
const APP_API_SECRET: &str = "APP_API_SECRET";
const APP_ONLY: &str = "APP_ONLY";
const CURRENT_VALUE: &str = "CURRENT_VALUE";
const EMPTY_VALUE: &str = "EMPTY_VALUE";
const FILLED_VALUE: &str = "FILLED_VALUE";
const FIRST_SECRET: &str = "FIRST_SECRET";
const INVALID_ENV_VAR: &str = "invalid_env_var";
const SECOND_SECRET: &str = "SECOND_SECRET";
const SHARED_SECRET: &str = "SHARED_SECRET";
const STALE_VALUE: &str = "STALE_VALUE";
const WORKER_SECRET: &str = "WORKER_SECRET";

struct FakeTerminal {
    secrets: VecDeque<SecretBytes>,
    line_inputs: VecDeque<String>,
    lines: Vec<String>,
}

impl FakeTerminal {
    fn new(secret_inputs: &[&[u8]], line_inputs: &[&str]) -> Self {
        Self {
            secrets: secret_inputs
                .iter()
                .map(|input| SecretBytes::try_from(*input).expect("test secret"))
                .collect(),
            line_inputs: line_inputs.iter().map(|input| input.to_string()).collect(),
            lines: Vec::new(),
        }
    }
}

impl VaultTerminal for FakeTerminal {
    fn prompt_hidden_secret(&mut self, _prompt: &str) -> Result<SecretBytes, Error> {
        Ok(self
            .secrets
            .pop_front()
            .expect("expected test secret prompt"))
    }

    fn select_menu_index(
        &mut self,
        prompt: &str,
        _help_message: &str,
        options: &[String],
    ) -> Result<usize, Error> {
        self.lines.push(prompt.to_owned());
        for option in options {
            self.lines.push(format!("  {option}"));
        }
        let choice = self
            .line_inputs
            .pop_front()
            .expect("expected test menu choice");
        Ok(fake_menu_choice_to_index(choice.trim(), options.len()))
    }

    fn write_line(&mut self, line: &str) -> Result<(), Error> {
        self.lines.push(line.to_owned());
        Ok(())
    }
}

fn fake_menu_choice_to_index(choice: &str, option_count: usize) -> usize {
    assert_ne!(option_count, 0, "test menu must have at least one option");
    if choice.is_empty() || choice == "0" {
        return option_count - 1;
    }
    let raw_index = choice.parse::<usize>().expect("test menu choice");
    let index = raw_index.checked_sub(1).expect("one-based test choice");
    assert!(index < option_count, "test menu choice out of range");
    index
}

#[derive(Default)]
struct FakeChildProcessRunner {
    calls: Vec<FakeChildProcessCall>,
}

struct FakeChildProcessCall {
    command: Vec<OsString>,
    projected_env: BTreeMap<EnvVarName, Vec<u8>>,
}

impl ChildProcessRunner for FakeChildProcessRunner {
    fn run_child_command(
        &mut self,
        command: Vec<OsString>,
        projected_env: BTreeMap<EnvVarName, SecretBytes>,
    ) -> Result<(), Error> {
        self.calls.push(FakeChildProcessCall {
            command,
            projected_env: projected_env
                .into_iter()
                .map(|(name, value)| (name, value.expose_secret().to_vec()))
                .collect(),
        });
        Ok(())
    }
}

#[test]
fn env_var_names_use_strict_ascii_env_shape() {
    assert_eq!(
        EnvVarName::new("APP_API_KEY").unwrap().as_str(),
        "APP_API_KEY"
    );
    assert!(matches!(
        EnvVarName::new("app_api_key"),
        Err(Error::InvalidEnvVarName { .. })
    ));
    assert!(matches!(
        EnvVarName::new("1APP_API_KEY"),
        Err(Error::InvalidEnvVarName { .. })
    ));
    assert!(matches!(
        EnvVarName::new("APP-API-KEY"),
        Err(Error::InvalidEnvVarName { .. })
    ));
}

#[test]
fn profiles_validate_names_and_required_values() {
    let profile =
        Profile::new("app_1", [APP_API_KEY, APP_API_KEY, APP_API_SECRET]).expect("profile");

    assert_eq!(profile.name(), "app_1");
    assert_eq!(profile.required_names().count(), 2);
    assert!(matches!(
        Profile::new("App", [APP_API_KEY]),
        Err(Error::InvalidProfileName { .. })
    ));
    assert!(matches!(
        Profile::new("empty", std::iter::empty::<&str>()),
        Err(Error::ProfileRequiresNoValues { .. })
    ));
    assert!(matches!(
        Profile::new("app", [INVALID_ENV_VAR]),
        Err(Error::InvalidEnvVarName { .. })
    ));
}

#[test]
fn runner_rejects_empty_profile_inventory() {
    assert!(matches!(
        VaultRunnerCore::with_terminal(std::iter::empty::<Profile>(), FakeTerminal::new(&[], &[]),),
        Err(Error::RunnerRequiresAtLeastOneProfile)
    ));
}

#[test]
fn vault_dir_resolves_from_absolute_root_and_relative_parent_path() {
    let root = std::env::temp_dir().join("env-wrapper-root");

    assert_eq!(
        vault_dir_from_root_and_relative_parent(&root, Path::new(".")).expect("vault dir"),
        root.join(VAULT_DIR_NAME)
    );
    assert_eq!(
        vault_dir_from_root_and_relative_parent(&root, Path::new("local/private"))
            .expect("vault dir"),
        root.join("local/private").join(VAULT_DIR_NAME)
    );
    assert!(matches!(
        vault_dir_from_root_and_relative_parent(Path::new("relative-root"), Path::new(".")),
        Err(Error::VaultRootMustBeAbsolute { path }) if path == PathBuf::from("relative-root")
    ));
    assert!(matches!(
        vault_dir_from_root_and_relative_parent(&root, Path::new("")),
        Err(Error::VaultParentPathRelativeToRootMustNotBeEmpty)
    ));
    assert!(matches!(
        vault_dir_from_root_and_relative_parent(&root, &root),
        Err(Error::VaultParentPathMustBeRelative { path }) if path == root
    ));
    assert!(matches!(
        vault_dir_from_root_and_relative_parent(&root, Path::new("../outside")),
        Err(Error::VaultParentPathMustNotTraverseParent { path }) if path == PathBuf::from("../outside")
    ));
}

#[test]
fn configure_initializes_sets_checks_and_projects_without_plaintext_storage() {
    let dir = temp_vault_dir();
    let profile = Profile::new("app", [APP_API_KEY]).expect("profile");
    let mut config_runner = VaultRunnerCore::with_terminal(
        [profile],
        FakeTerminal::new(
            &[b"operator-password", b"operator-password", b"secret-value"],
            &["1", "1", "0", "0"],
        ),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    config_runner.password_kdf_params = minimal_test_kdf_params();

    config_runner
        .run_from_args(["env", "configure"])
        .expect("config");

    let mut check_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    check_runner
        .run_from_args(["env", "validate", "app"])
        .expect("profile check");

    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let project_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    let projected = project_runner
        .project_profile_env("app", &password)
        .expect("projected env");
    assert_eq!(
        projected
            .get(&EnvVarName::new("APP_API_KEY").expect("name"))
            .expect("projected secret")
            .expose_secret(),
        b"secret-value"
    );

    let vault_json = fs::read_to_string(dir.join(VAULT_FILE_NAME)).expect("vault json");
    assert!(!vault_json.contains("secret-value"));
    assert!(!vault_json.contains("operator-password"));
    assert_eq!(
        fs::read_to_string(dir.join(".gitignore")).expect("gitignore"),
        VAULT_GITIGNORE_CONTENT
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[cfg(unix)]
#[test]
fn config_creates_vault_directory_and_files_with_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_vault_dir();
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );

    runner.run_from_args(["env", "configure"]).expect("config");

    assert_eq!(
        fs::metadata(&dir)
            .expect("vault dir metadata")
            .permissions()
            .mode()
            & 0o777,
        VAULT_DIR_MODE
    );
    assert_eq!(
        fs::metadata(dir.join(VAULT_FILE_NAME))
            .expect("vault metadata")
            .permissions()
            .mode()
            & 0o777,
        VAULT_FILE_MODE
    );
    assert_eq!(
        fs::metadata(dir.join(".gitignore"))
            .expect("gitignore metadata")
            .permissions()
            .mode()
            & 0o777,
        VAULT_FILE_MODE
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[cfg(unix)]
#[test]
fn validate_restricts_existing_vault_directory_and_file_permissions_before_reading() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_vault_dir();
    write_vault_with_current_and_stale_values(&dir);
    let vault_path = dir.join(VAULT_FILE_NAME);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("loosen dir");
    fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o644)).expect("loosen vault");

    let mut runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [CURRENT_VALUE]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    runner
        .run_from_args(["env", "validate", "app"])
        .expect("validate");

    assert_eq!(
        fs::metadata(&dir)
            .expect("vault dir metadata")
            .permissions()
            .mode()
            & 0o777,
        VAULT_DIR_MODE
    );
    assert_eq!(
        fs::metadata(&vault_path)
            .expect("vault metadata")
            .permissions()
            .mode()
            & 0o777,
        VAULT_FILE_MODE
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_rejects_conflicting_vault_gitignore_before_writing_values() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create vault dir");
    let gitignore_path = dir.join(".gitignore");
    fs::write(&gitignore_path, "vault.json\n").expect("write conflicting gitignore");

    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    assert!(matches!(
        runner.run_from_args(["env", "configure"]),
        Err(Error::VaultPathConflict { path }) if path == gitignore_path
    ));
    assert_eq!(
        fs::read_to_string(&gitignore_path).expect("gitignore"),
        "vault.json\n"
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_rejects_fixed_vault_directory_path_conflict() {
    let dir = temp_vault_dir();
    fs::write(&dir, "not a directory").expect("write conflicting file");
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );

    assert!(matches!(
        runner.run_from_args(["env", "configure"]),
        Err(Error::VaultPathConflict { path }) if path == dir
    ));

    fs::remove_file(dir).expect("remove temp vault file");
}

#[test]
fn config_rejects_fixed_vault_file_path_conflict_before_password_prompt() {
    let dir = temp_vault_dir();
    fs::create_dir_all(dir.join(VAULT_FILE_NAME)).expect("create conflicting directory");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let mut runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    runner.password_kdf_params = minimal_test_kdf_params();

    assert!(matches!(
        runner.run_from_args(["env", "configure"]),
        Err(Error::VaultPathConflict { path }) if path == vault_path
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn existing_config_rejects_malformed_vault_before_password_prompt() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create vault dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    fs::write(&vault_path, br#"{"version":1,"encrypted_env":}"#).expect("write malformed vault");
    let mut runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    runner.password_kdf_params = minimal_test_kdf_params();

    assert!(matches!(
        runner.run_from_args(["env", "configure"]),
        Err(Error::Json(_))
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn existing_config_rejects_wrong_password_before_menu_or_writes() {
    let dir = temp_vault_dir();
    let profile = Profile::new("app", [APP_API_KEY]).expect("profile");
    let mut init_runner = VaultRunnerCore::with_terminal(
        [profile],
        FakeTerminal::new(&[b"operator-password", b"operator-password"], &["0"]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    init_runner.password_kdf_params = minimal_test_kdf_params();

    init_runner
        .run_from_args(["env", "configure"])
        .expect("init config");

    let mut runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[b"wrong-password"], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        runner.run_from_args(["env", "configure"]),
        Err(Error::PasswordRejected)
    ));

    let vault = read_vault(&dir.join(VAULT_FILE_NAME)).expect("vault");
    assert!(!vault.encrypted_env.contains_key("APP_API_KEY"));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn ciphertext_copied_between_secret_names_is_rejected() {
    let dir = temp_vault_dir();
    let profile = Profile::new("app", [FIRST_SECRET, SECOND_SECRET]).expect("profile");
    let mut runner = configured_runner(
        dir.clone(),
        [profile],
        &[
            b"operator-password",
            b"operator-password",
            b"first-value",
            b"second-value",
        ],
        &["1", "1", "2", "0", "0"],
    );

    runner.run_from_args(["env", "configure"]).expect("config");

    let vault_path = dir.join(VAULT_FILE_NAME);
    let mut vault = read_vault(&vault_path).expect("vault");
    let first_entry = vault
        .encrypted_env
        .get("FIRST_SECRET")
        .expect("first entry")
        .clone();
    vault
        .encrypted_env
        .insert("SECOND_SECRET".to_owned(), first_entry);
    write_vault_atomically(&vault_path, &vault).expect("write tampered vault");

    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    assert!(matches!(
        runner.project_profile_env("app", &password),
        Err(Error::Crypto(crate::crypto::Error::DecryptionFailed))
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_lock_blocks_second_writer_and_drop_releases() {
    let dir = temp_vault_dir();
    let first = acquire_vault_lock(&dir).expect("first lock");

    assert!(matches!(
        acquire_vault_lock(&dir),
        Err(Error::VaultLocked { .. })
    ));

    drop(first);
    let third = acquire_vault_lock(&dir).expect("third lock");
    drop(third);

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_lock_loss_blocks_secret_write() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create vault dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let password = SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    let keyset = unlock_vault_keyset(&vault, &password).expect("keyset");
    let lock = acquire_vault_lock(&dir).expect("lock");
    lock.mark_lock_lost_for_test();
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"secret-value"],
        &[],
    );
    let name = EnvVarName::new(APP_API_KEY).expect("name");

    assert!(matches!(
        runner.write_one_value(&vault_path, &mut vault, &keyset, &name, &lock),
        Err(Error::VaultLockLost { .. })
    ));
    assert!(!vault_path.exists());

    drop(lock);
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn read_vault_reports_missing_vault_without_path_exists_race() {
    let dir = temp_vault_dir();
    let vault_path = dir.join(VAULT_FILE_NAME);

    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::VaultMissing { path }) if path == vault_path
    ));
}

#[test]
fn read_vault_rejects_oversized_vault_file_before_json_parsing() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    fs::File::create(&vault_path)
        .expect("create vault")
        .set_len(MAX_VAULT_FILE_BYTES + 1)
        .expect("set vault length");

    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::VaultFileTooLarge { actual, max })
            if actual == MAX_VAULT_FILE_BYTES + 1 && max == MAX_VAULT_FILE_BYTES
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn atomic_vault_replace_replaces_existing_vault_file() {
    let dir = temp_vault_dir();
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let first_name = EnvVarName::new("FIRST_SECRET").expect("name");
    let second_name = EnvVarName::new("SECOND_SECRET").expect("name");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    let keyset = unlock_vault_keyset(&vault, &password).expect("keyset");

    vault
        .set_encrypted_value(
            &keyset,
            &first_name,
            &SecretBytes::try_from(b"first".as_slice()).expect("secret"),
        )
        .expect("set first secret");
    write_vault_atomically(&vault_path, &vault).expect("first write");
    vault
        .set_encrypted_value(
            &keyset,
            &second_name,
            &SecretBytes::try_from(b"second".as_slice()).expect("secret"),
        )
        .expect("set second secret");
    write_vault_atomically(&vault_path, &vault).expect("second write");

    let written = read_vault(&vault_path).expect("written vault");

    assert!(written.encrypted_env.contains_key(first_name.as_str()));
    assert!(written.encrypted_env.contains_key(second_name.as_str()));
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_validation_rejects_malformed_stored_env_names() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    let keyset = unlock_vault_keyset(&vault, &password).expect("keyset");
    let valid_name = EnvVarName::new("APP_API_KEY").expect("name");
    vault
        .set_encrypted_value(
            &keyset,
            &valid_name,
            &SecretBytes::try_from(b"secret".as_slice()).unwrap(),
        )
        .expect("set secret");
    let entry = vault
        .encrypted_env
        .remove(valid_name.as_str())
        .expect("entry");
    vault.encrypted_env.insert("app_api_key".to_owned(), entry);
    write_vault_json_direct(&vault_path, &vault);

    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::InvalidEnvVarName { name }) if name == "app_api_key"
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_validation_rejects_wrong_vault_id_length() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    vault.vault_id = encode_public_bytes(PublicBytes::try_from(b"short".as_slice()).unwrap());
    write_vault_json_direct(&vault_path, &vault);

    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::InvalidVaultIdLength { actual: 5 })
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_validation_rejects_stored_kdf_work_factor_above_local_bounds() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");

    vault.kdf.memory_cost_kib = STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB + 1;
    write_vault_json_direct(&vault_path, &vault);
    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::PasswordKdfMemoryCostTooLarge { actual, max })
            if actual == STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB + 1
                && max == STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB
    ));

    vault.kdf.memory_cost_kib = crate::crypto::PASSWORD_KDF_MIN_MEMORY_COST_KIB;
    vault.kdf.iterations = STORED_PASSWORD_KDF_MAX_ITERATIONS + 1;
    write_vault_json_direct(&vault_path, &vault);
    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::PasswordKdfIterationsTooMany { actual, max })
            if actual == STORED_PASSWORD_KDF_MAX_ITERATIONS + 1
                && max == STORED_PASSWORD_KDF_MAX_ITERATIONS
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_creation_rejects_local_kdf_work_factor_above_read_bounds() {
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let memory_heavy_params = PasswordKdfParams::new(
        STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB + 1,
        crate::crypto::PASSWORD_KDF_MIN_ITERATIONS,
        1,
    )
    .expect("params");
    assert!(matches!(
        VaultFile::new(&password, memory_heavy_params),
        Err(Error::PasswordKdfMemoryCostTooLarge { actual, max })
            if actual == STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB + 1
                && max == STORED_PASSWORD_KDF_MAX_MEMORY_COST_KIB
    ));

    let iteration_heavy_params = PasswordKdfParams::new(
        crate::crypto::PASSWORD_KDF_MIN_MEMORY_COST_KIB,
        STORED_PASSWORD_KDF_MAX_ITERATIONS + 1,
        1,
    )
    .expect("params");
    assert!(matches!(
        VaultFile::new(&password, iteration_heavy_params),
        Err(Error::PasswordKdfIterationsTooMany { actual, max })
            if actual == STORED_PASSWORD_KDF_MAX_ITERATIONS + 1
                && max == STORED_PASSWORD_KDF_MAX_ITERATIONS
    ));
}

#[test]
fn vault_validation_rejects_malformed_ciphertext_without_echoing_it() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    vault.encrypted_env.insert(
        "APP_API_KEY".to_owned(),
        EncryptedEnvEntry {
            version: ENCRYPTED_ENTRY_VERSION,
            updated_at_unix_seconds: unix_now().expect("now"),
            ciphertext: "secret-value".to_owned(),
        },
    );
    write_vault_json_direct(&vault_path, &vault);

    let error = read_vault(&vault_path).expect_err("malformed ciphertext rejected");
    assert_error_text_does_not_contain(&error, "secret-value");

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn json_and_password_errors_do_not_echo_secret_inputs() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(VAULT_FILE_NAME);
    fs::write(
        &vault_path,
        br#"{"version":1,"secret":"secret-value","encrypted_env":}"#,
    )
    .expect("write malformed json");
    let json_error = read_vault(&vault_path).expect_err("json rejected");
    assert_error_text_does_not_contain(&json_error, "secret-value");
    fs::remove_file(&vault_path).expect("remove malformed vault");

    let mut init_runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner
        .run_from_args(["env", "configure"])
        .expect("init config");
    let mut wrong_password_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[b"secret-wrong-password"], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    let password_error = wrong_password_runner
        .run_from_args(["env", "configure"])
        .expect_err("wrong password rejected");
    assert_error_text_does_not_contain(&password_error, "secret-wrong-password");

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn parser_rejects_extra_args_missing_child_command_and_unknown_profile() {
    let dir = temp_vault_dir();
    let mut init_runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner
        .run_from_args(["env", "configure"])
        .expect("init");

    let mut extra_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        extra_runner.run_from_args(["env", "validate", "app", "extra"]),
        Err(Error::InvalidCommandUsage)
    ));

    let mut empty_child_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        empty_child_runner.run_from_args(["env", "run", "app", "--"]),
        Err(Error::InvalidCommandUsage)
    ));

    let mut bare_profile_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        bare_profile_runner.run_from_args(["env", "app"]),
        Err(Error::InvalidCommandUsage)
    ));

    let mut unknown_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        unknown_runner.run_from_args(["env", "validate", "worker"]),
        Err(Error::UnknownProfile { .. })
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn unknown_profile_is_rejected_before_vault_io_or_password_prompt() {
    let dir = temp_vault_dir();
    let mut validate_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        validate_runner.run_from_args(["env", "validate", "worker"]),
        Err(Error::UnknownProfile { name }) if name == "worker"
    ));
    assert!(!dir.exists());

    let mut run_runner = VaultRunnerCore::with_terminal_and_child_process(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
        FakeChildProcessRunner::default(),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        run_runner.run_from_args(["env", "run", "worker", "--", "cargo"]),
        Err(Error::UnknownProfile { name }) if name == "worker"
    ));
    assert!(!dir.exists());
}

#[test]
fn config_profile_review_reports_missing_values() {
    let dir = temp_vault_dir();
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["2", "1", "0", "0"],
    );

    runner
        .run_from_args(["env", "configure"])
        .expect("config stays open");

    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "  APP_API_KEY - missing")
    );
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_value_menu_reports_profile_required_values_and_profile_counts() {
    let dir = temp_vault_dir();
    let mut runner = configured_runner(
        dir.clone(),
        [
            Profile::new("app", [APP_ONLY, SHARED_SECRET]).expect("profile"),
            Profile::new("worker", [SHARED_SECRET]).expect("profile"),
        ],
        &[b"operator-password", b"operator-password"],
        &["1", "0", "0"],
    );

    runner
        .run_from_args(["env", "configure"])
        .expect("config stays open");

    assert!(runner.terminal.lines.iter().any(|line| {
        line.contains("APP_ONLY")
            && line.contains("missing")
            && line.contains("required by 1 profile")
    }));
    assert!(runner.terminal.lines.iter().any(|line| {
        line.contains("SHARED_SECRET")
            && line.contains("missing")
            && line.contains("required by 2 profiles")
    }));
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_store_feedback_reports_empty_or_non_empty_without_exact_length() {
    let dir = temp_vault_dir();
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [EMPTY_VALUE, FILLED_VALUE]).expect("profile")],
        &[b"operator-password", b"operator-password", b"", b"filled"],
        &["1", "1", "2", "0", "0"],
    );

    runner.run_from_args(["env", "configure"]).expect("config");

    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "Stored EMPTY_VALUE (0 bytes)")
    );
    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "Stored FILLED_VALUE (1+ bytes)")
    );
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_keeps_values_not_required_by_profiles_until_explicit_cleanup() {
    let dir = temp_vault_dir();
    write_vault_with_current_and_stale_values(&dir);

    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [CURRENT_VALUE]).expect("profile")],
        &[b"operator-password"],
        &["0"],
    );
    runner.run_from_args(["env", "configure"]).expect("config");

    let vault = read_vault(&dir.join(VAULT_FILE_NAME)).expect("vault");
    assert!(vault.encrypted_env.contains_key("CURRENT_VALUE"));
    assert!(vault.encrypted_env.contains_key("STALE_VALUE"));
    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line.contains("Remove values not required by profiles (1 value)"))
    );
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_removes_values_not_required_by_profiles_only_from_explicit_cleanup_menu() {
    let dir = temp_vault_dir();
    write_vault_with_current_and_stale_values(&dir);

    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [CURRENT_VALUE]).expect("profile")],
        &[b"operator-password"],
        &["3", "1", "0"],
    );
    runner.run_from_args(["env", "configure"]).expect("config");

    let vault = read_vault(&dir.join(VAULT_FILE_NAME)).expect("vault");
    assert!(vault.encrypted_env.contains_key("CURRENT_VALUE"));
    assert!(!vault.encrypted_env.contains_key("STALE_VALUE"));
    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "Not required STALE_VALUE")
    );
    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "Removed 1 stale value")
    );
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn validate_command_still_fails_when_required_names_are_missing() {
    let dir = temp_vault_dir();
    let mut init_runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner
        .run_from_args(["env", "configure"])
        .expect("init");

    let mut check_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());

    assert!(matches!(
        check_runner.run_from_args(["env", "validate", "app"]),
        Err(Error::MissingProfileValues)
    ));
    assert!(
        check_runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "Missing APP_API_KEY")
    );
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn run_profile_rejects_missing_values_before_password_prompt() {
    let dir = temp_vault_dir();
    let mut init_runner = configured_runner(
        dir.clone(),
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner
        .run_from_args(["env", "configure"])
        .expect("init");

    let mut runner = VaultRunnerCore::with_terminal_and_child_process(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[], &[]),
        FakeChildProcessRunner::default(),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());

    assert!(matches!(
        runner.run_from_args(["env", "run", "app", "--", "cargo"]),
        Err(Error::MissingProfileValues)
    ));
    assert!(runner.child_process.calls.is_empty());

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn child_command_builder_preserves_program_args_and_overlays_projected_env() {
    let mut projected = BTreeMap::new();
    projected.insert(
        EnvVarName::new("APP_API_KEY").expect("name"),
        SecretBytes::try_from(b"app-key".as_slice()).expect("secret"),
    );

    let command = build_child_command_with_projected_env(
        vec![OsString::from("program"), OsString::from("arg")],
        projected,
    )
    .expect("command");

    assert_eq!(command.get_program(), OsStr::new("program"));
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        vec![OsStr::new("arg")]
    );
    let projected_value = command
        .get_envs()
        .find_map(|(name, value)| {
            if name == OsStr::new("APP_API_KEY") {
                value
            } else {
                None
            }
        })
        .expect("projected env value");
    assert_eq!(projected_value, OsStr::new("app-key"));
}

#[test]
fn child_command_builder_rejects_non_utf8_projected_values_before_spawn() {
    let mut projected = BTreeMap::new();
    projected.insert(
        EnvVarName::new("APP_API_KEY").expect("name"),
        SecretBytes::try_from(vec![0xff]).expect("secret"),
    );

    assert!(matches!(
        build_child_command_with_projected_env(vec![OsString::from("program")], projected),
        Err(Error::SecretValueNotUtf8 { name }) if name.as_str() == "APP_API_KEY"
    ));
}

#[test]
fn profile_run_projects_only_required_env_into_child_process() {
    let dir = temp_vault_dir();
    let mut config_runner = configured_runner(
        dir.clone(),
        [
            Profile::new("app", [APP_API_KEY]).expect("profile"),
            Profile::new("worker", [WORKER_SECRET]).expect("profile"),
        ],
        &[
            b"operator-password",
            b"operator-password",
            b"app-key",
            b"worker-secret",
        ],
        &["1", "1", "2", "0", "0"],
    );
    config_runner
        .run_from_args(["env", "configure"])
        .expect("config");

    let mut runner = VaultRunnerCore::with_terminal_and_child_process(
        [Profile::new("app", [APP_API_KEY]).expect("profile")],
        FakeTerminal::new(&[b"operator-password"], &[]),
        FakeChildProcessRunner::default(),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());

    runner
        .run_from_args(["env", "run", "app", "--", "cargo", "run", "-p", "app"])
        .expect("run profile");

    assert_eq!(runner.child_process.calls.len(), 1);
    let call = &runner.child_process.calls[0];
    assert_eq!(
        call.command,
        vec![
            OsString::from("cargo"),
            OsString::from("run"),
            OsString::from("-p"),
            OsString::from("app"),
        ]
    );
    assert_eq!(
        call.projected_env
            .get(&EnvVarName::new("APP_API_KEY").expect("name"))
            .expect("app key"),
        b"app-key"
    );
    assert!(
        !call
            .projected_env
            .contains_key(&EnvVarName::new("WORKER_SECRET").expect("name"))
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

fn configured_runner<const P: usize>(
    dir: PathBuf,
    profiles: [Profile; P],
    secret_inputs: &[&[u8]],
    line_inputs: &[&str],
) -> VaultRunnerCore<FakeTerminal, SystemChildProcessRunner> {
    let mut runner =
        VaultRunnerCore::with_terminal(profiles, FakeTerminal::new(secret_inputs, line_inputs))
            .expect("runner")
            .with_vault_dir(dir);
    runner.password_kdf_params = minimal_test_kdf_params();
    runner
}

fn write_vault_with_current_and_stale_values(dir: &Path) {
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    let keyset = unlock_vault_keyset(&vault, &password).expect("keyset");
    for (name, value) in [
        (CURRENT_VALUE, b"current".as_slice()),
        (STALE_VALUE, b"stale".as_slice()),
    ] {
        vault
            .set_encrypted_value(
                &keyset,
                &EnvVarName::new(name).expect("name"),
                &SecretBytes::try_from(value).expect("secret"),
            )
            .expect("set value");
    }
    write_vault_atomically(&dir.join(VAULT_FILE_NAME), &vault).expect("write vault");
}

fn minimal_test_kdf_params() -> PasswordKdfParams {
    PasswordKdfParams::new(
        crate::crypto::PASSWORD_KDF_MIN_MEMORY_COST_KIB,
        crate::crypto::PASSWORD_KDF_MIN_ITERATIONS,
        1,
    )
    .expect("test params")
}

fn write_vault_json_direct(path: &Path, vault: &VaultFile) {
    fs::write(
        path,
        serde_json::to_vec_pretty(vault).expect("serialize vault"),
    )
    .expect("write vault");
}

fn assert_error_text_does_not_contain(error: &Error, forbidden: &str) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(
        !display.contains(forbidden),
        "display leaked forbidden text: {display}"
    );
    assert!(
        !debug.contains(forbidden),
        "debug leaked forbidden text: {debug}"
    );
}

fn temp_vault_dir() -> PathBuf {
    let unique = format!(
        "paranoid-local-env-vault-test-{}-{}",
        std::process::id(),
        encode_public_bytes(random_public_bytes(8).expect("random"))
    );
    std::env::temp_dir().join(unique)
}
