use std::collections::VecDeque;

use super::*;

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
    fn prompt_line(&mut self, _prompt: &str) -> Result<String, Error> {
        Ok(self
            .line_inputs
            .pop_front()
            .expect("expected test line prompt"))
    }

    fn prompt_hidden_secret(&mut self, _prompt: &str) -> Result<SecretBytes, Error> {
        Ok(self
            .secrets
            .pop_front()
            .expect("expected test secret prompt"))
    }

    fn write_line(&mut self, line: &str) -> Result<(), Error> {
        self.lines.push(line.to_owned());
        Ok(())
    }
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
fn profiles_validate_names_and_required_env_vars() {
    let profile =
        Profile::new("app_1", ["APP_API_KEY", "APP_API_KEY", "APP_API_SECRET"]).expect("profile");

    assert_eq!(profile.name(), "app_1");
    assert_eq!(profile.required_names().count(), 2);
    assert!(matches!(
        Profile::new("App", ["APP_API_KEY"]),
        Err(Error::InvalidProfileName { .. })
    ));
    assert!(matches!(
        Profile::new("empty", std::iter::empty::<&str>()),
        Err(Error::ProfileRequiresNoEnvVars { .. })
    ));
}

#[test]
fn no_args_config_initializes_sets_checks_and_projects_without_plaintext_storage() {
    let dir = temp_vault_dir();
    let profile = Profile::new("app", ["APP_API_KEY"]).expect("profile");
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

    config_runner.run_from_args(["env"]).expect("config");

    let mut check_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    check_runner
        .run_from_args(["env", "app"])
        .expect("profile check");

    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let project_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
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

    let vault_json = fs::read_to_string(dir.join(DEFAULT_VAULT_FILE_NAME)).expect("vault json");
    assert!(!vault_json.contains("secret-value"));
    assert!(!vault_json.contains("operator-password"));
    assert_eq!(
        fs::read_to_string(dir.join(".gitignore")).expect("gitignore"),
        VAULT_GITIGNORE_CONTENT
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_repairs_vault_gitignore_before_writing_secrets() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create vault dir");
    fs::write(dir.join(".gitignore"), "vault.json\n").expect("write unsafe gitignore");

    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    runner.run_from_args(["env"]).expect("config");

    assert_eq!(
        fs::read_to_string(dir.join(".gitignore")).expect("gitignore"),
        VAULT_GITIGNORE_CONTENT
    );

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn existing_config_rejects_wrong_password_before_menu_or_writes() {
    let dir = temp_vault_dir();
    let profile = Profile::new("app", ["APP_API_KEY"]).expect("profile");
    let mut init_runner = VaultRunnerCore::with_terminal(
        [profile],
        FakeTerminal::new(&[b"operator-password", b"operator-password"], &["0"]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    init_runner.password_kdf_params = minimal_test_kdf_params();

    init_runner.run_from_args(["env"]).expect("init config");

    let mut runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[b"wrong-password"], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        runner.run_from_args(["env"]),
        Err(Error::PasswordRejected)
    ));

    let vault = read_vault(&dir.join(DEFAULT_VAULT_FILE_NAME)).expect("vault");
    assert!(!vault.encrypted_env.contains_key("APP_API_KEY"));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn ciphertext_copied_between_secret_names_is_rejected() {
    let dir = temp_vault_dir();
    let profile = Profile::new("app", ["FIRST_SECRET", "SECOND_SECRET"]).expect("profile");
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

    runner.run_from_args(["env"]).expect("config");

    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);
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
    let first_lost = Arc::new(AtomicBool::new(false));
    let first = acquire_vault_lock(&dir, &first_lost).expect("first lock");

    let second_lost = Arc::new(AtomicBool::new(false));
    assert!(matches!(
        acquire_vault_lock(&dir, &second_lost),
        Err(Error::VaultLocked { .. })
    ));

    drop(first);
    let third_lost = Arc::new(AtomicBool::new(false));
    let third = acquire_vault_lock(&dir, &third_lost).expect("third lock");
    drop(third);

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_lock_loss_blocks_secret_write() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create vault dir");
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);
    let password = SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let mut vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    let keyset = unlock_vault_keyset(&vault, &password).expect("keyset");
    let lock_lost = Arc::new(AtomicBool::new(false));
    let lock = acquire_vault_lock(&dir, &lock_lost).expect("lock");
    lock_lost.store(true, Ordering::SeqCst);
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        &[b"secret-value"],
        &[],
    );
    let name = EnvVarName::new("APP_API_KEY").expect("name");

    assert!(matches!(
        runner.write_one_secret(&vault_path, &mut vault, &keyset, &name, &lock, &lock_lost),
        Err(Error::VaultLockLost { .. })
    ));
    assert!(!vault_path.exists());

    drop(lock);
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn read_vault_reports_missing_vault_without_path_exists_race() {
    let dir = temp_vault_dir();
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);

    assert!(matches!(
        read_vault(&vault_path),
        Err(Error::VaultMissing { path }) if path == vault_path
    ));
}

#[test]
fn failed_atomic_vault_replace_removes_temporary_file() {
    let dir = temp_vault_dir();
    fs::create_dir_all(dir.join(DEFAULT_VAULT_FILE_NAME)).expect("create target directory");
    let password: SecretBytes =
        SecretBytes::try_from(b"operator-password".as_slice()).expect("password");
    let vault = VaultFile::new(&password, minimal_test_kdf_params()).expect("vault");
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);

    assert!(matches!(
        write_vault_atomically(&vault_path, &vault),
        Err(Error::Io(_))
    ));
    let leftover_tmp_files = fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".vault.json.tmp."))
        })
        .count();

    assert_eq!(leftover_tmp_files, 0);
    assert!(vault_path.is_dir());
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn vault_validation_rejects_malformed_stored_env_names() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);
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
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);
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
fn vault_validation_rejects_malformed_ciphertext_without_echoing_it() {
    let dir = temp_vault_dir();
    fs::create_dir_all(&dir).expect("create dir");
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);
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
    let vault_path = dir.join(DEFAULT_VAULT_FILE_NAME);
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
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner.run_from_args(["env"]).expect("init config");
    let mut wrong_password_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[b"secret-wrong-password"], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    let password_error = wrong_password_runner
        .run_from_args(["env"])
        .expect_err("wrong password rejected");
    assert_error_text_does_not_contain(&password_error, "secret-wrong-password");

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn parser_rejects_extra_args_missing_child_command_and_unknown_profile() {
    let dir = temp_vault_dir();
    let mut init_runner = configured_runner(
        dir.clone(),
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner.run_from_args(["env"]).expect("init");

    let mut extra_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        extra_runner.run_from_args(["env", "app", "extra"]),
        Err(Error::UnexpectedExtraArgs)
    ));

    let mut empty_child_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        empty_child_runner.run_from_args(["env", "app", "--"]),
        Err(Error::MissingChildCommand)
    ));

    let mut unknown_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());
    assert!(matches!(
        unknown_runner.run_from_args(["env", "worker"]),
        Err(Error::UnknownProfile { .. })
    ));

    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn config_profile_menu_reports_set_and_missing_profile_secret_status() {
    let dir = temp_vault_dir();
    let mut runner = configured_runner(
        dir.clone(),
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["1", "0", "0"],
    );

    runner.run_from_args(["env"]).expect("config stays open");

    assert!(
        runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "1. APP_API_KEY missing")
    );
    fs::remove_dir_all(dir).expect("remove temp vault dir");
}

#[test]
fn profile_check_command_still_fails_when_required_names_are_missing() {
    let dir = temp_vault_dir();
    let mut init_runner = configured_runner(
        dir.clone(),
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        &[b"operator-password", b"operator-password"],
        &["0"],
    );
    init_runner.run_from_args(["env"]).expect("init");

    let mut check_runner = VaultRunnerCore::with_terminal(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[], &[]),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());

    assert!(matches!(
        check_runner.run_from_args(["env", "app"]),
        Err(Error::MissingProfileSecrets)
    ));
    assert!(
        check_runner
            .terminal
            .lines
            .iter()
            .any(|line| line == "missing APP_API_KEY")
    );
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
            Profile::new("app", ["APP_API_KEY"]).expect("profile"),
            Profile::new("worker", ["WORKER_SECRET"]).expect("profile"),
        ],
        &[
            b"operator-password",
            b"operator-password",
            b"app-key",
            b"worker-secret",
        ],
        &["1", "1", "0", "2", "1", "0", "0"],
    );
    config_runner.run_from_args(["env"]).expect("config");

    let mut runner = VaultRunnerCore::with_terminal_and_child_process(
        [Profile::new("app", ["APP_API_KEY"]).expect("profile")],
        FakeTerminal::new(&[b"operator-password"], &[]),
        FakeChildProcessRunner::default(),
    )
    .expect("runner")
    .with_vault_dir(dir.clone());

    runner
        .run_from_args(["env", "app", "--", "cargo", "run", "-p", "app"])
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

fn configured_runner<const N: usize>(
    dir: PathBuf,
    profiles: [Profile; N],
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
