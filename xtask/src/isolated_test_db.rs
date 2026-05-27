use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_COMPOSE_FILE_NAME: &str = "docker-compose.test.yml";
const DEFAULT_TEST_DSN_PATTERN_PREFIX: &str = "postgres://test:test@localhost:";
const DEFAULT_TEST_DSN_PATTERN_SUFFIX: &str = "/test?sslmode=disable";
const TEST_STACK_PROJECT_PREFIX: &str = "paranoid_testkit_";
const TEST_STACK_MANAGED_LABEL: &str = "paranoid.isolated_db.managed";
const DOCKER_LIST_CONTAINER_PROJECT_FORMAT: &str = "{{.Label \"com.docker.compose.project\"}}|{{.Label \"paranoid.isolated_db.managed\"}}|{{.Label \"paranoid.isolated_db.owner_pid\"}}";
const DOCKER_LIST_PROJECT_LABEL_FORMAT: &str = "{{.Label \"com.docker.compose.project\"}}";
const DOCKER_LIST_PROJECT_STATE_FORMAT: &str =
    "{{.Label \"com.docker.compose.project\"}}|{{.State}}";
const MAX_STACK_START_ATTEMPTS: u8 = 5;

pub(crate) fn run_from_args(args: Vec<OsString>) -> Result<i32, String> {
    let child_command = child_command_from_cli_args(args);
    if child_command.is_empty() {
        return Err("isolated test stack child command is required".to_owned());
    }

    let compose_file = resolve_compose_file()?;
    if let Err(error) = cleanup_stale_isolated_test_stacks(&compose_file) {
        eprintln!("cleanup warning: {error}");
    }

    let project_base = new_project_name()?;
    let mut last_start_error = "isolated test stack did not start".to_owned();
    for attempt in 1..=MAX_STACK_START_ATTEMPTS {
        let project_name =
            project_name_for_attempt(&project_base, attempt, MAX_STACK_START_ATTEMPTS);
        let compose_env = compose_env_for_current_process();

        println!("Starting isolated test stack: project={project_name}");
        let startup_result = docker_compose(&compose_file, &project_name, &compose_env)
            .args(["up", "-d", "--wait"])
            .status()
            .map_err(|error| format!("start isolated test stack: {error}"));

        let run_result = match startup_result {
            Ok(status) if status.success() => run_child_with_stack_environment(
                &child_command,
                &compose_file,
                &project_name,
                &compose_env,
            ),
            Ok(status) => {
                last_start_error =
                    format!("isolated test stack startup failed (attempt {attempt}): {status}");
                eprintln!("{last_start_error}");
                let _ = compose_down(&compose_file, &project_name, &compose_env);
                continue;
            }
            Err(error) => {
                last_start_error = error;
                let _ = compose_down(&compose_file, &project_name, &compose_env);
                continue;
            }
        };

        let cleanup_status = compose_down(&compose_file, &project_name, &compose_env)?;
        if !cleanup_status.success() && matches!(run_result, Ok(0)) {
            return Ok(exit_code_from_status(cleanup_status));
        }
        return run_result;
    }

    Err(last_start_error)
}

fn child_command_from_cli_args(args: Vec<OsString>) -> Vec<OsString> {
    if args.first().is_some_and(|arg| arg == "--") {
        return args.into_iter().skip(1).collect();
    }
    args
}

fn resolve_compose_file() -> Result<PathBuf, String> {
    if let Some(compose_file) = env::var_os("COMPOSE_FILE") {
        let path = PathBuf::from(compose_file);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("compose file {:?} does not exist", path));
    }

    let mut dir =
        env::current_dir().map_err(|error| format!("resolve working directory: {error}"))?;
    loop {
        let candidate = dir.join(DEFAULT_COMPOSE_FILE_NAME);
        if candidate.exists() {
            return Ok(candidate);
        }
        if !dir.pop() {
            break;
        }
    }

    Err(format!(
        "could not find {DEFAULT_COMPOSE_FILE_NAME:?} from current directory upward"
    ))
}

fn new_project_name() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before unix epoch: {error}"))?
        .as_nanos();
    Ok(format!(
        "{TEST_STACK_PROJECT_PREFIX}{nanos}_{}",
        std::process::id()
    ))
}

fn project_name_for_attempt(project_base: &str, attempt: u8, max_attempts: u8) -> String {
    if max_attempts > 1 {
        format!("{project_base}_{attempt}")
    } else {
        project_base.to_owned()
    }
}

fn compose_env_for_current_process() -> Vec<(String, String)> {
    vec![
        ("TEST_PGBOUNCER_PORT".to_owned(), "0".to_owned()),
        ("TEST_POSTGRES_PORT".to_owned(), "0".to_owned()),
        ("TEST_OWNER_PID".to_owned(), std::process::id().to_string()),
    ]
}

fn stale_stack_compose_env() -> Vec<(String, String)> {
    vec![
        ("TEST_PGBOUNCER_PORT".to_owned(), "1".to_owned()),
        ("TEST_POSTGRES_PORT".to_owned(), "1".to_owned()),
        ("TEST_OWNER_PID".to_owned(), "0".to_owned()),
    ]
}

fn run_child_with_stack_environment(
    child_command: &[OsString],
    compose_file: &PathBuf,
    project_name: &str,
    compose_env: &[(String, String)],
) -> Result<i32, String> {
    let pgbouncer_port =
        lookup_compose_service_host_port(compose_file, project_name, "pgbouncer", compose_env)?;
    let postgres_port =
        lookup_compose_service_host_port(compose_file, project_name, "postgres", compose_env)?;
    let pooler_dsn = test_dsn_for_port(&pgbouncer_port);
    let direct_dsn = test_dsn_for_port(&postgres_port);

    let mut command = Command::new(&child_command[0]);
    command.args(&child_command[1..]);
    command
        .env("TEST_DSN", &pooler_dsn)
        .env("TEST_DATABASE_URL", &pooler_dsn)
        .env("PARANOID_TEST_DATABASE_URL", &pooler_dsn)
        .env("TEST_DSN_DIRECT", &direct_dsn)
        .env("PARANOID_TEST_DATABASE_DIRECT_URL", &direct_dsn)
        .env("TEST_SKIP_ISOLATED_DB", "1")
        .env_remove("TEST_FORCE_ISOLATED_DB");

    let status = command
        .status()
        .map_err(|error| format!("run child command {:?}: {error}", child_command[0]))?;
    Ok(exit_code_from_status(status))
}

fn cleanup_stale_isolated_test_stacks(compose_file: &PathBuf) -> Result<(), String> {
    let stale_container_projects = list_stale_isolated_test_projects(process_is_likely_alive)?;
    let container_states = list_prefixed_container_project_states()?;
    let stopped_projects = select_stopped_prefixed_isolated_test_projects(&container_states);
    let running_projects = select_running_prefixed_isolated_test_projects(&container_states);
    let volume_projects = list_prefixed_project_names_from_resource_labels("volume")?;
    let network_projects = list_prefixed_project_names_from_resource_labels("network")?;

    let mut resource_projects = merge_unique_project_names(&[volume_projects, network_projects]);
    resource_projects = exclude_project_names(&resource_projects, &running_projects);
    resource_projects = select_resource_only_prefixed_isolated_test_projects_safe_to_cleanup(
        &resource_projects,
        process_is_likely_alive,
    );

    let projects_to_cleanup = merge_unique_project_names(&[
        stale_container_projects,
        stopped_projects,
        resource_projects,
    ]);
    let compose_env = stale_stack_compose_env();
    for project_name in projects_to_cleanup {
        println!("Cleaning stale isolated test stack: project={project_name}");
        let status = compose_down(compose_file, &project_name, &compose_env)?;
        if !status.success() {
            eprintln!(
                "cleanup warning: failed to cleanup stale stack project={project_name}: {status}"
            );
        }
    }

    Ok(())
}

fn list_stale_isolated_test_projects(
    is_process_alive: fn(u32) -> bool,
) -> Result<Vec<String>, String> {
    let output = docker_output(&[
        "ps",
        "-a",
        "--filter",
        &format!("label={TEST_STACK_MANAGED_LABEL}=true"),
        "--format",
        DOCKER_LIST_CONTAINER_PROJECT_FORMAT,
    ])?;
    let containers = parse_docker_test_stack_container_rows(&output);
    Ok(select_stale_isolated_test_projects(
        &containers,
        is_process_alive,
    ))
}

fn list_prefixed_container_project_states() -> Result<Vec<DockerProjectStateRow>, String> {
    let output = docker_output(&["ps", "-a", "--format", DOCKER_LIST_PROJECT_STATE_FORMAT])?;
    Ok(parse_docker_project_state_rows(&output))
}

fn list_prefixed_project_names_from_resource_labels(
    resource_type: &str,
) -> Result<Vec<String>, String> {
    if resource_type != "volume" && resource_type != "network" {
        return Err(format!(
            "unsupported docker resource type {resource_type:?}"
        ));
    }
    let output = docker_output(&[
        resource_type,
        "ls",
        "--format",
        DOCKER_LIST_PROJECT_LABEL_FORMAT,
    ])?;
    Ok(parse_prefixed_project_name_lines(&output))
}

fn docker_output(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|error| format!("docker {}: {error}", args.join(" ")))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!("docker {}: {}", args.join(" "), stderr.trim()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerTestStackContainer {
    project_name: String,
    is_managed: bool,
    owner_pid: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerProjectStateRow {
    project_name: String,
    state: String,
}

fn parse_docker_test_stack_container_rows(raw_output: &str) -> Vec<DockerTestStackContainer> {
    raw_output
        .lines()
        .filter_map(parse_docker_test_stack_container_row)
        .collect()
}

fn parse_docker_test_stack_container_row(row: &str) -> Option<DockerTestStackContainer> {
    let mut parts = row.splitn(3, '|');
    let project_name = parts.next()?.trim();
    let managed = parts.next()?.trim();
    let owner_pid = parts.next()?.trim();
    if project_name.is_empty() {
        return None;
    }
    Some(DockerTestStackContainer {
        project_name: project_name.to_owned(),
        is_managed: managed.eq_ignore_ascii_case("true"),
        owner_pid: owner_pid.parse::<u32>().ok().filter(|pid| *pid > 0),
    })
}

fn parse_docker_project_state_rows(raw_output: &str) -> Vec<DockerProjectStateRow> {
    raw_output
        .lines()
        .filter_map(parse_docker_project_state_row)
        .collect()
}

fn parse_docker_project_state_row(row: &str) -> Option<DockerProjectStateRow> {
    let (project_name, state) = row.split_once('|')?;
    let project_name = project_name.trim();
    if project_name.is_empty() {
        return None;
    }
    Some(DockerProjectStateRow {
        project_name: project_name.to_owned(),
        state: state.trim().to_ascii_lowercase(),
    })
}

fn parse_prefixed_project_name_lines(raw_output: &str) -> Vec<String> {
    let mut project_names = Vec::new();
    for line in raw_output.lines().map(str::trim) {
        if line.is_empty() || !has_test_stack_project_prefix(line) {
            continue;
        }
        if !project_names
            .iter()
            .any(|project_name| project_name == line)
        {
            project_names.push(line.to_owned());
        }
    }
    project_names.sort();
    project_names
}

fn select_stale_isolated_test_projects(
    containers: &[DockerTestStackContainer],
    is_process_alive: fn(u32) -> bool,
) -> Vec<String> {
    let mut state_by_project = std::collections::BTreeMap::<String, (bool, Vec<u32>)>::new();
    for container in containers {
        let state = state_by_project
            .entry(container.project_name.clone())
            .or_insert((false, Vec::new()));
        if container.is_managed {
            state.0 = true;
        }
        if let Some(owner_pid) = container.owner_pid {
            state.1.push(owner_pid);
        }
    }

    state_by_project
        .into_iter()
        .filter_map(|(project_name, (is_managed, owner_pids))| {
            if !has_test_stack_project_prefix(&project_name) || !is_managed || owner_pids.is_empty()
            {
                return None;
            }
            if owner_pids.into_iter().any(is_process_alive) {
                return None;
            }
            Some(project_name)
        })
        .collect()
}

fn select_stopped_prefixed_isolated_test_projects(
    project_state_rows: &[DockerProjectStateRow],
) -> Vec<String> {
    let mut state_by_project = std::collections::BTreeMap::<String, (bool, bool)>::new();
    for row in project_state_rows {
        if !has_test_stack_project_prefix(&row.project_name) {
            continue;
        }
        let state = state_by_project
            .entry(row.project_name.clone())
            .or_insert((false, false));
        state.0 = true;
        if !is_stopped_container_state(&row.state) {
            state.1 = true;
        }
    }
    state_by_project
        .into_iter()
        .filter_map(|(project_name, (has_container, has_non_stopped))| {
            if has_container && !has_non_stopped {
                Some(project_name)
            } else {
                None
            }
        })
        .collect()
}

fn select_running_prefixed_isolated_test_projects(
    project_state_rows: &[DockerProjectStateRow],
) -> Vec<String> {
    let mut running_projects = Vec::new();
    for row in project_state_rows {
        if !has_test_stack_project_prefix(&row.project_name)
            || is_stopped_container_state(&row.state)
            || running_projects
                .iter()
                .any(|project_name| project_name == &row.project_name)
        {
            continue;
        }
        running_projects.push(row.project_name.clone());
    }
    running_projects.sort();
    running_projects
}

fn select_resource_only_prefixed_isolated_test_projects_safe_to_cleanup(
    project_names: &[String],
    is_process_alive: fn(u32) -> bool,
) -> Vec<String> {
    let mut safe_projects = Vec::new();
    for project_name in project_names {
        if let Some(owner_pid) = isolated_test_project_owner_pid_from_project_name(project_name) {
            if is_process_alive(owner_pid) {
                continue;
            }
        }
        safe_projects.push(project_name.clone());
    }
    safe_projects.sort();
    safe_projects
}

fn merge_unique_project_names(project_lists: &[Vec<String>]) -> Vec<String> {
    let mut merged = Vec::new();
    for project_list in project_lists {
        for project_name in project_list {
            if project_name.is_empty() || merged.iter().any(|seen| seen == project_name) {
                continue;
            }
            merged.push(project_name.clone());
        }
    }
    merged.sort();
    merged
}

fn exclude_project_names(
    project_names: &[String],
    excluded_project_names: &[String],
) -> Vec<String> {
    project_names
        .iter()
        .filter(|project_name| {
            !excluded_project_names
                .iter()
                .any(|excluded| excluded == *project_name)
        })
        .cloned()
        .collect()
}

fn isolated_test_project_owner_pid_from_project_name(project_name: &str) -> Option<u32> {
    let suffix = project_name.strip_prefix(TEST_STACK_PROJECT_PREFIX)?;
    let mut parts = suffix.split('_');
    parts.next()?;
    parts.next()?.parse::<u32>().ok().filter(|pid| *pid > 0)
}

fn has_test_stack_project_prefix(project_name: &str) -> bool {
    project_name.starts_with(TEST_STACK_PROJECT_PREFIX)
}

fn is_stopped_container_state(state: &str) -> bool {
    matches!(state, "exited" | "dead")
}

fn process_is_likely_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output();
    output
        .map(|output| {
            output.status.success() && !String::from_utf8_lossy(&output.stdout).trim().is_empty()
        })
        .unwrap_or(false)
}

fn lookup_compose_service_host_port(
    compose_file: &PathBuf,
    project_name: &str,
    service_name: &str,
    compose_env: &[(String, String)],
) -> Result<String, String> {
    let output = docker_compose(compose_file, project_name, compose_env)
        .args(["port", service_name, "5432"])
        .output()
        .map_err(|error| format!("lookup compose service port for {service_name}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "lookup compose service port for {service_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_compose_port_output(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        format!(
            "compose service port output for {service_name}:5432 was empty or invalid: {:?}",
            String::from_utf8_lossy(&output.stdout).trim()
        )
    })
}

fn parse_compose_port_output(output: &str) -> Option<String> {
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some((_, port)) = line.rsplit_once(':') {
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Some(port.to_owned());
            }
        }
    }
    None
}

fn test_dsn_for_port(port: &str) -> String {
    format!("{DEFAULT_TEST_DSN_PATTERN_PREFIX}{port}{DEFAULT_TEST_DSN_PATTERN_SUFFIX}")
}

fn docker_compose(
    compose_file: &PathBuf,
    project_name: &str,
    compose_env: &[(String, String)],
) -> Command {
    let mut command = Command::new("docker");
    command
        .args(["compose", "-p", project_name, "-f"])
        .arg(compose_file);
    for (key, value) in compose_env {
        command.env(key, value);
    }
    command
}

fn compose_down(
    compose_file: &PathBuf,
    project_name: &str,
    compose_env: &[(String, String)],
) -> Result<ExitStatus, String> {
    docker_compose(compose_file, project_name, compose_env)
        .args(["down", "--remove-orphans", "--volumes"])
        .status()
        .map_err(|error| format!("cleanup isolated test stack: {error}"))
}

fn exit_code_from_status(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_command_parser_strips_optional_separator() {
        let args = vec![
            OsString::from("--"),
            OsString::from("cargo"),
            OsString::from("test"),
        ];

        assert_eq!(
            child_command_from_cli_args(args),
            vec![OsString::from("cargo"), OsString::from("test")]
        );
    }

    #[test]
    fn child_command_parser_keeps_args_without_separator() {
        let args = vec![OsString::from("cargo"), OsString::from("test")];

        assert_eq!(child_command_from_cli_args(args.clone()), args);
    }

    #[test]
    fn compose_port_parser_accepts_ipv4_ipv6_and_hostname_outputs() {
        assert_eq!(
            parse_compose_port_output("0.0.0.0:65432\n"),
            Some("65432".to_owned())
        );
        assert_eq!(
            parse_compose_port_output("[::]:15432\n"),
            Some("15432".to_owned())
        );
        assert_eq!(
            parse_compose_port_output("localhost:25432\n"),
            Some("25432".to_owned())
        );
    }

    #[test]
    fn compose_port_parser_rejects_empty_and_malformed_outputs() {
        assert_eq!(parse_compose_port_output(""), None);
        assert_eq!(parse_compose_port_output("localhost:not-a-port\n"), None);
        assert_eq!(parse_compose_port_output("no-port-here\n"), None);
    }

    #[test]
    fn test_dsn_uses_expected_local_postgres_shape() {
        assert_eq!(
            test_dsn_for_port("65432"),
            "postgres://test:test@localhost:65432/test?sslmode=disable"
        );
    }

    #[test]
    fn docker_test_stack_container_row_parser_accepts_expected_label_shape() {
        assert_eq!(
            parse_docker_test_stack_container_row("paranoid_testkit_100_4242|true|4242"),
            Some(DockerTestStackContainer {
                project_name: "paranoid_testkit_100_4242".to_owned(),
                is_managed: true,
                owner_pid: Some(4242),
            })
        );
    }

    #[test]
    fn stale_project_selection_requires_managed_prefix_owner_and_dead_owner() {
        let containers = vec![
            DockerTestStackContainer {
                project_name: "paranoid_testkit_100_1".to_owned(),
                is_managed: true,
                owner_pid: Some(1),
            },
            DockerTestStackContainer {
                project_name: "paranoid_testkit_100_2".to_owned(),
                is_managed: true,
                owner_pid: Some(2),
            },
            DockerTestStackContainer {
                project_name: "other_100_3".to_owned(),
                is_managed: true,
                owner_pid: Some(3),
            },
        ];

        assert_eq!(
            select_stale_isolated_test_projects(&containers, |pid| pid == 2),
            vec!["paranoid_testkit_100_1".to_owned()]
        );
    }

    #[test]
    fn stopped_and_running_project_selection_uses_all_container_states() {
        let rows = vec![
            DockerProjectStateRow {
                project_name: "paranoid_testkit_100_1".to_owned(),
                state: "exited".to_owned(),
            },
            DockerProjectStateRow {
                project_name: "paranoid_testkit_100_2".to_owned(),
                state: "exited".to_owned(),
            },
            DockerProjectStateRow {
                project_name: "paranoid_testkit_100_2".to_owned(),
                state: "running".to_owned(),
            },
        ];

        assert_eq!(
            select_stopped_prefixed_isolated_test_projects(&rows),
            vec!["paranoid_testkit_100_1".to_owned()]
        );
        assert_eq!(
            select_running_prefixed_isolated_test_projects(&rows),
            vec!["paranoid_testkit_100_2".to_owned()]
        );
    }

    #[test]
    fn resource_only_cleanup_skips_live_owner_from_project_name() {
        let project_names = vec![
            "paranoid_testkit_100_1".to_owned(),
            "paranoid_testkit_100_2".to_owned(),
            "paranoid_testkit_no_owner_suffix".to_owned(),
        ];

        assert_eq!(
            select_resource_only_prefixed_isolated_test_projects_safe_to_cleanup(
                &project_names,
                |pid| pid == 2,
            ),
            vec![
                "paranoid_testkit_100_1".to_owned(),
                "paranoid_testkit_no_owner_suffix".to_owned(),
            ]
        );
    }

    #[test]
    fn project_name_owner_pid_parser_accepts_current_prefix() {
        assert_eq!(
            isolated_test_project_owner_pid_from_project_name("paranoid_testkit_100_4242"),
            Some(4242)
        );
        assert_eq!(
            isolated_test_project_owner_pid_from_project_name("paranoid_testkit_no_owner"),
            None
        );
    }
}
