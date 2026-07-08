use std::env;
use std::ffi::OsString;

use paranoid::db::testing::{IsolatedPostgresTestHarness, IsolatedPostgresTestHarnessConfig};

pub(crate) fn run_from_args(args: Vec<OsString>) -> Result<i32, String> {
    let child_command = child_command_from_cli_args(args);
    if child_command.is_empty() {
        return Err("isolated test database child command must follow --".to_owned());
    }

    set_deterministic_postgres_locale_before_runtime();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create isolated test database runtime: {error}"))?;
    runtime.block_on(run_child_inside_isolated_database(child_command))
}

fn set_deterministic_postgres_locale_before_runtime() {
    unsafe {
        env::set_var("LC_ALL", "C");
        env::set_var("LANG", "C");
    }
}

async fn run_child_inside_isolated_database(child_command: Vec<OsString>) -> Result<i32, String> {
    let root_directory =
        env::current_dir().map_err(|error| format!("read current directory: {error}"))?;
    let harness = IsolatedPostgresTestHarness::start_with_config(
        IsolatedPostgresTestHarnessConfig::new(root_directory),
    )
    .await
    .map_err(|error| error.to_string())?;

    let program = child_command
        .first()
        .ok_or_else(|| "isolated test database child command is empty".to_owned())?;
    let exit_code = harness
        .run_child_command_with_database_environment(program, child_command.iter().skip(1))
        .map_err(|error| error.to_string());
    let cleanup_result = harness.shutdown().await.map_err(|error| error.to_string());

    match (exit_code, cleanup_result) {
        (Ok(exit_code), Ok(())) => Ok(exit_code),
        (Ok(0), Err(error)) => Err(error),
        (Ok(exit_code), Err(error)) => {
            eprintln!("isolated test database cleanup warning: {error}");
            Ok(exit_code)
        }
        (Err(error), Ok(())) => Err(error),
        (Err(child_error), Err(cleanup_error)) => {
            Err(format!("{child_error}; cleanup failed: {cleanup_error}"))
        }
    }
}

fn child_command_from_cli_args(args: Vec<OsString>) -> Vec<OsString> {
    if args.first().is_none_or(|arg| arg != "--") {
        return Vec::new();
    }
    args.into_iter().skip(1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_command_parser_strips_required_separator() {
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
    fn child_command_parser_rejects_args_without_separator() {
        let args = vec![OsString::from("cargo"), OsString::from("test")];

        assert_eq!(child_command_from_cli_args(args), Vec::<OsString>::new());
    }
}
