use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_FUZZ_RUNS: u64 = 4096;
const GATE_LOG_DIR: &str = "logs.local";

#[derive(Debug, Eq, PartialEq)]
struct Options {
    fuzz_runs: u64,
}

#[derive(Debug, Eq, PartialEq)]
struct GateStep {
    name: &'static str,
    command: Vec<OsString>,
    env: Vec<(&'static str, OsString)>,
}

#[derive(Debug, Eq, PartialEq)]
struct StepFailure {
    name: &'static str,
    log_path: PathBuf,
    reason: String,
}

pub(crate) fn run_from_args<I>(args: I) -> Result<i32, String>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let options = parse_args(args)?;
    run_gate(options)
}

fn parse_args<I>(args: I) -> Result<Options, String>
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut fuzz_runs = DEFAULT_FUZZ_RUNS;
    let mut iter = args.into_iter().map(Into::into);

    while let Some(arg) = iter.next() {
        match arg.to_str() {
            Some("--runs") => {
                let value = next_utf8_value("--runs", iter.next())?;
                fuzz_runs = parse_positive_u64("--runs", &value)?;
            }
            Some(other) => return Err(format!("unknown argument {other:?}")),
            None => return Err("gate arguments must be valid UTF-8".to_owned()),
        }
    }

    Ok(Options { fuzz_runs })
}

fn next_utf8_value(flag: &str, value: Option<OsString>) -> Result<String, String> {
    value
        .ok_or_else(|| format!("{flag} requires a value"))?
        .into_string()
        .map_err(|_| format!("{flag} value must be valid UTF-8"))
}

fn parse_positive_u64(flag: &str, value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a positive integer"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be a positive integer"));
    }
    Ok(parsed)
}

fn run_gate(options: Options) -> Result<i32, String> {
    let log_dir = PathBuf::from(GATE_LOG_DIR);
    fs::create_dir_all(&log_dir)
        .map_err(|error| format!("create gate log directory {}: {error}", log_dir.display()))?;

    let steps = gate_steps(options.fuzz_runs);
    let mut failures = Vec::new();

    for (index, step) in steps.iter().enumerate() {
        let log_path = step_log_path(&log_dir, index, step.name);
        println!("Running {}...", step.name);
        match run_step(step, &log_path) {
            Ok(()) => println!("{} passed ({})", step.name, log_path.display()),
            Err(reason) => {
                println!("{} failed ({})", step.name, log_path.display());
                failures.push(StepFailure {
                    name: step.name,
                    log_path,
                    reason,
                });
            }
        }
    }

    if failures.is_empty() {
        println!("All passed");
        return Ok(0);
    }

    let failed_names = failures
        .iter()
        .map(|failure| failure.name)
        .collect::<Vec<_>>()
        .join(", ");
    println!("[{failed_names}] failed");
    for failure in failures {
        println!(
            "{}: {} ({})",
            failure.name,
            failure.reason,
            failure.log_path.display()
        );
    }
    Ok(1)
}

fn gate_steps(fuzz_runs: u64) -> Vec<GateStep> {
    vec![
        make_step("feature-gate"),
        make_step("tool-gate"),
        make_step("bench-gate"),
        make_step("test"),
        GateStep {
            name: "fuzz",
            command: make_command("fuzz"),
            env: vec![("FUZZ_RUNS", OsString::from(fuzz_runs.to_string()))],
        },
    ]
}

fn make_step(name: &'static str) -> GateStep {
    GateStep {
        name,
        command: make_command(name),
        env: Vec::new(),
    }
}

fn make_command(target: &str) -> Vec<OsString> {
    ["make", "--no-print-directory", target]
        .into_iter()
        .map(OsString::from)
        .collect()
}

fn step_log_path(log_dir: &Path, index: usize, step_name: &str) -> PathBuf {
    log_dir.join(format!(
        "gate-{:02}-{}.txt",
        index + 1,
        sanitized_log_name(step_name)
    ))
}

fn sanitized_log_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn run_step(step: &GateStep, log_path: &Path) -> Result<(), String> {
    let mut log_file = File::create(log_path)
        .map_err(|error| format!("create log file {}: {error}", log_path.display()))?;
    write_step_header(&mut log_file, step)?;
    let stdout = log_file
        .try_clone()
        .map_err(|error| format!("clone log file {}: {error}", log_path.display()))?;
    let stderr = log_file;

    let (program, args) = step
        .command
        .split_first()
        .ok_or_else(|| "gate step command cannot be empty".to_owned())?;
    let mut command = Command::new(program);
    command.args(args);
    for (name, value) in &step.env {
        command.env(name, value);
    }
    let status = command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .map_err(|error| format!("spawn {}: {error}", step.name))?;
    if status.success() {
        Ok(())
    } else {
        Err(status.to_string())
    }
}

fn write_step_header(log_file: &mut File, step: &GateStep) -> Result<(), String> {
    let command_text = step
        .command
        .iter()
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    writeln!(log_file, "$ {command_text}").map_err(format_log_write_error)?;
    for (name, value) in &step.env {
        writeln!(log_file, "{name}={}", value.to_string_lossy()).map_err(format_log_write_error)?;
    }
    writeln!(log_file).map_err(format_log_write_error)?;
    log_file.flush().map_err(format_log_write_error)
}

fn format_log_write_error(error: io::Error) -> String {
    format!("write gate log: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_defaults_and_custom_run_count() {
        assert_eq!(
            parse_args(Vec::<OsString>::new()).unwrap(),
            Options {
                fuzz_runs: DEFAULT_FUZZ_RUNS,
            }
        );
        assert_eq!(
            parse_args(["--runs", "17"]).unwrap(),
            Options { fuzz_runs: 17 }
        );
    }

    #[test]
    fn parser_rejects_unknown_zero_and_non_utf8_values() {
        assert!(parse_args(["--wat"]).is_err());
        assert!(parse_args(["--runs", "0"]).is_err());
        assert!(parse_args(["--runs"]).is_err());
    }

    #[test]
    fn gate_steps_match_full_gate_order_and_pass_fuzz_runs_through_env() {
        let steps = gate_steps(9);
        let names = steps.iter().map(|step| step.name).collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["feature-gate", "tool-gate", "bench-gate", "test", "fuzz"]
        );
        assert_eq!(steps[4].env, vec![("FUZZ_RUNS", OsString::from("9"))]);
    }

    #[test]
    fn log_paths_are_ordered_and_safe() {
        assert_eq!(
            step_log_path(Path::new("logs.local"), 0, "feature-gate"),
            PathBuf::from("logs.local/gate-01-feature-gate.txt")
        );
        assert_eq!(sanitized_log_name("bad/name"), "bad_name");
    }
}
