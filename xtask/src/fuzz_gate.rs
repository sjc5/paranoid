use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_FUZZ_RUNS: u64 = 4096;
const DEFAULT_FUZZ_TARGETS: &[&str] = &[
    "paranoid_codecs",
    "paranoid_envelope",
    "paranoid_id",
    "paranoid_db_validators",
];
const LIBFUZZER_PROGRESS_DONE_MARKER: &str = "\tDONE";

#[derive(Debug, Eq, PartialEq)]
struct Options {
    targets: Vec<String>,
    runs: u64,
}

#[derive(Debug, Eq, PartialEq)]
enum ParsedArgs {
    Help,
    Run(Options),
}

pub(crate) fn run_from_args<I>(args: I) -> Result<(), String>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let parsed = parse_args(args)?;
    let ParsedArgs::Run(options) = parsed else {
        print_usage();
        return Ok(());
    };

    for target in &options.targets {
        run_fuzz_target(target, options.runs)?;
    }

    Ok(())
}

fn parse_args<I>(args: I) -> Result<ParsedArgs, String>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut targets = Vec::new();
    let mut runs = DEFAULT_FUZZ_RUNS;
    let mut iter = args.into_iter().map(Into::into);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParsedArgs::Help),
            "--target" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--target requires a value".to_owned())?;
                if value.is_empty() {
                    return Err("--target cannot be empty".to_owned());
                }
                targets.push(value);
            }
            "--runs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--runs requires a value".to_owned())?;
                runs = parse_positive_u64("--runs", &value)?;
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    if targets.is_empty() {
        targets = DEFAULT_FUZZ_TARGETS
            .iter()
            .map(|target| (*target).to_owned())
            .collect();
    }

    Ok(ParsedArgs::Run(Options { targets, runs }))
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

fn run_fuzz_target(target: &str, runs: u64) -> Result<(), String> {
    println!("==> running cargo-fuzz target {target} for {runs} runs");

    let corpus_dir = temporary_corpus_dir_for_target(target)?;
    let output = Command::new("cargo")
        .args([
            "+nightly",
            "fuzz",
            "run",
            target,
            corpus_dir
                .to_str()
                .ok_or_else(|| format!("temporary corpus path for {target} is not UTF-8"))?,
            "--",
            &format!("-runs={runs}"),
        ])
        .output()
        .map_err(|error| format!("failed to run cargo fuzz for {target}: {error}"))?;
    let cleanup_result = fs::remove_dir_all(&corpus_dir)
        .map_err(|error| format!("cleanup temporary fuzz corpus for {target}: {error}"));

    write_all(io::stdout(), &output.stdout)
        .map_err(|error| format!("failed to write cargo-fuzz stdout for {target}: {error}"))?;
    write_all(io::stderr(), &output.stderr)
        .map_err(|error| format!("failed to write cargo-fuzz stderr for {target}: {error}"))?;

    let mut combined_output = String::from_utf8_lossy(&output.stdout).into_owned();
    combined_output.push_str(&String::from_utf8_lossy(&output.stderr));

    if !output.status.success() {
        return Err(format!("cargo fuzz failed for {target}: {}", output.status));
    }
    cleanup_result?;

    validate_libfuzzer_execution_output(&combined_output, target)
}

fn temporary_corpus_dir_for_target(target: &str) -> Result<PathBuf, String> {
    let temp_dir = env::temp_dir().join(format!(
        "paranoid_fuzz_gate_{}_{}_{}",
        sanitized_target_name(target),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before unix epoch: {error}"))?
            .as_nanos(),
    ));
    fs::create_dir_all(&temp_dir)
        .map_err(|error| format!("create temporary fuzz corpus for {target}: {error}"))?;

    let source_dir = repo_root().join("fuzz").join("corpus").join(target);
    copy_corpus_files_if_present(&source_dir, &temp_dir)?;
    Ok(temp_dir)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask should live directly under the repository root")
        .to_path_buf()
}

fn copy_corpus_files_if_present(source_dir: &Path, destination_dir: &Path) -> Result<(), String> {
    if !source_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(source_dir)
        .map_err(|error| format!("read seed corpus {}: {error}", source_dir.display()))?
    {
        let entry = entry
            .map_err(|error| format!("read seed corpus entry {}: {error}", source_dir.display()))?;
        let source_path = entry.path();
        if !source_path.is_file() {
            continue;
        }
        let destination_path = destination_dir.join(entry.file_name());
        fs::copy(&source_path, &destination_path).map_err(|error| {
            format!(
                "copy seed corpus file {} to {}: {error}",
                source_path.display(),
                destination_path.display()
            )
        })?;
    }
    Ok(())
}

fn sanitized_target_name(target: &str) -> String {
    target
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn write_all<W>(mut writer: W, bytes: &[u8]) -> io::Result<()>
where
    W: Write,
{
    writer.write_all(bytes)
}

fn validate_libfuzzer_execution_output(output: &str, target: &str) -> Result<(), String> {
    if did_libfuzzer_execute_mutational_run(output) {
        return Ok(());
    }

    Err(format!(
        "cargo fuzz completed for {target} without libFuzzer execution markers"
    ))
}

fn did_libfuzzer_execute_mutational_run(output: &str) -> bool {
    let saw_progress_done_line = output.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with('#') && trimmed.contains(LIBFUZZER_PROGRESS_DONE_MARKER)
    });
    let saw_positive_run_count = output
        .lines()
        .any(libfuzzer_completion_line_has_positive_run_count);

    saw_progress_done_line && saw_positive_run_count
}

fn libfuzzer_completion_line_has_positive_run_count(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix("Done ") else {
        return false;
    };
    let digit_count = rest
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 {
        return false;
    }
    let Ok(runs) = rest[..digit_count].parse::<u64>() else {
        return false;
    };
    runs > 0 && rest[digit_count..].starts_with(" runs in ")
}

fn print_usage() {
    eprintln!("usage: xtask fuzz-gate [--target <cargo-fuzz-target>]... [--runs <positive-int>]");
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_CARGO_FUZZ_OUTPUT: &str = "\
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2211219560
INFO: Loaded 1 modules   (28329 inline 8-bit counters): 28329 [0x10300bda0, 0x103012c49),
INFO: Loaded 1 PC tables (28329 PCs): 28329 [0x103012c50,0x1030816e0),
INFO:        0 files found in fuzz/corpus/paranoid_codecs
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2\tINITED cov: 337 ft: 337 corp: 1/1b exec/s: 0 rss: 54Mb
#2\tDONE   cov: 337 ft: 337 corp: 1/1b lim: 4 exec/s: 0 rss: 54Mb
Done 2 runs in 0 second(s)
";

    #[test]
    fn parser_accepts_real_libfuzzer_run_output() {
        assert!(did_libfuzzer_execute_mutational_run(REAL_CARGO_FUZZ_OUTPUT));
    }

    #[test]
    fn parser_rejects_compile_only_cargo_output() {
        let output = "\
   Compiling paranoid-fuzz v0.0.0
    Finished `release` profile [optimized + debuginfo] target(s) in 0.49s
";

        assert!(!did_libfuzzer_execute_mutational_run(output));
    }

    #[test]
    fn parser_rejects_completion_line_without_progress_done_line() {
        let output = "\
INFO: Running with entropic power schedule (0xFF, 100).
Done 2 runs in 0 second(s)
";

        assert!(!did_libfuzzer_execute_mutational_run(output));
    }

    #[test]
    fn parser_rejects_zero_run_completion_line() {
        let output = "\
#0\tDONE   cov: 0 ft: 0 corp: 0/0b lim: 0 exec/s: 0 rss: 0Mb
Done 0 runs in 0 second(s)
";

        assert!(!did_libfuzzer_execute_mutational_run(output));
    }

    #[test]
    fn default_args_run_all_paranoid_fuzz_targets() {
        let parsed = parse_args(std::iter::empty::<String>()).expect("parse args");
        let ParsedArgs::Run(options) = parsed else {
            panic!("expected run options");
        };

        assert_eq!(
            options,
            Options {
                targets: vec![
                    "paranoid_codecs".to_owned(),
                    "paranoid_envelope".to_owned(),
                    "paranoid_id".to_owned(),
                    "paranoid_db_validators".to_owned(),
                ],
                runs: DEFAULT_FUZZ_RUNS
            }
        );
    }

    #[test]
    fn default_fuzz_targets_match_cargo_fuzz_manifest_bins() {
        let manifest =
            fs::read_to_string(repo_root().join("fuzz/Cargo.toml")).expect("read fuzz manifest");
        let mut manifest_targets = fuzz_target_names_from_manifest(&manifest);
        let mut default_targets: Vec<&str> = DEFAULT_FUZZ_TARGETS.to_vec();

        manifest_targets.sort_unstable();
        default_targets.sort_unstable();

        assert_eq!(default_targets, manifest_targets);
    }

    #[test]
    fn explicit_args_can_select_targets_and_run_count() {
        let parsed = parse_args([
            "--target",
            "paranoid_codecs",
            "--target",
            "paranoid_envelope",
            "--runs",
            "17",
        ])
        .expect("parse args");
        let ParsedArgs::Run(options) = parsed else {
            panic!("expected run options");
        };

        assert_eq!(
            options,
            Options {
                targets: vec!["paranoid_codecs".to_owned(), "paranoid_envelope".to_owned()],
                runs: 17
            }
        );
    }

    #[test]
    fn zero_runs_are_rejected() {
        let err = parse_args(["--runs", "0"]).expect_err("reject zero runs");
        assert_eq!(err, "--runs must be a positive integer");
    }

    #[test]
    fn target_names_are_sanitized_for_temporary_paths() {
        assert_eq!(
            sanitized_target_name("paranoid/codecs:weird"),
            "paranoid_codecs_weird",
        );
    }

    fn fuzz_target_names_from_manifest(manifest: &str) -> Vec<&str> {
        let mut names = Vec::new();
        let mut inside_bin = false;

        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed == "[[bin]]" {
                inside_bin = true;
                continue;
            }
            if trimmed.starts_with('[') {
                inside_bin = false;
                continue;
            }
            if !inside_bin {
                continue;
            }
            let Some(raw_name) = trimmed.strip_prefix("name = ") else {
                continue;
            };
            let name = raw_name
                .trim()
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .expect("fuzz bin name should be a quoted string");
            names.push(name);
        }

        assert!(
            !names.is_empty(),
            "fuzz manifest should define fuzz targets"
        );
        names
    }
}
