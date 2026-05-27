use std::env;
use std::ffi::OsString;

mod fuzz_gate;
mod gate;
mod isolated_test_db;

fn main() {
    let exit_code = match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("xtask: {error}");
            1
        }
    };

    std::process::exit(exit_code);
}

fn run() -> Result<i32, String> {
    let mut args = env::args_os();
    let _binary_name = args.next();
    let Some(command) = args.next() else {
        print_usage();
        return Ok(1);
    };

    match command.to_str() {
        Some("fuzz-gate") => {
            let args = utf8_args_for_command("fuzz-gate", args.collect())?;
            fuzz_gate::run_from_args(args)?;
            Ok(0)
        }
        Some("gate") => gate::run_from_args(args),
        Some("with-isolated-test-db") => isolated_test_db::run_from_args(args.collect()),
        Some("--help" | "-h") => {
            print_usage();
            Ok(0)
        }
        Some(other) => Err(format!("unknown xtask command {other:?}")),
        None => Err("xtask command must be valid UTF-8".to_owned()),
    }
}

fn utf8_args_for_command(command: &str, args: Vec<OsString>) -> Result<Vec<String>, String> {
    args.into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| format!("{command} arguments must be valid UTF-8"))
        })
        .collect()
}

fn print_usage() {
    eprintln!("usage: cargo run --manifest-path xtask/Cargo.toml -- <command> [args...]");
    eprintln!("commands:");
    eprintln!("  fuzz-gate [--target <cargo-fuzz-target>]... [--runs <positive-int>]");
    eprintln!("  gate [--runs <positive-int>] [--log-dir <path>]");
    eprintln!("  with-isolated-test-db -- <command...>");
}
