use paranoid::local_env_vault::{Error, Profile, VaultRunner};

// Global Env Keys
const DATABASE_URL: &str = "DATABASE_URL";
const PUBLIC_BASE_URL: &str = "PUBLIC_BASE_URL";
const QUEUE_URL: &str = "QUEUE_URL";
const SERVICE_API_TOKEN: &str = "SERVICE_API_TOKEN";

// API Env Profile
const API_PROFILE_NAME: &str = "api";
const API_ENV_KEYS: [&str; 3] = [DATABASE_URL, PUBLIC_BASE_URL, SERVICE_API_TOKEN];

// Worker Env Profile
const WORKER_PROFILE_NAME: &str = "worker";
const WORKER_ENV_KEYS: [&str; 3] = [DATABASE_URL, QUEUE_URL, SERVICE_API_TOKEN];

fn main() -> Result<(), Error> {
    let mut runner = VaultRunner::new(
        env!("CARGO_MANIFEST_DIR"),
        ".",
        [
            Profile::new(API_PROFILE_NAME, API_ENV_KEYS)?,
            Profile::new(WORKER_PROFILE_NAME, WORKER_ENV_KEYS)?,
        ],
    )?;
    runner.run_from_args(std::env::args_os())
}
