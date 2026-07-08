//! Compares the wall-clock round-trip cost of [`portable_query_scalar`]'s single
//! simple-protocol `Query` against a raw SQLx extended-protocol `query_scalar` call, over
//! the same [`Pool`] against a real Postgres instance sitting behind a transaction-mode
//! PgBouncer.
//!
//! # What this measures
//!
//! Both benchmarked calls run sequentially (no concurrency) against `pool.sqlx_pool()`,
//! so each measured iteration is dominated by one full client/server round trip:
//!
//! - `portable_query_scalar`: the bound value is rendered as a safely-escaped literal and
//!   substituted into the SQL text, then sent as one simple-protocol `Query` message.
//! - raw SQLx `query_scalar`: SQLx's ordinary extended-protocol path — `Parse`, `Bind`,
//!   `Execute`, using the unnamed statement, since [`Pool::connect`] disables the
//!   persistent prepared-statement cache (`statement_cache_capacity(0)`) for every
//!   Paranoid-owned pool regardless of which path is used, matching Paranoid's
//!   pooler-safe posture. Two protocol messages round-trip per call instead of one.
//!
//! # What this does not measure
//!
//! This does not isolate CPU-only literal-encoding cost from network round-trip time;
//! that cost is separately covered by the encoder's own unit and property tests. It also
//! is not a substitute for production network-latency profiling: it runs against a single
//! local isolated Postgres/PgBouncer instance, so absolute latencies reflect this sandbox,
//! not a production deployment. The comparison that matters here is round-trip *count*
//! (one message vs. two), not the absolute nanosecond figures.
//!
//! # Running
//!
//! This bench needs a live, isolated Postgres/PgBouncer instance and reads its connection
//! URL from `TEST_DSN` or `PARANOID_TEST_DATABASE_URL`. Use `make bench-db`, which starts
//! and tears down that instance automatically.

use std::env;
use std::future::Future;
use std::hint::black_box;
use std::time::{Duration, Instant};

use paranoid::db::{Pool, PoolConfig, portable_query_scalar};
use secrecy::SecretString;

const DEFAULT_ITERATIONS: u64 = 500;
const WARMUP_ITERATIONS: u64 = 20;
const BENCH_APPLICATION_NAME: &str = "paranoid_bench_portable_query_round_trip";

#[tokio::main]
async fn main() {
    let iterations = iteration_count_from_args();
    print_benchmark_header(iterations);

    let database_url = database_url_from_env();
    let mut config = PoolConfig::new(SecretString::from(database_url));
    config.application_name = Some(BENCH_APPLICATION_NAME.to_owned());
    let pool = Pool::connect(config)
        .await
        .expect("connect bench pool to isolated test database");
    let sqlx_pool = pool.sqlx_pool().clone();

    run_async_benchmark("portable_query_scalar[select_bigint]", iterations, || {
        let sqlx_pool = sqlx_pool.clone();
        async move {
            portable_query_scalar::<i64>("SELECT $1::bigint")
                .bind(42_i64)
                .fetch_one(&sqlx_pool)
                .await
                .expect("portable_query_scalar bench fetch_one")
        }
    })
    .await;

    run_async_benchmark(
        "sqlx_extended_protocol_query_scalar[select_bigint]",
        iterations,
        || {
            let sqlx_pool = sqlx_pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT $1::bigint")
                    .bind(42_i64)
                    .fetch_one(&sqlx_pool)
                    .await
                    .expect("sqlx query_scalar bench fetch_one")
            }
        },
    )
    .await;

    run_async_benchmark(
        "portable_query_scalar[select_quoted_text]",
        iterations,
        || {
            let sqlx_pool = sqlx_pool.clone();
            async move {
                portable_query_scalar::<String>("SELECT $1::text")
                    .bind("o'brien's literal")
                    .fetch_one(&sqlx_pool)
                    .await
                    .expect("portable_query_scalar text bench fetch_one")
            }
        },
    )
    .await;

    run_async_benchmark(
        "sqlx_extended_protocol_query_scalar[select_quoted_text]",
        iterations,
        || {
            let sqlx_pool = sqlx_pool.clone();
            async move {
                sqlx::query_scalar::<_, String>("SELECT $1::text")
                    .bind("o'brien's literal")
                    .fetch_one(&sqlx_pool)
                    .await
                    .expect("sqlx query_scalar text bench fetch_one")
            }
        },
    )
    .await;
}

fn print_benchmark_header(iterations: u64) {
    println!("os: {}", std::env::consts::OS);
    println!("arch: {}", std::env::consts::ARCH);
    println!("pkg: {}", env!("CARGO_PKG_NAME"));
    println!("bench: portable_query_round_trip");
    println!("iterations: {iterations}");
}

fn iteration_count_from_args() -> u64 {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--iters"
            && let Some(raw_count) = args.next()
        {
            return raw_count
                .parse::<u64>()
                .expect("--iters must be an unsigned integer")
                .max(1);
        }
    }
    DEFAULT_ITERATIONS
}

fn database_url_from_env() -> String {
    ["TEST_DSN", "PARANOID_TEST_DATABASE_URL"]
        .iter()
        .find_map(|env_name| env::var(env_name).ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            panic!(
                "portable_query_round_trip bench requires a live isolated test database; \
                 set TEST_DSN or PARANOID_TEST_DATABASE_URL (see `make bench-db`)"
            )
        })
}

async fn run_async_benchmark<Operation, OperationFuture, Output>(
    name: &str,
    iterations: u64,
    mut operation: Operation,
) where
    Operation: FnMut() -> OperationFuture,
    OperationFuture: Future<Output = Output>,
{
    for _ in 0..WARMUP_ITERATIONS {
        black_box(operation().await);
    }

    let started_at = Instant::now();
    for _ in 0..iterations {
        black_box(operation().await);
    }

    print_result(name, iterations, started_at.elapsed());
}

fn print_result(name: &str, iterations: u64, elapsed: Duration) {
    let elapsed_nanos = elapsed.as_nanos();
    let nanos_per_operation = elapsed_nanos as f64 / iterations as f64;
    println!("{name}: {nanos_per_operation:.2} ns/op ({iterations} iterations)");
}
