use std::hint::black_box;
use std::time::{Duration, Instant};

use paranoid::id::SortableId;

const DEFAULT_ITERATIONS: u64 = 1_000_000;
const NEW_ITERATIONS_DIVISOR: u64 = 5;
const NEW_MULTI_ITERATIONS_DIVISOR: u64 = 20;

fn main() {
    let iterations = iteration_count_from_args();
    print_benchmark_header(iterations);
    let id = SortableId::new().expect("benchmark id");
    let id_text = id.to_text();
    let uppercase_id_text = id_text.to_uppercase();
    let id_bytes = *id.as_bytes();

    run_benchmark("new", iterations / NEW_ITERATIONS_DIVISOR, || {
        SortableId::new().expect("new id")
    });
    run_benchmark(
        "new_multi_16",
        iterations / NEW_MULTI_ITERATIONS_DIVISOR,
        || SortableId::new_multi(16).expect("new ids"),
    );
    run_benchmark("to_text", iterations, || id.to_text());
    run_benchmark("parse_lower", iterations, || {
        SortableId::parse(&id_text).expect("parse lower")
    });
    run_benchmark("parse_upper", iterations, || {
        SortableId::parse(&uppercase_id_text).expect("parse upper")
    });
    run_benchmark("from_bytes", iterations, || {
        SortableId::from_bytes(&id_bytes).expect("from bytes")
    });
    run_benchmark("to_unix_micros", iterations, || id.to_unix_micros());
}

fn print_benchmark_header(iterations: u64) {
    println!("os: {}", std::env::consts::OS);
    println!("arch: {}", std::env::consts::ARCH);
    println!("pkg: {}", env!("CARGO_PKG_NAME"));
    println!("bench: id");
    println!("iterations: {iterations}");
}

fn iteration_count_from_args() -> u64 {
    let mut args = std::env::args().skip(1);
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

fn run_benchmark<T>(name: &str, iterations: u64, mut operation: impl FnMut() -> T) {
    let iterations = iterations.max(1);
    for _ in 0..1_000 {
        black_box(operation());
    }

    let started_at = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }

    print_result(name, iterations, started_at.elapsed());
}

fn print_result(name: &str, iterations: u64, elapsed: Duration) {
    let elapsed_nanos = elapsed.as_nanos();
    let nanos_per_operation = elapsed_nanos as f64 / iterations as f64;
    println!("{name}: {nanos_per_operation:.2} ns/op ({iterations} iterations)");
}
