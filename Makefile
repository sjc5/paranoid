FUZZ_RUNS ?= 4096
XTASK ?= cargo run --manifest-path xtask/Cargo.toml --quiet --

DB_FEATURES := --no-default-features --features db

.PHONY: fuzz

# Compiles Paranoid with every feature enabled, including integration tests.
check:
	@cargo check --all-features --tests
	@$(MAKE) --no-print-directory playground-local-env-vault

# Runs the normal all-feature test suite.
test:
	@$(XTASK) with-isolated-test-db -- cargo test --all-features

# Runs every DB integration test inside an isolated PgBouncer-backed stack.
test-db:
	@$(XTASK) with-isolated-test-db -- cargo test $(DB_FEATURES)

# Runs only the KV DB integration tests inside the isolated DB stack.
test-db-kv:
	@$(XTASK) with-isolated-test-db -- cargo test $(DB_FEATURES) db::kv::postgres_tests

# Runs only the Fleet DB integration tests inside the isolated DB stack.
test-db-fleet:
	@$(XTASK) with-isolated-test-db -- cargo test $(DB_FEATURES) db::fleet::postgres_tests

# Runs only the Queue DB integration tests inside the isolated DB stack.
test-db-queue:
	@$(XTASK) with-isolated-test-db -- cargo test $(DB_FEATURES) db::queue::postgres_tests

# Checks the public API surface for no-feature, single-feature, and all-feature builds.
feature-gate:
	@$(MAKE) --no-print-directory feature-none
	@$(MAKE) --no-print-directory feature-crypto
	@$(MAKE) --no-print-directory feature-id
	@$(MAKE) --no-print-directory feature-local-lock
	@$(MAKE) --no-print-directory feature-local-env-vault
	@$(MAKE) --no-print-directory feature-web
	@$(MAKE) --no-print-directory feature-db
	@$(MAKE) --no-print-directory feature-db-test-harness
	@$(MAKE) --no-print-directory feature-all
	@$(MAKE) --no-print-directory playground-local-env-vault

# Checks the local-env-vault application wrapper playground.
playground-local-env-vault:
	@cargo check -p paranoid-local-env-vault-playground
	@cargo test -p paranoid-local-env-vault-playground

# Checks the empty-default feature surface.
feature-none:
	@cargo check
	@cargo test --lib
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
	@cargo test --doc

# Checks one single-feature surface; the feature name is derived from the target name.
feature-crypto feature-id feature-local-lock feature-local-env-vault:
	@cargo check --no-default-features --features '$(@:feature-%=%)' --tests
	@cargo test --no-default-features --features '$(@:feature-%=%)' --lib
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-default-features --features '$(@:feature-%=%)' --no-deps
	@cargo test --no-default-features --features '$(@:feature-%=%)' --doc

# Checks the db feature surface without running DB-backed tests; runtime DB coverage is in test-db.
feature-db:
	@cargo check --no-default-features --features db --tests
	@cargo test --no-default-features --features db --lib --no-run
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-default-features --features db --no-deps
	@cargo test --no-default-features --features db --doc

# Checks the public DB test harness feature without running unrelated DB tests outside the harness.
feature-db-test-harness:
	@cargo check --no-default-features --features db-test-harness --tests
	@cargo test --no-default-features --features db-test-harness db::testing
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-default-features --features db-test-harness --no-deps
	@cargo test --no-default-features --features db-test-harness --doc

# Checks the web feature surface, including the web integration test.
feature-web:
	@cargo check --no-default-features --features web --tests
	@cargo test --no-default-features --features web --lib
	@cargo test --no-default-features --features web --test web_stack
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-default-features --features web --no-deps
	@cargo test --no-default-features --features web --doc

# Checks the all-features public surface.
feature-all:
	@cargo check --all-features --tests
	@cargo test --all-features --no-run
	@RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
	@cargo test --all-features --doc

# Runs clippy across every target and feature with warnings denied.
clippy-gate:
	@cargo clippy --all-targets --all-features -- -D warnings

# Runs unit tests for the maintainer xtask crate.
tool-gate:
	@cargo test --manifest-path xtask/Cargo.toml

# Compiles benchmark targets without running benchmarks.
bench-gate:
	@cargo bench --all-features --no-run

# Runs every cargo-fuzz target through the local fuzz gate.
fuzz:
	@$(XTASK) fuzz-gate --runs '$(FUZZ_RUNS)'

# Runs the full local confidence gate.
gate:
	@$(XTASK) gate --runs '$(FUZZ_RUNS)'

# Formats non-Rust files with oxfmt per explicit config.
non-rust-fmt:
	pnpm exec oxfmt --config=oxfmt.config.ts --write .
