use super::sql_state::{
    SQLSTATE_CHECK_VIOLATION, SQLSTATE_DEADLOCK_DETECTED, SQLSTATE_FOREIGN_KEY_VIOLATION,
    SQLSTATE_NOT_NULL_VIOLATION, SQLSTATE_SERIALIZATION_FAILURE, SQLSTATE_UNIQUE_VIOLATION,
};
use super::*;
use proptest::prelude::*;
use secrecy::SecretString;
use sqlx::{ConnectOptions, Execute};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

#[test]
fn pg_identifier_accepts_safe_unqualified_names() {
    for input in ["users", "_private", "Table_123", &"a".repeat(63)] {
        let identifier = PgIdentifier::new(input).expect("identifier");
        assert_eq!(identifier.as_str(), input);
        assert_eq!(identifier.quoted().to_string(), format!("\"{input}\""));
    }
}

#[test]
fn pg_identifier_rejects_injection_and_ambiguous_names() {
    let cases = [
        "",
        "1table",
        "has-hyphen",
        "has space",
        "has.dot",
        "has\"quote",
        "has\0nul",
        "éclair",
        &"a".repeat(64),
    ];

    for input in cases {
        assert!(
            PgIdentifier::new(input).is_err(),
            "expected rejection for {input:?}"
        );
    }
}

#[test]
fn qualified_table_names_quote_each_part() {
    let unqualified = PgQualifiedTableName::unqualified("__paranoid_kv_store").expect("table");
    assert_eq!(unqualified.quoted().to_string(), "\"__paranoid_kv_store\"");

    let schema = PgSchemaName::from_identifier_text("auth_schema").expect("schema");
    assert_eq!(schema.as_str(), "auth_schema");

    let qualified = PgQualifiedTableName::with_schema("auth_schema", "__paranoid_queue_jobs")
        .expect("qualified table");
    assert_eq!(
        qualified.quoted().to_string(),
        "\"auth_schema\".\"__paranoid_queue_jobs\""
    );
}

#[test]
fn qualified_table_names_reject_prejoined_names() {
    assert!(PgQualifiedTableName::unqualified("public.users").is_err());
    assert!(PgQualifiedTableName::with_schema("public.auth", "users").is_err());
    assert!(PgQualifiedTableName::with_schema("public", "users;drop").is_err());
}

proptest! {
    #[test]
    fn generated_pg_identifier_text_matches_public_ascii_identifier_contract(
        raw_bytes in prop::collection::vec(any::<u8>(), 0..=96),
    ) {
        let input = String::from_utf8_lossy(&raw_bytes).into_owned();
        let result = PgIdentifier::new(&input);
        let expected_valid = pg_identifier_text_matches_public_contract(&input);

        prop_assert_eq!(
            result.is_ok(),
            expected_valid,
            "identifier text {:?} bytes {:?}",
            input,
            input.as_bytes()
        );

        if let Ok(identifier) = result {
            prop_assert_eq!(identifier.as_str(), input.as_str());
            prop_assert_eq!(identifier.quoted().to_string(), format!("\"{input}\""));
            prop_assert_eq!(
                PgIdentifier::from_str(&input).expect("from_str should match new"),
                identifier
            );
        }
    }

    #[test]
    fn generated_qualified_table_names_quote_valid_parts_without_accepting_joined_text(
        schema in generated_valid_pg_identifier_text(),
        table in generated_valid_pg_identifier_text(),
    ) {
        let qualified = PgQualifiedTableName::with_schema(&schema, &table)
            .expect("generated schema and table identifiers should be valid");

        prop_assert_eq!(
            qualified.quoted().to_string(),
            format!("\"{schema}\".\"{table}\"")
        );
        prop_assert_eq!(qualified.schema().expect("schema").as_str(), schema.as_str());
        prop_assert_eq!(qualified.table().as_str(), table.as_str());

        prop_assert!(
            PgQualifiedTableName::unqualified(format!("{schema}.{table}")).is_err(),
            "prejoined table text must be rejected instead of accepted as a raw identifier"
        );
    }
}

fn generated_valid_pg_identifier_text() -> impl Strategy<Value = String> {
    let first_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
        .chars()
        .collect::<Vec<_>>();
    let trailing_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        .chars()
        .collect::<Vec<_>>();

    (
        prop::sample::select(first_chars),
        prop::collection::vec(
            prop::sample::select(trailing_chars),
            0..MAX_PG_IDENTIFIER_BYTES,
        ),
    )
        .prop_map(|(first, trailing)| {
            let mut identifier = String::with_capacity(1 + trailing.len());
            identifier.push(first);
            identifier.extend(trailing);
            identifier
        })
}

fn pg_identifier_text_matches_public_contract(input: &str) -> bool {
    let bytes = input.as_bytes();
    let Some((&first, trailing)) = bytes.split_first() else {
        return false;
    };

    bytes.len() <= MAX_PG_IDENTIFIER_BYTES
        && (first == b'_' || first.is_ascii_alphabetic())
        && trailing
            .iter()
            .all(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
}

#[test]
fn schema_ledger_migration_sql_uses_c_collation_and_no_session_level_postgres_features() {
    let config = SchemaLedgerConfig::default();
    let statement = build_migrate_schema_ledger_statement_for_test(&config);
    let statement_lowercase = statement.to_lowercase();

    assert!(statement.contains(r#"component TEXT COLLATE "C" NOT NULL CHECK"#));
    assert!(statement.contains(r#"instance_key TEXT COLLATE "C" NOT NULL CHECK"#));
    assert!(statement.contains(r#"schema_fingerprint TEXT COLLATE "C" NOT NULL CHECK"#));
    assert!(statement.contains("PRIMARY KEY (component, instance_key)"));
    for forbidden in ["advisory", "listen", "notify"] {
        assert!(
            !statement_lowercase.contains(forbidden),
            "schema ledger SQL must not contain {forbidden:?}"
        );
    }
}

#[test]
fn pg_sql_state_maps_known_codes_and_preserves_unknown_codes() {
    assert_eq!(
        PgSqlState::from_code(SQLSTATE_UNIQUE_VIOLATION),
        PgSqlState::UniqueViolation
    );
    assert_eq!(
        PgSqlState::from_code(SQLSTATE_FOREIGN_KEY_VIOLATION),
        PgSqlState::ForeignKeyViolation
    );
    assert_eq!(
        PgSqlState::from_code(SQLSTATE_CHECK_VIOLATION),
        PgSqlState::CheckViolation
    );
    assert_eq!(
        PgSqlState::from_code(SQLSTATE_NOT_NULL_VIOLATION),
        PgSqlState::NotNullViolation
    );
    assert_eq!(
        PgSqlState::from_code(SQLSTATE_SERIALIZATION_FAILURE),
        PgSqlState::SerializationFailure
    );
    assert_eq!(
        PgSqlState::from_code(SQLSTATE_DEADLOCK_DETECTED),
        PgSqlState::DeadlockDetected
    );

    let other = PgSqlState::from_code("ZZ999");
    assert_eq!(other, PgSqlState::Other("ZZ999".to_owned()));
    assert_eq!(other.as_str(), "ZZ999");
}

#[test]
fn check_constraint_expression_matching_is_exact_after_normalization() {
    assert_eq!(
        normalize_check_constraint_expression("(( fencing_token > 0 ))"),
        "fencing_token>0"
    );
    assert_eq!(
        normalize_check_constraint_expression("(octet_length(lease_token) = 32)"),
        "octet_length(lease_token)=32"
    );
    assert_eq!(
        normalize_check_constraint_expression(
            "(octet_length(key) > 0 AND octet_length(key) <= 2048)"
        ),
        "octet_length(key)>0ANDoctet_length(key)<=2048"
    );
    assert_eq!(
        normalize_check_constraint_expression(
            "(octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512)"
        ),
        "octet_length(holder_id)>0ANDoctet_length(holder_id)<=512"
    );
    assert_ne!(
        normalize_check_constraint_expression("(fencing_token > 0) OR true"),
        "fencing_token>0"
    );
    assert_ne!(
        normalize_check_constraint_expression("(octet_length(lease_token) = 32) OR true"),
        "octet_length(lease_token)=32"
    );
    assert_ne!(
        normalize_check_constraint_expression(
            "(octet_length(key) > 0 AND octet_length(key) <= 2048) OR true"
        ),
        "octet_length(key)>0ANDoctet_length(key)<=2048"
    );
    assert_ne!(
        normalize_check_constraint_expression(
            "(octet_length(holder_id) > 0 AND octet_length(holder_id) <= 512) OR true"
        ),
        "octet_length(holder_id)>0ANDoctet_length(holder_id)<=512"
    );
}

#[test]
fn pooler_safe_connect_options_override_url_statement_cache_capacity() {
    let mut config = test_pool_config(
        "postgres://paranoid:secret@127.0.0.1:5432/paranoid_test?statement-cache-capacity=100&sslmode=disable",
    );
    config.application_name = Some("paranoid_db_foundation_test".to_owned());
    config.ssl_mode = Some(SslMode::VerifyFull);

    let options = build_pooler_safe_pg_connect_options(&config).expect("connect options");
    let url = options.to_url_lossy();
    let query_pairs = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();

    assert_eq!(
        query_pairs
            .get("statement-cache-capacity")
            .map(String::as_str),
        Some("0")
    );
    assert_eq!(
        options.get_application_name(),
        Some("paranoid_db_foundation_test")
    );
    assert!(matches!(
        options.get_ssl_mode(),
        sqlx::postgres::PgSslMode::VerifyFull
    ));
}

#[test]
fn portable_query_constructors_disable_persistent_prepared_statements() {
    let untyped_query = portable_query("SELECT 1");
    let row_query = portable_query_as::<(i64,)>("SELECT 1");
    let scalar_query = portable_query_scalar::<i64>("SELECT 1");
    let unparameterized_query = unparameterized_simple_query("SELECT 1");

    assert!(!Execute::persistent(&untyped_query));
    assert!(!Execute::persistent(&row_query));
    assert!(!Execute::persistent(&scalar_query));
    assert!(!<sqlx::RawSql as Execute<'_, sqlx::Postgres>>::persistent(
        &unparameterized_query
    ));
}

#[test]
fn production_db_code_uses_portable_query_constructors() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let forbidden_needles = [
        "sqlx::query(",
        "sqlx::query_as",
        "sqlx::query_scalar",
        "sqlx::raw_sql",
    ];
    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for needle in forbidden_needles {
            if source.contains(needle) {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!("{} contains {needle}", relative.display()));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Paranoid-owned DB code must use db::portable_query/db::portable_query_as/db::portable_query_scalar/db::unparameterized_simple_query so SQLx persistent prepared statements stay disabled and unparameterized simple-protocol SQL stays explicit:\n{}",
        violations.join("\n")
    );
}

#[test]
fn production_db_code_does_not_bypass_internal_pool_wrappers() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let forbidden_needles = [".sqlx_pool()"];
    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_public_pool_definition(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for needle in forbidden_needles {
            if source.contains(needle) {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!("{} contains {needle}", relative.display()));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Paranoid-owned DB code must not call the public raw SQLx pool accessor internally. Use Pool::begin_transaction plus the DB portable query constructors so transaction boundaries, operation observation, and internal portability stay centralized:\n{}",
        violations.join("\n")
    );
}

#[test]
fn production_db_sql_does_not_use_session_level_postgres_features() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let forbidden_needles = [
        "pg_advisory",
        "listen ",
        "notify ",
        "create temp",
        "create temporary",
        "set session",
        "prepare ",
        "deallocate ",
    ];
    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let source_lowercase = source.to_lowercase();
        for needle in forbidden_needles {
            if source_contains_forbidden_sql_phrase(&source_lowercase, needle) {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!("{} contains {needle:?}", relative.display()));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Paranoid-owned DB SQL must avoid session-level Postgres features and connection-pooler-hostile prepared-statement commands:\n{}",
        violations.join("\n")
    );
}

#[test]
fn production_db_set_config_calls_are_transaction_local() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let allowed_transaction_local_statement_timeout = "set_config('statement_timeout', $1, true)";
    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for (line_index, line) in source.lines().enumerate() {
            let line_lowercase = line.to_lowercase();
            if line_lowercase.contains("set_config(")
                && !line_lowercase.contains(allowed_transaction_local_statement_timeout)
            {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!(
                    "{}:{} contains a non-approved set_config call",
                    relative.display(),
                    line_index + 1
                ));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Paranoid-owned DB SQL may only use set_config for transaction-local worker statement timeouts; session-scoped set_config would violate transaction-pooler safety:\n{}",
        violations.join("\n")
    );
}

#[test]
fn production_db_sql_uses_statement_timestamp_for_database_owned_time() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let forbidden_clock_functions = [
        "current_timestamp",
        "transaction_timestamp(",
        "clock_timestamp(",
        "now(",
    ];
    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let source_lowercase = source.to_lowercase();
        for needle in forbidden_clock_functions {
            if source_contains_forbidden_database_clock_call(&source_lowercase, needle) {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!("{} contains {needle:?}", relative.display()));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Paranoid-owned DB SQL must use statement_timestamp() for database-owned lifecycle time instead of transaction, wall-clock, or application-side clock shortcuts:\n{}",
        violations.join("\n")
    );
}

#[test]
fn in_current_transaction_function_names_require_transaction_parameter() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for signature in rust_function_signatures(&source) {
            if signature.contains("_in_current_transaction(") && !signature.contains("&mut Tx<'_>")
            {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!(
                    "{} has transaction-named function without &mut Tx<'_>: {}",
                    relative.display(),
                    signature.replace('\n', " ")
                ));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Functions named *_in_current_transaction must encode caller-owned transaction usage in the Rust signature:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pool_owned_read_wrappers_use_rollback_only_transaction_finishers() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for function in rust_function_blocks(&source) {
            let Some(function_name) = rust_function_name(function.signature) else {
                continue;
            };
            if !is_pool_owned_read_function_name(function_name)
                || !function.signature.contains("pool: &Pool")
                || !function.body.contains("pool.begin_transaction()")
            {
                continue;
            }

            let uses_read_finisher = function.body.contains("_read_transaction(")
                || function
                    .body
                    .contains("finish_db_pool_validation_transaction(")
                || function.body.contains(
                    "finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error(",
                );
            if !uses_read_finisher {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!(
                    "{} has pool-owned read wrapper using a non-read transaction finisher: {}",
                    relative.display(),
                    function.signature.replace('\n', " ")
                ));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Pool-owned read wrappers that open transactions must roll back on success so accidental writes cannot persist through read-shaped APIs:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pool_owned_schema_validation_wrappers_use_rollback_only_transaction_finishers() {
    let violations = pool_owned_schema_wrapper_finisher_violations(
        "validate_schema",
        &[
            "finish_db_pool_validation_transaction(",
            "finish_queue_validation_transaction(",
            "finish_pool_owned_rollback_only_transaction_and_preserve_rollback_error(",
        ],
        "validation",
    );
    assert!(
        violations.is_empty(),
        "Pool-owned schema validation wrappers must roll back on success so validation probes cannot persist state:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pool_owned_schema_migration_wrappers_use_write_transaction_finishers() {
    let violations = pool_owned_schema_wrapper_finisher_violations(
        "migrate_schema",
        &[
            "finish_db_pool_transaction(",
            "finish_queue_pool_transaction(",
            "finish_pool_owned_write_transaction_and_preserve_rollback_error(",
        ],
        "write",
    );
    assert!(
        violations.is_empty(),
        "Pool-owned schema migration wrappers must commit on success and preserve rollback errors on failure through write finishers:\n{}",
        violations.join("\n")
    );
}

fn pool_owned_schema_wrapper_finisher_violations(
    function_name: &str,
    accepted_finishers: &[&str],
    finisher_label: &str,
) -> Vec<String> {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for function in rust_function_blocks(&source) {
            if rust_function_name(function.signature) != Some(function_name)
                || !function.signature.contains("pool: &Pool")
                || !function.body.contains("pool.begin_transaction()")
            {
                continue;
            }

            if !accepted_finishers
                .iter()
                .any(|finisher| function.body.contains(finisher))
            {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!(
                    "{} has pool-owned {function_name} wrapper using a non-{finisher_label} transaction finisher: {}",
                    relative.display(),
                    function.signature.replace('\n', " ")
                ));
            }
        }
    }

    violations.sort();
    violations
}

#[test]
fn schema_migrations_record_versions_only_after_physical_validation() {
    let kv_schema_source = read_crate_source_file("src/db/kv/schema.rs");
    let kv_body =
        rust_function_body_by_name(&kv_schema_source, "migrate_schema_in_current_transaction");
    assert_source_order(
        kv_body,
        "validate_physical_schema_in_current_transaction(tx, config).await?",
        "record_kv_schema_version_in_current_transaction(tx, config).await?",
        "KV migration must physically validate the migrated schema before recording its schema version",
    );
    assert_source_order(
        kv_body,
        "record_kv_schema_version_in_current_transaction(tx, config).await?",
        "validate_schema_in_current_transaction(tx, config).await",
        "KV migration must revalidate the recorded schema version before commit",
    );

    let queue_schema_source = read_crate_source_file("src/db/queue/schema.rs");
    let queue_body = rust_function_body_by_name(
        &queue_schema_source,
        "migrate_schema_in_current_transaction",
    );
    assert_source_order(
        queue_body,
        "validate_physical_schema_in_current_transaction(tx, queue.config()).await?",
        "record_queue_schema_version_in_current_transaction(tx, queue.config()).await?",
        "Queue migration must physically validate the migrated schema before recording its schema version",
    );
    assert_source_order(
        queue_body,
        "record_queue_schema_version_in_current_transaction(tx, queue.config()).await?",
        "validate_queue_schema_version_in_current_transaction(tx, queue.config()).await?",
        "Queue migration must revalidate the recorded schema version before commit",
    );

    let fleet_store_source = read_crate_source_file("src/db/fleet/store.rs");
    let fleet_body = rust_function_body_by_name_containing(
        &fleet_store_source,
        "migrate_schema_in_current_transaction",
        "record_fleet_schema_version_in_current_transaction",
    );
    assert_source_order(
        fleet_body,
        "migrate_kv_schema_in_current_transaction(tx, &config.kv_store_config()).await?",
        "record_fleet_schema_version_in_current_transaction(tx, config).await?",
        "Fleet migration must finish migrating and validating its KV backing store before recording Fleet's schema version",
    );
    assert_source_order(
        fleet_body,
        "migrate_lease_schema_in_current_transaction(tx, &config.lease_store_config()).await?",
        "record_fleet_schema_version_in_current_transaction(tx, config).await?",
        "Fleet migration must finish migrating and validating its lease backing store before recording Fleet's schema version",
    );
    assert_source_order(
        fleet_body,
        "record_fleet_schema_version_in_current_transaction(tx, config).await?",
        "validate_schema_in_current_transaction(tx, config).await",
        "Fleet migration must revalidate the recorded schema version before commit",
    );
}

#[test]
fn direct_transaction_finish_calls_are_centralized() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path)
            || path_allows_direct_transaction_finish_calls(&path)
        {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for (line_index, line) in source.lines().enumerate() {
            if line.contains(".commit().await") || line.contains(".rollback().await") {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!(
                    "{}:{} directly finishes a transaction",
                    relative.display(),
                    line_index + 1
                ));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Direct transaction commit/rollback calls in production DB code must stay centralized in Tx itself, shared transaction finishers, or the explicitly audited Fleet Once atomic runner:\n{}",
        violations.join("\n")
    );
}

#[test]
fn pool_owned_transaction_begins_use_centralized_finishers() {
    let db_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db");
    let mut source_files = Vec::new();
    collect_db_source_files(&db_root, &mut source_files);

    let mut violations = Vec::new();
    for path in source_files {
        if path_is_db_test_or_pooler_safe_query_helper(&path)
            || path_allows_direct_transaction_finish_calls(&path)
        {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for function in rust_function_blocks(&source) {
            if !function_opens_pool_owned_transaction(function) {
                continue;
            }
            let Some(function_name) = rust_function_name(function.signature) else {
                continue;
            };
            if function_name == "begin_worker_database_operation" {
                continue;
            }
            if !function_uses_centralized_transaction_finisher(function) {
                let relative = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                violations.push(format!(
                    "{} starts a pool-owned transaction without a centralized finisher: {}",
                    relative.display(),
                    function.signature.replace('\n', " ")
                ));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Pool-owned transaction wrappers must use centralized transaction finishers so commit/rollback behavior and rollback-error preservation stay uniform:\n{}",
        violations.join("\n")
    );
}

#[test]
fn fleet_async_drop_cleanup_uses_captured_runtime_handles() {
    for (relative_path, guard_type) in [
        ("src/db/fleet/mutex_guard.rs", "MutexGuard"),
        ("src/db/fleet/semaphore.rs", "SemaphoreClaimGuard"),
        ("src/db/fleet/throttler_guard.rs", "ThrottlerPermitGuard"),
    ] {
        let source = read_crate_source_file(relative_path);
        let drop_body = rust_drop_impl_body(&source, guard_type);
        assert!(
            drop_body.contains("self.runtime_handle.spawn("),
            "{relative_path} Drop for {guard_type} must schedule cleanup through the guard's captured runtime handle"
        );
    }
}

#[test]
fn fleet_live_cleanup_guard_types_are_must_use() {
    for (relative_path, guard_type) in [
        ("src/db/fleet/mutex_model.rs", "MutexGuard"),
        ("src/db/fleet/semaphore_model.rs", "SemaphoreClaimGuard"),
        ("src/db/fleet/throttler_model.rs", "ThrottlerPermitGuard"),
        ("src/db/fleet/throttler_model.rs", "RateLimiterPermitGuard"),
        (
            "src/db/fleet/throttler_model.rs",
            "CircuitBreakerPermitGuard",
        ),
    ] {
        let source = read_crate_source_file(relative_path);
        assert!(
            rust_struct_declaration_has_attribute(&source, guard_type, "#[must_use"),
            "{relative_path} {guard_type} owns live cleanup state and must stay #[must_use]"
        );
    }
}

#[test]
fn queue_worker_cleanup_ordering_preserves_async_boundaries() {
    let source = read_crate_source_file("src/db/queue/worker_job.rs");
    let process_body = rust_function_body_by_name(&source, "process_claimed_queue_job");
    assert_source_order(
        process_body,
        "stop_worker_heartbeat_loop(heartbeat_handle).await",
        "let finalization_result =",
        "queue worker heartbeat must be stopped before terminal job finalization",
    );

    let cleanup_body =
        rust_function_body_by_name(&source, "return_claimed_jobs_after_worker_task_failure");
    assert_source_order(
        cleanup_body,
        "return_available_owned_unstarted_running_jobs_to_pending_with_database_operation_timeout",
        "return_available_owned_started_running_jobs_to_pending_with_database_operation_timeout",
        "worker cleanup must return unstarted claims before started claims",
    );
    assert_source_order(
        cleanup_body,
        "return_available_owned_started_running_jobs_to_pending_with_database_operation_timeout",
        "count_worker_owned_running_jobs_with_database_operation_timeout",
        "queue worker cleanup must return unstarted claims, then started claims, then count remaining ownership",
    );
}

#[test]
fn queue_reclaim_maintenance_stays_atomic_and_ordered() {
    let api_source = read_crate_source_file("src/db/queue/api/listing_and_maintenance.rs");
    let pool_wrapper_body =
        rust_function_body_by_name(&api_source, "reclaim_available_stale_running_jobs_once");
    assert_source_order(
        pool_wrapper_body,
        "pool.begin_transaction()",
        "reclaim_available_stale_running_jobs_once_in_current_transaction(",
        "queue reclaim pool wrapper must start a transaction before running reclaim stages",
    );
    assert_source_order(
        pool_wrapper_body,
        "reclaim_available_stale_running_jobs_once_in_current_transaction(",
        "finish_queue_pool_transaction(\"reclaim stale running jobs once\"",
        "queue reclaim pool wrapper must finish the transaction through the centralized finisher",
    );

    let maintenance_source = read_crate_source_file("src/db/queue/operations/maintenance.rs");
    let reclaim_body = rust_function_body_by_name(
        &maintenance_source,
        "reclaim_available_stale_running_jobs_once_in_current_transaction",
    );
    assert_source_order(
        reclaim_body,
        "let never_started_jobs_returned_to_pending = reclaim_never_started_running_jobs(",
        "let expired_jobs_moved_to_failed = reclaim_expired_running_jobs_to_failed(",
        "stale reclaim must return never-started claims before handling expired executions",
    );
    assert_source_order(
        reclaim_body,
        "let expired_jobs_moved_to_failed = reclaim_expired_running_jobs_to_failed(",
        "move_failed_jobs_to_dead_letter_batch(",
        "stale reclaim must dead-letter only jobs already moved to failed in the same transaction",
    );
    assert_source_order(
        reclaim_body,
        "move_failed_jobs_to_dead_letter_batch(",
        "let expired_jobs_returned_to_pending_for_retry =",
        "stale reclaim must finish max-retry dead lettering before retryable jobs return to pending",
    );
    assert!(
        reclaim_body.contains(".map(|job| job.id)"),
        "stale reclaim dead-letter stage must derive its batch from the failed jobs returned by the previous stage"
    );
}

#[test]
fn queue_cleanup_until_empty_commits_each_batch_before_delay() {
    let source = read_crate_source_file("src/db/queue/operations/maintenance.rs");
    let body = rust_function_body_by_name(&source, "cleanup_target_older_than_until_empty");
    assert_source_order(
        body,
        "RuntimeCancellationSignal::is_cancellation_requested",
        "pool.begin_transaction()",
        "queue cleanup-until-empty must observe cancellation before opening the next batch transaction",
    );
    assert_source_order(
        body,
        "pool.begin_transaction()",
        "finish_queue_pool_transaction(",
        "queue cleanup-until-empty must finish each batch transaction after opening it",
    );
    assert_source_order(
        body,
        "finish_queue_pool_transaction(",
        "checked_add_cleanup_total(",
        "queue cleanup-until-empty must count only committed batch results",
    );
    assert_source_order(
        body,
        "if deleted < u64::from(batch_size)",
        "sleep_before_next_cleanup_batch_or_cancellation(",
        "queue cleanup-until-empty must decide whether more work remains before the cancellable delay",
    );
    assert_source_order(
        body,
        "finish_queue_pool_transaction(",
        "sleep_before_next_cleanup_batch_or_cancellation(",
        "queue cleanup-until-empty must not sleep between batches until the current batch transaction is closed",
    );
}

#[test]
fn queue_fleet_maintenance_supervisor_cancels_and_awaits_all_components() {
    let source = read_crate_source_file("src/db/queue/worker_maintenance.rs");
    let run_body =
        rust_function_body_by_name(&source, "run_queue_worker_loop_with_fleet_maintenance");
    for required in [
        "worker_join_result = &mut worker_join_handle",
        "reclaim_join_result = &mut reclaim_join_handle",
        "cleanup_join_result = &mut cleanup_join_handle",
    ] {
        assert!(
            run_body.contains(required),
            "queue Fleet maintenance supervisor must select on {required}"
        );
    }

    let worker_stopped_body =
        rust_function_body_by_name(&source, "finish_queue_worker_after_worker_stopped");
    assert_source_order(
        worker_stopped_body,
        "runtime.worker_shutdown_signal.request_cancellation();",
        "reclaim_join_handle.await",
        "queue maintenance supervisor must request cancellation before awaiting reclaim cron",
    );
    assert_source_order(
        worker_stopped_body,
        "runtime.worker_shutdown_signal.request_cancellation();",
        "cleanup_join_handle.await",
        "queue maintenance supervisor must request cancellation before awaiting cleanup cron",
    );

    let maintenance_stopped_body = rust_function_body_by_name(
        &source,
        "finish_queue_worker_after_maintenance_cron_stopped",
    );
    assert_source_order(
        maintenance_stopped_body,
        "runtime.worker_shutdown_signal.request_cancellation();",
        "worker_join_handle.await",
        "queue maintenance supervisor must request cancellation before awaiting worker loop",
    );
    assert_source_order(
        maintenance_stopped_body,
        "runtime.worker_shutdown_signal.request_cancellation();",
        "other_cron_join_handle.await",
        "queue maintenance supervisor must request cancellation before awaiting the other cron",
    );
}

#[test]
fn fleet_cron_tenure_checks_stop_and_leadership_between_task_runs() {
    let source = read_crate_source_file("src/db/fleet/cron.rs");
    let body = rust_function_body_by_name(
        &source,
        "run_single_leadership_tenure_until_stopped_with_task_error_policy",
    );
    assert_source_order(
        body,
        "self.execute_task_while_guarded(&guard, &mut *task).await",
        "let sleep = tokio::time::sleep(self.interval);",
        "Fleet cron must run the guarded task before entering the between-run wait",
    );
    assert_source_order(
        body,
        "() = stop.as_mut() =>",
        "guard.release().await.map_err(|source| CronRunError::Release { source })?",
        "Fleet cron must release leadership when stop wins the between-run wait",
    );
    assert!(
        body.contains("() = guard.wait_until_leadership_lost() =>"),
        "Fleet cron between-run wait must observe leadership loss"
    );
    assert!(
        body.contains("release_cron_guard_after_leadership_lost(guard.release().await)"),
        "Fleet cron leadership-loss paths must release guard ownership"
    );
}

#[test]
fn db_retry_loops_are_limited_to_acquisition_database_or_explicit_runtime_semantics() {
    let kv_store_source = read_crate_source_file("src/db/kv/store.rs");
    assert_source_contains_all(
        rust_function_body_by_name(
            &kv_store_source,
            "delete_expired_keys_until_empty_with_delay_between_batches",
        ),
        &[
            "loop {",
            "self.delete_expired_keys_once(pool, batch_size).await?",
            "deleted < u64::from(batch_size)",
        ],
        "KV expired cleanup retry loop must stay a database-only batch drain",
    );

    let kv_item_source = read_crate_source_file("src/db/kv/item_lifecycle.rs");
    assert_source_contains_all(
        rust_function_body_by_name(
            &kv_item_source,
            "delete_entire_namespace_in_current_transaction",
        ),
        &[
            "loop {",
            ".delete_namespace_keys_with_prefix_once_in_current_transaction(",
            "deleted < u64::from(MAX_KV_DELETE_BATCH_SIZE)",
        ],
        "KV namespace cleanup retry loop must stay a database-only batch drain",
    );

    let fleet_mutex_source = read_crate_source_file("src/db/fleet/mutex.rs");
    assert_source_contains_all(
        rust_function_body_by_name(&fleet_mutex_source, "claim_guard_for_holder_when_available"),
        &[
            "loop {",
            ".try_claim_manual_renewal_for_holder(pool, holder_id)",
            "tokio::time::sleep(fleet_mutex_acquire_retry_delay_with_jitter(",
        ],
        "Fleet mutex blocking acquire retry loop must stay pre-task acquisition",
    );

    let fleet_semaphore_source = read_crate_source_file("src/db/fleet/semaphore.rs");
    assert_source_contains_all(
        rust_function_body_by_name(&fleet_semaphore_source, "run_task_when_available"),
        &[
            "let mut pending_task = Some(task);",
            "loop {",
            "if let Some(guard) = self.try_acquire_guard(pool).await?",
            "let task = pending_task",
            "return Ok(guard.run_task(task).await);",
        ],
        "Fleet semaphore blocking task helper must keep caller task pending until acquisition succeeds",
    );

    let fleet_throttler_source = read_crate_source_file("src/db/fleet/throttler_acquire.rs");
    assert_source_contains_all(
        rust_function_body_by_name(
            &fleet_throttler_source,
            "acquire_with_optional_holder_when_ready",
        ),
        &[
            "loop {",
            ".try_acquire_with_optional_holder(pool, holder_id)",
            "ThrottlerManualPermitAcquireResult::Acquired(permit) => return Ok(permit)",
            "tokio::time::sleep(",
        ],
        "Fleet throttler blocking acquire retry loop must stay pre-task acquisition",
    );

    let fleet_cache_source = read_crate_source_file("src/db/fleet/cache.rs");
    assert_source_contains_all(
        rust_function_body_by_name(&fleet_cache_source, "acquire_compute_mutex_guard"),
        &[
            "loop {",
            "if let Some(guard) = mutex.try_claim_guard(pool, guard_config).await?",
            "CoalescingCacheLockWaitTimedOut",
        ],
        "Fleet cache lock retry loop must stay pre-compute acquisition",
    );
    assert_source_order(
        rust_function_body_by_name(&fleet_cache_source, "fetch_or_compute"),
        "let guard = self.acquire_compute_mutex_guard(pool, &mutex).await?;",
        ".fetch_or_compute_while_holding_mutex(pool, &key_parts, &guard, compute_value)",
        "Fleet cache compute callback must run only after the compute mutex is acquired",
    );

    let fleet_topic_source = read_crate_source_file("src/db/fleet/topic.rs");
    let subscription_loop_body = rust_function_body_by_name(
        &fleet_topic_source,
        "run_polling_until_stopped_or_handler_error_with_poll_error_policy_and_success_hook",
    );
    assert_source_contains_all(
        subscription_loop_body,
        &[
            "subscription_poll_error_retry_delay_from_policy(error, &mut on_poll_error)",
            "if let Err(source) = handle_events(events).await",
            "if let Err(source) = self.advance_cursor_if_needed(pool, new_cursor).await",
        ],
        "Fleet subscription retry policy must stay scoped to database polling errors",
    );
    assert_source_order(
        subscription_loop_body,
        "if let Err(source) = handle_events(events).await",
        "if let Err(source) = self.advance_cursor_if_needed(pool, new_cursor).await",
        "Fleet subscription must advance the cursor only after handler success",
    );

    let queue_enqueue_source = read_crate_source_file("src/db/queue/operations/enqueue.rs");
    let dedupe_enqueue_body = rust_function_body_by_name(
        &queue_enqueue_source,
        "execute_dedupe_enqueue_in_current_transaction",
    );
    assert_source_contains_all(
        dedupe_enqueue_body,
        &[
            "for attempt_index in 0..MAX_QUEUE_DEDUPE_INSERT_ATTEMPTS",
            "DedupeEnqueueAttemptOutcome::RetryAfterInvisibleConflict",
            "prepared.job_id = JobId::new()?",
        ],
        "Queue dedupe enqueue retry loop must stay a database-only invisible-conflict retry",
    );
    assert_source_contains_none(
        dedupe_enqueue_body,
        &["handler", "TaskHandler", "run_queue_task_handler"],
        "Queue dedupe enqueue retry loop must not execute caller handlers",
    );

    let queue_operator_source = read_crate_source_file("src/db/queue/api/operator_transitions.rs");
    let retry_failed_body = rust_function_body_by_name(
        &queue_operator_source,
        "retry_available_failed_jobs_in_current_transaction",
    );
    assert_source_contains_all(
        retry_failed_body,
        &[
            "for attempt_index in 0..5",
            "SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
            "sqlx_error_is_active_dedupe_unique_violation",
            "ROLLBACK TO SAVEPOINT __paranoid_queue_retry_available_failed_jobs",
        ],
        "Queue retry-available-failed-jobs retry loop must stay a savepoint-scoped database retry",
    );
    assert_source_contains_none(
        retry_failed_body,
        &["handler", "TaskHandler", "run_queue_task_handler"],
        "Queue retry-available-failed-jobs retry loop must not execute caller handlers",
    );

    let queue_runtime_source = read_crate_source_file("src/db/queue/runtime_helpers.rs");
    let worker_database_retry_body = rust_function_body_by_name(
        &queue_runtime_source,
        "retry_worker_database_operation_while_job_locked",
    );
    assert!(
        queue_runtime_source.contains("F: FnMut(Duration) -> Fut"),
        "Queue worker lock retry helper must stay parameterized over database-operation closures"
    );
    assert_source_contains_all(
        worker_database_retry_body,
        &[
            "Err(Error::JobLockedByConcurrentTransaction)",
            "remaining_worker_database_operation_timeout",
        ],
        "Queue worker lock retry helper must stay a database-operation retry with a shrinking timeout budget",
    );
    assert_source_contains_none(
        worker_database_retry_body,
        &["TaskHandler", "run_queue_task_handler", "handler("],
        "Queue worker lock retry helper must not execute caller handlers",
    );

    let queue_worker_source = read_crate_source_file("src/db/queue/worker_job.rs");
    assert!(
        !rust_function_body_by_name(&queue_worker_source, "run_queue_task_handler")
            .contains("retry_worker_database_operation_while_job_locked("),
        "Queue task handler execution must not be wrapped by the worker database retry helper"
    );
    assert_source_contains_none(
        rust_function_body_by_name(
            &queue_worker_source,
            "return_claimed_jobs_after_worker_task_failure",
        ),
        &["TaskHandler", "run_queue_task_handler", "handler("],
        "Queue claimed-job cleanup loop must not execute caller handlers",
    );

    let queue_maintenance_source = read_crate_source_file("src/db/queue/operations/maintenance.rs");
    assert_source_contains_all(
        rust_function_body_by_name(
            &queue_maintenance_source,
            "cleanup_target_older_than_until_empty",
        ),
        &[
            "loop {",
            "finish_queue_pool_transaction(operation, tx, deleted).await?",
            "deleted < u64::from(batch_size)",
            "cancellation_signal",
        ],
        "Queue cleanup-until-empty loop must stay a committed batch-maintenance loop",
    );
}

fn function_opens_pool_owned_transaction(function: RustFunctionBlock<'_>) -> bool {
    function.signature.contains("pool: &Pool") && function.body.contains(".begin_transaction()")
}

fn function_uses_centralized_transaction_finisher(function: RustFunctionBlock<'_>) -> bool {
    [
        "finish_db_pool_transaction(",
        "finish_db_pool_validation_transaction(",
        "finish_fleet_pool_transaction(",
        "finish_kv_callback_pool_transaction(",
        "finish_kv_pool_transaction(",
        "finish_kv_read_transaction(",
        "finish_lease_pool_transaction(",
        "finish_lease_read_transaction(",
        "finish_queue_pool_transaction(",
        "finish_queue_read_transaction(",
        "finish_queue_validation_transaction(",
        "finish_worker_database_operation(",
    ]
    .iter()
    .any(|finisher| function.body.contains(finisher))
}

fn rust_function_signatures(source: &str) -> Vec<&str> {
    let mut signatures = Vec::new();
    let mut search_start = 0;
    while let Some(offset) = source[search_start..].find("fn ") {
        let fn_start = search_start + offset;
        let Some(open_brace_offset) = source[fn_start..].find('{') else {
            break;
        };
        let signature_end = fn_start + open_brace_offset;
        signatures.push(&source[fn_start..signature_end]);
        search_start = signature_end + 1;
    }
    signatures
}

fn read_crate_source_file(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {relative_path}: {error}"))
}

#[derive(Clone, Copy)]
struct RustFunctionBlock<'a> {
    signature: &'a str,
    body: &'a str,
}

fn rust_function_blocks(source: &str) -> Vec<RustFunctionBlock<'_>> {
    let mut functions = Vec::new();
    let mut search_start = 0;
    while let Some(offset) = source[search_start..].find("fn ") {
        let fn_start = search_start + offset;
        let Some(open_brace_offset) = source[fn_start..].find('{') else {
            break;
        };
        let open_brace = fn_start + open_brace_offset;
        let Some(close_brace) = find_matching_brace(source, open_brace) else {
            break;
        };
        functions.push(RustFunctionBlock {
            signature: &source[fn_start..open_brace],
            body: &source[open_brace + 1..close_brace],
        });
        search_start = close_brace + 1;
    }
    functions
}

fn rust_function_body_by_name<'a>(source: &'a str, function_name: &str) -> &'a str {
    rust_function_blocks(source)
        .into_iter()
        .find(|function| rust_function_name(function.signature) == Some(function_name))
        .unwrap_or_else(|| panic!("missing function {function_name}"))
        .body
}

fn rust_function_body_by_name_containing<'a>(
    source: &'a str,
    function_name: &str,
    required_body_needle: &str,
) -> &'a str {
    rust_function_blocks(source)
        .into_iter()
        .find(|function| {
            rust_function_name(function.signature) == Some(function_name)
                && function.body.contains(required_body_needle)
        })
        .unwrap_or_else(|| {
            panic!("missing function {function_name} containing {required_body_needle:?}")
        })
        .body
}

fn rust_drop_impl_body<'a>(source: &'a str, type_name: &str) -> &'a str {
    let needle = format!("impl Drop for {type_name}");
    let impl_start = source
        .find(&needle)
        .unwrap_or_else(|| panic!("missing {needle}"));
    let open_brace = impl_start
        + source[impl_start..]
            .find('{')
            .unwrap_or_else(|| panic!("missing opening brace for {needle}"));
    let close_brace = find_matching_brace(source, open_brace)
        .unwrap_or_else(|| panic!("missing closing brace for {needle}"));
    &source[open_brace + 1..close_brace]
}

fn rust_struct_declaration_has_attribute(
    source: &str,
    type_name: &str,
    attribute_prefix: &str,
) -> bool {
    let struct_needle = format!("pub struct {type_name}");
    let struct_start = find_source_needle_with_identifier_boundary(source, &struct_needle)
        .unwrap_or_else(|| panic!("missing {struct_needle}"));
    let preceding = &source[..struct_start];
    preceding
        .lines()
        .rev()
        .take_while(|line| {
            let trimmed = line.trim();
            trimmed.is_empty()
                || trimmed.starts_with("#[")
                || trimmed.starts_with("///")
                || trimmed.starts_with("#[derive")
        })
        .any(|line| line.trim_start().starts_with(attribute_prefix))
}

fn assert_source_order(source: &str, first: &str, second: &str, message: &str) {
    let first_position = source
        .find(first)
        .unwrap_or_else(|| panic!("missing source needle {first:?}"));
    let second_position = source
        .find(second)
        .unwrap_or_else(|| panic!("missing source needle {second:?}"));
    assert!(first_position < second_position, "{message}");
}

fn assert_source_contains_all(source: &str, needles: &[&str], message: &str) {
    for needle in needles {
        assert!(
            source.contains(needle),
            "{message}: missing source needle {needle:?}"
        );
    }
}

fn assert_source_contains_none(source: &str, needles: &[&str], message: &str) {
    for needle in needles {
        assert!(
            !source.contains(needle),
            "{message}: unexpected source needle {needle:?}"
        );
    }
}

fn find_source_needle_with_identifier_boundary(source: &str, needle: &str) -> Option<usize> {
    let mut search_start = 0;
    while let Some(offset) = source[search_start..].find(needle) {
        let absolute_start = search_start + offset;
        let after_needle = absolute_start + needle.len();
        let followed_by_identifier_char = source[after_needle..]
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if !followed_by_identifier_char {
            return Some(absolute_start);
        }
        search_start = after_needle;
    }
    None
}

fn find_matching_brace(source: &str, open_brace: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open_brace..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_brace + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn rust_function_name(signature: &str) -> Option<&str> {
    let after_fn = signature.split_once("fn ")?.1;
    let name_end = after_fn
        .find(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .unwrap_or(after_fn.len());
    Some(&after_fn[..name_end])
}

fn is_pool_owned_read_function_name(function_name: &str) -> bool {
    if function_name.contains("_or_init") {
        return false;
    }
    ["fetch_", "get_", "check_", "count_", "list_", "scan_"]
        .iter()
        .any(|prefix| function_name.starts_with(prefix))
}

fn source_contains_forbidden_sql_phrase(source_lowercase: &str, needle: &str) -> bool {
    let mut search_start = 0;
    while let Some(offset) = source_lowercase[search_start..].find(needle) {
        let absolute_start = search_start + offset;
        let preceded_by_identifier_char = source_lowercase[..absolute_start]
            .chars()
            .next_back()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if !preceded_by_identifier_char {
            return true;
        }
        search_start = absolute_start + needle.len();
    }
    false
}

fn source_contains_forbidden_database_clock_call(source_lowercase: &str, needle: &str) -> bool {
    let mut search_start = 0;
    while let Some(offset) = source_lowercase[search_start..].find(needle) {
        let absolute_start = search_start + offset;
        let preceding_char = source_lowercase[..absolute_start].chars().next_back();
        let preceded_by_identifier_char =
            preceding_char.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        let preceded_by_rust_namespace_or_method =
            preceding_char.is_some_and(|ch| ch == ':' || ch == '.');
        if !preceded_by_identifier_char && !preceded_by_rust_namespace_or_method {
            return true;
        }
        search_start = absolute_start + needle.len();
    }
    false
}

fn collect_db_source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read directory {}: {error}", dir.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| {
            panic!(
                "failed to read directory entry in {}: {error}",
                dir.display()
            )
        });
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_db_source_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn path_is_db_test_or_pooler_safe_query_helper(path: &Path) -> bool {
    let relative = path
        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .to_string_lossy();
    relative.ends_with("src/db/portable_query.rs")
        || relative.ends_with("tests.rs")
        || relative.ends_with("postgres_tests.rs")
        || relative.ends_with("postgres_operation_count_tests.rs")
        || relative.contains("/postgres_operation_count_tests/")
        || relative.contains("/tests/")
}

fn path_is_db_test_or_public_pool_definition(path: &Path) -> bool {
    path_is_db_test_or_pooler_safe_query_helper(path)
        || path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(path)
            .to_string_lossy()
            .ends_with("src/db/pool.rs")
}

fn path_allows_direct_transaction_finish_calls(path: &Path) -> bool {
    let relative = path
        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .to_string_lossy();
    relative.ends_with("src/db/mod.rs")
        || relative.ends_with("src/db/pool.rs")
        || relative.ends_with("src/db/fleet/once_task.rs")
}

#[test]
fn connect_options_preserve_url_ssl_mode_without_explicit_override() {
    let config =
        test_pool_config("postgres://paranoid:secret@127.0.0.1:5432/paranoid_test?sslmode=require");

    let options = build_pooler_safe_pg_connect_options(&config).expect("connect options");

    assert!(matches!(
        options.get_ssl_mode(),
        sqlx::postgres::PgSslMode::Require
    ));
}

#[test]
fn pool_options_use_explicit_config_values() {
    let mut config = test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    config.max_connections = 17;
    config.min_connections = 3;
    config.acquire_timeout = Duration::from_secs(11);
    config.idle_timeout = Some(Duration::from_secs(23));
    config.max_lifetime = Some(Duration::from_secs(41));

    let options = build_pg_pool_options(&config).expect("pool options");

    assert_eq!(options.get_max_connections(), 17);
    assert_eq!(options.get_min_connections(), 3);
    assert_eq!(options.get_acquire_timeout(), Duration::from_secs(11));
    assert_eq!(options.get_idle_timeout(), Some(Duration::from_secs(23)));
    assert_eq!(options.get_max_lifetime(), Some(Duration::from_secs(41)));
}

#[test]
fn pool_config_rejects_ambiguous_or_useless_values() {
    let mut zero_max = test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    zero_max.max_connections = 0;
    assert!(matches!(
        build_pg_pool_options(&zero_max),
        Err(DbError::InvalidPoolConfig { .. })
    ));

    let mut excessive_min = test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    excessive_min.max_connections = 2;
    excessive_min.min_connections = 3;
    assert!(matches!(
        build_pg_pool_options(&excessive_min),
        Err(DbError::InvalidPoolConfig { .. })
    ));

    let mut empty_application_name =
        test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    empty_application_name.application_name = Some(String::new());
    assert!(matches!(
        build_pooler_safe_pg_connect_options(&empty_application_name),
        Err(DbError::InvalidPoolConfig { .. })
    ));

    let mut zero_acquire_timeout =
        test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    zero_acquire_timeout.acquire_timeout = Duration::ZERO;
    assert!(matches!(
        build_pg_pool_options(&zero_acquire_timeout),
        Err(DbError::InvalidPoolConfig { .. })
    ));

    let mut zero_idle_timeout =
        test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    zero_idle_timeout.idle_timeout = Some(Duration::ZERO);
    assert!(matches!(
        build_pg_pool_options(&zero_idle_timeout),
        Err(DbError::InvalidPoolConfig { .. })
    ));

    let mut zero_max_lifetime =
        test_pool_config("postgres://paranoid:secret@localhost/paranoid_test");
    zero_max_lifetime.max_lifetime = Some(Duration::ZERO);
    assert!(matches!(
        build_pg_pool_options(&zero_max_lifetime),
        Err(DbError::InvalidPoolConfig { .. })
    ));
}

#[test]
fn pool_config_debug_does_not_expose_database_url_secret() {
    let config =
        test_pool_config("postgres://paranoid:super_secret_password@localhost/paranoid_test");

    let debug_output = format!("{config:?}");

    assert!(!debug_output.contains("super_secret_password"));
    assert!(!debug_output.contains("postgres://"));
}

fn test_pool_config(database_url: &str) -> PoolConfig {
    PoolConfig::new(SecretString::from(database_url.to_owned()))
}
