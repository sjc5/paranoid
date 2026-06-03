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
    let config = test_schema_ledger_config();
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

mod source_guards;

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
