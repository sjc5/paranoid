use super::sql_state::{
    SQLSTATE_CHECK_VIOLATION, SQLSTATE_DEADLOCK_DETECTED, SQLSTATE_FOREIGN_KEY_VIOLATION,
    SQLSTATE_NOT_NULL_VIOLATION, SQLSTATE_SERIALIZATION_FAILURE, SQLSTATE_UNIQUE_VIOLATION,
};
use super::*;
use crate::id::SortableId as UniqueTestId;
use proptest::prelude::*;
use secrecy::SecretString;
use sqlx::{ConnectOptions, Execute, Row};
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
fn component_schema_public_constructors_reject_missing_physical_validation() {
    let version = ComponentSchemaVersion {
        component: "test_component",
        instance_key: "state=\"app\".\"component_state\"",
        version: 1,
        fingerprint: "schema-v1",
    };

    let err = ComponentSchema::new(version, &[], &[], &[]).expect_err("missing validation");

    assert!(
        err.to_string().contains("validation checks"),
        "error = {err:?}"
    );
}

#[test]
fn component_schema_statement_rejects_empty_null_and_multi_statement_sql() {
    let empty = ComponentSchemaStatement::from_static_sql(" \n\t").expect_err("empty SQL");
    assert!(
        empty.to_string().contains("must not be empty"),
        "error = {empty:?}"
    );

    let null_byte = ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(
        "SELECT '\0'".to_owned(),
    ))
    .expect_err("null byte SQL");
    assert!(
        null_byte.to_string().contains("null bytes"),
        "error = {null_byte:?}"
    );

    let multi_statement =
        ComponentSchemaStatement::from_static_sql("CREATE TABLE t (id integer); SELECT 1")
            .expect_err("multi-statement SQL");
    assert!(
        multi_statement.to_string().contains("semicolons"),
        "error = {multi_statement:?}"
    );
}

#[test]
fn component_schema_validation_check_rejects_empty_null_and_multi_statement_sql() {
    let empty = ComponentSchemaValidationCheck::from_static_boolean_expression(" \n\t")
        .expect_err("empty validation check");
    assert!(
        empty.to_string().contains("must not be empty"),
        "error = {empty:?}"
    );

    let null_byte = ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(
        AuditedSql::new("true /* \0 */".to_owned()),
    )
    .expect_err("null byte validation check");
    assert!(
        null_byte.to_string().contains("null bytes"),
        "error = {null_byte:?}"
    );

    let multi_statement = ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(
        AuditedSql::new("true; SELECT true".to_owned()),
    )
    .expect_err("multi-statement validation check");
    assert!(
        multi_statement.to_string().contains("semicolons"),
        "error = {multi_statement:?}"
    );
}

#[test]
fn component_schema_instance_key_includes_validated_labels_and_qualified_tables() {
    let state_label = PgIdentifier::new("state").expect("state label");
    let audit_label = PgIdentifier::new("audit").expect("audit label");
    let state_table = PgQualifiedTableName::with_schema("app_auth", "state").expect("state table");
    let audit_table = PgQualifiedTableName::with_schema("app_audit", "state").expect("audit table");

    let instance_key = component_schema_instance_key_for_tables([
        (&state_label, &state_table),
        (&audit_label, &audit_table),
    ]);

    assert_eq!(
        instance_key,
        "state=\"app_auth\".\"state\";audit=\"app_audit\".\"state\""
    );
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
    let audited_untyped_query = portable_query(AuditedSql::new("SELECT 1".to_owned()));
    let row_query = portable_query_as::<(i64,)>("SELECT 1");
    let scalar_query = portable_query_scalar::<i64>("SELECT 1");
    let unparameterized_query = unparameterized_simple_query("SELECT 1");

    assert!(!Execute::persistent(&untyped_query));
    assert!(!Execute::persistent(&audited_untyped_query));
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

#[tokio::test]
async fn component_schema_migration_uses_bootstrapped_ledger_and_supports_qualified_tables() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool = connect_write_pool_for_db_test(
        &database_url,
        "paranoid_component_schema_migration_bootstrap_test",
    )
    .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsm_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsm_component");
    let component_table = PgQualifiedTableName::new(
        Some(component_schema_name.clone()),
        PgIdentifier::new("component_state").expect("component table identifier"),
    );
    let component = "test_component_upgrade";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let v1 = ComponentSchemaVersion {
        component,
        instance_key: instance_key.as_str(),
        version: 1,
        fingerprint: "test-v1",
    };
    let v2 = ComponentSchemaVersion {
        version: 2,
        fingerprint: "test-v2",
        ..v1
    };
    let v1_fresh_install = [
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            component_schema_name.identifier().quoted()
        )))
        .expect("component schema creation statement"),
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE TABLE {} (id BYTEA PRIMARY KEY)",
            component_table.quoted()
        )))
        .expect("v1 fresh install statement"),
    ];
    let v1_validation = [
        ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(AuditedSql::new(
            format!(
                "NOT EXISTS (SELECT id FROM {} WHERE false)",
                component_table.quoted()
            ),
        ))
        .expect("v1 validation check"),
    ];
    let v1_schema =
        ComponentSchema::new(v1, &v1_fresh_install, &[], &v1_validation).expect("v1 schema");

    let v2_upgrade_statements =
        [
            ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
                "ALTER TABLE {} ADD COLUMN payload BYTEA NOT NULL DEFAULT ''::bytea",
                component_table.quoted()
            )))
            .expect("v2 migration statement"),
        ];
    let v2_migrations = [ComponentSchemaMigration::new(
        ComponentSchemaMigrationStep::new(
            ComponentSchemaMigrationTarget::new(1, "test-v1"),
            ComponentSchemaMigrationTarget::new(2, "test-v2"),
        ),
        &v2_upgrade_statements,
    )];
    let v2_validation = [
        ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(AuditedSql::new(
            format!(
                "NOT EXISTS (SELECT id, payload FROM {} WHERE false)",
                component_table.quoted()
            ),
        ))
        .expect("v2 validation check"),
    ];
    let v2_schema =
        ComponentSchema::new(v2, &[], &v2_migrations, &v2_validation).expect("v2 schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &v1_schema)
            .await
            .expect("migrate v1 schema"),
        ComponentSchemaMigrationOutcome::FreshInstall { version: 1 }
    );

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &v2_schema)
            .await
            .expect("migrate v2 schema"),
        ComponentSchemaMigrationOutcome::Upgraded {
            from_version: 1,
            to_version: 2,
            steps_applied: 1,
        }
    );

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &v2_schema)
            .await
            .expect("validate already-current v2 schema"),
        ComponentSchemaMigrationOutcome::AlreadyCurrent { version: 2 }
    );

    let mut validation_tx = pool
        .begin_transaction()
        .await
        .expect("begin physical assertion transaction");
    assert!(
        fetch_column_exists_in_current_transaction(&mut validation_tx, &component_table, "payload")
            .await
    );
    validation_tx
        .rollback()
        .await
        .expect("rollback physical assertion transaction");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_validation_false_rejects_before_recording_component_version() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool = connect_write_pool_for_db_test(
        &database_url,
        "paranoid_component_schema_validation_false_test",
    )
    .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsvf_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsvf_component");
    let component_table = PgQualifiedTableName::new(
        Some(component_schema_name.clone()),
        PgIdentifier::new("component_state").expect("component table identifier"),
    );
    let component = "test_component_validation_false";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let version = ComponentSchemaVersion {
        component,
        instance_key: instance_key.as_str(),
        version: 1,
        fingerprint: "test-v1",
    };
    let fresh_install = [
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            component_schema_name.identifier().quoted()
        )))
        .expect("component schema creation statement"),
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE TABLE {} (id BYTEA PRIMARY KEY)",
            component_table.quoted()
        )))
        .expect("fresh install statement"),
    ];
    let false_validation = [
        ComponentSchemaValidationCheck::from_static_boolean_expression("false")
            .expect("false validation check"),
    ];
    let false_schema =
        ComponentSchema::new(version, &fresh_install, &[], &false_validation).expect("schema");
    let null_validation = [
        ComponentSchemaValidationCheck::from_static_boolean_expression("NULL::boolean")
            .expect("null validation check"),
    ];
    let null_schema =
        ComponentSchema::new(version, &fresh_install, &[], &null_validation).expect("schema");
    let true_validation = [
        ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(AuditedSql::new(
            format!(
                "NOT EXISTS (SELECT id FROM {} WHERE false)",
                component_table.quoted()
            ),
        ))
        .expect("true validation check"),
    ];
    let true_schema =
        ComponentSchema::new(version, &fresh_install, &[], &true_validation).expect("schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");

    let error = stores
        .migrate_component_schema(&pool, &false_schema)
        .await
        .expect_err("false validation check must fail migration");
    assert!(
        error.to_string().contains("returned false"),
        "error = {error:?}"
    );

    let error = stores
        .migrate_component_schema(&pool, &null_schema)
        .await
        .expect_err("null validation check must fail migration");
    assert!(
        error.to_string().contains("returned null"),
        "error = {error:?}"
    );

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &true_schema)
            .await
            .expect("true validation check should still fresh install"),
        ComponentSchemaMigrationOutcome::FreshInstall { version: 1 }
    );

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &true_schema)
            .await
            .expect("already-current validation should pass"),
        ComponentSchemaMigrationOutcome::AlreadyCurrent { version: 1 }
    );

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn component_schema_migration_serializes_concurrent_startup_for_same_component() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool = connect_write_pool_for_db_test(
        &database_url,
        "paranoid_component_schema_concurrent_migration_test",
    )
    .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsc_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsc_component");
    let component_table = PgQualifiedTableName::new(
        Some(component_schema_name.clone()),
        PgIdentifier::new("component_state").expect("component table identifier"),
    );
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let fresh_install = [
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            component_schema_name.identifier().quoted()
        )))
        .expect("component schema creation statement"),
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE TABLE {} (id BYTEA PRIMARY KEY)",
            component_table.quoted()
        )))
        .expect("fresh install statement"),
    ];
    let validation = [
        ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(AuditedSql::new(
            format!(
                "NOT EXISTS (SELECT id FROM {} WHERE false)",
                component_table.quoted()
            ),
        ))
        .expect("validation check"),
    ];
    let schema = ComponentSchema::new(
        ComponentSchemaVersion {
            component: "test_component_concurrent_startup",
            instance_key: &instance_key,
            version: 1,
            fingerprint: "test-v1",
        },
        &fresh_install,
        &[],
        &validation,
    )
    .expect("component schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");

    let results = tokio::join!(
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
        stores.migrate_component_schema(&pool, &schema),
    );
    let mut fresh_installs = 0;
    let mut already_current = 0;
    for result in [
        results.0, results.1, results.2, results.3, results.4, results.5, results.6, results.7,
    ] {
        match result.expect("concurrent migration must succeed") {
            ComponentSchemaMigrationOutcome::FreshInstall { version: 1 } => fresh_installs += 1,
            ComponentSchemaMigrationOutcome::AlreadyCurrent { version: 1 } => already_current += 1,
            other => panic!("unexpected concurrent migration outcome: {other:?}"),
        }
    }

    assert_eq!(fresh_installs, 1);
    assert_eq!(already_current, 7);

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn component_schema_migration_serializes_concurrent_upgrade_for_same_component() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool = connect_write_pool_for_db_test(
        &database_url,
        "paranoid_component_schema_concurrent_upgrade_test",
    )
    .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsu_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsu_component");
    let component_table = component_test_table(&component_schema_name, "component_state");
    let component = "test_component_concurrent_upgrade";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let v1 = component_test_version(component, &instance_key, 1, "test-v1");
    let v2 = component_test_version(component, &instance_key, 2, "test-v2");
    let v1_fresh_install =
        component_fresh_install_statements(&component_schema_name, &component_table);
    let v1_validation = [component_select_validation_check(&component_table, "id")];
    let v1_schema =
        ComponentSchema::new(v1, &v1_fresh_install, &[], &v1_validation).expect("v1 schema");
    let v2_upgrade_statements = [component_add_column_statement(
        &component_table,
        "payload",
        "BYTEA NOT NULL DEFAULT ''::bytea",
    )];
    let v2_migrations = [ComponentSchemaMigration::new(
        component_test_step(1, "test-v1", 2, "test-v2"),
        &v2_upgrade_statements,
    )];
    let v2_validation = [component_select_validation_check(
        &component_table,
        "id, payload",
    )];
    let v2_schema =
        ComponentSchema::new(v2, &[], &v2_migrations, &v2_validation).expect("v2 schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    assert_eq!(
        stores
            .migrate_component_schema(&pool, &v1_schema)
            .await
            .expect("fresh install v1"),
        ComponentSchemaMigrationOutcome::FreshInstall { version: 1 }
    );

    let results = tokio::join!(
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
        stores.migrate_component_schema(&pool, &v2_schema),
    );
    let mut upgrades = 0;
    let mut already_current = 0;
    for result in [
        results.0, results.1, results.2, results.3, results.4, results.5, results.6, results.7,
    ] {
        match result.expect("concurrent upgrade must succeed") {
            ComponentSchemaMigrationOutcome::Upgraded {
                from_version: 1,
                to_version: 2,
                steps_applied: 1,
            } => upgrades += 1,
            ComponentSchemaMigrationOutcome::AlreadyCurrent { version: 2 } => already_current += 1,
            other => panic!("unexpected concurrent upgrade outcome: {other:?}"),
        }
    }

    assert_eq!(upgrades, 1);
    assert_eq!(already_current, 7);
    assert_component_column_exists(&pool, &component_table, "payload").await;

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_failed_upgrade_rolls_back_physical_work_and_ledger_update() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool =
        connect_write_pool_for_db_test(&database_url, "paranoid_component_schema_bad_upgrade_test")
            .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsbu_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsbu_component");
    let component_table = component_test_table(&component_schema_name, "component_state");
    let component = "test_component_bad_upgrade";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let v1 = component_test_version(component, &instance_key, 1, "test-v1");
    let v2 = component_test_version(component, &instance_key, 2, "test-v2");
    let v1_fresh_install =
        component_fresh_install_statements(&component_schema_name, &component_table);
    let v1_validation = [component_select_validation_check(&component_table, "id")];
    let v1_schema =
        ComponentSchema::new(v1, &v1_fresh_install, &[], &v1_validation).expect("v1 schema");
    let bad_v2_upgrade_statements = [
        component_add_column_statement(
            &component_table,
            "payload",
            "BYTEA NOT NULL DEFAULT ''::bytea",
        ),
        component_add_column_statement(
            &component_table,
            "payload",
            "BYTEA NOT NULL DEFAULT ''::bytea",
        ),
    ];
    let bad_v2_migrations = [ComponentSchemaMigration::new(
        component_test_step(1, "test-v1", 2, "test-v2"),
        &bad_v2_upgrade_statements,
    )];
    let v2_validation = [component_select_validation_check(
        &component_table,
        "id, payload",
    )];
    let bad_v2_schema =
        ComponentSchema::new(v2, &[], &bad_v2_migrations, &v2_validation).expect("bad v2 schema");
    let good_v2_upgrade_statements = [component_add_column_statement(
        &component_table,
        "payload",
        "BYTEA NOT NULL DEFAULT ''::bytea",
    )];
    let good_v2_migrations = [ComponentSchemaMigration::new(
        component_test_step(1, "test-v1", 2, "test-v2"),
        &good_v2_upgrade_statements,
    )];
    let good_v2_schema =
        ComponentSchema::new(v2, &[], &good_v2_migrations, &v2_validation).expect("good v2 schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    stores
        .migrate_component_schema(&pool, &v1_schema)
        .await
        .expect("fresh install v1");

    stores
        .migrate_component_schema(&pool, &bad_v2_schema)
        .await
        .expect_err("duplicate column upgrade must fail");

    assert_component_column_missing(&pool, &component_table, "payload").await;
    assert_eq!(
        fetch_component_schema_ledger_row(
            &pool,
            stores.schema_ledger_table_name(),
            component,
            &instance_key,
        )
        .await,
        Some((1, "test-v1".to_owned())),
        "failed upgrade must leave the component ledger at v1"
    );

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &good_v2_schema)
            .await
            .expect("good upgrade should still run after failed upgrade rollback"),
        ComponentSchemaMigrationOutcome::Upgraded {
            from_version: 1,
            to_version: 2,
            steps_applied: 1,
        }
    );

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_already_current_validation_rejects_physical_drift() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool =
        connect_write_pool_for_db_test(&database_url, "paranoid_component_schema_drift_test").await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsd_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsd_component");
    let component_table = component_test_table(&component_schema_name, "component_state");
    let component = "test_component_physical_drift";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let version = component_test_version(component, &instance_key, 1, "test-v1");
    let fresh_install =
        component_fresh_install_statements(&component_schema_name, &component_table);
    let validation = [component_select_validation_check(&component_table, "id")];
    let schema = ComponentSchema::new(version, &fresh_install, &[], &validation).expect("schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    stores
        .migrate_component_schema(&pool, &schema)
        .await
        .expect("fresh install schema");
    execute_component_test_statement(
        pool.sqlx_pool(),
        format!("DROP TABLE {}", component_table.quoted()),
    )
    .await;

    let error = stores
        .migrate_component_schema(&pool, &schema)
        .await
        .expect_err("already-current ledger must not hide physical drift");
    let error_debug = format!("{error:?}");
    assert!(
        error_debug.contains("42P01") && error_debug.contains("component_state"),
        "error should be the physical validation query failing on the missing component table: {error:?}"
    );

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_migration_rejects_conflicting_ledger_rows_before_physical_work() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool =
        connect_write_pool_for_db_test(&database_url, "paranoid_component_schema_conflict_test")
            .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcscl_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcscl_component");
    let future_table = component_test_table(&component_schema_name, "future_state");
    let fingerprint_table = component_test_table(&component_schema_name, "fingerprint_state");
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let future_instance_key =
        component_schema_instance_key_for_tables([(&state_label, &future_table)]);
    let fingerprint_instance_key =
        component_schema_instance_key_for_tables([(&state_label, &fingerprint_table)]);
    let future_fresh_install =
        component_fresh_install_statements(&component_schema_name, &future_table);
    let future_validation = [component_select_validation_check(&future_table, "id")];
    let future_schema = ComponentSchema::new(
        component_test_version(
            "test_component_future_conflict",
            &future_instance_key,
            1,
            "test-v1",
        ),
        &future_fresh_install,
        &[],
        &future_validation,
    )
    .expect("future conflict schema");
    let fingerprint_fresh_install =
        component_fresh_install_statements(&component_schema_name, &fingerprint_table);
    let fingerprint_validation = [component_select_validation_check(&fingerprint_table, "id")];
    let fingerprint_schema = ComponentSchema::new(
        component_test_version(
            "test_component_fingerprint_conflict",
            &fingerprint_instance_key,
            1,
            "test-v1",
        ),
        &fingerprint_fresh_install,
        &[],
        &fingerprint_validation,
    )
    .expect("fingerprint conflict schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    insert_component_schema_ledger_row(
        &pool,
        stores.schema_ledger_table_name(),
        "test_component_future_conflict",
        &future_instance_key,
        9,
        "future",
    )
    .await;
    insert_component_schema_ledger_row(
        &pool,
        stores.schema_ledger_table_name(),
        "test_component_fingerprint_conflict",
        &fingerprint_instance_key,
        1,
        "different",
    )
    .await;

    let future_error = stores
        .migrate_component_schema(&pool, &future_schema)
        .await
        .expect_err("future recorded version must fail before physical work");
    assert!(
        future_error.to_string().contains("newer than supported"),
        "error = {future_error:?}"
    );
    let fingerprint_error = stores
        .migrate_component_schema(&pool, &fingerprint_schema)
        .await
        .expect_err("same-version fingerprint mismatch must fail before physical work");
    assert!(
        fingerprint_error
            .to_string()
            .contains("recorded fingerprint"),
        "error = {fingerprint_error:?}"
    );
    assert!(
        !fetch_component_table_exists(&pool, &future_table).await,
        "future-version conflict must not execute fresh-install DDL"
    );
    assert!(
        !fetch_component_table_exists(&pool, &fingerprint_table).await,
        "fingerprint conflict must not execute fresh-install DDL"
    );

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_migration_executes_multi_step_upgrade_in_one_transaction() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool =
        connect_write_pool_for_db_test(&database_url, "paranoid_component_schema_multistep_test")
            .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsms_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsms_component");
    let component_table = component_test_table(&component_schema_name, "component_state");
    let component = "test_component_multi_step";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let v1 = component_test_version(component, &instance_key, 1, "test-v1");
    let v3 = component_test_version(component, &instance_key, 3, "test-v3");
    let v1_fresh_install =
        component_fresh_install_statements(&component_schema_name, &component_table);
    let v1_validation = [component_select_validation_check(&component_table, "id")];
    let v1_schema =
        ComponentSchema::new(v1, &v1_fresh_install, &[], &v1_validation).expect("v1 schema");
    let add_payload = [component_add_column_statement(
        &component_table,
        "payload",
        "BYTEA NOT NULL DEFAULT ''::bytea",
    )];
    let add_marker = [component_add_column_statement(
        &component_table,
        "marker",
        "INTEGER NOT NULL DEFAULT 0",
    )];
    let v3_migrations = [
        ComponentSchemaMigration::new(
            component_test_step(1, "test-v1", 2, "test-v2"),
            &add_payload,
        ),
        ComponentSchemaMigration::new(component_test_step(2, "test-v2", 3, "test-v3"), &add_marker),
    ];
    let v3_validation = [component_select_validation_check(
        &component_table,
        "id, payload, marker",
    )];
    let v3_schema =
        ComponentSchema::new(v3, &[], &v3_migrations, &v3_validation).expect("v3 schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    stores
        .migrate_component_schema(&pool, &v1_schema)
        .await
        .expect("fresh install v1");

    assert_eq!(
        stores
            .migrate_component_schema(&pool, &v3_schema)
            .await
            .expect("upgrade directly to v3"),
        ComponentSchemaMigrationOutcome::Upgraded {
            from_version: 1,
            to_version: 3,
            steps_applied: 2,
        }
    );
    assert_component_column_exists(&pool, &component_table, "payload").await;
    assert_component_column_exists(&pool, &component_table, "marker").await;

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_instance_key_keeps_same_component_physical_instances_isolated() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool =
        connect_write_pool_for_db_test(&database_url, "paranoid_component_schema_instances_test")
            .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsi_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsi_component");
    let first_table = component_test_table(&component_schema_name, "first_state");
    let second_table = component_test_table(&component_schema_name, "second_state");
    let component = "test_component_shared_name";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let first_instance_key =
        component_schema_instance_key_for_tables([(&state_label, &first_table)]);
    let second_instance_key =
        component_schema_instance_key_for_tables([(&state_label, &second_table)]);
    let first_fresh_install =
        component_fresh_install_statements(&component_schema_name, &first_table);
    let first_validation = [component_select_validation_check(&first_table, "id")];
    let first_schema = ComponentSchema::new(
        component_test_version(component, &first_instance_key, 1, "first-v1"),
        &first_fresh_install,
        &[],
        &first_validation,
    )
    .expect("first component schema");
    let second_fresh_install =
        component_fresh_install_statements(&component_schema_name, &second_table);
    let second_validation = [component_select_validation_check(&second_table, "id")];
    let second_schema = ComponentSchema::new(
        component_test_version(component, &second_instance_key, 1, "second-v1"),
        &second_fresh_install,
        &[],
        &second_validation,
    )
    .expect("second component schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    assert_eq!(
        stores
            .migrate_component_schema(&pool, &first_schema)
            .await
            .expect("fresh install first instance"),
        ComponentSchemaMigrationOutcome::FreshInstall { version: 1 }
    );
    assert_eq!(
        stores
            .migrate_component_schema(&pool, &second_schema)
            .await
            .expect("fresh install second instance"),
        ComponentSchemaMigrationOutcome::FreshInstall { version: 1 }
    );
    assert_eq!(
        fetch_component_schema_ledger_row(
            &pool,
            stores.schema_ledger_table_name(),
            component,
            &first_instance_key,
        )
        .await,
        Some((1, "first-v1".to_owned()))
    );
    assert_eq!(
        fetch_component_schema_ledger_row(
            &pool,
            stores.schema_ledger_table_name(),
            component,
            &second_instance_key,
        )
        .await,
        Some((1, "second-v1".to_owned()))
    );

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_same_instance_conflicting_definition_does_not_run_physical_work() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool = connect_write_pool_for_db_test(
        &database_url,
        "paranoid_component_schema_same_instance_test",
    )
    .await;
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsid_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsid_component");
    let component_table = component_test_table(&component_schema_name, "component_state");
    let component = "test_component_same_instance_conflict";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let first_fresh_install =
        component_fresh_install_statements(&component_schema_name, &component_table);
    let first_validation = [component_select_validation_check(&component_table, "id")];
    let first_schema = ComponentSchema::new(
        component_test_version(component, &instance_key, 1, "test-v1"),
        &first_fresh_install,
        &[],
        &first_validation,
    )
    .expect("first component schema");
    let conflicting_statement = [component_add_column_statement(
        &component_table,
        "should_not_exist",
        "INTEGER NOT NULL DEFAULT 0",
    )];
    let validation = [component_select_validation_check(&component_table, "id")];
    let conflicting_schema = ComponentSchema::new(
        component_test_version(component, &instance_key, 1, "different-v1"),
        &conflicting_statement,
        &[],
        &validation,
    )
    .expect("conflicting schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");
    stores
        .migrate_component_schema(&pool, &first_schema)
        .await
        .expect("fresh install first definition");

    let error = stores
        .migrate_component_schema(&pool, &conflicting_schema)
        .await
        .expect_err("same instance with a different fingerprint must fail");
    assert!(
        error.to_string().contains("recorded fingerprint"),
        "error = {error:?}"
    );
    assert_component_column_missing(&pool, &component_table, "should_not_exist").await;

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

#[tokio::test]
async fn component_schema_public_migration_path_emits_expected_operation_shapes() {
    let database_url = postgres_test_support::standard_test_database_url();
    let pool =
        connect_write_pool_for_db_test(&database_url, "paranoid_component_schema_op_count_test")
            .await;
    let observer = DatabaseOperationObserver::default();
    let observed_pool = pool.clone_with_database_operation_observer(observer.clone());
    let bootstrap_config = BootstrapConfig::new(unique_db_test_schema_name("__pcsoc_bootstrap"));
    let component_schema_name = unique_db_test_schema_name("__pcsoc_component");
    let component_table = component_test_table(&component_schema_name, "component_state");
    let component = "test_component_operation_count";
    let state_label = PgIdentifier::new("state").expect("schema instance key label");
    let instance_key = component_schema_instance_key_for_tables([(&state_label, &component_table)]);
    let v1 = component_test_version(component, &instance_key, 1, "test-v1");
    let v2 = component_test_version(component, &instance_key, 2, "test-v2");
    let v1_fresh_install =
        component_fresh_install_statements(&component_schema_name, &component_table);
    let v1_validation = [component_select_validation_check(&component_table, "id")];
    let v1_schema =
        ComponentSchema::new(v1, &v1_fresh_install, &[], &v1_validation).expect("v1 schema");
    let v2_upgrade_statements = [component_add_column_statement(
        &component_table,
        "payload",
        "BYTEA NOT NULL DEFAULT ''::bytea",
    )];
    let v2_migrations = [ComponentSchemaMigration::new(
        component_test_step(1, "test-v1", 2, "test-v2"),
        &v2_upgrade_statements,
    )];
    let v2_validation = [component_select_validation_check(
        &component_table,
        "id, payload",
    )];
    let v2_schema =
        ComponentSchema::new(v2, &[], &v2_migrations, &v2_validation).expect("v2 schema");

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
    let stores = bootstrap_config
        .migrate_schema(&pool)
        .await
        .expect("migrate Paranoid DB foundation");

    stores
        .migrate_component_schema(&observed_pool, &v1_schema)
        .await
        .expect("fresh install v1");
    assert_eq!(
        component_schema_operation_shapes(&observer),
        component_schema_fresh_install_operation_shapes(2, 1)
    );
    observer.clear();

    stores
        .migrate_component_schema(&observed_pool, &v2_schema)
        .await
        .expect("upgrade to v2");
    assert_eq!(
        component_schema_operation_shapes(&observer),
        component_schema_upgrade_operation_shapes(1, 1)
    );
    observer.clear();

    stores
        .migrate_component_schema(&observed_pool, &v2_schema)
        .await
        .expect("validate already-current v2");
    assert_eq!(
        component_schema_operation_shapes(&observer),
        component_schema_already_current_operation_shapes(1)
    );

    drop_test_schema(pool.sqlx_pool(), bootstrap_config.schema_name()).await;
    drop_test_schema(pool.sqlx_pool(), &component_schema_name).await;
}

type ComponentSchemaOperationShape = (DatabaseOperationKind, &'static str);

fn component_test_table(schema_name: &PgSchemaName, table_name: &str) -> PgQualifiedTableName {
    PgQualifiedTableName::new(
        Some(schema_name.clone()),
        PgIdentifier::new(table_name).expect("test component table identifier"),
    )
}

fn component_test_version<'a>(
    component: &'a str,
    instance_key: &'a str,
    version: i32,
    fingerprint: &'a str,
) -> ComponentSchemaVersion<'a> {
    ComponentSchemaVersion {
        component,
        instance_key,
        version,
        fingerprint,
    }
}

fn component_test_step(
    from_version: i32,
    from_fingerprint: &'static str,
    to_version: i32,
    to_fingerprint: &'static str,
) -> ComponentSchemaMigrationStep<'static> {
    ComponentSchemaMigrationStep::new(
        ComponentSchemaMigrationTarget::new(from_version, from_fingerprint),
        ComponentSchemaMigrationTarget::new(to_version, to_fingerprint),
    )
}

fn component_fresh_install_statements(
    schema_name: &PgSchemaName,
    table_name: &PgQualifiedTableName,
) -> [ComponentSchemaStatement<'static>; 2] {
    [
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE SCHEMA IF NOT EXISTS {}",
            schema_name.identifier().quoted()
        )))
        .expect("component schema creation statement"),
        ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
            "CREATE TABLE {} (id BYTEA PRIMARY KEY)",
            table_name.quoted()
        )))
        .expect("component table creation statement"),
    ]
}

fn component_add_column_statement(
    table_name: &PgQualifiedTableName,
    column_name: &str,
    column_type: &str,
) -> ComponentSchemaStatement<'static> {
    let column = PgIdentifier::new(column_name).expect("test component column identifier");
    ComponentSchemaStatement::from_audited_dynamic_sql(AuditedSql::new(format!(
        "ALTER TABLE {} ADD COLUMN {} {}",
        table_name.quoted(),
        column.quoted(),
        column_type
    )))
    .expect("component add-column statement")
}

fn component_select_validation_check(
    table_name: &PgQualifiedTableName,
    select_list: &str,
) -> ComponentSchemaValidationCheck<'static> {
    ComponentSchemaValidationCheck::from_audited_dynamic_boolean_expression(AuditedSql::new(
        format!(
            "NOT EXISTS (SELECT {select_list} FROM {} WHERE false)",
            table_name.quoted()
        ),
    ))
    .expect("component select validation check")
}

fn component_schema_operation_shapes(
    observer: &DatabaseOperationObserver,
) -> Vec<ComponentSchemaOperationShape> {
    observer
        .records()
        .into_iter()
        .map(|record| (record.kind, record.label))
        .collect()
}

fn component_schema_fresh_install_operation_shapes(
    fresh_statement_count: usize,
    validation_check_count: usize,
) -> Vec<ComponentSchemaOperationShape> {
    [
        vec![(
            DatabaseOperationKind::BeginTransaction,
            "db.begin_transaction",
        )],
        component_schema_ledger_claim_shapes(),
        repeated_component_operation_shape(
            DatabaseOperationKind::Execute,
            COMPONENT_SCHEMA_OPERATION_EXECUTE_FRESH_INSTALL_STATEMENT,
            fresh_statement_count,
        ),
        repeated_component_operation_shape(
            DatabaseOperationKind::FetchOne,
            COMPONENT_SCHEMA_OPERATION_EXECUTE_VALIDATION_CHECK,
            validation_check_count,
        ),
        component_schema_ledger_fresh_completion_shapes(),
        vec![(DatabaseOperationKind::CommitTransaction, "db.tx.commit")],
    ]
    .concat()
}

fn component_schema_upgrade_operation_shapes(
    upgrade_statement_count: usize,
    validation_check_count: usize,
) -> Vec<ComponentSchemaOperationShape> {
    [
        vec![(
            DatabaseOperationKind::BeginTransaction,
            "db.begin_transaction",
        )],
        component_schema_ledger_lock_shapes(),
        repeated_component_operation_shape(
            DatabaseOperationKind::Execute,
            COMPONENT_SCHEMA_OPERATION_EXECUTE_UPGRADE_STATEMENT,
            upgrade_statement_count,
        ),
        repeated_component_operation_shape(
            DatabaseOperationKind::FetchOne,
            COMPONENT_SCHEMA_OPERATION_EXECUTE_VALIDATION_CHECK,
            validation_check_count,
        ),
        component_schema_ledger_upgrade_completion_shapes(),
        vec![(DatabaseOperationKind::CommitTransaction, "db.tx.commit")],
    ]
    .concat()
}

fn component_schema_already_current_operation_shapes(
    validation_check_count: usize,
) -> Vec<ComponentSchemaOperationShape> {
    [
        vec![(
            DatabaseOperationKind::BeginTransaction,
            "db.begin_transaction",
        )],
        component_schema_ledger_lock_shapes(),
        repeated_component_operation_shape(
            DatabaseOperationKind::FetchOne,
            COMPONENT_SCHEMA_OPERATION_EXECUTE_VALIDATION_CHECK,
            validation_check_count,
        ),
        vec![(DatabaseOperationKind::CommitTransaction, "db.tx.commit")],
    ]
    .concat()
}

fn component_schema_ledger_claim_shapes() -> Vec<ComponentSchemaOperationShape> {
    [
        component_schema_ledger_ensure_and_validate_shapes(),
        vec![(
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_CLAIM_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

fn component_schema_ledger_lock_shapes() -> Vec<ComponentSchemaOperationShape> {
    [
        component_schema_ledger_claim_shapes(),
        vec![(
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_LOCK_COMPONENT_VERSION,
        )],
    ]
    .concat()
}

fn component_schema_ledger_fresh_completion_shapes() -> Vec<ComponentSchemaOperationShape> {
    vec![
        (
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_RECORD_COMPONENT_VERSION,
        ),
        (
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
        ),
    ]
}

fn component_schema_ledger_upgrade_completion_shapes() -> Vec<ComponentSchemaOperationShape> {
    vec![
        (
            DatabaseOperationKind::Execute,
            SCHEMA_LEDGER_OPERATION_UPDATE_COMPONENT_VERSION,
        ),
        (
            DatabaseOperationKind::FetchOptional,
            SCHEMA_LEDGER_OPERATION_FETCH_COMPONENT_VERSION,
        ),
    ]
}

fn component_schema_ledger_ensure_and_validate_shapes() -> Vec<ComponentSchemaOperationShape> {
    [
        vec![
            (
                DatabaseOperationKind::Execute,
                SCHEMA_LEDGER_OPERATION_CREATE_SAVEPOINT,
            ),
            (
                DatabaseOperationKind::Execute,
                SCHEMA_LEDGER_OPERATION_CREATE_TABLE,
            ),
            (
                DatabaseOperationKind::Execute,
                SCHEMA_LEDGER_OPERATION_RELEASE_SAVEPOINT,
            ),
        ],
        component_schema_ledger_physical_validation_shapes(),
    ]
    .concat()
}

fn component_schema_ledger_physical_validation_shapes() -> Vec<ComponentSchemaOperationShape> {
    vec![
        (
            DatabaseOperationKind::FetchAll,
            SCHEMA_LEDGER_OPERATION_VALIDATE_COLUMNS,
        ),
        (
            DatabaseOperationKind::FetchOne,
            SCHEMA_LEDGER_OPERATION_VALIDATE_PRIMARY_KEY,
        ),
        (
            DatabaseOperationKind::FetchAll,
            SCHEMA_LEDGER_OPERATION_VALIDATE_CHECK_CONSTRAINTS,
        ),
    ]
}

fn repeated_component_operation_shape(
    kind: DatabaseOperationKind,
    label: &'static str,
    count: usize,
) -> Vec<ComponentSchemaOperationShape> {
    vec![(kind, label); count]
}

async fn execute_component_test_statement(pool: &sqlx::PgPool, statement: String) {
    unparameterized_simple_query(AuditedSql::new(statement))
        .execute(pool)
        .await
        .expect("execute component test statement");
}

async fn insert_component_schema_ledger_row(
    pool: &WritePool,
    ledger_table: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
    version: i32,
    fingerprint: &str,
) {
    let statement = format!(
        r#"
        INSERT INTO {} (
            component,
            instance_key,
            schema_version,
            schema_fingerprint,
            applied_at
        )
        VALUES ($1, $2, $3, $4, statement_timestamp())
        "#,
        ledger_table.quoted()
    );
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin schema ledger seed transaction");
    portable_query(AuditedSql::new(statement))
        .bind(component)
        .bind(instance_key)
        .bind(version)
        .bind(fingerprint)
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .expect("insert component schema ledger row");
    tx.commit()
        .await
        .expect("commit schema ledger seed transaction");
}

async fn fetch_component_schema_ledger_row(
    pool: &WritePool,
    ledger_table: &PgQualifiedTableName,
    component: &str,
    instance_key: &str,
) -> Option<(i32, String)> {
    let statement = format!(
        r#"
        SELECT schema_version, schema_fingerprint
        FROM {}
        WHERE component = $1
          AND instance_key = $2
        "#,
        ledger_table.quoted()
    );
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin schema ledger assertion transaction");
    let row = portable_query_as::<(i32, String)>(AuditedSql::new(statement))
        .bind(component)
        .bind(instance_key)
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .expect("fetch component schema ledger row");
    tx.rollback()
        .await
        .expect("rollback schema ledger assertion transaction");
    row
}

async fn fetch_component_table_exists(pool: &WritePool, table_name: &PgQualifiedTableName) -> bool {
    let schema_name = table_name.schema().map(PgSchemaName::as_str);
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin table assertion transaction");
    let row = portable_query(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = COALESCE($1, current_schema())
              AND table_name = $2
        )
        "#,
    )
    .bind(schema_name)
    .bind(table_name.table().as_str())
    .fetch_one(tx.sqlx_transaction().as_mut())
    .await
    .expect("fetch table existence");

    let exists = row.try_get(0).expect("decode table existence");
    tx.rollback()
        .await
        .expect("rollback table assertion transaction");
    exists
}

async fn assert_component_column_exists(
    pool: &WritePool,
    table_name: &PgQualifiedTableName,
    column_name: &str,
) {
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin column assertion transaction");
    assert!(
        fetch_column_exists_in_current_transaction(&mut tx, table_name, column_name).await,
        "expected column {column_name:?} to exist on {}",
        table_name.quoted()
    );
    tx.rollback()
        .await
        .expect("rollback column assertion transaction");
}

async fn assert_component_column_missing(
    pool: &WritePool,
    table_name: &PgQualifiedTableName,
    column_name: &str,
) {
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin column assertion transaction");
    assert!(
        !fetch_column_exists_in_current_transaction(&mut tx, table_name, column_name).await,
        "expected column {column_name:?} to be absent from {}",
        table_name.quoted()
    );
    tx.rollback()
        .await
        .expect("rollback column assertion transaction");
}

fn test_pool_config(database_url: &str) -> PoolConfig {
    PoolConfig::new(SecretString::from(database_url.to_owned()))
}

async fn connect_write_pool_for_db_test(database_url: &str, application_name: &str) -> WritePool {
    let mut config = test_pool_config(database_url);
    config.max_connections = 5;
    config.application_name = Some(application_name.to_owned());
    WritePool::connect(config)
        .await
        .expect("connect write pool")
}

fn unique_db_test_schema_name(prefix: &str) -> PgSchemaName {
    let suffix = UniqueTestId::new()
        .expect("new unique test id")
        .to_text()
        .replace('-', "_");
    PgSchemaName::from_identifier_text(format!("{prefix}_{suffix}")).expect("test schema name")
}

async fn drop_test_schema(pool: &sqlx::PgPool, schema_name: &PgSchemaName) {
    unparameterized_simple_query(AuditedSql::new(format!(
        "DROP SCHEMA IF EXISTS {} CASCADE",
        schema_name.identifier().quoted()
    )))
    .execute(pool)
    .await
    .expect("drop test schema");
}

async fn fetch_column_exists_in_current_transaction(
    tx: &mut WriteTx<'_>,
    table_name: &PgQualifiedTableName,
    column_name: &str,
) -> bool {
    let schema_name = table_name.schema().map(PgSchemaName::as_str);
    let row = portable_query(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = COALESCE($1, current_schema())
              AND table_name = $2
              AND column_name = $3
        )
        "#,
    )
    .bind(schema_name)
    .bind(table_name.table().as_str())
    .bind(column_name)
    .fetch_one(tx.sqlx_transaction().as_mut())
    .await
    .expect("fetch column existence");

    row.try_get(0).expect("decode column existence")
}
