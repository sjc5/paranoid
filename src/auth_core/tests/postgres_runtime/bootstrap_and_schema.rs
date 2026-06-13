use super::*;

#[test]
fn postgres_method_registry_rejects_duplicate_method_registration() {
    let schema = PgSchemaName::from_identifier_text("__paranoid_auth_registry_test")
        .expect("test schema name");
    let left: Arc<dyn super::super::super::postgres_method_runtime::PostgresAuthMethodPlugin> =
        Arc::new(TestPostgresAuthMethodPlugin::new(
            &schema,
            TestMethodCommitFailureMode::None,
        ));
    let right: Arc<dyn super::super::super::postgres_method_runtime::PostgresAuthMethodPlugin> =
        Arc::new(TestPostgresAuthMethodPlugin::new(
            &schema,
            TestMethodCommitFailureMode::None,
        ));

    let error = super::super::super::postgres_method_runtime::PostgresAuthMethodRegistry::new([
        left, right,
    ])
    .expect_err("duplicate method plugins must be rejected");

    assert!(
        matches!(
            error,
            super::super::super::postgres_method_runtime::PostgresAuthMethodRegistryError::DuplicateMethod {
                family: ProofFamily::OutOfBandCode,
                ref method_label,
            } if method_label == "email_otp"
        ),
        "expected duplicate email_otp registration error, got {error:?}"
    );
}

#[test]
fn postgres_method_registry_rejects_core_owned_method_registration() {
    let schema = PgSchemaName::from_identifier_text("__paranoid_auth_registry_test")
        .expect("test schema name");
    let plugin: Arc<dyn super::super::super::postgres_method_runtime::PostgresAuthMethodPlugin> =
        Arc::new(TestPostgresAuthMethodPlugin::with_method(
            &schema,
            ProofMethodDeclaration::new(ProofFamily::TrustedDevice, "trusted_device")
                .expect("core-owned method declaration"),
            TestMethodCommitFailureMode::None,
        ));

    let error =
        super::super::super::postgres_method_runtime::PostgresAuthMethodRegistry::new([plugin])
            .expect_err("core-owned methods must not be registered as plugins");

    assert!(
        matches!(
            error,
            super::super::super::postgres_method_runtime::PostgresAuthMethodRegistryError::CoreOwnedMethod {
                family: ProofFamily::TrustedDevice,
                ref method_label,
            } if method_label == "trusted_device"
        ),
        "expected core-owned method registration error, got {error:?}"
    );
}

#[tokio::test]
async fn auth_bootstrap_facade_uses_db_foundation_schema() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let database_url = required_auth_postgres_runtime_test_database_url();
    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let raw_pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let database_operation_observer = DatabaseOperationObserver::default();
    let pool = raw_pool.clone_with_database_operation_observer(database_operation_observer.clone());
    let schema_name = unique_runtime_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let db_bootstrap_config = BootstrapConfig::new(schema.clone());
    db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth bootstrap");

    let auth_bootstrap = first_party_postgres_auth_bootstrap_for_test(db_bootstrap_config.clone());
    let store_config = auth_bootstrap
        .auth_store_config()
        .expect("auth store config");

    let _store = auth_bootstrap
        .migrate_schema_after_db_bootstrap(&write_pool)
        .await
        .expect("migrate auth schema through bootstrap facade");
    first_party_postgres_auth_bootstrap_for_test(db_bootstrap_config.clone())
        .validate_schema_after_db_bootstrap(&pool)
        .await
        .expect("validate auth schema through bootstrap facade");

    let expected_auth_table_names = expected_first_party_auth_bootstrap_table_names(&store_config);
    let actual_auth_table_names =
        fetch_auth_runtime_test_schema_table_names_with_prefix(&pool, &schema, "auth_").await;
    assert_eq!(
        actual_auth_table_names, expected_auth_table_names,
        "auth bootstrap must create exactly the core plus public-alpha first-party method tables in the DB foundation schema"
    );

    let ledger_row_count = count_auth_schema_ledger_rows(&pool, &store_config).await;
    assert_eq!(
        ledger_row_count, 1,
        "auth bootstrap must record exactly one auth-core row in the DB foundation schema ledger"
    );
    assert!(
        database_operation_observer
            .records()
            .into_iter()
            .filter_map(|record| record.statement)
            .all(|statement| !statement.contains("pg_advisory")),
        "auth bootstrap must not use the DB bootstrap advisory-lock exception"
    );

    drop_auth_runtime_test_schema(&pool, &schema).await;
}

fn expected_first_party_auth_bootstrap_table_names(
    store_config: &super::super::super::postgres_store::PostgresAuthStoreConfig,
) -> Vec<String> {
    let mut table_names = PostgresAuthCoreSchemaContract::table_kinds()
        .iter()
        .map(|table| {
            store_config
                .table_name(*table)
                .expect("core auth table name")
                .table()
                .as_str()
                .to_owned()
        })
        .collect::<Vec<_>>();
    table_names.extend(
        [
            "auth_email_otp_challenges",
            "auth_email_otp_delivery_commands",
            "auth_password_signature_verifiers",
            "auth_recovery_code_codes",
            "auth_totp_verifiers",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    table_names.sort();
    table_names
}

async fn fetch_auth_runtime_test_schema_table_names_with_prefix(
    pool: &Pool,
    schema: &PgSchemaName,
    table_name_prefix: &str,
) -> Vec<String> {
    let statement = r#"
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = $1
          AND table_type = 'BASE TABLE'
          AND left(table_name, length($2)) = $2
        ORDER BY table_name
    "#;
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin auth runtime table-name read transaction");
    let table_names = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(statement))
        .bind(schema.as_str())
        .bind(table_name_prefix)
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .expect("fetch auth runtime schema table names");
    tx.rollback()
        .await
        .expect("rollback auth runtime table-name read transaction");
    table_names
}

#[tokio::test]
async fn postgres_runtime_validates_all_first_party_method_schemas_after_migration() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_totp_plugin: true,
                include_recovery_code_plugin: true,
                include_password_derived_signature_plugin: true,
            },
            config(),
            None,
        )
        .await;
    let store = postgres_runtime_test_store_with_method_registry_for_harness(&harness);

    store
        .validate_schema(&harness.pool)
        .await
        .expect("first-party auth method schemas must validate after migration");

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_first_party_method_schema_with_missing_check_constraint() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let totp_table = harness
        .totp_plugin
        .as_ref()
        .expect("totp plugin")
        .verifier_table_name_for_test()
        .expect("totp verifier table");
    drop_first_check_constraint_matching_for_auth_runtime_test(
        &harness.pool,
        &totp_table,
        "%verifier_version%",
    )
    .await;
    let store = postgres_runtime_test_store_with_method_registry_for_harness(&harness);

    let validate_error = store
        .validate_schema(&harness.pool)
        .await
        .expect_err("auth method schema validation must reject missing generated checks")
        .to_string();
    assert!(
        validate_error.contains("verifier_version") && validate_error.contains("CHECK"),
        "unexpected validation error: {validate_error}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_first_party_method_schema_with_missing_required_index() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_recovery_code_method().await;
    let recovery_code_table = harness
        .recovery_code_plugin
        .as_ref()
        .expect("recovery code plugin")
        .recovery_code_table_name_for_test()
        .expect("recovery code table");
    let active_credential_index = PgIdentifier::new(format!(
        "{}_active_credential_idx",
        recovery_code_table.table().as_str()
    ))
    .expect("active credential index name");
    drop_auth_runtime_test_index(&harness.pool, &recovery_code_table, active_credential_index)
        .await;
    let store = postgres_runtime_test_store_with_method_registry_for_harness(&harness);

    let validate_error = store
        .validate_schema(&harness.pool)
        .await
        .expect_err("auth method schema validation must reject missing required indexes")
        .to_string();
    assert!(
        validate_error.contains("active credential lookup")
            && validate_error.contains("credential_instance_id"),
        "unexpected validation error: {validate_error}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_first_party_method_schema_with_default_collation_text() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_email_otp_method().await;
    let challenge_table = harness
        .email_otp_plugin
        .as_ref()
        .expect("email OTP plugin")
        .challenge_table_name_for_test()
        .expect("email OTP challenge table");
    let alter_statement = format!(
        r#"ALTER TABLE {} ALTER COLUMN recipient_handle TYPE TEXT COLLATE "default""#,
        challenge_table.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(alter_statement.as_str()))
        .execute(harness.pool.sqlx_pool())
        .await
        .expect("alter email OTP recipient handle to default collation");
    let store = postgres_runtime_test_store_with_method_registry_for_harness(&harness);

    let validate_error = store
        .validate_schema(&harness.pool)
        .await
        .expect_err("auth method schema validation must reject default-collation method text")
        .to_string();
    assert!(
        validate_error.contains("recipient_handle") && validate_error.contains("collation"),
        "unexpected validation error: {validate_error}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_first_party_method_schema_with_unexpected_column() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness = PostgresRuntimeTestHarness::connect_required_with_totp_method().await;
    let totp_table = harness
        .totp_plugin
        .as_ref()
        .expect("totp plugin")
        .verifier_table_name_for_test()
        .expect("totp verifier table");
    let alter_statement = format!(
        "ALTER TABLE {} ADD COLUMN unexpected_extra BYTEA",
        totp_table.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(alter_statement.as_str()))
        .execute(harness.pool.sqlx_pool())
        .await
        .expect("add unexpected TOTP method table column");
    let store = postgres_runtime_test_store_with_method_registry_for_harness(&harness);

    let validate_error = store
        .validate_schema(&harness.pool)
        .await
        .expect_err("auth method schema validation must reject unexpected method columns")
        .to_string();
    assert!(
        validate_error.contains("unexpected_extra") && validate_error.contains("unexpected column"),
        "unexpected validation error: {validate_error}"
    );

    harness.drop_schema().await;
}

#[tokio::test]
async fn postgres_runtime_rejects_malformed_adopted_method_schema_before_recording_ledger() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let database_url = required_auth_postgres_runtime_test_database_url();
    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let schema_name = unique_runtime_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let db_bootstrap_config = BootstrapConfig::new(schema.clone());
    db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth bootstrap");
    let auth_bootstrap = first_party_postgres_auth_bootstrap_for_test(db_bootstrap_config.clone());
    let store_config = auth_bootstrap
        .auth_store_config()
        .expect("auth store config");
    let malformed_email_challenge_table = PgQualifiedTableName::new(
        Some(schema.clone()),
        PgIdentifier::new("auth_email_otp_challenges").expect("email challenge table"),
    );
    let create_malformed_table_statement = format!(
        "CREATE TABLE {} (challenge_id BYTEA NOT NULL)",
        malformed_email_challenge_table.quoted()
    );
    unparameterized_simple_query(sqlx::AssertSqlSafe(
        create_malformed_table_statement.as_str(),
    ))
    .execute(pool.sqlx_pool())
    .await
    .expect("create malformed adopted email OTP challenge table");

    let migrate_error = match auth_bootstrap
        .migrate_schema_after_db_bootstrap(&write_pool)
        .await
    {
        Ok(_) => panic!("auth migration must reject adopted malformed method tables"),
        Err(error) => error.to_string(),
    };
    assert!(
        migrate_error.contains("method/plugin registry failed during migrate_schema"),
        "unexpected migration error: {migrate_error}"
    );
    let ledger_row_count = count_auth_schema_ledger_rows(&pool, &store_config).await;
    assert_eq!(
        ledger_row_count, 0,
        "failed auth method schema validation must not record a trusted component schema version"
    );

    drop_auth_runtime_test_schema(&pool, &schema).await;
}

#[tokio::test]
async fn postgres_runtime_rejects_adopted_schema_drift_for_every_alpha_auth_table() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let harness =
        PostgresRuntimeTestHarness::connect_required_with_registered_plugins_for_test_method_configured_methods_and_config(
            None,
            true,
            None,
            None,
            TestActiveMethodVerificationMode::BeforeStateLoad,
            FirstPartyMethodSelection {
                include_totp_plugin: true,
                include_recovery_code_plugin: true,
                include_password_derived_signature_plugin: true,
            },
            config(),
            None,
        )
        .await;
    let store = postgres_runtime_test_store_with_method_registry_for_harness(&harness);
    let table_names = final_public_alpha_auth_table_names_for_harness(&harness);
    let expected_table_count =
        expected_first_party_auth_bootstrap_table_names(&harness.store_config).len();
    assert_eq!(
        table_names.len(),
        expected_table_count,
        "adopted-schema drift test must cover the exact final public-alpha auth table set"
    );

    for table_name in &table_names {
        let check_constraint =
            fetch_first_check_constraint_name_for_auth_runtime_test(&harness.pool, table_name)
                .await;
        let drop_check_statement = format!(
            "ALTER TABLE {} DROP CONSTRAINT {}",
            table_name.quoted(),
            check_constraint.quoted()
        );
        assert_auth_schema_validation_rejects_after_transactional_schema_drift(
            &harness,
            &store,
            drop_check_statement,
            &format!(
                "missing check constraint on adopted auth table {}",
                table_name.quoted()
            ),
            "CHECK",
        )
        .await;

        let primary_key_constraint =
            fetch_primary_key_constraint_name_for_auth_runtime_test(&harness.pool, table_name)
                .await;
        let drop_primary_key_statement = format!(
            "ALTER TABLE {} DROP CONSTRAINT {}",
            table_name.quoted(),
            primary_key_constraint.quoted()
        );
        assert_auth_schema_validation_rejects_after_transactional_schema_drift(
            &harness,
            &store,
            drop_primary_key_statement,
            &format!(
                "missing primary-key index on adopted auth table {}",
                table_name.quoted()
            ),
            "primary",
        )
        .await;

        let add_unexpected_column_statement = format!(
            "ALTER TABLE {} ADD COLUMN unexpected_auth_schema_drift BYTEA",
            table_name.quoted()
        );
        assert_auth_schema_validation_rejects_after_transactional_schema_drift(
            &harness,
            &store,
            add_unexpected_column_statement,
            &format!(
                "unexpected column on adopted auth table {}",
                table_name.quoted()
            ),
            "unexpected column",
        )
        .await;
    }

    let mut tested_text_column_count = 0;
    for table_name in &table_names {
        for column_name in
            fetch_text_column_names_for_auth_runtime_test(&harness.pool, table_name).await
        {
            tested_text_column_count += 1;
            let quoted_column = PgIdentifier::new(column_name.clone())
                .expect("auth runtime text column identifier");
            let alter_collation_statement = format!(
                r#"ALTER TABLE {} ALTER COLUMN {} TYPE TEXT COLLATE "default""#,
                table_name.quoted(),
                quoted_column.quoted()
            );
            assert_auth_schema_validation_rejects_after_transactional_schema_drift(
                &harness,
                &store,
                alter_collation_statement,
                &format!(
                    "default-collation text column {}.{}",
                    table_name.quoted(),
                    quoted_column.quoted()
                ),
                "collation",
            )
            .await;
        }
    }
    assert!(
        tested_text_column_count > 0,
        "adopted-schema drift test must exercise default-collation text rejection"
    );

    harness.drop_schema().await;
}

fn final_public_alpha_auth_table_names_for_harness(
    harness: &PostgresRuntimeTestHarness,
) -> Vec<PgQualifiedTableName> {
    let mut table_names = PostgresAuthCoreSchemaContract::table_kinds()
        .iter()
        .map(|table| {
            harness
                .store_config
                .table_name(*table)
                .expect("core auth table name")
        })
        .collect::<Vec<_>>();
    table_names.push(
        harness
            .email_otp_plugin
            .as_ref()
            .expect("email OTP plugin")
            .challenge_table_name_for_test()
            .expect("email OTP challenge table"),
    );
    table_names.push(
        harness
            .email_otp_plugin
            .as_ref()
            .expect("email OTP plugin")
            .delivery_command_table_name_for_test()
            .expect("email OTP delivery table"),
    );
    table_names.push(
        harness
            .totp_plugin
            .as_ref()
            .expect("TOTP plugin")
            .verifier_table_name_for_test()
            .expect("TOTP verifier table"),
    );
    table_names.push(
        harness
            .recovery_code_plugin
            .as_ref()
            .expect("recovery code plugin")
            .recovery_code_table_name_for_test()
            .expect("recovery code table"),
    );
    table_names.push(
        harness
            .password_derived_signature_plugin
            .as_ref()
            .expect("password-derived signature plugin")
            .verifier_table_name_for_test()
            .expect("password-derived signature verifier table"),
    );
    table_names.sort_by(|left, right| left.quoted().to_string().cmp(&right.quoted().to_string()));
    table_names
}

async fn assert_auth_schema_validation_rejects_after_transactional_schema_drift(
    harness: &PostgresRuntimeTestHarness,
    store: &super::super::super::postgres_store::PostgresAuthStore,
    drift_statement: String,
    context: &str,
    expected_error_fragment: &str,
) {
    let mut tx = harness
        .pool
        .begin_transaction()
        .await
        .expect("begin auth schema drift validation transaction");
    unparameterized_simple_query(sqlx::AssertSqlSafe(drift_statement.as_str()))
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .unwrap_or_else(|error| panic!("apply schema drift for {context}: {error}"));
    let validate_error = match store.validate_schema_in_current_transaction(&mut tx).await {
        Ok(()) => panic!("auth schema validation must reject {context}"),
        Err(error) => error.to_string(),
    };
    assert!(
        validate_error.contains(expected_error_fragment),
        "unexpected validation error for {context}: {validate_error}"
    );
    tx.rollback()
        .await
        .expect("rollback auth schema drift validation transaction");
}

async fn fetch_first_check_constraint_name_for_auth_runtime_test(
    pool: &Pool,
    table: &PgQualifiedTableName,
) -> PgIdentifier {
    let statement = r#"
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'c'
          AND con.convalidated
        ORDER BY con.conname
        LIMIT 1
        "#;
    let constraint_name = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<String>(statement).bind(table.quoted().to_string()),
        "find first auth check constraint"
    );
    PgIdentifier::new(constraint_name).expect("auth check constraint identifier")
}

async fn fetch_primary_key_constraint_name_for_auth_runtime_test(
    pool: &Pool,
    table: &PgQualifiedTableName,
) -> PgIdentifier {
    let statement = r#"
        SELECT con.conname
        FROM pg_constraint con
        WHERE con.conrelid = to_regclass($1)
          AND con.contype = 'p'
        ORDER BY con.conname
        LIMIT 1
        "#;
    let constraint_name = auth_runtime_test_fetch_one_in_transaction!(
        pool,
        pooler_safe_query_scalar::<String>(statement).bind(table.quoted().to_string()),
        "find auth primary-key constraint"
    );
    PgIdentifier::new(constraint_name).expect("auth primary-key constraint identifier")
}

async fn fetch_text_column_names_for_auth_runtime_test(
    pool: &Pool,
    table: &PgQualifiedTableName,
) -> Vec<String> {
    let statement = r#"
        SELECT attr.attname
        FROM pg_attribute attr
        WHERE attr.attrelid = to_regclass($1)
          AND attr.attnum > 0
          AND NOT attr.attisdropped
          AND pg_catalog.format_type(attr.atttypid, attr.atttypmod) = 'text'
        ORDER BY attr.attname
        "#;
    let mut tx = pool
        .begin_transaction()
        .await
        .expect("begin auth text-column read transaction");
    let column_names = pooler_safe_query_scalar::<String>(sqlx::AssertSqlSafe(statement))
        .bind(table.quoted().to_string())
        .fetch_all(tx.sqlx_transaction().as_mut())
        .await
        .expect("fetch auth text columns");
    tx.rollback()
        .await
        .expect("rollback auth text-column read transaction");
    column_names
}

#[tokio::test]
async fn auth_bootstrap_facade_builds_configured_mounted_runtime_routes() {
    let _postgres_runtime_test_guard = AUTH_POSTGRES_RUNTIME_TEST_LOCK.lock().await;
    let database_url = required_auth_postgres_runtime_test_database_url();
    let write_pool = WritePool::connect(PoolConfig::new(SecretString::from(database_url.clone())))
        .await
        .expect("connect write test database");
    let raw_pool = Pool::connect(PoolConfig::new(SecretString::from(database_url)))
        .await
        .expect("connect test database");
    let database_operation_observer = DatabaseOperationObserver::default();
    let pool = raw_pool.clone_with_database_operation_observer(database_operation_observer.clone());
    let schema_name = unique_runtime_test_schema_name();
    let schema = PgSchemaName::new(schema_name.clone());
    let db_bootstrap_config = BootstrapConfig::new(schema.clone());
    let db_bootstrap_stores = db_bootstrap_config
        .migrate_schema(&write_pool)
        .await
        .expect("migrate DB foundation before auth bootstrap");

    let store_config = first_party_postgres_auth_bootstrap_for_test(db_bootstrap_config.clone())
        .auth_store_config()
        .expect("auth store config");
    let recovery_code_plugin = PostgresRecoveryCodeMethodPlugin::new(
        PostgresRecoveryCodeMethodPluginConfig::for_db_bootstrap_config(&db_bootstrap_config)
            .expect("recovery code method config"),
        test_keyset("tests.auth.postgres-bootstrap.recovery-code.v1"),
    )
    .expect("recovery code method plugin");
    let plausible_unused_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(
            &id("mounted-http-plausible-unused-recovery-code-subject"),
            b"mounted-http-unused-recovery-code",
        )
        .expect("plausible unused recovery code");
    let consumed_recovery_code_subject_id: SubjectId =
        id("mounted-http-consumed-recovery-code-subject");
    let consumed_recovery_code_credential_id: VerifiedProofSourceId =
        id("mounted-http-consumed-recovery-code-set");
    let consumed_recovery_code_id = recovery_code_id_for_runtime_test(0x45);
    let consumed_recovery_code_secret = b"mounted-http-consumed-recovery-code";
    let consumed_recovery_code_response = recovery_code_plugin
        .sealed_recovery_code_response_for_test(
            &consumed_recovery_code_subject_id,
            consumed_recovery_code_secret,
        )
        .expect("consumed recovery code response");
    let postgres_auth_system_config = PostgresAuthSystemConfig::new(
        db_bootstrap_config.clone(),
        test_keyset("tests.auth.postgres-bootstrap.credentials.v1"),
        config(),
        auth_web_transport(),
        Arc::new(hashcash_verifier_for_test()),
        MountedAuthRouteMountPath::new("/auth").expect("mounted auth route path"),
        MountedAuthDurableEffectWorkerIntegrations::new(
            Arc::new(RecordingCoreAuthOutOfBandMessageDeliverer::new(Ok(()))),
            Arc::new(RecordingCoreAuthSecurityNotificationDeliverer::new(Ok(()))),
            Arc::new(RecordingCoreAuthApplicationSubjectDataLifecycleIntegrator::new(Ok(()))),
        ),
    )
    .with_email_otp_full_authentication_method(
        test_keyset("tests.auth.postgres-bootstrap.mounted-email-otp.v1"),
        Arc::new(StaticEmailOtpSubjectResolver::new(
            "bootstrap@example.test",
            id("postgres-bootstrap-email-subject"),
            id("postgres-bootstrap-email-source"),
        )),
    )
    .expect("mounted email OTP full-authentication method")
    .with_recovery_code_to_password_derived_signature_no_session_recovery(test_keyset(
        "tests.auth.postgres-bootstrap.mounted-recovery-code.v1",
    ))
    .expect("mounted no-session recovery flow")
    .with_password_derived_signature_credential_addition_route(
        "password-signature",
        CredentialResetPolicyRole::OrdinaryCredential,
        vec![CredentialAdditionRecoveryAuthorityRule {
            action: CredentialLifecycleAction::Create,
            authority_id: id("postgres-bootstrap-mounted-add-session-authority"),
            timing: RecoveryAuthorityTiming::Immediate,
        }],
        vec![id("postgres-bootstrap-mounted-add-new-authority")],
    )
    .expect("mounted password credential-addition route");
    let mounted_system = postgres_auth_system_config
        .migrate_schema_and_build_after_db_bootstrap(&write_pool, pool.clone())
        .await
        .expect("migrate auth schema and build mounted system");
    assert_eq!(mounted_system.mount_path().as_str(), "/auth");
    let worker_service = mounted_system
        .durable_effect_worker(write_pool.clone(), db_bootstrap_stores.queue.clone())
        .expect("configured durable-effect worker service");
    let task_registry = worker_service
        .build_task_registry()
        .expect("configured durable-effect worker task registry");
    let task_names = task_registry.registered_task_names();
    assert!(
        task_names.contains(&AUTH_APPLICATION_SUBJECT_DATA_LIFECYCLE_QUEUE_TASK_NAME.to_owned())
    );
    assert!(task_names.contains(&AUTH_OUT_OF_BAND_MESSAGE_QUEUE_TASK_NAME.to_owned()));
    assert!(task_names.contains(&AUTH_SECURITY_NOTIFICATION_QUEUE_TASK_NAME.to_owned()));
    let http_mount = mounted_system.http_mount();
    assert_eq!(http_mount.mount_path().as_str(), "/auth");
    let route_manifest = mounted_system.route_manifest();
    assert_eq!(
        route_manifest.routes().len(),
        25,
        "configured mounted runtime must expose the coherent configured-system route surface"
    );
    assert!(
        route_manifest
            .routes()
            .iter()
            .any(|route| route.kind() == MountedAuthRouteKind::AuthenticatedCredentialAddition),
        "configured mounted runtime must advertise password credential-addition route"
    );
    assert!(
        route_manifest.routes().iter().any(|route| route.kind()
            == MountedAuthRouteKind::NoSessionCredentialRecovery(
                MountedNoSessionCredentialRecoveryEndpoint::ExecuteImmediateReset
            )),
        "configured mounted runtime must advertise the immediate recovery reset route"
    );
    assert!(
        route_manifest
            .routes()
            .iter()
            .any(|route| route.kind() == MountedAuthRouteKind::AuthenticatedCredentialInventory),
        "configured mounted runtime must advertise the authenticated credential inventory route"
    );
    assert!(
        route_manifest.routes().iter().any(|route| route.kind()
            == MountedAuthRouteKind::DelayedSubjectAuthStateDeletion(
                MountedDelayedSubjectAuthStateDeletionEndpoint::ScheduleDeletion
            )),
        "configured mounted runtime must advertise delayed subject auth-state deletion routes"
    );
    let mut request_resolution_service = http_mount
        .request_resolution_layer(RequestKind::SafeRead)
        .with_fixed_now_for_tests(at(70))
        .layer(MountedAuthRequestStateEchoService);
    database_operation_observer.clear();
    let request_resolution_response = request_resolution_service
        .call(
            Request::builder()
                .method(Method::GET)
                .uri("https://example.com/app")
                .body(Full::new(Bytes::new()))
                .expect("mounted app request"),
        )
        .await
        .expect("mounted request-resolution layer should call inner service");
    assert_eq!(
        request_resolution_response.body().as_slice(),
        b"needs_full_authentication",
        "mounted request-resolution layer must insert the coarse auth state for app services"
    );
    assert_http_response_has_no_set_cookie(
        &request_resolution_response,
        "missing-cookie mounted request resolution must not emit Set-Cookie headers",
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing-cookie mounted request resolution must reject before any database operation",
    );

    let mut http_route_service = mounted_system
        .http_route_service()
        .with_fixed_now_for_tests(at(70));
    recovery_code_plugin
        .store_recovery_code_for_test(
            &pool,
            &consumed_recovery_code_subject_id,
            &consumed_recovery_code_credential_id,
            &consumed_recovery_code_id,
            consumed_recovery_code_secret,
            at(60),
        )
        .await
        .expect("store consumed recovery code verifier state");
    let recovery_code_table = recovery_code_plugin
        .recovery_code_table_name_for_test()
        .expect("recovery code table");
    let mark_consumed_statement = format!(
        "UPDATE {} SET consumed_at = $3 WHERE subject_id = $1 AND recovery_code_id = $2",
        recovery_code_table.quoted(),
    );
    let mut mark_consumed_tx = pool
        .begin_transaction()
        .await
        .expect("begin mark consumed recovery code transaction");
    pooler_safe_query(sqlx::AssertSqlSafe(mark_consumed_statement.as_str()))
        .bind(consumed_recovery_code_subject_id.as_bytes())
        .bind(consumed_recovery_code_id.as_slice())
        .bind(61_i64)
        .execute(mark_consumed_tx.sqlx_transaction().as_mut())
        .await
        .expect("mark recovery code consumed");
    mark_consumed_tx
        .commit()
        .await
        .expect("commit mark consumed recovery code transaction");
    let recovery_method = proof_method(ProofFamily::RecoveryCode);
    let preflight_response = challenge_issue_preflight_response_for_test(
        at(70),
        ProofUse::RecoverOrReplaceCredential,
        &recovery_method,
    );
    database_operation_observer.clear();
    let unknown_route_request = Request::builder()
        .method(Method::POST)
        .uri("https://example.com/auth/unknown")
        .body(Full::new(Bytes::from_static(b"not-json-and-not-a-route")))
        .expect("unknown mounted auth route request");
    let unknown_route_response = http_route_service
        .call(unknown_route_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(unknown_route_response.status(), StatusCode::NOT_FOUND);
    assert_http_response_has_no_set_cookie(
        &unknown_route_response,
        "unknown mounted auth route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&unknown_route_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("not_found")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "unknown mounted auth route must reject before any database operation",
    );

    let invalid_http_body_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(Full::new(Bytes::from_static(
            br#"{"this_is_not_the_recovery_start_shape":true}"#,
        )))
        .expect("invalid mounted endpoint request");

    database_operation_observer.clear();
    let invalid_body_response = http_route_service
        .call(invalid_http_body_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(invalid_body_response.status(), StatusCode::BAD_REQUEST);
    assert_http_response_has_no_set_cookie(
        &invalid_body_response,
        "invalid mounted auth route body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&invalid_body_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("bad_request")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "invalid HTTP mounted auth route body must reject before any database operation",
    );

    let invalid_proof_payload_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(Full::new(Bytes::from_static(
            br#"{"secret_response_base64url":"not base64"}"#,
        )))
        .expect("invalid mounted recovery proof payload request");

    database_operation_observer.clear();
    let invalid_proof_payload_response = http_route_service
        .call(invalid_proof_payload_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        invalid_proof_payload_response.status(),
        StatusCode::BAD_REQUEST
    );
    assert_http_response_has_no_set_cookie(
        &invalid_proof_payload_response,
        "invalid mounted recovery proof payload must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&invalid_proof_payload_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("bad_request")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "invalid mounted recovery proof payload must reject before any database operation",
    );

    let csrf_required_request_with_junk_body = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
        ))
        .body(Full::new(Bytes::from_static(
            b"body-must-not-be-parsed-before-csrf",
        )))
        .expect("CSRF-required mounted endpoint request with junk body");

    database_operation_observer.clear();
    let csrf_response = http_route_service
        .call(csrf_required_request_with_junk_body)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &csrf_response,
        "missing CSRF on mounted auth route must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on a CSRF-required mounted auth route must reject before body parsing or database operation",
    );

    let csrf_required_reset_request_with_junk_body = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH
        ))
        .body(Full::new(Bytes::from_static(
            b"reset-body-must-not-be-parsed-before-csrf",
        )))
        .expect("CSRF-required mounted recovery reset request with junk body");

    database_operation_observer.clear();
    let reset_csrf_response = http_route_service
        .call(csrf_required_reset_request_with_junk_body)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(reset_csrf_response.status(), StatusCode::FORBIDDEN);
    assert_http_response_has_no_set_cookie(
        &reset_csrf_response,
        "missing CSRF on mounted recovery reset must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&reset_csrf_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("forbidden")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing CSRF on mounted recovery reset must reject before body parsing or database operation",
    );

    let csrf_issue_request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/auth")
        .body(())
        .expect("CSRF issue request");
    let csrf_cookie_header = auth_web_transport()
        .issue_csrf_token_cookie_if_needed_for_request(&csrf_issue_request)
        .expect("issue CSRF cookie for mounted route test")
        .expect("CSRF cookie should be issued");
    let csrf_cookie_pair = csrf_cookie_header
        .as_str()
        .split(';')
        .next()
        .expect("CSRF Set-Cookie starts with name=value");
    let csrf_token = csrf_cookie_pair
        .split_once('=')
        .expect("CSRF cookie pair contains equals")
        .1;

    let reset_request_missing_content_type = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH
        ))
        .header(COOKIE, csrf_cookie_pair)
        .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
        .body(Full::new(Bytes::from_static(b"{}")))
        .expect("mounted recovery reset request without content-type");

    database_operation_observer.clear();
    let reset_missing_content_type_response = http_route_service
        .call(reset_request_missing_content_type)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        reset_missing_content_type_response.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_http_response_has_no_set_cookie(
        &reset_missing_content_type_response,
        "missing content-type on mounted recovery reset must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&reset_missing_content_type_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("unsupported_media_type")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "missing content-type on mounted recovery reset must reject before any database operation",
    );

    let schedule_request_with_valid_csrf_and_body = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
        ))
        .header(COOKIE, csrf_cookie_pair)
        .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
        .body(Full::new(Bytes::from_static(b"x")))
        .expect("CSRF-valid mounted schedule request with body");

    database_operation_observer.clear();
    let schedule_body_limit_response = http_route_service
        .call(schedule_request_with_valid_csrf_and_body)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        schedule_body_limit_response.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_http_response_has_no_set_cookie(
        &schedule_body_limit_response,
        "non-empty schedule route body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&schedule_body_limit_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("payload_too_large")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "route-specific mounted auth body limits must reject before any database operation",
    );

    let oversized_body_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(Full::new(Bytes::from(vec![
            b' ';
            http_route_service
                .max_body_bytes()
                + 1
        ])))
        .expect("oversized mounted endpoint request");

    database_operation_observer.clear();
    let oversized_body_response = http_route_service
        .call(oversized_body_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        oversized_body_response.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_http_response_has_no_set_cookie(
        &oversized_body_response,
        "oversized mounted auth route body must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&oversized_body_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("payload_too_large")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "oversized mounted auth route body must reject before any database operation",
    );

    let preflight_payload_base64url = BASE64URL_NOPAD.encode(preflight_response.payload());
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_START_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(Full::new(Bytes::from(
            format!(
                r#"{{
                    "preflight_gate_kind": "proof_of_work",
                    "preflight_gate_method_label": "{}",
                    "preflight_gate_payload_base64url": "{}"
                }}"#,
                preflight_response.summary().method_label(),
                preflight_payload_base64url,
            )
            .into_bytes(),
        )))
        .expect("mounted endpoint request");

    let response = http_route_service
        .call(request)
        .await
        .expect("mounted auth Tower service is infallible");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        auth_runtime_test_json_response_body(&response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_attempt_started")
    );
    assert!(
        auth_runtime_test_json_response_body(&response)
            .get("expires_at_unix_seconds")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "mounted endpoint response should include the recovery attempt expiry"
    );
    assert!(
        response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .next()
            .is_some(),
        "mounted endpoint response should render continuation cookies into Set-Cookie headers"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "mounted runtime route service must commit the recovery attempt through the bootstrapped store"
    );
    let continuation_cookie_pair = cookie_pair_from_http_response_set_cookie(
        &response,
        "__Host-__paranoid_auth_active_proof_continuation=",
    );
    let unaccepted_schedule_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_SCHEDULE_RESET_ROUTE_PATH
        ))
        .header(
            COOKIE,
            format!("{}; {}", continuation_cookie_pair, csrf_cookie_pair),
        )
        .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
        .body(Full::new(Bytes::new()))
        .expect("unaccepted mounted recovery schedule request");

    database_operation_observer.clear();
    let unaccepted_schedule_response = http_route_service
        .call(unaccepted_schedule_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        unaccepted_schedule_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_http_response_has_no_set_cookie(
        &unaccepted_schedule_response,
        "unaccepted mounted recovery schedule continuation must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&unaccepted_schedule_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("internal_error")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "unaccepted mounted recovery schedule continuation must reject before any database operation",
    );

    let reset_payload_base64url =
        BASE64URL_NOPAD.encode(b"unaccepted-mounted-recovery-reset-payload".as_slice());
    let unaccepted_execute_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_EXECUTE_RESET_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(
            COOKIE,
            format!("{}; {}", continuation_cookie_pair, csrf_cookie_pair),
        )
        .header(crate::web::DEFAULT_CSRF_HEADER_NAME, csrf_token)
        .body(Full::new(Bytes::from(
            format!(
                r#"{{
                    "method_payload_base64url": "{}"
                }}"#,
                reset_payload_base64url,
            )
            .into_bytes(),
        )))
        .expect("unaccepted mounted recovery execute request");

    database_operation_observer.clear();
    let unaccepted_execute_response = http_route_service
        .call(unaccepted_execute_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(
        unaccepted_execute_response.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_http_response_has_no_set_cookie(
        &unaccepted_execute_response,
        "unaccepted mounted recovery execute continuation must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&unaccepted_execute_response)
            .get("error")
            .and_then(serde_json::Value::as_str),
        Some("internal_error")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "unaccepted mounted recovery execute continuation must reject before any database operation",
    );

    let malformed_recovery_secret_base64url = BASE64URL_NOPAD.encode(b"not-a-sealed-recovery-code");
    let malformed_proof_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(COOKIE, continuation_cookie_pair.as_str())
        .body(Full::new(Bytes::from(
            format!(
                r#"{{
                    "secret_response_base64url": "{}"
                }}"#,
                malformed_recovery_secret_base64url,
            )
            .into_bytes(),
        )))
        .expect("malformed mounted recovery proof request");

    database_operation_observer.clear();
    let malformed_proof_response = http_route_service
        .call(malformed_proof_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(malformed_proof_response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &malformed_proof_response,
        "malformed mounted recovery proof must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&malformed_proof_response)
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_proof_rejected")
    );
    assert_no_database_operations(
        &database_operation_observer,
        "malformed mounted recovery proof must reject before any database operation",
    );
    let malformed_rejection_body = auth_runtime_test_json_response_body(&malformed_proof_response);
    assert_eq!(
        malformed_rejection_body
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("credential_recovery_proof_rejected")
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "malformed mounted recovery proof must leave the recovery attempt open"
    );

    let plausible_unused_proof_base64url =
        BASE64URL_NOPAD.encode(plausible_unused_response.expose_secret());
    let plausible_unused_proof_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(COOKIE, continuation_cookie_pair.as_str())
        .body(Full::new(Bytes::from(
            format!(
                r#"{{
                    "secret_response_base64url": "{}"
                }}"#,
                plausible_unused_proof_base64url,
            )
            .into_bytes(),
        )))
        .expect("plausible unused mounted recovery proof request");

    let plausible_unused_proof_response = http_route_service
        .call(plausible_unused_proof_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(plausible_unused_proof_response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &plausible_unused_proof_response,
        "plausible unused mounted recovery proof must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&plausible_unused_proof_response),
        malformed_rejection_body,
        "malformed and plausible-but-unused recovery proofs must render the same public HTTP response body"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "plausible unused mounted recovery proof must not turn into a successful recovery ceremony"
    );
    let consumed_proof_base64url =
        BASE64URL_NOPAD.encode(consumed_recovery_code_response.expose_secret());
    let consumed_proof_request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://example.com/auth{}",
            MOUNTED_NO_SESSION_CREDENTIAL_RECOVERY_PROOF_ROUTE_PATH
        ))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(COOKIE, continuation_cookie_pair.as_str())
        .body(Full::new(Bytes::from(
            format!(
                r#"{{
                    "secret_response_base64url": "{}"
                }}"#,
                consumed_proof_base64url,
            )
            .into_bytes(),
        )))
        .expect("consumed mounted recovery proof request");

    let consumed_proof_response = http_route_service
        .call(consumed_proof_request)
        .await
        .expect("mounted auth Tower service is infallible");
    assert_eq!(consumed_proof_response.status(), StatusCode::OK);
    assert_http_response_has_no_set_cookie(
        &consumed_proof_response,
        "consumed mounted recovery proof must not emit Set-Cookie headers",
    );
    assert_eq!(
        auth_runtime_test_json_response_body(&consumed_proof_response),
        malformed_rejection_body,
        "consumed recovery proofs must render the same public HTTP response body as malformed and unused proofs"
    );
    assert_eq!(
        count_all_active_proof_attempts(&pool, &store_config).await,
        1,
        "consumed mounted recovery proof must not turn into a successful recovery ceremony"
    );

    drop_auth_runtime_test_schema(&pool, &schema).await;
}
